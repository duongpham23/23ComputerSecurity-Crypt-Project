"""
kv.engine — Feature 1: Encrypted-at-Rest KV Storage + Ownership Access Control.

Features implemented:
    1.1  write / read / delete with AES-256-GCM encryption using the vault DEK.
         Fresh random nonce per write. GCM tag is verified before returning data.
    1.2  Ownership-based access control: path must start with ``secret/<email>/``.
         Mismatches are refused BEFORE any crypto operation, with a generic error
         that does not reveal whether the path exists.
"""

import base64
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.auth.session import Unauthenticated, verify_token  # noqa: F401
from src.core.vault import VaultLocked, get_dek  # noqa: F401
from src.storage.db import get_db

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PermissionDenied(Exception):
    """Raised when a token owner tries to access another user's path."""

    pass


class NotFound(Exception):
    """Raised when a path does not exist in the KV store."""

    pass


class TagMismatch(Exception):
    """Raised when GCM authentication tag verification fails (tampered data)."""

    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PATH_PREFIX = "secret/"


def _check_ownership(path: str, caller_email: str) -> None:
    """
    Ensure *path* lives under ``secret/<caller_email>/...``.

    Raises PermissionDenied (generic) if:
      - the path doesn't start with 'secret/'
      - the email segment doesn't match the caller
    The error intentionally does NOT reveal whether the path exists.
    Denied attempts are logged to the audit log per spec §1.2.
    """
    from src.storage.audit import log_action

    if not path.startswith(_PATH_PREFIX):
        log_action(
            action="KV_ACCESS_DENIED",
            actor_email=caller_email,
            resource=path,
            detail={"reason": "INVALID_PATH_PREFIX"},
            result="DENIED",
        )
        raise PermissionDenied("PERMISSION_DENIED")

    # Extract the email segment between the first and second '/' after "secret/"
    rest = path[len(_PATH_PREFIX) :]
    slash_idx = rest.find("/")
    if slash_idx == -1:
        # Path is just "secret/<email>" with no sub-path — still valid
        path_email = rest
    else:
        path_email = rest[:slash_idx]

    if path_email != caller_email:
        # Check if they have an ACL grant
        from src.transit.acl import check_grant

        if not check_grant("kv", path, caller_email):
            log_action(
                action="KV_ACCESS_DENIED",
                actor_email=caller_email,
                resource=path,
                detail={"reason": "NAMESPACE_MISMATCH", "path_owner": path_email},
                result="DENIED",
            )
            raise PermissionDenied("PERMISSION_DENIED")


def _encrypt(dek: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM using *dek*.

    Returns:
        (nonce, ciphertext, tag)  — nonce is 12 bytes, tag is last 16 bytes of
        the AESGCM output.
    """
    nonce = os.urandom(12)  # 96-bit nonce, unique per write
    aesgcm = AESGCM(dek)
    # AESGCM.encrypt returns ciphertext || tag (tag is last 16 bytes)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return nonce, ciphertext, tag


def _decrypt(dek: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.

    Raises TagMismatch when the GCM tag does not verify (tampered data).
    """
    aesgcm = AESGCM(dek)
    ct_with_tag = ciphertext + tag
    try:
        return aesgcm.decrypt(nonce, ct_with_tag, None)
    except Exception as exc:
        raise TagMismatch(
            "GCM authentication tag mismatch — data may have been tampered with"
        ) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def write(path: str, data: dict, token: str) -> dict:
    """
    Encrypt and persist a JSON secret at the given path.

    Args:
        path:  Storage path, must be in the form ``secret/<owner_email>/...``.
        data:  Any JSON-serialisable dict.
        token: Session token (used to authenticate and derive the owner email).

    Returns:
        {"path": path, "version": int, "created_at": float, "updated_at": float}

    Raises:
        Unauthenticated: bad/expired token.
        VaultLocked:     vault not unlocked.
        PermissionDenied: path namespace does not match token owner.
    """
    # 1. Authenticate
    caller_email = verify_token(token)

    # 2. Check vault is unlocked (raises VaultLocked)
    dek = get_dek()

    # 3. Ownership check BEFORE any crypto (spec requirement 1.2)
    _check_ownership(path, caller_email)

    # 4. Encrypt the entire JSON payload
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    nonce, ciphertext, tag = _encrypt(dek, plaintext)

    nonce_b64 = base64.b64encode(nonce).decode()
    ct_b64 = base64.b64encode(ciphertext).decode()
    tag_b64 = base64.b64encode(tag).decode()

    now = time.time()
    conn = get_db()

    # Check if path already exists → upsert
    existing = conn.execute(
        "SELECT version, created_at FROM kv_secrets WHERE path = ?",
        (path,),
    ).fetchone()

    if existing:
        new_version = existing["version"] + 1
        created_at = existing["created_at"]

        # Archive old version into kv_versions (for extra-credit versioning)
        old = conn.execute("SELECT * FROM kv_secrets WHERE path = ?", (path,)).fetchone()
        conn.execute(
            """INSERT INTO kv_versions
               (path, owner_email, nonce_b64, ciphertext_b64, tag_b64, version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                old["path"],
                old["owner_email"],
                old["nonce_b64"],
                old["ciphertext_b64"],
                old["tag_b64"],
                old["version"],
                old["created_at"],
            ),
        )

        conn.execute(
            """UPDATE kv_secrets
               SET nonce_b64 = ?, ciphertext_b64 = ?, tag_b64 = ?,
                   version = ?, updated_at = ?
               WHERE path = ?""",
            (nonce_b64, ct_b64, tag_b64, new_version, now, path),
        )
    else:
        new_version = 1
        created_at = now
        conn.execute(
            """INSERT INTO kv_secrets
               (path, owner_email, nonce_b64, ciphertext_b64, tag_b64, version, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (path, caller_email, nonce_b64, ct_b64, tag_b64, 1, now, now),
        )

    conn.commit()
    return {
        "path": path,
        "version": new_version,
        "created_at": created_at,
        "updated_at": now,
    }


def read(path: str, token: str) -> dict:
    """
    Decrypt and return the secret at the given path.

    Args:
        path:  Storage path.
        token: Session token.

    Returns:
        The original JSON dict stored by write().

    Raises:
        Unauthenticated: bad/expired token.
        VaultLocked:     vault not unlocked.
        PermissionDenied: path namespace mismatch.
        NotFound:        path does not exist.
        TagMismatch:     GCM tag mismatch — on-disk data has been tampered with.
    """
    caller_email = verify_token(token)
    dek = get_dek()
    _check_ownership(path, caller_email)

    conn = get_db()
    row = conn.execute(
        "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM kv_secrets WHERE path = ?",
        (path,),
    ).fetchone()

    if row is None:
        raise NotFound(f"NOT_FOUND: {path}")

    nonce = base64.b64decode(row["nonce_b64"])
    ciphertext = base64.b64decode(row["ciphertext_b64"])
    tag = base64.b64decode(row["tag_b64"])

    plaintext = _decrypt(dek, nonce, ciphertext, tag)
    return json.loads(plaintext)


def delete(path: str, token: str) -> dict:
    """
    Permanently delete the secret at the given path.

    Args:
        path:  Storage path.
        token: Session token.

    Returns:
        {"deleted": True, "path": path}

    Raises:
        Unauthenticated, VaultLocked, PermissionDenied, NotFound.
    """
    caller_email = verify_token(token)
    get_dek()  # Ensure vault is unlocked
    _check_ownership(path, caller_email)

    conn = get_db()
    row = conn.execute("SELECT 1 FROM kv_secrets WHERE path = ?", (path,)).fetchone()
    if row is None:
        raise NotFound(f"NOT_FOUND: {path}")

    conn.execute("DELETE FROM kv_secrets WHERE path = ?", (path,))
    conn.commit()
    
    from src.storage.audit import log_action
    log_action(
        action="KV_DELETE",
        actor_email=caller_email,
        resource=path,
        detail={},
    )
    
    return {"deleted": True, "path": path}


def list_secrets(token: str) -> list[dict]:
    """
    List all secrets owned by the caller.

    Args:
        token: Session token.

    Returns:
        List of dicts: [{"path": str, "updated_at": float}]
    """
    caller_email = verify_token(token)
    # The vault does not need to be unlocked just to list metadata, but we might want to check it.
    # To match read/write behavior, we require an unlocked vault.
    get_dek()

    conn = get_db()
    rows = conn.execute(
        """
        SELECT path, updated_at, 0 AS is_shared 
        FROM kv_secrets 
        WHERE owner_email = ?
        UNION
        SELECT k.path, k.updated_at, 1 AS is_shared
        FROM kv_secrets k
        JOIN acl_grants a ON k.path = a.resource_id
        WHERE a.grantee_email = ? AND a.resource_type = 'kv'
        ORDER BY path ASC
        """,
        (caller_email, caller_email),
    ).fetchall()

    return [{"path": r["path"], "updated_at": r["updated_at"], "is_shared": bool(r["is_shared"])} for r in rows]
