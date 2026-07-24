"""
transit.keys — Feature 2.1: Named Key Management.

Handles creation, listing, and revocation of named AES-256 encryption keys
AND asymmetric signing keys. Keys are always stored encrypted-at-rest using
the vault DEK. The raw key material is NEVER returned through any API.

Also provides shared internal helpers used by crypto.py and signing.py.
"""

import base64
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.auth.session import verify_token
from src.core.vault import get_dek
from src.storage.db import get_db

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class KeyAlreadyExists(Exception):
    """Raised when create_key is called with a name already owned by the user."""

    pass


class KeyNotFound(Exception):
    """Raised when the requested key_name does not exist or has been revoked."""

    pass


class InvalidKeyUsage(Exception):
    """Raised when a key is used for an operation incompatible with its key_usage."""

    pass


# ---------------------------------------------------------------------------
# Internal helpers (used by crypto.py and signing.py too)
# ---------------------------------------------------------------------------


def _encrypt_with_dek(dek: bytes, material: bytes) -> tuple[str, str, str]:
    """
    Encrypt raw key material using the vault DEK (AES-256-GCM).

    Returns (nonce_b64, ciphertext_b64, tag_b64) — the three are concatenated
    and stored as ``encrypted_key_material_b64`` in the DB for simplicity:
    ``base64(nonce || ciphertext || tag)``.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(dek)
    ct_with_tag = aesgcm.encrypt(nonce, material, None)
    # Pack as a single blob: nonce(12) || ciphertext || tag(16)
    blob = nonce + ct_with_tag
    return base64.b64encode(blob).decode()


def _decrypt_with_dek(dek: bytes, encrypted_b64: str) -> bytes:
    """
    Decrypt key material previously encrypted by ``_encrypt_with_dek``.

    Returns the raw key material bytes.
    """
    blob = base64.b64decode(encrypted_b64)
    nonce = blob[:12]
    ct_with_tag = blob[12:]
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ct_with_tag, None)


def _get_active_key(
    key_name: str, owner_email: str, *, required_usage: str | None = None
) -> dict:
    """
    Look up the latest active version of a named key.

    Raises KeyNotFound or InvalidKeyUsage as appropriate.
    Returns the row as a dict.
    """
    conn = get_db()
    row = conn.execute(
        """SELECT * FROM transit_keys
           WHERE key_name = ? AND owner_email = ? AND is_active = 1
           ORDER BY key_version DESC LIMIT 1""",
        (key_name, owner_email),
    ).fetchone()

    if row is None:
        raise KeyNotFound(f"KEY_NOT_FOUND: {key_name}")

    if required_usage and row["key_usage"] != required_usage:
        raise InvalidKeyUsage(
            f"INVALID_KEY_USAGE: key '{key_name}' has usage "
            f"'{row['key_usage']}', expected '{required_usage}'"
        )

    return dict(row)


def _check_key_ownership(key_name: str, caller_email: str, version: int | None = None) -> dict:
    """
    Verify the caller owns the named key, returning the key row.

    If version is provided, fetches that specific version. Otherwise fetches the latest active.
    Returns the key row as a dict.
    Raises KeyNotFound (generic, does not disclose existence to non-owners).
    """
    from src.kv.engine import PermissionDenied

    conn = get_db()
    
    # We first verify ownership of ANY version of this key to distinguish NotFound from PermissionDenied
    any_row = conn.execute(
        "SELECT owner_email FROM transit_keys WHERE key_name = ? LIMIT 1",
        (key_name,),
    ).fetchone()

    if any_row is None:
        raise KeyNotFound(f"KEY_NOT_FOUND: {key_name}")

    if any_row["owner_email"] != caller_email:
        # Check if they have an ACL grant
        from src.transit.acl import check_grant
        if not check_grant('transit', key_name, caller_email):
            raise PermissionDenied("PERMISSION_DENIED")

    if version is not None:
        row = conn.execute(
            """SELECT * FROM transit_keys
               WHERE key_name = ? AND owner_email = ? AND key_version = ?""",
            (key_name, caller_email, version),
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT * FROM transit_keys
               WHERE key_name = ? AND owner_email = ? AND is_active = 1
               ORDER BY key_version DESC LIMIT 1""",
            (key_name, caller_email),
        ).fetchone()

    if row is None:
        raise KeyNotFound(f"KEY_NOT_FOUND: {key_name} (version {version or 'latest'})")

    return dict(row)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_key(key_name: str, token: str) -> dict:
    """
    Generate and store a new AES-256 named key (key_usage=ENCRYPT_DECRYPT).

    The key is encrypted with the DEK before being written to disk.

    Args:
        key_name: Unique name for the key (scoped to the token owner).
        token:    Session token.

    Returns:
        {"key_name": str, "key_usage": "ENCRYPT_DECRYPT", "created_at": float}

    Raises:
        Unauthenticated, VaultLocked, KeyAlreadyExists.
    """
    caller_email = verify_token(token)
    dek = get_dek()

    conn = get_db()
    existing = conn.execute(
        """SELECT 1 FROM transit_keys
           WHERE key_name = ? AND owner_email = ? AND is_active = 1""",
        (key_name, caller_email),
    ).fetchone()

    if existing:
        raise KeyAlreadyExists(f"KEY_ALREADY_EXISTS: {key_name}")

    # Generate a random 256-bit AES key
    raw_key = os.urandom(32)
    encrypted_b64 = _encrypt_with_dek(dek, raw_key)

    now = time.time()
    conn.execute(
        """INSERT INTO transit_keys
           (key_name, owner_email, key_usage, signing_algorithm,
            encrypted_key_material_b64, public_key_b64, key_version, is_active, created_at)
           VALUES (?, ?, 'ENCRYPT_DECRYPT', NULL, ?, NULL, 1, 1, ?)""",
        (key_name, caller_email, encrypted_b64, now),
    )
    conn.commit()

    from src.storage.audit import log_action
    log_action(
        action="CREATE_KEY",
        actor_email=caller_email,
        resource=key_name,
        detail={"key_usage": "ENCRYPT_DECRYPT", "version": 1}
    )

    return {
        "key_name": key_name,
        "key_usage": "ENCRYPT_DECRYPT",
        "created_at": now,
    }


def list_keys(token: str) -> list[dict]:
    """
    List all active named keys owned by the token holder.

    Returns ONLY metadata — never the raw key material.

    Returns:
        [{"key_name": str, "key_usage": str, "key_version": int, "created_at": float}, ...]
    """
    caller_email = verify_token(token)
    get_dek()  # Ensure vault is unlocked

    conn = get_db()
    rows = conn.execute(
        """SELECT key_name, key_usage, key_version, signing_algorithm, created_at
           FROM transit_keys
           WHERE owner_email = ? AND is_active = 1
           ORDER BY created_at""",
        (caller_email,),
    ).fetchall()

    return [
        {
            "key_name": r["key_name"],
            "key_usage": r["key_usage"],
            "key_version": r["key_version"],
            "signing_algorithm": r["signing_algorithm"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def revoke_key(key_name: str, token: str) -> dict:
    """
    Permanently revoke (soft-delete) a named key.

    Returns:
        {"revoked": True, "key_name": str}

    Raises:
        Unauthenticated, VaultLocked, PermissionDenied, KeyNotFound.
    """
    caller_email = verify_token(token)
    get_dek()  # Ensure vault is unlocked

    _check_key_ownership(key_name, caller_email)

    conn = get_db()
    conn.execute(
        """UPDATE transit_keys SET is_active = 0
           WHERE key_name = ? AND owner_email = ?""",
        (key_name, caller_email),
    )
    conn.commit()

    return {"revoked": True, "key_name": key_name}
