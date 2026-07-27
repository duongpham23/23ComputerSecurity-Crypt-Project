"""
kv.versioning — Feature 4.1: Extra Credit.

Allows retrieving past versions of an overwritten secret.
The write() function in kv/engine.py already pushes old versions to the
kv_versions table automatically.
"""

import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.auth.session import verify_token
from src.core.vault import get_dek
from src.kv.engine import NotFound, TagMismatch, _check_ownership
from src.storage.db import get_db


def read_version(path: str, version: int, token: str) -> dict:
    """
    Read a specific historical version of a KV secret.

    Args:
        path:    Storage path.
        version: The exact version number to retrieve.
        token:   Session token.

    Returns:
        The original JSON dict for that version.

    Raises:
        Unauthenticated, VaultLocked, PermissionDenied, NotFound, TagMismatch.
    """
    caller_email = verify_token(token)
    dek = get_dek()

    # Reuse ownership logic (will check acl_grants later in Task 4.3)
    _check_ownership(path, caller_email)

    conn = get_db()

    # Check if the requested version is currently the active one in kv_secrets
    active_row = conn.execute(
        "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM kv_secrets WHERE path = ? AND version = ?",
        (path, version)
    ).fetchone()

    if active_row:
        row = active_row
    else:
        # Check historical versions
        row = conn.execute(
            "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM kv_versions WHERE path = ? AND version = ?",
            (path, version)
        ).fetchone()

    if not row:
        raise NotFound(f"NOT_FOUND: version {version} of {path} does not exist")

    # Decrypt
    try:
        nonce = base64.b64decode(row["nonce_b64"])
        ct = base64.b64decode(row["ciphertext_b64"])
        tag = base64.b64decode(row["tag_b64"])
    except Exception as exc:
        raise ValueError("MALFORMED_DATA") from exc

    aesgcm = AESGCM(dek)
    try:
        # AEAD decryption: requires nonce, ciphertext + tag concatenated
        plaintext = aesgcm.decrypt(nonce, ct + tag, None)
    except Exception as exc:
        raise TagMismatch("TAG_MISMATCH") from exc

    return json.loads(plaintext.decode("utf-8"))
