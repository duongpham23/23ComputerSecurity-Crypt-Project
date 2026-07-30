"""
transit.rotation — Feature 4.2: Extra Credit.

Supports generating new versions of existing keys for cryptographic rotation.
Old ciphertexts remain decipherable using their tagged key version, while new
encryptions use the latest key version.
"""

import os
import time

from src.auth.session import verify_token
from src.core.vault import get_dek
from src.storage.db import get_db
from src.transit.keys import _check_key_ownership, _encrypt_with_dek


def rotate_key(key_name: str, token: str) -> dict:
    """
    Generate a new AES-256 key material for an existing ENCRYPT_DECRYPT key.
    Increments the key_version.

    Args:
        key_name: The name of the key to rotate.
        token:    Session token.

    Returns:
        {"key_name": key_name, "key_version": new_version}
    """
    caller_email = verify_token(token)
    dek = get_dek()

    # Verify ownership and get current latest version
    old_key = _check_key_ownership(key_name, caller_email)

    if old_key["key_usage"] != "ENCRYPT_DECRYPT":
        raise ValueError("Only ENCRYPT_DECRYPT keys can be rotated")

    new_version = old_key["key_version"] + 1

    # Generate new key material
    new_material = os.urandom(32)
    enc_material = _encrypt_with_dek(dek, new_material)

    conn = get_db()
    now = time.time()

    conn.execute(
        """INSERT INTO transit_keys
           (key_name, owner_email, key_usage, signing_algorithm,
            encrypted_key_material_b64, public_key_b64, key_version, is_active, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            key_name,
            caller_email,
            old_key["key_usage"],
            old_key["signing_algorithm"],
            enc_material,
            old_key["public_key_b64"],
            new_version,
            1,
            now,
        ),
    )
    conn.commit()

    return {"key_name": key_name, "key_version": new_version}
