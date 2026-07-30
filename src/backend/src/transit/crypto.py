"""
transit.crypto — Feature 2.2 & 2.3: Encryption/Decryption as a Service + Access Control.

Ciphertext format: ``vault:<key_name>:v<version>:<base64(nonce || ciphertext || tag)>``

The AES key used is NEVER returned to the client at any point.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.auth.session import verify_token
from src.core.vault import get_dek
from src.transit.keys import (
    InvalidKeyUsage,
    _check_key_ownership,
    _decrypt_with_dek,
)


def encrypt(key_name: str, plaintext_b64: str, token: str) -> str:
    """
    Encrypt base64-encoded plaintext using the named AES-256 key.

    Args:
        key_name:      Name of the ENCRYPT_DECRYPT key to use.
        plaintext_b64: Base64-encoded plaintext bytes.
        token:         Session token (must be the key owner — section 2.3).

    Returns:
        Ciphertext string of the form ``vault:<key_name>:v<N>:<base64(nonce+ct+tag)>``.

    Raises:
        Unauthenticated, VaultLocked, KeyNotFound, InvalidKeyUsage, PermissionDenied.
    """
    caller_email = verify_token(token)
    dek = get_dek()

    # Ownership + existence check (raises PermissionDenied or KeyNotFound)
    key_row = _check_key_ownership(key_name, caller_email)

    # Reject if key_usage is not ENCRYPT_DECRYPT
    if key_row["key_usage"] != "ENCRYPT_DECRYPT":
        raise InvalidKeyUsage(
            f"INVALID_KEY_USAGE: key '{key_name}' has usage "
            f"'{key_row['key_usage']}', expected 'ENCRYPT_DECRYPT'"
        )

    # Decrypt the stored AES key using the DEK (temporary, in-memory only)
    raw_aes_key = _decrypt_with_dek(dek, key_row["encrypted_key_material_b64"])

    # Encrypt the plaintext with the named key
    plaintext = base64.b64decode(plaintext_b64)
    nonce = os.urandom(12)
    aesgcm = AESGCM(raw_aes_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Pack nonce || ct_with_tag into a single blob
    blob = nonce + ct_with_tag
    blob_b64 = base64.b64encode(blob).decode()

    version = key_row["key_version"]
    return f"vault:{key_name}:v{version}:{blob_b64}"


def decrypt(ciphertext: str, token: str) -> str:
    """
    Decrypt a vault ciphertext string and return the original base64 plaintext.

    Parses the key_name from the ciphertext, checks ownership, decrypts.

    Args:
        ciphertext: The ``vault:<key_name>:v<N>:<blob>`` string from encrypt().
        token:      Session token (must be the key owner).

    Returns:
        Base64-encoded original plaintext.

    Raises:
        Unauthenticated, VaultLocked, KeyNotFound, InvalidKeyUsage,
        PermissionDenied, ValueError (malformed ciphertext or tag mismatch).
    """
    caller_email = verify_token(token)
    dek = get_dek()

    # Parse the ciphertext format
    parts = ciphertext.split(":")
    if len(parts) != 4 or parts[0] != "vault":
        raise ValueError("MALFORMED_CIPHERTEXT: invalid format")

    _, key_name, version_str, blob_b64 = parts

    if not version_str.startswith("v"):
        raise ValueError("MALFORMED_CIPHERTEXT: invalid version string")

    try:
        key_version = int(version_str[1:])
    except ValueError:
        raise ValueError("MALFORMED_CIPHERTEXT: invalid version number")

    # Pass the key_version from the ciphertext so old ciphertexts can be decrypted
    key_row = _check_key_ownership(key_name, caller_email, version=key_version)

    if key_row["key_usage"] != "ENCRYPT_DECRYPT":
        raise InvalidKeyUsage(
            f"INVALID_KEY_USAGE: key '{key_name}' has usage "
            f"'{key_row['key_usage']}', expected 'ENCRYPT_DECRYPT'"
        )

    # Decrypt the stored AES key
    raw_aes_key = _decrypt_with_dek(dek, key_row["encrypted_key_material_b64"])

    # Decrypt the payload
    try:
        blob = base64.b64decode(blob_b64)
    except Exception as exc:
        raise ValueError("MALFORMED_CIPHERTEXT: invalid base64 blob") from exc

    if len(blob) < 12 + 16:
        raise ValueError("MALFORMED_CIPHERTEXT: blob too short")

    nonce = blob[:12]
    ct_with_tag = blob[12:]

    aesgcm = AESGCM(raw_aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
    except Exception as exc:
        raise ValueError(
            "TAG_MISMATCH: GCM authentication failed — ciphertext may have been tampered with"
        ) from exc

    return base64.b64encode(plaintext).decode()
