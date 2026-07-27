"""
transit.signing — Feature 2.4: Sign & Verify as a Service.

Supports ED25519 and RSASSA_PKCS1_V1_5_SHA_256.
The private signing key is NEVER returned through any API.

Modeled after AWS KMS Sign / Verify APIs:
  - message_type: RAW (system hashes with SHA-256) or DIGEST (client pre-hashed).
  - verify() returns {key_name, signature_valid, signing_algorithm}, never raises
    on bad signatures.
"""

import base64
import hashlib
import time
from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.auth.session import verify_token
from src.core.vault import get_dek
from src.storage.db import get_db
from src.transit.keys import (
    InvalidKeyUsage,
    KeyAlreadyExists,
    _check_key_ownership,
    _decrypt_with_dek,
    _encrypt_with_dek,
)

MessageType = Literal["RAW", "DIGEST"]
SigningAlgorithm = Literal["ED25519", "RSASSA_PKCS1_V1_5_SHA_256"]

_SHA256_DIGEST_LEN = 32  # expected length for a pre-computed SHA-256 digest


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_key_pair(algorithm: SigningAlgorithm) -> tuple[bytes, bytes]:
    """
    Generate an asymmetric key pair for the given algorithm.

    Returns:
        (private_key_bytes, public_key_bytes) in DER format.
    """
    if algorithm == "ED25519":
        private_key = Ed25519PrivateKey.generate()
        priv_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    elif algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        priv_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        raise ValueError(f"Unsupported signing algorithm: {algorithm}")

    return priv_bytes, pub_bytes


def _prepare_digest(message_b64: str, message_type: MessageType) -> bytes:
    """
    Prepare the digest from the message.

    RAW:    SHA-256 hash of the decoded message.
    DIGEST: Use as-is after validating length.
    """
    message = base64.b64decode(message_b64)

    if message_type == "RAW":
        return hashlib.sha256(message).digest()
    elif message_type == "DIGEST":
        if len(message) != _SHA256_DIGEST_LEN:
            raise ValueError(
                f"DIGEST_LENGTH_MISMATCH: expected {_SHA256_DIGEST_LEN} bytes "
                f"for SHA-256 digest, got {len(message)}"
            )
        return message
    else:
        raise ValueError(f"Invalid message_type: {message_type}")


def _sign_with_key(priv_key_bytes: bytes, algorithm: SigningAlgorithm, digest: bytes) -> bytes:
    """Produce a signature using the private key material."""
    if algorithm == "ED25519":
        # Ed25519 signs the full message, but since we always compute the digest
        # ourselves, we sign the digest bytes directly.
        private_key = Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
        return private_key.sign(digest)
    elif algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        private_key = serialization.load_der_private_key(priv_key_bytes, password=None)
        return private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def _verify_with_key(
    pub_key_bytes: bytes,
    algorithm: SigningAlgorithm,
    digest: bytes,
    signature: bytes,
) -> bool:
    """
    Verify a signature. Returns True if valid, False otherwise.
    Never raises on bad signatures.
    """
    try:
        if algorithm == "ED25519":
            public_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            public_key.verify(signature, digest)
            return True
        elif algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
            public_key = serialization.load_der_public_key(pub_key_bytes)
            public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
            return True
        else:
            return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_signing_key(
    key_name: str,
    signing_algorithm: SigningAlgorithm,
    token: str,
) -> dict:
    """
    Generate and store an asymmetric signing key pair (key_usage=SIGN_VERIFY).

    Private key is encrypted with the DEK. Public key is stored plaintext
    for server-side verification only — it is NOT exposed to unauthorised callers.

    Args:
        key_name:          Unique name (scoped to token owner).
        signing_algorithm: ``"ED25519"`` or ``"RSASSA_PKCS1_V1_5_SHA_256"``.
        token:             Session token.

    Returns:
        {"key_name": str, "key_usage": "SIGN_VERIFY", "signing_algorithm": str, "created_at": float}

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

    priv_bytes, pub_bytes = _generate_key_pair(signing_algorithm)

    # Encrypt private key with DEK
    encrypted_priv_b64 = _encrypt_with_dek(dek, priv_bytes)
    pub_b64 = base64.b64encode(pub_bytes).decode()

    now = time.time()
    conn.execute(
        """INSERT INTO transit_keys
           (key_name, owner_email, key_usage, signing_algorithm,
            encrypted_key_material_b64, public_key_b64, key_version, is_active, created_at)
           VALUES (?, ?, 'SIGN_VERIFY', ?, ?, ?, 1, 1, ?)""",
        (key_name, caller_email, signing_algorithm, encrypted_priv_b64, pub_b64, now),
    )
    conn.commit()

    return {
        "key_name": key_name,
        "key_usage": "SIGN_VERIFY",
        "signing_algorithm": signing_algorithm,
        "created_at": now,
    }


def sign(
    key_name: str,
    message_b64: str,
    message_type: MessageType,
    token: str,
) -> dict:
    """
    Sign a message using the named signing key.

    Args:
        key_name:     Name of the SIGN_VERIFY key.
        message_b64:  Base64-encoded message bytes.
        message_type: ``"RAW"`` (hash first) or ``"DIGEST"`` (pre-hashed).
        token:        Session token (must be the key owner).

    Returns:
        {"signature_b64": str, "key_name": str, "signing_algorithm": str}

    Raises:
        Unauthenticated, VaultLocked, KeyNotFound, InvalidKeyUsage,
        PermissionDenied, ValueError (bad DIGEST length).
    """
    caller_email = verify_token(token)
    dek = get_dek()

    key_row = _check_key_ownership(key_name, caller_email)

    if key_row["key_usage"] != "SIGN_VERIFY":
        raise InvalidKeyUsage(
            f"INVALID_KEY_USAGE: key '{key_name}' has usage "
            f"'{key_row['key_usage']}', expected 'SIGN_VERIFY'"
        )

    algorithm = key_row["signing_algorithm"]
    digest = _prepare_digest(message_b64, message_type)

    # Temporarily decrypt the private key
    priv_bytes = _decrypt_with_dek(dek, key_row["encrypted_key_material_b64"])
    signature = _sign_with_key(priv_bytes, algorithm, digest)

    return {
        "signature_b64": base64.b64encode(signature).decode(),
        "key_name": key_name,
        "signing_algorithm": algorithm,
    }


def verify(
    key_name: str,
    message_b64: str,
    message_type: MessageType,
    signature_b64: str,
    token: str,
) -> dict:
    """
    Verify a signature against the named signing key.

    Never raises on bad signature — always returns a structured result.

    Args:
        key_name:      Name of the SIGN_VERIFY key.
        message_b64:   Base64-encoded message bytes.
        message_type:  ``"RAW"`` or ``"DIGEST"``.
        signature_b64: Base64-encoded signature to verify.
        token:         Session token (must be the key owner).

    Returns:
        {"key_name": str, "signature_valid": bool, "signing_algorithm": str}

    Raises:
        Unauthenticated, VaultLocked, KeyNotFound, InvalidKeyUsage, PermissionDenied.
        (Bad/malformed signature → signature_valid: false, not an exception.)
    """
    caller_email = verify_token(token)
    get_dek()  # Ensure vault is unlocked

    key_row = _check_key_ownership(key_name, caller_email)

    if key_row["key_usage"] != "SIGN_VERIFY":
        raise InvalidKeyUsage(
            f"INVALID_KEY_USAGE: key '{key_name}' has usage "
            f"'{key_row['key_usage']}', expected 'SIGN_VERIFY'"
        )

    algorithm = key_row["signing_algorithm"]

    # Decode the signature (bad base64 → signature_valid: false)
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return {
            "key_name": key_name,
            "signature_valid": False,
            "signing_algorithm": algorithm,
        }

    # Prepare the digest
    try:
        digest = _prepare_digest(message_b64, message_type)
    except ValueError:
        return {
            "key_name": key_name,
            "signature_valid": False,
            "signing_algorithm": algorithm,
        }

    # Load the public key and verify
    pub_bytes = base64.b64decode(key_row["public_key_b64"])
    is_valid = _verify_with_key(pub_bytes, algorithm, digest, signature)

    return {
        "key_name": key_name,
        "signature_valid": is_valid,
        "signing_algorithm": algorithm,
    }
