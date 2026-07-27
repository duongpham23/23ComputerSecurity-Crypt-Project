"""
transit.signing — Feature 2.4: Sign & Verify as a Service.

Supports ED25519 and RSASSA_PKCS1_V1_5_SHA_256.
The private signing key is NEVER returned through any API.

Modeled after AWS KMS Sign / Verify APIs:
  - message_type: RAW or DIGEST.
  - ED25519 does NOT support DIGEST mode (Ed25519 handles hashing internally).
    Passing DIGEST to an ED25519 key raises ValueError with a clear message (Fix 3).
  - RSASSA_PKCS1_V1_5_SHA_256 supports both RAW (SHA-256 applied) and DIGEST (pre-hashed).
  - verify() returns {key_name, signature_valid, signing_algorithm}; bad signatures
    return signature_valid: false rather than raising. DIGEST-mode errors on ED25519
    propagate as 400-style exceptions for consistency with sign() (Q2 answer).
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

_SHA256_DIGEST_LEN = 32  # expected byte length for a pre-computed SHA-256 digest


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_key_pair(algorithm: SigningAlgorithm) -> tuple[bytes, bytes]:
    """
    Generate an asymmetric key pair for the given algorithm.

    Returns:
        (private_key_bytes, public_key_bytes) in DER/Raw format.
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


def _prepare_signing_input(
    message_b64: str,
    message_type: MessageType,
    algorithm: SigningAlgorithm,
) -> bytes:
    """
    Return the bytes to pass into the signing/verification primitive.

    ED25519:
      - RAW:    return the raw decoded message bytes.
                Ed25519 handles its own internal hashing (SHA-512); do NOT pre-hash.
      - DIGEST: raises ValueError — Ed25519 has no pre-hash variant (Fix 3).

    RSASSA_PKCS1_V1_5_SHA_256:
      - RAW:    return SHA-256(decoded message).
      - DIGEST: validate that the decoded bytes are exactly 32 bytes (SHA-256 output),
                then return them as-is.

    Raises:
        ValueError: ED25519 + DIGEST mode, or RSA DIGEST with wrong length.
    """
    message = base64.b64decode(message_b64)

    if algorithm == "ED25519":
        if message_type == "DIGEST":
            raise ValueError(
                "ED25519_NO_PREHASH: ED25519 does not support DIGEST mode. "
                "Use message_type=RAW and let the server hash the message."
            )
        # RAW: pass the full message; Ed25519 handles hashing internally.
        return message

    elif algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        if message_type == "RAW":
            return hashlib.sha256(message).digest()
        elif message_type == "DIGEST":
            if len(message) != _SHA256_DIGEST_LEN:
                raise ValueError(
                    f"DIGEST_LENGTH_MISMATCH: expected {_SHA256_DIGEST_LEN} bytes "
                    f"for SHA-256 digest, got {len(message)}"
                )
            return message

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def _sign_with_key(
    priv_key_bytes: bytes,
    algorithm: SigningAlgorithm,
    signing_input: bytes,
) -> bytes:
    """
    Produce a signature.

    For ED25519, signing_input is the raw message (library does SHA-512 internally).
    For RSA, signing_input is a SHA-256 digest (used with Prehashed).
    """
    if algorithm == "ED25519":
        private_key = Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
        return private_key.sign(signing_input)
    elif algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        private_key = serialization.load_der_private_key(priv_key_bytes, password=None)
        return private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def _verify_with_key(
    pub_key_bytes: bytes,
    algorithm: SigningAlgorithm,
    signing_input: bytes,
    signature: bytes,
) -> bool:
    """
    Verify a signature. Returns True if valid, False otherwise.
    Never raises on bad signatures — all exceptions are caught and return False.
    """
    try:
        if algorithm == "ED25519":
            public_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            public_key.verify(signature, signing_input)
            return True
        elif algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
            public_key = serialization.load_der_public_key(pub_key_bytes)
            public_key.verify(
                signature,
                signing_input,
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
        message_type: ``"RAW"`` (hash first for RSA; raw for ED25519) or
                      ``"DIGEST"`` (RSA only — pre-computed SHA-256 hash).
        token:        Session token (must be the key owner).

    Returns:
        {"signature_b64": str, "key_name": str, "signing_algorithm": str}

    Raises:
        Unauthenticated, VaultLocked, KeyNotFound, InvalidKeyUsage,
        PermissionDenied, ValueError (bad DIGEST length, or ED25519 + DIGEST mode).
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

    # Prepare signing input — raises ValueError for ED25519+DIGEST (Fix 3).
    signing_input = _prepare_signing_input(message_b64, message_type, algorithm)

    # Temporarily decrypt the private key (stays in memory only).
    priv_bytes = _decrypt_with_dek(dek, key_row["encrypted_key_material_b64"])
    signature = _sign_with_key(priv_bytes, algorithm, signing_input)

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

    Bad signatures (wrong key, tampered message) return signature_valid: false.
    Usage errors (ED25519 + DIGEST mode) raise ValueError — consistent with sign()
    so the same request cannot be accepted on one path and rejected on the other (Q2).

    Args:
        key_name:      Name of the SIGN_VERIFY key.
        message_b64:   Base64-encoded message bytes.
        message_type:  ``"RAW"`` or ``"DIGEST"`` (RSA only).
        signature_b64: Base64-encoded signature to verify.
        token:         Session token (must be the key owner).

    Returns:
        {"key_name": str, "signature_valid": bool, "signing_algorithm": str}

    Raises:
        Unauthenticated, VaultLocked, KeyNotFound, InvalidKeyUsage, PermissionDenied,
        ValueError (ED25519 + DIGEST mode, or RSA DIGEST wrong length).
        (Bad/malformed signature bytes themselves → signature_valid: false, not an exception.)
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

    # Decode the signature bytes (malformed base64 → signature_valid: false).
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return {
            "key_name": key_name,
            "signature_valid": False,
            "signing_algorithm": algorithm,
        }

    # Prepare signing input.
    # ValueError (e.g. ED25519 + DIGEST mode) propagates as a 400 error,
    # consistent with sign() behaviour (Q2 answer — apply to both paths).
    signing_input = _prepare_signing_input(message_b64, message_type, algorithm)

    # Load the public key and verify (bad signature → False, never raises).
    pub_bytes = base64.b64decode(key_row["public_key_b64"])
    is_valid = _verify_with_key(pub_bytes, algorithm, signing_input, signature)

    return {
        "key_name": key_name,
        "signature_valid": is_valid,
        "signing_algorithm": algorithm,
    }
