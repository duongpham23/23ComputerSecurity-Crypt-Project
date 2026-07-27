"""
src.core.vault — Feature 0.1: Vault DEK lifecycle & locking.

Security model:
  - A random 256-bit Data Encryption Key (DEK) is generated once on first init.
  - The DEK is wrapped with a key derived from the Master Passphrase via Argon2id.
  - Only the *wrapped* DEK is persisted to disk — the plaintext DEK never touches disk.
  - On every process start, the vault is LOCKED (DEK is not in memory).
  - The correct Master Passphrase must be supplied to unlock (unwrap the DEK).
  - A wrong passphrase causes an AES-GCM tag mismatch — no detail is disclosed.
"""

import base64
import json
import os
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class VaultLocked(Exception):
    """Raised when any operation is attempted while the vault is locked."""

    pass


# ---------------------------------------------------------------------------
# Argon2id KDF parameters (OWASP recommended minimums)
# ---------------------------------------------------------------------------
_ARGON2_TIME_COST = 3  # iterations
_ARGON2_MEMORY_COST = 65536  # 64 MiB
_ARGON2_PARALLELISM = 2
_ARGON2_HASH_LEN = 32  # output length matches AES-256 key size
_ARGON2_SALT_LEN = 16  # 128-bit random salt

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def _meta_path() -> Path:
    """Return path to the vault metadata file (read from env for testability)."""
    data_dir = Path(os.getenv("VAULT_DATA_DIR", "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "vault_meta.json"


# ---------------------------------------------------------------------------
# In-memory vault state — LOCKED by default on every import/restart
# ---------------------------------------------------------------------------
_dek: bytes | None = None
_unlocked: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _derive_wrapping_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit wrapping key from *passphrase* + *salt* using Argon2id.

    The wrapping key is used to AES-GCM-encrypt the DEK and is NEVER stored.
    """
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_ARGON2_HASH_LEN,
        type=Type.ID,
    )


def _wrap_dek(wrapping_key: bytes, dek: bytes) -> tuple[str, str]:
    """
    Encrypt *dek* with AES-256-GCM using *wrapping_key*.

    Returns (nonce_b64, ciphertext_b64) where ciphertext includes the 16-byte GCM tag.
    The tag mismatch on decrypt is what signals a wrong passphrase — no other hint.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrapping_key)
    ct_with_tag = aesgcm.encrypt(nonce, dek, None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct_with_tag).decode()


def _unwrap_dek(wrapping_key: bytes, nonce_b64: str, ct_b64: str) -> bytes:
    """
    Decrypt the wrapped DEK.

    Raises VaultLocked (with generic message) if the GCM tag does not verify —
    this is the only signal that the passphrase was wrong.
    """
    nonce = base64.b64decode(nonce_b64)
    ct_with_tag = base64.b64decode(ct_b64)
    aesgcm = AESGCM(wrapping_key)
    try:
        return aesgcm.decrypt(nonce, ct_with_tag, None)
    except Exception:
        # Generic error: do not disclose whether passphrase was wrong or file is corrupt
        raise VaultLocked("INVALID_PASSPHRASE")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_dek() -> bytes:
    """Return the active DEK or raise VaultLocked if the vault is sealed."""
    if not _unlocked or _dek is None:
        raise VaultLocked("VAULT_LOCKED")
    return _dek


def is_unlocked() -> bool:
    """True if the DEK is currently loaded in memory."""
    return _unlocked


def is_initialized() -> bool:
    """True if vault_meta.json exists (vault has been initialised at least once)."""
    return _meta_path().exists()


def init_vault(passphrase: str) -> None:
    """
    First-run initialisation.

    1. Generate a random Argon2id salt and a random 256-bit DEK.
    2. Derive a wrapping key from *passphrase* + salt.
    3. Wrap the DEK with AES-256-GCM.
    4. Persist {kdf, kdf_salt_b64, nonce_b64, encrypted_dek_b64, status} to disk.
    5. Load the plaintext DEK into memory (vault transitions to unlocked).

    The plaintext DEK is NEVER written to disk.
    """
    global _dek, _unlocked

    salt = os.urandom(_ARGON2_SALT_LEN)
    dek = os.urandom(32)  # 256-bit DEK

    wrapping_key = _derive_wrapping_key(passphrase, salt)
    nonce_b64, encrypted_dek_b64 = _wrap_dek(wrapping_key, dek)

    meta = {
        "kdf": "argon2id",
        "kdf_salt_b64": base64.b64encode(salt).decode(),
        "nonce_b64": nonce_b64,
        "encrypted_dek_b64": encrypted_dek_b64,
        "status": "locked",  # on-disk status is always "locked" (in-memory state differs)
    }
    _meta_path().write_text(json.dumps(meta, indent=2))

    # Load DEK into memory — vault is now unlocked for this session
    _dek = dek
    _unlocked = True


def unlock_vault(passphrase: str) -> None:
    """
    Re-derive the wrapping key from *passphrase*, decrypt the stored DEK,
    and load it into memory.

    Raises VaultLocked with a generic message if:
      - vault_meta.json does not exist (vault was never initialised).
      - The GCM tag does not verify (wrong passphrase or tampered file).
    """
    global _dek, _unlocked

    meta_file = _meta_path()
    if not meta_file.exists():
        raise VaultLocked("VAULT_NOT_INITIALIZED")

    meta = json.loads(meta_file.read_text())

    salt = base64.b64decode(meta["kdf_salt_b64"])
    wrapping_key = _derive_wrapping_key(passphrase, salt)

    # _unwrap_dek raises VaultLocked on tag mismatch — passphrase wrong
    dek = _unwrap_dek(wrapping_key, meta["nonce_b64"], meta["encrypted_dek_b64"])

    _dek = dek
    _unlocked = True


def lock_vault() -> None:
    """Clear the DEK from memory, transitioning the vault to locked state."""
    global _dek, _unlocked
    _dek = None
    _unlocked = False
