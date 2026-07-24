"""
conftest.py — shared pytest fixtures for all test modules.

Since core/ and auth/ are implemented by the teammate, this file injects
lightweight mock modules into sys.modules so Feature 1 & 2 tests run
independently, without needing Feature 0 to be complete.

Fixtures provide:
  - Mock vault module with controllable DEK state.
  - Mock session module with deterministic token→email resolution.
  - A fresh isolated SQLite DB per test (tmp_path).
  - Two test users (alice, bob) with pre-inserted DB rows + valid stub tokens.
"""

import os
import sys
import time
import types
import pytest


# ---------------------------------------------------------------------------
# Inject mock MiniVault.core.vault before any test imports kv/transit code.
# Replace this block with the real module once Feature 0 is done.
# ---------------------------------------------------------------------------
_vault_mod = types.ModuleType("src.core.vault")
_vault_mod._dek: bytes | None = None
_vault_mod._unlocked: bool = False


class _VaultLocked(Exception):
    """Raised when any operation is attempted while the vault is locked."""
    pass


def _get_dek() -> bytes:
    if not _vault_mod._unlocked or _vault_mod._dek is None:
        raise _VaultLocked("VAULT_LOCKED")
    return _vault_mod._dek


_vault_mod.VaultLocked = _VaultLocked
_vault_mod.get_dek = _get_dek
_vault_mod.is_unlocked = lambda: _vault_mod._unlocked

# Also expose under the core package namespace
_core_mod = types.ModuleType("src.core")
_core_mod.vault = _vault_mod

sys.modules.setdefault("src.core", _core_mod)
sys.modules.setdefault("src.core.vault", _vault_mod)

# ---------------------------------------------------------------------------
# Inject mock MiniVault.auth.session
# Tokens are simple strings: "stub-token-<email>" → email extracted by split.
# Replace this block with the real module once Feature 0 is done.
# ---------------------------------------------------------------------------
_session_mod = types.ModuleType("src.auth.session")


class _Unauthenticated(Exception):
    """Raised when a token is missing, malformed, or expired."""
    pass


def _verify_token(token: str) -> str:
    """
    Stub: expects tokens of the form 'stub-token-<email>'.
    Anything else raises Unauthenticated.
    """
    prefix = "stub-token-"
    if not token or not token.startswith(prefix):
        raise _Unauthenticated("UNAUTHENTICATED")
    return token[len(prefix):]


_session_mod.Unauthenticated = _Unauthenticated
_session_mod.verify_token = _verify_token
_session_mod.issue_token = lambda email: f"stub-token-{email}"

_auth_mod = types.ModuleType("src.auth")
_auth_mod.session = _session_mod

sys.modules.setdefault("src.auth", _auth_mod)
sys.modules.setdefault("src.auth.session", _session_mod)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_vault():
    """Reset mock vault state before/after every test for isolation."""
    _vault_mod._dek = None
    _vault_mod._unlocked = False
    yield
    _vault_mod._dek = None
    _vault_mod._unlocked = False


@pytest.fixture()
def unlocked_vault():
    """
    Unlock the mock vault with a random DEK.
    Tests that require a locked vault should NOT request this fixture.
    """
    _vault_mod._dek = os.urandom(32)
    _vault_mod._unlocked = True
    return _vault_mod._dek


@pytest.fixture()
def db_conn(tmp_path, monkeypatch):
    """Isolated SQLite connection for each test (uses a temp directory)."""
    import src.storage.db as db

    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    db._local.__dict__.clear()  # drop any cached thread-local connection
    db.init_db()
    conn = db.get_db()
    yield conn
    conn.close()
    db._local.__dict__.clear()


@pytest.fixture()
def alice_token(unlocked_vault, db_conn):
    """
    Session token for alice@example.com.
    User row inserted directly so no auth module is needed.
    """
    db_conn.execute(
        "INSERT OR IGNORE INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
        ("alice@example.com", "hashed", time.time()),
    )
    db_conn.commit()
    return "stub-token-alice@example.com"


@pytest.fixture()
def bob_token(unlocked_vault, db_conn):
    """Session token for bob@example.com."""
    db_conn.execute(
        "INSERT OR IGNORE INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
        ("bob@example.com", "hashed", time.time()),
    )
    db_conn.commit()
    return "stub-token-bob@example.com"
