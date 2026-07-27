"""
conftest.py — shared pytest fixtures for all test modules.
"""

import pytest

import src.core.vault as vault_mod
from src.auth.session import login, register


@pytest.fixture(autouse=True)
def vault_data_dir(tmp_path, monkeypatch):
    """Point VAULT_DATA_DIR to a temporary directory."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _reset_vault(vault_data_dir):
    """Reset real vault state before/after every test for isolation."""
    vault_mod._dek = None
    vault_mod._unlocked = False
    yield
    vault_mod._dek = None
    vault_mod._unlocked = False


@pytest.fixture()
def db_conn(vault_data_dir):
    """Isolated SQLite connection for each test."""
    import src.storage.db as db

    db._local.__dict__.clear()
    db.init_db()
    conn = db.get_db()
    yield conn
    conn.close()
    db._local.__dict__.clear()


@pytest.fixture()
def unlocked_vault(db_conn):
    """Initialize and unlock the real vault."""
    vault_mod.init_vault("TestPassphrase123!")
    return vault_mod.get_dek()


@pytest.fixture()
def alice_token(unlocked_vault, db_conn):
    """Session token for alice@example.com."""
    register("alice@example.com", "AlicePassphrase123!")
    session = login("alice@example.com", "AlicePassphrase123!")
    return session["token"]


@pytest.fixture()
def bob_token(unlocked_vault, db_conn):
    """Session token for bob@example.com."""
    register("bob@example.com", "BobPassphrase123!")
    session = login("bob@example.com", "BobPassphrase123!")
    return session["token"]
