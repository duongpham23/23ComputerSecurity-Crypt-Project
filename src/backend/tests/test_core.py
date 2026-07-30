"""tests/test_core.py — Feature 0.1: Vault init & unlock tests."""

import base64
import json

import pytest

import src.core.vault as vault_mod

# ---------------------------------------------------------------------------
# Helper: reset vault state between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_vault_state(tmp_path, monkeypatch):
    """
    Isolate each test: point VAULT_DATA_DIR at a temp dir and reset
    the module-level vault state (DEK + unlocked flag) before and after.
    """
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    # Reset in-memory state
    vault_mod._dek = None
    vault_mod._unlocked = False
    yield
    vault_mod._dek = None
    vault_mod._unlocked = False


# ---------------------------------------------------------------------------
# is_initialized
# ---------------------------------------------------------------------------


class TestVaultInit:
    def test_vault_starts_locked(self):
        """0.1 — vault is locked on import (no DEK in memory)."""
        assert not vault_mod.is_unlocked()

    def test_vault_starts_uninitialized(self):
        """0.1 — vault reports un-initialized before first init."""
        assert not vault_mod.is_initialized()

    def test_init_creates_meta_file(self, tmp_path):
        """0.1 — init_vault writes vault_meta.json to data dir."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        meta_file = tmp_path / "vault_meta.json"
        assert meta_file.exists()

    def test_meta_file_contains_expected_fields(self, tmp_path):
        """0.1 — vault_meta.json has kdf, kdf_salt_b64, nonce_b64, encrypted_dek_b64."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        meta = json.loads((tmp_path / "vault_meta.json").read_text())
        assert meta["kdf"] == "argon2id"
        assert "kdf_salt_b64" in meta
        assert "nonce_b64" in meta
        assert "encrypted_dek_b64" in meta

    def test_plaintext_dek_not_in_meta_file(self, tmp_path):
        """0.1 — the plaintext DEK must never appear in vault_meta.json."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        dek = vault_mod.get_dek()  # in-memory DEK (vault unlocked after init)
        raw_file = (tmp_path / "vault_meta.json").read_text()
        # Plaintext DEK encoded in various ways must not appear in the file
        assert base64.b64encode(dek).decode() not in raw_file
        assert dek.hex() not in raw_file

    def test_init_unlocks_vault(self):
        """0.1 — after init_vault, the vault is unlocked (DEK in memory)."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        assert vault_mod.is_unlocked()
        assert vault_mod.get_dek() is not None

    def test_get_dek_while_locked_raises(self):
        """0.1 — get_dek raises VaultLocked when vault is not unlocked."""
        with pytest.raises(vault_mod.VaultLocked):
            vault_mod.get_dek()

    def test_is_initialized_true_after_init(self, tmp_path):
        """0.1 — is_initialized returns True once vault_meta.json exists."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        assert vault_mod.is_initialized()


# ---------------------------------------------------------------------------
# Unlock tests
# ---------------------------------------------------------------------------


class TestVaultUnlock:
    def test_unlock_with_correct_passphrase(self, tmp_path):
        """0.1 — correct passphrase unlocks the vault and loads the same DEK."""
        passphrase = "Str0ngPassphrase!99"
        vault_mod.init_vault(passphrase)
        original_dek = vault_mod.get_dek()

        # Simulate restart: lock the vault (clear in-memory DEK)
        vault_mod.lock_vault()
        assert not vault_mod.is_unlocked()

        # Unlock with the same passphrase
        vault_mod.unlock_vault(passphrase)
        assert vault_mod.is_unlocked()
        assert vault_mod.get_dek() == original_dek  # same DEK recovered

    def test_unlock_wrong_passphrase_raises(self, tmp_path):
        """0.1 — wrong passphrase causes GCM tag mismatch → VaultLocked (generic error)."""
        vault_mod.init_vault("CorrectPassphrase!1")
        vault_mod.lock_vault()

        with pytest.raises(vault_mod.VaultLocked):
            vault_mod.unlock_vault("WrongPassphrase!1")

    def test_vault_stays_locked_after_wrong_passphrase(self, tmp_path):
        """0.1 — vault remains locked if the wrong passphrase is used."""
        vault_mod.init_vault("CorrectPassphrase!1")
        vault_mod.lock_vault()

        try:
            vault_mod.unlock_vault("WrongPassphrase!1")
        except vault_mod.VaultLocked:
            pass

        assert not vault_mod.is_unlocked()

    def test_unlock_without_init_raises(self):
        """0.1 — unlock without prior init raises VaultLocked."""
        with pytest.raises(vault_mod.VaultLocked):
            vault_mod.unlock_vault("any")

    def test_lock_vault_clears_dek(self, tmp_path):
        """0.1 — lock_vault removes DEK from memory."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        assert vault_mod.is_unlocked()
        vault_mod.lock_vault()
        assert not vault_mod.is_unlocked()
        with pytest.raises(vault_mod.VaultLocked):
            vault_mod.get_dek()

    def test_meta_file_status_field_is_locked(self, tmp_path):
        """0.1 — on-disk status is always 'locked' (state lives in memory only)."""
        vault_mod.init_vault("Str0ngPassphrase!99")
        # Vault is unlocked in memory, but the file must still say 'locked'
        meta = json.loads((tmp_path / "vault_meta.json").read_text())
        assert meta["status"] == "locked"

    def test_salt_is_random_across_inits(self, tmp_path):
        """0.1 — each init generates a fresh random salt."""
        vault_mod.init_vault("SamePassphrase!1")
        meta1 = json.loads((tmp_path / "vault_meta.json").read_text())

        # Re-init (simulating a re-setup)
        vault_mod.lock_vault()
        vault_mod.init_vault("SamePassphrase!1")
        meta2 = json.loads((tmp_path / "vault_meta.json").read_text())

        # Different salt → different encrypted DEK even with same passphrase
        assert meta1["kdf_salt_b64"] != meta2["kdf_salt_b64"]
        assert meta1["encrypted_dek_b64"] != meta2["encrypted_dek_b64"]
