"""tests/test_kv.py — Feature 1: KV Engine tests."""

import pytest

from src.core.vault import VaultLocked
from src.kv.engine import (
    NotFound,
    PermissionDenied,
    TagMismatch,
    delete,
    read,
    write,
)


class TestKVWriteRead:
    def test_write_read_roundtrip(self, unlocked_vault, alice_token):
        """1.1 — write then read must return the exact original data."""
        data = {"password": "s3cr3t", "host": "db.prod"}
        write("secret/alice@example.com/db", data, alice_token)
        result = read("secret/alice@example.com/db", alice_token)
        assert result == data

    def test_read_not_found(self, unlocked_vault, alice_token):
        """1.1 — reading a nonexistent path raises NotFound."""
        with pytest.raises(NotFound):
            read("secret/alice@example.com/missing", alice_token)

    def test_write_overwrites_existing(self, unlocked_vault, alice_token):
        """1.1 — overwrite is allowed; read returns the latest value."""
        write("secret/alice@example.com/key", {"v": 1}, alice_token)
        write("secret/alice@example.com/key", {"v": 2}, alice_token)
        assert read("secret/alice@example.com/key", alice_token) == {"v": 2}

    def test_delete_removes_secret(self, unlocked_vault, alice_token):
        """1.1 — delete then read raises NotFound."""
        write("secret/alice@example.com/tmp", {"x": 1}, alice_token)
        delete("secret/alice@example.com/tmp", alice_token)
        with pytest.raises(NotFound):
            read("secret/alice@example.com/tmp", alice_token)

    def test_tampered_ciphertext_raises_tag_mismatch(self, unlocked_vault, alice_token, db_conn):
        """1.1 — altering 1 byte in the ciphertext on disk must raise TagMismatch."""
        write("secret/alice@example.com/tamper", {"secret": "value"}, alice_token)
        # Flip a byte in the stored ciphertext_b64
        row = db_conn.execute(
            "SELECT ciphertext_b64 FROM kv_secrets WHERE path = ?",
            ("secret/alice@example.com/tamper",),
        ).fetchone()
        import base64

        ct = bytearray(base64.b64decode(row["ciphertext_b64"]))
        ct[0] ^= 0xFF  # flip first byte
        db_conn.execute(
            "UPDATE kv_secrets SET ciphertext_b64 = ? WHERE path = ?",
            (base64.b64encode(bytes(ct)).decode(), "secret/alice@example.com/tamper"),
        )
        db_conn.commit()
        with pytest.raises(TagMismatch):
            read("secret/alice@example.com/tamper", alice_token)

    def test_no_plaintext_in_db(self, unlocked_vault, alice_token, db_conn):
        """1.1 — ciphertext column must not contain the plaintext string."""
        write("secret/alice@example.com/plain", {"api_key": "TOP_SECRET"}, alice_token)
        row = db_conn.execute(
            "SELECT ciphertext_b64 FROM kv_secrets WHERE path = ?",
            ("secret/alice@example.com/plain",),
        ).fetchone()
        assert "TOP_SECRET" not in row["ciphertext_b64"]


class TestKVAccessControl:
    def test_cross_user_read_denied(self, unlocked_vault, alice_token, bob_token):
        """1.2 — Bob cannot read Alice's secret."""
        write("secret/alice@example.com/private", {"x": 1}, alice_token)
        with pytest.raises(PermissionDenied):
            read("secret/alice@example.com/private", bob_token)

    def test_cross_user_write_denied(self, unlocked_vault, alice_token, bob_token):
        """1.2 — Bob cannot write to Alice's namespace."""
        with pytest.raises(PermissionDenied):
            write("secret/alice@example.com/injected", {"x": 1}, bob_token)

    def test_cross_user_delete_denied(self, unlocked_vault, alice_token, bob_token):
        """1.2 — Bob cannot delete Alice's secret."""
        write("secret/alice@example.com/deleteme", {"x": 1}, alice_token)
        with pytest.raises(PermissionDenied):
            delete("secret/alice@example.com/deleteme", bob_token)

    def test_invalid_token_rejected(self, unlocked_vault):
        """1.2 — A completely invalid token must be rejected before path check."""
        from src.auth.session import Unauthenticated

        with pytest.raises(Unauthenticated):
            read("secret/alice@example.com/x", "bad-token")


class TestKVVaultLocked:
    def test_write_while_locked_raises(self, db_conn):
        """1.1 — write must raise VaultLocked when the vault is not unlocked."""
        from src.auth.session import login, register

        register("alice@example.com", "Passphrase123!")
        token = login("alice@example.com", "Passphrase123!")["token"]
        with pytest.raises(VaultLocked):
            write("secret/alice@example.com/x", {}, token)

    def test_read_while_locked_raises(self, db_conn):
        """1.1 — read must raise VaultLocked when the vault is not unlocked."""
        from src.auth.session import login, register

        try:
            register("alice@example.com", "Passphrase123!")
        except Exception:
            pass
        token = login("alice@example.com", "Passphrase123!")["token"]
        with pytest.raises(VaultLocked):
            read("secret/alice@example.com/x", token)
