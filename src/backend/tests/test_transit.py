"""tests/test_transit.py — Feature 2: Transit Engine tests."""

import base64

import pytest

from src.auth.session import Unauthenticated
from src.core.vault import VaultLocked
from src.transit.keys import InvalidKeyUsage, KeyAlreadyExists, KeyNotFound, create_key, revoke_key
from src.transit.crypto import decrypt, encrypt
from src.transit.signing import (
    MessageType,
    SigningAlgorithm,
    create_signing_key,
    sign,
    verify,
)


# ---------------------------------------------------------------------------
# 2.1 — Named Key Management
# ---------------------------------------------------------------------------
class TestTransitKeyManagement:
    def test_create_key_returns_metadata_only(self, unlocked_vault, alice_token):
        """2.1 — create_key must not return the raw AES key."""
        result = create_key("my-key", alice_token)
        assert result["key_name"] == "my-key"
        assert result["key_usage"] == "ENCRYPT_DECRYPT"
        assert "key_material" not in result
        assert "encrypted_key" not in result

    def test_create_duplicate_key_rejected(self, unlocked_vault, alice_token):
        """2.1 — creating a key_name that already exists must be rejected."""
        create_key("dup-key", alice_token)
        with pytest.raises(KeyAlreadyExists):
            create_key("dup-key", alice_token)

    def test_revoke_key_then_encrypt_fails(self, unlocked_vault, alice_token):
        """2.1 — encrypting with a revoked key must raise KeyNotFound."""
        create_key("revoke-me", alice_token)
        revoke_key("revoke-me", alice_token)
        with pytest.raises(KeyNotFound):
            encrypt("revoke-me", base64.b64encode(b"hello").decode(), alice_token)


# ---------------------------------------------------------------------------
# 2.2 + 2.3 — Encrypt / Decrypt + Access Control
# ---------------------------------------------------------------------------
class TestTransitEncryptDecrypt:
    def test_encrypt_decrypt_text_roundtrip(self, unlocked_vault, alice_token):
        """2.2 — encrypt→decrypt must return the exact original plaintext (text)."""
        create_key("text-key", alice_token)
        pt = base64.b64encode(b"hello world").decode()
        ct = encrypt("text-key", pt, alice_token)
        assert decrypt(ct, alice_token) == pt

    def test_encrypt_decrypt_json_roundtrip(self, unlocked_vault, alice_token):
        """2.2 — round-trip with JSON payload."""
        import json

        create_key("json-key", alice_token)
        payload = json.dumps({"api_key": "xyz", "host": "db.prod"}).encode()
        pt = base64.b64encode(payload).decode()
        ct = encrypt("json-key", pt, alice_token)
        assert decrypt(ct, alice_token) == pt

    def test_encrypt_decrypt_binary_roundtrip(self, unlocked_vault, alice_token):
        """2.2 — round-trip with binary payload."""
        import os

        create_key("bin-key", alice_token)
        raw = os.urandom(64)
        pt = base64.b64encode(raw).decode()
        ct = encrypt("bin-key", pt, alice_token)
        assert decrypt(ct, alice_token) == pt

    def test_tampered_ciphertext_decrypt_fails(self, unlocked_vault, alice_token):
        """2.2 — flipping any byte in the ciphertext must make decrypt fail."""
        create_key("tamper-key", alice_token)
        pt = base64.b64encode(b"sensitive").decode()
        ct = encrypt("tamper-key", pt, alice_token)
        # ct format: vault:<key_name>:v<N>:<b64blob>
        parts = ct.split(":")
        blob = bytearray(base64.b64decode(parts[-1]))
        blob[0] ^= 0xFF
        parts[-1] = base64.b64encode(bytes(blob)).decode()
        tampered = ":".join(parts)
        with pytest.raises(Exception):  # ValueError or TagMismatch
            decrypt(tampered, alice_token)

    def test_malformed_ciphertext_rejected(self, unlocked_vault, alice_token):
        """2.2 — malformed ciphertext must be refused."""
        create_key("mal-key", alice_token)
        with pytest.raises(Exception):
            decrypt("not-a-valid-ciphertext", alice_token)

    def test_cross_user_encrypt_denied(self, unlocked_vault, alice_token, bob_token):
        """2.3 — Bob cannot encrypt using Alice's key."""
        create_key("alice-key", alice_token)
        from src.kv.engine import PermissionDenied

        with pytest.raises(PermissionDenied):
            encrypt("alice-key", base64.b64encode(b"x").decode(), bob_token)

    def test_cross_user_decrypt_denied(self, unlocked_vault, alice_token, bob_token):
        """2.3 — Bob cannot decrypt a ciphertext produced by Alice's key."""
        create_key("alice-only", alice_token)
        ct = encrypt("alice-only", base64.b64encode(b"secret").decode(), alice_token)
        from src.kv.engine import PermissionDenied

        with pytest.raises(PermissionDenied):
            decrypt(ct, bob_token)

    def test_sign_key_rejected_for_encrypt(self, unlocked_vault, alice_token):
        """2.2 — using a SIGN_VERIFY key for encrypt must raise InvalidKeyUsage."""
        create_signing_key("sign-key", "ED25519", alice_token)
        with pytest.raises(InvalidKeyUsage):
            encrypt("sign-key", base64.b64encode(b"x").decode(), alice_token)


# ---------------------------------------------------------------------------
# 2.4 — Sign & Verify
# ---------------------------------------------------------------------------
class TestTransitSignVerify:
    @pytest.mark.parametrize("algo", ["ED25519", "RSASSA_PKCS1_V1_5_SHA_256"])
    def test_sign_verify_roundtrip(self, unlocked_vault, alice_token, algo):
        """2.4 — sign→verify on unmodified message must return signature_valid: True."""
        create_signing_key(f"sig-{algo}", algo, alice_token)
        msg = base64.b64encode(b"authenticate me").decode()
        result = sign(f"sig-{algo}", msg, "RAW", alice_token)
        vresult = verify(f"sig-{algo}", msg, "RAW", result["signature_b64"], alice_token)
        assert vresult["signature_valid"] is True
        assert vresult["signing_algorithm"] == algo

    def test_tampered_message_invalid_signature(self, unlocked_vault, alice_token):
        """2.4 — altering 1 byte of the message must make verify return false."""
        create_signing_key("tamper-sig", "ED25519", alice_token)
        msg = base64.b64encode(b"original").decode()
        sig = sign("tamper-sig", msg, "RAW", alice_token)["signature_b64"]
        tampered_msg = base64.b64encode(b"0riginal").decode()  # 'o' → '0'
        result = verify("tamper-sig", tampered_msg, "RAW", sig, alice_token)
        assert result["signature_valid"] is False

    def test_wrong_key_signature_invalid(self, unlocked_vault, alice_token):
        """2.4 — verifying sig from key-A against key-B must return false."""
        create_signing_key("key-a", "ED25519", alice_token)
        create_signing_key("key-b", "ED25519", alice_token)
        msg = base64.b64encode(b"message").decode()
        sig_a = sign("key-a", msg, "RAW", alice_token)["signature_b64"]
        result = verify("key-b", msg, "RAW", sig_a, alice_token)
        assert result["signature_valid"] is False

    def test_encrypt_key_rejected_for_sign(self, unlocked_vault, alice_token):
        """2.4 — using an ENCRYPT_DECRYPT key for sign must raise InvalidKeyUsage."""
        create_key("enc-key", alice_token)
        with pytest.raises(InvalidKeyUsage):
            sign("enc-key", base64.b64encode(b"x").decode(), "RAW", alice_token)

    def test_malformed_signature_returns_false(self, unlocked_vault, alice_token):
        """2.4 — malformed signature passed to verify must return false, not raise."""
        create_signing_key("safe-verify", "ED25519", alice_token)
        msg = base64.b64encode(b"msg").decode()
        result = verify(
            "safe-verify",
            msg,
            "RAW",
            base64.b64encode(b"garbage-sig").decode(),
            alice_token,
        )
        assert result["signature_valid"] is False

    def test_cross_user_sign_denied(self, unlocked_vault, alice_token, bob_token):
        """2.4 — Bob cannot sign using Alice's signing key."""
        from src.kv.engine import PermissionDenied

        create_signing_key("alice-sign", "ED25519", alice_token)
        msg = base64.b64encode(b"x").decode()
        with pytest.raises(PermissionDenied):
            sign("alice-sign", msg, "RAW", bob_token)

    def test_digest_wrong_length_rejected(self, unlocked_vault, alice_token):
        """2.4 — DIGEST mode with wrong-length hash must be rejected."""
        create_signing_key("digest-key", "ED25519", alice_token)
        bad_digest = base64.b64encode(b"short").decode()
        with pytest.raises(ValueError):
            sign("digest-key", bad_digest, "DIGEST", alice_token)


class TestTransitVaultLocked:
    def test_create_key_locked(self, db_conn):
        """2.1 — create_key must raise VaultLocked when vault is locked."""
        from src.auth.session import register, login
        register("alice@example.com", "Passphrase123!")
        token = login("alice@example.com", "Passphrase123!")["token"]
        with pytest.raises(VaultLocked):
            create_key("x", token)

    def test_encrypt_locked(self, db_conn):
        """2.2 — encrypt must raise VaultLocked when vault is locked."""
        from src.auth.session import register, login
        try:
            register("alice@example.com", "Passphrase123!")
        except:
            pass
        token = login("alice@example.com", "Passphrase123!")["token"]
        with pytest.raises(VaultLocked):
            encrypt("x", base64.b64encode(b"x").decode(), token)
