"""tests/test_auth.py — Feature 0.2: User authentication tests."""

import time

import pytest

from src.auth.session import (
    LOCKOUT_MAX_ATTEMPTS,
    AccountLocked,
    RegistrationError,
    Unauthenticated,
    login,
    logout,
    register,
    verify_token,
)

# ---------------------------------------------------------------------------
# Helper: register a fresh user (email unique per test via tmp_path)
# ---------------------------------------------------------------------------


def _reg(email: str, passphrase: str = "StrongPass123!") -> dict:
    return register(email, passphrase)


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_success(self, db_conn):
        """0.2 — valid registration creates a user and returns email."""
        result = _reg("carol@example.com")
        assert result["email"] == "carol@example.com"
        assert "created_at" in result

    def test_register_duplicate_rejected(self, db_conn):
        """0.2 — registering the same email twice is rejected (generic error)."""
        _reg("dup@example.com")
        with pytest.raises(RegistrationError):
            _reg("dup@example.com")

    def test_register_short_passphrase_rejected(self, db_conn):
        """0.2 — passphrase shorter than minimum is rejected."""
        with pytest.raises(RegistrationError):
            register("short@example.com", "abc")

    def test_register_invalid_email_rejected(self, db_conn):
        """0.2 — invalid email format is rejected."""
        with pytest.raises(RegistrationError):
            register("not-an-email", "StrongPass123!")

    def test_password_not_stored_in_plaintext(self, db_conn):
        """0.2 — the passphrase must not appear verbatim in the DB."""
        _reg("plain@example.com", passphrase="SuperSecret!99")
        row = db_conn.execute(
            "SELECT password_hash FROM users WHERE email = ?", ("plain@example.com",)
        ).fetchone()
        assert "SuperSecret!99" not in row["password_hash"]
        # bcrypt hashes start with $2b$
        assert row["password_hash"].startswith("$2b$")


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------


class TestLogin:
    def test_login_success(self, db_conn):
        """0.2 — correct credentials return a token and expiry."""
        _reg("alice2@example.com")
        result = login("alice2@example.com", "StrongPass123!")
        assert "token" in result
        assert result["token"]
        assert result["expires_at"] > time.time()
        assert result["email"] == "alice2@example.com"

    def test_login_wrong_passphrase_rejected(self, db_conn):
        """0.2 — wrong passphrase raises Unauthenticated."""
        _reg("bob2@example.com")
        with pytest.raises(Unauthenticated):
            login("bob2@example.com", "WrongPass999!")

    def test_login_nonexistent_email_rejected(self, db_conn):
        """0.2 — non-existent email raises Unauthenticated (generic, no enumeration)."""
        with pytest.raises(Unauthenticated):
            login("ghost@example.com", "anything")

    def test_token_stored_in_sessions_table(self, db_conn):
        """0.2 — issued token is persisted in the sessions table with expiry."""
        _reg("dave@example.com")
        result = login("dave@example.com", "StrongPass123!")
        row = db_conn.execute(
            "SELECT email, expires_at FROM sessions WHERE token = ?",
            (result["token"],),
        ).fetchone()
        assert row is not None
        assert row["email"] == "dave@example.com"
        assert row["expires_at"] > time.time()


# ---------------------------------------------------------------------------
# Token verification tests
# ---------------------------------------------------------------------------


class TestVerifyToken:
    def test_valid_token_returns_email(self, db_conn):
        """0.2 — verify_token returns the owner email for a valid token."""
        _reg("eve@example.com")
        session = login("eve@example.com", "StrongPass123!")
        assert verify_token(session["token"]) == "eve@example.com"

    def test_missing_token_raises(self, db_conn):
        """0.2 — empty token raises Unauthenticated."""
        with pytest.raises(Unauthenticated):
            verify_token("")

    def test_invalid_token_raises(self, db_conn):
        """0.2 — garbage token raises Unauthenticated."""
        with pytest.raises(Unauthenticated):
            verify_token("not-a-real-token")

    def test_expired_token_raises(self, db_conn, monkeypatch):
        """0.2 — expired token raises Unauthenticated (session_expired)."""
        _reg("frank@example.com")
        session = login("frank@example.com", "StrongPass123!")
        # Manually expire the token in the DB
        db_conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE token = ?",
            (time.time() - 1, session["token"]),
        )
        db_conn.commit()
        with pytest.raises(Unauthenticated):
            verify_token(session["token"])


# ---------------------------------------------------------------------------
# Account lockout tests — mandatory per spec
# ---------------------------------------------------------------------------


class TestAccountLockout:
    def test_five_wrong_attempts_lock_account(self, db_conn):
        """0.2 — MANDATORY: 5 consecutive wrong passwords must lock the account."""
        _reg("grace@example.com")
        for _ in range(LOCKOUT_MAX_ATTEMPTS - 1):
            with pytest.raises(Unauthenticated):
                login("grace@example.com", "WRONG_PASSWORD!")

        # The 5th attempt triggers the lockout
        with pytest.raises(AccountLocked):
            login("grace@example.com", "WRONG_PASSWORD!")

    def test_correct_password_rejected_while_locked(self, db_conn):
        """0.2 — MANDATORY: correct password must fail while account is locked."""
        _reg("henry@example.com")
        # Exhaust all attempts
        for _ in range(LOCKOUT_MAX_ATTEMPTS):
            try:
                login("henry@example.com", "WRONG_PASSWORD!")
            except (Unauthenticated, AccountLocked):
                pass
        # Correct password must still be rejected
        with pytest.raises(AccountLocked):
            login("henry@example.com", "StrongPass123!")

    def test_lockout_expires_after_duration(self, db_conn, monkeypatch):
        """0.2 — account unlocks automatically after LOCKOUT_DURATION seconds."""
        _reg("iris@example.com")
        # Force the account into locked state by setting locked_until in the past
        db_conn.execute(
            """UPDATE users SET failed_attempts = ?, locked_until = ?
               WHERE email = ?""",
            (LOCKOUT_MAX_ATTEMPTS, time.time() - 1, "iris@example.com"),
        )
        db_conn.commit()
        # Login should now succeed (lockout has expired)
        result = login("iris@example.com", "StrongPass123!")
        assert "token" in result

    def test_successful_login_resets_counter(self, db_conn):
        """0.2 — a successful login resets the failed-attempt counter."""
        _reg("jack@example.com")
        # Two wrong attempts
        for _ in range(2):
            with pytest.raises(Unauthenticated):
                login("jack@example.com", "WRONG!")
        # One correct login
        login("jack@example.com", "StrongPass123!")
        row = db_conn.execute(
            "SELECT failed_attempts FROM users WHERE email = ?", ("jack@example.com",)
        ).fetchone()
        assert row["failed_attempts"] == 0


# ---------------------------------------------------------------------------
# Logout tests
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_invalidates_token(self, db_conn):
        """0.2 — after logout, token is no longer valid."""
        _reg("kate@example.com")
        session = login("kate@example.com", "StrongPass123!")
        token = session["token"]
        logout(token)
        with pytest.raises(Unauthenticated):
            verify_token(token)

    def test_logout_idempotent(self, db_conn):
        """0.2 — calling logout twice with the same token is safe."""
        _reg("luke@example.com")
        session = login("luke@example.com", "StrongPass123!")
        logout(session["token"])
        logout(session["token"])  # should not raise
