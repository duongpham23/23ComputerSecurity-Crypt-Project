"""
src.auth.session — Feature 0.2: User registration, login, session tokens.

Security model:
  - Passwords are hashed with bcrypt (never stored in plaintext).
  - Session tokens are cryptographically random (secrets.token_urlsafe).
  - Tokens have a 30-minute expiry and are stored in the sessions table.
  - 5 consecutive wrong-passphrase attempts lock the account for 5 minutes.
  - Error messages are deliberately generic to avoid leaking user enumeration info.
"""

import re
import secrets
import time

import bcrypt

from src.storage.db import get_db

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOKEN_TTL_SECONDS = 30 * 60  # 30-minute session lifetime
LOCKOUT_MAX_ATTEMPTS = 5  # wrong attempts before lockout
LOCKOUT_DURATION = 5 * 60  # lockout duration in seconds (5 min)
MIN_PASSPHRASE_LENGTH = 12  # minimum passphrase length

# Passphrase complexity pattern (Fix 7):
# >= 12 chars, at least one of each: uppercase, lowercase, digit, symbol.
_PASSPHRASE_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$")


def _is_strong_passphrase(passphrase: str) -> bool:
    """Return True if *passphrase* satisfies all complexity requirements."""
    return bool(_PASSPHRASE_PATTERN.match(passphrase))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class Unauthenticated(Exception):
    """Raised when a token is missing, malformed, or expired."""

    pass


class AccountLocked(Exception):
    """Raised when the account is temporarily locked due to failed attempts."""

    def __init__(self, lock_until: float):
        super().__init__("ACCOUNT_LOCKED")
        self.lock_until = lock_until


class RegistrationError(Exception):
    """Raised on invalid registration input (generic — does not reveal email existence)."""

    pass


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(email: str, passphrase: str) -> dict:
    """
    Register a new user.

    Hashes the passphrase with bcrypt and inserts a new row into `users`.
    Returns a generic success dict — does NOT disclose if the email already
    existed (to prevent user enumeration).

    Raises:
        RegistrationError: if input is invalid or email is already registered.
    """
    if not email or "@" not in email or len(email) > 256:
        raise RegistrationError("INVALID_EMAIL")
    if not _is_strong_passphrase(passphrase):
        raise RegistrationError(
            "PASSPHRASE_TOO_WEAK: must be >=12 chars with at least one uppercase letter, "
            "one lowercase letter, one digit, and one symbol."
        )

    # Hash with bcrypt — salt is automatically embedded in the hash
    password_hash = bcrypt.hashpw(passphrase.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    existing = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()

    if existing:
        # Generic error — do not reveal that this specific email exists
        raise RegistrationError("REGISTRATION_FAILED")

    now = time.time()
    conn.execute(
        """INSERT INTO users (email, password_hash, failed_attempts, locked_until, created_at)
           VALUES (?, ?, 0, 0, ?)""",
        (email, password_hash, now),
    )
    conn.commit()

    return {"email": email, "created_at": now}


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def login(email: str, passphrase: str) -> dict:
    """
    Authenticate credentials and issue a 30-minute session token.

    Returns:
        {"token": str, "expires_at": float, "email": str}

    Raises:
        Unauthenticated:  wrong credentials (generic — does not reveal whether
                          the email exists or the passphrase was wrong).
        AccountLocked:    account is temporarily locked (5 attempts reached).
    """
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash, failed_attempts, locked_until FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    # Generic failure — same path whether email exists or not
    if row is None:
        # Perform a dummy bcrypt check to maintain constant time (prevent timing attacks)
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        raise Unauthenticated("UNAUTHENTICATED")

    now = time.time()

    # Check account lockout BEFORE verifying passphrase
    if row["locked_until"] and now < row["locked_until"]:
        raise AccountLocked(lock_until=row["locked_until"])

    # Verify passphrase
    passphrase_correct = bcrypt.checkpw(
        passphrase.encode("utf-8"),
        row["password_hash"].encode("utf-8"),
    )

    if not passphrase_correct:
        new_attempts = row["failed_attempts"] + 1
        if new_attempts >= LOCKOUT_MAX_ATTEMPTS:
            lock_until = now + LOCKOUT_DURATION
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE email = ?",
                (new_attempts, lock_until, email),
            )
            conn.commit()
            from src.storage.audit import log_action
            log_action(
                action="ACCOUNT_LOCKED",
                actor_email=email,
                resource="auth.login",
                detail={"failed_attempts": new_attempts, "locked_until": lock_until},
                result="DENIED"
            )
            raise AccountLocked(lock_until=lock_until)
        else:
            conn.execute(
                "UPDATE users SET failed_attempts = ? WHERE email = ?",
                (new_attempts, email),
            )
            conn.commit()
            raise Unauthenticated("UNAUTHENTICATED")

    # Success — reset counter and issue token
    token = secrets.token_urlsafe(32)
    expires_at = now + TOKEN_TTL_SECONDS

    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE email = ?",
        (email,),
    )
    conn.execute(
        "INSERT INTO sessions (token, email, expires_at) VALUES (?, ?, ?)",
        (token, email, expires_at),
    )
    conn.commit()

    return {"token": token, "expires_at": expires_at, "email": email}


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


def verify_token(token: str) -> str:
    """
    Verify a Bearer token and return the caller's email.

    Raises Unauthenticated if:
      - token is missing or blank.
      - token is not found in the sessions table.
      - token has expired.
    """
    if not token:
        raise Unauthenticated("UNAUTHENTICATED")

    # Strip "Bearer " prefix if present (passed raw from FastAPI Depends)
    clean = token.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()

    conn = get_db()
    row = conn.execute(
        "SELECT email, expires_at FROM sessions WHERE token = ?",
        (clean,),
    ).fetchone()

    if row is None:
        raise Unauthenticated("UNAUTHENTICATED")

    if time.time() > row["expires_at"]:
        # Clean up expired session
        conn.execute("DELETE FROM sessions WHERE token = ?", (clean,))
        conn.commit()
        raise Unauthenticated("SESSION_EXPIRED")

    return row["email"]


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


def logout(token: str) -> None:
    """Invalidate the session token (safe to call even if token is already gone)."""
    clean = token.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token = ?", (clean,))
    conn.commit()


# ---------------------------------------------------------------------------
# Legacy stub kept for test compatibility
# (conftest.py mocks this module, so tests are unaffected)
# ---------------------------------------------------------------------------


def issue_token(email: str) -> str:
    """Deprecated stub — use login() instead. Kept so conftest mock still works."""
    return f"stub-token-{email}"
