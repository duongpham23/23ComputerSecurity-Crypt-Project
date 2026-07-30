"""
storage.db — SQLite connection pool and schema initialisation.

All tables are created here. Modules import get_db() to acquire a connection.
"""

import os
import sqlite3
import threading
from pathlib import Path

# Thread-local storage so each thread gets its own connection (sqlite3 is not
# thread-safe by default when sharing a single connection object).
_local = threading.local()


def _data_dir() -> Path:
    """Return the configured data directory (re-read from env each call)."""
    return Path(os.getenv("VAULT_DATA_DIR", "data"))


def get_db() -> sqlite3.Connection:
    """
    Return a thread-local SQLite connection.

    The connection uses WAL journal mode for better read/write concurrency and
    enforces foreign-key constraints.
    """
    if not hasattr(_local, "conn") or _local.conn is None:
        data_dir = _data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        db_path = data_dir / "minivault.db"
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        _local.conn = conn
    return _local.conn


def init_db() -> None:
    """Create all tables if they do not yet exist."""
    conn = get_db()
    conn.executescript(
        """
        -- ----------------------------------------------------------------
        -- Feature 0
        -- ----------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS users (
            email           TEXT PRIMARY KEY,
            password_hash   TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    REAL,
            created_at      REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            email       TEXT NOT NULL,
            expires_at  REAL NOT NULL,
            FOREIGN KEY (email) REFERENCES users(email)
        );

        -- ----------------------------------------------------------------
        -- Feature 1 — KV Engine
        -- ----------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS kv_secrets (
            path            TEXT PRIMARY KEY,
            owner_email     TEXT NOT NULL,
            nonce_b64       TEXT NOT NULL,
            ciphertext_b64  TEXT NOT NULL,
            tag_b64         TEXT NOT NULL,
            version         INTEGER NOT NULL DEFAULT 1,
            created_at      REAL NOT NULL,
            updated_at      REAL NOT NULL,
            FOREIGN KEY (owner_email) REFERENCES users(email)
        );

        -- KV version history
        CREATE TABLE IF NOT EXISTS kv_versions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            path            TEXT NOT NULL,
            owner_email     TEXT NOT NULL,
            nonce_b64       TEXT NOT NULL,
            ciphertext_b64  TEXT NOT NULL,
            tag_b64         TEXT NOT NULL,
            version         INTEGER NOT NULL,
            created_at      REAL NOT NULL
        );

        -- ----------------------------------------------------------------
        -- Feature 2 — Transit Engine
        -- ----------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS transit_keys (
            key_name                    TEXT NOT NULL,
            owner_email                 TEXT NOT NULL,
            key_usage                   TEXT NOT NULL
                CHECK(key_usage IN ('ENCRYPT_DECRYPT', 'SIGN_VERIFY')),
            signing_algorithm           TEXT,
            encrypted_key_material_b64  TEXT NOT NULL,
            public_key_b64              TEXT,
            key_version                 INTEGER NOT NULL DEFAULT 1,
            is_active                   INTEGER NOT NULL DEFAULT 1,
            created_at                  REAL NOT NULL,
            PRIMARY KEY (key_name, owner_email, key_version),
            FOREIGN KEY (owner_email) REFERENCES users(email)
        );

        -- [EXTRA] ACL grants for cross-user key/secret sharing
        CREATE TABLE IF NOT EXISTS acl_grants (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_type   TEXT NOT NULL
                CHECK(resource_type IN ('kv', 'transit')),
            resource_id     TEXT NOT NULL,
            owner_email     TEXT NOT NULL,
            grantee_email   TEXT NOT NULL,
            permissions     TEXT NOT NULL,
            granted_at      REAL NOT NULL,
            FOREIGN KEY (owner_email)   REFERENCES users(email),
            FOREIGN KEY (grantee_email) REFERENCES users(email)
        );

        -- Tamper-evident audit log (hash-chained)
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL,
            actor_email TEXT,
            action      TEXT    NOT NULL,
            resource    TEXT,
            result      TEXT    NOT NULL
                CHECK(result IN ('ALLOWED', 'DENIED')),
            detail      TEXT,
            prev_hash   TEXT    NOT NULL,
            row_hash    TEXT    NOT NULL
        );
        """
    )
    conn.commit()
