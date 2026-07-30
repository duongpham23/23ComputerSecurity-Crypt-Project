"""
audit.log — [EXTRA CREDIT] Tamper-evident, hash-chained audit log.

Public API:
  append()       — write a new audit entry (forwarded to storage.audit.log_action).
  verify_chain() — recompute every row's hash and confirm the chain is unbroken.

Previously contained NotImplementedError stubs (Fix 6). Now wired to
storage/audit.py which holds the actual SQLite-backed implementation.
"""

import hashlib

from src.storage.audit import log_action as _log_action
from src.storage.db import get_db


def append(
    actor_email: str | None,
    action: str,
    resource: str | None,
    result: str,
    detail: str | None = None,
) -> None:
    """
    Append a new entry to the audit log.

    Args:
        actor_email: Email of the user performing the action (or None for system events).
        action:      Short action name, e.g. ``"kv.read"``, ``"transit.encrypt"``.
        resource:    The path or key_name being accessed.
        result:      ``"ALLOWED"`` or ``"DENIED"``.
        detail:      Optional extra context string.
    """
    _log_action(
        action=action,
        actor_email=actor_email or "",
        resource=resource or "",
        detail={"info": detail} if detail else {},
        result=result,
    )


def verify_chain() -> bool:
    """
    Recompute every row's SHA-256 hash and verify the chain is unbroken.

    Each row stores prev_hash (the previous row's row_hash) and row_hash
    (SHA-256 of prev_hash || action || actor_email || resource || detail || result || timestamp).
    Any deletion or modification of a row breaks the chain.

    Returns:
        True if the log is intact; False if any row has been tampered with.
    """
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()

    if not rows:
        return True

    for i, row in enumerate(rows):
        expected_prev = "0" * 64 if i == 0 else rows[i - 1]["row_hash"]

        # The chain link must match.
        if row["prev_hash"] != expected_prev:
            return False

        # Recompute the row_hash using the same algorithm as storage/audit.py.
        hasher = hashlib.sha256()
        hasher.update(row["prev_hash"].encode())
        hasher.update(row["action"].encode())
        hasher.update((row["actor_email"] or "").encode())
        hasher.update((row["resource"] or "").encode())
        hasher.update((row["detail"] or "{}").encode())
        hasher.update(row["result"].encode())
        hasher.update(str(row["timestamp"]).encode())
        computed_hash = hasher.hexdigest()

        if computed_hash != row["row_hash"]:
            return False

    return True
