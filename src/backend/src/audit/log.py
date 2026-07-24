"""
audit.log — [EXTRA CREDIT] Tamper-evident, hash-chained audit log.

Every access-denied event and key operation is logged.
Each row's HMAC is chained to the previous row's hash, so any deletion or
modification of a row breaks the chain and is detected by verify_chain().
"""


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
        detail:      Optional extra context (error code, etc.).
    """
    raise NotImplementedError


def verify_chain() -> bool:
    """
    Recompute every row's HMAC and check the chain is unbroken.

    Returns:
        True if the log is intact; False if any row has been tampered with.
    """
    raise NotImplementedError
