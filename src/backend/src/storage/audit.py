"""
storage.audit — Feature 4.4: Extra Credit.

Implements a hash-chained audit log for critical operations.
"""

import time
import json
import hashlib
from src.storage.db import get_db

def log_action(action: str, actor_email: str, resource: str, detail: dict, result: str = "ALLOWED"):
    """
    Log an action with a cryptographic hash chain.
    """
    conn = get_db()
    
    # Get the previous hash
    row = conn.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["row_hash"] if row else "0" * 64
    
    now = time.time()
    detail_str = json.dumps(detail, sort_keys=True) if detail else "{}"
    
    # Compute new hash: SHA256(prev_hash || action || actor_email || resource || detail_str || result || timestamp)
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode())
    hasher.update(action.encode())
    hasher.update((actor_email or "").encode())
    hasher.update((resource or "").encode())
    hasher.update(detail_str.encode())
    hasher.update(result.encode())
    hasher.update(str(now).encode())
    row_hash = hasher.hexdigest()
    
    conn.execute(
        """INSERT INTO audit_log 
           (timestamp, actor_email, action, resource, result, detail, prev_hash, row_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (now, actor_email, action, resource, result, detail_str, prev_hash, row_hash)
    )
    conn.commit()
