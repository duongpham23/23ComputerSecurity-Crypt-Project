import os
import sys
import types
import json
import base64
import time

# --- Setup Mocks for Core/Auth ---
_vault_mod = types.ModuleType("src.core.vault")
_vault_mod._dek = os.urandom(32)
_vault_mod._unlocked = True

def _get_dek() -> bytes:
    return _vault_mod._dek

_vault_mod.get_dek = _get_dek
_vault_mod.is_unlocked = lambda: True

class _VaultLocked(Exception): pass
_vault_mod.VaultLocked = _VaultLocked

sys.modules["src.core.vault"] = _vault_mod
sys.modules.setdefault("src.core", types.ModuleType("src.core"))
sys.modules["src.core"].vault = _vault_mod

_session_mod = types.ModuleType("src.auth.session")
def _verify_token(token: str) -> str:
    if token.startswith("stub-token-"):
        return token.split("stub-token-")[1]
    raise Exception("UNAUTHENTICATED")
class _Unauthenticated(Exception): pass
_session_mod.verify_token = _verify_token
_session_mod.Unauthenticated = _Unauthenticated

sys.modules["src.auth.session"] = _session_mod
sys.modules.setdefault("src.auth", types.ModuleType("src.auth"))
sys.modules["src.auth"].session = _session_mod

# --- Set up data directory ---
import src.storage.db as db_mod
samples_dir = os.path.join(os.path.dirname(__file__), "data", "samples")
os.makedirs(samples_dir, exist_ok=True)
os.environ["VAULT_DATA_DIR"] = samples_dir

# Force re-init of db
db_mod.init_db()
conn = db_mod.get_db()

# Insert dummy user
conn.execute(
    "INSERT OR IGNORE INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
    ("alice@example.com", "fake_hash", time.time())
)
conn.commit()

token = "stub-token-alice@example.com"

# --- 1. KV Engine Sample Data ---
from src.kv import engine as kv_engine

kv_engine.write("secret/alice@example.com/db_creds", {"username": "admin", "password": "supersecret"}, token)
kv_engine.write("secret/alice@example.com/api_keys", {"aws": "AKIA...", "stripe": "sk_test..."}, token)
# (This populates storage.db inside samples_dir)

# --- 2. Transit Engine Sample Data ---
from src.transit import keys as transit_keys
from src.transit import crypto as transit_crypto
from src.transit import signing as transit_signing

transit_keys.create_key("my-app-key", token)
plaintext = base64.b64encode(b"Sensitive user data goes here").decode()
ciphertext = transit_crypto.encrypt("my-app-key", plaintext, token)

transit_signing.create_signing_key("my-signer", "ED25519", token)
msg_b64 = base64.b64encode(b"This contract is signed").decode()
sig_res = transit_signing.sign("my-signer", msg_b64, "RAW", token)
signature = sig_res["signature_b64"]

transit_samples = {
    "key_name_used": "my-app-key",
    "encrypted_ciphertext": ciphertext,
    "signing_key_used": "my-signer",
    "signed_message_b64": msg_b64,
    "signature_b64": signature
}

with open(os.path.join(samples_dir, "transit_sample.json"), "w") as f:
    json.dump(transit_samples, f, indent=4)

conn.close()

import shutil
# Copy minivault.db to kv_sample.db
db_path = os.path.join(samples_dir, "minivault.db")
sample_db_path = os.path.join(samples_dir, "kv_sample.db")
shutil.copy(db_path, sample_db_path)

print(f"Sample data generated in {samples_dir}")
