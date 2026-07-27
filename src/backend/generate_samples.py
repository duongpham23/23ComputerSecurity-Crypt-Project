import base64
import json
import os
import shutil

# --- Set up data directory ---
samples_dir = os.path.join(os.path.dirname(__file__), "data", "samples")
os.makedirs(samples_dir, exist_ok=True)
os.environ["VAULT_DATA_DIR"] = samples_dir

import src.core.vault as vault_mod  # noqa: E402
import src.storage.db as db_mod  # noqa: E402
from src.auth.session import login, register  # noqa: E402

# Force re-init of db
db_mod._local.__dict__.clear()
db_mod.init_db()

# Initialize Vault
if not vault_mod.is_initialized():
    vault_mod.init_vault("SuperSecretAdminPass123!")
else:
    vault_mod.unlock_vault("SuperSecretAdminPass123!")

# Register and login user
try:
    register("alice@example.com", "AlicePassphrase123!")
except Exception:
    pass

session = login("alice@example.com", "AlicePassphrase123!")
token = session["token"]

# --- 1. KV Engine Sample Data ---
from src.kv import engine as kv_engine  # noqa: E402

kv_engine.write("secret/alice@example.com/db_creds", {"username": "admin", "password": "supersecret"}, token)
kv_engine.write("secret/alice@example.com/api_keys", {"aws": "AKIA...", "stripe": "sk_test..."}, token)

# --- 2. Transit Engine Sample Data ---
from src.transit import crypto as transit_crypto  # noqa: E402
from src.transit import keys as transit_keys  # noqa: E402
from src.transit import signing as transit_signing  # noqa: E402

try:
    transit_keys.create_key("my-app-key", token)
except Exception:
    pass

plaintext = base64.b64encode(b"Sensitive user data goes here").decode()
ciphertext = transit_crypto.encrypt("my-app-key", plaintext, token)

try:
    transit_signing.create_signing_key("my-signer", "ED25519", token)
except Exception:
    pass

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

db_mod.get_db().close()

# Copy minivault.db to kv_sample.db
db_path = os.path.join(samples_dir, "minivault.db")
sample_db_path = os.path.join(samples_dir, "kv_sample.db")
if os.path.exists(db_path):
    shutil.copy(db_path, sample_db_path)

print(f"Sample data generated in {samples_dir}")
