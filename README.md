# MiniVault — Secure Storage & Transit Engine

A cryptographic key-value store and transit encryption service built with FastAPI.
Implements Feature 1 (KV Engine) and Feature 2 (Transit Engine) according to the
Crypt Project 1 spec, as well as Feature 0 (Vault Initialization and Auth).

## Team Members
- Alice (12345678) — Core & Auth (Feature 0)
- Bob (87654321) — KV Engine (Feature 1)
- Charlie (11223344) — Transit Engine (Feature 2)

## Setup & Installation

### Requirements
- Python 3.10+
- `pip`

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run the Server
```bash
uvicorn main:app --reload --port 8000
```
The API will be available at `http://localhost:8000`.

### Run Tests
```bash
cd src/backend
pytest tests/ -v
```
All 56 tests across KV, Transit, Auth, and Core pass.

### Generate Sample Data
To generate the required sample files in `data/samples/`:
```bash
python generate_samples.py
```

## Security Features Implemented

- **Feature 0.1**: Vault DEK wrapped with Argon2id-derived key from Master Passphrase. Vault starts locked.
- **Feature 0.2**: bcrypt password hashing, 30-minute session tokens, 5-attempt account lockout.
- **Feature 1.1**: AES-256-GCM encrypted-at-rest KV storage with GCM tag verification.
- **Feature 1.2**: Ownership-based access control (namespace isolation).
- **Feature 2.1**: Named Key Management for Encryption and Signing.
- **Feature 2.2**: Encryption & Decryption as a Service (AES-256-GCM).
- **Feature 2.3**: Transit Key Access Control.
- **Feature 2.4**: Signing & Verification (ED25519 & RSA-2048).

### Extra Credit Features Included
- **KV Versioning**: Old versions of secrets are preserved.
- **Key Rotation**: Transit keys can be rotated.
- **ACL Sharing**: Secrets and Keys can be shared with other users.
- **Audit Log**: Tamper-evident, hash-chained audit log of all security events.

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/vault/init` | POST | Initialize vault with master passphrase |
| `/vault/unlock`| POST | Unlock vault |
| `/users` | POST | Register a new user |
| `/auth/sessions`| POST | Login and get token |
| `/kv/write` | POST | Write a secret |
| `/kv/read` | GET | Read a secret |
| `/transit/keys` | POST/GET | Create or list encryption keys |
| `/transit/encrypt`| POST | Encrypt data |
| `/transit/decrypt`| POST | Decrypt data |
| `/transit/signing-keys`| POST | Create signing key |
| `/transit/sign` | POST | Sign a message |
| `/transit/verify` | POST | Verify a signature |

## Demo Video
[Demo Video Link (YouTube)]()
