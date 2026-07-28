# MiniVault — Detailed Mechanisms

## Table of Contents

- Introduction
- Cryptographic Parameters (global)
- Feature 0 — Initialization & Unlock (Master Passphrase)
- Feature 0.2 — Authentication (Register / Login / Sessions)
- Feature 1 — KV Engine (Encrypted-at-Rest Storage)
- Feature 2 — Transit Engine (Named Keys, Encrypt/Decrypt, Signing)
- Tamper-Evident Audit Log
- Operational Notes
- API Reference (selected endpoints & examples)
- Tests and Acceptance Criteria (how to run)
- References

---

## Introduction

This document expands the high-level report into actionable implementation details so developers and graders can reproduce, test, and validate security claims. It emphasizes deterministic cryptographic parameters, concrete data formats, and expected runtime behavior.

In this project, we did integrate an UI/UX for MiniVault. This allows users to interact with the Mini Vault system more easily instead of calling API from Postman or something else.

## Cryptographic Parameters (global)

- DEK size: 256 bits (32 bytes). All symmetric keys use AES-256.
- AEAD mode: AES-256-GCM.
  - Nonce length: 96 bits (12 bytes).
  - Tag length: 128 bits (16 bytes).
- KDF for Master Passphrase: Argon2id (recommended parameters):
  - time_cost: 3
  - memory_cost: 65536 (64 MiB)
  - parallelism: 4
  - hash_len: 32 (256-bit derived key)

  These parameters balance security and moderate server CPU/memory; graders may increase `memory_cost` for stronger brute-force resistance if environment allows.

- Password hashing for user accounts: bcrypt with cost (rounds) = 12.
- Randomness source: `os.urandom()` or `secrets` for key generation, nonces, and salts.

## Basic Features

### Feature 0 — Initialization & Unlock (Master Passphrase)

#### Key derivation and DEK wrapping

**Mechanism**:
On first initialization, the system securely generates a 256-bit Data Encryption Key (DEK) and a 16-byte cryptographic salt using `os.urandom`. The administrator's Master Passphrase and the salt are fed into the Argon2id Key Derivation Function (KDF) to compute a 256-bit Wrapping Key. Argon2id is specifically configured with memory-hard parameters to aggressively resist GPU-based brute-force attacks and ASIC cracking arrays. The resulting Wrapping Key is then used to encrypt the DEK using AES-256-GCM. A unique 96-bit nonce is generated for this operation, and AES-GCM outputs the encrypted DEK payload along with a 128-bit MAC tag.

Security rule: plaintext `DEK` must never be persisted. Only the encrypted DEK is written to disk.

#### On-disk format: `vault_meta.json`

Example JSON:

```json
{
  "kdf": "argon2id",
  "kdf_salt_b64": "...",
  "wrap_nonce_b64": "...",
  "encrypted_dek_b64": "...",
  "tag_b64": "...",
  "status": "locked"
}
```

#### Unlock flow and locked state behavior

**Mechanism**:
When the vault is unlocked via the `/vault/unlock` endpoint, the system reads `vault_meta.json` and extracts the Argon2id salt, nonce, ciphertext, and MAC tag. It re-derives the Wrapping Key using the inputted passphrase and the stored salt. The system then attempts to decrypt the encrypted DEK using AES-256-GCM.

If the passphrase is correct, the MAC tag verification succeeds, the plaintext DEK is loaded securely into server memory, and the vault state transitions to `unlocked`. If the passphrase is wrong or the file is tampered with, the GCM MAC tag verification mathematically fails. The system throws a generic `VAULT_UNLOCK_FAILED` exception without exposing whether the failure was due to a wrong passphrase or data corruption.

### Feature 0.2 — Authentication (Register / Login / Sessions)

#### Registration and Password Hashing

**Mechanism**:
To securely authenticate operators without storing raw credentials, MiniVault uses `bcrypt`. During registration, bcrypt generates a unique 16-byte salt and hashes the user's password with a predefined work factor (cost = 12). The resulting hash string (which inherently embeds the salt and cost factor) is stored in the `users` table. By enforcing a high work factor, the system ensures that offline dictionary attacks remain computationally infeasible.

#### Login and Session Tokens

**Mechanism**:
During login, the system extracts the salt from the stored bcrypt string, hashes the incoming password attempt, and performs a constant-time string comparison to neutralize timing side-channel attacks. Upon success, a 32-byte hexadecimal session token is securely generated via `secrets.token_hex(32)`. This token is mapped to the user in a session table with a strict 30-minute expiration sliding window. Middleware validates this token on every subsequent API request.

#### Account Lockout

**Mechanism**:
To neutralize online dictionary and brute-force attacks, the backend tracks consecutive failed login attempts per account in the database. Upon reaching 5 failures, the system updates a `locked_until` timestamp to 5 minutes in the future and clears the failure counter. While an account is locked, the system immediately rejects all login attempts with a generic auth failure, regardless of whether the password provided is correct or not.

### Feature 1 — KV Engine (Encrypted-at-Rest Storage)

#### Storage schema (simplified)

- Table `kv_secrets` columns (SQLite):
  - `id` INTEGER PRIMARY KEY
  - `owner_email` TEXT
  - `path` TEXT
  - `nonce_b64` TEXT
  - `ciphertext_b64` TEXT
  - `tag_b64` TEXT
  - `created_at` TIMESTAMP
  - `updated_at` TIMESTAMP

#### Write and Read Mechanics

**Mechanism**:
The KV Engine provides Authenticated Encryption with Associated Data (AEAD). When a user writes a secret string to a logical path, the backend generates a fresh, cryptographically secure 96-bit nonce using `os.urandom(12)`. The plaintext secret is then encrypted using the globally loaded in-memory DEK via AES-256-GCM.

AES-GCM operates as a stream cipher utilizing a Galois field multiplier. It simultaneously encrypts the data and computes a 128-bit authentication MAC tag over the ciphertext. The final payload written to the SQLite database includes the nonce, the ciphertext, and the MAC tag in base64 format.

During a read operation, the system retrieves these components and attempts decryption. This design achieves absolute Confidentiality and Authenticity. Any unauthorized bit-flip or modification in the database by a rogue admin will cause the MAC verification to instantly fail during decryption, triggering a `DATA_INTEGRITY_ERROR`.

#### Ownership-based access control

**Mechanism**:
Namespace isolation is strictly enforced at the database query level. Every secret's database row is bound to the creator's identity (`owner_email`). Before any read, write, or delete operation is performed, the system verifies that the authenticated caller's email matches the row's owner. If they do not match, the system returns a generic `PERMISSION_DENIED` error without disclosing whether the path actually exists.

### Feature 2 — Transit Engine (Named Keys, Encrypt/Decrypt, Signing)

#### Named Key Lifecycle (Create, List, Revoke)

**Mechanism**:
When an administrator creates a named key, the system generates a raw 256-bit AES backing key (`key_material`) using `os.urandom(32)`. To protect this key at rest, the system encrypts the `key_material` itself using the Vault's central DEK via AES-GCM (generating a specific `wrap_nonce`). The encrypted key material, wrap nonce, and metadata (`key_name`, `owner_email`, `key_version`) are stored in the database.

When listing keys, the API only returns metadata and never exposes the plaintext key material. Revocation acts as a soft-delete mechanism: it marks a named key as `revoked` in metadata so it can no longer be used for new cryptographic operations, but preserves the record for auditability.

#### Encrypt / Decrypt API and Ciphertext Format

**Mechanism**:
The Transit Engine provides cryptography as a service. When a client requests encryption, they provide a base64-encoded plaintext payload. The Vault locates the active AES key in the database, decrypts it into memory using the DEK, generates a unique 96-bit nonce, and encrypts the client's payload.

The critical mechanism is the custom ciphertext formatting: the Vault concatenates the data into a string structured as `vault:v<version>:<nonce_b64>:<ciphertext_b64>`. When a decryption request arrives, the Vault parses this string, extracts the exact version number, fetches the corresponding historical key from the database, decodes the nonce, and decrypts the payload. This strict formatting ensures zero ambiguity during decryption.

#### Sign / Verify (ED25519) Flows

**Mechanism**:
ED25519 is an elliptical curve signature scheme providing deterministic, high-speed signing and verification using 256-bit keys. When a signing key is generated, the Vault securely stores the public key in plaintext but strictly encrypts the private key using the central DEK before persisting it to the database.

The Signing API mirrors AWS KMS design: it accepts a `message_type` parameter (`RAW` or `DIGEST`). If `RAW`, the Vault hashes the incoming payload using SHA-256. It then mathematically applies the ED25519 signature using the temporarily decrypted private key in memory. The `verify` endpoint operates symmetrically, utilizing the public key to verify the signature's integrity, ensuring non-repudiation and data authenticity without ever exposing the private key to the caller.

## Extra Credit Features

### KV Versioning

**Mechanism**:
Instead of executing destructive SQL `UPDATE` statements when a user modifies a secret, MiniVault adopts an Append-Only Storage Model. When a user updates a value, the system does not overwrite the old row. Instead, it increments the internal version number and inserts a completely new row into the database containing the latest encrypted payload and timestamp.

Read operations are designed to automatically query and return the row with the latest timestamp/version for a given path, while also allowing users to explicitly query historical values. This provides a resilient audit trail for data modifications and ensures disaster recovery capabilities.

### Tamper-Evident Audit Log

**Mechanism**:
To prevent malicious internal actors from covering their tracks, the system employs a hash-chaining data structure heavily inspired by blockchain Merkle trees.

Whenever a security-critical event occurs (e.g., Vault unlocks, secret deletions, ACL sharing, key revocations), the backend queries the database for the cryptographic hash of the chronologically previous log row. The system constructs a serialized string containing the current event's details and concatenates it with the previous row's hash. This combined string is then hashed using SHA-256 to produce the current row's hash, which is permanently inserted into the database. Any mutation, insertion, or deletion of historical rows instantly invalidates the entire mathematical chain.

### Key Rotation / Versioning in Transit

**Mechanism**:
Cryptographic hygiene dictates that encryption keys must not be used indefinitely. When an administrator rotates a Transit Key, the system generates a fresh 256-bit AES backing key. This new key is wrapped with the DEK and inserted into the database under the same `key_name` but with an incremented `key_version` integer.

The system marks this new key as the active key for all future encryption operations. Because the Vault explicitly encodes the key version into the returned ciphertext string (`vault:vX:...`), older ciphertexts remain perfectly decryptable since the Vault automatically identifies and fetches the correct historical key version.

### ACL / Policy-based Sharing

**Mechanism**:
Instead of relying solely on basic namespace ownership checks (`WHERE owner_email = caller_email`), MiniVault implements a granular Policy-Based Authorization engine.

The system utilizes a relational `acl_grants` table mapping four attributes: `(grantee_email, resource_type, resource_id, permission_level)`. When a user attempts to access a KV secret or Transit key they do not own, the backend intercepts the request and performs an authorization SQL JOIN sub-query against the `acl_grants` table. If a valid grant exists authorizing the specific action, the operation proceeds. This allows users to securely share specific secrets or delegate cryptographic duties without compromising raw credentials or relinquishing primary ownership.

## References

- NIST SP 800-38D — GCM specification
- Argon2 specification and `argon2-cffi` docs
- `cryptography` (Python) library docs
- bcrypt project docs
