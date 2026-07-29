# MiniVault — Secure Storage & Transit Engine

A cryptographic key-value store and transit encryption service inspired by HashiCorp Vault.
It features a robust **FastAPI backend** handling all cryptographic primitives and a modern **React/Vite frontend** for an intuitive User Interface.

Implements Feature 1 (KV Engine) and Feature 2 (Transit Engine) according to the Crypt Project 1 spec, as well as Feature 0 (Vault Initialization and Auth).

## Team Members

- Dang Anh Kiet (23127077)
- Pham Hong Thai Duong (23127355)

## Setup & Installation

The easiest way to run the entire stack (Frontend + Backend) is using Docker Compose.

### Requirements

- Docker & Docker Compose
- pip (for local development & testing)
- Node.js (for local development & testing)

### Run the Application (Recommended)

```bash
docker compose up --build
```

or just run **run_docker.bat**.

- **Frontend Dashboard:** `http://localhost:5173`
- **Backend API:** `http://localhost:8000`

### Local Development (Without Docker)

If you prefer running the services locally:

**1. Backend (Python 3.10+ & pip)**

```bash
cd src/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**2. Frontend (Node.js 20+)**

```bash
cd src/frontend
npm install
npm run dev
```

## Running Tests (Backend)

The project includes a comprehensive test suite covering all security constraints.

```bash
cd src/backend
pip install -r requirements.txt
pytest tests/ -v
```

All 75 tests across KV, Transit, Auth, and Core operations pass successfully.

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

### Additional Features

- **Full UI/UX Interface**: A beautiful frontend dashboard to easily interact with the MiniVault instead of manually calling APIs.

## Documentation

Detailed architectural reports and operational mechanisms can be found in the `docs/report/` directory:

- `docs/report/report.md`

## Demo Video

[Demo Video Link (YouTube)](https://youtu.be/SDzRLVYCQQw)
