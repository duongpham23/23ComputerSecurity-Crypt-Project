# UI/UX & System Requirements for Mini Vault (Monogatari Aesthetic)

## 1. Context & Overview
**Mini Vault** is a secure storage (KV Engine) and Encryption/Signing as a Service (Transit Engine) application. 
The system solves two core problems:
1. **Secure Storage**: Storing secrets (DB passwords, API keys) so data on disk is always encrypted and access-controlled.
2. **Transit Engine**: Allowing applications to encrypt/decrypt or digitally sign data without ever holding the encryption or signing key themselves.

**Design Goal for AI Stitch**: Design a clean, modern, and highly secure Web UI for Mini Vault, *strictly adhering to the Monogatari Series aesthetic defined in `DESIGN.md`*.

## 2. Technical Stack & Architecture Requirements
* **Frontend Framework**: React (JavaScript).
* **UI/Styling Libraries**: **Tailwind CSS** (for rapid, strict geometric utility classes) + **Radix UI** (for accessible, unstyled components that can be sharply customized).
* **State Management**: **Zustand** (for global states like `isVaultLocked`, `isAuthenticated`).
* **Token Storage**: `sessionStorage` (for the 30-minute session token).
* **Backend API Routing**: Endpoints calling the backend must be organized into a dedicated folder and separated into distinct files based on functionality. For example:
  * `/routes/auth.js` (login, register, session management)
  * `/routes/kv.js` (read, write, delete secrets)
  * `/routes/transit.js` (key management, encrypt, decrypt, sign, verify)

## 3. STRICT DESIGN REQUIREMENT
**STRICT REQUIREMENT:** You MUST read and strictly follow the design system, typography (Mincho/Gothic mix), hard-cut motion behaviors, and UI layouts defined in the `DESIGN.md` file before generating any code.
*   **Zero Border Radius:** All UI elements must have completely sharp corners (`0px` radius).
*   **Colors:** Strictly utilize Void Black, Blood Red, Paper White, and Character Accents as defined.
*   **Typography over Iconography:** Rely heavily on high-contrast text and "Flash Screens" for state transitions, rather than standard icons.
*   **Modals:** Any modal used must follow the "Flash Card" component style (e.g., pure black or red background, stark typography, completely sharp edges).

## 4. Functional Requirements

### 4.1. Initialization and Unlock (System-Level)
* **First Run (Init)**: UI must prompt the admin to set a strong Master Passphrase to generate the Data Encryption Key (DEK).
* **Unlock**: On every system restart, the vault defaults to a "locked" state. The UI must block access to KV and Transit features and prompt for the Master Passphrase to unlock the system.
* **Error Handling (`VAULT_LOCKED`)**: If a user encounters a system-locked state during an operation, the UI MUST display a critical Modal blocking the screen. The user must explicitly click a confirmation button. UPON CONFIRMATION, the system will clear their session and redirect them to the `/unlock` screen.

### 4.2. User Authentication (User-Level)
* **Register**: Users provide email, passphrase, and confirm passphrase. UI should indicate passphrase strength.
* **Login**: Users log in with email and passphrase to receive a session token (30-minute expiry).
* **Account Lockout**: After 5 consecutive failed login attempts, the UI must reflect that the account is temporarily locked for exactly 5 minutes.

### 4.3. Secure Storage (KV Engine)
* **Write Secret**: User can input a path (e.g., `secret/<email>/db`) and a JSON payload.
* **Read Secret**: User can retrieve their stored JSON data via the path.
* **Delete Secret**: User can permanently delete a secret.
* **Access Control**: Users can only access paths matching their own email namespace. Unauthorized access attempts must show generic errors (`PERMISSION_DENIED`).

### 4.4. Transit Engine: Encryption & Decryption
* **Named Key Management**: Users can create (with a unique `key_name`), list, and revoke named keys for the purpose of `ENCRYPT_DECRYPT`. 
* **Encrypt**: User inputs raw data (base64) and selects a `key_name`. The UI displays the resulting self-describing ciphertext.
* **Decrypt**: User inputs the ciphertext. The system verifies ownership and returns the decrypted plaintext.
* **Security Constraint**: The actual AES keys are NEVER exposed to the client/UI.

### 4.5. Transit Engine: Sign & Verify
* **Create Signing Key**: Users can generate asymmetric keys (e.g., RSA/ED25519) specifying the algorithm.
* **Sign**: User inputs a message and selects a signing key. The system returns a digital signature.
* **Verify**: User inputs the key name, message, and signature. The UI displays whether the signature is valid (`signature_valid: true/false`).
* **Security Constraint**: The private signing keys are NEVER exposed to the client/UI.

## 5. Non-Functional Requirements & UX/UI Behaviors
* **Security First**: The UI must never display raw encryption keys or private signing keys. 
* **Zero-Knowledge Principle**: Error messages must be generic to prevent attackers from enumerating users, paths, or keys.
* **Frontend Security (Anti-XSS)**: Because the token is stored in `sessionStorage`, the UI is inherently vulnerable to XSS. The frontend MUST rigorously validate and sanitize all user inputs before state updates or API calls. React's default DOM escaping must be strictly maintained, and external HTML injection must be blocked. Input length and type constraints must be enforced on the client side. *(Note: SQL Injection prevention is explicitly delegated to the Backend).*
* **General Error Handling (UX)**: Standard operational errors (e.g., wrong path, typing mistakes) should NOT block the screen with a confirmation modal. Instead, display them as aggressive, sharp-edged **Toast Notifications** (referencing the `dialogue-bar` from DESIGN.md) that auto-dismiss after a few seconds.
* **Critical Error Handling (UX)**: System-level failures (like Token Expiry or `VAULT_LOCKED`) MUST trigger a full-screen, stark Modal requiring user confirmation before redirecting them out of the current view.
* **Session Management**: The UI must handle 30-minute session expirations gracefully via the aforementioned critical modal flow.

## 6. Extra Credit Functions (Optional Features for UI Consideration)
If possible, the UI/UX design can accommodate the following advanced features:
1. **Policy/ACL System**: UI for sharing named keys/secrets across multiple users.
2. **MFA (OTP/TOTP)**: An additional UI step during login.
3. **Shamir's Secret Sharing**: UI for entering multiple key shares.
4. **Key Rotation**: UI indicating key versions for Transit keys.
5. **KV Versioning**: UI to view and restore previous versions of a secret.
6. **Audit Log**: A dashboard view for a tamper-evident audit log.
7. **Public Verification**: Allowing any authenticated user to verify signatures.
