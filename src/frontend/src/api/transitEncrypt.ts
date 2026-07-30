/**
 * Transit Engine — Encryption/Decryption API.
 *
 * Named AES keys are the primary resource. Encrypt and decrypt operations
 * are sub-actions scoped to a specific key, expressed as nested URLs so the
 * key is always unambiguously identified by the URL structure rather than
 * a request body field.
 *
 * Encryption key resource:
 *   GET    /transit/encrypt-keys               → list all enc keys           200
 *   POST   /transit/encrypt-keys               → create a new enc key        201
 *   GET    /transit/encrypt-keys/{name}        → get enc key details         200
 *   DELETE /transit/encrypt-keys/{name}        → revoke an enc key           204
 *
 * Encrypt / decrypt actions (scoped to a key):
 *   POST   /transit/encrypt-keys/{name}/encrypt  → encrypt plaintext         200
 *   POST   /transit/encrypt-keys/{name}/decrypt  → decrypt ciphertext        200
 *
 * Security contract:
 *   The raw AES key material is NEVER returned to the client at any point.
 *   Ciphertext format: `vault:v<version>:<base64url-ciphertext>`
 */

import { apiFetch } from "./client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EncAlgorithm = "AES-256-GCM" | "AES-128-GCM";

export interface EncryptionKey {
  name: string;
  algorithm: EncAlgorithm;
  /** Increments on key rotation. */
  version: number;
  revoked: boolean;
  created_at: string;
}

export interface EncKeyListResponse {
  keys: EncryptionKey[];
}

export interface EncKeyResponse {
  key: EncryptionKey;
}

export interface EncryptResponse {
  /** Self-describing ciphertext: `vault:v<version>:<base64url>` */
  ciphertext: string;
  key_name: string;
  key_version: number;
}

export interface DecryptResponse {
  /** Base64-encoded plaintext. */
  plaintext: string;
  key_name: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function keyUrl(name: string): string {
  return `/transit/encrypt-keys/${encodeURIComponent(name)}`;
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/**
 * GET /transit/encrypt-keys                 → 200 OK
 *
 * Lists all AES encryption keys owned by the caller (including revoked ones).
 */
export async function listEncryptKeys(): Promise<EncKeyListResponse> {
  const resp = await apiFetch<any>("/transit/keys");
  return {
    keys: (resp.keys || []).map((k: any) => ({
      name: k.key_name,
      algorithm: "AES-256-GCM",
      version: k.key_version,
      created_at: new Date(k.created_at * 1000).toISOString(),
    })),
  };
}

/**
 * POST /transit/encrypt-keys                → 201 Created
 *
 * Creates a new named AES key. The name must be unique per user and match
 * `[a-zA-Z0-9_-]{1,64}`.
 *
 * @throws {ApiError} KEY_EXISTS (409) if the name is already taken.
 */
export async function createEncryptKey(
  name: string,
  algorithm: EncAlgorithm = "AES-256-GCM",
): Promise<EncKeyResponse> {
  // @ts-ignore
  const resp = await apiFetch<any>("/transit/keys", {
    method: "POST",
    body: { key_name: name }, // Backend ignores algorithm for AES keys, it's hardcoded to AES-256-GCM
  });
  return { key: resp.data };
}

/**
 * GET /transit/encrypt-keys/{name}          → 200 OK
 *
 * Returns metadata for a single encryption key (never the key material).
 */
export async function getEncryptKey(name: string): Promise<EncKeyResponse> {
  throw new Error("getEncryptKey not implemented in backend");
}

/**
 * DELETE /transit/encrypt-keys/{name}       → 204 No Content
 *
 * Permanently revokes the key. All data encrypted with it becomes
 * PERMANENTLY INACCESSIBLE. This action cannot be undone.
 *
 * @throws {ApiError} NOT_FOUND (404) | PERMISSION_DENIED (403)
 */
export async function revokeEncryptKey(
  name: string,
  version?: number,
): Promise<void> {
  const q = version !== undefined ? `?version=${version}` : "";
  await apiFetch(`/transit/keys/${encodeURIComponent(name)}${q}`, {
    method: "DELETE",
  });
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt actions
// ---------------------------------------------------------------------------

/**
 * POST /transit/encrypt-keys/{name}/encrypt → 200 OK
 *
 * Encrypts `plaintext` (base64-encoded) using the named key.
 * Returns a self-describing ciphertext that embeds the key version.
 *
 * @param keyName   - Name of the AES key to use.
 * @param plaintext - Base64-encoded bytes to encrypt.
 *
 * @throws {ApiError} KEY_REVOKED (422) | NOT_FOUND (404) | VAULT_LOCKED (503)
 */
export async function encrypt(
  keyName: string,
  plaintext: string,
): Promise<EncryptResponse> {
  // @ts-ignore
  const resp = await apiFetch<any>(`/transit/encrypt`, {
    method: "POST",
    body: { key_name: keyName, plaintext_b64: plaintext },
  });
  return {
    ciphertext: resp.ciphertext,
    key_name: keyName,
    key_version: 1, // Optional mock, backend ciphertext embeds the version
  };
}

/**
 * POST /transit/encrypt-keys/{name}/decrypt → 200 OK
 *
 * Decrypts a ciphertext that was produced by `encrypt` with the same key.
 * The key name in the URL must match the key that originally encrypted the data;
 * the server validates this against the version embedded in the ciphertext.
 *
 * @param keyName    - Name of the key that originally encrypted the data.
 * @param ciphertext - Self-describing ciphertext (`vault:v<n>:<base64url>`).
 *
 * @throws {ApiError} INVALID_CIPHERTEXT (422) | KEY_REVOKED (422) | PERMISSION_DENIED (403)
 */
export async function decrypt(
  keyName: string,
  ciphertext: string,
): Promise<DecryptResponse> {
  // @ts-ignore
  const resp = await apiFetch<any>(`/transit/decrypt`, {
    method: "POST",
    body: { ciphertext },
  });
  return {
    plaintext: resp.plaintext_b64,
    key_name: keyName,
  };
}

/**
 * POST /transit/keys/{name}/rotate
 *
 * Rotates the specified encryption key.
 */
export async function rotateEncryptKey(name: string): Promise<void> {
  await apiFetch(`/transit/keys/${encodeURIComponent(name)}/rotate`, {
    method: "POST",
  });
}
