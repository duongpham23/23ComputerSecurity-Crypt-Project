/**
 * Transit Engine — Digital Signing/Verification API.
 *
 * Named asymmetric key pairs are the primary resource. Sign and verify
 * operations are sub-actions scoped to a specific key so the key is always
 * identified by the URL, never by a request body field.
 *
 * Signing key resource:
 *   GET    /transit/sign-keys               → list all signing keys          200
 *   POST   /transit/sign-keys               → create a new signing key       201
 *   GET    /transit/sign-keys/{name}        → get signing key details        200
 *   DELETE /transit/sign-keys/{name}        → revoke a signing key           204
 *
 * Sign / verify actions (scoped to a key):
 *   POST   /transit/sign-keys/{name}/sign   → produce a digital signature    200
 *   POST   /transit/sign-keys/{name}/verify → verify a digital signature     200
 *
 * Security contract:
 *   Private key material is NEVER returned to the client.
 *   Signature format: `v<version>:<base64url-signature>`
 */

import { apiFetch } from "./client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SignAlgorithm = "ED25519" | "RSA-2048" | "RSA-4096" | "ECDSA-P256";

export interface SigningKey {
  name: string;
  algorithm: SignAlgorithm;
  /** Increments on key rotation. */
  version: number;
  revoked: boolean;
  created_at: string;
}

export interface SignKeyListResponse {
  keys: SigningKey[];
}

export interface SignKeyResponse {
  key: SigningKey;
}

export interface SignResponse {
  /** Signature string: `v<version>:<base64url-signature>` */
  signature: string;
  key_name: string;
  key_version: number;
}

export interface VerifyResponse {
  /** True when the signature is cryptographically valid. */
  signature_valid: boolean;
  key_name: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function keyUrl(name: string): string {
  return `/transit/sign-keys/${encodeURIComponent(name)}`;
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/**
 * GET /transit/sign-keys                    → 200 OK
 *
 * Lists all signing keys owned by the caller (including revoked ones).
 */
export async function listSignKeys(): Promise<SignKeyListResponse> {
  return apiFetch<SignKeyListResponse>("/transit/sign-keys");
}

/**
 * POST /transit/sign-keys                   → 201 Created
 *
 * Creates a new named asymmetric key pair. The private key is generated and
 * stored encrypted server-side and is never accessible to the client.
 *
 * @throws {ApiError} KEY_EXISTS (409) if the name is already taken.
 */
export async function createSignKey(
  name: string,
  algorithm: SignAlgorithm = "ED25519",
): Promise<SignKeyResponse> {
  return apiFetch<SignKeyResponse>("/transit/sign-keys", {
    method: "POST",
    body: { name, algorithm },
  });
}

/**
 * GET /transit/sign-keys/{name}             → 200 OK
 *
 * Returns metadata for a single signing key (never the private key material).
 */
export async function getSignKey(name: string): Promise<SignKeyResponse> {
  return apiFetch<SignKeyResponse>(keyUrl(name));
}

/**
 * DELETE /transit/sign-keys/{name}          → 204 No Content
 *
 * Permanently revokes the key. Any signatures produced by this key can no
 * longer be verified. This action cannot be undone.
 *
 * @throws {ApiError} NOT_FOUND (404) | PERMISSION_DENIED (403)
 */
export async function revokeSignKey(name: string): Promise<void> {
  await apiFetch(keyUrl(name), { method: "DELETE" });
}

// ---------------------------------------------------------------------------
// Sign / verify actions
// ---------------------------------------------------------------------------

/**
 * POST /transit/sign-keys/{name}/sign       → 200 OK
 *
 * Produces a digital signature for `message` using the named signing key.
 *
 * @param keyName - Name of the key to sign with.
 * @param message - Plaintext message (UTF-8 string).
 *
 * @throws {ApiError} KEY_REVOKED (422) | NOT_FOUND (404) | VAULT_LOCKED (503)
 */
export async function signMessage(
  keyName: string,
  message: string,
): Promise<SignResponse> {
  return apiFetch<SignResponse>(`${keyUrl(keyName)}/sign`, {
    method: "POST",
    body: { message },
  });
}

/**
 * POST /transit/sign-keys/{name}/verify     → 200 OK
 *
 * Verifies `signature` against `message` using the named key.
 * A mismatched signature is a LOGICAL result (`signature_valid: false`),
 * not an HTTP error — the endpoint only throws on infrastructure failures.
 *
 * @param keyName   - Name of the key that produced the signature.
 * @param message   - The original plaintext message.
 * @param signature - Signature to verify (`v<n>:<base64url>`).
 *
 * @throws {ApiError} NOT_FOUND (404) | PERMISSION_DENIED (403) | VAULT_LOCKED (503)
 */
export async function verifySignature(
  keyName: string,
  message: string,
  signature: string,
): Promise<VerifyResponse> {
  return apiFetch<VerifyResponse>(`${keyUrl(keyName)}/verify`, {
    method: "POST",
    body: { message, signature },
  });
}
