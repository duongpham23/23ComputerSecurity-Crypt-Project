/**
 * KV Engine API — Secure Secret Storage.
 *
 * Secrets are identified by a hierarchical path: `secret/<email>/<key>`.
 * The server enforces namespace isolation — each user can only access paths
 * under their own email prefix. Cross-namespace attempts return HTTP 403.
 *
 * Collection & resource endpoints:
 *
 *   GET    /secrets                → list all secret paths for the caller    200
 *   PUT    /secrets/{path}         → create or update a secret               200 / 201
 *   GET    /secrets/{path}         → read a single secret                    200
 *   DELETE /secrets/{path}         → permanently destroy a secret            204
 *
 * Path encoding:
 *   The path is passed as a URL path segment. Slashes within the path are
 *   preserved (the server uses a catch-all path param). The '@' in email
 *   addresses is valid in a URL path and does not require encoding.
 *
 * HTTP method rationale:
 *   PUT is used for write (not POST) because the client supplies the full
 *   resource identifier (the path). PUT is idempotent: writing the same
 *   value twice has no additional effect.
 */

import { apiFetch } from "./client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SecretResource {
  /** Full path, e.g. `secret/alice@example.com/db`. */
  path: string;
  /** Decrypted JSON payload — only returned on GET /secrets/{path}. */
  value: Record<string, unknown>;
  /** ISO-8601 last-modified timestamp. */
  updated_at: string;
}

export interface SecretListItem {
  /** Path only — values are never included in list responses. */
  path: string;
  updated_at: string;
}

export interface SecretListResponse {
  secrets: SecretListItem[];
}

export interface SecretWriteResponse {
  path: string;
  updated_at: string;
  /** True when the secret was created for the first time (HTTP 201). */
  created: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Builds the resource URL for a given secret path. */
function secretUrl(path: string): string {
  // The path already contains slashes (e.g. "secret/alice@example.com/db").
  // Joining directly gives the correct hierarchical URL segment.
  return `/secrets/${path}`;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

/**
 * GET /secrets
 *
 * Returns a list of all secret paths owned by the caller.
 * Values are never included — use `readSecret` to fetch a specific value.
 */
export async function listSecrets(): Promise<SecretListResponse> {
  return apiFetch<SecretListResponse>("/secrets");
}

/**
 * PUT /secrets/{path}                      → 200 OK (update) | 201 Created (new)
 *
 * Creates or fully replaces the secret at the given path.
 * Idempotent: calling with the same payload twice has the same effect as once.
 *
 * @param path  - Full secret path within the caller's namespace.
 * @param value - Arbitrary JSON object. The server encrypts this at rest.
 */
export async function writeSecret(
  path: string,
  value: Record<string, unknown>,
): Promise<SecretWriteResponse> {
  return apiFetch<SecretWriteResponse>(secretUrl(path), {
    method: "PUT",
    body: { value },
  });
}

/**
 * GET /secrets/{path}                      → 200 OK
 *
 * Returns the decrypted secret at the given path.
 *
 * @throws {ApiError} NOT_FOUND (404) if the path does not exist.
 * @throws {ApiError} PERMISSION_DENIED (403) if the path is outside the caller's namespace.
 */
export async function readSecret(path: string): Promise<SecretResource> {
  return apiFetch<SecretResource>(secretUrl(path));
}

/**
 * DELETE /secrets/{path}                   → 204 No Content
 *
 * Permanently destroys the secret. This is irreversible.
 *
 * @throws {ApiError} NOT_FOUND (404) if the path does not exist.
 * @throws {ApiError} PERMISSION_DENIED (403) for cross-namespace access.
 */
export async function deleteSecret(path: string): Promise<void> {
  await apiFetch(secretUrl(path), { method: "DELETE" });
}
