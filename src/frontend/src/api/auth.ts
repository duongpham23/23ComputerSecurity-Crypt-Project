/**
 * Auth API — vault lifecycle + user session management.
 *
 *   GET  /vault          → current status (initialized, locked)
 *   POST /vault/init     → first-run: set passphrase, generate DEK   [controller]
 *   POST /vault/unlock   → subsequent starts: derive DEK from passphrase [controller]
 *   POST /vault/lock     → seal vault explicitly, unloads DEK [controller]
 *
 * User lifecycle:
 *   POST   /users                  → register (creates a User resource)   → 201
 *   POST   /auth/sessions          → login (creates a Session resource)    → 201
 *   DELETE /auth/sessions/current  → logout (destroys the current session) → 204
 */

import { apiFetch, setToken, clearToken, setUserLocal } from "./client";

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

export interface VaultStatusResponse {
  /** Whether the vault has ever been initialized with a master passphrase. */
  initialized: boolean;
  /** Whether the DEK is currently loaded in memory (vault is usable). */
  locked: boolean;
}

export interface UserResource {
  email: string;
  created_at: string;
}

export interface RegisterResponse {
  /** 201 Created — user resource just created. */
  user: UserResource;
}

export interface SessionResource {
  /** Bearer token for the 30-minute session. */
  token: string;
  /** ISO-8601 expiry timestamp. */
  expires_at: string;
  user: Pick<UserResource, "email">;
}

// ---------------------------------------------------------------------------
// Vault operations  (no auth token required)
// ---------------------------------------------------------------------------

/**
 * GET /vault
 *
 * Returns the current vault state. Called on every app start to decide
 * which screen to show (init / unlock / login).
 */
export async function vaultStatus(): Promise<VaultStatusResponse> {
  return apiFetch<VaultStatusResponse>("/vault", { skipAuth: true });
}

/**
 * POST /vault/init
 *
 * Controller endpoint — one-time first-run setup.
 * Sets the master passphrase and derives the DEK; the plaintext DEK is
 * never persisted and lives only in server memory until the next restart.
 */
export async function vaultInit(passphrase: string): Promise<void> {
  await apiFetch("/vault/init", {
    method: "POST",
    skipAuth: true,
    body: { passphrase },
  });
}

/**
 * POST /vault/unlock
 *
 * Controller endpoint — every restart after the first.
 * Re-derives the DEK from the passphrase and loads it into memory,
 * transitioning the vault from locked → unlocked.
 */
export async function vaultUnlock(passphrase: string): Promise<void> {
  await apiFetch("/vault/unlock", {
    method: "POST",
    skipAuth: true,
    body: { passphrase },
  });
}

// ---------------------------------------------------------------------------
// Audit resource
// ---------------------------------------------------------------------------

export interface AuditEvent {
  id: number;
  action: string;
  actor_email: string;
  resource: string;
  detail: any;
  result: string;
  timestamp: string;
}

export interface AuditListResponse {
  events: AuditEvent[];
  total: number;
}

/**
 * GET /audit/events
 *
 * Fetches the 50 most recent audit logs. Protected by VaultLocked state.
 */
export async function listAuditEvents(): Promise<AuditListResponse> {
  return apiFetch<AuditListResponse>("/audit/events", { skipAuth: true });
}

// ---------------------------------------------------------------------------
// User resource
// ---------------------------------------------------------------------------

/**
 * POST /users                              → 201 Created
 *
 * Creates a new User resource. Passphrase is hashed server-side (bcrypt).
 * Returns a generic envelope — never reveals whether the email already exists.
 */
export async function register(
  email: string,
  passphrase: string,
): Promise<RegisterResponse> {
  return apiFetch<RegisterResponse>("/users", {
    method: "POST",
    skipAuth: true,
    body: { email, passphrase },
  });
}

// ---------------------------------------------------------------------------
// Session resource
// ---------------------------------------------------------------------------

/**
 * POST /auth/sessions                      → 201 Created
 *
 * Creates a new Session: authenticates credentials and returns a 30-minute
 * Bearer token. The token is stored in sessionStorage automatically.
 *
 * After 5 consecutive failures the server returns HTTP 429 + ACCOUNT_LOCKED.
 */
export async function login(
  email: string,
  passphrase: string,
): Promise<SessionResource> {
  const data = await apiFetch<SessionResource>("/auth/sessions", {
    method: "POST",
    skipAuth: true,
    body: { email, passphrase },
  });
  setToken(data.token);
  setUserLocal(data.user);
  return data;
}

/**
 * DELETE /auth/sessions/current            → 204 No Content
 *
 * Destroys the current Session server-side and clears the local token.
 * Safe to call even if the token has already expired.
 */
export async function logout(): Promise<void> {
  try {
    await apiFetch("/auth/sessions/current", { method: "DELETE" });
  } finally {
    clearToken();
  }
}
