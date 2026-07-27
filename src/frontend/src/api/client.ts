/**
 * Base API client for Mini Vault.
 *
 * All API modules build on top of `apiFetch`. It handles:
 *  - Attaching the session token from sessionStorage
 *  - Parsing JSON responses
 *  - Normalizing backend error envelopes into typed `ApiError` instances
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const BASE_URL: string =
  ((import.meta as any).env?.VITE_API_BASE_URL as string | undefined) ?? "/api/v1";

/** Key used to store the session token in sessionStorage. */
export const SESSION_TOKEN_KEY = "mini_vault_token";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/**
 * Typed error codes that the UI reacts to beyond a generic toast.
 *
 * - `VAULT_LOCKED`      → show blocking critical modal, redirect to /unlock
 * - `SESSION_EXPIRED`   → show blocking critical modal, clear session, redirect to /login
 * - `ACCOUNT_LOCKED`    → show toast with remaining lockout time
 * - `PERMISSION_DENIED` → show generic "access denied" toast
 */
export type ApiErrorCode =
  | "VAULT_LOCKED"
  | "SESSION_EXPIRED"
  | "ACCOUNT_LOCKED"
  | "PERMISSION_DENIED"
  | "NOT_FOUND"
  | "KEY_REVOKED"
  | "KEY_EXISTS"
  | "INVALID_CIPHERTEXT"
  | "SIGNATURE_INVALID"
  | "VALIDATION_ERROR"
  | "NETWORK_ERROR"
  | "UNKNOWN_ERROR";

export class ApiError extends Error {
  constructor(
    /** Machine-readable error code for programmatic handling in the UI. */
    public readonly code: ApiErrorCode,
    message: string,
    /** HTTP status code, or 0 for network-level failures. */
    public readonly status: number,
    /** Raw response body from the server, if available. */
    public readonly detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

export function getToken(): string | null {
  return sessionStorage.getItem(SESSION_TOKEN_KEY);
}

export function getUserLocal(): { email: string } | null {
  const u = sessionStorage.getItem("mini_vault_user");
  return u ? JSON.parse(u) : null;
}

export function setUserLocal(user: { email: string }): void {
  sessionStorage.setItem("mini_vault_user", JSON.stringify(user));
}

export function setToken(token: string): void {
  sessionStorage.setItem(SESSION_TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
  sessionStorage.removeItem("mini_vault_user");
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

interface FetchOptions {
  method?: HttpMethod;
  /** JSON-serialisable request body. Automatically sets Content-Type. */
  body?: unknown;
  /** Additional query parameters appended to the URL. */
  params?: Record<string, string>;
  /**
   * When `true` the request is sent without an Authorization header.
   * Used for endpoints that don't require authentication (login, register, etc.).
   */
  skipAuth?: boolean;
}

/**
 * Core fetch wrapper used by every API module.
 *
 * @throws {ApiError} on any non-2xx response or network failure.
 */
export async function apiFetch<T = unknown>(
  path: string,
  options: FetchOptions = {},
): Promise<T> {
  const { method = "GET", body, params, skipAuth = false } = options;

  // Build URL
  const url = new URL(`${BASE_URL}${path}`, window.location.origin);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
  }

  // Build headers
  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (!skipAuth) {
    const token = getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  // Execute request
  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    throw new ApiError(
      "NETWORK_ERROR",
      "NETWORK FAILURE — CHECK YOUR CONNECTION",
      0,
      err,
    );
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  // Parse body
  let data: unknown;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  // 2xx — success
  if (response.ok) {
    return data as T;
  }

  // Error — map to ApiError
  const errorPayload = data as {
    code?: string;
    detail?: string | any;
    message?: string;
    lock_expires_at?: string;
  } | null;

  let serverCode = errorPayload?.code?.toUpperCase() ?? "";
  let serverMessage = errorPayload?.message ?? response.statusText;
  let apiDetail = errorPayload;

  if (errorPayload?.detail) {
    if (typeof errorPayload.detail === "string") {
      serverMessage = errorPayload.detail;
      if (!serverCode) serverCode = errorPayload.detail.toUpperCase();
    } else if (typeof errorPayload.detail === "object") {
      serverCode = errorPayload.detail.code?.toUpperCase() ?? serverCode;
      serverMessage = errorPayload.detail.message ?? errorPayload.detail.detail ?? serverCode;
      apiDetail = errorPayload.detail;
    }
  }

  // Map HTTP status / server codes to our typed ApiErrorCode
  let code: ApiErrorCode;
  if (serverCode === "VAULT_LOCKED" || response.status === 423) {
    code = "VAULT_LOCKED";
  } else if (response.status === 401) {
    code = "SESSION_EXPIRED";
  } else if (serverCode === "ACCOUNT_LOCKED") {
    code = "ACCOUNT_LOCKED";
  } else if (response.status === 403 || serverCode === "PERMISSION_DENIED") {
    code = "PERMISSION_DENIED";
  } else if (response.status === 404 || serverCode === "NOT_FOUND") {
    code = "NOT_FOUND";
  } else if (serverCode === "KEY_REVOKED") {
    code = "KEY_REVOKED";
  } else if (serverCode === "KEY_EXISTS") {
    code = "KEY_EXISTS";
  } else if (serverCode === "INVALID_CIPHERTEXT") {
    code = "INVALID_CIPHERTEXT";
  } else if (serverCode === "SIGNATURE_INVALID") {
    code = "SIGNATURE_INVALID";
  } else if (response.status === 422 || serverCode === "VALIDATION_ERROR") {
    code = "VALIDATION_ERROR";
  } else {
    code = "UNKNOWN_ERROR";
  }

  throw new ApiError(code, String(serverMessage), response.status, apiDetail);
}
