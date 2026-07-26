/**
 * Audit API — tamper-evident event log.
 *
 * Events are immutable, append-only records produced by the server for every
 * security-relevant action. Clients read their own events; admins can query
 * across all users.
 *
 *   GET /audit/events   → paginated collection of AuditEvent resources   200
 *
 * Query parameters (all optional):
 *   page        — 1-based page number          (default: 1)
 *   page_size   — records per page, max 200     (default: 50)
 *   user        — filter by email (admin only)
 *   action      — filter by action type
 *   status      — filter by outcome (SUCCESS | FAILURE | DENIED)
 *   from        — ISO-8601 start timestamp
 *   to          — ISO-8601 end timestamp
 */

import { apiFetch } from "./client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditAction =
  | "VAULT_INIT"
  | "VAULT_UNLOCK"
  | "USER_REGISTER"
  | "USER_LOGIN"
  | "USER_LOGIN_FAIL"
  | "USER_LOGOUT"
  | "SECRET_WRITE"
  | "SECRET_READ"
  | "SECRET_DELETE"
  | "ENCRYPT_KEY_CREATE"
  | "ENCRYPT_KEY_REVOKE"
  | "ENCRYPT"
  | "DECRYPT"
  | "SIGN_KEY_CREATE"
  | "SIGN_KEY_REVOKE"
  | "SIGN"
  | "VERIFY";

export type AuditStatus = "SUCCESS" | "FAILURE" | "DENIED";

export interface AuditEvent {
  /** Server-assigned unique ID for this event. */
  id: string;
  /** ISO-8601 timestamp of when the event occurred. */
  occurred_at: string;
  /** Email of the actor. */
  user: string;
  /** What was attempted. */
  action: AuditAction;
  /** The resource that was targeted (a secret path, a key name, etc.). */
  target: string;
  /** Outcome of the action. */
  status: AuditStatus;
}

export interface AuditEventListResponse {
  events: AuditEvent[];
  /** Total matching events across all pages. */
  total: number;
  page: number;
  page_size: number;
}

// ---------------------------------------------------------------------------
// Query options
// ---------------------------------------------------------------------------

export interface AuditQueryOptions {
  /** 1-based page number. Default: 1. */
  page?: number;
  /** Records per page (max 200). Default: 50. */
  pageSize?: number;
  /** Filter by actor email — admin only; ignored for regular users. */
  user?: string;
  /** Filter to a specific action type. */
  action?: AuditAction;
  /** Filter to a specific outcome. */
  status?: AuditStatus;
  /** ISO-8601 lower bound for `occurred_at`. */
  from?: string;
  /** ISO-8601 upper bound for `occurred_at`. */
  to?: string;
}

// ---------------------------------------------------------------------------
// API function
// ---------------------------------------------------------------------------

/**
 * GET /audit/events                         → 200 OK
 *
 * Returns a paginated collection of AuditEvent resources.
 * Regular users see only their own events.
 * Admin-level callers can omit `user` to retrieve all events system-wide.
 */
export async function listAuditEvents(
  options: AuditQueryOptions = {},
): Promise<AuditEventListResponse> {
  const params: Record<string, string> = {};

  if (options.page !== undefined)     params.page      = String(options.page);
  if (options.pageSize !== undefined) params.page_size = String(options.pageSize);
  if (options.user)                   params.user      = options.user;
  if (options.action)                 params.action    = options.action;
  if (options.status)                 params.status    = options.status;
  if (options.from)                   params.from      = options.from;
  if (options.to)                     params.to        = options.to;

  return apiFetch<AuditEventListResponse>("/audit/events", { params });
}
