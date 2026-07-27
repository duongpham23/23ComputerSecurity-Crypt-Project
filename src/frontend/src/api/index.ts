/**
 * Mini Vault — Frontend API Layer
 *
 * Import from this barrel for a single entry point:
 *
 *   import { login, logout, vaultStatus }          from "@/api";
 *   import { writeSecret, readSecret, listSecrets } from "@/api";
 *   import { encrypt, decrypt, listEncryptKeys }   from "@/api";
 *   import { signMessage, verifySignature }        from "@/api";
 *   import { listAuditEvents }                     from "@/api";
 *   import { ApiError }                            from "@/api";
 *
 * Or import a specific module for better tree-shaking:
 *
 *   import { login }        from "@/api/auth";
 *   import { writeSecret }  from "@/api/kv";
 *   import { encrypt }      from "@/api/transitEncrypt";
 */

// ── Base client ─────────────────────────────────────────────────────────────
export {
  ApiError,
  getToken,
  setToken,
  clearToken,
  SESSION_TOKEN_KEY,
  BASE_URL,
} from "./client";
export type { ApiErrorCode } from "./client";

// ── Vault lifecycle + Auth ───────────────────────────────────────────────────
export {
  vaultStatus,
  vaultInit,
  vaultUnlock,
  register,
  login,
  logout,
} from "./auth";
export type {
  VaultStatusResponse,
  UserResource,
  RegisterResponse,
  SessionResource,
} from "./auth";

// ── KV Engine — Secrets ──────────────────────────────────────────────────────
export {
  listSecrets,
  writeSecret,
  readSecret,
  deleteSecret,
} from "./kv";
export type {
  SecretResource,
  SecretListItem,
  SecretListResponse,
  SecretWriteResponse,
} from "./kv";

// ── Transit — Encryption / Decryption ───────────────────────────────────────
export {
  listEncryptKeys,
  createEncryptKey,
  getEncryptKey,
  revokeEncryptKey,
  encrypt,
  decrypt,
} from "./transitEncrypt";
export type {
  EncAlgorithm,
  EncryptionKey,
  EncKeyListResponse,
  EncKeyResponse,
  EncryptResponse,
  DecryptResponse,
} from "./transitEncrypt";

// ── Transit — Sign / Verify ──────────────────────────────────────────────────
export {
  listSignKeys,
  createSignKey,
  getSignKey,
  revokeSignKey,
  signMessage,
  verifySignature,
} from "./transitSign";
export type {
  SignAlgorithm,
  SigningKey,
  SignKeyListResponse,
  SignKeyResponse,
  SignResponse,
  VerifyResponse,
} from "./transitSign";

// ── Audit Events ─────────────────────────────────────────────────────────────
export { listAuditEvents } from "./audit";
export type {
  AuditEvent,
  AuditEventListResponse,
  AuditAction,
  AuditStatus,
  AuditQueryOptions,
} from "./audit";
