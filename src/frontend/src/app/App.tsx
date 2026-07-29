import React, { useState, useEffect, useCallback } from "react";
import { setToken, ApiError } from "@/api/client";
import { useUI } from "@/context/UIContext";
import { vaultInit, vaultUnlock, register, login, vaultStatus } from "@/api/auth";
import { writeSecret, readSecret, deleteSecret, listSecrets, readSecretVersion } from "@/api/kv";
import { createEncryptKey, encrypt, decrypt, listEncryptKeys, revokeEncryptKey, rotateEncryptKey } from "@/api/transitEncrypt";
import { grantAccess } from "@/api/acl";
import { createSignKey, signMessage, verifySignature, listSignKeys, revokeSignKey } from "@/api/transitSign";
import { listAuditEvents, AuditEvent } from "@/api/auth";

// ─── Types ─────────────────────────────────────────────────────────────────────

// Screen and tab routing is now handled by react-router (see src/router.tsx)

export interface Toast { id: string; message: string; type: "error" | "success" | "info"; }
export interface CritModal { title: string; body: string; confirmLabel: string; variant: "black" | "red"; onConfirm: () => void; }
export interface KVEntry { path: string; value: string; ts: string; is_shared?: boolean; }
export interface VKey { name: string; kind: "enc" | "sign"; algorithm: string; version: number; revoked: boolean; ts: string; }
export interface User { email: string; }
export interface AuditRow { ts: string; user: string; action: string; target: string; status: "OK" | "DENIED" | "FAIL"; }

// ─── Design Tokens — Light Mode ────────────────────────────────────────────────

export const C = {
  // surfaces
  appBg: "#F4F1EA",       // warm paper — overall background
  surface: "#FDFCFA",     // cards, panels
  surfaceAlt: "#EDE9E0",  // sidebar, alternate rows
  border: "#C8C3B8",      // dividers
  borderStrong: "#8A8378",// focused / strong dividers

  // text
  text: "#111111",
  subdued: "#666666",
  inverse: "#F8F8F8",

  // accents (unchanged — these ARE the brand)
  red: "#CC0000",
  yellow: "#FFCC00",
  gold: "#FFD700",
  purple: "#7851A9",
  green: "#2E8B57",
  blue: "#003366",

  // hard offset shadow color
  shadow: "#000000",
} as const;

export const MINCHO = "'Shippori Mincho', 'Noto Serif JP', serif";
export const GOTHIC = "'Noto Sans JP', sans-serif";

// Blueprint grid — same as HTML, now on paper surface
export const PAPER_BG: React.CSSProperties = {
  backgroundColor: C.appBg,
  backgroundImage: `linear-gradient(${C.blue}22 1px, transparent 1px), linear-gradient(90deg, ${C.blue}22 1px, transparent 1px)`,
  backgroundSize: "64px 64px",
  backgroundPosition: "center",
};

// Form card: white surface, black hard-offset shadow (Monogatari print style)
export const FORM_SHADOW: React.CSSProperties = {
  backgroundColor: C.surface,
  boxShadow: `16px 16px 0px 0px ${C.shadow}`,
};

// ─── Helpers ───────────────────────────────────────────────────────────────────

export function sanitize(s: string) {
  return s.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" }[c] ?? c));
}
export function isEmail(s: string) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 256; }
export function isKeyName(s: string) { return /^[a-zA-Z0-9_-]{1,64}$/.test(s); }
export function isValidPath(p: string, email?: string) {
  const validFormat = /^[a-zA-Z0-9/_@.-]{1,256}$/.test(p) && p.startsWith("secret/");
  if (!email) return validFormat;
  return validFormat && p.startsWith(`secret/${email}/`);
}

export function passStrength(p: string) {
  let s = 0;
  if (p.length >= 12) s++; if (p.length >= 20) s++;
  if (/[A-Z]/.test(p)) s++; if (/[0-9]/.test(p)) s++; if (/[^A-Za-z0-9]/.test(p)) s++;
  const labels = ["WEAK", "WEAK", "FAIR", "STRONG", "STRONG", "VERY STRONG"];
  const colors = [C.red, C.red, C.yellow, C.green, C.green, C.gold];
  return { score: s, label: labels[s], color: colors[s] };
}

export function uid() { return Math.random().toString(36).slice(2); }

// ─── Flash Screen (stays black/red — cinematic takeover) ───────────────────────

export function FlashScreen({ text, variant, onDone }: { text: string; variant: "black" | "red"; onDone: () => void }) {
  useEffect(() => { const t = setTimeout(onDone, 1500); return () => clearTimeout(t); }, [onDone]);
  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center text-center"
      style={{ padding: 64, backgroundColor: variant === "red" ? C.red : "#000000" }}>
      <p style={{ fontFamily: MINCHO, fontSize: 72, fontWeight: 700, lineHeight: 1, letterSpacing: 2, textTransform: "uppercase", color: variant === "red" ? "#000000" : C.inverse }}>
        {text}
      </p>
    </div>
  );
}

// ─── Critical Modal ────────────────────────────────────────────────────────────

export function CritModalOverlay({ modal, onClose }: { modal: CritModal; onClose: () => void }) {
  const isRed = modal.variant === "red";
  return (
    <div className="fixed inset-0 z-[150] flex items-center justify-center" style={{ backgroundColor: "rgba(244,241,234,0.88)" }}>
      <div style={{
        width: "100%", maxWidth: 600, padding: 64,
        backgroundColor: isRed ? C.red : C.surface,
        boxShadow: `16px 16px 0px 0px ${isRed ? C.shadow : C.red}`,
        border: isRed ? "none" : `2px solid ${C.red}`,
      }}>
        <p style={{ fontFamily: MINCHO, fontSize: 56, fontWeight: 700, lineHeight: 1.1, letterSpacing: 1.5, color: isRed ? "#000" : C.red, marginBottom: 32 }}>
          {modal.title}
        </p>
        <p style={{ fontFamily: GOTHIC, fontSize: 16, lineHeight: 1.6, color: isRed ? "#000" : C.text, marginBottom: 48 }}>
          {modal.body}
        </p>
        <div className="flex gap-4">
          <HoverBtn bg={isRed ? "#000" : C.red} color={isRed ? C.inverse : "#000"} onClick={() => { modal.onConfirm(); onClose(); }}>
            {modal.confirmLabel}
          </HoverBtn>
          <HoverBtn bg="transparent" color={isRed ? "#000" : C.subdued} border={`2px solid ${isRed ? "#000" : C.border}`} onClick={onClose}>
            CANCEL
          </HoverBtn>
        </div>
      </div>
    </div>
  );
}

// ─── HoverBtn ─────────────────────────────────────────────────────────────────

export function HoverBtn({ children, onClick, bg, color, border, disabled, fullWidth }: {
  children: React.ReactNode; onClick: () => void;
  bg: string; color: string; border?: string;
  disabled?: boolean; fullWidth?: boolean;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button onClick={onClick} disabled={disabled}
      onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}
      style={{
        fontFamily: GOTHIC, fontSize: 18, fontWeight: 900, letterSpacing: 2, textTransform: "uppercase",
        padding: "16px 32px", cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.3 : 1, width: fullWidth ? "100%" : undefined,
        border: border ?? "none", borderRadius: 0,
        backgroundColor: hovered && !disabled ? C.yellow : bg,
        color: hovered && !disabled ? "#000" : color,
      }}>
      {children}
    </button>
  );
}

// ─── Toast ─────────────────────────────────────────────────────────────────────

export function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  useEffect(() => { const t = setTimeout(() => onDismiss(toast.id), 4000); return () => clearTimeout(t); }, [toast.id, onDismiss]);
  const accent = toast.type === "error" ? C.red : toast.type === "success" ? C.green : C.purple;
  return (
    <div className="flex items-start gap-3 mb-2 cursor-pointer" onClick={() => onDismiss(toast.id)}
      style={{ backgroundColor: C.surface, borderLeft: `8px solid ${accent}`, padding: "12px 20px", maxWidth: 420, boxShadow: `4px 4px 0 ${C.shadow}` }}>
      <span style={{ fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 2, color: accent, flexShrink: 0, paddingTop: 2 }}>
        {toast.type === "error" ? "ERROR" : toast.type === "success" ? "OK" : "INFO"}
      </span>
      <span style={{ fontFamily: GOTHIC, fontSize: 13, lineHeight: 1.6, color: C.text }}>{toast.message}</span>
    </div>
  );
}

export function ToastStack({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: string) => void }) {
  if (!toasts.length) return null;
  return (
    <div className="fixed bottom-20 right-6 z-[120] flex flex-col items-end">
      {toasts.map((t) => <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />)}
    </div>
  );
}

// ─── Auth screen wrapper — light header/footer, paper+grid canvas ──────────────

export function AuthCanvas({ children, topRight, lockedBar }: { children: React.ReactNode; topRight?: React.ReactNode; lockedBar?: boolean }) {
  return (
    <div className="flex flex-col" style={{ height: "100vh" }}>
      {/* Light top bar */}
      <div className="flex-shrink-0 flex items-center justify-between px-8"
        style={{ height: 64, backgroundColor: C.surface, borderBottom: lockedBar ? `2px solid ${C.red}` : `2px solid ${C.shadow}` }}>
        <div className="flex items-center gap-4">
          <span style={{ fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 4, color: C.red }}>MINI VAULT</span>
          {lockedBar && (
            <>
              <div style={{ width: 1, height: 16, backgroundColor: C.border }} />
              <div className="flex items-center gap-2">
                <div style={{ width: 8, height: 8, backgroundColor: C.red }} />
                <span style={{ fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 2, color: C.red }}>VAULT LOCKED</span>
              </div>
            </>
          )}
        </div>
        {topRight}
      </div>

      {/* Paper + blueprint grid canvas */}
      <div className="flex-1 flex items-center justify-center overflow-hidden" style={{ ...PAPER_BG }}>
        {children}
      </div>

      {/* Light bottom bar */}
      <div style={{ height: 64, backgroundColor: C.surface, borderTop: `8px solid ${C.red}`, flexShrink: 0 }} />
    </div>
  );
}

/** Black card with red hard-offset shadow — sits on paper canvas */
export function FormCard({ children, width = 560 }: { children: React.ReactNode; width?: number }) {
  return (
    <div style={{
      backgroundColor: "#000000",
      boxShadow: `16px 16px 0px 0px ${C.red}`,
      padding: "64px",
      width,
      maxWidth: "92vw",
      position: "relative",
      zIndex: 10,
    }}>
      {children}
    </div>
  );
}

// ─── Form inputs ───────────────────────────────────────────────────────────────

export function VInput({ label, value, onChange, type = "text", placeholder = "", maxLength = 512 }: {
  label: string; value: string; onChange: (v: string) => void;
  type?: string; placeholder?: string; maxLength?: number;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <div style={{ marginBottom: 32, display: "flex", flexDirection: "column", gap: 8 }}>
      <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1 }}>
        {label}
      </label>
      <input
        type={type} value={value} onChange={(e) => onChange(e.target.value.slice(0, maxLength))}
        placeholder={placeholder} autoComplete="off"
        onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
        style={{
          backgroundColor: focused ? "rgba(204,0,0,0.06)" : "transparent",
          border: `2px solid ${focused ? C.red : C.border}`,
          color: C.text, padding: 16,
          fontFamily: GOTHIC, fontSize: 16, outline: "none", borderRadius: 0,
          caretColor: C.red, width: "100%", boxSizing: "border-box",
        }}
      />
    </div>
  );
}

export function VTextarea({ label, value, onChange, placeholder = "", rows = 4, accent = C.red }: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; rows?: number; accent?: string;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <div style={{ marginBottom: 32, display: "flex", flexDirection: "column", gap: 8 }}>
      <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1 }}>
        {label}
      </label>
      <textarea
        value={value} onChange={(e) => onChange(e.target.value.slice(0, 8192))}
        placeholder={placeholder} rows={rows}
        onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
        style={{
          backgroundColor: focused ? "rgba(204,0,0,0.06)" : "transparent",
          border: `2px solid ${focused ? accent : C.border}`,
          color: C.text, padding: 16,
          fontFamily: GOTHIC, fontSize: 16, outline: "none", borderRadius: 0,
          caretColor: accent, resize: "none", width: "100%", boxSizing: "border-box",
        }}
      />
    </div>
  );
}

export function StrengthBar({ passphrase }: { passphrase: string }) {
  if (!passphrase) return null;
  const { score, label, color } = passStrength(passphrase);
  return (
    <div style={{ marginTop: -24, marginBottom: 24, display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{ flex: 1, height: 2, backgroundColor: C.border }}>
        <div style={{ height: 2, width: `${(score / 5) * 100}%`, backgroundColor: color }} />
      </div>
      <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color }}>{label}</span>
    </div>
  );
}

export function BtnLink({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}
      style={{ background: "transparent", color: hovered ? C.text : C.subdued, fontFamily: GOTHIC, fontSize: 14, border: "none", cursor: "pointer", textDecoration: "underline", marginTop: 16, padding: 0 }}>
      {children}
    </button>
  );
}

// Dark input — used by auth screens (black background)
export function DInput({ label, value, onChange, type = "text", placeholder = "", maxLength = 512 }: {
  label: string; value: string; onChange: (v: string) => void;
  type?: string; placeholder?: string; maxLength?: number;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <div style={{ marginBottom: 24, display: "flex", flexDirection: "column", gap: 8 }}>
      <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1 }}>
        {label}
      </label>
      <input
        type={type} value={value} onChange={(e) => onChange(e.target.value.slice(0, maxLength))}
        placeholder={placeholder} autoComplete="off"
        onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
        style={{
          backgroundColor: focused ? "rgba(204,0,0,0.10)" : "transparent",
          border: `1px solid ${focused ? C.red : "#333"}`,
          color: "#F8F8F8", padding: 16,
          fontFamily: GOTHIC, fontSize: 16, outline: "none", borderRadius: 0,
          caretColor: C.red, width: "100%", boxSizing: "border-box",
        }}
      />
    </div>
  );
}

export function DStrengthBar({ passphrase }: { passphrase: string }) {
  if (!passphrase) return null;
  const { score, label, color } = passStrength(passphrase);
  return (
    <div style={{ marginTop: -16, marginBottom: 24, display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{ flex: 1, height: 1, backgroundColor: "#222" }}>
        <div style={{ height: 1, width: `${(score / 5) * 100}%`, backgroundColor: color }} />
      </div>
      <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color }}>{label}</span>
    </div>
  );
}

// ─── Shared auth heading — "STATE: LABEL" pattern from the image ───────────────

export function AuthHeading({ state, label }: { state: string; label: string }) {
  return (
    <p style={{ fontFamily: MINCHO, fontSize: 40, fontWeight: 700, lineHeight: 1.2, letterSpacing: 1, color: "#F8F8F8", marginBottom: 48 }}>
      {state}: <span style={{ color: C.red }}>{label}</span>
    </p>
  );
}

// ─── Init Screen ───────────────────────────────────────────────────────────────

export function InitScreen({ onInit, addToast, showFlash }: {
  onInit: () => void; addToast: (m: string, t: Toast["type"]) => void;
  showFlash: (text: string, v: "black" | "red", cb?: () => void) => void;
}) {
  const [pass, setPass] = useState(""); const [conf, setConf] = useState("");
  async function handle() {
    if (pass.length < 12) { addToast("PASSPHRASE MUST BE AT LEAST 12 CHARACTERS", "error"); return; }
    if (pass !== conf) { addToast("PASSPHRASES DO NOT MATCH", "error"); return; }
    try {
      await vaultInit(pass);
      showFlash("INITIALIZING", "black", () => showFlash("VAULT SEALED", "red", onInit));
    } catch (err: any) {
      addToast(err.message, "error");
    }
  }
  return (
    <AuthCanvas>
      <FormCard>
        <AuthHeading state="STATE" label="FIRST RUN" />
        <DInput label="Master Passphrase" value={pass} onChange={setPass} type="password" placeholder="ENTER STRONG PASSPHRASE" />
        <DStrengthBar passphrase={pass} />
        <DInput label="Confirm Passphrase" value={conf} onChange={setConf} type="password" placeholder="REPEAT PASSPHRASE" />
        <HoverBtn bg={C.red} color="#000" onClick={handle} fullWidth>INITIALIZE VAULT</HoverBtn>
      </FormCard>
    </AuthCanvas>
  );
}

// ─── Unlock Screen ─────────────────────────────────────────────────────────────

export function UnlockScreen({ onUnlock, addToast, showFlash }: {
  onUnlock: () => void; addToast: (m: string, t: Toast["type"]) => void;
  showFlash: (text: string, v: "black" | "red", cb?: () => void) => void;
}) {
  const [pass, setPass] = useState("");
  async function handle() {
    if (!pass) { addToast("PASSPHRASE REQUIRED", "error"); return; }
    try {
      await vaultUnlock(pass);
      showFlash("UNLOCKING", "black", () => showFlash("ACCESS GRANTED", "red", onUnlock));
    } catch (err: any) {
      addToast(err.message, "error");
    }
  }
  return (
    <AuthCanvas lockedBar>
      <FormCard>
        <AuthHeading state="STATE" label="LOCKED" />
        <DInput label="Master Passphrase" value={pass} onChange={setPass} type="password" placeholder="ENTER TO DECRYPT DEK" />
        <HoverBtn bg={C.red} color="#000" onClick={handle} fullWidth>UNLOCK VAULT</HoverBtn>
      </FormCard>
    </AuthCanvas>
  );
}

// ─── Login Screen ──────────────────────────────────────────────────────────────

export function LoginScreen({ onLogin, onGoRegister, addToast, showFlash }: {
  onLogin: (u: User) => void; onGoRegister: () => void;
  addToast: (m: string, t: Toast["type"]) => void;
  showFlash: (text: string, v: "black" | "red", cb?: () => void) => void;
}) {
  const [email, setEmail] = useState(""); const [pass, setPass] = useState("");
  const [attempts, setAttempts] = useState(0); const [lockedUntil, setLockedUntil] = useState<Date | null>(null);
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    if (!lockedUntil) return;
    const id = setInterval(() => {
      const r = Math.max(0, Math.ceil((lockedUntil.getTime() - Date.now()) / 1000));
      setRemaining(r);
      if (r === 0) { setLockedUntil(null); setAttempts(0); clearInterval(id); }
    }, 1000);
    return () => clearInterval(id);
  }, [lockedUntil]);

  const locked = !!lockedUntil;

  async function handle() {
    if (locked) { addToast(`ACCOUNT LOCKED — ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")} REMAINING`, "error"); return; }
    if (!isEmail(email)) { addToast("INVALID EMAIL FORMAT", "error"); return; }
    if (!pass) { addToast("PASSPHRASE REQUIRED", "error"); return; }
    try {
      const st = await vaultStatus();
      if (!st.initialized || st.locked) {
        addToast("VAULT LOCKED — PLEASE UNLOCK VIA /admin", "error");
        return;
      }
    } catch {
      addToast("VAULT LOCKED — PLEASE UNLOCK VIA /admin", "error");
      return;
    }

    try {
      const data = await login(email, pass);
      setAttempts(0);
      showFlash("ACCESS GRANTED", "red", () => onLogin({ email: data.user.email }));
    } catch (err: any) {
      if (err instanceof ApiError && err.code === "ACCOUNT_LOCKED") {
        // @ts-ignore
        setLockedUntil(new Date(err.detail?.lock_expires_at ? err.detail.lock_expires_at * 1000 : Date.now() + 300000));
        setRemaining(300);
        showFlash("ACCOUNT LOCKED", "red");
      } else {
        const next = attempts + 1;
        setAttempts(next);
        addToast(err.message, "error");
      }
    }
  }

  return (
    <AuthCanvas topRight={
      <button onClick={onGoRegister} style={{ fontFamily: GOTHIC, fontSize: 11, letterSpacing: 2, color: C.subdued, background: "none", border: "none", cursor: "pointer" }}>
        NEW OPERATOR →
      </button>
    }>
      <FormCard>
        <AuthHeading state="STATE" label="IDENTIFICATION" />
        {locked && (
          <div style={{ backgroundColor: C.red, padding: "12px 16px", marginBottom: 24 }}>
            <p style={{ fontFamily: GOTHIC, fontSize: 12, fontWeight: 900, letterSpacing: 1, color: "#000" }}>
              ACCOUNT LOCKED — {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, "0")} REMAINING
            </p>
          </div>
        )}
        <DInput label="Email / Operator ID" value={email} onChange={setEmail} type="email" placeholder="ALICE@EXAMPLE.COM" />
        <DInput label="Passphrase" value={pass} onChange={setPass} type="password" placeholder="••••••••" />
        {attempts > 0 && attempts < 5 && !locked && (
          <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.red, marginTop: -16, marginBottom: 20, letterSpacing: 1 }}>
            {5 - attempts} ATTEMPT{5 - attempts !== 1 ? "S" : ""} REMAINING BEFORE LOCKOUT
          </p>
        )}
        <HoverBtn bg={C.red} color="#000" onClick={handle} disabled={locked} fullWidth>AUTHENTICATE</HoverBtn>
        <div className="flex justify-center" style={{ marginTop: 16 }}>
          <button onClick={onGoRegister} style={{ background: "transparent", color: "#555", fontFamily: GOTHIC, fontSize: 13, border: "none", cursor: "pointer", letterSpacing: 1 }}>
            NEW OPERATOR? REGISTER HERE
          </button>
        </div>
      </FormCard>
    </AuthCanvas>
  );
}

// ─── Register Screen ───────────────────────────────────────────────────────────

export function RegisterScreen({ onRegister, onGoLogin, addToast, showFlash }: {
  onRegister: (u: User) => void; onGoLogin: () => void;
  addToast: (m: string, t: Toast["type"]) => void;
  showFlash: (text: string, v: "black" | "red", cb?: () => void) => void;
}) {
  const [email, setEmail] = useState(""); const [pass, setPass] = useState(""); const [conf, setConf] = useState("");
  async function handle() {
    if (!isEmail(email)) { addToast("INVALID EMAIL FORMAT", "error"); return; }
    if (pass.length < 12) { addToast("PASSPHRASE MUST BE AT LEAST 12 CHARACTERS", "error"); return; }
    if (pass !== conf) { addToast("PASSPHRASES DO NOT MATCH", "error"); return; }
    try {
      await register(email, pass);
      showFlash("REGISTERED", "black", () => showFlash("CREDENTIALS STORED", "black", () => onGoLogin()));
    } catch (err: any) {
      addToast(err.message, "error");
    }
  }
  return (
    <AuthCanvas topRight={
      <button onClick={onGoLogin} style={{ fontFamily: GOTHIC, fontSize: 11, letterSpacing: 2, color: C.subdued, background: "none", border: "none", cursor: "pointer" }}>
        ← SIGN IN
      </button>
    }>
      <FormCard>
        <AuthHeading state="STATE" label="REGISTRATION" />
        <DInput label="Email" value={email} onChange={setEmail} type="email" placeholder="ALICE@EXAMPLE.COM" />
        <DInput label="Passphrase" value={pass} onChange={setPass} type="password" placeholder="••••••••" />
        <DStrengthBar passphrase={pass} />
        <DInput label="Confirm Passphrase" value={conf} onChange={setConf} type="password" placeholder="••••••••" />
        <HoverBtn bg={C.red} color="#000" onClick={handle} fullWidth>INITIALIZE CREDENTIALS</HoverBtn>
        <div className="flex justify-center" style={{ marginTop: 16 }}>
          <button onClick={onGoLogin} style={{ background: "transparent", color: "#555", fontFamily: GOTHIC, fontSize: 13, border: "none", cursor: "pointer", letterSpacing: 1 }}>
            RETURN TO LOGIN
          </button>
        </div>
      </FormCard>
    </AuthCanvas>
  );
}

// ─── Dashboard shared select style ────────────────────────────────────────────

export const SELECT_STYLE: React.CSSProperties = {
  width: "100%", backgroundColor: C.surface, border: `2px solid ${C.border}`,
  color: C.text, padding: 16, fontFamily: GOTHIC, fontSize: 16,
  outline: "none", borderRadius: 0, marginBottom: 32,
};

// ─── KV Panel ──────────────────────────────────────────────────────────────────

export function KVPanel({ user, addToast, showCrit }: { user: User; addToast: (m: string, t: Toast["type"]) => void; showCrit: (m: CritModal) => void }) {
  const [mode, setMode] = useState<"read" | "write" | "delete" | "share">("read");
  const [path, setPath] = useState(`secret/${user.email}/`);
  const [payload, setPayload] = useState("");
  const [versionStr, setVersionStr] = useState("");
  const [granteeEmail, setGranteeEmail] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [entries, setEntries] = useState<KVEntry[]>([]);

  useEffect(() => {
    listSecrets().then(res => setEntries(res.secrets.map((s: any) => ({ path: s.path, value: "", ts: s.updated_at, is_shared: s.is_shared }))))
                 .catch(err => addToast(err.message, "error"));
  }, [addToast]);

  async function doWrite() {
    const p = sanitize(path.trim());
    if (!isValidPath(p, user.email)) { addToast("INVALID PATH OR PERMISSION_DENIED", "error"); return; }
    let parsed;
    try { parsed = JSON.parse(payload); } catch { addToast("PAYLOAD MUST BE VALID JSON", "error"); return; }
    try {
      await writeSecret(p, parsed);
      setResult(`Written to: ${p}`); addToast(`SECRET STORED: ${p}`, "success"); setPayload("");
      const res = await listSecrets();
      setEntries(res.secrets.map((s: any) => ({ path: s.path, value: "", ts: s.updated_at, is_shared: s.is_shared })));
    } catch (err: any) { addToast(err.message, "error"); }
  }
  async function doRead() {
    const p = sanitize(path.trim());
    if (!isValidPath(p)) { addToast("INVALID PATH FORMAT", "error"); return; }
    try {
      let data;
      if (versionStr) {
        const v = parseInt(versionStr, 10);
        if (isNaN(v) || v < 1) { addToast("INVALID VERSION", "error"); return; }
        data = await readSecretVersion(p, v);
      } else {
        data = await readSecret(p);
      }
      setResult(JSON.stringify(data.value, null, 2));
    } catch (err: any) { addToast(err.message, "error"); }
  }
  async function doShare() {
    const p = sanitize(path.trim());
    const email = sanitize(granteeEmail.trim());
    if (!email) { addToast("GRANTEE EMAIL REQUIRED", "error"); return; }
    try {
      await grantAccess("kv", p, email, "READ");
      addToast(`SHARED ${p} WITH ${email}`, "success");
      setGranteeEmail("");
    } catch (err: any) { addToast(err.message, "error"); }
  }
  async function doDelete() {
    const p = sanitize(path.trim());
    if (!isValidPath(p, user.email)) { addToast("PERMISSION_DENIED", "error"); return; }
    showCrit({ title: "DELETE SECRET", body: `This is permanent. The secret at "${p}" will be destroyed and cannot be recovered.`, confirmLabel: "DESTROY SECRET", variant: "red", onConfirm: async () => { 
        try {
          await deleteSecret(p);
          setResult(null); addToast(`SECRET DELETED: ${p}`, "success"); 
          const res = await listSecrets();
          setEntries(res.secrets.map((s: any) => ({ path: s.path, value: "", ts: s.updated_at, is_shared: s.is_shared })));
        } catch(err: any) { addToast(err.message, "error"); }
    } });
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 flex items-center px-8 py-4 gap-4" style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: C.surface }}>
        <p style={{ fontFamily: MINCHO, fontSize: 20, fontWeight: 700, letterSpacing: 2, color: C.text }}>KV ENGINE</p>
        <div className="ml-auto flex gap-1">
          {(["read", "write", "delete", "share"] as const).map((m) => (
            <button key={m} onClick={() => { setMode(m); setResult(null); }} style={{
              fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 2, textTransform: "uppercase",
              padding: "8px 16px", cursor: "pointer", border: "none", borderRadius: 0,
              backgroundColor: mode === m ? C.red : "transparent",
              color: mode === m ? "#000" : C.subdued,
            }}>{m}</button>
          ))}
        </div>
      </div>
      <div className="flex flex-1 overflow-hidden">
        <div className="flex flex-col overflow-y-auto p-8" style={{ width: "50%", borderRight: `1px solid ${C.border}`, backgroundColor: C.surface }}>
          <VInput label="Secret Path" value={path} onChange={setPath} placeholder={`secret/${user.email}/mykey`} />
          {mode === "read" && <VInput label="Version (Optional)" value={versionStr} onChange={setVersionStr} placeholder="e.g. 1" type="number" />}
          {mode === "write" && <VTextarea label="JSON Payload" value={payload} onChange={setPayload} placeholder='{"key": "value"}' rows={6} />}
          {mode === "share" && <VInput label="Grantee Email" value={granteeEmail} onChange={setGranteeEmail} placeholder="bob@example.com" type="email" />}
          <HoverBtn
            bg={mode === "delete" ? "transparent" : C.red}
            color={mode === "delete" ? C.red : "#000"}
            border={mode === "delete" ? `2px solid ${C.red}` : undefined}
            onClick={mode === "write" ? doWrite : mode === "read" ? doRead : mode === "share" ? doShare : doDelete}
            fullWidth>
            {mode === "write" ? "STORE SECRET" : mode === "read" ? "RETRIEVE SECRET" : mode === "share" ? "SHARE SECRET" : "DESTROY SECRET"}
          </HoverBtn>
          {result && (
            <div style={{ marginTop: 32, border: `1px solid ${C.border}`, padding: 16, backgroundColor: C.appBg }}>
              <p style={{ fontFamily: MINCHO, fontSize: 12, color: C.red, marginBottom: 8, letterSpacing: 2, textTransform: "uppercase" }}>RESULT</p>
              <pre style={{ fontFamily: GOTHIC, fontSize: 12, color: C.text, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}>{result}</pre>
            </div>
          )}
        </div>
        <div className="overflow-y-auto p-8" style={{ width: "50%", backgroundColor: C.appBg }}>
          <p style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.subdued, marginBottom: 16 }}>STORED SECRETS ({entries.filter(e => !e.is_shared).length})</p>
          {entries.filter(e => !e.is_shared).map((e) => (
            <div key={e.path} onClick={() => setPath(e.path)}
              style={{ border: `1px solid ${C.border}`, backgroundColor: C.surface, padding: "12px 16px", marginBottom: 8, cursor: "pointer" }}
              onMouseEnter={(ev) => ev.currentTarget.style.borderColor = C.red}
              onMouseLeave={(ev) => ev.currentTarget.style.borderColor = C.border}>
              <div className="flex items-center gap-2 mb-1">
                <div style={{ width: 4, height: 4, backgroundColor: C.red, flexShrink: 0 }} />
                <p style={{ fontFamily: GOTHIC, fontSize: 13, fontWeight: 700, color: C.text }}>{e.path}</p>
              </div>
              <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, paddingLeft: 12 }}>{new Date(parseFloat(e.ts as any) * 1000).toLocaleString()}</p>
            </div>
          ))}
          <p style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.subdued, marginBottom: 16, marginTop: 24 }}>SHARED WITH ME ({entries.filter(e => e.is_shared).length})</p>
          {entries.filter(e => e.is_shared).map((e) => (
            <div key={e.path} onClick={() => setPath(e.path)}
              style={{ border: `1px solid ${C.border}`, backgroundColor: C.surface, padding: "12px 16px", marginBottom: 8, cursor: "pointer" }}
              onMouseEnter={(ev) => ev.currentTarget.style.borderColor = C.blue}
              onMouseLeave={(ev) => ev.currentTarget.style.borderColor = C.border}>
              <div className="flex items-center gap-2 mb-1">
                <div style={{ width: 4, height: 4, backgroundColor: C.blue, flexShrink: 0 }} />
                <p style={{ fontFamily: GOTHIC, fontSize: 13, fontWeight: 700, color: C.text }}>{e.path}</p>
              </div>
              <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, paddingLeft: 12 }}>{new Date(parseFloat(e.ts as any) * 1000).toLocaleString()}</p>
            </div>
          ))}
          {entries.length === 0 && (
            <div className="flex items-center justify-center" style={{ height: 120 }}>
              <p style={{ fontFamily: GOTHIC, fontSize: 11, letterSpacing: 2, color: C.subdued }}>VAULT EMPTY</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Transit Encrypt Panel ─────────────────────────────────────────────────────

export function TransitEncPanel({ user, addToast, showCrit }: { user: User; addToast: (m: string, t: Toast["type"]) => void; showCrit: (m: CritModal) => void }) {
  const [tab, setTab] = useState<"keys" | "encrypt" | "decrypt">("keys");
  const [keys, setKeys] = useState<VKey[]>([]);
  const [newName, setNewName] = useState(""); const [selKey, setSelKey] = useState("");
  const [plaintext, setPlaintext] = useState(""); const [ciphertext, setCiphertext] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const ACCENT = C.purple;

  useEffect(() => {
    listEncryptKeys().then(res => setKeys(res.keys as any))
                     .catch(err => addToast(err.message, "error"));
  }, [addToast]);

  async function createKey() {
    const n = sanitize(newName.trim());
    if (!isKeyName(n)) { addToast("INVALID KEY NAME — ALPHANUMERIC + DASH/UNDERSCORE", "error"); return; }
    try {
      await createEncryptKey(n);
      addToast(`ENCRYPTION KEY CREATED: ${n}`, "success"); setNewName("");
      const res = await listEncryptKeys();
      setKeys(res.keys as any);
    } catch(err: any) { addToast(err.message, "error"); }
  }
  async function revokeKey(name: string) {
    showCrit({ title: "REVOKE KEY", body: `Revoking "${name}" is irreversible. All data encrypted with this key becomes permanently inaccessible.`, confirmLabel: "REVOKE KEY", variant: "red", onConfirm: async () => { 
      try {
        await revokeEncryptKey(name);
        addToast(`KEY REVOKED: ${name}`, "info"); 
        const res = await listEncryptKeys();
        setKeys(res.keys as any);
      } catch(err: any) { addToast(err.message, "error"); }
    } });
  }
  async function rotateKey(name: string) {
    try {
      await rotateEncryptKey(name);
      addToast(`KEY ROTATED: ${name}`, "success");
      const res = await listEncryptKeys();
      setKeys(res.keys as any);
    } catch(err: any) { addToast(err.message, "error"); }
  }
  async function doEncrypt() {
    if (!selKey) { addToast("SELECT A KEY", "error"); return; }
    if (!plaintext) { addToast("PLAINTEXT REQUIRED", "error"); return; }
    try {
      const data = await encrypt(selKey, btoa(sanitize(plaintext)));
      setResult(data.ciphertext);
      addToast("DATA ENCRYPTED", "success");
    } catch(err: any) { addToast(err.message, "error"); }
  }
  async function doDecrypt() {
    if (!ciphertext.startsWith("vault:")) { addToast("INVALID CIPHERTEXT FORMAT", "error"); return; }
    try {
      const data = await decrypt("", ciphertext);
      setResult(atob(data.plaintext));
      addToast("DATA DECRYPTED", "success");
    } catch(err: any) { addToast(err.message, "error"); }
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 flex items-center px-8 py-4 gap-4" style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: C.surface }}>
        <p style={{ fontFamily: MINCHO, fontSize: 20, fontWeight: 700, letterSpacing: 2, color: C.text }}>TRANSIT — ENCRYPT/DECRYPT</p>
        <div className="ml-auto flex gap-1">
          {(["keys", "encrypt", "decrypt"] as const).map((t) => (
            <button key={t} onClick={() => { setTab(t); setResult(null); }} style={{
              fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 2, textTransform: "uppercase",
              padding: "8px 16px", cursor: "pointer", border: "none", borderRadius: 0,
              backgroundColor: tab === t ? ACCENT : "transparent",
              color: tab === t ? "#fff" : C.subdued,
            }}>{t}</button>
          ))}
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: C.appBg }}>
        {tab === "keys" && (
          <div>
            <div className="flex gap-4" style={{ alignItems: "flex-end", marginBottom: 24 }}>
              <div style={{ flex: 1, backgroundColor: C.surface, padding: "0" }}>
                <VInput label="Key Name" value={newName} onChange={setNewName} placeholder="my-encryption-key" maxLength={64} />
              </div>
              <div style={{ marginBottom: 32 }}>
                <HoverBtn bg={ACCENT} color="#fff" onClick={createKey}>CREATE KEY</HoverBtn>
              </div>
            </div>
            <p style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.subdued, marginBottom: 16 }}>ENCRYPTION KEYS ({keys.length})</p>
            {keys.map((k) => (
              <div key={k.name} className="flex items-center" style={{ border: `1px solid ${C.border}`, backgroundColor: C.surface, padding: "12px 16px", marginBottom: 8, opacity: k.revoked ? 0.5 : 1 }}>
                <div style={{ width: 4, height: 24, backgroundColor: ACCENT, marginRight: 16, flexShrink: 0 }} />
                <div style={{ flex: 1 }}>
                  <p style={{ fontFamily: GOTHIC, fontSize: 13, fontWeight: 700, color: C.text }}>{k.name}</p>
                  <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, marginTop: 2 }}>{k.algorithm} · v{k.version} · {k.revoked ? "REVOKED" : "ACTIVE"} · PRIVATE KEY SEALED</p>
                </div>
                {!k.revoked && (
                  <div className="flex gap-4">
                    <button onClick={() => rotateKey(k.name)} style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 1, color: ACCENT, background: "none", border: "none", cursor: "pointer" }}>ROTATE</button>
                    <button onClick={() => revokeKey(k.name)} style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 1, color: C.red, background: "none", border: "none", cursor: "pointer" }}>REVOKE</button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        {tab === "encrypt" && (
          <div style={{ maxWidth: 560 }}>
            <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1, display: "block", marginBottom: 8 }}>Select Key</label>
            <select value={selKey} onChange={(e) => setSelKey(e.target.value)} style={{ ...SELECT_STYLE }}>
              <option value="">— choose key —</option>
              {keys.filter((k) => !k.revoked).map((k) => <option key={k.name} value={k.name}>{k.name}</option>)}
            </select>
            <VTextarea label="Plaintext (Base64)" value={plaintext} onChange={setPlaintext} placeholder="Base64-encoded data..." accent={ACCENT} />
            <HoverBtn bg={ACCENT} color="#fff" onClick={doEncrypt} fullWidth>ENCRYPT</HoverBtn>
            {result && <div style={{ marginTop: 32, border: `1px solid ${C.border}`, padding: 16, backgroundColor: C.surface }}><p style={{ fontFamily: MINCHO, fontSize: 12, color: ACCENT, marginBottom: 8, letterSpacing: 2, textTransform: "uppercase" }}>CIPHERTEXT</p><pre style={{ fontFamily: GOTHIC, fontSize: 12, color: C.text, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}>{result}</pre></div>}
          </div>
        )}
        {tab === "decrypt" && (
          <div style={{ maxWidth: 560 }}>
            <VTextarea label="Ciphertext" value={ciphertext} onChange={setCiphertext} placeholder="vault:<key_name>:v1:<cipher>" rows={4} accent={ACCENT} />
            <HoverBtn bg={ACCENT} color="#fff" onClick={doDecrypt} fullWidth>DECRYPT</HoverBtn>
            {result && <div style={{ marginTop: 32, border: `1px solid ${C.border}`, padding: 16, backgroundColor: C.surface }}><p style={{ fontFamily: MINCHO, fontSize: 12, color: ACCENT, marginBottom: 8, letterSpacing: 2, textTransform: "uppercase" }}>PLAINTEXT</p><pre style={{ fontFamily: GOTHIC, fontSize: 12, color: C.text, lineHeight: 1.6, margin: 0 }}>{result}</pre></div>}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Transit Sign Panel ────────────────────────────────────────────────────────

export function TransitSignPanel({ user, addToast, showCrit }: { user: User; addToast: (m: string, t: Toast["type"]) => void; showCrit: (m: CritModal) => void }) {
  const [tab, setTab] = useState<"keys" | "sign" | "verify">("keys");
  const [keys, setKeys] = useState<VKey[]>([]);
  const [newName, setNewName] = useState(""); const [algo, setAlgo] = useState("ED25519");
  const [selKey, setSelKey] = useState(""); const [message, setMessage] = useState("");
  const [sig, setSig] = useState(""); const [signResult, setSignResult] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const ACCENT = "#B8860B"; // dark gold — readable on light

  useEffect(() => {
    listSignKeys().then(res => setKeys(res.keys as any))
                  .catch(err => addToast(err.message, "error"));
  }, [addToast]);

  async function createKey() {
    const n = sanitize(newName.trim());
    if (!isKeyName(n)) { addToast("INVALID KEY NAME", "error"); return; }
    try {
      await createSignKey(n, algo as any);
      addToast(`SIGNING KEY CREATED: ${n}`, "success"); setNewName("");
      const res = await listSignKeys();
      setKeys(res.keys as any);
    } catch(err: any) { addToast(err.message, "error"); }
  }
  async function doSign() {
    if (!selKey) { addToast("SELECT A KEY", "error"); return; }
    if (!message) { addToast("MESSAGE REQUIRED", "error"); return; }
    try {
      const data = await signMessage(selKey, message);
      setSignResult(data.signature);
      addToast("MESSAGE SIGNED", "success");
    } catch(err: any) { addToast(err.message, "error"); }
  }
  async function doVerify() {
    if (!selKey || !message || !sig) { addToast("KEY, MESSAGE AND SIGNATURE REQUIRED", "error"); return; }
    try {
      const data = await verifySignature(selKey, message, sig);
      setVerifyResult(data.signature_valid);
    } catch(err: any) { addToast(err.message, "error"); }
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 flex items-center px-8 py-4 gap-4" style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: C.surface }}>
        <p style={{ fontFamily: MINCHO, fontSize: 20, fontWeight: 700, letterSpacing: 2, color: C.text }}>TRANSIT — SIGN/VERIFY</p>
        <div className="ml-auto flex gap-1">
          {(["keys", "sign", "verify"] as const).map((t) => (
            <button key={t} onClick={() => { setTab(t); setSignResult(null); setVerifyResult(null); }} style={{
              fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 2, textTransform: "uppercase",
              padding: "8px 16px", cursor: "pointer", border: "none", borderRadius: 0,
              backgroundColor: tab === t ? ACCENT : "transparent",
              color: tab === t ? "#fff" : C.subdued,
            }}>{t}</button>
          ))}
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: C.appBg }}>
        {tab === "keys" && (
          <div style={{ maxWidth: 480 }}>
            <VInput label="Key Name" value={newName} onChange={setNewName} placeholder="my-signing-key" maxLength={64} />
            <div style={{ marginBottom: 32 }}>
              <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1, display: "block", marginBottom: 8 }}>Algorithm</label>
              <select value={algo} onChange={(e) => setAlgo(e.target.value)} style={{ width: "100%", backgroundColor: C.surface, border: `2px solid ${C.border}`, color: C.text, padding: 16, fontFamily: GOTHIC, fontSize: 16, outline: "none", borderRadius: 0 }}>
                <option value="ED25519">ED25519</option>
                <option value="RSASSA_PKCS1_V1_5_SHA_256">RSA-2048 (PKCS#1 v1.5 SHA-256)</option>
              </select>
            </div>
            <HoverBtn bg={ACCENT} color="#fff" onClick={createKey} fullWidth>CREATE SIGNING KEY</HoverBtn>
            <p style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.subdued, marginBottom: 16, marginTop: 32 }}>SIGNING KEYS ({keys.length})</p>
            {keys.map((k) => (
              <div key={k.name} className="flex items-center" style={{ border: `1px solid ${C.border}`, backgroundColor: C.surface, padding: "12px 16px", marginBottom: 8, opacity: k.revoked ? 0.5 : 1 }}>
                <div style={{ width: 4, height: 24, backgroundColor: ACCENT, marginRight: 16, flexShrink: 0 }} />
                <div style={{ flex: 1 }}>
                  <p style={{ fontFamily: GOTHIC, fontSize: 13, fontWeight: 700, color: C.text }}>{k.name}</p>
                  <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, marginTop: 2 }}>{k.algorithm} · v{k.version} · PRIVATE KEY SEALED · {k.revoked ? "REVOKED" : "ACTIVE"}</p>
                </div>
              </div>
            ))}
          </div>
        )}
        {tab === "sign" && (
          <div style={{ maxWidth: 560 }}>
            <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1, display: "block", marginBottom: 8 }}>Select Signing Key</label>
            <select value={selKey} onChange={(e) => setSelKey(e.target.value)} style={{ ...SELECT_STYLE }}>
              <option value="">— choose key —</option>
              {keys.filter((k) => !k.revoked).map((k) => <option key={k.name} value={k.name}>{k.name}</option>)}
            </select>
            <VTextarea label="Message" value={message} onChange={setMessage} placeholder="Data to sign..." accent={ACCENT} />
            <HoverBtn bg={ACCENT} color="#fff" onClick={doSign} fullWidth>SIGN MESSAGE</HoverBtn>
            {signResult && <div style={{ marginTop: 32, border: `1px solid ${C.border}`, padding: 16, backgroundColor: C.surface }}><p style={{ fontFamily: MINCHO, fontSize: 12, color: ACCENT, marginBottom: 8, letterSpacing: 2, textTransform: "uppercase" }}>DIGITAL SIGNATURE</p><pre style={{ fontFamily: GOTHIC, fontSize: 12, color: C.text, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}>{signResult}</pre></div>}
          </div>
        )}
        {tab === "verify" && (
          <div style={{ maxWidth: 560 }}>
            <label style={{ fontFamily: MINCHO, fontSize: 14, color: C.subdued, textTransform: "uppercase", letterSpacing: 1, display: "block", marginBottom: 8 }}>Key Name</label>
            <select value={selKey} onChange={(e) => setSelKey(e.target.value)} style={{ ...SELECT_STYLE }}>
              <option value="">— choose key —</option>
              {keys.map((k) => <option key={k.name} value={k.name}>{k.name}</option>)}
            </select>
            <VTextarea label="Original Message" value={message} onChange={setMessage} placeholder="The original message..." accent={ACCENT} />
            <VTextarea label="Signature" value={sig} onChange={setSig} placeholder="signature:..." accent={ACCENT} />
            <HoverBtn bg={ACCENT} color="#fff" onClick={doVerify} fullWidth>VERIFY SIGNATURE</HoverBtn>
            {verifyResult !== null && (
              <div style={{ marginTop: 32, border: `2px solid ${verifyResult ? C.green : C.red}`, padding: 24, backgroundColor: C.surface }}>
                <p style={{ fontFamily: MINCHO, fontSize: 12, color: verifyResult ? C.green : C.red, marginBottom: 12, letterSpacing: 2, textTransform: "uppercase" }}>VERIFICATION RESULT</p>
                <p style={{ fontFamily: MINCHO, fontSize: 32, fontWeight: 700, letterSpacing: 3, color: verifyResult ? C.green : C.red }}>{verifyResult ? "SIGNATURE VALID" : "SIGNATURE INVALID"}</p>
                <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, marginTop: 8 }}>signature_valid: {String(verifyResult)}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Audit Panel ───────────────────────────────────────────────────────────────

export function AuditPanel() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const { addToast } = useUI();

  useEffect(() => {
    listAuditEvents().then(res => setEvents(res.events))
      .catch(err => addToast(err.message, "error"));
  }, [addToast]);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 flex items-center px-8 py-4 gap-4" style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: C.surface }}>
        <p style={{ fontFamily: MINCHO, fontSize: 20, fontWeight: 700, letterSpacing: 2, color: C.text }}>AUDIT LOG</p>
        <div className="ml-auto flex items-center gap-2">
          <div style={{ width: 8, height: 8, backgroundColor: C.green }} />
          <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.green }}>TAMPER-EVIDENT</span>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto" style={{ backgroundColor: C.appBg }}>
        <div className="grid px-8 py-3" style={{ gridTemplateColumns: "200px 1fr 1fr 1fr 80px", borderBottom: `1px solid ${C.border}`, backgroundColor: C.surfaceAlt }}>
          {["TIMESTAMP", "USER", "ACTION", "TARGET", "STATUS"].map((h) => (
            <span key={h} style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.subdued }}>{h}</span>
          ))}
        </div>
        {events.map((row, i) => {
          const sc = row.result === "OK" ? C.green : row.result === "DENIED" ? C.red : "#A0750A";
          return (
            <div key={i} className="grid px-8 py-3" style={{ gridTemplateColumns: "200px 1fr 1fr 1fr 80px", borderBottom: `1px solid ${C.border}`, backgroundColor: i % 2 === 0 ? C.surface : C.surfaceAlt }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = C.appBg}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = i % 2 === 0 ? C.surface : C.surfaceAlt}>
              <span style={{ fontFamily: "monospace", fontSize: 11, color: C.subdued }}>{new Date(parseFloat(row.timestamp) * 1000).toLocaleString()}</span>
              <span style={{ fontFamily: GOTHIC, fontSize: 12, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.actor_email}</span>
              <span style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, letterSpacing: 1 }}>{row.action}</span>
              <span style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.resource}</span>
              <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 1, color: sc }}>{row.result}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Dashboard shell and App root have moved to src/layouts/ and src/router.tsx
