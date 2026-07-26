import { createContext, useContext } from "react";

// ── Shared types ──────────────────────────────────────────────────────────────

export interface ToastMsg {
  id: string;
  message: string;
  type: "error" | "success" | "info";
}

export interface ModalCfg {
  title: string;
  body: string;
  confirmLabel: string;
  variant: "black" | "red";
  onConfirm: () => void;
}

export interface CurrentUser {
  email: string;
}

// ── Context shape ─────────────────────────────────────────────────────────────

export interface UIContextValue {
  addToast: (message: string, type: ToastMsg["type"]) => void;
  showCrit: (cfg: ModalCfg) => void;
  showFlash: (text: string, variant: "black" | "red", cb?: () => void) => void;
  /** Smart error handler: routes VAULT_LOCKED / SESSION_EXPIRED to a blocking
   *  modal (then /login), and everything else to a toast. */
  handleApiError: (err: unknown) => void;
  user: CurrentUser | null;
  setUser: (u: CurrentUser | null) => void;
}

const noop = () => {};

export const UIContext = createContext<UIContextValue>({
  addToast: noop,
  showCrit: noop,
  showFlash: noop,
  handleApiError: noop,
  user: null,
  setUser: noop,
});

export function useUI() {
  return useContext(UIContext);
}
