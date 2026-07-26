import { useState, useCallback } from "react";
import { Outlet, useNavigate } from "react-router";

import {
  C, FlashScreen, CritModalOverlay, ToastStack,
} from "@/app/App";
import type { Toast, CritModal, User } from "@/app/App";
import { UIContext } from "@/context/UIContext";
import type { ToastMsg, ModalCfg, CurrentUser } from "@/context/UIContext";
import { ApiError } from "@/api/client";
import { clearToken } from "@/api/client";

export function ClientLayout() {
  const navigate = useNavigate();

  const [toasts, setToasts] = useState<Toast[]>([]);
  const [modal, setModal] = useState<CritModal | null>(null);
  const [flash, setFlash] = useState<{ text: string; variant: "black" | "red"; cb?: () => void } | null>(null);
  const [user, setUser] = useState<User | null>(null);

  const addToast = useCallback((message: string, type: Toast["type"]) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((prev) => [...prev.slice(-4), { id, message, type }]);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showCrit = useCallback((cfg: CritModal) => setModal(cfg), []);

  const showFlash = useCallback(
    (text: string, variant: "black" | "red", cb?: () => void) =>
      setFlash({ text, variant, cb }),
    [],
  );

  const handleApiError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.code === "VAULT_LOCKED") {
          showCrit({
            title: "VAULT LOCKED",
            body: "The vault has been locked. You will be redirected to the login screen.",
            confirmLabel: "UNDERSTOOD",
            variant: "red",
            onConfirm: () => {
              clearToken();
              setUser(null);
              navigate("/login", { replace: true });
            },
          });
          return;
        }
        if (err.code === "SESSION_EXPIRED") {
          showCrit({
            title: "SESSION EXPIRED",
            body: "Your 30-minute session has ended. Please authenticate again.",
            confirmLabel: "SIGN IN AGAIN",
            variant: "black",
            onConfirm: () => {
              clearToken();
              setUser(null);
              navigate("/login", { replace: true });
            },
          });
          return;
        }
        addToast(err.message, "error");
        return;
      }
      addToast("AN UNEXPECTED ERROR OCCURRED", "error");
    },
    [addToast, showCrit, navigate],
  );

  function handleFlashDone() {
    const cb = flash?.cb;
    setFlash(null);
    cb?.();
  }

  // Adapt local state types to UIContext types (structurally identical)
  const ctxValue = {
    addToast,
    showCrit: showCrit as (cfg: ModalCfg) => void,
    showFlash,
    handleApiError,
    user: user as CurrentUser | null,
    setUser: setUser as (u: CurrentUser | null) => void,
  };

  return (
    <UIContext.Provider value={ctxValue}>
      <div
        style={{
          position: "relative",
          width: "100%",
          height: "100vh",
          overflow: "hidden",
          backgroundColor: C.appBg,
        }}
      >
        {flash && (
          <FlashScreen
            text={flash.text}
            variant={flash.variant}
            onDone={handleFlashDone}
          />
        )}
        {modal && !flash && (
          <CritModalOverlay modal={modal} onClose={() => setModal(null)} />
        )}
        {!flash && <Outlet />}
        <ToastStack toasts={toasts} onDismiss={dismissToast} />
      </div>
    </UIContext.Provider>
  );
}
