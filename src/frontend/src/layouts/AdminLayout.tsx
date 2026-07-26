import { useState, useCallback } from "react";
import { Outlet, useNavigate } from "react-router";

import { C, FlashScreen, CritModalOverlay, ToastStack } from "@/app/App";
import type { Toast, CritModal } from "@/app/App";
import { UIContext } from "@/context/UIContext";
import type { ModalCfg } from "@/context/UIContext";

export function AdminLayout() {
  const navigate = useNavigate();

  const [toasts, setToasts] = useState<Toast[]>([]);
  const [modal, setModal] = useState<CritModal | null>(null);
  const [flash, setFlash] = useState<{
    text: string;
    variant: "black" | "red";
    cb?: () => void;
  } | null>(null);

  const addToast = useCallback((message: string, type: Toast["type"]) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((prev) => [...prev.slice(-4), { id, message, type }]);
  }, []);

  const dismissToast = useCallback(
    (id: string) => setToasts((prev) => prev.filter((t) => t.id !== id)),
    [],
  );

  const showCrit = useCallback((cfg: CritModal) => setModal(cfg), []);

  const showFlash = useCallback(
    (text: string, variant: "black" | "red", cb?: () => void) =>
      setFlash({ text, variant, cb }),
    [],
  );

  const handleApiError = useCallback(
    (err: unknown) => {
      if (err instanceof Error) {
        // VAULT_LOCKED on admin pages just redirect back to /admin (passphrase)
        const code = (err as { code?: string }).code ?? "";
        if (code === "VAULT_LOCKED") {
          navigate("/admin", { replace: true });
          return;
        }
        addToast(err.message, "error");
        return;
      }
      addToast("AN UNEXPECTED ERROR OCCURRED", "error");
    },
    [addToast, navigate],
  );

  function handleFlashDone() {
    const cb = flash?.cb;
    setFlash(null);
    cb?.();
  }

  return (
    <UIContext.Provider
      value={{
        addToast,
        showCrit: showCrit as (cfg: ModalCfg) => void,
        showFlash,
        handleApiError,
        user: null,
        setUser: () => {},
      }}
    >
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
