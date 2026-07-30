import { useState, useEffect } from "react";
import { Navigate, useNavigate } from "react-router";

import {
  AuthCanvas, FormCard, AuthHeading,
  DInput, DStrengthBar, HoverBtn,
} from "@/app/App";
import { useUI } from "@/context/UIContext";
import { vaultStatus, vaultInit, vaultUnlock } from "@/api/auth";

type VaultState = "loading" | "uninit" | "locked" | "open";

export function AdminPassphrasePage() {
  const { addToast, showFlash, handleApiError } = useUI();
  const navigate = useNavigate();

  const [vaultState, setVaultState] = useState<VaultState>("loading");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    vaultStatus()
      .then((s) => {
        if (!s.locked) setVaultState("open");
        else if (s.initialized) setVaultState("locked");
        else setVaultState("uninit");
      })
      .catch(() => setVaultState("locked"));
  }, []);

  if (vaultState === "loading") return null;
  if (vaultState === "open") return <Navigate to="/admin/audit" replace />;

  const isFirstRun = vaultState === "uninit";

  async function handleSubmit() {
    if (!passphrase) { addToast("PASSPHRASE REQUIRED", "error"); return; }
    if (passphrase.length < 12) { addToast("PASSPHRASE MUST BE AT LEAST 12 CHARACTERS", "error"); return; }
    if (isFirstRun && passphrase !== confirm) { addToast("PASSPHRASES DO NOT MATCH", "error"); return; }

    setSubmitting(true);
    try {
      if (isFirstRun) {
        await vaultInit(passphrase);
        showFlash("VAULT INITIALIZED", "black", () =>
          showFlash("ACCESS GRANTED", "red", () => navigate("/admin/audit")),
        );
      } else {
        await vaultUnlock(passphrase);
        showFlash("UNLOCKING", "black", () =>
          showFlash("ACCESS GRANTED", "red", () => navigate("/admin/audit")),
        );
      }
    } catch (err) {
      handleApiError(err);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCanvas lockedBar={!isFirstRun}>
      <FormCard>
        <AuthHeading
          state="ADMIN"
          label={isFirstRun ? "INITIALIZE" : "UNLOCK"}
        />
        <DInput
          label="Master Passphrase"
          value={passphrase}
          onChange={setPassphrase}
          type="password"
          placeholder={isFirstRun ? "SET STRONG PASSPHRASE" : "ENTER PASSPHRASE"}
        />
        {isFirstRun && <DStrengthBar passphrase={passphrase} />}
        {isFirstRun && (
          <DInput
            label="Confirm Passphrase"
            value={confirm}
            onChange={setConfirm}
            type="password"
            placeholder="REPEAT PASSPHRASE"
          />
        )}
        <HoverBtn
          bg="#CC0000"
          color="#000"
          onClick={handleSubmit}
          disabled={submitting}
          fullWidth
        >
          {isFirstRun ? "INITIALIZE VAULT" : "UNLOCK VAULT"}
        </HoverBtn>
      </FormCard>
    </AuthCanvas>
  );
}
