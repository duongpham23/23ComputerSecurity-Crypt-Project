import { useState, useEffect } from "react";
import { Navigate, Outlet } from "react-router";
import { vaultStatus } from "@/api/auth";

export function AdminGuard() {
  const [status, setStatus] = useState<"checking" | "locked" | "open">("checking");

  useEffect(() => {
    vaultStatus()
      .then((s) => setStatus(s.locked ? "locked" : "open"))
      .catch(() => setStatus("locked"));
  }, []);

  if (status === "checking") return null;
  if (status === "locked") return <Navigate to="/admin" replace />;
  return <Outlet />;
}
