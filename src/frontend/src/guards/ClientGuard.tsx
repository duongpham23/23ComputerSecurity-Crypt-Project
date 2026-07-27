import { Navigate, Outlet } from "react-router";
import { getToken } from "@/api/client";

export function ClientGuard() {
  const token = getToken();
  return token ? <Outlet /> : <Navigate to="/login" replace />;
}
