import { createBrowserRouter, Navigate } from "react-router";

import { ClientLayout } from "@/layouts/ClientLayout";
import { DashboardLayout } from "@/layouts/DashboardLayout";
import { AdminLayout } from "@/layouts/AdminLayout";

import { ClientGuard } from "@/guards/ClientGuard";
import { AdminGuard } from "@/guards/AdminGuard";

import { LoginPage } from "@/pages/client/LoginPage";
import { RegisterPage } from "@/pages/client/RegisterPage";
import { KVPage } from "@/pages/client/KVPage";
import { TransitEncryptPage } from "@/pages/client/TransitEncryptPage";
import { TransitSignPage } from "@/pages/client/TransitSignPage";

import { AdminPassphrasePage } from "@/pages/admin/AdminPassphrasePage";
import { AdminAuditPage } from "@/pages/admin/AdminAuditPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <ClientLayout />,
    children: [
      { index: true, element: <Navigate to="/login" replace /> },
      { path: "login", element: <LoginPage /> },
      { path: "register", element: <RegisterPage /> },
      {
        element: <ClientGuard />,
        children: [
          {
            element: <DashboardLayout />,
            children: [
              { path: "kv", element: <KVPage /> },
              { path: "transit/encrypt", element: <TransitEncryptPage /> },
              { path: "transit/sign", element: <TransitSignPage /> },
            ],
          },
        ],
      },
    ],
  },
  {
    path: "/admin",
    element: <AdminLayout />,
    children: [
      { index: true, element: <AdminPassphrasePage /> },
      {
        element: <AdminGuard />,
        children: [{ path: "audit", element: <AdminAuditPage /> }],
      },
    ],
  },
]);
