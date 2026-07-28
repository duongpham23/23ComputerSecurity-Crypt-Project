import { useState } from "react";
import { NavLink, Outlet, useNavigate, useLocation } from "react-router";

import { C, GOTHIC, MINCHO } from "@/app/App";
import { useUI } from "@/context/UIContext";
import { clearToken } from "@/api/client";

const NAV = [
  { path: "/kv",              label: "KV ENGINE", sub: "Secure Storage",    accent: C.red },
  { path: "/transit/encrypt", label: "TRANSIT",   sub: "Encrypt / Decrypt", accent: C.purple },
  { path: "/transit/sign",    label: "TRANSIT",   sub: "Sign / Verify",     accent: "#B8860B" },
] as const;

export function DashboardLayout() {
  const { user, showCrit, showFlash, setUser } = useUI();
  const navigate = useNavigate();
  const location = useLocation();
  const [logoutHover, setLogoutHover] = useState(false);

  const activeNav =
    NAV.find((n) => location.pathname.startsWith(n.path)) ?? NAV[0];

  function handleLogout() {
    showCrit({
      title: "SIGN OUT",
      body: "Your session token will be invalidated. You will need to authenticate again to access the vault.",
      confirmLabel: "CONFIRM LOGOUT",
      variant: "black",
      onConfirm: () =>
        showFlash("GOODBYE", "black", () => {
          clearToken();
          setUser(null);
          navigate("/login", { replace: true });
        }),
    });
  }

  return (
    <div
      className="flex flex-col"
      style={{ height: "100vh", backgroundColor: C.appBg, overflow: "hidden" }}
    >
      {/* ── Top bar ── */}
      <div
        className="flex-shrink-0 flex items-center px-8 gap-6"
        style={{ height: 64, backgroundColor: C.surface, borderBottom: `2px solid #000` }}
      >
        <div className="flex items-center gap-4">
          <span style={{ fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 4, color: C.red }}>
            MINI VAULT
          </span>
        </div>
        <div style={{ width: 1, height: 20, backgroundColor: C.border }} />
        <span style={{ fontFamily: GOTHIC, fontSize: 11, letterSpacing: 2, color: C.subdued }}>
          {user?.email}
        </span>
        <div className="ml-auto flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div style={{ width: 8, height: 8, backgroundColor: C.green }} />
            <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.green }}>
              VAULT OPEN
            </span>
          </div>
          <button
            onClick={handleLogout}
            onMouseEnter={() => setLogoutHover(true)}
            onMouseLeave={() => setLogoutHover(false)}
            style={{
              fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2,
              color: logoutHover ? C.red : C.subdued,
              background: "none", border: "none", cursor: "pointer",
            }}
          >
            SIGN OUT
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* ── Sidebar ── */}
        <div
          className="flex-shrink-0 flex flex-col"
          style={{ width: 220, borderRight: `1px solid ${C.border}`, backgroundColor: C.surfaceAlt }}
        >
          {NAV.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: "block",
                textAlign: "left",
                padding: "20px 24px",
                borderBottom: `1px solid ${C.border}`,
                cursor: "pointer",
                textDecoration: "none",
                backgroundColor: isActive ? C.surface : "transparent",
                borderLeft: isActive
                  ? `4px solid ${item.accent}`
                  : "4px solid transparent",
              })}
            >
              {({ isActive }) => (
                <>
                  <span
                    style={{
                      fontFamily: GOTHIC, fontSize: 10, fontWeight: 900,
                      letterSpacing: 2,
                      color: isActive ? item.accent : C.subdued,
                      display: "block", marginBottom: 4,
                    }}
                  >
                    {item.label}
                  </span>
                  <p style={{ fontFamily: GOTHIC, fontSize: 11, color: C.subdued, margin: 0 }}>
                    {item.sub}
                  </p>
                </>
              )}
            </NavLink>
          ))}
        </div>

        {/* ── Content ── */}
        <div className="flex-1 overflow-hidden flex flex-col">
          <Outlet />
        </div>
      </div>

      {/* ── Bottom bar — accent tracks active route ── */}
      <div
        className="flex-shrink-0 flex items-center px-8"
        style={{
          height: 64,
          backgroundColor: C.surface,
          borderTop: `8px solid ${activeNav.accent}`,
        }}
      >
        <span
          style={{
            marginLeft: "auto",
            fontFamily: GOTHIC, fontSize: 10, letterSpacing: 2, color: C.subdued,
          }}
        >
          {activeNav.label} — {activeNav.sub.toUpperCase()}
        </span>
      </div>
    </div>
  );
}
