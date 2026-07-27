import { useNavigate } from "react-router";
import { AuditPanel, HoverBtn } from "@/app/App";
import { C, GOTHIC, MINCHO } from "@/app/App";
import { useUI } from "@/context/UIContext";
import { apiFetch } from "@/api/client";

export function AdminAuditPage() {
  const navigate = useNavigate();
  const { showFlash, handleApiError } = useUI();

  async function handleLock() {
    try {
      await apiFetch("/vault/lock", { method: "POST", skipAuth: true });
      showFlash("SYSTEM LOCKED", "red", () => navigate("/admin"));
    } catch (err) {
      handleApiError(err);
    }
  }

  return (
    <div
      className="flex flex-col"
      style={{ height: "100vh", backgroundColor: "#F4F1EA", overflow: "hidden" }}
    >
      {/* Admin top bar */}
      <div
        className="flex-shrink-0 flex items-center px-8 gap-6"
        style={{ height: 64, backgroundColor: C.surface, borderBottom: `2px solid #000` }}
      >
        <span style={{ fontFamily: GOTHIC, fontSize: 11, fontWeight: 900, letterSpacing: 4, color: C.red }}>
          MINI VAULT
        </span>
        <div style={{ width: 1, height: 20, backgroundColor: C.border }} />
        <span style={{ fontFamily: GOTHIC, fontSize: 11, letterSpacing: 2, color: C.subdued }}>
          ADMIN
        </span>
        <div className="ml-auto flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div style={{ width: 8, height: 8, backgroundColor: C.green }} />
            <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.green }}>
              VAULT OPEN
            </span>
          </div>
          <button
            onClick={handleLock}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "transparent"; e.currentTarget.style.color = C.red; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = C.red; e.currentTarget.style.color = "#FFF"; }}
            style={{
              padding: "4px 12px", fontSize: 10, fontFamily: GOTHIC, fontWeight: 900,
              backgroundColor: C.red, color: "#FFF", border: `2px solid ${C.red}`,
              cursor: "pointer", transition: "all 0.15s ease-in-out"
            }}
          >
            LOCK VAULT
          </button>
        </div>
      </div>

      {/* Audit panel fills remaining height */}
      <div className="flex-1 overflow-hidden">
        <AuditPanel />
      </div>

      {/* Bottom accent bar */}
      <div
        className="flex-shrink-0"
        style={{ height: 64, backgroundColor: C.surface, borderTop: `8px solid ${C.green}` }}
      />
    </div>
  );
}
