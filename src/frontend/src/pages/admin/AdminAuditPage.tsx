import { AuditPanel } from "@/app/App";
import { C, GOTHIC, MINCHO } from "@/app/App";

export function AdminAuditPage() {
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
        <div className="ml-auto flex items-center gap-2">
          <div style={{ width: 8, height: 8, backgroundColor: C.green }} />
          <span style={{ fontFamily: GOTHIC, fontSize: 10, fontWeight: 900, letterSpacing: 2, color: C.green }}>
            VAULT OPEN
          </span>
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
