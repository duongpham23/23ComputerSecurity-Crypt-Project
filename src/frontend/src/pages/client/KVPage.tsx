import { KVPanel } from "@/app/App";
import { useUI } from "@/context/UIContext";

export function KVPage() {
  const { user, addToast, showCrit } = useUI();
  if (!user) return null;
  return <KVPanel user={user} addToast={addToast} showCrit={showCrit} />;
}
