import { TransitEncPanel } from "@/app/App";
import { useUI } from "@/context/UIContext";

export function TransitEncryptPage() {
  const { user, addToast, showCrit } = useUI();
  if (!user) return null;
  return <TransitEncPanel user={user} addToast={addToast} showCrit={showCrit} />;
}
