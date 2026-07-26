import { TransitSignPanel } from "@/app/App";
import { useUI } from "@/context/UIContext";

export function TransitSignPage() {
  const { user, addToast, showCrit } = useUI();
  if (!user) return null;
  return <TransitSignPanel user={user} addToast={addToast} showCrit={showCrit} />;
}
