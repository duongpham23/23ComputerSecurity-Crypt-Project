import { useNavigate } from "react-router";
import { RegisterScreen } from "@/app/App";
import { useUI } from "@/context/UIContext";

export function RegisterPage() {
  const navigate = useNavigate();
  const { setUser, addToast, showFlash } = useUI();

  return (
    <RegisterScreen
      onRegister={(u) => {
        setUser(u);
        navigate("/kv", { replace: true });
      }}
      onGoLogin={() => navigate("/login")}
      addToast={addToast}
      showFlash={showFlash}
    />
  );
}
