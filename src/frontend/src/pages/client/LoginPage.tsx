import { useNavigate } from "react-router";
import { LoginScreen } from "@/app/App";
import { useUI } from "@/context/UIContext";

export function LoginPage() {
  const navigate = useNavigate();
  const { setUser, addToast, showFlash } = useUI();

  return (
    <LoginScreen
      onLogin={(u) => {
        setUser(u);
        navigate("/kv", { replace: true });
      }}
      onGoRegister={() => navigate("/register")}
      addToast={addToast}
      showFlash={showFlash}
    />
  );
}
