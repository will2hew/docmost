import { useState } from "react";
import { login, setupWorkspace } from "@/features/auth/services/auth-service";
import { useNavigate } from "react-router-dom";
import { useAtom } from "jotai";
import { authTokensAtom } from "@/features/auth/atoms/auth-tokens-atom";
import { currentUserAtom } from "@/features/user/atoms/current-user-atom";
import {
  ILogin,
  IRegister,
  ISetupWorkspace,
} from "@/features/auth/types/auth.types";
import { notifications } from "@mantine/notifications";
import { IAcceptInvite } from "@/features/workspace/types/workspace.types.ts";
import { acceptInvitation } from "@/features/workspace/services/workspace-service.ts";
import Cookies from "js-cookie";
import { jwtDecode } from "jwt-decode";
import APP_ROUTE from "@/lib/app-route.ts";
import api from "@/lib/api-client";

export default function useAuth() {
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const [, setCurrentUser] = useAtom(currentUserAtom);

  const handleSignIn = async (data: ILogin) => {
    setIsLoading(true);

    try {
      const res = await api.post("/auth/login", data);

      setIsLoading(false);
      navigate(APP_ROUTE.HOME);
    } catch (err) {
      console.log(err);
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleInvitationSignUp = async (data: IAcceptInvite) => {
    setIsLoading(true);

    try {
      const res = await acceptInvitation(data);
      setIsLoading(false);

      console.log(res);
      setAuthToken(res.tokens);

      navigate(APP_ROUTE.HOME);
    } catch (err) {
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleSetupWorkspace = async (data: ISetupWorkspace) => {
    setIsLoading(true);

    try {
      const res = await setupWorkspace(data);
      setIsLoading(false);

      setAuthToken(res.tokens);

      navigate(APP_ROUTE.HOME);
    } catch (err) {
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleIsAuthenticated = async () => {
    if (!authToken) {
      return false;
    }

    try {
      const accessToken = authToken.accessToken;
      const payload = jwtDecode(accessToken);

      // true if jwt is active
      const now = Date.now().valueOf() / 1000;
      return payload.exp >= now;
    } catch (err) {
      console.log("invalid jwt token", err);
      return false;
    }
  };

  const handleLogout = async () => {
    await api.post("/auth/logout");
    navigate(APP_ROUTE.AUTH.LOGIN);
  };

  return {
    signIn: handleSignIn,
    invitationSignup: handleInvitationSignUp,
    setupWorkspace: handleSetupWorkspace,
    isAuthenticated: handleIsAuthenticated,
    logout: handleLogout,
    isLoading,
  };
}
