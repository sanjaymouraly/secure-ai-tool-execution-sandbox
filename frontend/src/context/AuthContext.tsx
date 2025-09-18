import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { ApiError, api } from "../api/client";
import type { CurrentUser } from "../api/client";

interface Permissions {
  can_approve: boolean;
  can_edit_policy: boolean;
  can_run_attack_lab: boolean;
}

interface AuthState {
  user: CurrentUser | null;
  permissions: Permissions;
  authMode: string;
  loading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

const EMPTY_PERMISSIONS: Permissions = {
  can_approve: false,
  can_edit_policy: false,
  can_run_attack_lab: false,
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [permissions, setPermissions] = useState<Permissions>(EMPTY_PERMISSIONS);
  const [authMode, setAuthMode] = useState("multiuser");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.get<{
        user: CurrentUser;
        auth_mode: string;
        permissions: Permissions;
      }>("/auth/me");
      setUser(data.user);
      setPermissions(data.permissions);
      setAuthMode(data.auth_mode);
      setError(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        setUser(null);
        setPermissions(EMPTY_PERMISSIONS);
      } else {
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    setError(null);
    try {
      await api.post("/auth/login", { username, password });
      await refresh();
    } catch (caught) {
      const message =
        caught instanceof ApiError ? caught.detail : caught instanceof Error ? caught.message : String(caught);
      setError(message);
      throw caught;
    }
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      /* the session is cleared regardless */
    }
    setUser(null);
    setPermissions(EMPTY_PERMISSIONS);
  }, []);

  const value = useMemo<AuthState>(
    () => ({ user, permissions, authMode, loading, error, login, logout, refresh }),
    [user, permissions, authMode, loading, error, login, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside an AuthProvider");
  return context;
}
