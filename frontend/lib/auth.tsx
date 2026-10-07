"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { api, refreshAccessToken, setAccessToken } from "@/lib/api";
import type { User } from "@/types/api";

type Status = "loading" | "anon" | "authed";

interface AuthValue {
  status: Status;
  user: User | null;
  canViewPanel: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (email: string, password: string, fullName: string) => Promise<User>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);
const PANEL_ROLES = ["SECURITY_ANALYST", "ADMINISTRATOR"];

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<{ status: Status; user: User | null }>({
    status: "loading",
    user: null,
  });
  const queryClient = useQueryClient();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (await refreshAccessToken()) {
        try {
          const user = await api<User>("/api/auth/me");
          if (!cancelled) setState({ status: "authed", user });
          return;
        } catch {
          /* fall through to anon */
        }
      }
      if (!cancelled) setState({ status: "anon", user: null });
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const tokens = await api<{ access_token: string }>(
      "/api/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }) },
      false,
    );
    setAccessToken(tokens.access_token);
    const user = await api<User>("/api/auth/me");
    setState({ status: "authed", user });
    return user;
  }, []);

  const register = useCallback(
    async (email: string, password: string, fullName: string) => {
      await api(
        "/api/auth/register",
        { method: "POST", body: JSON.stringify({ email, password, full_name: fullName }) },
        false,
      );
      return login(email, password);
    },
    [login],
  );

  const logout = useCallback(async () => {
    try {
      await api("/api/auth/logout", { method: "POST" }, false);
    } finally {
      setAccessToken(null);
      queryClient.clear();
      setState({ status: "anon", user: null });
    }
  }, [queryClient]);

  const value = useMemo<AuthValue>(
    () => ({
      ...state,
      canViewPanel: !!state.user?.roles.some((r) => PANEL_ROLES.includes(r)),
      isAdmin: !!state.user?.roles.includes("ADMINISTRATOR"),
      login,
      register,
      logout,
    }),
    [state, login, register, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
