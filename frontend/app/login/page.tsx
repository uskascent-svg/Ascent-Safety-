"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";

import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";

export default function LoginPage() {
  const { login, register } = useAuth();
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const email = String(data.get("email"));
    const password = String(data.get("password"));
    setBusy(true);
    setError(null);
    try {
      const user =
        mode === "login"
          ? await login(email, password)
          : await register(email, password, String(data.get("full_name")));
      const canViewPanel = user.roles.some(
        (role) => role === "SECURITY_ANALYST" || role === "ADMINISTRATOR",
      );
      router.push(canViewPanel ? "/security-panel" : "/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Invalid email or password. If you are new, choose “Need an account? Register” below.");
      } else {
        setError(err instanceof Error ? err.message : "Something went wrong.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto grid min-h-[calc(100svh-60px)] max-w-6xl items-center gap-8 px-4 py-10 sm:px-6 lg:grid-cols-2 lg:gap-16 lg:px-10">
      <div className="hidden max-w-lg lg:block">
        <p className="eyebrow flex items-center gap-2"><LockKeyhole className="h-3.5 w-3.5" aria-hidden="true" /> Secure workspace access</p>
        <h1 className="mt-5 text-4xl font-light leading-tight tracking-tight text-white">A clearer view of your security operations.</h1>
        <p className="mt-4 max-w-md text-sm leading-relaxed text-slate-400">Sign in to review data your connected sources have reported. Access to event records is determined by your account role.</p>
        <div className="mt-8 flex items-center gap-3 border-t border-white/[0.07] pt-5 text-xs text-slate-500"><ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" />Role-based access · protected event data</div>
      </div>
      <form onSubmit={onSubmit} className="glass mx-auto w-full max-w-md space-y-4 p-6 sm:p-8" aria-labelledby="auth-title">
        <div className="mb-5"><p className="eyebrow">Ascent Safety</p><h2 id="auth-title" className="mt-2 text-xl font-semibold text-white">
          {mode === "login" ? "Sign in" : "Create account"}
        </h2><p className="mt-1 text-xs text-slate-500">Continue to your security workspace.</p></div>
        {mode === "register" && (
          <label className="block text-sm text-slate-300">
            Full name
            <input
              name="full_name"
              required
              maxLength={120}
              autoComplete="name"
              className="field mt-1"
            />
          </label>
        )}
        <label className="block text-sm text-slate-300">
          Email
          <input name="email" type="email" required autoComplete="email" className="field mt-1" />
        </label>
        <label className="block text-sm text-slate-300">
          Password
          <input
            name="password"
            type="password"
            required
            minLength={mode === "register" ? 12 : 1}
            maxLength={128}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            className="field mt-1"
          />
          {mode === "register" && (
            <span className="mt-1 block text-xs text-slate-400">At least 12 characters.</span>
          )}
        </label>
        {error && (
          <p role="alert" className="text-sm text-sev-high">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy} className="btn-primary w-full">
          {busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
        </button>
        <button
          type="button"
          className="w-full text-sm text-slate-400 hover:text-white"
          onClick={() => {
            setMode(mode === "login" ? "register" : "login");
            setError(null);
          }}
        >
          {mode === "login" ? "Need an account? Register" : "Already have an account? Sign in"}
        </button>
        {mode === "register" && (
          <p className="text-xs text-slate-400">
            New accounts get standard access. An administrator assigns the Security Analyst role.
          </p>
        )}
      </form>
    </div>
  );
}
