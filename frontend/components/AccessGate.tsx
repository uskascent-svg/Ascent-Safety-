"use client";

import { Lock } from "lucide-react";
import Link from "next/link";

import { Skeleton } from "@/components/States";
import { useAuth } from "@/lib/auth";

/** Renders children only for analysts/administrators; otherwise an honest explanation. */
export default function AccessGate({ children }: { children: React.ReactNode }) {
  const { status, canViewPanel } = useAuth();

  if (status === "loading") return <Skeleton className="h-64 w-full" />;
  if (status === "anon") {
    return (
      <Gate text="Sign in with a security analyst or administrator account to view live security events.">
        <Link href="/login" className="btn-primary">
          Sign in
        </Link>
      </Gate>
    );
  }
  if (!canViewPanel) {
    return (
      <Gate text="Your account does not have access to security events. Ask an administrator to assign the Security Analyst role." />
    );
  }
  return <>{children}</>;
}

function Gate({ text, children }: { text: string; children?: React.ReactNode }) {
  return (
    <div className="glass flex flex-col items-center gap-3 px-6 py-12 text-center" role="status">
      <Lock className="h-6 w-6 text-accent" aria-hidden="true" />
      <p className="max-w-md text-sm text-slate-300">{text}</p>
      {children}
    </div>
  );
}
