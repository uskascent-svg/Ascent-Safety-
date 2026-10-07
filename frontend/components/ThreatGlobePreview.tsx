"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useState } from "react";

import type { User } from "@/types/api";

const ThreatGlobe = dynamic(() => import("@/components/ThreatGlobe"), {
  ssr: false,
  loading: () => <div className="h-full w-full animate-pulse bg-white/5" aria-hidden="true" />,
});

export default function ThreatGlobePreview({ user }: { user: User | null }) {
  const [unavailable, setUnavailable] = useState<string | null>(null);

  return (
    <section className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:py-10">
      <div className="grid gap-6 lg:grid-cols-[minmax(18rem,0.72fr)_minmax(0,1.28fr)]">
        <div className="flex flex-col justify-center py-3 lg:py-8">
          <p className="eyebrow">Global security intelligence</p>
          <h2 className="mt-3 max-w-xl text-3xl font-semibold leading-tight tracking-tight text-white sm:text-4xl">
            A clearer view of the signals that matter.
          </h2>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-slate-300 sm:text-base">
            Ascent Safety analyzes events reported by connected security sources. Location markers
            and routes appear only when an authorized event includes those coordinates.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            {!user && (
              <Link href="/login" className="btn-primary">
                Sign in
              </Link>
            )}
            <Link href="/phishing" className="btn-secondary">
              Analyze a message
            </Link>
          </div>
          <p className="mt-5 max-w-lg border-l border-slate-700 pl-3 text-xs leading-relaxed text-slate-400">
            {user
              ? "Your account can use the phishing tools. Ask an administrator to assign the Security Analyst role to view protected event locations."
              : "The Earth preview contains no threat markers. Sign in with a Security Analyst or Administrator account to access protected event data."}
          </p>
        </div>

        <div className="glass relative h-[320px] overflow-hidden sm:h-[400px] lg:h-[480px]">
          <ThreatGlobe
            events={[]}
            selectedId={null}
            onSelect={() => undefined}
            onUnavailable={setUnavailable}
          />
          {unavailable && (
            <div className="absolute inset-0 z-10 grid place-items-center bg-cyber-black/90 p-6 text-center" role="status">
              <p className="max-w-sm text-sm text-slate-300">
                {unavailable} The map and event feed will be available after an authorized sign-in.
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
