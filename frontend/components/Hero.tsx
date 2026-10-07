"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useState } from "react";

import EventDetail from "@/components/EventDetail";
import ThreatMapPanel from "@/components/ThreatMapPanel";
import { defaultFilters } from "@/lib/filters";
import { useAuth } from "@/lib/auth";

const ThreatGlobe = dynamic(() => import("@/components/ThreatGlobe"), {
  ssr: false,
  loading: () => <div className="h-full w-full bg-transparent" aria-hidden="true" />,
});

export default function Hero() {
  const { status, canViewPanel, user } = useAuth();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [globeError, setGlobeError] = useState<string | null>(null);
  const authorized = status === "authed" && canViewPanel;

  return (
    <section className="relative isolate min-h-[min(850px,calc(100svh-60px))] overflow-hidden border-b border-white/[0.06] bg-[#05070d]">
      <div className="absolute inset-0 lg:left-[15%]" aria-label="Earth visualization">
        {authorized ? (
          <ThreatMapPanel
            filters={defaultFilters}
            selectedId={selectedId}
            onSelect={setSelectedId}
            className="!absolute !inset-0 !rounded-none !border-0 !bg-transparent !shadow-none"
          />
        ) : (
          <ThreatGlobe events={[]} selectedId={null} onSelect={() => undefined} onUnavailable={setGlobeError} />
        )}
      </div>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_70%_48%,transparent_10%,rgba(5,7,13,0.1)_43%,rgba(5,7,13,0.66)_100%)]" />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-[#05070d] via-[#05070d]/85 to-transparent lg:via-[#05070d]/65" />
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-48 bg-gradient-to-t from-[#05070d] to-transparent" />
      {globeError && !authorized && <div className="absolute bottom-20 right-5 z-10 max-w-xs rounded-lg border border-white/[0.08] bg-[#0b1020]/90 px-3 py-2 text-[11px] text-slate-400 sm:right-8 lg:right-12" role="status">{globeError} Sign in to use the event map when WebGL is unavailable.</div>}

      <div className="relative z-10 mx-auto flex min-h-[min(850px,calc(100svh-60px))] max-w-[1480px] flex-col justify-center px-5 pb-20 pt-12 sm:px-8 lg:px-12">
        <div className="max-w-xl">
          <p className="eyebrow flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_12px_rgba(0,217,255,0.7)]" />Ascent Safety <span className="text-slate-700">/</span> Security intelligence</p>
          <h1 className="mt-6 text-4xl font-light leading-[1.08] tracking-[-0.04em] text-white sm:text-5xl lg:text-6xl">
            Clarity across<br /><span className="font-medium">the threat landscape.</span>
          </h1>
          <p className="mt-5 max-w-md text-sm leading-relaxed text-slate-400 sm:text-base">
            Investigate reported security events, understand the evidence, and guide your next response from one workspace.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link href={authorized ? "/security-panel" : "/login"} className="btn-primary">
              {authorized ? "Open security" : "Sign in to security"}
            </Link>
            <Link href="/guidance" className="btn-secondary">Get guidance</Link>
          </div>
          <p className="mt-5 max-w-sm text-[11px] leading-relaxed text-slate-600">
            {authorized
              ? "Markers and routes reflect coordinates reported by your connected sources."
              : user
                ? "The Earth preview contains no event data. Your current role does not include access to protected security records."
                : "The Earth preview contains no threat records. Sign in with an authorized security account to view event data."}
          </p>
        </div>

        <div className="absolute bottom-6 left-5 right-5 flex items-center justify-between gap-4 border-t border-white/[0.07] pt-4 sm:left-8 sm:right-8 lg:left-12 lg:right-12">
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.14em] text-slate-600"><span className="h-1 w-1 rounded-full bg-emerald-400" />Coordinates from connected telemetry</div>
          <a href="#workspace-panels" className="text-[10px] uppercase tracking-[0.14em] text-slate-500 transition hover:text-accent-strong">Explore workspace ↓</a>
        </div>
      </div>
      {selectedId && <EventDetail id={selectedId} onClose={() => setSelectedId(null)} />}
    </section>
  );
}
