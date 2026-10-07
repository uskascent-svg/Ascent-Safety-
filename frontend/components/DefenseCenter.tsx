"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import AccessGate from "@/components/AccessGate";
import AlertsPanel from "@/components/AlertsPanel";
import EventDetail from "@/components/EventDetail";
import EventFeed from "@/components/EventFeed";
import EndpointsAdmin from "@/components/EndpointsAdmin";
import ThreatMapPanel from "@/components/ThreatMapPanel";
import { useLiveUpdates } from "@/hooks/useLiveUpdates";
import { api } from "@/lib/api";
import { defaultFilters } from "@/lib/filters";
import { timeAgo } from "@/lib/format";
import { useAuth } from "@/lib/auth";
import type { AlertPage, Endpoint } from "@/types/api";

function DefenseContent() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { isAdmin } = useAuth();
  const live = useLiveUpdates(true);
  const endpoints = useQuery({
    queryKey: ["security", "endpoints"],
    queryFn: () => api<Endpoint[]>("/api/endpoints"),
  });
  const alerts = useQuery({
    queryKey: ["security", "malware-alerts"],
    queryFn: () => api<AlertPage>("/api/alerts?status=open&status=acknowledged&severity=critical&severity=high&limit=100"),
  });
  const malwareAlerts = useMemo(
    () => (alerts.data?.items ?? []).filter((item) => item.threat_type === "malware_ransomware"),
    [alerts.data],
  );
  const sources = endpoints.data ?? [];
  const activeSources = sources.filter((item) => item.is_active);
  const [now, setNow] = useState(0);
  useEffect(() => {
    const timer = window.setTimeout(() => setNow(Date.now()), 0);
    return () => window.clearTimeout(timer);
  }, []);
  const reporting = activeSources.filter((item) => item.last_seen_at && now - Date.parse(item.last_seen_at) < 15 * 60_000);
  const inactive = activeSources.length - reporting.length;

  // Event ingestion and admin changes arrive on the existing SSE bus.
  useEffect(() => {
    queryClient.invalidateQueries({ queryKey: ["security"] });
  }, [live, queryClient]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="eyebrow">SOC / ENDPOINT DEFENSE</p>
          <h1 className="mt-1 text-2xl font-semibold text-white sm:text-3xl">Defense Center</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-400">Endpoint health and malware activity reported by connected telemetry sources.</p>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate-300" role="status">
          <span className={`h-2 w-2 rounded-full ${live === "live" ? "bg-emerald-400" : "bg-amber-400"}`} />
          Event stream {live === "live" ? "connected" : live}
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Endpoint health">
        <Metric title="Registered endpoints" value={endpoints.isPending ? "—" : String(sources.length)} detail="Sources registered with this workspace" />
        <Metric title="Active sources" value={endpoints.isPending ? "—" : String(activeSources.length)} detail="Enabled endpoint API keys" />
        <Metric title="Reporting now" value={endpoints.isPending ? "—" : String(reporting.length)} detail="Seen in the last 15 minutes" />
        <Metric title="High / critical alerts" value={alerts.isPending ? "—" : String(malwareAlerts.length)} detail="Unresolved malware telemetry alerts" tone={malwareAlerts.length ? "warning" : "normal"} />
      </section>

      {isAdmin && <div className="flex justify-end"><Link href="#endpoint-sources" className="btn-secondary">Manage endpoint sources</Link></div>}

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(300px,0.75fr)]">
        <ThreatMapPanel
          filters={{ ...defaultFilters, threatType: ["malware_ransomware"] }}
          selectedId={selectedId}
          onSelect={setSelectedId}
          onRangeChange={() => undefined}
          className="h-[360px] sm:h-[460px] xl:h-[540px]"
        />
        <div className="space-y-4">
          <section className="glass p-4">
            <h2 className="panel-heading">Telemetry status</h2>
            {endpoints.isPending ? <p className="mt-3 text-sm text-slate-400">Loading connected sources…</p> : activeSources.length === 0 ? (
              <div className="mt-3 rounded-lg border border-slate-700/70 p-4">
                <p className="text-sm font-medium text-slate-200">No endpoint agent configured</p>
                <p className="mt-1 text-sm text-slate-400">The platform does not include an endpoint agent. Register a source and send telemetry to populate this view.</p>
              </div>
            ) : (
              <ul className="mt-3 divide-y divide-white/5">
                {activeSources.slice(0, 8).map((endpoint) => {
                  const isReporting = endpoint.last_seen_at && now - Date.parse(endpoint.last_seen_at) < 15 * 60_000;
                  return <li key={endpoint.id} className="flex items-center justify-between gap-3 py-3">
                    <div className="min-w-0"><p className="truncate text-sm font-medium text-slate-100">{endpoint.name}</p><p className="text-xs text-slate-400">{endpoint.os} · {endpoint.region ?? endpoint.country ?? "Location unavailable"}</p></div>
                    <span className={`shrink-0 text-xs ${isReporting ? "text-emerald-300" : "text-amber-300"}`}>{endpoint.last_seen_at ? `Seen ${timeAgo(endpoint.last_seen_at)}` : "Never reported"}</span>
                  </li>;
                })}
              </ul>
            )}
            {inactive > 0 && <p className="mt-2 text-xs text-amber-300">{inactive} source{inactive === 1 ? " is" : "s are"} not reporting in the last 15 minutes.</p>}
          </section>
          <section className="glass p-4">
            <h2 className="panel-heading">Ransomware response</h2>
            <p className="mt-2 text-sm text-slate-400">Findings are generated from behavior reported by connected agents. Ascent Safety does not execute, contain, or quarantine endpoints.</p>
          </section>
        </div>
      </section>

      <AlertsPanel onSelect={setSelectedId} />
      <EventFeed filters={{ ...defaultFilters, threatType: ["malware_ransomware"] }} page={0} onPage={() => undefined} selectedId={selectedId} onSelect={setSelectedId} className="max-h-[520px]" />
      {selectedId && <EventDetail id={selectedId} onClose={() => setSelectedId(null)} />}
      {isAdmin && <section id="endpoint-sources" className="scroll-mt-4"><h2 className="mb-3 text-xl font-semibold text-white">Endpoint sources</h2><p className="mb-4 text-sm text-slate-400">Register or deactivate telemetry sources. API keys are shown once at creation.</p><EndpointRegistration /></section>}
    </div>
  );
}

function Metric({ title, value, detail, tone = "normal" }: { title: string; value: string; detail: string; tone?: "normal" | "warning" }) {
  return <div className="glass p-4"><p className="text-xs uppercase tracking-wider text-slate-400">{title}</p><p className={`mt-3 text-3xl font-semibold ${tone === "warning" ? "text-amber-300" : "text-white"}`}>{value}</p><p className="mt-1 text-xs text-slate-500">{detail}</p></div>;
}

function EndpointRegistration() {
  return <EndpointsAdmin />;
}

export default function DefenseCenter() {
  return <AccessGate><DefenseContent /></AccessGate>;
}
