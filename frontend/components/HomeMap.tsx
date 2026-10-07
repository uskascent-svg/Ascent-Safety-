"use client";

import { ArrowRight, BookOpen, Compass, Shield } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import AlertsPanel from "@/components/AlertsPanel";
import { GlobalThreatPanel, RegionsPanel, SystemStatusPanel, ThreatCategoriesPanel, ThreatTimelinePanel } from "@/components/AnalyticsPanels";
import EventDetail from "@/components/EventDetail";
import EventFeed from "@/components/EventFeed";
import KpiCards from "@/components/KpiCards";
import { useLiveUpdates } from "@/hooks/useLiveUpdates";
import { useAuth } from "@/lib/auth";
import { defaultFilters } from "@/lib/filters";

const MODULES = [
  { href: "/security-panel", title: "Security", description: "Review protected events, alerts, and telemetry activity.", icon: Shield, label: "Analyst workspace" },
  { href: "/case-studies", title: "Case studies", description: "Explore incident records marked resolved by your team.", icon: BookOpen, label: "Resolved records" },
  { href: "/guidance", title: "Personal guidance", description: "Get help with the product’s documented workflows.", icon: Compass, label: "Curated assistant" },
];

function WorkspaceModules() {
  return (
    <section id="workspace-panels" className="mx-auto max-w-[1480px] scroll-mt-20 px-4 py-16 sm:px-6 lg:px-9 lg:py-20">
      <div className="mb-7 max-w-2xl"><p className="eyebrow">Workspace</p><h2 className="mt-3 text-2xl font-medium tracking-tight text-white sm:text-3xl">Tools for a clearer response.</h2><p className="mt-2 text-sm text-slate-500">Open a workspace panel. Protected security records remain limited to authorized roles.</p></div>
      <div className="grid gap-3 md:grid-cols-3">
        {MODULES.map(({ href, title, description, icon: Icon, label }) => <Link key={href} href={href} className="glass interactive-panel group p-5 sm:p-6">
          <div className="flex items-start justify-between"><span className="grid h-10 w-10 place-items-center rounded-lg border border-white/[0.08] bg-white/[0.025] text-accent-strong"><Icon className="h-[18px] w-[18px]" aria-hidden="true" /></span><ArrowRight className="mt-1 h-4 w-4 text-slate-600 transition group-hover:translate-x-1 group-hover:text-accent-strong" aria-hidden="true" /></div>
          <p className="mt-6 text-[9px] uppercase tracking-[0.16em] text-slate-600">{label}</p><h3 className="mt-1 text-base font-medium text-white">{title}</h3><p className="mt-2 text-xs leading-relaxed text-slate-500">{description}</p>
        </Link>)}
      </div>
    </section>
  );
}

function LiveDashboard() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const live = useLiveUpdates(true);
  const { isAdmin } = useAuth();

  return (
    <section id="workspace-panels" className="mx-auto max-w-[1480px] scroll-mt-20 px-4 py-12 sm:px-6 lg:px-9 lg:py-16">
      <div className="mb-7 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div><p className="eyebrow">Security operations</p><h2 className="mt-2 text-2xl font-medium tracking-tight text-white sm:text-3xl">Workspace overview</h2><p className="mt-2 text-sm text-slate-500">Live event records and aggregates from connected sources.</p></div>
        <span className="inline-flex items-center gap-2 text-[11px] text-slate-400" role="status"><span className={`h-1.5 w-1.5 rounded-full ${live === "live" ? "bg-emerald-400" : "bg-amber-400 animate-pulse"}`} />{live === "live" ? "Event stream connected" : live === "connecting" ? "Connecting event stream" : "Reconnecting event stream"}</span>
      </div>

      {isAdmin && <section aria-labelledby="connect-telemetry-heading" className="glass mb-4 flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"><div><h3 id="connect-telemetry-heading" className="text-sm font-medium text-white">Connect telemetry</h3><p className="mt-1 text-xs text-slate-500">Analyze reports from security sources you operate.</p></div><div className="flex flex-wrap gap-2"><Link href="/endpoints" className="btn-secondary !px-3 !py-2 text-xs">Endpoints</Link><Link href="/sensors" className="btn-secondary !px-3 !py-2 text-xs">Network sensors</Link></div></section>}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(280px,0.75fr)]">
        <KpiCards filters={defaultFilters} />
        <GlobalThreatPanel />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(300px,0.7fr)]">
        <ThreatTimelinePanel filters={defaultFilters} />
        <SystemStatusPanel live={live} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <RegionsPanel filters={defaultFilters} />
        <ThreatCategoriesPanel filters={defaultFilters} />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.75fr)]">
        <EventFeed filters={defaultFilters} page={page} onPage={setPage} selectedId={selectedId} onSelect={setSelectedId} className="max-h-[560px] lg:min-h-[430px]" />
        <AlertsPanel onSelect={setSelectedId} />
      </div>
      <p className="mt-3 text-[11px] text-slate-600">Threat locations and routes are visualized in the Earth above. No coordinates are inferred for unlocated events.</p>
      {selectedId && <EventDetail id={selectedId} onClose={() => setSelectedId(null)} />}
    </section>
  );
}

export default function HomeMap() {
  const { status, canViewPanel } = useAuth();
  if (status === "loading") return <div id="workspace-panels" className="min-h-64" />;
  return canViewPanel ? <LiveDashboard /> : <WorkspaceModules />;
}
