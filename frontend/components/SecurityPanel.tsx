"use client";

import { useCallback, useEffect, useState } from "react";

import AccessGate from "@/components/AccessGate";
import AlertsPanel from "@/components/AlertsPanel";
import CyberAlertsPanel, { ActiveCyberAlertBanner } from "@/components/CyberAlertsPanel";
import { GlobalThreatPanel, RegionsPanel, SystemStatusPanel, ThreatCategoriesPanel, ThreatTimelinePanel } from "@/components/AnalyticsPanels";
import EventDetail from "@/components/EventDetail";
import EventFeed from "@/components/EventFeed";
import FilterBar from "@/components/FilterBar";
import KpiCards from "@/components/KpiCards";
import ThreatMapPanel from "@/components/ThreatMapPanel";
import { useLiveUpdates, type LiveStatus } from "@/hooks/useLiveUpdates";
import { useAuth } from "@/lib/auth";
import { defaultFilters, type Filters } from "@/lib/filters";
import Link from "next/link";

const LIVE_LABEL: Record<LiveStatus, string> = {
  connecting: "Connecting…",
  live: "Live",
  reconnecting: "Reconnecting…",
};

function Panel() {
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const [page, setPage] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const live = useLiveUpdates(true);
  const { isAdmin } = useAuth();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const query = params.get("q")?.trim();
    const eventId = params.get("event_id")?.trim();
    const timer = window.setTimeout(() => {
      if (query) setFilters((current) => ({ ...current, q: query }));
      if (eventId) setSelectedId(eventId);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const onFilters = useCallback((patch: Partial<Filters>) => {
    setFilters((f) => {
      const next = { ...f, ...patch };
      return JSON.stringify(next) === JSON.stringify(f) ? f : next;
    });
    setPage(0);
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-white">Security Panel</h1>
        <span className="flex items-center gap-4 text-xs text-slate-300">
          {isAdmin && (
            <>
              <Link href="/endpoints" className="text-accent-strong hover:underline">
                Manage endpoints
              </Link>
              <Link href="/sensors" className="text-accent-strong hover:underline">
                Manage sensors
              </Link>
            </>
          )}
          <span className="flex items-center gap-2" role="status">
            <span
              aria-hidden="true"
              className={`h-2 w-2 rounded-full ${live === "live" ? "bg-accent" : "bg-slate-500"}`}
            />
            {LIVE_LABEL[live]}
          </span>
        </span>
      </div>

      <FilterBar key={filters.q} value={filters} onChange={onFilters} />
      <ActiveCyberAlertBanner />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(300px,0.75fr)]">
        <KpiCards filters={filters} />
        <GlobalThreatPanel />
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(300px,0.7fr)]">
        <ThreatTimelinePanel filters={filters} />
        <SystemStatusPanel live={live} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <RegionsPanel filters={filters} />
        <ThreatCategoriesPanel filters={filters} />
      </div>
      <AlertsPanel onSelect={setSelectedId} />
      <CyberAlertsPanel />

      <div className="grid gap-4 lg:grid-cols-3">
        <ThreatMapPanel
          filters={filters}
          selectedId={selectedId}
          onSelect={setSelectedId}
          onRangeChange={(range) => onFilters({ range })}
          className="h-[360px] sm:h-[460px] lg:col-span-2 lg:h-[620px]"
        />
        <EventFeed
          filters={filters}
          page={page}
          onPage={setPage}
          selectedId={selectedId}
          onSelect={setSelectedId}
          className="max-h-[520px] lg:h-[620px] lg:max-h-none"
        />
      </div>

      {selectedId && <EventDetail id={selectedId} onClose={() => setSelectedId(null)} />}
    </div>
  );
}

export default function SecurityPanel() {
  return (
    <AccessGate>
      <Panel />
    </AccessGate>
  );
}
