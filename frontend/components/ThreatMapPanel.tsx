"use client";

import dynamic from "next/dynamic";
import { useState } from "react";

import { EmptyState, ErrorState } from "@/components/States";
import { useLocations } from "@/hooks/useSecurityData";
import { TIME_RANGES, type Filters, type TimeRange } from "@/lib/filters";

// Both WebGL visualizations are client-only; the existing 2D map remains available as a fallback.
const ThreatGlobe = dynamic(() => import("@/components/ThreatGlobe"), {
  ssr: false,
  loading: () => <div className="h-full w-full animate-pulse bg-white/5" aria-hidden="true" />,
});
const ThreatMap = dynamic(() => import("@/components/ThreatMap"), {
  ssr: false,
  loading: () => <div className="h-full w-full animate-pulse bg-white/5" aria-hidden="true" />,
});

interface Props {
  filters: Filters;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onRangeChange?: (range: TimeRange) => void;
  className?: string;
}

export default function ThreatMapPanel({ filters, selectedId, onSelect, onRangeChange, className = "" }: Props) {
  const { data, isPending, isError, refetch } = useLocations(filters, true);
  const events = data?.items ?? [];
  const globeEvents = events.slice(0, 250);
  const mappedEvents = events.filter((event) => event.latitude !== null && event.longitude !== null);
  const [view, setView] = useState<"globe" | "map">("globe");
  const [displayMode, setDisplayMode] = useState<"markers" | "heatmap">("markers");
  const [fallbackReason, setFallbackReason] = useState<string | null>(null);

  return (
    <div className={`glass relative overflow-hidden ${className}`}>
      {view === "globe" ? (
        <ThreatGlobe
          events={globeEvents}
          selectedId={selectedId}
          onSelect={onSelect}
          onUnavailable={(reason) => {
            setFallbackReason(reason);
            setView("map");
          }}
        />
      ) : (
        <ThreatMap events={events} selectedId={selectedId} onSelect={onSelect} displayMode={displayMode} />
      )}

      <div
        className="absolute left-3 top-3 z-10 inline-flex rounded-md border border-slate-700 bg-cyber-black/90 p-1"
        role="group"
        aria-label="Threat visualization mode"
      >
        <button
          type="button"
          aria-pressed={view === "globe"}
          className={`rounded px-2.5 py-1.5 text-xs ${view === "globe" ? "bg-slate-700 text-white" : "text-slate-400 hover:text-white"}`}
          onClick={() => setView("globe")}
        >
          3D Earth
        </button>
        <button
          type="button"
          aria-pressed={view === "map"}
          className={`rounded px-2.5 py-1.5 text-xs ${view === "map" ? "bg-slate-700 text-white" : "text-slate-400 hover:text-white"}`}
          onClick={() => setView("map")}
        >
          2D map
        </button>
      </div>

      <div className="absolute right-3 top-3 z-10 flex flex-wrap items-center justify-end gap-2">
        <label className="flex h-9 items-center gap-2 rounded-md border border-slate-700 bg-cyber-black/90 px-2.5 text-[11px] text-slate-400">
          <span>Range</span>
          <select
            aria-label="Threat visualization time range"
            className="max-w-28 bg-transparent text-xs text-slate-200 outline-none"
            value={filters.range}
            onChange={(event) => onRangeChange?.(event.target.value as TimeRange)}
            disabled={!onRangeChange}
          >
            {TIME_RANGES.map((range) => <option key={range.value} value={range.value} className="bg-slate-900">{range.label}</option>)}
          </select>
        </label>
        {view === "map" && (
          <div className="inline-flex h-9 items-center rounded-md border border-slate-700 bg-cyber-black/90 p-1" role="group" aria-label="Map data display">
            {(["markers", "heatmap"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                aria-pressed={displayMode === mode}
                className={`rounded px-2 py-1 text-[11px] capitalize ${displayMode === mode ? "bg-slate-700 text-white" : "text-slate-400 hover:text-white"}`}
                onClick={() => setDisplayMode(mode)}
              >{mode}</button>
            ))}
          </div>
        )}
      </div>

      {fallbackReason && view === "map" && (
        <p className="absolute bottom-10 left-3 max-w-sm rounded bg-cyber-black/90 px-2 py-1 text-xs text-slate-300" role="status">
          {fallbackReason} The event feed remains available.
        </p>
      )}

      {isPending && (
        <div className="absolute inset-0 grid place-items-center bg-ink-950/60" role="status">
          <span className="text-sm text-slate-300">Loading security events…</span>
        </div>
      )}
      {isError && (
        <div className="absolute inset-0 grid place-items-center bg-ink-950/80">
          <ErrorState message="Could not load threat locations." onRetry={() => refetch()} />
        </div>
      )}
      {data && events.length === 0 && (
        <div className="pointer-events-none absolute inset-x-0 top-4 flex justify-center">
          <div className="glass bg-ink-950/80">
            <EmptyState
              title="No geographic event data yet"
              hint="Connected sources can report an event location or an explicit origin and destination route."
            />
          </div>
        </div>
      )}
      {data && view === "map" && events.length > 0 && mappedEvents.length === 0 && (
        <div className="pointer-events-none absolute inset-x-0 top-4 flex justify-center">
          <div className="glass bg-ink-950/90">
            <EmptyState
              title="Routes are shown on the 3D Earth"
              hint="The 2D map can display reported event locations. This result contains explicit route endpoints only."
            />
          </div>
        </div>
      )}
      {data && (data.truncated || globeEvents.length < events.length) && (
        <p className="absolute bottom-2 left-2 rounded bg-ink-950/80 px-2 py-1 text-xs text-slate-300">
          Showing {view === "globe" ? globeEvents.length : events.length} of {data.total} geographic events.
        </p>
      )}
    </div>
  );
}
