"use client";

import { ArrowDownRight, ArrowUpRight, Minus, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import { useRegions, useSeverity, useThreatTypes, useTimeline } from "@/hooks/useSecurityData";
import type { LiveStatus } from "@/hooks/useLiveUpdates";
import { defaultFilters, type Filters } from "@/lib/filters";
import { SEVERITIES, SEVERITY_META, THREAT_TYPE_LABEL } from "@/lib/labels";
import type { TimelinePoint } from "@/types/api";

const EMPTY_TIMELINE: TimelinePoint[] = [];

function PanelTitle({ title, caption }: { title: string; caption?: string }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div>
        <h2 className="text-sm font-medium tracking-wide text-slate-100">{title}</h2>
        {caption && <p className="mt-1 text-[11px] text-slate-500">{caption}</p>}
      </div>
    </div>
  );
}

function trendForLastDay(points: { bucket: string; count: number }[]) {
  const split = Date.now() - 12 * 60 * 60 * 1000;
  const previous = points
    .filter((point) => new Date(point.bucket).getTime() < split)
    .reduce((total, point) => total + point.count, 0);
  const current = points
    .filter((point) => new Date(point.bucket).getTime() >= split)
    .reduce((total, point) => total + point.count, 0);
  if (previous === 0 && current === 0) return { label: "No activity", direction: "flat" as const };
  if (previous === 0) return { label: "New activity", direction: "up" as const };
  const change = Math.round(((current - previous) / previous) * 100);
  return {
    label: `${Math.abs(change)}% vs prior 12h`,
    direction: change > 0 ? ("up" as const) : change < 0 ? ("down" as const) : ("flat" as const),
  };
}

export function GlobalThreatPanel() {
  const filters = { ...defaultFilters, range: "24h" as const };
  const severity = useSeverity(filters, true);
  const timeline = useTimeline(filters, "hour", true);
  const highest = SEVERITIES.find((key) => severity.data?.some((row) => row.key === key && row.count > 0));
  const total = severity.data?.reduce((sum, row) => sum + row.count, 0) ?? 0;
  const elevated =
    severity.data?.filter((row) => row.key === "critical" || row.key === "high").reduce((sum, row) => sum + row.count, 0) ?? 0;
  const share = total > 0 ? Math.round((elevated / total) * 100) : 0;
  const trend = trendForLastDay(timeline.data ?? []);
  const severityMeta = highest ? SEVERITY_META[highest as keyof typeof SEVERITY_META] : null;
  const TrendIcon = trend.direction === "up" ? ArrowUpRight : trend.direction === "down" ? ArrowDownRight : Minus;

  return (
    <section className="glass interactive-panel p-5" aria-label="Global threat level">
      <PanelTitle title="Global threat level" caption="Highest severity reported · last 24 hours" />
      {severity.isPending || timeline.isPending ? (
        <Skeleton className="h-24 w-full" />
      ) : severity.isError || timeline.isError ? (
        <ErrorState message="Threat level is unavailable." onRetry={() => { void severity.refetch(); void timeline.refetch(); }} />
      ) : total === 0 ? (
        <div className="flex min-h-24 items-center gap-4">
          <div className="grid h-12 w-12 shrink-0 place-items-center rounded-full border border-slate-700 bg-white/[0.025] text-slate-500">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
          </div>
          <div><p className="text-sm font-medium text-slate-200">No events in this window</p><p className="mt-1 text-xs text-slate-500">Threat level will reflect stored telemetry.</p></div>
        </div>
      ) : (
        <div className="flex items-center gap-5">
          <div className="relative grid h-[82px] w-[82px] shrink-0 place-items-center">
            <svg viewBox="0 0 80 80" className="h-full w-full -rotate-90" aria-hidden="true">
              <circle cx="40" cy="40" r="32" fill="none" stroke="#1e293b" strokeWidth="5" />
              <circle cx="40" cy="40" r="32" fill="none" stroke={severityMeta?.hex ?? "#00d9ff"} strokeWidth="5" strokeLinecap="round" strokeDasharray={`${(share / 100) * 201} 201`} />
            </svg>
            <span className="absolute text-base font-semibold text-white">{share}%</span>
          </div>
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-[0.16em] text-slate-500">Current highest</p>
            <p className={`mt-1 text-xl font-semibold ${severityMeta?.classes.split(" ")[0] ?? "text-slate-300"}`}>
              {severityMeta?.label ?? "No events"}
            </p>
            <div className="mt-2 flex items-center gap-1.5 text-[11px] text-slate-400">
              <TrendIcon className={`h-3.5 w-3.5 ${trend.direction === "up" ? "text-amber-400" : trend.direction === "down" ? "text-emerald-400" : "text-slate-500"}`} aria-hidden="true" />
              <span>{trend.label}</span>
            </div>
          </div>
        </div>
      )}
      <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3 text-[10px] text-slate-500">
        <span>Critical + high share</span><span>Security score: not configured</span>
      </div>
    </section>
  );
}

export function ThreatTimelinePanel({ filters }: { filters: Filters }) {
  const bucket = filters.range === "1h" || filters.range === "24h" ? "hour" : "day";
  const timelineFilters = filters.range === "all" ? { ...filters, range: "30d" as const } : filters;
  const { data, isPending, isError, refetch } = useTimeline(timelineFilters, bucket, true);
  const points = data ?? EMPTY_TIMELINE;
  const max = Math.max(1, ...points.map((point) => point.count));
  const chart = useMemo(() => {
    if (points.length === 0) return { line: "", area: "" };
    const coordinates = points.map((point, index) => {
      const x = 12 + (index / Math.max(1, points.length - 1)) * 576;
      const y = 136 - (point.count / max) * 112;
      return [x, y] as const;
    });
    const line = coordinates.map(([x, y]) => `${x},${y}`).join(" ");
    return { line, area: `12,148 ${line} 588,148` };
  }, [points, max]);

  return (
    <section className="glass interactive-panel p-5" aria-label="Threat timeline">
      <PanelTitle title="Threat timeline" caption={filters.range === "all" ? "Last 30 days · daily buckets" : `${filters.range.toUpperCase()} · ${bucket === "hour" ? "hourly" : "daily"} event counts`} />
      {isPending ? <Skeleton className="h-40 w-full" /> : isError ? <ErrorState message="Timeline data is unavailable." onRetry={() => void refetch()} /> : points.length === 0 ? <EmptyState title="No activity to chart" hint="Timeline points come from stored security events." /> : (
        <div>
          <svg viewBox="0 0 600 160" className="h-40 w-full overflow-visible" role="img" aria-label={`Security event timeline, peak bucket count ${max}`}>
            <defs><linearGradient id="timeline-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#00d9ff" stopOpacity="0.24" /><stop offset="100%" stopColor="#00d9ff" stopOpacity="0" /></linearGradient></defs>
            {[36, 72, 108, 148].map((y) => <line key={y} x1="12" x2="588" y1={y} y2={y} stroke="#1e293b" strokeWidth="1" />)}
            <polygon points={chart.area} fill="url(#timeline-fill)" />
            <polyline points={chart.line} fill="none" stroke="#00d9ff" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
            {points.map((point, index) => {
              const x = 12 + (index / Math.max(1, points.length - 1)) * 576;
              const y = 136 - (point.count / max) * 112;
              return <circle key={point.bucket} cx={x} cy={y} r="2.5" fill="#b2f5ff"><title>{new Date(point.bucket).toLocaleString()}: {point.count}</title></circle>;
            })}
          </svg>
          <div className="mt-1 flex justify-between font-mono text-[9px] text-slate-600">
            <span>{new Date(points[0].bucket).toLocaleDateString()}</span><span>{new Date(points.at(-1)!.bucket).toLocaleDateString()}</span>
          </div>
        </div>
      )}
    </section>
  );
}

export function RegionsPanel({ filters }: { filters: Filters }) {
  const { data, isPending, isError, refetch } = useRegions(true, filters);
  const rows = (data ?? []).slice(0, 5);
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <section className="glass interactive-panel p-5" aria-label="Events by region">
      <PanelTitle title="Regional activity" caption="Event counts by reported region" />
      {isPending ? <div className="space-y-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-8 w-full" />)}</div> : isError ? <ErrorState message="Regional data is unavailable." onRetry={() => void refetch()} /> : rows.length === 0 ? <EmptyState title="No regions reported" hint="Events need a region field to appear here." /> : (
        <ul className="space-y-4">{rows.map((row) => <li key={row.region}>
          <div className="mb-1.5 flex items-center justify-between gap-3 text-xs"><span className="truncate text-slate-300">{row.region}</span><span className="font-mono text-slate-500">{row.count.toLocaleString()}</span></div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className="h-full rounded-full bg-gradient-to-r from-accent/70 to-blue-500/70" style={{ width: `${Math.max(3, (row.count / max) * 100)}%` }} /></div>
        </li>)}</ul>
      )}
      <p className="mt-4 border-t border-white/[0.06] pt-3 text-[10px] text-slate-600">Counts reflect the selected event filter: {filters.range}.</p>
    </section>
  );
}

export function ThreatCategoriesPanel({ filters }: { filters: Filters }) {
  const { data, isPending, isError, refetch } = useThreatTypes(filters, true);
  const rows = data ?? [];
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <section className="glass interactive-panel p-5" aria-label="Threat categories">
      <PanelTitle title="Threat categories" caption="Classification from stored event records" />
      {isPending ? <div className="space-y-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-8 w-full" />)}</div> : isError ? <ErrorState message="Category data is unavailable." onRetry={() => void refetch()} /> : rows.length === 0 ? <EmptyState title="No categories reported" hint="Threat types appear after a source reports an event." /> : (
        <ul className="space-y-3">{rows.map((row) => <li key={row.key}>
          <div className="mb-1 flex items-center justify-between gap-3 text-xs"><span className="truncate text-slate-300">{THREAT_TYPE_LABEL[row.key as keyof typeof THREAT_TYPE_LABEL] ?? row.key}</span><span className="font-mono text-slate-500">{row.count.toLocaleString()}</span></div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className="h-full rounded-full bg-accent/80" style={{ width: `${Math.max(3, (row.count / max) * 100)}%` }} /></div>
        </li>)}</ul>
      )}
      {total > 0 && <p className="mt-4 border-t border-white/[0.06] pt-3 text-[10px] text-slate-600">{total.toLocaleString()} classified events in this view</p>}
    </section>
  );
}

export function SystemStatusPanel({ live }: { live: LiveStatus }) {
  const [ready, setReady] = useState<"checking" | "ready" | "degraded">("checking");
  useEffect(() => {
    let active = true;
    const check = async () => {
      try {
        const response = await fetch("/api/health/ready", { cache: "no-store" });
        const body = (await response.json()) as { status?: string };
        if (active) setReady(response.ok && body.status === "ready" ? "ready" : "degraded");
      } catch { if (active) setReady("degraded"); }
    };
    void check();
    const timer = window.setInterval(check, 30_000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);
  const rows = [
    { label: "API + database", value: ready === "checking" ? "Checking" : ready === "ready" ? "Online" : "Degraded", ok: ready === "ready" },
    { label: "Event stream · SSE", value: live === "live" ? "Connected" : live === "connecting" ? "Connecting" : "Reconnecting", ok: live === "live" },
    { label: "Threat intelligence", value: "Checked per lookup", ok: null },
    { label: "Security guidance", value: "Curated workflows", ok: null },
  ];
  return (
    <section className="glass interactive-panel p-5" aria-label="System status">
      <PanelTitle title="System status" caption="Signals available from this deployment" />
      <ul className="divide-y divide-white/[0.06]">{rows.map((row) => <li key={row.label} className="flex items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
        <span className="flex items-center gap-2 text-xs text-slate-400"><span className={`h-1.5 w-1.5 rounded-full ${row.ok === true ? "bg-emerald-400" : row.ok === false ? "bg-amber-400" : "bg-slate-600"}`} />{row.label}</span>
        <span className={`text-[11px] ${row.ok === true ? "text-emerald-300" : row.ok === false ? "text-amber-300" : "text-slate-500"}`}>{row.value}</span>
      </li>)}</ul>
      <p className="mt-4 text-[10px] leading-relaxed text-slate-600">AI scoring and provider health do not expose aggregate system probes in this deployment.</p>
    </section>
  );
}
