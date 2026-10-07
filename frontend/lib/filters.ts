import type { EventStatus, Severity, ThreatType } from "@/types/api";

export type TimeRange = "1h" | "24h" | "7d" | "30d" | "all";

export interface Filters {
  severity: Severity[];
  threatType: ThreatType[];
  status: EventStatus[];
  region: string;
  q: string;
  range: TimeRange;
}

export const defaultFilters: Filters = {
  severity: [],
  threatType: [],
  status: [],
  region: "",
  q: "",
  range: "24h",
};

export const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "all", label: "All time" },
];

const RANGE_MS: Record<Exclude<TimeRange, "all">, number> = {
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 604_800_000,
  "30d": 2_592_000_000,
};

/** Query string shared by the list, map and dashboard endpoints (they accept identical filters). */
export function toParams(f: Filters, now: number = Date.now()): URLSearchParams {
  const p = new URLSearchParams();
  f.severity.forEach((s) => p.append("severity", s));
  f.threatType.forEach((t) => p.append("threat_type", t));
  f.status.forEach((s) => p.append("status", s));
  if (f.region) p.set("region", f.region);
  if (f.q.trim()) p.set("q", f.q.trim());
  if (f.range !== "all") p.set("since", new Date(now - RANGE_MS[f.range]).toISOString());
  return p;
}
