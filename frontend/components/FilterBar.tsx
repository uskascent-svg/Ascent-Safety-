"use client";

import { useEffect, useState } from "react";

import { useRegions } from "@/hooks/useSecurityData";
import { TIME_RANGES, type Filters, type TimeRange } from "@/lib/filters";
import { SEVERITIES, SEVERITY_META, STATUS_LABEL, THREAT_TYPE_LABEL } from "@/lib/labels";
import type { EventStatus, Severity, ThreatType } from "@/types/api";

interface Props {
  value: Filters;
  onChange: (patch: Partial<Filters>) => void;
}

export default function FilterBar({ value, onChange }: Props) {
  const { data: regions } = useRegions(true);
  const [q, setQ] = useState(value.q);

  useEffect(() => {
    const t = setTimeout(() => onChange({ q }), 300);
    return () => clearTimeout(t);
  }, [q, onChange]);

  const toggleSeverity = (s: Severity) =>
    onChange({
      severity: value.severity.includes(s)
        ? value.severity.filter((x) => x !== s)
        : [...value.severity, s],
    });

  return (
    <div className="glass space-y-3 p-4">
      <fieldset>
        <legend className="mb-2 text-xs font-medium text-slate-400">Severity</legend>
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => {
            const on = value.severity.includes(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                onClick={() => toggleSeverity(s)}
                className={`rounded-md border px-2.5 py-1 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent ${
                  on ? SEVERITY_META[s].classes : "border-white/15 text-slate-300 hover:bg-white/5"
                }`}
              >
                {SEVERITY_META[s].label}
              </button>
            );
          })}
        </div>
      </fieldset>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <label className="text-xs text-slate-400">
          Time
          <select
            className="field mt-1"
            value={value.range}
            onChange={(e) => onChange({ range: e.target.value as TimeRange })}
          >
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Threat type
          <select
            className="field mt-1"
            value={value.threatType[0] ?? ""}
            onChange={(e) =>
              onChange({ threatType: e.target.value ? [e.target.value as ThreatType] : [] })
            }
          >
            <option value="">All types</option>
            {Object.entries(THREAT_TYPE_LABEL).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Status
          <select
            className="field mt-1"
            value={value.status[0] ?? ""}
            onChange={(e) =>
              onChange({ status: e.target.value ? [e.target.value as EventStatus] : [] })
            }
          >
            <option value="">All statuses</option>
            {Object.entries(STATUS_LABEL).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Region
          <select
            className="field mt-1"
            value={value.region}
            onChange={(e) => onChange({ region: e.target.value })}
          >
            <option value="">All regions</option>
            {regions?.map((r) => (
              <option key={r.region} value={r.region}>
                {r.region}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Search
          <input
            type="search"
            className="field mt-1"
            placeholder="Title or description"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
      </div>
    </div>
  );
}
