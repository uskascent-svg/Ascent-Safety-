"use client";

import { ErrorState, Skeleton } from "@/components/States";
import { useSummary } from "@/hooks/useSecurityData";
import type { Filters } from "@/lib/filters";

const CARDS = [
  { key: "total_events", label: "Total Security Events" },
  { key: "active_threats", label: "Active Threats" },
  { key: "blocked_threats", label: "Blocked Threats" },
  { key: "critical_events", label: "Critical Events" },
  { key: "affected_regions", label: "Affected Regions" },
] as const;

export default function KpiCards({ filters }: { filters: Filters }) {
  const { data, isPending, isError, refetch } = useSummary(filters, true);

  if (isError) {
    return (
      <div className="glass">
        <ErrorState message="Could not load summary statistics." onRetry={() => refetch()} />
      </div>
    );
  }

  return (
    <section aria-label="Summary statistics">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {CARDS.map((c) => (
          <div key={c.key} className="glass p-4">
            <dt className="font-mono text-[11px] uppercase tracking-wide text-slate-400">
              {c.label}
            </dt>
            <dd className="mt-2 text-2xl font-semibold text-white">
              {isPending ? <Skeleton className="h-8 w-16" /> : data[c.key].toLocaleString()}
            </dd>
          </div>
        ))}
      </dl>
      {data?.total_events === 0 && (
        <p className="mt-2 text-xs text-slate-400">
          Awaiting security telemetry — no events match the current filters.
        </p>
      )}
    </section>
  );
}
