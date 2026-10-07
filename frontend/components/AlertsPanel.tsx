"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import SeverityBadge from "@/components/SeverityBadge";
import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { THREAT_TYPE_LABEL } from "@/lib/labels";
import type { Alert, AlertPage } from "@/types/api";

export default function AlertsPanel({ onSelect }: { onSelect: (eventId: string) => void }) {
  const queryClient = useQueryClient();
  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ["security", "alerts"],
    queryFn: () => api<AlertPage>("/api/alerts?status=open&status=acknowledged&limit=10"),
  });
  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "acknowledged" | "resolved" }) =>
      api<Alert>(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["security"] }),
  });

  return (
    <section id="alerts-list" aria-labelledby="alerts-title" className="glass">
      <h2 id="alerts-title" className="panel-heading">
        Open Alerts{data ? ` (${data.total})` : ""}
      </h2>
      {isPending && (
        <div className="space-y-2 p-4" role="status" aria-label="Loading alerts">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      )}
      {isError && <ErrorState message="Could not load alerts." onRetry={() => refetch()} />}
      {data && data.items.length === 0 && (
        <EmptyState
          title="No open alerts"
          hint="Alerts are created when a stored event meets the alert severity threshold."
        />
      )}
      {update.isError && (
        <p role="alert" className="px-4 pt-3 text-sm text-sev-high">
          {update.error.message}
        </p>
      )}
      {data && data.items.length > 0 && (
        <ul className="divide-y divide-white/5">
          {data.items.map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <button
                type="button"
                onClick={() => onSelect(a.event_id)}
                className="min-w-0 flex-1 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
              >
                <span className="flex items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="text-xs text-slate-400">
                    {a.status === "acknowledged" ? "Acknowledged" : "Open"} ·{" "}
                    {timeAgo(a.created_at)}
                  </span>
                </span>
                <span className="mt-1 block truncate text-sm font-medium text-slate-100">
                  {a.title}
                </span>
                <span className="block truncate text-xs text-slate-400">
                  {THREAT_TYPE_LABEL[a.threat_type]} · {a.source}
                  {a.region ? ` · ${a.region}` : ""}
                </span>
              </button>
              <span className="flex gap-2">
                {a.status === "open" && (
                  <button
                    type="button"
                    className="btn-secondary !px-3 !py-1 text-xs"
                    disabled={update.isPending}
                    onClick={() => update.mutate({ id: a.id, status: "acknowledged" })}
                  >
                    Acknowledge
                  </button>
                )}
                <button
                  type="button"
                  className="btn-secondary !px-3 !py-1 text-xs"
                  disabled={update.isPending}
                  onClick={() => update.mutate({ id: a.id, status: "resolved" })}
                >
                  Resolve
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
