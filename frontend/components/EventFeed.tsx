"use client";

import { ChevronLeft, ChevronRight } from "lucide-react";

import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import SeverityBadge from "@/components/SeverityBadge";
import { PAGE_SIZE, useEvents } from "@/hooks/useSecurityData";
import type { Filters } from "@/lib/filters";
import { fullDate, timeAgo } from "@/lib/format";
import { STATUS_LABEL, THREAT_TYPE_LABEL } from "@/lib/labels";

interface Props {
  filters: Filters;
  page: number;
  onPage: (page: number) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  className?: string;
}

export default function EventFeed({
  filters,
  page,
  onPage,
  selectedId,
  onSelect,
  className = "",
}: Props) {
  const { data, isPending, isError, refetch } = useEvents(filters, page, true);
  const total = data?.total ?? 0;
  const from = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to = Math.min(total, (page + 1) * PAGE_SIZE);

  return (
    <section aria-label="Recent events" className={`glass flex flex-col ${className}`}>
      <h2 className="border-b border-white/10 px-4 py-3 text-sm font-semibold text-white">
        Recent Events
      </h2>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {isPending && (
          <div className="space-y-3 p-4" role="status" aria-label="Loading events">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        )}
        {isError && <ErrorState message="Could not load events." onRetry={() => refetch()} />}
        {data && data.items.length === 0 && (
          <EmptyState
            title="No security events available"
            hint="Nothing matches the current filters."
          />
        )}
        {data && data.items.length > 0 && (
          <ul className="divide-y divide-white/5">
            {data.items.map((e) => (
              <li key={e.id}>
                <button
                  type="button"
                  onClick={() => onSelect(e.id)}
                  aria-pressed={selectedId === e.id}
                  className={`block w-full px-4 py-3 text-left transition hover:bg-white/5 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent ${
                    selectedId === e.id ? "bg-white/10" : ""
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge severity={e.severity} />
                    <time
                      dateTime={e.occurred_at}
                      title={fullDate(e.occurred_at)}
                      className="text-xs text-slate-400"
                    >
                      {timeAgo(e.occurred_at)}
                    </time>
                  </div>
                  <p className="mt-1.5 truncate text-sm font-medium text-slate-100">{e.title}</p>
                  <p className="mt-0.5 truncate text-xs text-slate-400">
                    {THREAT_TYPE_LABEL[e.threat_type]} · {STATUS_LABEL[e.status]}
                    {e.region ? ` · ${e.region}` : ""}
                    {e.country ? ` · ${e.country}` : ""}
                  </p>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {total > 0 && (
        <div className="flex items-center justify-between border-t border-white/10 px-4 py-2 text-xs text-slate-400">
          <span>
            {from}–{to} of {total}
          </span>
          <span className="flex gap-1">
            <button
              type="button"
              className="btn-secondary !px-2 !py-1"
              disabled={page === 0}
              onClick={() => onPage(page - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              type="button"
              className="btn-secondary !px-2 !py-1"
              disabled={to >= total}
              onClick={() => onPage(page + 1)}
              aria-label="Next page"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </span>
        </div>
      )}
    </section>
  );
}
