"use client";

import { ArrowUpRight, BookOpen, ChevronLeft, ChevronRight, MapPin } from "lucide-react";
import { useState } from "react";

import AccessGate from "@/components/AccessGate";
import EventDetail from "@/components/EventDetail";
import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import SeverityBadge from "@/components/SeverityBadge";
import { PAGE_SIZE, useEvents } from "@/hooks/useSecurityData";
import { fullDate } from "@/lib/format";
import { THREAT_TYPE_LABEL } from "@/lib/labels";
import type { EventStatus, Severity, ThreatType } from "@/types/api";

const RESOLVED_FILTER = {
  severity: [] as Severity[],
  threatType: [] as ThreatType[],
  status: ["resolved"] as EventStatus[],
  region: "",
  q: "",
  range: "all" as const,
};

function CaseStudiesView() {
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const { data, isPending, isError, refetch } = useEvents(RESOLVED_FILTER, page, true);
  const total = data?.total ?? 0;

  return (
    <div className="mx-auto max-w-[1480px] px-4 py-8 sm:px-6 lg:px-9 lg:py-10">
      <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div>
          <p className="eyebrow">Learn from resolved incidents</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Case studies</h1>
          <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-400">A reviewable archive built from incidents marked resolved in your event database. Each record links back to its original source and event detail.</p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.025] px-3 py-2 text-xs text-slate-400">
          <BookOpen className="h-4 w-4 text-accent-strong" aria-hidden="true" />
          {isPending ? "Loading records" : `${total.toLocaleString()} resolved records`}
        </div>
      </div>

      {isPending && <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[0, 1, 2].map((item) => <Skeleton key={item} className="h-52 w-full" />)}</div>}
      {isError && <div className="glass"><ErrorState message="Could not load resolved incident records." onRetry={() => void refetch()} /></div>}
      {data && data.items.length === 0 && <div className="glass"><EmptyState title="No resolved incidents yet" hint="When an event is marked Resolved, it will appear here. This page does not use sample or fictional cases." /></div>}
      {data && data.items.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data.items.map((event) => (
            <button key={event.id} type="button" onClick={() => setSelected(event.id)} className="glass interactive-panel group p-5 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent">
              <div className="flex items-start justify-between gap-3"><SeverityBadge severity={event.severity} /><ArrowUpRight className="h-4 w-4 text-slate-600 transition group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-accent-strong" aria-hidden="true" /></div>
              <h2 className="mt-5 line-clamp-2 text-base font-medium leading-snug text-white">{event.title}</h2>
              <p className="mt-2 text-xs text-slate-400">{THREAT_TYPE_LABEL[event.threat_type]}</p>
              {event.description && <p className="mt-3 line-clamp-3 text-xs leading-relaxed text-slate-500">{event.description}</p>}
              <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-3 text-[10px] text-slate-500">
                <span className="inline-flex items-center gap-1.5"><MapPin className="h-3 w-3" aria-hidden="true" />{[event.region, event.country].filter(Boolean).join(" · ") || "No location reported"}</span>
                <time dateTime={event.occurred_at} title={fullDate(event.occurred_at)}>{new Date(event.occurred_at).toLocaleDateString()}</time>
              </div>
            </button>
          ))}
        </div>
      )}
      {total > PAGE_SIZE && <div className="mt-5 flex items-center justify-between text-xs text-slate-500"><span>{page * PAGE_SIZE + 1}–{Math.min(total, (page + 1) * PAGE_SIZE)} of {total}</span><div className="flex gap-2"><button type="button" className="btn-secondary !px-2 !py-1.5" disabled={page === 0} onClick={() => setPage((value) => value - 1)} aria-label="Previous case studies"><ChevronLeft className="h-4 w-4" /></button><button type="button" className="btn-secondary !px-2 !py-1.5" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((value) => value + 1)} aria-label="Next case studies"><ChevronRight className="h-4 w-4" /></button></div></div>}
      {selected && <EventDetail id={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

export default function CaseStudies() {
  return <AccessGate><CaseStudiesView /></AccessGate>;
}
