"use client";

import { X } from "lucide-react";
import { useEffect } from "react";

import IntelPanel from "@/components/IntelPanel";
import { ErrorState, Skeleton } from "@/components/States";
import SeverityBadge from "@/components/SeverityBadge";
import { useEvent } from "@/hooks/useSecurityData";
import { fullDate } from "@/lib/format";
import { STATUS_LABEL, THREAT_TYPE_LABEL } from "@/lib/labels";

export default function EventDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: e, isPending, isError } = useEvent(id);

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => ev.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const rows: [string, string | null | undefined][] = e
    ? [
        ["Threat type", THREAT_TYPE_LABEL[e.threat_type]],
        ["Status", STATUS_LABEL[e.status]],
        ["Source", e.source],
        ["Source reference", e.external_id],
        ["Source IP", e.source_ip],
        ["Country", e.country],
        ["Region", e.region],
        [
          "Coordinates",
          e.latitude != null && e.longitude != null ? `${e.latitude}, ${e.longitude}` : null,
        ],
        [
          "Reported origin",
          e.origin_latitude != null && e.origin_longitude != null
            ? `${e.origin_latitude}, ${e.origin_longitude}`
            : null,
        ],
        [
          "Reported destination",
          e.destination_latitude != null && e.destination_longitude != null
            ? `${e.destination_latitude}, ${e.destination_longitude}`
            : null,
        ],
        ["Occurred", fullDate(e.occurred_at)],
      ]
    : [];

  return (
    <aside
      role="dialog"
      aria-label="Event details"
      className="fixed inset-y-0 right-0 z-50 w-full max-w-md overflow-y-auto border-l border-white/10 bg-ink-900/95 p-5 backdrop-blur-md"
    >
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-lg font-semibold text-white">Event details</h2>
        <button
          type="button"
          onClick={onClose}
          className="btn-secondary !p-1.5"
          aria-label="Close details"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {isPending && <Skeleton className="mt-6 h-40 w-full" />}
      {isError && <ErrorState message="Could not load this event." />}
      {e && (
        <div className="mt-4">
          <SeverityBadge severity={e.severity} />
          <p className="mt-2 text-base font-medium text-slate-100">{e.title}</p>
          {e.description && (
            <p className="mt-2 whitespace-pre-wrap text-sm text-slate-300">{e.description}</p>
          )}
          <dl className="mt-5 space-y-3 text-sm">
            {rows
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <div key={k} className="flex justify-between gap-4 border-b border-white/5 pb-2">
                  <dt className="text-slate-400">{k}</dt>
                  <dd className="text-right text-slate-100 break-all">{v}</dd>
                </div>
              ))}
          </dl>
          {e.source_ip && <IntelPanel key={e.id} eventId={e.id} />}
        </div>
      )}
    </aside>
  );
}
