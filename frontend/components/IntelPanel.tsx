"use client";

import { useMutation } from "@tanstack/react-query";

import IntelResults from "@/components/IntelResults";
import { ErrorState, Skeleton } from "@/components/States";
import { api } from "@/lib/api";
import type { IntelLookup } from "@/types/api";

/** On-demand source-IP reputation for an event. Runs only when the analyst asks (uses API quota). */
export default function IntelPanel({ eventId }: { eventId: string }) {
  const check = useMutation({
    mutationFn: () => api<IntelLookup>(`/api/security-events/${eventId}/intel`),
  });

  return (
    <section className="mt-6" aria-label="Threat intelligence">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">Threat intelligence</h3>
        <button
          type="button"
          className="btn-secondary !px-3 !py-1 text-xs"
          disabled={check.isPending}
          onClick={() => check.mutate()}
        >
          {check.data ? "Re-check" : "Check IP reputation"}
        </button>
      </div>
      <p className="mt-1 text-xs text-slate-500">
        Sends this event&apos;s source IP to the configured reputation services.
      </p>
      <div className="mt-3">
        {check.isPending && <Skeleton className="h-24 w-full" />}
        {check.isError && <ErrorState message={check.error.message} />}
        {check.data && !check.isPending && <IntelResults lookup={check.data} />}
      </div>
    </section>
  );
}
