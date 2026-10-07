import { PROVIDER_LABEL, VERDICT_META } from "@/lib/labels";
import type { IntelLookup } from "@/types/api";

const STATUS_TEXT: Record<string, string> = {
  not_found: "No record",
  rate_limited: "Rate limited",
  error: "Unavailable",
};

function formatDetail(detail: Record<string, unknown>): string {
  return Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(
      ([k, v]) =>
        `${k.replace(/_/g, " ")}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`,
    )
    .join(" · ");
}

export default function IntelResults({ lookup }: { lookup: IntelLookup }) {
  const overall = VERDICT_META[lookup.verdict];
  return (
    <div className="space-y-3" aria-live="polite">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-slate-400">Overall</span>
        <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${overall.classes}`}>
          {overall.label}
        </span>
      </div>
      <ul className="space-y-2">
        {lookup.results.map((r) => {
          const meta = VERDICT_META[r.verdict];
          return (
            <li key={r.provider} className="rounded-lg border border-slate-800 bg-cyber-navy p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-slate-100">
                  {PROVIDER_LABEL[r.provider] ?? r.provider}
                </span>
                {r.status === "ok" ? (
                  <span
                    className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${meta.classes}`}
                  >
                    {meta.label}
                  </span>
                ) : (
                  <span className="text-xs text-slate-400">
                    {STATUS_TEXT[r.status] ?? r.status}
                  </span>
                )}
              </div>
              {formatDetail(r.detail) && (
                <p className="mt-1 break-words font-mono text-xs text-slate-400">
                  {formatDetail(r.detail)}
                </p>
              )}
              {r.cached && <p className="mt-1 text-[11px] text-slate-500">Cached result</p>}
            </li>
          );
        })}
      </ul>
      <p className="text-xs text-slate-500">{lookup.note}</p>
    </div>
  );
}
