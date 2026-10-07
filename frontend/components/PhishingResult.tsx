import SeverityBadge from "@/components/SeverityBadge";
import { CLASSIFICATION_META } from "@/lib/labels";
import type { PhishingAnalysis } from "@/types/api";

export default function PhishingResult({ analysis: a }: { analysis: PhishingAnalysis }) {
  const meta = CLASSIFICATION_META[a.classification];
  return (
    <div className="space-y-4" aria-live="polite">
      <div className="grid grid-cols-2 gap-3 font-mono text-xs">
        <div className="rounded-lg border border-slate-800 bg-cyber-navy p-3">
          <span className="block text-[10px] uppercase text-slate-400">Risk score</span>
          <span className="text-2xl font-bold text-white">{a.risk_score}/100</span>
        </div>
        <div className="rounded-lg border border-slate-800 bg-cyber-navy p-3">
          <span className="block text-[10px] uppercase text-slate-400">Classification</span>
          <span
            className={`mt-1 inline-block rounded-md border px-2 py-0.5 text-sm font-semibold ${meta.classes}`}
          >
            {meta.label}
          </span>
        </div>
      </div>

      <section className="rounded-lg border border-slate-800 bg-cyber-navy p-3">
        <h3 className="mb-2 font-mono text-[10px] uppercase text-slate-400">Why this result</h3>
        <ul className="list-disc space-y-1 pl-4 text-sm text-slate-300">
          {a.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </section>

      {a.indicators.length > 0 && (
        <section className="rounded-lg border border-slate-800 bg-cyber-navy p-3">
          <h3 className="mb-2 font-mono text-[10px] uppercase text-slate-400">
            Indicators ({a.indicators.length})
          </h3>
          <ul className="space-y-3">
            {a.indicators.map((i) => (
              <li key={i.code}>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={i.severity} />
                  <code className="font-mono text-xs text-slate-300">{i.code}</code>
                </div>
                {i.evidence.map((e) => (
                  <p key={e} className="mt-1 break-all font-mono text-xs text-slate-400">
                    {e}
                  </p>
                ))}
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="font-mono text-xs text-slate-400">
        {a.ml.available && a.ml.probability !== null
          ? `ML classifier (${a.ml.model_version}): ${Math.round(a.ml.probability * 100)}% phishing probability.`
          : "Machine-learning classification is not enabled; this result uses rule-based analysis only."}{" "}
        Links found: {a.link_count} · Attachments: {a.attachment_count}
      </p>

      {a.intel && (
        <p className="font-mono text-xs text-slate-400">
          {a.intel.providers.length > 0
            ? `Threat intelligence: ${a.intel.indicators_checked} indicator(s) checked via ${a.intel.providers.join(", ")}.`
            : "Threat intelligence: not checked."}
          {a.intel.note ? ` ${a.intel.note}` : ""}
        </p>
      )}

      <section className="rounded-lg border border-slate-800 bg-cyber-navy p-3">
        <h3 className="mb-1 font-mono text-[10px] uppercase text-slate-400">Recommended action</h3>
        <p className="text-sm text-cyan-300">{a.recommended_action}</p>
      </section>
    </div>
  );
}
