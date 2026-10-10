"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import AccessGate from "@/components/AccessGate";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

type Metrics = {
  refreshed_at: string;
  window_days: number;
  total: number;
  by_verdict: Record<string, number>;
  by_severity: Record<string, number>;
  detection_quality: Record<string, number> | null;
  model_status: { state: string; version?: string | null; metrics?: Record<string, number> };
  detector_runtime: { state: string; model_family: string | null; model_version: string | null };
  source: string;
  note: string;
};

type Feedback = {
  id: string;
  analysis_id: string;
  candidate_label: string;
  status: string;
  reason: string;
  training_sample: string | null;
  created_at: string;
};

type ModelVersion = {
  id: string;
  version: string;
  model_family: string;
  state: string;
  metrics: Record<string, number>;
  created_at: string;
};
type TrainingJob = {
  id: string;
  status: string;
  message: string;
  sample_count: number;
  metrics: Record<string, number> | null;
  finished_at: string | null;
};

function Dashboard() {
  const { canReviewThreatData, canOperateThreatModels } = useAuth();
  const client = useQueryClient();
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [trainingJobId, setTrainingJobId] = useState<string | null>(null);
  const [windowDays, setWindowDays] = useState(30);
  const [rejectNotes, setRejectNotes] = useState<Record<string, string>>({});
  const metrics = useQuery({
    queryKey: ["threat-analysis", "admin-metrics", windowDays],
    queryFn: () => api<Metrics>(`/api/threat-analysis/admin/dashboard?days=${windowDays}`),
    refetchInterval: 30_000,
  });
  const feedback = useQuery({
    queryKey: ["threat-analysis", "admin-feedback"],
    queryFn: () => api<Feedback[]>("/api/threat-analysis/admin/feedback?status=pending"),
    refetchInterval: 30_000,
    enabled: canReviewThreatData,
  });
  const review = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approve" | "reject" }) =>
      api(`/api/threat-analysis/admin/feedback/${id}/review`, {
        method: "POST",
        body: JSON.stringify({ decision, note: notes[id] ?? "" }),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["threat-analysis", "admin-feedback"] }),
  });
  const models = useQuery({
    queryKey: ["threat-analysis", "models"],
    queryFn: () => api<ModelVersion[]>("/api/threat-analysis/admin/models"),
  });
  const job = useQuery({
    queryKey: ["threat-analysis", "training-job", trainingJobId],
    queryFn: () => api<TrainingJob>(`/api/threat-analysis/admin/training-jobs/${trainingJobId}`),
    enabled: Boolean(trainingJobId) && canOperateThreatModels,
    refetchInterval: (query) => ["queued", "running"].includes(query.state.data?.status ?? "") ? 2000 : false,
  });
  const train = useMutation({
    mutationFn: () => api<{ id: string }>("/api/threat-analysis/admin/training-jobs", { method: "POST" }),
    onSuccess: ({ id }) => { setTrainingJobId(id); void client.invalidateQueries({ queryKey: ["threat-analysis", "models"] }); },
  });
  const modelAction = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "promote" | "rollback" | "reject" }) => {
      return api(`/api/threat-analysis/admin/models/${id}/${action}`, {
        method: "POST",
        ...(action === "reject" ? { body: JSON.stringify({ note: rejectNotes[id] ?? "" }) } : {}),
      });
    },
    onSuccess: () => void client.invalidateQueries({ queryKey: ["threat-analysis", "models"] }),
  });
  return <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
    <p className="eyebrow">Administrative monitoring</p><h1 className="mt-2 text-2xl font-semibold text-white">Threat Detection Network</h1>
    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Operational summary from stored threat analyses. Refreshes every 30 seconds; empty or unavailable values are reported directly.</p>
    <section className="glass mt-5 p-4" aria-labelledby="detector-runtime-heading"><h2 id="detector-runtime-heading" className="text-sm font-semibold text-white">Analysis runtime</h2>{metrics.data?.detector_runtime ? <><p className="mt-2 text-sm text-slate-300">{metrics.data.detector_runtime.state === "model_ready" ? `Hybrid rules + ${metrics.data.detector_runtime.model_family ?? "verified model"} · ${metrics.data.detector_runtime.model_version ?? "version unknown"}` : "Rules-only fallback · Awaiting an approved, loadable model artifact."}</p><p className="mt-1 text-xs text-slate-500">A configured ML_MODEL_PATH takes precedence over the signed registry model. Model scores are uncalibrated and do not establish that content is safe.</p></> : <p className="mt-2 text-sm text-slate-400">Runtime status unavailable.</p>}</section>
    {metrics.isPending ? <section className="glass mt-6 p-6 text-sm text-slate-400" role="status">Loading persisted analysis metrics…</section>
      : metrics.isError ? <section className="glass mt-6 p-6 text-sm text-amber-200" role="alert">Metrics are unavailable. The dashboard cannot confirm the analysis database right now.</section>
      : <>
        <div className="mt-6 flex flex-wrap items-end justify-between gap-3"><label className="text-xs text-slate-400">Analysis time window<select className="field mt-1 block" value={windowDays} onChange={(event) => setWindowDays(Number(event.target.value))}><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option><option value={365}>Last 365 days</option></select></label><p className="text-[10px] text-slate-500">Window is calculated in UTC; refresh time is shown below in your local timezone.</p></div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <article className="glass p-5"><p className="eyebrow">Persisted analyses · last {metrics.data.window_days} days</p><p className="mt-3 text-3xl font-semibold text-white">{metrics.data.total}</p><p className="mt-2 text-xs text-slate-500">Source: {metrics.data.source}</p></article>
          {Object.entries(metrics.data.by_verdict).map(([name, value]) => <article className="glass p-5" key={name}><p className="eyebrow">{name} verdict</p><p className="mt-3 text-2xl font-semibold text-white">{value}</p></article>)}
        </div>
        <section className="glass mt-5 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-sm font-semibold text-white">Registry evaluation</h2><span className="rounded-full border border-amber-300/15 px-3 py-1 text-xs text-amber-100">{metrics.data.detection_quality ? "Independent artifact evaluation available" : "Not measured"}</span></div><p className="mt-3 text-sm text-slate-400">{metrics.data.note}</p>{metrics.data.detection_quality && <p className="mt-2 text-xs text-slate-300">F1 {metrics.data.detection_quality.f1?.toFixed(3)} · precision {metrics.data.detection_quality.precision?.toFixed(3)} · recall {metrics.data.detection_quality.recall?.toFixed(3)} · false positive rate {metrics.data.detection_quality.false_positive_rate?.toFixed(3)}</p>}<p className="mt-2 text-xs text-slate-600">Severity totals: {Object.entries(metrics.data.by_severity).map(([key, value]) => `${key} ${value}`).join(" · ")}</p><p className="mt-2 text-xs text-slate-600">Registry artifact state: {metrics.data.model_status.state}{metrics.data.model_status.version ? ` · ${metrics.data.model_status.version}` : ""}</p><p className="mt-3 text-[10px] text-slate-600">Metrics generated {new Date(metrics.data.refreshed_at).toLocaleString()} · refreshes every 30 seconds</p></section>
      </>}
    {canReviewThreatData && <section className="glass mt-5 p-5" aria-labelledby="feedback-queue-heading"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 id="feedback-queue-heading" className="text-sm font-semibold text-white">Candidate feedback review</h2><p className="mt-1 text-xs text-slate-500">Approved feedback is training-eligible only when the submitter explicitly opted in and the sample is encrypted.</p></div><button type="button" className="btn-secondary !py-1.5 text-xs" onClick={() => void feedback.refetch()}>Refresh queue</button></div>
      {feedback.isPending ? <p className="mt-4 text-xs text-slate-400">Loading review queue…</p> : feedback.isError ? <p role="alert" className="mt-4 text-xs text-amber-200">Feedback queue is unavailable.</p> : feedback.data.length ? <ul className="mt-3 divide-y divide-white/[0.06]">{feedback.data.map((item) => <li className="py-4" key={item.id}><div className="flex flex-wrap justify-between gap-2"><span className="text-xs font-medium text-white">Candidate label: {item.candidate_label}</span><time className="text-[10px] text-slate-500">{new Date(item.created_at).toLocaleString()}</time></div><p className="mt-2 text-xs leading-5 text-slate-400">{item.reason}</p>{item.training_sample && <div className="mt-2 rounded-lg border border-white/[0.06] p-3"><p className="text-[10px] uppercase text-slate-500">Opted-in sample · decrypted for authorized review</p><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words font-sans text-xs text-slate-300">{item.training_sample}</pre></div>}<p className="mt-1 font-mono text-[10px] text-slate-600">Analysis {item.analysis_id}</p><label className="mt-3 block text-xs text-slate-400">Review rationale<input className="field mt-1" minLength={10} maxLength={2000} value={notes[item.id] ?? ""} onChange={(event) => setNotes((old) => ({ ...old, [item.id]: event.target.value }))} /></label>{review.isError && <p role="alert" className="mt-2 text-xs text-red-300">Review action failed. Confirm the rationale and retry.</p>}<div className="mt-3 flex gap-2"><button className="btn-secondary !py-1.5 text-xs" type="button" disabled={review.isPending || (notes[item.id] ?? "").trim().length < 10} onClick={() => review.mutate({ id: item.id, decision: "approve" })}>Approve label</button><button className="btn-secondary !py-1.5 text-xs" type="button" disabled={review.isPending || (notes[item.id] ?? "").trim().length < 10} onClick={() => review.mutate({ id: item.id, decision: "reject" })}>Reject label</button></div></li>)}</ul> : <p className="mt-4 text-xs text-slate-500">No pending feedback.</p>}
    </section>}
    {canOperateThreatModels && <section className="glass mt-5 p-5" aria-labelledby="model-lifecycle-heading"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 id="model-lifecycle-heading" className="text-sm font-semibold text-white">Neural model training and registry</h2><p className="mt-1 text-xs text-slate-500">Uses only approved, explicitly opted-in samples and a separate independent labeled test set. Validated registry activation is used by the analyzer unless ML_MODEL_PATH overrides it.</p></div><button className="btn-secondary !py-1.5 text-xs" type="button" disabled={train.isPending} onClick={() => train.mutate()}>{train.isPending ? "Queueing…" : "Train candidate"}</button></div>
      {train.isError && <p role="alert" className="mt-3 text-xs text-amber-200">{train.error instanceof Error ? train.error.message : "Training could not start. Check encryption, signing, and independent-set configuration."}</p>}
      {job.data && <p className="mt-3 rounded-lg border border-white/[0.06] p-3 text-xs text-slate-300">Job {job.data.status}: {job.data.message} · {job.data.sample_count} samples{job.data.metrics ? ` · F1 ${job.data.metrics.f1?.toFixed(3)} · precision ${job.data.metrics.precision?.toFixed(3)} · recall ${job.data.metrics.recall?.toFixed(3)}` : ""}</p>}
      {models.isPending ? <p className="mt-3 text-xs text-slate-400">Loading model versions…</p> : models.isError ? <p role="alert" className="mt-3 text-xs text-amber-200">Model versions are unavailable.</p> : models.data.length ? <ul className="mt-3 divide-y divide-white/[0.06]">{models.data.map((model) => <li key={model.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><p className="text-xs font-medium text-white">{model.version} · {model.model_family} · registry: {model.state}</p><p className="mt-1 text-[10px] text-slate-500">Independent registry evaluation F1 {model.metrics.f1?.toFixed(3) ?? "unavailable"} · created {new Date(model.created_at).toLocaleString()}</p></div><div className="flex flex-wrap items-center gap-2">{model.state === "candidate" && <><label className="text-[10px] text-slate-500">Rejection rationale<input className="field mt-1 text-[10px]" minLength={10} maxLength={500} value={rejectNotes[model.id] ?? ""} onChange={(event) => setRejectNotes((old) => ({ ...old, [model.id]: event.target.value }))} /></label><button className="btn-secondary !py-1 text-[10px]" disabled={modelAction.isPending || (rejectNotes[model.id] ?? "").trim().length < 10} onClick={() => modelAction.mutate({ id: model.id, action: "reject" })}>Reject candidate</button></>}{(model.state === "candidate" || model.state === "superseded") && <button className="btn-secondary !py-1 text-[10px]" disabled={modelAction.isPending} onClick={() => modelAction.mutate({ id: model.id, action: model.state === "candidate" ? "promote" : "rollback" })}>{model.state === "candidate" ? "Promote in registry" : "Rollback registry state"}</button>}</div></li>)}</ul> : <p className="mt-3 text-xs text-slate-500">No candidate or active model versions. The rules-only fallback is available.</p>}
      {modelAction.isError && <p role="alert" className="mt-3 text-xs text-red-300">Model lifecycle action failed. The active model was not changed unless the API confirmed success.</p>}
    </section>}
  </main>;
}

export default function ThreatNetworkPage() {
  const { status, canAccessThreatNetwork } = useAuth();
  if (status !== "authed" || !canAccessThreatNetwork) return <AccessGate><p /></AccessGate>;
  return <Dashboard />;
}
