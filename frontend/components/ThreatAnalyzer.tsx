"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import AccessGate from "@/components/AccessGate";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

type Finding = {
  detector: string;
  code: string;
  severity: string;
  title: string;
  explanation: string;
  evidence: string[];
};
type Result = {
  id: string;
  created_at: string;
  verdict: string;
  severity: string;
  heuristic_score: number;
  score_type: "heuristic" | "hybrid";
  detector_mode: "rules_only" | "hybrid";
  model_version: string | null;
  model_family: string | null;
  model_confidence: number | null;
  combined_score: number | null;
  completeness: string;
  input_kind: string;
  findings: Finding[];
  explanation: string;
  remediation: string;
  extraction_status?: string;
  extraction_notes?: string[];
};
type History = { items: Pick<Result, "id" | "created_at" | "verdict" | "severity" | "input_kind">[]; total: number };

function AnalyzerContent() {
  const [text, setText] = useState("");
  const [kind, setKind] = useState<"message" | "url" | "document_text">("message");
  const [result, setResult] = useState<Result | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [feedbackLabel, setFeedbackLabel] = useState("suspicious");
  const [feedbackReason, setFeedbackReason] = useState("");
  const [includeTraining, setIncludeTraining] = useState(false);
  const [trainingSample, setTrainingSample] = useState("");
  const [feedbackMessage, setFeedbackMessage] = useState("");
  const queryClient = useQueryClient();
  const history = useQuery({
    queryKey: ["threat-analysis", "history"],
    queryFn: () => api<History>("/api/threat-analysis/analyses?limit=10"),
  });
  const analyze = useMutation({
    mutationFn: () => api<Result>("/api/threat-analysis/analyze", {
      method: "POST",
      body: JSON.stringify({ text, input_kind: kind }),
    }),
    onSuccess: (data) => {
      setResult(data);
      void queryClient.invalidateQueries({ queryKey: ["threat-analysis", "history"] });
    },
  });
  const analyzeFile = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("Choose a file first.");
      const form = new FormData();
      form.set("file", file);
      return api<Result>("/api/threat-analysis/analyze-file", { method: "POST", body: form });
    },
    onSuccess: (data) => {
      setResult(data);
      void queryClient.invalidateQueries({ queryKey: ["threat-analysis", "history"] });
    },
  });
  const feedback = useMutation({
    mutationFn: () => api(`/api/threat-analysis/analyses/${result?.id}/feedback`, {
      method: "POST",
      body: JSON.stringify({
        candidate_label: feedbackLabel,
        reason: feedbackReason,
        include_in_training: includeTraining,
        ...(includeTraining ? { training_sample: trainingSample } : {}),
      }),
    }),
    onSuccess: () => { setFeedbackMessage("Feedback submitted for administrator review."); setFeedbackReason(""); },
  });

  return <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div><p className="eyebrow">User security workspace</p><h1 className="mt-2 text-2xl font-semibold text-white">Threat Analyzer</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Inspect message text, one URL, or extracted document text with explainable rules and an optional independently evaluated neural model. URLs are never visited. Submitted content is analyzed in memory and not stored.</p></div>
      <span className="rounded-full border border-amber-300/15 bg-amber-300/[0.04] px-3 py-1.5 text-xs text-amber-100">Rules always active · model used only when ready</span>
    </div>
    <div className="grid gap-5 lg:grid-cols-12">
      <form className="glass space-y-4 p-5 lg:col-span-6" onSubmit={(event) => { event.preventDefault(); analyze.mutate(); }}>
        <label className="block text-sm font-medium text-slate-200">Analysis input
          <select className="field mt-2" value={kind} onChange={(event) => setKind(event.target.value as typeof kind)}>
            <option value="message">Message text</option><option value="url">Single URL</option><option value="document_text">Extracted document text</option>
          </select>
        </label>
        <label className="block text-sm font-medium text-slate-200">Content
          <textarea className="field mt-2 min-h-64 font-mono text-xs" value={text} onChange={(event) => setText(event.target.value)} minLength={20} maxLength={100_000} required placeholder={kind === "url" ? "https://example.com/path" : "Paste message text or text extracted from a document"} aria-describedby="input-note" />
        </label>
        <p id="input-note" className="text-xs text-slate-500">20–100,000 characters. Do not paste passwords, access tokens, or other secrets.</p>
        {analyze.isError && <p role="alert" className="text-sm text-red-300">{analyze.error instanceof Error ? analyze.error.message : "Analysis failed. Try again."}</p>}
        <button className="btn-primary" type="submit" disabled={text.trim().length < 20 || analyze.isPending}>{analyze.isPending ? "Analyzing…" : "Analyze content"}</button>
      </form>
      <form className="glass space-y-4 p-5 lg:col-span-6" onSubmit={(event) => { event.preventDefault(); analyzeFile.mutate(); }}>
        <div><h2 className="text-sm font-semibold text-white">Analyze a file</h2><p className="mt-1 text-xs leading-5 text-slate-500">Supported: TXT, EML, PDF, DOCX, PNG, JPG, WEBP, BMP, TIF. Maximum 12 MB by default. Files are parsed in a time-limited worker and are not retained.</p></div>
        <label className="block text-sm text-slate-300">Choose document or image<input className="field mt-2" type="file" accept=".txt,.eml,.msg,.pdf,.docx,.png,.jpg,.jpeg,.webp,.bmp,.tif,.tiff" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>
        {analyzeFile.isError && <p role="alert" className="text-sm text-red-300">{analyzeFile.error instanceof Error ? analyzeFile.error.message : "File analysis failed."}</p>}
        <button className="btn-secondary" type="submit" disabled={!file || analyzeFile.isPending}>{analyzeFile.isPending ? "Extracting and analyzing…" : "Analyze file"}</button>
      </form>
      <section className="glass min-h-80 p-5 lg:col-span-6" aria-live="polite" aria-label="Analysis result">
        <h2 className="border-b border-white/[0.06] pb-3 text-sm font-semibold text-white">Assessment</h2>
        {analyze.isPending && <p className="py-10 text-sm text-slate-400">Applying configured rules and checking the approved model…</p>}
        {!analyze.isPending && !result && <p className="py-10 text-sm text-slate-500">Your assessment will appear here. Unsupported file uploads are not enabled.</p>}
        {result && <div className="pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3"><span className="rounded-full border border-accent/20 bg-accent/[0.05] px-3 py-1 text-xs uppercase text-accent-strong">{result.verdict}</span><span className="text-xs text-slate-500">{result.severity} severity · rules score {result.heuristic_score}/100{result.combined_score !== null && result.detector_mode === "hybrid" ? ` · combined score ${result.combined_score}/100` : ""}</span></div>
          <p className="mt-2 text-xs text-slate-500">{result.detector_mode === "hybrid" && result.model_confidence !== null ? `${result.model_family ?? "Machine-learning model"} score ${(result.model_confidence * 100).toFixed(1)}% · version ${result.model_version ?? "unknown"}. This score is not a calibrated probability.` : "Machine-learning model unavailable for this analysis; rules-only fallback was used."}</p>
          <p className="mt-4 text-sm text-slate-300">{result.explanation}</p>
          <p className="mt-2 text-xs text-slate-500">Analysis completeness: {result.completeness}. Result ID: <span className="font-mono">{result.id}</span></p>
          {result.extraction_status && result.extraction_status !== "not_applicable" && <div className="mt-3 rounded-lg border border-white/[0.06] p-3 text-xs text-slate-400"><p>Extraction: {result.extraction_status}</p>{(result.extraction_notes ?? []).map((note) => <p className="mt-1" key={note}>{note}</p>)}</div>}
          <h3 className="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-300">Evidence ({result.findings.length})</h3>
          {result.findings.length ? <ul className="mt-2 space-y-2">{result.findings.map((finding, index) => <li key={`${finding.code}-${index}`} className="rounded-lg border border-white/[0.07] p-3"><div className="flex flex-wrap justify-between gap-2"><span className="text-sm text-white">{finding.title}</span><span className="text-[10px] uppercase text-amber-200">{finding.severity} · {finding.detector}</span></div><p className="mt-1 text-xs leading-5 text-slate-400">{finding.explanation}</p><p className="mt-1 text-[10px] text-slate-600">{finding.evidence.join(" · ")}</p></li>)}</ul> : <p className="mt-2 rounded-lg border border-dashed border-slate-700 p-3 text-xs text-slate-400">No configured indicators matched. This does not establish that content is safe.</p>}
          <p className="mt-4 rounded-lg border border-accent/10 p-3 text-xs leading-5 text-slate-300"><strong>Recommended response:</strong> {result.remediation}</p>
          <form className="mt-4 border-t border-white/[0.06] pt-4" onSubmit={(event) => { event.preventDefault(); if (feedbackMessage) setFeedbackMessage(""); feedback.mutate(); }}><h3 className="text-xs font-semibold text-slate-200">Report an incorrect or incomplete finding</h3><div className="mt-3 grid gap-3 sm:grid-cols-2"><label className="text-xs text-slate-400">Your assessment<select className="field mt-1" value={feedbackLabel} onChange={(event) => setFeedbackLabel(event.target.value)}><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="benign">Benign</option><option value="unknown">Unknown</option></select></label><label className="text-xs text-slate-400 sm:col-span-2">Reason<textarea className="field mt-1" minLength={10} maxLength={2000} required value={feedbackReason} onChange={(event) => setFeedbackReason(event.target.value)} rows={3} /></label></div><label className="mt-3 flex gap-2 text-xs text-slate-400"><input type="checkbox" checked={includeTraining} onChange={(event) => setIncludeTraining(event.target.checked)} />I explicitly agree that the sample below may be encrypted and retained for possible model training.</label>{includeTraining && <label className="mt-2 block text-xs text-slate-400">Training sample (benign or malicious label only)<textarea className="field mt-1" minLength={20} maxLength={100000} required value={trainingSample} onChange={(event) => setTrainingSample(event.target.value)} rows={4} /><span className="mt-1 block text-slate-600">Only administrators can review it. Opting in is optional and is required before it can be considered for training.</span></label>}{feedback.isError && <p role="alert" className="mt-2 text-xs text-red-300">{feedback.error instanceof Error ? feedback.error.message : "Could not submit feedback."}</p>}{feedbackMessage && <p role="status" className="mt-2 text-xs text-emerald-200">{feedbackMessage}</p>}<button type="submit" className="btn-secondary mt-3 !py-1.5 text-xs" disabled={feedback.isPending || feedbackReason.trim().length < 10 || (includeTraining && trainingSample.trim().length < 20)}>{feedback.isPending ? "Submitting…" : "Submit for review"}</button></form>
        </div>}
      </section>
    </div>
    <section className="glass mt-5 p-5" aria-labelledby="analysis-history-heading"><div className="flex items-center justify-between gap-4"><div><h2 id="analysis-history-heading" className="text-sm font-semibold text-white">Your recent analyses</h2><p className="mt-1 text-xs text-slate-500">Private to your account</p></div><button className="btn-secondary !py-1.5 text-xs" onClick={() => void history.refetch()} type="button">Refresh</button></div>
      {history.isPending ? <p className="mt-4 text-xs text-slate-400">Loading history…</p> : history.isError ? <p role="alert" className="mt-4 text-xs text-amber-200">Analysis history is temporarily unavailable.</p> : history.data.items.length ? <ul className="mt-3 divide-y divide-white/[0.06]">{history.data.items.map((item) => <li key={item.id} className="flex flex-wrap justify-between gap-2 py-3 text-xs"><span className="text-slate-200">{item.verdict} · {item.severity} · {item.input_kind}</span><time className="text-slate-500" dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time></li>)}</ul> : <p className="mt-4 text-xs text-slate-500">No analyses yet.</p>}
    </section>
  </main>;
}

export default function ThreatAnalyzer() {
  const { status } = useAuth();
  if (status !== "authed") return <AccessGate><p /></AccessGate>;
  return <AnalyzerContent />;
}
