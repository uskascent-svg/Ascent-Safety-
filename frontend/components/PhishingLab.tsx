"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ChevronRight, Clock3, FileWarning, LoaderCircle, Mail, ShieldAlert, ShieldCheck, SquareArrowOutUpRight } from "lucide-react";
import Link from "next/link";

import PhishingResult from "@/components/PhishingResult";
import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { PhishingAnalysis, PhishingRequest, TrainingAttemptResult, TrainingProgress, TrainingScenario } from "@/types/api";

type Mode = "simulation" | "analyst";
type Decision = "report" | "safe";

const INDICATOR_CATALOG = [
  ["sender_mismatch", "Sender identity or domain mismatch"], ["reply_mismatch", "Reply-to mismatch"],
  ["domain_lookalike", "Lookalike or suspicious domain"], ["credential_request", "Unexpected credential request"],
  ["urgency", "Urgency, secrecy, or manipulation"], ["attachment", "Unexpected or risky attachment"],
  ["unexpected_attachment", "Unexpected executable or active content"], ["payment_request", "Unusual payment or bank-detail request"],
  ["sensitive_data", "Requests financial or sensitive information"], ["unexpected_auth", "Unexpected authentication prompt"],
  ["unexpected_fee", "Unexpected fee or payment"], ["otp_request", "One-time code request"],
  ["hidden_destination", "Hidden QR or link destination"], ["routine_notice", "Routine notice with no risky action"],
] as const;

const ACTIONS = [
  ["report_message", "Report the message through the approved security channel"],
  ["avoid_clicking", "Do not click, scan, reply, or open attachments"],
  ["preserve_evidence", "Preserve the original message and headers"],
  ["contact_security", "Contact the security team through a known channel"],
  ["reset_credentials", "Reset credentials if they may have been entered"],
  ["enable_mfa", "Enable strong MFA after securing the account"],
  ["block_sender", "Block or report the sender using approved controls"],
] as const;

export default function PhishingLab() {
  const { status, isAdmin } = useAuth();
  const [mode, setMode] = useState<Mode>("simulation");
  const [selectedId, setSelectedId] = useState("");
  const [investigating, setInvestigating] = useState(false);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [indicators, setIndicators] = useState<string[]>([]);
  const [actions, setActions] = useState<string[]>([]);
  const [startedAt, setStartedAt] = useState(0);
  const [raw, setRaw] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [useIntel, setUseIntel] = useState(false);
  const client = useQueryClient();

  const scenarios = useQuery({
    queryKey: ["phishing-training", "scenarios"],
    queryFn: () => api<{ items: TrainingScenario[]; total: number }>("/api/phishing-training/scenarios"),
    enabled: status === "authed",
  });
  const progress = useQuery({
    queryKey: ["phishing-training", "progress"],
    queryFn: () => api<TrainingProgress>("/api/phishing-training/progress"),
    enabled: status === "authed",
  });
  const selectedScenario = useMemo(() => scenarios.data?.items.find((item) => item.id === selectedId) ?? scenarios.data?.items[0] ?? null, [scenarios.data, selectedId]);

  const attempt = useMutation({
    mutationFn: (payload: { scenario_id: string; decision: Decision; discovered_indicators: string[]; response_actions: string[]; elapsed_seconds: number }) =>
      api<TrainingAttemptResult>("/api/phishing-training/attempts", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["phishing-training"] }),
  });
  const analyze = useMutation({
    mutationFn: (payload: PhishingRequest) => api<PhishingAnalysis>("/api/phishing/analyze", { method: "POST", body: JSON.stringify(payload) }),
  });

  const resetScenario = (id: string, time: number) => {
    setSelectedId(id);
    setInvestigating(false);
    setDecision(null);
    setIndicators([]);
    setActions([]);
    setStartedAt(time);
    attempt.reset();
  };
  const toggle = (list: string[], setList: (value: string[]) => void, value: string, time: number) => {
    if (!startedAt) setStartedAt(time);
    setList(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  };
  const beginInvestigation = (time: number) => { if (!startedAt) setStartedAt(time); setInvestigating(true); };
  const chooseDecision = (value: Decision, time: number) => { if (!startedAt) setStartedAt(time); setDecision(value); };
  const submitAttempt = (time: number) => {
    if (!selectedScenario || !decision || attempt.isPending) return;
    const elapsedSeconds = Math.min(3600, Math.max(0, Math.floor((time - (startedAt || time)) / 1000)));
    attempt.mutate({
      scenario_id: selectedScenario.id,
      decision,
      discovered_indicators: indicators,
      response_actions: actions,
      elapsed_seconds: elapsedSeconds,
    });
  };

  const submitAnalysis = (event: React.FormEvent) => {
    event.preventDefault();
    analyze.mutate({
      ...(useIntel && { check_threat_intel: true }),
      ...(raw.trim() ? { raw_email: raw } : { body_text: body, ...(sender.trim() && { sender: sender.trim() }), ...(subject.trim() && { subject: subject.trim() }) }),
    });
  };
  const analysisError = analyze.error instanceof ApiError && analyze.error.status === 429
    ? "Too many analyses in a short time. Please wait and try again."
    : (analyze.error?.message ?? "Analysis failed.");

  if (status === "loading") return <Skeleton className="h-96 w-full" />;
  if (status === "anon") return <div className="mx-auto max-w-3xl px-4 py-16"><div className="glass p-8 text-center"><Mail className="mx-auto h-7 w-7 text-accent" aria-hidden="true" /><h1 className="mt-4 text-xl font-semibold text-white">Sign in to enter the Phishing Lab</h1><p className="mt-2 text-sm text-slate-400">Practice with fictional, non-interactive scenarios or analyze a message safely.</p><Link href="/login" className="btn-primary mt-5">Sign in</Link></div></div>;

  return (
    <div className="mx-auto max-w-[1480px] px-4 py-7 sm:px-6 lg:px-9 lg:py-9">
      <header className="mb-6 flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div><p className="eyebrow">Security awareness · analyst practice</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Phishing Simulation &amp; Training Lab</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Investigate fictional emails, messages, URLs, and sign-in pages. Training links use reserved example domains and never open.</p></div>
        <div className="flex gap-2" role="tablist" aria-label="Phishing lab mode">{(["simulation", "analyst"] as const).map((value) => <button key={value} type="button" role="tab" aria-selected={mode === value} onClick={() => setMode(value)} className={`rounded-lg border px-4 py-2.5 text-sm capitalize transition ${mode === value ? "border-accent/30 bg-accent/[0.07] text-white" : "border-white/[0.08] text-slate-400 hover:text-white"}`}>{value === "simulation" ? "Training simulations" : "Analyst inspection"}</button>)}</div>
      </header>

      {mode === "simulation" ? <>
        <TrainingProgressPanel progress={progress.data} pending={progress.isPending} />
        {scenarios.isPending ? <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(220px,0.55fr)_minmax(0,1.5fr)]"><Skeleton className="h-[600px]" /><Skeleton className="h-[600px]" /></div> : scenarios.isError ? <div className="mt-5"><ErrorState message="Training scenarios are unavailable." onRetry={() => void scenarios.refetch()} /></div> : !selectedScenario ? <div className="mt-5 glass p-10"><EmptyState title="No training scenarios configured" hint="An administrator can create scenarios in the training content manager." /></div> : <div className="mt-5 grid items-start gap-5 xl:grid-cols-[minmax(220px,0.55fr)_minmax(0,1.5fr)]">
          <aside className="glass p-4" aria-label="Scenario selection"><div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-white">Scenario queue</h2><span className="text-xs text-slate-500">{scenarios.data?.total ?? 0}</span></div><div className="mt-3 space-y-2">{scenarios.data?.items.map((item) => <button key={item.id} type="button" onClick={(event) => resetScenario(item.id, event.timeStamp)} aria-pressed={selectedId === item.id} className={`w-full rounded-lg border p-3 text-left transition ${selectedId === item.id ? "border-accent/30 bg-accent/[0.06]" : "border-white/[0.06] hover:bg-white/[0.025]"}`}><span className="flex items-start justify-between gap-2"><span className="text-sm font-medium leading-5 text-slate-200">{item.title}</span><ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" /></span><span className="mt-2 flex flex-wrap gap-1.5"><span className="rounded border border-white/[0.07] px-1.5 py-0.5 text-[10px] capitalize text-slate-500">{item.category.replaceAll("_", " ")}</span><span className="rounded border border-white/[0.07] px-1.5 py-0.5 text-[10px] capitalize text-slate-500">{item.artifact_type.replaceAll("_", " ")}</span><span className="rounded border border-white/[0.07] px-1.5 py-0.5 text-[10px] capitalize text-slate-500">{item.difficulty}</span></span></button>)}</div></aside>

          <div className="space-y-5">
            <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)]">
              <section className="glass overflow-hidden" aria-labelledby="message-heading">
                <header className="flex items-center justify-between border-b border-white/[0.07] bg-white/[0.015] px-4 py-3"><div className="flex items-center gap-2"><Mail className="h-4 w-4 text-accent-strong" aria-hidden="true" /><h2 id="message-heading" className="text-sm font-semibold text-white">Simulated message</h2></div><span className="rounded-full border border-amber-300/15 bg-amber-300/[0.04] px-2 py-1 text-[10px] text-amber-100">TRAINING · FICTIONAL</span></header>
                <div className="space-y-3 p-4 sm:p-5"><p className="text-sm font-semibold text-slate-100">{selectedScenario.subject}</p><div className="grid gap-1.5 text-xs text-slate-400"><p><span className="inline-block w-16 text-slate-600">From</span>{selectedScenario.sender}</p><p><span className="inline-block w-16 text-slate-600">Reply-to</span>{selectedScenario.reply_to ?? "Not present"}</p><p><span className="inline-block w-16 text-slate-600">Received</span>{selectedScenario.received_at}</p></div><div className="whitespace-pre-wrap border-t border-white/[0.06] pt-4 text-sm leading-6 text-slate-300">{selectedScenario.body}</div>
                  {!!selectedScenario.links.length && <div className="rounded-lg border border-white/[0.06] bg-black/10 p-3"><p className="text-[11px] font-medium text-slate-400">Link destination evidence · never opened</p>{selectedScenario.links.map((link) => <div key={link.url} className="mt-2 flex items-start gap-2 text-xs"><SquareArrowOutUpRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-600" aria-hidden="true" /><span><span className="block text-slate-300">{link.label}</span><code className="mt-1 block break-all font-mono text-accent-strong">{link.url}</code></span></div>)}</div>}
                  {!!selectedScenario.attachments.length && <div className="rounded-lg border border-white/[0.06] p-3"><p className="text-[11px] font-medium text-slate-400">Attachments · simulated, never opened</p>{selectedScenario.attachments.map((file) => <p key={file.name} className="mt-2 flex items-center gap-2 text-xs text-slate-300"><FileWarning className="h-4 w-4 text-amber-300" aria-hidden="true" />{file.name}<span className="text-slate-600">{file.type}</span></p>)}</div>}
                  <details className="rounded-lg border border-white/[0.06] px-3 py-2"><summary className="cursor-pointer text-xs font-medium text-slate-400">Inspect message headers and authentication</summary><dl className="mt-3 space-y-2">{Object.entries(selectedScenario.headers).map(([key, value]) => <div key={key} className="grid gap-1 text-xs sm:grid-cols-[150px_1fr]"><dt className="font-mono text-slate-600">{key}</dt><dd className="break-all font-mono text-slate-300">{value}</dd></div>)}</dl><p className="mt-3 text-[10px] text-slate-600">Authentication results are explicitly simulated training evidence.</p></details>
                </div>
                <footer className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] p-4"><button type="button" onClick={(event) => beginInvestigation(event.timeStamp)} className="btn-secondary !px-3 !py-2 text-xs">Investigate</button><button type="button" onClick={(event) => chooseDecision("report", event.timeStamp)} aria-pressed={decision === "report"} className={`rounded-lg border px-3 py-2 text-xs ${decision === "report" ? "border-red-300/30 bg-red-300/[0.08] text-red-100" : "border-white/[0.08] text-slate-300"}`}><ShieldAlert className="mr-1.5 inline h-3.5 w-3.5" aria-hidden="true" />Report phishing</button><button type="button" onClick={(event) => chooseDecision("safe", event.timeStamp)} aria-pressed={decision === "safe"} className={`rounded-lg border px-3 py-2 text-xs ${decision === "safe" ? "border-emerald-300/30 bg-emerald-300/[0.08] text-emerald-100" : "border-white/[0.08] text-slate-300"}`}><ShieldCheck className="mr-1.5 inline h-3.5 w-3.5" aria-hidden="true" />Safe</button><span className="ml-auto text-[10px] text-slate-600">No real message, destination, or attachment exists</span></footer>
              </section>

              <section className="glass p-4 sm:p-5" aria-labelledby="investigation-heading"><div className="flex items-start justify-between gap-3"><div><p className="eyebrow">Investigation workspace</p><h2 id="investigation-heading" className="mt-1 text-base font-semibold text-white">Examine the evidence</h2></div><span className="inline-flex items-center gap-1.5 text-xs text-slate-500"><Clock3 className="h-3.5 w-3.5" aria-hidden="true" />Timer started</span></div><p className="mt-2 text-xs leading-5 text-slate-500">Objective: {selectedScenario.objective}</p>
                {!investigating && <button type="button" onClick={(event) => beginInvestigation(event.timeStamp)} className="btn-secondary mt-4 w-full justify-center !py-2.5 text-sm">Begin investigation</button>}
                {investigating && <div className="mt-4 space-y-4"><fieldset><legend className="text-xs font-medium text-slate-300">Which signals did you find?</legend><div className="mt-2 grid gap-1.5">{INDICATOR_CATALOG.map(([id, label]) => <label key={id} className="flex cursor-pointer items-start gap-2 rounded-md px-2 py-1.5 text-xs text-slate-400 hover:bg-white/[0.025]"><input type="checkbox" checked={indicators.includes(id)} onChange={(event) => toggle(indicators, setIndicators, id, event.timeStamp)} className="mt-0.5 accent-cyan-400" />{label}</label>)}</div></fieldset><fieldset><legend className="text-xs font-medium text-slate-300">What response actions would you take?</legend><div className="mt-2 grid gap-1.5">{ACTIONS.map(([id, label]) => <label key={id} className="flex cursor-pointer items-start gap-2 rounded-md px-2 py-1.5 text-xs text-slate-400 hover:bg-white/[0.025]"><input type="checkbox" checked={actions.includes(id)} onChange={(event) => toggle(actions, setActions, id, event.timeStamp)} className="mt-0.5 accent-cyan-400" />{label}</label>)}</div></fieldset><div className="rounded-lg border border-accent/10 bg-accent/[0.025] p-3"><p className="text-xs font-medium text-slate-300">What happens if you click?</p><p className="mt-1 text-[11px] leading-5 text-slate-500">Simulation only: message → reserved training destination → fictional sign-in or request → warning screen → report and response steps. The link never opens and the lab never accepts credentials.</p></div><button type="button" onClick={(event) => submitAttempt(event.timeStamp)} disabled={!decision || attempt.isPending} className="btn-primary w-full justify-center !py-2.5 text-sm disabled:cursor-not-allowed">{attempt.isPending ? <><LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />Scoring investigation…</> : "Submit investigation"}</button>{attempt.isError && <p className="text-xs text-red-300" role="alert">{attempt.error.message}</p>}</div>}
              </section>
            </div>

            {attempt.data && <TrainingFeedback result={attempt.data} onNext={() => { const next = scenarios.data?.items.find((item) => item.id !== selectedId); if (next) resetScenario(next.id, 0); }} />}
          </div>
        </div>}
        {isAdmin && <AdminScenarioManager />}
      </> : <AnalystInspection raw={raw} setRaw={setRaw} sender={sender} setSender={setSender} subject={subject} setSubject={setSubject} body={body} setBody={setBody} useIntel={useIntel} setUseIntel={setUseIntel} submit={submitAnalysis} analyze={analyze} errorMessage={analysisError} />}
    </div>
  );
}

function TrainingProgressPanel({ progress, pending }: { progress?: TrainingProgress; pending: boolean }) {
  if (pending) return <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-20" />)}</div>;
  const metrics = [
    ["Scenarios completed", progress?.scenarios_completed ?? 0],
    ["Detection accuracy", `${progress?.detection_accuracy ?? 0}%`],
    ["Training level", progress?.training_level ?? "Foundation"],
    ["Practice streak", `${progress?.current_streak ?? 0} days`],
  ];
  return <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{metrics.map(([label, value]) => <div key={String(label)} className="glass px-4 py-3"><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-xl font-semibold text-slate-100">{value}</p></div>)}</div>;
}

function TrainingFeedback({ result, onNext }: { result: TrainingAttemptResult; onNext: () => void }) {
  const [showDetails, setShowDetails] = useState(false);
  return <section className="glass p-5 sm:p-6" aria-labelledby="training-result-heading"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="eyebrow">Investigation complete</p><h2 id="training-result-heading" className="mt-1 text-xl font-semibold text-white">Security score · {result.security_score}/100</h2><p className="mt-1 text-xs text-slate-400">Detection accuracy {result.detection_accuracy}% · {result.indicators_found.length} indicators found · {result.indicators_missed.length} missed</p></div><span className={`rounded-full border px-3 py-1.5 text-xs ${result.decision_correct ? "border-emerald-300/20 bg-emerald-300/[0.05] text-emerald-200" : "border-amber-300/20 bg-amber-300/[0.05] text-amber-100"}`}>{result.decision_correct ? "Decision correct" : "Review your final decision"}</span></div>
    <p className="mt-4 rounded-lg border border-accent/10 bg-accent/[0.025] p-3 text-sm text-slate-300">{result.recommended_improvement}</p><div className="mt-4 grid gap-4 md:grid-cols-2"><div><h3 className="text-xs font-semibold uppercase tracking-wide text-emerald-200">What you noticed</h3>{result.indicators_found.length ? <ul className="mt-2 space-y-2">{result.indicators_found.map((item) => <li key={item.id} className="rounded-md border border-emerald-300/10 bg-emerald-300/[0.025] p-2.5"><p className="text-xs font-medium text-slate-200">{item.label}</p><p className="mt-1 text-[11px] leading-5 text-slate-500">{item.explanation}</p></li>)}</ul> : <p className="mt-2 text-xs text-slate-500">No scenario indicators were selected.</p>}</div><div><h3 className="text-xs font-semibold uppercase tracking-wide text-amber-100">What you missed</h3>{result.indicators_missed.length ? <ul className="mt-2 space-y-2">{result.indicators_missed.map((item) => <li key={item.id} className="rounded-md border border-amber-300/10 bg-amber-300/[0.025] p-2.5"><p className="text-xs font-medium text-slate-200">{item.label}</p><p className="mt-1 text-[11px] leading-5 text-slate-500">{item.explanation}</p></li>)}</ul> : <p className="mt-2 text-xs text-slate-500">You found every listed signal.</p>}</div></div>
    <div className="mt-4 grid gap-3 md:grid-cols-3"><div className="rounded-lg border border-white/[0.06] p-3"><p className="text-[10px] uppercase text-slate-600">Attack technique</p><p className="mt-1 text-xs text-slate-300">{result.attack_technique}</p></div><div className="rounded-lg border border-white/[0.06] p-3 md:col-span-2"><p className="text-[10px] uppercase text-slate-600">Why it was suspicious</p><p className="mt-1 text-xs leading-5 text-slate-400">{result.explanation}</p></div></div>
    <details className="mt-4 rounded-lg border border-white/[0.06] px-3 py-2" open={showDetails} onToggle={(event) => setShowDetails(event.currentTarget.open)}><summary className="cursor-pointer text-xs font-medium text-slate-300">Response actions · correct response · how to prevent it</summary><ul className="mt-3 space-y-2">{result.actions_feedback.map((action) => <li key={action.id} className="flex gap-2 text-xs"><CheckCircle2 className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${action.correct && action.selected ? "text-emerald-300" : action.correct ? "text-amber-200" : "text-slate-600"}`} aria-hidden="true" /><span className="text-slate-300"><strong>{action.label}</strong> · {action.selected ? (action.correct ? "selected" : "not recommended") : action.correct ? "recommended" : "not selected"}<span className="mt-0.5 block text-slate-500">{action.rationale}</span></span></li>)}</ul><p className="mt-3 border-t border-white/[0.06] pt-3 text-xs leading-5 text-slate-400">{result.prevention}</p></details><button type="button" onClick={onNext} className="btn-primary mt-4">Next scenario<ChevronRight className="h-4 w-4" aria-hidden="true" /></button></section>;
}

function AnalystInspection({ raw, setRaw, sender, setSender, subject, setSubject, body, setBody, useIntel, setUseIntel, submit, analyze, errorMessage }: {
  raw: string; setRaw: (value: string) => void; sender: string; setSender: (value: string) => void; subject: string; setSubject: (value: string) => void; body: string; setBody: (value: string) => void; useIntel: boolean; setUseIntel: (value: boolean) => void; submit: (event: React.FormEvent) => void; analyze: { isPending: boolean; isError: boolean; error: Error | null; data: PhishingAnalysis | undefined; isIdle: boolean }; errorMessage: string;
}) {
  const [inputMode, setInputMode] = useState<"raw" | "fields">("raw");
  const ready = inputMode === "raw" ? raw.trim().length > 0 : body.trim().length > 0;
  return <div className="grid gap-5 lg:grid-cols-12"><form onSubmit={submit} className="glass space-y-4 p-5 lg:col-span-6"><div><p className="eyebrow">Existing rules-based analyzer</p><h2 className="mt-1 text-lg font-semibold text-white">Inspect a message you received</h2><p className="mt-1 text-xs text-slate-500">Content is analyzed as text. URLs are never visited and files are never opened.</p></div><div className="flex gap-2">{(["raw", "fields"] as const).map((value) => <button key={value} type="button" onClick={() => setInputMode(value)} aria-pressed={inputMode === value} className={`rounded-lg border px-3 py-2 text-xs ${inputMode === value ? "border-accent/25 bg-accent/[0.05] text-white" : "border-white/[0.07] text-slate-400"}`}>{value === "raw" ? "Email headers" : "Message fields"}</button>)}</div>{inputMode === "raw" ? <label className="block text-xs text-slate-300">Raw email<textarea value={raw} onChange={(event) => setRaw(event.target.value)} maxLength={1_000_000} rows={14} placeholder="Paste full message source, including headers" className="field mt-2 font-mono text-xs" /></label> : <><label className="block text-xs text-slate-300">Sender<input value={sender} onChange={(event) => setSender(event.target.value)} maxLength={320} className="field mt-2" /></label><label className="block text-xs text-slate-300">Subject<input value={subject} onChange={(event) => setSubject(event.target.value)} maxLength={998} className="field mt-2" /></label><label className="block text-xs text-slate-300">Message body<textarea value={body} onChange={(event) => setBody(event.target.value)} maxLength={500_000} rows={9} className="field mt-2 font-mono text-xs" /></label></>}
    <label className="flex items-start gap-3 rounded-lg border border-white/[0.06] p-3 text-xs text-slate-400"><input type="checkbox" checked={useIntel} onChange={(event) => setUseIntel(event.target.checked)} className="mt-0.5 accent-cyan-500" /><span>Optional reputation lookups<span className="mt-1 block text-[11px] text-slate-600">Shares link addresses with configured threat-intelligence providers. The message body is not sent.</span></span></label><p className="text-xs text-slate-600">Only the sender, subject, and derived analysis are stored.</p><button type="submit" disabled={!ready || analyze.isPending} className="btn-primary">{analyze.isPending ? "Analyzing…" : "Analyze message"}</button></form><section className="glass min-h-80 p-5 lg:col-span-6" aria-label="Analysis result"><h2 className="border-b border-white/[0.06] pb-3 text-sm font-semibold text-white">Assessment</h2>{analyze.isPending && <Skeleton className="mt-4 h-64 w-full" />}{analyze.isError && <div className="mt-4"><ErrorState message={errorMessage} /></div>}{analyze.data && !analyze.isPending && <PhishingResult analysis={analyze.data} />}{analyze.isIdle && <div className="mt-5"><EmptyState title="Ready for analysis" hint="Submit a message to see its rules-based risk score and indicators." /></div>}</section></div>;
}

function AdminScenarioManager() {
  const queryClient = useQueryClient();
  const [scenarioId, setScenarioId] = useState("");
  const [json, setJson] = useState("");
  const [message, setMessage] = useState("");
  const library = useQuery({ queryKey: ["phishing-training", "admin-scenarios"], queryFn: () => api<Record<string, unknown>[]>("/api/phishing-training/admin/scenarios?include_inactive=true") });
  const save = useMutation({
    mutationFn: async () => {
      const parsed = JSON.parse(json) as Record<string, unknown>;
      delete parsed.id; delete parsed.created_by; delete parsed.created_at; delete parsed.updated_at;
      return scenarioId
        ? api(`/api/phishing-training/admin/scenarios/${scenarioId}`, { method: "PUT", body: JSON.stringify(parsed) })
        : api("/api/phishing-training/admin/scenarios", { method: "POST", body: JSON.stringify(parsed) });
    },
    onSuccess: () => { setMessage("Training content saved to the database."); void queryClient.invalidateQueries({ queryKey: ["phishing-training"] }); void library.refetch(); },
  });
  const selectScenario = (id: string) => {
    setScenarioId(id);
    const row = library.data?.find((item) => item.id === id);
    if (row) { const copy = { ...row }; delete copy.id; delete copy.created_by; delete copy.created_at; delete copy.updated_at; setJson(JSON.stringify(copy, null, 2)); }
    else setJson(JSON.stringify({ slug: "new-fictional-scenario", title: "New training scenario", category: "credential_phishing", difficulty: "beginner", artifact_type: "email", sender: "Training Desk <notice@sample.example>", reply_to: null, subject: "Review this request", received_at: "Training only", headers: {}, body: "Fictional scenario text. No real links or credentials.", links: [], attachments: [], indicators: [{ id: "sender_mismatch", label: "Sender mismatch", severity: "high", explanation: "Explain the simulated indicator." }], correct_decision: "report", attack_technique: "Credential phishing simulation", explanation: "Explain the fictional attack pattern.", prevention: "Explain safe verification steps.", correct_actions: ["report_message", "avoid_clicking"], action_rationales: { report_message: "Report through the approved process.", avoid_clicking: "Do not open untrusted destinations." }, objective: "Describe the learning objective.", is_active: true }, null, 2));
    setMessage("");
  };
  return <section className="glass mt-6 p-4 sm:p-5" aria-labelledby="training-content-heading"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="eyebrow">Administrator content management</p><h2 id="training-content-heading" className="mt-1 text-base font-semibold text-white">Training scenario library</h2><p className="mt-1 text-xs text-slate-500">Scenario content and scoring keys are stored in PostgreSQL. Links must use reserved .example domains.</p></div><label className="text-xs text-slate-400">Edit a scenario<select value={scenarioId} onChange={(event) => selectScenario(event.target.value)} className="field mt-1 block min-w-60"><option value="">Create new scenario…</option>{library.data?.map((row) => <option key={String(row.id)} value={String(row.id)}>{String(row.title)}</option>)}</select></label></div>{library.isError && <p className="mt-3 text-xs text-red-300">Could not load the scenario library.</p>}<label className="mt-4 block text-xs text-slate-400">Scenario JSON<textarea value={json} onChange={(event) => setJson(event.target.value)} rows={16} spellCheck={false} className="field mt-2 font-mono text-xs" placeholder="Choose an existing scenario or create a new one" /></label>{save.isError && <p className="mt-2 text-xs text-red-300" role="alert">{save.error instanceof Error ? save.error.message : "Could not save training content."}</p>}{message && <p className="mt-2 text-xs text-emerald-200" role="status">{message}</p>}<button type="button" disabled={!json || save.isPending} onClick={() => { setMessage(""); save.mutate(); }} className="btn-secondary mt-3">{save.isPending ? "Saving…" : scenarioId ? "Save scenario changes" : "Create scenario"}</button></section>;
}
