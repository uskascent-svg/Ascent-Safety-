"use client";

import { ArrowRight, Bot, ChevronRight, Compass, LockKeyhole, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

const TOPICS = [
  {
    id: "email",
    prompt: "I need to check a suspicious email",
    title: "Review the message safely",
    response: "Use the Phishing Lab to submit the raw message or its text fields. The analyzer treats links as text; it does not visit them, and it does not open attachments.",
    steps: ["Open Phishing Lab and choose raw email or message text.", "Review the risk score, indicators, and recommended action returned by the analysis.", "Threat-intelligence checks are optional and share link addresses with the providers you have configured."],
    href: "/phishing",
    action: "Open Phishing Lab",
  },
  {
    id: "event",
    prompt: "I need to investigate a security event",
    title: "Start with the event record",
    response: "The Security panel lists events and alerts stored by connected sources. Open a record to review its reported evidence; if it includes a source IP, you can request a reputation lookup from the detail view.",
    steps: ["Open Security and narrow the list by severity, status, time range, or region.", "Select an event and review its source, timestamp, location, and description.", "Treat an intelligence lookup as provider evidence for that indicator, not as a complete incident verdict."],
    href: "/security-panel",
    action: "Open Security",
  },
  {
    id: "telemetry",
    prompt: "I want to connect telemetry",
    title: "Connect a source you operate",
    response: "Ascent Safety evaluates reports sent by integrations; it does not install endpoint agents or capture network traffic itself. Administrators can register endpoint and network sources and configure their forwarders.",
    steps: ["Register an endpoint or sensor from its administration page.", "Copy its API key at creation time and store it in your deployment secret manager.", "Send validated events using the documented telemetry payload and confirm they appear in Security."],
    href: "/endpoints",
    action: "Manage sources",
  },
  {
    id: "locations",
    prompt: "How do threat locations and routes appear?",
    title: "Coordinates must come from the source",
    response: "A marker represents coordinates explicitly reported on an event. An animated route is drawn only when an event includes complete origin and destination coordinate pairs. The application does not infer geography from IP addresses.",
    steps: ["Review the source event payload and confirm the location fields are correct.", "For a route, provide both latitude/longitude pairs in the telemetry event.", "Events without coordinates remain available in the event feed without a map marker."],
    href: "/security-panel",
    action: "Review Security",
  },
  {
    id: "privacy",
    prompt: "What happens to the email I submit?",
    title: "Understand analysis data handling",
    response: "The Phishing Lab states that it stores the sender, subject, and analysis results, not the message body. If you enable threat-intelligence checks, link addresses are sent to the configured third-party reputation services.",
    steps: ["Avoid submitting content your organization is not allowed to process.", "Leave the optional intelligence checkbox off unless external lookups are approved.", "Review configured provider credentials and privacy requirements with your administrator."],
    href: "/phishing",
    action: "Open Phishing Lab",
  },
];

export default function GuidanceAssistant() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = TOPICS.find((topic) => topic.id === selectedId);

  return (
    <div className="mx-auto max-w-[1280px] px-4 py-8 sm:px-6 lg:px-9 lg:py-10">
      <div className="mb-8 max-w-3xl">
        <p className="eyebrow">Product guidance</p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Personal guidance assistant</h1>
        <p className="mt-3 text-sm leading-relaxed text-slate-400">Choose a topic to get help using Ascent Safety and its documented workflows.</p>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,0.82fr)_minmax(0,1.18fr)]">
        <section className="glass p-5 sm:p-6" aria-labelledby="guidance-topics-heading">
          <div className="mb-4 flex items-center gap-3">
            <span className="grid h-9 w-9 place-items-center rounded-lg border border-accent/20 bg-accent/[0.06] text-accent-strong"><Compass className="h-4 w-4" aria-hidden="true" /></span>
            <div><h2 id="guidance-topics-heading" className="text-sm font-medium text-slate-100">What can I help with?</h2><p className="mt-1 text-[10px] text-slate-500">Select a workflow</p></div>
          </div>
          <div className="space-y-2">{TOPICS.map((topic) => <button key={topic.id} type="button" aria-pressed={selectedId === topic.id} onClick={() => setSelectedId(topic.id)} className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3.5 py-3 text-left text-xs transition ${selectedId === topic.id ? "border-accent/30 bg-accent/[0.07] text-white" : "border-white/[0.06] bg-white/[0.015] text-slate-400 hover:border-white/[0.12] hover:text-slate-200"}`}><span>{topic.prompt}</span><ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-600" aria-hidden="true" /></button>)}</div>
          <div className="mt-5 flex gap-2 rounded-lg border border-white/[0.06] bg-black/15 p-3 text-[10px] leading-relaxed text-slate-500"><LockKeyhole className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-600" aria-hidden="true" /><p>Guidance is curated from the product workflows. It does not send your questions to an AI service or inspect your private event data.</p></div>
        </section>

        <section className="glass min-h-[420px] p-5 sm:p-6" aria-live="polite" aria-label="Guidance answer">
          <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
            <div className="flex items-center gap-3"><span className="grid h-9 w-9 place-items-center rounded-lg border border-slate-700 bg-white/[0.025] text-slate-300"><Bot className="h-4 w-4" aria-hidden="true" /></span><div><p className="text-sm font-medium text-slate-100">Ascent guide</p><p className="mt-1 text-[10px] text-slate-600">Documented product workflows</p></div></div>
            <span className="rounded-full border border-emerald-500/15 bg-emerald-500/[0.05] px-2.5 py-1 text-[9px] uppercase tracking-[0.12em] text-emerald-300"><ShieldCheck className="mr-1 inline h-3 w-3" aria-hidden="true" />Privacy-first</span>
          </div>
          {!selected ? (
            <div className="grid min-h-[310px] place-items-center text-center"><div className="max-w-sm"><p className="text-sm text-slate-300">Select a workflow to get started.</p><p className="mt-2 text-xs leading-relaxed text-slate-500">The guide explains existing tools and data handling. It does not make incident decisions for you.</p></div></div>
          ) : (
            <div className="pt-5">
              <div className="ml-auto max-w-[90%] rounded-xl rounded-br-sm border border-accent/15 bg-accent/[0.05] px-4 py-3 text-xs leading-relaxed text-slate-200">{selected.prompt}</div>
              <div className="mt-5 flex gap-3"><span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full border border-slate-700 bg-slate-900 text-accent-strong"><Bot className="h-3.5 w-3.5" aria-hidden="true" /></span><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold text-white">{selected.title}</h2><p className="mt-2 text-xs leading-relaxed text-slate-400">{selected.response}</p><ol className="mt-4 space-y-2.5">{selected.steps.map((step, index) => <li key={step} className="flex gap-2.5 text-xs leading-relaxed text-slate-300"><span className="font-mono text-[10px] text-accent-strong">0{index + 1}</span><span>{step}</span></li>)}</ol><Link href={selected.href} className="btn-secondary mt-5 !px-3 !py-2 text-xs">{selected.action}<ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></Link></div></div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
