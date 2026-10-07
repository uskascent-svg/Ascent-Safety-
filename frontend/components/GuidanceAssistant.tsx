"use client";

import { Bot, LockKeyhole, Send, ShieldCheck, UserRound } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

type Turn = { role: "user" | "assistant"; text: string };
type AssistantStatus = { provider: "gemini" | "rules"; model: string | null };
type AssistantReply = AssistantStatus & { answer: string };

const PROMPTS = [
  "How do I investigate a suspicious email safely?",
  "What should I do if an endpoint may be compromised?",
  "How does a location get onto the threat map?",
  "How do I review and publish a user report?",
];

export default function GuidanceAssistant() {
  const { status: authStatus, user } = useAuth();
  const [messages, setMessages] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const providerStatus = useQuery({
    queryKey: ["guidance", "status"],
    queryFn: () => api<AssistantStatus>("/api/guidance/status"),
    enabled: authStatus === "authed",
  });
  const chat = useMutation({
    mutationFn: (nextMessages: Turn[]) =>
      api<AssistantReply>("/api/guidance/chat", {
        method: "POST",
        body: JSON.stringify({ messages: nextMessages.slice(-12) }),
      }),
    onSuccess: (reply) => {
      setMessages((current) => [...current, { role: "assistant", text: reply.answer }]);
      requestAnimationFrame(() => bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" }));
    },
  });

  const send = (value: string) => {
    const text = value.trim();
    if (!text || chat.isPending) return;
    const next = [...messages, { role: "user" as const, text }];
    setMessages(next);
    setDraft("");
    chat.mutate(next);
  };

  if (authStatus === "loading") return <div className="mx-auto max-w-5xl px-4 py-12 text-sm text-slate-400">Loading assistant…</div>;
  if (authStatus === "anon") return <div className="mx-auto max-w-3xl px-4 py-16"><div className="glass p-8 text-center"><Bot className="mx-auto h-7 w-7 text-accent" aria-hidden="true" /><h1 className="mt-4 text-xl font-semibold text-white">Sign in for personalized guidance</h1><p className="mt-2 text-sm text-slate-400">Answers adapt to your workspace role. The assistant does not inspect private incident records.</p><Link href="/login" className="btn-primary mt-5">Sign in</Link></div></div>;

  const usingGemini = providerStatus.data?.provider === "gemini";
  return (
    <div className="mx-auto max-w-[1100px] px-4 py-8 sm:px-6 lg:py-10">
      <div className="mb-6 max-w-3xl">
        <p className="eyebrow">Role-aware product guidance</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Personal guidance assistant</h1>
        <p className="mt-3 text-sm leading-relaxed text-slate-400">Ask about phishing response, incident triage, reports, telemetry, and the Ascent Safety workspace.</p>
      </div>

      <section className="glass overflow-hidden" aria-label="Guidance chat">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3"><span className="grid h-10 w-10 place-items-center rounded-xl border border-accent/20 bg-accent/[0.06] text-accent-strong"><Bot className="h-5 w-5" aria-hidden="true" /></span><div><h2 className="text-sm font-semibold text-white">Ascent guide</h2><p className="mt-0.5 text-xs text-slate-500">Guidance for {user?.roles.includes("ADMINISTRATOR") ? "administrators" : user?.roles.includes("SECURITY_ANALYST") ? "security analysts" : "workspace users"}</p></div></div>
          <span className={`rounded-full border px-3 py-1.5 text-[11px] ${usingGemini ? "border-emerald-400/20 bg-emerald-400/[0.05] text-emerald-200" : "border-amber-300/15 bg-amber-300/[0.04] text-amber-100"}`}><ShieldCheck className="mr-1.5 inline h-3.5 w-3.5" aria-hidden="true" />{usingGemini ? `Gemini · ${providerStatus.data?.model}` : "Rules guidance · Gemini key not configured"}</span>
        </header>

        <div className="min-h-[360px] space-y-4 p-4 sm:p-6" aria-live="polite" aria-relevant="additions text">
          {messages.length === 0 ? <div className="mx-auto max-w-2xl py-8 text-center"><Bot className="mx-auto h-8 w-8 text-slate-500" aria-hidden="true" /><h3 className="mt-4 text-base font-medium text-slate-200">How can I help?</h3><p className="mt-2 text-sm text-slate-500">The assistant gives defensive guidance based on your verified workspace role. It does not read private records.</p><div className="mt-6 grid gap-2 sm:grid-cols-2">{PROMPTS.map((prompt) => <button key={prompt} type="button" onClick={() => send(prompt)} className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-3 text-left text-sm text-slate-300 transition hover:border-accent/25 hover:bg-accent/[0.04]">{prompt}</button>)}</div></div> : messages.map((message, index) => <article key={`${message.role}-${index}`} className={`flex gap-3 ${message.role === "user" ? "justify-end" : "justify-start"}`}><div className={`flex max-w-[88%] gap-3 ${message.role === "user" ? "flex-row-reverse" : ""}`}><span className={`mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full border ${message.role === "assistant" ? "border-accent/15 bg-accent/[0.04] text-accent-strong" : "border-white/10 bg-white/[0.03] text-slate-300"}`}>{message.role === "assistant" ? <Bot className="h-4 w-4" aria-hidden="true" /> : <UserRound className="h-4 w-4" aria-hidden="true" />}</span><p className={`whitespace-pre-wrap rounded-xl px-4 py-3 text-sm leading-6 ${message.role === "assistant" ? "border border-white/[0.07] bg-white/[0.025] text-slate-300" : "border border-accent/15 bg-accent/[0.05] text-slate-200"}`}>{message.text}</p></div></article>)}
          {chat.isPending && <p className="ml-11 text-sm text-slate-500" role="status">Preparing guidance…</p>}
          {chat.isError && <p role="alert" className="ml-11 text-sm text-red-300">The assistant could not respond. Your previous messages are still here; please retry.</p>}
          <div ref={bottomRef} />
        </div>

        {messages.length > 0 && <div className="flex flex-wrap gap-2 border-t border-white/[0.05] px-4 py-3 sm:px-6">{PROMPTS.slice(0, 3).map((prompt) => <button key={prompt} type="button" disabled={chat.isPending} onClick={() => send(prompt)} className="rounded-full border border-white/[0.07] px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 disabled:opacity-50">{prompt}</button>)}</div>}
        <form onSubmit={(event) => { event.preventDefault(); send(draft); }} className="border-t border-white/[0.07] bg-black/10 p-4 sm:px-6"><label htmlFor="guidance-message" className="sr-only">Ask the guidance assistant</label><div className="flex items-end gap-2"><textarea id="guidance-message" value={draft} onChange={(event) => setDraft(event.target.value)} maxLength={1500} rows={2} className="field min-h-12 flex-1 resize-y !py-3 text-sm" placeholder="Ask a security or product guidance question…" /><button type="submit" disabled={!draft.trim() || chat.isPending} className="btn-primary h-11 shrink-0 !px-4" aria-label="Send message"><Send className="h-4 w-4" aria-hidden="true" /><span className="hidden sm:inline">Send</span></button></div><p className="mt-2 flex items-center gap-1.5 text-[11px] text-slate-600"><LockKeyhole className="h-3 w-3" aria-hidden="true" />Do not include passwords, OTPs, tokens, or confidential incident evidence.</p></form>
      </section>
    </div>
  );
}
