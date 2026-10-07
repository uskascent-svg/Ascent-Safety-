"use client";

import { useMutation } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import PhishingResult from "@/components/PhishingResult";
import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { PhishingAnalysis, PhishingRequest } from "@/types/api";

type Mode = "raw" | "fields";

export default function PhishingLab() {
  const { status } = useAuth();
  const [mode, setMode] = useState<Mode>("raw");
  const [raw, setRaw] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [useIntel, setUseIntel] = useState(false);

  const analyze = useMutation({
    mutationFn: (payload: PhishingRequest) =>
      api<PhishingAnalysis>("/api/phishing/analyze", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
  });

  const ready = mode === "raw" ? raw.trim().length > 0 : body.trim().length > 0;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    analyze.mutate({
      ...(useIntel && { check_threat_intel: true }),
      ...(mode === "raw"
        ? { raw_email: raw }
        : {
            body_text: body,
            ...(sender.trim() && { sender: sender.trim() }),
            ...(subject.trim() && { subject: subject.trim() }),
          }),
    });
  }

  const errorMessage =
    analyze.error instanceof ApiError && analyze.error.status === 429
      ? "Too many analyses in a short time. Please wait a minute and try again."
      : (analyze.error?.message ?? "Analysis failed.");

  return (
    <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6">
      <p className="eyebrow mb-1">Phishing Analysis</p>
      <h1 className="text-3xl font-bold text-white">Email Phishing Lab</h1>
      <p className="mb-8 mt-2 max-w-2xl text-sm text-slate-400">
        Paste a suspicious email to see a risk score and exactly which signals produced it. Links
        are analysed as text and never visited; attachments are never opened.
      </p>

      {status === "anon" ? (
        <div className="glass px-6 py-12 text-center">
          <p className="text-sm text-slate-300">Sign in to analyse emails.</p>
          <Link href="/login" className="btn-primary mt-4">
            Sign in
          </Link>
        </div>
      ) : (
        <div className="grid gap-8 lg:grid-cols-12">
          <form onSubmit={submit} className="glass-panel space-y-4 p-6 lg:col-span-6">
            <div role="tablist" aria-label="Input type" className="flex gap-2">
              {(["raw", "fields"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  role="tab"
                  aria-selected={mode === m}
                  onClick={() => setMode(m)}
                  className={`rounded-full border px-4 py-1.5 font-mono text-xs transition ${
                    mode === m
                      ? "border-accent bg-accent/10 text-accent-strong"
                      : "border-slate-700 text-slate-300 hover:bg-white/5"
                  }`}
                >
                  {m === "raw" ? "Raw email (with headers)" : "Message text"}
                </button>
              ))}
            </div>

            {mode === "raw" ? (
              <label className="block font-mono text-xs uppercase text-slate-300">
                Raw email
                <textarea
                  value={raw}
                  onChange={(e) => setRaw(e.target.value)}
                  maxLength={1_000_000}
                  rows={14}
                  placeholder={
                    "Paste the full message source, including headers (From:, Subject:, …)"
                  }
                  className="field mt-2 font-mono text-xs normal-case"
                />
              </label>
            ) : (
              <>
                <label className="block font-mono text-xs uppercase text-slate-300">
                  Sender (optional)
                  <input
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    maxLength={320}
                    className="field mt-2 normal-case"
                  />
                </label>
                <label className="block font-mono text-xs uppercase text-slate-300">
                  Subject (optional)
                  <input
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    maxLength={998}
                    className="field mt-2 normal-case"
                  />
                </label>
                <label className="block font-mono text-xs uppercase text-slate-300">
                  Message body
                  <textarea
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    maxLength={500_000}
                    rows={9}
                    className="field mt-2 font-mono text-xs normal-case"
                  />
                </label>
              </>
            )}

            <label className="flex items-start gap-3 rounded-lg border border-slate-800 bg-cyber-navy p-3 text-xs text-slate-300">
              <input
                type="checkbox"
                checked={useIntel}
                onChange={(e) => setUseIntel(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-cyan-500"
              />
              <span>
                Also check links against threat-intelligence services
                <span className="mt-0.5 block text-slate-500">
                  Sends link addresses (never the message body) to third-party reputation services.
                  Nothing is visited or scanned.
                </span>
              </span>
            </label>

            <div className="flex items-center justify-between gap-4">
              <p className="text-xs text-slate-500">
                Only the sender, subject and results are stored — not the message body.
              </p>
              <button
                type="submit"
                disabled={!ready || analyze.isPending}
                className="btn-primary shrink-0 uppercase tracking-wider text-xs"
              >
                {analyze.isPending ? "Analyzing…" : "Analyze"}
              </button>
            </div>
          </form>

          <section aria-label="Analysis result" className="glass p-6 lg:col-span-6">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="font-mono text-sm font-semibold uppercase tracking-wider text-white">
                Analysis assessment
              </h2>
            </div>
            {analyze.isPending && <Skeleton className="h-64 w-full" />}
            {analyze.isError && <ErrorState message={errorMessage} />}
            {analyze.data && !analyze.isPending && <PhishingResult analysis={analyze.data} />}
            {analyze.isIdle && (
              <EmptyState
                title="Ready for analysis"
                hint="Submit an email to see its risk score, indicators and recommended action."
              />
            )}
          </section>
        </div>
      )}
    </div>
  );
}
