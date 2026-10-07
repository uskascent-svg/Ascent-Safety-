"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { EmptyState, ErrorState, Skeleton } from "@/components/States";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import type { TelemetrySource } from "@/types/api";

export interface SourceConfig {
  eyebrow: string;
  title: string;
  intro: string;
  noun: string; // "endpoint" | "sensor"
  apiBase: string; // "/api/endpoints" | "/api/sensors"
  kindField: "os" | "kind";
  kindLabel: string;
  kinds: { value: string; label: string }[];
  keyHeader: string;
  ingestPath: string;
  emptyHint: string;
}

const EMPTY = { name: "", kind: "", region: "", country: "", latitude: "", longitude: "" };
type Issued = { source: TelemetrySource; api_key: string };
const wrap = (res: Record<string, unknown>, noun: string): Issued => ({
  source: res[noun] as TelemetrySource,
  api_key: res.api_key as string,
});

function Panel({ cfg }: { cfg: SourceConfig }) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY, kind: cfg.kinds[0].value });
  const [issued, setIssued] = useState<{ name: string; key: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const list = useQuery({
    queryKey: ["sources", cfg.apiBase],
    queryFn: () => api<TelemetrySource[]>(cfg.apiBase),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["sources", cfg.apiBase] });
  const onIssued = (res: Record<string, unknown>) => {
    const r = wrap(res, cfg.noun);
    setIssued({ name: r.source.name, key: r.api_key });
    setCopied(false);
    refresh();
  };

  const register = useMutation({
    mutationFn: () => {
      const lat = form.latitude.trim();
      const lng = form.longitude.trim();
      return api<Record<string, unknown>>(cfg.apiBase, {
        method: "POST",
        body: JSON.stringify({
          name: form.name.trim(),
          [cfg.kindField]: form.kind,
          ...(form.region.trim() && { region: form.region.trim() }),
          ...(form.country.trim() && { country: form.country.trim() }),
          ...(lat && lng && { latitude: Number(lat), longitude: Number(lng) }),
        }),
      });
    },
    onSuccess: (res) => {
      onIssued(res);
      setForm({ ...EMPTY, kind: cfg.kinds[0].value });
    },
  });
  const rotate = useMutation({
    mutationFn: (id: string) =>
      api<Record<string, unknown>>(`${cfg.apiBase}/${id}/rotate-key`, { method: "POST" }),
    onSuccess: onIssued,
  });
  const deactivate = useMutation({
    mutationFn: (id: string) => api(`${cfg.apiBase}/${id}`, { method: "DELETE" }),
    onSuccess: refresh,
  });

  const set =
    (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
      setForm((f) => ({ ...f, [k]: e.target.value }));
  const error = register.error ?? rotate.error ?? deactivate.error;

  return (
    <div className="space-y-8">
      {issued && (
        <div role="alert" className="glass border-accent/40 p-4">
          <p className="text-sm font-semibold text-white">API key for “{issued.name}”</p>
          <p className="mt-1 text-xs text-slate-300">
            Copy it now — it is shown only once and cannot be retrieved later. The {cfg.noun} sends
            it in the <code className="font-mono">{cfg.keyHeader}</code> header to{" "}
            <code className="font-mono">POST {cfg.ingestPath}</code>.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <code className="break-all rounded bg-cyber-navy px-2 py-1 font-mono text-xs text-cyan-300">
              {issued.key}
            </code>
            <button
              type="button"
              className="btn-secondary !px-3 !py-1 text-xs"
              onClick={async () => {
                await navigator.clipboard.writeText(issued.key);
                setCopied(true);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button
              type="button"
              className="btn-secondary !px-3 !py-1 text-xs"
              onClick={() => setIssued(null)}
            >
              I have saved it
            </button>
          </div>
        </div>
      )}

      <form
        className="glass-panel grid gap-3 p-5 sm:grid-cols-2 lg:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault();
          register.mutate();
        }}
      >
        <h2 className="text-sm font-semibold text-white sm:col-span-2 lg:col-span-3">
          Register a {cfg.noun}
        </h2>
        <label className="text-xs text-slate-400">
          Name
          <input
            required
            maxLength={48}
            pattern="[A-Za-z0-9][A-Za-z0-9 ._\-]{0,47}"
            className="field mt-1"
            value={form.name}
            onChange={set("name")}
          />
        </label>
        <label className="text-xs text-slate-400">
          {cfg.kindLabel}
          <select className="field mt-1" value={form.kind} onChange={set("kind")}>
            {cfg.kinds.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Region (optional)
          <input
            maxLength={64}
            className="field mt-1"
            value={form.region}
            onChange={set("region")}
          />
        </label>
        <label className="text-xs text-slate-400">
          Country (optional)
          <input
            maxLength={64}
            className="field mt-1"
            value={form.country}
            onChange={set("country")}
          />
        </label>
        <label className="text-xs text-slate-400">
          Site latitude (optional)
          <input
            type="number"
            step="any"
            min={-90}
            max={90}
            className="field mt-1"
            value={form.latitude}
            onChange={set("latitude")}
          />
        </label>
        <label className="text-xs text-slate-400">
          Site longitude (optional)
          <input
            type="number"
            step="any"
            min={-180}
            max={180}
            className="field mt-1"
            value={form.longitude}
            onChange={set("longitude")}
          />
        </label>
        <p className="text-xs text-slate-500 sm:col-span-2">
          Location is the physical site you enter; events from this {cfg.noun} appear on the map
          there.
        </p>
        <button type="submit" disabled={register.isPending} className="btn-primary self-end">
          {register.isPending ? "Registering…" : "Register"}
        </button>
      </form>

      {error && (
        <p role="alert" className="text-sm text-sev-high">
          {error.message}
        </p>
      )}

      <section aria-label={`Registered ${cfg.noun}s`} className="glass">
        <h2 className="border-b border-white/10 px-4 py-3 text-sm font-semibold text-white">
          Registered {cfg.noun}s
        </h2>
        {list.isPending && <Skeleton className="m-4 h-16" />}
        {list.isError && (
          <ErrorState message={`Could not load ${cfg.noun}s.`} onRetry={() => list.refetch()} />
        )}
        {list.data && list.data.length === 0 && (
          <EmptyState title={`No ${cfg.noun}s registered`} hint={cfg.emptyHint} />
        )}
        {list.data && list.data.length > 0 && (
          <ul className="divide-y divide-white/5">
            {list.data.map((s) => (
              <li
                key={s.id}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-slate-100">{s.name}</p>
                  <p className="truncate text-xs text-slate-400">
                    {s.os ?? s.kind} ·{" "}
                    {[s.region, s.country].filter(Boolean).join(", ") || "no location"} · key{" "}
                    {s.key_prefix}… ·{" "}
                    {s.last_seen_at
                      ? `last telemetry ${timeAgo(s.last_seen_at)}`
                      : "no telemetry received yet"}
                  </p>
                </div>
                <span className="flex gap-2">
                  <button
                    type="button"
                    className="btn-secondary !px-3 !py-1 text-xs"
                    disabled={rotate.isPending}
                    onClick={() => rotate.mutate(s.id)}
                  >
                    Rotate key
                  </button>
                  <button
                    type="button"
                    className="btn-secondary !px-3 !py-1 text-xs"
                    disabled={deactivate.isPending}
                    onClick={() => deactivate.mutate(s.id)}
                  >
                    Deactivate
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

export default function SourcesAdmin({ cfg }: { cfg: SourceConfig }) {
  const { status, isAdmin } = useAuth();
  return (
    <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
      <p className="eyebrow mb-1">{cfg.eyebrow}</p>
      <h1 className="text-3xl font-bold text-white">{cfg.title}</h1>
      <p className="mb-8 mt-2 max-w-2xl text-sm text-slate-400">{cfg.intro}</p>
      {status === "loading" && <Skeleton className="h-40 w-full" />}
      {status === "anon" && (
        <div className="glass px-6 py-12 text-center">
          <p className="text-sm text-slate-300">Sign in with an administrator account.</p>
          <Link href="/login" className="btn-primary mt-4">
            Sign in
          </Link>
        </div>
      )}
      {status === "authed" && !isAdmin && (
        <div className="glass px-6 py-12 text-center text-sm text-slate-300" role="status">
          Only administrators can manage {cfg.noun}s.
        </div>
      )}
      {status === "authed" && isAdmin && <Panel cfg={cfg} />}
    </div>
  );
}
