"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { ThreatType } from "@/types/api";

type AlertStatus = "draft" | "approved" | "active" | "expired" | "revoked";
interface CyberAlert {
  id: string; title: string; severity: string; threat_type: ThreatType; affected_region: string;
  summary: string; recommended_actions: string[]; related_event_ids: string[]; status: AlertStatus;
  created_by_id: string;
  location_status: string; expires_at: string; published_at: string | null; published_event_id: string | null;
  history?: { id: string; actor_id: string | null; action: string; created_at: string; changes: Record<string, unknown> }[];
}
interface Page { items: CyberAlert[]; total: number }

const THREAT_TYPES: ThreatType[] = ["phishing", "malware_ransomware", "mitm", "unsafe_network", "vulnerability", "suspicious_login", "other"];
const defaultExpiry = () => new Date(Date.now() + 24 * 60 * 60_000).toISOString().slice(0, 16);

export function ActiveCyberAlertBanner() {
  const { isAuthenticated } = useAuth();
  const { data } = useQuery({
    queryKey: ["cyber-alerts", "active"],
    queryFn: () => api<Page>("/api/cyber-alerts"),
    enabled: isAuthenticated,
    refetchInterval: 60_000,
  });
  const active = data?.items.filter((item) => item.status === "active").slice(0, 2) ?? [];
  if (!active.length) return null;
  return <section aria-label="Active cyber alerts" className="mb-4 space-y-2">{active.map((item) => <article key={item.id} className="rounded-xl border border-amber-400/30 bg-amber-950/25 p-4 sm:flex sm:items-start sm:justify-between sm:gap-4"><div><p className="text-xs font-semibold uppercase tracking-wider text-amber-300">Active cyber alert · {item.severity}</p><h2 className="mt-1 text-base font-semibold text-white">{item.title}</h2><p className="mt-1 text-sm text-slate-300">{item.affected_region} · {item.summary}</p></div><p className="mt-2 shrink-0 text-xs text-slate-400 sm:mt-1">Expires {new Date(item.expires_at).toLocaleString()}</p></article>)}</section>;
}

export default function CyberAlertsPanel() {
  const { isAdmin, isAnalyst, user } = useAuth();
  const queryClient = useQueryClient();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("high");
  const [threatType, setThreatType] = useState<ThreatType>("other");
  const [region, setRegion] = useState("");
  const [summary, setSummary] = useState("");
  const [actions, setActions] = useState("");
  const [expiresAt, setExpiresAt] = useState(defaultExpiry);
  const [relatedIds, setRelatedIds] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const query = useQuery({ queryKey: ["cyber-alerts"], queryFn: () => api<Page>("/api/cyber-alerts"), enabled: isAdmin || isAnalyst });
  const create = useMutation({
    mutationFn: () => api<CyberAlert>(editingId ? `/api/cyber-alerts/${editingId}` : "/api/cyber-alerts", { method: editingId ? "PUT" : "POST", body: JSON.stringify({ title, severity, threat_type: threatType, affected_region: region, summary, recommended_actions: actions.split("\n").map((line) => line.trim()).filter(Boolean), related_event_ids: relatedIds.split(",").map((id) => id.trim()).filter(Boolean), expires_at: new Date(expiresAt).toISOString() }) }),
    onSuccess: async () => { setError(""); setTitle(""); setRegion(""); setSummary(""); setActions(""); setRelatedIds(""); setEditingId(null); await queryClient.invalidateQueries({ queryKey: ["cyber-alerts"] }); },
    onError: (e: Error) => setError(e.message),
  });
  const transition = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "approve" | "publish" | "revoke" }) => api<CyberAlert>(`/api/cyber-alerts/${id}/${action}`, { method: "POST" }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["cyber-alerts"] }); await queryClient.invalidateQueries({ queryKey: ["security"] }); },
    onError: (e: Error) => setError(e.message),
  });
  const editDraft = (alert: CyberAlert) => {
    setEditingId(alert.id); setTitle(alert.title); setSeverity(alert.severity); setThreatType(alert.threat_type);
    setRegion(alert.affected_region); setSummary(alert.summary); setActions(alert.recommended_actions.join("\n"));
    setRelatedIds(alert.related_event_ids.join(", "));
    const date = new Date(alert.expires_at);
    setExpiresAt(new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16));
  };

  if (!isAdmin && !isAnalyst) return null;
  return <section className="glass space-y-4 p-4 sm:p-5">
    <div><p className="eyebrow">AUTHORIZED RESPONSE</p><h2 className="mt-1 text-lg font-semibold text-white">Cyber Alert Declarations</h2><p className="mt-1 text-sm text-slate-400">Create an advisory tied to a region. Publication creates a stored event that appears on the map and event stream.</p></div>
    {(isAdmin || isAnalyst) && <form className="grid gap-3 rounded-lg border border-white/10 p-4 md:grid-cols-2" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
      <label className="text-sm text-slate-300">Alert title<input required minLength={5} maxLength={200} className="input mt-1 w-full" value={title} onChange={(e) => setTitle(e.target.value)} /></label>
      <label className="text-sm text-slate-300">Affected region<input required minLength={2} maxLength={120} placeholder="City, region, or country" className="input mt-1 w-full" value={region} onChange={(e) => setRegion(e.target.value)} /></label>
      <label className="text-sm text-slate-300">Severity<select className="input mt-1 w-full" value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
      <label className="text-sm text-slate-300">Threat type<select className="input mt-1 w-full" value={threatType} onChange={(e) => setThreatType(e.target.value as ThreatType)}>{THREAT_TYPES.map((type) => <option key={type} value={type}>{type.replaceAll("_", " ")}</option>)}</select></label>
      <label className="text-sm text-slate-300 md:col-span-2">Summary<textarea required minLength={20} maxLength={3000} className="input mt-1 min-h-20 w-full" value={summary} onChange={(e) => setSummary(e.target.value)} /></label>
      <label className="text-sm text-slate-300 md:col-span-2">Recommended actions <span className="text-slate-500">(one per line)</span><textarea required className="input mt-1 min-h-20 w-full" value={actions} onChange={(e) => setActions(e.target.value)} /></label>
      <label className="text-sm text-slate-300 md:col-span-2">Related event IDs <span className="text-slate-500">(optional, comma separated)</span><input className="input mt-1 w-full" value={relatedIds} onChange={(e) => setRelatedIds(e.target.value)} /></label>
      <label className="text-sm text-slate-300">Expires at<input required type="datetime-local" className="input mt-1 w-full" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} /></label>
      <div className="flex items-end gap-2"><button className="btn-primary" disabled={create.isPending}>{create.isPending ? "Saving…" : editingId ? "Update draft" : "Save as draft"}</button>{editingId && <button type="button" className="btn-secondary" onClick={() => { setEditingId(null); setTitle(""); setRegion(""); setSummary(""); setActions(""); setRelatedIds(""); }}>Cancel edit</button>}</div>
      <p className="text-xs text-slate-500 md:col-span-2">Critical alerts require administrator approval and can only be published by an administrator.</p>
    </form>}
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
    {query.isPending ? <p className="text-sm text-slate-400">Loading declarations…</p> : query.isError ? <p role="alert" className="text-sm text-red-300">Could not load declarations.</p> : query.data?.items.length ? <ul className="divide-y divide-white/5">{query.data.items.map((alert) => <li key={alert.id} className="py-4"><div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="font-medium text-white">{alert.title}</h3><span className="rounded border border-white/10 px-2 py-0.5 text-xs uppercase text-slate-300">{alert.status}</span><span className="text-xs uppercase text-amber-300">{alert.severity}</span></div><p className="mt-1 text-sm text-slate-400">{alert.affected_region} · {alert.summary}</p><p className="mt-1 text-xs text-slate-500">Location: {alert.location_status} · Expires {new Date(alert.expires_at).toLocaleString()}</p><details className="mt-2 text-xs text-slate-400"><summary className="cursor-pointer">Audit history ({alert.history?.length ?? 0})</summary><ol className="mt-2 space-y-2 border-l border-white/10 pl-3">{alert.history?.map((entry) => <li key={entry.id}><p className="text-slate-300">{entry.action} · {new Date(entry.created_at).toLocaleString()}</p><p className="text-[10px] text-slate-500">Actor {entry.actor_id ?? "system"}</p><pre className="mt-1 whitespace-pre-wrap break-all text-[10px] text-slate-500">{JSON.stringify(entry.changes)}</pre></li>)}</ol></details></div><div className="flex flex-wrap gap-2">{alert.status === "draft" && (isAdmin || alert.created_by_id === user?.id) && <button className="btn-secondary !py-1.5 text-xs" onClick={() => editDraft(alert)}>Edit</button>}{alert.status === "draft" && isAdmin && <button className="btn-secondary !py-1.5 text-xs" disabled={transition.isPending} onClick={() => transition.mutate({ id: alert.id, action: "approve" })}>Approve</button>}{alert.status === "approved" && (alert.severity !== "critical" || isAdmin) && <button className="btn-secondary !py-1.5 text-xs" disabled={transition.isPending} onClick={() => transition.mutate({ id: alert.id, action: "publish" })}>Publish</button>}{(alert.status === "active" || alert.status === "approved") && isAdmin && <button className="btn-secondary !py-1.5 text-xs" disabled={transition.isPending} onClick={() => transition.mutate({ id: alert.id, action: "revoke" })}>Revoke</button>}</div></div></li>)}</ul> : <p className="rounded-lg border border-dashed border-slate-700 p-5 text-sm text-slate-400">No alert declarations. New advisories will appear here after creation.</p>}
  </section>;
}
