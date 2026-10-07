"use client";

import { useMemo, useRef, useState } from "react";
import { AlertTriangle, Check, ChevronDown, CircleHelp, FilePlus2, LoaderCircle, ShieldAlert, MapPin, Radio } from "lucide-react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ErrorState, Skeleton } from "@/components/States";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AdminReportPage, GeocodeOption, GeocodeOptionPage, ReportPage, ReportStatus, ReportSubmission, ReportType, SecurityReport, Severity, User } from "@/types/api";

const issueTypes: { value: ReportType; label: string }[] = [
  { value: "phishing_website", label: "Phishing website" },
  { value: "suspicious_url", label: "Suspicious URL" },
  { value: "malicious_email", label: "Malicious email" },
  { value: "scam_message", label: "Scam message" },
  { value: "malware", label: "Malware" },
  { value: "credential_theft", label: "Credential theft" },
  { value: "impersonation", label: "Impersonation" },
  { value: "suspicious_attachment", label: "Suspicious attachment" },
  { value: "other", label: "Other cybersecurity issue" },
];

const severityOptions: Severity[] = ["low", "medium", "high", "critical"];
const statusLabels: Record<ReportStatus, string> = {
  submitted: "Submitted",
  under_review: "Under review",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive",
  reopened: "Reopened",
};

function localDateTime() {
  const now = new Date();
  return new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function dateLabel(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function statusTone(status: ReportStatus) {
  if (status === "resolved") return "border-emerald-300/20 bg-emerald-300/[0.07] text-emerald-200";
  if (status === "false_positive") return "border-slate-300/15 bg-slate-300/[0.05] text-slate-300";
  if (status === "investigating" || status === "reopened") return "border-amber-300/20 bg-amber-300/[0.07] text-amber-100";
  return "border-cyan-300/20 bg-cyan-300/[0.07] text-cyan-100";
}

export default function ReportsWorkspace() {
  const { status: authStatus, user, isAdmin } = useAuth();
  const client = useQueryClient();
  const [reportedAt, setReportedAt] = useState(localDateTime);
  const [queueQuery, setQueueQuery] = useState("");
  const [queueStatus, setQueueStatus] = useState<ReportStatus | "all">("all");
  const [formError, setFormError] = useState("");
  const [successCode, setSuccessCode] = useState("");
  const [trackingToken, setTrackingToken] = useState("");
  const [submissionLocationStatus, setSubmissionLocationStatus] = useState<ReportSubmission["location_status"] | "">("");
  const [trackedAnonymous, setTrackedAnonymous] = useState<SecurityReport | null>(null);

  const mine = useQuery({
    queryKey: ["reports", "mine"],
    queryFn: () => api<ReportPage>("/api/reports/mine"),
    enabled: authStatus === "authed",
  });
  const admin = useQuery({
    queryKey: ["reports", "admin", queueQuery, queueStatus],
    queryFn: () => {
      const params = new URLSearchParams();
      if (queueQuery.trim()) params.set("q", queueQuery.trim());
      if (queueStatus !== "all") params.set("status", queueStatus);
      return api<AdminReportPage>(`/api/reports/admin?${params.toString()}`);
    },
    enabled: authStatus === "authed" && isAdmin,
  });
  const users = useQuery({
    queryKey: ["users", "assignable"],
    queryFn: () => api<User[]>("/api/users"),
    enabled: authStatus === "authed" && isAdmin,
  });

  const submit = useMutation({
    mutationFn: (form: HTMLFormElement) => {
      const values = new FormData(form);
      return api<ReportSubmission>("/api/reports", {
        method: "POST",
        body: JSON.stringify({
          issue_type: values.get("issue_type"),
          title: values.get("title"),
          description: values.get("description"),
          suspicious_url: values.get("suspicious_url") || null,
          source_location: values.get("source_location") || null,
          reported_at: new Date(String(values.get("reported_at"))).toISOString(),
          severity: values.get("severity"),
          additional_notes: values.get("additional_notes") || null,
          anonymous: values.get("anonymous") === "on",
          publish_to_map: values.get("publish_to_map") === "on",
        }),
      });
    },
    onSuccess: (result) => {
      setFormError("");
      setSuccessCode(result.report_code);
      setTrackingToken(result.tracking_token ?? "");
      setSubmissionLocationStatus(result.location_status);
      client.invalidateQueries({ queryKey: ["reports", "mine"] });
      client.invalidateQueries({ queryKey: ["reports", "admin"] });
      const form = document.getElementById("report-threat-form") as HTMLFormElement | null;
      form?.reset();
      setReportedAt(localDateTime());
    },
    onError: (error) => setFormError(error instanceof ApiError && error.status === 429 ? "Report limit reached. Wait before submitting another report." : error.message),
  });

  const updateReport = useMutation({
    mutationFn: ({ code, patch }: { code: string; patch: Record<string, unknown> }) =>
      api(`/api/reports/admin/${encodeURIComponent(code)}`, { method: "PATCH", body: JSON.stringify(patch) }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["reports", "admin"] });
      client.invalidateQueries({ queryKey: ["reports", "mine"] });
    },
  });

  const promoteReport = useMutation({
    mutationFn: ({ code, payload }: { code: string; payload: Record<string, unknown> }) =>
      api(`/api/reports/admin/${encodeURIComponent(code)}/promote`, { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["reports", "admin"] });
      client.invalidateQueries({ queryKey: ["reports", "mine"] });
      client.invalidateQueries({ queryKey: ["security"] });
    },
  });

  const trackAnonymous = useMutation({
    mutationFn: () => api<SecurityReport>(`/api/reports/track/${encodeURIComponent(successCode)}`, {
      method: "POST",
      body: JSON.stringify({ token: trackingToken }),
    }),
    onSuccess: setTrackedAnonymous,
  });

  const analysts = useMemo(() => users.data?.filter((candidate) => candidate.roles.some((role) => role === "ADMINISTRATOR" || role === "SECURITY_ANALYST")) ?? [], [users.data]);

  if (authStatus === "loading") return <Skeleton className="h-80 w-full" />;
  return (
    <div className="mx-auto max-w-[1440px] px-4 py-8 sm:px-6 lg:px-10 lg:py-10">
      <div className="mb-7 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div><p className="eyebrow">Community reporting · private by default</p><h1 className="mt-2 text-3xl font-semibold tracking-[-0.04em] text-white">Report a security issue</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Send suspicious activity to the response team and follow its status. A city-level map point appears only after an analyst reviews and publishes the report.</p></div>
        {isAdmin && <span className="inline-flex items-center gap-2 self-start rounded-full border border-accent/20 bg-accent/[0.06] px-3 py-1.5 text-[10px] text-accent-strong sm:self-auto"><ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" /> Analyst operations enabled</span>}
      </div>

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.9fr)]">
        <section className="glass p-5 sm:p-6" aria-labelledby="report-form-title">
          <div className="flex items-start gap-3"><span className="grid h-9 w-9 place-items-center rounded-lg border border-accent/20 bg-accent/[0.06] text-accent-strong"><FilePlus2 className="h-4 w-4" aria-hidden="true" /></span><div><h2 id="report-form-title" className="text-base font-semibold text-white">Submit a report</h2><p className="mt-1 text-xs text-slate-500">Include enough detail for an analyst to investigate.</p></div></div>
          {successCode && <div className="mt-4 rounded-lg border border-emerald-300/20 bg-emerald-300/[0.06] p-3 text-xs text-emerald-100" role="status"><Check className="mr-2 inline h-4 w-4" aria-hidden="true" />Report submitted successfully. Reference <strong className="font-mono">{successCode}</strong> · status: Submitted · location: {submissionLocationStatus === "resolved" ? "approximate location resolved" : submissionLocationStatus === "unavailable" ? "location unavailable" : "not shared"}.{trackingToken && <><span className="mt-2 block break-all text-amber-100">Save this anonymous tracking token; it is shown once: <code>{trackingToken}</code></span><button type="button" onClick={() => trackAnonymous.mutate()} disabled={trackAnonymous.isPending} className="btn-secondary mt-2 !px-3 !py-1.5 text-[10px]">{trackAnonymous.isPending ? "Loading report…" : "View report"}</button>{trackAnonymous.isError && <span className="ml-2 text-red-200">Could not load this report.</span>}{trackedAnonymous && <div className="mt-3 border-t border-emerald-100/10 pt-2 text-slate-300"><strong>{trackedAnonymous.title}</strong><span className="ml-2">{statusLabels[trackedAnonymous.status]}</span><ReportTimeline timeline={trackedAnonymous.timeline} /></div>}</>}</div>}
          {formError && <p className="mt-4 rounded-lg border border-red-300/20 bg-red-300/[0.06] p-3 text-xs text-red-200" role="alert">{formError}</p>}
          <form id="report-threat-form" className="mt-5 space-y-4" onSubmit={(event) => { event.preventDefault(); setFormError(""); setSuccessCode(""); void submit.mutateAsync(event.currentTarget).catch(() => undefined); }}>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block text-xs text-slate-300">Issue type<select className="field mt-1.5" name="issue_type" required defaultValue="phishing_website">{issueTypes.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}</select></label>
              <label className="block text-xs text-slate-300">Severity<select className="field mt-1.5" name="severity" required defaultValue="medium">{severityOptions.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select></label>
            </div>
            <label className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-xs text-slate-300"><input type="checkbox" name="anonymous" className="mt-0.5 accent-cyan-400" /><span>Submit anonymously<span className="mt-1 block text-[10px] leading-4 text-slate-500">Your account identity will not be attached to the report. Keep the one-time tracking token shown after submission.</span></span></label>
            <label className="flex items-start gap-3 rounded-lg border border-cyan-300/10 bg-cyan-300/[0.025] p-3 text-xs text-slate-300"><input type="checkbox" name="publish_to_map" className="mt-0.5 accent-cyan-400" /><span>Share a privacy-safe summary on the organization threat map<span className="mt-1 block text-[10px] leading-4 text-slate-500">The public event uses generic text and server-set medium severity. If you enter a city/region, only that place name is sent for approximate lookup. Your name, report description, URL, and evidence stay private. Ambiguous locations remain unmapped.</span></span></label>
            <label className="block text-xs text-slate-300">Title<input className="field mt-1.5" name="title" minLength={3} maxLength={160} required placeholder="Briefly describe the issue" /></label>
            <label className="block text-xs text-slate-300">Description<textarea className="field mt-1.5 min-h-28 resize-y" name="description" minLength={10} maxLength={5000} required placeholder="What happened? Include indicators and steps already taken." /></label>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block text-xs text-slate-300">Suspicious URL <span className="text-slate-600">(optional)</span><input className="field mt-1.5" name="suspicious_url" type="url" maxLength={2048} placeholder="https://example.invalid/path" /></label>
              <label className="block text-xs text-slate-300">Source location <span className="text-slate-600">(optional)</span><input className="field mt-1.5" name="source_location" maxLength={120} placeholder="City, region or country only" /><span className="mt-1 block text-[10px] text-slate-600">Enter a city, region or country name only. An analyst may resolve it to an approximate map point after review.</span></label>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block text-xs text-slate-300">When did you observe it?<input className="field mt-1.5" name="reported_at" type="datetime-local" required value={reportedAt} onChange={(event) => setReportedAt(event.target.value)} /></label>
              <label className="block text-xs text-slate-300">Additional notes <span className="text-slate-600">(optional)</span><input className="field mt-1.5" name="additional_notes" maxLength={3000} placeholder="Anything else that may help" /></label>
            </div>
            <div className="flex gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-[10px] leading-5 text-slate-500"><CircleHelp className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />Evidence uploads are disabled until private object storage and malware scanning are configured. Do not include passwords, personal data, or secrets in this form.</div>
            <button type="submit" disabled={submit.isPending} className="btn-primary w-full sm:w-auto">{submit.isPending ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" /> : <FilePlus2 className="h-4 w-4" aria-hidden="true" />}Submit report</button>
          </form>
        </section>

        <section className="glass overflow-hidden" aria-labelledby="my-reports-title">
          <div className="panel-heading flex items-center justify-between"><div><h2 id="my-reports-title">My reports</h2><p className="mt-1 text-[10px] font-normal text-slate-500">{mine.data?.total ?? 0} reports submitted by {user?.full_name}</p></div><ChevronDown className="h-4 w-4 text-slate-500" aria-hidden="true" /></div>
          {authStatus === "anon" ? <div className="p-8 text-center"><p className="text-sm font-medium text-slate-300">Anonymous report tracking</p><p className="mt-2 text-xs leading-5 text-slate-500">After submitting anonymously, save the one-time token shown with your reference code. Sign in to keep future reports together in My reports.</p><Link href="/login" className="btn-secondary mt-4 !px-3 !py-2 text-xs">Sign in</Link></div> : mine.isPending ? <div className="space-y-3 p-4"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></div> : mine.isError ? <div className="p-4"><ErrorState message="Could not load your reports." onRetry={() => void mine.refetch()} /></div> : mine.data?.items.length ? <div className="divide-y divide-white/[0.06]">{mine.data.items.map((report) => <article key={report.report_code} className="p-4 sm:p-5"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-[10px] text-accent-strong">{report.report_code}</span><span className={`rounded-full border px-2 py-1 text-[9px] uppercase tracking-wide ${statusTone(report.status)}`}>{statusLabels[report.status]}</span></div><h3 className="mt-2 text-sm font-medium text-slate-100">{report.title}</h3><p className="mt-1 line-clamp-2 text-xs leading-5 text-slate-500">{report.description}</p><div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-slate-600"><span>{issueTypes.find((type) => type.value === report.issue_type)?.label ?? report.issue_type}</span><span>{report.severity.toUpperCase()}</span><span>{dateLabel(report.created_at)}</span></div><ReportTimeline timeline={report.timeline} /></article>)}</div> : <div className="p-8 text-center"><AlertTriangle className="mx-auto h-5 w-5 text-slate-600" aria-hidden="true" /><p className="mt-3 text-xs font-medium text-slate-300">No reports yet</p><p className="mt-1 text-[10px] text-slate-600">Submitted reports will appear here with their status.</p></div>}
        </section>
      </div>

      {isAdmin && <section className="glass mt-6 overflow-hidden" aria-labelledby="report-queue-title">
        <div className="panel-heading flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><h2 id="report-queue-title">Reports &amp; incidents queue</h2><p className="mt-1 text-[10px] font-normal text-slate-500">Private reports visible to security analysts and administrators.</p></div><div className="flex flex-col gap-2 sm:flex-row"><input aria-label="Search reports" className="field !w-full !py-2 text-xs sm:!w-52" placeholder="Search reports" value={queueQuery} onChange={(event) => setQueueQuery(event.target.value)} /><select aria-label="Filter reports by status" className="field !w-full !py-2 text-xs sm:!w-40" value={queueStatus} onChange={(event) => setQueueStatus(event.target.value as ReportStatus | "all")}><option value="all">All statuses</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div></div>
        {admin.isPending ? <div className="space-y-3 p-4"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></div> : admin.isError ? <div className="p-4"><ErrorState message="Could not load the report queue." onRetry={() => void admin.refetch()} /></div> : admin.data?.items.length ? <div className="divide-y divide-white/[0.06]">{admin.data.items.map((report) => <article key={report.report_code} className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_minmax(280px,0.7fr)] lg:p-5"><div><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[10px] text-accent-strong">{report.report_code}</span><span className={`rounded-full border px-2 py-1 text-[9px] uppercase tracking-wide ${statusTone(report.status)}`}>{statusLabels[report.status]}</span><span className="text-[9px] text-slate-600">{report.severity.toUpperCase()}</span></div><h3 className="mt-2 text-sm font-medium text-slate-100">{report.title}</h3><p className="mt-1 text-[10px] text-slate-500">{report.reporter_name} · {report.reporter_email} · {dateLabel(report.created_at)}</p><p className="mt-2 whitespace-pre-wrap text-xs leading-5 text-slate-400">{report.description}</p>{report.suspicious_url && <a href={report.suspicious_url} target="_blank" rel="noopener noreferrer" className="mt-2 inline-block break-all text-[10px] text-accent-strong underline">{report.suspicious_url}</a>}{report.source_location && <p className="mt-2 text-[10px] text-slate-500">Location provided: {report.source_location} · resolver available during review</p>}{report.internal_notes.length > 0 && <div className="mt-3 space-y-2 rounded-lg border border-amber-300/10 bg-amber-300/[0.03] p-3"><p className="eyebrow !text-[9px] !text-amber-200">Internal analyst notes · not visible to reporter</p>{report.internal_notes.map((note, index) => <p key={`${note.created_at}-${index}`} className="text-[10px] leading-4 text-slate-400"><strong className="text-slate-300">{note.author}</strong> · {dateLabel(note.created_at)}<br />{note.content}</p>)}</div>}<ReportTimeline timeline={report.timeline} /></div><div className="space-y-3 rounded-lg border border-white/[0.06] bg-black/10 p-3"><label className="block text-[10px] text-slate-500">Status<select className="field mt-1.5 !py-2 text-xs" value={report.status} onChange={(event) => void updateReport.mutateAsync({ code: report.report_code, patch: { status: event.target.value } }).catch(() => undefined)}>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value} disabled={value !== report.status && !allowedTransition(report.status, value as ReportStatus)}>{label}</option>)}</select></label><label className="block text-[10px] text-slate-500">Assigned analyst<select className="field mt-1.5 !py-2 text-xs" value={report.assigned_to_id ?? ""} onChange={(event) => void updateReport.mutateAsync({ code: report.report_code, patch: { assigned_to_id: event.target.value || null } }).catch(() => undefined)}><option value="">Unassigned</option>{analysts.map((analyst) => <option key={analyst.id} value={analyst.id}>{analyst.full_name} · {analyst.email}</option>)}</select></label><InternalNote reportCode={report.report_code} pending={updateReport.isPending} onSubmit={(internal_note) => updateReport.mutateAsync({ code: report.report_code, patch: { internal_note } })} />{report.promoted_event_id ? <p className="rounded border border-emerald-300/15 bg-emerald-300/[0.04] p-2 text-[10px] text-emerald-200"><Radio className="mr-1 inline h-3 w-3" aria-hidden="true" />Published event {report.promoted_event_id}</p> : (report.status === "under_review" || report.status === "investigating") && <PromotionForm report={report} pending={promoteReport.isPending} error={promoteReport.error instanceof Error ? promoteReport.error.message : ""} onSubmit={(payload) => promoteReport.mutateAsync({ code: report.report_code, payload })} />}</div></article>)}</div> : <div className="p-8 text-center text-xs text-slate-500">No reports match the selected filters.</div>}
      </section>}
    </div>
  );
}

function allowedTransition(from: ReportStatus, to: ReportStatus) {
  const transitions: Record<ReportStatus, ReportStatus[]> = {
    submitted: ["under_review"],
    under_review: ["investigating", "resolved", "false_positive"],
    investigating: ["under_review", "resolved", "false_positive"],
    resolved: ["reopened"],
    false_positive: ["reopened"],
    reopened: ["under_review", "investigating", "resolved", "false_positive"],
  };
  return transitions[from].includes(to);
}

function ReportTimeline({ timeline }: { timeline: { action: string; summary: string; created_at: string; actor_name: string | null }[] }) {
  if (!timeline.length) return null;
  return <details className="mt-4 rounded-lg border border-white/[0.06] bg-white/[0.015] px-3 py-2">
    <summary className="cursor-pointer text-[10px] font-medium text-slate-400">Report timeline · {timeline.length} updates</summary>
    <ol className="mt-3 space-y-3 border-l border-white/[0.08] pl-3">
      {timeline.map((item, index) => <li key={`${item.action}-${item.created_at}-${index}`} className="relative text-[10px] text-slate-500"><span className="absolute -left-[17px] top-1 h-1.5 w-1.5 rounded-full bg-accent/70" /><p className="text-slate-300">{item.summary}</p><p className="mt-0.5">{dateLabel(item.created_at)}{item.actor_name ? ` · ${item.actor_name}` : ""}</p></li>)}
    </ol>
  </details>;
}

function InternalNote({ reportCode, pending, onSubmit }: { reportCode: string; pending: boolean; onSubmit: (note: string) => Promise<unknown> }) {
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  return <form className="border-t border-white/[0.06] pt-3" onSubmit={(event) => { event.preventDefault(); const value = note.trim(); if (!value) return; setError(""); void onSubmit(value).then(() => setNote("")).catch((err: unknown) => setError(err instanceof Error ? err.message : `Could not add note to ${reportCode}`)); }}><label className="block text-[10px] text-slate-500">Add internal note<textarea className="field mt-1.5 min-h-16 resize-y !py-2 text-xs" value={note} onChange={(event) => setNote(event.target.value)} maxLength={2000} placeholder="Visible only to analysts and administrators" /></label>{error && <p className="mt-1 text-[10px] text-red-300" role="alert">{error}</p>}<button disabled={!note.trim() || pending} type="submit" className="btn-secondary mt-2 !px-3 !py-1.5 text-[10px]">Add note</button></form>;
}

function PromotionForm({ report, pending, error, onSubmit }: {
  report: AdminReportPage["items"][number];
  pending: boolean;
  error: string;
  onSubmit: (payload: Record<string, unknown>) => Promise<unknown>;
}) {
  const [message, setMessage] = useState("");
  const [lookupPending, setLookupPending] = useState(false);
  const [lookupError, setLookupError] = useState("");
  const [options, setOptions] = useState<GeocodeOption[]>([]);
  const [selected, setSelected] = useState<GeocodeOption | null>(null);
  const countryRef = useRef<HTMLInputElement>(null);
  const regionRef = useRef<HTMLInputElement>(null);
  const latitudeRef = useRef<HTMLInputElement>(null);
  const longitudeRef = useRef<HTMLInputElement>(null);
  const defaultType = report.issue_type === "phishing_website" || report.issue_type === "suspicious_url" || report.issue_type === "impersonation"
    ? "phishing"
    : report.issue_type === "malware" || report.issue_type === "suspicious_attachment"
      ? "malware_ransomware"
      : "other";
  const resolveLocation = async () => {
    setLookupPending(true);
    setLookupError("");
    setOptions([]);
    setSelected(null);
    try {
      const result = await api<GeocodeOptionPage>(`/api/reports/admin/${encodeURIComponent(report.report_code)}/location-options`);
      setOptions(result.items);
      if (!result.items.length) setLookupError("No matching city or region was found. Check the location name or enter verified coarse coordinates.");
    } catch (lookupFailure) {
      setLookupError(lookupFailure instanceof Error ? lookupFailure.message : "Could not resolve this place name.");
    } finally {
      setLookupPending(false);
    }
  };
  const chooseLocation = (option: GeocodeOption) => {
    setSelected(option);
    if (countryRef.current) countryRef.current.value = option.country ?? "";
    if (regionRef.current) regionRef.current.value = option.region ?? option.locality;
    if (latitudeRef.current) latitudeRef.current.value = option.latitude.toFixed(2);
    if (longitudeRef.current) longitudeRef.current.value = option.longitude.toFixed(2);
  };
  return <form className="space-y-2 border-t border-white/[0.06] pt-3" onSubmit={(event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setMessage("");
    void onSubmit({
      content_reviewed: form.get("content_reviewed") === "on",
      location_verified: form.get("location_verified") === "on",
      threat_type: form.get("threat_type"),
      title: form.get("title"),
      description: form.get("description"),
      country: form.get("country") || null,
      region: form.get("region") || null,
      latitude: Number(form.get("latitude")),
      longitude: Number(form.get("longitude")),
    }).then(() => setMessage("Reviewed event published to the security event feed.")).catch(() => undefined);
  }}>
    <p className="flex items-center gap-1 text-[10px] font-medium text-slate-300"><MapPin className="h-3 w-3 text-accent-strong" aria-hidden="true" />Promote reviewed intelligence</p>
    <p className="text-[9px] leading-4 text-slate-500">A map point appears only after publication. Resolve the submitted city name, choose the correct match, and confirm the approximate location. Only the place name is sent to OpenStreetMap for lookup.</p>
    {report.source_location && <div className="rounded-md border border-white/[0.06] bg-white/[0.02] p-2"><p className="text-[9px] text-slate-400">Submitted place name: <span className="text-slate-200">{report.source_location}</span></p><button type="button" onClick={() => void resolveLocation()} disabled={lookupPending} className="btn-secondary mt-2 !px-3 !py-1.5 text-[10px]">{lookupPending ? "Finding places…" : "Resolve location name"}</button>{lookupError && <p className="mt-2 text-[9px] text-amber-200" role="status">{lookupError}</p>}{options.length > 0 && <div className="mt-2 space-y-1" aria-label="Location matches">{options.map((option, index) => <button key={`${option.latitude}-${option.longitude}-${index}`} type="button" onClick={() => chooseLocation(option)} aria-pressed={selected === option} className={`block w-full rounded border px-2 py-1.5 text-left text-[9px] transition-colors ${selected === option ? "border-accent/40 bg-accent/[0.08] text-accent-strong" : "border-white/[0.06] text-slate-300 hover:bg-white/[0.04]"}`}>{option.label} <span className="text-slate-500">· {option.latitude.toFixed(2)}, {option.longitude.toFixed(2)}</span></button>)}<p className="text-[8px] text-slate-600">Place data <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer" className="underline">© OpenStreetMap contributors</a></p></div>}</div>}
    <label className="block text-[10px] text-slate-500">Threat category<select name="threat_type" className="field mt-1 !py-2 text-xs" defaultValue={defaultType}><option value="phishing">Phishing</option><option value="malware_ransomware">Malware / ransomware</option><option value="mitm">Man in the middle</option><option value="unsafe_network">Unsafe network</option><option value="vulnerability">Vulnerability</option><option value="suspicious_login">Suspicious login</option><option value="other">Other</option></select></label>
    <label className="block text-[10px] text-slate-500">Public event title<input name="title" required minLength={3} maxLength={200} className="field mt-1 !py-2 text-xs" defaultValue={report.title.slice(0, 200)} /></label>
    <label className="block text-[10px] text-slate-500">Sanitized event summary<textarea name="description" required minLength={10} maxLength={4000} className="field mt-1 min-h-16 !py-2 text-xs" defaultValue={report.description} /></label>
    <div className="grid grid-cols-2 gap-2"><label className="block text-[10px] text-slate-500">Country<input ref={countryRef} name="country" maxLength={64} className="field mt-1 !py-2 text-xs" placeholder="Optional" /></label><label className="block text-[10px] text-slate-500">Region / city<input ref={regionRef} name="region" maxLength={64} className="field mt-1 !py-2 text-xs" placeholder="Optional" /></label></div>
    <div className="grid grid-cols-2 gap-2"><label className="block text-[10px] text-slate-500">Approx. latitude<input ref={latitudeRef} name="latitude" type="number" min={-90} max={90} step="0.01" required className="field mt-1 !py-2 text-xs" placeholder="Resolve a place name" /></label><label className="block text-[10px] text-slate-500">Approx. longitude<input ref={longitudeRef} name="longitude" type="number" min={-180} max={180} step="0.01" required className="field mt-1 !py-2 text-xs" placeholder="Resolve a place name" /></label></div>
    <label className="flex gap-2 text-[9px] leading-4 text-slate-400"><input name="content_reviewed" type="checkbox" required className="mt-0.5 accent-cyan-400" />I reviewed the evidence and removed reporter identity, secrets, and unverified claims from the public summary.</label>
    <label className="flex gap-2 text-[9px] leading-4 text-slate-400"><input name="location_verified" type="checkbox" required className="mt-0.5 accent-cyan-400" />I checked this approximate city-level location against the evidence and approve its publication on the threat map.</label>
    {(error || message) && <p className={`text-[10px] ${error ? "text-red-300" : "text-emerald-300"}`} role={error ? "alert" : "status"}>{error || message}</p>}
    <button type="submit" disabled={pending} className="btn-secondary w-full !py-2 text-[10px]">{pending ? "Publishing…" : "Publish reviewed event"}</button>
  </form>;
}
