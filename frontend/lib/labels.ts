import type { EventStatus, Severity, ThreatType } from "@/types/api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<Severity, { label: string; classes: string; hex: string }> = {
  critical: {
    label: "Critical",
    classes: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
    hex: "#ef4444",
  },
  high: {
    label: "High",
    classes: "text-sev-high border-sev-high/50 bg-sev-high/10",
    hex: "#f97316",
  },
  medium: {
    label: "Medium",
    classes: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
    hex: "#f59e0b",
  },
  low: { label: "Low", classes: "text-sev-low border-sev-low/50 bg-sev-low/10", hex: "#10b981" },
  info: {
    label: "Info",
    classes: "text-sev-info border-sev-info/50 bg-sev-info/10",
    hex: "#94a3b8",
  },
};

export const THREAT_TYPE_LABEL: Record<ThreatType, string> = {
  phishing: "Phishing",
  malware_ransomware: "Malware & Ransomware",
  mitm: "Man-in-the-Middle",
  unsafe_network: "Unsafe Network",
  vulnerability: "Vulnerability",
  suspicious_login: "Suspicious Login",
  other: "Other",
};

export const STATUS_LABEL: Record<EventStatus, string> = {
  open: "Open",
  investigating: "Investigating",
  blocked: "Blocked",
  resolved: "Resolved",
  false_positive: "False positive",
};

import type { Classification } from "@/types/api";

// Classification comes from the backend detection engine; this only maps it to a label and style.
export const CLASSIFICATION_META: Record<
  Classification,
  { label: string; classes: string; severity: Severity }
> = {
  likely_phishing: {
    label: "Likely phishing",
    classes: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
    severity: "critical",
  },
  suspicious: {
    label: "Suspicious",
    classes: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
    severity: "medium",
  },
  low_risk: {
    label: "Low risk",
    classes: "text-sev-low border-sev-low/50 bg-sev-low/10",
    severity: "low",
  },
};

import type { Verdict } from "@/types/api";

// Verdicts come from the backend aggregator; "clean" only means "not flagged".
export const VERDICT_META: Record<Verdict, { label: string; classes: string }> = {
  malicious: {
    label: "Malicious",
    classes: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
  },
  suspicious: {
    label: "Suspicious",
    classes: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
  },
  clean: { label: "Not flagged", classes: "text-sev-low border-sev-low/50 bg-sev-low/10" },
  unknown: { label: "Unknown", classes: "text-sev-info border-sev-info/50 bg-sev-info/10" },
};

export const PROVIDER_LABEL: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlhaus: "URLhaus",
  otx: "AlienVault OTX",
};
