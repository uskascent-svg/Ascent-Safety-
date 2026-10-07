export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ThreatType =
  | "phishing"
  | "malware_ransomware"
  | "mitm"
  | "unsafe_network"
  | "vulnerability"
  | "suspicious_login"
  | "other";
export type EventStatus = "open" | "investigating" | "blocked" | "resolved" | "false_positive";
export type ReportStatus = "submitted" | "under_review" | "investigating" | "resolved" | "false_positive" | "reopened";
export type ReportType = "phishing_website" | "suspicious_url" | "malicious_email" | "scam_message" | "malware" | "credential_theft" | "impersonation" | "suspicious_attachment" | "other";

export interface SecurityReport {
  report_code: string;
  issue_type: ReportType;
  title: string;
  description: string;
  suspicious_url: string | null;
  source_location: string | null;
  reported_at: string;
  severity: Severity;
  additional_notes: string | null;
  status: ReportStatus;
  created_at: string;
  updated_at: string;
  timeline: { action: string; summary: string; created_at: string; actor_name: string | null }[];
}

export interface ReportSubmission extends SecurityReport {
  tracking_token: string | null;
  location_status: "not_shared" | "resolved" | "unavailable";
  published_event_id: string | null;
}

export interface AdminSecurityReport extends SecurityReport {
  reporter_id: string;
  reporter_name: string;
  reporter_email: string;
  assigned_to_id: string | null;
  assigned_to_name: string | null;
  internal_notes: { content: string; created_at: string; author: string }[];
  promoted_event_id: string | null;
  published_event_id: string | null;
}

export interface ReportPage {
  items: SecurityReport[];
  total: number;
  limit: number;
  offset: number;
}

export interface AdminReportPage {
  items: AdminSecurityReport[];
  total: number;
  limit: number;
  offset: number;
}

export interface GeocodeOption {
  label: string;
  locality: string;
  region: string | null;
  country: string | null;
  latitude: number;
  longitude: number;
}

export interface GeocodeOptionPage {
  items: GeocodeOption[];
  cached: boolean;
  attribution: string;
}

export interface NotificationItem {
  id: string;
  event_id: string;
  title: string;
  created_at: string;
  read_at: string | null;
}

export interface NotificationPage {
  items: NotificationItem[];
  total: number;
  unread: number;
}

export interface SecurityEvent {
  id: string;
  source: string;
  external_id: string | null;
  threat_type: ThreatType;
  severity: Severity;
  status: EventStatus;
  title: string;
  description: string | null;
  source_ip: string | null;
  country: string | null;
  region: string | null;
  latitude: number | null;
  longitude: number | null;
  origin_latitude: number | null;
  origin_longitude: number | null;
  destination_latitude: number | null;
  destination_longitude: number | null;
  occurred_at: string;
}

export interface EventPage {
  items: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface EventLocation {
  id: string;
  latitude: number | null;
  longitude: number | null;
  origin_latitude: number | null;
  origin_longitude: number | null;
  destination_latitude: number | null;
  destination_longitude: number | null;
  country: string | null;
  region: string | null;
  threat_type: ThreatType;
  severity: Severity;
  status: EventStatus;
  source: string;
  title: string;
  occurred_at: string;
}

export interface EventLocationList {
  items: EventLocation[];
  total: number;
  truncated: boolean;
}

export interface DashboardSummary {
  total_events: number;
  active_threats: number;
  blocked_threats: number;
  critical_events: number;
  affected_regions: number;
}

export interface RegionItem {
  region: string;
  count: number;
}

export interface DistributionItem {
  key: string;
  count: number;
}

export interface TimelinePoint {
  bucket: string;
  count: number;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  roles: string[];
}

export type Classification = "low_risk" | "suspicious" | "likely_phishing";

export interface PhishingIndicator {
  code: string;
  category: string;
  severity: Severity;
  description: string;
  evidence: string[];
}

export interface PhishingAnalysis {
  id: string;
  created_at: string;
  sender: string | null;
  subject: string | null;
  risk_score: number;
  classification: Classification;
  reasons: string[];
  indicators: PhishingIndicator[];
  ml: {
    available: boolean;
    probability: number | null;
    model_version: string | null;
    top_terms: string[];
  };
  recommended_action: string;
  link_count: number;
  attachment_count: number;
  intel?: IntelSummary | null;
}

export interface IntelSummary {
  providers: string[];
  indicators_checked: number;
  unavailable: number;
  note: string | null;
}

export interface PhishingRequest {
  raw_email?: string;
  sender?: string;
  subject?: string;
  body_text?: string;
  check_threat_intel?: boolean;
}

export interface TrainingScenario {
  id: string;
  slug: string;
  title: string;
  category: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  artifact_type: "email" | "sms" | "url" | "login_page";
  sender: string;
  reply_to: string | null;
  subject: string;
  received_at: string;
  headers: Record<string, string>;
  body: string;
  links: { label: string; url: string }[];
  attachments: { name: string; type: string; size: string }[];
  objective: string;
}

export interface TrainingIndicator {
  id: string;
  label: string;
  severity: Severity;
  explanation: string;
}

export interface TrainingAttemptResult {
  id: string;
  scenario_id: string;
  security_score: number;
  detection_accuracy: number;
  indicator_score: number;
  action_score: number;
  indicators_found: TrainingIndicator[];
  indicators_missed: TrainingIndicator[];
  actions_feedback: { id: string; label: string; correct: boolean; selected: boolean; rationale: string }[];
  decision_correct: boolean;
  attack_technique: string;
  explanation: string;
  prevention: string;
  recommended_improvement: string;
  created_at: string;
}

export interface TrainingProgress {
  scenarios_completed: number;
  average_score: number;
  detection_accuracy: number;
  training_level: string;
  weakest_category: string | null;
  current_streak: number;
  badges: string[];
  certificate_eligible: boolean;
  recommended_next: TrainingScenario | null;
}

export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface IntelProviderResult {
  provider: string;
  status: "ok" | "not_found" | "rate_limited" | "error";
  verdict: Verdict;
  detail: Record<string, unknown>;
  cached: boolean;
  checked_at: string | null;
}

export interface IntelLookup {
  indicator: string;
  indicator_type: string;
  verdict: Verdict;
  results: IntelProviderResult[];
  note: string;
}

export interface Alert {
  id: string;
  event_id: string;
  severity: Severity;
  title: string;
  status: "open" | "acknowledged" | "resolved";
  created_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  resolution_note: string | null;
  threat_type: ThreatType;
  source: string;
  region: string | null;
  occurred_at: string;
}

export interface AlertPage {
  items: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export interface Endpoint {
  id: string;
  name: string;
  os: "windows" | "linux" | "macos";
  hostname: string | null;
  agent_version: string | null;
  region: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  key_prefix: string;
  is_active: boolean;
  created_at: string;
  last_seen_at: string | null;
}

export interface EndpointCreated {
  endpoint: Endpoint;
  api_key: string;
}

export interface Sensor {
  id: string;
  name: string;
  kind: "zeek" | "suricata" | "proxy" | "agent" | "other";
  region: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  key_prefix: string;
  is_active: boolean;
  created_at: string;
  last_seen_at: string | null;
}

/** Fields shared by endpoints and sensors (both are registered telemetry sources). */
export interface TelemetrySource {
  id: string;
  name: string;
  os?: string;
  kind?: string;
  region: string | null;
  country: string | null;
  key_prefix: string;
  is_active: boolean;
  last_seen_at: string | null;
}
