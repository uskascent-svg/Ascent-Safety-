# Endpoint telemetry (malware & ransomware monitoring)

Ascent Safety **does not include an endpoint agent** and does not protect endpoints. It receives
behaviour reports from agents *you* connect (an EDR export, Sysmon/auditd forwarder, custom
collector, …), evaluates them with the detectors in `backend/app/detection/malware/`, and records
findings as security events and alerts. Nothing is executed, quarantined or blocked.

## Connect an agent
1. An administrator registers the endpoint (`/endpoints` page or `POST /api/endpoints`). An API key
   (`ascent_ep_…`) is returned **once**; only its hash is stored. Rotate with `/rotate-key`.
2. The agent sends batches (max 500 observations) to `POST /api/endpoint-telemetry` with the header
   `X-Endpoint-Key: <key>`. Timestamps must be ISO-8601 with a timezone and not in the future.
3. The response reports `received`, `findings`, `events_created`, `duplicates_skipped`. Benign
   telemetry is discarded; only findings (with evidence) are stored.

Events inherit the endpoint's `region`, `country` and site coordinates, as entered by the
administrator. Events at or above `ALERT_MIN_SEVERITY` (default `high`) also create an alert.

## Observation types (format illustration, not data)
Every observation has `type` and `occurred_at`; unknown fields are rejected.

| type | fields |
|---|---|
| `process` | `image`, `command_line?`, `parent_image?`, `user?`, `sha256?` |
| `file` | `path`, `action` (created/modified/renamed/deleted/executed), `process_image?`, `sha256?` |
| `file_activity` | `window_seconds`, `files_modified`, `files_renamed`, `files_deleted`, `distinct_directories`, `new_extensions[]`, `mean_write_entropy?` (0–8), `process_image?` |
| `persistence` | `mechanism` (run_key, scheduled_task, service, startup_folder, launch_agent, cron, wmi_subscription, other), `target`, `name?`, `signed?` |
| `network` | `process_image`, `remote_ip`, `remote_port`, `protocol?`, `direction?` |

```
curl -X POST "$API/api/endpoint-telemetry" -H "X-Endpoint-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"observations":[{"type":"process","occurred_at":"<ISO-8601 time>","image":"<path>","command_line":"<command>"}]}'
```

## What is detected
| code | severity | signal |
|---|---|---|
| `SHADOW_COPY_OR_BACKUP_TAMPERING` | critical | vssadmin/wmic/wbadmin/bcdedit recovery-inhibiting commands |
| `RANSOMWARE_ENCRYPTION_BEHAVIOR` | high / critical | ≥ `RANSOMWARE_MIN_FILE_CHANGES` changes **plus** high-entropy writes and/or mass rename to new extensions (both = critical). Bulk changes alone never fire. |
| `RANSOM_NOTE_FILENAME` / `_SPREAD` | medium / high | ransom-note-style filenames (spread = ≥3 directories) |
| `OFFICE_SPAWNED_INTERPRETER` | high | Office app launching cmd/PowerShell/script hosts |
| `DOWNLOAD_AND_EXECUTE`, `LOLBIN_DOWNLOAD`, `ENCODED_POWERSHELL` | high / medium | command-line patterns |
| `SUSPICIOUS_PERSISTENCE` | high / medium | encoded/download-exec target, unsigned program in a user-writable path, WMI subscription |
| `INTERPRETER_UNUSUAL_OUTBOUND` | medium | script host / Office app → public IP on a non-web port |
| `KNOWN_MALICIOUS_FILE_HASH` | critical | optional: threat-intel verdict on SHA-256 (`ENDPOINT_HASH_ENRICHMENT=true`, max 5 lookups/batch) |

These are heuristics: they can miss attacks and can fire on legitimate administration (each
finding's description says so). Add a detector by writing a function
`(list[Observation]) -> list[Finding]` and appending it to `DETECTORS` in `engine.py`.
Repeated identical findings from one endpoint within 10 minutes are collapsed.
