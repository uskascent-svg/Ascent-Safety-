# Network telemetry (network security monitoring)

Ascent Safety **does not capture traffic and includes no network sensor.** It receives observations
from sensors *you* connect (Zeek/Suricata exports, a proxy, a client agent, …), evaluates them with
the detectors in `backend/app/detection/network/`, and records findings as security events and
alerts. Without a connected sensor, no network threats are detected — and none are claimed.

## Connect a sensor
1. An administrator registers it (`/sensors` page or `POST /api/sensors`). The API key
   (`ascent_sn_…`) is returned **once**; only its hash is stored. Rotate with `/rotate-key`.
2. The sensor sends batches (max 1000 observations) to `POST /api/network-telemetry` with the header
   `X-Sensor-Key: <key>`. Timestamps: ISO-8601 with timezone, not in the future. Unknown fields are rejected.
3. Events inherit the sensor's administrator-entered region/country/coordinates. Events at or above
   `ALERT_MIN_SEVERITY` create alerts. Repeats within 10 minutes are collapsed.

## Observation types (format reference)
| type | fields |
|---|---|
| `tls_connection` | `server_ip`, `server_port?`, `server_name?`, `tls_version` (SSLv2…TLSv1.3), `client_ip?`, `certificate?` {`issuer`, `not_before`, `not_after`, `subject_cn?`, `self_signed?`, `chain_valid?`, `hostname_match?`, `sha256?`} |
| `connection` | `src_ip`, `dst_ip`, `dst_port`, `protocol?`, `state` (established/rejected/no_response/reset), `service?`, `encrypted?`, `credentials_in_cleartext?`, `bytes_out?`, `bytes_in?` |
| `arp_change` | `ip`, `old_mac`, `new_mac`, `is_gateway?` |
| `wifi_network` | `ssid`, `bssid`, `security` (open/wep/wpa/wpa2/wpa3/unknown), `connected?`, `captive_portal?` |

Certificate validity (`chain_valid`, `hostname_match`) is judged **by the sensor** against its own
trust store; Ascent Safety records and reasons about those results.

## TLS baselines (how interception indicators work)
Per sensor and host, Ascent Safety remembers the issuer, highest TLS version and sighting count of
**validly-issued** certificates only (valid chain, matching hostname, not self-signed, not expired).
After `TLS_BASELINE_MIN_OBSERVATIONS` (default 3) sightings a host is "established". A batch is
always judged against the baseline from *before* it, and certificates that fail validation never
update the baseline — so an attacker's certificate cannot become the new normal. A valid certificate
from a different CA is flagged once and then adopted (legitimate CA changes happen).

## What is detected
| code | severity | signal |
|---|---|---|
| `POSSIBLE_TLS_INTERCEPTION` | high | established host: different issuer **and** invalid chain / hostname mismatch / self-signed |
| `TLS_ISSUER_CHANGED` | medium | established host: different issuer, otherwise valid |
| `TLS_CERT_INVALID_FOR_KNOWN_HOST` | medium | established host: validation problems, same issuer |
| `TLS_VERSION_DOWNGRADE` | medium | lower TLS version than previously seen |
| `TLS_CERT_VALIDATION_FAILURE`, `TLS_CERT_EXPIRED`, `TLS_DEPRECATED_VERSION` | low | no history needed |
| `UNENCRYPTED_CREDENTIALS` | high | sensor saw credentials in cleartext |
| `CLEARTEXT_PROTOCOL` | medium / low | telnet/ftp/rlogin/rsh/pop3/imap unencrypted (public / private destination) |
| `PORT_SCAN_ACTIVITY` | medium / high | ≥ `PORTSCAN_MIN_TARGETS` distinct targets, ≥70% not completing, within 10 minutes |
| `PERIODIC_BEACONING` | medium | ≥ `BEACON_MIN_CONNECTIONS` connections to one public host at near-constant ≥5s intervals (within one batch) |
| `POSSIBLE_ARP_SPOOFING_GATEWAY` | high | gateway MAC changed |
| `UNSAFE_WIFI_OPEN` / `_WEP` | medium | connected to an open or WEP network |
| `POSSIBLE_EVIL_TWIN` | high | same SSID offered both open and secured by different access points |
| `KNOWN_MALICIOUS_IP` | high | optional (`NETWORK_IP_ENRICHMENT=true`): threat-intel verdict on public destination IPs (max 5 per batch) |

**Limits you should know:** several indicators have benign causes (TLS-inspection proxies, certificate
rotation, monitoring agents, vulnerability scanners), which is why wording says "possible".
Beaconing and scan detection look only within one batch, so sensors should send reasonably sized
time windows. Add a detector by writing `(observations, context) -> findings` and appending it to
`DETECTORS` in `engine.py`.
