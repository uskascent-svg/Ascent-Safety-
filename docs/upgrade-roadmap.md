# Platform upgrade roadmap

This roadmap reviews the three supplied product prompts against the existing Ascent Safety implementation. The intent is to extend the current FastAPI, PostgreSQL, Next.js, Three.js, and MapLibre application in small, reviewable steps.

## What already exists

- FastAPI with PostgreSQL, Alembic migrations, access/refresh authentication, database-backed role checks, rate limits, audit logging, security headers, and readiness checks.
- Database-backed security events with severity/type/time filters, alerts, dashboard aggregates, and authenticated server-sent events.
- A Three.js/WebGL Earth and MapLibre map that both read the same event-location API; the 2D map is a graceful fallback when WebGL is unavailable.
- Phishing analysis, endpoint/network telemetry, case studies from resolved events, responsive dark theme, reduced-motion handling, and empty/error/loading states.

## Gaps mapped from the prompts

| Area | Existing state | Upgrade direction |
| --- | --- | --- |
| Threat visualization | Shared backend event dataset, 3D Earth and MapLibre map exist. Selection focus, event-backed geographic heatmap, and reviewed report-originated intelligence are implemented. | Continue to use the common event API; never invent coordinates or event relationships. |
| User reporting | Added a distinct authenticated report model with validation, user-owned tracking, and lifecycle. Telemetry ingestion remains a separate machine-authenticated pipeline. | Keep user-provided evidence private; expose only reviewed, sanitized records as intelligence. Do not accept arbitrary file uploads until private object storage and malware scanning are configured. |
| Incident operations | Added an administrator queue with search and status filters, assignment to active analysts/admins, internal notes, status transitions including reopen/false-positive, and audit records. | Add an incident timeline and controlled promotion to the global event stream only after verified coarse location and analyst review. Keep internal notes invisible to reporters. |
| Legal/compliance | No reference center exists. | Added an India-first searchable reference center, sourced to official government/regulator pages, with international references, clear applicability caveats, and legal disclaimer. Content lives in a version-controlled data layer rather than UI component markup. |
| DPDP currency | Supplied prompt mentions only the 2023 Act. | Include the final DPDP Rules, 2025 and phased commencement information in the catalog; avoid implying all duties are already effective for every entity. Re-verify official sources before relying on this content. |
| Advanced intelligence | No campaign correlation, organization/personal score, or persistent notification center is defined in the current data model. | Defer until trustworthy source fields, relationship rules, and user-specific event data are available; do not simulate these features. |
| Guidance assistant | Curated workflow guidance only. | Added authenticated, role-aware Gemini integration with server-side secret handling and rules fallback. Gemini stays inactive until a deployment secret is configured. |
| Phishing training | Existing single-message analysis. | Added database-backed fictional scenarios, scored attempts, progress, admin scenario editing, safe click-consequence walkthrough, and response practice. Department leaderboard awaits organization/team data. |
| Security-event reporting | Private reports and analyst-reviewed promotion. | Added anonymous one-time report tracking and separately consented, privacy-safe map events through the existing event store/SSE pipeline. Evidence upload is still disabled pending private scanning storage. |
| Cyber alert declarations | Telemetry-generated triage alerts only. | Added a distinct admin-approved draft/publish/expire/revoke lifecycle with immutable history, role checks, notifications, and linked map events. |
| Endpoint defense | Endpoint registration and telemetry ingestion. | `/endpoints` now presents live source health, actual malware/ransomware events, critical alerts, the shared event map, and the existing registration controls. It remains empty when no agent data is connected. |
| Admin legal editor | No general content-management or audit-backed publication workflow exists. | Current legal dataset is maintained in source control. Database-backed editing should follow a dedicated authorized API, schema, migration, and audit trail rather than a frontend-only editor. |

## Implemented in this pass

1. Add a Legal & Compliance route and persistent navigation entry.
2. Store reference metadata and summaries in a structured TypeScript content layer, including source, authority, jurisdiction, category, dates, applicability note, and verification date.
3. Add search and jurisdiction/category filters, source links, framework-vs-law labels, and a prominent legal-information disclaimer.
4. Add authenticated user reports, reporter-only status tracking, administrator queue operations, internal notes, audit records, and migration 0007.
5. Keep user reports separate from the existing security-event dataset unless an analyst explicitly validates and promotes sanitized intelligence.

## Follow-on implementation sequence

1. Configure private object storage, content-type/size validation, malware scanning, retention controls, and private attachment retrieval before enabling uploads.
2. **Completed:** administrator-only report promotion writes through the common event-ingestion pipeline after explicit content and location review. Analysts can request city-level candidate matches for the submitted place name, select a result, and confirm its coordinates rounded to two decimals. A persistent cache avoids repeat provider calls; the report remains private until publication. The promoted event records the report/event link, audit entry, alerts, and live updates.
3. **Completed:** synchronize map/globe selection focus; add a MapLibre heatmap based on backend event coordinates; expose the shared time-range filter directly on the visualization panel.
4. **Completed:** append-only report timelines preserve public lifecycle changes separately from internal assignments and notes.
5. **Completed:** high-severity alert notifications are persisted per active analyst/admin, isolated by recipient, and have individual and bulk read state.
6. Add analyst-attributed campaign relationships only with explicit source event links and review provenance; do not infer campaigns from coincidental text or locations.
7. Add a legal-content admin workflow only with database-backed content, role authorization, version history, and audit coverage.

## Production boundary

Legal summaries are an awareness aid, not legal advice. Application of a law depends on facts, jurisdiction, sector, and commencement provisions. Official sources should be rechecked routinely. No provider health, threat count, geolocation, campaign, or analytics value should be presented as live unless returned by a real configured backend source.

## Configuration and remaining prerequisites

- Set `GOOGLE_API_KEY` in the backend deployment secret manager to activate Google ADK. Never commit it or put it in the frontend/browser. The old `GEMINI_API_KEY` setting is accepted temporarily for local migration. With no key, the assistant reports `rules` as its active provider.
- Configure private object storage, upload size/type rules, malware scanning, retention, and authorized retrieval before enabling evidence attachments.
- The current user schema has no department/team or organization entity. A private department leaderboard needs that data model and tenant boundaries first; no synthetic ranking is shown.
- Map updates use the existing single-process SSE broker. Scale-out deployment requires shared pub/sub (for example Redis) before running multiple API replicas.
