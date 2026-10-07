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
| Admin legal editor | No general content-management or audit-backed publication workflow exists. | Current legal dataset is maintained in source control. Database-backed editing should follow a dedicated authorized API, schema, migration, and audit trail rather than a frontend-only editor. |

## Implemented in this pass

1. Add a Legal & Compliance route and persistent navigation entry.
2. Store reference metadata and summaries in a structured TypeScript content layer, including source, authority, jurisdiction, category, dates, applicability note, and verification date.
3. Add search and jurisdiction/category filters, source links, framework-vs-law labels, and a prominent legal-information disclaimer.
4. Add authenticated user reports, reporter-only status tracking, administrator queue operations, internal notes, audit records, and migration 0007.
5. Keep user reports separate from the existing security-event dataset unless an analyst explicitly validates and promotes sanitized intelligence.

## Follow-on implementation sequence

1. Configure private object storage, content-type/size validation, malware scanning, retention controls, and private attachment retrieval before enabling uploads.
2. **Completed:** administrator-only report promotion writes through the common event-ingestion pipeline after explicit content and location review. It requires analyst-entered event text and independently verified coordinates rounded to two decimals; records a report/event link, audit entry, alerts, and live updates. Reporter-entered location text and notes are never copied or geocoded.
3. **Completed:** synchronize map/globe selection focus; add a MapLibre heatmap based on backend event coordinates; expose the shared time-range filter directly on the visualization panel.
4. **Completed:** append-only report timelines preserve public lifecycle changes separately from internal assignments and notes.
5. **Completed:** high-severity alert notifications are persisted per active analyst/admin, isolated by recipient, and have individual and bulk read state.
6. Add analyst-attributed campaign relationships only with explicit source event links and review provenance; do not infer campaigns from coincidental text or locations.
7. Add a legal-content admin workflow only with database-backed content, role authorization, version history, and audit coverage.

## Production boundary

Legal summaries are an awareness aid, not legal advice. Application of a law depends on facts, jurisdiction, sector, and commencement provisions. Official sources should be rechecked routinely. No provider health, threat count, geolocation, campaign, or analytics value should be presented as live unless returned by a real configured backend source.
