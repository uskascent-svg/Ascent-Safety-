# Implementation plan and decisions

This file records the reasoning behind the deployment and integration work so the project can be
continued without needing the original chat.

## Product scope

- Ascent Safety is a cybersecurity monitoring application. The existing product includes accounts
  and roles, security events, alert triage, phishing analysis, threat intelligence, and endpoint and
  network telemetry ingestion.
- The supplied UI brief mentions railway cameras and trains, but those are not part of this
  project's domain or backend. They will not be represented with invented data or pretend feeds.
- The UI must present only API/database-backed values. Empty, loading, error, offline, and
  unauthorized states are preferable to fabricated activity.

## Architecture choices

- PostgreSQL is the deployed source of truth. Schema changes go through Alembic; application startup
  must not silently create or alter tables.
- FastAPI remains the single API boundary. The Next.js frontend calls the API through a same-origin
  `/api` rewrite in deployments, so refresh cookies work without browser CORS assumptions. The
  internal API origin is deployment configuration, not UI data.
- Existing REST endpoints remain the contract for users, events, alerts, sensors, endpoints,
  phishing analysis, and threat intelligence. Server-sent events remain the live-update mechanism.
- API keys for telemetry sources are returned once and stored as hashes. JWT/cookie secrets,
  provider credentials, and database passwords belong in an untracked `.env` or deployment secret
  store, never source code.
- The optional guidance provider is a single Google ADK LlmAgent restricted to defensive
  cybersecurity. It has no tools or application-data access, retains no server-side chat session,
  processes a bounded recent transcript, uses a short output cap and one request per turn, and falls
  back to deterministic rules. Its API key is `GOOGLE_API_KEY` in the backend secret store only.
- Render uses a private managed PostgreSQL database and one API instance so the existing process-local
  SSE broker and rate limiter keep their intended semantics. The current Render Blueprint targets the
  free plans to avoid a payment method, which is preview-only (database expiry after 30 days, no
  backups, and the web service spins down). Migrations run at single-instance API startup because
  Render's pre-deploy command is paid-only. The Blueprint prompts for the provider key; the Vercel
  frontend forwards same-origin `/api` routes through a server-only `API_INTERNAL_URL` setting.
- Docker Compose is the reproducible single-host deployment path: database health check, one-shot
  migration, API readiness, then frontend. Production TLS and public ingress are expected to be
  provided by a reverse proxy or hosting platform.
- Rate limits use per-credential buckets for telemetry and authenticated requests, and a forwarded
  client address for anonymous requests behind ingress. Production ingress must overwrite
  `X-Forwarded-For` with the actual peer address.

## Delivery sequence

1. Close deployment wiring: web image, same-origin API proxy, DB readiness, migration ordering,
   security headers, CORS methods/headers, and environment validation.
2. Add operator documentation for local startup, production configuration, migrations, backup and
   restore, and the limits of telemetry-based detection.
3. Install dependencies, run frontend and backend tests, type/lint/build checks, and fix failures
   attributable to the implementation.
4. Review the screens against the product brief: remove dead links and fake data, and ensure
   operational states come from API state.
5. Lock Python runtime and development dependencies, then verify a clean npm install and repeat
   the complete available test/build suite.

## Deployment boundaries

- A clean build and passing tests do not prove a production deployment is live. Production still
  needs a managed host, TLS/domain, secure secret injection, backup retention, provider keys if
  desired, and real sensors/EDR sources.
- Detection findings are heuristics over submitted telemetry. Ascent Safety does not capture packets,
  install endpoint agents, block attacks, or guarantee detection.
- The live event broker and limiter are process-local. Run a single API worker/container until the
  broker is moved to shared pub/sub and the limiter to shared storage; otherwise multi-replica SSE and
  rate limits are not consistent.
- Docker Compose runs the full application as a single-host deployment. CI builds both images; local
  startup was also verified with Docker Desktop after locating its per-user installation. The
  browser preview was not available because the desktop browser-access policy denied the local
  preview request; HTTP route and same-origin API proxy checks were used instead.
- Threat-intelligence lookups are optional and subject to provider credentials, network availability,
  provider quotas, and privacy review.
- Report place names are private until an administrator explicitly requests a lookup during review.
  The lookup sends only the submitted city/region/country string to the configurable Nominatim
  provider, returns settlement-level candidates rounded to two decimals, and stores only a hash of
  the search string with cached candidate results. The analyst must select a match and confirm the
  approximate point before the report is promoted into the shared event feed and map. Do not enter
  street addresses or personal data. Public Nominatim use is rate-limited to one request per second
  within the single API process, has a valid User-Agent, and shows OpenStreetMap attribution; use a
  self-hosted/configured provider if scale or provider policy requires it.

## Change log

- 2026-10-07: Added an India-first Legal & Compliance center with structured source-controlled content
  for the IT Act, CERT-In Directions, DPDP Act and final 2025 Rules, GDPR, NIST CSF 2.0, ISO/IEC 27001,
  PCI DSS, HIPAA, and SOC 2. Sources were checked against official authorities on 7 October 2026; the
  page distinguishes laws, guidance, standards, frameworks, and assurance reporting and includes a
  legal disclaimer. Added private user security reports, reporter-only tracking, analyst/admin search,
  assignment, validated status transitions, internal notes, audit logging, and migration 0007. Added
  administrator-only promotion into the common event pipeline with independent content/location review,
  analyst-authored sanitized text, two-decimal coarse coordinates, duplicate protection, event linkage,
  alerts, and migration 0008. Reports do not enter the globe feed from free-text locations; uploads
  remain disabled until safe object storage and malware scanning are configured. Synchronized globe/map
  event focus, added an event-backed heatmap and shared time filters, plus durable recipient-scoped
  alert notifications and public/internal report timelines in migration 0009. See
  `docs/upgrade-roadmap.md` for the inspected gap map
  and follow-on sequence.

- 2026-10-07: Reworked the shared visual system into a responsive dark command workspace with desktop navigation, full-height real Earth hero, API-backed overview panels, event search and alert count. Added resolved-event case studies and a curated, explicitly non-AI guidance assistant. Security metrics and statuses without existing backend contracts remain marked unconfigured rather than fabricated. Frontend verification: 33 tests, typecheck, lint, production build, and zero production dependency vulnerabilities. Deployed with `docker compose up --build -d`; all main pages and API readiness return HTTP 200. The explicitly requested existing account has `ADMINISTRATOR`; the supplied password returned 401 and was not overwritten.
- 2026-10-07: Extended the guidance assistant with a server-side Gemini REST integration and a role-aware defensive system prompt. The rules-based guidance remains available when the provider key is unset or unavailable; no key is committed or displayed to the client. The local secret is not configured, so this environment currently uses the rules provider.
- 2026-10-07: Added a database-backed phishing-training library and attempt/progress records in migration 0011, seeded with fictional scenarios using reserved `.example` domains. The lab never opens training URLs or collects credentials, returns indicators only after scoring, and stores learner selections and scores rather than submitted message contents. Department ranking is not enabled because the account model has no department/team field. File upload remains unavailable until private object storage and malware scanning are configured.
- 2026-10-07: Added anonymous report submission with one-time tracking tokens (only SHA-256 hashes are stored), and an explicit consent path for a privacy-safe event summary to enter the existing map/event pipeline. A location is attached only after a unique geocoding result; otherwise the shared event has no coordinates. Migration 0012 adds the nullable reporter and alert declaration/audit tables.
- 2026-10-07: Added Cyber Alert Declarations with draft editing, administrator approval, Critical publication restriction, expiry/revocation, append-only lifecycle history, notifications, and persisted map events using the existing SSE path. The `/endpoints` page now combines actual registered endpoint freshness, malware/ransomware events, alerts, and the existing admin source-registration flow. No endpoint data or incidents are seeded as live activity.
- 2026-10-07: Replaced direct Gemini REST calls with a single Google ADK defensive cybersecurity agent. It makes at most one bounded Flash-Lite model request per chat turn, has no tools or access to app records, keeps only a transient in-memory session, and returns the existing rules guidance if unconfigured or unavailable. Added Render Blueprint wiring for a private PostgreSQL database, migration-before-deploy, generated JWT secret, secure cookies, health checks, and a prompt for the Google key as a secret. Public deployment still requires creating the Render resources and connecting the resulting service URL to Vercel.
- 2026-10-07: Increased sidebar navigation typography and retained the existing responsive design system. Verification: frontend typecheck, lint, production build, and 36 tests passed; 202 backend tests and Ruff passed. Migrations reached 0012 on the local PostgreSQL database; `/`, `/guidance`, `/phishing`, `/endpoints`, `/reports`, `/security-panel`, and `/api/health/ready` returned HTTP 200 and all Docker services were healthy. A final notification-recipient adjustment subsequently passed 30 focused backend tests; the containers were rebuilt again afterward.
- 2026-10-07: Completed the planned interactive Earth feature in `docs/implementation-plan-premium-globe.md`. Kept the existing Next.js/FastAPI/PostgreSQL system and RBAC; added explicit event origin/destination route coordinates, Alembic migration 0006, a Three.js WebGL Earth with NASA day/night material textures, backend-derived markers/routes, a protected live view and non-sensitive empty landing preview, plus the existing 2D map fallback. Tests: 30 frontend and 180 backend pass; frontend typecheck, ESLint, production build, Ruff, and Compose config pass. Deployed through the standard multi-stage Dockerfile and full Compose startup. Home, login, phishing, Security Panel, Earth textures, and proxied readiness return HTTP 200; all services are healthy. See the detailed scope and limitations in the premium-globe plan.

- 2026-10-07: Began deployment-readiness work from the phase 7 archive. Confirmed that the repository
  is cybersecurity-focused, uses PostgreSQL/SQLAlchemy/Alembic, FastAPI, and Next.js, and already has
  unit/API tests. Initial test attempts could not start because frontend and Python test dependencies
  were not installed.
- 2026-10-07: Added a full Compose web/API/database/migration sequence, same-origin API rewrite,
  readiness and CORS handling, local secret generation, first-admin CLI, deployment/operations
  guide, PostgreSQL migration smoke check in CI, and tests for health, CORS, and rate-limit identity.
- 2026-10-07: Upgraded vulnerable frontend runtime/build dependencies. The npm audit is clean after
  removing the affected legacy lint package. Simplified global UI surfaces and replaced the generic
  landing hero with an operational overview.
- 2026-10-07: Added Python runtime and development lock files; `npm ci` completed with zero audited
  vulnerabilities. Final checks: frontend typecheck/lint, 19 frontend tests, production build, 175
  backend tests, Ruff, Compose configuration validation, and a same-origin API rewrite smoke check.
- 2026-10-07: Started Docker Desktop and launched the Compose application. PostgreSQL, API, and web
  containers are healthy; migrations completed; `/`, `/login`, and the frontend-proxied API readiness
  endpoint return HTTP 200. The application is running locally at http://localhost:3000. Visual
  browser review remains unverified because desktop browser access was denied by policy.
- 2026-10-07: Fixed post-login navigation so standard users land on the home page and analyst/admin
  users land on the analyst-only Security Panel. The prior redirect sent every role to the panel,
  which made a successful standard-user login appear broken. Invalid-credential feedback now points
  new users to registration. Added redirect/error tests; frontend suite now passes 22 tests and the
  production web container was rebuilt and verified healthy. Existing API logs showed a successful
  register/login/me sequence followed by 401s for later attempts, which indicate credentials that
  do not match; the app does not expose whether an email exists.
- 2026-10-07: Added administrator-triggered city-name resolution for report locations. Analysts can
  select a matching settlement, which fills the event's country, region, and coarse coordinates;
  reviewed publication then makes that event appear in the existing threat map. Lookups use a
  persistent 30-day cache and never publish a report automatically. See `docs/upgrade-roadmap.md`.
