# Premium cyber-intelligence experience: inspection and implementation plan

Date: 2026-10-07

## Request and reference boundary

The user's direct request is to inspect the existing repository before editing, preserve working
functionality, document an architecture-based plan, then implement it incrementally. The direct
globe requirement is an interactive Three.js/WebGL Earth with geographic threat markers, atmosphere,
night-city illumination, and animated origin-to-destination arcs whose threat objects come from the
backend.

The attached text files and screenshots are product/design references. They describe a premium dark
cyber-intelligence look and a much wider set of possible modules (case studies, incident response,
training, community, toolkit, policy, and additional admin areas), and include alternative stack
recommendations. They do not override the direct request or authorize replacing the architecture.
This plan therefore keeps the current Next.js/FastAPI/PostgreSQL architecture and does not invent
records or implement unsupported modules as decorative mock screens. Those modules can be planned
separately after their data sources, workflows, and authorization requirements are defined.

## Repository inspection

- Frontend: Next.js App Router, React 19, TypeScript, Tailwind CSS 4, TanStack Query, and Vitest.
  Existing pages cover home, sign-in, phishing analysis, the security panel, and endpoint/sensor
  administration. Existing shared components provide navigation, loading/error/empty states, event
  feed, alert triage, summary metrics, and event details.
- Data access: `frontend/lib/api.ts`, React Query hooks in `frontend/hooks/useSecurityData.ts`, and
  authenticated SSE invalidation in `frontend/hooks/useLiveUpdates.ts`.
- Current map: `ThreatMap.tsx` renders MapLibre 2D points from `GET /api/security-events/locations`.
  The home and security panel use it through `ThreatMapPanel`; access is gated to analysts and
  administrators. The existing map is functional and will remain available as a non-WebGL fallback
  or compact alternate view while the 3D globe is introduced.
- Backend: FastAPI routers in `backend/app/api`, Pydantic contracts in `backend/app/schemas`,
  SQLAlchemy models in `backend/app/models`, shared event persistence/alert/audit/SSE publication in
  `backend/app/services/event_ingest.py`, and PostgreSQL migrations in Alembic.
- Current geography: security events have one optional `latitude`/`longitude` pair plus
  country/region. Those coordinates describe the event/site location; they do not imply an attack
  origin or destination. Endpoint and sensor site coordinates can be inherited by generated events.
  The API accepts caller-supplied event coordinates; the repository does not currently geolocate
  source and destination IPs.
- Authorization: event, map, summary, and stream APIs require analyst/admin roles on the server.
  The frontend `AccessGate` mirrors this for presentation. The running local database currently has
  zero security events and zero analyst/admin accounts, so the correct initial map state is empty;
  an administrator must promote an intended account before it can access the protected panel.
- Deployment: Docker Compose runs PostgreSQL, a migration job, FastAPI, and the Next standalone
  frontend. CI covers frontend tests/typecheck/lint/build/audit, backend tests and PostgreSQL
  migration/readiness, and container builds. There is no existing public asset set beyond the empty
  frontend public directory.
- Existing application features and their APIs are to be preserved: authentication/RBAC, phishing
  analysis, threat-intelligence lookups, event and alert triage, endpoint/network ingestion,
  telemetry administration, and SSE updates.

## Architecture decisions

1. Keep Next.js and dynamically load a client-only Three.js globe. Use Three.js directly for the
   scene lifecycle and controls; do not migrate to Vite, Supabase, or a second backend. Keep the
   current TanStack Query API hooks as the only threat-data path.
2. Keep event and location reads behind backend analyst/admin authorization. Do not make global
   threat coordinates public merely to simplify the landing page.
3. Preserve the existing `latitude`/`longitude` contract as a reported point. Add optional,
   explicitly named origin and destination coordinate pairs for route visualization. Validate pair
   completeness and geographic ranges in Pydantic and PostgreSQL. Existing producers remain
   compatible and produce markers only; routes appear only when an authenticated telemetry source
   provides both ends.
4. Extend the existing location response rather than introducing a parallel source of truth. The
   existing SSE event invalidation will refresh marker and route data after a committed event.
5. Use real globe geometry and locally bundled, license-reviewed Earth surface/night-light textures
   as material maps. Textures are visual assets mapped onto a Three.js sphere, not a flat Earth
   substitute. Use a lighting shader/material for atmosphere, geographic coordinate conversion for
   points, and great-circle curves for arcs. Keep controls bounded, respect reduced-motion settings,
   cap renderer pixel ratio, and dispose all GPU resources on teardown.
6. If WebGL or texture loading fails, show an actionable fallback to the existing MapLibre map and
   accessible event list. Empty data stays empty; no demo threats, fake counts, random routes, or
   fabricated destination coordinates.

## Incremental delivery plan

### Phase 1 — data contract and compatibility

- Add optional origin/destination coordinates to the event SQLAlchemy model, create an Alembic
  migration, validate complete coordinate pairs/ranges in the request contract, and expose the
  fields in event/location responses.
- Preserve the existing event coordinates and all old ingestion payloads.
- Add API/schema/migration tests for absent coordinates, valid routes, invalid ranges, and incomplete
  pairs. Confirm events without route data still appear as location markers only.

### Phase 2 — globe foundation

- Add the Three.js dependency and license-reviewed local Earth day/night textures with attribution.
- Build a reusable client-only globe component with resource cleanup, bounded drag/zoom controls,
  keyboard-reachable surrounding controls, WebGL/asset failure states, reduced-motion support, and
  correct responsive sizing.
- Unit-test coordinate conversion and great-circle path construction; add component tests for empty
  and populated backend props without hardcoding application threat data.

### Phase 3 — backend-connected threat visualization

- Extend the existing event location query to provide point and optional route data from PostgreSQL.
- Replace the map panel's primary visualization with the globe while preserving the textual event
  feed and MapLibre fallback. Reuse React Query, filters, auth gate, event selection, and SSE
  invalidation.
- Render event markers and animated arcs only from returned event rows. Route selection links back to
  the existing event detail view.

### Phase 4 — premium product composition and responsive QA

- Rework the existing home composition to reflect the references: dark editorial hierarchy,
  restrained typography, carefully placed panels, functional existing calls to action, and a
  cinematic globe that remains a real, data-bound product visualization.
- Keep summary counts, alerts, and activity driven by current backend queries and show honest empty,
  loading, error, and authorization states. Do not ship unsupported reference modules as mock data.
- Verify desktop/mobile sizing, keyboard access, reduced motion, WebGL unavailable behavior, empty
  database behavior, and the full existing app flows.

## Acceptance criteria

- An actual WebGL-rendered Three.js sphere is present; no globe image, CSS circle, GIF, or scripted
  fake orbit is used as the Earth visualization.
- Any marker corresponds to a backend event with valid geographic coordinates. Any animated arc
  corresponds to an event with explicit backend origin and destination coordinates.
- Old producers and existing APIs remain compatible; database changes are Alembic migrations.
- Existing auth, authorization, phishing, intelligence, event/alert, endpoint/sensor, and SSE flows
  keep working.
- Loading, empty, error, unauthorized, unsupported-WebGL, and reduced-motion states are usable and
  accessible; no synthetic activity is introduced.
- Frontend unit/type/lint/build/audit and backend unit/migration checks pass, and Docker Compose
  starts and health-checks the complete local stack.

## Implementation status

- Inspection completed before edits; architecture and phased plan recorded before implementation.
- Phase 1 complete: optional origin/destination coordinate pairs are validated by Pydantic and
  PostgreSQL, persisted through additive migration `0006`, and included in the protected location
  API. Existing reported event coordinates retain their original meaning. Empty route data yields
  no route objects. PostgreSQL migration `0006` was applied to the local Compose database.
- Phase 2 complete: Three.js client-only Earth component uses locally bundled NASA Blue Marble day
  and Black Marble night-light textures, geographic coordinate projection, atmospheric rim shader,
  bounded OrbitControls, reduced-motion support, responsive sizing, cleanup, and WebGL/texture
  fallback handling. Geometry and data-projection unit tests cover coordinate bounds, great-circle
  paths (including antipodal points), empty results, point events, and explicit/incomplete routes.
- Phase 3 complete: protected live globe uses the existing authorized event-location API, query
  filters and selection; markers and arcs are projected only from event payload coordinates. The
  existing MapLibre mode and event feed remain available. Rendering is capped at 250 recent returned
  rows per globe frame. Visitors and users without analyst/admin access see an actual empty Earth
  preview and do not issue the protected location query. Server-side role checks are unchanged.
- Phase 4 implemented: home hero and globe composition use the supplied dark/editorial design
  direction while preserving working phishing and Security Panel calls to action. Empty, loading,
  error, authorization, reduced-motion, and WebGL fallback states remain explicit. No threat data,
  counts, routes, or modules were fabricated.
- Assets and reuse notes: see `frontend/public/textures/README.md` for NASA source and attribution.
- Verification: frontend tests (30), TypeScript, ESLint, production Next build, backend tests (180),
  Ruff, and Docker Compose configuration validation pass. The source database currently contains no
  security events, so its live globe is correctly empty. The local browser's WebGL rendering was not
  visually inspected in this run.
- 2026-10-07 visual and panel continuation: replaced the previous generic header with a responsive
  dark command bar and desktop navigation rail; applied the black/navy/cyan/emerald design tokens
  across the shared UI; moved the real Three.js globe into a full-height cinematic landing hero; and
  added backend-driven threat severity/trend, timeline, regional activity, categories, system
  readiness, notification count, and event search. Added a resolved-event case archive and a
  curated product guidance assistant. Case studies never fabricate examples; guidance explicitly
  does not claim to be an AI service. A numeric security score, aggregate AI service state, and
  provider-wide threat-intel health are not present in backend contracts and are shown as
  unconfigured/on-demand instead of invented values.
- 2026-10-07 continuation verification: 33 frontend tests, TypeScript, ESLint, production build, and
  production dependency audit (zero vulnerabilities) pass. The standard Compose multi-stage web
  image was rebuilt and deployed. `/`, `/login`, `/security-panel`, `/case-studies`, `/guidance`,
  `/phishing`, the proxied readiness endpoint, and both Earth texture URLs return HTTP 200; all
  Compose services remain healthy and migration `0006` is current.
- Account request: the existing `uskascent@gmail.com` account was explicitly promoted to
  `ADMINISTRATOR` via the repository bootstrap command. The supplied password did not authenticate
  (API returned 401), so its existing password was left unchanged; registration enforces a
  12-character minimum and no password-reset endpoint exists. Use the account's current valid
  password or add a secure password-reset workflow before changing it.
- Deployment: the standard multi-stage Dockerfile build completed successfully (npm install found
  zero vulnerabilities; Next optimized build and TypeScript passed), then `docker compose up --build
  -d` deployed the full stack. Alembic is at `0006 (head)`. Home, login, phishing, Security Panel,
  frontend-proxied readiness, and both Earth texture routes return HTTP 200; web, API, and database
  containers are healthy. For hosts that already have a Next standalone build,
  `frontend/Dockerfile.prebuilt` remains an optional packaging path and patches the same-origin rewrite
  to the configured API service.
