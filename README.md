# Ascent Safety

Ascent Safety is a cybersecurity monitoring application for event triage, phishing analysis,
threat-intelligence lookups, and endpoint/network telemetry findings. It stores operational data in
PostgreSQL and exposes it through a FastAPI API consumed by a Next.js interface.

This application analyzes reports from integrations you connect. It does not capture network
traffic, install endpoint agents, block activity, or guarantee threat detection. Review
[endpoint telemetry](docs/endpoint-telemetry.md) and [network telemetry](docs/network-telemetry.md)
before connecting production sources.

## Run locally with Docker Compose

Requirements: Docker Engine with the Compose plugin. Compose is the supported full-stack path; it
starts PostgreSQL, applies Alembic migrations, waits for API readiness, and then starts the web app.

Windows PowerShell:

```powershell
.\scripts\init-env.ps1
docker compose up --build -d
docker compose ps
```

Linux/macOS:

```sh
./scripts/init-env.sh
docker compose up --build -d
docker compose ps
```

Open <http://localhost:3000>. The API health checks are available at
<http://localhost:8000/api/health> and <http://localhost:8000/api/health/ready>. Both host ports are
bound to loopback by default. The browser calls `/api` on the web origin; Next.js forwards those
requests to the API service, which also keeps refresh cookies same-origin.

The home page includes an interactive Three.js Earth. Security analysts and administrators see
markers and routes from authorized event records; route arcs require explicit origin and destination
coordinates from an ingestion source. Empty databases produce an empty globe. Visitors see a globe
preview without requesting protected event data. See
[the architecture and implementation plan](docs/implementation-plan-premium-globe.md) and the
[Earth texture attributions](frontend/public/textures/README.md).

The security overview's counts, categories, regions, event timeline, alerts, and system readiness
come from API responses. Case studies show only security events marked resolved; no sample incidents
are bundled. The guidance assistant is curated product help rather than an AI service. A numeric
security score and aggregate AI/provider health probes are not defined by the backend and are
presented as unavailable rather than simulated.

Signed-in users can submit private security reports and track their status. Administrators can search,
assign, triage, resolve, reopen, or mark reports as false positives; internal notes are restricted to
the operations queue and sensitive actions are audited. Reporters and analysts have a privacy-aware
report timeline. High-severity event alerts create persistent, individually readable notifications for
active analyst and administrator accounts. Report attachments are disabled
until private object storage and malware scanning are configured. User-entered locations remain private
report metadata and do not create map events; only separately ingested, coordinate-backed events appear
on the globe/map. The Legal & Compliance center contains version-controlled awareness references linked
to official sources; it is not legal advice or an automated compliance assessment.

Authenticated users can also open **Threat Analyzer** for static message, URL, and supported file
triage. Submitted URLs are inspected as strings and are never fetched. Analysis records contain a
content hash and derived findings, not uploaded bytes or extracted text. The parser runs in a separate
isolated Python process, with upload-size, parse-time, concurrency, and extracted-text limits; supported
formats and signatures are enforced by the parser. Analysis history, detail, deletion, and feedback
are owner-scoped by the API. Extraction failures and unsupported content remain unknown/partial rather
than being reported as safe. The administrator-only **Threat Detection Network** view aggregates
persisted analyses; the dashboard explicitly reports detection quality as unmeasured until an
independent labeled evaluation exists. It does not claim queue, sensor, or worker telemetry.

The API supports three narrowly scoped roles in addition to the existing administrator role:
`THREAT_MONITOR` can read threat-network metrics and model state, `THREAT_DATA_REVIEWER` can inspect
consented feedback samples and approve/reject labels, and `THREAT_MODEL_OPERATOR` can queue training
and reject/promote/rollback artifacts. Existing `ADMINISTRATOR` accounts retain access to all three
areas. All checks use role records from the database on each request. Grant these roles only through
the existing trusted database/deployment administration process; never trust client-supplied roles.

After applying migrations, operators can grant or revoke a scoped role from the deployment shell:

```sh
docker compose exec api python -m app.bootstrap_threat_role reviewer@example.com THREAT_DATA_REVIEWER
docker compose exec api python -m app.bootstrap_threat_role operator@example.com THREAT_MODEL_OPERATOR
docker compose exec api python -m app.bootstrap_threat_role reviewer@example.com THREAT_DATA_REVIEWER --revoke
```

The command accepts only active existing users and the three scoped threat roles. It does not grant
administrator access.

Authorized data reviewers can inspect a training sample only after explicit user opt-in. Samples are
encrypted at rest with `THREAT_ANALYSIS_DATA_KEY` and sample disclosure is audited. Only reviewed,
opted-in benign/malicious samples can be considered.
Training stays unavailable until operators configure that Fernet key, a secret
`THREAT_ANALYSIS_MODEL_HMAC_KEY` (at least 32 characters), `THREAT_ANALYSIS_MODEL_DIR` on persistent
storage, and `THREAT_ANALYSIS_INDEPENDENT_TEST_SET` as a separate UTF-8 JSONL dataset with `text` and
`label` (`benign` or `malicious`) fields. The evaluation set needs 20 unique examples and at least 10
per class; MLP training additionally requires ten approved samples per class. The fixed malicious
score cutoff is shared by training evaluation and live analysis. Thresholds are fixed in code,
artifacts are SHA-256/HMAC verified before load, and promotion re-evaluates against the configured
test set and applies a non-regression gate versus the current active model. Treat the test set as
controlled, access-restricted evaluation data: it must not overlap with user training samples. Back up
the model directory and its signing key together with database metadata. Rotating the HMAC key
requires a controlled re-signing/migration procedure; otherwise model artifacts fail closed to the
rules-based analyzer. The trainer currently runs as a bounded FastAPI background task, not a durable
external job queue; a process restart marks queued/running jobs failed and operators may submit a new
job. Do not enable this workflow until its deployment storage and evaluation data are reviewed.

The initialization script creates fresh local JWT and PostgreSQL secrets in `.env`, refuses to
overwrite an existing `.env`, and never prints the secret values. `.env` is ignored by Git. For a
production deployment, use your hosting provider's secret manager instead of copying these local
secrets.

### First administrator

1. Create an account at <http://localhost:3000/login>.
2. Promote that account from the deployment shell:

   ```sh
   docker compose exec api python -m app.bootstrap_admin admin@example.com
   ```

   Replace the address with the account you created. The command is idempotent and adds the
   administrator role; it does not print or change the user's password.
3. Sign in again so the new role is reflected in the access token.

Self-registration grants standard user access only. Administrators can register endpoints and
network sensors. Self-registration can never grant elevated access; promote additional trusted
accounts with the same deployment-shell command when appropriate.

## Configure a production deployment

1. Provide PostgreSQL, a persistent volume, and a TLS-terminating reverse proxy or hosting platform.
   Keep the database private. The Compose API and web ports bind to `127.0.0.1` so a host reverse
   proxy can reach them without exposing the containers directly.
2. Inject a unique `JWT_SECRET` of at least 32 characters, `POSTGRES_PASSWORD`, and the matching
   `DATABASE_URL`. Do not reuse local secrets. Set `COOKIE_SECURE=true` when traffic uses HTTPS.
3. Set `CORS_ORIGINS` to the exact trusted browser origins only if the frontend is served on a
   different origin. Same-origin `/api` proxying is the supported setup and usually needs no extra
   origins.
4. Use `API_INTERNAL_URL` for the web container's server-side rewrite target. It is embedded when
   the frontend image is built, so rebuild the web image when it changes.
5. Set `NEXT_PUBLIC_MAP_STYLE_URL` to a map style URL suitable for your deployment. The default
   uses Carto's public dark basemap; production teams should review its availability and terms or
   provide a self-hosted style.
6. Add threat-intelligence provider credentials only when enabled and approved. Endpoint hash and
   network IP enrichment are opt-in and send observed indicators to configured providers.
7. To load a locally trained phishing model, place the reviewed artifact in `ml/models`, set
   `ML_MODEL_PATH=/models/phishing_tfidf_lr.joblib`, and rebuild/restart the API. The Compose mount is
   read-only; never load an artifact from an untrusted source.
8. To enable threat-analysis feedback training, first configure the four `THREAT_ANALYSIS_*` values
   documented above, provision a persistent private artifact directory, and validate the independent
   JSONL set and recovery procedure. Keep the encryption/signing keys in the host secret manager. The
   optional sample-extraction worker uses installed document-parser packages; deployments must keep
   the worker and API dependency versions aligned. On Windows, process memory/CPU hard limits are not
   equivalent to POSIX `rlimit`; production uploads should run on the documented Linux container
   deployment and be subjected to archive/resource-exhaustion testing before enabling uploads.
9. Put TLS and public ingress in front of the web app. Forward `/api` to the web app so the Next.js
   rewrite can route API calls, SSE, and telemetry ingestion to FastAPI. The ingress proxy must
   replace `X-Forwarded-For` with the actual client address; never trust a client-supplied value.
   Configure proxy timeouts for long-lived SSE connections and rate limits for public ingestion
   routes.

### Render deployment (API, database, and optional web service)

The repository includes a Render Blueprint at [`render.yaml`](render.yaml). It uses Render's free
web and Postgres plans so it can deploy without a payment method. Deploy it from the
Render dashboard using **New → Blueprint**, select this repository, and enter the Google AI key into
the `GOOGLE_API_KEY` secret prompt (or leave blank to use the built-in rules fallback). The
key is a Render-only secret: do not add it to GitHub, Vercel, a browser environment variable, or a
local committed file.

The Blueprint provisions:
- **`ascent-safety-db`**: A managed PostgreSQL database running migrations automatically at API startup.
- **`ascent-safety-api`**: The FastAPI backend with health checks, generated JWT secret, and secure cookies.
- **`ascent-safety-web`**: The Next.js frontend with dynamic `/api` reverse proxying to the backend.

#### Promoting the first administrator on Render
Because Render free web services do not include an interactive web shell:
1. Register a new user at `https://<your-web-service>.onrender.com/login`.
2. In the Render Dashboard under **`ascent-safety-api` → Environment**, add `BOOTSTRAP_ADMIN_EMAIL` set to that user's email address and save.
3. On the next restart/deploy, the API will grant the `ADMINISTRATOR` role to that account.

If you choose to host the frontend on **Vercel** instead of Render:
Set the Vercel **Production** environment variable `API_INTERNAL_URL` to the Render service's HTTPS origin (e.g. `https://ascent-safety-api.onrender.com`) and redeploy. Verify `/api/health/ready`, sign in, and check `/api/guidance/status`; never paste the Google key into the frontend or browser.

The guidance agent uses Google ADK with one bounded Gemini Flash-Lite call per user request, no
tools, no browsing, no record access, a short conversation window, and a rules-based fallback when
the provider is not configured or unavailable. Store `GOOGLE_API_KEY` only in the backend host's
secret store. Rotate the key if it was ever committed or exposed in logs.

Useful configuration is documented in `.env.example` and validated by the backend settings model.
`INGEST_API_KEY` can remain unset to disable generic event ingestion. Telemetry endpoint/sensor API
keys are created inside the authenticated admin pages, shown once, and persisted only as hashes.

## Database operations

Migrations run as a one-shot Compose service before the API starts. Apply migrations explicitly with:

```sh
docker compose run --rm migrate alembic upgrade head
docker compose up -d api web
```

Take regular encrypted off-host backups. A local PostgreSQL custom-format backup can be created with:

```sh
docker compose exec -T db pg_dump -U ascent -d ascent -Fc > ascent-backup.dump
```

Restore only after stopping application writers and confirming the target database. Keep the backup
outside the repository and test restoration on a separate database before relying on it.

The threat-analysis integration adds Alembic revisions `0013`–`0015`. Revision `0013` creates
analysis, feedback, training-job, and model-version tables; `0014` adds the scoped monitoring,
reviewer, and model-operator roles; `0015` adds per-analysis detector provenance and model-family
metadata. The normal deployment startup migrates to `0015`; for a manual rollout, first take and
verify a PostgreSQL backup, then run
`docker compose run --rm migrate alembic upgrade head` (or `cd backend; alembic upgrade head` in the
configured virtual environment). Deploy the API and web images after the migration succeeds. To roll
back application code, stop API writers and restore the pre-upgrade database backup; the downgrade
removes the new `threat_analyses` table and therefore deletes analyses created after migration.
Downgrading `0014` removes scoped-role records and their assignments; downgrading `0015` removes
hybrid provenance fields. Never
run a destructive downgrade against the only production copy. Existing records and migration history
are otherwise unchanged.

## Development and tests

Frontend (Node.js and npm):

```sh
cd frontend
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

Backend (Python 3.12):

```sh
cd backend
python -m venv .venv
# Activate .venv, then:
python -m pip install -r requirements-dev.txt
python -m pytest
ruff check app tests alembic
```

The API tests use an isolated in-memory SQLite database and do not need production credentials.
The production application uses PostgreSQL and Alembic. A green unit/API suite does not replace a
staging deployment check using PostgreSQL, TLS, real integration sources, and provider credentials.
CI applies migrations and probes API readiness against PostgreSQL before running the isolated tests.

## Product limits

- There is no railway, camera, or train-monitoring subsystem in this project. Do not populate those
  screens with simulated data.
- Phishing, endpoint, network, and reputation checks are indicators for analyst review. They are not
  substitutes for a full EDR, SIEM, packet-capture sensor, incident response process, or security
  guarantee.
- No reviewed dataset or trained neural artifact is bundled. Threat Analyzer always applies its
  explainable phishing/text rules and uses the signed TF-IDF + MLP model only when an operator has
  trained, independently evaluated, and promoted one. User feedback is never training data until an
  authorized reviewer approves it and the user explicitly opted in. Until then analysis reports a
  rules-only fallback; see [ML setup](ml/README.md) and the threat-learning verification notes.
- Events, alerts, summaries, and map locations are API/database-backed. Empty states mean no matching
  data has been received.
- User reports do not accept uploaded files until secure private object storage and malware scanning
  are configured. A report's free-text location is never geocoded or published to the threat map.
- Legal summaries and framework notes are informational. They do not determine applicability or
  prove compliance; consult the current official materials and qualified counsel.

See [implementation decisions](docs/implementation-decisions.md) for the architecture rationale and
delivery notes.
