# Threat analyzer upgrade verification

## Incremental neural-model integration — 10 October 2026

- The uploaded ZIP was inspected in place; its separate API/token auth, plaintext JSONL feedback,
  unrestricted artifact handling, direct live-model replacement, and unused Torch dependency were
  not mounted. Its TF-IDF word/character features and scikit-learn MLP design were adapted to the
  existing PostgreSQL feedback, scoped roles, signed artifact registry, and independent-evaluation
  gates. No Torch dependency was added because the ZIP model uses `MLPClassifier` and does not use
  Torch for inference or training.
- Threat Analyzer now runs the existing phishing rules and general text rules, then adds the
  approved active classifier when a verified model is available. It persists detector mode, model
  family/version, uncalibrated model score, and combined score; model load/inference errors fall
  back to rules-only analysis. The same decision cutoff is used by independent evaluation and
  inference. URLs remain unvisited.
- New manual training jobs build TF-IDF + MLP candidates only from analyst-approved, user-opted-in,
  encrypted benign/malicious samples. Candidates must pass the separate labeled test-set gates,
  signed artifact checks, and authorized promotion before loading. Ten training examples per class
  are now required. Training is not periodic/automatic; no dataset was supplied in the ZIP, and no
  candidate was trained or promoted as part of this code integration.
- Alembic `0015` adds nullable model provenance to previous analysis rows while preserving them;
  existing rows default to the `rules_only` detector mode. Threat Network reports actual runtime
  classifier identity and only shows registry evaluation metrics when the serving version matches.

- The typed navigation configuration now contains the nine intended workspace routes and applies
  existing verified role capabilities to security operations and Threat Detection Network links.
- `/phishing` redirects to `/threat-analyzer`; phishing detection remains available because the
  Threat Analyzer backend continues to call the existing phishing parser and rules engine. The
  separate training/practice page is no longer linked from navigation, the footer, or the overview.
- The Threat Detection Network analysis window is selectable (7, 30, 90, or 365 days), with server
  validation and persisted analysis aggregation. It distinguishes independent evaluation from
  operational runtime status.

## Hybrid model verification update — 10 October 2026

### Passed

- Backend: `pytest -q` — 223 passed; `ruff check app tests alembic` passed. One Starlette
  deprecation warning remains for the upload-size status constant.
- Frontend: Vitest — 15 files / 39 tests passed; `npm run typecheck`, `npm run lint`, and
  `npm run build` passed.
- Local deployment: `docker compose up --build -d api web` completed; API, web, and database report
  healthy. Database is at Alembic `0015 (head)`. `/threat-analyzer` and `/api/health/ready` return
  200. Unauthenticated `/api/threat-analysis/admin/dashboard` returns 401.
- `git diff --check` passed.

### Not run or blocked

- No reviewed corpus, independent evaluation dataset, signing-key setup, or deployable trained model
  was included in the uploaded code package. Therefore the local live detector remains rules-only;
  MLP training and promotion are implemented in the existing controlled workflow but were not
  performed on production/user data. Periodic scheduling is not implemented.
- Production deployment, external service/load testing, a visual desktop/mobile browser audit, and
  production database backup restoration remain unverified. The local Compose migration was applied
  without resetting the database.
- The frontend is build-verified and component-test results above are genuine; the report does not
  claim a full browser-driven end-to-end analysis flow.

Verification recorded 10 October 2026 against the local ASCENT SAFETY checkout and Compose stack.
The upgrade preserves the existing FastAPI, Next.js, PostgreSQL, SQLAlchemy, Alembic, session/JWT
identity, and audit-log boundaries. Threat analysis is an added feature; the v3 package's separate
API-key and SQLite identity system was not mounted into the application.

## Results

### Passed

- Historical checkpoint (before the hybrid model update): backend `pytest -q` — 222 passed. `ruff check app tests alembic` passed. The targeted Ruff
  format check passed without changing unrelated files.
- Frontend: typecheck, lint, Vitest — 13 files / 36 tests passed — and production build passed.
- Historical checkpoint (before the hybrid model update): local Compose API, web, and PostgreSQL
  healthy; Alembic reported `0014 (head)`.
- HTTP GET smoke checks: `/`, `/login`, `/threat-analyzer`, `/threat-network`, and
  `/api/health/ready` each returned 200.
- Upgrade-package suite: Linux package environment — 83 passed. Windows package environment — 81
  passed; see the platform-specific failures below.
- `git diff --check` passed.

The new backend tests cover owner and role authorization, upload bounds and worker timeout behavior,
archive traversal rejection, retention cascade and audit events, consent-gated encrypted feedback,
restart failure handling, signed artifact verification, isolated holdout evaluation, model promotion,
and rollback. Existing frontend tests were retained; the new pages compile and build, but are not
yet covered by dedicated component tests.

### Failed

- The v3 package's Windows-only run has two platform-dependent failures: its worker memory-limit test
  expects POSIX `resource` limits, which Windows does not provide, and its backup mode-bit assertion
  expects POSIX `0600` semantics while Windows reports a different mode. These checks passed in the
  Linux package run; no test was changed or weakened.
- The main backend suite emitted one Starlette deprecation warning for
  `HTTP_413_REQUEST_ENTITY_TOO_LARGE`; it did not fail a test.
- Pre-integration baseline: backend 203 passed / 1 failed (TLS finding deduplication); frontend 36
  passed. This baseline failure predates the threat-analysis changes.

### Blocked or not executed

- Production-like security/load tests requiring external infrastructure (real object storage,
  malware scanning, distributed task queue, multiple API replicas, and deployment ingress controls)
  were not run. The repository has no such infrastructure configured in this environment.
- Visual browser review across desktop/mobile viewport sizes, keyboard-only operation, and assistive
  technology was not executed. The production build and route responses are verified, which does not
  establish those interaction/accessibility checks.
- Production backup restoration and production database migration rehearsal were not run. Local
  migration to `0014` completed; the production operator must take and test an off-host backup.
- No live threat sensors or model artifact/evaluation dataset are configured here. Consequently the
  dashboard does not claim sensor/worker freshness, and training/promotion remains unavailable until
  the required deployment configuration and independently labeled evaluation set are supplied.

## Architecture and security boundaries

- Migration `0013` adds threat analysis, feedback, training-job, and model-version tables;
  `0014` adds `THREAT_MONITOR`, `THREAT_DATA_REVIEWER`, and `THREAT_MODEL_OPERATOR` roles. The
  existing administrator role remains supported. Apply migrations with the existing migration
  service; do not reset the database.
- `backend/app/bootstrap_threat_role.py` grants or revokes scoped threat roles for an existing
  account. Assign the minimum role required. Reviewers can access consented review samples; model
  operators can run the controlled model lifecycle. Administrative API authorization is enforced
  server-side.
- User analysis and report history are owner-scoped. Analysis records store content hashes and
  bounded result data; raw input is not retained by default. Training sample access requires
  explicit consent and is audited. Retention deletion explicitly removes linked feedback first.
- File extraction runs in a separate worker process with bounded input handling and traversal
  defenses. Process isolation is not equivalent to a hardened OS/container sandbox. On restart,
  interrupted in-process jobs are marked failed; they are not durably queued or resumed.
- Model artifacts are integrity-checked and signed with the configured HMAC key. Evaluation uses a
  distinct configured holdout file; it is the operator's responsibility to ensure labels are
  verified, samples are independent, and no training-data leakage exists. The confidence value is
  an uncalibrated classifier score, not a calibrated probability.
- No metrics are fabricated to fill unavailable telemetry. Empty/unavailable operational sources
  are represented as unavailable rather than as live zero-activity measurements.

## Deployment and rollback

1. Back up PostgreSQL to encrypted off-host storage, and verify restoration on a separate database.
2. Configure secrets in the deployment secret manager: `THREAT_ANALYSIS_DATA_KEY` (Fernet key),
   `THREAT_ANALYSIS_MODEL_HMAC_KEY` (at least 32 bytes), and `THREAT_ANALYSIS_MODEL_DIR` on private
   persistent storage. Configure `THREAT_ANALYSIS_INDEPENDENT_TEST_SET` only with an independently
   labeled evaluation file. Keep training disabled until all required inputs and procedures are
   reviewed.
3. Apply `docker compose run --rm migrate alembic upgrade head` (or the deployment's existing
   migration step), and verify revision `0015` before routing traffic to the new API/web images.
4. Create scoped threat-role assignments for named operators using the CLI, then verify user and
   admin sessions through the ordinary authentication system. Monitor migration, API, worker, and
   database logs for failures.
5. For rollback, stop writers and restore the verified pre-upgrade database backup before reverting
   application images. Downgrading removes threat tables and post-upgrade analyses; do not run it
   against the only production copy.

See the database operations and test commands in [README.md](../README.md), and the implementation
history in [implementation-decisions.md](implementation-decisions.md).

## Changed source areas

- Backend: threat analysis API/schemas/models, extraction worker, trainer/artifact lifecycle,
  settings, existing phishing analyzer integration, role enum, migrations `0013`/`0014`, role CLI,
  dependency locks, and API/training tests.
- Frontend: existing header/auth capability mapping and the new `/threat-analyzer` and
  `/threat-network` pages/components, using the existing theme and API client.
- Operations/docs: `.env.example`, README deployment/migration guidance, and this verification
  report. Existing dirty deployment files (`README.md`, `backend/render-start.sh`,
  `frontend/Dockerfile`, `render.yaml`, and untracked `frontend/render-start.sh`) predated this
  integration and were preserved.
