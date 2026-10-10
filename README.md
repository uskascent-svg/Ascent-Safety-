# Ascent Safety

**Evidence-Driven Cybersecurity Monitoring, Threat Analysis & Security Operations**

Ascent Safety is a modular cybersecurity monitoring platform designed to help security analysts investigate suspicious content, review security events, enrich threat indicators, and manage security reports through a centralized interface.

The platform combines a Next.js frontend, FastAPI backend, PostgreSQL database, event ingestion integrations, explainable threat analysis, and controlled machine-learning model governance.

**Live Application:** https://ascent-safety-web.onrender.com

**Repository:** https://github.com/uskascent-svg/Ascent-Safety-

---

## Table of Contents

- [Overview](#overview)
- [Core Capabilities](#core-capabilities)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [How It Works](#how-it-works)
- [Threat Analyzer](#threat-analyzer)
- [Threat Detection Network](#threat-detection-network)
- [Security Events and Telemetry](#security-events-and-telemetry)
- [Security Reports and Incident Management](#security-reports-and-incident-management)
- [Authentication and Access Control](#authentication-and-access-control)
- [Privacy and Security](#privacy-and-security)
- [Prerequisites](#prerequisites)
- [Run Locally with Docker Compose](#run-locally-with-docker-compose)
- [Local Development](#local-development)
- [Production Deployment](#production-deployment)
- [Database Operations](#database-operations)
- [Testing and Code Quality](#testing-and-code-quality)
- [Project Structure](#project-structure)
- [Current Limitations](#current-limitations)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Cybersecurity teams need reliable ways to examine suspicious messages, investigate alerts, review endpoint and network telemetry, and understand relationships between security events.

Ascent Safety brings these workflows together in a centralized application.

Its design emphasizes:

- Evidence-based security findings.
- Explainable threat analysis.
- Backend-connected dashboards.
- Authorized security-event visualization.
- Controlled threat-intelligence enrichment.
- Privacy-aware report handling.
- Auditable analyst workflows.
- Secure model evaluation and promotion.
- Clear separation between detection, investigation, and prevention.

Ascent Safety is designed to analyze data from supported integrations and user-submitted content. Its visibility depends on the sources that have actually been connected and configured.

**Core principle:** Every operational metric must come from real records or verified integration responses. Missing data must remain missing rather than being replaced with fabricated activity.

## Core Capabilities

### 1. Security Operations Dashboard

The security overview presents operational information retrieved from the backend.

Depending on available data, it can display:

- Security-event counts and categories.
- Alert and case status.
- Event timelines.
- Threat-region visualizations.
- Security report summaries.
- System and integration readiness.
- Detection and analysis activity.

Metrics are derived from persisted records and authorized API responses. Empty or unavailable datasets are represented honestly.

A detected threat is not automatically considered blocked, and an alert is not automatically considered a confirmed incident.

### 2. Threat Analyzer

Threat Analyzer provides static analysis of supported messages, URL strings, and files.

Its capabilities include:

- Explainable phishing and suspicious-text rules.
- Supported document and file parsing.
- Suspicious indicator extraction.
- Analysis history and detailed findings.
- Content-hash-based analysis records.
- Optional integration with an approved machine-learning model.
- Owner-scoped history, deletion, and feedback.
- Partial-result handling when extraction is incomplete.

Submitted URLs are analyzed as strings and are not fetched by default.

Unsupported formats and extraction failures are not automatically classified as safe.

### 3. Threat Detection Network

The Threat Detection Network provides administrator-authorized threat-analysis analytics and model-state information.

It can aggregate persisted analyses and associated detector metadata to help operators examine:

- Analysis volume and findings.
- Detector families and model versions.
- Reviewed feedback.
- Training and model lifecycle state.
- Available evaluation results.
- Related analysis records.

Detection-quality metrics remain unavailable until valid evaluation data and actual evaluation results exist.

The platform does not invent model accuracy, synthetic security events, or nonexistent sensor activity.

### 4. Threat Intelligence

Ascent Safety supports approved threat-intelligence enrichment integrations.

Depending on configuration, supported indicators may include:

- URLs and domains.
- IP addresses.
- File hashes.
- Other indicators supported by configured providers.

External lookups are subject to integration configuration, authorization, and provider availability.

Indicator enrichment supplies additional context for analyst review. It does not independently prove that an indicator is malicious.

### 5. Endpoint and Network Telemetry

The backend supports registered telemetry sources and security-event ingestion workflows.

Authorized administrators can configure supported endpoint and network integrations. Received events can then be stored, analyzed, and displayed through the application.

Telemetry coverage depends on the actual integration deployed and its configuration.

Ascent Safety does not automatically capture all network traffic or monitor endpoints merely because an account has been created.

### 6. Interactive Threat Globe

The home page includes an interactive Three.js Earth visualization.

Authorized analysts and administrators can view eligible markers and routes derived from ingested event records.

The visualization follows these rules:

- Event markers require authorized event data and valid coordinates.
- Route arcs require explicit origin and destination coordinates from an ingestion source.
- Empty datasets produce an empty globe.
- User-entered report locations remain private metadata.
- Free-text locations are not automatically converted into public map events.
- Visitors receive a public globe preview without protected event data.

### 7. Security Reports and Case Management

Authenticated users can submit private security reports and track their status.

Authorized administrators can manage reports through supported workflows, including:

- Searching and reviewing reports.
- Assigning reports.
- Updating triage status.
- Resolving and reopening reports.
- Marking false positives.
- Adding restricted internal notes.
- Reviewing privacy-aware report timelines.

Sensitive operations are audited, and high-severity event alerts can generate persistent notifications for active analyst and administrator accounts.

Report attachments remain disabled until secure private object storage and malware scanning are configured.

---

## Architecture

Ascent Safety uses a modular application architecture that separates presentation, API access, security logic, persistence, and background processing.

```text
                         SECURITY USERS
                               |
                               v
                    +----------------------+
                    |   Next.js Frontend   |
                    |----------------------|
                    | Security Dashboard   |
                    | Threat Analyzer      |
                    | Threat Network       |
                    | Reports and Alerts   |
                    | Interactive Earth    |
                    +----------+-----------+
                               |
                         Same-origin /api
                               |
                               v
                    +----------------------+
                    |    FastAPI Backend   |
                    |----------------------|
                    | Authentication       |
                    | Authorization        |
                    | API Validation       |
                    | Security Services    |
                    | Event Ingestion      |
                    | Audit and Reporting  |
                    +----------+-----------+
                               |
             +-----------------+-----------------+
             |                 |                 |
             v                 v                 v
    +----------------+ +----------------+ +----------------+
    | Threat Analysis| | Telemetry and   | | Alerts, Cases  |
    | Rules and ML   | | Intelligence    | | and Reports    |
    +----------------+ +----------------+ +----------------+
             |                 |                 |
             +-----------------+-----------------+
                               |
                               v
                    +----------------------+
                    |      PostgreSQL      |
                    |----------------------|
                    | Security Events      |
                    | Analysis Records     |
                    | Reports and Alerts   |
                    | User and Role Data   |
                    | Model Metadata       |
                    | Audit Records        |
                    +----------------------+

                    Optional Background Work
                    -------------------------
                    Isolated File Parsing
                    Threat Enrichment
                    Model Training and Evaluation
```

### Architectural Principles

- **Modularity:** Security capabilities are separated into maintainable modules.
- **Centralized authorization:** Protected operations are enforced by the backend.
- **Data integrity:** PostgreSQL stores operational records and model metadata.
- **Evidence-driven analytics:** Dashboard metrics are derived from real data.
- **Privacy:** Sensitive content is not retained unnecessarily.
- **Controlled machine learning:** Models require evaluation and explicit promotion.
- **Auditing:** Sensitive operations have an attributable history.
- **Graceful degradation:** Missing providers or models do not justify fabricated results.

The architecture can be extended with a durable job queue or additional services when workload and reliability requirements justify them.

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js |
| Frontend language | TypeScript / JavaScript |
| UI styling | Existing project styling and reusable components |
| Interactive visualization | Three.js |
| Backend API | FastAPI |
| Backend language | Python 3.12 |
| Database | PostgreSQL |
| Database migrations | Alembic |
| Data access | Existing SQLAlchemy-based backend |
| Machine learning | Optional TF-IDF and MLP-based threat-analysis model |
| Model integrity | SHA-256 and HMAC verification |
| Containerization | Docker and Docker Compose |
| Deployment | Render |
| Testing | pytest, frontend tests, and project validation scripts |
| Code quality | Ruff, frontend linting, and type checking |

The optional model is not bundled as a pre-trained production detector. Its use depends on a reviewed artifact, configuration, and successful evaluation.

---

## How It Works

The typical analysis workflow is:

1. **Input:** A user submits a supported message, URL string, or file, or a registered integration supplies a security event.
2. **Validation:** The backend authenticates the request, validates the input, and checks authorization.
3. **Processing:** Supported content is analyzed using the applicable deterministic rules and, when enabled, an approved model.
4. **Finding generation:** The analyzer records supported findings, indicator references, processing status, and detector provenance.
5. **Persistence:** The backend stores permitted analysis metadata and operational records in PostgreSQL.
6. **Presentation:** The frontend retrieves authorized results and displays the analysis or event details.
7. **Investigation:** Authorized users review findings, submit feedback, and manage related reports or cases.
8. **Evaluation:** Eligible, consented, and reviewed samples can enter the controlled model-evaluation and training workflow.

Not every input produces a definitive result. Unsupported content, unavailable providers, incomplete extraction, and insufficient evidence must be reflected in the result.

---

## Threat Analyzer

Threat Analyzer uses an explainable, layered analysis design.

### Detection Pipeline

```text
Submitted Message / URL String / Supported File
                       |
                       v
                Input Validation
                       |
                       v
             Isolated Content Parsing
                       |
                       v
              Deterministic Rules
                       |
                       v
           Optional Approved ML Model
                       |
                       v
           Findings and Provenance
                       |
                       v
             Persist Analysis Record
                       |
                       v
             Authorized Result View
```

### Rules-Based Detection

The rules-based analyzer provides the fallback detection path.

It can identify suspicious patterns supported by the implemented rules and available extracted content.

Rule-based findings should identify the matched evidence rather than relying solely on an unexplained risk label.

### Optional Machine Learning

The existing design supports an optional signed TF-IDF + MLP model for phishing and text analysis.

The model is used only when a compatible, trusted artifact has been trained, evaluated, and approved.

Without an eligible model, the application reports the rules-based fallback rather than claiming that a trained neural detector is active.

### File Safety

File analysis uses a separate Python parsing process with resource controls and supported-format validation.

Safeguards include upload-size limits, parsing timeouts, concurrency limits, extracted-text limits, and restricted file-format support.

Production deployments should use the documented Linux container environment and validate resource-exhaustion protections before enabling uploads.

### Analysis Privacy

Analysis records contain a content hash and derived findings rather than uploaded file bytes or extracted text.

History, details, deletion, and feedback operations are scoped to the authorized owner.

This design reduces unnecessary data retention but does not eliminate every possible privacy risk. Submitted text and other sensitive data must still be handled according to the application's configured logging, processing, and integration policies.

---

## Threat Detection Network

The Threat Detection Network is an analytics and model-governance view, not an independent network sensor.

Its information comes from persisted threat analyses, authorized feedback records, model metadata, and supported operational records.

### Scoped Roles

| Role | Permissions |
|---|---|
| `ADMINISTRATOR` | Existing administrative access, including threat-management functions |
| `THREAT_MONITOR` | Read threat-network metrics and model state |
| `THREAT_DATA_REVIEWER` | Inspect eligible consented samples and approve or reject labels |
| `THREAT_MODEL_OPERATOR` | Queue training and manage model promotion, rejection, and rollback |

Role assignments are database-backed and enforced by the API.

### Controlled Model Lifecycle

The model-governance workflow is designed around:

1. Explicit user consent.
2. Authorized reviewer approval.
3. Eligible labeled training samples.
4. An independent evaluation dataset.
5. Candidate model training and evaluation.
6. Artifact integrity verification.
7. Non-regression checks.
8. Authorized model promotion.
9. Version tracking and rollback.

User feedback is not automatically accepted as ground truth or used for training.

### Evaluation Metrics

When supported by valid evaluation results, the platform can report:

- Precision.
- Recall.
- F1 score.
- False-positive rate.
- Confusion matrix.
- Evaluation sample counts.

These metrics must be calculated from actual predictions and trusted labels.

A green status indicator, successful API response, or presence of a model artifact is not evidence of detection accuracy.

---

## Security Events and Telemetry

Ascent Safety distinguishes between event ingestion, threat analysis, alert generation, and enforcement.

### Event Ingestion

Configured integrations can submit supported telemetry and security events to the backend.

Production ingestion should enforce:

- Source authentication.
- Request and schema validation.
- Rate limiting.
- Event identifiers and deduplication.
- Timestamp and source provenance.
- Controlled error handling.
- Appropriate access controls.
- Auditability.

### Threat Correlation

Events may be related through explicit indicators such as a matching domain, IP address, file hash, or source-provided endpoint identifier.

Relationships should be traceable and distinguish exact matches from contextual enrichment or inferred associations.

A correlation does not automatically establish that one event caused another.

### Network Visualization

The threat globe and map show eligible coordinate-backed event records.

IP-derived geographic information, when available, must be presented with appropriate uncertainty. It must not be represented as an exact attacker location without reliable evidence.

The application does not claim to provide universal packet capture, endpoint detection and response, or automatic network blocking.

---

## Security Reports and Incident Management

Ascent Safety supports private security-report submission and authorized operational workflows.

### Report Workflow

```text
User Submits Report
         |
         v
Backend Validation and Persistence
         |
         v
Authorized Analyst Review
         |
         v
Assignment and Triage
         |
         v
Investigation and Internal Notes
         |
         v
Resolution / Reopening / False Positive
         |
         v
Audited Status History
```

Reports, alerts, and confirmed incidents are distinct entities and must retain their correct meanings.

Sensitive report details and internal notes are accessible only to authorized users.

User-provided location metadata does not automatically become a public geographic event.

File attachments are not enabled until the required private storage and malware-scanning infrastructure is configured.

---

## Authentication and Access Control

Ascent Safety supports authenticated users, database-backed roles, and restricted administrative operations.

Security controls include:

- Server-enforced role checks.
- Secure refresh-cookie handling.
- Same-origin `/api` routing.
- Owner-scoped analysis history.
- Restricted reviewer and model-operator operations.
- Auditing of sensitive actions.
- Controlled administrator provisioning.

Self-registration grants standard user access only.

An administrator can provision the first administrator account through the documented deployment process. Elevated access must never be granted using client-supplied role values.

Keep JWT signing secrets, database credentials, API keys, and model-signing keys out of source control and browser-accessible environment variables.

---

## Privacy and Security

Security is a foundational requirement of Ascent Safety.

### Current Design Safeguards

- Uploaded analysis bytes and extracted text are not stored in analysis records.
- URL submissions are inspected as strings by default.
- File parsing is isolated and resource-limited.
- User analysis history is owner-scoped.
- Feedback training requires explicit consent and authorized review.
- Training samples are encrypted when the documented encryption key is configured.
- Model artifacts are integrity-checked before loading.
- Sensitive administrative operations are audited.
- Report locations remain private metadata unless separately represented by an authorized ingestion event.
- External threat-intelligence lookups are controlled by provider configuration.
- Report attachments remain disabled until their security dependencies are configured.

### Production Recommendations

Before processing sensitive production data:

- Enforce HTTPS.
- Configure secure cookies.
- Restrict database network access.
- Store secrets in the hosting provider's secret manager.
- Configure retention and deletion policies.
- Review outbound network access.
- Audit access to sensitive data.
- Maintain encrypted backups.
- Test backup restoration.
- Review all connected providers and their data-sharing behavior.
- Validate isolation and authorization controls through testing.

These safeguards reduce risk but do not constitute a guarantee of complete security.

---

## Prerequisites

For a complete local deployment:

- Docker Engine.
- Docker Compose plugin.
- Git.
- Internet access for retrieving required container images and dependencies.

For development outside Docker:

- Node.js and npm, compatible with the frontend lockfile and project configuration.
- Python 3.12.
- PostgreSQL or the project's configured test database.
- Dependencies defined by the repository.

---

## Run Locally with Docker Compose

Docker Compose is the supported full-stack development path.

It starts PostgreSQL, applies Alembic migrations, waits for API readiness, and then starts the web application.

### 1. Clone the repository

```bash
git clone https://github.com/uskascent-svg/Ascent-Safety-.git
cd Ascent-Safety-
```

### 2. Initialize the environment

**Windows PowerShell**

```powershell
.\scripts\init-env.ps1
```

**Linux/macOS**

```bash
chmod +x scripts/init-env.sh
./scripts/init-env.sh
```

The initialization script creates local secrets in `.env`, refuses to overwrite an existing `.env`, and does not print secret values.

Do not commit `.env` to Git.

### 3. Start the application

```bash
docker compose up --build -d
```

### 4. Check the running services

```bash
docker compose ps
docker compose logs --tail=100
```

### 5. Open the application

- Frontend: http://localhost:3000
- API liveness: http://localhost:8000/api/health
- API readiness: http://localhost:8000/api/health/ready

The host ports bind to loopback by default.

The browser uses the frontend's same-origin `/api` path. Next.js forwards API requests to FastAPI, preserving the supported refresh-cookie flow.

Do not expose development ports directly to the public internet.

### Stop the application

```bash
docker compose down
```

To stop the application and preserve database data, do not add the `-v` flag.

---

## Local Development

### Frontend

```bash
cd frontend
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

Use the scripts defined in `frontend/package.json` if the repository's available commands differ.

### Backend

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment before installing dependencies.

**Linux/macOS**

```bash
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
.\.venv\Scripts\Activate.ps1
```

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run the tests and lint checks:

```bash
python -m pytest
ruff check app tests alembic
```

The API tests use an isolated in-memory SQLite database. Passing those tests does not replace staging validation against PostgreSQL, HTTPS, real integrations, and production configuration.

---

## Production Deployment

Ascent Safety includes a Render Blueprint in `render.yaml`.

### Render deployment

1. Push the repository to GitHub.
2. Open the Render Dashboard.
3. Select **New → Blueprint**.
4. Connect the repository.
5. Review the services and environment configuration defined in `render.yaml`.
6. Provide the requested provider secrets only if you intend to enable the corresponding integration.
7. Deploy and inspect the build and runtime logs.
8. Verify API readiness, authentication, database migrations, and frontend-to-backend communication.

The Blueprint defines the PostgreSQL, FastAPI, and Next.js services. Resource availability, persistent storage, pricing, and provider restrictions depend on the selected Render plans and current platform policies.

### Production Environment

Configure the following values through the hosting provider's secret manager or environment settings as applicable:

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Signs authentication tokens |
| `POSTGRES_PASSWORD` | PostgreSQL authentication |
| `DATABASE_URL` | Backend database connection |
| `COOKIE_SECURE` | Enables secure-cookie behavior over HTTPS |
| `API_INTERNAL_URL` | Server-side frontend rewrite target |
| `CORS_ORIGINS` | Trusted browser origins when cross-origin access is required |
| `INGEST_API_KEY` | Optional generic ingestion authentication |
| `GOOGLE_API_KEY` | Optional backend guidance-provider integration |
| `ML_MODEL_PATH` | Optional approved phishing-model artifact path |
| `THREAT_ANALYSIS_DATA_KEY` | Encryption key for eligible training samples |
| `THREAT_ANALYSIS_MODEL_HMAC_KEY` | Model artifact signing and verification |
| `THREAT_ANALYSIS_MODEL_DIR` | Persistent model-artifact directory |
| `THREAT_ANALYSIS_INDEPENDENT_TEST_SET` | Independent labeled evaluation dataset |
| `BOOTSTRAP_ADMIN_EMAIL` | Temporary administrator provisioning configuration |

Consult `.env.example` and the backend settings model for the authoritative list of variables, validation requirements, and defaults.

Never copy real production secrets into GitHub, public documentation, browser environment variables, or committed configuration files.

### First Administrator on Render

1. Register an account through the deployed login page.
2. Open `ascent-safety-api` in the Render Dashboard.
3. Add `BOOTSTRAP_ADMIN_EMAIL` with the exact email address of the intended account.
4. Save the configuration and restart or redeploy the API.
5. Sign in again to refresh the account's authorization state.
6. Remove `BOOTSTRAP_ADMIN_EMAIL` after successful promotion.

Self-registration does not grant administrator privileges.

### Production Networking

Use HTTPS and route public application traffic through the frontend, allowing the Next.js `/api` rewrite to forward requests to FastAPI.

Configure reverse-proxy timeouts for long-lived Server-Sent Events, appropriate request-size limits, and rate limits for exposed ingestion routes.

Ensure the proxy replaces forwarded client-address headers rather than trusting arbitrary client-supplied values.

### Optional Machine-Learning Configuration

Only load trusted, reviewed model artifacts.

The optional phishing model uses the configured model path, for example:

```text
ML_MODEL_PATH=/models/phishing_tfidf_lr.joblib
```

The actual artifact must exist, be compatible with the running code, and pass the implemented integrity checks.

Do not enable training until encryption and signing keys, persistent private storage, consent and review workflows, and independent evaluation data are configured.

---

## Database Operations

Database migrations are managed through Alembic.

### Apply migrations

```bash
docker compose run --rm migrate alembic upgrade head
docker compose up -d api web
```

### Create a backup

```bash
docker compose exec -T db pg_dump -U ascent -d ascent -Fc > ascent-backup.dump
```

Protect the backup, store it outside the repository, and encrypt it according to your operational requirements.

### Restore considerations

Before restoring:

1. Stop application writers.
2. Verify the backup file.
3. Confirm the target database.
4. Restore into an appropriate recovery environment.
5. Validate the restored records and application behavior.
6. Resume production traffic only after verification.

Test restoration regularly. A backup that has never been restored is not a verified recovery procedure.

### Threat-analysis migrations

The threat-analysis integration includes Alembic revisions `0013` through `0015`, covering analysis records, feedback, training jobs, model versions, scoped roles, and additional detector provenance.

Before applying production migrations, take and verify a database backup.

Avoid destructive downgrades against the only production copy. Some downgrades remove newly introduced tables or fields and may permanently delete data created after the migration.

---

## Testing and Code Quality

Ascent Safety uses backend and frontend tests to validate functionality and reduce regressions.

### Backend checks

```bash
cd backend
python -m pytest
ruff check app tests alembic
```

### Frontend checks

```bash
cd frontend
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

### Important validation areas

- Authentication and session handling.
- Database-backed authorization.
- Cross-user and tenant isolation.
- Analysis history ownership.
- Parser failures and resource limits.
- Ingestion validation and deduplication.
- Event and notification consistency.
- Model artifact verification.
- Consent and reviewer approval.
- Migration compatibility.
- API readiness and frontend integration.
- Backup restoration and deployment configuration.

A successful unit-test suite does not independently establish production readiness. Validate the complete application in a staging environment using PostgreSQL, TLS, actual integration sources, and appropriate security testing.

---

## Project Structure

The following is a conceptual overview of the repository's responsibilities. The actual directory structure and filenames should be verified against the checked-out source.

```text
Ascent-Safety-/
|
|-- frontend/
|   |-- Next.js application
|   |-- UI components and routes
|   |-- Threat Analyzer interface
|   |-- Security dashboard
|   |-- Threat visualization
|   |-- Public assets and textures
|
|-- backend/
|   |-- FastAPI application
|   |-- Authentication and authorization
|   |-- Security analysis services
|   |-- Event ingestion
|   |-- Report and alert workflows
|   |-- Database models and repositories
|   |-- Alembic migrations
|   |-- Tests
|
|-- ml/
|   |-- Optional model artifacts
|   |-- Model configuration and documentation
|
|-- docs/
|   |-- Implementation plan
|   |-- Architecture decisions
|   |-- Endpoint telemetry
|   |-- Network telemetry
|
|-- scripts/
|   |-- Local environment initialization
|
|-- docker-compose.yml
|-- render.yaml
|-- .env.example
|-- README.md
```

Refer to the repository for the authoritative file and directory names.

---

## Current Limitations

Ascent Safety is designed to assist with cybersecurity analysis and investigation. Its actual capabilities depend on the deployed code, configured integrations, available data, and verified operational environment.

The following limitations are important:

- **No universal network capture:** The application does not automatically capture all network packets.
- **No automatic endpoint protection:** Endpoint monitoring requires a separately deployed and configured telemetry source or agent.
- **No guaranteed blocking:** Detection and analysis do not automatically prevent malicious activity.
- **No bundled production-trained neural model:** The optional ML workflow requires a trusted artifact, independent evaluation, and authorized promotion.
- **No fabricated analytics:** Empty datasets and unavailable metrics remain empty or unavailable.
- **No guaranteed detection accuracy:** Performance must be measured against appropriate independent labeled data.
- **No automatic safe verdict:** Unsupported formats and incomplete parsing cannot establish that content is benign.
- **No default URL fetching:** Submitted URLs are inspected as strings unless a separate approved integration is configured.
- **No report attachments by default:** Secure storage and malware-scanning requirements must be met before enabling them.
- **No automatic legal compliance certification:** Compliance guidance is informational and does not establish legal applicability or prove compliance.
- **No unrelated monitoring subsystems:** Railway, camera, and train-monitoring functionality is not part of the project.

Ascent Safety complements security operations and investigation workflows. It is not a replacement for a complete EDR, SIEM, packet-capture platform, firewall, or incident-response program.

---

## Roadmap

Potential improvements should be implemented and validated incrementally.

### Platform Reliability

- Strengthen API observability and integration health reporting.
- Improve ingestion idempotency and event normalization.
- Add durable background-job processing where required.
- Improve database performance and recovery procedures.

### Detection and Investigation

- Expand explainable detection rules.
- Improve evidence-backed event correlation.
- Enhance indicator enrichment and provenance.
- Strengthen analyst investigation workflows.
- Improve independent detection-quality evaluation.

### Machine-Learning Governance

- Improve reviewed feedback workflows.
- Strengthen model compatibility checks.
- Expand controlled model evaluation.
- Improve artifact promotion and rollback procedures.
- Add monitoring for measured model performance when sufficient evaluation data exists.

### User Experience

- Improve responsive dashboard layouts.
- Refine event exploration and case navigation.
- Enhance accessible data visualizations.
- Improve loading, empty, stale, and error states.
- Keep every operational component connected to authoritative data.

These items are a development roadmap, not a claim that every capability has already been implemented.

---

## Documentation

Consult the following repository documentation for implementation details:

- [Implementation Decisions](https://github.com/uskascent-svg/Ascent-Safety-/blob/main/docs/implementation-decisions.md)
- [Premium Globe Implementation Plan](https://github.com/uskascent-svg/Ascent-Safety-/blob/main/docs/implementation-plan-premium-globe.md)
- [Endpoint Telemetry Guide](https://github.com/uskascent-svg/Ascent-Safety-/blob/main/docs/endpoint-telemetry.md)
- [Network Telemetry Guide](https://github.com/uskascent-svg/Ascent-Safety-/blob/main/docs/network-telemetry.md)
- [Machine-Learning Setup](https://github.com/uskascent-svg/Ascent-Safety-/blob/main/ml/README.md)
- [Earth Texture Attributions](https://github.com/uskascent-svg/Ascent-Safety-/blob/main/frontend/public/textures/README.md)

Review the telemetry guides before connecting production data sources.

---

## Contributing

Contributions that improve reliability, security, maintainability, documentation, and detection quality are welcome.

Before submitting a change:

1. Review the existing architecture and implementation decisions.
2. Keep changes focused and compatible with existing functionality.
3. Add or update tests.
4. Run relevant frontend and backend checks.
5. Review database migrations for data-loss risks.
6. Verify that sensitive information is not committed.
7. Document new environment variables and deployment requirements.
8. Describe any known limitations honestly.

Never submit fabricated production telemetry, real credentials, private training samples, or untrusted model artifacts.

---

## License

Check the repository for an existing `LICENSE` file before redistributing or reusing this project.

If no license is present, the project's redistribution and reuse permissions should not be assumed. Add an appropriate license only after determining the intended licensing terms.

---

**Ascent Safety — Security analysis grounded in evidence, privacy, and operational accountability.**
