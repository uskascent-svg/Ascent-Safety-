# Core detection foundation

## Scale and ML integration

The evaluator accepts catalogs up to 10,000 unique declarative rules and normalizes each event once, filtering candidates by exact source family plus wildcard rules. The 10,000 limit is a tested capacity limit, not a claim that 10,000 validated detections ship enabled. The checked-in catalog now contains 303 disabled draft candidates, including three provenance-linked Windows endpoint candidates. Do not inflate counts with generated placeholder rules or enable candidates without telemetry mappings and quality evidence.

The existing threat-analysis path includes a TF-IDF classifier and a controlled feedback-training workflow: encrypted opt-in samples, reviewer approval, deduplication, independent holdout evaluation, signed model artifacts, candidate/active states, operator promotion, audit records and rollback. Training is intentionally unavailable unless the encryption key, model-signing key and independent labeled test set are configured. It is not online self-modification: analyst feedback must be reviewed and a candidate must pass evaluation before promotion.


Additive to the existing FastAPI application. Existing phishing/file analysis, authentication, database and audit integrations remain authoritative.

## Catalog status

`core_rules.json` contains 300 unique disabled draft candidates across six source families. They are not validated production detections and must not be enabled as-is. They have no guessed ATT&CK mappings or test dates. Add source-specific mappings, positive and benign-negative fixtures, false-positive measurements and analyst review before promotion.

## Safety

Rules are declarative data; no arbitrary expression is executed. Only rules explicitly marked both `production` and `enabled` can fire. Invalid operators, malformed field paths, duplicate IDs and invalid catalog schemas are rejected. Normalization does not invent missing context.

## Tests

From `backend/`, run `python -m pytest -q tests/test_core_rules.py tests/test_core_catalog.py` and `ruff check app/detection/core_rules.py tests/test_core_rules.py tests/test_core_catalog.py`.

## Shadow integration

The event-ingestion service now invokes `app.services.core_rule_adapter` after storing a security event and records the evaluator status, match count and matched rule IDs in the existing audit record. It does not add a table, endpoint, dependency, or bypass the existing ingest key, event transaction, alert policy or audit flow. A malformed/missing catalog fails closed for detection while allowing the original event ingest to continue.

The adapter maps only fields already present in `SecurityEvent`. It deliberately does not infer `event.action` from titles/descriptions or guess a source family from a provider name. Since the catalog currently contains only disabled draft candidates, expected match count is zero. Matches are shadow/audit metadata only; they do not create alerts or change severity.

## Remaining Phase 1 work

Add real source-specific adapters that supply verified action/context, per-rule positive and benign-negative fixtures, analyst-reviewed rule promotion and alert persistence for approved production detections. Then run full backend/frontend tests, migrations, Compose smoke tests and deployment/capacity validation. No production rule is enabled by this foundation.


## Operating the feedback-trained model

1. Configure `THREAT_ANALYSIS_DATA_KEY`, `THREAT_ANALYSIS_MODEL_HMAC_KEY`, `THREAT_ANALYSIS_INDEPENDENT_TEST_SET`, and a persistent `THREAT_ANALYSIS_MODEL_DIR` using deployment secrets and a protected volume.
2. Collect feedback with explicit opt-in for training samples. Do not upload sensitive samples unless the data policy permits it.
3. Have an authorized reviewer approve labels after independent review. Conflicted or duplicate samples are excluded by the trainer.
4. Run the controlled training workflow and inspect precision, recall, F1, false-positive rate, false-negative rate, sample counts and candidate artifact integrity.
5. Promote only through the authorized model-operator endpoint; monitor outcomes and use the audited rollback path if quality regresses.
6. Verify model artifact and evaluation-set backups before production rollout.

Never train directly on unreviewed user feedback or treat model confidence as proof that a sample is malicious.


## Evidence-based rule promotion gate

Use `app.detection.promotion_gates.evaluate_promotion_candidate` to evaluate a candidate against representative positive and benign-negative event fixtures before any manual catalog edit. The gate checks provenance (source and reference), an ISO-formatted test date, ATT&CK mapping, fixture presence, that all supplied positive fixtures match, and that no supplied negative fixture matches. It returns a structured report with failed checks and fixture counts.

This gate is deliberately advisory and non-mutating: it never changes `lifecycle`, `enabled`, or the catalog, and even a passing result requires authorized human approval. Fixture quality and representativeness still require analyst review; passing a small fixture set is not proof of production efficacy. Rule promotion must remain a reviewed change with regression tests and false-positive measurement.


## Catalog readiness report

From `backend/`, run `python -m app.detection.catalog_health` to emit a machine-readable JSON report. It validates the same catalog schema used by the evaluator and reports the actual catalog count, capacity remaining, lifecycle/source-family counts, enabled production rules, and stored promotion-evidence gaps. The report is diagnostic only: available capacity is not detection coverage, evidence presence is not proof of fixture quality, and no lifecycle state is changed. Current checked-in catalog evidence must be measured from the file at the time the report runs; do not copy example counts into dashboards as constants.

The catalog is intentionally not padded from 303 to 10,000 with cloned or synthetic placeholder detections. The evaluator is tested to accept up to 10,000 unique rules, but filling that capacity with defensible detections requires verified source telemetry, source provenance, meaningful positive/negative fixtures, ATT&CK review, false-positive measurement and analyst approval.

## Pinned Windows endpoint candidates (2026-10-20)

Three additional endpoint candidates (AS-CORE-0301 through AS-CORE-0303) are narrow adaptations of SigmaHQ rules pinned to commit `f083329893e4f44869bf7d283c7aa001ad86a0cd`:

- Encoded PowerShell command with a specific Base64 marker — upstream Sigma rule `ca2092a1-c273-4878-9b4b-0d60115bf5ea`, ATT&CK T1059.001.
- Scheduled-task persistence targeting a temporary-path PowerShell script — upstream Sigma rule `3a734d25-df5c-4b99-8034-af1ddb5883a4`, ATT&CK T1053.005.
- Rundll32 command referencing a PNG extension — upstream Sigma rule `4aa6040b-3f28-44e3-a769-9208e5feb5ec`, ATT&CK T1218.011.

Each candidate includes source provenance and positive/benign-negative regression fixtures. The fixtures are intentionally small and test only the narrow translated condition; they do not establish production precision, recall, or low false-positive rates. Upstream Sigma statuses were `test`, not proof of universal reliability. All three candidates remain `draft` and disabled.

**Endpoint telemetry integration:** the existing authenticated `/api/endpoint-telemetry` path already accepts typed `ProcessObs` and `PersistenceObs` observations. The core-rule adapter now maps only those explicit fields (`process.image`, `process.command_line`, `persistence.mechanism`, and `persistence.target`) into the rule schema and evaluates enabled production rules alongside existing endpoint detectors. It does not infer Windows Event ID 4698 or synthesize scheduled-task XML. The three catalog candidates remain disabled drafts and therefore cannot create findings. Regression tests validate field mapping and candidate conditions in isolation; this is not a claim of production detection quality or representative false-positive measurement.

Run the focused checks from `backend/`:

```bash
python -m pytest -q tests/test_verified_endpoint_candidates.py tests/test_catalog_health.py tests/test_promotion_gates.py
ruff check tests/test_verified_endpoint_candidates.py tests/test_catalog_health.py
```



### Endpoint core-rule adapter regression checks

From `backend/`, run `python -m pytest -q tests/test_endpoint_core_rule_adapter.py tests/test_verified_endpoint_candidates.py tests/test_core_rule_adapter.py tests/test_endpoint_ingest.py` (where the endpoint ingest test module is present). Draft rules must remain inert; only explicitly enabled production rules may create endpoint findings. Raw command lines and persistence targets are not copied into new core-rule finding descriptions or evidence.
