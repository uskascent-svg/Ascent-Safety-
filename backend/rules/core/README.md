# Core detection foundation

## Scale and ML integration

The evaluator accepts catalogs up to 10,000 unique declarative rules and normalizes each event once, filtering candidates by exact source family plus wildcard rules. The 10,000 limit is a tested capacity limit, not a claim that 10,000 validated detections ship enabled. The checked-in catalog still contains 300 disabled draft candidates. Do not inflate counts with generated placeholder rules or enable candidates without telemetry mappings and quality evidence.

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
