# Core detection foundation

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
