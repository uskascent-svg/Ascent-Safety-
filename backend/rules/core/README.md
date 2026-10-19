# Core detection foundation

Additive to the existing FastAPI application. Existing phishing/file analysis, authentication, database and audit integrations remain authoritative.

## Catalog status

`core_rules.json` contains 300 unique disabled draft candidates across six source families. They are not validated production detections and must not be enabled as-is. They have no guessed ATT&CK mappings or test dates. Add source-specific mappings, positive and benign-negative fixtures, false-positive measurements and analyst review before promotion.

## Safety

Rules are declarative data; no arbitrary expression is executed. Only rules explicitly marked both `production` and `enabled` can fire. Invalid operators, malformed field paths, duplicate IDs and invalid catalog schemas are rejected. Normalization does not invent missing context.

## Tests

From `backend/`, run `python -m pytest -q tests/test_core_rules.py tests/test_core_catalog.py` and `ruff check app/detection/core_rules.py tests/test_core_rules.py tests/test_core_catalog.py`.

## Remaining Phase 1 work

Integrate the catalog into existing alert/event flow and existing database/auth/audit controls. Add per-rule fixtures and quality gates, then run full backend/frontend tests, migrations, Compose smoke tests and deployment/capacity validation. No production rule is enabled by this foundation.
