# Phase 1 core detection foundation

This package is an additive, dependency-free foundation for the existing ASCENT SAFETY FastAPI application. It does not replace the current phishing, file, or threat-analysis routes.

## Scope and assumptions

- Existing FastAPI, SQLAlchemy/PostgreSQL, authentication and audit boundaries remain authoritative.
- Rules are data-driven and disabled/draft by default. The evaluator only executes rules explicitly marked both `production` and `enabled`.
- Events use an ECS-inspired shape; normalization preserves supplied data and does not fabricate host/user/asset context.
- Conditions are ANDed and restricted to a small typed operator set. Untrusted rule expressions are never evaluated as Python.
- This first commit provides the engine primitive and tests; it does not claim 300 production-validated rules, Kafka throughput, distributed sharding, or production deployment.

## Rule metadata

Every rule should include: `id`, `title`, `source`, `severity`, `confidence`, `conditions`, ATT&CK technique IDs, FP notes, owner, last-tested date, playbook link, lifecycle, and enabled state. Unknown metadata should be explicitly null or marked pending review, not guessed.

## Lifecycle

`draft -> test -> shadow -> production -> review -> retired`

Only reviewed production rules may be enabled. Promotion and rule changes must be authorized, tested, audited, and version-controlled. This module intentionally does not implement an API endpoint that changes lifecycle.

## Local verification

From `backend/`:

```bash
pytest -q tests/test_core_rules.py
ruff check app/detection/core_rules.py tests/test_core_rules.py
```

## Phase 1 remaining work

1. Curate/import 300 source-attributed core rules and add positive/negative fixtures per rule.
2. Add DB migrations and authenticated read-only catalog endpoints after reviewing existing models/routes.
3. Add CI syntax, duplicate, fixture and performance gates.
4. Integrate normalized events into existing alert/audit flow without duplicating authentication or model registry.
5. Run the full backend/frontend suites and Compose smoke tests in a real checkout before merge.
