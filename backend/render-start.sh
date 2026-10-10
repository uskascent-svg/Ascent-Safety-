#!/bin/sh
set -eu

# Render free instances do not support a separate pre-deploy command.
alembic upgrade head

if [ -n "${BOOTSTRAP_ADMIN_EMAIL:-}" ]; then
  python -m app.bootstrap_admin "$BOOTSTRAP_ADMIN_EMAIL" || true
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
