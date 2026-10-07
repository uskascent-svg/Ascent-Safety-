#!/bin/sh
set -eu

# Render free instances do not support a separate pre-deploy command.
alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
