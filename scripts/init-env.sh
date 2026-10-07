#!/usr/bin/env sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$PROJECT_ROOT"

if [ -e .env ]; then
  echo ".env already exists. Keep it intact and edit it directly if needed." >&2
  exit 1
fi

JWT_SECRET=$(openssl rand -hex 48)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
sed \
  -e "s|^JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" \
  -e "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+psycopg://ascent:$POSTGRES_PASSWORD@db:5432/ascent|" \
  .env.example > .env
chmod 600 .env
echo "Created .env with fresh local secrets. Review deployment-specific settings before production use."
