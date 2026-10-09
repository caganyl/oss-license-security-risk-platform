#!/usr/bin/env bash
set -euo pipefail

direction="${1:-up}"
migrations_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/migrations" && pwd)"

if [[ "$direction" != "up" && "$direction" != "down" ]]; then
  echo "Usage: DATABASE_URL=postgres://<user>@<host>:5432/<database> $0 [up|down]  (password via PGPASSWORD or pgpass; psql >= 10)" >&2
  echo "  up:   applies pending migrations; each file + its schema_migrations row in one transaction" >&2
  echo "  down: rolls back ALL applied migrations in reverse order, including 001 (drops all data)" >&2
  exit 64
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL is required." >&2
  exit 64
fi

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SQL

migration_applied() {
  local version="$1"
  local result

  result="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v version="$version" -At <<'SQL'
SELECT 1 FROM schema_migrations WHERE version = :'version';
SQL
)" || exit 1

  [[ "$result" == "1" ]]
}

apply_up() {
  local file="$1"
  local version
  version="$(basename "$file" .up.sql)"

  if migration_applied "$version"; then
    echo "Skipping $version"
    return
  fi

  echo "Applying $version"
  # One psql session, one transaction: --single-transaction wraps ALL -f
  # inputs (psql >= 10) in a single BEGIN/COMMIT, so the migration file and
  # its schema_migrations row commit or roll back together. The migration
  # path stays a command-line argument (Git Bash converts /c/... paths for
  # the native psql.exe); the bookkeeping statement comes from stdin (-f -).
  # Migration files must not contain BEGIN/COMMIT.
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v version="$version" \
    --single-transaction -f "$file" -f - <<'SQL'
INSERT INTO schema_migrations (version) VALUES (:'version');
SQL
}

apply_down() {
  local file="$1"
  local version
  version="$(basename "$file" .down.sql)"

  if ! migration_applied "$version"; then
    echo "Skipping $version"
    return
  fi

  echo "Rolling back $version"
  # Same single-transaction pattern as apply_up: down file + DELETE together.
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v version="$version" \
    --single-transaction -f "$file" -f - <<'SQL'
DELETE FROM schema_migrations WHERE version = :'version';
SQL
}

if [[ "$direction" == "up" ]]; then
  for file in "$migrations_dir"/*.up.sql; do
    [[ -e "$file" ]] || continue
    apply_up "$file"
  done
else
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    apply_down "$file"
  done < <(find "$migrations_dir" -maxdepth 1 -type f -name '*.down.sql' | sort -r)
fi
