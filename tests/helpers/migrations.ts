import fs from 'node:fs';
import path from 'node:path';
import type { ClientBase } from 'pg';
import { REPO_ROOT } from './paths';

export const MIGRATIONS_DIR = path.join(REPO_ROOT, 'db', 'migrations');

/** `NNN_name` of every db/migrations/*.up.sql, in apply order. */
export function migrationVersions(): string[] {
  return listMigrationFiles('up').map((f) => path.basename(f, '.up.sql'));
}

/** db/migrations/*.<direction>.sql in apply order (down = reverse). */
export function listMigrationFiles(direction: 'up' | 'down' = 'up'): string[] {
  const suffix = `.${direction}.sql`;
  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith(suffix))
    .sort();
  if (direction === 'down') files.reverse();
  return files.map((name) => path.join(MIGRATIONS_DIR, name));
}

export interface ApplyMigrationsOptions {
  /**
   * Last version to apply (inclusive), e.g. `004_finding_fingerprint`: builds
   * the "F1 database" of REQ-003 AC-P11-3. Default: every version.
   */
  through?: string;
}

/**
 * Test-side, independent re-implementation of the F1 `db/migrate.sh`
 * bookkeeping (the script itself was removed in REQ-003, AC-P11-15): every
 * `db/migrations/*.up.sql` in file order, one transaction per file together
 * with its `schema_migrations(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ
 * NOT NULL DEFAULT NOW())` row. Deliberately does not use `src/db/migrator.ts`,
 * so it can serve as the oracle of the AC-P11-3 compatibility test and as the
 * builder of the template database. Only ever called against throw-away test
 * databases (AC-G-4).
 */
export async function applyMigrations(client: ClientBase, options: ApplyMigrationsOptions = {}): Promise<string[]> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    TEXT        PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
  const all = listMigrationFiles('up');
  if (options.through && !all.some((f) => path.basename(f, '.up.sql') === options.through)) {
    throw new Error(`applyMigrations: unknown version ${options.through}`);
  }
  const applied: string[] = [];
  for (const file of all) {
    const version = path.basename(file, '.up.sql');
    // A leading UTF-8 BOM is dropped (001…005 have none; psql would choke on one too).
    const raw = fs.readFileSync(file, 'utf8');
    const sql = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [version]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`migration ${version} failed: ${msg}`);
    }
    applied.push(version);
    if (version === options.through) break;
  }
  return applied;
}
