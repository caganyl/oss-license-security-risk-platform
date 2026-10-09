import fs from 'node:fs';
import path from 'node:path';
import type { ClientBase } from 'pg';
import { REPO_ROOT } from './paths';

export const MIGRATIONS_DIR = path.join(REPO_ROOT, 'db', 'migrations');

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

/**
 * Applies every db/migrations/*.up.sql in order, the same way db/migrate.sh
 * does: one transaction per file, together with its schema_migrations row.
 * Only ever called against throw-away test databases (AC-G-5).
 */
export async function applyMigrations(client: ClientBase): Promise<string[]> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    TEXT        PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
  const applied: string[] = [];
  for (const file of listMigrationFiles('up')) {
    const version = path.basename(file, '.up.sql');
    const sql = fs.readFileSync(file, 'utf8');
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
  }
  return applied;
}
