/**
 * REQ-002 · AC-G-10 (migration side), AC-P05-5, AC-P08-5
 *
 * Runs db/tests/f1_migrations_test.sql (written for psql) through
 * node-postgres: \ir lines are inlined, \set/\echo dropped
 * (tests/helpers/psqlScript.ts). The script runs 001-004 up, asserts,
 * 004-002 down, re-applies, and ROLLs BACK everything.
 */
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { useTestDatabase } from '../helpers/db';
import { expandPsqlScript } from '../helpers/psqlScript';
import { listMigrationFiles } from '../helpers/migrations';
import { REPO_ROOT } from '../helpers/paths';
import { adminClient } from '../helpers/pgCluster';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const SCRIPT = path.join(REPO_ROOT, 'db', 'tests', 'f1_migrations_test.sql');

describe('F1 migrations (db/tests/f1_migrations_test.sql)', () => {
  const emptyDb = useTestDatabase({ scope: 'file', migrated: false });

  it('converts the psql script: every \\ir resolves to an existing migration file', () => {
    const expanded = expandPsqlScript(SCRIPT);
    const names = expanded.included.map((p) => path.basename(p));
    expect(names).toEqual([
      '001_initial_core_schema.up.sql',
      '002_local_auth.up.sql',
      '003_declared_range.up.sql',
      '004_finding_fingerprint.up.sql',
      '004_finding_fingerprint.down.sql',
      '003_declared_range.down.sql',
      '002_local_auth.down.sql',
      '002_local_auth.up.sql',
      '003_declared_range.up.sql',
      '004_finding_fingerprint.up.sql',
    ]);
    expect(expanded.echoes.join('\n')).toContain('ALL ASSERTIONS PASSED');
  });

  it('AC-P05-5 / AC-P08-5 / AC-G-10: up -> assert -> down -> up passes on an empty database and leaves it empty', async () => {
    const { sql } = expandPsqlScript(SCRIPT);
    const client = adminClient(emptyDb.cluster, emptyDb.name);
    await client.connect();
    try {
      // Throws (test fails) on the first RAISE EXCEPTION 'ASSERT FAILED: ...'.
      await client.query(sql);
      const leftovers = await client.query(
        `SELECT to_regclass('public.users') AS users, to_regclass('public.findings') AS findings`,
      );
      expect(leftovers.rows[0]).toEqual({ users: null, findings: null });
    } finally {
      await client.end();
    }
  });
});

describe('F1 migrations applied like db/migrate.sh (template used by all DB tests)', () => {
  const db = useTestDatabase({ scope: 'file' });

  it('AC-G-10: every db/migrations/*.up.sql is recorded in schema_migrations, in order', async () => {
    const expected = listMigrationFiles('up').map((f) => path.basename(f, '.up.sql'));
    const rows = await db.query<{ version: string }>('SELECT version FROM schema_migrations ORDER BY version');
    expect(rows.map((r) => r.version)).toEqual(expected);
    expect(expected).toEqual(
      expect.arrayContaining(['002_local_auth', '003_declared_range', '004_finding_fingerprint']),
    );
  });

  it('AC-P05-2 / AC-P08-5: schema exposes declared_range, nullable packages.version and NOT NULL findings.fingerprint', async () => {
    const cols = await db.query<{ table_name: string; column_name: string; is_nullable: string }>(
      `SELECT table_name, column_name, is_nullable FROM information_schema.columns
       WHERE table_schema = 'public'
         AND (table_name, column_name) IN (('scan_dependencies','declared_range'),('packages','version'),
                                           ('findings','fingerprint'),('findings','carried_from_finding_id'))
       ORDER BY table_name, column_name`,
    );
    expect(cols).toEqual([
      { table_name: 'findings', column_name: 'carried_from_finding_id', is_nullable: 'YES' },
      { table_name: 'findings', column_name: 'fingerprint', is_nullable: 'NO' },
      { table_name: 'packages', column_name: 'version', is_nullable: 'YES' },
      { table_name: 'scan_dependencies', column_name: 'declared_range', is_nullable: 'YES' },
    ]);
  });
});
