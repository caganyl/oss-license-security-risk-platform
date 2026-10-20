/**
 * REQ-003 · P-11 migration tool (AC-P11-1…13, 15…18; ADR-004 Karar 10) and the
 * shared single-instance lock (AC-P11-11, D-34; building blocks of AC-P12-15).
 *
 * Real embedded PostgreSQL (AC-G-4): one cluster for the file, a fresh
 * scratch database per scenario. The CLI is driven in-process through
 * `runMigrateCli(argv, { env, out, err, migrationsDir, clientFactory })`; the
 * last block also transpiles `src/db/*.ts` into a temp folder and runs the
 * compiled `migrate.js` as a real `node` process (AC-P11-1: compiled output).
 * Synthetic migration folders live under os.tmpdir(); nothing in db/ is
 * written.
 */
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Client, type ClientConfig } from 'pg';
import ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  INSTANCE_LOCK_ID,
  INSTANCE_LOCK_NAMESPACE,
  MIGRATE_LOCK_APPLICATION_NAME,
  acquireInstanceLock,
  findInstanceLockHolders,
  releaseInstanceLock,
  tryAcquireInstanceLock,
  type LockLostEvent,
} from '../../src/db/advisoryLock';
import { LOCK_HELD_MESSAGE, MIGRATE_EXIT, parseMigrateArgs, runMigrateCli } from '../../src/db/migrate';
import {
  MigrationRejectedError,
  checkMigrationsForStartup,
  decodeMigrationSql,
  findForbiddenStatements,
  loadMigrations,
  migrateDown,
  migrateUp,
  type MigrationClient,
} from '../../src/db/migrator';
import { useScratchDatabases, useTestDatabase, type ScratchDatabase } from '../helpers/db';
import { MIGRATIONS_DIR, applyMigrations, migrationVersions } from '../helpers/migrations';
import { REPO_ROOT } from '../helpers/paths';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const base = useTestDatabase({ scope: 'file', migrated: false });
const newDb = useScratchDatabases(base);

const ALL = [
  '001_initial_core_schema',
  '002_local_auth',
  '003_declared_range',
  '004_finding_fingerprint',
  '005_scan_next_attempt',
  '006_registry_enrichment', // REQ-004
  '007_vulnerability_recheck', // REQ-005
  '008_nuget_enrichment', // REQ-006
  '009_web_scan', // REQ-008
  '010_new_ecosystems', // REQ-011
];
/** tech_ecosystem values added by 010 (REQ-011 D-300); older reference databases do not have them. */
const REQ011_ECOSYSTEMS = new Set(['rust', 'dart', 'swift']);

/** Enum snapshot without the 010 tech_ecosystem values (comparison with a reference database older than 010). */
function typesBefore010(types: unknown): unknown {
  // `pg` returns an enum label array as its text form (`{a,b}`); the labels hold no comma, quote or brace.
  const strip = (labels: string): string => `{${labels.slice(1, -1).split(',').filter((l) => !REQ011_ECOSYSTEMS.has(l)).join(',')}}`;
  return (types as Array<{ typname: string; labels: string }>).map((t) =>
    t.typname === 'tech_ecosystem' ? { ...t, labels: strip(t.labels) } : t,
  );
}
/** Newest real migration (the "latest version" of the --to / compiled-CLI scenarios). */
const LATEST = ALL[ALL.length - 1];
/** Versions pending on the F1 database (001…004 applied). */
const AFTER_F1 = ALL.slice(4);
/** Applied version the code has no file for ("database newer than the code"); numbered above LATEST. */
const FUTURE = `${String(Number(LATEST.slice(0, 3)) + 1).padStart(3, '0')}_from_the_future`;
const LOCK_SQL = `SELECT pg_advisory_lock(${INSTANCE_LOCK_NAMESPACE}, ${INSTANCE_LOCK_ID})`;

let tmpBase = '';
beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p11-'));
});
afterAll(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
interface CliRun {
  code: number;
  out: string[];
  err: string[];
  /** stdout + stderr joined (leak assertions). */
  all: string;
}

async function cli(
  args: string[],
  opts: { url?: string | null; dir?: string; clientFactory?: (config: ClientConfig) => Client } = {},
): Promise<CliRun> {
  const out: string[] = [];
  const err: string[] = [];
  const env: NodeJS.ProcessEnv = {};
  if (opts.url) env.DATABASE_URL = opts.url;
  const code = await runMigrateCli(args, {
    env,
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    migrationsDir: opts.dir,
    clientFactory: opts.clientFactory,
  });
  return { code, out, err, all: [...out, ...err].join('\n') };
}

async function connect(url: string): Promise<Client> {
  const c = new Client({ connectionString: url });
  c.on('error', () => undefined);
  await c.connect();
  return c;
}

/** Empty database with 001…004 applied the way db/migrate.sh did (AC-P11-3). */
async function f1Database(): Promise<ScratchDatabase> {
  const db = await newDb({ migrated: false });
  const c = await connect(db.url);
  try {
    await applyMigrations(c, { through: '004_finding_fingerprint' });
  } finally {
    await c.end();
  }
  return db;
}

async function versions(db: ScratchDatabase): Promise<string[] | null> {
  const [{ present }] = await db.query<{ present: boolean }>(`SELECT to_regclass('schema_migrations') IS NOT NULL AS present`);
  if (!present) return null;
  return (await db.query<{ version: string }>('SELECT version FROM schema_migrations ORDER BY version')).map((r) => r.version);
}

async function tableExists(db: ScratchDatabase, name: string): Promise<boolean> {
  const [{ present }] = await db.query<{ present: boolean }>('SELECT to_regclass($1) IS NOT NULL AS present', [name]);
  return present;
}

async function columnExists(db: ScratchDatabase, table: string, column: string): Promise<boolean> {
  return (
    await db.query(
      `SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
      [table, column],
    )
  ).length === 1;
}

/** Catalog snapshot of the public schema (schema_migrations excluded); ordinal positions ignored. */
async function schemaSnapshot(db: ScratchDatabase) {
  const columns = await db.query(
    `SELECT table_name, column_name, data_type, udt_name, is_nullable, column_default
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name <> 'schema_migrations'
     ORDER BY table_name, column_name`,
  );
  const indexes = await db.query(
    `SELECT tablename, indexname, indexdef FROM pg_indexes
     WHERE schemaname = 'public' AND tablename <> 'schema_migrations' ORDER BY tablename, indexname`,
  );
  const constraints = await db.query(
    `SELECT conrelid::regclass::text AS tbl, conname, pg_get_constraintdef(oid) AS def
     FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND conrelid::regclass::text <> 'schema_migrations'
     ORDER BY 1, 2`,
  );
  const types = await db.query(
    `SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder) AS labels
     FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid
     WHERE t.typnamespace = 'public'::regnamespace GROUP BY t.typname ORDER BY t.typname`,
  );
  return { columns, indexes, constraints, types };
}

/** Writes a synthetic migration folder; values are file contents (string = UTF-8). */
function migDir(files: Record<string, string | Buffer>): string {
  const dir = fs.mkdtempSync(path.join(tmpBase, 'm-'));
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
  return dir;
}

/** Error of a rejected query (pg DatabaseError: code + constraint). */
async function pgError(p: Promise<unknown>): Promise<{ code?: string; constraint?: string }> {
  const e = await p.then(
    () => null,
    (err: unknown) => err,
  );
  expect(e, 'query should have been rejected').not.toBeNull();
  return e as { code?: string; constraint?: string };
}

/** Comment of one column (NULL when none). */
async function columnComment(db: ScratchDatabase, table: string, column: string): Promise<string | null> {
  const rows = await db.query<{ comment: string | null }>(
    `SELECT col_description(a.attrelid, a.attnum) AS comment FROM pg_attribute a
     WHERE a.attrelid = to_regclass($1) AND a.attname = $2 AND NOT a.attisdropped`,
    [table, column],
  );
  return rows[0]?.comment ?? null;
}

function pair(version: string, up: string, down: string): Record<string, string> {
  return { [`${version}.up.sql`]: up, [`${version}.down.sql`]: down };
}

/** Copy of db/migrations in a temp folder (to add files next to the real ones). */
function copyOfRealMigrations(): string {
  const dir = fs.mkdtempSync(path.join(tmpBase, 'real-'));
  for (const name of fs.readdirSync(MIGRATIONS_DIR)) fs.copyFileSync(path.join(MIGRATIONS_DIR, name), path.join(dir, name));
  return dir;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

function urlWith(db: ScratchDatabase, change: { password?: string; port?: number; database?: string }): string {
  const u = new URL(db.url);
  if (change.password !== undefined) u.password = change.password;
  if (change.port !== undefined) u.port = String(change.port);
  if (change.database !== undefined) u.pathname = `/${change.database}`;
  return u.toString();
}

// ---------------------------------------------------------------------------
describe('AC-P11-1 / AC-P11-2 / AC-P11-3: up on a database migrated by the F1 db/migrate.sh', () => {
  it('status shows 001…004 applied (with applied_at) and 005…latest pending; up applies only those, keeps data; a second up skips everything', async () => {
    const db = await f1Database();
    const before = await db.query<{ version: string; applied_at: Date }>('SELECT version, applied_at FROM schema_migrations ORDER BY version');
    expect(before.map((r) => r.version)).toEqual(ALL.slice(0, 4));
    const [project] = await db.query<{ id: string }>(`INSERT INTO projects (name) VALUES ('kept-across-005') RETURNING id`);

    const status = await cli(['status'], { url: db.url });
    expect(status.code).toBe(MIGRATE_EXIT.ok);
    for (const r of before) {
      expect(status.out.some((l) => l.startsWith('uygulanmış') && l.includes(r.version) && l.includes(r.applied_at.toISOString()))).toBe(true);
    }
    for (const v of AFTER_F1) expect(status.out.some((l) => new RegExp(`^bekleyen\\s+${v}$`).test(l)), v).toBe(true);
    expect(status.out).toContain(`özet: 4 uygulanmış, ${AFTER_F1.length} bekleyen, 0 bilinmeyen`);
    expect(await versions(db)).toEqual(ALL.slice(0, 4)); // status changed nothing

    const up = await cli([], { url: db.url }); // default command = up
    expect(up.code, up.all).toBe(MIGRATE_EXIT.ok);
    expect(up.out.slice(0, 4)).toEqual(ALL.slice(0, 4).map((v) => `atlandı ${v}`));
    AFTER_F1.forEach((v, i) => expect(up.out[4 + i]).toMatch(new RegExp(`^uygulandı ${v} \\(\\d+ ms\\)$`)));
    expect(up.out).toContain(`Tamam: ${AFTER_F1.length} göç uygulandı, 4 atlandı.`);
    expect(up.err).toEqual([]);

    const after = await db.query<{ version: string; applied_at: Date }>('SELECT version, applied_at FROM schema_migrations ORDER BY version');
    expect(after.map((r) => r.version)).toEqual(ALL);
    // 001…004 rows untouched, no table re-created (the project row survived).
    expect(after.slice(0, 4)).toEqual(before);
    expect(await db.query('SELECT id FROM projects WHERE id = $1', [project.id])).toHaveLength(1);
    expect(await columnExists(db, 'scans', 'next_attempt_at')).toBe(true);

    const again = await cli(['up'], { url: db.url });
    expect(again.code).toBe(MIGRATE_EXIT.ok);
    expect(again.out.slice(0, ALL.length)).toEqual(ALL.map((v) => `atlandı ${v}`));
    expect(again.out).toContain('Bekleyen göç yok.');
    expect(await db.query('SELECT version, applied_at FROM schema_migrations ORDER BY version')).toEqual(after);
  });
});

describe('AC-P11-16: migration 005_scan_next_attempt', () => {
  it('adds scans.next_attempt_at TIMESTAMPTZ NULL without default, with a comment, and no index or CHECK constraint (ADR-004 Karar 11)', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const cols = await db.query(
      `SELECT data_type, is_nullable, column_default FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'scans' AND column_name = 'next_attempt_at'`,
    );
    expect(cols).toEqual([{ data_type: 'timestamp with time zone', is_nullable: 'YES', column_default: null }]);
    const [{ comment }] = await db.query<{ comment: string | null }>(
      `SELECT col_description('scans'::regclass, a.attnum) AS comment FROM pg_attribute a
       WHERE a.attrelid = 'scans'::regclass AND a.attname = 'next_attempt_at'`,
    );
    expect(comment ?? '').toMatch(/retry/i);
    expect(await db.query(`SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexdef ILIKE '%next_attempt_at%'`)).toEqual([]);
    expect(
      await db.query(
        `SELECT conname FROM pg_constraint WHERE conrelid = 'scans'::regclass AND contype = 'c'
         AND pg_get_constraintdef(oid) ILIKE '%next_attempt_at%'`,
      ),
    ).toEqual([]);
    // The .down.sql states that only the retry scheduling is lost.
    const down = fs.readFileSync(path.join(MIGRATIONS_DIR, '005_scan_next_attempt.down.sql'), 'utf8');
    expect(down).toMatch(/next_attempt_at/);
    expect(down).toMatch(/retry/i);
  });

  it('AC-P11-7 / AC-P11-8: up -> down --to 003_declared_range (latest … 005 then 004, listed first) -> up restores the identical schema', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const full = await schemaSnapshot(db);

    const down = await cli(['down', '--to', '003_declared_range'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    const reverted = ALL.slice(3).reverse(); // newest first, 004 last
    const listed = down.out.findIndex((l) => l === `geri alınacak (sırayla): ${reverted.join(', ')}`);
    expect(listed).toBeGreaterThanOrEqual(0);
    let previous = listed;
    for (const v of reverted) {
      const at = down.out.findIndex((l) => new RegExp(`^geri alındı ${v} \\(\\d+ ms\\)$`).test(l));
      expect(at, v).toBeGreaterThan(previous); // strictly in reverse version order
      previous = at;
    }
    expect(down.out).toContain(`Tamam: ${reverted.length} göç geri alındı; son uygulanmış sürüm 003_declared_range.`);
    expect(await versions(db)).toEqual(ALL.slice(0, 3));
    expect(await columnExists(db, 'scans', 'next_attempt_at')).toBe(false);
    expect(await columnExists(db, 'findings', 'fingerprint')).toBe(false);

    const up = await cli(['up'], { url: db.url });
    expect(up.code).toBe(0);
    expect(up.out.filter((l) => l.startsWith('uygulandı ')).map((l) => l.split(' ')[1])).toEqual(ALL.slice(3));
    expect(await versions(db)).toEqual(ALL);
    expect(await schemaSnapshot(db)).toEqual(full);
  });
});

describe('REQ-005 AC-G-7: migration 007_vulnerability_recheck', () => {
  const V007 = '007_vulnerability_recheck';

  /** project -> scan -> package -> scan_dependency; returns the ids a finding needs. */
  async function seedDependency(db: ScratchDatabase): Promise<{ scanId: string; depId: string }> {
    const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name) VALUES ('qa-007') RETURNING id`);
    const [s] = await db.query<{ id: string }>(
      `INSERT INTO scans (project_id, trigger, status, ref, completed_at) VALUES ($1, 'manual', 'completed', 'main', NOW()) RETURNING id`,
      [p.id],
    );
    const [pkg] = await db.query<{ id: string }>(
      `INSERT INTO packages (ecosystem, name, version, purl) VALUES ('nodejs', 'qa-007-pkg', '1.0.0', 'pkg:npm/qa-007-pkg@1.0.0') RETURNING id`,
    );
    const [d] = await db.query<{ id: string }>(
      `INSERT INTO scan_dependencies (scan_id, package_id, manifest_file, manifest_path) VALUES ($1, $2, 'package-lock.json', 'package-lock.json') RETURNING id`,
      [s.id, pkg.id],
    );
    return { scanId: s.id, depId: d.id };
  }

  async function insertRun(db: ScratchDatabase, status: string): Promise<string> {
    const [r] = await db.query<{ id: string }>(
      `INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at, finished_at)
       VALUES ('qa-run', $1, NOW(), CASE WHEN $1 = 'running' THEN NULL ELSE NOW() END) RETURNING id`,
      [status],
    );
    return r.id;
  }

  async function insertFinding(db: ScratchDatabase, ids: { scanId: string; depId: string }, recheckRunId: string | null, n: number): Promise<string> {
    const [f] = await db.query<{ id: string }>(
      `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, fingerprint, recheck_run_id)
       VALUES ($1, $2, 'security', $3, $4) RETURNING id`,
      [ids.scanId, ids.depId, String(n).repeat(64), recheckRunId],
    );
    return f.id;
  }

  it('up -> down --to 006 (restores exactly the 006 schema, enum types untouched) -> up yields the identical schema', async () => {
    const db = await newDb({ migrated: false });
    const up = await cli(['up'], { url: db.url });
    expect(up.code, up.all).toBe(0);
    expect(up.out).toContainEqual(expect.stringMatching(new RegExp(`^uygulandı ${V007} \\(\\d+ ms\\)$`)));
    const full = await schemaSnapshot(db);

    // Reference: a fresh database migrated with 001…006 only (007 and every later file removed).
    const dir006 = copyOfRealMigrations();
    for (const v of ALL.slice(6)) for (const f of [`${v}.up.sql`, `${v}.down.sql`]) fs.rmSync(path.join(dir006, f));
    expect((await loadMigrations(dir006)).map((m) => m.version)).toEqual(ALL.slice(0, 6));
    const ref = await newDb({ migrated: false });
    expect((await cli(['up'], { url: ref.url, dir: dir006 })).code).toBe(0);
    const at006 = await schemaSnapshot(ref);

    const down = await cli(['down', '--to', '006'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    expect(down.out).toContain(`geri alınacak (sırayla): ${ALL.slice(6).reverse().join(', ')}`);
    expect(await versions(db)).toEqual(ALL.slice(0, 6));
    for (const t of ['vulnerability_recheck_runs', 'osv_vulnerability_cache', 'nvd_cvss_cache']) expect(await tableExists(db, t), t).toBe(false);
    for (const [t, c] of [
      ['scans', 'vulnerability_data_status'],
      ['scans', 'vulnerability_checked_at'],
      ['findings', 'recheck_run_id'],
      ['scan_dependencies', 'lock_integrity'],
      ['scan_dependencies', 'license_unclassified'], // 008
      ['registry_package_cache', 'canonical_name'], // 008
    ]) {
      expect(await columnExists(db, t, c), `${t}.${c}`).toBe(false);
    }
    expect(await schemaSnapshot(db)).toEqual(at006);
    // No enum type gains or loses a value (finding_status, audit_action, scan_trigger …) except the 010 tech_ecosystem values.
    expect(typesBefore010(full.types)).toEqual(at006.types);

    const again = await cli(['up'], { url: db.url });
    expect(again.code, again.all).toBe(0);
    expect(again.out.filter((l) => l.startsWith('uygulandı ')).map((l) => l.split(' ')[1])).toEqual(ALL.slice(6));
    expect(await versions(db)).toEqual(ALL);
    expect(await schemaSnapshot(db)).toEqual(full);
  });

  it('CHECK value sets: recheck run status, scans.vulnerability_data_status, scan_dependencies.lock_integrity, nvd_cvss_cache.outcome', async () => {
    const db = await newDb(); // migrated template: 001…latest
    const ids = await seedDependency(db);

    for (const status of ['completed', 'partial', 'failed', 'interrupted', 'disabled']) await insertRun(db, status);
    await insertRun(db, 'running');
    expect((await pgError(insertRun(db, 'bogus'))).code).toBe('23514');
    // running <=> finished_at IS NULL
    expect(
      (await pgError(db.query(`INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at, finished_at) VALUES ('qa', 'completed', NOW(), NULL)`))).constraint,
    ).toBe('vulnerability_recheck_runs_finished');

    for (const v of ['complete', 'partial', 'unavailable', 'disabled', null]) {
      await db.query(`UPDATE scans SET vulnerability_data_status = $1 WHERE id = $2`, [v, ids.scanId]);
    }
    expect((await pgError(db.query(`UPDATE scans SET vulnerability_data_status = 'bogus' WHERE id = $1`, [ids.scanId]))).code).toBe('23514');

    for (const v of ['match', 'mismatch', 'not_comparable', null]) {
      await db.query(`UPDATE scan_dependencies SET lock_integrity = $1 WHERE id = $2`, [v, ids.depId]);
    }
    expect((await pgError(db.query(`UPDATE scan_dependencies SET lock_integrity = 'bogus' WHERE id = $1`, [ids.depId]))).code).toBe('23514');

    const nvd = (cve: string, outcome: string, score: number | null) =>
      db.query(
        `INSERT INTO nvd_cvss_cache (cve_id, outcome, cvss_score, fetched_at, expires_at) VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 day')`,
        [cve, outcome, score],
      );
    await nvd('CVE-2024-0001', 'found', 7.5);
    await nvd('CVE-2024-0002', 'no_cvss', null);
    expect((await pgError(nvd('CVE-2024-0003', 'error', null))).code).toBe('23514'); // transient errors are never stored
    expect((await pgError(nvd('CVE-2024-0004', 'found', null))).constraint).toBe('nvd_cvss_cache_found');

    // The declared sets match the contract exactly (no extra value hidden in the definition).
    const defs = await db.query<{ tbl: string; def: string }>(
      `SELECT conrelid::regclass::text AS tbl, pg_get_constraintdef(oid) AS def FROM pg_constraint
       WHERE contype = 'c' AND connamespace = 'public'::regnamespace
         AND conrelid::regclass::text IN ('vulnerability_recheck_runs', 'scans', 'scan_dependencies', 'nvd_cvss_cache')`,
    );
    const setOf = (tbl: string, column: string): string[] => {
      const def = defs.find((d) => d.tbl === tbl && new RegExp(`\\(?${column}\\b.*ANY`).test(d.def))?.def ?? '';
      return [...def.matchAll(/'([^']+)'::text/g)].map((m) => m[1]).sort();
    };
    expect(setOf('vulnerability_recheck_runs', 'status')).toEqual(['completed', 'disabled', 'failed', 'interrupted', 'partial', 'running']);
    expect(setOf('scans', 'vulnerability_data_status')).toEqual(['complete', 'disabled', 'partial', 'unavailable']);
    expect(setOf('scan_dependencies', 'lock_integrity')).toEqual(['match', 'mismatch', 'not_comparable']);
    expect(setOf('nvd_cvss_cache', 'outcome')).toEqual(['found', 'no_cvss']);
  });

  it('at most one running recheck run: a second running row -> 23505 on uq_vulnerability_recheck_runs_running; a finished row frees the slot', async () => {
    const db = await newDb();
    const first = await insertRun(db, 'running');
    const err = await pgError(insertRun(db, 'running'));
    expect(err).toMatchObject({ code: '23505', constraint: 'uq_vulnerability_recheck_runs_running' });
    expect(await db.query(`SELECT 1 FROM vulnerability_recheck_runs WHERE status = 'running'`)).toHaveLength(1);
    await insertRun(db, 'completed'); // finished rows are not limited
    await db.query(`UPDATE vulnerability_recheck_runs SET status = 'interrupted', finished_at = NOW() WHERE id = $1`, [first]);
    await insertRun(db, 'running');
    expect(await db.query(`SELECT 1 FROM vulnerability_recheck_runs WHERE status = 'running'`)).toHaveLength(1);
  });

  it('findings.recheck_run_id is ON DELETE SET NULL: deleting run history keeps the finding', async () => {
    const db = await newDb();
    const ids = await seedDependency(db);
    const run = await insertRun(db, 'completed');
    const linked = await insertFinding(db, ids, run, 1);
    const [{ deltype }] = await db.query<{ deltype: string }>(
      `SELECT confdeltype AS deltype FROM pg_constraint
       WHERE conrelid = 'findings'::regclass AND contype = 'f' AND confrelid = 'vulnerability_recheck_runs'::regclass`,
    );
    expect(deltype).toBe('n'); // SET NULL

    await db.query(`DELETE FROM vulnerability_recheck_runs WHERE id = $1`, [run]);
    expect(await db.query(`SELECT id, recheck_run_id FROM findings WHERE id = $1`, [linked])).toEqual([{ id: linked, recheck_run_id: null }]);
  });

  it('down keeps every finding (recheck-opened ones lose only their link); the .down.sql header lists the lost data', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const ids = await seedDependency(db);
    const run = await insertRun(db, 'completed');
    const byRecheck = await insertFinding(db, ids, run, 2);
    const byScan = await insertFinding(db, ids, null, 3);
    await db.query(`UPDATE scan_dependencies SET lock_integrity = 'mismatch' WHERE id = $1`, [ids.depId]);
    await db.query(`UPDATE scans SET vulnerability_data_status = 'partial', vulnerability_checked_at = NOW() WHERE id = $1`, [ids.scanId]);

    const down = await cli(['down', '--to', '006'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    const rows = await db.query<{ id: string; scan_id: string; status: string }>(`SELECT id, scan_id, status::text AS status FROM findings ORDER BY id`);
    expect(rows.map((r) => r.id).sort()).toEqual([byRecheck, byScan].sort());
    expect(rows.every((r) => r.scan_id === ids.scanId && r.status === 'open')).toBe(true);
    expect(await db.query(`SELECT 1 FROM scan_dependencies WHERE id = $1`, [ids.depId])).toHaveLength(1);
    expect(await db.query(`SELECT 1 FROM scans WHERE id = $1`, [ids.scanId])).toHaveLength(1);

    const text = fs.readFileSync(path.join(MIGRATIONS_DIR, `${V007}.down.sql`), 'utf8');
    expect(text).toMatch(/DATA LOSS/);
    for (const what of ['vulnerability_recheck_runs', 'findings.recheck_run_id', 'scans.vulnerability_data_status', 'scan_dependencies.lock_integrity']) {
      expect(text, what).toContain(what);
    }
    expect(text).toMatch(/findings THEMSELVES are KEPT/);
  });
});

describe('REQ-006 AC-G-7: migration 008_nuget_enrichment (contract REQ-004 1.4.0 §4.1, §4.5; ADR-008 Karar 14)', () => {
  const V007 = '007_vulnerability_recheck';
  const V008 = '008_nuget_enrichment';
  /** The 008 columns: [table, column]. */
  const NEW_COLUMNS: Array<[string, string]> = [
    ['registry_package_cache', 'license_unclassified'],
    ['registry_package_cache', 'license_file_path'],
    ['registry_package_cache', 'canonical_name'],
    ['scan_dependencies', 'license_unclassified'],
  ];
  /** The tables 008 alters. */
  const TABLES_008 = ['registry_package_cache', 'registry_archive_cache', 'scan_dependencies'];

  /** CHECK constraints of the 008 tables: name -> definition. */
  async function checkConstraints(db: ScratchDatabase): Promise<Record<string, string>> {
    const rows = await db.query<{ conname: string; def: string }>(
      `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
       WHERE contype = 'c' AND connamespace = 'public'::regnamespace AND conrelid::regclass::text = ANY($1::text[])
       ORDER BY conname`,
      [TABLES_008],
    );
    return Object.fromEntries(rows.map((r) => [r.conname, r.def]));
  }

  /** Values of an `x = ANY (ARRAY['a'::text, …])` CHECK, sorted. */
  function valueSet(defs: Record<string, string>, conname: string): string[] {
    expect(defs[conname], `${conname} exists`).toBeDefined();
    return [...(defs[conname] ?? '').matchAll(/'([^']+)'::text/g)].map((m) => m[1]).sort();
  }

  /** Reference database migrated with 001…007 only. */
  async function at007Database(): Promise<ScratchDatabase> {
    const dir = copyOfRealMigrations();
    // 008 and every later migration removed (REQ-008 added 009 on top).
    for (const v of ALL.slice(7)) for (const f of [`${v}.up.sql`, `${v}.down.sql`]) fs.rmSync(path.join(dir, f));
    expect((await loadMigrations(dir)).map((m) => m.version)).toEqual(ALL.slice(0, 7));
    const ref = await newDb({ migrated: false });
    const run = await cli(['up'], { url: ref.url, dir });
    expect(run.code, run.all).toBe(0);
    return ref;
  }

  async function insertPackageCache(
    db: ScratchDatabase,
    row: { ecosystem: string; name: string; outcome?: 'found' | 'not_found'; unclassified?: string | null; filePath?: string | null; canonical?: string | null },
  ): Promise<unknown> {
    const outcome = row.outcome ?? 'found';
    return db.query(
      `INSERT INTO registry_package_cache (ecosystem, name, version, outcome, declared_license, extractor_version, expires_at,
                                           license_unclassified, license_file_path, canonical_name)
       VALUES ($1, $2, '1.0.0', $3, NULL, 1, CASE WHEN $3 = 'not_found' THEN NOW() + INTERVAL '1 day' END, $4, $5, $6)`,
      [row.ecosystem, row.name, outcome, row.unclassified ?? null, row.filePath ?? null, row.canonical ?? null],
    );
  }

  async function insertArchive(db: ScratchDatabase, ecosystem: string, name: string): Promise<string> {
    const [a] = await db.query<{ id: string }>(
      `INSERT INTO registry_archive_cache (ecosystem, name, version, archive_digest, archive_url, archive_size, outcome, extractor_version)
       VALUES ($1, $2, '1.0.0', 'sha512-qa', 'https://registry.invalid/qa', 10, 'collected', 1) RETURNING id`,
      [ecosystem, name],
    );
    return a.id;
  }

  /** project -> completed scan; packages are added with `dependency`. */
  async function seedScan(db: ScratchDatabase): Promise<string> {
    const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name) VALUES ('qa-008') RETURNING id`);
    const [s] = await db.query<{ id: string }>(
      `INSERT INTO scans (project_id, trigger, status, ref, completed_at) VALUES ($1, 'manual', 'completed', 'main', NOW()) RETURNING id`,
      [p.id],
    );
    return s.id;
  }

  async function dependency(
    db: ScratchDatabase,
    scanId: string,
    pkg: { ecosystem: 'dotnet' | 'nodejs'; name: string; purl: string },
    lic: { expression: string | null; source: string; status: string; noticeStatus?: string | null; archiveId?: string | null; lockIntegrity?: string | null },
  ): Promise<string> {
    const [row] = await db.query<{ id: string }>(
      `INSERT INTO packages (ecosystem, name, version, purl) VALUES ($1, $2, '1.0.0', $3) RETURNING id`,
      [pkg.ecosystem, pkg.name, pkg.purl],
    );
    const manifest = pkg.ecosystem === 'dotnet' ? 'packages.lock.json' : 'package-lock.json';
    const [d] = await db.query<{ id: string }>(
      `INSERT INTO scan_dependencies (scan_id, package_id, manifest_file, manifest_path, license_expression, license_source,
                                      license_enrichment_status, notice_status, notice_archive_id, lock_integrity)
       VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [scanId, row.id, manifest, lic.expression, lic.source, lic.status, lic.noticeStatus ?? null, lic.archiveId ?? null, lic.lockIntegrity ?? null],
    );
    return d.id;
  }

  it('up -> down --to 007 (restores exactly the 007 schema and comments, enum types untouched) -> up yields the identical schema', async () => {
    const db = await newDb({ migrated: false });
    const up = await cli(['up'], { url: db.url });
    expect(up.code, up.all).toBe(0);
    expect(up.out).toContainEqual(expect.stringMatching(new RegExp(`^uygulandı ${V008} \\(\\d+ ms\\)$`)));
    const full = await schemaSnapshot(db);
    for (const [t, c] of NEW_COLUMNS) {
      expect(await columnExists(db, t, c), `${t}.${c}`).toBe(true);
      expect(await columnComment(db, t, c), `${t}.${c} comment`).toEqual(expect.any(String));
    }
    const fullLockComment = await columnComment(db, 'scan_dependencies', 'lock_integrity');
    expect(fullLockComment ?? '').toMatch(/NuGet/);
    // Nullable, no default: existing rows get NULL, no table rewrite.
    const cols = await db.query(
      `SELECT table_name, column_name, data_type, is_nullable, column_default FROM information_schema.columns
       WHERE table_schema = 'public' AND (table_name, column_name) IN
         (('registry_package_cache','license_unclassified'), ('registry_package_cache','license_file_path'),
          ('registry_package_cache','canonical_name'), ('scan_dependencies','license_unclassified'))
       ORDER BY table_name, column_name`,
    );
    expect(cols).toEqual(
      [...NEW_COLUMNS]
        .sort((a, b) => (a[0] + a[1]).localeCompare(b[0] + b[1]))
        .map(([table_name, column_name]) => ({ table_name, column_name, data_type: 'text', is_nullable: 'YES', column_default: null })),
    );
    // 008 creates no index.
    expect(await db.query(`SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND (indexdef ILIKE '%license_unclassified%' OR indexdef ILIKE '%canonical_name%' OR indexdef ILIKE '%license_file_path%')`)).toEqual([]);

    const ref = await at007Database();
    const at007 = await schemaSnapshot(ref);
    const refLockComment = await columnComment(ref, 'scan_dependencies', 'lock_integrity');

    const down = await cli(['down', '--to', '007'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    expect(down.out).toContain(`geri alınacak (sırayla): ${ALL.slice(7).reverse().join(', ')}`);
    expect(down.out).toContainEqual(expect.stringMatching(new RegExp(`^geri alındı ${V008} \\(\\d+ ms\\)$`)));
    expect(down.out).toContain(`Tamam: ${ALL.length - 7} göç geri alındı; son uygulanmış sürüm ${V007}.`);
    expect(await versions(db)).toEqual(ALL.slice(0, 7));
    for (const [t, c] of NEW_COLUMNS) expect(await columnExists(db, t, c), `${t}.${c}`).toBe(false);
    expect((await checkConstraints(db)).registry_package_cache_nuget_fields).toBeUndefined();
    expect(await schemaSnapshot(db)).toEqual(at007);
    // The lock_integrity comment is put back to its 007 text.
    expect(await columnComment(db, 'scan_dependencies', 'lock_integrity')).toBe(refLockComment);
    expect(refLockComment).not.toBe(fullLockComment);
    // No enum type gains or loses a value (tech_ecosystem already had 'dotnet'), except the 010 tech_ecosystem values.
    expect(typesBefore010(full.types)).toEqual(at007.types);

    const again = await cli(['up'], { url: db.url });
    expect(again.code, again.all).toBe(0);
    expect(again.out.filter((l) => l.startsWith('uygulandı ')).map((l) => l.split(' ')[1])).toEqual(ALL.slice(7));
    expect(await versions(db)).toEqual(ALL);
    expect(await schemaSnapshot(db)).toEqual(full);
    expect(await columnComment(db, 'scan_dependencies', 'lock_integrity')).toBe(fullLockComment);
  });

  it('CHECK value sets (binding names): cache ecosystems incl. nuget, license_source incl. registry:nuget, license_unclassified file|url', async () => {
    const db = await newDb(); // migrated template: 001…latest
    const defs = await checkConstraints(db);
    // REQ-011 (010) widens the package cache and license_source sets with deps.dev / pub.dev; the archive cache is unchanged.
    expect(valueSet(defs, 'registry_package_cache_ecosystem_check')).toEqual(['depsdev', 'npm', 'nuget', 'pubdev', 'pypi']);
    expect(valueSet(defs, 'registry_archive_cache_ecosystem_check')).toEqual(['npm', 'nuget', 'pypi']);
    expect(valueSet(defs, 'scan_dependencies_license_source_check')).toEqual(
      ['lockfile (unverified)', 'none', 'registry:depsdev', 'registry:npm', 'registry:nuget', 'registry:pubdev', 'registry:pypi'],
    );
    expect(valueSet(defs, 'scan_dependencies_license_unclassified_check')).toEqual(['file', 'url']);
    expect(valueSet(defs, 'registry_package_cache_license_unclassified_check')).toEqual(['file', 'url']);
    expect(defs.registry_package_cache_license_file_path_check).toMatch(/char_length\(license_file_path\) <= 256/);
    expect(defs.registry_package_cache_canonical_name_check).toMatch(/char_length\(canonical_name\) <= 100/);
    // Exactly one CHECK per column: the old 006 CHECK was replaced, not left next to the new one.
    for (const column of ['ecosystem', 'license_source', 'license_unclassified']) {
      for (const table of TABLES_008) {
        const hits = Object.entries(defs).filter(([name, def]) => name.startsWith(`${table}_`) && new RegExp(`\\(?${column} = ANY`).test(def));
        expect(hits.length, `${table}.${column}`).toBeLessThanOrEqual(1);
      }
    }

    // Behaviour of the scan_dependencies CHECKs.
    const scanId = await seedScan(db);
    const depId = await dependency(db, scanId, { ecosystem: 'dotnet', name: 'Qa.Nuget', purl: 'pkg:nuget/Qa.Nuget@1.0.0' }, { expression: 'MIT', source: 'registry:nuget', status: 'ok' });
    for (const v of ['file', 'url', null]) {
      await db.query(`UPDATE scan_dependencies SET license_unclassified = $1 WHERE id = $2`, [v, depId]);
    }
    expect(await pgError(db.query(`UPDATE scan_dependencies SET license_unclassified = 'bogus' WHERE id = $1`, [depId]))).toMatchObject({
      code: '23514',
      constraint: 'scan_dependencies_license_unclassified_check',
    });
    expect(await pgError(db.query(`UPDATE scan_dependencies SET license_source = 'registry:maven' WHERE id = $1`, [depId]))).toMatchObject({
      code: '23514',
      constraint: 'scan_dependencies_license_source_check',
    });

    // Archive cache: nuget accepted, anything else rejected.
    await insertArchive(db, 'nuget', 'qa.nuget');
    expect(await pgError(insertArchive(db, 'maven', 'qa.maven'))).toMatchObject({ code: '23514', constraint: 'registry_archive_cache_ecosystem_check' });
  });

  it('registry_package_cache_nuget_fields and length limits: the NuGet fields exist only on NuGet found rows; 256 / 100 characters (not bytes)', async () => {
    const db = await newDb();
    // NuGet found rows may carry every field; non-ASCII counts by characters.
    await insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.full', unclassified: 'file', filePath: 'ü'.repeat(256), canonical: 'Ç'.repeat(100) });
    await insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.url', unclassified: 'url' });
    await insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.plain' });
    await insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.missing', outcome: 'not_found' });
    await insertPackageCache(db, { ecosystem: 'npm', name: 'qa-npm' });
    await insertPackageCache(db, { ecosystem: 'pypi', name: 'qa-pypi' });

    const fieldsRule = { code: '23514', constraint: 'registry_package_cache_nuget_fields' };
    expect(await pgError(insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.nf1', outcome: 'not_found', canonical: 'Qa.Nf1' }))).toMatchObject(fieldsRule);
    expect(await pgError(insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.nf2', outcome: 'not_found', unclassified: 'url' }))).toMatchObject(fieldsRule);
    expect(await pgError(insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.nf3', outcome: 'not_found', filePath: 'LICENSE' }))).toMatchObject(fieldsRule);
    expect(await pgError(insertPackageCache(db, { ecosystem: 'npm', name: 'qa-npm-2', unclassified: 'file' }))).toMatchObject(fieldsRule);
    expect(await pgError(insertPackageCache(db, { ecosystem: 'pypi', name: 'qa-pypi-2', canonical: 'Qa' }))).toMatchObject(fieldsRule);
    expect(await pgError(insertPackageCache(db, { ecosystem: 'npm', name: 'qa-npm-3', filePath: 'LICENSE' }))).toMatchObject(fieldsRule);

    expect(await pgError(insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.long1', filePath: 'ü'.repeat(257) }))).toMatchObject({
      code: '23514',
      constraint: 'registry_package_cache_license_file_path_check',
    });
    expect(await pgError(insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.long2', canonical: 'Ç'.repeat(101) }))).toMatchObject({
      code: '23514',
      constraint: 'registry_package_cache_canonical_name_check',
    });
    expect(await pgError(insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.bad', unclassified: 'expression' }))).toMatchObject({
      code: '23514',
      constraint: 'registry_package_cache_license_unclassified_check',
    });
    expect(await pgError(insertPackageCache(db, { ecosystem: 'maven', name: 'qa.maven' }))).toMatchObject({
      code: '23514',
      constraint: 'registry_package_cache_ecosystem_check',
    });
    expect(await db.query(`SELECT ecosystem, name FROM registry_package_cache ORDER BY ecosystem, name`)).toEqual([
      { ecosystem: 'npm', name: 'qa-npm' },
      { ecosystem: 'nuget', name: 'qa.full' },
      { ecosystem: 'nuget', name: 'qa.missing' },
      { ecosystem: 'nuget', name: 'qa.plain' },
      { ecosystem: 'nuget', name: 'qa.url' },
      { ecosystem: 'pypi', name: 'qa-pypi' },
    ]);
  });

  it('down: NuGet cache rows deleted, npm/PyPI rows kept; registry:nuget -> none with license_expression kept; notice_archive_id SET NULL; no scan/dependency/package/finding deleted', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);

    await insertPackageCache(db, { ecosystem: 'nuget', name: 'newtonsoft.json', canonical: 'Newtonsoft.Json' });
    await insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.unclassified', unclassified: 'file', filePath: 'LICENSE.txt', canonical: 'Qa.Unclassified' });
    await insertPackageCache(db, { ecosystem: 'nuget', name: 'qa.gone', outcome: 'not_found' });
    await insertPackageCache(db, { ecosystem: 'npm', name: 'left-pad' });
    await insertPackageCache(db, { ecosystem: 'pypi', name: 'requests' });
    const nugetArchive = await insertArchive(db, 'nuget', 'newtonsoft.json');
    const npmArchive = await insertArchive(db, 'npm', 'left-pad');
    const pypiArchive = await insertArchive(db, 'pypi', 'requests');

    const scanId = await seedScan(db);
    const nuget = await dependency(
      db,
      scanId,
      { ecosystem: 'dotnet', name: 'Newtonsoft.Json', purl: 'pkg:nuget/Newtonsoft.Json@1.0.0' },
      { expression: 'MIT', source: 'registry:nuget', status: 'ok', noticeStatus: 'collected', archiveId: nugetArchive, lockIntegrity: 'match' },
    );
    const unclassified = await dependency(
      db,
      scanId,
      { ecosystem: 'dotnet', name: 'Qa.Unclassified', purl: 'pkg:nuget/Qa.Unclassified@1.0.0' },
      { expression: null, source: 'none', status: 'no_license', noticeStatus: 'no_license_file', lockIntegrity: 'not_comparable' },
    );
    await db.query(`UPDATE scan_dependencies SET license_unclassified = 'file' WHERE id = $1`, [unclassified]);
    const npm = await dependency(
      db,
      scanId,
      { ecosystem: 'nodejs', name: 'left-pad', purl: 'pkg:npm/left-pad@1.0.0' },
      { expression: 'WTFPL', source: 'registry:npm', status: 'ok', noticeStatus: 'collected', archiveId: npmArchive, lockIntegrity: 'match' },
    );
    const [finding] = await db.query<{ id: string }>(
      `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, fingerprint) VALUES ($1, $2, 'security', $3) RETURNING id`,
      [scanId, nuget, 'e'.repeat(64)],
    );
    const counts = async () =>
      (
        await db.query<{ scans: number; deps: number; packages: number; findings: number }>(
          `SELECT (SELECT count(*)::int FROM scans) AS scans, (SELECT count(*)::int FROM scan_dependencies) AS deps,
                  (SELECT count(*)::int FROM packages) AS packages, (SELECT count(*)::int FROM findings) AS findings`,
        )
      )[0];
    const before = await counts();

    const down = await cli(['down', '--to', '007'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);

    expect(await db.query(`SELECT ecosystem, name FROM registry_package_cache ORDER BY ecosystem`)).toEqual([
      { ecosystem: 'npm', name: 'left-pad' },
      { ecosystem: 'pypi', name: 'requests' },
    ]);
    expect((await db.query<{ id: string }>(`SELECT id FROM registry_archive_cache ORDER BY ecosystem`)).map((r) => r.id)).toEqual([npmArchive, pypiArchive]);

    const dep = async (id: string) =>
      (
        await db.query(
          `SELECT license_expression, license_source, license_enrichment_status, notice_status, notice_archive_id, lock_integrity
           FROM scan_dependencies WHERE id = $1`,
          [id],
        )
      )[0];
    // registry:nuget -> none, the expression stays; the archive link goes (ON DELETE SET NULL), notice_status stays.
    expect(await dep(nuget)).toEqual({
      license_expression: 'MIT',
      license_source: 'none',
      license_enrichment_status: 'ok',
      notice_status: 'collected',
      notice_archive_id: null,
      lock_integrity: 'match',
    });
    // The unclassified marker is gone with its column; the row itself is a plain no_license / none row.
    expect(await dep(unclassified)).toEqual({
      license_expression: null,
      license_source: 'none',
      license_enrichment_status: 'no_license',
      notice_status: 'no_license_file',
      notice_archive_id: null,
      lock_integrity: 'not_comparable',
    });
    expect(await dep(npm)).toEqual({
      license_expression: 'WTFPL',
      license_source: 'registry:npm',
      license_enrichment_status: 'ok',
      notice_status: 'collected',
      notice_archive_id: npmArchive,
      lock_integrity: 'match',
    });
    expect(await counts()).toEqual(before);
    expect(await db.query(`SELECT id FROM findings WHERE id = $1`, [finding.id])).toHaveLength(1);
    expect(await db.query(`SELECT 1 FROM packages WHERE ecosystem = 'dotnet'`)).toHaveLength(2);

    // The 007 CHECKs are back: NuGet values are rejected again.
    expect(await pgError(db.query(`UPDATE scan_dependencies SET license_source = 'registry:nuget' WHERE id = $1`, [nuget]))).toMatchObject({
      code: '23514',
      constraint: 'scan_dependencies_license_source_check',
    });
    expect(
      await pgError(
        db.query(`INSERT INTO registry_package_cache (ecosystem, name, version, outcome, extractor_version) VALUES ('nuget', 'qa.after', '1.0.0', 'found', 1)`),
      ),
    ).toMatchObject({ code: '23514', constraint: 'registry_package_cache_ecosystem_check' });
    expect(await pgError(insertArchive(db, 'nuget', 'qa.after'))).toMatchObject({ code: '23514', constraint: 'registry_archive_cache_ecosystem_check' });

    // Up again works on the rolled-back data; the lost marker is not restored.
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    expect(await db.query(`SELECT license_unclassified FROM scan_dependencies WHERE id = $1`, [unclassified])).toEqual([{ license_unclassified: null }]);
    expect((await dep(nuget))?.license_source).toBe('none');
  });

  it('the .down.sql opens with a DATA LOSS header naming what is lost and what is kept (before any statement)', () => {
    const text = decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, `${V008}.down.sql`)));
    const firstStatement = text.search(/^(DELETE|UPDATE|ALTER|DROP|COMMENT)\b/m);
    expect(firstStatement).toBeGreaterThan(0);
    const header = text.slice(0, firstStatement);
    expect(header.split('\n').filter((l) => l.trim() !== '').every((l) => l.startsWith('--'))).toBe(true);
    expect(header).toMatch(/DATA LOSS/);
    for (const what of [
      'registry_package_cache',
      'registry_archive_cache',
      "'nuget'",
      'notice_archive_id',
      'ON DELETE SET NULL',
      "'registry:nuget' is rewritten to 'none'",
      'license_expression is KEPT',
      'scan_dependencies.license_unclassified is dropped',
      'license_unclassified',
      'license_file_path',
      'canonical_name',
    ]) {
      expect(header, what).toContain(what);
    }
    expect(header).toMatch(/No scan, scan_dependencies, package, finding or license_findings row is\s+(--\s+)?deleted/);
    expect(header).toMatch(/explicit human approval/);
    // The up file is all-or-nothing: no transaction control, no CONCURRENTLY.
    const upText = decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, `${V008}.up.sql`)));
    expect(findForbiddenStatements(upText)).toEqual([]);
    expect(findForbiddenStatements(text)).toEqual([]);
    expect(upText.split('\n').filter((l) => !l.trimStart().startsWith('--')).join('\n')).not.toMatch(/CONCURRENTLY/i);
  });

  it('db/schema.sql equals 001…008: same columns, enum types, CHECK constraints of the 008 tables and comments of the 008 columns', async () => {
    const migrated = await newDb({ migrated: false });
    expect((await cli(['up'], { url: migrated.url })).code).toBe(0);
    const fromSchema = await newDb({ migrated: false });
    const c = await connect(fromSchema.url);
    try {
      await c.query(decodeMigrationSql(fs.readFileSync(path.join(REPO_ROOT, 'db', 'schema.sql'))));
    } finally {
      await c.end();
    }
    const a = await schemaSnapshot(migrated);
    const b = await schemaSnapshot(fromSchema);
    expect(b.columns).toEqual(a.columns);
    expect(b.types).toEqual(a.types);
    expect(await checkConstraints(fromSchema)).toEqual(await checkConstraints(migrated));
    for (const [t, col] of [...NEW_COLUMNS, ['scan_dependencies', 'lock_integrity'] as [string, string]]) {
      expect(await columnComment(fromSchema, t, col), `${t}.${col}`).toBe(await columnComment(migrated, t, col));
    }
    expect(await fs.promises.readFile(path.join(REPO_ROOT, 'db', 'schema.sql'), 'utf8')).toContain(V008);
  });
});

describe('AC-P11-8: --to forms and targets', () => {
  it('--to 003 (number) equals --to 003_declared_range; --to=<latest number> is a no-op; --to 001 keeps 001 applied', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);

    const latest = await cli(['down', `--to=${LATEST.slice(0, 3)}`], { url: db.url });
    expect(latest.code).toBe(0);
    expect(latest.out.join('\n')).toMatch(/geri alınacak sürüm yok/);
    expect(await versions(db)).toEqual(ALL);

    const byNumber = await cli(['down', '--to', '003'], { url: db.url });
    expect(byNumber.code, byNumber.all).toBe(0);
    expect(await versions(db)).toEqual(ALL.slice(0, 3));

    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const toFirst = await cli(['down', '--to', '001'], { url: db.url });
    expect(toFirst.code, toFirst.all).toBe(0);
    expect(toFirst.out).toContain(`geri alınacak (sırayla): ${ALL.slice(1).reverse().join(', ')}`);
    expect(await versions(db)).toEqual(['001_initial_core_schema']);
    expect(await tableExists(db, 'projects')).toBe(true);
  });

  it('--to 999 (no such version), --to 004 when 004 is not applied, and --to with an unknown name -> exit 3, nothing changed', async () => {
    const db = await f1Database();
    const snapshot = await schemaSnapshot(db);
    // 005 is pending here, so 005 is a valid-but-not-applied target.
    for (const args of [['down', '--to', '999'], ['down', '--to', '005'], ['down', '--to', '003_wrong_name'], ['down', '--to=000']]) {
      const run = await cli(args, { url: db.url });
      expect(run.code, `${args.join(' ')}: ${run.all}`).toBe(MIGRATE_EXIT.rejected);
      expect(run.err.join('\n')).toMatch(/Hiçbir değişiklik yapılmadı/);
    }
    expect(await versions(db)).toEqual(ALL.slice(0, 4));
    expect(await schemaSnapshot(db)).toEqual(snapshot);
  });
});

describe('AC-P11-6 / AC-P11-18: usage and configuration errors -> exit 2, database untouched', () => {
  const USAGE_CASES: string[][] = [
    ['down'],
    ['down', '--to'],
    ['down', '--to', ''],
    ['down', '--to='],
    ['down', '--to', '-1'],
    ['down', '003'],
    ['down', '--to', '003', 'extra'],
    ['frobnicate'],
    ['up', 'now'],
    ['status', '--verbose'],
    ['--to', '003'],
    ['UP'],
  ];

  it('down without --to, empty/flag-like targets, extra arguments and unknown commands -> 2 with the usage text', async () => {
    const db = await newDb({ migrated: false });
    for (const args of USAGE_CASES) {
      const run = await cli(args, { url: db.url });
      expect(run.code, args.join(' ')).toBe(MIGRATE_EXIT.usage);
      expect(run.err.join('\n'), args.join(' ')).toMatch(/Kullanım: npm run db:migrate/);
    }
    expect(await versions(db)).toBeNull(); // not even schema_migrations was created
  });

  it('missing or blank DATABASE_URL -> 2 with a hint, no connection attempt', async () => {
    const factory = vi.fn((config: ClientConfig) => new Client(config));
    for (const env of [{}, { DATABASE_URL: '   ' }]) {
      const err: string[] = [];
      const code = await runMigrateCli(['status'], { env, out: () => undefined, err: (l) => err.push(l), clientFactory: factory });
      expect(code).toBe(MIGRATE_EXIT.usage);
      expect(err.join('\n')).toMatch(/DATABASE_URL tanımlı değil/);
    }
    expect(factory).not.toHaveBeenCalled();
  });

  it('help -> 0; parseMigrateArgs is pure and accepts exactly up | status | down --to X | down --to=X', () => {
    expect(parseMigrateArgs([])).toEqual({ kind: 'up' });
    expect(parseMigrateArgs(['up'])).toEqual({ kind: 'up' });
    expect(parseMigrateArgs(['status'])).toEqual({ kind: 'status' });
    expect(parseMigrateArgs(['down', '--to', '003'])).toEqual({ kind: 'down', to: '003' });
    expect(parseMigrateArgs(['down', '--to=003_declared_range'])).toEqual({ kind: 'down', to: '003_declared_range' });
    expect(parseMigrateArgs(['--help'])).toEqual({ kind: 'help' });
    for (const args of USAGE_CASES) expect(parseMigrateArgs(args).kind, args.join(' ')).toBe('usage-error');
  });

  it('`help` prints the usage text and exits 0 without touching the database', async () => {
    const run = await cli(['help'], { url: 'postgres://nobody@127.0.0.1:1/none' });
    expect(run.code).toBe(MIGRATE_EXIT.ok);
    expect(run.out.join('\n')).toMatch(/Çıkış kodları/);
  });
});

describe('AC-P11-11 / D-34: shared single-instance lock', () => {
  it('lock held by another session: status, up and down -> exit 4 with the message, nothing changed, holder keeps the lock', async () => {
    const db = await f1Database();
    const holder = await connect(db.url);
    try {
      await holder.query(LOCK_SQL);
      const [{ pid }] = (await holder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows;
      for (const args of [['status'], ['up'], [], ['down', '--to', '003']]) {
        const run = await cli(args, { url: db.url });
        expect(run.code, args.join(' ')).toBe(MIGRATE_EXIT.locked);
        expect(run.err).toEqual([LOCK_HELD_MESSAGE]);
        expect(run.out).toEqual([]);
      }
      expect(LOCK_HELD_MESSAGE).toMatch(/uygulama çalışıyor veya başka bir göç sürüyor; önce durdurun/);
      expect(await versions(db)).toEqual(ALL.slice(0, 4));
      expect(await columnExists(db, 'scans', 'next_attempt_at')).toBe(false);
      expect(await findInstanceLockHolders(holder)).toEqual([pid]);
    } finally {
      await holder.end();
    }
    // Lock gone with the session: the tool works again.
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
  });

  it('acquireInstanceLock: second acquire on the same database fails, another database is independent; the CLI uses one oss-risk:migrate connection and leaves no holder', async () => {
    const db = await newDb();
    const other = await newDb();
    const first = await acquireInstanceLock({ connection: db.url, applicationName: 'qa-first' });
    expect(first.acquired).toBe(true);
    if (!first.acquired) return;
    try {
      expect(first.lock.backendPid).toEqual(expect.any(Number));
      expect(await acquireInstanceLock({ connection: db.url, applicationName: 'qa-second' })).toEqual({ acquired: false });
      const elsewhere = await acquireInstanceLock({ connection: other.url, applicationName: 'qa-other-db' });
      expect(elsewhere.acquired).toBe(true);
      if (elsewhere.acquired) expect(await elsewhere.lock.release()).toBe(true);

      const probe = await connect(db.url);
      try {
        expect(await findInstanceLockHolders(probe)).toEqual([first.lock.backendPid]);
        // the failed second attempt closed its connection
        const apps = await probe.query(`SELECT 1 FROM pg_stat_activity WHERE application_name = 'qa-second'`);
        expect(apps.rows).toEqual([]);
      } finally {
        await probe.end();
      }
    } finally {
      expect(await first.lock.release()).toBe(true);
      expect(await first.lock.release()).toBe(false); // idempotent
    }

    const configs: ClientConfig[] = [];
    const statements: string[] = [];
    const factory = (config: ClientConfig) => {
      configs.push(config);
      const c = new Client(config);
      const query = c.query.bind(c) as (...a: unknown[]) => Promise<unknown>;
      (c as unknown as { query: (...a: unknown[]) => Promise<unknown> }).query = (...a: unknown[]) => {
        if (typeof a[0] === 'string') statements.push(a[0]);
        return query(...a);
      };
      return c;
    };
    const run = await cli(['status'], { url: db.url, clientFactory: factory });
    expect(run.code).toBe(0);
    expect(configs).toHaveLength(1);
    expect(configs[0].application_name).toBe(MIGRATE_LOCK_APPLICATION_NAME);
    expect(statements.some((s) => s.includes(`pg_try_advisory_lock(${INSTANCE_LOCK_NAMESPACE}, ${INSTANCE_LOCK_ID})`))).toBe(true);
    expect(statements.some((s) => s.includes(`pg_advisory_unlock(${INSTANCE_LOCK_NAMESPACE}, ${INSTANCE_LOCK_ID})`))).toBe(true);
    expect(await findInstanceLockHolders(db.pool)).toEqual([]);
  });

  it('low-level primitives: tryAcquireInstanceLock / releaseInstanceLock on one session', async () => {
    const db = await newDb();
    const a = await connect(db.url);
    const b = await connect(db.url);
    try {
      expect(await tryAcquireInstanceLock(a)).toBe(true);
      expect(await tryAcquireInstanceLock(b)).toBe(false);
      expect(await releaseInstanceLock(b)).toBe(false);
      expect(await releaseInstanceLock(a)).toBe(true);
      expect(await tryAcquireInstanceLock(b)).toBe(true);
    } finally {
      await a.end();
      await b.end();
    }
  });
});

describe('ADR-004 Karar 3: losing the lock connection (building block of AC-P12-15)', () => {
  it('pg_terminate_backend on the lock session -> onLost exactly once, lost = true, late listeners called at once, release() false, re-acquire succeeds', async () => {
    const db = await newDb();
    const res = await acquireInstanceLock({ connection: db.url, applicationName: 'qa-loss', heartbeatIntervalMs: 50, heartbeatTimeoutMs: 1_000 });
    expect(res.acquired).toBe(true);
    if (!res.acquired) return;
    const { lock } = res;
    const events: LockLostEvent[] = [];
    lock.onLost((e) => events.push(e));
    lock.startHeartbeat();
    lock.startHeartbeat(); // idempotent

    const [{ ok }] = await db.query<{ ok: boolean }>('SELECT pg_terminate_backend($1) AS ok', [lock.backendPid]);
    expect(ok).toBe(true);
    await vi.waitFor(() => expect(events).toHaveLength(1), { timeout: 5_000, interval: 20 });
    await new Promise((r) => setTimeout(r, 300)); // several heartbeat periods: no second event
    expect(events).toHaveLength(1);
    expect(events[0].reason).toMatch(/^(connection-error|connection-ended|heartbeat-failed|heartbeat-timeout)$/);
    expect(lock.lost).toBe(true);
    const late = vi.fn();
    lock.onLost(late);
    expect(late).toHaveBeenCalledTimes(1);

    expect(await lock.release()).toBe(false);
    expect(lock.released).toBe(true);
    expect(lock.lost).toBe(true);

    const again = await acquireInstanceLock({ connection: db.url, applicationName: 'qa-reacquire' });
    expect(again.acquired).toBe(true);
    if (again.acquired) expect(await again.lock.release()).toBe(true);
  });

  it('no false alarm: a healthy heartbeat never fires onLost, and release() (which ends the connection) is not a loss', async () => {
    const db = await newDb();
    const res = await acquireInstanceLock({ connection: db.url, applicationName: 'qa-healthy', heartbeatIntervalMs: 20 });
    expect(res.acquired).toBe(true);
    if (!res.acquired) return;
    const onLost = vi.fn();
    res.lock.onLost(onLost);
    res.lock.startHeartbeat();
    await new Promise((r) => setTimeout(r, 400));
    expect(await res.lock.release()).toBe(true);
    await new Promise((r) => setTimeout(r, 100));
    expect(onLost).not.toHaveBeenCalled();
    expect(res.lock.lost).toBe(false);
    expect(await findInstanceLockHolders(db.pool)).toEqual([]);
  });
});

describe('AC-P11-9: applied version without a file (database newer than the code)', () => {
  it('up and down -> exit 3 naming the version, nothing changed; status -> 0 and lists it as bilinmeyen; the startup check reports unknown_versions', async () => {
    const db = await newDb(); // migrated template: 001…latest
    await db.query(`INSERT INTO schema_migrations (version) VALUES ($1)`, [FUTURE]);
    const before = await schemaSnapshot(db);

    const up = await cli(['up'], { url: db.url });
    expect(up.code).toBe(MIGRATE_EXIT.rejected);
    expect(up.err.join('\n')).toContain(`bilinmeyen sürüm: ${FUTURE}`);
    const down = await cli(['down', '--to', '003'], { url: db.url });
    expect(down.code).toBe(MIGRATE_EXIT.rejected);
    expect(down.err.join('\n')).toContain(FUTURE);
    expect(await versions(db)).toEqual([...ALL, FUTURE]);
    expect(await schemaSnapshot(db)).toEqual(before);

    const status = await cli(['status'], { url: db.url });
    expect(status.code).toBe(0);
    expect(status.out.some((l) => new RegExp(`^bilinmeyen\\s+${FUTURE}\\s`).test(l) && l.includes('(dosyası yok)'))).toBe(true);
    expect(status.out).toContain(`özet: ${ALL.length} uygulanmış, 0 bekleyen, 1 bilinmeyen`);

    const c = await connect(db.url);
    try {
      expect(await checkMigrationsForStartup(c)).toMatchObject({ ok: false, reason: 'unknown_versions', versions: [FUTURE] });
    } finally {
      await c.end();
    }
  });
});

describe('AC-P11-5: status on an empty database', () => {
  it('does not create schema_migrations and lists every version as pending; the startup check says pending until up', async () => {
    const db = await newDb({ migrated: false });
    const run = await cli(['status'], { url: db.url });
    expect(run.code).toBe(0);
    expect(run.out[0]).toBe('schema_migrations tablosu yok; tüm sürümler bekleyen.');
    for (const v of ALL) expect(run.out.some((l) => new RegExp(`^bekleyen\\s+${v}$`).test(l))).toBe(true);
    expect(run.out).toContain(`özet: 0 uygulanmış, ${ALL.length} bekleyen, 0 bilinmeyen`);
    expect(await versions(db)).toBeNull();

    const c = await connect(db.url);
    try {
      const check = await checkMigrationsForStartup(c);
      expect(check).toMatchObject({ ok: false, reason: 'pending', versions: ALL });
      if (!check.ok) expect(check.message).toMatch(/npm run db:migrate/);
      expect(await versions(db)).toBeNull(); // the check never writes
      expect((await cli(['up'], { url: db.url })).code).toBe(0);
      expect(await checkMigrationsForStartup(c)).toEqual({ ok: true, applied: ALL });
    } finally {
      await c.end();
    }
  });
});

describe('AC-P11-4: atomic failure', () => {
  it('002 fails (1/0) -> exit 1, message names 002_ and SQLSTATE 22012, 002 rolled back with its row, 001 stays, 003 never tried', async () => {
    const dir = migDir({
      ...pair('001_good', 'CREATE TABLE qa_one (id int);', 'DROP TABLE qa_one;'),
      ...pair('002_broken', 'CREATE TABLE qa_two (id int);\nINSERT INTO qa_two VALUES (1);\nSELECT 1/0;\n', 'DROP TABLE qa_two;'),
      ...pair('003_after', 'CREATE TABLE qa_three (id int);', 'DROP TABLE qa_three;'),
    });
    const db = await newDb({ migrated: false });
    const run = await cli(['up'], { url: db.url, dir });
    expect(run.code).toBe(MIGRATE_EXIT.failure);
    const message = run.err.join('\n');
    expect(message).toMatch(/002_broken/);
    expect(message).toMatch(/\[22012\]/);
    expect(message).toMatch(/sonraki sürümler denenmedi/);
    expect(run.out).toEqual([expect.stringMatching(/^uygulandı 001_good \(\d+ ms\)$/)]);
    expect(await versions(db)).toEqual(['001_good']);
    expect(await tableExists(db, 'qa_one')).toBe(true);
    expect(await tableExists(db, 'qa_two')).toBe(false);
    expect(await tableExists(db, 'qa_three')).toBe(false);
  });
});

describe('AC-P11-13: BOM, CRLF and DO blocks', () => {
  it('a BOM + CRLF file with DO $$ … RAISE NOTICE is applied; the NOTICE goes to stdout; CRLF decodes like LF', async () => {
    const lf = "CREATE TABLE qa_crlf (id int);\nDO $$\nBEGIN\n  RAISE NOTICE 'qa notice %', 42;\nEND\n$$;\n";
    const crlfBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(lf.replace(/\n/g, '\r\n'), 'utf8')]);
    expect(decodeMigrationSql(crlfBom)).toBe(lf);
    const dir = migDir({ '001_crlf.up.sql': crlfBom, '001_crlf.down.sql': Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('DROP TABLE qa_crlf;\r\n', 'utf8')]) });
    const db = await newDb({ migrated: false });
    const run = await cli(['up'], { url: db.url, dir });
    expect(run.code, run.all).toBe(0);
    expect(run.out).toContain('NOTICE: qa notice 42');
    expect(await tableExists(db, 'qa_crlf')).toBe(true);
    const down = await cli(['down', '--to', '001'], { url: db.url, dir });
    expect(down.code).toBe(0); // nothing above 001
  });
});

describe('AC-P11-17: out-of-order pending version', () => {
  it('with 001…005 applied, a new 000_* file makes up exit 3 naming it; nothing applied; status marks it', async () => {
    const dir = copyOfRealMigrations();
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url, dir })).code).toBe(0);
    fs.writeFileSync(path.join(dir, '000_late_arrival.up.sql'), 'CREATE TABLE qa_late (id int);');
    fs.writeFileSync(path.join(dir, '000_late_arrival.down.sql'), 'DROP TABLE qa_late;');
    const run = await cli(['up'], { url: db.url, dir });
    expect(run.code).toBe(MIGRATE_EXIT.rejected);
    expect(run.err.join('\n')).toMatch(/Sıra dışı bekleyen sürüm: 000_late_arrival/);
    expect(await tableExists(db, 'qa_late')).toBe(false);
    expect(await versions(db)).toEqual(ALL);
    const status = await cli(['status'], { url: db.url, dir });
    expect(status.out.some((l) => l.includes('000_late_arrival') && l.includes('sıra dışı'))).toBe(true);
  });
});

describe('AC-P11-10: folder validation before any change', () => {
  const OK_DOWN = 'SELECT 1;';
  const REJECTED: Array<[string, Record<string, string | Buffer>, RegExp]> = [
    ['BEGIN; line', pair('001_a', 'BEGIN;\nCREATE TABLE x (id int);', OK_DOWN), /001_a\.up\.sql satır 1 \(transaction kontrolü\)/],
    ['commit ; (lower case, space)', pair('001_a', 'CREATE TABLE x (id int);\n  commit ;', OK_DOWN), /satır 2 \(transaction kontrolü\)/],
    ['START TRANSACTION;', pair('001_a', 'START TRANSACTION;', OK_DOWN), /transaction kontrolü/],
    ['ROLLBACK; in the down file', pair('001_a', 'SELECT 1;', 'ROLLBACK;'), /001_a\.down\.sql satır 1/],
    ['psql \\set', pair('001_a', '\\set ON_ERROR_STOP on\nSELECT 1;', OK_DOWN), /psql meta komutu/],
    ['upper case name', pair('001_Abc', 'SELECT 1;', OK_DOWN), /001_Abc\.up\.sql: dosya adı kurala uymuyor/],
    ['one-digit number', pair('1_a', 'SELECT 1;', OK_DOWN), /1_a\.up\.sql: dosya adı kurala uymuyor/],
    ['.SQL extension', { '001_a.up.SQL': 'SELECT 1;', '001_a.down.SQL': 'SELECT 1;' }, /001_a\.up\.SQL: dosya adı kurala uymuyor/],
    ['up without down', { '001_a.up.sql': 'SELECT 1;' }, /001_a: \.down\.sql eşi yok/],
    ['down without up', { '001_a.down.sql': 'SELECT 1;' }, /001_a: \.up\.sql eşi yok/],
    ['same number twice', { ...pair('002_a', 'SELECT 1;', OK_DOWN), ...pair('002_b', 'SELECT 1;', OK_DOWN) }, /numara 002 birden çok sürümde kullanılıyor: 002_a, 002_b/],
    ['invalid UTF-8', pair('001_a', Buffer.from([0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0xff, 0xfe, 0x3b]) as unknown as string, OK_DOWN), /001_a\.up\.sql: geçerli UTF-8 değil/],
  ];

  it.each(REJECTED)('%s -> invalid_directory', async (_label, files, detail) => {
    const dir = migDir(files);
    const err = await loadMigrations(dir).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MigrationRejectedError);
    expect((err as MigrationRejectedError).code).toBe('invalid_directory');
    expect((err as MigrationRejectedError).details.join('\n')).toMatch(detail);
  });

  it('a missing folder -> invalid_directory; all problems of a folder are reported together', async () => {
    const missing = await loadMigrations(path.join(tmpBase, 'does-not-exist')).catch((e: unknown) => e);
    expect(missing).toMatchObject({ code: 'invalid_directory' });
    const many = await loadMigrations(migDir({ ...pair('001_a', 'BEGIN;', OK_DOWN), 'X_b.up.sql': '' })).catch((e: unknown) => e);
    expect((many as MigrationRejectedError).details).toHaveLength(2);
  });

  it('accepted: DO $$ BEGIN … END $$ blocks, END; inside PL/pgSQL, a commented "-- BEGIN;", and non-.sql files', async () => {
    const up = [
      '-- BEGIN;',
      '-- COMMIT;',
      'DO $$',
      'BEGIN',
      '  IF true THEN',
      '    RAISE NOTICE \'ok\';',
      '  END IF;',
      'END',
      '$$;',
      'DO $$ BEGIN PERFORM 1; END $$;',
      'CREATE FUNCTION qa_f() RETURNS int LANGUAGE plpgsql AS $f$',
      'BEGIN',
      '  RETURN 1;',
      'END;',
      '$f$;',
    ].join('\n');
    expect(findForbiddenStatements(up)).toEqual([]);
    const dir = migDir({ ...pair('001_ok', up, 'DROP FUNCTION qa_f();'), 'README.md': 'BEGIN;\n\\set x' });
    const migrations = await loadMigrations(dir);
    expect(migrations.map((m) => m.version)).toEqual(['001_ok']);
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url, dir })).code).toBe(0);
  });

  it('through the CLI: a file with BEGIN; and (separately) one with \\set -> exit 3 before connecting; nothing changed', async () => {
    const db = await newDb({ migrated: false });
    const factory = vi.fn((config: ClientConfig) => new Client(config));
    for (const files of [pair('001_a', 'BEGIN;\nSELECT 1;', OK_DOWN), pair('001_a', '\\set x 1\nSELECT 1;', OK_DOWN)]) {
      const run = await cli(['up'], { url: db.url, dir: migDir(files), clientFactory: factory });
      expect(run.code).toBe(MIGRATE_EXIT.rejected);
      expect(run.err.join('\n')).toMatch(/hiçbir değişiklik yapılmadı/);
    }
    expect(factory).not.toHaveBeenCalled();
    expect(await versions(db)).toBeNull();
  });
});

describe('AC-P11-12: connection errors never print the password, host, port or database name', () => {
  const WRONG = 'Wr0ng-QA-Password-not-a-secret';

  function expectNoConnectionDetails(run: CliRun, db: ScratchDatabase, extra: string[] = []): void {
    const { password, host, port } = db.cluster;
    for (const needle of [password, encodeURIComponent(password), host, String(port), db.name, db.url, ...extra]) {
      expect(run.all.includes(needle), `output contains "${needle === password ? '<password>' : needle}"`).toBe(false);
    }
  }

  it('wrong password -> exit 1, 28P01 explained, no password/host/database in the output', async () => {
    const db = await newDb();
    const run = await cli(['status'], { url: urlWith(db, { password: WRONG }) });
    expect(run.code).toBe(MIGRATE_EXIT.failure);
    expect(run.err.join('\n')).toMatch(/Veritabanına bağlanılamadı \(28P01\): parola doğrulaması başarısız/);
    expectNoConnectionDetails(run, db, [WRONG]);
  });

  it('closed port -> exit 1 with ECONNREFUSED', async () => {
    const db = await newDb();
    const port = await freePort();
    const run = await cli(['up'], { url: urlWith(db, { port }) });
    expect(run.code).toBe(MIGRATE_EXIT.failure);
    expect(run.err.join('\n')).toMatch(/\(ECONNREFUSED\)/);
    expectNoConnectionDetails(run, db, [String(port)]);
  });

  it('database does not exist -> exit 1 with 3D000, the name is not printed', async () => {
    const db = await newDb();
    const missing = `qa_missing_${crypto.randomBytes(4).toString('hex')}`;
    const run = await cli(['status'], { url: urlWith(db, { database: missing }) });
    expect(run.code).toBe(MIGRATE_EXIT.failure);
    expect(run.err.join('\n')).toMatch(/\(3D000\): veritabanı yok/);
    expectNoConnectionDetails(run, db, [missing]);
  });
});

describe('AC-P11-16: db/schema.sql reference snapshot', () => {
  it('loaded into an empty database it yields the same tables/columns as every migration (001…latest)', async () => {
    const migrated = await newDb({ migrated: false });
    expect((await cli(['up'], { url: migrated.url })).code).toBe(0);
    const fromSchema = await newDb({ migrated: false });
    const c = await connect(fromSchema.url);
    try {
      await c.query(decodeMigrationSql(fs.readFileSync(path.join(REPO_ROOT, 'db', 'schema.sql'))));
    } finally {
      await c.end();
    }
    const a = await schemaSnapshot(migrated);
    const b = await schemaSnapshot(fromSchema);
    expect(b.columns).toEqual(a.columns);
    expect(b.types).toEqual(a.types);
  });
});

describe('ADR-004 implementer warning 1: migration SQL goes through the simple query protocol', () => {
  it('every migration file is sent with a single-argument client.query(sql) (up and down); bookkeeping uses parameters', async () => {
    const db = await newDb({ migrated: false });
    const c = await connect(db.url);
    const calls: unknown[][] = [];
    const recorder: MigrationClient = {
      query: (...args: unknown[]) => {
        calls.push(args);
        return (c.query as (...a: unknown[]) => Promise<{ rows: unknown[] }>)(...args);
      },
    };
    try {
      const migrations = await loadMigrations();
      expect(migrations.map((m) => m.version)).toEqual(ALL);
      await migrateUp(recorder, migrations);
      await migrateDown(recorder, migrations, '001');
      for (const m of migrations) {
        const upCalls = calls.filter((a) => a[0] === m.upSql);
        expect(upCalls, m.version).toHaveLength(1);
        expect(upCalls[0]).toHaveLength(1);
        if (m.number !== '001') {
          const downCalls = calls.filter((a) => a[0] === m.downSql);
          expect(downCalls, m.version).toHaveLength(1);
          expect(downCalls[0]).toHaveLength(1);
        }
      }
      const bookkeeping = calls.filter((a) => typeof a[0] === 'string' && /INTO schema_migrations|FROM schema_migrations WHERE/.test(a[0]));
      expect(bookkeeping.length).toBeGreaterThan(0);
      for (const call of bookkeeping) expect(call[1]).toEqual([expect.stringMatching(/^\d{3}_/)]);
    } finally {
      await c.end();
    }
  });
});

describe('AC-P11-15 / applied migrations are immutable', () => {
  // Normalized content (BOM removed, CRLF -> LF): checkout line endings do not matter.
  const FROZEN: Record<string, string> = {
    '001_initial_core_schema.up.sql': '14f32bc30ac7bf50f2c89e27c74da313517b2e8baff094f4d67f79884b80e5ac',
    '001_initial_core_schema.down.sql': '41606c5b8d10fe64dc946f87e30a54c6a844782e230b19ce5a763ba48d5ad895',
    '002_local_auth.up.sql': 'e2e6eda418fa6bdc3e73c92d651ec27ca56b86f7ca931a5e4ae4cdd82a516647',
    '002_local_auth.down.sql': '43a6a040261809eb07cbc64b2f18d4878be63c37df7a295981b590c509115dd7',
    '003_declared_range.up.sql': 'd23f4be30b77a83b5a3efc33326d111567631801c04ecf0c8c5f31b00a9f0c82',
    '003_declared_range.down.sql': 'e3f190dc9579bf14742d165d6c90d2e5a2d4f82480616e0faa32e1764f47229a',
    '004_finding_fingerprint.up.sql': 'e5fdbbdcb8d54d81dc792b2464bff79c95bdc36c00395884f70be4b6635afbe1',
    '004_finding_fingerprint.down.sql': '9708def3bd9acbfe38f9067c7244dfeb3111f60376ece06b5b766ffe03b59fdf',
    '005_scan_next_attempt.up.sql': '452d55a75895bba91675509ddb4b326681958ff170c106801afc747263e17240',
    '005_scan_next_attempt.down.sql': '4e24e0aaacf81ccc18f54ed445f61783b0c554653cc4426209705bb7a0a092b6',
    // REQ-004 AC-G-7: frozen once REQ-004 ships (QA batch B).
    '006_registry_enrichment.up.sql': '4fa782f6a5f01c9562bea6d533fdd24c8f3c071c9d2130bedbd6f7edd4a14a85',
    '006_registry_enrichment.down.sql': '36b32e6e35b8ba193fef5a2221010eea3af8ce31aac5c91c8574ea8a0181ee79',
    // REQ-005 AC-G-7: frozen with the 007 commit (32a6ee2).
    '007_vulnerability_recheck.up.sql': '6147d9288c2147b008bcb9a1f4a0f5bf6969ab1546bb7261fa2b6d4d3969f4c8',
    '007_vulnerability_recheck.down.sql': '39305662c8c90d6e69ed7a2c0bdd2202cbf968359082bd1ff599bb973f079835',
    // REQ-006 AC-G-7: frozen with the 008 commit (6f4701d).
    '008_nuget_enrichment.up.sql': 'e1d27b34b66f60afe3f1d964c9d59e1caf76fbfa56e2ad4ce685404ceafea6e0',
    '008_nuget_enrichment.down.sql': '65c9ca47d63dd2836012ee26fb46bbd7531d549fc6b906a501d075a16b7d383f',
  };

  it('AC-G-7 (REQ-004, REQ-005, REQ-006): 001…008 keep their normalized SHA-256 (a released migration is never edited; add a new one instead)', () => {
    const actual = Object.fromEntries(
      Object.keys(FROZEN).map((name) => [
        name,
        crypto.createHash('sha256').update(decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, name))), 'utf8').digest('hex'),
      ]),
    );
    expect(actual).toEqual(FROZEN);
    expect(migrationVersions().slice(0, 8)).toEqual(ALL.slice(0, 8));
    expect(migrationVersions()).toEqual(ALL); // ALL above lists every real migration
  });

  it('db/migrate.sh is gone (AC-P11-15, AC-G-6)', () => {
    expect(fs.existsSync(path.join(REPO_ROOT, 'db', 'migrate.sh'))).toBe(false);
  });
});

describe('AC-P11-1 / AC-P11-12 / AC-P11-18: the compiled CLI as a real node process', () => {
  let cliDir = '';
  let migrateJs = '';

  /** Transpiles src/db/{migrate,migrator,advisoryLock}.ts to CommonJS under <cliDir>/dist/db (dotenv/pg resolved from the repo). */
  beforeAll(() => {
    cliDir = fs.mkdtempSync(path.join(tmpBase, 'compiled-'));
    const outDir = path.join(cliDir, 'dist', 'db');
    fs.mkdirSync(outDir, { recursive: true });
    const req = createRequire(path.join(REPO_ROOT, 'package.json'));
    const external: Record<string, string> = { dotenv: req.resolve('dotenv'), pg: req.resolve('pg') };
    for (const name of ['migrate.ts', 'migrator.ts', 'advisoryLock.ts']) {
      const out = ts.transpileModule(fs.readFileSync(path.join(REPO_ROOT, 'src', 'db', name), 'utf8'), {
        fileName: name,
        compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
      });
      const js = out.outputText.replace(/require\("([^"]+)"\)/g, (whole, spec: string) => {
        if (spec.startsWith('node:') || spec.startsWith('./')) return whole;
        if (external[spec]) return `require(${JSON.stringify(external[spec])})`;
        throw new Error(`${name}: unexpected runtime import ${spec}`);
      });
      fs.writeFileSync(path.join(outDir, name.replace(/\.ts$/, '.js')), js);
    }
    // dist/db/migrate.js resolves ../../db/migrations, like the real build output.
    fs.mkdirSync(path.join(cliDir, 'db'));
    fs.cpSync(MIGRATIONS_DIR, path.join(cliDir, 'db', 'migrations'), { recursive: true });
    migrateJs = path.join(outDir, 'migrate.js');
  });

  function runNode(args: string[], options: { databaseUrl?: string; cwd?: string } = {}) {
    const env: NodeJS.ProcessEnv = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (!/^(DATABASE_URL|PG[A-Z]*)$/.test(k)) env[k] = v;
    }
    if (options.databaseUrl) env.DATABASE_URL = options.databaseUrl;
    // cwd = an empty temp folder: dotenv must not pick up the developer's .env.
    const cwd = options.cwd ?? fs.mkdtempSync(path.join(tmpBase, 'cwd-'));
    const res = spawnSync(process.execPath, [migrateJs, ...args], { cwd, env, encoding: 'utf8', timeout: 60_000 });
    return { code: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  it('without DATABASE_URL (and no .env) -> exit 2 with a hint, no stack trace', () => {
    const res = runNode(['status']);
    expect(res.code).toBe(2);
    expect(res.stderr).toMatch(/DATABASE_URL tanımlı değil/);
    expect(res.stderr).not.toMatch(/\n\s+at\s/);
  });

  it('unknown command -> 2; --help -> 0', () => {
    expect(runNode(['frobnicate']).code).toBe(2);
    const help = runNode(['--help']);
    expect(help.code).toBe(0);
    expect(help.stdout).toMatch(/Kullanım: npm run db:migrate/);
  });

  it('up on an empty database -> 0 and exits on its own; status reads DATABASE_URL from .env in the working directory', async () => {
    const db = await newDb({ migrated: false });
    const up = runNode([], { databaseUrl: db.url });
    expect(up.code, up.stderr).toBe(0);
    for (const v of ALL) expect(up.stdout).toContain(`uygulandı ${v}`);
    expect(await versions(db)).toEqual(ALL);

    const cwd = fs.mkdtempSync(path.join(tmpBase, 'envcwd-'));
    fs.writeFileSync(path.join(cwd, '.env'), `DATABASE_URL=${db.url}\n`);
    const status = runNode(['status'], { cwd });
    expect(status.code, status.stderr).toBe(0);
    expect(status.stdout).toContain(`özet: ${ALL.length} uygulanmış, 0 bekleyen, 0 bilinmeyen`);
    expect(status.stdout + status.stderr).not.toContain(db.cluster.password);
  });
});

describe('REQ-008 AC-G-3: migration 009_web_scan (contract REQ-008 1.0.0 §2; ADR-010 Karar 1, 2)', () => {
  const V009 = '009_web_scan';
  const WEB_COLUMNS: Array<[string, string]> = [
    ['projects', 'web_url'],
    ['projects', 'web_scan_mode'],
    ['scans', 'scan_kind'],
    ['scans', 'target_url'],
    ['scans', 'web_summary'],
  ];

  it('up -> down --to 008 (deletes web scans only, restores exactly the 008 schema) -> up yields the identical schema', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const full = await schemaSnapshot(db);
    for (const [t, c] of WEB_COLUMNS) expect(await columnExists(db, t, c), `${t}.${c}`).toBe(true);
    for (const t of ['web_findings', 'web_scan_components']) expect(await tableExists(db, t), t).toBe(true);

    // Existing scans default to 'dependency'; the kind/target CHECK binds both ways.
    const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, web_url) VALUES ('qa-009', 'https://app.local/') RETURNING id`);
    await db.query(`INSERT INTO scans (project_id, trigger) VALUES ($1, 'manual')`, [p.id]);
    const [web] = await db.query<{ id: string }>(`INSERT INTO scans (project_id, trigger, scan_kind, target_url) VALUES ($1, 'manual', 'web', 'https://app.local/') RETURNING id`, [p.id]);
    expect((await pgError(db.query(`INSERT INTO scans (project_id, trigger, scan_kind) VALUES ($1, 'manual', 'web')`, [p.id]))).constraint).toBe('scans_web_target_chk');
    expect((await pgError(db.query(`INSERT INTO scans (project_id, trigger, target_url) VALUES ($1, 'manual', 'https://x/')`, [p.id]))).constraint).toBe('scans_web_target_chk');
    expect((await pgError(db.query(`UPDATE projects SET web_scan_mode = 'loud' WHERE id = $1`, [p.id]))).constraint).toBe('projects_web_scan_mode_chk');
    await db.query(
      `INSERT INTO web_findings (scan_id, project_id, rule_id, source, category, severity, title, description, recommendation, fingerprint)
       VALUES ($1, $2, 'WEB-HDR-001', 'builtin', 'headers', 'medium', 't', 'd', 'r', $3)`,
      [web.id, p.id, 'a'.repeat(64)],
    );
    expect((await pgError(db.query(
      `INSERT INTO web_findings (scan_id, project_id, rule_id, source, category, severity, title, description, recommendation, fingerprint)
       VALUES ($1, $2, 'NOT-A-RULE', 'builtin', 'headers', 'medium', 't', 'd', 'r', $3)`,
      [web.id, p.id, 'b'.repeat(64)],
    ))).constraint).toBe('web_findings_rule_id_chk');

    const ref = copyOfRealMigrations();
    // 009 and every later migration removed (REQ-011 added 010 on top).
    for (const v of ALL.slice(8)) for (const f of [`${v}.up.sql`, `${v}.down.sql`]) fs.rmSync(path.join(ref, f));
    const at008Db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: at008Db.url, dir: ref })).code).toBe(0);
    const at008 = await schemaSnapshot(at008Db);

    const down = await cli(['down', '--to', '008'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    expect(down.out).toContain(`geri alınacak (sırayla): ${ALL.slice(8).reverse().join(', ')}`);
    expect(down.out).toContain(`Tamam: ${ALL.length - 8} göç geri alındı; son uygulanmış sürüm 008_nuget_enrichment.`);
    expect(await schemaSnapshot(db)).toEqual(at008);
    // Web scans are deleted; the dependency scan and the project stay.
    expect(await db.query(`SELECT id FROM scans WHERE id = $1`, [web.id])).toEqual([]);
    expect((await db.query(`SELECT id FROM scans WHERE project_id = $1`, [p.id])).length).toBe(1);
    expect(typesBefore010(full.types)).toEqual(at008.types);

    const again = await cli(['up'], { url: db.url });
    expect(again.code, again.all).toBe(0);
    expect(await versions(db)).toEqual(ALL);
    expect(await schemaSnapshot(db)).toEqual(full);
  });

  it('db/schema.sql equals 001…009 including the CHECK constraints and column comments of 009', async () => {
    const migrated = await newDb({ migrated: false });
    expect((await cli(['up'], { url: migrated.url })).code).toBe(0);
    const fromSchema = await newDb({ migrated: false });
    const c = await connect(fromSchema.url);
    try {
      await c.query(decodeMigrationSql(fs.readFileSync(path.join(REPO_ROOT, 'db', 'schema.sql'))));
    } finally {
      await c.end();
    }
    expect(await schemaSnapshot(fromSchema)).toEqual(await schemaSnapshot(migrated));
    for (const [t, col] of WEB_COLUMNS) {
      expect(await columnComment(fromSchema, t, col), `${t}.${col}`).toBe(await columnComment(migrated, t, col));
      expect(await columnComment(migrated, t, col), `${t}.${col}`).toEqual(expect.any(String));
    }
    const upText = decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, `${V009}.up.sql`)));
    expect(findForbiddenStatements(upText)).toEqual([]);
    const downText = decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, `${V009}.down.sql`)));
    expect(findForbiddenStatements(downText)).toEqual([]);
    expect(downText).toMatch(/DATA LOSS/);
    expect(downText).toMatch(/explicit human approval/);
  });
});

describe('REQ-011 AC-P40-1 / AC-P43-1 / AC-P43-2: migration 010_new_ecosystems (ADR-012 Karar 4; D-300, D-318)', () => {
  const V009 = '009_web_scan';
  const V010 = '010_new_ecosystems';

  async function checkDefs(db: ScratchDatabase): Promise<Record<string, string>> {
    const rows = await db.query<{ conname: string; def: string }>(
      `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
        WHERE connamespace = 'public'::regnamespace
          AND conname IN ('registry_package_cache_ecosystem_check', 'registry_archive_cache_ecosystem_check', 'scan_dependencies_license_source_check')`,
    );
    return Object.fromEntries(rows.map((r) => [r.conname, r.def]));
  }
  const values = (def: string | undefined): string[] => [...(def ?? '').matchAll(/'([^']+)'::text/g)].map((m) => m[1]).sort();

  async function enumLabels(db: ScratchDatabase): Promise<string[]> {
    const [row] = await db.query<{ labels: string[] }>(
      `SELECT array_agg(e.enumlabel::text ORDER BY e.enumsortorder) AS labels
         FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid
        WHERE t.typname = 'tech_ecosystem' AND t.typnamespace = 'public'::regnamespace`,
    );
    return row.labels;
  }

  /** project + completed scan + one package / scan dependency / finding / scan file / catalog row per ecosystem; returns the project id. */
  async function seed(db: ScratchDatabase, ecosystems: string[]): Promise<string> {
    const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name) VALUES ('qa-010') RETURNING id`);
    const [s] = await db.query<{ id: string }>(
      `INSERT INTO scans (project_id, trigger, status, ref, completed_at) VALUES ($1, 'manual', 'completed', 'main', NOW()) RETURNING id`,
      [p.id],
    );
    for (const eco of ecosystems) {
      await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, $2::tech_ecosystem)`, [p.id, eco]);
      const [pkg] = await db.query<{ id: string }>(
        `INSERT INTO packages (ecosystem, name, version, purl) VALUES ($1::tech_ecosystem, $2, '1.0.0', $3) RETURNING id`,
        [eco, `qa-${eco}`, `pkg:generic/qa-${eco}@1.0.0`],
      );
      const [dep] = await db.query<{ id: string }>(
        `INSERT INTO scan_dependencies (scan_id, package_id, manifest_file, manifest_path, license_source, license_enrichment_status)
         VALUES ($1, $2, 'm', '.', $3, $4) RETURNING id`,
        [s.id, pkg.id, ...(eco === 'go' || eco === 'rust' ? ['registry:depsdev', 'ok'] : ['none', 'no_license'])],
      );
      await db.query(
        `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, fingerprint) VALUES ($1, $2, 'license', $3)`,
        [s.id, dep.id, crypto.createHash('sha256').update(eco).digest('hex')],
      );
      await db.query(
        `INSERT INTO scan_files (scan_id, filename, file_path, ecosystem, file_hash) VALUES ($1, 'm', 'm', $2::tech_ecosystem, 'h')`,
        [s.id, eco],
      );
      await db.query(
        `INSERT INTO vulnerabilities (osv_id, title, affected_ecosystem, affected_package, severity) VALUES ($1, 't', $2::tech_ecosystem, $3, 'low')`,
        [`QA-010-${eco}`, eco, `qa-${eco}`],
      );
    }
    return p.id;
  }

  it('up adds rust/dart/swift next to their neighbours and widens the package cache and license_source CHECKs', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    expect(await enumLabels(db)).toEqual(['nodejs', 'python', 'java', 'dotnet', 'go', 'php', 'rust', 'ruby', 'dart', 'swift', 'container', 'other']);
    const defs = await checkDefs(db);
    expect(values(defs.registry_package_cache_ecosystem_check)).toEqual(['depsdev', 'npm', 'nuget', 'pubdev', 'pypi']);
    expect(values(defs.registry_archive_cache_ecosystem_check)).toEqual(['npm', 'nuget', 'pypi']);
    expect(values(defs.scan_dependencies_license_source_check)).toEqual(
      ['lockfile (unverified)', 'none', 'registry:depsdev', 'registry:npm', 'registry:nuget', 'registry:pubdev', 'registry:pypi'],
    );
    // Every new value is usable after the migration's transaction.
    await seed(db, ['rust', 'dart', 'swift', 'java', 'go', 'php', 'ruby']);
    await db.query(
      `INSERT INTO registry_package_cache (ecosystem, name, version, outcome, declared_license, extractor_version)
       VALUES ('depsdev', 'GO:qa', '1.0.0', 'found', 'MIT', 1), ('pubdev', 'qa', '1.0.0', 'found', 'MIT', 1)`,
    );
    const rejected = await pgError(
      db.query(`INSERT INTO registry_package_cache (ecosystem, name, version, outcome, extractor_version) VALUES ('maven', 'qa', '1', 'found', 1)`),
    );
    expect(rejected.constraint).toBe('registry_package_cache_ecosystem_check');
  });

  it('down --to 009 deletes only rust/dart/swift data, restores exactly the 009 schema; up again yields the identical schema', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const full = await schemaSnapshot(db);
    const projectId = await seed(db, ['rust', 'dart', 'swift', 'java', 'go']);
    await db.query(
      `INSERT INTO registry_package_cache (ecosystem, name, version, outcome, declared_license, extractor_version)
       VALUES ('depsdev', 'GO:qa', '1.0.0', 'found', 'MIT', 1), ('npm', 'qa', '1.0.0', 'found', 'MIT', 1)`,
    );

    const ref = copyOfRealMigrations();
    for (const v of ALL.slice(9)) for (const f of [`${v}.up.sql`, `${v}.down.sql`]) fs.rmSync(path.join(ref, f));
    const at009Db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: at009Db.url, dir: ref })).code).toBe(0);
    const at009 = await schemaSnapshot(at009Db);

    const down = await cli(['down', '--to', '009'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    expect(down.out).toContain(`geri alınacak (sırayla): ${ALL.slice(9).reverse().join(', ')}`);
    expect(down.out).toContain(`Tamam: ${ALL.length - 9} göç geri alındı; son uygulanmış sürüm ${V009}.`);
    expect(await schemaSnapshot(db)).toEqual(at009);
    expect(typesBefore010(full.types)).toEqual(at009.types);

    const ecosystemsOf = async (sql: string, params: unknown[] = []) =>
      (await db.query<{ ecosystem: string }>(sql, params)).map((r) => r.ecosystem);
    expect(await ecosystemsOf(`SELECT ecosystem::text AS ecosystem FROM packages ORDER BY 1`)).toEqual(['go', 'java']);
    expect(await ecosystemsOf(`SELECT ecosystem::text AS ecosystem FROM project_tech_stacks WHERE project_id = $1 ORDER BY 1`, [projectId])).toEqual(['go', 'java']);
    expect(await ecosystemsOf(`SELECT ecosystem::text AS ecosystem FROM scan_files ORDER BY 1`)).toEqual(['go', 'java']);
    expect((await db.query(`SELECT 1 FROM findings`)).length).toBe(2);
    expect(await db.query(`SELECT osv_id, affected_ecosystem::text AS eco FROM vulnerabilities ORDER BY osv_id`)).toEqual([
      { osv_id: 'QA-010-dart', eco: null },
      { osv_id: 'QA-010-go', eco: 'go' },
      { osv_id: 'QA-010-java', eco: 'java' },
      { osv_id: 'QA-010-rust', eco: null },
      { osv_id: 'QA-010-swift', eco: null },
    ]);
    expect((await db.query<{ license_source: string }>(`SELECT license_source FROM scan_dependencies ORDER BY 1`)).map((r) => r.license_source)).toEqual(['none', 'none']);
    expect(await ecosystemsOf(`SELECT ecosystem FROM registry_package_cache`)).toEqual(['npm']);

    const again = await cli(['up'], { url: db.url });
    expect(again.code, again.all).toBe(0);
    expect(await versions(db)).toEqual(ALL);
    expect(await schemaSnapshot(db)).toEqual(full);
  });

  it('db/schema.sql equals 001…010; the 010 files hold no transaction control and the down file names its data loss', async () => {
    const migrated = await newDb({ migrated: false });
    expect((await cli(['up'], { url: migrated.url })).code).toBe(0);
    const fromSchema = await newDb({ migrated: false });
    const c = await connect(fromSchema.url);
    try {
      await c.query(decodeMigrationSql(fs.readFileSync(path.join(REPO_ROOT, 'db', 'schema.sql'))));
    } finally {
      await c.end();
    }
    expect(await schemaSnapshot(fromSchema)).toEqual(await schemaSnapshot(migrated));
    const upText = decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, `${V010}.up.sql`)));
    expect(findForbiddenStatements(upText)).toEqual([]);
    const downText = decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, `${V010}.down.sql`)));
    expect(findForbiddenStatements(downText)).toEqual([]);
    expect(downText).toMatch(/DATA LOSS/);
    expect(downText).toMatch(/explicit human approval/);
  });
});
