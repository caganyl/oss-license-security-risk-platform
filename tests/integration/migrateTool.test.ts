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

const ALL = ['001_initial_core_schema', '002_local_auth', '003_declared_range', '004_finding_fingerprint', '005_scan_next_attempt'];
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
  it('status shows 001…004 applied (with applied_at) and 005 pending; up applies only 005, keeps data; a second up skips everything', async () => {
    const db = await f1Database();
    const before = await db.query<{ version: string; applied_at: Date }>('SELECT version, applied_at FROM schema_migrations ORDER BY version');
    expect(before.map((r) => r.version)).toEqual(ALL.slice(0, 4));
    const [project] = await db.query<{ id: string }>(`INSERT INTO projects (name) VALUES ('kept-across-005') RETURNING id`);

    const status = await cli(['status'], { url: db.url });
    expect(status.code).toBe(MIGRATE_EXIT.ok);
    for (const r of before) {
      expect(status.out.some((l) => l.startsWith('uygulanmış') && l.includes(r.version) && l.includes(r.applied_at.toISOString()))).toBe(true);
    }
    expect(status.out.some((l) => /^bekleyen\s+005_scan_next_attempt$/.test(l))).toBe(true);
    expect(status.out).toContain('özet: 4 uygulanmış, 1 bekleyen, 0 bilinmeyen');
    expect(await versions(db)).toEqual(ALL.slice(0, 4)); // status changed nothing

    const up = await cli([], { url: db.url }); // default command = up
    expect(up.code, up.all).toBe(MIGRATE_EXIT.ok);
    expect(up.out.slice(0, 4)).toEqual(ALL.slice(0, 4).map((v) => `atlandı ${v}`));
    expect(up.out[4]).toMatch(/^uygulandı 005_scan_next_attempt \(\d+ ms\)$/);
    expect(up.out).toContain('Tamam: 1 göç uygulandı, 4 atlandı.');
    expect(up.err).toEqual([]);

    const after = await db.query<{ version: string; applied_at: Date }>('SELECT version, applied_at FROM schema_migrations ORDER BY version');
    expect(after.map((r) => r.version)).toEqual(ALL);
    // 001…004 rows untouched, no table re-created (the project row survived).
    expect(after.slice(0, 4)).toEqual(before);
    expect(await db.query('SELECT id FROM projects WHERE id = $1', [project.id])).toHaveLength(1);
    expect(await columnExists(db, 'scans', 'next_attempt_at')).toBe(true);

    const again = await cli(['up'], { url: db.url });
    expect(again.code).toBe(MIGRATE_EXIT.ok);
    expect(again.out.slice(0, 5)).toEqual(ALL.map((v) => `atlandı ${v}`));
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

  it('AC-P11-7 / AC-P11-8: up -> down --to 003_declared_range (005 then 004, listed first) -> up restores the identical schema', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const full = await schemaSnapshot(db);

    const down = await cli(['down', '--to', '003_declared_range'], { url: db.url });
    expect(down.code, down.all).toBe(MIGRATE_EXIT.ok);
    const listed = down.out.findIndex((l) => l === 'geri alınacak (sırayla): 005_scan_next_attempt, 004_finding_fingerprint');
    const rev5 = down.out.findIndex((l) => /^geri alındı 005_scan_next_attempt \(\d+ ms\)$/.test(l));
    const rev4 = down.out.findIndex((l) => /^geri alındı 004_finding_fingerprint \(\d+ ms\)$/.test(l));
    expect(listed).toBeGreaterThanOrEqual(0);
    expect(rev5).toBeGreaterThan(listed);
    expect(rev4).toBeGreaterThan(rev5);
    expect(down.out).toContain('Tamam: 2 göç geri alındı; son uygulanmış sürüm 003_declared_range.');
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

describe('AC-P11-8: --to forms and targets', () => {
  it('--to 003 (number) equals --to 003_declared_range; --to=005 on the latest version is a no-op; --to 001 keeps 001 applied', async () => {
    const db = await newDb({ migrated: false });
    expect((await cli(['up'], { url: db.url })).code).toBe(0);

    const latest = await cli(['down', '--to=005'], { url: db.url });
    expect(latest.code).toBe(0);
    expect(latest.out.join('\n')).toMatch(/geri alınacak sürüm yok/);
    expect(await versions(db)).toEqual(ALL);

    const byNumber = await cli(['down', '--to', '003'], { url: db.url });
    expect(byNumber.code, byNumber.all).toBe(0);
    expect(await versions(db)).toEqual(ALL.slice(0, 3));

    expect((await cli(['up'], { url: db.url })).code).toBe(0);
    const toFirst = await cli(['down', '--to', '001'], { url: db.url });
    expect(toFirst.code, toFirst.all).toBe(0);
    expect(toFirst.out).toContain(
      'geri alınacak (sırayla): 005_scan_next_attempt, 004_finding_fingerprint, 003_declared_range, 002_local_auth',
    );
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
    const db = await newDb(); // migrated template: 001…005
    await db.query(`INSERT INTO schema_migrations (version) VALUES ('006_from_the_future')`);
    const before = await schemaSnapshot(db);

    const up = await cli(['up'], { url: db.url });
    expect(up.code).toBe(MIGRATE_EXIT.rejected);
    expect(up.err.join('\n')).toMatch(/bilinmeyen sürüm: 006_from_the_future/);
    const down = await cli(['down', '--to', '003'], { url: db.url });
    expect(down.code).toBe(MIGRATE_EXIT.rejected);
    expect(down.err.join('\n')).toMatch(/006_from_the_future/);
    expect(await versions(db)).toEqual([...ALL, '006_from_the_future']);
    expect(await schemaSnapshot(db)).toEqual(before);

    const status = await cli(['status'], { url: db.url });
    expect(status.code).toBe(0);
    expect(status.out.some((l) => /^bilinmeyen\s+006_from_the_future\s/.test(l) && l.includes('(dosyası yok)'))).toBe(true);
    expect(status.out).toContain('özet: 5 uygulanmış, 0 bekleyen, 1 bilinmeyen');

    const c = await connect(db.url);
    try {
      expect(await checkMigrationsForStartup(c)).toMatchObject({ ok: false, reason: 'unknown_versions', versions: ['006_from_the_future'] });
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
    expect(run.out).toContain('özet: 0 uygulanmış, 5 bekleyen, 0 bilinmeyen');
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
  it('loaded into an empty database it yields the same tables/columns as 001…005', async () => {
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
  };

  it('001…005 keep their normalized SHA-256 (a released migration is never edited; add a new one instead)', () => {
    const actual = Object.fromEntries(
      Object.keys(FROZEN).map((name) => [
        name,
        crypto.createHash('sha256').update(decodeMigrationSql(fs.readFileSync(path.join(MIGRATIONS_DIR, name))), 'utf8').digest('hex'),
      ]),
    );
    expect(actual).toEqual(FROZEN);
    expect(migrationVersions().slice(0, 5)).toEqual(ALL);
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
    expect(up.stdout).toMatch(/uygulandı 005_scan_next_attempt/);
    expect(await versions(db)).toEqual(ALL);

    const cwd = fs.mkdtempSync(path.join(tmpBase, 'envcwd-'));
    fs.writeFileSync(path.join(cwd, '.env'), `DATABASE_URL=${db.url}\n`);
    const status = runNode(['status'], { cwd });
    expect(status.code, status.stderr).toBe(0);
    expect(status.stdout).toMatch(/özet: 5 uygulanmış, 0 bekleyen, 0 bilinmeyen/);
    expect(status.stdout + status.stderr).not.toContain(db.cluster.password);
  });
});
