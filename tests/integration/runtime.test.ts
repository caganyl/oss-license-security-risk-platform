/**
 * REQ-003 · P-12 single-process runtime (AC-P12-1, 2, 4…11, 15; ADR-004
 * Karar 1–6, 9) against real embedded PostgreSQL (AC-G-4).
 *
 * The runtime is created in-process with `createRuntime(options)`; every
 * test injects `exit: vi.fn()` (the 15 s forced-exit timer must never reach
 * the real `process.exit`), a fixed free port (the Host allow-list is built
 * from `options.port`, so port 0 would reject every request), a capturing
 * logger, `checkGit` (no `git --version` child process) and fake
 * clone/parser/report-service unless the test needs the real parser thread.
 * The scan worker poll interval is lowered to 200 ms for this file
 * (`WORKER_POLL_INTERVAL_MS`, read when runner.config.ts is loaded).
 */
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Client, type ClientConfig, type Pool } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const savedPollInterval = vi.hoisted(() => {
  const previous = process.env.WORKER_POLL_INTERVAL_MS;
  process.env.WORKER_POLL_INTERVAL_MS = '200';
  return previous;
});

import { INSTANCE_LOCK_ID, INSTANCE_LOCK_NAMESPACE, findInstanceLockHolders, type LockClient } from '../../src/db/advisoryLock';
import { createPool } from '../../src/lib/db';
import type { ReportService } from '../../src/reports/reportService';
import {
  LOCK_HELD_MESSAGE,
  RuntimeStartupError,
  createRuntime,
  installProcessHandlers,
  type ProcessLike,
  type RuntimeHandle,
  type RuntimeOptions,
} from '../../src/runtime';
import { ORPHAN_RECOVERY_MESSAGE } from '../../src/scanner/retryPolicy';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import { useScratchDatabases, useTestDatabase, type ScratchDatabase } from '../helpers/db';
import { applyMigrations } from '../helpers/migrations';
import { FIXTURES_DIR } from '../helpers/paths';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const base = useTestDatabase({ scope: 'file', migrated: false });
const newDb = useScratchDatabases(base);

const LOCK_SQL = `SELECT pg_advisory_lock(${INSTANCE_LOCK_NAMESPACE}, ${INSTANCE_LOCK_ID})`;

let tmpBase = '';
const started: RuntimeHandle[] = [];
const openClients: Client[] = [];

beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p12-'));
});
afterAll(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
  if (savedPollInterval === undefined) delete process.env.WORKER_POLL_INTERVAL_MS;
  else process.env.WORKER_POLL_INTERVAL_MS = savedPollInterval;
});
beforeEach(() => {
  // OSV lookups of the real parser path answer "no vulnerabilities" (AC-G-4: no network).
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify({ vulns: [], results: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })),
  );
  // /health logs through console on a database error; keep the output quiet.
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
});
afterEach(async () => {
  for (const runtime of started.splice(0)) await runtime.shutdown('manual').catch(() => undefined);
  for (const c of openClients.splice(0)) await c.end().catch(() => undefined);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
interface Deferred<T = void> {
  promise: Promise<T>;
  resolve: (v: T) => void;
}
function deferred<T = void>(): Deferred<T> {
  let resolve: (v: T) => void = () => undefined;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

function canListen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

/** GET /health with the allowed Host header; resolves the status code, rejects when nothing listens. */
function health(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/health', agent: false }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
    req.setTimeout(5_000, () => req.destroy(new Error('health timeout')));
  });
}

function emptyResult(scanId: string): SandboxScanResult {
  return { scan_id: scanId, status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] };
}

interface Harness {
  runtime: RuntimeHandle;
  logs: string[];
  exit: ReturnType<typeof vi.fn<(code: number) => void>>;
  port: number;
  root: string;
}

interface HarnessOptions extends Partial<RuntimeOptions> {
  /** Report generation (default: marks the report ready). */
  processReport?: (id: string) => Promise<void>;
}

async function harness(db: ScratchDatabase, overrides: HarnessOptions = {}): Promise<Harness> {
  const logs: string[] = [];
  const push = (...a: unknown[]) => logs.push(a.map((x) => (x instanceof Error ? `${x.name}: ${x.message}` : String(x))).join(' '));
  const logger = { log: push, warn: push, error: push };
  const exit = vi.fn<(code: number) => void>();
  const port = overrides.port ?? (await freePort());
  const root = fs.mkdtempSync(path.join(tmpBase, 'root-'));
  const parser: RunParserFn = async (_dir, _eco, scanId) => emptyResult(scanId);
  const { processReport, ...rest } = overrides;
  const reportService = {
    processReport:
      processReport ??
      (async (id: string) => {
        await db.query(`UPDATE reports SET status = 'ready', completed_at = NOW() WHERE id = $1`, [id]);
      }),
  } as unknown as ReportService;
  const options: RuntimeOptions = {
    env: { DATABASE_URL: db.url },
    logger,
    exit,
    port,
    scanRoots: [root],
    tmpRoot: fs.mkdtempSync(path.join(tmpBase, 'tmp-')),
    heartbeatIntervalMs: 100,
    relockIntervalMs: 300,
    shutdownTimeoutMs: 10_000,
    reportDrainMs: 300,
    checkGit: async () => undefined,
    ...rest,
    scanWorker: { runParser: parser, logger, ...rest.scanWorker },
    exportWorker: {
      reportService,
      config: { maxConcurrentExports: 2, pollIntervalMs: 100, timeoutMs: 60_000 },
      logger,
      ...rest.exportWorker,
    },
  };
  const runtime = createRuntime(options);
  started.push(runtime);
  return { runtime, logs, exit, port, root };
}

async function connect(url: string): Promise<Client> {
  const c = new Client({ connectionString: url });
  c.on('error', () => undefined);
  await c.connect();
  openClients.push(c);
  return c;
}

async function insertProject(db: ScratchDatabase, repoUrl: string | null): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [
    `p-${Math.random().toString(36).slice(2)}`,
    repoUrl,
  ]);
  await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, 'nodejs')`, [p.id]);
  return p.id;
}

async function insertScan(
  db: ScratchDatabase,
  projectId: string,
  fields: { status?: string; retry_count?: number; worker_id?: string | null; error_message?: string | null } = {},
): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at, retry_count, worker_id, error_message, started_at)
     VALUES ($1, 'manual', $2::scan_status, 'main', NOW(), $3, $4, $5, CASE WHEN $2 = 'running' THEN NOW() END)
     RETURNING id`,
    [projectId, fields.status ?? 'pending', fields.retry_count ?? 0, fields.worker_id ?? null, fields.error_message ?? null],
  );
  return s.id;
}

async function insertReport(db: ScratchDatabase, status = 'pending'): Promise<string> {
  const [u] = await db.query<{ id: string }>(
    `INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id`,
    [`qa-${Math.random().toString(36).slice(2)}@example.test`],
  );
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO reports (report_type, format, status, requested_by) VALUES ('executive_summary', 'json', $1::report_status, $2) RETURNING id`,
    [status, u.id],
  );
  return r.id;
}

interface ScanRow {
  status: string;
  retry_count: number;
  worker_id: string | null;
  error_message: string | null;
  next_attempt_at: Date | null;
  backoff_seconds: number | null;
  completed_at: Date | null;
  total_dependencies: number;
  updated_at: Date;
}

async function scan(db: ScratchDatabase, id: string): Promise<ScanRow> {
  const [row] = await db.query<ScanRow>(
    `SELECT status::text, retry_count, worker_id, error_message, next_attempt_at, completed_at, total_dependencies, updated_at,
            EXTRACT(EPOCH FROM next_attempt_at - updated_at)::float8 AS backoff_seconds
     FROM scans WHERE id = $1`,
    [id],
  );
  return row;
}

async function reportStatus(db: ScratchDatabase, id: string): Promise<string> {
  const [row] = await db.query<{ status: string }>('SELECT status::text FROM reports WHERE id = $1', [id]);
  return row.status;
}

async function holders(db: ScratchDatabase): Promise<number[]> {
  return findInstanceLockHolders(db.pool);
}

/** Pool whose query/connect fail while `outage.on` (AC-P12-8); records pool.end. */
function outagePool(outage: { on: boolean }, events: string[]) {
  return (connectionString: string, logger: Pick<Console, 'log' | 'warn' | 'error'>): Pool => {
    const real = createPool({ connectionString, logger });
    const fail = () => Promise.reject(Object.assign(new Error('connect ECONNREFUSED (simulated outage)'), { code: 'ECONNREFUSED' }));
    return new Proxy(real, {
      get(target, prop) {
        if (outage.on && (prop === 'query' || prop === 'connect')) return fail;
        if (prop === 'end') {
          return () => {
            events.push('pool.end');
            return target.end();
          };
        }
        const value = Reflect.get(target, prop, target) as unknown;
        return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
      },
    });
  };
}

/** Lock connection factory that records the unlock statement. */
function recordingLockFactory(events: string[]) {
  return (config: ClientConfig): LockClient => {
    const c = new Client(config);
    const query = c.query.bind(c) as (...a: unknown[]) => Promise<unknown>;
    (c as unknown as { query: (...a: unknown[]) => Promise<unknown> }).query = (...a: unknown[]) => {
      if (typeof a[0] === 'string' && a[0].includes('pg_advisory_unlock')) events.push('unlock');
      return query(...a);
    };
    return c as unknown as LockClient;
  };
}

// ---------------------------------------------------------------------------
describe('AC-P12-1 / AC-P12-2 / AC-P12-6: one process runs the API and both workers', () => {
  it('starts in order, listens on 127.0.0.1 only, /health 200; a queued local scan (real parser thread) completes and a pending report becomes ready', async () => {
    const db = await newDb();
    const fixture = path.join(FIXTURES_DIR, 'p05-ranges-no-lockfile');
    const scanId = await insertScan(db, await insertProject(db, fixture), { status: 'queued' });
    const reportId = await insertReport(db);
    const { runtime, logs, exit, port } = await harness(db, { scanRoots: [fixture], scanWorker: { runParser: undefined } }); // default: real parser thread

    await runtime.start();
    expect(runtime.state).toBe('running');
    expect(runtime.address).toMatchObject({ address: '127.0.0.1', port });
    expect(runtime.scanWorker).not.toBeNull();
    expect(runtime.exportWorker).not.toBeNull();
    expect(await health(port)).toBe(200);

    await vi.waitFor(async () => expect((await scan(db, scanId)).status).toBe('completed'), { timeout: 30_000, interval: 100 });
    await vi.waitFor(async () => expect(await reportStatus(db, reportId)).toBe('ready'), { timeout: 10_000, interval: 100 });
    const done = await scan(db, scanId);
    expect(done.total_dependencies).toBeGreaterThan(0);
    expect(done.worker_id).toBe(runtime.runId); // per-process run id, no WORKER_ID env (AC-P12-3)

    const at = (re: RegExp) => logs.findIndex((l) => re.test(l));
    expect(at(new RegExp(`^API dinliyor: http://127\\.0\\.0\\.1:${port}$`))).toBeGreaterThanOrEqual(0);
    expect(at(/^Tarama worker'ı başladı/)).toBeGreaterThan(at(/^API dinliyor/));
    expect(at(/^Rapor worker'ı başladı/)).toBeGreaterThan(at(/^API dinliyor/));
    expect(at(/^Uygulama hazır/)).toBeGreaterThan(at(/^Rapor worker'ı başladı/));

    // The lock lives on its own connection; the pool uses another application_name.
    const lockPid = runtime.lock?.backendPid;
    expect(await holders(db)).toEqual([lockPid]);
    const apps = await db.query<{ pid: number; application_name: string }>(
      `SELECT pid, application_name FROM pg_stat_activity WHERE datname = current_database() AND application_name LIKE 'oss-risk:%'`,
    );
    expect(apps.find((a) => a.pid === lockPid)?.application_name).toBe('oss-risk:instance');
    expect(apps.some((a) => a.application_name === 'oss-risk:app')).toBe(true);

    expect(await runtime.shutdown('manual')).toBe(0);
    expect(await holders(db)).toEqual([]);
    expect(exit).not.toHaveBeenCalled();
  });
});

describe('AC-P12-4: single instance per database (D-34)', () => {
  it('a second runtime on the same database refuses with exit 1 and the lock message; the first keeps serving and holding the lock', async () => {
    const db = await newDb();
    const first = await harness(db);
    await first.runtime.start();
    const second = await harness(db);

    const err = await second.runtime.start().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RuntimeStartupError);
    expect(err).toMatchObject({ exitCode: 1, message: LOCK_HELD_MESSAGE });
    expect(second.runtime.state).toBe('failed');
    expect(second.runtime.server).toBeNull();
    expect(await canListen(second.port)).toBe(true);
    expect(second.exit).not.toHaveBeenCalled();

    expect(await health(first.port)).toBe(200);
    expect(first.runtime.state).toBe('running');
    expect(await holders(db)).toEqual([first.runtime.lock?.backendPid]);
  });
});

describe('AC-P12-5 / D-35: migration check at start-up (never applies)', () => {
  it('pending 005 -> exit 1 naming npm run db:migrate; nothing listens, nothing applied, lock released', async () => {
    const db = await newDb({ migrated: false });
    const c = await connect(db.url);
    await applyMigrations(c, { through: '004_finding_fingerprint' });
    const { runtime, port } = await harness(db);

    const err = await runtime.start().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RuntimeStartupError);
    expect((err as RuntimeStartupError).exitCode).toBe(1);
    expect((err as Error).message).toMatch(/Bekleyen göç var: 005_scan_next_attempt\. Önce `npm run db:migrate` çalıştırın\./);
    expect(await canListen(port)).toBe(true);
    expect((await db.query('SELECT version FROM schema_migrations')).length).toBe(4);
    expect(await holders(db)).toEqual([]);
  });

  it('a version unknown to the code -> exit 1 (database newer than the code)', async () => {
    const db = await newDb();
    await db.query(`INSERT INTO schema_migrations (version) VALUES ('006_from_the_future')`);
    const { runtime } = await harness(db);
    const err = await runtime.start().catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 1 });
    expect((err as Error).message).toMatch(/bilinmeyen sürüm: 006_from_the_future/);
    expect(await holders(db)).toEqual([]);
  });
});

describe('AC-P12-6: early failures close what was opened and change no row', () => {
  it('D-52 / REQ-002 AC-P09-3: DATABASE_URL missing -> exit 1 naming the variable, no connection attempted', async () => {
    const db = await newDb();
    const factory = vi.fn((config: ClientConfig) => new Client(config) as unknown as LockClient);
    for (const env of [{}, { DATABASE_URL: '  ' }]) {
      const { runtime } = await harness(db, { env, lockClientFactory: factory });
      const err = await runtime.start().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RuntimeStartupError);
      expect((err as Error).message).toMatch(/DATABASE_URL/);
    }
    expect(factory).not.toHaveBeenCalled();
  });

  async function seedUntouchable(db: ScratchDatabase) {
    const projectId = await insertProject(db, null);
    const orphan = await insertScan(db, projectId, { status: 'running', worker_id: 'previous-run', retry_count: 0 });
    const queued = await insertScan(db, projectId, { status: 'queued' });
    const report = await insertReport(db, 'generating');
    const snapshot = async () => ({
      scans: await db.query('SELECT id, status::text, retry_count, worker_id, error_message, next_attempt_at, updated_at FROM scans ORDER BY id'),
      reports: await db.query('SELECT id, status::text, error_message FROM reports ORDER BY id'),
      audit: await db.query('SELECT count(*)::int AS n FROM audit_logs'),
    });
    return { orphan, queued, report, before: await snapshot(), snapshot };
  }

  it('port already in use -> exit 1; the orphaned running scan, the queued scan and the generating report are untouched (recovery runs after listen)', async () => {
    const db = await newDb();
    const seed = await seedUntouchable(db);
    const blocker = net.createServer();
    const port = await freePort();
    await new Promise<void>((r) => blocker.listen(port, '127.0.0.1', () => r()));
    try {
      const { runtime } = await harness(db, { port });
      const err = await runtime.start().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RuntimeStartupError);
      expect((err as Error).message).toMatch(/HTTP sunucusu 127\.0\.0\.1 üzerinde dinleyemedi \(EADDRINUSE\)/);
      expect(runtime.scanWorker).toBeNull();
      expect(await seed.snapshot()).toEqual(seed.before);
      expect(await holders(db)).toEqual([]);
    } finally {
      await new Promise<void>((r) => blocker.close(() => r()));
    }
  });

  it('invalid SCAN_ROOTS -> exit 1 before listening; nothing changed, lock released', async () => {
    const db = await newDb();
    const seed = await seedUntouchable(db);
    const { runtime, port } = await harness(db, { scanRoots: [path.join(tmpBase, 'no-such-root')] });
    const err = await runtime.start().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RuntimeStartupError);
    expect((err as Error).message).toMatch(/^SCAN_ROOTS geçersiz/);
    expect(await canListen(port)).toBe(true);
    expect(await seed.snapshot()).toEqual(seed.before);
    expect(await holders(db)).toEqual([]);
  });
});

describe('AC-P12-11 / D-41: orphaned scan recovery at start-up', () => {
  it('running scans of another run id are recovered as transient failures (retry with backoff, or failed + scan_failed); generating reports -> failed', async () => {
    const db = await newDb();
    const projectId = await insertProject(db, null);
    const retryable = await insertScan(db, projectId, { status: 'running', worker_id: 'some-other-run', retry_count: 0 });
    const exhausted = await insertScan(db, projectId, { status: 'running', worker_id: null, retry_count: 2 });
    const report = await insertReport(db, 'generating');
    const parser = vi.fn<RunParserFn>(async (_d, _e, id) => emptyResult(id));
    const { runtime } = await harness(db, { scanWorker: { runParser: parser } });

    await runtime.start();
    const r = await scan(db, retryable);
    expect(r).toMatchObject({ status: 'queued', retry_count: 1, worker_id: null, error_message: ORPHAN_RECOVERY_MESSAGE });
    expect(r.backoff_seconds).toBe(30);
    const x = await scan(db, exhausted);
    expect(x).toMatchObject({ status: 'failed', retry_count: 2, next_attempt_at: null, error_message: ORPHAN_RECOVERY_MESSAGE });
    expect(x.completed_at).not.toBeNull();
    expect(await db.query(`SELECT 1 FROM audit_logs WHERE action = 'scan_failed' AND entity_id = $1`, [exhausted])).toHaveLength(1);
    expect(await reportStatus(db, report)).toBe('failed');

    await sleep(600); // three polls: the backoff keeps the recovered scan unclaimed
    expect((await scan(db, retryable)).status).toBe('queued');
    expect(parser).not.toHaveBeenCalled();
  });
});

describe('AC-P12-7 / AC-P12-8: job and database failures do not stop the process', () => {
  it('AC-P12-7: a permanently failing scan only fails itself; the next queued scan is processed and /health stays 200', async () => {
    const db = await newDb();
    const { runtime, port, root } = await harness(db, {
      scanWorker: {
        runParser: async (_d, _e, id) => {
          const [row] = await db.query<{ ref: string }>('SELECT ref FROM scans WHERE id = $1', [id]);
          if (row.ref === 'boom') throw Object.assign(new Error('parser crashed (simulated)'), { permanent: true });
          return emptyResult(id);
        },
      },
    });
    await db.query('UPDATE system_settings SET value = $1 WHERE key = $2', ['3', 'scan.max_retries']);
    const projectId = await insertProject(db, root);
    const bad = await insertScan(db, projectId, { status: 'queued' });
    await db.query(`UPDATE scans SET ref = 'boom', created_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, [bad]);
    const good = await insertScan(db, projectId, { status: 'queued' });

    await runtime.start();
    await vi.waitFor(async () => expect((await scan(db, good)).status).toBe('completed'), { timeout: 10_000, interval: 100 });
    expect((await scan(db, bad)).status).toBe('failed');
    expect(await health(port)).toBe(200);
    expect(runtime.state).toBe('running');
  });

  it('AC-P12-8: while the database is unreachable /health is 500 and polls are logged and retried; afterwards the queued scan is processed', async () => {
    const db = await newDb();
    const outage = { on: false };
    const { runtime, port, root, logs, exit } = await harness(db, { createPool: outagePool(outage, []) });
    await runtime.start();
    outage.on = true;
    const scanId = await insertScan(db, await insertProject(db, root), { status: 'queued' });

    expect(await health(port)).toBe(500);
    await vi.waitFor(() => expect(logs.some((l) => /Tarama işi sahiplenilemedi \(ECONNREFUSED\)/.test(l))).toBe(true), { timeout: 5_000 });
    expect((await scan(db, scanId)).status).toBe('queued');
    expect(runtime.state).toBe('running');
    expect(logs.join('\n')).not.toContain(db.cluster.password);

    outage.on = false;
    await vi.waitFor(async () => expect((await scan(db, scanId)).status).toBe('completed'), { timeout: 10_000, interval: 100 });
    expect(await health(port)).toBe(200);
    expect(exit).not.toHaveBeenCalled();
  });
});

describe('AC-P12-10 / D-39: graceful shutdown', () => {
  it("shutdown('signal'): running scan back to queued (retry_count, error_message kept; next_attempt_at, worker_id NULL), unfinished report pending, pool closed, lock released last; idempotent", async () => {
    const db = await newDb();
    const events: string[] = [];
    const parserStarted = deferred();
    const reportGate = deferred();
    const { runtime, port, root, logs, exit } = await harness(db, {
      createPool: outagePool({ on: false }, events),
      lockClientFactory: recordingLockFactory(events),
      processReport: () => reportGate.promise,
      scanWorker: {
        runParser: (_d, _e, _id, signal) =>
          new Promise<SandboxScanResult>((_resolve, reject) => {
            parserStarted.resolve();
            signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
          }),
      },
    });
    const scanId = await insertScan(db, await insertProject(db, root), { retry_count: 1, error_message: 'earlier attempt failed' });
    const reportId = await insertReport(db);

    await runtime.start();
    await parserStarted.promise;
    await vi.waitFor(async () => expect(await reportStatus(db, reportId)).toBe('generating'), { timeout: 5_000, interval: 50 });
    await sleep(600); // several polls: the active job is never swept as an orphan
    expect(await scan(db, scanId)).toMatchObject({ status: 'running', retry_count: 1, worker_id: runtime.runId });

    const first = runtime.shutdown('signal');
    expect(runtime.shutdown('signal')).toBe(first);
    expect(runtime.shuttingDown).toBe(true);
    expect(await first).toBe(0);

    expect(await scan(db, scanId)).toMatchObject({
      status: 'queued',
      retry_count: 1,
      next_attempt_at: null,
      worker_id: null,
      error_message: 'earlier attempt failed',
    });
    expect(await reportStatus(db, reportId)).toBe('pending');
    expect(events.indexOf('unlock')).toBeGreaterThan(events.indexOf('pool.end'));
    expect(events.at(-1)).toBe('unlock');
    expect(events.indexOf('pool.end')).toBeGreaterThanOrEqual(0);
    expect(await holders(db)).toEqual([]);
    await expect(health(port)).rejects.toThrow();
    expect(runtime.state).toBe('stopped');
    expect(await runtime.shutdown('fatal')).toBe(0); // still the first result
    expect(logs).toContain('Kapanış tamamlandı.');
    expect(exit).not.toHaveBeenCalled();
    reportGate.resolve();
  });

  it('installProcessHandlers on the real runtime: SIGINT -> shutdown -> exit(0); a second signal meanwhile -> exit(1) at once', async () => {
    const db = await newDb();
    const { runtime, logs } = await harness(db);
    await runtime.start();
    const proc = Object.assign(new EventEmitter(), { env: { DATABASE_URL: db.url } }) as unknown as ProcessLike & EventEmitter;
    const exit = vi.fn<(code: number) => void>();
    const logger = { log: (m: string) => logs.push(m), warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) };
    const uninstall = installProcessHandlers(runtime, proc, exit, logger);

    proc.emit('SIGINT');
    proc.emit('SIGBREAK');
    expect(exit).toHaveBeenNthCalledWith(1, 1);
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0), { timeout: 10_000 });
    expect(runtime.state).toBe('stopped');
    expect(await holders(db)).toEqual([]);
    expect(logs).toContain('SIGINT alındı.');
    uninstall();
    expect(proc.listenerCount('SIGINT')).toBe(0);
  });

  it('AC-P12-9: unhandledRejection on the real runtime -> one redacted log entry, shutdown, exit(1)', async () => {
    const db = await newDb();
    const { runtime } = await harness(db);
    await runtime.start();
    const proc = Object.assign(new EventEmitter(), { env: { DATABASE_URL: db.url } }) as unknown as ProcessLike & EventEmitter;
    const exit = vi.fn<(code: number) => void>();
    const errors: string[] = [];
    installProcessHandlers(runtime, proc, exit, { log: () => undefined, warn: () => undefined, error: (m: string) => errors.push(m) });

    proc.emit('unhandledRejection', new Error(`query failed on ${db.url}`));
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1), { timeout: 10_000 });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/^unhandledRejection: Error: query failed on /);
    expect(errors[0]).not.toContain(db.cluster.password);
    expect(errors[0]).toContain('[REDACTED]');
    expect(runtime.state).toBe('stopped');
    expect(await holders(db)).toEqual([]);
  });
});

describe('AC-P12-15: losing the lock connection -> degraded mode', () => {
  it('pg_terminate_backend on the lock session: workers stop claiming, the API keeps answering, the lock is re-acquired and processing resumes', async () => {
    const db = await newDb();
    const parser = vi.fn<RunParserFn>(async (_d, _e, id) => emptyResult(id));
    const { runtime, port, root, logs, exit } = await harness(db, { relockIntervalMs: 1_500, scanWorker: { runParser: parser } });
    await runtime.start();
    const oldPid = runtime.lock?.backendPid;
    expect(oldPid).toEqual(expect.any(Number));

    await db.query('SELECT pg_terminate_backend($1)', [oldPid]);
    await vi.waitFor(() => expect(runtime.state).toBe('degraded'), { timeout: 5_000, interval: 20 });
    expect(logs.some((l) => /bozulmuş kip/.test(l))).toBe(true);

    const scanId = await insertScan(db, await insertProject(db, root), { status: 'queued' });
    expect(await health(port)).toBe(200);
    await sleep(500); // > two poll intervals
    const whileDegraded = await scan(db, scanId);
    expect(runtime.state).toBe('degraded'); // the read above happened in degraded mode
    expect(whileDegraded.status).toBe('queued');
    expect(parser).not.toHaveBeenCalled();

    await vi.waitFor(() => expect(runtime.state).toBe('running'), { timeout: 10_000, interval: 50 });
    expect(logs.some((l) => /kilidi yeniden alındı/.test(l))).toBe(true);
    await vi.waitFor(async () => expect((await scan(db, scanId)).status).toBe('completed'), { timeout: 10_000, interval: 50 });
    const newPid = runtime.lock?.backendPid;
    expect(newPid).not.toBe(oldPid);
    expect(await holders(db)).toEqual([newPid]);
    expect(exit).not.toHaveBeenCalled();
  });

  it('lock taken by another session meanwhile -> "başka bir örneğe geçti", graceful shutdown, exit(1)', async () => {
    const db = await newDb();
    const { runtime, logs, exit } = await harness(db, { relockIntervalMs: 500 });
    await runtime.start();
    const oldPid = runtime.lock?.backendPid;
    const other = await connect(db.url);
    const [{ pid: otherPid }] = (await other.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows;

    await db.query('SELECT pg_terminate_backend($1)', [oldPid]);
    await other.query(LOCK_SQL); // waits until the terminated session is gone
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1), { timeout: 10_000, interval: 50 });
    expect(exit).toHaveBeenCalledTimes(1);
    expect(logs.some((l) => /başka bir örneğe geçti/.test(l))).toBe(true);
    expect(runtime.state).toBe('stopped');
    expect(await holders(db)).toEqual([otherPid]);
  });
});
