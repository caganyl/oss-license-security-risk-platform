/**
 * REQ-003 · P-13 retry/backoff/timeout in the scan worker (AC-P13-2…8),
 * poll-time orphan recovery and the run-id write fence (AC-P12-11, ADR-004
 * Karar 4, 9) and AC-G-8 (no queue-internal columns in API responses).
 *
 * The worker is driven with `runOnce()` (orphan sweep + one claim + full
 * processing) against a fresh migrated database per test. Clone and parser
 * are injected; database failures are injected through a Pool proxy that
 * rejects matching statements. All timings use the database clock
 * (`next_attempt_at - updated_at`, both set by the same statement).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Pool, PoolClient } from 'pg';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GitUnavailableError } from '../../src/scanner/gitVersion';
import { ParserCrashedError, ParserMemoryLimitError } from '../../src/scanner/parsers/threadParser';
import { ORPHAN_RECOVERY_MESSAGE, timeoutMessage } from '../../src/scanner/retryPolicy';
import { ScanWorker, type ScanWorkerDeps } from '../../src/scanner/worker';
import type { CloneRepoFn } from '../../src/scanner/workspace';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import { useTestDatabase } from '../helpers/db';
import { makeApp, req, setupPassword } from '../helpers/http';
import { TEST_KEY_A, TEST_TOKEN, encryptToken } from '../helpers/tokenCrypto';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

let tmpRoot = '';
let root = '';
let logs: string[] = [];
const push = (...a: unknown[]) => logs.push(a.map((x) => (x instanceof Error ? `${x.name}: ${x.message}` : String(x))).join(' '));
const logger = { log: push, warn: push, error: push };
let savedKey: string | undefined;

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p13-'));
  root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
  logs = [];
  savedKey = process.env.ENCRYPTION_KEY;
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulns: [], results: [] }), { status: 200 })));
  await db.query(`UPDATE system_settings SET value = '3' WHERE key = 'scan.max_retries'`);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (savedKey === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = savedKey;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
const okParser: RunParserFn = async (_d, _e, scanId) => result(scanId);
function result(scanId: string, status: 'completed' | 'failed' = 'completed'): SandboxScanResult {
  return { scan_id: scanId, status, total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] };
}

function worker(deps: Partial<ScanWorkerDeps> = {}): ScanWorker {
  return new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runParser: okParser, runId: 'run-A', ...deps });
}

async function insertProject(repoUrl: string | null): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [
    `p-${Math.random().toString(36).slice(2)}`,
    repoUrl,
  ]);
  return p.id;
}

async function insertScan(projectId: string, integrationId: string | null = null): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, integration_id, trigger, status, ref, queued_at) VALUES ($1, $2, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId, integrationId],
  );
  return s.id;
}

interface Row {
  status: string;
  retry_count: number;
  error_message: string | null;
  next_attempt_at: Date | null;
  worker_id: string | null;
  completed_at: Date | null;
  backoff: number | null;
  timeout_window: number | null;
}

async function row(id: string): Promise<Row> {
  const [r] = await db.query<Row>(
    `SELECT status::text, retry_count, error_message, next_attempt_at, worker_id, completed_at,
            EXTRACT(EPOCH FROM next_attempt_at - updated_at)::float8 AS backoff,
            EXTRACT(EPOCH FROM timeout_at - started_at)::float8 AS timeout_window
     FROM scans WHERE id = $1`,
    [id],
  );
  return r;
}

const makeDue = (id: string) => db.query(`UPDATE scans SET next_attempt_at = NOW() - INTERVAL '1 second' WHERE id = $1`, [id]);
const failedAudits = async (id: string) =>
  (await db.query(`SELECT 1 FROM audit_logs WHERE action = 'scan_failed' AND entity_id = $1`, [id])).length;
const leftovers = () => fs.readdirSync(tmpRoot).filter((n) => n.startsWith('ossrisk-scan-'));

/** Pool whose checked-out clients reject statements matching `fail(text)`. */
function faultyPool(pool: Pool, fail: (text: string) => boolean): Pool {
  const wrapClient = (client: PoolClient): PoolClient =>
    new Proxy(client, {
      get(target, prop) {
        if (prop === 'query') {
          return (...args: unknown[]) => {
            if (typeof args[0] === 'string' && fail(args[0])) {
              return Promise.reject(Object.assign(new Error('Connection terminated unexpectedly (simulated)'), { code: '57P01' }));
            }
            return (target.query as (...a: unknown[]) => Promise<unknown>)(...args);
          };
        }
        const value = Reflect.get(target, prop, target) as unknown;
        return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
      },
    });
  return new Proxy(pool, {
    get(target, prop) {
      if (prop === 'connect') return async () => wrapClient(await target.connect());
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

const COMPLETED_WRITE = /SET status = 'completed'/;
const FAILURE_WRITES = /UPDATE scans\s+SET status = '(queued|failed)'/;

// ---------------------------------------------------------------------------
describe('AC-P13-2 / AC-P13-3 / AC-P13-8: transient failures retry with backoff, then fail', () => {
  it('clone failure: queued with retry_count+1 and next_attempt_at = NOW()+30 s/60 s; not claimable before, claimable after; third failure -> failed + scan_failed; no token anywhere', async () => {
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    const projectId = await insertProject('https://github.com/org/private.git');
    const [integration] = await db.query<{ id: string }>(
      `INSERT INTO integrations (project_id, provider, name, repo_url, access_token_enc) VALUES ($1, 'github', 'gh', 'https://github.com/org/private.git', $2) RETURNING id`,
      [projectId, encryptToken(TEST_TOKEN, TEST_KEY_A)],
    );
    const scanId = await insertScan(projectId, integration.id);
    const clones: string[] = [];
    const failingClone: CloneRepoFn = async (url, _ref, dest, token) => {
      clones.push(url);
      fs.mkdirSync(dest, { recursive: true });
      throw new Error(`fatal: unable to access 'https://x-access-token:${token}@github.com/org/private.git/': simulated`);
    };
    const w = worker({ cloneRepo: failingClone, gitVersion: null });

    expect(await w.runOnce()).toBe(scanId);
    let r = await row(scanId);
    expect(r).toMatchObject({ status: 'queued', retry_count: 1, worker_id: null, completed_at: null });
    expect(r.backoff).toBe(30);
    expect(r.error_message).toMatch(/unable to access/);
    const retryLog = logs.find((l) => l.startsWith(`Tarama ${scanId} deneme 1/3 başarısız; sonraki deneme `));
    expect(retryLog).toBeDefined();
    expect(retryLog).toContain(r.next_attempt_at!.toISOString());

    // Not claimable before next_attempt_at (bugünkü kodda hemen alınırdı).
    expect(await w.runOnce()).toBeNull();
    expect(clones).toHaveLength(1);

    await makeDue(scanId);
    expect(await w.runOnce()).toBe(scanId);
    r = await row(scanId);
    expect(r).toMatchObject({ status: 'queued', retry_count: 2 });
    expect(r.backoff).toBe(60);
    expect(logs.some((l) => l.startsWith(`Tarama ${scanId} deneme 2/3 başarısız`))).toBe(true);

    await makeDue(scanId);
    expect(await w.runOnce()).toBe(scanId);
    r = await row(scanId);
    expect(r).toMatchObject({ status: 'failed', retry_count: 2, next_attempt_at: null });
    expect(r.completed_at).not.toBeNull();
    expect(await failedAudits(scanId)).toBe(1);
    expect(clones).toHaveLength(3);
    expect(leftovers()).toEqual([]);

    const haystack = `${r.error_message}\n${logs.join('\n')}`;
    expect(haystack).not.toContain(TEST_TOKEN);
    expect(haystack).not.toContain(Buffer.from(`x-access-token:${TEST_TOKEN}`).toString('base64'));
  });

  it('AC-P13-5: a database error while writing the result is transient (queued, retry_count+1, backoff)', async () => {
    const scanId = await insertScan(await insertProject(root));
    let failures = 0;
    const pool = faultyPool(db.pool, (sql) => COMPLETED_WRITE.test(sql) && failures++ === 0);
    expect(await worker({ db: pool }).runOnce()).toBe(scanId);
    const r = await row(scanId);
    expect(r).toMatchObject({ status: 'queued', retry_count: 1 });
    expect(r.backoff).toBe(30);
    expect(await db.query('SELECT 1 FROM scan_dependencies WHERE scan_id = $1', [scanId])).toEqual([]);
  });
});

describe('AC-P13-7: claim order and waiting retries', () => {
  it('a new scan has next_attempt_at NULL and is claimable at once; a waiting retry does not block a newer scan; order is created_at', async () => {
    const projectId = await insertProject(root);
    const waiting = await insertScan(projectId);
    await db.query(
      `UPDATE scans SET status = 'queued', retry_count = 1, next_attempt_at = NOW() + INTERVAL '10 minutes', created_at = NOW() - INTERVAL '1 hour' WHERE id = $1`,
      [waiting],
    );
    const older = await insertScan(projectId);
    await db.query(`UPDATE scans SET created_at = NOW() - INTERVAL '30 minutes' WHERE id = $1`, [older]);
    const newer = await insertScan(projectId);
    expect((await row(newer)).next_attempt_at).toBeNull();

    const w = worker();
    expect(await w.runOnce()).toBe(older);
    expect(await w.runOnce()).toBe(newer);
    expect(await w.runOnce()).toBeNull();
    expect((await row(waiting)).status).toBe('queued');
    await makeDue(waiting);
    expect(await w.runOnce()).toBe(waiting);
    expect((await row(waiting)).status).toBe('completed');
  });
});

describe('AC-P13-4 / D-41: permanent failures fail at once (retries left, next_attempt_at stays NULL)', () => {
  async function expectPermanent(scanId: string, w: ScanWorker, message: RegExp): Promise<void> {
    expect(await w.runOnce()).toBe(scanId);
    const r = await row(scanId);
    expect(r).toMatchObject({ status: 'failed', retry_count: 0, next_attempt_at: null });
    expect(r.error_message).toMatch(message);
    expect(await failedAudits(scanId)).toBe(1);
  }

  it('undecryptable token', async () => {
    delete process.env.ENCRYPTION_KEY;
    const projectId = await insertProject('https://github.com/org/private.git');
    const [i] = await db.query<{ id: string }>(
      `INSERT INTO integrations (project_id, provider, name, repo_url, access_token_enc) VALUES ($1, 'github', 'gh', 'https://github.com/org/private.git', $2) RETURNING id`,
      [projectId, Buffer.from('too-short')],
    );
    const clone = vi.fn<CloneRepoFn>();
    await expectPermanent(await insertScan(projectId, i.id), worker({ cloneRepo: clone, gitVersion: null }), /could not be decrypted/);
    expect(clone).not.toHaveBeenCalled();
  });

  it('invalid source (local path outside SCAN_ROOTS)', async () => {
    const outside = fs.mkdtempSync(path.join(tmpRoot, 'outside-'));
    await expectPermanent(await insertScan(await insertProject(outside)), worker(), /.+/);
  });

  it('parser thread over its memory limit, parser thread crash, parser `failed` result', async () => {
    const projectId = await insertProject(root);
    await expectPermanent(await insertScan(projectId), worker({ runParser: async () => Promise.reject(new ParserMemoryLimitError(512)) }), /bellek sınırını aştı/);
    await expectPermanent(await insertScan(projectId), worker({ runParser: async () => Promise.reject(new ParserCrashedError('thread exited with code 3')) }), /thread exited/);
    await expectPermanent(await insertScan(projectId), worker({ runParser: async (_d, _e, id) => result(id, 'failed') }), /parsing failure/);
  });

  it('git missing or older than 2.32 for a remote scan (no clone, no temp folder)', async () => {
    const clone = vi.fn<CloneRepoFn>();
    const gitVersion = async () => ({ found: true, version: '2.30.1', major: 2, minor: 30, supported: false });
    const scanId = await insertScan(await insertProject('https://github.com/org/repo.git'));
    await expectPermanent(scanId, worker({ cloneRepo: clone, gitVersion }), /git 2\.32 veya üstü gerekli \(bulunan: 2\.30\.1\)/);
    expect(clone).not.toHaveBeenCalled();
    expect(leftovers()).toEqual([]);
    expect(new GitUnavailableError({ found: false, version: null, major: null, minor: null, supported: false }).permanent).toBe(true);
  });
});

describe('AC-P13-6 / D-42: job time limit', () => {
  beforeEach(async () => {
    await db.query(`UPDATE system_settings SET value = '0.01'::jsonb WHERE key = 'scan.timeout_minutes'`);
  });

  it('a blocking parser is aborted after 0.6 s: failed (no retry), exact message, timeout_at = started_at + limit', async () => {
    const scanId = await insertScan(await insertProject(root));
    const seen: AbortSignal[] = [];
    const blocking: RunParserFn = (_d, _e, _id, signal) =>
      new Promise((_resolve, reject) => {
        seen.push(signal!);
        signal!.addEventListener('abort', () => reject(signal!.reason), { once: true });
      });
    const startedAt = Date.now();
    expect(await worker({ runParser: blocking }).runOnce()).toBe(scanId);
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(550);
    const r = await row(scanId);
    expect(r).toMatchObject({ status: 'failed', retry_count: 0, next_attempt_at: null, error_message: 'Tarama süre sınırını aştı (0.01 dk).' });
    expect(r.error_message).toBe(timeoutMessage(0.01));
    expect(r.timeout_window).toBeCloseTo(0.6, 3);
    expect(seen[0].aborted).toBe(true);
    expect(await failedAudits(scanId)).toBe(1);
  });

  it('a blocking clone is aborted the same way and its temp workspace is removed', async () => {
    const scanId = await insertScan(await insertProject('https://github.com/org/slow.git'));
    const blockingClone: CloneRepoFn = (_u, _r, dest, _t, signal) =>
      new Promise((_resolve, reject) => {
        fs.mkdirSync(dest, { recursive: true });
        fs.writeFileSync(path.join(dest, 'partial'), 'x');
        signal!.addEventListener('abort', () => reject(signal!.reason), { once: true });
      });
    const parser = vi.fn<RunParserFn>();
    expect(await worker({ cloneRepo: blockingClone, gitVersion: null, runParser: parser }).runOnce()).toBe(scanId);
    expect(await row(scanId)).toMatchObject({ status: 'failed', retry_count: 0, error_message: 'Tarama süre sınırını aştı (0.01 dk).' });
    expect(parser).not.toHaveBeenCalled();
    expect(leftovers()).toEqual([]);
  });
});

describe('AC-P12-11 / ADR-004 Karar 9: orphan recovery on every poll', () => {
  it('(3) a scan whose final writes failed stays running and is recovered by the next runOnce (independent of worker_id)', async () => {
    const scanId = await insertScan(await insertProject(root));
    const outage = { on: true };
    const pool = faultyPool(db.pool, (sql) => outage.on && (COMPLETED_WRITE.test(sql) || FAILURE_WRITES.test(sql)));
    const w = worker({ db: pool });
    expect(await w.runOnce()).toBe(scanId);
    expect(await row(scanId)).toMatchObject({ status: 'running', worker_id: 'run-A', retry_count: 0 });
    expect(w.activeScanIds).toEqual([]);
    expect(logs.some((l) => /hata durumu yazılamadı \(57P01\)/.test(l))).toBe(true);

    outage.on = false;
    expect(await w.runOnce()).toBeNull(); // recovered, but waiting for its backoff
    const r = await row(scanId);
    expect(r).toMatchObject({ status: 'queued', retry_count: 1, worker_id: null, error_message: ORPHAN_RECOVERY_MESSAGE });
    expect(r.backoff).toBe(30);
  });

  it('a job in the active set is never swept while it runs; a running row of another run id is', async () => {
    const projectId = await insertProject(root);
    const foreign = await insertScan(projectId);
    await db.query(`UPDATE scans SET status = 'running', worker_id = 'run-B', started_at = NOW() WHERE id = $1`, [foreign]);
    const mine = await insertScan(projectId);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const started: string[] = [];
    const w = worker({
      runParser: async (_d, _e, id) => {
        started.push(id);
        await gate;
        return result(id);
      },
    });
    const first = w.runOnce(); // sweeps `foreign`, claims `mine`
    await vi.waitFor(() => expect(started).toEqual([mine]));
    expect(await w.recoverOrphanedScans()).toBe(0); // `mine` is active
    expect(await row(mine)).toMatchObject({ status: 'running', worker_id: 'run-A' });
    expect(await row(foreign)).toMatchObject({ status: 'queued', retry_count: 1, worker_id: null });
    release();
    expect(await first).toBe(mine);
    expect((await row(mine)).status).toBe('completed');
  });
});

describe('ADR-004 Karar 4: write fence on worker_id', () => {
  async function claimThenTakeOver(outcome: 'result' | 'error') {
    const scanId = await insertScan(await insertProject(root));
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let started = false;
    const w = worker({
      runParser: async (_d, _e, id) => {
        started = true;
        await gate;
        if (outcome === 'error') throw new Error('transient parser hiccup');
        return { ...result(id), total_deps: 1, dependencies: [
          { ecosystem: 'nodejs', name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', scope: 'direct', licenses: ['MIT'], manifest_file: 'package.json', manifest_path: '.' },
        ] };
      },
    });
    const run = w.runOnce();
    await vi.waitFor(() => expect(started).toBe(true));
    // Another instance took the row over meanwhile.
    await db.query(`UPDATE scans SET worker_id = 'run-B' WHERE id = $1`, [scanId]);
    release();
    expect(await run).toBe(scanId);
    return scanId;
  }

  it('the result of a run that no longer owns the row is dropped', async () => {
    const scanId = await claimThenTakeOver('result');
    expect(await row(scanId)).toMatchObject({ status: 'running', worker_id: 'run-B', retry_count: 0 });
    expect(await db.query('SELECT 1 FROM scan_dependencies WHERE scan_id = $1', [scanId])).toEqual([]);
    expect(logs.some((l) => l.includes(`Tarama ${scanId} başka bir örnek tarafından devralındı; sonuç atıldı.`))).toBe(true);
  });

  it('the failure write of a run that no longer owns the row is dropped', async () => {
    const scanId = await claimThenTakeOver('error');
    expect(await row(scanId)).toMatchObject({ status: 'running', worker_id: 'run-B', retry_count: 0, error_message: null });
    expect(logs.some((l) => l.includes(`Tarama ${scanId} başka bir örnek tarafından devralındı; hata yazılmadı.`))).toBe(true);
  });
});

describe('AC-G-8 / D-43: next_attempt_at and timeout_at never appear in API responses', () => {
  it('POST /api/scans, GET /api/scans/:id and GET /api/scans', async () => {
    const app = await makeApp(db.pool, { scanRoots: [root] });
    const cookie = await setupPassword(app);
    const projectId = await insertProject(root);
    const created = await req(app, 'post', '/api/scans', { cookie }).send({ projectId });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const scanId = created.body.data.id as string;
    await db.query(`UPDATE scans SET next_attempt_at = NOW(), timeout_at = NOW() WHERE id = $1`, [scanId]);

    const one = await req(app, 'get', `/api/scans/${scanId}`, { cookie });
    const list = await req(app, 'get', '/api/scans', { cookie });
    expect(one.status).toBe(200);
    expect(list.status).toBe(200);
    for (const body of [created.body.data, one.body.data, ...(list.body.data as unknown[])]) {
      expect(Object.keys(body as object)).not.toContain('next_attempt_at');
      expect(Object.keys(body as object)).not.toContain('timeout_at');
    }
    expect(Object.keys(one.body.data)).toEqual(expect.arrayContaining(['id', 'status', 'retry_count', 'worker_id', 'error_message']));
  });
});
