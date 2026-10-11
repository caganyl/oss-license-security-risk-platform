/**
 * REQ-005 post-review fixes against embedded PostgreSQL and the loopback fake
 * OSV server (no real network):
 *   M-1  recheck write-phase time cap: the current project is rolled back,
 *        run `partial` + `osv:time_limit` (contract 1.1.0 section 3.5.1)
 *   L-3  scheduler pause aborts an in-flight expiry evaluation, no expiry while paused
 *   L-6  concurrent transactions inserting the same vulnerability both succeed
 *   L-7  paged recheck scope: 10 001 packages -> 10 000 checked + `osv:package_limit`,
 *        no query returns more than one scope page (query spy)
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import type { AppClock } from '../../src/lib/clock';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import { createExpiryEvaluator, type ExpiryEvaluator } from '../../src/vulnerability/expiry';
import { upsertVulnerability } from '../../src/vulnerability/findingWriter';
import { normalizeOsvVulnerability } from '../../src/vulnerability/normalize';
import { createRecheckRunner } from '../../src/vulnerability/recheck';
import { createVulnerabilityScheduler, type VulnerabilityScheduler } from '../../src/vulnerability/scheduler';
import { useTestDatabase } from '../helpers/db';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { makeF4Lookup, seedF4Scan } from '../helpers/f4Seed';

vi.setConfig({ testTimeout: 180_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

const H = 60 * 60_000;
const T0 = Date.parse('2026-10-10T08:00:00.000Z');
let nowMs = T0;
const clock: AppClock = { now: () => nowMs, sleep: async () => undefined };
let osv: FakeOsv;
let logs: string[] = [];
const clients: VulnerabilityClient[] = [];
const schedulers: VulnerabilityScheduler[] = [];
const logger = { log: (...a: unknown[]) => logs.push(a.map(String).join(' ')), warn: (...a: unknown[]) => logs.push(a.map(String).join(' ')), error: (...a: unknown[]) => logs.push(a.map(String).join(' ')) };

beforeEach(async () => {
  nowMs = T0;
  logs = [];
  osv = await startFakeOsv();
});
afterEach(async () => {
  for (const s of schedulers.splice(0)) await s.stop();
  for (const c of clients.splice(0)) c.close();
  await osv.close();
});

type QueryFn = (...args: unknown[]) => Promise<{ rows?: unknown[] }>;

/** Pool wrapper that reports every query text and its row count (pool and checked-out clients). */
function spyPool(pool: Pool, onQuery: (text: string, rows: number) => void): Pool {
  const wrap = (query: QueryFn): QueryFn => async (...args: unknown[]) => {
    const result = await query(...args);
    const first = args[0];
    const text = typeof first === 'string' ? first : typeof first === 'object' && first !== null ? String((first as { text?: unknown }).text ?? '') : '';
    onQuery(text, Array.isArray(result?.rows) ? result.rows.length : 0);
    return result;
  };
  return {
    query: wrap(pool.query.bind(pool) as unknown as QueryFn),
    connect: async () => {
      const client = await pool.connect();
      const mutable = client as unknown as { query: QueryFn; release: (err?: unknown) => void };
      const originalQuery = mutable.query;
      const originalRelease = mutable.release;
      mutable.query = wrap(originalQuery.bind(client) as QueryFn);
      mutable.release = (err?: unknown) => {
        mutable.query = originalQuery;
        mutable.release = originalRelease;
        originalRelease.call(client, err);
      };
      return client;
    },
  } as unknown as Pool;
}

async function lastRun() {
  const rows = await db.query<{ status: string; projects_checked: number; packages_checked: number; packages_unchecked: number; findings_opened: number; error_summary: string | null }>(
    `SELECT status, projects_checked, packages_checked, packages_unchecked, findings_opened, error_summary FROM vulnerability_recheck_runs ORDER BY started_at DESC, id DESC LIMIT 1`,
  );
  return rows[0];
}

describe('M-1: recheck write-phase time cap', () => {
  it('M-1 / section 3.5.1: the run limit expires inside a project transaction -> that project is rolled back, run partial with osv:time_limit', async () => {
    const seeded = await seedF4Scan(db, { projectName: 'time-cap', deps: [['tc-a', '1.0.0'], ['tc-b', '1.0.0']] });
    for (const [name, id] of [['tc-a', 'GHSA-tcap-tcap-aaaa'], ['tc-b', 'GHSA-tcap-tcap-bbbb']] as const) {
      osv.vulns.set(osvKey('npm', name, '1.0.0'), [{ id, modified: '2026-01-01T00:00:00Z' }]);
      osv.addRecord(id);
    }
    const runTimeoutMs = 10 * H;
    let findingInserts = 0;
    // The first finding insert of the project moves the clock past the run deadline, so the
    // deadline check before the next dependency fires inside the open transaction.
    const pool = spyPool(db.pool, (text) => {
      if (/INSERT INTO findings/i.test(text)) {
        findingInserts++;
        nowMs = T0 + runTimeoutMs;
      }
    });
    const lookup = makeF4Lookup(db, osv.origin, clock, logs, clients);
    const runner = createRecheckRunner({ db: pool, lookup, expiry: createExpiryEvaluator({ db: db.pool, clock, logger }), runtimeRunId: 'rt-M1', clock, logger, limits: { runTimeoutMs } });
    await runner.run(new AbortController().signal);

    expect(findingInserts).toBe(1);
    const findings = await db.query(`SELECT 1 FROM findings WHERE scan_id = $1 AND finding_type = 'security'`, [seeded.scanId]);
    expect(findings).toHaveLength(0); // rolled back
    const run = await lastRun();
    expect(run.status).toBe('partial');
    expect(run.error_summary ?? '').toContain('osv:time_limit');
    expect(run.projects_checked).toBe(0);
    expect(run.findings_opened).toBe(0);
    const [scan] = await db.query<{ total: number }>(`SELECT total_vulnerabilities AS total FROM scans WHERE id = $1`, [seeded.scanId]);
    expect(scan.total).toBe(0);
  });
});

describe('L-3: pause aborts the in-flight expiry evaluation', () => {
  it.each([
    ['L-3: pause() aborts a running P-19 evaluation; no expiry tick runs while paused; resume() allows it again', false],
    // Regression guard (fixed in 3cda79a): a second tick queued behind the mutex must not replace
    // the running evaluation's controller; pause() aborts every tracked expiry controller.
    ['L-3: pause() aborts the running P-19 evaluation even when another expiry tick is queued behind it', true],
  ])('%s', async (_name, queueSecondTick) => {
    let queued: Promise<void> = Promise.resolve();
    const signals: AbortSignal[] = [];
    const expiry = {
      evaluate: (signal: AbortSignal) =>
        new Promise<{ reopened: number }>((resolve) => {
          signals.push(signal);
          if (signal.aborted) resolve({ reopened: 0 });
          else signal.addEventListener('abort', () => resolve({ reopened: 0 }), { once: true });
          setTimeout(() => resolve({ reopened: 0 }), 300);
        }),
    } as unknown as ExpiryEvaluator;
    const stubDb = { query: async () => ({ rows: [] }) } as unknown as Pool;
    const s = createVulnerabilityScheduler({
      db: stubDb,
      lookup: null,
      expiry,
      config: { recheckEnabled: false, intervalHours: 24 },
      runtimeRunId: 'rt-L3',
      isRunning: () => true,
      clock,
      logger,
      firstCheckDelayMs: 24 * H,
      expiryIntervalMs: 24 * H,
    });
    schedulers.push(s);
    await s.start(); // start-up expiry tick runs in the background
    await vi.waitFor(() => expect(signals).toHaveLength(1));
    if (queueSecondTick) queued = s.expiryTick(); // waits behind the mutex
    s.pause();
    expect(signals[0].aborted, 'in-flight evaluation aborted by pause()').toBe(true);
    await queued;
    expect(signals).toHaveLength(1); // the queued tick did not evaluate
    await s.expiryTick();
    expect(signals).toHaveLength(1); // paused: no expiry tick
    s.resume();
    await s.expiryTick();
    expect(signals).toHaveLength(2);
    expect(signals[1].aborted).toBe(false);
  });
});

describe('L-6: conflict-safe vulnerability catalog upsert', () => {
  it('L-6: two concurrent transactions (scan + recheck) inserting the same new vulnerability both commit with one catalog row', async () => {
    const dep = { ecosystem: 'nodejs' as const, name: 'race-pkg' };
    const vuln = normalizeOsvVulnerability({ id: 'GHSA-race-race-race', aliases: ['CVE-2026-22222'], summary: 'race', severity: [] }, dep);
    const a: PoolClient = await db.pool.connect();
    const b: PoolClient = await db.pool.connect();
    try {
      await a.query('BEGIN');
      await b.query('BEGIN');
      const stored = await upsertVulnerability(a, vuln);
      let bDone = false;
      const pending = upsertVulnerability(b, vuln).then((v) => {
        bDone = true;
        return v;
      });
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(bDone).toBe(false); // waits on the unique index held by A
      await a.query('COMMIT');
      const storedB = await pending;
      await b.query('COMMIT');
      expect(storedB.id).toBe(stored.id);
    } finally {
      await a.query('ROLLBACK').catch(() => undefined);
      await b.query('ROLLBACK').catch(() => undefined);
      a.release();
      b.release();
    }
    const rows = await db.query(`SELECT id FROM vulnerabilities WHERE ghsa_id = 'GHSA-race-race-race' OR cve_id = 'CVE-2026-22222'`);
    expect(rows).toHaveLength(1);
  });
});

describe('L-7: paged recheck scope', () => {
  it('L-7: 10 001 packages -> 10 000 checked + osv:package_limit, scope read in pages (no query returns more than 5000 rows)', async () => {
    const seeded = await seedF4Scan(db, { projectName: 'many-packages', deps: [] });
    await db.query(
      `WITH pk AS (
         INSERT INTO packages (ecosystem, name, version, purl)
         SELECT 'nodejs', 'lp-' || lpad(g::text, 5, '0'), '1.0.0', 'pkg:npm/lp-' || lpad(g::text, 5, '0') || '@1.0.0' FROM generate_series(1, 10001) g
         RETURNING id)
       INSERT INTO scan_dependencies (scan_id, package_id, scope, manifest_file, manifest_path, depth)
       SELECT $1, id, 'direct', 'package-lock.json', '.', 0 FROM pk`,
      [seeded.scanId],
    );
    const queries: Array<{ text: string; rows: number }> = [];
    const pool = spyPool(db.pool, (text, rows) => queries.push({ text, rows }));
    const lookup = makeF4Lookup(db, osv.origin, clock, logs, clients);
    const runner = createRecheckRunner({ db: pool, lookup, expiry: createExpiryEvaluator({ db: db.pool, clock, logger }), runtimeRunId: 'rt-L7', clock, logger });
    await runner.run(new AbortController().signal);

    const run = await lastRun();
    expect(run.packages_checked).toBe(10_000);
    expect(run.packages_unchecked).toBe(1);
    expect(run.status).toBe('partial');
    expect(run.error_summary ?? '').toContain('osv:package_limit');
    expect(osv.batches().reduce((n, b) => n + b.length, 0)).toBe(10_000);
    // Scope phase: only paged queries (LIMIT $4), each at most one page; the run never loads the
    // whole candidate table at once. (The per-project write phase reads that project's own
    // scan_dependencies in one query; that is outside the L-7 scope fix.)
    const pageQueries = queries.filter((q) => /LIMIT \$4/.test(q.text));
    expect(pageQueries.length).toBeGreaterThanOrEqual(3); // 10 001 rows / 5000 per page
    expect(Math.max(...pageQueries.map((q) => q.rows))).toBeLessThanOrEqual(5_000);
    expect(pageQueries.reduce((n, q) => n + q.rows, 0)).toBe(10_001);
    const scopeEnd = queries.findIndex((q, i) => i > queries.indexOf(pageQueries[pageQueries.length - 1]) && !/LIMIT \$4/.test(q.text));
    expect(Math.max(...queries.slice(0, scopeEnd === -1 ? queries.length : scopeEnd).map((q) => q.rows))).toBeLessThanOrEqual(5_000);
  });
});
