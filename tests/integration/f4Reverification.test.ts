/**
 * REQ-005 security re-verification follow-ups (2026-10-11) against embedded
 * PostgreSQL and the loopback fake OSV server (no real network):
 *   Y-1  recheck lookup budget = 5/6 of the run limit, counted from the run
 *        start; a lookup that fills its budget still leaves time to write
 *   Y-3  `upsertVulnerability` retries once on `40P01`/`40001` inside its
 *        savepoint (earlier work of the transaction kept), the second failure
 *        is thrown; the recheck project transaction is retried once on
 *        `40P01`, a second failure rolls the project back with `db:40`
 * SQLSTATE errors are injected through a pool/client query spy.
 * (Y-2, the NVD limiter, is covered in `unit/vulnLookup.test.ts`.)
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import type { AppClock } from '../../src/lib/clock';
import { VULNERABILITY_LIMITS } from '../../src/scanner/sandbox/runner.config';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import { createExpiryEvaluator, type ExpiryEvaluator } from '../../src/vulnerability/expiry';
import { isTransientLockError, upsertVulnerability } from '../../src/vulnerability/findingWriter';
import type { VulnerabilityLookup } from '../../src/vulnerability/lookup';
import { normalizeOsvVulnerability } from '../../src/vulnerability/normalize';
import { createRecheckRunner } from '../../src/vulnerability/recheck';
import { useTestDatabase } from '../helpers/db';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { makeF4Lookup, seedF4Scan } from '../helpers/f4Seed';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

const MIN = 60_000;
const T0 = Date.parse('2026-10-10T08:00:00.000Z');
let nowMs = T0;
const clockSleeps: number[] = [];
const clock: AppClock = {
  now: () => nowMs,
  sleep: async (ms) => {
    clockSleeps.push(ms);
  },
};
let osv: FakeOsv;
let logs: string[] = [];
const clients: VulnerabilityClient[] = [];
const logger = { log: (...a: unknown[]) => logs.push(a.map(String).join(' ')), warn: (...a: unknown[]) => logs.push(a.map(String).join(' ')), error: (...a: unknown[]) => logs.push(a.map(String).join(' ')) };

beforeEach(async () => {
  nowMs = T0;
  logs = [];
  clockSleeps.length = 0;
  osv = await startFakeOsv();
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  await osv.close();
});

type QueryFn = (...args: unknown[]) => Promise<unknown>;

const textOf = (args: unknown[]): string => {
  const first = args[0];
  return typeof first === 'string' ? first : typeof first === 'object' && first !== null ? String((first as { text?: unknown }).text ?? '') : '';
};

/** A pg-like error carrying a SQLSTATE (message must never be logged). */
const sqlStateError = (code: string): Error => Object.assign(new Error(`injected raw message ${code}`), { code });

/**
 * Replaces `client.query` with a spy: every statement text is logged; when
 * `inject(text, args)` returns a SQLSTATE, the statement is replaced by a
 * really failing one (`SELECT 1/0`, so PostgreSQL aborts the transaction as a
 * real deadlock would) and then rejected with that SQLSTATE.
 */
function spyClient(client: PoolClient, statements: string[], inject: (text: string, args: unknown[]) => string | null): () => void {
  const mutable = client as unknown as { query: QueryFn };
  const original = mutable.query;
  const bound = original.bind(client) as QueryFn;
  mutable.query = async (...args: unknown[]) => {
    const text = textOf(args);
    statements.push(text);
    const code = inject(text, args);
    if (code !== null) {
      await bound('SELECT 1/0').catch(() => undefined);
      throw sqlStateError(code);
    }
    return bound(...args);
  };
  return () => {
    mutable.query = original;
  };
}

/** Pool wrapper whose checked-out clients go through `spyClient`. */
function injectingPool(pool: Pool, statements: string[], inject: (text: string, args: unknown[]) => string | null): Pool {
  return {
    query: pool.query.bind(pool),
    connect: async () => {
      const client = await pool.connect();
      const restore = spyClient(client, statements, inject);
      const mutable = client as unknown as { release: (err?: unknown) => void };
      const originalRelease = mutable.release;
      mutable.release = (err?: unknown) => {
        restore();
        mutable.release = originalRelease;
        originalRelease.call(client, err);
      };
      return client;
    },
  } as unknown as Pool;
}

function publish(name: string, id: string): void {
  osv.vulns.set(osvKey('npm', name, '1.0.0'), [{ id, modified: '2026-01-01T00:00:00Z' }]);
  osv.addRecord(id);
}

async function lastRun() {
  const rows = await db.query<{ status: string; projects_checked: number; findings_opened: number; error_summary: string | null }>(
    `SELECT status, projects_checked, findings_opened, error_summary FROM vulnerability_recheck_runs ORDER BY started_at DESC, id DESC LIMIT 1`,
  );
  return rows[0];
}

async function securityFindingCount(scanId: string): Promise<number> {
  return (await db.query(`SELECT 1 FROM findings WHERE scan_id = $1 AND finding_type = 'security'`, [scanId])).length;
}

const expiryOf = (): ExpiryEvaluator => createExpiryEvaluator({ db: db.pool, clock, logger });

// ---------------------------------------------------------------------------
describe('Y-1: recheck lookup budget reserves the write phase', () => {
  it('Y-1: the lookup budget is 5/6 of the run limit (25 of 30 min); a lookup that fills it still leaves the project written', async () => {
    expect(VULNERABILITY_LIMITS.recheck.lookupBudgetShare).toBeCloseTo(5 / 6, 12);
    const seeded = await seedF4Scan(db, { projectName: 'y1-default', deps: [['y1-pkg', '1.0.0']] });
    publish('y1-pkg', 'GHSA-y1y1-y1y1-aaaa');
    const inner = makeF4Lookup(db, osv.origin, clock, logs, clients);
    const budgets: Array<number | undefined> = [];
    const lookup = {
      get enabled() {
        return inner.enabled;
      },
      lookup: async (...args: Parameters<VulnerabilityLookup['lookup']>) => {
        const result = await inner.lookup(...args);
        budgets.push(args[1]?.budgetMs);
        // The lookup used its entire budget (it ends exactly at its deadline).
        nowMs += args[1]?.budgetMs ?? 0;
        return result;
      },
    } as unknown as VulnerabilityLookup;
    const summary = await createRecheckRunner({ db: db.pool, lookup, expiry: expiryOf(), runtimeRunId: 'rt-Y1', clock, logger }).run(new AbortController().signal);

    expect(budgets).toEqual([25 * MIN]);
    expect(nowMs).toBe(T0 + 25 * MIN); // 5 min left of the 30 min run limit
    expect(summary).toMatchObject({ status: 'completed', projectsChecked: 1, findingsOpened: 1, errorSummary: null });
    expect(await securityFindingCount(seeded.scanId)).toBe(1);
  });

  it('Y-1: the budget is counted from the run start (P-19 and scope time included): 3 min spent before the lookup -> 22 min; a custom 12 min run limit -> 10 min', async () => {
    const seeded = await seedF4Scan(db, { projectName: 'y1-start', deps: [['y1-pkg2', '1.0.0']] });
    publish('y1-pkg2', 'GHSA-y1y1-y1y1-bbbb');
    const inner = makeF4Lookup(db, osv.origin, clock, logs, clients);
    const budgets: Array<number | undefined> = [];
    const lookup = {
      get enabled() {
        return inner.enabled;
      },
      lookup: async (...args: Parameters<VulnerabilityLookup['lookup']>) => {
        budgets.push(args[1]?.budgetMs);
        const result = await inner.lookup(...args);
        nowMs += args[1]?.budgetMs ?? 0;
        return result;
      },
    } as unknown as VulnerabilityLookup;
    const realExpiry = expiryOf();
    const slowExpiry = {
      evaluate: async (...args: Parameters<ExpiryEvaluator['evaluate']>) => {
        const r = await realExpiry.evaluate(...args);
        nowMs += 3 * MIN; // the run-start expiry evaluation took 3 min
        return r;
      },
      lastEvaluatedAt: () => realExpiry.lastEvaluatedAt(),
    } as unknown as ExpiryEvaluator;
    const first = await createRecheckRunner({ db: db.pool, lookup, expiry: slowExpiry, runtimeRunId: 'rt-Y1b', clock, logger }).run(new AbortController().signal);
    expect(budgets).toEqual([22 * MIN]);
    expect(first).toMatchObject({ status: 'completed', projectsChecked: 1, findingsOpened: 1 });
    expect(await securityFindingCount(seeded.scanId)).toBe(1);

    budgets.length = 0;
    nowMs = T0 + 24 * 60 * MIN;
    await createRecheckRunner({ db: db.pool, lookup, expiry: expiryOf(), runtimeRunId: 'rt-Y1c', clock, logger, limits: { runTimeoutMs: 12 * MIN } }).run(new AbortController().signal);
    expect(budgets).toEqual([10 * MIN]);
    expect((await lastRun()).status).toBe('completed');
  });
});

// ---------------------------------------------------------------------------
describe('Y-3: upsertVulnerability savepoint retry', () => {
  const dep = { ecosystem: 'nodejs' as const, name: 'y3-pkg' };

  it.each(['40P01', '40001'])('Y-3: %s on the catalog insert is retried once inside the savepoint; earlier work of the transaction is kept', async (code) => {
    const vuln = normalizeOsvVulnerability({ id: `GHSA-y3y3-${code.toLowerCase()}-aaaa`, summary: 'y3', severity: [] }, dep);
    const statements: string[] = [];
    let injected = 0;
    const client = await db.pool.connect();
    const restore = spyClient(client, statements, (text) => (/INSERT INTO vulnerabilities\b/i.test(text) && injected++ === 0 ? code : null));
    let projectName = '';
    try {
      await client.query('BEGIN');
      projectName = `y3-earlier-${code}`;
      await client.query(`INSERT INTO projects (name, repo_url) VALUES ($1, 'https://example.test/y3.git')`, [projectName]);
      const stored = await upsertVulnerability(client, vuln);
      await client.query('COMMIT');
      expect(stored.ghsaId).toBe(vuln.ghsaId);
    } finally {
      await client.query('ROLLBACK').catch(() => undefined);
      restore();
      client.release();
    }
    expect(injected).toBe(2); // first attempt injected, second attempt passed through
    const savepointOps = statements.filter((s) => /SAVEPOINT/i.test(s)).map((s) => s.trim().replace(/\s+/g, ' '));
    expect(savepointOps).toEqual(['SAVEPOINT vulnerability_upsert', 'ROLLBACK TO SAVEPOINT vulnerability_upsert', 'RELEASE SAVEPOINT vulnerability_upsert']);
    expect(await db.query(`SELECT 1 FROM projects WHERE name = $1`, [projectName])).toHaveLength(1);
    expect(await db.query(`SELECT 1 FROM vulnerabilities WHERE ghsa_id = $1`, [vuln.ghsaId])).toHaveLength(1);
  });

  it('Y-3: a second 40P01 is thrown (one retry only); the caller rolls back and nothing is stored', async () => {
    const vuln = normalizeOsvVulnerability({ id: 'GHSA-y3y3-twice-aaaa', summary: 'y3', severity: [] }, dep);
    const statements: string[] = [];
    let injected = 0;
    const client = await db.pool.connect();
    const restore = spyClient(client, statements, (text) => {
      if (!/INSERT INTO vulnerabilities\b/i.test(text)) return null;
      injected++;
      return '40P01';
    });
    let thrown: unknown = null;
    try {
      await client.query('BEGIN');
      await upsertVulnerability(client, vuln).catch((err: unknown) => {
        thrown = err;
      });
      await client.query('ROLLBACK');
    } finally {
      restore();
      client.release();
    }
    expect(injected).toBe(2);
    expect((thrown as { code?: string } | null)?.code).toBe('40P01');
    expect(isTransientLockError(thrown)).toBe(true);
    expect(await db.query(`SELECT 1 FROM vulnerabilities WHERE ghsa_id = $1`, [vuln.ghsaId])).toHaveLength(0);
  });

  it('Y-3: a non-transient error (23514) is not retried', async () => {
    const vuln = normalizeOsvVulnerability({ id: 'GHSA-y3y3-other-aaaa', summary: 'y3', severity: [] }, dep);
    const statements: string[] = [];
    let injected = 0;
    const client = await db.pool.connect();
    const restore = spyClient(client, statements, (text) => {
      if (!/INSERT INTO vulnerabilities\b/i.test(text)) return null;
      injected++;
      return '23514';
    });
    let thrown: unknown = null;
    try {
      await client.query('BEGIN');
      await upsertVulnerability(client, vuln).catch((err: unknown) => {
        thrown = err;
      });
      await client.query('ROLLBACK');
    } finally {
      restore();
      client.release();
    }
    expect(injected).toBe(1);
    expect((thrown as { code?: string } | null)?.code).toBe('23514');
    expect(statements.some((s) => /ROLLBACK TO SAVEPOINT/i.test(s))).toBe(false);
    expect(isTransientLockError(thrown)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe('Y-3: recheck project transaction retry', () => {
  it('Y-3: a 40P01 in the project transaction is retried once after a short wait -> project written, run completed', async () => {
    const seeded = await seedF4Scan(db, { projectName: 'y3-retry', deps: [['y3r-pkg', '1.0.0']] });
    publish('y3r-pkg', 'GHSA-y3y3-retr-aaaa');
    const statements: string[] = [];
    let injected = 0;
    // Injected outside the upsert savepoint (finding insert), so only the project-level retry can recover.
    const pool = injectingPool(db.pool, statements, (text) => (/INSERT INTO findings\b/i.test(text) && injected++ === 0 ? '40P01' : null));
    const lookup = makeF4Lookup(db, osv.origin, clock, logs, clients);
    const summary = await createRecheckRunner({ db: pool, lookup, expiry: expiryOf(), runtimeRunId: 'rt-Y3a', clock, logger }).run(new AbortController().signal);

    expect(injected).toBe(2);
    expect(statements.filter((s) => s === 'BEGIN')).toHaveLength(2); // two project transactions
    expect(clockSleeps).toHaveLength(1);
    expect(clockSleeps[0]).toBeGreaterThanOrEqual(100);
    expect(clockSleeps[0]).toBeLessThanOrEqual(200);
    expect(summary).toMatchObject({ status: 'completed', projectsChecked: 1, findingsOpened: 1, errorSummary: null });
    expect(await lastRun()).toMatchObject({ status: 'completed', projects_checked: 1, findings_opened: 1, error_summary: null });
    expect(await securityFindingCount(seeded.scanId)).toBe(1);
    const [scan] = await db.query<{ total: number }>(`SELECT total_vulnerabilities AS total FROM scans WHERE id = $1`, [seeded.scanId]);
    expect(scan.total).toBe(1);
  });

  it('Y-3: a second 40P01 rolls the project back with db:40 in error_summary (run partial); another project is still written; no raw message logged', async () => {
    const failing = await seedF4Scan(db, { projectName: 'y3-fail', deps: [['y3f-pkg', '1.0.0']] });
    const healthy = await seedF4Scan(db, { projectName: 'y3-ok', deps: [['y3o-pkg', '1.0.0']] });
    publish('y3f-pkg', 'GHSA-y3y3-fail-aaaa');
    publish('y3o-pkg', 'GHSA-y3y3-okok-aaaa');
    const statements: string[] = [];
    let injected = 0;
    const pool = injectingPool(db.pool, statements, (text, args) => {
      const params = Array.isArray(args[1]) ? (args[1] as unknown[]) : [];
      if (!/INSERT INTO findings\b/i.test(text) || params[0] !== failing.scanId) return null;
      injected++;
      return '40P01';
    });
    const lookup = makeF4Lookup(db, osv.origin, clock, logs, clients);
    const summary = await createRecheckRunner({ db: pool, lookup, expiry: expiryOf(), runtimeRunId: 'rt-Y3b', clock, logger }).run(new AbortController().signal);

    expect(injected).toBe(2); // first attempt + exactly one retry
    expect(summary).toMatchObject({ status: 'partial', projectsChecked: 1, findingsOpened: 1, errorSummary: 'db:40' });
    expect(await lastRun()).toMatchObject({ status: 'partial', projects_checked: 1, findings_opened: 1, error_summary: 'db:40' });
    expect(await securityFindingCount(failing.scanId)).toBe(0);
    expect(await securityFindingCount(healthy.scanId)).toBe(1);
    const [scan] = await db.query<{ total: number; vds: string | null }>(`SELECT total_vulnerabilities AS total, vulnerability_data_status AS vds FROM scans WHERE id = $1`, [failing.scanId]);
    expect(scan.total).toBe(0);
    expect(logs.some((l) => l.includes('proje yazımı geri alındı') && l.includes('40'))).toBe(true);
    expect(logs.join('\n')).not.toContain('injected raw message');
  });
});
