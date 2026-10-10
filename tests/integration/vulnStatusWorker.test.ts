/**
 * REQ-005 · `GET /api/vulnerability-data/status` (AC-P18-10, AC-P19-2/6/7;
 * contract REQ-005 section 2) and the scan worker's vulnerability write path
 * against the loopback fake OSV server (AC-P17-5/11 DB level, AC-G-8;
 * contract section 3). Embedded PostgreSQL, injected clock, no real network.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type { Express } from 'express';
import { createApp } from '../../src/app';
import { createDependencyEnricher, type DependencyEnricher } from '../../src/enrichment';
import type { AppClock } from '../../src/lib/clock';
import { ScanWorker } from '../../src/scanner/worker';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import type { VulnerabilityLookup } from '../../src/vulnerability/lookup';
import { createExpiryEvaluator } from '../../src/vulnerability/expiry';
import type { VulnerabilitySchedulerView } from '../../src/vulnerability/scheduler';
import { useTestDatabase } from '../helpers/db';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { startFakeRegistry } from '../helpers/fakeRegistry';
import { insertFindingRow, insertReview, insertUser, makeF4Lookup, seedF4Scan } from '../helpers/f4Seed';
import { TEST_PORT, createApiKey, expectErrorBody, req, setupPassword } from '../helpers/http';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

const H = 60 * 60_000;
const T0 = Date.parse('2026-10-10T08:00:00.000Z');
let nowMs = T0;
const clock: AppClock = { now: () => nowMs, sleep: async () => undefined };
let osv: FakeOsv;
let logs: string[] = [];
const clients: VulnerabilityClient[] = [];
const enrichers: DependencyEnricher[] = [];
const push = (...a: unknown[]) => logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };
let tmpRoot = '';

beforeEach(async () => {
  nowMs = T0;
  logs = [];
  osv = await startFakeOsv();
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-f4s-'));
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  for (const e of enrichers.splice(0)) e.close();
  await osv.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

const STATUS = '/api/vulnerability-data/status';
function appOf(view: (() => VulnerabilitySchedulerView | null) | undefined, pool: Pool = db.pool): Express {
  return createApp({ db: pool, port: TEST_PORT, host: '127.0.0.1', clock, ...(view ? { vulnerabilityScheduler: view } : {}) });
}
const stubView = (over: Partial<VulnerabilitySchedulerView> = {}): VulnerabilitySchedulerView => ({
  runtimeRunId: 'rt-A',
  isPaused: () => false,
  nextDue: async () => new Date(T0 + H),
  lastEvaluatedAt: () => new Date(T0 - 60_000),
  ...over,
});

describe('AC-P18-10: status endpoint — auth, headers, schema', () => {
  it('AC-P18-10: 401 without credentials; 200 with cookie and with Bearer; 403 without scans:read', async () => {
    const app = appOf(undefined);
    expectErrorBody(await req(app, 'get', STATUS), 401, 'setup_required');
    const cookie = await setupPassword(app);
    expectErrorBody(await req(app, 'get', STATUS), 401, 'unauthenticated');
    const { key } = await createApiKey(app, cookie);
    const byCookie = await req(app, 'get', STATUS, { cookie });
    expect(byCookie.status).toBe(200);
    expect(byCookie.headers['cache-control']).toBe('no-store');
    expect(String(byCookie.headers['content-type'])).toContain('application/json');
    const byBearer = await req(app, 'get', `${STATUS}?force=1`, { bearer: key });
    expect(byBearer.status).toBe(200);
    await db.query('DELETE FROM user_roles');
    const denied = await req(app, 'get', STATUS, { cookie });
    expectErrorBody(denied, 403, 'forbidden');
    expect(denied.body.message).toBe('Permission "scans:read" is required');
  });

  it('AC-P18-10: without a scheduler -> paused true, null-safe; exact key set (additionalProperties false); no NVD key information', async () => {
    const app = appOf(undefined);
    const cookie = await setupPassword(app);
    const res = await req(app, 'get', STATUS, { cookie });
    expect(res.status).toBe(200);
    const data = res.body.data;
    expect(Object.keys(res.body)).toEqual(['data']);
    expect(Object.keys(data).sort()).toEqual(
      ['generated_at', 'last_run', 'project_status_counts', 'projects', 'projects_truncated', 'risk_acceptance_expiry', 'scheduler', 'settings'].sort(),
    );
    expect(Object.keys(data.settings).sort()).toEqual(['interval_hours', 'lookup_enabled', 'nvd_enabled', 'recheck_enabled']);
    expect(data.generated_at).toBe(new Date(T0).toISOString());
    expect(data.scheduler).toEqual({ paused: true, next_check_earliest_at: null, current_run: null });
    expect(data.last_run).toBeNull();
    expect(data.projects).toEqual([]);
    expect(data.projects_truncated).toBe(false);
    expect(data.project_status_counts).toEqual({ complete: 0, partial: 0, unavailable: 0, disabled: 0, not_checked: 0 });
    expect(data.risk_acceptance_expiry).toEqual({ reopened_last_7_days: 0, last_evaluated_at: null });
    expect(JSON.stringify(res.body)).not.toMatch(/api_?key|nvd_key|rate_limit|has_key/i);
  });

  it('AC-P18-10: scheduler view values, current_run of this process only, last_run fields, projects and counts over all projects, reopened_last_7_days', async () => {
    await db.query(
      `INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at, finished_at, projects_checked, packages_checked, packages_unchecked, findings_opened, acceptances_reopened, error_summary)
       VALUES ('rt-OLD', 'completed', $1, $1, 9, 9, 0, 9, 0, NULL),
              ('rt-OLD', 'partial', $2, $3, 3, 410, 12, 1, 2, 'osv:unreachable')`,
      [new Date(T0 - 48 * H), new Date(T0 - 5 * H), new Date(T0 - 5 * H + 1234)],
    );
    await db.query(`INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at) VALUES ('rt-A', 'running', $1)`, [new Date(T0 - 60_000)]);
    await seedF4Scan(db, { projectName: 'b-proj', deps: [['a', '1.0.0']], vulnerabilityDataStatus: 'partial', vulnerabilityCheckedAt: '2026-10-10T03:00:00.000Z' });
    await seedF4Scan(db, { projectName: 'A-proj', deps: [['a', '1.0.0']], vulnerabilityDataStatus: 'complete' });
    const evil = await seedF4Scan(db, { projectName: '<img src=x onerror=alert(1)>\nline2', deps: [['a', '1.0.0']] });
    await seedF4Scan(db, { projectId: evil.projectId, deps: [['a', '1.0.0']], status: 'failed', completedAt: null });
    await seedF4Scan(db, { projectName: 'no-completed', deps: [['a', '1.0.0']], status: 'failed', completedAt: null });
    const [anyFinding] = await db.query<{ id: string }>(`SELECT gen_random_uuid()::text AS id`);
    await db.query(
      `INSERT INTO audit_logs (action, entity_type, entity_id, old_data, new_data, occurred_at) VALUES
        ('finding_updated', 'finding', $1, '{"status":"accepted"}', '{"status":"open","reason":"risk_acceptance_expired"}', $2),
        ('finding_updated', 'finding', $1, '{"status":"accepted"}', '{"status":"open","reason":"risk_acceptance_expired"}', $3),
        ('finding_updated', 'finding', $1, '{"status":"accepted"}', '{"status":"open","reason":"risk_acceptance_expired"}', $4),
        ('finding_updated', 'finding', $1, NULL, '{"finding":{}}', $2)`,
      [anyFinding.id, new Date(T0 - H), new Date(T0 - 7 * 24 * H + 60_000), new Date(T0 - 8 * 24 * H)],
    );
    const app = appOf(() => stubView());
    const cookie = await setupPassword(app);
    const auditBefore = (await db.query(`SELECT 1 FROM audit_logs`)).length;
    const runsBefore = await db.query(`SELECT * FROM vulnerability_recheck_runs ORDER BY id`);
    const res = await req(app, 'get', STATUS, { cookie });
    expect(res.status).toBe(200);
    const d = res.body.data;
    expect(d.scheduler.paused).toBe(false);
    // Contract 2.4: null when recheck_enabled is false (effective setting of the test environment).
    expect(d.scheduler.next_check_earliest_at).toBe(d.settings.recheck_enabled ? new Date(T0 + H).toISOString() : null);
    expect(d.scheduler.current_run).toMatchObject({ started_at: new Date(T0 - 60_000).toISOString() });
    expect(d.last_run).toMatchObject({
      status: 'partial', started_at: new Date(T0 - 5 * H).toISOString(), finished_at: new Date(T0 - 5 * H + 1234).toISOString(),
      projects_checked: 3, packages_checked: 410, packages_unchecked: 12, findings_opened: 1, acceptances_reopened: 2, error_summary: 'osv:unreachable',
    });
    expect(Object.keys(d.last_run).sort()).toEqual(
      ['acceptances_reopened', 'error_summary', 'finished_at', 'findings_opened', 'id', 'packages_checked', 'packages_unchecked', 'projects_checked', 'started_at', 'status'].sort(),
    );
    expect(d.projects.map((p: { project_name: string }) => p.project_name)).toEqual(['<img src=x onerror=alert(1)> line2', 'A-proj', 'b-proj']);
    for (const p of d.projects) {
      expect(Object.keys(p).sort()).toEqual(['latest_scan_completed_at', 'latest_scan_id', 'project_id', 'project_name', 'vulnerability_checked_at', 'vulnerability_data_status']);
    }
    expect(d.projects[0]).toMatchObject({ latest_scan_id: evil.scanId, vulnerability_data_status: null, vulnerability_checked_at: null });
    expect(d.projects[2]).toMatchObject({ vulnerability_data_status: 'partial', vulnerability_checked_at: '2026-10-10T03:00:00.000Z' });
    expect(d.project_status_counts).toEqual({ complete: 1, partial: 1, unavailable: 0, disabled: 0, not_checked: 1 });
    expect(d.risk_acceptance_expiry).toEqual({ reopened_last_7_days: 2, last_evaluated_at: new Date(T0 - 60_000).toISOString() });
    // No writes, no audit rows.
    expect(await db.query(`SELECT 1 FROM audit_logs`)).toHaveLength(auditBefore);
    expect(await db.query(`SELECT * FROM vulnerability_recheck_runs ORDER BY id`)).toEqual(runsBefore);
    expect(osv.requests).toHaveLength(0);
  });

  it('AC-P18-10: more than 500 projects -> 500 items, projects_truncated, counts over all projects', async () => {
    await db.query(
      `WITH p AS (INSERT INTO projects (name, repo_url) SELECT 'proj-' || lpad(g::text, 4, '0'), 'https://example.test/r.git' FROM generate_series(1, 501) g RETURNING id)
       INSERT INTO scans (project_id, trigger, status, ref, completed_at, vulnerability_data_status) SELECT id, 'manual', 'completed', 'main', NOW(), 'unavailable' FROM p`,
    );
    const app = appOf(() => stubView());
    const cookie = await setupPassword(app);
    const d = (await req(app, 'get', STATUS, { cookie })).body.data;
    expect(d.projects).toHaveLength(500);
    expect(d.projects_truncated).toBe(true);
    expect(d.project_status_counts.unavailable).toBe(501);
  });

  it('AC-P18-10: database error -> 500 internal_error with Cache-Control no-store, raw message not returned', async () => {
    const failing = new Proxy(db.pool, {
      get(target, prop, receiver) {
        if (prop === 'connect') return async () => { throw Object.assign(new Error('raw db secret text'), { code: '57P01' }); };
        const v = Reflect.get(target, prop, receiver);
        return typeof v === 'function' ? v.bind(target) : v;
      },
    });
    const okApp = appOf(undefined);
    const cookie = await setupPassword(okApp);
    const app = appOf(undefined, failing as Pool);
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const res = await req(app, 'get', STATUS, { cookie });
      expectErrorBody(res, 500, 'internal_error');
      expect(res.headers['cache-control']).toBe('no-store');
      expect(JSON.stringify(res.body)).not.toContain('raw db secret text');
    } finally {
      errors.mockRestore();
    }
  });
});

describe('AC-P19-2 / AC-P19-6 / AC-P19-7: reopened finding through the existing API', () => {
  it('AC-P19-2 / AC-P19-6 / AC-P19-7: expired acceptance -> workflow open; can be re-accepted; counted in reopened_last_7_days', async () => {
    const app = appOf(() => stubView());
    const cookie = await setupPassword(app);
    const reviewer = await insertUser(db);
    const seeded = await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    const fid = await insertFindingRow(db, { scanId: seeded.scanId, sdId: seeded.sd.a, status: 'accepted' });
    await insertReview(db, { findingId: fid, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil: '2026-10-01' });
    const keep = await insertFindingRow(db, { scanId: seeded.scanId, sdId: seeded.sd.a, status: 'accepted' });
    await insertReview(db, { findingId: keep, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil: '2026-12-31' });
    expect((await createExpiryEvaluator({ db: db.pool, clock, logger }).evaluate()).reopened).toBe(1);
    const wf = await req(app, 'get', `/api/findings/${fid}/workflow`, { cookie });
    expect(wf.status).toBe(200);
    expect(JSON.stringify(wf.body)).toContain('"open"');
    const kept = await req(app, 'get', `/api/findings/${keep}/workflow`, { cookie });
    expect(JSON.stringify(kept.body)).toContain('"accepted"');
    const status = (await req(app, 'get', STATUS, { cookie })).body.data;
    expect(status.risk_acceptance_expiry.reopened_last_7_days).toBe(1);
    const again = await req(app, 'post', `/api/findings/${fid}/accept-risk`, { cookie }).send({ accepted_until: '2026-12-31', acceptedUntil: '2026-12-31', notes: 'renewed', reason: 'renewed' });
    expect(again.status, JSON.stringify(again.body)).toBeLessThan(300);
    const [row] = await db.query<{ status: string }>(`SELECT status::text AS status FROM findings WHERE id = $1`, [fid]);
    expect(row.status).toBe('accepted');
  });
});

// ---------------------------------------------------------------------------
type Dep = SandboxScanResult['dependencies'][number];
const npmDep = (name: string, version: string): Dep =>
  ({ ecosystem: 'nodejs', name, version, purl: `pkg:npm/${name}@${version}`, scope: 'direct', licenses: ['MIT'], manifest_file: 'package-lock.json', manifest_path: '.' }) as Dep;

async function workerScan(opts: { lookup?: VulnerabilityLookup; enricher?: DependencyEnricher; deps: Dep[] }): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id::text AS id`, [`w-${Math.random().toString(36).slice(2)}`, tmpRoot]);
  const [s] = await db.query<{ id: string }>(`INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id::text AS id`, [p.id]);
  const runParser: RunParserFn = async (_d, _e, scanId) => ({ scan_id: scanId, status: 'completed', total_deps: opts.deps.length, dependencies: opts.deps, scan_files: [], parse_errors: [] });
  const w = new ScanWorker({
    db: db.pool, tmpRoot, logger, scanRoots: [tmpRoot], runParser, runId: 'run-W', clock,
    ...(opts.lookup ? { vulnerabilityLookup: opts.lookup } : {}),
    ...(opts.enricher ? { enricher: opts.enricher } : {}),
  });
  expect(await w.runOnce()).toBe(s.id);
  return s.id;
}
async function scanRow(scanId: string) {
  const [r] = await db.query<{ status: string; error_message: string | null; vds: string | null; checked: Date | null; total: number }>(
    `SELECT status::text AS status, error_message, vulnerability_data_status AS vds, vulnerability_checked_at AS checked, total_vulnerabilities AS total FROM scans WHERE id = $1`,
    [scanId],
  );
  return r;
}
const securityCount = async (scanId: string) => (await db.query(`SELECT 1 FROM findings WHERE scan_id = $1 AND finding_type = 'security'`, [scanId])).length;

describe('AC-P17-11 / AC-G-8: scan worker vulnerability write path', () => {
  it('AC-P17-5 / AC-P17-11: OSV hit -> security finding, status complete, checked_at = lookup start, no [osv] line', async () => {
    osv.vulns.set(osvKey('npm', 'vuln-pkg', '1.0.0'), [{ id: 'GHSA-2222-3333-4444', modified: '2026-01-01T00:00:00Z' }]);
    osv.addRecord('GHSA-2222-3333-4444');
    const scanId = await workerScan({ lookup: makeF4Lookup(db, osv.origin, clock, logs, clients), deps: [npmDep('vuln-pkg', '1.0.0'), npmDep('clean', '1.0.0')] });
    const row = await scanRow(scanId);
    expect(row).toMatchObject({ status: 'completed', vds: 'complete', total: 1 });
    expect(row.checked?.getTime()).toBe(T0);
    expect(row.error_message ?? '').not.toContain('[osv]');
    expect(await securityCount(scanId)).toBe(1);
  });

  it('AC-P17-5: detail record missing -> minimal finding persisted, status partial, [osv] line counts the missing detail', async () => {
    osv.vulns.set(osvKey('npm', 'vuln-pkg', '1.0.0'), [{ id: 'GHSA-5555-6666-7777', modified: '2026-01-01T00:00:00Z' }]);
    const scanId = await workerScan({ lookup: makeF4Lookup(db, osv.origin, clock, logs, clients), deps: [npmDep('vuln-pkg', '1.0.0')] });
    const row = await scanRow(scanId);
    expect(row.status).toBe('completed');
    expect(await securityCount(scanId)).toBe(1);
    expect(row.vds).toBe('partial');
    expect(row.error_message).toContain('[osv] Vulnerability data partial: 0 of 1 package(s) could not be checked; 1 vulnerability record(s) missing details.');
  });

  it('AC-P17-11 / contract 3.4: registry and OSV offline -> scan completed, [registry] then [osv] unavailable, no clean claim, no package names', async () => {
    const deadReg = await startFakeRegistry();
    const regOrigin = deadReg.origin;
    await deadReg.close();
    const deadOsv = osv.origin;
    await osv.close();
    osv = await startFakeOsv();
    const enricher = createDependencyEnricher({ config: { enabled: true, timeoutMs: 3_000, concurrency: 4 }, db: db.pool, logger, endpoints: { npm: regOrigin, pypi: regOrigin, files: regOrigin }, clock, env: {} });
    enrichers.push(enricher);
    const scanId = await workerScan({ lookup: makeF4Lookup(db, deadOsv, clock, logs, clients), enricher, deps: [npmDep('left-pad', '1.3.0'), npmDep('right-pad', '2.0.0')] });
    const row = await scanRow(scanId);
    expect(row).toMatchObject({ status: 'completed', vds: 'unavailable', total: 0 });
    const lines = (row.error_message ?? '').split('\n');
    const reg = lines.findIndex((l) => l.startsWith('[registry]'));
    const osvLine = lines.findIndex((l) => l.startsWith('[osv]'));
    expect(reg).toBeGreaterThanOrEqual(0);
    expect(osvLine).toBe(reg + 1);
    expect(lines[osvLine]).toBe('[osv] Vulnerability data unavailable: 2 of 2 package(s) could not be checked; 0 vulnerability record(s) missing details.');
    expect(lines.filter((l) => l.startsWith('[nvd]'))).toHaveLength(0);
    expect(row.error_message).not.toMatch(/left-pad|right-pad|127\.0\.0\.1/);
  });

  it('AC-G-8: engine not injected -> status and checked_at NULL, no [osv]/[nvd] line (F3 identical)', async () => {
    osv.vulns.set(osvKey('npm', 'vuln-pkg', '1.0.0'), [{ id: 'GHSA-2222-3333-4444' }]);
    const scanId = await workerScan({ deps: [npmDep('vuln-pkg', '1.0.0')] });
    const row = await scanRow(scanId);
    expect(row).toMatchObject({ status: 'completed', vds: null, checked: null, total: 0 });
    expect(row.error_message ?? '').not.toMatch(/\[osv\]|\[nvd\]/);
    expect(osv.requests).toHaveLength(0);
  });

  it('AC-P17-12: VULNERABILITY_LOOKUP=off engine -> disabled status, [osv] disabled line, no network', async () => {
    const scanId = await workerScan({ lookup: makeF4Lookup(db, osv.origin, clock, logs, clients, { lookupEnabled: false }), deps: [npmDep('vuln-pkg', '1.0.0')] });
    const row = await scanRow(scanId);
    expect(row.vds).toBe('disabled');
    expect(row.error_message).toContain('[osv] Vulnerability data disabled: vulnerability lookup disabled; 1 package(s) not checked.');
    expect(osv.requests).toHaveLength(0);
  });
});
