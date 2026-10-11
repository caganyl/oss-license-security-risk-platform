/**
 * REQ-005 P-18 / P-19 · Vulnerability recheck run, scheduler and risk
 * acceptance expiry against embedded PostgreSQL and the loopback fake OSV
 * server (AC-P18-1…9, 12, 13; AC-P19-1…5, 8; ADR-007 Karar 7–9; contract
 * REQ-005 sections 3.1, 4, 5). Injected clock; scheduler bodies are driven
 * through `tick()` / `expiryTick()` (timer delays only in the fake-timer test
 * with stub components and no database).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import type { AppClock } from '../../src/lib/clock';
import { ScanWorker } from '../../src/scanner/worker';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import { EXPIRY_BATCH_SIZE, createExpiryEvaluator, type ExpiryEvaluator } from '../../src/vulnerability/expiry';
import type { VulnerabilityLookup } from '../../src/vulnerability/lookup';
import { buildErrorSummary, createRecheckRunner, type RecheckRunner } from '../../src/vulnerability/recheck';
import { computeNextDue, createVulnerabilityScheduler, type VulnerabilityScheduler, type VulnerabilitySchedulerDeps } from '../../src/vulnerability/scheduler';
import { useTestDatabase } from '../helpers/db';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { insertFindingRow, insertReview, insertUser, makeF4Lookup, seedF4Scan } from '../helpers/f4Seed';
import { f3Dep, seedScan } from '../helpers/f3Seed';
import { REPO_ROOT } from '../helpers/paths';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

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
let tmpRoot = '';

beforeEach(async () => {
  nowMs = T0;
  logs = [];
  osv = await startFakeOsv();
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-f4r-'));
});
afterEach(async () => {
  vi.useRealTimers();
  for (const s of schedulers.splice(0)) await s.stop();
  for (const c of clients.splice(0)) c.close();
  await osv.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

const GHSA = 'GHSA-2222-3333-4444';
const lookupOf = (config = {}) => makeF4Lookup(db, osv.origin, clock, logs, clients, config);
const expiryOf = () => createExpiryEvaluator({ db: db.pool, clock, logger });
function runnerOf(lookup: VulnerabilityLookup = lookupOf(), limits?: { maxPackages?: number }, runtimeRunId = 'rt-A'): RecheckRunner {
  return createRecheckRunner({ db: db.pool, lookup, expiry: expiryOf(), runtimeRunId, clock, logger, ...(limits ? { limits } : {}) });
}
function schedulerOf(overrides: Partial<VulnerabilitySchedulerDeps> = {}): VulnerabilityScheduler {
  const s = createVulnerabilityScheduler({
    db: db.pool,
    lookup: lookupOf(),
    config: { recheckEnabled: true, intervalHours: 24 },
    runtimeRunId: 'rt-A',
    isRunning: () => true,
    clock,
    logger,
    firstCheckDelayMs: 24 * H,
    expiryIntervalMs: 24 * H,
    ...overrides,
  });
  schedulers.push(s);
  return s;
}
function publish(name: string, id = GHSA, version = '1.0.0'): void {
  osv.vulns.set(osvKey('npm', name, version), [{ id, modified: '2026-01-01T00:00:00Z' }]);
  osv.addRecord(id);
}
async function runs(): Promise<Array<Record<string, unknown>>> {
  return db.query(`SELECT id::text AS id, runtime_run_id, status, started_at, finished_at, projects_checked, packages_checked, packages_unchecked,
                          findings_opened, acceptances_reopened, error_summary FROM vulnerability_recheck_runs ORDER BY started_at, id`);
}
async function scanState(scanId: string) {
  const [r] = await db.query<{ vds: string | null; checked: Date | null; total: number; critical: number; error_message: string | null }>(
    `SELECT vulnerability_data_status AS vds, vulnerability_checked_at AS checked, total_vulnerabilities AS total, critical_vulns AS critical, error_message
       FROM scans WHERE id = $1`,
    [scanId],
  );
  return r;
}
async function securityFindings(scanId: string) {
  return db.query<{ id: string; status: string; fingerprint: string; recheck_run_id: string | null; carried_from_finding_id: string | null; scan_dependency_id: string; vulnerability_id: string }>(
    `SELECT f.id::text AS id, f.status::text AS status, f.fingerprint, f.recheck_run_id::text AS recheck_run_id, f.carried_from_finding_id::text AS carried_from_finding_id,
            f.scan_dependency_id::text AS scan_dependency_id, sf.vulnerability_id::text AS vulnerability_id
       FROM findings f JOIN security_findings sf ON sf.finding_id = f.id WHERE f.scan_id = $1 ORDER BY f.created_at, f.id`,
    [scanId],
  );
}

// Worker harness (P-18 acceptance and fingerprint consistency).
type Dep = SandboxScanResult['dependencies'][number];
const npmDep = (name: string, version: string): Dep =>
  ({ ecosystem: 'nodejs', name, version, purl: `pkg:npm/${name}@${version}`, scope: 'direct', licenses: ['MIT'], manifest_file: 'package-lock.json', manifest_path: '.' }) as Dep;
async function workerScan(projectId: string, lookup: VulnerabilityLookup, deps: Dep[]): Promise<string> {
  const [s] = await db.query<{ id: string }>(`INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id::text AS id`, [projectId]);
  const runParser: RunParserFn = async (_d, _e, scanId) => ({ scan_id: scanId, status: 'completed', total_deps: deps.length, dependencies: deps, scan_files: [], parse_errors: [] });
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [tmpRoot], runParser, runId: 'run-W', vulnerabilityLookup: lookup, clock });
  expect(await w.runOnce()).toBe(s.id);
  return s.id;
}

// ---------------------------------------------------------------------------
describe('AC-P18-4: a CVE published after the scan becomes a finding without a new scan', () => {
  it('AC-P18-4 / AC-P18-5 / AC-P18-8 / AC-P18-12: scan with empty OSV, publish, advance the interval, recheck -> open finding on the same scan, counters +1, audit row', async () => {
    const lookup = lookupOf();
    const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ('accept-p18', $1) RETURNING id::text AS id`, [tmpRoot]);
    const scanId = await workerScan(p.id, lookup, [npmDep('left-pad', '1.3.0')]);
    expect(await securityFindings(scanId)).toEqual([]);
    expect((await scanState(scanId)).vds).toBe('complete');
    const errorBefore = (await scanState(scanId)).error_message;

    publish('left-pad', GHSA, '1.3.0');
    nowMs += 24 * H;
    const s = schedulerOf({ lookup });
    await s.start();
    await s.tick();

    expect(await db.query(`SELECT 1 FROM scans WHERE project_id = $1`, [p.id])).toHaveLength(1);
    const [run] = await runs();
    expect(run).toMatchObject({ status: 'completed', runtime_run_id: 'rt-A', projects_checked: 1, packages_checked: 1, packages_unchecked: 0, findings_opened: 1, acceptances_reopened: 0, error_summary: null });
    const findings = await securityFindings(scanId);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ status: 'open', recheck_run_id: run.id });
    const [sdRow] = await db.query<{ id: string }>(`SELECT id::text AS id FROM scan_dependencies WHERE scan_id = $1`, [scanId]);
    expect(findings[0].scan_dependency_id).toBe(sdRow.id);
    const state = await scanState(scanId);
    expect(state).toMatchObject({ total: 1, vds: 'complete' });
    // The severity counter of the stored severity went up by one.
    const [sev] = await db.query<{ severity: string; critical: number; high: number; medium: number; low: number }>(
      `SELECT sf.severity::text AS severity, s.critical_vulns AS critical, s.high_vulns AS high, s.medium_vulns AS medium, s.low_vulns AS low
         FROM security_findings sf JOIN findings f ON f.id = sf.finding_id JOIN scans s ON s.id = f.scan_id WHERE f.id = $1`,
      [findings[0].id],
    );
    expect(sev.critical + sev.high + sev.medium + sev.low).toBe(1);
    expect((sev as unknown as Record<string, number>)[sev.severity]).toBe(1);
    expect(state.checked?.getTime()).toBe(nowMs);
    expect(state.error_message).toBe(errorBefore);
    // SLA from the recheck moment (critical default days from system settings).
    const [sla] = await db.query<{ sla: Date }>(`SELECT sla_deadline AS sla FROM security_findings WHERE finding_id = $1`, [findings[0].id]);
    expect(sla.sla.getTime()).toBeGreaterThan(nowMs);

    const audit = await db.query<Record<string, unknown>>(
      `SELECT action::text AS action, actor_id, actor_email, entity_type, entity_id::text AS entity_id, old_data, new_data, occurred_at FROM audit_logs WHERE action = 'finding_opened'`,
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actor_id: null, actor_email: null, entity_type: 'finding', entity_id: findings[0].id, old_data: null });
    expect((audit[0].occurred_at as Date).getTime()).toBe(nowMs);
    expect(audit[0].new_data).toEqual({
      source: 'vulnerability_recheck', recheck_run_id: run.id, scan_id: scanId, finding_id: findings[0].id,
      fingerprint: findings[0].fingerprint, vulnerability_id: findings[0].vulnerability_id, status: 'open',
    });
    // One summary line (contract 4.4) without package names.
    const summary = logs.filter((l) => l.startsWith('Güvenlik açığı yeniden kontrolü bitti'));
    expect(summary).toHaveLength(1);
    expect(summary[0]).toContain('durum=completed');
    expect(logs.join('\n')).not.toContain('left-pad');

    // AC-P18-5: the next run opens no duplicate.
    nowMs += 24 * H;
    await s.tick();
    expect(await securityFindings(scanId)).toHaveLength(1);
    expect((await runs())[1]).toMatchObject({ status: 'completed', findings_opened: 0, projects_checked: 1 });

    // AC-P18-5: the fingerprint equals the scan-path fingerprint (a new scan of the project).
    const second = await workerScan(p.id, lookup, [npmDep('left-pad', '1.3.0')]);
    const scanFindings = await securityFindings(second);
    expect(scanFindings).toHaveLength(1);
    expect(scanFindings[0].fingerprint).toBe(findings[0].fingerprint);
    expect(scanFindings[0].recheck_run_id).toBeNull();
  });
});

describe('AC-P18-3: scope = latest completed scan of every project', () => {
  it('AC-P18-3: shared package is one query; older scans and failed latest scans are not queried; project without completed scan skipped', async () => {
    const a = await seedF4Scan(db, { deps: [['old-only', '1.0.0']], completedAt: '2026-10-01T00:00:00Z' });
    await seedF4Scan(db, { projectId: a.projectId, deps: [['shared', '1.0.0']], completedAt: '2026-10-05T00:00:00Z' });
    await seedF4Scan(db, { projectId: a.projectId, deps: [['failed-only', '1.0.0']], status: 'failed', completedAt: null });
    await seedF4Scan(db, { deps: [['shared', '1.0.0'], ['p2only', '2.0.0']] });
    await seedF4Scan(db, { deps: [['never', '1.0.0']], status: 'failed', completedAt: null });
    const summary = await runnerOf().run(new AbortController().signal);
    const names = osv.batches().flat().map((q) => q.package.name).sort();
    expect(names).toEqual(['p2only', 'shared']);
    expect(summary).toMatchObject({ status: 'completed', projectsChecked: 2, packagesChecked: 2, packagesUnchecked: 0, findingsOpened: 0 });
  });

  it('AC-P18-3: more than the package limit -> excess unchecked, run partial with osv:package_limit', async () => {
    await seedF4Scan(db, { deps: [['a', '1.0.0'], ['b', '1.0.0'], ['c', '1.0.0']] });
    const summary = await runnerOf(lookupOf(), { maxPackages: 2 }).run(new AbortController().signal);
    expect(osv.batches().flat()).toHaveLength(2);
    expect(summary).toMatchObject({ status: 'partial', packagesChecked: 2, packagesUnchecked: 1, errorSummary: 'osv:package_limit' });
  });
});

describe('REQ-006 security review I-7: recheck scope key of PyPI/NuGet names is Turkish-locale safe', () => {
  /**
   * The scope SQL is not exported; it is read from the source text so the test
   * runs exactly the SQL the runner sends (only `${LATEST_SCANS_SQL}` is
   * substituted). The test database is `--locale=C`, so a Turkish ICU
   * collation is put on `packages.name` of this fresh per-test database to
   * reproduce a `tr_TR` ctype database: there `lower('I')` is a dotless `ı`
   * unless `COLLATE "C"` is applied.
   */
  const scopeSql = (): string => {
    const source = fs.readFileSync(path.join(REPO_ROOT, 'src', 'vulnerability', 'recheck.ts'), 'utf8');
    const latest = /const LATEST_SCANS_SQL = `([\s\S]*?)`;/.exec(source)?.[1];
    const scope = /const SCOPE_PAGE_SQL = `([\s\S]*?)`;/.exec(source)?.[1];
    expect(latest, 'LATEST_SCANS_SQL in recheck.ts').toBeDefined();
    expect(scope, 'SCOPE_PAGE_SQL in recheck.ts').toBeDefined();
    expect(scope).toContain('${LATEST_SCANS_SQL}');
    return scope!.replace('${LATEST_SCANS_SQL}', latest!);
  };
  const turkishCollation = async (): Promise<string | null> => {
    const rows = await db.query<{ collname: string }>(
      `SELECT collname FROM pg_collation WHERE collprovider = 'i' AND collname IN ('tr-TR-x-icu', 'tr-x-icu') ORDER BY collname LIMIT 1`,
    );
    return rows[0]?.collname ?? null;
  };

  it('I-7: every lower() in the scope SQL runs under COLLATE "C"', () => {
    const sql = scopeSql();
    const lowers = sql.match(/lower\(/g) ?? [];
    expect(lowers.length).toBeGreaterThanOrEqual(3);
    expect(sql).toContain(`lower(regexp_replace(p.name, '[-_.]+', '-', 'g') COLLATE "C")`);
    expect(sql).toContain(`lower(p.name COLLATE "C")`);
    expect(sql).toContain(`lower(p.version COLLATE "C")`);
  });

  it('I-7: "Ixml_Pkg", "IXML.pkg" and "ixml-pkg" are one PyPI key "ixml-pkg" (and "Ion.Core" one NuGet key) even with a Turkish column collation', async () => {
    // The pinned embedded PostgreSQL ships ICU; without a Turkish collation this test would be vacuous, so it fails instead.
    const tr = await turkishCollation();
    expect(tr, 'ICU Turkish collation (tr-TR-x-icu / tr-x-icu) in the test PostgreSQL').not.toBeNull();
    // Non-vacuous: this collation really lowers I to a dotless ı.
    const [probe] = await db.query<{ v: string }>(`SELECT lower('Ixml' COLLATE "${tr}") AS v`);
    expect(probe.v).toBe('ıxml');
    await db.query(`ALTER TABLE packages ALTER COLUMN name TYPE text COLLATE "${tr}"`);
    await seedScan(db, { projectName: 'i7-a', deps: [f3Dep({ ecosystem: 'python', name: 'Ixml_Pkg', version: '1.0', purl: 'pkg:pypi/ixml-pkg@1.0' })] });
    await seedScan(db, { projectName: 'i7-b', deps: [f3Dep({ ecosystem: 'python', name: 'IXML.pkg', version: '1.0', purl: 'pkg:pypi/ixml-pkg@1.0#b' })] });
    await seedScan(db, {
      projectName: 'i7-c',
      deps: [
        f3Dep({ ecosystem: 'python', name: 'ixml-pkg', version: '1.0', purl: 'pkg:pypi/ixml-pkg@1.0#c' }),
        f3Dep({ ecosystem: 'dotnet', name: 'Ion.Core', version: '1.0.0', purl: 'pkg:nuget/Ion.Core@1.0.0' }),
        f3Dep({ ecosystem: 'dotnet', name: 'ION.CORE', version: '1.0.0', purl: 'pkg:nuget/ION.CORE@1.0.0' }),
      ],
    });

    // The exact scope SQL: one row per registry key, ASCII-lowered.
    const rows = await db.query<{ eco: string; req: string; version: string }>(scopeSql(), [null, null, null, 5_000]);
    expect(rows.map((r) => [r.eco, r.req, r.version])).toEqual([
      ['nuget', 'ion.core', '1.0.0'],
      ['pypi', 'ixml-pkg', '1.0'],
    ]);
    // Mutation check: the pre-I-7 PyPI expression (no COLLATE "C") splits the key under this collation.
    const before = scopeSql().replace(`lower(regexp_replace(p.name, '[-_.]+', '-', 'g') COLLATE "C")`, `lower(regexp_replace(p.name, '[-_.]+', '-', 'g'))`);
    const split = await db.query<{ eco: string; req: string }>(before, [null, null, null, 5_000]);
    expect(split.filter((r) => r.eco === 'pypi').map((r) => r.req)).toEqual(['ixml-pkg', 'ıxml-pkg']);

    // The runner sends one PyPI and one NuGet query.
    const summary = await runnerOf().run(new AbortController().signal);
    const queries = osv.batches().flat().map((q) => `${q.package.ecosystem}|${q.package.name}@${q.version}`).sort();
    expect(queries).toHaveLength(2);
    expect(queries[1]).toBe('PyPI|ixml-pkg@1.0');
    expect(queries[0]).toMatch(/^NuGet\|(Ion\.Core|ION\.CORE)@1\.0\.0$/);
    expect(summary).toMatchObject({ packagesChecked: 2, packagesUnchecked: 0 });
  });
});

describe('AC-P18-5: decision carry-over in the recheck (ADR-003 c)', () => {
  it('AC-P18-5 / AC-P19-1: false_positive and an unexpired acceptance (boundary day = local today) are carried; an expired one is reopened at the run start and a new open finding is opened', async () => {
    const reviewer = await insertUser(db);
    const projects: Record<string, string> = {};
    for (const name of ['fp', 'acc', 'expired']) {
      const seeded = await seedF4Scan(db, { projectName: name, deps: [['vuln-pkg', '1.0.0']], completedAt: '2026-10-01T00:00:00Z' });
      projects[name] = seeded.projectId;
    }
    publish('vuln-pkg');
    await runnerOf().run(new AbortController().signal);
    const first = await db.query<{ id: string; name: string; scan_id: string }>(
      `SELECT f.id::text AS id, p.name, f.scan_id::text AS scan_id FROM findings f JOIN scans s ON s.id = f.scan_id JOIN projects p ON p.id = s.project_id`,
    );
    expect(first).toHaveLength(3);
    const byName = Object.fromEntries(first.map((f) => [f.name, f]));
    await db.query(`UPDATE findings SET status = 'false_positive' WHERE id = $1`, [byName.fp.id]);
    await insertReview(db, { findingId: byName.fp.id, reviewerId: reviewer, decision: 'false_positive' });
    await db.query(`UPDATE findings SET status = 'accepted' WHERE id = ANY($1::uuid[])`, [[byName.acc.id, byName.expired.id]]);
    // "today" of the injected clock in the process-local zone.
    nowMs = new Date(2026, 9, 12, 12, 0, 0).getTime();
    await insertReview(db, { findingId: byName.acc.id, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil: '2026-10-12' });
    await insertReview(db, { findingId: byName.expired.id, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil: '2026-10-11' });

    const newer: Record<string, string> = {};
    for (const name of ['fp', 'acc', 'expired']) {
      newer[name] = (await seedF4Scan(db, { projectId: projects[name], deps: [['vuln-pkg', '1.0.0']], completedAt: '2026-10-11T00:00:00Z' })).scanId;
    }
    const summary = await runnerOf().run(new AbortController().signal);
    expect(summary).toMatchObject({ status: 'completed', findingsOpened: 3, acceptancesReopened: 1 });
    const fp = (await securityFindings(newer.fp))[0];
    const acc = (await securityFindings(newer.acc))[0];
    const exp = (await securityFindings(newer.expired))[0];
    expect(fp).toMatchObject({ status: 'false_positive', carried_from_finding_id: byName.fp.id });
    expect(acc).toMatchObject({ status: 'accepted', carried_from_finding_id: byName.acc.id });
    expect(exp).toMatchObject({ status: 'open', carried_from_finding_id: null });
    expect(await db.query(`SELECT 1 FROM finding_reviews WHERE finding_id = ANY($1::uuid[])`, [[fp.id, acc.id]])).toHaveLength(2);
    const [old] = await db.query<{ status: string }>(`SELECT status::text AS status FROM findings WHERE id = $1`, [byName.expired.id]);
    expect(old.status).toBe('open');
    const audits = await db.query<{ new_data: { status: string; finding_id: string } }>(
      `SELECT new_data FROM audit_logs WHERE action = 'finding_opened' AND new_data->>'recheck_run_id' = $1`,
      [summary!.id],
    );
    expect(audits.map((a) => a.new_data.status).sort()).toEqual(['accepted', 'false_positive', 'open']);
  });
});

describe('AC-P18-6: concurrency and consistency', () => {
  it('AC-P18-6: a newer scan completed during the run -> nothing written to the older scan, project not counted', async () => {
    const seeded = await seedF4Scan(db, { deps: [['vuln-pkg', '1.0.0']], completedAt: '2026-10-01T00:00:00Z' });
    publish('vuln-pkg');
    const inner = lookupOf();
    let newerScan = '';
    const wrapped = {
      get enabled() {
        return inner.enabled;
      },
      lookup: async (...args: Parameters<VulnerabilityLookup['lookup']>) => {
        newerScan = (await seedF4Scan(db, { projectId: seeded.projectId, deps: [['other', '1.0.0']], completedAt: '2026-10-09T00:00:00Z' })).scanId;
        return inner.lookup(...args);
      },
    } as unknown as VulnerabilityLookup;
    const summary = await runnerOf(wrapped).run(new AbortController().signal);
    expect(summary).toMatchObject({ status: 'completed', projectsChecked: 0, findingsOpened: 0 });
    expect(await securityFindings(seeded.scanId)).toEqual([]);
    expect(await securityFindings(newerScan)).toEqual([]);
    expect((await scanState(seeded.scanId)).total).toBe(0);
  });

  it('AC-P18-6 / AC-P18-8: fence — the run row taken away during the run -> no writes, run reported interrupted, row not overwritten', async () => {
    const seeded = await seedF4Scan(db, { deps: [['vuln-pkg', '1.0.0']] });
    publish('vuln-pkg');
    const inner = lookupOf();
    const wrapped = {
      get enabled() {
        return inner.enabled;
      },
      lookup: async (...args: Parameters<VulnerabilityLookup['lookup']>) => {
        await db.query(`UPDATE vulnerability_recheck_runs SET status = 'interrupted', finished_at = NOW() WHERE status = 'running'`);
        return inner.lookup(...args);
      },
    } as unknown as VulnerabilityLookup;
    const summary = await runnerOf(wrapped).run(new AbortController().signal);
    expect(summary?.status).toBe('interrupted');
    expect(await securityFindings(seeded.scanId)).toEqual([]);
    const [row] = await runs();
    expect(row).toMatchObject({ status: 'interrupted', findings_opened: 0, projects_checked: 0 });
  });

  it('AC-P18-1 / AC-P18-8: a second running row is rejected (partial unique index) -> run not started', async () => {
    await db.query(`INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at) VALUES ('rt-OTHER', 'running', NOW())`);
    await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    expect(await runnerOf().run(new AbortController().signal)).toBeNull();
    expect(await runs()).toHaveLength(1);
    expect(osv.requests).toHaveLength(0);
  });

  it('AC-P18-8: abort during the network wait -> interrupted, no writes', async () => {
    const seeded = await seedF4Scan(db, { deps: [['vuln-pkg', '1.0.0']] });
    osv.override('/v1/querybatch', { hang: true });
    const ac = new AbortController();
    const pending = runnerOf().run(ac.signal);
    await vi.waitFor(() => expect(osv.count('/v1/querybatch')).toBeGreaterThan(0), { timeout: 10_000 });
    ac.abort('shutdown');
    const summary = await pending;
    expect(summary?.status).toBe('interrupted');
    expect((await runs())[0]).toMatchObject({ status: 'interrupted' });
    expect(await securityFindings(seeded.scanId)).toEqual([]);
  });
});

describe('AC-P18-7: vulnerability_data_status transitions (r2 table)', () => {
  const PREV = [null, 'unavailable', 'disabled', 'complete', 'partial'] as const;
  async function seedTable() {
    const checkedAt = '2026-10-01T00:00:00.000Z';
    const rows: Array<{ prev: string | null; scanId: string }> = [];
    for (const prev of PREV) {
      const s = await seedF4Scan(db, { deps: [['a', '1.0.0'], ['b', '1.0.0']], vulnerabilityDataStatus: prev, vulnerabilityCheckedAt: prev === null ? null : checkedAt });
      rows.push({ prev, scanId: s.scanId });
    }
    const onlyB = await seedF4Scan(db, { deps: [['b', '1.0.0']], vulnerabilityDataStatus: 'unavailable', vulnerabilityCheckedAt: checkedAt });
    return { rows, onlyB: onlyB.scanId, checkedAt };
  }

  it('AC-P18-7 (all checked): every previous status -> complete, checked_at = run start', async () => {
    const { rows, onlyB } = await seedTable();
    const summary = await runnerOf().run(new AbortController().signal);
    expect(summary).toMatchObject({ status: 'completed', errorSummary: null });
    for (const r of [...rows, { prev: 'unavailable', scanId: onlyB }]) {
      const st = await scanState(r.scanId);
      expect(st.vds, String(r.prev)).toBe('complete');
      expect(st.checked?.getTime(), String(r.prev)).toBe(T0);
    }
  });

  it('AC-P18-7 (some checked): unavailable/NULL/disabled -> partial, partial stays, complete never lowered; zero checked -> unchanged; checked_at unchanged', async () => {
    const { rows, onlyB, checkedAt } = await seedTable();
    const summary = await runnerOf(lookupOf(), { maxPackages: 1 }).run(new AbortController().signal);
    expect(summary).toMatchObject({ status: 'partial', packagesChecked: 1, packagesUnchecked: 1, errorSummary: 'osv:package_limit' });
    const expected: Record<string, string> = { null: 'partial', unavailable: 'partial', disabled: 'partial', complete: 'complete', partial: 'partial' };
    for (const r of rows) {
      const st = await scanState(r.scanId);
      expect(st.vds, String(r.prev)).toBe(expected[String(r.prev)]);
      expect(st.checked === null ? null : st.checked.toISOString(), String(r.prev)).toBe(r.prev === null ? null : checkedAt);
    }
    expect(await scanState(onlyB)).toMatchObject({ vds: 'unavailable' });
  });

  it('AC-P18-7 / AC-P18-9 (none checked, OSV down): run failed with osv:unreachable, statuses unchanged, findings kept, nothing pulled to complete', async () => {
    const { rows } = await seedTable();
    const [sd] = await db.query<{ id: string }>(`SELECT id::text AS id FROM scan_dependencies WHERE scan_id = $1 LIMIT 1`, [rows[1].scanId]);
    const kept = await insertFindingRow(db, { scanId: rows[1].scanId, sdId: sd.id, status: 'open' });
    const deadOrigin = osv.origin;
    await osv.close();
    osv = await startFakeOsv();
    const summary = await createRecheckRunner({ db: db.pool, lookup: makeF4Lookup(db, deadOrigin, clock, logs, clients), expiry: expiryOf(), runtimeRunId: 'rt-A', clock, logger }).run(new AbortController().signal);
    expect(summary).toMatchObject({ status: 'failed', packagesChecked: 0, packagesUnchecked: 2, errorSummary: 'osv:unreachable', projectsChecked: 0 });
    for (const r of rows) expect((await scanState(r.scanId)).vds, String(r.prev)).toBe(r.prev);
    expect(await db.query(`SELECT 1 FROM findings WHERE id = $1`, [kept])).toHaveLength(1);
  });
});

describe('AC-P18-8: error_summary codes (contract 4.3)', () => {
  it('AC-P18-8: fixed table order, no repetition, db classes sorted, internal last, <= 500 code points', () => {
    expect(buildErrorSummary(new Set(['package_limit', 'unreachable', 'invalid_response']), new Set(['40', '23']), true)).toBe(
      'osv:unreachable, osv:invalid_response, osv:package_limit, db:23, db:40, internal:error',
    );
    expect(buildErrorSummary(new Set(), new Set(), false)).toBeNull();
    const many = new Set(Array.from({ length: 200 }, (_, i) => String(i).padStart(2, '0').slice(-2)));
    const out = buildErrorSummary(new Set(), many, false)!;
    expect(Array.from(out).length).toBeLessThanOrEqual(500);
    expect(out).toMatch(/^db:\d\d(, db:\d\d)*$/);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P18-1 / AC-P18-2: scheduler due rule (computeNextDue, pure)', () => {
  const run = (status: string, startedMs: number, finishedMs: number | null = startedMs + 60_000) => ({
    status, startedAt: new Date(startedMs), finishedAt: finishedMs === null ? null : new Date(finishedMs),
  });
  const due = (runs: ReturnType<typeof run>[], now: number) => computeNextDue(runs, now, { intervalHours: 24 }).getTime();

  it('AC-P18-1: 23 h 50 min after a successful start -> not due; 24 h -> due', () => {
    const r = [run('completed', T0)];
    expect(due(r, T0 + 23 * H + 50 * 60_000)).toBeGreaterThan(T0 + 23 * H + 50 * 60_000);
    expect(due(r, T0 + 24 * H)).toBe(T0 + 24 * H);
  });
  it('AC-P18-1: failed -> earliest finished_at + 1 h (30 min not due, 60 min due); failed before the last success ignored', () => {
    const r = [run('completed', T0 - 48 * H), run('failed', T0, T0)];
    expect(due(r, T0 + 30 * 60_000)).toBe(T0 + H);
    expect(due([run('failed', T0 - 2 * H), run('completed', T0)], T0 + H)).toBe(T0 + 24 * H);
  });
  it('AC-P18-1: partial counts as successful (10 min later not due); disabled counts; interrupted does not move the due time', () => {
    expect(due([run('partial', T0)], T0 + 10 * 60_000)).toBe(T0 + 24 * H);
    expect(due([run('disabled', T0, T0)], T0 + H)).toBe(T0 + 24 * H);
    expect(due([run('completed', T0), run('interrupted', T0 + 2 * H)], T0 + 3 * H)).toBe(T0 + 24 * H);
  });
  it('AC-P18-2: no run -> now; last run 3 days ago -> due already (one run, not one per missed day)', () => {
    expect(due([], T0)).toBe(T0);
    expect(due([run('completed', T0 - 72 * H)], T0)).toBe(T0 - 48 * H);
  });
  it('AC-P18-1: interval hours setting is used', () => {
    expect(computeNextDue([run('completed', T0)], T0, { intervalHours: 6 }).getTime()).toBe(T0 + 6 * H);
  });
});

describe('AC-P18-1 / AC-P18-2 / AC-P19-3: scheduler timers (fake timers, stub components, no database)', () => {
  it('AC-P18-2 / AC-P19-3: expiry at start then hourly; first recheck check after 60 s, then every 10 min', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const calls = { run: 0, evaluate: 0 };
    const fakeDb = { query: async () => ({ rows: [] }) } as unknown as Pool;
    const expiry: ExpiryEvaluator = { evaluate: async () => { calls.evaluate++; return { reopened: 0, evaluatedFor: '2026-10-10', ok: true }; }, lastEvaluatedAt: () => null };
    const recheck: RecheckRunner = { run: async () => { calls.run++; return null; }, writeDisabled: async () => undefined };
    const lookup = { enabled: true, lookup: async () => { throw new Error('unused'); } } as unknown as VulnerabilityLookup;
    const s = createVulnerabilityScheduler({ db: fakeDb, lookup, config: { recheckEnabled: true, intervalHours: 24 }, runtimeRunId: 'rt-T', isRunning: () => true, clock, logger, expiry, recheck });
    await s.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toEqual({ run: 0, evaluate: 1 });
    await vi.advanceTimersByTimeAsync(59_999);
    expect(calls.run).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls.run).toBe(1);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(calls.run).toBe(2);
    await vi.advanceTimersByTimeAsync(50 * 60_000);
    expect(calls.evaluate).toBe(2);
    expect(calls.run).toBe(7);
    await s.stop();
    await vi.advanceTimersByTimeAsync(2 * H);
    expect(calls).toEqual({ run: 7, evaluate: 2 });
  });
});

describe('AC-P18-1 / AC-P18-2 / AC-P18-13: scheduler with the database', () => {
  it('AC-P18-8: start-up sweep closes stale running rows as interrupted', async () => {
    await db.query(`INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at) VALUES ('rt-DEAD', 'running', $1)`, [new Date(T0 - H)]);
    await schedulerOf().start();
    const [row] = await runs();
    expect(row.status).toBe('interrupted');
    expect((row.finished_at as Date).getTime()).toBe(T0);
  });

  it('AC-P18-2: last run 3 days ago -> one run after start, the next tick does not run again', async () => {
    await db.query(`INSERT INTO vulnerability_recheck_runs (runtime_run_id, status, started_at, finished_at) VALUES ('rt-OLD', 'completed', $1, $1)`, [new Date(T0 - 72 * H)]);
    await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    const s = schedulerOf();
    await s.start();
    await s.tick();
    nowMs += 10 * 60_000;
    await s.tick();
    expect((await runs()).map((r) => r.status)).toEqual(['completed', 'completed']);
  });

  it('AC-P18-1: failed run -> no retry after 30 min, retry after 60 min', async () => {
    await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    const deadOrigin = osv.origin;
    await osv.close();
    osv = await startFakeOsv();
    const s = schedulerOf({ lookup: makeF4Lookup(db, deadOrigin, clock, logs, clients) });
    await s.start();
    await s.tick();
    expect((await runs()).map((r) => r.status)).toEqual(['failed']);
    nowMs += 30 * 60_000;
    await s.tick();
    expect(await runs()).toHaveLength(1);
    nowMs += 31 * 60_000;
    await s.tick();
    expect((await runs()).map((r) => r.status)).toEqual(['failed', 'failed']);
  });

  it('AC-P18-1: two concurrent triggers -> one run', async () => {
    await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    const s = schedulerOf();
    await s.start();
    await Promise.all([s.tick(), s.tick()]);
    expect(await runs()).toHaveLength(1);
  });

  it('AC-P18-1: degraded mode — pause aborts the in-flight run (interrupted) and blocks triggers; resume continues; isRunning false blocks', async () => {
    await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    osv.override('/v1/querybatch', { hang: true });
    const s = schedulerOf();
    await s.start();
    const inFlight = s.tick();
    await vi.waitFor(() => expect(osv.count('/v1/querybatch')).toBeGreaterThan(0), { timeout: 10_000 });
    s.pause();
    await inFlight;
    expect((await runs()).map((r) => r.status)).toEqual(['interrupted']);
    expect(s.isPaused()).toBe(true);
    osv.clearOverride('/v1/querybatch');
    await s.tick();
    expect(await runs()).toHaveLength(1);
    s.resume();
    expect(s.isPaused()).toBe(false);
    nowMs += 60_000;
    await s.tick();
    expect((await runs()).map((r) => r.status)).toEqual(['interrupted', 'completed']);

    let running = false;
    const t = schedulerOf({ isRunning: () => running, runtimeRunId: 'rt-B' });
    await t.start();
    nowMs += 25 * H;
    await t.tick();
    expect(await runs()).toHaveLength(2);
    expect(t.isPaused()).toBe(true);
    running = true;
    await t.tick();
    expect(await runs()).toHaveLength(3);
  });

  it('AC-P18-13 / AC-P19-3: VULNERABILITY_RECHECK=off -> no run row and no OSV request as time advances; expiry still reopens', async () => {
    const reviewer = await insertUser(db);
    const seeded = await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    const fid = await insertFindingRow(db, { scanId: seeded.scanId, sdId: seeded.sd.a, status: 'accepted' });
    await insertReview(db, { findingId: fid, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil: '2026-10-20' });
    const s = schedulerOf({ config: { recheckEnabled: false, intervalHours: 24 } });
    await s.start();
    for (let i = 0; i < 3; i++) {
      nowMs += 24 * H;
      await s.tick();
    }
    expect(await runs()).toEqual([]);
    expect(osv.requests).toHaveLength(0);
    expect(await s.nextDue()).toBeNull();
    nowMs = new Date(2026, 9, 21, 0, 0, 0).getTime();
    await s.expiryTick();
    const [f] = await db.query<{ status: string }>(`SELECT status::text AS status FROM findings WHERE id = $1`, [fid]);
    expect(f.status).toBe('open');
  });

  it('AC-P18-13: VULNERABILITY_LOOKUP=off -> one disabled row per interval, counters 0, no network', async () => {
    await seedF4Scan(db, { deps: [['a', '1.0.0']] });
    const s = schedulerOf({ lookup: lookupOf({ lookupEnabled: false }) });
    await s.start();
    await s.tick();
    nowMs += H;
    await s.tick();
    nowMs += 24 * H;
    await s.tick();
    const rows = await runs();
    expect(rows.map((r) => r.status)).toEqual(['disabled', 'disabled']);
    expect(rows[0]).toMatchObject({ projects_checked: 0, packages_checked: 0, packages_unchecked: 0, findings_opened: 0, acceptances_reopened: 0, error_summary: null });
    expect((rows[0].started_at as Date).getTime()).toBe((rows[0].finished_at as Date).getTime());
    expect(osv.requests).toHaveLength(0);
    // Lookup not injected at all behaves the same.
    const n = schedulerOf({ lookup: null, runtimeRunId: 'rt-N' });
    await n.start();
    nowMs += 24 * H;
    await n.tick();
    expect((await runs()).map((r) => r.status)).toEqual(['disabled', 'disabled', 'disabled']);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P19-1 / AC-P19-2 / AC-P19-4: risk acceptance expiry', () => {
  async function acceptedFinding(acceptedUntil: string | null | 'none', reviewer: string, assignee: string | null = null) {
    const seeded = await seedF4Scan(db, { deps: [[`pkg-${Math.random().toString(36).slice(2, 8)}`, '1.0.0']] });
    const sdId = Object.values(seeded.sd)[0];
    const id = await insertFindingRow(db, { scanId: seeded.scanId, sdId, status: 'accepted', assigneeId: assignee });
    const reviewId = acceptedUntil === 'none' ? null : await insertReview(db, { findingId: id, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil });
    return { id, reviewId };
  }
  const statusOf = async (id: string) => (await db.query<{ status: string }>(`SELECT status::text AS status FROM findings WHERE id = $1`, [id]))[0].status;

  it('AC-P19-1 / AC-P19-2 / AC-P19-4 / AC-P18-10: boundary day stays accepted until local midnight; NULL and no review expire; audit shape; no review row; assignee kept; lastEvaluatedAt', async () => {
    const reviewer = await insertUser(db);
    const assignee = await insertUser(db);
    const boundary = await acceptedFinding('2026-10-10', reviewer, assignee);
    const open = await acceptedFinding(null, reviewer);
    const none = await acceptedFinding('none', reviewer);
    const evaluator = expiryOf();
    expect(evaluator.lastEvaluatedAt()).toBeNull();

    nowMs = new Date(2026, 9, 10, 23, 59, 0).getTime();
    const first = await evaluator.evaluate();
    expect(first).toMatchObject({ reopened: 2, evaluatedFor: '2026-10-10', ok: true });
    expect(await statusOf(boundary.id)).toBe('accepted');
    expect(await statusOf(open.id)).toBe('open');
    expect(await statusOf(none.id)).toBe('open');
    expect(evaluator.lastEvaluatedAt()?.getTime()).toBe(nowMs);

    const reviewsBefore = await db.query(`SELECT id FROM finding_reviews`);
    nowMs = new Date(2026, 9, 11, 0, 0, 0).getTime();
    expect((await evaluator.evaluate()).reopened).toBe(1);
    expect(await statusOf(boundary.id)).toBe('open');
    expect(await db.query(`SELECT id FROM finding_reviews`)).toHaveLength(reviewsBefore.length);
    const [f] = await db.query<{ assignee_id: string }>(`SELECT assignee_id::text AS assignee_id FROM findings WHERE id = $1`, [boundary.id]);
    expect(f.assignee_id).toBe(assignee);

    const audits = await db.query<Record<string, unknown>>(
      `SELECT entity_id::text AS entity_id, actor_id, actor_email, entity_type, old_data, new_data, occurred_at, ip_address, user_agent
         FROM audit_logs WHERE action = 'finding_updated' ORDER BY occurred_at, entity_id`,
    );
    expect(audits).toHaveLength(3);
    const byId = Object.fromEntries(audits.map((a) => [a.entity_id as string, a]));
    for (const a of audits) expect(a).toMatchObject({ actor_id: null, actor_email: null, entity_type: 'finding', old_data: { status: 'accepted' }, ip_address: null, user_agent: null });
    expect(byId[boundary.id].new_data).toEqual({ status: 'open', reason: 'risk_acceptance_expired', review_id: boundary.reviewId, accepted_until: '2026-10-10', evaluated_for: '2026-10-11' });
    expect((byId[boundary.id].occurred_at as Date).getTime()).toBe(nowMs);
    expect(byId[open.id].new_data).toEqual({ status: 'open', reason: 'risk_acceptance_expired', review_id: open.reviewId, accepted_until: null, evaluated_for: '2026-10-10' });
    expect(byId[none.id].new_data).toEqual({ status: 'open', reason: 'risk_acceptance_expired', review_id: null, accepted_until: null, evaluated_for: '2026-10-10' });
  });

  it('AC-P19-5: idempotent; a fresh future accept_risk just before keeps the finding accepted', async () => {
    const reviewer = await insertUser(db);
    const renewed = await acceptedFinding('2026-10-01', reviewer);
    await insertReview(db, { findingId: renewed.id, reviewerId: reviewer, decision: 'accept_risk', acceptedUntil: '2026-12-31', createdAt: new Date(Date.now() + 60_000).toISOString() });
    const expired = await acceptedFinding('2026-10-01', reviewer);
    const evaluator = expiryOf();
    expect((await evaluator.evaluate()).reopened).toBe(1);
    expect(await statusOf(renewed.id)).toBe('accepted');
    expect(await statusOf(expired.id)).toBe('open');
    const auditCount = (await db.query(`SELECT 1 FROM audit_logs`)).length;
    expect((await evaluator.evaluate()).reopened).toBe(0);
    expect(await db.query(`SELECT 1 FROM audit_logs`)).toHaveLength(auditCount);
  });

  it('AC-P19-5: batches of 500 with FOR UPDATE SKIP LOCKED; a row locked by a user transaction is skipped and picked up next time', async () => {
    const seeded = await seedF4Scan(db, { deps: [['bulk', '1.0.0']] });
    await db.query(
      `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status, fingerprint)
       SELECT $1, $2, 'security', 'accepted', md5(g::text) || md5((g + 1)::text) FROM generate_series(1, 1201) g`,
      [seeded.scanId, seeded.sd.bulk],
    );
    const [locked] = await db.query<{ id: string }>(`SELECT id::text AS id FROM findings ORDER BY id DESC LIMIT 1`);
    const holder = await db.pool.connect();
    const selects: string[] = [];
    const spyPool = {
      connect: async () => {
        const client = await db.pool.connect();
        const original = client.query.bind(client) as (...a: unknown[]) => unknown;
        (client as unknown as { query: (...a: unknown[]) => unknown }).query = (...a: unknown[]) => {
          if (typeof a[0] === 'string' && a[0].includes("f.status = 'accepted'")) selects.push(a[0]);
          return original(...a);
        };
        return client as PoolClient;
      },
    } as unknown as Pool;
    try {
      await holder.query('BEGIN');
      await holder.query(`SELECT id FROM findings WHERE id = $1 FOR UPDATE`, [locked.id]);
      const result = await createExpiryEvaluator({ db: spyPool, clock, logger }).evaluate();
      expect(result.reopened).toBe(1200);
      expect(EXPIRY_BATCH_SIZE).toBe(500);
      expect(selects.length).toBe(3);
      for (const q of selects) {
        expect(q).toContain('LIMIT 500');
        expect(q).toContain('FOR UPDATE SKIP LOCKED');
      }
      expect(await statusOf(locked.id)).toBe('accepted');
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
    }
    expect((await expiryOf().evaluate()).reopened).toBe(1);
    expect((await db.query(`SELECT 1 FROM audit_logs WHERE action = 'finding_updated'`)).length).toBe(1201);
  });

  it('AC-P19-8: a database error rolls the batch back, logs only the class/code and the next trigger retries', async () => {
    const reviewer = await insertUser(db);
    const f = await acceptedFinding('2026-10-01', reviewer);
    let fail = true;
    const failingPool = {
      connect: async () => {
        const client = await db.pool.connect();
        const original = client.query.bind(client) as (...a: unknown[]) => unknown;
        (client as unknown as { query: (...a: unknown[]) => unknown }).query = (...a: unknown[]) => {
          if (fail && typeof a[0] === 'string' && a[0].includes('INSERT INTO audit_logs')) {
            return Promise.reject(Object.assign(new Error('secret raw message'), { code: '40001' }));
          }
          return original(...a);
        };
        return client as PoolClient;
      },
    } as unknown as Pool;
    const evaluator = createExpiryEvaluator({ db: failingPool, clock, logger });
    const r = await evaluator.evaluate();
    expect(r).toMatchObject({ ok: false, reopened: 0 });
    expect(await statusOf(f.id)).toBe('accepted');
    expect(evaluator.lastEvaluatedAt()).toBeNull();
    const line = logs.find((l) => l.includes('Risk kabulü süre değerlendirmesi başarısız'));
    expect(line).toContain('40001');
    expect(logs.join('\n')).not.toContain('secret raw message');
    fail = false;
    expect((await evaluator.evaluate()).reopened).toBe(1);
    expect(await statusOf(f.id)).toBe('open');
  });

  it('AC-P19-3: the recheck run evaluates expiry at its start (acceptances_reopened counter)', async () => {
    const reviewer = await insertUser(db);
    await acceptedFinding('2026-10-01', reviewer);
    const summary = await runnerOf().run(new AbortController().signal);
    expect(summary?.acceptancesReopened).toBe(1);
    expect((await runs())[0].acceptances_reopened).toBe(1);
  });

  it('AC-P19-3: scheduler start runs the expiry evaluation at once (background) regardless of the settings', async () => {
    const reviewer = await insertUser(db);
    const f = await acceptedFinding('2026-10-01', reviewer);
    const s = schedulerOf({ config: { recheckEnabled: false, intervalHours: 24 }, lookup: null });
    expect(s.lastEvaluatedAt()).toBeNull();
    await s.start();
    await vi.waitFor(async () => expect(await statusOf(f.id)).toBe('open'), { timeout: 10_000 });
    await vi.waitFor(() => expect(s.lastEvaluatedAt()).not.toBeNull(), { timeout: 10_000 });
  });
});
