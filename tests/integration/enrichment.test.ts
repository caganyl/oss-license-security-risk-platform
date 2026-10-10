/**
 * REQ-004 · Registry enrichment end to end in the scan worker (P-14, P-15,
 * L-6; AC-P14-6/8/14/15/16, AC-P15-1/10, AC-L6-1…3, AC-G-7, AC-G-8, D-82).
 *
 * Real embedded PostgreSQL (fresh migrated DB per test), `ScanWorker.runOnce`
 * with an injected parser and an injected enricher pointed at the loopback
 * fake registry (helpers/fakeRegistry). The archive stage runs the real
 * archive thread. No non-loopback connection is possible (network guard).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type DependencyEnricher, type DependencyEnricherOptions, createDependencyEnricher } from '../../src/enrichment';
import type { RegistryClock } from '../../src/enrichment/registryClient';
import { ScanWorker } from '../../src/scanner/worker';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import { buildZip } from '../helpers/archiveBuilder';
import { REPO_ROOT } from '../helpers/paths';
import { useTestDatabase } from '../helpers/db';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

let tmpRoot = '';
let root = '';
let reg: FakeRegistry;
let logs: string[] = [];
const enrichers: DependencyEnricher[] = [];
const push = (...a: unknown[]) => logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p14-'));
  root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
  logs = [];
  reg = await startFakeRegistry();
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulns: [], results: [] }), { status: 200 })));
});
afterEach(async () => {
  for (const e of enrichers.splice(0)) e.close();
  vi.unstubAllGlobals();
  await reg.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
type Dep = SandboxScanResult['dependencies'][number];
const npmDep = (name: string, version: string | null, licenses: string[] = [], scope = 'direct'): Dep =>
  ({ ecosystem: 'nodejs', name, version, purl: version ? `pkg:npm/${name}@${version}` : `pkg:npm/${name}`, scope, licenses, manifest_file: 'package-lock.json', manifest_path: '.' }) as Dep;
const pyDep = (name: string, version: string): Dep =>
  ({ ecosystem: 'python', name, version, purl: `pkg:pypi/${name.toLowerCase()}@${version}`, scope: 'direct', licenses: [], manifest_file: 'requirements.txt', manifest_path: '.' }) as Dep;

const DEPS: Dep[] = [
  npmDep('left-pad', '1.3.0'),
  npmDep('gpl-pkg', '1.0.0', ['MIT']),
  npmDep('ghost', '9.9.9', ['ISC']),
  npmDep('nover', null, ['MIT']),
  npmDep('devpkg', '1.0.0', [], 'dev'),
  pyDep('Requests', '2.31.0'),
];

function seedRegistry(): void {
  reg.addNpmPackage('left-pad', '1.3.0', { license: 'MIT' });
  reg.addNpmPackage('gpl-pkg', '1.0.0', { license: 'GPL-3.0-only' });
  reg.addNpmPackage('devpkg', '1.0.0', { license: 'ISC' });
  reg.addPypiPackage('requests', '2.31.0', {
    info: { license_expression: 'Apache-2.0', classifiers: ['License :: OSI Approved :: Apache Software License'] },
    files: [{ filename: 'requests-2.31.0-py3-none-any.whl', packagetype: 'bdist_wheel', bytes: buildZip([
      { name: 'requests/__init__.py', data: '' },
      { name: 'requests-2.31.0.dist-info/LICENSE', data: 'Apache License\nCopyright 2019 Kenneth Reitz\n' },
    ]) }],
  });
}

function enricher(overrides: Partial<DependencyEnricherOptions> = {}): DependencyEnricher {
  const e = createDependencyEnricher({
    config: { enabled: true, timeoutMs: 3_000, concurrency: 4 },
    db: db.pool,
    logger,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin },
    clock: fastClock,
    env: {},
    ...overrides,
  });
  enrichers.push(e);
  return e;
}

async function insertProject(): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`p-${Math.random().toString(36).slice(2)}`, root]);
  return p.id;
}

async function scan(projectId: string, e: DependencyEnricher | null, deps: Dep[] = DEPS): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId],
  );
  const runParser: RunParserFn = async (_d, _e, scanId) => ({ scan_id: scanId, status: 'completed', total_deps: deps.length, dependencies: deps, scan_files: [], parse_errors: [] });
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runParser, runId: 'run-A', ...(e ? { enricher: e } : {}) });
  expect(await w.runOnce()).toBe(s.id);
  return s.id;
}

interface DepRow {
  name: string;
  version: string | null;
  scope: string;
  license_expression: string | null;
  license_source: string | null;
  license_lock_hint: string | null;
  license_hint_differs: boolean | null;
  license_enrichment_status: string | null;
  notice_status: string | null;
  notice_archive_id: string | null;
}

async function deps(scanId: string): Promise<Record<string, DepRow>> {
  const rows = await db.query<DepRow>(
    `SELECT p.name, p.version, sd.scope::text, sd.license_expression, sd.license_source, sd.license_lock_hint, sd.license_hint_differs,
            sd.license_enrichment_status, sd.notice_status, sd.notice_archive_id
       FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1`,
    [scanId],
  );
  return Object.fromEntries(rows.map((r) => [r.name.toLowerCase(), r]));
}

async function scanRow(scanId: string): Promise<{ status: string; error_message: string | null }> {
  const [r] = await db.query<{ status: string; error_message: string | null }>(`SELECT status::text, error_message FROM scans WHERE id = $1`, [scanId]);
  return r;
}

async function licenseFindings(scanId: string): Promise<Array<{ name: string; normalized_license: string; fingerprint: string }>> {
  return db.query(
    `SELECT p.name, lf.normalized_license, f.fingerprint
       FROM findings f JOIN license_findings lf ON lf.finding_id = f.id
       JOIN scan_dependencies sd ON sd.id = f.scan_dependency_id JOIN packages p ON p.id = sd.package_id
      WHERE f.scan_id = $1 ORDER BY p.name, lf.normalized_license`,
    [scanId],
  );
}

// ---------------------------------------------------------------------------
describe('P-14 / P-15 acceptance: scan with enrichment against the fake registry', () => {
  it('AC-P14-6 / AC-L6-1…3 / AC-P15-1: license and NOTICE columns are filled (npm and Python), statuses follow L-6', async () => {
    seedRegistry();
    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());
    expect((await scanRow(scanId)).status).toBe('completed');
    const d = await deps(scanId);
    expect(d['left-pad']).toMatchObject({ license_expression: 'MIT', license_source: 'registry:npm', license_enrichment_status: 'ok', notice_status: 'collected' });
    expect(d['left-pad'].notice_archive_id).not.toBeNull();
    expect(d['gpl-pkg']).toMatchObject({ license_expression: 'GPL-3.0-only', license_source: 'registry:npm', license_lock_hint: 'MIT', license_hint_differs: true });
    expect(d.ghost).toMatchObject({ license_enrichment_status: 'not_found', license_source: 'lockfile (unverified)', license_expression: 'ISC', notice_status: 'not_attempted' });
    expect(d.nover).toMatchObject({ license_enrichment_status: 'version_unknown', license_source: 'none', license_expression: null, license_lock_hint: 'MIT' });
    expect(d.devpkg).toMatchObject({ license_enrichment_status: 'ok', notice_status: 'not_runtime' });
    // P-14 acceptance: the Python license column is filled.
    expect(d.requests).toMatchObject({ license_expression: 'Apache-2.0', license_source: 'registry:pypi', notice_status: 'collected' });
    // No request for version-less keys, no archive download for dev scope.
    expect(reg.requests.some((r) => r.path.startsWith('/nover'))).toBe(false);
    expect(reg.requests.some((r) => r.path.endsWith('devpkg-1.0.0.tgz'))).toBe(false);
    // Enrichment on, nothing incomplete -> no [registry] line.
    expect((await scanRow(scanId)).error_message ?? '').not.toContain('[registry]');
    // Archive cache content.
    const [arch] = await db.query<{ copyright_lines: string[] }>(`SELECT copyright_lines FROM registry_archive_cache WHERE name = 'requests'`);
    expect(arch.copyright_lines).toEqual(['Copyright 2019 Kenneth Reitz']);
  });

  it('AC-L6-1 / D-73: the license policy evaluates the effective (registry) license, not the lockfile hint', async () => {
    seedRegistry();
    const projectId = await insertProject();
    const on = await licenseFindings(await scan(projectId, enricher(), [npmDep('gpl-pkg', '1.0.0', ['MIT'])]));
    const p2 = await insertProject();
    const off = await licenseFindings(await scan(p2, null, [npmDep('gpl-pkg', '1.0.0', ['MIT'])]));
    expect(on.map((f) => f.normalized_license)).toContain('GPL-3.0-only');
    expect(off.map((f) => f.normalized_license)).not.toContain('GPL-3.0-only');
  });

  it('AC-P14-8 / AC-P15-10: a second scan makes zero registry requests (metadata and archive cache); not_found expires after 24 h', async () => {
    seedRegistry();
    const projectId = await insertProject();
    const first = await scan(projectId, enricher());
    expect(reg.count('/ghost/9.9.9')).toBe(1);
    const [nf] = await db.query<{ ttl: number }>(`SELECT EXTRACT(EPOCH FROM expires_at - fetched_at)::float8 AS ttl FROM registry_package_cache WHERE name = 'ghost'`);
    expect(nf.ttl).toBe(24 * 3600);
    expect(await db.query(`SELECT 1 FROM registry_package_cache WHERE outcome = 'found' AND expires_at IS NOT NULL`)).toEqual([]);

    reg.resetCounts();
    const second = await scan(projectId, enricher());
    expect(reg.total()).toBe(0);
    const a = await deps(first);
    const b = await deps(second);
    for (const name of Object.keys(a)) {
      expect({ ...b[name] }, name).toEqual({ ...a[name] });
    }

    // Expire the not_found row (database clock): only that key is asked again.
    await db.query(`UPDATE registry_package_cache SET fetched_at = NOW() - INTERVAL '25 hours', expires_at = NOW() - INTERVAL '1 hour' WHERE name = 'ghost'`);
    reg.resetCounts();
    await scan(projectId, enricher());
    expect(reg.requests.map((r) => r.path)).toEqual(['/ghost/9.9.9']);
  });

  it('AC-P14-15: registry offline never fails the scan; one [registry] line, lock hints used', async () => {
    const dead = await startFakeRegistry();
    const deadOrigin = dead.origin;
    await dead.close();
    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher({ endpoints: { npm: deadOrigin, pypi: deadOrigin, files: deadOrigin } }));
    const row = await scanRow(scanId);
    expect(row.status).toBe('completed');
    const lines = (row.error_message ?? '').split('\n').filter((l) => l.startsWith('[registry]'));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^\[registry\] Registry lookup incomplete for 5 package\(s\) \(unreachable: 5, error: 0, time budget exceeded: 0\); license from lockfile \(unverified\): 2, no license: 3\.$/);
    const d = await deps(scanId);
    expect(d['gpl-pkg']).toMatchObject({ license_enrichment_status: 'unreachable', license_source: 'lockfile (unverified)', license_expression: 'MIT' });
    expect(await db.query(`SELECT 1 FROM registry_package_cache`)).toEqual([]);
  });

  it('AC-P14-15: an enricher that throws is logged and the scan completes with error outcomes', async () => {
    const real = enricher();
    const broken: DependencyEnricher = { enabled: true, enrich: async () => { throw Object.assign(new Error('boom'), { code: 'EBOOM' }); }, failed: (x) => real.failed(x), close: () => undefined };
    const scanId = await scan(await insertProject(), broken);
    expect((await scanRow(scanId)).status).toBe('completed');
    expect((await deps(scanId))['left-pad'].license_enrichment_status).toBe('error');
    expect(logs.some((l) => l.includes('registry enrichment failed (EBOOM)'))).toBe(true);
  });

  it('AC-P14-14: an exhausted budget marks the remaining keys budget_exceeded and the scan completes', async () => {
    for (const name of ['left-pad', 'gpl-pkg', 'ghost', 'devpkg']) reg.route(`/${name}/${name === 'ghost' ? '9.9.9' : name === 'left-pad' ? '1.3.0' : '1.0.0'}`, { hang: true });
    reg.route('/pypi/requests/2.31.0/json', { hang: true });
    const real = enricher();
    const tight: DependencyEnricher = { enabled: true, enrich: (d, o) => real.enrich(d, { ...o, budgetMs: 300 }), failed: (x) => real.failed(x), close: () => undefined };
    const t = performance.now();
    const scanId = await scan(await insertProject(), tight);
    expect(performance.now() - t).toBeLessThan(20_000);
    expect((await scanRow(scanId)).status).toBe('completed');
    const d = await deps(scanId);
    for (const name of ['left-pad', 'gpl-pkg', 'ghost', 'requests']) expect(d[name].license_enrichment_status, name).toBe('budget_exceeded');
    expect((await scanRow(scanId)).error_message).toMatch(/time budget exceeded: 5\)/);
  });
});

describe('AC-G-8 / D-82 / AC-P14-16: REGISTRY_ENRICHMENT=off equals F2 except the single [registry] line', () => {
  it('AC-G-8: no request, no cache access; dependencies and finding fingerprints equal a scan without enricher', async () => {
    seedRegistry();
    const projectId = await insertProject();
    const f2 = await scan(projectId, null);
    const off = await scan(projectId, enricher({ config: { enabled: false, timeoutMs: 3_000, concurrency: 4 } }));
    expect(reg.total()).toBe(0);
    expect(await db.query(`SELECT 1 FROM registry_package_cache`)).toEqual([]);
    expect(await deps(off)).toEqual(await deps(f2));
    const fp = async (id: string) => (await licenseFindings(id)).map((f) => `${f.name}|${f.normalized_license}|${f.fingerprint}`);
    expect(await fp(off)).toEqual(await fp(f2));
    expect((await deps(off))['gpl-pkg']).toMatchObject({ license_enrichment_status: 'disabled', license_source: 'lockfile (unverified)', license_expression: 'MIT' });
    expect((await deps(off)).nover).toMatchObject({ license_enrichment_status: 'disabled', license_source: 'lockfile (unverified)' });
    expect((await scanRow(f2)).error_message).toBeNull();
    expect((await scanRow(off)).error_message).toBe(
      '[registry] License enrichment disabled: 3 package(s) use the lockfile license (unverified), 3 have no license.',
    );
  });
});

describe('AC-G-7: migration 006 constraints', () => {
  it('AC-G-7: CHECK value sets, source/status together, ON DELETE SET NULL of notice_archive_id', async () => {
    seedRegistry();
    const scanId = await scan(await insertProject(), enricher(), [npmDep('left-pad', '1.3.0')]);
    const [row] = await db.query<{ id: string; notice_archive_id: string }>(`SELECT id, notice_archive_id FROM scan_dependencies WHERE scan_id = $1`, [scanId]);
    expect(row.notice_archive_id).not.toBeNull();
    await expect(db.query(`UPDATE scan_dependencies SET license_enrichment_status = 'bogus' WHERE id = $1`, [row.id])).rejects.toThrow(/check/i);
    await expect(db.query(`UPDATE scan_dependencies SET notice_status = 'bogus' WHERE id = $1`, [row.id])).rejects.toThrow(/check/i);
    await expect(db.query(`UPDATE scan_dependencies SET license_source = 'registry:maven' WHERE id = $1`, [row.id])).rejects.toThrow(/check/i);
    await expect(db.query(`UPDATE scan_dependencies SET license_source = NULL WHERE id = $1`, [row.id])).rejects.toThrow(/license_f3_together/);
    await expect(db.query(`INSERT INTO registry_package_cache (ecosystem, name, version, outcome, extractor_version, expires_at) VALUES ('npm','x','1','not_found',1,NULL)`)).rejects.toThrow(/expiry/);
    await db.query(`DELETE FROM registry_archive_cache`);
    const [after] = await db.query<{ notice_archive_id: string | null; notice_status: string }>(`SELECT notice_archive_id, notice_status FROM scan_dependencies WHERE id = $1`, [row.id]);
    expect(after).toEqual({ notice_archive_id: null, notice_status: 'collected' });
  });

  it('AC-G-7: 006 down then up again restores the schema', async () => {
    const sql = (f: string) => fs.readFileSync(path.join(REPO_ROOT, 'db', 'migrations', f), 'utf8');
    await db.query(sql('006_registry_enrichment.down.sql'));
    expect(await db.query(`SELECT 1 FROM information_schema.tables WHERE table_name IN ('registry_package_cache', 'registry_archive_cache')`)).toEqual([]);
    expect(await db.query(`SELECT 1 FROM information_schema.columns WHERE table_name = 'scan_dependencies' AND column_name = 'license_source'`)).toEqual([]);
    await db.query(sql('006_registry_enrichment.up.sql'));
    expect(await db.query(`SELECT 1 FROM information_schema.tables WHERE table_name IN ('registry_package_cache', 'registry_archive_cache')`)).toHaveLength(2);
    expect(await db.query(`SELECT 1 FROM information_schema.columns WHERE table_name = 'scan_dependencies' AND (column_name LIKE 'license_%' OR column_name LIKE 'notice_%')`)).toHaveLength(7);
  });
});
