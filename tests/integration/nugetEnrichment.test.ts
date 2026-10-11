/**
 * REQ-006 · P-21 NuGet enrichment, NOTICE/Excel/SBOM and OSV NuGet end to end
 * (AC-P21-4…11, AC-P21-14, AC-P20-18, AC-NV-1…3, AC-G-4).
 *
 * A temp scan root holds two `packages.lock.json` files whose `contentHash`
 * values are computed at test time from `.nupkg` archives built by
 * helpers/fakeNuget (signed-like and unsigned). `ScanWorker.runOnce` runs the
 * real lock-aware parser thread, the real enricher (archive thread included)
 * pointed at the loopback fake registry, and the real vulnerability lookup
 * pointed at the loopback fake OSV. Real embedded PostgreSQL, fresh DB per
 * test. No request leaves 127.0.0.1 (network guard).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ExcelJS from 'exceljs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type DependencyEnricher, createDependencyEnricher } from '../../src/enrichment';
import type { RegistryClock } from '../../src/enrichment/registryClient';
import type { AppClock } from '../../src/lib/clock';
import { NoticeService } from '../../src/notice/noticeService';
import { ReportService } from '../../src/reports/reportService';
import { SbomService } from '../../src/sbom/sbomService';
import { ScanWorker } from '../../src/scanner/worker';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import { createExpiryEvaluator } from '../../src/vulnerability/expiry';
import { createRecheckRunner } from '../../src/vulnerability/recheck';
import { buildZip, sha512b64 } from '../helpers/archiveBuilder';
import { useTestDatabase } from '../helpers/db';
import { f3Dep, seedScan } from '../helpers/f3Seed';
import { makeF4Lookup } from '../helpers/f4Seed';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { addNugetPackage, independentContentHash, nugetPaths, nupkgEntries, nuspecXml, packagesLockJson } from '../helpers/fakeNuget';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 180_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

let tmpRoot = '';
let root = '';
let outDir = '';
let reg: FakeRegistry;
let osv: FakeOsv;
let logs: string[] = [];
const enrichers: DependencyEnricher[] = [];
const clients: VulnerabilityClient[] = [];
const push = (...a: unknown[]) => void logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };
const appClock: AppClock = { now: () => Date.parse('2026-10-11T08:00:00.000Z'), sleep: async () => undefined };
const savedEnv: Record<string, string | undefined> = {};

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-nuget-p21-'));
  root = path.join(tmpRoot, 'repo');
  outDir = path.join(tmpRoot, 'out');
  fs.mkdirSync(outDir, { recursive: true });
  for (const k of ['REPORT_OUTPUT_DIR', 'SBOM_OUTPUT_DIR']) {
    savedEnv[k] = process.env[k];
    process.env[k] = outDir;
  }
  logs = [];
  reg = await startFakeRegistry();
  osv = await startFakeOsv();
});
afterEach(async () => {
  for (const e of enrichers.splice(0)) e.close();
  for (const c of clients.splice(0)) c.close();
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  await reg.close();
  await osv.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// fixture: lock files + fake flat container
// ---------------------------------------------------------------------------
const EULA = 'ACME END USER LICENSE AGREEMENT\nCopyright 2023 Acme Corp\n';
const P = {
  expr: { id: 'Acme.Expr', version: '1.0.0' },
  file: { id: 'Acme.FileLic', version: '2.0.0' },
  bad: { id: 'Acme.Bad', version: '3.0.0' },
  url: { id: 'Acme.UrlLic', version: '4.0.0' },
  multi: { id: 'Acme.Multi', version: '5.0.0' },
  depr: { id: 'Acme.Deprecated', version: '6.0.0' },
  redir: { id: 'Acme.Redir', version: '7.0.0' },
  wrong: { id: 'Acme.WrongId', version: '8.0.0' },
} as const;

function setupFixture(): void {
  // Acme.Expr: repository-signed-like package; lock value = NuGet content hash (raw hash differs).
  const exprEntries = nupkgEntries(P.expr.id, { signed: true });
  const exprNupkg = buildZip(exprEntries);
  const exprHash = independentContentHash(exprEntries);
  expect(sha512b64(exprNupkg)).not.toBe(exprHash);
  addNugetPackage(reg, P.expr.id, P.expr.version, { nuspec: nuspecXml({ id: P.expr.id, version: P.expr.version, expression: 'MIT' }), nupkg: exprNupkg });

  // Acme.FileLic: unsigned package; lock value = raw SHA-512; type="file" -> docs/EULA.md.
  const fileNupkg = buildZip(
    nupkgEntries(P.file.id, {
      entries: [
        { name: `${P.file.id}.nuspec`, data: nuspecXml({ id: P.file.id, version: P.file.version, file: 'docs/EULA.md' }) },
        { name: 'docs/EULA.md', data: EULA },
        { name: 'lib/net8.0/LICENSE', data: 'NESTED LICENSE MUST NOT BE COLLECTED\n' },
      ],
    }),
  );
  addNugetPackage(reg, P.file.id, P.file.version, { nuspec: nuspecXml({ id: P.file.id, version: P.file.version, file: 'docs/EULA.md', licenseUrl: 'https://licenses.nuget.org/MIT' }), nupkg: fileNupkg });

  // Acme.Bad: lock value differs from both hashes of the served archive -> L-5 fail-safe.
  addNugetPackage(reg, P.bad.id, P.bad.version, { nuspec: nuspecXml({ id: P.bad.id, version: P.bad.version, expression: 'MIT' }), nupkg: buildZip(nupkgEntries(P.bad.id, { signed: true })) });
  const badHash = sha512b64(Buffer.from('tampered'));

  // Acme.UrlLic: unknown licenseUrl on the fake origin (must never be requested); no lock value.
  addNugetPackage(reg, P.url.id, P.url.version, { nuspec: nuspecXml({ id: P.url.id, version: P.url.version, licenseUrl: `${reg.origin}/license/eula` }) });
  reg.route('/license/eula', { body: 'EULA' });

  // Acme.Multi: two distinct lock values for the same key -> mismatch without download.
  addNugetPackage(reg, P.multi.id, P.multi.version, { nuspec: nuspecXml({ id: P.multi.id, version: P.multi.version, licenseUrl: 'https://licenses.nuget.org/Apache-2.0' }), nupkg: buildZip(nupkgEntries(P.multi.id)) });

  // Acme.Deprecated: nuspec <id> casing differs from the lock; aka.ms placeholder only.
  addNugetPackage(reg, P.depr.id, P.depr.version, { nuspec: nuspecXml({ id: 'ACME.Deprecated', version: P.depr.version, licenseUrl: 'https://aka.ms/deprecateLicenseUrl' }) });

  // Acme.Redir: nuspec same-origin redirect (allowed), nupkg redirect (not allowed).
  const redir = nugetPaths(P.redir.id, P.redir.version);
  reg.route(redir.nuspecPath, { status: 302, headers: { location: `${reg.origin}/v3-flatcontainer/_moved/acme.redir.nuspec` } });
  reg.route('/v3-flatcontainer/_moved/acme.redir.nuspec', { body: nuspecXml({ id: P.redir.id, version: P.redir.version, expression: 'Apache-2.0' }), headers: { 'content-type': 'application/xml' } });
  reg.route(redir.nupkgPath, { status: 302, headers: { location: `${reg.origin}/v3-flatcontainer/_moved/acme.redir.nupkg` } });
  reg.route('/v3-flatcontainer/_moved/acme.redir.nupkg', { body: buildZip(nupkgEntries(P.redir.id)) });

  // Acme.WrongId: nuspec for another id -> BAD_NUSPEC (status error, not cached).
  addNugetPackage(reg, P.wrong.id, P.wrong.version, { nuspec: nuspecXml({ id: 'Other.Id', version: P.wrong.version, expression: 'MIT' }) });

  const app = path.join(root, 'src', 'App');
  const lib = path.join(root, 'src', 'Lib');
  fs.mkdirSync(app, { recursive: true });
  fs.mkdirSync(lib, { recursive: true });
  fs.writeFileSync(
    path.join(app, 'packages.lock.json'),
    packagesLockJson([
      { ...P.expr, hash: exprHash },
      { ...P.file, hash: sha512b64(fileNupkg) },
      { ...P.bad, hash: badHash },
      { ...P.url, hash: null },
      { ...P.multi, hash: sha512b64(Buffer.from('multi-1')) },
      { ...P.depr, hash: null },
      { ...P.redir, hash: sha512b64(Buffer.from('redir')) },
      { ...P.wrong, hash: null },
    ]),
  );
  fs.writeFileSync(path.join(lib, 'packages.lock.json'), packagesLockJson([{ ...P.multi, hash: sha512b64(Buffer.from('multi-2')) }]));
}

function enricher(): DependencyEnricher {
  const e = createDependencyEnricher({
    config: { enabled: true, timeoutMs: 5_000, concurrency: 4 },
    db: db.pool,
    logger,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin, nuget: reg.origin },
    clock: fastClock,
    env: {},
  });
  enrichers.push(e);
  return e;
}

async function insertProject(): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`nuget-p21-${Math.random().toString(36).slice(2)}`, root]);
  await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, 'dotnet')`, [p.id]);
  return p.id;
}

async function scan(projectId: string, e: DependencyEnricher): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId],
  );
  const lookup = makeF4Lookup(db, osv.origin, appClock, logs, clients);
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runId: 'run-p21', enricher: e, vulnerabilityLookup: lookup });
  expect(await w.runOnce()).toBe(s.id);
  const [row] = await db.query<{ status: string }>(`SELECT status::text FROM scans WHERE id = $1`, [s.id]);
  expect(row.status, logs.join('\n')).toBe('completed');
  return s.id;
}

interface Row {
  name: string;
  manifest_path: string;
  license_expression: string | null;
  license_source: string | null;
  license_enrichment_status: string | null;
  notice_status: string | null;
  lock_integrity: string | null;
  license_unclassified: string | null;
}

async function rows(scanId: string): Promise<Map<string, Row>> {
  const r = await db.query<Row>(
    `SELECT p.name, sd.manifest_path, sd.license_expression, sd.license_source, sd.license_enrichment_status, sd.notice_status,
            sd.lock_integrity, sd.license_unclassified
       FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1 ORDER BY sd.manifest_path`,
    [scanId],
  );
  return new Map(r.map((x) => [x.name, x]));
}

const pick = (r: Row | undefined) => r && [r.license_enrichment_status, r.license_source, r.license_expression, r.notice_status, r.lock_integrity, r.license_unclassified];

async function excelRows(projectId: string, scanId: string, sheetName = 'Dependencies'): Promise<Map<string, unknown[]>> {
  const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id`, [`qa-${Math.random().toString(36).slice(2)}@example.test`]);
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by) VALUES ($1, 'project_report', 'excel', 'generating', $2::jsonb, $3) RETURNING id`,
    [projectId, JSON.stringify({ scanId }), u.id],
  );
  const record = await new ReportService(db.pool).processReport(r.id);
  expect(record.status).toBe('ready');
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(record.storageKey!);
  const sheet = wb.getWorksheet(sheetName)!;
  const out = new Map<string, unknown[]>();
  for (let i = 2; i <= sheet.rowCount; i++) {
    const values = (sheet.getRow(i).values as unknown[]).slice(1);
    out.set(String(values[0]), values);
  }
  return out;
}

// ---------------------------------------------------------------------------
describe('AC-P21-5…10 / AC-P21-14: NuGet enrichment end to end', () => {
  it('AC-P21-9 / AC-P21-5 / AC-P21-6 / AC-P21-4 / AC-P21-8: statuses, sources, lock integrity, unclassified, requests and cache', async () => {
    setupFixture();
    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());
    const r = await rows(scanId);

    // AC-P21-9 r2: signed-like archive verified by the NuGet content hash -> match, collected.
    expect(pick(r.get('Acme.Expr'))).toEqual(['ok', 'registry:nuget', 'MIT', 'collected', 'match', null]);
    // AC-P21-5 r2: type="file" beats licenseUrl; no_license + none + 'file'; raw-hash archive match.
    expect(pick(r.get('Acme.FileLic'))).toEqual(['no_license', 'none', null, 'collected', 'match', 'file']);
    // AC-P21-9: different hash -> L-5 fail-safe (no license in policy, not_attempted, mismatch, unclassified NULL).
    expect(pick(r.get('Acme.Bad'))).toEqual(['ok', 'none', null, 'not_attempted', 'mismatch', null]);
    // AC-P21-6 / AC-P21-9: unknown licenseUrl -> 'url'; no lock value -> no download, no_candidate, not_comparable.
    expect(pick(r.get('Acme.UrlLic'))).toEqual(['no_license', 'none', null, 'no_candidate', 'not_comparable', 'url']);
    // AC-P21-9 r2: two distinct lock values -> mismatch without a download (both manifest rows).
    const multi = await db.query<{ lock_integrity: string; notice_status: string; license_source: string }>(
      `SELECT sd.lock_integrity, sd.notice_status, sd.license_source FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1 AND p.name = 'Acme.Multi'`,
      [scanId],
    );
    expect(multi).toHaveLength(2);
    for (const m of multi) expect(m).toEqual({ lock_integrity: 'mismatch', notice_status: 'not_attempted', license_source: 'none' });
    // AC-P21-6: aka.ms placeholder ignored -> no_license without unclassified.
    expect(pick(r.get('Acme.Deprecated'))).toEqual(['no_license', 'none', null, 'no_candidate', 'not_comparable', null]);
    // AC-P21-4 / AC-P21-2: same-origin nuspec redirect followed; nupkg redirect refused -> not collected, not_comparable.
    const redir = r.get('Acme.Redir')!;
    expect([redir.license_enrichment_status, redir.license_source, redir.license_expression, redir.lock_integrity]).toEqual(['ok', 'registry:nuget', 'Apache-2.0', 'not_comparable']);
    expect(redir.notice_status).not.toBe('collected');
    // AC-P21-4: BAD_NUSPEC (other id) -> error.
    expect(r.get('Acme.WrongId')?.license_enrichment_status).toBe('error');

    // Requests (AC-P21-6: licenseUrl never fetched; AC-P21-9: no download without one lock value).
    const count = (p: { id: string; version: string }, kind: 'nuspecPath' | 'nupkgPath') => reg.count(nugetPaths(p.id, p.version)[kind]);
    expect(reg.count('/license/eula')).toBe(0);
    expect([count(P.expr, 'nupkgPath'), count(P.file, 'nupkgPath'), count(P.bad, 'nupkgPath'), count(P.url, 'nupkgPath'), count(P.multi, 'nupkgPath'), count(P.depr, 'nupkgPath'), count(P.redir, 'nupkgPath')]).toEqual([1, 1, 1, 0, 0, 0, 1]);
    expect(reg.count('/v3-flatcontainer/_moved/acme.redir.nuspec')).toBe(1);
    expect(reg.count('/v3-flatcontainer/_moved/acme.redir.nupkg')).toBe(0);
    for (const req of reg.requests) expect(req.path).toMatch(/^\/(v3-flatcontainer|moved)\//);

    // AC-P21-8 / AC-P21-4: found rows cached under 'nuget' with the canonical <id>; BAD_NUSPEC not cached.
    const cache = await db.query<{ name: string; outcome: string; canonical_name: string | null }>(`SELECT name, outcome, canonical_name FROM registry_package_cache WHERE ecosystem = 'nuget' ORDER BY name`);
    expect(cache.map((c) => c.name)).toEqual(['acme.bad', 'acme.deprecated', 'acme.expr', 'acme.filelic', 'acme.multi', 'acme.redir', 'acme.urllic']);
    expect(cache.find((c) => c.name === 'acme.deprecated')?.canonical_name).toBe('ACME.Deprecated');
    expect(cache.find((c) => c.name === 'acme.expr')?.canonical_name).toBe('Acme.Expr');
    // AC-P21-9: the mismatching archive is never cached.
    const archives = await db.query<{ name: string; archive_digest: string }>(`SELECT name, archive_digest FROM registry_archive_cache WHERE ecosystem = 'nuget' ORDER BY name`);
    expect(archives.map((a) => a.name)).toEqual(['acme.expr', 'acme.filelic']);
    for (const a of archives) expect(a.archive_digest).toMatch(/^sha512-/);

    // AC-P21-14: NuGet keys counted in the single [registry] line (error 1, mismatches 2), no package names.
    const [s] = await db.query<{ error_message: string | null }>(`SELECT error_message FROM scans WHERE id = $1`, [scanId]);
    const line = (s.error_message ?? '').split('\n').find((l) => l.startsWith('[registry]')) ?? '';
    expect(line).toMatch(/error: 1/);
    expect(line).toMatch(/mismatch/i);
    expect(line).toMatch(/\b2 package\(s\)/);
    expect(line).not.toMatch(/Acme/i);

    // AC-P21-8: second scan -> zero .nuspec requests for found keys; cached archives give 'match' without a download;
    // the mismatching archive (not cached) is downloaded again; BAD_NUSPEC is requested again (not cached).
    reg.resetCounts();
    const scan2 = await scan(projectId, enricher());
    const r2 = await rows(scan2);
    for (const p of [P.expr, P.file, P.bad, P.url, P.multi, P.depr]) expect(count(p, 'nuspecPath'), p.id).toBe(0);
    expect(reg.count('/v3-flatcontainer/_moved/acme.redir.nuspec')).toBe(0);
    expect(count(P.wrong, 'nuspecPath')).toBe(1);
    expect([count(P.expr, 'nupkgPath'), count(P.file, 'nupkgPath'), count(P.bad, 'nupkgPath')]).toEqual([0, 0, 1]);
    expect(pick(r2.get('Acme.Expr'))).toEqual(['ok', 'registry:nuget', 'MIT', 'collected', 'match', null]);
    expect(pick(r2.get('Acme.FileLic'))).toEqual(['no_license', 'none', null, 'collected', 'match', 'file']);
    expect(pick(r2.get('Acme.Bad'))).toEqual(['ok', 'none', null, 'not_attempted', 'mismatch', null]);
  });

  it('AC-P21-11 / AC-P21-5 / AC-P21-9 / AC-P20-18: NOTICE, Excel License Source and SBOM of the NuGet scan', async () => {
    setupFixture();
    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());

    // --- NOTICE (contract 1.4.0 §3.3, §4.3 row 7a, unclassified prefix, row 15).
    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    const block = (name: string) => {
      const start = text.indexOf(`Package: ${name}\n`);
      expect(start, name).toBeGreaterThanOrEqual(0);
      const next = text.indexOf('\nPackage: ', start + 1);
      return text.slice(start, next === -1 ? undefined : next);
    };
    expect(block('Acme.Expr')).toContain('Ecosystem: nuget');
    expect(block('Acme.Expr')).toContain('License source: registry:nuget');
    expect(block('Acme.Expr')).toContain('MIT License');
    expect(block('Acme.Expr')).toContain('PURL: pkg:nuget/Acme.Expr@1.0.0');
    expect(block('Acme.FileLic')).toContain('ACME END USER LICENSE AGREEMENT');
    expect(block('Acme.FileLic')).toContain('License: NOASSERTION');
    expect(block('Acme.FileLic')).not.toContain('NESTED LICENSE MUST NOT BE COLLECTED');
    expect(block('Acme.UrlLic')).toContain('Reason: license URL not classified; package archive not downloaded (no lockfile integrity value)');
    expect(block('Acme.Deprecated')).toContain('Reason: package archive not downloaded (no lockfile integrity value)');
    expect(block('Acme.Bad')).toContain('Reason: lockfile integrity does not match registry; license not verified');
    expect(block('Acme.Bad')).not.toContain('MIT License');
    expect(text).not.toContain('license enrichment not supported for this ecosystem');
    expect(text).not.toContain(`${reg.origin}/license/eula`);

    // --- Excel License Source (contract 1.4.0 §4.1; precedence L-5 > unclassified > source).
    const x = await excelRows(projectId, scanId);
    const src = (n: string) => x.get(n)?.[8];
    expect(src('Acme.Expr')).toBe('registry:nuget');
    expect(x.get('Acme.Expr')?.[7]).toBe('MIT');
    expect(src('Acme.FileLic')).toBe('none (license file in package, not classified)');
    expect(src('Acme.UrlLic')).toBe('none (license URL not classified)');
    expect(src('Acme.Bad')).toBe('none (lockfile integrity mismatch)');
    expect(src('Acme.Multi')).toBe('none (lockfile integrity mismatch)');
    expect(src('Acme.Deprecated')).toBe('none');
    expect(x.get('Acme.Expr')?.[6]).toBe('pkg:nuget/Acme.Expr@1.0.0');

    // --- SBOM (contract §6): purl casing as scanned, NOASSERTION for unclassified / mismatch.
    const sbom = new SbomService(db.pool);
    const spdx = JSON.parse(fs.readFileSync((await sbom.generate(scanId, 'spdx_json')).storageKey, 'utf8')) as {
      packages: Array<{ name: string; licenseDeclared?: string; externalRefs?: Array<{ referenceLocator: string }> }>;
    };
    const pkg = (n: string) => spdx.packages.find((p) => p.name === n);
    expect(pkg('Acme.Expr')?.licenseDeclared).toBe('MIT');
    for (const n of ['Acme.FileLic', 'Acme.UrlLic', 'Acme.Bad', 'Acme.Multi']) expect(pkg(n)?.licenseDeclared, n).toBe('NOASSERTION');
    expect(pkg('Acme.Deprecated')?.externalRefs?.map((e) => e.referenceLocator)).toContain('pkg:nuget/Acme.Deprecated@6.0.0');
  });

  it('AC-P21-7 / contract 1.4.0 §5.1 (C-29): License = expression or empty, License Source never empty, NOASSERTION finding in Licenses', async () => {
    setupFixture();
    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());
    const x = await excelRows(projectId, scanId);
    const lic = (n: string) => x.get(n)?.[7] ?? '';
    expect(lic('Acme.Expr')).toBe('MIT');
    expect(lic('Acme.Redir')).toBe('Apache-2.0');
    const noLicense = ['Acme.FileLic', 'Acme.UrlLic', 'Acme.Deprecated', 'Acme.Bad'];
    for (const n of noLicense) expect(lic(n), n).toBe('');
    for (const [name, row] of x) if (name.startsWith('Acme.')) expect(String(row[8] ?? ''), name).not.toBe('');
    const licenses = await excelRows(projectId, scanId, 'Licenses');
    for (const n of noLicense) expect((licenses.get(n) ?? []).map(String), n).toContain('NOASSERTION');
  });
});

// ---------------------------------------------------------------------------
// security review follow-ups (L-3, I-8) through the real worker and enricher
// ---------------------------------------------------------------------------
function writeLock(entries: Array<{ id: string; version: string; hash: string | null }>): void {
  const app = path.join(root, 'src', 'App');
  fs.mkdirSync(app, { recursive: true });
  fs.writeFileSync(path.join(app, 'packages.lock.json'), packagesLockJson(entries));
}

describe('REQ-006 security review L-3: a redirect to another version\'s .nuspec never supplies this version\'s license', () => {
  it('L-3: redirect to the 1.0.0 nuspec for 2.0.0 and a nuspec without <version> -> error, not cached, requested again; normalized versions match', async () => {
    // Acme.Moved 2.0.0: same-origin redirect (allowed by the client) to the 1.0.0 nuspec of the same id.
    const moved = nugetPaths('Acme.Moved', '2.0.0');
    const old = nugetPaths('Acme.Moved', '1.0.0');
    reg.route(moved.nuspecPath, { status: 302, headers: { location: `${reg.origin}${old.nuspecPath}` } });
    reg.route(old.nuspecPath, { body: nuspecXml({ id: 'Acme.Moved', version: '1.0.0', expression: 'MIT' }), headers: { 'content-type': 'application/xml' } });
    // Acme.NoVer 3.0.0: no <version> element at all.
    const noVer = addNugetPackage(reg, 'Acme.NoVer', '3.0.0', { nuspec: nuspecXml({ id: 'Acme.NoVer', version: null, expression: 'MIT' }) });
    // Acme.FourPart 4.0.0: nuspec says 4.0.0.0 (NuGet-normalized equal).
    const four = addNugetPackage(reg, 'Acme.FourPart', '4.0.0', { nuspec: nuspecXml({ id: 'Acme.FourPart', version: '4.0.0.0', expression: 'Apache-2.0' }) });
    // Acme.Pre 5.0.0-beta: nuspec says 5.0.0-BETA+build.7 (case-insensitive, build metadata ignored).
    const pre = addNugetPackage(reg, 'Acme.Pre', '5.0.0-beta', { nuspec: nuspecXml({ id: 'Acme.Pre', version: '5.0.0-BETA+build.7', expression: 'BSD-3-Clause' }) });
    writeLock([
      { id: 'Acme.Moved', version: '2.0.0', hash: null },
      { id: 'Acme.NoVer', version: '3.0.0', hash: null },
      { id: 'Acme.FourPart', version: '4.0.0', hash: null },
      { id: 'Acme.Pre', version: '5.0.0-beta', hash: null },
    ]);

    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());
    const r = await rows(scanId);
    for (const n of ['Acme.Moved', 'Acme.NoVer']) {
      expect([r.get(n)?.license_enrichment_status, r.get(n)?.license_source, r.get(n)?.license_expression], n).toEqual(['error', 'none', null]);
    }
    expect([r.get('Acme.FourPart')?.license_enrichment_status, r.get('Acme.FourPart')?.license_source, r.get('Acme.FourPart')?.license_expression]).toEqual(['ok', 'registry:nuget', 'Apache-2.0']);
    expect([r.get('Acme.Pre')?.license_enrichment_status, r.get('Acme.Pre')?.license_source, r.get('Acme.Pre')?.license_expression]).toEqual(['ok', 'registry:nuget', 'BSD-3-Clause']);
    // The redirect was followed (the check is on the body, not on the redirect).
    expect([reg.count(moved.nuspecPath), reg.count(old.nuspecPath)]).toEqual([1, 1]);

    // Not cached under any version; the matching ones are cached under the requested (normalized) version.
    const cache = await db.query<{ name: string; version: string; outcome: string }>(`SELECT name, version, outcome FROM registry_package_cache WHERE ecosystem = 'nuget' ORDER BY name, version`);
    expect(cache.map((c) => [c.name, c.version, c.outcome])).toEqual([
      ['acme.fourpart', '4.0.0', 'found'],
      ['acme.pre', '5.0.0-beta', 'found'],
    ]);
    const [s] = await db.query<{ error_message: string | null }>(`SELECT error_message FROM scans WHERE id = $1`, [scanId]);
    const line = (s.error_message ?? '').split('\n').find((l) => l.startsWith('[registry]')) ?? '';
    expect(line).toMatch(/error: 2/);
    expect(line).not.toMatch(/Acme/i);

    // Second scan: the BAD_NUSPEC keys are requested again, the cached ones are not.
    reg.resetCounts();
    const r2 = await rows(await scan(projectId, enricher()));
    expect([reg.count(moved.nuspecPath), reg.count(old.nuspecPath), reg.count(noVer.nuspecPath), reg.count(four.nuspecPath), reg.count(pre.nuspecPath)]).toEqual([1, 1, 1, 0, 0]);
    expect(r2.get('Acme.Moved')?.license_enrichment_status).toBe('error');
    expect(r2.get('Acme.FourPart')?.license_expression).toBe('Apache-2.0');
  });
});

describe('REQ-006 security review I-8: a nuspec declaring .signature.p7s as its license file', () => {
  it('I-8: the signature entry is never a license file (any casing): archive verified, nothing collected, NOTICE has no signature bytes', async () => {
    const signedEntries = (id: string, version: string, declared: string) =>
      nupkgEntries(id, {
        signed: true,
        entries: [
          { name: `${id}.nuspec`, data: nuspecXml({ id, version, file: declared }) },
          { name: 'lib/net8.0/x.dll', data: Buffer.alloc(64, 7) },
        ],
      });
    const pkgs = [
      { id: 'Acme.SigLic', version: '6.0.0', declared: '.signature.p7s' },
      { id: 'Acme.SigCase', version: '7.0.0', declared: '.SIGNATURE.P7S' },
      { id: 'Acme.SigDot', version: '8.0.0', declared: './.signature.p7s' },
    ];
    const lock: Array<{ id: string; version: string; hash: string }> = [];
    for (const p of pkgs) {
      const entries = signedEntries(p.id, p.version, p.declared);
      addNugetPackage(reg, p.id, p.version, { nuspec: nuspecXml({ id: p.id, version: p.version, file: p.declared }), nupkg: buildZip(entries) });
      lock.push({ id: p.id, version: p.version, hash: independentContentHash(entries) });
    }
    writeLock(lock);

    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());
    const r = await rows(scanId);
    for (const p of pkgs) {
      const row = r.get(p.id);
      // The archive itself is verified (content hash match) and the declaration is kept as "file, not classified".
      expect([row?.license_enrichment_status, row?.license_source, row?.license_expression, row?.lock_integrity, row?.license_unclassified], p.id).toEqual(['no_license', 'none', null, 'match', 'file']);
      expect(row?.notice_status, p.id).not.toBe('collected');
    }
    const archives = await db.query<{ name: string; license_files: unknown[] }>(`SELECT name, license_files FROM registry_archive_cache WHERE ecosystem = 'nuget' ORDER BY name`);
    expect(archives.map((a) => a.name)).toEqual(['acme.sigcase', 'acme.sigdot', 'acme.siglic']);
    for (const a of archives) expect(a.license_files, a.name).toEqual([]);

    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    expect(text).not.toContain('3082fake-pkcs7-signature-bytes');
    expect(text).not.toContain('.signature.p7s');
    for (const p of pkgs) {
      const start = text.indexOf(`Package: ${p.id}\n`);
      expect(start, p.id).toBeGreaterThanOrEqual(0);
      const next = text.indexOf('\nPackage: ', start + 1);
      const block = text.slice(start, next === -1 ? undefined : next);
      expect(block, p.id).toContain('License files: 0');
      expect(block, p.id).toContain('License: NOASSERTION');
    }
  });
});

describe('AC-NV-1…3: OSV NuGet through the worker and the daily recheck', () => {
  it('AC-NV-1 / AC-NV-2 / AC-NV-3: querybatch NuGet names (nuspec <id>, else first-seen casing), case-insensitive affected, recheck dotnet->nuget with canonical_name', async () => {
    setupFixture();
    osv.vulns.set(osvKey('NuGet', 'Acme.Expr', '1.0.0'), [{ id: 'GHSA-acme-expr-0001', modified: '2026-01-01T00:00:00Z' }]);
    osv.addRecord('GHSA-acme-expr-0001', { affected: [{ package: { ecosystem: 'NuGet', name: 'acme.expr' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }] });
    const projectId = await insertProject();
    const scanId = await scan(projectId, enricher());

    const queries = osv.batches().flat();
    const nuget = queries.filter((q) => q.package.ecosystem === 'NuGet');
    expect(queries.every((q) => q.package.ecosystem === 'NuGet')).toBe(true);
    const names = nuget.map((q) => `${q.package.name}@${q.version}`).sort();
    expect(names).toEqual(expect.arrayContaining(['ACME.Deprecated@6.0.0', 'Acme.Expr@1.0.0', 'Acme.WrongId@8.0.0', 'Acme.Multi@5.0.0']));
    expect(names.some((n) => n === n.toLowerCase())).toBe(false);

    const [s] = await db.query<{ total: number }>(`SELECT total_vulnerabilities AS total FROM scans WHERE id = $1`, [scanId]);
    expect(Number(s.total)).toBe(1);

    // AC-NV-3: recheck scope maps dotnet -> NuGet and uses the cached .nuspec <id>.
    osv.resetCounts();
    const runner = createRecheckRunner({
      db: db.pool,
      lookup: makeF4Lookup(db, osv.origin, appClock, logs, clients),
      expiry: createExpiryEvaluator({ db: db.pool, clock: appClock, logger }),
      runtimeRunId: 'rt-nuget',
      clock: appClock,
      logger,
    });
    await runner.run(new AbortController().signal);
    const recheck = osv.batches().flat().filter((q) => q.package.ecosystem === 'NuGet').map((q) => `${q.package.name}@${q.version}`);
    expect(recheck).toEqual(expect.arrayContaining(['ACME.Deprecated@6.0.0', 'Acme.Expr@1.0.0']));
    expect(recheck).not.toContain('acme.deprecated@6.0.0');
  });
});

describe('AC-P20-18 / contract 3.3: NOTICE ordering and NuGet uniqueness (seeded rows)', () => {
  it('AC-P20-18: entries ordered npm < nuget < pypi; NuGet ids differing only in case are one entry', async () => {
    const { scanId } = await seedScan(db, {
      projectName: 'notice-order-nuget',
      deps: [
        f3Dep({ ecosystem: 'python', name: 'a-py', version: '1.0', purl: 'pkg:pypi/a-py@1.0', licenseExpression: 'MIT', licenseSource: 'registry:pypi' }),
        f3Dep({ ecosystem: 'dotnet', name: 'Zed.Nu', version: '1.0.0', purl: 'pkg:nuget/Zed.Nu@1.0.0', licenseExpression: 'MIT', licenseSource: 'registry:nuget' }),
        f3Dep({ ecosystem: 'dotnet', name: 'zed.nu', version: '1.0.0', purl: 'pkg:nuget/zed.nu@1.0.0', licenseExpression: 'MIT', licenseSource: 'registry:nuget', manifestPath: 'src/Other' }),
        f3Dep({ ecosystem: 'nodejs', name: 'z-npm', version: '1.0.0', purl: 'pkg:npm/z-npm@1.0.0', licenseExpression: 'MIT' }),
      ],
    });
    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    const ecos = text.split('\n').filter((l) => l.startsWith('Ecosystem: ')).map((l) => l.slice(11));
    expect(ecos).toEqual(['npm', 'nuget', 'pypi']);
    expect(text).toContain('Packages: 3\n');
  });

  it('AC-P21-5 / contract 1.4.0 §4.3: unclassified prefix on the Reason line of seeded NuGet rows; npm rows unchanged', async () => {
    const { scanId } = await seedScan(db, {
      projectName: 'notice-prefix-nuget',
      deps: [
        f3Dep({ ecosystem: 'dotnet', name: 'U.File', version: '1.0.0', purl: 'pkg:nuget/U.File@1.0.0', licenseSource: 'none', enrichmentStatus: 'no_license', noticeStatus: 'no_candidate' }),
        f3Dep({ ecosystem: 'dotnet', name: 'U.Url', version: '1.0.0', purl: 'pkg:nuget/U.Url@1.0.0', licenseSource: 'none', enrichmentStatus: 'no_license', noticeStatus: 'no_candidate' }),
      ],
    });
    await db.query(
      `UPDATE scan_dependencies sd SET license_unclassified = CASE p.name WHEN 'U.File' THEN 'file' ELSE 'url' END FROM packages p WHERE p.id = sd.package_id AND sd.scan_id = $1`,
      [scanId],
    );
    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    expect(text).toContain('Reason: license is a file inside the package (not classified); package archive not downloaded (no lockfile integrity value)');
    expect(text).toContain('Reason: license URL not classified; package archive not downloaded (no lockfile integrity value)');
  });
});

describe('AC-G-4: license_unclassified is internal (never in an API JSON response)', () => {
  it('AC-G-4: only the worker, enrichment, NOTICE and report generators reference the column', () => {
    const srcRoot = path.resolve(__dirname, '../../src');
    const hits: string[] = [];
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (/\.(ts|tsx|js)$/.test(e.name) && /license_unclassified|licenseUnclassified/.test(fs.readFileSync(full, 'utf8'))) hits.push(path.relative(srcRoot, full).replace(/\\/g, '/'));
      }
    };
    walk(srcRoot);
    const allowed = /^(enrichment\/|scanner\/worker\.ts$|notice\/noticeService\.ts$|reports\/reportService\.ts$)/;
    expect(hits.filter((h) => !allowed.test(h))).toEqual([]);
    expect(hits).toContain('scanner/worker.ts');
  });
});
