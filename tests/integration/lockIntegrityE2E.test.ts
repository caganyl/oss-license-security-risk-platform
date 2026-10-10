/**
 * REQ-005 · L-5 lock `integrity` mismatch end to end through the scan worker
 * (AC-L5-2, AC-L5-4; REQ-004 contract 1.3.0 §4.1, §4.3 row 15, §4.4, §5.1,
 * §6, §8; ADR-007 Karar 12).
 *
 * A real npm project folder (package.json + package-lock.json v3) is scanned
 * by `ScanWorker.runOnce` with the default lock-aware parser thread (the L-5
 * side channel is produced by the real parser) and an enricher pointed at the
 * loopback fake registry (helpers/fakeRegistry). One runtime package's lock
 * `integrity` (sha512) differs from the registry `dist.integrity`; a control
 * package matches. Outputs are then produced from the database by the real
 * services: Excel (`ReportService`), NOTICE (`NoticeService`) and SBOM
 * (`SbomService`). Real embedded PostgreSQL, fresh migrated DB per test; no
 * non-loopback connection is possible (network guard).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ExcelJS from 'exceljs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type DependencyEnricher, createDependencyEnricher } from '../../src/enrichment';
import type { RegistryClock } from '../../src/enrichment/registryClient';
import { NoticeService } from '../../src/notice/noticeService';
import { ReportService } from '../../src/reports/reportService';
import { SbomService, type SbomFormat } from '../../src/sbom/sbomService';
import { ScanWorker } from '../../src/scanner/worker';
import { sha512b64 } from '../helpers/archiveBuilder';
import { useTestDatabase } from '../helpers/db';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

let tmpRoot = '';
let root = '';
let outDir = '';
let reg: FakeRegistry;
let logs: string[] = [];
const enrichers: DependencyEnricher[] = [];
const savedEnv: Record<string, string | undefined> = {};
const push = (...a: unknown[]) => logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-l5e2e-'));
  root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
  outDir = fs.mkdtempSync(path.join(tmpRoot, 'out-'));
  for (const k of ['REPORT_OUTPUT_DIR', 'SBOM_OUTPUT_DIR']) {
    savedEnv[k] = process.env[k];
    process.env[k] = outDir;
  }
  logs = [];
  reg = await startFakeRegistry();
});
afterEach(async () => {
  for (const e of enrichers.splice(0)) e.close();
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  await reg.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
/** Contract §4.3 row 15. */
const REASON_MISMATCH = 'Reason: lockfile integrity does not match registry; license not verified';
/** Contract §4.1 / §5.1. */
const EXCEL_MISMATCH = 'none (lockfile integrity mismatch)';
/** sha512 SRI of bytes that are not the published tarball. */
const FOREIGN_SRI = `sha512-${sha512b64(Buffer.from('not the published tarball'))}`;
const SEPARATOR = '='.repeat(80);

interface LockEntry {
  name: string;
  version: string;
  integrity: string;
  /** Lock `license` field (the L-6 lock hint). */
  license?: string;
  dev?: boolean;
}

/** package.json + package-lock.json v3 in the scan root. */
function writeProject(entries: LockEntry[]): void {
  const runtime = Object.fromEntries(entries.filter((e) => !e.dev).map((e) => [e.name, `^${e.version}`]));
  const dev = Object.fromEntries(entries.filter((e) => e.dev).map((e) => [e.name, `^${e.version}`]));
  const pkg = { name: 'l5-app', version: '1.0.0', dependencies: runtime, devDependencies: dev };
  const packages: Record<string, unknown> = { '': { name: 'l5-app', version: '1.0.0', dependencies: runtime, devDependencies: dev } };
  for (const e of entries) {
    packages[`node_modules/${e.name}`] = {
      version: e.version,
      integrity: e.integrity,
      ...(e.license !== undefined ? { license: e.license } : {}),
      ...(e.dev ? { dev: true } : {}),
    };
  }
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(pkg, null, 2));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ name: 'l5-app', version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2));
}

function enricher(): DependencyEnricher {
  const e = createDependencyEnricher({
    config: { enabled: true, timeoutMs: 3_000, concurrency: 4 },
    db: db.pool,
    logger,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin },
    clock: fastClock,
    env: {},
  });
  enrichers.push(e);
  return e;
}

async function insertProject(name: string): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [name, root]);
  await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, 'nodejs')`, [p.id]);
  return p.id;
}

/** One scan through the worker: default lock-aware parser thread (no injected runParser). */
async function scan(projectId: string): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId],
  );
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runId: 'run-L5', enricher: enricher() });
  expect(await w.runOnce()).toBe(s.id);
  return s.id;
}

interface DepRow {
  name: string;
  scope: string;
  license_expression: string | null;
  license_source: string | null;
  license_lock_hint: string | null;
  license_hint_differs: boolean | null;
  license_enrichment_status: string | null;
  notice_status: string | null;
  notice_archive_id: string | null;
  lock_integrity: string | null;
}

async function deps(scanId: string): Promise<Record<string, DepRow>> {
  const rows = await db.query<DepRow>(
    `SELECT p.name, sd.scope::text, sd.license_expression, sd.license_source, sd.license_lock_hint, sd.license_hint_differs,
            sd.license_enrichment_status, sd.notice_status, sd.notice_archive_id, sd.lock_integrity
       FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1`,
    [scanId],
  );
  return Object.fromEntries(rows.map((r) => [r.name, r]));
}

async function scanRow(scanId: string): Promise<{ status: string; error_message: string | null }> {
  const [r] = await db.query<{ status: string; error_message: string | null }>(`SELECT status::text, error_message FROM scans WHERE id = $1`, [scanId]);
  return r;
}

async function licenseFindings(scanId: string): Promise<Array<{ name: string; normalized_license: string; finding_type: string }>> {
  return db.query(
    `SELECT p.name, lf.normalized_license, f.finding_type::text
       FROM findings f JOIN license_findings lf ON lf.finding_id = f.id
       JOIN scan_dependencies sd ON sd.id = f.scan_dependency_id JOIN packages p ON p.id = sd.package_id
      WHERE f.scan_id = $1 ORDER BY p.name, lf.normalized_license`,
    [scanId],
  );
}

async function excel(projectId: string, scanId: string): Promise<ExcelJS.Workbook> {
  const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id`, [`qa-${Math.random().toString(36).slice(2)}@example.test`]);
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by) VALUES ($1, 'project_report', 'excel', 'generating', $2::jsonb, $3) RETURNING id`,
    [projectId, JSON.stringify({ scanId }), u.id],
  );
  const record = await new ReportService(db.pool).processReport(r.id);
  expect(record.status).toBe('ready');
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(record.storageKey!);
  return wb;
}

/** Sheet rows keyed by the first cell (1-based cells as plain values, header excluded). */
function rowsByName(sheet: ExcelJS.Worksheet): Map<string, unknown[]> {
  const rows = new Map<string, unknown[]>();
  for (let i = 2; i <= sheet.rowCount; i++) {
    const values = (sheet.getRow(i).values as unknown[]).slice(1);
    rows.set(String(values[0]), values);
  }
  return rows;
}

async function notice(scanId: string): Promise<string> {
  return (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
}

/** NOTICE entry of `name` (lines between two separators). */
function noticeEntry(text: string, name: string): string[] {
  const block = text.split(`\n${SEPARATOR}\n`).find((b) => b.startsWith(`Package: ${name}\n`));
  expect(block, `NOTICE entry of ${name}`).toBeDefined();
  return (block as string).split('\n').filter((l) => l !== '');
}

const mismatchEntry = (name: string, version: string) => [
  `Package: ${name}`,
  `Version: ${version}`,
  'Ecosystem: npm',
  `PURL: pkg:npm/${name}@${version}`,
  'License: NOASSERTION',
  'License source: none',
  'Copyright: (none found)',
  'License files: 0',
  REASON_MISMATCH,
];

// ---------------------------------------------------------------------------
describe('AC-L5-2 / AC-L5-4: lock integrity mismatch through the scan worker (REQ-004 contract 1.3.0)', () => {
  it('AC-L5-2: mismatching sha512 -> NOASSERTION finding, no tarball request, lock_integrity=mismatch, license_source=none, notice_status=not_attempted; Excel/NOTICE/SBOM/[registry] per contract; matching control package enriched as in F3 (AC-L5-4)', async () => {
    // mis-pkg: registry says GPL-3.0-only, lock hint says MIT, lock integrity is a foreign sha512.
    const mis = reg.addNpmPackage('mis-pkg', '1.0.0', { license: 'GPL-3.0-only' });
    // ok-pkg: lock integrity equals the published sha512 (control, AC-L5-4).
    const ok = reg.addNpmPackage('ok-pkg', '2.0.0', { license: 'MIT' });
    // dev-mis: dev scope, foreign sha512 -> mismatch but not_runtime, no finding.
    const devMis = reg.addNpmPackage('dev-mis', '3.0.0', { license: 'ISC' });
    expect(mis.tarball).not.toBeNull();
    writeProject([
      { name: 'mis-pkg', version: '1.0.0', integrity: FOREIGN_SRI, license: 'MIT' },
      { name: 'ok-pkg', version: '2.0.0', integrity: `sha512-${sha512b64(ok.tarball as Buffer)}`, license: 'MIT' },
      { name: 'dev-mis', version: '3.0.0', integrity: FOREIGN_SRI, dev: true },
    ]);
    const projectId = await insertProject('l5-e2e');
    const scanId = await scan(projectId);
    const row = await scanRow(scanId);
    expect(row.status).toBe('completed');

    // --- registry traffic: metadata asked for all three, tarball only for the matching runtime package.
    expect(reg.count(mis.docPath)).toBe(1);
    expect(reg.count(mis.tarballPath)).toBe(0);
    expect(reg.count(devMis.tarballPath)).toBe(0);
    expect(reg.count(ok.tarballPath)).toBe(1);

    // --- scan_dependencies (contract §4.4 stored values).
    const d = await deps(scanId);
    expect(d['mis-pkg']).toMatchObject({
      scope: 'direct',
      lock_integrity: 'mismatch',
      license_expression: null,
      license_source: 'none',
      license_hint_differs: false,
      license_enrichment_status: 'ok', // metadata result is kept
      license_lock_hint: 'MIT', // stored, never shown
      notice_status: 'not_attempted',
      notice_archive_id: null,
    });
    expect(d['dev-mis']).toMatchObject({ scope: 'dev', lock_integrity: 'mismatch', license_source: 'none', license_expression: null, notice_status: 'not_runtime', notice_archive_id: null });
    expect(d['ok-pkg']).toMatchObject({ lock_integrity: 'match', license_expression: 'MIT', license_source: 'registry:npm', license_enrichment_status: 'ok', notice_status: 'collected' });
    expect(d['ok-pkg'].notice_archive_id).not.toBeNull();
    // No archive cache row was written for the mismatching keys.
    expect(await db.query(`SELECT name FROM registry_archive_cache ORDER BY name`)).toEqual([{ name: 'ok-pkg' }]);

    // --- findings: NOASSERTION ("unknown") for the runtime mismatch; neither the registry license nor the hint enters the policy.
    const findings = await licenseFindings(scanId);
    expect(findings.filter((f) => f.name === 'mis-pkg')).toEqual([{ name: 'mis-pkg', normalized_license: 'NOASSERTION', finding_type: 'license' }]);
    expect(findings.filter((f) => f.name === 'dev-mis')).toEqual([]);
    expect(findings.some((f) => f.normalized_license === 'GPL-3.0-only')).toBe(false);
    expect(findings.some((f) => f.name === 'ok-pkg' && f.normalized_license === 'NOASSERTION')).toBe(false);

    // --- [registry] line: T = 0, X = 2 -> third template, single line (contract §8).
    const registryLines = (row.error_message ?? '').split('\n').filter((l) => l.startsWith('[registry]'));
    expect(registryLines).toEqual(['[registry] Lockfile integrity mismatch for 2 package(s); registry license and lockfile hint not used.']);

    // --- Excel (contract §4.1, §5.1, §5.1a).
    const wb = await excel(projectId, scanId);
    const depRows = rowsByName(wb.getWorksheet('Dependencies')!);
    const lic = (n: string) => [depRows.get(n)?.[7] ?? '', depRows.get(n)?.[8] ?? ''];
    expect(lic('mis-pkg')).toEqual(['', EXCEL_MISMATCH]);
    expect(lic('dev-mis')).toEqual(['', EXCEL_MISMATCH]);
    expect(lic('ok-pkg')).toEqual(['MIT', 'registry:npm']);
    // Neither the hint nor the registry license is written into the mismatch cell.
    expect(String(lic('mis-pkg')[1])).not.toMatch(/MIT|GPL|hint ignored/);
    const licRows = [...rowsByName(wb.getWorksheet('Licenses')!).values()];
    const misLic = licRows.filter((r) => r[0] === 'mis-pkg');
    expect(misLic).toHaveLength(1);
    expect(misLic[0][3]).toBe('NOASSERTION'); // Normalized License
    expect(licRows.some((r) => r[0] === 'dev-mis')).toBe(false);

    // --- NOTICE (contract §4.3 row 15): text-less entry, Reason line, no SPDX line, no cached archive read.
    const text = await notice(scanId);
    expect(noticeEntry(text, 'mis-pkg')).toEqual(mismatchEntry('mis-pkg', '1.0.0'));
    expect(text).not.toContain('Package: dev-mis\n'); // not_runtime -> not in NOTICE
    const okEntry = noticeEntry(text, 'ok-pkg');
    expect(okEntry.slice(0, 8)).toEqual([
      'Package: ok-pkg',
      'Version: 2.0.0',
      'Ecosystem: npm',
      'PURL: pkg:npm/ok-pkg@2.0.0',
      'License: MIT',
      'License source: registry:npm',
      'Copyright: Copyright (c) 2020 ok-pkg authors',
      'License files: 1',
    ]);
    expect(okEntry.some((l) => l.startsWith('Reason:'))).toBe(false);
    expect(text.split('\n').filter((l) => l === REASON_MISMATCH)).toHaveLength(1);

    // --- SBOM (contract §6): NOASSERTION, no licenseComments, no CycloneDX licenses/copyright.
    const svc = new SbomService(db.pool);
    const read = async (f: SbomFormat) => fs.readFileSync((await svc.generate(scanId, f)).storageKey, 'utf8');
    type SpdxPkg = { name: string; licenseDeclared?: string; copyrightText?: string; licenseComments?: string };
    const spdx = JSON.parse(await read('spdx_json')) as { packages: SpdxPkg[] };
    const spdxMis = spdx.packages.find((p) => p.name === 'mis-pkg')!;
    expect(spdxMis).toMatchObject({ licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION' });
    expect(spdxMis.licenseComments).toBeUndefined();
    const spdxOk = spdx.packages.find((p) => p.name === 'ok-pkg')!;
    expect(spdxOk).toMatchObject({ licenseDeclared: 'MIT', copyrightText: 'Copyright (c) 2020 ok-pkg authors' });

    const tv = await read('spdx_tag_value');
    const start = tv.indexOf('PackageName: mis-pkg\n');
    expect(start).toBeGreaterThanOrEqual(0);
    const next = tv.indexOf('PackageName:', start + 1);
    const tvMis = tv.slice(start, next === -1 ? undefined : next);
    expect(tvMis).toContain('PackageLicenseDeclared: NOASSERTION\n');
    expect(tvMis).toContain('PackageCopyrightText: NOASSERTION\n');
    expect(tvMis).not.toContain('PackageLicenseComments');

    type CdxComp = { name: string; licenses?: unknown[]; copyright?: string };
    const cdx = JSON.parse(await read('cyclonedx_json')) as { components: CdxComp[] };
    const cdxMis = cdx.components.find((c) => c.name === 'mis-pkg')!;
    expect(cdxMis.licenses).toBeUndefined();
    expect(cdxMis.copyright).toBeUndefined();
    const cdxOk = cdx.components.find((c) => c.name === 'ok-pkg')!;
    expect(cdxOk.licenses).toBeDefined();
    expect(cdxOk.copyright).toBe('Copyright (c) 2020 ok-pkg authors');
  });

  it('AC-L5-2: a cached archive of the same key is not used: a rescan after the lock changes to a foreign sha512 makes no request, stores no archive id and NOTICE does not read the cache', async () => {
    const mis = reg.addNpmPackage('mis-pkg', '1.0.0', { license: 'MIT' });
    const good = `sha512-${sha512b64(mis.tarball as Buffer)}`;
    writeProject([{ name: 'mis-pkg', version: '1.0.0', integrity: good }]);
    const projectId = await insertProject('l5-cache');

    // 1st scan: matching lock -> archive collected and cached (AC-L5-4 control).
    const first = await scan(projectId);
    expect((await deps(first))['mis-pkg']).toMatchObject({ lock_integrity: 'match', notice_status: 'collected', license_source: 'registry:npm' });
    expect(reg.count(mis.tarballPath)).toBe(1);
    expect(await db.query(`SELECT 1 FROM registry_archive_cache WHERE name = 'mis-pkg'`)).toHaveLength(1);

    // 2nd scan: the lock now points at different bytes (metadata comes from the cache).
    writeProject([{ name: 'mis-pkg', version: '1.0.0', integrity: FOREIGN_SRI }]);
    reg.resetCounts();
    const second = await scan(projectId);
    expect(reg.total()).toBe(0);
    expect((await deps(second))['mis-pkg']).toMatchObject({
      lock_integrity: 'mismatch',
      license_source: 'none',
      license_expression: null,
      notice_status: 'not_attempted',
      notice_archive_id: null,
    });
    // The cache row still exists, but the NOTICE entry is text-less with the row 15 reason.
    expect(await db.query(`SELECT 1 FROM registry_archive_cache WHERE name = 'mis-pkg'`)).toHaveLength(1);
    const text = await notice(second);
    expect(noticeEntry(text, 'mis-pkg')).toEqual(mismatchEntry('mis-pkg', '1.0.0'));
    expect(text).not.toContain('Copyright (c) 2020 mis-pkg authors');
    expect((await licenseFindings(second)).map((f) => f.normalized_license)).toEqual(['NOASSERTION']);
    expect((await scanRow(second)).error_message).toBe('[registry] Lockfile integrity mismatch for 1 package(s); registry license and lockfile hint not used.');
    // The first scan's NOTICE is unchanged (still reads its own archive id).
    expect(noticeEntry(await notice(first), 'mis-pkg')).toContain('Copyright: Copyright (c) 2020 mis-pkg authors');
  });

  it('AC-L5-4: matching or not comparable keys -> F3 behaviour, X = 0 -> no [registry] line', async () => {
    const a = reg.addNpmPackage('match-pkg', '1.0.0', { license: 'MIT' });
    const b = reg.addNpmPackage('sha1-only', '1.0.0', { license: 'ISC' });
    writeProject([
      // Several SRI items: one matching sha512 is enough.
      { name: 'match-pkg', version: '1.0.0', integrity: `sha1-q83vEjRWeJA= ${FOREIGN_SRI} sha512-${sha512b64(a.tarball as Buffer)}` },
      // Only sha1 in the lock -> not comparable.
      { name: 'sha1-only', version: '1.0.0', integrity: 'sha1-q83vEjRWeJA=' },
    ]);
    const scanId = await scan(await insertProject('l5-regression'));
    const d = await deps(scanId);
    expect(d['match-pkg']).toMatchObject({ lock_integrity: 'match', license_source: 'registry:npm', license_expression: 'MIT', notice_status: 'collected' });
    expect(d['sha1-only']).toMatchObject({ lock_integrity: 'not_comparable', license_source: 'registry:npm', license_expression: 'ISC', notice_status: 'collected' });
    expect(reg.count(a.tarballPath)).toBe(1);
    expect(reg.count(b.tarballPath)).toBe(1);
    expect((await scanRow(scanId)).error_message ?? '').not.toContain('[registry]');
    const text = await notice(scanId);
    expect(text).not.toContain(REASON_MISMATCH);
    expect(noticeEntry(text, 'match-pkg')).toContain('License source: registry:npm');
    expect((await licenseFindings(scanId)).some((f) => f.normalized_license === 'NOASSERTION')).toBe(false);
  });
});
