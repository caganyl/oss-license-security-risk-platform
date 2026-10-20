/**
 * REQ-011 P-43 · New-ecosystem licenses end to end in the scan worker
 * (AC-P43-1…3, AC-P40-7, AC-G-3; D-312, D-318…D-321).
 *
 * Real embedded PostgreSQL (fresh migrated DB per test), `ScanWorker.runOnce`
 * with an injected parser and an injected enricher whose deps.dev and pub.dev
 * endpoints point at the loopback fake registry. No non-loopback connection
 * is possible (network guard).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type DependencyEnricher, createDependencyEnricher } from '../../src/enrichment';
import type { RegistryClock } from '../../src/enrichment/registryClient';
import { NoticeService } from '../../src/notice/noticeService';
import { ScanWorker } from '../../src/scanner/worker';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
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
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p43-'));
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

type Dep = SandboxScanResult['dependencies'][number];
const dep = (ecosystem: string, name: string, version: string | null, purl: string, licenses: string[] = [], manifest = 'lock'): Dep =>
  ({ ecosystem, name, version, purl, scope: 'direct', licenses, manifest_file: manifest, manifest_path: '.' }) as Dep;

const DEPS: Dep[] = [
  dep('go', 'github.com/stretchr/testify', 'v1.8.4', 'pkg:golang/github.com/stretchr/testify@v1.8.4', [], 'go.mod'),
  dep('java', 'org.slf4j:slf4j-api', '2.0.9', 'pkg:maven/org.slf4j/slf4j-api@2.0.9', [], 'pom.xml'),
  dep('rust', 'serde', '1.0.193', 'pkg:cargo/serde@1.0.193', [], 'Cargo.lock'),
  dep('ruby', 'rails', '7.1.2', 'pkg:gem/rails@7.1.2', [], 'Gemfile.lock'),
  dep('dart', 'http', '1.1.0', 'pkg:pub/http@1.1.0', [], 'pubspec.lock'),
  dep('php', 'monolog/monolog', '3.5.0', 'pkg:composer/monolog/monolog@3.5.0', ['MIT'], 'composer.lock'),
  dep('swift', 'github.com/apple/swift-nio', '2.62.0', 'pkg:swift/github.com/apple/swift-nio@2.62.0', [], 'Package.resolved'),
];

const DD = (system: string, encodedName: string, version: string) => `/v3/systems/${system}/packages/${encodedName}/versions/${version}`;
const ROUTES = {
  go: DD('GO', 'github.com%2Fstretchr%2Ftestify', 'v1.8.4'),
  maven: DD('MAVEN', 'org.slf4j%3Aslf4j-api', '2.0.9'),
  cargo: DD('CARGO', 'serde', '1.0.193'),
  gem: DD('RUBYGEMS', 'rails', '7.1.2'),
  pub: '/api/packages/http/score',
};

function seed(): void {
  reg.route(ROUTES.go, { body: { licenses: ['MIT'] } });
  reg.route(ROUTES.maven, { body: { licenses: ['MIT'] } });
  reg.route(ROUTES.cargo, { body: { licenses: ['MIT OR Apache-2.0'] } });
  reg.route(ROUTES.gem, { body: { licenses: ['MIT'] } });
  reg.route(ROUTES.pub, { body: { tags: ['license:bsd-3-clause', 'license:osi-approved', 'sdk:dart'] } });
}

function enricher(enabled = true): DependencyEnricher {
  const e = createDependencyEnricher({
    config: { enabled, timeoutMs: 3_000, concurrency: 4 },
    db: db.pool,
    logger,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin, nuget: reg.origin, depsdev: reg.origin, pubdev: reg.origin },
    clock: fastClock,
    env: {},
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
  license_expression: string | null;
  license_source: string | null;
  license_enrichment_status: string | null;
  notice_status: string | null;
  notice_archive_id: string | null;
  lock_integrity: string | null;
}

async function rows(scanId: string): Promise<Record<string, DepRow>> {
  const r = await db.query<DepRow>(
    `SELECT p.name, sd.license_expression, sd.license_source, sd.license_enrichment_status, sd.notice_status,
            sd.notice_archive_id, sd.lock_integrity
       FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1`,
    [scanId],
  );
  return Object.fromEntries(r.map((row) => [row.name, row]));
}

async function scanRow(scanId: string): Promise<{ status: string; error_message: string | null }> {
  const [r] = await db.query<{ status: string; error_message: string | null }>(`SELECT status::text, error_message FROM scans WHERE id = $1`, [scanId]);
  return r;
}

const noticeText = async (scanId: string) => (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');

/** The NOTICE block of one package (from `Package: <name>` to the next separator). */
function block(text: string, name: string): string {
  const start = text.indexOf(`Package: ${name}\n`);
  expect(start, name).toBeGreaterThanOrEqual(0);
  const end = text.indexOf('\n====', start);
  return text.slice(start, end === -1 ? undefined : end);
}

// ---------------------------------------------------------------------------
describe('AC-P43-1 / AC-P43-2: new-ecosystem licenses in a scan', () => {
  it('go/maven/cargo/rubygems -> registry:depsdev, dart -> registry:pubdev; php keeps the composer.lock license; swift none; no row is pre-F3', async () => {
    seed();
    const scanId = await scan(await insertProject(), enricher());
    expect((await scanRow(scanId)).status).toBe('completed');
    const d = await rows(scanId);
    const reg1 = { license_enrichment_status: 'ok', notice_status: 'not_attempted', notice_archive_id: null, lock_integrity: null };
    expect(d['github.com/stretchr/testify']).toMatchObject({ ...reg1, license_expression: 'MIT', license_source: 'registry:depsdev' });
    expect(d['org.slf4j:slf4j-api']).toMatchObject({ ...reg1, license_expression: 'MIT', license_source: 'registry:depsdev' });
    expect(d.serde).toMatchObject({ ...reg1, license_expression: 'MIT OR Apache-2.0', license_source: 'registry:depsdev' });
    expect(d.rails).toMatchObject({ ...reg1, license_expression: 'MIT', license_source: 'registry:depsdev' });
    expect(d.http).toMatchObject({ ...reg1, license_expression: 'BSD-3-Clause', license_source: 'registry:pubdev' });
    // D-319 / AC-P40-7: no PHP request; the lock license with its unverified source.
    expect(d['monolog/monolog']).toMatchObject({ license_enrichment_status: 'disabled', license_source: 'lockfile (unverified)', license_expression: 'MIT' });
    // D-320: Swift has no source.
    expect(d['github.com/apple/swift-nio']).toMatchObject({ license_enrichment_status: 'disabled', license_source: 'none', license_expression: null });
    expect(Object.values(d).every((r) => r.license_source !== null && r.license_enrichment_status !== null)).toBe(true);
    // Exactly one request per deps.dev / pub.dev package; nothing for php/swift; no archive download.
    expect(reg.requests.map((r) => r.path).sort()).toEqual(Object.values(ROUTES).sort());
    // D-318: cache rows keyed depsdev/pubdev.
    const cache = await db.query<{ ecosystem: string; name: string; version: string; outcome: string; declared_license: string | null }>(
      `SELECT ecosystem, name, version, outcome, declared_license FROM registry_package_cache ORDER BY ecosystem, name`,
    );
    expect(cache).toEqual([
      { ecosystem: 'depsdev', name: 'CARGO:serde', version: '1.0.193', outcome: 'found', declared_license: 'MIT OR Apache-2.0' },
      { ecosystem: 'depsdev', name: 'GO:github.com/stretchr/testify', version: 'v1.8.4', outcome: 'found', declared_license: 'MIT' },
      { ecosystem: 'depsdev', name: 'MAVEN:org.slf4j:slf4j-api', version: '2.0.9', outcome: 'found', declared_license: 'MIT' },
      { ecosystem: 'depsdev', name: 'RUBYGEMS:rails', version: '7.1.2', outcome: 'found', declared_license: 'MIT' },
      { ecosystem: 'pubdev', name: 'http', version: '1.1.0', outcome: 'found', declared_license: 'bsd-3-clause' },
    ]);
    expect(await db.query(`SELECT 1 FROM registry_archive_cache`)).toEqual([]);

    // Second scan: served from the cache, no new request (AC-P43-3).
    reg.resetCounts();
    const before = reg.requests.length;
    const again = await rows(await scan(await insertProject(), enricher()));
    expect(reg.requests.length).toBe(before);
    expect(again.http.license_source).toBe('registry:pubdev');
  });

  it('D-321 / D-312: NOTICE shows the SPDX id and source only; php/swift keep the "not supported" reason', async () => {
    seed();
    const text = await noticeText(await scan(await insertProject(), enricher()));
    expect(text).not.toContain('predates license enrichment');
    const maven = block(text, 'org.slf4j:slf4j-api');
    expect(maven).toContain('License: MIT\nLicense source: registry:depsdev\n');
    expect(maven).toContain('License files: 0\n');
    expect(block(text, 'http')).toContain('License: BSD-3-Clause\nLicense source: registry:pubdev\n');
    expect(block(text, 'monolog/monolog')).toContain('License: MIT\nLicense source: lockfile (unverified)\n');
    expect(block(text, 'monolog/monolog')).toContain('Reason: license enrichment not supported for this ecosystem');
    expect(block(text, 'github.com/apple/swift-nio')).toContain('License: NOASSERTION\nLicense source: none\n');
    expect(block(text, 'github.com/apple/swift-nio')).toContain('Reason: license enrichment not supported for this ecosystem');
  });
});

describe('AC-P43-3 / AC-G-3: failures and the off switch', () => {
  it('unreachable deps.dev and pub.dev -> license unknown (status unreachable), scan completes with the [registry] line', async () => {
    for (const p of Object.values(ROUTES)) reg.route(p, { reset: true });
    const scanId = await scan(await insertProject(), enricher());
    const s = await scanRow(scanId);
    expect(s.status).toBe('completed');
    expect(s.error_message ?? '').toContain('[registry] Registry lookup incomplete for 5 package(s) (unreachable: 5');
    const d = await rows(scanId);
    for (const name of ['github.com/stretchr/testify', 'org.slf4j:slf4j-api', 'serde', 'rails', 'http']) {
      expect(d[name], name).toMatchObject({ license_enrichment_status: 'unreachable', license_source: 'none', license_expression: null });
    }
    // Transient failures are never cached.
    expect(await db.query(`SELECT 1 FROM registry_package_cache`)).toEqual([]);
  });

  it('404 -> not_found, license unknown', async () => {
    const scanId = await scan(await insertProject(), enricher(), [DEPS[2], DEPS[4]]);
    const d = await rows(scanId);
    expect(d.serde).toMatchObject({ license_enrichment_status: 'not_found', license_source: 'none' });
    expect(d.http).toMatchObject({ license_enrichment_status: 'not_found', license_source: 'none' });
  });

  it('REGISTRY_ENRICHMENT=off -> no request; every new-ecosystem row disabled (php keeps its lock license)', async () => {
    seed();
    const scanId = await scan(await insertProject(), enricher(false));
    expect(reg.total()).toBe(0);
    const d = await rows(scanId);
    expect(Object.values(d).map((r) => r.license_enrichment_status)).toEqual(Array(DEPS.length).fill('disabled'));
    expect(d['monolog/monolog'].license_source).toBe('lockfile (unverified)');
    expect(d.serde.license_source).toBe('none');
  });

  it('no enricher injected (saveScanResults path) -> php/swift and registry ecosystems still get a status', async () => {
    const d = await rows(await scan(await insertProject(), null));
    expect(Object.values(d).every((r) => r.license_enrichment_status === 'disabled')).toBe(true);
  });
});
