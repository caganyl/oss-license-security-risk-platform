/**
 * REQ-006 · NuGet scan gates through the real scan worker:
 * - AC-G-10 (D-142): a full local-folder .NET scan with enrichment ON (fake
 *   NuGet flat container) and the OSV lookup ON (fake OSV) spawns no child
 *   process — `child_process.spawn/spawnSync/exec/execSync/execFile/
 *   execFileSync/fork` are patched in the test process around the scan.
 * - AC-P21-13 (D-138): with `REGISTRY_ENRICHMENT=off` (the test default) the
 *   enricher built from the environment makes 0 requests to the fake NuGet
 *   server, writes no `nuget` cache rows and every NuGet row is `disabled`.
 * - OSV NuGet name casing regression (AC-NV-1, D-149): main-session evidence
 *   from api.osv.dev on 2026-10-11 — `Newtonsoft.Json` 12.0.1 returns
 *   GHSA-5crp-9r3c-p9vr while `newtonsoft.json` and `NEWTONSOFT.JSON` return
 *   nothing (OSV NuGet names are case-sensitive). The querybatch body must
 *   carry the `.nuspec` `<id>` casing even when the lock / csproj spelled the
 *   id in lower case. The fake OSV answers only the exact (canonical) key.
 *
 * Real embedded PostgreSQL, fresh migrated DB per test. No request leaves
 * 127.0.0.1 (network guard; git clone is not involved for local scans).
 *
 * Scope note (AC-G-10): the patch covers the test process's main thread,
 * where the scan worker, enricher and lookup run. The parser and archive
 * `worker_threads` load their own module instances; their "no
 * child_process" guarantee is the static import ban in
 * security/staticCode.test.ts.
 */
import cp from 'node:child_process';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type DependencyEnricher, createDependencyEnricher } from '../../src/enrichment';
import type { RegistryClock } from '../../src/enrichment/registryClient';
import type { AppClock } from '../../src/lib/clock';
import { probeGitVersion } from '../../src/scanner/gitVersion';
import { enrichmentConfigFrom } from '../../src/scanner/sandbox/runner.config';
import { ScanWorker } from '../../src/scanner/worker';
import type { VulnerabilityLookup } from '../../src/vulnerability/lookup';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import { buildZip } from '../helpers/archiveBuilder';
import { useTestDatabase } from '../helpers/db';
import { makeF4Lookup } from '../helpers/f4Seed';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { addNugetPackage, nupkgEntries, nuspecXml, packagesLockJson } from '../helpers/fakeNuget';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';
import { SAMPLE_SOLUTION, parseDotnet } from '../helpers/nugetGolden';

vi.setConfig({ testTimeout: 180_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

let tmpRoot = '';
let root = '';
let reg: FakeRegistry;
let osv: FakeOsv;
let logs: string[] = [];
const enrichers: DependencyEnricher[] = [];
const clients: VulnerabilityClient[] = [];
const push = (...a: unknown[]) => void logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };
const appClock: AppClock = { now: () => Date.parse('2026-10-11T08:00:00.000Z'), sleep: async () => undefined };

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-nuget-gates-'));
  root = path.join(tmpRoot, 'repo');
  logs = [];
  reg = await startFakeRegistry();
  osv = await startFakeOsv();
});
afterEach(async () => {
  for (const e of enrichers.splice(0)) e.close();
  for (const c of clients.splice(0)) c.close();
  await reg.close();
  await osv.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function enricher(enabled = true): DependencyEnricher {
  const e = createDependencyEnricher({
    config: { enabled, timeoutMs: 5_000, concurrency: 4 },
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
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`nuget-gates-${Math.random().toString(36).slice(2)}`, root]);
  await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, 'dotnet')`, [p.id]);
  return p.id;
}

async function scan(projectId: string, e: DependencyEnricher | null, lookup: VulnerabilityLookup | null): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId],
  );
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runId: 'run-nuget-gates', enricher: e, vulnerabilityLookup: lookup });
  expect(await w.runOnce()).toBe(s.id);
  const [row] = await db.query<{ status: string }>(`SELECT status::text FROM scans WHERE id = $1`, [s.id]);
  expect(row.status, logs.join('\n')).toBe('completed');
  return s.id;
}

interface DepRow {
  name: string;
  version: string | null;
  license_enrichment_status: string | null;
  license_source: string | null;
  license_expression: string | null;
  lock_integrity: string | null;
  notice_status: string | null;
}

async function dotnetRows(scanId: string): Promise<DepRow[]> {
  return db.query<DepRow>(
    `SELECT p.name, p.version, sd.license_enrichment_status, sd.license_source, sd.license_expression, sd.lock_integrity, sd.notice_status
       FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id
      WHERE sd.scan_id = $1 AND p.ecosystem = 'dotnet' ORDER BY p.name, sd.manifest_path`,
    [scanId],
  );
}

/** Routes a nuspec (MIT) and a .nupkg for every versioned package of the sample solution. */
function routeSampleSolution(): number {
  const seen = new Set<string>();
  for (const d of parseDotnet(root, 'x').dependencies) {
    if (d.version === null || seen.has(`${d.name.toLowerCase()}@${d.version}`)) continue;
    seen.add(`${d.name.toLowerCase()}@${d.version}`);
    addNugetPackage(reg, d.name, d.version, { nuspec: nuspecXml({ id: d.name, version: d.version, expression: 'MIT' }), nupkg: buildZip(nupkgEntries(d.name)) });
  }
  return seen.size;
}

// ---------------------------------------------------------------------------
// AC-G-10: no child process during a full NuGet scan
// ---------------------------------------------------------------------------
const SPAWNERS = ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'] as const;

/**
 * Replaces the child_process spawners with recorders that throw (nothing is
 * ever started) and re-syncs the builtin ESM named exports, so both
 * `import { spawn } from 'child_process'` and `cp.spawn` see the recorder.
 */
function patchChildProcess(): { calls: string[]; restore: () => void } {
  const mod = cp as unknown as Record<string, unknown>;
  const originals = new Map<string, unknown>(SPAWNERS.map((k) => [k, mod[k]]));
  const calls: string[] = [];
  for (const k of SPAWNERS) {
    mod[k] = (...args: unknown[]) => {
      calls.push(`${k} ${String(args[0])}`);
      throw new Error(`child_process.${k} blocked by AC-G-10 test`);
    };
  }
  syncBuiltinESMExports();
  return {
    calls,
    restore: () => {
      for (const [k, v] of originals) mod[k] = v;
      syncBuiltinESMExports();
    },
  };
}

describe('AC-G-10 (D-142): no child process is started during a .NET scan', () => {
  it('AC-G-10: local-folder scan of the sample solution with NuGet enrichment and OSV lookup on -> 0 spawn/exec/execFile/fork calls', async () => {
    fs.cpSync(SAMPLE_SOLUTION, root, { recursive: true });
    const routed = routeSampleSolution();
    expect(routed).toBeGreaterThan(5);
    const projectId = await insertProject();
    const e = enricher();
    const lookup = makeF4Lookup(db, osv.origin, appClock, logs, clients);

    const patch = patchChildProcess();
    try {
      // Positive control: a src module that does spawn sees the recorder (and starts nothing).
      expect((await probeGitVersion({ timeoutMs: 1_000 })).found).toBe(false);
      expect(patch.calls).toEqual(['spawn git']);
      patch.calls.length = 0;

      const scanId = await scan(projectId, e, lookup);
      expect(patch.calls).toEqual([]);

      // The scan really exercised the network paths that could have shelled out.
      const rows = await dotnetRows(scanId);
      expect(rows.length).toBe(18);
      expect(rows.some((r) => r.license_source === 'registry:nuget')).toBe(true);
      expect(reg.requests.some((r) => r.path.endsWith('.nuspec'))).toBe(true);
      expect(reg.requests.some((r) => r.path.endsWith('.nupkg'))).toBe(true);
      expect(osv.batches().flat().some((q) => q.package.ecosystem === 'NuGet')).toBe(true);
    } finally {
      patch.restore();
    }
    expect(cp.spawn).not.toBe(undefined);
  });
});

// ---------------------------------------------------------------------------
// AC-P21-13: REGISTRY_ENRICHMENT=off
// ---------------------------------------------------------------------------
describe('AC-P21-13 (D-138): REGISTRY_ENRICHMENT=off -> no NuGet request, no nuget cache rows, NuGet keys disabled', () => {
  it('AC-P21-13: the enricher built from the environment is off; 0 requests to the fake NuGet server; rows disabled / none; [registry] disabled line', async () => {
    fs.cpSync(SAMPLE_SOLUTION, root, { recursive: true });
    routeSampleSolution();
    expect(process.env.REGISTRY_ENRICHMENT).toBe('off');
    const config = enrichmentConfigFrom(process.env);
    expect(config.enabled).toBe(false);
    const e = createDependencyEnricher({ config, db: db.pool, logger, endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin, nuget: reg.origin }, clock: fastClock, env: {} });
    enrichers.push(e);

    const scanId = await scan(await insertProject(), e, null);
    expect(reg.total()).toBe(0);
    expect(await db.query(`SELECT 1 FROM registry_package_cache WHERE ecosystem = 'nuget'`)).toEqual([]);
    expect(await db.query(`SELECT 1 FROM registry_archive_cache WHERE ecosystem = 'nuget'`)).toEqual([]);

    const rows = await dotnetRows(scanId);
    expect(rows.length).toBe(18);
    for (const r of rows) {
      // AC-P21-12 / AC-P21-13: disabled, no effective license (no NuGet lock hint); D-156: lock_integrity NULL when off.
      expect([r.license_enrichment_status, r.license_source, r.license_expression, r.lock_integrity], `${r.name}@${r.version}`).toEqual(['disabled', 'none', null, null]);
    }
    const [s] = await db.query<{ error_message: string | null }>(`SELECT error_message FROM scans WHERE id = $1`, [scanId]);
    const line = (s.error_message ?? '').split('\n').find((l) => l.startsWith('[registry]')) ?? '';
    expect(line).toMatch(/^\[registry\] License enrichment disabled: /);
    // Counted per (lower-case id, version) key, not per manifest row (18 rows -> 16 keys); no lock hint for NuGet.
    const keys = new Set(rows.map((r) => `${r.name.toLowerCase()}@${r.version ?? ''}`)).size;
    expect(keys).toBe(16);
    expect(line).toBe(`[registry] License enrichment disabled: 0 package(s) use the lockfile license (unverified), ${keys} have no license.`);
  });
});

// ---------------------------------------------------------------------------
// OSV NuGet name casing (real finding, 2026-10-11)
// ---------------------------------------------------------------------------
const GHSA = 'GHSA-5crp-9r3c-p9vr';

function newtonsoftLowerCase(): void {
  // Lock spells the id lower case; a second project references it lower case in a csproj.
  const app = path.join(root, 'src', 'App');
  const other = path.join(root, 'src', 'Other');
  fs.mkdirSync(app, { recursive: true });
  fs.mkdirSync(other, { recursive: true });
  fs.writeFileSync(path.join(app, 'packages.lock.json'), packagesLockJson([{ id: 'newtonsoft.json', version: '12.0.1', hash: null }]));
  fs.writeFileSync(
    path.join(other, 'Other.csproj'),
    '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n    <PackageReference Include="newtonsoft.json" Version="12.0.1" />\n  </ItemGroup>\n</Project>\n',
  );
  // nuget.org's .nuspec carries the canonical casing.
  addNugetPackage(reg, 'Newtonsoft.Json', '12.0.1', { nuspec: nuspecXml({ id: 'Newtonsoft.Json', version: '12.0.1', expression: 'MIT' }) });
  // Fake OSV answers only the exact canonical key, like api.osv.dev did.
  osv.vulns.set(osvKey('NuGet', 'Newtonsoft.Json', '12.0.1'), [{ id: GHSA, modified: '2026-01-01T00:00:00Z' }]);
  osv.addRecord(GHSA, { affected: [{ package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '13.0.1' }] }] }] });
}

describe('AC-NV-1 / D-149 regression: OSV NuGet names are case-sensitive (api.osv.dev, 2026-10-11)', () => {
  it('AC-NV-1: lock/csproj spell "newtonsoft.json" -> querybatch sends the .nuspec <id> "Newtonsoft.Json" once and the GHSA is found', async () => {
    newtonsoftLowerCase();
    const scanId = await scan(await insertProject(), enricher(), makeF4Lookup(db, osv.origin, appClock, logs, clients));

    const names = osv.batches().flat().filter((q) => q.package.ecosystem === 'NuGet').map((q) => `${q.package.name}@${q.version}`);
    expect(names).toEqual(['Newtonsoft.Json@12.0.1']);
    const [s] = await db.query<{ total: number }>(`SELECT total_vulnerabilities AS total FROM scans WHERE id = $1`, [scanId]);
    expect(Number(s.total)).toBe(1);
    const cache = await db.query<{ canonical_name: string | null }>(`SELECT canonical_name FROM registry_package_cache WHERE ecosystem = 'nuget' AND name = 'newtonsoft.json'`);
    expect(cache.map((c) => c.canonical_name)).toEqual(['Newtonsoft.Json']);
  });

  it('D-149 control: without a .nuspec <id> (enrichment off, empty cache) the first-seen casing is sent and the case-sensitive OSV finds nothing', async () => {
    newtonsoftLowerCase();
    const scanId = await scan(await insertProject(), enricher(false), makeF4Lookup(db, osv.origin, appClock, logs, clients));
    expect(reg.total()).toBe(0);
    const names = osv.batches().flat().filter((q) => q.package.ecosystem === 'NuGet').map((q) => `${q.package.name}@${q.version}`);
    expect(names).toEqual(['newtonsoft.json@12.0.1']);
    const [s] = await db.query<{ total: number }>(`SELECT total_vulnerabilities AS total FROM scans WHERE id = $1`, [scanId]);
    expect(Number(s.total)).toBe(0);
  });
});
