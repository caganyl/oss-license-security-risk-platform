/**
 * REQ-002 worker behaviour: P-03, P-05, P-06, P-07, P-08, P-09 (worker side).
 *
 * Expected API (src/scanner/worker.ts, see tests/README.md):
 *   new ScanWorker(deps?: Partial<{ db, cloneRepo, runParser, scanRoots, tmpRoot, logger }>)
 *   worker.runOnce(): Promise<string | null>   claims + fully processes one scan
 *   worker.saveScanResults(scanId, projectId, result): Promise<void>
 * Network: global fetch is stubbed (OSV lookups answer "no vulns"); clone is
 * always a fake; the real Python parser runs only on local fixtures.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { useTestDatabase } from '../helpers/db';
import { MissingImplementationError, loadSrc } from '../helpers/loadSrc';
import { FIXTURES_DIR, REPO_ROOT } from '../helpers/paths';
import type {
  CloneRepoFn,
  RunParserFn,
  ScanControllerModule,
  ScanResultFixture,
  ScanWorkerDeps,
  ScanWorkerInstance,
  ScannedDependencyFixture,
  WorkerModule,
} from '../helpers/contracts';
import { TEST_KEY_A, TEST_KEY_B, TEST_SHORT_TOKEN, TEST_TOKEN, encryptToken, leakForms } from '../helpers/tokenCrypto';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file', setDatabaseUrlEnv: true });
const sha256 = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
let tmpRoot = '';
let logs: string[] = [];
const savedEnv: Record<string, string | undefined> = {};
const logger = {
  log: (...a: unknown[]) => logs.push(a.map(String).join(' ')),
  warn: (...a: unknown[]) => logs.push(a.map(String).join(' ')),
  error: (...a: unknown[]) => logs.push(a.map((x) => (x instanceof Error ? `${x.message} ${x.stack}` : String(x))).join(' ')),
};

beforeAll(() => {
  for (const k of ['ENCRYPTION_KEY', 'PYTHONDONTWRITEBYTECODE', 'SCAN_ROOTS']) savedEnv[k] = process.env[k];
  process.env.PYTHONDONTWRITEBYTECODE = '1'; // no __pycache__ under src/
});
afterAll(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-test-worker-'));
  logs = [];
  for (const m of ['log', 'info', 'warn', 'error'] as const) {
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
      logs.push(a.map((x) => (x instanceof Error ? `${x.message} ${x.stack}` : String(x))).join(' '));
    });
  }
  // No real OSV/NVD traffic: every vulnerability lookup answers "no vulnerabilities".
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulns: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })));
  // only the scan created by the current test may be claimed
  await db.query(`UPDATE scans SET status = 'cancelled' WHERE status IN ('pending','queued','running')`);
  await db.query(`UPDATE system_settings SET value = '3' WHERE key = 'scan.max_retries'`);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

const leftovers = () => fs.readdirSync(tmpRoot).filter((n) => n.startsWith('ossrisk-scan-'));

async function newWorker(deps: Partial<ScanWorkerDeps> = {}): Promise<ScanWorkerInstance> {
  const { ScanWorker } = await loadSrc<WorkerModule>('src/scanner/worker.ts', ['ScanWorker']);
  return new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [], ...deps });
}

async function runOnce(worker: ScanWorkerInstance): Promise<string | null> {
  if (typeof worker.runOnce !== 'function') throw new MissingImplementationError('ScanWorker#runOnce() does not exist');
  return worker.runOnce();
}

async function save(worker: ScanWorkerInstance, scanId: string, projectId: string, deps: ScannedDependencyFixture[]): Promise<void> {
  if (typeof worker.saveScanResults !== 'function') throw new MissingImplementationError('ScanWorker#saveScanResults() is not callable');
  await worker.saveScanResults(scanId, projectId, result(scanId, deps));
}

function result(scanId: string, deps: ScannedDependencyFixture[]): ScanResultFixture {
  return { scan_id: scanId, status: 'completed', total_deps: deps.length, dependencies: deps, scan_files: [], parse_errors: [] };
}

function npm(name: string, version: string | null, extra: Partial<ScannedDependencyFixture> = {}): ScannedDependencyFixture {
  return {
    ecosystem: 'nodejs',
    name,
    version,
    purl: version ? `pkg:npm/${name}@${version}` : `pkg:npm/${name}`,
    scope: 'direct',
    manifest_file: 'package.json',
    manifest_path: '.',
    ...extra,
  };
}

async function insertProject(repoUrl: string | null, ecosystems: string[] = ['nodejs']): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`p-${crypto.randomUUID()}`, repoUrl]);
  for (const e of ecosystems) await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, $2::tech_ecosystem)`, [p.id, e]);
  return p.id;
}

async function insertScan(projectId: string, status = 'pending', integrationId: string | null = null): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, integration_id, trigger, status, ref, queued_at) VALUES ($1, $2, 'manual', $3::scan_status, 'main', now()) RETURNING id`,
    [projectId, integrationId, status],
  );
  return s.id;
}

async function scanRow(scanId: string): Promise<{ status: string; error_message: string | null; retry_count: number }> {
  const [row] = await db.query<{ status: string; error_message: string | null; retry_count: number }>(
    'SELECT status::text, error_message, retry_count FROM scans WHERE id = $1',
    [scanId],
  );
  return row;
}

async function depCount(scanId: string): Promise<number> {
  return (await db.query('SELECT id FROM scan_dependencies WHERE scan_id = $1', [scanId])).length;
}

function fakeClone(onClone?: (dest: string) => void): { fn: CloneRepoFn; calls: Array<{ url: string; ref: string | null; dest: string; token: string | null }> } {
  const calls: Array<{ url: string; ref: string | null; dest: string; token: string | null }> = [];
  const fn: CloneRepoFn = async (url, ref, dest, token) => {
    calls.push({ url, ref, dest, token });
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, 'package.json'), JSON.stringify({ name: 'cloned', dependencies: { 'left-pad': '1.3.0' } }));
    onClone?.(dest);
  };
  return { fn, calls };
}

function fakeParser(deps: ScannedDependencyFixture[] = []): { fn: RunParserFn; calls: string[] } {
  const calls: string[] = [];
  const fn: RunParserFn = async (workDir, _eco, scanId) => {
    calls.push(workDir);
    return result(scanId, deps);
  };
  return { fn, calls };
}

// ---------------------------------------------------------------------------
describe('P-03 remote sources: temp workspace, no platform-folder fallback (AC-P03-2…6)', () => {
  it('AC-P03-3 / AC-P03-4: https repo is shallow-cloned into ossrisk-scan-* under tmpRoot, parsed there, then removed', async () => {
    const projectId = await insertProject('https://github.com/org/repo.git');
    const scanId = await insertScan(projectId);
    const clone = fakeClone();
    const parser = fakeParser([npm('left-pad', '1.3.0', { licenses: ['MIT'] })]);
    const worker = await newWorker({ cloneRepo: clone.fn, runParser: parser.fn });
    expect(await runOnce(worker)).toBe(scanId);

    expect(clone.calls).toHaveLength(1);
    expect(clone.calls[0]).toMatchObject({ url: 'https://github.com/org/repo.git', ref: 'main', token: null });
    const workspace = path.dirname(clone.calls[0].dest);
    expect(path.dirname(workspace)).toBe(tmpRoot);
    expect(path.basename(workspace)).toMatch(/^ossrisk-scan-/);
    expect(parser.calls).toHaveLength(1);
    expect(path.resolve(parser.calls[0]).startsWith(path.resolve(workspace))).toBe(true);
    expect(path.resolve(parser.calls[0])).not.toBe(path.resolve(REPO_ROOT));
    expect((await scanRow(scanId)).status).toBe('completed');
    expect(fs.existsSync(workspace)).toBe(false);
    expect(leftovers()).toEqual([]);
  });

  it('AC-P03-5 / AC-P03-6: clone failure -> failed with a message, workspace removed, platform folder never scanned', async () => {
    await db.query(`UPDATE system_settings SET value = '1' WHERE key = 'scan.max_retries'`);
    const projectId = await insertProject('https://github.com/org/unreachable.git', ['nodejs', 'python']);
    const scanId = await insertScan(projectId);
    const failingClone: CloneRepoFn = async (_u, _r, dest) => {
      fs.mkdirSync(dest, { recursive: true });
      throw new Error('fatal: unable to access repository (simulated)');
    };
    // default runParser (real Python): if the worker fell back to '.', it would
    // parse the platform's own package.json and write express/pg/... here.
    const worker = await newWorker({ cloneRepo: failingClone });
    expect(await runOnce(worker)).toBe(scanId);
    const row = await scanRow(scanId);
    expect(row.status).toBe('failed');
    expect(row.error_message ?? '').not.toBe('');
    expect(await depCount(scanId)).toBe(0);
    expect(await db.query(`SELECT 1 FROM packages WHERE name IN ('express','pg','vitest','dotenv')`)).toEqual([]);
    expect(leftovers()).toEqual([]);
  });

  it('AC-P03-4: parser failure after a successful clone -> failed, workspace removed', async () => {
    await db.query(`UPDATE system_settings SET value = '1' WHERE key = 'scan.max_retries'`);
    const scanId = await insertScan(await insertProject('https://github.com/org/repo.git'));
    const parser: RunParserFn = async () => {
      throw new Error('parser crashed (simulated)');
    };
    const worker = await newWorker({ cloneRepo: fakeClone().fn, runParser: parser });
    await runOnce(worker);
    expect((await scanRow(scanId)).status).toBe('failed');
    expect(leftovers()).toEqual([]);
  });

  it('AC-P03-2: project without repo_url -> failed; nothing cloned or parsed (no "." fallback)', async () => {
    const scanId = await insertScan(await insertProject(null));
    const clone = fakeClone();
    const parser = fakeParser();
    const worker = await newWorker({ cloneRepo: clone.fn, runParser: parser.fn });
    await runOnce(worker);
    expect((await scanRow(scanId)).status).toBe('failed');
    expect(clone.calls).toEqual([]);
    expect(parser.calls).toEqual([]);
  });

  it('AC-P03-7: non-https remote stored in the DB (http://) -> failed, clone never attempted', async () => {
    const scanId = await insertScan(await insertProject('http://github.com/org/repo.git'));
    const clone = fakeClone();
    const parser = fakeParser();
    await runOnce(await newWorker({ cloneRepo: clone.fn, runParser: parser.fn }));
    expect((await scanRow(scanId)).status).toBe('failed');
    expect(clone.calls).toEqual([]);
    expect(parser.calls).toEqual([]);
  });
});

describe('P-04 worker re-check of local paths (TOCTOU, ADR-002 karar 4)', () => {
  it('AC-P04-3: local path outside SCAN_ROOTS stored in the DB -> failed, parser not called', async () => {
    const outside = fs.mkdtempSync(path.join(tmpRoot, 'outside-'));
    const root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
    const scanId = await insertScan(await insertProject(outside));
    const parser = fakeParser();
    await runOnce(await newWorker({ runParser: parser.fn, cloneRepo: fakeClone().fn, scanRoots: [root] }));
    expect((await scanRow(scanId)).status).toBe('failed');
    expect(parser.calls).toEqual([]);
  });

  it('AC-P04-2: local path under SCAN_ROOTS -> parsed in place with the canonical path, no clone', async () => {
    const root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
    const proj = path.join(root, 'proj');
    fs.mkdirSync(proj);
    const scanId = await insertScan(await insertProject(proj));
    const clone = fakeClone();
    const parser = fakeParser();
    await runOnce(await newWorker({ runParser: parser.fn, cloneRepo: clone.fn, scanRoots: [root] }));
    expect((await scanRow(scanId)).status).toBe('completed');
    expect(clone.calls).toEqual([]);
    expect(parser.calls).toEqual([fs.realpathSync.native(proj)]);
  });
});

// ---------------------------------------------------------------------------
describe('P-05 declared ranges (AC-P05-1…4)', () => {
  it('AC-P05-1…4: real parser on two lock-less manifests with different lodash ranges -> completed, one versionless package row, ranges per manifest', async () => {
    const fixture = fs.realpathSync.native(path.join(FIXTURES_DIR, 'p05-ranges-no-lockfile'));
    const scanId = await insertScan(await insertProject(fixture, ['nodejs', 'python']));
    const worker = await newWorker({ scanRoots: [fs.realpathSync.native(FIXTURES_DIR)] });
    await runOnce(worker);
    const row = await scanRow(scanId);
    expect(row.status, row.error_message ?? '').toBe('completed');

    const pkgs = await db.query<{ version: string | null; purl: string }>(`SELECT version, purl FROM packages WHERE ecosystem = 'nodejs' AND name = 'lodash'`);
    expect(pkgs).toEqual([{ version: null, purl: 'pkg:npm/lodash' }]);
    const deps = await db.query<{ declared_range: string; manifest_path: string }>(
      `SELECT sd.declared_range, sd.manifest_path FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id
       WHERE sd.scan_id = $1 AND p.name = 'lodash' ORDER BY sd.manifest_path`,
      [scanId],
    );
    expect(deps).toEqual([
      { declared_range: '^4.17.0', manifest_path: 'a' },
      { declared_range: '~4.16.0', manifest_path: 'b' },
    ]);
    const [req] = await db.query<{ version: string | null; declared_range: string | null }>(
      `SELECT p.version, sd.declared_range FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id
       WHERE sd.scan_id = $1 AND p.name = 'requests'`,
      [scanId],
    );
    expect(req).toEqual({ version: null, declared_range: '>=2,<3' });
    const ranged = await db.query(`SELECT version FROM packages WHERE version ~ '[\\^~<>=*, ]|^unknown$'`);
    expect(ranged).toEqual([]);
  });

  it('AC-P05-1 / AC-P05-2: saveScanResults with two ranges for the same package (parser contract) -> completed, version NULL', async () => {
    const projectId = await insertProject(null);
    const scanId = await insertScan(projectId, 'running');
    const worker = await newWorker();
    await save(worker, scanId, projectId, [
      npm('range-lib', null, { declared_range: '^1.2.0', manifest_path: 'a' }),
      npm('range-lib', null, { declared_range: '^2.0.0', manifest_path: 'b' }),
    ]);
    expect((await scanRow(scanId)).status).toBe('completed');
    expect(await db.query(`SELECT version, purl FROM packages WHERE name = 'range-lib'`)).toEqual([{ version: null, purl: 'pkg:npm/range-lib' }]);
    const ranges = await db.query<{ declared_range: string }>(
      `SELECT declared_range FROM scan_dependencies WHERE scan_id = $1 ORDER BY declared_range`,
      [scanId],
    );
    expect(ranges.map((r) => r.declared_range)).toEqual(['^1.2.0', '^2.0.0']);
  });
});

// ---------------------------------------------------------------------------
async function licenseFindings(scanId: string) {
  return db.query<{ name: string; risk_level: string; normalized_license: string | null; license_id: string | null }>(
    `SELECT p.name, lf.risk_level::text, lf.normalized_license, lf.license_id
     FROM findings f JOIN license_findings lf ON lf.finding_id = f.id
     JOIN scan_dependencies sd ON sd.id = f.scan_dependency_id JOIN packages p ON p.id = sd.package_id
     WHERE f.scan_id = $1 AND f.finding_type = 'license' ORDER BY p.name`,
    [scanId],
  );
}

describe('P-06 unknown license finding (AC-P06-1…4)', () => {
  it('AC-P06-1 / AC-P06-4: runtime npm and Python packages without license -> unknown finding (NOASSERTION, no license_id)', async () => {
    const projectId = await insertProject(null, ['nodejs', 'python']);
    const scanId = await insertScan(projectId, 'running');
    await save(await newWorker(), scanId, projectId, [
      npm('nolicense-lib', '1.0.0'),
      { ecosystem: 'python', name: 'requests', version: '2.31.0', purl: 'pkg:pypi/requests@2.31.0', scope: 'direct', manifest_file: 'requirements.txt', manifest_path: '.' },
      npm('dev-nolicense', '1.0.0', { scope: 'dev' }),
    ]);
    expect(await licenseFindings(scanId)).toEqual([
      { name: 'nolicense-lib', risk_level: 'unknown', normalized_license: 'NOASSERTION', license_id: null },
      { name: 'requests', risk_level: 'unknown', normalized_license: 'NOASSERTION', license_id: null },
    ]);
  });

  it('AC-P06-3: dev package without license -> in inventory, no finding', async () => {
    const projectId = await insertProject(null);
    const scanId = await insertScan(projectId, 'running');
    await save(await newWorker(), scanId, projectId, [npm('dev-nolicense', '1.0.0', { scope: 'dev' }), npm('mit-lib', '1.0.0', { licenses: ['MIT'] })]);
    expect(await licenseFindings(scanId)).toEqual([]);
    const inv = await db.query(`SELECT sd.scope::text FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1 AND p.name = 'dev-nolicense'`, [scanId]);
    expect(inv).toEqual([{ scope: 'dev' }]);
  });

  it('AC-P06-2: the unknown finding is returned by the scan findings API (GET /api/scans/:id/findings)', async () => {
    const projectId = await insertProject(null);
    const scanId = await insertScan(projectId, 'running');
    await save(await newWorker(), scanId, projectId, [npm('nolicense-lib', '1.0.0')]);
    const { ScanController } = await loadSrc<ScanControllerModule>('src/controllers/scanController.ts', ['ScanController']);
    let body: { data: Array<{ risk_level: string; package_name: string }> } | undefined;
    const res = { json: (b: typeof body) => { body = b; }, status: () => res };
    await new ScanController(db.pool).getScanFindings({ params: { id: scanId }, query: {} }, res, (err) => { throw err; });
    expect(body?.data).toEqual(expect.arrayContaining([expect.objectContaining({ package_name: 'nolicense-lib', risk_level: 'unknown' })]));
  });
});

describe('P-07 dev/test scope is not a license violation (AC-P07-1…4)', () => {
  it('AC-P07-1 / AC-P07-2 / AC-P07-4: GPL devDependency is in the inventory but not in the violation list', async () => {
    const projectId = await insertProject(null);
    const scanId = await insertScan(projectId, 'running');
    await save(await newWorker(), scanId, projectId, [npm('gpl-dev-tool', '1.0.0', { scope: 'dev', licenses: ['GPL-3.0-only'] })]);
    const inv = await db.query(`SELECT sd.scope::text FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1 AND p.name = 'gpl-dev-tool'`, [scanId]);
    expect(inv).toEqual([{ scope: 'dev' }]);
    expect(await licenseFindings(scanId)).toEqual([]);
    const [scan] = await db.query<{ license_violations: number }>('SELECT license_violations FROM scans WHERE id = $1', [scanId]);
    expect(scan.license_violations).toBe(0);
  });

  it('AC-P07-3 (regression): the same GPL package as runtime / peer / optional dependency is a violation', async () => {
    const projectId = await insertProject(null);
    const scanId = await insertScan(projectId, 'running');
    await save(await newWorker(), scanId, projectId, [
      npm('gpl-runtime-lib', '1.0.0', { licenses: ['GPL-3.0-only'] }),
      npm('gpl-peer-lib', '1.0.0', { scope: 'peer', licenses: ['GPL-3.0-only'] }),
      npm('gpl-optional-lib', '1.0.0', { scope: 'optional', licenses: ['GPL-3.0-only'] }),
      npm('gpl-dev-tool', '1.0.0', { scope: 'dev', licenses: ['GPL-3.0-only'] }),
    ]);
    expect((await licenseFindings(scanId)).map((f) => f.name)).toEqual(['gpl-optional-lib', 'gpl-peer-lib', 'gpl-runtime-lib']);
    const [scan] = await db.query<{ license_violations: number }>('SELECT license_violations FROM scans WHERE id = $1', [scanId]);
    expect(scan.license_violations).toBe(3);
  });
});

// ---------------------------------------------------------------------------
describe('P-08 fingerprint and decision carry-over (AC-P08-1…11)', () => {
  const CVE = 'CVE-2099-0001';
  let reviewerId = '';

  beforeAll(async () => {
    const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name, status) VALUES ('reviewer@example.invalid', 'Reviewer', 'active') RETURNING id`);
    reviewerId = u.id;
  });

  type Pair = { license: { id: string; status: string; fingerprint: string; carried: string | null }; security: { id: string; status: string; fingerprint: string; carried: string | null } };

  async function scanWith(projectId: string, version: string, manifests: string[] = ['.']): Promise<Pair> {
    const scanId = await insertScan(projectId, 'running');
    const deps = manifests.map((m) =>
      npm('carry-lib', version, { manifest_path: m, licenses: ['GPL-3.0-only'], vulnerabilities: [{ id: CVE, fix_versions: ['9.9.9'] }] }),
    );
    await save(await newWorker(), scanId, projectId, deps);
    const rows = await db.query<{ id: string; finding_type: string; status: string; fingerprint: string; carried: string | null }>(
      `SELECT id, finding_type::text, status::text, fingerprint, carried_from_finding_id AS carried FROM findings WHERE scan_id = $1`,
      [scanId],
    );
    const pick = (t: string) => {
      const found = rows.filter((r) => r.finding_type === t);
      expect(found, `${t} findings in scan`).toHaveLength(1);
      return found[0];
    };
    return { license: pick('license'), security: pick('security') };
  }

  async function decide(findingId: string, status: string, decision: string | null, acceptedUntilSql = 'NULL'): Promise<void> {
    await db.query(`UPDATE findings SET status = $2::finding_status WHERE id = $1`, [findingId, status]);
    if (decision) {
      await db.query(
        `INSERT INTO finding_reviews (finding_id, decision, reviewer_id, accepted_until, notes)
         VALUES ($1, $2::review_decision, $3, ${acceptedUntilSql}, 'test decision')`,
        [findingId, decision, reviewerId],
      );
    }
  }

  async function reviews(findingId: string) {
    return db.query<{ decision: string; accepted_until: string | null }>(
      `SELECT decision::text, to_char(accepted_until, 'YYYY-MM-DD') AS accepted_until FROM finding_reviews WHERE finding_id = $1`,
      [findingId],
    );
  }

  it('AC-P08-1: stored fingerprints follow ADR-003 (license versionless, CVE versioned)', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    expect(first.license.fingerprint).toBe(sha256(`v1|${projectId}|pkg:npm/carry-lib|license|gpl-3.0-only`));
    expect(first.security.fingerprint).toBe(sha256(`v1|${projectId}|pkg:npm/carry-lib@1.0.0|security|${CVE}`));
  });

  it('AC-P08-2: same input twice -> same fingerprints; same package in two manifests -> one finding per fingerprint', async () => {
    const projectId = await insertProject(null);
    const a = await scanWith(projectId, '1.0.0', ['a', 'b']);
    const b = await scanWith(projectId, '1.0.0', ['a', 'b']);
    expect(b.license.fingerprint).toBe(a.license.fingerprint);
    expect(b.security.fingerprint).toBe(a.security.fingerprint);
  });

  it('AC-P08-3 / AC-P08-6: false_positive comes back closed on the next scan, review carried', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.license.id, 'false_positive', 'false_positive');
    await decide(first.security.id, 'false_positive', 'false_positive');
    const second = await scanWith(projectId, '1.0.0');
    expect(second.license).toMatchObject({ status: 'false_positive', carried: first.license.id });
    expect(second.security).toMatchObject({ status: 'false_positive', carried: first.security.id });
    expect(await reviews(second.license.id)).toEqual([{ decision: 'false_positive', accepted_until: null }]);
  });

  it('AC-P08-4: unexpired risk acceptance is carried with the same accepted_until', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.security.id, 'accepted', 'accept_risk', `CURRENT_DATE + 30`);
    const second = await scanWith(projectId, '1.0.0');
    expect(second.security).toMatchObject({ status: 'accepted', carried: first.security.id });
    const [orig] = await reviews(first.security.id);
    expect(await reviews(second.security.id)).toEqual([{ decision: 'accept_risk', accepted_until: orig.accepted_until }]);
  });

  it('AC-P08-4: acceptance valid until today (accepted_until = CURRENT_DATE) is still carried', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.license.id, 'accepted', 'accept_risk', 'CURRENT_DATE');
    expect((await scanWith(projectId, '1.0.0')).license.status).toBe('accepted');
  });

  it('AC-P08-7 / AC-P08-11: license false_positive and unexpired acceptance survive a version bump (1.0.0 -> 1.1.0)', async () => {
    const p1 = await insertProject(null);
    const a1 = await scanWith(p1, '1.0.0');
    await decide(a1.license.id, 'false_positive', 'false_positive');
    const b1 = await scanWith(p1, '1.1.0');
    expect(b1.license.fingerprint).toBe(a1.license.fingerprint);
    expect(b1.license).toMatchObject({ status: 'false_positive', carried: a1.license.id });

    const p2 = await insertProject(null);
    const a2 = await scanWith(p2, '1.0.0');
    await decide(a2.license.id, 'accepted', 'accept_risk', 'CURRENT_DATE + 10');
    expect((await scanWith(p2, '1.1.0')).license.status).toBe('accepted');
  });

  it('AC-P08-8 / AC-P08-11: CVE decision is NOT carried to a new version -> open, different fingerprint', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.security.id, 'false_positive', 'false_positive');
    const second = await scanWith(projectId, '1.1.0');
    expect(second.security.fingerprint).not.toBe(first.security.fingerprint);
    expect(second.security).toMatchObject({ status: 'open', carried: null });

    const p2 = await insertProject(null);
    const a2 = await scanWith(p2, '1.0.0');
    await decide(a2.security.id, 'accepted', 'accept_risk', 'CURRENT_DATE + 30');
    expect((await scanWith(p2, '1.1.0')).security.status).toBe('open');
  });

  it('AC-P08-9 / AC-P08-11: expired risk acceptance is not carried -> open', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.license.id, 'accepted', 'accept_risk', 'CURRENT_DATE - 1');
    await decide(first.security.id, 'accepted', 'accept_risk', 'CURRENT_DATE - 1');
    const second = await scanWith(projectId, '1.0.0');
    expect(second.license).toMatchObject({ status: 'open', carried: null });
    expect(second.security).toMatchObject({ status: 'open', carried: null });
    expect(await reviews(second.license.id)).toEqual([]);
  });

  it('AC-P08-10 / AC-P08-11: wont_fix is not carried -> open', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.license.id, 'wont_fix', 'wont_fix');
    const second = await scanWith(projectId, '1.0.0');
    expect(second.license).toMatchObject({ status: 'open', carried: null });
  });

  it('ADR-003: a reopened finding (latest is open) is not closed again by an older decision', async () => {
    const projectId = await insertProject(null);
    const first = await scanWith(projectId, '1.0.0');
    await decide(first.license.id, 'false_positive', 'false_positive');
    const second = await scanWith(projectId, '1.0.0');
    await decide(second.license.id, 'open', null); // reopen
    expect((await scanWith(projectId, '1.0.0')).license.status).toBe('open');
  });

  it('AC-P08-1: decisions never leak across projects (project id is part of the fingerprint)', async () => {
    const pA = await insertProject(null);
    const pB = await insertProject(null);
    const a = await scanWith(pA, '1.0.0');
    await decide(a.license.id, 'false_positive', 'false_positive');
    const b = await scanWith(pB, '1.0.0');
    expect(b.license.fingerprint).not.toBe(a.license.fingerprint);
    expect(b.license.status).toBe('open');
  });
});

// ---------------------------------------------------------------------------
describe('P-09 integration token handling in the worker (AC-P09-5, D-14)', () => {
  async function scanWithToken(token: Buffer | null): Promise<string> {
    const projectId = await insertProject('https://github.com/org/private.git');
    const [i] = await db.query<{ id: string }>(
      `INSERT INTO integrations (project_id, provider, name, repo_url, access_token_enc) VALUES ($1, 'github', 'gh', 'https://github.com/org/private.git', $2) RETURNING id`,
      [projectId, token],
    );
    return insertScan(projectId, 'pending', i.id);
  }

  async function expectFailedWithoutLeak(token: Buffer, plain: string): Promise<void> {
    const scanId = await scanWithToken(token);
    const clone = fakeClone();
    await runOnce(await newWorker({ cloneRepo: clone.fn, runParser: fakeParser().fn }));
    const row = await scanRow(scanId);
    expect(row.status, 'token errors are deterministic: failed without retry').toBe('failed');
    expect(clone.calls).toEqual([]);
    expect(leftovers()).toEqual([]);
    const haystack = `${row.error_message ?? ''}\n${logs.join('\n')}`;
    for (const form of leakForms(token, plain)) expect(haystack).not.toContain(form);
  }

  it('AC-P09-5 (a): ENCRYPTION_KEY undefined -> scan failed, no clone, token not in error/log', async () => {
    delete process.env.ENCRYPTION_KEY;
    await expectFailedWithoutLeak(encryptToken(TEST_TOKEN, TEST_KEY_A), TEST_TOKEN);
  });

  it('AC-P09-5 (b): token encrypted with another key -> scan failed, no clone, no leak', async () => {
    process.env.ENCRYPTION_KEY = TEST_KEY_B;
    await expectFailedWithoutLeak(encryptToken(TEST_TOKEN, TEST_KEY_A), TEST_TOKEN);
  });

  it('AC-P09-5 (c): buffer shorter than 28 bytes (plaintext-stored token) -> scan failed, no clone, no leak', async () => {
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    await expectFailedWithoutLeak(Buffer.from(TEST_SHORT_TOKEN, 'utf8'), TEST_SHORT_TOKEN);
  });

  it('control: valid encrypted token reaches cloneRepo as the 4th argument (never in the URL)', async () => {
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    const scanId = await scanWithToken(encryptToken(TEST_TOKEN, TEST_KEY_A));
    const clone = fakeClone();
    await runOnce(await newWorker({ cloneRepo: clone.fn, runParser: fakeParser().fn }));
    expect((await scanRow(scanId)).status).toBe('completed');
    expect(clone.calls).toHaveLength(1);
    expect(clone.calls[0].token).toBe(TEST_TOKEN);
    expect(clone.calls[0].url).not.toContain(TEST_TOKEN);
    expect(logs.join('\n')).not.toContain(TEST_TOKEN);
  });

  it('AC-P09-5: no token (access_token_enc NULL) -> scan proceeds token-less even without ENCRYPTION_KEY', async () => {
    delete process.env.ENCRYPTION_KEY;
    const scanId = await scanWithToken(null);
    const clone = fakeClone();
    await runOnce(await newWorker({ cloneRepo: clone.fn, runParser: fakeParser().fn }));
    expect((await scanRow(scanId)).status).toBe('completed');
    expect(clone.calls[0].token).toBeNull();
  });
});
