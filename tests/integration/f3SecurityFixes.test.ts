/**
 * REQ-004 · post-review fixes with a real database (commit e526d6d; security
 * review `docs/quality/security-reports/REQ-004-security-review.md`, contract
 * 1.1.0 section 3.7):
 *
 *   B-2  end-to-end scan with the loopback fake registry returning
 *        `GPL-3.0-or-later` completes (the real-network scan crashed with
 *        "Maximum call stack size exceeded")
 *   L-3  worker license policy with inherited keys (`constructor`, …) opens
 *        `unknown` findings instead of silently passing; NOTICE omitted-reason
 *        map ignores inherited keys
 *   M-1  NOTICE texts read in batches of TEXT_BATCH_SIZE inside one
 *        REPEATABLE READ snapshot, no text query after the size cap, output
 *        bytes unchanged
 *
 * Pure parts: tests/unit/f3SecurityFixes.test.ts.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Pool, PoolClient } from 'pg';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type DependencyEnricher, createDependencyEnricher } from '../../src/enrichment';
import type { RegistryClock } from '../../src/enrichment/registryClient';
import { NOTICE_SIZE_LIMIT_LINE, NoticeService, TEXT_BATCH_SIZE } from '../../src/notice/noticeService';
import { ScanWorker } from '../../src/scanner/worker';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import { useTestDatabase } from '../helpers/db';
import { f3Dep, seedScan } from '../helpers/f3Seed';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

const E = '='.repeat(80);
const F = '-'.repeat(80);

let tmpRoot = '';
let root = '';
let reg: FakeRegistry;
let logs: string[] = [];
const enrichers: DependencyEnricher[] = [];
const push = (...a: unknown[]) => logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-f3fix-'));
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
const npmDep = (name: string, version: string, licenses: string[] = []): Dep =>
  ({ ecosystem: 'nodejs', name, version, purl: `pkg:npm/${name}@${version}`, scope: 'direct', licenses, manifest_file: 'package-lock.json', manifest_path: '.' }) as Dep;

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

async function scan(deps: Dep[], e: DependencyEnricher | null): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`p-${Math.random().toString(36).slice(2)}`, root]);
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [p.id],
  );
  const runParser: RunParserFn = async (_d, _e, scanId) => ({ scan_id: scanId, status: 'completed', total_deps: deps.length, dependencies: deps, scan_files: [], parse_errors: [] });
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runParser, runId: 'run-A', ...(e ? { enricher: e } : {}) });
  expect(await w.runOnce()).toBe(s.id);
  return s.id;
}

async function scanStatus(scanId: string): Promise<{ status: string; error_message: string | null }> {
  const [r] = await db.query<{ status: string; error_message: string | null }>(`SELECT status::text AS status, error_message FROM scans WHERE id = $1`, [scanId]);
  return r;
}

async function licenseFindings(scanId: string): Promise<Array<{ name: string; detected: string; normalized: string; risk: string }>> {
  return db.query(
    `SELECT p.name, lf.detected_license AS detected, lf.normalized_license AS normalized, lf.risk_level::text AS risk
       FROM findings f
       JOIN license_findings lf ON lf.finding_id = f.id
       JOIN scan_dependencies sd ON sd.id = f.scan_dependency_id
       JOIN packages p ON p.id = sd.package_id
      WHERE f.scan_id = $1
      ORDER BY p.name`,
    [scanId],
  );
}

// ---------------------------------------------------------------------------
describe('B-2: end-to-end scan with -or-later registry licenses completes', () => {
  it('B-2 / AC-P14-1: fake registry returns GPL-3.0-or-later / LGPL-2.1-or-later / (MIT OR GPL-3.0-or-later) -> scan completed, licenses stored, GPL finding opened', async () => {
    reg.addNpmPackage('gpl-later', '1.0.0', { license: 'GPL-3.0-or-later' });
    reg.addNpmPackage('lgpl-later', '2.0.0', { license: 'LGPL-2.1-or-later' });
    reg.addNpmPackage('dual-later', '3.0.0', { license: '(MIT OR GPL-3.0-or-later)' });
    const scanId = await scan([
      npmDep('gpl-later', '1.0.0', ['GPL-3.0-or-later']),
      npmDep('lgpl-later', '2.0.0'),
      npmDep('dual-later', '3.0.0', ['Apache-2.0 WITH LLVM-exception']),
    ], enricher());
    expect(await scanStatus(scanId)).toEqual({ status: 'completed', error_message: null });
    expect(logs.join('\n')).not.toMatch(/Maximum call stack|RangeError/);
    const rows = await db.query<{ name: string; license_expression: string | null; license_source: string | null }>(
      `SELECT p.name, sd.license_expression, sd.license_source FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1 ORDER BY p.name`,
      [scanId],
    );
    expect(rows).toEqual([
      { name: 'dual-later', license_expression: '(MIT OR GPL-3.0-or-later)', license_source: 'registry:npm' },
      { name: 'gpl-later', license_expression: 'GPL-3.0-or-later', license_source: 'registry:npm' },
      { name: 'lgpl-later', license_expression: 'LGPL-2.1-or-later', license_source: 'registry:npm' },
    ]);
    const gpl = (await licenseFindings(scanId)).filter((f) => f.name === 'gpl-later');
    expect(gpl).toEqual([{ name: 'gpl-later', detected: 'GPL-3.0-or-later', normalized: 'GPL-3.0-or-later', risk: 'high' }]);
  });
});

describe('L-3: inherited keys in the worker license policy', () => {
  it('SEC L-3: lockfile licenses constructor / __proto__ / toString / hasOwnProperty -> scan completes, one "unknown" license finding each (no silent pass)', async () => {
    const keys = ['constructor', '__proto__', 'toString', 'hasOwnProperty'];
    const scanId = await scan(keys.map((k, i) => npmDep(`inh-${i}`, '1.0.0', [k])), null);
    expect(await scanStatus(scanId)).toEqual({ status: 'completed', error_message: null });
    const found = await licenseFindings(scanId);
    expect(found).toEqual(keys.map((k, i) => ({ name: `inh-${i}`, detected: k, normalized: k, risk: 'unknown' })));
  });

  it('SEC L-3: NOTICE omitted-reason map ignores inherited keys ([omitted: not available])', async () => {
    const { scanId } = await seedScan(db, {
      projectName: 'l3-notice',
      deps: [f3Dep({
        ecosystem: 'nodejs', name: 'omit-inh', version: '1.0.0', purl: 'pkg:npm/omit-inh@1.0.0', licenseExpression: 'MIT', noticeStatus: 'collected',
        archive: { ecosystem: 'npm', name: 'omit-inh', version: '1.0.0', outcome: 'collected', licenseFiles: [{ path: 'package/A', omitted: 'constructor' }, { path: 'package/B', omitted: '__proto__' }, { path: 'package/C', omitted: 'toString' }] },
      })],
    });
    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    expect(text.split('\n').filter((l) => l.startsWith('[omitted: '))).toEqual(Array(3).fill('[omitted: not available]'));
    expect(text).not.toMatch(/function|native code/);
  });
});

// ---------------------------------------------------------------------------
// M-1
// ---------------------------------------------------------------------------
const N = 2 * TEXT_BATCH_SIZE + 20; // three batches
const pad = (i: number) => String(i).padStart(3, '0');

async function seedMany(): Promise<string> {
  const { scanId } = await seedScan(db, {
    projectName: 'm1-app',
    deps: Array.from({ length: N }, (_, i) => f3Dep({
      ecosystem: 'nodejs', name: `p${pad(i)}`, version: '1.0.0', purl: `pkg:npm/p${pad(i)}@1.0.0`, licenseExpression: 'MIT', noticeStatus: 'collected',
      archive: {
        ecosystem: 'npm', name: `p${pad(i)}`, version: '1.0.0', outcome: 'collected',
        licenseFiles: [{ path: 'package/LICENSE', text: `License text ${pad(i)}\nline two\n` }], copyrightLines: [`Copyright ${pad(i)}`],
      },
    })),
  });
  return scanId;
}

/** Expected NOTICE written from contract section 3 (not copied from the implementation); `cutAfter` = last entry whose text fits. */
function expectedNotice(scanId: string, cutAfter = Infinity): { text: string; bytesThrough: (i: number) => number } {
  const header = [
    'THIRD-PARTY SOFTWARE NOTICES', 'NOTICE format: 1', 'Project: m1-app', `Scan ID: ${scanId}`, 'Scan completed at: 2026-10-10T08:15:30.123Z',
    `Packages: ${N}`, `Packages with license files: ${N}`, 'Packages without license files: 0',
    'Generated automatically; not legal advice. Review before distribution.',
  ];
  const ends: number[] = [];
  let text = `${header.join('\n')}\n`;
  for (let i = 0; i < N; i++) {
    const body = i <= cutAfter ? [`License text ${pad(i)}`, 'line two'] : [NOTICE_SIZE_LIMIT_LINE];
    text += `${['', E, `Package: p${pad(i)}`, 'Version: 1.0.0', 'Ecosystem: npm', `PURL: pkg:npm/p${pad(i)}@1.0.0`, 'License: MIT', 'License source: registry:npm',
      `Copyright: Copyright ${pad(i)}`, 'License files: 1', F, 'File: package/LICENSE', F, ...body].join('\n')}\n`;
    ends.push(Buffer.byteLength(text, 'utf8'));
  }
  return { text, bytesThrough: (i) => ends[i] };
}

/** Pool whose clients record every SQL text (same connection, real queries). */
function recordingPool(sqls: string[]): Pool {
  return {
    connect: async () => {
      const client = await db.pool.connect();
      return new Proxy(client, {
        get(target, prop) {
          if (prop === 'query') {
            return (sql: string | { text: string }, ...rest: unknown[]) => {
              sqls.push(typeof sql === 'string' ? sql : sql.text);
              return (target.query as (...a: unknown[]) => unknown)(sql, ...rest);
            };
          }
          const v = Reflect.get(target, prop) as unknown;
          return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
        },
      }) as PoolClient;
    },
  } as unknown as Pool;
}

const isTextQuery = (sql: string) => sql.includes("->> 'text'") || /SELECT\s+c\.name,\s*c\.version,\s*c\.license_text/.test(sql);

describe('M-1: NOTICE texts read in batches, never after the size cap; bytes unchanged', () => {
  it(`SEC M-1 / contract 3.7: ${N} entries (> TEXT_BATCH_SIZE=${TEXT_BATCH_SIZE}) byte-identical to the contract-built expectation; one REPEATABLE READ snapshot; one text query per batch; structure queries carry no text`, async () => {
    expect(TEXT_BATCH_SIZE).toBe(50);
    const scanId = await seedMany();
    const sqls: string[] = [];
    const doc = await new NoticeService(recordingPool(sqls)).generate(scanId);
    expect(doc.body.toString('utf8')).toBe(expectedNotice(scanId).text);
    expect(sqls[0]).toMatch(/^BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY$/);
    expect(sqls[sqls.length - 1]).toBe('COMMIT');
    expect(sqls.filter(isTextQuery)).toHaveLength(Math.ceil(N / TEXT_BATCH_SIZE));
    // The archive structure query strips `text` (f - 'text'); it never selects the text itself.
    const structure = sqls.filter((s) => s.includes('registry_archive_cache') && !isTextQuery(s));
    expect(structure.length).toBeGreaterThan(0);
    for (const s of structure) expect(s).toContain("f - 'text'");
    // Same bytes as the default pool (batching is invisible in the output).
    expect((await new NoticeService(db.pool).generate(scanId)).body.equals(doc.body)).toBe(true);
  });

  it('SEC M-1 / C-18: after the first overflow no text query runs (cap in batch 1 -> 1 text query; cap in batch 2 -> 2); output = later blocks replaced by the omission line', async () => {
    const scanId = await seedMany();
    for (const [cutAfter, queries] of [[10, 1], [TEXT_BATCH_SIZE + 10, 2]] as const) {
      const maxBytes = expectedNotice(scanId).bytesThrough(cutAfter);
      const sqls: string[] = [];
      const body = (await new NoticeService(recordingPool(sqls), { maxBytes }).generate(scanId)).body.toString('utf8');
      expect(body).toBe(expectedNotice(scanId, cutAfter).text);
      expect(body.split('\n').filter((l) => l === NOTICE_SIZE_LIMIT_LINE)).toHaveLength(N - cutAfter - 1);
      expect(sqls.filter(isTextQuery), `cutAfter=${cutAfter}`).toHaveLength(queries);
    }
    // maxBytes = 0: no text query at all? The first batch is read before the first overflow is known.
    const sqls0: string[] = [];
    await new NoticeService(recordingPool(sqls0), { maxBytes: 0 }).generate(scanId);
    expect(sqls0.filter(isTextQuery)).toHaveLength(1);
  });
});
