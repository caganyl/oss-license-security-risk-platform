/**
 * REQ-003 · L-5 end to end (AC-T-4, AC-P13-8; D-48; ADR-002 Ek E3): every
 * text the workers persist goes through `sanitizeErrorText`.
 *
 * - scan worker: clone error (transient, retry log), parser error, and the
 *   `parse_errors` warning join of a completed scan -> `scans.error_message`;
 * - report worker + real ReportService: a file-system error whose message
 *   carries an absolute temp path, and a thrown error with a token, a
 *   credential URL and control characters -> `reports.error_message`.
 *
 * Real embedded PostgreSQL (AC-G-4); clone and parser are injected, OSV is a
 * `fetch` stub. Token-shaped samples are assembled at run time and are not
 * real credentials (tests/README.md "Kurallar").
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ReportService } from '../../src/reports/reportService';
import { ExportWorker } from '../../src/reports/worker';
import { ScanWorker, type ScanWorkerDeps } from '../../src/scanner/worker';
import type { CloneRepoFn } from '../../src/scanner/workspace';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import { useTestDatabase } from '../helpers/db';
import { TEST_KEY_A, TEST_TOKEN, encryptToken } from '../helpers/tokenCrypto';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });

let tmpRoot = '';
let root = '';
let logs: string[] = [];
const push = (...a: unknown[]) => logs.push(a.map((x) => (x instanceof Error ? `${x.name}: ${x.message}` : String(x))).join(' '));
const logger = { log: push, warn: push, error: push };
const saved: Record<string, string | undefined> = {};

const CONTROL_EXCEPT_NL_TAB = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/; // eslint-disable-line no-control-regex
const FILLER = 'FAKE0TEST0'.repeat(4);
const fake = (...parts: string[]) => parts.join('');
const BASIC = Buffer.from(`x-access-token:${TEST_TOKEN}`, 'utf8').toString('base64');
const HOME = os.homedir();
const codePoints = (t: string) => Array.from(t).length;

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-l5-'));
  root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
  logs = [];
  for (const k of ['ENCRYPTION_KEY', 'REPORT_OUTPUT_DIR']) saved[k] = process.env[k];
  process.env.ENCRYPTION_KEY = TEST_KEY_A;
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulns: [], results: [] }), { status: 200 })));
  // only the scan/report created by the current test may be claimed
  await db.query(`UPDATE scans SET status = 'cancelled' WHERE status IN ('pending','queued','running')`);
  await db.query(`UPDATE reports SET status = 'failed' WHERE status IN ('pending','generating')`);
  await db.query(`UPDATE system_settings SET value = '3' WHERE key = 'scan.max_retries'`);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function result(scanId: string, extra: Partial<SandboxScanResult> = {}): SandboxScanResult {
  return { scan_id: scanId, status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [], ...extra };
}
function worker(deps: Partial<ScanWorkerDeps> = {}): ScanWorker {
  return new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runParser: async (_d, _e, id) => result(id), runId: 'run-L5', ...deps });
}
async function insertProject(repoUrl: string): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`p-${Math.random().toString(36).slice(2)}`, repoUrl]);
  return p.id;
}
async function insertScan(projectId: string, integrationId: string | null = null): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, integration_id, trigger, status, ref, queued_at) VALUES ($1, $2, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId, integrationId],
  );
  return s.id;
}
async function scanRow(id: string): Promise<{ status: string; error_message: string | null }> {
  const [r] = await db.query<{ status: string; error_message: string | null }>('SELECT status::text, error_message FROM scans WHERE id = $1', [id]);
  return r;
}

/** Shared assertions for a persisted text. */
function expectClean(text: string, forbiddenPaths: string[], forbidden: string[] = []): void {
  expect(codePoints(text)).toBeLessThanOrEqual(2000);
  expect(text).not.toMatch(CONTROL_EXCEPT_NL_TAB);
  expect(text).not.toContain('\r');
  const lower = text.toLowerCase();
  for (const p of forbiddenPaths) {
    expect(lower, p).not.toContain(p.toLowerCase());
    expect(lower, p).not.toContain(p.replace(/\\/g, '/').toLowerCase());
  }
  for (const f of forbidden) expect(text, 'secret survived').not.toContain(f);
}

describe('AC-T-4 / L-5: scan worker error_message', () => {
  it('AC-T-4: clone error with token (raw + base64), workspace, SCAN_ROOTS, profile, ossr_ key, control characters and 3000 characters -> sanitized error_message and retry log', async () => {
    const projectId = await insertProject('https://github.com/org/private.git');
    const [integration] = await db.query<{ id: string }>(
      `INSERT INTO integrations (project_id, provider, name, repo_url, access_token_enc) VALUES ($1, 'github', 'gh', 'https://github.com/org/private.git', $2) RETURNING id`,
      [projectId, encryptToken(TEST_TOKEN, TEST_KEY_A)],
    );
    const scanId = await insertScan(projectId, integration.id);
    const apiKey = fake('ossr', '_', '0123456789abcdef', '_', 'Q'.repeat(43));
    let workspace = '';
    const clone: CloneRepoFn = async (_url, _ref, dest, token) => {
      workspace = path.dirname(dest);
      throw new Error(
        [
          `git clone failed (exit code 128): \x1b[31mfatal:\x1b[0m unable to access 'https://x-access-token:${token}@github.com/org/private.git/'\x07`,
          `trace: Authorization: Basic ${BASIC}\x00`,
          `error: could not lock ${dest}\\.git\\config`,
          `warning: ${workspace.replace(/\\/g, '/').toUpperCase()}/hooks`,
          `note: ${path.join(root, 'pkg', 'package.json')} and ${path.join(HOME, '.gitconfig')}`,
          `api key ${apiKey}`,
          'x'.repeat(3000),
        ].join('\r\n'),
      );
    };
    expect(await worker({ cloneRepo: clone, gitVersion: null }).runOnce()).toBe(scanId);
    const r = await scanRow(scanId);
    expect(r.status).toBe('queued');
    const msg = r.error_message ?? '';
    expectClean(msg, [workspace, root, HOME, tmpRoot], [TEST_TOKEN, BASIC, apiKey]);
    expect(msg).toContain('<workspace>');
    expect(msg).toContain('<scan-root>');
    expect(msg).toContain('[REDACTED]');
    // AC-P13-8: the retry log line carries the same sanitized, shortened text
    const retryLog = logs.find((l) => l.startsWith(`Tarama ${scanId} deneme 1/3 başarısız`));
    expect(retryLog).toBeDefined();
    expectClean(logs.join('\n'), [workspace, root, HOME], [TEST_TOKEN, BASIC, apiKey]);
  });

  it('AC-T-4: parser error text with SCAN_ROOTS, profile path, provider token and control characters -> sanitized error_message', async () => {
    const scanId = await insertScan(await insertProject(root));
    const ghToken = fake('gh', 'p_', FILLER);
    const parser: RunParserFn = async () => {
      throw new Error(`parse failed in ${path.join(root, 'a', 'package-lock.json')}\x1b[2K: ${path.join(HOME, 'x')} ${ghToken}\x00\x7f`);
    };
    expect(await worker({ runParser: parser }).runOnce()).toBe(scanId);
    const r = await scanRow(scanId);
    expect(['queued', 'failed']).toContain(r.status);
    const msg = r.error_message ?? '';
    expectClean(msg, [root, HOME, tmpRoot], [ghToken]);
    expect(msg).toContain('<scan-root>');
    expect(msg).toContain('[REDACTED]');
  });

  it('AC-T-4: parse_errors of a completed scan are joined and sanitized (absolute paths, control characters, 2000 characters)', async () => {
    const scanId = await insertScan(await insertProject(root));
    const parser: RunParserFn = async (_d, _e, id) =>
      result(id, {
        parse_errors: [
          { ecosystem: 'nodejs', file: path.join(root, 'broken', 'package.json'), error: `Unexpected token \x1b[31m}\x1b[0m in ${path.join(root, 'broken')}` },
          { ecosystem: 'python', file: 'requirements.txt', error: `${'y'.repeat(2500)}\x07` },
        ],
      });
    expect(await worker({ runParser: parser }).runOnce()).toBe(scanId);
    const r = await scanRow(scanId);
    expect(r.status).toBe('completed');
    const msg = r.error_message ?? '';
    expectClean(msg, [root, HOME, tmpRoot]);
    expect(msg).toContain('<scan-root>');
    expect(codePoints(msg)).toBe(2000);
  });
});

describe('AC-T-4 / L-5: report worker error_message (D-48 covers every persisted error text)', () => {
  async function insertUser(): Promise<string> {
    const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id`, [
      `qa-${Math.random().toString(36).slice(2)}@example.test`,
    ]);
    return u.id;
  }
  async function reportRow(id: string): Promise<{ status: string; error_message: string | null }> {
    const [r] = await db.query<{ status: string; error_message: string | null }>('SELECT status::text, error_message FROM reports WHERE id = $1', [id]);
    return r;
  }
  function exportWorker(reportService: ReportService): ExportWorker {
    return new ExportWorker({ db: db.pool, logger, reportService, config: { maxConcurrentExports: 1, pollIntervalMs: 50, timeoutMs: 30_000 } });
  }

  it('AC-T-4: real ReportService — a file-system error naming an absolute temp path is stored with <temp>/<home>, not the path', async () => {
    const projectId = await insertProject(root);
    const scanId = await insertScan(projectId);
    await worker().saveScanResults(scanId, projectId, result(scanId));
    const blocker = path.join(tmpRoot, 'not-a-dir.txt');
    fs.writeFileSync(blocker, 'x');
    process.env.REPORT_OUTPUT_DIR = path.join(blocker, 'out');
    const [rep] = await db.query<{ id: string }>(
      `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by) VALUES ($1, 'project_report', 'excel', 'pending', $2::jsonb, $3) RETURNING id`,
      [projectId, JSON.stringify({ scanId }), await insertUser()],
    );
    const w = exportWorker(new ReportService(db.pool));
    w.startPolling();
    try {
      await vi.waitFor(async () => expect((await reportRow(rep.id)).status).toBe('failed'), { timeout: 20_000, interval: 50 });
      await vi.waitFor(() => expect(logs.some((l) => l.startsWith(`Failed to generate report ${rep.id}`))).toBe(true), { timeout: 5_000, interval: 50 });
    } finally {
      w.stop();
      await w.waitForIdle(5_000);
    }
    const msg = (await reportRow(rep.id)).error_message ?? '';
    expect(msg.length).toBeGreaterThan(0);
    expectClean(msg, [tmpRoot, os.tmpdir(), HOME]);
    expect(msg).toMatch(/<temp>|<home>/);
    expectClean(logs.join('\n'), [tmpRoot, HOME]);
  });

  it('AC-T-4: a thrown error with a provider token, credential URL, control characters and 3000 characters -> sanitized reports.error_message', async () => {
    const ghToken = fake('github', '_pat_', FILLER, '_', FILLER);
    const [rep] = await db.query<{ id: string }>(
      `INSERT INTO reports (report_type, format, status, requested_by) VALUES ('executive_summary', 'pdf', 'pending', $1) RETURNING id`,
      [await insertUser()],
    );
    const reportService = {
      processReport: async () => {
        // A space separates the ANSI sequence from the token here; the glued form is a
        // known sanitizer gap covered by tests/unit/errorText.test.ts ("glued to ANSI").
        throw new Error(`render failed \x1b[31m ${ghToken}\x1b[0m https://qa-user:not-a-real-pass@git.example.test/x ${path.join(HOME, 'r.pdf')}\x00\r\n${'z'.repeat(3000)}`);
      },
    } as unknown as ReportService;
    const w = exportWorker(reportService);
    w.startPolling();
    try {
      await vi.waitFor(async () => expect((await reportRow(rep.id)).status).toBe('failed'), { timeout: 20_000, interval: 50 });
    } finally {
      w.stop();
      await w.waitForIdle(5_000);
    }
    const msg = (await reportRow(rep.id)).error_message ?? '';
    expectClean(msg, [HOME], [ghToken, 'not-a-real-pass', 'qa-user:']);
    expect(msg).toContain('[REDACTED]');
    expect(codePoints(msg)).toBe(2000);
  });
});
