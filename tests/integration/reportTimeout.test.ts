/**
 * REQ-003 security review L-5 (second part): the report time limit aborts
 * `ReportService.processReport(reportId, signal)`. Once the signal fires no
 * file is written and the row is never set to `ready`.
 *
 * Real ReportService and embedded PostgreSQL (AC-G-4); the private
 * `renderContent` step is wrapped (`vi.spyOn` on the prototype) to fire the
 * abort or to delay past the worker's time limit, then calls the real
 * renderer. `REPORT_OUTPUT_DIR` points to a per-test temp folder.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ReportService } from '../../src/reports/reportService';
import { ExportWorker } from '../../src/reports/worker';
import { ScanWorker } from '../../src/scanner/worker';
import { useTestDatabase } from '../helpers/db';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });

let tmpRoot = '';
let outDir = '';
let savedOut: string | undefined;
const quiet = { log: () => undefined, warn: () => undefined, error: () => undefined };

type Render = (this: ReportService, ...args: unknown[]) => Promise<Buffer>;
const proto = ReportService.prototype as unknown as { renderContent: Render };
const realRender: Render = proto.renderContent;

beforeEach(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-l5r-'));
  outDir = path.join(tmpRoot, 'out');
  savedOut = process.env.REPORT_OUTPUT_DIR;
  process.env.REPORT_OUTPUT_DIR = outDir;
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulns: [], results: [] }), { status: 200 })));
  await db.query(`UPDATE reports SET status = 'failed' WHERE status IN ('pending','generating')`);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (savedOut === undefined) delete process.env.REPORT_OUTPUT_DIR;
  else process.env.REPORT_OUTPUT_DIR = savedOut;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

/** A project with a completed (empty) scan and a report row for it. */
async function seedReport(status: 'pending' | 'generating'): Promise<{ reportId: string; scanId: string }> {
  const root = fs.mkdtempSync(path.join(tmpRoot, 'root-'));
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`p-${Math.random().toString(36).slice(2)}`, root]);
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [p.id],
  );
  const worker = new ScanWorker({ db: db.pool, tmpRoot, logger: quiet, scanRoots: [root], runId: 'run-L5R' });
  await worker.saveScanResults(s.id, p.id, { scan_id: s.id, status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] });
  const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id`, [`qa-${Math.random().toString(36).slice(2)}@example.test`]);
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by) VALUES ($1, 'project_report', 'excel', $2::report_status, $3::jsonb, $4) RETURNING id`,
    [p.id, status, JSON.stringify({ scanId: s.id }), u.id],
  );
  return { reportId: r.id, scanId: s.id };
}

async function reportRow(id: string) {
  const [r] = await db.query<{ status: string; error_message: string | null; storage_key: string | null }>(
    'SELECT status::text, error_message, storage_key FROM reports WHERE id = $1',
    [id],
  );
  return r;
}
const generatedAudits = async (id: string) => (await db.query(`SELECT 1 FROM audit_logs WHERE action = 'report_generated' AND entity_id = $1`, [id])).length;
const filesWritten = () => (fs.existsSync(outDir) ? fs.readdirSync(outDir) : []);

describe('L-5: report time limit aborts processReport', () => {
  it('control: without a signal the real service writes the file and sets ready', async () => {
    const { reportId } = await seedReport('generating');
    await new ReportService(db.pool).processReport(reportId);
    expect((await reportRow(reportId)).status).toBe('ready');
    expect(filesWritten()).toHaveLength(1);
  });

  it('L-5: the signal fires while rendering -> rejected with the abort reason, row failed (not ready), no file, no report_generated audit', async () => {
    const { reportId } = await seedReport('generating');
    const controller = new AbortController();
    vi.spyOn(proto, 'renderContent').mockImplementation(async function (this: ReportService, ...args: unknown[]) {
      const content = await realRender.apply(this, args);
      controller.abort(new Error('Report generation timed out after 100ms'));
      return content;
    });
    await expect(new ReportService(db.pool).processReport(reportId, controller.signal)).rejects.toThrow(/timed out after 100ms/);
    const r = await reportRow(reportId);
    expect(r.status).toBe('failed');
    expect(r.error_message).toMatch(/timed out after 100ms/);
    expect(r.storage_key).toBeNull();
    expect(filesWritten()).toEqual([]);
    expect(await generatedAudits(reportId)).toBe(0);
  });

  it('L-5: an already aborted signal -> nothing is read, rendered or written', async () => {
    const { reportId } = await seedReport('generating');
    const render = vi.spyOn(proto, 'renderContent');
    const controller = new AbortController();
    controller.abort(new Error('aborted before start'));
    await expect(new ReportService(db.pool).processReport(reportId, controller.signal)).rejects.toThrow('aborted before start');
    expect(render).not.toHaveBeenCalled();
    expect((await reportRow(reportId)).status).toBe('generating');
    expect(filesWritten()).toEqual([]);
  });

  // Timing-independent: under full-suite load `loadReportData` alone may exceed the
  // 150 ms limit, so the abort can hit before `renderContent` is ever called. The test
  // therefore does not assume where the abort lands: it captures the promise of the
  // real `processReport` call made by the worker and waits until that call has
  // settled (every checkpoint passed, render finished if it started), then asserts
  // the end state.
  it('L-5: ExportWorker time limit (150 ms) shorter than the render (600 ms) -> failed with the timeout text; once processReport has settled the row is not ready and no file exists', async () => {
    const { reportId } = await seedReport('pending');
    vi.spyOn(proto, 'renderContent').mockImplementation(async function (this: ReportService, ...args: unknown[]) {
      await new Promise((r) => setTimeout(r, 600));
      return realRender.apply(this, args);
    });
    const service = new ReportService(db.pool);
    const realProcess = ReportService.prototype.processReport;
    const calls: Promise<PromiseSettledResult<unknown>>[] = [];
    vi.spyOn(service, 'processReport').mockImplementation((id: string, signal?: AbortSignal) => {
      const p = realProcess.call(service, id, signal);
      calls.push(Promise.allSettled([p]).then(([res]) => res));
      return p;
    });
    const worker = new ExportWorker({
      db: db.pool,
      logger: quiet,
      reportService: service,
      config: { maxConcurrentExports: 1, pollIntervalMs: 50, timeoutMs: 150 },
    });
    worker.startPolling();
    let settled: PromiseSettledResult<unknown>[] = [];
    try {
      await vi.waitFor(() => expect(calls.length).toBeGreaterThan(0), { timeout: 10_000, interval: 25 });
      settled = await Promise.all(calls);
      await vi.waitFor(async () => expect((await reportRow(reportId)).status).toBe('failed'), { timeout: 10_000, interval: 25 });
    } finally {
      worker.stop();
      await worker.waitForIdle(5_000);
    }
    expect(settled.map((s) => s.status)).toEqual(['rejected']);
    const r = await reportRow(reportId);
    expect(r.status).toBe('failed');
    expect(r.error_message).toMatch(/Report generation timed out after 150ms/);
    expect(r.storage_key).toBeNull();
    expect(filesWritten()).toEqual([]);
    expect(await generatedAudits(reportId)).toBe(0);
  });
});
