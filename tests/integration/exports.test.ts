/**
 * REQ-007 · P-24 one-click exports, HTTP and content (contract
 * `docs/contracts/REQ-007-cli-and-exports.md` section 6 and 7; REQ-004
 * contract 1.5.0 sections 5.3 / 5.4):
 *   AC-P24-1  three GET routes, reports:read, 400/401/403/404, error order (N-6)
 *   AC-P24-2  headers (type, disposition, length, checksum, no-store)
 *   AC-P24-3  sync PDF text == async project_report PDF text (minus Generated)
 *   AC-P24-4  sync XLSX cells == async license_inventory Excel cells (minus Generated At)
 *   AC-P24-5  CSV cells == Excel `Dependencies` cells
 *   AC-P24-7  export_busy limiter (429 + Retry-After: 5, before 404; NOTICE outside)
 *   AC-P24-9  endpoint half: 200, Content-Type, non-empty body with cookie and Bearer
 *   AC-P24-10 V-12 row in Excel Summary (last row) and PDF Summary (last item), five values
 *   AC-P24-11 PDF truncation note per table (40/40/50), cut and not cut
 *   AC-P24-1 / 6.3 side-effect free (no reports/audit/sbom rows, no file, no fetch)
 * Real embedded PostgreSQL; rows seeded with SQL. No network.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ExcelJS from 'exceljs';
import type { Express } from 'express';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ExportLimiter } from '../../src/reports/exportLimiter';
import { ReportService } from '../../src/reports/reportService';
import { useTestDatabase } from '../helpers/db';
import { f3Dep, seedScan } from '../helpers/f3Seed';
import { createApiKey, expectErrorBody, makeApp, req, setupPassword } from '../helpers/http';
import { pdfLines } from '../helpers/pdfText';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });

const KINDS = [
  { kind: 'project-report.pdf', type: 'application/pdf', file: (id: string) => `project-report-${id}.pdf` },
  { kind: 'license-inventory.xlsx', type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', file: (id: string) => `license-inventory-${id}.xlsx` },
  { kind: 'license-inventory.csv', type: 'text/csv; charset=utf-8', file: (id: string) => `license-inventory-${id}.csv` },
] as const;
const MISSING = '00000000-0000-4000-8000-000000000000';
const EMOJI = String.fromCodePoint(0x1f600);

let app: Express;
let limiter: ExportLimiter;
let cookie = '';
let apiKey = '';
let scanId = '';
let outDir = '';
let savedOut: string | undefined;

const binary = (r: ReturnType<typeof req>) => r.buffer(true).parse((res, cb) => {
  const chunks: Buffer[] = [];
  res.on('data', (c: Buffer) => chunks.push(Buffer.from(c)));
  res.on('end', () => cb(null, Buffer.concat(chunks)));
});
const exportReq = (id: string, kind: string, opts: Parameters<typeof req>[3] = { cookie }) => binary(req(app, 'get', `/api/scans/${id}/exports/${kind}`, opts));

async function seedFindings(sid: string, security: number, license: number): Promise<void> {
  const sds = await db.query<{ id: string }>('SELECT id::text AS id FROM scan_dependencies WHERE scan_id = $1 ORDER BY id', [sid]);
  for (let i = 0; i < security; i += 1) {
    const [f] = await db.query<{ id: string }>(
      `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status, fingerprint)
       VALUES ($1, $2, 'security', 'open', md5(random()::text) || md5(random()::text)) RETURNING id::text AS id`,
      [sid, sds[i % sds.length].id],
    );
    const [v] = await db.query<{ id: string }>(
      `INSERT INTO vulnerabilities (osv_id, title, severity, source) VALUES ($1, 'qa vuln', 'high', 'osv') RETURNING id::text AS id`,
      [`QA-${crypto.randomUUID()}`],
    );
    await db.query(`INSERT INTO security_findings (finding_id, vulnerability_id, severity) VALUES ($1, $2, 'high')`, [f.id, v.id]);
  }
  for (let i = 0; i < license; i += 1) {
    const [f] = await db.query<{ id: string }>(
      `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status, fingerprint)
       VALUES ($1, $2, 'license', 'open', md5(random()::text) || md5(random()::text)) RETURNING id::text AS id`,
      [sid, sds[i % sds.length].id],
    );
    await db.query(
      `INSERT INTO license_findings (finding_id, detected_license, normalized_license, risk_level, applied_policy)
       VALUES ($1, 'GPL-3.0-only', 'GPL-3.0-only', 'high', 'restricted')`,
      [f.id],
    );
  }
}

const manyDeps = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => f3Dep({
  ecosystem: 'nodejs', name: `${prefix}-${String(i).padStart(3, '0')}`, version: '1.0.0', purl: `pkg:npm/${prefix}-${i}@1.0.0`, licenseExpression: 'MIT',
}));

beforeAll(async () => {
  outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-exports-'));
  savedOut = process.env.REPORT_OUTPUT_DIR;
  process.env.REPORT_OUTPUT_DIR = outDir;
  ({ scanId } = await seedScan(db, {
    projectName: 'exports-app',
    deps: [
      f3Dep({ ecosystem: 'nodejs', name: 'a,b', version: '1.0.0', purl: 'pkg:npm/a%2Cb@1.0.0', licenseExpression: 'MIT' }),
      f3Dep({ ecosystem: 'nodejs', name: 'say"hi"', version: '=cmd', purl: 'pkg:npm/sayhi@0', manifestPath: 'sub\ndir', depth: 2, licenseExpression: '-1' }),
      f3Dep({ ecosystem: 'nodejs', name: 'çğışöü', version: `1.0.0-${EMOJI}`, purl: 'pkg:npm/tr@1', scope: 'dev', licenseExpression: ' MIT ' }),
      f3Dep({ ecosystem: 'python', name: 'six', version: '1.16.0', purl: 'pkg:pypi/six@1.16.0', licenseExpression: 'MIT\nOR Apache-2.0', licenseSource: 'registry:pypi' }),
      f3Dep({ ecosystem: 'nodejs', name: 'nolic', version: '2.0.0', purl: 'pkg:npm/nolic@2.0.0', licenseSource: 'none', enrichmentStatus: 'no_license', licenseLockHint: 'ISC' }),
    ],
  }));
  await db.query(`UPDATE scans SET vulnerability_data_status = 'partial' WHERE id = $1`, [scanId]);
  await seedFindings(scanId, 2, 2);
  limiter = new ExportLimiter();
  app = await makeApp(db.pool, { exportLimiter: limiter });
  cookie = await setupPassword(app);
  apiKey = (await createApiKey(app, cookie)).key;
}, 240_000);

afterAll(() => {
  if (savedOut === undefined) delete process.env.REPORT_OUTPUT_DIR;
  else process.env.REPORT_OUTPUT_DIR = savedOut;
  fs.rmSync(outDir, { recursive: true, force: true });
});

/** Async report through the existing ReportService path (reports row + processReport). */
async function asyncReport(sid: string, reportType: string, format: 'pdf' | 'excel'): Promise<Buffer> {
  const [s] = await db.query<{ project_id: string }>('SELECT project_id::text FROM scans WHERE id = $1', [sid]);
  const [u] = await db.query<{ id: string }>('SELECT id::text AS id FROM users LIMIT 1');
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by)
     VALUES ($1, $2::report_type, $3::report_format, 'generating', $4::jsonb, $5) RETURNING id::text AS id`,
    [s.project_id, reportType, format, JSON.stringify({ scanId: sid }), u.id],
  );
  const record = await new ReportService(db.pool).processReport(r.id);
  return fs.readFileSync(record.storageKey!);
}

async function workbook(buf: Buffer): Promise<ExcelJS.Workbook> {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buf as unknown as ArrayBuffer);
  return wb;
}

/** Cell values of every row of a sheet, as text ('' for empty). */
function sheetRows(sheet: ExcelJS.Worksheet): string[][] {
  const rows: string[][] = [];
  sheet.eachRow({ includeEmpty: true }, (row) => {
    const values = (row.values as unknown[]).slice(1);
    const cells: string[] = [];
    for (let c = 0; c < sheet.columnCount; c += 1) {
      const v = values[c];
      cells.push(v === null || v === undefined ? '' : String(v));
    }
    rows.push(cells);
  });
  return rows;
}

/** RFC 4180 parser (test-side, independent of src/reports/csv.ts). */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let i = 0;
  let quoted = false;
  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i += 2; continue; }
      if (c === '"') { quoted = false; i += 1; continue; }
      field += c; i += 1; continue;
    }
    if (c === '"') { quoted = true; i += 1; continue; }
    if (c === ',') { row.push(field); field = ''; i += 1; continue; }
    if (c === '\r' && text[i + 1] === '\n') { row.push(field); rows.push(row); row = []; field = ''; i += 2; continue; }
    field += c; i += 1;
  }
  if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

const withoutGenerated = (lines: string[]) => lines.filter((l) => !l.startsWith('Generated:'));

// ---------------------------------------------------------------------------
describe('AC-P24-1 / AC-P24-2 / AC-P24-9: 200 responses and headers', () => {
  it('each export with the session cookie and with Bearer: 200, exact headers, checksum = body digest, non-empty body', async () => {
    for (const { kind, type, file } of KINDS) {
      for (const opts of [{ cookie }, { bearer: apiKey }]) {
        const res = await exportReq(scanId, kind, opts);
        expect(res.status, kind).toBe(200);
        const body = res.body as Buffer;
        expect(body.length).toBeGreaterThan(0);
        expect(res.headers['content-type']).toBe(type);
        expect(res.headers['content-disposition']).toBe(`attachment; filename="${file(scanId)}"`);
        expect(res.headers['content-length']).toBe(String(body.length));
        expect(res.headers['x-checksum-sha256']).toBe(crypto.createHash('sha256').update(body).digest('hex'));
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        expect(res.headers['content-disposition']).not.toContain('exports-app');
      }
    }
  });

  it('magic bytes: PDF %PDF-, XLSX zip, CSV UTF-8 BOM; upper-case scanId -> lower-case canonical filename', async () => {
    const pdf = (await exportReq(scanId.toUpperCase(), 'project-report.pdf')).body as Buffer;
    expect(pdf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    const xlsx = await exportReq(scanId.toUpperCase(), 'license-inventory.xlsx');
    expect((xlsx.body as Buffer).subarray(0, 2).toString('latin1')).toBe('PK');
    expect(xlsx.headers['content-disposition']).toBe(`attachment; filename="license-inventory-${scanId}.xlsx"`);
    const csv = (await exportReq(scanId, 'license-inventory.csv')).body as Buffer;
    expect([...csv.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
  });

  it('CSV is byte-for-byte deterministic for the same scan', async () => {
    const a = (await exportReq(scanId, 'license-inventory.csv')).body as Buffer;
    const b = (await exportReq(scanId, 'license-inventory.csv')).body as Buffer;
    expect(a.equals(b)).toBe(true);
  });
});

describe('AC-P24-1: errors (contract 6.5) — JSON envelope, no Content-Disposition', () => {
  it('400 invalid_request for malformed scanId on all three routes', async () => {
    for (const { kind } of KINDS) {
      for (const bad of ['not-a-uuid', '3f2b8c1e-5d4a-0b6f-9c2d-1a2b3c4d5e6f', `${scanId}x`]) {
        const res = await req(app, 'get', `/api/scans/${bad}/exports/${kind}`, { cookie });
        expectErrorBody(res, 400, 'invalid_request');
        expect(res.body.message).toBe('scanId must be a valid UUID');
        expect(res.headers['content-disposition']).toBeUndefined();
      }
    }
  });

  it('401 unauthenticated without credentials (even for an invalid scanId)', async () => {
    for (const { kind } of KINDS) {
      for (const id of [scanId, 'bad']) {
        const res = await req(app, 'get', `/api/scans/${id}/exports/${kind}`);
        expectErrorBody(res, 401, 'unauthenticated');
        expect(res.headers['content-disposition']).toBeUndefined();
      }
    }
  });

  it('404 not_found for a missing scan and for running / failed / pending scans (NOTICE text)', async () => {
    const ids = [MISSING];
    for (const status of ['running', 'failed', 'pending']) ids.push((await seedScan(db, { projectName: `exp-${status}`, status, deps: [] })).scanId);
    for (const { kind } of KINDS) {
      for (const id of ids) {
        const res = await req(app, 'get', `/api/scans/${id}/exports/${kind}`, { cookie });
        expectErrorBody(res, 404, 'not_found');
        expect(res.body.message).toBe('Scan not found or not yet completed');
        expect(res.headers['content-disposition']).toBeUndefined();
      }
    }
  });

  it('unknown export suffix falls to the /api 404', async () => {
    const res = await req(app, 'get', `/api/scans/${scanId}/exports/foo.pdf`, { cookie });
    expectErrorBody(res, 404, 'not_found');
    expect(res.headers['content-disposition']).toBeUndefined();
  });

  it('403 forbidden without reports:read (user without roles) — before 400 (N-6 order)', async () => {
    const roles = await db.query<{ user_id: string; role_id: string }>('SELECT user_id, role_id FROM user_roles');
    await db.query('DELETE FROM user_roles');
    try {
      for (const { kind } of KINDS) {
        for (const id of [scanId, 'not-a-uuid']) {
          const res = await req(app, 'get', `/api/scans/${id}/exports/${kind}`, { cookie });
          expectErrorBody(res, 403, 'forbidden');
          expect(res.body.message).toBe('Permission "reports:read" is required');
          expect(res.headers['content-disposition']).toBeUndefined();
        }
      }
    } finally {
      for (const r of roles) await db.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [r.user_id, r.role_id]);
    }
  });
});

describe('AC-P24-7: export_busy limiter and N-6 order (400 -> 429 -> 404)', () => {
  it('2 slots held -> 429 export_busy + Retry-After: 5 on all routes (also for a missing scan, before 404); 400 still wins; NOTICE unaffected; freed slot -> 200', async () => {
    const r1 = limiter.tryAcquire();
    const r2 = limiter.tryAcquire();
    expect(r1).not.toBeNull();
    expect(r2).not.toBeNull();
    try {
      for (const { kind } of KINDS) {
        for (const id of [scanId, MISSING]) {
          const res = await req(app, 'get', `/api/scans/${id}/exports/${kind}`, { bearer: apiKey });
          expectErrorBody(res, 429, 'export_busy');
          expect(res.body.message).toBe('Too many exports in progress; retry shortly');
          expect(res.headers['retry-after']).toBe('5');
          expect(res.headers['content-disposition']).toBeUndefined();
        }
        expectErrorBody(await req(app, 'get', `/api/scans/bad/exports/${kind}`, { cookie }), 400, 'invalid_request');
      }
      const notice = await req(app, 'get', `/api/scans/${scanId}/notice`, { cookie });
      expect(notice.status).toBe(200);
      expect(limiter.inUse).toBe(2);
      r1!();
      expect((await exportReq(scanId, 'license-inventory.csv')).status).toBe(200);
      expect(limiter.inUse).toBe(1); // the request released its slot
    } finally {
      r1!();
      r2!();
    }
    expect(limiter.inUse).toBe(0);
  });

  it('two exports in flight hold both slots; a third concurrent one gets 429 (real concurrency)', async () => {
    let releaseGate: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => { releaseGate = resolve; });
    const original = ReportService.prototype.renderExport;
    const spy = vi.spyOn(ReportService.prototype, 'renderExport').mockImplementation(async function (this: ReportService, ...args) {
      await gate;
      return original.apply(this, args);
    });
    try {
      const p1 = exportReq(scanId, 'license-inventory.csv').then((r) => r);
      const p2 = exportReq(scanId, 'project-report.pdf').then((r) => r);
      const start = Date.now();
      while (limiter.inUse < 2 && Date.now() - start < 5000) await new Promise((r) => setTimeout(r, 10));
      expect(limiter.inUse).toBe(2);
      const third = await req(app, 'get', `/api/scans/${scanId}/exports/license-inventory.xlsx`, { cookie });
      expectErrorBody(third, 429, 'export_busy');
      releaseGate();
      expect((await p1).status).toBe(200);
      expect((await p2).status).toBe(200);
      expect(limiter.inUse).toBe(0);
    } finally {
      releaseGate();
      spy.mockRestore();
    }
  });

  it('a render error releases the slot and answers 500 internal_error without raw text', async () => {
    const spy = vi.spyOn(ReportService.prototype, 'renderExport').mockRejectedValue(new Error(`boom at ${os.tmpdir()}`));
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const res = await req(app, 'get', `/api/scans/${scanId}/exports/license-inventory.csv`, { cookie });
      expectErrorBody(res, 500, 'internal_error');
      expect(JSON.stringify(res.body)).not.toContain('boom');
      expect(res.headers['content-disposition']).toBeUndefined();
      expect(limiter.inUse).toBe(0);
    } finally {
      spy.mockRestore();
      errSpy.mockRestore();
    }
  });
});

describe('AC-P24-1 / contract 6.3: side-effect free', () => {
  it('no reports / audit_logs / sbom_documents row, no file in REPORT_OUTPUT_DIR, no fetch', async () => {
    const count = async () => (await db.query<{ n: string }>(
      `SELECT (SELECT count(*) FROM sbom_documents) + (SELECT count(*) FROM reports) + (SELECT count(*) FROM audit_logs) AS n`,
    ))[0].n;
    const before = await count();
    const filesBefore = fs.readdirSync(outDir);
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    try {
      for (const { kind } of KINDS) expect((await exportReq(scanId, kind)).status).toBe(200);
    } finally {
      vi.unstubAllGlobals();
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(await count()).toBe(before);
    expect(fs.readdirSync(outDir)).toEqual(filesBefore);
  });
});

describe('AC-P24-3 / AC-P24-4 / AC-P24-5: same renderers as the async reports', () => {
  it('AC-P24-3: sync PDF text == async project_report PDF text (Generated line excluded)', async () => {
    const sync = pdfLines((await exportReq(scanId, 'project-report.pdf')).body as Buffer);
    const asyncPdf = pdfLines(await asyncReport(scanId, 'project_report', 'pdf'));
    expect(sync.some((l) => l.startsWith('Generated:'))).toBe(true);
    expect(sync).toContain('Dependency Inventory');
    expect(sync).toContain('Security Findings');
    expect(withoutGenerated(sync)).toEqual(withoutGenerated(asyncPdf));
  });

  it('AC-P24-4: sync XLSX cells == async license_inventory Excel cells on all four sheets (Generated At excluded)', async () => {
    const sync = await workbook((await exportReq(scanId, 'license-inventory.xlsx')).body as Buffer);
    const asyncWb = await workbook(await asyncReport(scanId, 'license_inventory', 'excel'));
    expect(sync.worksheets.map((w) => w.name)).toEqual(['Summary', 'Dependencies', 'Licenses', 'Vulnerabilities']);
    expect(asyncWb.worksheets.map((w) => w.name)).toEqual(sync.worksheets.map((w) => w.name));
    for (const ws of sync.worksheets) {
      const strip = (rows: string[][]) => rows.filter((r) => r[0] !== 'Generated At');
      expect(strip(sheetRows(ws)), ws.name).toEqual(strip(sheetRows(asyncWb.getWorksheet(ws.name)!)));
    }
    // formula guard kept in the sync export
    const deps = sheetRows(sync.getWorksheet('Dependencies')!);
    expect(deps.some((r) => r[1] === "'=cmd")).toBe(true);
    expect(sync.getWorksheet('Summary')!.getRow(1).values).toEqual([undefined, 'Metric', 'Value']);
  });

  it('AC-P24-5: every CSV cell equals the Excel Dependencies cell text (same headers, order, rows)', async () => {
    const csvBuf = (await exportReq(scanId, 'license-inventory.csv')).body as Buffer;
    const csv = parseCsv(csvBuf.subarray(3).toString('utf8'));
    const xlsx = sheetRows((await workbook((await exportReq(scanId, 'license-inventory.xlsx')).body as Buffer)).getWorksheet('Dependencies')!);
    expect(csv[0]).toEqual(['Name', 'Version', 'Ecosystem', 'Scope', 'Manifest', 'Depth', 'PURL', 'License', 'License Source']);
    expect(csv).toEqual(xlsx);
    expect(csv).toHaveLength(6);
    const tr = csv.find((r) => r[0] === 'çğışöü')!;
    expect(tr[7]).toBe(' MIT ');
    expect(csv.find((r) => r[0] === 'six')![7]).toBe('MIT OR Apache-2.0');
    expect(csv.find((r) => r[0] === 'say"hi"')![4]).toBe('sub\ndir');
    expect(csvBuf.toString('utf8').endsWith('\r\n')).toBe(true);
  });
});

describe('AC-P24-10: V-12 Vulnerability Data Status row (five values)', () => {
  const VALUES: Array<[string | null, string]> = [
    ['complete', 'complete'],
    ['partial', 'partial (some packages could not be checked)'],
    ['unavailable', 'unavailable (vulnerability source unreachable)'],
    ['disabled', 'disabled (lookup turned off)'],
    [null, 'not checked'],
  ];
  it.each(VALUES)('%j -> Excel Summary last row and PDF Summary last item "%s"', async (status, text) => {
    const { scanId: sid } = await seedScan(db, { projectName: `v12-${String(status)}`, deps: manyDeps(`v12${String(status)}`, 1) });
    await db.query('UPDATE scans SET vulnerability_data_status = $2 WHERE id = $1', [sid, status]);
    const wb = await workbook((await exportReq(sid, 'license-inventory.xlsx')).body as Buffer);
    const summary = sheetRows(wb.getWorksheet('Summary')!);
    expect(summary.map((r) => r[0])).toEqual([
      'Metric', 'Report Type', 'Project', 'Project Criticality', 'Repository', 'Scan ID', 'Reference', 'Completed At', 'Generated At',
      'Total Dependencies', 'Total Vulnerabilities', 'Critical Vulnerabilities', 'High Vulnerabilities', 'Medium Vulnerabilities',
      'Low Vulnerabilities', 'License Violations', 'Vulnerability Data Status',
    ]);
    expect(summary[summary.length - 1]).toEqual(['Vulnerability Data Status', text]);
    const lines = pdfLines((await exportReq(sid, 'project-report.pdf')).body as Buffer);
    const at = lines.findIndex((l) => l.startsWith('License violations:'));
    expect(at).toBeGreaterThan(-1);
    expect(lines[at + 1]).toBe(`Vulnerability Data Status: ${text}`);
    expect(lines[at + 2]).toBe('Security Findings');
  });
});

describe('AC-P24-11: PDF truncation note per table (40 / 40 / 50)', () => {
  const note = (n: number, total: number) => `Showing first ${n} of ${total}; see the Excel or CSV export for the full list.`;
  const section = (lines: string[], from: string, to: string | null) => {
    const a = lines.indexOf(from);
    const b = to === null ? lines.length : lines.indexOf(to);
    expect(a).toBeGreaterThan(-1);
    expect(b).toBeGreaterThan(a);
    return lines.slice(a + 1, b);
  };

  it('cut tables (41 security, 41 license, 51 deps) each get their own note right after the last row', async () => {
    const { scanId: sid } = await seedScan(db, { projectName: 'trunc-cut', deps: manyDeps('cut', 51) });
    await seedFindings(sid, 41, 41);
    const lines = pdfLines((await exportReq(sid, 'project-report.pdf')).body as Buffer);
    const sec = section(lines, 'Security Findings', 'License Findings');
    const lic = section(lines, 'License Findings', 'Dependency Inventory');
    const inv = section(lines, 'Dependency Inventory', null);
    expect(sec[sec.length - 1]).toBe(note(40, 41));
    expect(sec).toHaveLength(1 + 40 + 1); // header + rows + note
    expect(lic[lic.length - 1]).toBe(note(40, 41));
    expect(lic).toHaveLength(1 + 40 + 1);
    expect(inv[inv.length - 1]).toBe(note(50, 51));
    expect(inv).toHaveLength(1 + 50 + 1);
    expect(lines.filter((l) => l.startsWith('Showing first'))).toHaveLength(3);
  });

  it('tables exactly at the limit (40 / 40 / 50) get no note', async () => {
    const { scanId: sid } = await seedScan(db, { projectName: 'trunc-edge', deps: manyDeps('edge', 50) });
    await seedFindings(sid, 40, 40);
    const lines = pdfLines((await exportReq(sid, 'project-report.pdf')).body as Buffer);
    expect(lines.filter((l) => l.startsWith('Showing first'))).toEqual([]);
    expect(section(lines, 'Dependency Inventory', null)).toHaveLength(1 + 50);
  });

  it('only one table cut -> only that table gets a note (security cut, others not)', async () => {
    const { scanId: sid } = await seedScan(db, { projectName: 'trunc-one', deps: manyDeps('one', 3) });
    await seedFindings(sid, 45, 1);
    const lines = pdfLines((await exportReq(sid, 'project-report.pdf')).body as Buffer);
    expect(lines.filter((l) => l.startsWith('Showing first'))).toEqual([note(40, 45)]);
  });
});
