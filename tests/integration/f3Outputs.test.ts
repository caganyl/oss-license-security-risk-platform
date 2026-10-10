/**
 * REQ-004 · F3 outputs from the database: Excel `Dependencies` License /
 * License Source columns and PDF generation (AC-P14-18, AC-L6-4, C-8,
 * contract section 5) and SBOM copyright through `SbomService` (AC-P16-7,
 * contract section 6). Real embedded PostgreSQL, rows seeded with SQL
 * (helpers/f3Seed); output written to temp folders.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ExcelJS from 'exceljs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ReportService } from '../../src/reports/reportService';
import { SbomService, type SbomFormat } from '../../src/sbom/sbomService';
import { useTestDatabase } from '../helpers/db';
import { f3Dep, seedScan } from '../helpers/f3Seed';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });
let outDir = '';
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-f3out-'));
  for (const k of ['REPORT_OUTPUT_DIR', 'SBOM_OUTPUT_DIR']) {
    saved[k] = process.env[k];
    process.env[k] = outDir;
  }
});
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(outDir, { recursive: true, force: true });
});

async function report(projectId: string, scanId: string, format: 'excel' | 'pdf'): Promise<string> {
  const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id`, [`qa-${Math.random().toString(36).slice(2)}@example.test`]);
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by) VALUES ($1, 'project_report', $2, 'generating', $3::jsonb, $4) RETURNING id`,
    [projectId, format, JSON.stringify({ scanId }), u.id],
  );
  const record = await new ReportService(db.pool).processReport(r.id);
  expect(record.status).toBe('ready');
  expect(record.errorMessage).toBeNull();
  return record.storageKey!;
}

/** Raw cell values (1-based columns) of a row. */
function cells(sheet: ExcelJS.Worksheet, row: number): unknown[] {
  return (sheet.getRow(row).values as unknown[]).slice(1);
}

describe('AC-P14-18 / AC-L6-4: Excel Dependencies License and License Source (contract 5.1)', () => {
  it('AC-P14-18 / AC-L6-4 / C-8: 9 headers in order, values, lockfile differs, hint ignored, lockfile (unverified), formula guard; Licenses sheet unchanged', async () => {
    const { scanId, projectId } = await seedScan(db, {
      projectName: 'xlsx-f3',
      deps: [
        f3Dep({ ecosystem: 'nodejs', name: 'a-differs', version: '1.0.0', purl: 'pkg:npm/a-differs@1.0.0', licenseExpression: 'GPL-3.0-only', licenseLockHint: `MIT${String.fromCharCode(0x202e)}\tx`, licenseHintDiffers: true }),
        f3Dep({ ecosystem: 'nodejs', name: 'b-ignored', version: '1.0.0', purl: 'pkg:npm/b-ignored@1.0.0', licenseSource: 'none', enrichmentStatus: 'no_license', licenseLockHint: 'ISC' }),
        f3Dep({ ecosystem: 'nodejs', name: 'c-lock', version: '1.0.0', purl: 'pkg:npm/c-lock@1.0.0', licenseExpression: 'BSD-2-Clause', licenseSource: 'lockfile (unverified)', enrichmentStatus: 'not_found', licenseLockHint: 'BSD-2-Clause' }),
        f3Dep({ ecosystem: 'nodejs', name: 'd-formula', version: '1.0.0', purl: 'pkg:npm/d-formula@1.0.0', licenseExpression: '=HYPERLINK("http://x","y")', licenseSource: 'lockfile (unverified)', enrichmentStatus: 'disabled' }),
        f3Dep({ ecosystem: 'nodejs', name: 'e-long', version: '1.0.0', purl: 'pkg:npm/e-long@1.0.0', licenseExpression: 'MIT', licenseLockHint: 'L'.repeat(300), licenseHintDiffers: true }),
        f3Dep({ ecosystem: 'nodejs', name: 'f-none', version: '1.0.0', purl: 'pkg:npm/f-none@1.0.0', licenseSource: 'none', enrichmentStatus: 'unreachable' }),
        f3Dep({ ecosystem: 'python', name: 'g-py', version: '2.0', purl: 'pkg:pypi/g-py@2.0', licenseExpression: '@SUM(1)', licenseSource: 'registry:pypi' }),
      ],
    });
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.readFile(await report(projectId, scanId, 'excel'));
    const sheet = wb.getWorksheet('Dependencies')!;
    expect(cells(sheet, 1)).toEqual(['Name', 'Version', 'Ecosystem', 'Scope', 'Manifest', 'Depth', 'PURL', 'License', 'License Source']);
    const rows = new Map<string, unknown[]>();
    for (let i = 2; i <= sheet.rowCount; i++) rows.set(String(cells(sheet, i)[0]), cells(sheet, i));
    const lic = (n: string) => [rows.get(n)![7] ?? '', rows.get(n)![8] ?? ''];
    expect(lic('a-differs')).toEqual(['GPL-3.0-only', expect.stringMatching(/^registry:npm \(lockfile differs: MIT/)]);
    expect(String(lic('a-differs')[1])).not.toContain(String.fromCharCode(0x202e));
    expect(lic('b-ignored')).toEqual(['', 'none (lockfile hint ignored: ISC)']);
    expect(lic('c-lock')).toEqual(['BSD-2-Clause', 'lockfile (unverified)']);
    expect(lic('d-formula')).toEqual([`'=HYPERLINK("http://x","y")`, 'lockfile (unverified)']);
    expect(lic('e-long')).toEqual(['MIT', `registry:npm (lockfile differs: ${'L'.repeat(200)})`]);
    expect(lic('f-none')).toEqual(['', 'none']);
    expect(lic('g-py')).toEqual(["'@SUM(1)", 'registry:pypi']);
    // Plain strings only (never { formula } / rich text) in the new columns.
    for (const r of rows.values()) for (const v of [r[7], r[8]]) if (v !== undefined && v !== null) expect(typeof v).toBe('string');
    expect(sheet.autoFilter).toBe('A1:I1');
    const licSheet = wb.getWorksheet('Licenses')!;
    expect(cells(licSheet, 1)).toEqual(['Package', 'Version', 'Detected License', 'Normalized License', 'Risk', 'Policy', 'Status', 'Suppressed']);
    expect(wb.worksheets.map((w) => w.name)).toEqual(['Summary', 'Dependencies', 'Licenses', 'Vulnerabilities']);
  });

  it('AC-P14-18: pre-F3 scan -> both new cells empty, Excel and PDF generated without error', async () => {
    const { scanId, projectId } = await seedScan(db, {
      projectName: 'xlsx-pre-f3',
      deps: [{ ecosystem: 'nodejs', name: 'old', version: '1.0.0', purl: 'pkg:npm/old-xlsx@1.0.0' }],
    });
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.readFile(await report(projectId, scanId, 'excel'));
    const row = cells(wb.getWorksheet('Dependencies')!, 2);
    expect([row[7] ?? '', row[8] ?? '']).toEqual(['', '']);
    const pdf = fs.readFileSync(await report(projectId, scanId, 'pdf'));
    expect(pdf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
  });

  it('AC-P14-18 / contract 5.2: PDF project_report with F3 licenses is generated (License column content: by inspection, streams compressed)', async () => {
    const { scanId, projectId } = await seedScan(db, {
      projectName: 'pdf-f3',
      deps: [
        f3Dep({ ecosystem: 'nodejs', name: 'p1', version: '1.0.0', purl: 'pkg:npm/p1-pdf@1.0.0', licenseExpression: 'MIT' }),
        f3Dep({ ecosystem: 'nodejs', name: 'p2', version: '1.0.0', purl: 'pkg:npm/p2-pdf@1.0.0', licenseSource: 'none', enrichmentStatus: 'unreachable' }),
      ],
    });
    const pdf = fs.readFileSync(await report(projectId, scanId, 'pdf'));
    expect(pdf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    expect(pdf.length).toBeGreaterThan(500);
  });
});

describe('AC-P16-7: copyrightText filled where possible (SbomService from the database)', () => {
  it('AC-P16-7: two runtime packages with extracted copyright, one without; SPDX JSON / tag-value / CycloneDX JSON / XML consistent', async () => {
    const arch = (name: string, lines: string[]) => ({ ecosystem: 'npm' as const, name, version: '1.0.0', outcome: 'collected' as const, licenseFiles: [{ path: 'package/LICENSE', text: 'x' }], copyrightLines: lines });
    const { scanId } = await seedScan(db, {
      projectName: 'sbom-f3',
      deps: [
        f3Dep({ ecosystem: 'nodejs', name: 'cr-a', version: '1.0.0', purl: 'pkg:npm/cr-a@1.0.0', licenseExpression: 'MIT', noticeStatus: 'collected', archive: arch('cr-a', ['Copyright (c) 2020 A']) }),
        f3Dep({ ecosystem: 'nodejs', name: 'cr-b', version: '1.0.0', purl: 'pkg:npm/cr-b@1.0.0', licenseExpression: 'ISC', noticeStatus: 'collected', archive: arch('cr-b', ['Copyright 2021 B1', 'Copyright 2022 B2']) }),
        f3Dep({ ecosystem: 'nodejs', name: 'cr-none', version: '1.0.0', purl: 'pkg:npm/cr-none@1.0.0', licenseExpression: 'MIT', noticeStatus: 'no_license_file', archive: { ...arch('cr-none', []), outcome: 'no_license_file', licenseFiles: [] } }),
      ],
    });
    const svc = new SbomService(db.pool);
    const read = async (f: SbomFormat) => fs.readFileSync((await svc.generate(scanId, f)).storageKey, 'utf8');
    const expected: Record<string, string | null> = { 'cr-a': 'Copyright (c) 2020 A', 'cr-b': 'Copyright 2021 B1\nCopyright 2022 B2', 'cr-none': null };

    const spdx = JSON.parse(await read('spdx_json')) as { packages: Array<{ name: string; copyrightText: string }> };
    for (const [n, c] of Object.entries(expected)) expect(spdx.packages.find((p) => p.name === n)!.copyrightText, n).toBe(c ?? 'NOASSERTION');

    const tv = await read('spdx_tag_value');
    expect(tv).toContain('PackageName: cr-a\n');
    expect(tv).toContain('PackageCopyrightText: <text>Copyright (c) 2020 A</text>\n');
    expect(tv).toContain('PackageCopyrightText: <text>Copyright 2021 B1\nCopyright 2022 B2</text>\n');
    expect(tv.split('\n').filter((l) => l === 'PackageCopyrightText: NOASSERTION')).toHaveLength(2); // root + cr-none

    const cdx = JSON.parse(await read('cyclonedx_json')) as { components: Array<{ name: string; copyright?: string }> };
    for (const [n, c] of Object.entries(expected)) expect(cdx.components.find((p) => p.name === n)!.copyright, n).toBe(c ?? undefined);

    const xml = await read('cyclonedx_xml');
    expect(xml).toContain('<copyright>Copyright (c) 2020 A</copyright>');
    expect(xml).toContain('<copyright>Copyright 2021 B1\nCopyright 2022 B2</copyright>');
    expect(xml.match(/<copyright>/g)).toHaveLength(2);
  });
});
