/**
 * REQ-004 · post-review fixes (commit e526d6d; security review
 * `docs/quality/security-reports/REQ-004-security-review.md`, contract
 * `docs/contracts/REQ-004-notice-and-outputs.md` 1.1.0 sections 3.6, 5.1a,
 * 6.1, 9). Pure / in-memory parts:
 *
 *   B-2  license normalizer: no recursion on `-or-later` / `-only` ids
 *   L-3  own-key lookups (normalizer, trove classifiers, CycloneDX scope)
 *   I-3  U+0085 / U+2028 / U+2029 folding and NOTICE shield
 *   L-1  SPDX tag-value single-line `<text>` escape (every single-line field)
 *   L-2  Excel formula guard on every string cell of every sheet (xlsx read back)
 *   L-4  process-wide in-flight archive byte budget + archive stage wiring
 *
 * Database paths (end-to-end scan, worker policy, NOTICE batching M-1) are in
 * tests/integration/f3SecurityFixes.test.ts.
 */
import ExcelJS from 'exceljs';
import { JSDOM } from 'jsdom';
import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  KNOWN_SPDX_IDS, canonicalSpdx, evaluateLicenseRisk, isRecognizedLicense, licenseFromClassifiers, normalizeLicense,
} from '../../src/analysis/licenseNormalizer';
import { type ArchiveStageContext, collectArchive } from '../../src/enrichment/archiveStage';
import { DownloadQuota, InFlightByteBudget, processInFlightBudget } from '../../src/enrichment/budget';
import { classifierTerm } from '../../src/enrichment/classifiers';
import type { ArchiveCandidate } from '../../src/enrichment/types';
import { ENTRY_SEP, FILE_SEP, noticeTextLines, shieldNoticeLine, singleLine, tagValueSingleLine } from '../../src/lib/outputText';
import { buildIdIndex } from '../../src/lib/spdxExpression';
import { ReportService } from '../../src/reports/reportService';
import { ENRICHMENT_LIMITS } from '../../src/scanner/sandbox/runner.config';
import { generateCycloneDxJson, generateCycloneDxXml } from '../../src/sbom/formats/cyclonedx';
import { generateSpdxJson, generateSpdxTagValue } from '../../src/sbom/formats/spdx';
import type { SbomDependency, SbomScanData } from '../../src/sbom/sbomService';

// Line separators / format characters built from code points (never literal in the source).
const NEL = String.fromCharCode(0x85);
const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);
const ZWSP = String.fromCharCode(0x200b);
/** Any line break a single-line value must not contain (built from code points). */
const ANY_BREAK_RE = new RegExp(`[\\n\\r\\t${NEL}${LS}${PS}]`);
/** Python `str.splitlines()` boundaries. */
const UNICODE_SPLIT_RE = new RegExp(`\\r\\n|[\\n\\r\\v\\f${String.fromCharCode(0x1c, 0x1d, 0x1e)}${NEL}${LS}${PS}]`);
const INHERITED = ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString'];

// ---------------------------------------------------------------------------
// B-2: normalizer recursion
// ---------------------------------------------------------------------------
describe('B-2: license normalizer handles -or-later / -only ids without recursion', () => {
  it('B-2 / AC-P14-1: GPL-3.0-or-later and LGPL-2.1-or-later are atomic known ids (no "Maximum call stack size exceeded")', () => {
    expect(normalizeLicense('GPL-3.0-or-later')).toMatchObject({ spdxId: 'GPL-3.0-or-later', normalized: 'GPL-3.0-or-later', riskLevel: 'high', isSpdxExpression: false });
    expect(normalizeLicense('LGPL-2.1-or-later')).toMatchObject({ spdxId: 'LGPL-2.1-or-later', riskLevel: 'medium', isSpdxExpression: false });
    expect(normalizeLicense('  GPL-3.0-or-later  ')).toMatchObject({ spdxId: 'GPL-3.0-or-later', isSpdxExpression: false });
    expect(normalizeLicense('gpl-3.0-or-later')).toMatchObject({ spdxId: 'GPL-3.0-or-later', riskLevel: 'high' }); // alias (case-insensitive)
  });

  it('B-2: *-only ids stay atomic', () => {
    expect(normalizeLicense('GPL-2.0-only')).toMatchObject({ spdxId: 'GPL-2.0-only', riskLevel: 'high', isSpdxExpression: false });
    expect(normalizeLicense('GPL-3.0-only')).toMatchObject({ spdxId: 'GPL-3.0-only', riskLevel: 'high', isSpdxExpression: false });
    expect(normalizeLicense('LGPL-2.1-only')).toMatchObject({ spdxId: 'LGPL-2.1-only', riskLevel: 'medium', isSpdxExpression: false });
  });

  it('B-2: (MIT OR GPL-3.0-or-later) -> expression, OR picks the lower risk; AND picks the higher', () => {
    expect(normalizeLicense('(MIT OR GPL-3.0-or-later)')).toMatchObject({ spdxId: 'MIT', riskLevel: 'safe', isSpdxExpression: true, normalized: '(MIT OR GPL-3.0-or-later)' });
    expect(normalizeLicense('GPL-3.0-or-later AND MIT')).toMatchObject({ spdxId: 'GPL-3.0-or-later', riskLevel: 'high', isSpdxExpression: true });
    expect(normalizeLicense('LGPL-2.1-or-later OR GPL-3.0-or-later')).toMatchObject({ riskLevel: 'medium', isSpdxExpression: true });
  });

  it('B-2: Apache-2.0 WITH LLVM-exception keeps the base license risk', () => {
    expect(normalizeLicense('Apache-2.0 WITH LLVM-exception')).toMatchObject({ spdxId: 'Apache-2.0', riskLevel: 'safe', isSpdxExpression: true, normalized: 'Apache-2.0 WITH LLVM-exception' });
    expect(normalizeLicense('GPL-2.0-or-later WITH Classpath-exception-2.0')).toMatchObject({ isSpdxExpression: true });
  });

  it('B-2: canonicalSpdx / isRecognizedLicense accept the -or-later ids and expressions over them', () => {
    expect(canonicalSpdx('GPL-3.0-or-later')).toBe('GPL-3.0-or-later');
    expect(canonicalSpdx('(MIT OR GPL-3.0-or-later)')).toBe('(MIT OR GPL-3.0-or-later)'); // canonical form keeps the parentheses
    expect(canonicalSpdx('mit or gpl-3.0-or-later')).toBe('MIT OR GPL-3.0-or-later');
    expect(isRecognizedLicense('GPL-3.0-or-later')).toBe(true);
    expect(isRecognizedLicense('LGPL-2.1-or-later')).toBe(true);
    expect(isRecognizedLicense('(MIT OR GPL-3.0-or-later)')).toBe(true);
  });

  it('B-2: operator-like substrings that are not whitespace-delimited never throw (deterministic fuzz, 5000 inputs)', () => {
    const parts = ['MIT', 'OR', 'AND', 'WITH', '-or-', '-and-', '-with-', '(', ')', 'GPL-3.0-or-later', 'x-or-later', ' ', '\t', 'or', 'with'];
    let seed = 0x2b2b;
    const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
    for (let i = 0; i < 5000; i++) {
      const n = 1 + (next() % 8);
      let s = '';
      for (let k = 0; k < n; k++) s += parts[next() % parts.length];
      expect(() => normalizeLicense(s), JSON.stringify(s)).not.toThrow();
      expect(() => isRecognizedLicense(s), JSON.stringify(s)).not.toThrow();
      expect(() => canonicalSpdx(s), JSON.stringify(s)).not.toThrow();
    }
    for (const s of ['MIT-or-later', 'foo-and-bar', 'x-with-y', 'OR', ' OR ', '( OR )', '(GPL-3.0-or-later)', 'MIT OR', 'OR MIT', `${'MIT OR '.repeat(5000)}MIT`]) {
      expect(() => normalizeLicense(s), s.slice(0, 40)).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// L-3: inherited keys
// ---------------------------------------------------------------------------
describe('L-3: inherited object keys are not licenses', () => {
  it('SEC L-3: constructor / toString / __proto__ / hasOwnProperty / … -> spdxId null, riskLevel "unknown" (a string), not recognized', () => {
    for (const k of [...INHERITED, 'Constructor', 'TOSTRING']) {
      const r = normalizeLicense(k);
      expect(r.spdxId, k).toBeNull();
      expect(r.riskLevel, k).toBe('unknown');
      expect(typeof r.normalized, k).toBe('string');
      expect(evaluateLicenseRisk(k), k).toBe('unknown');
      expect(isRecognizedLicense(k), k).toBe(false);
      expect(canonicalSpdx(k), k).toBeNull();
    }
  });

  it('SEC L-3: inherited keys inside expressions count as unknown (AND -> unknown, OR -> the known side)', () => {
    expect(normalizeLicense('MIT AND constructor').riskLevel).toBe('unknown');
    expect(normalizeLicense('MIT OR __proto__')).toMatchObject({ spdxId: 'MIT', riskLevel: 'safe' });
    expect(normalizeLicense('toString WITH LLVM-exception')).toMatchObject({ spdxId: null, riskLevel: 'unknown' });
    expect(isRecognizedLicense('MIT AND constructor')).toBe(false);
  });

  it('SEC L-3: trove classifier "License :: constructor" is a raw term (string), never a function-valued mapping', () => {
    for (const k of INHERITED) {
      expect(classifierTerm(`License :: ${k}`), k).toEqual({ kind: 'raw', text: k });
      expect(classifierTerm(`License :: OSI Approved :: ${k}`), k).toEqual({ kind: 'raw', text: k });
      expect(licenseFromClassifiers([`License :: ${k}`]), k).toBe(k);
    }
  });

  it('SEC L-3: CycloneDX scope map — scope "constructor" & co. give no scope (JSON and XML), no function source in the output', () => {
    const d = sbomData(INHERITED.map((s, i) => dep(`scope-${i}`, { scope: s as SbomDependency['scope'] })));
    const json = JSON.parse(generateCycloneDxJson(d)) as { components: Array<{ name: string; scope?: unknown }> };
    for (const c of json.components) expect(c.scope, c.name).toBeUndefined();
    const xml = generateCycloneDxXml(d);
    expect(xml).not.toMatch(/function|native code|\[object/i);
    const doc = new new JSDOM('').window.DOMParser().parseFromString(xml, 'application/xml');
    expect(doc.getElementsByTagName('parsererror')).toHaveLength(0);
    expect(doc.getElementsByTagName('components')[0].getElementsByTagName('scope')).toHaveLength(0);
    // Positive control: real scopes still map.
    const ok = JSON.parse(generateCycloneDxJson(sbomData([dep('rt', { scope: 'direct' }), dep('dv', { scope: 'dev' })]))) as { components: Array<{ name: string; scope?: string }> };
    expect(ok.components.find((c) => c.name === 'rt')?.scope).toBe('required');
  });
});

// ---------------------------------------------------------------------------
// I-3: Unicode line separators
// ---------------------------------------------------------------------------
describe('I-3: U+0085 / U+2028 / U+2029 in single-line values and the NOTICE shield', () => {
  it('SEC I-3 / contract 9 step 3: U+2028 and U+2029 each become one space; U+0085 is removed (step 2); no line break survives', () => {
    expect(singleLine(`a${LS}b${PS}c`)).toBe('a b c');
    expect(singleLine(`a${LS}${LS}b`)).toBe('a  b'); // one space per character, runs not collapsed
    expect(singleLine(`a\t${PS}\nb`)).toBe('a   b');
    const nel = singleLine(`a${NEL}b`);
    expect(nel).not.toContain(NEL);
    expect(['ab', 'a b']).toContain(nel);
    for (const v of [singleLine(`x${NEL}${LS}${PS}\r\n\t\ry`), tagValueSingleLine(`x${LS}y`)]) expect(v).not.toMatch(ANY_BREAK_RE);
  });

  it('SEC I-3 / contract 3.6: shield after U+0085 / U+2028 / U+2029 inserts one space after the break; break kept, other bytes unchanged', () => {
    expect(shieldNoticeLine(`abc${LS}${ENTRY_SEP}`)).toBe(`abc${LS} ${ENTRY_SEP}`);
    expect(shieldNoticeLine(`x${PS}${FILE_SEP}tail`)).toBe(`x${PS} ${FILE_SEP}tail`);
    expect(shieldNoticeLine(`${NEL}${ENTRY_SEP}`)).toBe(`${NEL} ${ENTRY_SEP}`);
    expect(shieldNoticeLine(`${ENTRY_SEP}${LS}${FILE_SEP}`)).toBe(` ${ENTRY_SEP}${LS} ${FILE_SEP}`);
    // No separator after the break / a short run of '=' -> unchanged.
    expect(shieldNoticeLine(`abc${LS}${'='.repeat(79)}`)).toBe(`abc${LS}${'='.repeat(79)}`);
    expect(shieldNoticeLine(`abc${LS}def`)).toBe(`abc${LS}def`);
    expect(shieldNoticeLine(`a ${ENTRY_SEP}`)).toBe(`a ${ENTRY_SEP}`);
  });

  it('SEC I-3 / contract 9: multi-line NOTICE text keeps U+2028/U+2029 (no folding) and shields after them; no forged separator line for splitlines()', () => {
    const lines = noticeTextLines(`ok${LS}${ENTRY_SEP}\nnext${PS}${FILE_SEP}\n`);
    expect(lines).toEqual([`ok${LS} ${ENTRY_SEP}`, `next${PS} ${FILE_SEP}`]);
    // A Unicode-aware splitter (Python str.splitlines) sees no line that is exactly a separator.
    const unicodeLines = lines.join('\n').split(UNICODE_SPLIT_RE);
    expect(unicodeLines.filter((l) => l === ENTRY_SEP || l === FILE_SEP)).toEqual([]);
  });

  it('SEC I-3 / contract 9: each copyright line is a single-line value — U+2028 inside a line folds in SPDX JSON, tag-value and CycloneDX', () => {
    const d = sbomData([dep('cr', { licenseExpression: 'MIT', licenseSource: 'registry:npm', copyrightLines: [`Copyright A${LS}B`, `Copyright C${PS}D`] })]);
    const spdx = (JSON.parse(generateSpdxJson(d)) as { packages: Array<{ name: string; copyrightText: string }> }).packages.find((p) => p.name === 'cr')!;
    expect(spdx.copyrightText).toBe('Copyright A B\nCopyright C D');
    expect(generateSpdxTagValue(d)).toContain('PackageCopyrightText: <text>Copyright A B\nCopyright C D</text>\n');
    const cdx = (JSON.parse(generateCycloneDxJson(d)) as { components: Array<{ name: string; copyright?: string }> }).components.find((c) => c.name === 'cr')!;
    expect(cdx.copyright).toBe('Copyright A B\nCopyright C D');
  });
});

// ---------------------------------------------------------------------------
// L-1: tag-value single-line <text> escape
// ---------------------------------------------------------------------------
const KNOWN = buildIdIndex([...KNOWN_SPDX_IDS]);

function dep(name: string, o: Partial<SbomDependency> = {}): SbomDependency {
  return {
    id: name, packageId: name, ecosystem: 'nodejs', name, version: '1.0.0', scope: 'direct',
    manifestFile: 'package-lock.json', manifestPath: '.', depth: 0, description: null, homepageUrl: null, author: null,
    licenseExpression: null, licenseSource: 'none', copyrightLines: [], licenses: [], vulnerabilities: [], ...o,
    purl: o.purl ?? `pkg:npm/${encodeURIComponent(name)}@1.0.0`,
  };
}

function sbomData(dependencies: SbomDependency[]): SbomScanData {
  return {
    scan: { id: '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f', ref: 'main', completedAt: new Date(0), createdAt: new Date(0), totalDependencies: dependencies.length },
    project: { id: '11111111-2222-4333-8444-555555555555', name: 'sbom-app', description: null, repoUrl: null },
    dependencies,
    knownLicenseIds: KNOWN,
  };
}

describe('L-1: SPDX tag-value single-line values never open or close a <text> block (contract 6.1, 1.1.0)', () => {
  it('SEC L-1 / C-14: tagValueSingleLine escapes <text>/</text> anywhere, any case, output lower case; other < > & untouched; runs after folding', () => {
    expect(tagValueSingleLine('a<text>b</text>c')).toBe('a&lt;text&gt;b&lt;/text&gt;c');
    expect(tagValueSingleLine('<TEXT></Text><tExT>')).toBe('&lt;text&gt;&lt;/text&gt;&lt;text&gt;');
    expect(tagValueSingleLine(`<te${ZWSP}xt>x</te${ZWSP}xt>`)).toBe('&lt;text&gt;x&lt;/text&gt;'); // formed by removed format chars
    expect(tagValueSingleLine('a<b&c>d <texts> </ text>')).toBe('a<b&c>d <texts> </ text>');
    expect(tagValueSingleLine('x\n<text>')).toBe('x &lt;text&gt;');
  });

  it('SEC L-1: every single-line field (DocumentName, Creator, PackageName, PackageVersion, download location, ExternalRef, PackageSupplier, PackageHomePage, LicenseDeclared) is escaped; only real blocks keep <text>', () => {
    const evil = `e<text>v</TEXT>i<te${ZWSP}xt>l`;
    const esc = 'e&lt;text&gt;v&lt;/text&gt;i&lt;text&gt;l';
    const d = sbomData([dep(evil, {
      version: `1<text>`, homepageUrl: `https://h.example/${evil}`, author: evil, purl: `pkg:npm/x@1?q=${evil}`,
      licenseExpression: `MIT <text>`, licenseSource: 'registry:npm', copyrightLines: [`(c) ${evil}`],
    })]);
    d.project.name = evil;
    d.project.repoUrl = `https://r.example/${evil}`;
    d.scan.ref = `ref</text>`;
    const tv = generateSpdxTagValue(d);
    const lines = tv.split('\n');
    expect(lines).toContain(`DocumentName: SBOM-${esc}-${d.scan.id}`);
    expect(lines).toContain(`Creator: Organization: ${esc}`);
    expect(lines).toContain(`PackageName: ${esc}`);
    expect(lines).toContain('PackageVersion: ref&lt;/text&gt;');
    expect(lines).toContain(`PackageDownloadLocation: https://r.example/${esc}`);
    expect(lines).toContain('PackageVersion: 1&lt;text&gt;');
    expect(lines).toContain(`PackageDownloadLocation: https://h.example/${esc}`);
    expect(lines).toContain(`PackageHomePage: https://h.example/${esc}`);
    expect(lines).toContain(`PackageSupplier: Organization: ${esc}`);
    expect(lines).toContain(`ExternalRef: PACKAGE-MANAGER purl pkg:npm/x@1?q=${esc}`);
    expect(lines.find((l) => l.startsWith('PackageLicenseDeclared: ') && l !== 'PackageLicenseDeclared: NOASSERTION')).toBeUndefined();
    // Remove the outer tags of the legitimate blocks: nothing else may contain a raw <text>/</text>.
    const blockFields = lines.filter((l) => /^[A-Za-z]+: <text>/.test(l)).map((l) => l.split(':')[0]);
    expect(blockFields.sort()).toEqual(['PackageCopyrightText', 'PackageLicenseComments']);
    const stripped = lines.map((l) => l.replace(/^(PackageLicenseComments|PackageCopyrightText): <text>(.*)<\/text>$/, '$1: $2'));
    expect(stripped.filter((l) => /<\/?text>/i.test(l))).toEqual([]);
    expect(lines.filter((l) => l.startsWith('PackageName: '))).toHaveLength(2);
    expect(lines.filter((l) => l.startsWith('Relationship: '))).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// L-2: Excel guard on every sheet (fake pool -> real renderer -> xlsx read back)
// ---------------------------------------------------------------------------
type ReportInternals = {
  loadReportData(scanId: string): Promise<unknown>;
  renderContent(data: unknown, reportType: string, format: string): Promise<Buffer>;
};

function reportPool(): Pool {
  const scanRow = {
    id: 'scan-l2', ref: '-ref', trigger: 'manual', completed_at: new Date('2026-10-10T08:00:00Z'), created_at: new Date('2026-10-10T07:00:00Z'),
    total_dependencies: 1, total_vulnerabilities: 1, critical_vulns: 0, high_vulns: 1, medium_vulns: 0, low_vulns: 0, license_violations: 1,
    project_id: 'proj-l2', project_name: '=cmd|calc', project_description: null, project_criticality: 'medium', repo_url: '+https://r.example',
  };
  const depRow = {
    scan_dependency_id: 'sd1', ecosystem: 'nodejs', name: '@evil', version: '\tv1', purl: '-pkg:npm/evil@1', scope: 'direct',
    manifest_file: 'package.json', manifest_path: '=HYPERLINK("x")', depth: 3,
    license_expression: '=L', license_source: 'registry:npm', license_lock_hint: null, license_hint_differs: null, license_enrichment_status: 'ok',
  };
  const plainDep = { ...depRow, scan_dependency_id: 'sd2', name: ' =plain', version: "'1.0", purl: 'pkg:npm/plain@1', manifest_path: 'x/package.json', depth: 0, license_expression: 'MIT' };
  const licRow = { scan_dependency_id: 'sd1', detected_license: '=D', normalized_license: '+N', risk_level: 'unknown', applied_policy: null, status: 'open', suppressed: false };
  const vulnRow = {
    scan_dependency_id: 'sd1', advisory_id: '@A-1', title: '\rTitle', severity: 'high', cvss_score: '7.5', fix_version: '-1.0.1',
    fix_available: true, status: 'open', suppressed: false, published_at: null,
  };
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('FROM scans s')) return { rows: [scanRow] };
    if (sql.includes('FROM scan_dependencies sd')) return { rows: [depRow, plainDep] };
    if (sql.includes('license_findings')) return { rows: [licRow] };
    if (sql.includes('security_findings')) return { rows: [vulnRow] };
    throw new Error(`unexpected query: ${sql.slice(0, 60)}`);
  });
  return { query } as unknown as Pool;
}

describe('L-2: Excel formula guard on every string cell of every sheet (contract 5.1a, 1.1.0)', () => {
  it("SEC L-2 / C-15: = + - @ \\t \\r prefixed with ' on Summary, Dependencies, Licenses, Vulnerabilities; numbers stay numbers; non-triggers unchanged", async () => {
    const svc = new ReportService(reportPool()) as unknown as ReportInternals;
    const buf = await svc.renderContent(await svc.loadReportData('scan-l2'), 'project_report', 'excel');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(buf as unknown as ArrayBuffer);
    expect(wb.worksheets.map((w) => w.name)).toEqual(['Summary', 'Dependencies', 'Licenses', 'Vulnerabilities']);
    const row = (sheet: string, n: number) => ((wb.getWorksheet(sheet)!.getRow(n).values as unknown[]).slice(1)).map((v) => v ?? '');

    const summary = new Map<string, unknown>();
    for (let i = 2; i <= wb.getWorksheet('Summary')!.rowCount; i++) { const [k, v] = row('Summary', i); summary.set(String(k), v); }
    expect(summary.get('Project')).toBe("'=cmd|calc");
    expect(summary.get('Repository')).toBe("'+https://r.example");
    expect(summary.get('Reference')).toBe("'-ref");
    expect(summary.get('Scan ID')).toBe('scan-l2');
    expect(summary.get('Completed At')).toBe('2026-10-10T08:00:00.000Z');
    for (const k of ['Total Dependencies', 'Total Vulnerabilities', 'High Vulnerabilities', 'License Violations']) expect(typeof summary.get(k), k).toBe('number');

    const deps = new Map<string, unknown[]>();
    for (let i = 2; i <= wb.getWorksheet('Dependencies')!.rowCount; i++) deps.set(String(row('Dependencies', i)[6]), row('Dependencies', i));
    expect(deps.get("'-pkg:npm/evil@1")).toEqual(["'@evil", "'\tv1", 'nodejs', 'direct', `'=HYPERLINK("x")`, 3, "'-pkg:npm/evil@1", "'=L", 'registry:npm']);
    expect(deps.get('pkg:npm/plain@1')).toEqual([' =plain', "'1.0", 'nodejs', 'direct', 'x/package.json', 0, 'pkg:npm/plain@1', 'MIT', 'registry:npm']);

    expect(row('Licenses', 2)).toEqual(["'@evil", "'\tv1", "'=D", "'+N", 'unknown', '', 'open', 'no']);

    const v = row('Vulnerabilities', 2);
    expect(v.slice(0, 3)).toEqual(["'@evil", "'\tv1", "'@A-1"]);
    // XML normalizes a raw CR in text to LF on read-back; the guard prefix is what matters.
    expect(String(v[3])).toMatch(/^'[\r\n]Title$/);
    expect(v.slice(4)).toEqual(['high', 7.5, "'-1.0.1", 'yes', 'open', 'no', 'n/a']);

    // Never a formula cell anywhere.
    for (const ws of wb.worksheets) ws.eachRow((r) => r.eachCell((c) => expect(c.type, `${ws.name}!${c.address}`).not.toBe(ExcelJS.ValueType.Formula)));
  });
});

// ---------------------------------------------------------------------------
// L-4: in-flight byte budget
// ---------------------------------------------------------------------------
const tick = () => new Promise<void>((r) => setImmediate(r));
/** Settles sync throws and rejections alike. */
const attempt = <T>(fn: () => Promise<T>) => Promise.resolve().then(fn);

describe('L-4: InFlightByteBudget (process-wide archive bytes in memory)', () => {
  it('SEC L-4: grants immediately while it fits; FIFO — a small later request does not overtake a waiting larger one', async () => {
    const b = new InFlightByteBudget(10);
    const order: string[] = [];
    const ra = await b.acquire(6);
    expect(b.inUse).toBe(6);
    const pb = b.acquire(6).then((r) => { order.push('b'); return r; });
    const pc = b.acquire(1).then((r) => { order.push('c'); return r; }); // would fit (7 <= 10) but must queue behind b
    await tick();
    expect(order).toEqual([]);
    expect(b.inUse).toBe(6);
    ra();
    const [rb, rc] = await Promise.all([pb, pc]);
    expect(order).toEqual(['b', 'c']);
    expect(b.inUse).toBe(7);
    rb(); rc();
    expect(b.inUse).toBe(0);
  });

  it('SEC L-4: abort while waiting rejects with the signal reason, leaves the queue, lets later waiters proceed; pre-aborted signal rejects at once', async () => {
    const b = new InFlightByteBudget(10);
    const ra = await b.acquire(6);
    const ac = new AbortController();
    const pb = b.acquire(6, ac.signal);
    let cGranted = false;
    const pc = b.acquire(4).then((r) => { cGranted = true; return r; });
    await tick();
    expect(cGranted).toBe(false);
    const reason = new Error('budget');
    ac.abort(reason);
    await expect(pb).rejects.toBe(reason);
    const rc = await pc; // 6 + 4 <= 10 once b left the queue
    expect(cGranted).toBe(true);
    expect(b.inUse).toBe(10);
    ra(); rc();
    expect(b.inUse).toBe(0);
    const pre = AbortSignal.abort(new Error('pre'));
    await expect(attempt(() => b.acquire(1, pre))).rejects.toThrow('pre');
    expect(b.inUse).toBe(0);
  });

  it('SEC L-4: release is idempotent — a double release never frees bytes held by someone else', async () => {
    const b = new InFlightByteBudget(10);
    const ra = await b.acquire(4);
    const rb = await b.acquire(4);
    ra(); ra(); ra();
    expect(b.inUse).toBe(4);
    let granted = false;
    void b.acquire(7).then(() => { granted = true; });
    await tick();
    expect(granted).toBe(false); // 4 + 7 > 10: the repeated release did not free rb's bytes
    rb(); rb();
    await tick();
    expect(granted).toBe(true);
    expect(b.inUse).toBe(7);
  });

  it('SEC L-4: an oversize request is clamped to the limit (proceeds alone, no deadlock); negative -> 0, fractional rounded up; grow adds without waiting', async () => {
    const b = new InFlightByteBudget(10);
    const big = await b.acquire(1_000);
    expect(b.inUse).toBe(10);
    let small = false;
    const ps = b.acquire(1).then((r) => { small = true; return r; });
    await tick();
    expect(small).toBe(false);
    big();
    const rs = await ps;
    expect(b.inUse).toBe(1);
    rs();
    const neg = await b.acquire(-5);
    expect(b.inUse).toBe(0);
    neg();
    const frac = await b.acquire(2.1);
    expect(b.inUse).toBe(3);
    const g = b.grow(20); // may exceed the limit: accounted, never waits
    expect(b.inUse).toBe(23);
    g(); g();
    frac();
    expect(b.inUse).toBe(0);
  });

  it('SEC L-4: processInFlightBudget is one process-wide instance of 256 MiB', () => {
    expect(ENRICHMENT_LIMITS.archive.processInFlightBytes).toBe(256 * 1024 * 1024);
    const a = processInFlightBudget(ENRICHMENT_LIMITS.archive.processInFlightBytes);
    expect(processInFlightBudget(1)).toBe(a);
    expect(a.limitBytes).toBe(256 * 1024 * 1024);
  });
});

describe('L-4: archive stage holds the budget from before the download until the archive is done', () => {
  const candidate = (size: number | null, url = 'http://127.0.0.1:9/pkg/-/pkg-1.0.0.tgz'): ArchiveCandidate => ({ url, algorithm: 'sha512', digests: ['ZGlnZXN0'], size, filename: null });
  const task = (name: string, size: number | null) => ({ ecosystem: 'npm' as const, requestName: name, version: '1.0.0', candidates: [candidate(size, `http://127.0.0.1:9/${name}/-/${name}-1.0.0.tgz`)] });

  function ctx(over: Partial<ArchiveStageContext> & { getArchive: (url: string) => Promise<unknown> }): ArchiveStageContext {
    const { getArchive, ...rest } = over;
    return {
      session: { isHostClosed: () => false, getArchive } as unknown as ArchiveStageContext['session'],
      db: {} as ArchiveStageContext['db'],
      signal: new AbortController().signal,
      cached: new Map(),
      quota: new DownloadQuota(10 * 1024 * 1024 * 1024),
      threadOptions: {} as ArchiveStageContext['threadOptions'],
      runThread: vi.fn(async () => { throw new Error('thread must not run in these tests'); }),
      warn: vi.fn(),
      ...rest,
    };
  }

  it('SEC L-4: two downloads of limit size are serialized (second download starts only after the first released); inUse back to 0', async () => {
    const inFlight = new InFlightByteBudget(100);
    const started: string[] = [];
    let finishFirst!: () => void;
    const first = new Promise<void>((r) => { finishFirst = r; });
    const c = ctx({
      inFlight,
      getArchive: async (url: string) => {
        started.push(url);
        if (url.includes('/a/')) await first;
        return { kind: 'download_failed', code: 'http_status' };
      },
    });
    const pa = collectArchive(task('a', 100), c);
    const pb = collectArchive(task('b', 100), c);
    await tick();
    expect(started).toHaveLength(1);
    expect(inFlight.inUse).toBe(100);
    finishFirst();
    expect(await pa).toEqual({ noticeStatus: 'download_failed', archiveId: null });
    expect(await pb).toEqual({ noticeStatus: 'download_failed', archiveId: null });
    expect(started).toHaveLength(2);
    expect(inFlight.inUse).toBe(0);
  });

  it('SEC L-4: quota refusal, integrity failure with a body larger than declared (grow) and unknown size all release everything', async () => {
    const inFlight = new InFlightByteBudget(ENRICHMENT_LIMITS.client.archiveMaxBytes * 2);
    const refused = await collectArchive(task('q', 10), ctx({ inFlight, quota: new DownloadQuota(0), getArchive: async () => { throw new Error('no download'); } }));
    expect(refused.noticeStatus).toBe('limit_exceeded');
    expect(inFlight.inUse).toBe(0);

    let during = -1;
    const grown = await collectArchive(task('g', 100), ctx({
      inFlight,
      getArchive: async () => { during = inFlight.inUse; return { kind: 'ok', body: Buffer.alloc(150), size: 150, digest: 'bm90LXRoZS1kaWdlc3Q=' }; },
    }));
    expect(during).toBe(100);
    expect(grown.noticeStatus).toBe('integrity_failed');
    expect(inFlight.inUse).toBe(0);

    const unknown = await collectArchive(task('u', null), ctx({ inFlight, getArchive: async () => { during = inFlight.inUse; return { kind: 'limit_exceeded', code: 'archive_size' }; } }));
    expect(during).toBe(ENRICHMENT_LIMITS.client.archiveMaxBytes); // unknown size reserves the per-archive cap
    expect(unknown.noticeStatus).toBe('limit_exceeded');
    expect(inFlight.inUse).toBe(0);
  });

  it('SEC L-4: a waiting archive stage aborts with the enrichment signal; it never downloads and holds nothing', async () => {
    const inFlight = new InFlightByteBudget(100);
    const hold = await inFlight.acquire(100);
    const ac = new AbortController();
    const getArchive = vi.fn(async () => ({ kind: 'download_failed', code: 'http_status' }));
    const p = collectArchive(task('w', 50), ctx({ inFlight, signal: ac.signal, getArchive }));
    await tick();
    const reason = new Error('enrichment budget');
    ac.abort(reason);
    await expect(p).rejects.toBe(reason);
    expect(getArchive).not.toHaveBeenCalled();
    hold();
    expect(inFlight.inUse).toBe(0);
  });
});
