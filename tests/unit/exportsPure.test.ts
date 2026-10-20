/**
 * REQ-007 · P-24 pure pieces of the one-click exports (contract
 * `docs/contracts/REQ-007-cli-and-exports.md` sections 6.6 and 7; REQ-004
 * contract 1.5.0 sections 5.3 and 5.4):
 *   AC-P24-5 / AC-P24-6  shared row builder + CSV serialiser, byte golden
 *   AC-P24-7             ExportLimiter (2 slots, idempotent release)
 *   AC-P24-10            V-12 value table (five values)
 *   AC-P24-11            truncation note text
 * The golden CSV below is hand-written from contract section 7, not captured
 * from the implementation.
 */
import { describe, expect, it } from 'vitest';
import { csvField, toCsv } from '../../src/reports/csv';
import { EXPORT_CONCURRENCY_LIMIT, EXPORT_RETRY_AFTER_SECONDS, ExportLimiter } from '../../src/reports/exportLimiter';
import {
  DEPENDENCY_HEADERS,
  type ReportDependency,
  dependencyRowCells,
  vulnerabilityDataStatusText,
} from '../../src/reports/reportService';
import { pdfTruncationNoteTr } from '../../src/reports/dependencyPdf';

const EMOJI = String.fromCodePoint(0x1f600);

function dep(over: Partial<ReportDependency>): ReportDependency {
  return {
    id: 'x', ecosystem: 'nodejs', name: 'n', version: '1.0.0', purl: 'pkg:npm/n@1.0.0', scope: 'direct',
    manifestFile: 'package-lock.json', manifestPath: '.', depth: 0,
    licenseExpression: 'MIT', licenseSource: 'registry:npm', licenseLockHint: null, licenseHintDiffers: null,
    licenseEnrichmentStatus: 'ok', lockIntegrity: null, licenseUnclassified: null, licenses: [], vulnerabilities: [],
    ...over,
  };
}

describe('AC-P24-6: csvField (RFC 4180 quoting, contract section 7)', () => {
  it.each([
    ['plain', 'plain'],
    ['a,b', '"a,b"'],
    ['say "hi"', '"say ""hi"""'],
    ['line\nbreak', '"line\nbreak"'],
    ['cr\rhere', '"cr\rhere"'],
    [' lead', '" lead"'],
    ['trail ', '"trail "'],
    ['\tlead-tab', '"\tlead-tab"'],
    ['in ner', 'in ner'],
    ['', ''],
  ])('%j -> %j', (input, expected) => {
    expect(csvField(input)).toBe(expected);
  });

  it('null / undefined -> empty field; a number -> plain integer text', () => {
    expect(csvField(null)).toBe('');
    expect(csvField(undefined)).toBe('');
    expect(csvField(3)).toBe('3');
    expect(csvField(0)).toBe('0');
  });

  it('a dependency-free table is BOM + header + CRLF', () => {
    const out = toCsv([DEPENDENCY_HEADERS]);
    expect([...out.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    expect(out.subarray(3).toString('utf8')).toBe('Name,Version,Ecosystem,Scope,Manifest,Depth,PURL,License,License Source\r\n');
  });
});

describe('AC-P24-5 / AC-P24-6: shared row builder + CSV golden (byte for byte)', () => {
  it('special characters (comma, quote, newline, =cmd, -1, @, tab, Turkish, emoji, edge space) -> expected bytes', () => {
    const deps = [
      dep({ name: 'a,b', purl: 'pkg:npm/a%2Cb@1.0.0' }),
      dep({ name: 'say"hi"', version: '=cmd', manifestPath: 'sub\ndir', depth: 2, licenseExpression: '-1', licenseSource: null }),
      dep({ name: 'çğışöü', version: `1.0.0-${EMOJI}`, scope: 'dev', licenseExpression: ' MIT ', purl: 'pkg:npm/x@1' }),
      dep({ name: '@scope/pkg', manifestPath: '', licenseExpression: 'MIT\nOR Apache-2.0', depth: 10, purl: '+p' }),
      dep({ name: '\tx', licenseExpression: null, licenseSource: 'none', licenseEnrichmentStatus: 'no_license', licenseLockHint: 'ISC' }),
    ];
    const expected = [
      'Name,Version,Ecosystem,Scope,Manifest,Depth,PURL,License,License Source',
      '"a,b",1.0.0,nodejs,direct,.,0,pkg:npm/a%2Cb@1.0.0,MIT,registry:npm',
      '"say""hi""",\'=cmd,nodejs,direct,"sub\ndir",2,pkg:npm/n@1.0.0,\'-1,',
      `çğışöü,1.0.0-${EMOJI},nodejs,dev,.,0,pkg:npm/x@1," MIT ",registry:npm`,
      "'@scope/pkg,1.0.0,nodejs,direct,package-lock.json,10,'+p,MIT OR Apache-2.0,registry:npm",
      "'\tx,1.0.0,nodejs,direct,.,0,pkg:npm/n@1.0.0,,none (lockfile hint ignored: ISC)",
    ].map((l) => `${l}\r\n`).join('');
    const out = toCsv([DEPENDENCY_HEADERS, ...deps.map(dependencyRowCells)]);
    expect(out.subarray(3).toString('utf8')).toBe(expected);
    expect(out.equals(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(expected, 'utf8')]))).toBe(true);
    // deterministic: same input, same bytes
    expect(toCsv([DEPENDENCY_HEADERS, ...deps.map(dependencyRowCells)]).equals(out)).toBe(true);
  });

  it('row builder: Depth stays a number; the formula guard is applied once (no double prefix in CSV)', () => {
    const cells = dependencyRowCells(dep({ name: '=x', depth: 7 }));
    expect(cells[5]).toBe(7);
    expect(cells[0]).toBe("'=x");
    expect(toCsv([cells]).subarray(3).toString('utf8').startsWith("'=x,")).toBe(true);
  });
});

describe('AC-P24-7: ExportLimiter (contract 6.6)', () => {
  it('2 slots; the third acquire is refused; release frees a slot; release is idempotent', () => {
    expect(EXPORT_CONCURRENCY_LIMIT).toBe(2);
    expect(EXPORT_RETRY_AFTER_SECONDS).toBe(5);
    const l = new ExportLimiter();
    const a = l.tryAcquire();
    const b = l.tryAcquire();
    expect(a).toBeTypeOf('function');
    expect(b).toBeTypeOf('function');
    expect(l.inUse).toBe(2);
    expect(l.tryAcquire()).toBeNull();
    a!();
    a!();
    expect(l.inUse).toBe(1);
    const c = l.tryAcquire();
    expect(c).toBeTypeOf('function');
    expect(l.tryAcquire()).toBeNull();
    b!();
    c!();
    expect(l.inUse).toBe(0);
  });

  it('instances do not share state', () => {
    const x = new ExportLimiter();
    x.tryAcquire();
    x.tryAcquire();
    expect(new ExportLimiter().tryAcquire()).toBeTypeOf('function');
  });
});

describe('AC-P24-10: V-12 value table (REQ-004 contract 1.5.0 5.3, C-34)', () => {
  it.each([
    ['complete', 'complete'],
    ['partial', 'partial (some packages could not be checked)'],
    ['unavailable', 'unavailable (vulnerability source unreachable)'],
    ['disabled', 'disabled (lookup turned off)'],
    [null, 'not checked'],
    [undefined, 'not checked'],
    ['bogus', 'not checked'],
    ['toString', 'not checked'],
  ])('%j -> %j', (status, text) => {
    expect(vulnerabilityDataStatusText(status as string | null | undefined)).toBe(text);
  });
});

describe('AC-P24-11: truncation note text (REQ-004 contract 1.6.0 5.4, Turkish since REQ-010)', () => {
  it('exact text, plain integers without grouping', () => {
    expect(pdfTruncationNoteTr(40, 41)).toBe('İlk 40 / 41 kayıt gösteriliyor; tam liste için Excel veya CSV çıktısına bakın.');
    expect(pdfTruncationNoteTr(50, 10000)).toBe('İlk 50 / 10000 kayıt gösteriliyor; tam liste için Excel veya CSV çıktısına bakın.');
  });
});
