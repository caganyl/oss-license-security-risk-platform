/**
 * REQ-003 · P-10 golden equivalence (AC-P10-1, AC-P10-3…9, ADR-005 Karar 2).
 *
 * Every `tests/fixtures/p10-golden/expected/*.json` (frozen Python 3.14.7
 * output, D-26) is compared with `parseManifests` (called directly, ADR-005
 * Karar 5) using the AC-P10-5 rules implemented in `helpers/parserGolden.ts`.
 * `deviation-*` folders are not golden cases; their behaviour is tested in
 * `parsersDeviations.test.ts`.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import type { SandboxScanResult, ScannedDependency } from '../../src/types/scan';
import {
  FORMATS_DIR,
  GOLDEN_DIR,
  errorTextProblems,
  loadGoldenCases,
  matchesGolden,
  normalizeActual,
  normalizeGolden,
  type GoldenCase,
} from '../helpers/parserGolden';

const ECOSYSTEMS = ['nodejs', 'python'];
const cases = loadGoldenCases();
const scanIdOf = (name: string) => `golden-${name}`;

const resultCache = new Map<string, SandboxScanResult>();
function run(c: GoldenCase): SandboxScanResult {
  let result = resultCache.get(c.name);
  if (!result) {
    result = parseManifests(c.rootDir, ECOSYSTEMS, scanIdOf(c.name));
    resultCache.set(c.name, result);
  }
  return result;
}
const byName = (name: string): GoldenCase => {
  const c = cases.find((x) => x.name === name);
  if (!c) throw new Error(`golden case ${name} is missing`);
  return c;
};

describe('P-10 golden set integrity', () => {
  it('AC-P10-4: every non-deviation format folder and both snapshots have exactly one golden file', () => {
    const formatFolders = fs
      .readdirSync(FORMATS_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith('deviation-'))
      .map((e) => `formats/${e.name}`);
    const snapshots = fs
      .readdirSync(GOLDEN_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name.startsWith('snapshot-'))
      .map((e) => e.name);
    expect(cases.map((c) => c.golden.root).sort()).toEqual([...formatFolders, ...snapshots].sort());
    expect(cases.length).toBe(34);
    for (const c of cases) {
      expect(fs.statSync(c.rootDir).isDirectory(), c.name).toBe(true);
      expect(c.golden.total_deps, c.name).toBe(c.golden.dependencies.length);
      expect(
        c.golden.root.split('/').some((segment) => segment.startsWith('deviation-')),
        `${c.name}: root must not be a deviation folder`,
      ).toBe(false);
    }
  });

  it('AC-P10-5: the golden set is not vacuous (dependencies, files and error records are compared)', () => {
    const totals = cases.reduce(
      (acc, c) => ({
        deps: acc.deps + c.golden.dependencies.length,
        files: acc.files + c.golden.scan_files.length,
        errors: acc.errors + c.golden.parse_errors.length,
      }),
      { deps: 0, files: 0, errors: 0 },
    );
    expect(totals.deps).toBeGreaterThan(1000);
    expect(totals.files).toBeGreaterThan(100);
    expect(totals.errors).toBeGreaterThan(20);
  });
});

describe('P-10 golden equivalence (AC-P10-3, AC-P10-4, AC-P10-5, AC-P10-6, AC-P10-7)', () => {
  it.each(cases.map((c) => [c.name, c] as const))('AC-P10-4 / AC-P10-5: %s equals the frozen Python output', (_name, c) => {
    const result = run(c);
    expect(normalizeActual(result)).toStrictEqual(normalizeGolden(c.golden, scanIdOf(c.name)));
    expect(errorTextProblems(result, c.rootDir)).toEqual([]);
    expect(matchesGolden(result, c.golden, scanIdOf(c.name), c.rootDir)).toBe(true);
  });

  it('AC-P10-3 (a): snapshot 1b2b934 yields exactly 219 dependencies (report criterion) and equals its golden', () => {
    const c = byName('snapshot-1b2b934');
    const result = run(c);
    expect(result.total_deps).toBe(219);
    expect(result.dependencies).toHaveLength(219);
    expect(c.golden.total_deps).toBe(219);
    expect(matchesGolden(result, c.golden, scanIdOf(c.name), c.rootDir)).toBe(true);
  });

  it('AC-P10-3 (b): snapshot 73db78b total_deps equals its golden value (496 at golden generation)', () => {
    const c = byName('snapshot-73db78b');
    const result = run(c);
    expect(c.golden.total_deps).toBe(496);
    expect(result.total_deps).toBe(c.golden.total_deps);
    expect(matchesGolden(result, c.golden, scanIdOf(c.name), c.rootDir)).toBe(true);
  });
});

describe('P-10 result shape (AC-P10-1, AC-P10-5, AC-P10-9)', () => {
  it('AC-P10-1: the result has exactly the SandboxScanResult keys; status completed; total_deps = dependencies.length', () => {
    for (const c of cases) {
      const result = run(c);
      expect(Object.keys(result).sort(), c.name).toEqual(
        ['dependencies', 'parse_errors', 'scan_files', 'scan_id', 'status', 'total_deps'].sort(),
      );
      expect(result.status, c.name).toBe('completed');
      expect(result.scan_id, c.name).toBe(scanIdOf(c.name));
      expect(result.total_deps, c.name).toBe(result.dependencies.length);
    }
  });

  it('AC-P10-5: every dependency carries declared_range (possibly null), no vulnerabilities key, no undefined values; licenses only when non-empty and sorted', () => {
    for (const c of cases) {
      for (const dep of run(c).dependencies) {
        const label = `${c.name}: ${dep.name}`;
        expect(Object.prototype.hasOwnProperty.call(dep, 'declared_range'), label).toBe(true);
        expect(dep.declared_range === null || typeof dep.declared_range === 'string', label).toBe(true);
        expect(Object.prototype.hasOwnProperty.call(dep, 'vulnerabilities'), label).toBe(false);
        expect(Object.values(dep).includes(undefined), label).toBe(false);
        if (Object.prototype.hasOwnProperty.call(dep, 'licenses')) {
          expect(dep.licenses!.length, label).toBeGreaterThan(0);
          expect(new Set(dep.licenses).size, label).toBe(dep.licenses!.length);
        }
      }
    }
  });

  it("AC-P10-9: file_path and manifest_path use '/' separators; a root manifest has manifest_path '.'", () => {
    let rootManifests = 0;
    for (const c of cases) {
      const result = run(c);
      for (const f of result.scan_files) expect(f.file_path, c.name).not.toContain('\\');
      for (const d of result.dependencies) {
        expect(d.manifest_path, c.name).not.toContain('\\');
        expect(d.manifest_path, c.name).not.toBe('');
        if (d.manifest_path === '.') rootManifests++;
      }
      for (const e of result.parse_errors) expect(e.file, c.name).not.toContain('\\');
    }
    expect(rootManifests).toBeGreaterThan(0);
    const nested = run(byName('unicode-path')).dependencies.map((d) => d.manifest_path);
    expect(nested.some((p) => p.includes('/'))).toBe(true);
  });

  it('AC-P10-8: CRLF yarn.lock and requirements.txt give the same dependency list as their LF twins; hash/size differ', () => {
    const depsOf = (name: string) => normalizeActual(run(byName(name))).dependencies;
    const filesOf = (name: string) => run(byName(name)).scan_files;
    for (const [lf, crlf] of [
      ['npm-yarn-v1-basic', 'npm-yarn-v1-crlf'],
      ['py-requirements-basic', 'py-requirements-crlf'],
    ] as const) {
      expect(depsOf(crlf)).toStrictEqual(depsOf(lf));
      expect(depsOf(lf).length).toBeGreaterThan(0);
      const lfLocks = filesOf(lf).filter((f) => f.filename !== 'package.json');
      const crlfLocks = filesOf(crlf).filter((f) => f.filename !== 'package.json');
      expect(crlfLocks.map((f) => f.file_hash)).not.toEqual(lfLocks.map((f) => f.file_hash));
      expect(crlfLocks.map((f) => f.size_bytes)).not.toEqual(lfLocks.map((f) => f.size_bytes));
    }
  });
});

// ---------------------------------------------------------------------------
// Negative control: the comparator must reject every kind of difference.
// ---------------------------------------------------------------------------
describe('P-10 golden comparator negative control (AC-P10-5)', () => {
  const c = byName('npm-errors');
  const scanId = scanIdOf(c.name);
  const fresh = (): SandboxScanResult => JSON.parse(JSON.stringify(run(c))) as SandboxScanResult;
  const firstDep = (r: SandboxScanResult): ScannedDependency => r.dependencies[0];

  it('baseline: the unmodified result matches', () => {
    expect(c.golden.dependencies.length).toBeGreaterThan(0);
    expect(c.golden.parse_errors.length).toBeGreaterThan(0);
    expect(matchesGolden(fresh(), c.golden, scanId, c.rootDir)).toBe(true);
  });

  it('a reordered result still matches (order independence is intended)', () => {
    const r = fresh();
    r.dependencies.reverse();
    r.scan_files.reverse();
    r.parse_errors.reverse();
    expect(matchesGolden(r, c.golden, scanId, c.rootDir)).toBe(true);
  });

  const mutations: Array<[string, (r: SandboxScanResult) => void]> = [
    ['changed purl', (r) => void (firstDep(r).purl += 'x')],
    ['changed scope', (r) => void (firstDep(r).scope = firstDep(r).scope === 'dev' ? 'direct' : 'dev')],
    ['missing declared_range key', (r) => void delete firstDep(r).declared_range],
    ['changed declared_range', (r) => void (firstDep(r).declared_range = 'zzz')],
    ['declared_range null instead of a value', (r) => void (r.dependencies.find((d) => d.declared_range !== null)!.declared_range = null)],
    ['extra licenses key', (r) => void (firstDep(r).licenses = ['MIT'])],
    ['dropped dependency', (r) => void r.dependencies.pop()],
    ['duplicated dependency', (r) => void r.dependencies.push({ ...firstDep(r) })],
    ['dropped scan file', (r) => void r.scan_files.pop()],
    ['changed file hash', (r) => void (r.scan_files[0].file_hash = '0'.repeat(64))],
    ['changed size_bytes', (r) => void (r.scan_files[0].size_bytes += 1)],
    ['changed parse_errors file', (r) => void (r.parse_errors[0].file = 'elsewhere/package.json')],
    ['changed parse_errors ecosystem', (r) => void (r.parse_errors[0].ecosystem = 'python')],
    ['dropped parse error', (r) => void r.parse_errors.pop()],
    ['empty error text', (r) => void (r.parse_errors[0].error = '  ')],
    ['absolute root path in error text', (r) => void (r.parse_errors[0].error = `failed: ${c.rootDir}`)],
    [
      'absolute root path (forward slashes) in error text',
      (r) => void (r.parse_errors[0].error = `failed: ${c.rootDir.replace(/\\/g, '/')}`),
    ],
    ['total_deps off by one', (r) => void (r.total_deps += 1)],
    ['other scan_id', (r) => void (r.scan_id = 'other')],
    ['failed status', (r) => void (r.status = 'failed')],
  ];

  it.each(mutations)('rejects: %s', (_label, mutate) => {
    const r = fresh();
    mutate(r);
    expect(matchesGolden(r, c.golden, scanId, c.rootDir)).toBe(false);
  });

  it('rejects a different golden case (the comparison is not vacuous across fixtures)', () => {
    const other = byName('npm-lock-v2');
    expect(matchesGolden(fresh(), other.golden, scanId, c.rootDir)).toBe(false);
  });

  it('error texts of the golden roots carry no absolute path (AC-P10-13)', () => {
    const roots = cases.filter((x) => x.golden.parse_errors.length > 0);
    expect(roots.length).toBeGreaterThan(0);
    for (const x of roots) expect(errorTextProblems(run(x), x.rootDir), x.name).toEqual([]);
    expect(path.isAbsolute(c.rootDir)).toBe(true);
  });
});
