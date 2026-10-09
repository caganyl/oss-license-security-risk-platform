/**
 * REQ-003 P-10 golden comparison (AC-P10-5, ADR-005 Karar 2).
 *
 * The golden files (`tests/fixtures/p10-golden/expected/*.json`) are the frozen
 * output of the legacy Python parsers (REQ-003 D-26). They carry no `scan_id`
 * or `status`; `root` is the scan root relative to `tests/fixtures/p10-golden`.
 *
 * Rules:
 *   - the TypeScript result is normalised with a JSON round trip;
 *   - `dependencies` and `scan_files` are compared order-independently (each
 *     item is sorted by its key-sorted JSON text) and must be deep-equal,
 *     including key presence (`declared_range: null` is not a missing key);
 *   - `parse_errors` are compared as sorted `(ecosystem, file)` pairs; every
 *     `error` must be a non-empty text without an absolute path;
 *   - `scan_id`, `status` and `total_deps` are compared exactly.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import type { SandboxScanResult } from '../../src/types/scan';
import { FIXTURES_DIR, REPO_ROOT } from './paths';

export const GOLDEN_DIR = path.join(FIXTURES_DIR, 'p10-golden');
export const EXPECTED_DIR = path.join(GOLDEN_DIR, 'expected');
export const FORMATS_DIR = path.join(GOLDEN_DIR, 'formats');

export interface GoldenFile {
  root: string;
  total_deps: number;
  dependencies: unknown[];
  scan_files: unknown[];
  parse_errors: Array<{ ecosystem: string; file: string }>;
  generator?: string;
  python?: string;
}

export interface GoldenCase {
  /** File name without `.json` (e.g. `npm-lock-v2`). */
  name: string;
  /** Absolute scan root. */
  rootDir: string;
  golden: GoldenFile;
}

export interface NormalizedResult {
  scan_id: unknown;
  status: unknown;
  total_deps: unknown;
  dependencies: unknown[];
  scan_files: unknown[];
  parse_errors: Array<{ ecosystem: unknown; file: unknown }>;
}

export function loadGoldenCases(): GoldenCase[] {
  return fs
    .readdirSync(EXPECTED_DIR)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((file) => {
      const golden = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, file), 'utf8')) as GoldenFile;
      return { name: file.slice(0, -'.json'.length), rootDir: path.join(GOLDEN_DIR, ...golden.root.split('/')), golden };
    });
}

/** JSON text with object keys sorted recursively (canonical item key). */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function sortCanonical(items: unknown[]): unknown[] {
  return items
    .map((item) => ({ key: canonicalJson(item), item: sortKeysDeep(item) }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((entry) => entry.item);
}

function errorPairs(records: Array<{ ecosystem?: unknown; file?: unknown }>): Array<{ ecosystem: unknown; file: unknown }> {
  return sortCanonical(records.map((r) => ({ ecosystem: r.ecosystem, file: r.file }))) as Array<{ ecosystem: unknown; file: unknown }>;
}

/** TypeScript result -> comparable form (JSON round trip, order-independent arrays). */
export function normalizeActual(result: SandboxScanResult): NormalizedResult {
  const r = JSON.parse(JSON.stringify(result)) as SandboxScanResult;
  return {
    scan_id: r.scan_id,
    status: r.status,
    total_deps: r.total_deps,
    dependencies: sortCanonical(r.dependencies ?? []),
    scan_files: sortCanonical(r.scan_files ?? []),
    parse_errors: errorPairs(r.parse_errors ?? []),
  };
}

/** Golden file -> the same comparable form. */
export function normalizeGolden(golden: GoldenFile, scanId: string): NormalizedResult {
  return {
    scan_id: scanId,
    status: 'completed',
    total_deps: golden.total_deps,
    dependencies: sortCanonical(golden.dependencies),
    scan_files: sortCanonical(golden.scan_files),
    parse_errors: errorPairs(golden.parse_errors),
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Absolute paths that must never appear in an `error` text (AC-P10-13): the
 * scan root (real and given form, both separators), the repository, the temp
 * folder and the user profile.
 */
export function forbiddenPathPatterns(rootDir: string): RegExp[] {
  const bases = new Set<string>();
  const add = (p: string | undefined) => {
    if (!p || p.length < 4) return;
    bases.add(p);
    try {
      bases.add(fs.realpathSync.native(p));
    } catch {
      // not a real path: keep the given form only
    }
  };
  add(rootDir);
  add(path.resolve(rootDir));
  add(REPO_ROOT);
  add(os.tmpdir());
  add(os.homedir());
  const patterns: RegExp[] = [];
  for (const base of bases) {
    for (const form of new Set([base, base.replace(/\\/g, '/'), base.replace(/\//g, '\\')])) {
      patterns.push(new RegExp(escapeRegExp(form), 'i'));
    }
  }
  return patterns;
}

/** Problems with the `error` texts: empty, or carrying an absolute path. */
export function errorTextProblems(result: SandboxScanResult, rootDir: string): string[] {
  const patterns = forbiddenPathPatterns(rootDir);
  const problems: string[] = [];
  for (const record of result.parse_errors ?? []) {
    const label = `${String(record.ecosystem)}:${String(record.file)}`;
    if (typeof record.error !== 'string' || record.error.trim() === '') {
      problems.push(`${label}: empty error text`);
      continue;
    }
    if (patterns.some((re) => re.test(record.error))) problems.push(`${label}: error text contains an absolute path`);
  }
  return problems;
}

/** Full golden verdict (used for the negative control: the comparator must not pass vacuously). */
export function matchesGolden(result: SandboxScanResult, golden: GoldenFile, scanId: string, rootDir: string): boolean {
  return (
    isDeepStrictEqual(normalizeActual(result), normalizeGolden(golden, scanId)) &&
    errorTextProblems(result, rootDir).length === 0
  );
}
