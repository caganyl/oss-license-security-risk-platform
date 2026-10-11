/**
 * `--fail-on` evaluation and data completeness (REQ-007 contract sections
 * 4.2–4.4 and 5.1, ADR-009 Karar 4). Pure functions: no network, no clock.
 */
import type { FailOn } from './args';
import { EXIT_FAIL, EXIT_INCOMPLETE, EXIT_PASS, type ExitCode } from './exitCodes';
import { cleanText } from './output';

export type Level = 'low' | 'medium' | 'high' | 'critical';
export type DataStatus = 'complete' | 'partial' | 'unavailable' | 'disabled' | 'not_checked' | 'unknown';
export type LevelCounts = Record<Level, number>;
export interface Counts {
  security: LevelCounts;
  license: LevelCounts;
}
export interface BreachItem {
  type: 'security' | 'license';
  package: string;
  version: string | null;
  level: Level;
  id: string;
}

const LEVELS: readonly Level[] = ['low', 'medium', 'high', 'critical'];
const RANK: Readonly<Record<Level, number>> = { low: 1, medium: 2, high: 3, critical: 4 };
const POLICY_FLOOR: Readonly<Record<string, Level>> = {
  prohibited: 'critical',
  restricted: 'high',
  review_required: 'medium',
};
const COUNTED_STATUSES: ReadonlySet<string> = new Set(['open', 'in_review']);

type Row = Record<string, unknown>;

function isLevel(value: unknown): value is Level {
  return typeof value === 'string' && (LEVELS as readonly string[]).includes(value);
}

function maxLevel(a: Level | null, b: Level | null): Level | null {
  if (a === null) return b;
  if (b === null) return a;
  return RANK[a] >= RANK[b] ? a : b;
}

/** Contract 4.2: only open/in_review security and license findings count. */
export function isCounted(row: Row): boolean {
  return (
    typeof row.status === 'string' &&
    COUNTED_STATUSES.has(row.status) &&
    (row.finding_type === 'security' || row.finding_type === 'license')
  );
}

/** Contract 4.3 level mapping; null = no level (never breaches, not counted). */
export function effectiveLevel(row: Row): Level | null {
  if (row.finding_type === 'security') {
    if (row.severity === 'none') return null;
    return isLevel(row.severity) ? row.severity : 'high';
  }
  if (row.finding_type === 'license') {
    let risk: Level | null;
    if (row.risk_level === 'safe') risk = null;
    else risk = isLevel(row.risk_level) ? row.risk_level : 'high';
    const floor = typeof row.applied_policy === 'string' ? (POLICY_FLOOR[row.applied_policy] ?? null) : null;
    return maxLevel(risk, floor);
  }
  return null;
}

function textOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** Output identity (contract 4.3). */
export function findingId(row: Row): string {
  if (row.finding_type === 'security') return textOrNull(row.cve_id) ?? textOrNull(row.ghsa_id) ?? '-';
  return textOrNull(row.normalized_license) ?? textOrNull(row.detected_license) ?? 'unknown';
}

/** Code point order (not UTF-16 code unit order). */
export function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const na = ia.next();
    const nb = ib.next();
    if (na.done || nb.done) return na.done === nb.done ? 0 : na.done ? -1 : 1;
    const ca = na.value.codePointAt(0) ?? 0;
    const cb = nb.value.codePointAt(0) ?? 0;
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
}

/** Contract 5.6 `breaching` order: level desc → package → version (null first) → id. */
export function compareBreach(a: BreachItem, b: BreachItem): number {
  if (a.level !== b.level) return RANK[b.level] - RANK[a.level];
  const p = compareCodePoints(a.package, b.package);
  if (p !== 0) return p;
  if (a.version !== b.version) {
    if (a.version === null) return -1;
    if (b.version === null) return 1;
    const v = compareCodePoints(a.version, b.version);
    if (v !== 0) return v;
  }
  return compareCodePoints(a.id, b.id);
}

export interface FindingsEvaluation {
  counts: Counts;
  /** All breaching findings, sorted, values already cleaned for output. */
  breaching: BreachItem[];
}

const zeroCounts = (): LevelCounts => ({ low: 0, medium: 0, high: 0, critical: 0 });

export function evaluateFindings(rows: readonly unknown[], failOn: FailOn): FindingsEvaluation {
  const counts: Counts = { security: zeroCounts(), license: zeroCounts() };
  const breaching: BreachItem[] = [];
  const threshold = failOn === 'none' ? null : RANK[failOn];
  for (const raw of rows) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const row = raw as Row;
    if (!isCounted(row)) continue;
    const level = effectiveLevel(row);
    if (level === null) continue;
    const type = row.finding_type as 'security' | 'license';
    counts[type][level]++;
    if (threshold !== null && RANK[level] >= threshold) {
      const version = textOrNull(row.package_version);
      breaching.push({
        type,
        package: cleanText(textOrNull(row.package_name) ?? '-'),
        version: version === null ? null : cleanText(version),
        level,
        id: cleanText(findingId(row)),
      });
    }
  }
  breaching.sort(compareBreach);
  return { counts, breaching };
}

/**
 * Contract 4.4: the status of the scanned scan in the status endpoint
 * response; `null` input (endpoint failed) or no matching project → unknown.
 */
export function dataStatusFrom(body: unknown, scanId: string): DataStatus {
  if (body === null || typeof body !== 'object') return 'unknown';
  const data = (body as Row).data;
  if (data === null || typeof data !== 'object') return 'unknown';
  const projects = (data as Row).projects;
  if (!Array.isArray(projects)) return 'unknown';
  const wanted = scanId.toLowerCase();
  const match = projects.find(
    (p) =>
      p !== null &&
      typeof p === 'object' &&
      typeof (p as Row).latest_scan_id === 'string' &&
      ((p as Row).latest_scan_id as string).toLowerCase() === wanted,
  ) as Row | undefined;
  if (!match) return 'unknown';
  const value = match.vulnerability_data_status;
  if (value === null) return 'not_checked';
  if (value === 'complete' || value === 'partial' || value === 'unavailable' || value === 'disabled') return value;
  return 'unknown';
}

export interface Decision {
  exitCode: ExitCode;
  result: 'pass' | 'fail' | 'incomplete';
  warnings: string[];
}

/** Contract 4.4 / 5.1 / 5.4: exit code, result and warnings of a completed scan. */
export function decide(
  failOn: FailOn,
  breachCount: number,
  status: DataStatus,
  allowIncomplete: boolean,
  scanId: string,
): Decision {
  const warnings: string[] = [];
  const incomplete = status !== 'complete' && status !== 'disabled';
  if (status === 'disabled') {
    warnings.push('vulnerability lookup is disabled on the server; security findings were not checked');
  } else if (incomplete) {
    warnings.push(`vulnerability data is ${status} for scan ${scanId}; security findings may be missing`);
  }
  if (failOn === 'none') return { exitCode: EXIT_PASS, result: 'pass', warnings };
  if (breachCount > 0) return { exitCode: EXIT_FAIL, result: 'fail', warnings };
  if (incomplete) {
    if (allowIncomplete) {
      warnings.push('--allow-incomplete is set; incomplete vulnerability data does not change the exit code');
      return { exitCode: EXIT_PASS, result: 'pass', warnings };
    }
    return { exitCode: EXIT_INCOMPLETE, result: 'incomplete', warnings };
  }
  return { exitCode: EXIT_PASS, result: 'pass', warnings };
}
