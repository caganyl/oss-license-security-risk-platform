/**
 * REQ-007 contract section 5.6 · Hand-written validator of the
 * `oss-risk scan --format json` object (JSON Schema draft 2020-12 in the
 * contract; no schema library is added, AC-G-5). Returns the list of
 * violations (empty = valid). Also checks the fixed key order and that the
 * stdout text is exactly one JSON object followed by a single `\n`.
 */

const KEYS = [
  'schemaVersion',
  'result',
  'exitCode',
  'project',
  'scan',
  'failOn',
  'vulnerabilityDataStatus',
  'counts',
  'breaching',
  'breachingTruncated',
  'warnings',
  'error',
] as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LEVELS = ['low', 'medium', 'high', 'critical'];

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const cpLen = (s: string) => [...s].length;

function exactKeys(errors: string[], where: string, v: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(v);
  if (actual.join(',') !== keys.join(',')) errors.push(`${where}: keys ${actual.join(',')} != ${keys.join(',')}`);
}

function levelCounts(errors: string[], where: string, v: unknown): void {
  if (!isObj(v)) {
    errors.push(`${where}: not an object`);
    return;
  }
  exactKeys(errors, where, v, LEVELS);
  for (const l of LEVELS) {
    if (!Number.isInteger(v[l]) || (v[l] as number) < 0) errors.push(`${where}.${l}: not a non-negative integer`);
  }
}

export function validateCliJson(value: unknown): string[] {
  const errors: string[] = [];
  if (!isObj(value)) return ['top level: not an object'];
  exactKeys(errors, 'top level', value, KEYS);
  if (value.schemaVersion !== 1) errors.push('schemaVersion != 1');
  if (!['pass', 'fail', 'incomplete', 'error'].includes(value.result as string)) errors.push('result: bad enum');
  if (!Number.isInteger(value.exitCode) || (value.exitCode as number) < 0 || (value.exitCode as number) > 5) errors.push('exitCode: not 0..5');
  if (value.project !== null) {
    if (!isObj(value.project)) errors.push('project: not object/null');
    else {
      exactKeys(errors, 'project', value.project, ['id', 'name']);
      if (typeof value.project.id !== 'string' || !UUID_RE.test(value.project.id)) errors.push('project.id: not a uuid');
      if (typeof value.project.name !== 'string' || cpLen(value.project.name) > 200) errors.push('project.name: not a string <= 200');
    }
  }
  if (value.scan !== null) {
    if (!isObj(value.scan)) errors.push('scan: not object/null');
    else {
      exactKeys(errors, 'scan', value.scan, ['id', 'status', 'totalDependencies']);
      if (typeof value.scan.id !== 'string' || !UUID_RE.test(value.scan.id)) errors.push('scan.id: not a uuid');
      if (typeof value.scan.status !== 'string') errors.push('scan.status: not a string');
      const td = value.scan.totalDependencies;
      if (td !== null && !(Number.isInteger(td) && (td as number) >= 0)) errors.push('scan.totalDependencies: bad');
    }
  }
  if (![...LEVELS, 'none', null].includes(value.failOn as string | null)) errors.push('failOn: bad enum');
  if (!['complete', 'partial', 'unavailable', 'disabled', 'not_checked', 'unknown', null].includes(value.vulnerabilityDataStatus as string | null)) {
    errors.push('vulnerabilityDataStatus: bad enum');
  }
  if (value.counts !== null) {
    if (!isObj(value.counts)) errors.push('counts: not object/null');
    else {
      exactKeys(errors, 'counts', value.counts, ['security', 'license']);
      levelCounts(errors, 'counts.security', value.counts.security);
      levelCounts(errors, 'counts.license', value.counts.license);
    }
  }
  if (!Array.isArray(value.breaching)) errors.push('breaching: not an array');
  else {
    if (value.breaching.length > 500) errors.push('breaching: more than 500 items');
    value.breaching.forEach((b, i) => {
      const w = `breaching[${i}]`;
      if (!isObj(b)) {
        errors.push(`${w}: not an object`);
        return;
      }
      exactKeys(errors, w, b, ['type', 'package', 'version', 'level', 'id']);
      if (b.type !== 'security' && b.type !== 'license') errors.push(`${w}.type: bad enum`);
      if (typeof b.package !== 'string' || cpLen(b.package) > 200) errors.push(`${w}.package: bad`);
      if (b.version !== null && (typeof b.version !== 'string' || cpLen(b.version) > 200)) errors.push(`${w}.version: bad`);
      if (!LEVELS.includes(b.level as string)) errors.push(`${w}.level: bad enum`);
      if (typeof b.id !== 'string' || cpLen(b.id) > 200) errors.push(`${w}.id: bad`);
    });
  }
  if (typeof value.breachingTruncated !== 'boolean') errors.push('breachingTruncated: not boolean');
  if (!Array.isArray(value.warnings) || value.warnings.some((w) => typeof w !== 'string')) errors.push('warnings: not a string array');
  if (value.error !== null) {
    if (!isObj(value.error)) errors.push('error: not object/null');
    else {
      exactKeys(errors, 'error', value.error, ['code', 'message']);
      if (typeof value.error.code !== 'string') errors.push('error.code: not a string');
      if (typeof value.error.message !== 'string' || cpLen(value.error.message) > 600) errors.push('error.message: bad');
    }
  }
  // Consistency rules of contract 5.1 / 5.6 (X-6).
  const byResult: Record<string, number[]> = { pass: [0], fail: [1], incomplete: [5], error: [2, 3, 4] };
  if (typeof value.result === 'string' && byResult[value.result] && !byResult[value.result].includes(value.exitCode as number)) {
    errors.push(`result ${String(value.result)} with exitCode ${String(value.exitCode)}`);
  }
  if ((value.result === 'error') !== (value.error !== null)) errors.push('error must be set exactly when result = error');
  return errors;
}

/** Parses stdout that must be exactly one JSON object plus one trailing `\n`. */
export function parseSingleJson(stdout: string): unknown {
  if (!stdout.endsWith('\n') || stdout.endsWith('\n\n') || stdout.slice(0, -1).includes('\n')) {
    throw new Error(`stdout is not one JSON line plus a single newline: ${JSON.stringify(stdout.slice(0, 200))}`);
  }
  return JSON.parse(stdout);
}
