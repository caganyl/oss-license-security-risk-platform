/**
 * Deterministic finding fingerprint (REQ-002 / P-08, ADR-003 (c), formula v1).
 *
 * fingerprint = lower_hex(sha256(UTF-8(
 *     "v1|" + project_id + "|" + purl_scope + "|" + finding_type + "|" + key)))
 *
 * Must stay byte-identical to the SQL backfill in
 * db/migrations/004_finding_fingerprint.up.sql; any rule change requires a new
 * "v" prefix and a matching migration.
 */
import crypto from 'node:crypto';

export type FingerprintFindingType = 'license' | 'security';

export interface FingerprintVulnerability {
  id: string;
  osvId?: string | null;
  ghsaId?: string | null;
  cveId?: string | null;
}

export interface FingerprintInput {
  projectId: string;
  /** packages.purl */
  purl: string;
  /** packages.version (may be passed untrimmed) */
  version: string | null;
  findingType: FingerprintFindingType;
  normalizedLicense?: string | null;
  vulnerability?: FingerprintVulnerability;
}

const FINGERPRINT_VERSION = 'v1';

/**
 * Matches PostgreSQL btrim(x, ' \t\n\v\f\r'). String.prototype.trim() would also
 * strip Unicode spaces (NBSP, U+2028, ...) and diverge from the SQL backfill.
 */
const ASCII_EDGE_WHITESPACE = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g;

function trimAsciiWhitespace(value: string): string {
  return value.replace(ASCII_EDGE_WHITESPACE, '');
}

/**
 * purl without qualifiers/subpath and without the trailing "@version" (only an
 * '@' after the last '/', so scoped npm names survive), lowercased; pypi names
 * PEP 503-normalised.
 */
export function purlBase(purl: string): string {
  const withoutSubpath = purl.split('#', 1)[0];
  const withoutQualifiers = withoutSubpath.split('?', 1)[0];
  const base = withoutQualifiers.replace(/@[^/]*$/, '').toLowerCase();
  const pypiPrefix = 'pkg:pypi/';
  if (base.startsWith(pypiPrefix)) {
    return pypiPrefix + base.slice(pypiPrefix.length).replace(/[-_.]+/g, '-');
  }
  return base;
}

function fingerprintKey(input: FingerprintInput): string {
  if (input.findingType === 'license') {
    return (input.normalizedLicense ?? 'NOASSERTION').toLowerCase();
  }
  const v = input.vulnerability;
  if (!v) throw new Error('security fingerprint requires a vulnerability');
  return (v.osvId ?? v.ghsaId ?? v.cveId ?? v.id).toUpperCase();
}

/** Returns the 64-character lowercase hex fingerprint of a finding. */
export function computeFindingFingerprint(input: FingerprintInput): string {
  const base = purlBase(input.purl);
  const trimmed = input.version === null ? '' : trimAsciiWhitespace(input.version);
  const version = trimmed === '' ? null : trimmed;
  const scope = input.findingType === 'security' && version !== null ? `${base}@${version}` : base;

  const canonical = [
    FINGERPRINT_VERSION,
    input.projectId.toLowerCase(),
    scope.split('|').join('%7C'),
    input.findingType,
    fingerprintKey(input),
  ].join('|');

  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}
