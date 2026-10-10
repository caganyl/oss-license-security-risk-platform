/**
 * Persistent registry caches (REQ-004 AC-P14-6…8, AC-P15-10; ADR-006
 * Karar 9, 10; migration `006_registry_enrichment`). The single `pg` access
 * point of `src/enrichment/`.
 *
 * - Metadata row is a hit when `extractor_version = METADATA_EXTRACTOR_VERSION`
 *   and (`expires_at IS NULL` or `expires_at > NOW()`); time is evaluated with
 *   the database clock.
 * - `not_found` (404/410) rows expire after 24 h; transient errors are never
 *   written.
 * - Stale-on-error: a `found` row written by another extractor version is
 *   returned as `stale`; the enricher uses it only when the refresh fails
 *   transiently. An expired `not_found` row is never used.
 * - Every write is its own autocommit statement (independent of the scan
 *   transaction, AC-P14-8); `WHERE extractor_version <= EXCLUDED…` keeps old
 *   code from overwriting a newer row.
 */
import type { Pool } from 'pg';
import type { RegistryEcosystem } from './coordinates';
import { coordinateKey } from './coordinates';
import type { DigestAlgorithm } from './integrity';
import type { ArchiveCandidate, RegistryMetadata } from './types';

/** Bump when metadata extraction changes (AC-P14-1/2/3 order, trove table, text rules). */
export const METADATA_EXTRACTOR_VERSION = 1;
/** Bump when archive extraction changes (readers, file selection, copyright rule). */
export const ARCHIVE_EXTRACTOR_VERSION = 1;

/** Anything with `pg`'s `query` (the pool; one statement = one autocommit transaction). */
export type CacheDb = Pick<Pool, 'query'>;

export interface MetadataKey {
  ecosystem: RegistryEcosystem;
  /** Request name (npm as-is, PyPI PEP 503). */
  name: string;
  version: string;
}

export type CachedMetadata =
  | { kind: 'hit'; outcome: { kind: 'found'; metadata: RegistryMetadata } | { kind: 'not_found' } }
  | { kind: 'stale'; metadata: RegistryMetadata };

const DIGEST_ALGORITHMS: ReadonlySet<string> = new Set(['sha512', 'sha1', 'sha256']);

/** Archive candidates read back from JSONB; malformed items are dropped (defence against manual edits). */
export function parseCandidates(value: unknown): ArchiveCandidate[] {
  if (!Array.isArray(value)) return [];
  const out: ArchiveCandidate[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const c = item as Record<string, unknown>;
    if (typeof c.url !== 'string' || typeof c.algorithm !== 'string' || !DIGEST_ALGORITHMS.has(c.algorithm)) continue;
    if (!Array.isArray(c.digests) || !c.digests.every((d) => typeof d === 'string')) continue;
    out.push({
      url: c.url,
      algorithm: c.algorithm as DigestAlgorithm,
      digests: [...(c.digests as string[])],
      size: typeof c.size === 'number' && Number.isInteger(c.size) && c.size >= 0 ? c.size : null,
      filename: typeof c.filename === 'string' ? c.filename : null,
    });
  }
  return out;
}

interface MetadataRow {
  ecosystem: RegistryEcosystem;
  name: string;
  version: string;
  outcome: 'found' | 'not_found';
  declared_license: string | null;
  license_text: string | null;
  archive_candidates: unknown;
  fresh: boolean;
}

/**
 * Reads the metadata rows of `keys` in one query (`unnest` arrays). Result
 * map key: `coordinateKey(ecosystem, name, version)`; misses are absent.
 */
export async function readMetadataCache(db: CacheDb, keys: readonly MetadataKey[]): Promise<Map<string, CachedMetadata>> {
  const result = new Map<string, CachedMetadata>();
  if (keys.length === 0) return result;
  const { rows } = await db.query<MetadataRow>(
    `SELECT c.ecosystem, c.name, c.version, c.outcome, c.declared_license, c.license_text, c.archive_candidates,
            (c.extractor_version = $4 AND (c.expires_at IS NULL OR c.expires_at > NOW())) AS fresh
       FROM unnest($1::text[], $2::text[], $3::text[]) AS k(ecosystem, name, version)
       JOIN registry_package_cache c
         ON c.ecosystem = k.ecosystem AND c.name = k.name AND c.version = k.version`,
    [keys.map((k) => k.ecosystem), keys.map((k) => k.name), keys.map((k) => k.version), METADATA_EXTRACTOR_VERSION],
  );
  for (const row of rows) {
    const key = coordinateKey(row.ecosystem, row.name, row.version);
    const metadata: RegistryMetadata = {
      declaredLicense: row.declared_license,
      licenseText: row.license_text,
      archiveCandidates: parseCandidates(row.archive_candidates),
    };
    if (row.fresh) {
      result.set(key, { kind: 'hit', outcome: row.outcome === 'found' ? { kind: 'found', metadata } : { kind: 'not_found' } });
    } else if (row.outcome === 'found') {
      result.set(key, { kind: 'stale', metadata });
    }
  }
  return result;
}

/** Upserts one metadata outcome (`found` never expires; `not_found` expires in 24 h). */
export async function writeMetadataCache(
  db: CacheDb,
  key: MetadataKey,
  outcome: { kind: 'found'; metadata: RegistryMetadata } | { kind: 'not_found' },
): Promise<void> {
  const found = outcome.kind === 'found';
  await db.query(
    `INSERT INTO registry_package_cache
       (ecosystem, name, version, outcome, declared_license, license_text, archive_candidates, extractor_version, fetched_at, expires_at)
     VALUES ($1, $2, $3, $4::text, $5, $6, $7::jsonb, $8, NOW(), CASE WHEN $4::text = 'not_found' THEN NOW() + INTERVAL '24 hours' END)
     ON CONFLICT (ecosystem, name, version) DO UPDATE SET
       outcome = EXCLUDED.outcome,
       declared_license = EXCLUDED.declared_license,
       license_text = EXCLUDED.license_text,
       archive_candidates = EXCLUDED.archive_candidates,
       extractor_version = EXCLUDED.extractor_version,
       expires_at = EXCLUDED.expires_at,
       fetched_at = NOW()
     WHERE registry_package_cache.extractor_version <= EXCLUDED.extractor_version`,
    [
      key.ecosystem,
      key.name,
      key.version,
      found ? 'found' : 'not_found',
      found ? outcome.metadata.declaredLicense : null,
      found ? outcome.metadata.licenseText : null,
      JSON.stringify(found ? outcome.metadata.archiveCandidates : []),
      METADATA_EXTRACTOR_VERSION,
    ],
  );
}

// ---------------------------------------------------------------------------
// Archive cache (used by the archive stage)
// ---------------------------------------------------------------------------

export type ArchiveOutcome = 'collected' | 'no_license_file' | 'unsupported_format' | 'limit_exceeded';

export type LicenseFileEntry = { path: string; text: string } | { path: string; omitted: string };

export interface ArchiveKey extends MetadataKey {
  /** `sha512-<b64>` | `sha1-<hex>` | `sha256-<hex>`. */
  digest: string;
}

export interface ArchiveRecord {
  outcome: ArchiveOutcome;
  outcomeDetail: string | null;
  licenseFiles: LicenseFileEntry[];
  copyrightLines: string[];
  archiveUrl: string;
  archiveSize: number;
}

export interface CachedArchive {
  id: string;
  outcome: ArchiveOutcome;
  outcomeDetail: string | null;
  licenseFiles: LicenseFileEntry[];
  copyrightLines: string[];
}

function parseLicenseFiles(value: unknown): LicenseFileEntry[] {
  if (!Array.isArray(value)) return [];
  const out: LicenseFileEntry[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const f = item as Record<string, unknown>;
    if (typeof f.path !== 'string') continue;
    if (typeof f.text === 'string') out.push({ path: f.path, text: f.text });
    else if (typeof f.omitted === 'string') out.push({ path: f.path, omitted: f.omitted });
  }
  return out;
}

/** Archive rows of the current extractor version for `keys` (map key: `coordinateKey` + `\0` + digest). */
export async function readArchiveCache(db: CacheDb, keys: readonly ArchiveKey[]): Promise<Map<string, CachedArchive>> {
  const result = new Map<string, CachedArchive>();
  if (keys.length === 0) return result;
  const { rows } = await db.query<{
    id: string;
    ecosystem: RegistryEcosystem;
    name: string;
    version: string;
    archive_digest: string;
    outcome: ArchiveOutcome;
    outcome_detail: string | null;
    license_files: unknown;
    copyright_lines: string[] | null;
  }>(
    `SELECT c.id, c.ecosystem, c.name, c.version, c.archive_digest, c.outcome, c.outcome_detail, c.license_files, c.copyright_lines
       FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS k(ecosystem, name, version, digest)
       JOIN registry_archive_cache c
         ON c.ecosystem = k.ecosystem AND c.name = k.name AND c.version = k.version AND c.archive_digest = k.digest
      WHERE c.extractor_version = $5`,
    [
      keys.map((k) => k.ecosystem),
      keys.map((k) => k.name),
      keys.map((k) => k.version),
      keys.map((k) => k.digest),
      ARCHIVE_EXTRACTOR_VERSION,
    ],
  );
  for (const row of rows) {
    result.set(`${coordinateKey(row.ecosystem, row.name, row.version)}\u0000${row.archive_digest}`, {
      id: row.id,
      outcome: row.outcome,
      outcomeDetail: row.outcome_detail,
      licenseFiles: parseLicenseFiles(row.license_files),
      copyrightLines: Array.isArray(row.copyright_lines) ? row.copyright_lines : [],
    });
  }
  return result;
}

/** Upserts one archive row (updated in place, same id) and returns its id. */
export async function writeArchiveCache(db: CacheDb, key: ArchiveKey, record: ArchiveRecord): Promise<string> {
  const params = [
    key.ecosystem,
    key.name,
    key.version,
    key.digest,
    record.archiveUrl,
    record.archiveSize,
    record.outcome,
    record.outcomeDetail,
    JSON.stringify(record.licenseFiles),
    record.copyrightLines,
    ARCHIVE_EXTRACTOR_VERSION,
  ];
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO registry_archive_cache
       (ecosystem, name, version, archive_digest, archive_url, archive_size, outcome, outcome_detail, license_files, copyright_lines, extractor_version)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::text[], $11)
     ON CONFLICT ON CONSTRAINT registry_archive_cache_key DO UPDATE SET
       archive_url = EXCLUDED.archive_url,
       archive_size = EXCLUDED.archive_size,
       outcome = EXCLUDED.outcome,
       outcome_detail = EXCLUDED.outcome_detail,
       license_files = EXCLUDED.license_files,
       copyright_lines = EXCLUDED.copyright_lines,
       extractor_version = EXCLUDED.extractor_version,
       updated_at = NOW()
     WHERE registry_archive_cache.extractor_version <= EXCLUDED.extractor_version
     RETURNING id`,
    params,
  );
  if (rows.length > 0) return rows[0].id;
  // A newer extractor version owns the row: read its id.
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM registry_archive_cache WHERE ecosystem = $1 AND name = $2 AND version = $3 AND archive_digest = $4`,
    [key.ecosystem, key.name, key.version, key.digest],
  );
  return existing.rows[0]?.id ?? '';
}
