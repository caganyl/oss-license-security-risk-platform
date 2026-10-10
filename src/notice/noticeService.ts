/**
 * NOTICE.txt generation (REQ-004 P-15, AC-P15-11…14; ADR-006 Karar 12;
 * contract `docs/contracts/REQ-004-notice-and-outputs.md` sections 2.5, 3, 4).
 *
 * Read-only and synchronous after three or four queries: no network request,
 * no write to any table or to disk, no audit entry. The body depends only on
 * the database (no generation time), so two requests return the same bytes
 * while the caches do not change.
 */
import crypto from 'node:crypto';
import type { Pool } from 'pg';
import { ARCHIVE_EXTRACTOR_VERSION } from '../enrichment/cache';
import { registryEcosystemOf, requestName } from '../enrichment/coordinates';
import { ENRICHMENT_LIMITS } from '../scanner/sandbox/runner.config';
import { KNOWN_SPDX_IDS } from '../analysis/licenseNormalizer';
import { ENTRY_SEP, FILE_SEP, noticeTextLines, singleLine } from '../lib/outputText';
import { buildIdIndex, canonicalizeSpdxExpression } from '../lib/spdxExpression';
import { isRuntimeScope, type DependencyScope } from '../types/scan';

/** NOTICE body limit (ADR-006 Karar 14: 64 MiB). */
export const NOTICE_MAX_BYTES = ENRICHMENT_LIMITS.notice.maxBytes;

export const NOTICE_SIZE_LIMIT_LINE = '[text omitted: NOTICE size limit]';
export const PRE_F3_NOTE =
  'Note: This scan predates license enrichment. License data is incomplete; rescan the project for a complete NOTICE.';

/** Archive outcomes stored in `registry_archive_cache` (ADR-006 Karar 7, 10). */
const CACHED_OUTCOMES: ReadonlySet<string> = new Set(['collected', 'no_license_file', 'unsupported_format', 'limit_exceeded']);

const OMITTED_REASONS: Readonly<Record<string, string>> = {
  file_too_large: 'license file exceeds 1 MiB limit',
  package_text_limit: 'package license text limit (4 MiB) reached',
};

/** Contract section 4.3, rows 3–11. */
const NOTICE_STATUS_REASONS: Readonly<Record<string, string>> = {
  collected: 'license files exceed size limits',
  no_license_file: 'no license file in package archive',
  unsupported_format: 'package archive format not supported',
  limit_exceeded: 'archive exceeds size limit',
  no_candidate: 'no verifiable package archive available',
  integrity_failed: 'package archive integrity check failed',
  download_failed: 'package archive could not be downloaded',
  processing_failed: 'package archive could not be processed',
  budget_exceeded: 'license enrichment time budget exceeded during scan',
};

/** Contract section 4.3, row 12 (`not_attempted` by enrichment status). */
const NOT_ATTEMPTED_REASONS: Readonly<Record<string, string>> = {
  not_found: 'package not found in registry',
  unreachable: 'registry unreachable during scan',
  error: 'registry lookup failed during scan',
  disabled: 'license enrichment disabled',
  version_unknown: 'version unknown',
  invalid_coordinates: 'invalid package name or version',
  budget_exceeded: 'license enrichment time budget exceeded during scan',
};

const REASON_PRE_F3 = 'scan predates license enrichment; rescan required';
const REASON_CACHE_CLEARED = 'license file data no longer cached; rescan required';
const REASON_UNSUPPORTED_ECOSYSTEM = 'license enrichment not supported for this ecosystem';
const REASON_NOT_COLLECTED = 'package archive not collected';

export interface NoticeDocument {
  /** Lower-case canonical scan UUID read from the database. */
  scanId: string;
  body: Buffer;
  /** SHA-256 of `body`, 64 lower-case hex characters. */
  sha256: string;
}

type LicenseFile = { path: string; text: string } | { path: string; omitted: string };

interface ArchiveRecord {
  outcome: string;
  licenseFiles: LicenseFile[];
  copyrightLines: string[];
}

interface DependencyRow {
  ecosystem: string;
  name: string;
  version: string | null;
  purl: string | null;
  scope: string | null;
  license_expression: string | null;
  license_source: string | null;
  license_enrichment_status: string | null;
  notice_status: string | null;
  notice_archive_id: string | null;
}

interface NoticeEntry {
  ecosystem: string;
  label: string;
  name: string;
  version: string | null;
  purl: string | null;
  row: DependencyRow;
  archive: ArchiveRecord | null;
  metadataText: string | null;
}

export interface NoticeServiceOptions {
  /** Body limit in bytes (default `NOTICE_MAX_BYTES`); code-level test injection only. */
  maxBytes?: number;
}

function notFound(): Error {
  return Object.assign(new Error('Scan not found or not yet completed'), { statusCode: 404 });
}

/** `nodejs` -> `npm`, `python` -> `pypi`, others as stored (contract 3.3). */
export function ecosystemLabel(ecosystem: string): string {
  return registryEcosystemOf(ecosystem) ?? ecosystem;
}

function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/** Sort key `(label, lower-case name, name, version)`, each compared as UTF-8 bytes (contract 3.3). */
function compareEntries(a: NoticeEntry, b: NoticeEntry): number {
  return (
    compareBytes(a.label, b.label) ||
    compareBytes(a.name.toLowerCase(), b.name.toLowerCase()) ||
    compareBytes(a.name, b.name) ||
    compareBytes(a.version ?? '', b.version ?? '')
  );
}

function parseLicenseFiles(value: unknown): LicenseFile[] {
  if (!Array.isArray(value)) return [];
  const files: LicenseFile[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const { path, text, omitted } = item as { path?: unknown; text?: unknown; omitted?: unknown };
    if (typeof path !== 'string') continue;
    if (typeof text === 'string') files.push({ path, text });
    else files.push({ path, omitted: typeof omitted === 'string' ? omitted : '' });
  }
  return files;
}

function toArchive(row: { outcome: string; license_files: unknown; copyright_lines: string[] | null }): ArchiveRecord {
  return {
    outcome: row.outcome,
    licenseFiles: parseLicenseFiles(row.license_files),
    copyrightLines: Array.isArray(row.copyright_lines) ? row.copyright_lines.filter((l) => typeof l === 'string') : [],
  };
}

function hasText(entry: NoticeEntry): boolean {
  return entry.archive !== null && entry.archive.licenseFiles.some((f) => 'text' in f);
}

/** Contract section 4.1 "NOTICE" column. */
function noticeSource(source: string | null): string {
  if (source === null) return 'not recorded';
  return singleLine(source);
}

/** Contract section 4.3: the `Reason:` text of an entry without license text. */
function reasonOf(entry: NoticeEntry, preF3: boolean): string {
  const { row, archive } = entry;
  if (registryEcosystemOf(entry.ecosystem) === null) return REASON_UNSUPPORTED_ECOSYSTEM;
  if (preF3) {
    if (archive === null) return REASON_PRE_F3;
    return NOTICE_STATUS_REASONS[archive.outcome] ?? REASON_NOT_COLLECTED;
  }
  const status = row.notice_status;
  if (row.notice_archive_id === null && status !== null && CACHED_OUTCOMES.has(status)) return REASON_CACHE_CLEARED;
  if (status === 'not_attempted' || status === null) {
    return NOT_ATTEMPTED_REASONS[row.license_enrichment_status ?? ''] ?? REASON_NOT_COLLECTED;
  }
  return NOTICE_STATUS_REASONS[status] ?? REASON_NOT_COLLECTED;
}

/** Byte-counting body builder (contract section 3.7). */
class NoticeWriter {
  private readonly parts: string[] = [];
  bytes = 0;
  truncated = false;

  constructor(private readonly maxBytes: number) {}

  line(text: string): void {
    const value = `${text}\n`;
    this.parts.push(value);
    this.bytes += Buffer.byteLength(value, 'utf8');
  }

  /**
   * A text block: written only while `written + block <= limit`; after the
   * first overflow every later block is replaced by the omission line
   * (deterministic, no retry with smaller blocks).
   */
  textBlock(lines: string[]): void {
    if (!this.truncated) {
      let blockBytes = 0;
      for (const l of lines) blockBytes += Buffer.byteLength(l, 'utf8') + 1;
      if (this.bytes + blockBytes > this.maxBytes) this.truncated = true;
    }
    if (this.truncated) {
      this.line(NOTICE_SIZE_LIMIT_LINE);
      return;
    }
    for (const l of lines) this.line(l);
  }

  toBuffer(): Buffer {
    return Buffer.from(this.parts.join(''), 'utf8');
  }
}

export class NoticeService {
  private readonly maxBytes: number;

  constructor(private readonly db: Pool, options: NoticeServiceOptions = {}) {
    this.maxBytes = options.maxBytes ?? NOTICE_MAX_BYTES;
  }

  async generate(scanId: string): Promise<NoticeDocument> {
    const scanResult = await this.db.query<{ id: string; completed_at: Date | null; project_name: string }>(
      `SELECT s.id::text AS id, s.completed_at, p.name AS project_name
       FROM scans s
       JOIN projects p ON p.id = s.project_id
       WHERE s.id = $1 AND s.status = 'completed'`,
      [scanId],
    );
    if (scanResult.rows.length === 0) throw notFound();
    const scan = scanResult.rows[0];

    const depResult = await this.db.query<DependencyRow>(
      `SELECT p.ecosystem::text AS ecosystem, p.name, p.version, p.purl, sd.scope::text AS scope,
              sd.license_expression, sd.license_source, sd.license_enrichment_status,
              sd.notice_status, sd.notice_archive_id::text AS notice_archive_id
       FROM scan_dependencies sd
       JOIN packages p ON p.id = sd.package_id
       WHERE sd.scan_id = $1
       ORDER BY sd.id`,
      [scan.id],
    );

    const rows = depResult.rows;
    // Pre-F3: at least one row and the effective license columns are NULL (contract 2.5).
    const preF3 = rows.length > 0 && rows.every((r) => r.license_source === null);
    const entries = this.groupRuntimeEntries(rows);
    await this.attachArchives(entries, preF3);
    await this.attachMetadataTexts(entries);
    entries.sort(compareEntries);

    // AC-P16-3 id set: the normalizer ids plus `licenses.spdx_id` (same as the SBOM writers).
    const licenseIds = await this.db.query<{ spdx_id: string }>('SELECT spdx_id FROM licenses WHERE spdx_id IS NOT NULL');
    const knownIds = buildIdIndex([...KNOWN_SPDX_IDS, ...licenseIds.rows.map((r) => r.spdx_id)]);

    const body = this.render(scan, entries, preF3, knownIds);
    return { scanId: scan.id.toLowerCase(), body, sha256: crypto.createHash('sha256').update(body).digest('hex') };
  }

  /** Runtime rows grouped by `(ecosystem, name, version)`; versionless rows by `(ecosystem, name)` (contract 3.3). */
  private groupRuntimeEntries(rows: DependencyRow[]): NoticeEntry[] {
    const byKey = new Map<string, NoticeEntry>();
    for (const row of rows) {
      if (!isRuntimeScope(row.scope as DependencyScope | null)) continue;
      const version = row.version === null || row.version === '' ? null : row.version;
      const key = JSON.stringify([row.ecosystem, row.name, version]);
      const existing = byKey.get(key);
      if (existing) {
        if (row.purl !== null && (existing.purl === null || compareBytes(row.purl, existing.purl) < 0)) existing.purl = row.purl;
        continue;
      }
      byKey.set(key, {
        ecosystem: row.ecosystem,
        label: ecosystemLabel(row.ecosystem),
        name: row.name,
        version,
        purl: row.purl,
        row,
        archive: null,
        metadataText: null,
      });
    }
    return [...byKey.values()];
  }

  /** F3: `registry_archive_cache` by `notice_archive_id`; pre-F3: by `(registry, request name, version)` at the current extractor version. */
  private async attachArchives(entries: NoticeEntry[], preF3: boolean): Promise<void> {
    if (!preF3) {
      const ids = [...new Set(entries.map((e) => e.row.notice_archive_id).filter((id): id is string => id !== null))];
      if (ids.length === 0) return;
      const result = await this.db.query<{ id: string; outcome: string; license_files: unknown; copyright_lines: string[] | null }>(
        `SELECT id::text AS id, outcome, license_files, copyright_lines
         FROM registry_archive_cache WHERE id = ANY($1::uuid[])`,
        [ids],
      );
      const byId = new Map(result.rows.map((r) => [r.id, toArchive(r)]));
      for (const entry of entries) {
        if (entry.row.notice_archive_id !== null) entry.archive = byId.get(entry.row.notice_archive_id) ?? null;
      }
      return;
    }
    const lookups = this.registryLookups(entries);
    if (lookups.size === 0) return;
    const keys = [...lookups.values()];
    const result = await this.db.query<{
      ecosystem: string; name: string; version: string; outcome: string; license_files: unknown; copyright_lines: string[] | null;
    }>(
      `SELECT DISTINCT ON (c.ecosystem, c.name, c.version)
              c.ecosystem, c.name, c.version, c.outcome, c.license_files, c.copyright_lines
       FROM registry_archive_cache c
       JOIN unnest($1::text[], $2::text[], $3::text[]) AS k(ecosystem, name, version)
         ON c.ecosystem = k.ecosystem AND c.name = k.name AND c.version = k.version
       WHERE c.extractor_version = $4
       ORDER BY c.ecosystem, c.name, c.version, c.archive_digest COLLATE "C"`,
      [keys.map((k) => k.ecosystem), keys.map((k) => k.name), keys.map((k) => k.version), ARCHIVE_EXTRACTOR_VERSION],
    );
    const found = new Map(result.rows.map((r) => [JSON.stringify([r.ecosystem, r.name, r.version]), toArchive(r)]));
    for (const [entry, key] of lookups) entry.archive = found.get(JSON.stringify([key.ecosystem, key.name, key.version])) ?? null;
  }

  private registryLookups(entries: NoticeEntry[]): Map<NoticeEntry, { ecosystem: string; name: string; version: string }> {
    const lookups = new Map<NoticeEntry, { ecosystem: string; name: string; version: string }>();
    for (const entry of entries) {
      const registry = registryEcosystemOf(entry.ecosystem);
      if (registry === null || entry.version === null) continue;
      lookups.set(entry, { ecosystem: registry, name: requestName(registry, entry.name), version: entry.version });
    }
    return lookups;
  }

  /** PyPI metadata license text for PyPI entries without license text (contract 3.5, AC-P15-13). */
  private async attachMetadataTexts(entries: NoticeEntry[]): Promise<void> {
    // Pre-F3 entries use the same lookup: the metadata cache is keyed by coordinates, not by scan.
    const candidates = entries.filter((e) => registryEcosystemOf(e.ecosystem) === 'pypi' && !hasText(e));
    const lookups = this.registryLookups(candidates);
    if (lookups.size === 0) return;
    const keys = [...lookups.values()];
    const result = await this.db.query<{ name: string; version: string; license_text: string }>(
      `SELECT c.name, c.version, c.license_text
       FROM registry_package_cache c
       JOIN unnest($1::text[], $2::text[]) AS k(name, version) ON c.name = k.name AND c.version = k.version
       WHERE c.ecosystem = 'pypi' AND c.outcome = 'found' AND c.license_text IS NOT NULL AND c.license_text <> ''`,
      [keys.map((k) => k.name), keys.map((k) => k.version)],
    );
    const found = new Map(result.rows.map((r) => [JSON.stringify([r.name, r.version]), r.license_text]));
    for (const [entry, key] of lookups) entry.metadataText = found.get(JSON.stringify([key.name, key.version])) ?? null;
  }

  private render(
    scan: { id: string; completed_at: Date | null; project_name: string },
    entries: NoticeEntry[],
    preF3: boolean,
    knownIds: ReadonlyMap<string, string>,
  ): Buffer {
    const w = new NoticeWriter(this.maxBytes);
    const withText = entries.filter(hasText).length;

    w.line('THIRD-PARTY SOFTWARE NOTICES');
    w.line('NOTICE format: 1');
    w.line(`Project: ${singleLine(scan.project_name)}`);
    w.line(`Scan ID: ${scan.id.toLowerCase()}`);
    w.line(`Scan completed at: ${scan.completed_at ? scan.completed_at.toISOString() : 'n/a'}`);
    w.line(`Packages: ${entries.length}`);
    w.line(`Packages with license files: ${withText}`);
    w.line(`Packages without license files: ${entries.length - withText}`);
    w.line('Generated automatically; not legal advice. Review before distribution.');
    if (preF3) w.line(PRE_F3_NOTE);

    for (const entry of entries) this.renderEntry(w, entry, preF3, knownIds);
    return w.toBuffer();
  }

  private renderEntry(w: NoticeWriter, entry: NoticeEntry, preF3: boolean, knownIds: ReadonlyMap<string, string>): void {
    const { row, archive } = entry;
    const expression = preF3 ? '' : singleLine(row.license_expression);
    w.line('');
    w.line(ENTRY_SEP);
    w.line(`Package: ${singleLine(entry.name)}`);
    w.line(`Version: ${entry.version === null ? '(unknown)' : singleLine(entry.version)}`);
    w.line(`Ecosystem: ${singleLine(entry.label)}`);
    w.line(`PURL: ${entry.purl === null || entry.purl === '' ? '(none)' : singleLine(entry.purl)}`);
    w.line(`License: ${expression.trim() === '' ? 'NOASSERTION' : expression}`);
    w.line(`License source: ${preF3 ? 'not recorded' : noticeSource(row.license_source)}`);
    const copyright = (archive?.copyrightLines ?? []).map((l) => singleLine(l)).filter((l) => l.trim() !== '');
    if (copyright.length === 0) w.line('Copyright: (none found)');
    for (const line of copyright) w.line(`Copyright: ${line}`);
    w.line(`License files: ${archive?.licenseFiles.length ?? 0}`);

    const textual = hasText(entry);
    if (!textual) {
      w.line(`Reason: ${reasonOf(entry, preF3)}`);
      const canonical = expression.trim() === '' ? null : canonicalizeSpdxExpression(expression, knownIds);
      if (canonical !== null) {
        for (const id of spdxLicenseIds(canonical)) w.line(`SPDX license: https://spdx.org/licenses/${id}.html`);
      }
    }

    for (const file of archive?.licenseFiles ?? []) {
      w.line(FILE_SEP);
      w.line(`File: ${singleLine(file.path)}`);
      if ('text' in file) {
        w.line(FILE_SEP);
        w.textBlock(noticeTextLines(file.text));
      } else {
        w.line(`[omitted: ${OMITTED_REASONS[file.omitted] ?? 'not available'}]`);
      }
    }

    if (!textual && entry.label === 'pypi' && entry.metadataText !== null) {
      w.line(FILE_SEP);
      w.line('License text from package metadata');
      w.line(FILE_SEP);
      w.textBlock(noticeTextLines(entry.metadataText));
    }
  }
}

/** License ids of a canonical expression in first-seen order, without `WITH` exceptions (contract 3.4). */
export function spdxLicenseIds(canonical: string): string[] {
  const ids: string[] = [];
  const tokens = canonical.replace(/[()]/g, ' ').split(/\s+/).filter((t) => t.length > 0);
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === 'AND' || token === 'OR') continue;
    if (token === 'WITH') {
      i++;
      continue;
    }
    if (!ids.includes(token)) ids.push(token);
  }
  return ids;
}
