/**
 * Archive path normalization and license file selection (REQ-004 AC-P15-6,
 * AC-P15-7, AC-P15-8; ADR-006 Karar 7, 8; D-67).
 *
 * - Paths: `\` -> `/`, leading `./` dropped; absolute paths, drive letters,
 *   `..` components, empty components (`//`) and NUL are never matched.
 * - Name: the last component starts (case-insensitive) with `LICENSE`,
 *   `LICENCE`, `COPYING`, `NOTICE` or `COPYRIGHT`.
 * - Location: npm tarball and sdist -> `<top folder>/<name>` (depth exactly
 *   2; the top folder is the first component of the first regular file);
 *   wheel -> `<x>.dist-info/<name>` and `<x>.dist-info/licenses/**`.
 * - At most 10 files in code point order of the normalized path (a bounded
 *   structure keeps the 10 smallest while streaming); a file over 1 MiB is
 *   `{ path, omitted: 'file_too_large' }`; once the package text would pass
 *   4 MiB the remaining files are `{ path, omitted: 'package_text_limit' }`.
 *
 * Boundary rule (ADR-006 Karar 1): loaded inside the archive thread; imports
 * only sibling thread modules.
 */
import { extractCopyrightLines } from '../copyright';
import { decodeAndSanitize } from '../text';

/** Persistent archive outcome codes (`registry_archive_cache.outcome`). */
export type ExtractOutcome = 'collected' | 'no_license_file' | 'unsupported_format' | 'limit_exceeded';

/** Limits of one archive (ADR-006 Karar 7; values from `ENRICHMENT_LIMITS.archive`). */
export interface ArchiveLimits {
  maxDecompressedBytes: number;
  maxEntries: number;
  maxFileBytes: number;
  maxPackageTextBytes: number;
  maxFiles: number;
  maxLongNameBytes: number;
}

export type LicenseFile = { path: string; text: string } | { path: string; omitted: 'file_too_large' | 'package_text_limit' };

export interface ExtractResult {
  outcome: ExtractOutcome;
  /** Fixed detail code (e.g. `entries`, `decompressed`, `zip64`), never free text. */
  outcomeDetail: string | null;
  licenseFiles: LicenseFile[];
  copyrightLines: string[];
}

/** A reader stopped the whole archive with a persistent outcome. */
export class ArchiveFailure extends Error {
  constructor(
    readonly outcome: 'unsupported_format' | 'limit_exceeded',
    readonly detail: string,
  ) {
    super(`${outcome}:${detail}`);
    this.name = 'ArchiveFailure';
  }
}

const LICENSE_PREFIXES = ['license', 'licence', 'copying', 'notice', 'copyright'];

/** Normalized archive path, or null when the name must never be matched. */
export function normalizeArchivePath(raw: string): string | null {
  if (raw.length === 0 || raw.includes('\u0000')) return null;
  let p = raw.replace(/\\/g, '/');
  while (p.startsWith('./')) p = p.slice(2);
  if (p.startsWith('/') || /^[A-Za-z]:/.test(p)) return null;
  // A directory entry ends with `/`; drop that single trailing slash before the component check.
  const trimmed = p.endsWith('/') ? p.slice(0, -1) : p;
  if (trimmed.length === 0) return null;
  const components = trimmed.split('/');
  for (const component of components) {
    if (component.length === 0 || component === '..') return null;
  }
  return trimmed;
}

export function isLicenseFileName(baseName: string): boolean {
  const lower = baseName.toLowerCase();
  return LICENSE_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export type ArchiveLayout = 'top-folder' | 'wheel';

/** Decides which normalized paths are license file candidates. */
export class LicenseFileMatcher {
  private topFolder: string | null = null;

  constructor(private readonly layout: ArchiveLayout) {}

  /** Call for every regular file in archive order (sets the top folder on the first one). */
  observeRegularFile(path: string): void {
    if (this.topFolder === null) this.topFolder = path.split('/')[0];
  }

  matches(path: string): boolean {
    const components = path.split('/');
    if (!isLicenseFileName(components[components.length - 1])) return false;
    if (this.layout === 'top-folder') {
      return components.length === 2 && this.topFolder !== null && components[0] === this.topFolder;
    }
    if (components.length < 2 || !components[0].endsWith('.dist-info') || components[0].length === '.dist-info'.length) return false;
    return components.length === 2 || (components.length >= 3 && components[1] === 'licenses');
  }
}

function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

interface Slot {
  path: string;
  /** Raw bytes, or null when the file is over the per-file limit. */
  bytes: Uint8Array | null;
}

/**
 * Keeps the `maxFiles` smallest candidate paths (code point order). Callers
 * ask `wants(path)` before buffering a body, then `add` the bytes (or null
 * for a file over the size limit).
 */
export class LicenseFileCollector {
  private readonly slots: Slot[] = [];

  constructor(private readonly limits: Pick<ArchiveLimits, 'maxFiles' | 'maxFileBytes' | 'maxPackageTextBytes'>) {}

  /** True when a file at `path` would be kept (not a duplicate and inside the 10 smallest). */
  wants(path: string): boolean {
    if (this.slots.some((s) => s.path === path)) return false;
    if (this.slots.length < this.limits.maxFiles) return true;
    return compareCodePoints(path, this.slots[this.slots.length - 1].path) < 0;
  }

  add(path: string, bytes: Uint8Array | null): void {
    if (!this.wants(path)) return;
    const stored = bytes !== null && bytes.length > this.limits.maxFileBytes ? null : bytes;
    let index = this.slots.findIndex((s) => compareCodePoints(path, s.path) < 0);
    if (index === -1) index = this.slots.length;
    this.slots.splice(index, 0, { path, bytes: stored });
    if (this.slots.length > this.limits.maxFiles) this.slots.pop();
  }

  get size(): number {
    return this.slots.length;
  }

  /** Decoded files and copyright lines; binary files (NUL after decoding) are dropped. */
  finish(): { licenseFiles: LicenseFile[]; copyrightLines: string[] } {
    const licenseFiles: LicenseFile[] = [];
    const texts: string[] = [];
    let total = 0;
    let textLimitReached = false;
    for (const slot of this.slots) {
      if (slot.bytes === null) {
        licenseFiles.push({ path: slot.path, omitted: 'file_too_large' });
        continue;
      }
      if (textLimitReached || total + slot.bytes.length > this.limits.maxPackageTextBytes) {
        textLimitReached = true;
        licenseFiles.push({ path: slot.path, omitted: 'package_text_limit' });
        continue;
      }
      const text = decodeAndSanitize(slot.bytes);
      if (text === null) continue;
      total += slot.bytes.length;
      licenseFiles.push({ path: slot.path, text });
      texts.push(text);
    }
    return { licenseFiles, copyrightLines: extractCopyrightLines(texts) };
  }
}

/** Final result of a collector: `no_license_file` when nothing was selected. */
export function collectedResult(collector: LicenseFileCollector, emptyOutcome?: { outcome: ExtractOutcome; detail: string }): ExtractResult {
  const { licenseFiles, copyrightLines } = collector.finish();
  if (licenseFiles.length === 0) {
    return { outcome: emptyOutcome?.outcome ?? 'no_license_file', outcomeDetail: emptyOutcome?.detail ?? null, licenseFiles: [], copyrightLines: [] };
  }
  return { outcome: 'collected', outcomeDetail: null, licenseFiles, copyrightLines };
}
