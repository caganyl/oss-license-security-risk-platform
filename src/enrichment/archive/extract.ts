/**
 * Combined archive flow run inside the archive thread (REQ-004 AC-P15-4…9;
 * ADR-006 Karar 7): format detection -> reader -> license file selection ->
 * decoding -> copyright lines.
 *
 * Format: npm -> gzip'd tar. PyPI -> the file name extension (`.whl`/`.zip`
 * -> zip, `.tar.gz` -> gzip'd tar) and the magic bytes (`1f 8b`,
 * `PK\x03\x04` or the empty zip `PK\x05\x06`) must agree, otherwise
 * `unsupported_format`.
 *
 * Boundary rule (ADR-006 Karar 1): thread module; imports only sibling
 * thread modules.
 */
import { gunzipStream } from './gzip';
import {
  ArchiveFailure,
  type ArchiveLimits,
  type ExtractResult,
  LicenseFileCollector,
  LicenseFileMatcher,
  collectedResult,
} from './licenseFiles';
import { TarReader } from './tar';
import { extractZip } from './zip';

export type ArchiveKind = 'npm' | 'pypi';

export interface ExtractInput {
  kind: ArchiveKind;
  /** PyPI file name (format detection); ignored for npm. */
  filename: string | null;
  bytes: Uint8Array;
  limits: ArchiveLimits;
}

type Format = 'tgz' | 'zip';

function isGzip(b: Uint8Array): boolean {
  return b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
}

function isZip(b: Uint8Array): boolean {
  return b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && ((b[2] === 0x03 && b[3] === 0x04) || (b[2] === 0x05 && b[3] === 0x06));
}

/** Detected format, or null when extension and magic bytes disagree. */
export function detectFormat(kind: ArchiveKind, filename: string | null, bytes: Uint8Array): { format: Format; wheel: boolean } | null {
  if (kind === 'npm') return isGzip(bytes) ? { format: 'tgz', wheel: false } : null;
  const lower = (filename ?? '').toLowerCase();
  if (lower.endsWith('.whl')) return isZip(bytes) ? { format: 'zip', wheel: true } : null;
  if (lower.endsWith('.zip')) return isZip(bytes) ? { format: 'zip', wheel: false } : null;
  if (lower.endsWith('.tar.gz')) return isGzip(bytes) ? { format: 'tgz', wheel: false } : null;
  return null;
}

function failureResult(outcome: 'unsupported_format' | 'limit_exceeded', detail: string): ExtractResult {
  return { outcome, outcomeDetail: detail, licenseFiles: [], copyrightLines: [] };
}

export async function extractArchive(input: ExtractInput): Promise<ExtractResult> {
  const detected = detectFormat(input.kind, input.filename, input.bytes);
  if (detected === null) return failureResult('unsupported_format', 'format');
  const matcher = new LicenseFileMatcher(detected.wheel ? 'wheel' : 'top-folder');
  const collector = new LicenseFileCollector(input.limits);
  try {
    if (detected.format === 'zip') {
      const buf = Buffer.from(input.bytes.buffer, input.bytes.byteOffset, input.bytes.byteLength);
      const { unsupportedEntry } = extractZip(buf, input.limits, matcher, collector);
      return collectedResult(collector, unsupportedEntry === null ? undefined : { outcome: 'unsupported_format', detail: unsupportedEntry });
    }
    const reader = new TarReader(input.limits, matcher, collector);
    let ended = false;
    await gunzipStream(input.bytes, input.limits.maxDecompressedBytes, (chunk) => {
      if (!reader.push(chunk)) {
        ended = true;
        return false;
      }
      return true;
    });
    if (!ended) reader.end();
    return collectedResult(collector);
  } catch (err) {
    if (err instanceof ArchiveFailure) return failureResult(err.outcome, err.detail);
    throw err;
  }
}
