/**
 * Central-directory zip reader for wheels and `.zip` sdists (REQ-004
 * AC-P15-5…7; ADR-006 Karar 7).
 *
 * - EOCD searched backwards within the last `22 + 65 535` bytes; the first
 *   candidate whose comment length ends exactly at the end of the buffer.
 * - ZIP64 (any `0xFFFF`/`0xFFFFFFFF` EOCD field, a ZIP64 locator, or a
 *   `0x0001` extra field) and multi-disk archives -> `unsupported_format`.
 * - More than `maxEntries` entries -> `limit_exceeded` (`entries`).
 * - Only the selected license file entries are opened: encrypted entries
 *   (flag bit 0 or 6) and methods other than stored/deflate are skipped; the
 *   local header must agree with the central directory; deflate output is
 *   capped at `min(declared, 1 MiB) + 1`; a size or CRC-32 mismatch skips
 *   the entry. A declared size over 1 MiB is "file too large" unopened.
 * - Names: UTF-8 with flag bit 11, latin1 otherwise (matching only).
 *
 * Boundary rule (ADR-006 Karar 1): thread module; imports only `node:zlib`
 * and sibling thread modules.
 */
import zlib from 'node:zlib';
import { ArchiveFailure, type ArchiveLimits, LicenseFileCollector, LicenseFileMatcher, normalizeArchivePath } from './licenseFiles';

/** `zlib.crc32` (Node >= 22.2); `@types/node` 20 does not declare it (ADR-006 Karar 5). */
const crc32 = (zlib as unknown as { crc32(data: Uint8Array): number }).crc32;

const EOCD_SIG = 0x06054b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

export interface ZipEntry {
  name: string;
  nameBytes: Buffer;
  flags: number;
  method: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
}

export type ZipEntryRead = { kind: 'ok'; bytes: Buffer } | { kind: 'too_large' } | { kind: 'skip'; reason: 'encrypted' | 'method' | 'corrupt' };

/** Central directory entries of `buf` (throws `ArchiveFailure`). */
export function readCentralDirectory(buf: Buffer, maxEntries: number): ZipEntry[] {
  if (buf.length < 22) throw new ArchiveFailure('unsupported_format', 'eocd');
  const lowest = Math.max(0, buf.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = buf.length - 22; i >= lowest; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG && i + 22 + buf.readUInt16LE(i + 20) === buf.length) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new ArchiveFailure('unsupported_format', 'eocd');

  const disk = buf.readUInt16LE(eocd + 4);
  const cdDisk = buf.readUInt16LE(eocd + 6);
  const diskEntries = buf.readUInt16LE(eocd + 8);
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if ([disk, cdDisk, diskEntries, totalEntries].includes(0xffff) || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ArchiveFailure('unsupported_format', 'zip64');
  }
  if (eocd >= 20 && buf.readUInt32LE(eocd - 20) === ZIP64_LOCATOR_SIG) throw new ArchiveFailure('unsupported_format', 'zip64');
  if (disk !== 0 || cdDisk !== 0 || diskEntries !== totalEntries) throw new ArchiveFailure('unsupported_format', 'multi_disk');
  if (totalEntries > maxEntries) throw new ArchiveFailure('limit_exceeded', 'entries');
  if (cdOffset + cdSize > eocd) throw new ArchiveFailure('unsupported_format', 'central_directory');

  const entries: ZipEntry[] = [];
  let pos = cdOffset;
  for (let n = 0; n < totalEntries; n++) {
    if (pos + 46 > cdOffset + cdSize || buf.readUInt32LE(pos) !== CENTRAL_SIG) {
      throw new ArchiveFailure('unsupported_format', 'central_directory');
    }
    const flags = buf.readUInt16LE(pos + 8);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const end = pos + 46 + nameLen + extraLen + commentLen;
    if (end > cdOffset + cdSize) throw new ArchiveFailure('unsupported_format', 'central_directory');
    if (buf.readUInt16LE(pos + 34) !== 0) throw new ArchiveFailure('unsupported_format', 'multi_disk');
    const compressedSize = buf.readUInt32LE(pos + 20);
    const uncompressedSize = buf.readUInt32LE(pos + 24);
    const localOffset = buf.readUInt32LE(pos + 42);
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      throw new ArchiveFailure('unsupported_format', 'zip64');
    }
    // Extra fields: a ZIP64 (0x0001) block is not supported.
    let x = pos + 46 + nameLen;
    const extraEnd = x + extraLen;
    while (x + 4 <= extraEnd) {
      const id = buf.readUInt16LE(x);
      const size = buf.readUInt16LE(x + 2);
      if (id === 0x0001) throw new ArchiveFailure('unsupported_format', 'zip64');
      x += 4 + size;
    }
    const nameBytes = buf.subarray(pos + 46, pos + 46 + nameLen);
    const name = (flags & 0x0800) !== 0 ? nameBytes.toString('utf8') : nameBytes.toString('latin1');
    entries.push({
      name,
      nameBytes,
      flags,
      method: buf.readUInt16LE(pos + 10),
      crc: buf.readUInt32LE(pos + 16),
      compressedSize,
      uncompressedSize,
      localOffset,
    });
    pos = end;
  }
  return entries;
}

/** Opens one entry (only called for selected license file candidates). */
export function readZipEntry(buf: Buffer, entry: ZipEntry, maxFileBytes: number): ZipEntryRead {
  if ((entry.flags & 0x0001) !== 0 || (entry.flags & 0x0040) !== 0) return { kind: 'skip', reason: 'encrypted' };
  if (entry.method !== 0 && entry.method !== 8) return { kind: 'skip', reason: 'method' };
  if (entry.uncompressedSize > maxFileBytes) return { kind: 'too_large' };
  const lo = entry.localOffset;
  if (lo + 30 > buf.length || buf.readUInt32LE(lo) !== LOCAL_SIG) return { kind: 'skip', reason: 'corrupt' };
  const nameLen = buf.readUInt16LE(lo + 26);
  const extraLen = buf.readUInt16LE(lo + 28);
  if (buf.readUInt16LE(lo + 8) !== entry.method) return { kind: 'skip', reason: 'corrupt' };
  const start = lo + 30 + nameLen + extraLen;
  const end = start + entry.compressedSize;
  if (lo + 30 + nameLen > buf.length || !buf.subarray(lo + 30, lo + 30 + nameLen).equals(entry.nameBytes) || end > buf.length) {
    return { kind: 'skip', reason: 'corrupt' };
  }
  const data = buf.subarray(start, end);
  let bytes: Buffer;
  if (entry.method === 0) {
    bytes = data;
  } else {
    try {
      bytes = zlib.inflateRawSync(data, { maxOutputLength: Math.min(entry.uncompressedSize, maxFileBytes) + 1 });
    } catch {
      return { kind: 'skip', reason: 'corrupt' };
    }
  }
  if (bytes.length !== entry.uncompressedSize || (crc32(bytes) >>> 0) !== entry.crc >>> 0) return { kind: 'skip', reason: 'corrupt' };
  return { kind: 'ok', bytes };
}

/**
 * License files of a zip archive. When every selected entry was skipped as
 * encrypted or with an unsupported method, the package outcome is
 * `unsupported_format` (ADR-006 Karar 7, per-entry note).
 */
export function extractZip(
  buf: Buffer,
  limits: ArchiveLimits,
  matcher: LicenseFileMatcher,
  collector: LicenseFileCollector,
): { unsupportedEntry: string | null } {
  const entries = readCentralDirectory(buf, limits.maxEntries);
  const selected: Array<{ path: string; entry: ZipEntry }> = [];
  for (const entry of entries) {
    if (entry.name.endsWith('/') || entry.name.endsWith('\\')) continue;
    const path = normalizeArchivePath(entry.name);
    if (path === null) continue;
    matcher.observeRegularFile(path);
    if (matcher.matches(path)) selected.push({ path, entry });
  }
  selected.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  let unsupportedEntry: string | null = null;
  for (const { path, entry } of selected) {
    if (!collector.wants(path)) continue;
    const read = readZipEntry(buf, entry, limits.maxFileBytes);
    if (read.kind === 'ok') collector.add(path, read.bytes);
    else if (read.kind === 'too_large') collector.add(path, null);
    else if (read.reason !== 'corrupt') unsupportedEntry ??= read.reason;
  }
  return { unsupportedEntry };
}
