/**
 * NuGet signed-package content hash (REQ-006 AC-P21-9, AC-P21-16; ADR-008
 * Karar 10.3): SHA-512 of the `.nupkg` as if the `.signature.p7s` entry had
 * never been added (NuGet.Packaging
 * `SignedPackageArchiveUtility.GetPackageContentHash`).
 *
 * Only structural zip metadata is read: no entry is opened or decompressed.
 * The hash covers (a) the bytes before the first local header, (b) every
 * other local entry (header + data + descriptor) in local order, (c) every
 * other central directory record with its local offset shifted down by the
 * signature entry's local length when it lies after it, and (d) the EOCD with
 * the entry count minus one, the central directory size minus the signature
 * record and the central directory offset minus the signature entry, then the
 * original comment length and comment.
 *
 * "Not computable" (null): no or several root `.signature.p7s` entries,
 * ZIP64/multi-disk/too many entries (`readCentralDirectory` rules), a local
 * header that disagrees, overlapping or non-contiguous entries, or anything
 * outside the buffer. Constant extra memory, O(n).
 *
 * Boundary rule: archive-thread module; imports only `node:crypto` and the
 * sibling zip reader.
 */
import crypto from 'node:crypto';
import { readCentralDirectory } from './zip';

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const DESCRIPTOR_SIG = 0x08074b50;
const SIGNATURE_NAME = '.signature.p7s';

interface LocalSpan {
  index: number;
  start: number;
  end: number;
}

function findEocd(buf: Buffer): number {
  const lowest = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= lowest; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG && i + 22 + buf.readUInt16LE(i + 20) === buf.length) return i;
  }
  return -1;
}

function u16(value: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(value, 0);
  return b;
}

function u32(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(value >>> 0, 0);
  return b;
}

/** `sha512-<base64>` content hash of a signed `.nupkg`, or null when it cannot be computed. */
export function nugetSignedContentHash(buf: Buffer, maxEntries: number): string | null {
  let entries;
  try {
    entries = readCentralDirectory(buf, maxEntries);
  } catch {
    return null;
  }
  const eocd = findEocd(buf);
  if (eocd === -1) return null;
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count !== entries.length || cdOffset + cdSize !== eocd) return null;

  const signatures = entries.flatMap((e, i) => (e.name === SIGNATURE_NAME ? [i] : []));
  if (signatures.length !== 1) return null;
  const sigIndex = signatures[0];

  // Central record spans (sequential, validated by readCentralDirectory).
  const central: Array<{ start: number; end: number }> = [];
  let pos = cdOffset;
  for (let n = 0; n < count; n++) {
    if (pos + 46 > eocd || buf.readUInt32LE(pos) !== CENTRAL_SIG) return null;
    const end = pos + 46 + buf.readUInt16LE(pos + 28) + buf.readUInt16LE(pos + 30) + buf.readUInt16LE(pos + 32);
    if (end > eocd) return null;
    central.push({ start: pos, end });
    pos = end;
  }
  if (pos !== eocd) return null;

  // Local entry spans: header + data (+ data descriptor when flag bit 3 is set).
  const spans: LocalSpan[] = [];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const lo = e.localOffset;
    if (lo + 30 > cdOffset || buf.readUInt32LE(lo) !== LOCAL_SIG) return null;
    const nameLen = buf.readUInt16LE(lo + 26);
    const extraLen = buf.readUInt16LE(lo + 28);
    if (nameLen !== e.nameBytes.length || !buf.subarray(lo + 30, lo + 30 + nameLen).equals(e.nameBytes)) return null;
    let end = lo + 30 + nameLen + extraLen + e.compressedSize;
    if ((e.flags & 0x0008) !== 0) {
      if (end + 12 > cdOffset) return null;
      end += buf.readUInt32LE(end) === DESCRIPTOR_SIG && end + 16 <= cdOffset ? 16 : 12;
    }
    if (end > cdOffset) return null;
    spans.push({ index: i, start: lo, end });
  }
  spans.sort((a, b) => a.start - b.start);
  for (let i = 1; i < spans.length; i++) {
    if (spans[i].start !== spans[i - 1].end) return null; // overlap or gap
  }
  if (spans.length === 0 || spans[spans.length - 1].end !== cdOffset) return null;

  const sigSpan = spans.find((s) => s.index === sigIndex) as LocalSpan;
  const sigLocalLength = sigSpan.end - sigSpan.start;
  const sigCentralLength = central[sigIndex].end - central[sigIndex].start;

  const hash = crypto.createHash('sha512');
  hash.update(buf.subarray(0, spans[0].start)); // (a)
  for (const span of spans) {
    if (span.index !== sigIndex) hash.update(buf.subarray(span.start, span.end)); // (b)
  }
  for (let i = 0; i < count; i++) {
    if (i === sigIndex) continue;
    const { start, end } = central[i]; // (c)
    const lo = entries[i].localOffset;
    hash.update(buf.subarray(start, start + 42));
    hash.update(u32(lo > sigSpan.start ? lo - sigLocalLength : lo));
    hash.update(buf.subarray(start + 46, end));
  }
  hash.update(buf.subarray(eocd, eocd + 8)); // (d)
  hash.update(u16(count - 1));
  hash.update(u16(count - 1));
  hash.update(u32(cdSize - sigCentralLength));
  hash.update(u32(cdOffset - sigLocalLength));
  hash.update(buf.subarray(eocd + 20));
  return `sha512-${hash.digest('base64')}`;
}
