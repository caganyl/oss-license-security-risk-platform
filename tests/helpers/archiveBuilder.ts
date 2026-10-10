/**
 * REQ-004 · In-test builders for tar / gzip'd tar / zip archives (AC-P15-5…8).
 * Every archive is generated at test time — nothing binary is committed
 * (gzip bombs included). Only `node:zlib` / `node:crypto` are used.
 */
import crypto from 'node:crypto';
import zlib from 'node:zlib';

const crc32 = (zlib as unknown as { crc32(data: Uint8Array): number }).crc32;

export interface TarEntry {
  name: string;
  data?: Buffer | string;
  /** Tar type flag (default `'0'`). */
  type?: string;
  /** ustar prefix field (name is then the part after it). */
  prefix?: string;
  /** Write the `ustar` magic (default true). */
  ustar?: boolean;
  /** Override the size field (e.g. a PAX `size` makes the header size irrelevant). */
  sizeField?: number;
  /** Corrupt the checksum. */
  badChecksum?: boolean;
  /** Raw 12-byte size field (e.g. GNU base-256). */
  rawSize?: Buffer;
}

function octal(value: number, length: number): string {
  return value.toString(8).padStart(length - 1, '0') + '\0';
}

export function tarHeader(entry: TarEntry, size: number): Buffer {
  const h = Buffer.alloc(512, 0);
  h.write(entry.name, 0, 100, 'utf8');
  h.write(octal(0o644, 8), 100, 'ascii');
  h.write(octal(0, 8), 108, 'ascii');
  h.write(octal(0, 8), 116, 'ascii');
  if (entry.rawSize) entry.rawSize.copy(h, 124);
  else h.write(octal(entry.sizeField ?? size, 12), 124, 'ascii');
  h.write(octal(0, 12), 136, 'ascii');
  h.write(entry.type ?? '0', 156, 'ascii');
  if (entry.ustar !== false) {
    h.write('ustar\u000000', 257, 'binary');
    if (entry.prefix) h.write(entry.prefix, 345, 155, 'utf8');
  }
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  if (entry.badChecksum) sum += 1;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  return h;
}

function pad512(data: Buffer): Buffer {
  const rest = (512 - (data.length % 512)) % 512;
  return rest === 0 ? data : Buffer.concat([data, Buffer.alloc(rest, 0)]);
}

/** Tar stream of `entries`; `end` appends the two zero blocks. */
export function buildTar(entries: readonly TarEntry[], options: { end?: boolean } = {}): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = entry.data === undefined ? Buffer.alloc(0) : Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, 'utf8');
    parts.push(tarHeader(entry, data.length), pad512(data));
  }
  if (options.end !== false) parts.push(Buffer.alloc(1024, 0));
  return Buffer.concat(parts);
}

/** PAX extended header entry (`x`) carrying `records`. */
export function paxEntry(records: Record<string, string>): TarEntry {
  let body = '';
  for (const [key, value] of Object.entries(records)) {
    const tail = ` ${key}=${value}\n`;
    let len = tail.length + 1;
    while (String(len).length + tail.length !== len) len = String(len).length + tail.length;
    body += `${len}${tail}`;
  }
  return { name: 'PaxHeader', type: 'x', data: body };
}

/** GNU long-name entry (`L`) for the next header. */
export function gnuLongName(name: string): TarEntry {
  return { name: '././@LongLink', type: 'L', data: `${name}\0` };
}

export function tgz(entries: readonly TarEntry[], options: { end?: boolean } = {}): Buffer {
  return zlib.gzipSync(buildTar(entries, options));
}

export interface ZipEntrySpec {
  name: string;
  data: Buffer | string;
  /** 0 = stored, 8 = deflate (default), anything else is written as is with stored bytes. */
  method?: number;
  flags?: number;
  /** Extra field bytes of the central directory record. */
  extra?: Buffer;
  /** Write a wrong CRC. */
  badCrc?: boolean;
}

export interface ZipOptions {
  /** Write 0xFFFF entry counts in the EOCD (ZIP64 marker). */
  zip64Eocd?: boolean;
  /** Insert a ZIP64 EOCD locator signature before the EOCD. */
  zip64Locator?: boolean;
}

export function buildZip(entries: readonly ZipEntrySpec[], options: ZipOptions = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data, 'utf8');
    const method = e.method ?? 8;
    const body = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const name = Buffer.from(e.name, 'utf8');
    const flags = (e.flags ?? 0) | 0x0800;
    const crc = ((crc32(raw) >>> 0) + (e.badCrc ? 1 : 0)) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, body);
    const extra = e.extra ?? Buffer.alloc(0);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(extra.length, 30);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name, extra);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  const count = options.zip64Eocd ? 0xffff : entries.length;
  eocd.writeUInt16LE(count, 8);
  eocd.writeUInt16LE(count, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  const locator = options.zip64Locator ? Buffer.alloc(20) : Buffer.alloc(0);
  if (options.zip64Locator) locator.writeUInt32LE(0x07064b50, 0);
  return Buffer.concat([...locals, cd, locator, eocd]);
}

export const sha512b64 = (b: Buffer): string => crypto.createHash('sha512').update(b).digest('base64');
export const sha1hex = (b: Buffer): string => crypto.createHash('sha1').update(b).digest('hex');
export const sha256hex = (b: Buffer): string => crypto.createHash('sha256').update(b).digest('hex');
