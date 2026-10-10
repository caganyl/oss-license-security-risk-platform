/**
 * Streaming tar reader (ustar, PAX `x`/`g`, GNU `L`/`K`) for gzip'd npm
 * tarballs and sdists (REQ-004 AC-P15-5…7; ADR-006 Karar 7).
 *
 * - 512-byte headers; the checksum (unsigned sum, `chksum` counted as
 *   spaces) must match, otherwise `unsupported_format` (`header`).
 * - Two zero blocks or the end of the stream finish the archive.
 * - Octal sizes only; GNU base-256 (first byte `0x80`) -> `unsupported_format`.
 * - Name: ustar `prefix + '/' + name`; PAX `path`/`size` and GNU `L` apply to
 *   the next entry; PAX/GNU bodies <= 64 KiB (`limit_exceeded`/`long_name`);
 *   malformed PAX records -> `unsupported_format` (`pax`).
 * - Types `0`, `\0`, `7` are regular files; every other type is skipped.
 * - More than `maxEntries` entries (meta headers included) ->
 *   `limit_exceeded` (`entries`).
 * Only the bodies of selected license files are buffered.
 *
 * Boundary rule (ADR-006 Karar 1): thread module; imports only sibling
 * thread modules.
 */
import { ArchiveFailure, type ArchiveLimits, LicenseFileCollector, LicenseFileMatcher, normalizeArchivePath } from './licenseFiles';

const BLOCK = 512;

type State =
  | { kind: 'header' }
  | { kind: 'body'; remaining: number; padding: number; sink: 'skip' | 'file' | 'meta'; path: string | null; metaType: string }
  | { kind: 'done' };

function cString(block: Uint8Array, start: number, length: number): Uint8Array {
  const field = block.subarray(start, start + length);
  const nul = field.indexOf(0);
  return nul === -1 ? field : field.subarray(0, nul);
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

function parseOctal(field: Uint8Array): number {
  let value = 0;
  let seen = false;
  for (const byte of field) {
    if (byte === 0 || byte === 0x20) {
      if (seen) break;
      continue;
    }
    if (byte < 0x30 || byte > 0x37) throw new ArchiveFailure('unsupported_format', 'header');
    value = value * 8 + (byte - 0x30);
    seen = true;
    if (value > Number.MAX_SAFE_INTEGER / 8) throw new ArchiveFailure('unsupported_format', 'header');
  }
  return value;
}

function isZeroBlock(block: Uint8Array): boolean {
  for (const byte of block) if (byte !== 0) return false;
  return true;
}

function verifyChecksum(block: Uint8Array): void {
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : block[i];
  if (parseOctal(block.subarray(148, 156)) !== sum) throw new ArchiveFailure('unsupported_format', 'header');
}

/** PAX extended header records (`"<length> <key>=<value>\n"`), parsed linearly. */
export function parsePaxRecords(body: Uint8Array): Map<string, string> {
  const records = new Map<string, string>();
  let pos = 0;
  while (pos < body.length) {
    // A trailing NUL padding run ends the records.
    if (body[pos] === 0) break;
    let length = 0;
    let i = pos;
    while (i < body.length && body[i] >= 0x30 && body[i] <= 0x39 && i - pos < 12) {
      length = length * 10 + (body[i] - 0x30);
      i++;
    }
    if (i === pos || i >= body.length || body[i] !== 0x20 || length <= i - pos + 1 || pos + length > body.length) {
      throw new ArchiveFailure('unsupported_format', 'pax');
    }
    const record = body.subarray(i + 1, pos + length);
    if (record.length === 0 || record[record.length - 1] !== 0x0a) throw new ArchiveFailure('unsupported_format', 'pax');
    const eq = record.indexOf(0x3d);
    if (eq <= 0) throw new ArchiveFailure('unsupported_format', 'pax');
    records.set(utf8.decode(record.subarray(0, eq)), utf8.decode(record.subarray(eq + 1, record.length - 1)));
    pos += length;
  }
  return records;
}

/**
 * Push-based tar state machine. `push` accepts decompressed chunks of any
 * size and returns false once the archive ended; `end` checks the stream did
 * not stop inside an entry.
 */
export class TarReader {
  private state: State = { kind: 'header' };
  private header = new Uint8Array(BLOCK);
  private headerFill = 0;
  private zeroBlocks = 0;
  private entries = 0;
  private pending: { path?: string; size?: number } = {};
  private parts: Buffer[] = [];
  private partsBytes = 0;

  constructor(
    private readonly limits: ArchiveLimits,
    private readonly matcher: LicenseFileMatcher,
    private readonly collector: LicenseFileCollector,
  ) {}

  push(chunk: Uint8Array): boolean {
    let offset = 0;
    while (offset < chunk.length) {
      const state = this.state;
      if (state.kind === 'done') return false;
      if (state.kind === 'header') {
        const take = Math.min(BLOCK - this.headerFill, chunk.length - offset);
        this.header.set(chunk.subarray(offset, offset + take), this.headerFill);
        this.headerFill += take;
        offset += take;
        if (this.headerFill === BLOCK) {
          this.headerFill = 0;
          this.onHeader(this.header);
        }
        continue;
      }
      // Body (data then padding).
      if (state.remaining > 0) {
        const take = Math.min(state.remaining, chunk.length - offset);
        if (state.sink !== 'skip') {
          this.parts.push(Buffer.from(chunk.subarray(offset, offset + take)));
          this.partsBytes += take;
        }
        state.remaining -= take;
        offset += take;
        if (state.remaining === 0) this.onBodyComplete(state);
        continue;
      }
      const take = Math.min(state.padding, chunk.length - offset);
      state.padding -= take;
      offset += take;
      if (state.padding === 0) this.state = { kind: 'header' };
    }
    return this.state.kind !== 'done';
  }

  end(): void {
    if (this.state.kind === 'body' || (this.state.kind === 'header' && this.headerFill > 0)) {
      throw new ArchiveFailure('unsupported_format', 'truncated');
    }
  }

  private onHeader(block: Uint8Array): void {
    if (isZeroBlock(block)) {
      this.zeroBlocks++;
      if (this.zeroBlocks >= 2) this.state = { kind: 'done' };
      return;
    }
    this.zeroBlocks = 0;
    verifyChecksum(block);
    this.entries++;
    if (this.entries > this.limits.maxEntries) throw new ArchiveFailure('limit_exceeded', 'entries');

    if ((block[124] & 0x80) !== 0) throw new ArchiveFailure('unsupported_format', 'base256');
    let size = parseOctal(block.subarray(124, 136));
    const type = String.fromCharCode(block[156]);
    const isUstar = utf8.decode(block.subarray(257, 262)) === 'ustar';
    let name = utf8.decode(cString(block, 0, 100));
    if (isUstar) {
      const prefix = utf8.decode(cString(block, 345, 155));
      if (prefix.length > 0) name = `${prefix}/${name}`;
    }

    const padding = (BLOCK - (size % BLOCK)) % BLOCK;
    if (type === 'x' || type === 'g' || type === 'L' || type === 'K') {
      if (size > this.limits.maxLongNameBytes) throw new ArchiveFailure('limit_exceeded', 'long_name');
      this.beginBody({ kind: 'body', remaining: size, padding, sink: 'meta', path: null, metaType: type });
      return;
    }

    const pending = this.pending;
    this.pending = {};
    if (pending.path !== undefined) name = pending.path;
    if (pending.size !== undefined) size = pending.size;
    const bodyPadding = (BLOCK - (size % BLOCK)) % BLOCK;

    if (type !== '0' && type !== '\u0000' && type !== '7') {
      this.beginBody({ kind: 'body', remaining: size, padding: bodyPadding, sink: 'skip', path: null, metaType: type });
      return;
    }
    const path = normalizeArchivePath(name);
    if (path === null || path.endsWith('/')) {
      this.beginBody({ kind: 'body', remaining: size, padding: bodyPadding, sink: 'skip', path: null, metaType: type });
      return;
    }
    this.matcher.observeRegularFile(path);
    if (!this.matcher.matches(path) || !this.collector.wants(path)) {
      this.beginBody({ kind: 'body', remaining: size, padding: bodyPadding, sink: 'skip', path: null, metaType: type });
      return;
    }
    if (size > this.limits.maxFileBytes) {
      this.collector.add(path, null);
      this.beginBody({ kind: 'body', remaining: size, padding: bodyPadding, sink: 'skip', path: null, metaType: type });
      return;
    }
    this.beginBody({ kind: 'body', remaining: size, padding: bodyPadding, sink: 'file', path, metaType: type });
  }

  private beginBody(state: Extract<State, { kind: 'body' }>): void {
    this.parts = [];
    this.partsBytes = 0;
    this.state = state;
    if (state.remaining === 0) this.onBodyComplete(state);
  }

  private onBodyComplete(state: Extract<State, { kind: 'body' }>): void {
    if (state.sink === 'file' && state.path !== null) {
      this.collector.add(state.path, Buffer.concat(this.parts, this.partsBytes));
    } else if (state.sink === 'meta') {
      const body = Buffer.concat(this.parts, this.partsBytes);
      if (state.metaType === 'x' || state.metaType === 'g') {
        const records = parsePaxRecords(body);
        if (state.metaType === 'x') {
          const paxPath = records.get('path');
          if (paxPath !== undefined) this.pending.path = paxPath;
          const paxSize = records.get('size');
          if (paxSize !== undefined) {
            if (!/^\d{1,15}$/.test(paxSize)) throw new ArchiveFailure('unsupported_format', 'pax');
            this.pending.size = Number(paxSize);
          }
        }
      } else if (state.metaType === 'L') {
        this.pending.path = utf8.decode(cString(body, 0, body.length));
      }
    }
    this.parts = [];
    this.partsBytes = 0;
    if (state.padding === 0) this.state = { kind: 'header' };
  }
}
