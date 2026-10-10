/**
 * Streaming gunzip with a decompressed-bytes cap (REQ-004 AC-P15-5;
 * ADR-006 Karar 7). The decompressed content is never held as a whole: each
 * 64 KiB chunk goes to `onChunk` (the tar state machine) and is dropped.
 * Concatenated gzip members are handled by Node's gunzip stream.
 *
 * Boundary rule (ADR-006 Karar 1): thread module; imports only `node:zlib`
 * and sibling thread modules.
 */
import zlib from 'node:zlib';
import { ArchiveFailure } from './licenseFiles';

const CHUNK_SIZE = 64 * 1024;

/**
 * Decompresses `input`, passing every chunk to `onChunk`. Rejects with
 * `ArchiveFailure('limit_exceeded', 'decompressed')` once more than
 * `maxOutputBytes` came out, `ArchiveFailure('unsupported_format', 'gzip')`
 * for corrupt data, or with whatever `onChunk` throws (the stream is
 * destroyed in every case). `onChunk` returning `false` stops early (e.g.
 * after the tar end-of-archive blocks) and resolves.
 */
export function gunzipStream(input: Uint8Array, maxOutputBytes: number, onChunk: (chunk: Buffer) => boolean | void): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const gunzip = zlib.createGunzip({ chunkSize: CHUNK_SIZE });
    let total = 0;
    let settled = false;
    const finish = (err?: unknown) => {
      if (settled) return;
      settled = true;
      gunzip.removeAllListeners('data');
      gunzip.destroy();
      if (err === undefined) resolve();
      else reject(err);
    };
    gunzip.on('data', (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxOutputBytes) {
        finish(new ArchiveFailure('limit_exceeded', 'decompressed'));
        return;
      }
      try {
        if (onChunk(chunk) === false) finish();
      } catch (err) {
        finish(err);
      }
    });
    gunzip.on('error', () => finish(new ArchiveFailure('unsupported_format', 'gzip')));
    gunzip.on('end', () => finish());
    gunzip.end(Buffer.from(input.buffer, input.byteOffset, input.byteLength));
  });
}
