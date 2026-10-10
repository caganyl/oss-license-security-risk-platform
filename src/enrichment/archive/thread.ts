/**
 * Archive thread entry (REQ-004 AC-P15-4; ADR-006 Karar 7). One thread per
 * archive: `workerData` carries `{ kind, filename, limits }`; the archive
 * bytes arrive as one transferred `ArrayBuffer` message. The reply is
 * `{ ok: true, result }` or `{ ok: false, error }` (error class name only).
 *
 * Boundary rule (ADR-006 Karar 1): imports only `node:worker_threads` and
 * sibling thread modules — no `fs`, `net`, `http(s)`, `child_process`, `pg`.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { type ArchiveKind, extractArchive } from './extract';
import type { ArchiveLimits } from './licenseFiles';

export interface ArchiveThreadData {
  kind: ArchiveKind;
  filename: string | null;
  limits: ArchiveLimits;
}

const port = parentPort;
if (port) {
  const data = workerData as ArchiveThreadData;
  port.once('message', (message: unknown) => {
    const bytes = message instanceof ArrayBuffer ? new Uint8Array(message) : null;
    if (bytes === null) {
      port.postMessage({ ok: false, error: 'BadInput' });
      return;
    }
    extractArchive({ kind: data.kind, filename: data.filename, bytes, limits: data.limits }).then(
      (result) => port.postMessage({ ok: true, result }),
      (err: unknown) => port.postMessage({ ok: false, error: err instanceof Error ? err.name : 'Error' }),
    );
  });
}
