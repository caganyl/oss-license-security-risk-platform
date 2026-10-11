/**
 * Archive thread entry (REQ-004 AC-P15-4; ADR-006 Karar 7). One thread per
 * archive: `workerData` carries `{ kind, filename, limits }` (NuGet also
 * `declaredLicensePath` and `verify`); the archive bytes arrive as one
 * transferred `ArrayBuffer` message. The reply is `{ ok: true, result }`,
 * `{ ok: true, integrityMismatch: true }` (NuGet content hash did not match:
 * no entry was opened, ADR-008 Karar 10.2) or `{ ok: false, error }` (error
 * class name only).
 *
 * Boundary rule (ADR-006 Karar 1): imports only `node:worker_threads` and
 * sibling thread modules — no `fs`, `net`, `http(s)`, `child_process`, `pg`.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { type ArchiveKind, extractArchive } from './extract';
import type { ArchiveLimits } from './licenseFiles';
import { nugetSignedContentHash } from './nupkgHash';

export interface ArchiveThreadData {
  kind: ArchiveKind;
  filename: string | null;
  limits: ArchiveLimits;
  /** NuGet `.nuspec` `<license type="file">` path. */
  declaredLicensePath?: string | null;
  /** NuGet: verify the signed-package content hash against these `sha512-<b64>` values BEFORE any entry is opened. */
  verify?: { nugetContentHash: string[] };
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
    if (data.verify !== undefined) {
      let computed: string | null = null;
      try {
        computed = nugetSignedContentHash(Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength), data.limits.maxEntries);
      } catch {
        computed = null;
      }
      if (computed === null || !data.verify.nugetContentHash.includes(computed)) {
        port.postMessage({ ok: true, integrityMismatch: true });
        return;
      }
    }
    extractArchive({ kind: data.kind, filename: data.filename, bytes, limits: data.limits, declaredLicensePath: data.declaredLicensePath ?? null }).then(
      (result) => port.postMessage({ ok: true, result }),
      (err: unknown) => port.postMessage({ ok: false, error: err instanceof Error ? err.name : 'Error' }),
    );
  });
}
