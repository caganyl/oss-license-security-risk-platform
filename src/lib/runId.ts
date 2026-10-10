import crypto from 'node:crypto';
import os from 'node:os';

/**
 * Per-process run id written to `scans.worker_id` (REQ-003 AC-P12-3, ADR-004
 * Karar 4): `<hostname>:<pid>:<8 random hex>`. It replaces the removed
 * worker-id environment variables (REQ-003 AC-P12-3). Used for
 * information and as the write fence (`status = 'running' AND worker_id = $runId`).
 */
export function createRunId(): string {
  return `${os.hostname()}:${process.pid}:${crypto.randomUUID().slice(0, 8)}`;
}
