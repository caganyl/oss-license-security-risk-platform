/**
 * Export job worker configuration.
 *
 * Polling interval, concurrency and timeout of the asynchronous report queue.
 * The worker runs inside the single runtime process (REQ-003 P-12); it has
 * no worker id of its own any more (AC-P12-3).
 */

import { boundedNumber } from '../lib/bounds';
import { MAX_JOB_TIMEOUT_MS, MAX_POLL_INTERVAL_MS, MAX_WORKER_CONCURRENCY } from '../scanner/sandbox/runner.config';

export interface ExportWorkerConfig {
  /**
   * Maximum number of export jobs that this worker may run concurrently.
   */
  maxConcurrentExports: number;

  /**
   * How often (ms) the worker polls the DB queue for new export jobs.
   */
  pollIntervalMs: number;

  /**
   * Hard timeout limit for a single export generation process in milliseconds.
   */
  timeoutMs: number;
}

// Range-checked (security review I-3): out of range -> default + warning.
export const exportWorkerConfig: ExportWorkerConfig = {
  maxConcurrentExports: boundedNumber(process.env.EXPORT_WORKER_MAX_CONCURRENT, 4, {
    name: 'EXPORT_WORKER_MAX_CONCURRENT',
    min: 1,
    max: MAX_WORKER_CONCURRENCY,
    integer: true,
  }),
  pollIntervalMs: boundedNumber(process.env.EXPORT_WORKER_POLL_INTERVAL_MS, 5000, {
    name: 'EXPORT_WORKER_POLL_INTERVAL_MS',
    min: 1,
    max: MAX_POLL_INTERVAL_MS,
    integer: true,
  }),
  // 10 minutes default
  timeoutMs: boundedNumber(process.env.EXPORT_WORKER_TIMEOUT_MS, 10 * 60 * 1000, {
    name: 'EXPORT_WORKER_TIMEOUT_MS',
    min: 1,
    max: MAX_JOB_TIMEOUT_MS,
    integer: true,
  }),
} as const;
