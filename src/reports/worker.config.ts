/**
 * Export job worker configuration.
 *
 * Polling interval, concurrency and timeout of the asynchronous report queue.
 * The worker runs inside the single runtime process (REQ-003 P-12); it has
 * no worker id of its own any more (AC-P12-3).
 */

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

export const exportWorkerConfig: ExportWorkerConfig = {
  maxConcurrentExports: Number(process.env.EXPORT_WORKER_MAX_CONCURRENT) || 4,
  pollIntervalMs: Number(process.env.EXPORT_WORKER_POLL_INTERVAL_MS) || 5000,
  timeoutMs: Number(process.env.EXPORT_WORKER_TIMEOUT_MS) || 10 * 60 * 1000, // 10 minutes default
} as const;
