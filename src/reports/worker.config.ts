/**
 * Export job worker configuration.
 *
 * Configures the polling interval, worker ID, concurrency, and timeout settings
 * for the asynchronous compliance report and export queue.
 */

export interface ExportWorkerConfig {
  /**
   * Unique identifier for this worker instance.
   * Defaults to hostname + PID if not set via env.
   */
  workerId: string;

  /**
   * Maximum number of export jobs that this worker process may run
   * concurrently.
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
  workerId:
    process.env.EXPORT_WORKER_ID ??
    `${process.env.HOSTNAME ?? 'export-worker'}-${process.pid}`,
  maxConcurrentExports: Number(process.env.EXPORT_WORKER_MAX_CONCURRENT) || 4,
  pollIntervalMs: Number(process.env.EXPORT_WORKER_POLL_INTERVAL_MS) || 5000,
  timeoutMs: Number(process.env.EXPORT_WORKER_TIMEOUT_MS) || 10 * 60 * 1000, // 10 minutes default
} as const;
