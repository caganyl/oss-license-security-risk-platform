/**
 * Retry, timeout and failure classification of scan jobs (REQ-003 P-13;
 * ADR-004 Karar 7, 8, 9). Pure functions and error classes only: the worker
 * (`src/scanner/worker.ts`) does the database writes.
 */
import { boundedNumber } from '../lib/bounds';
import { MAX_SCAN_ATTEMPTS, MAX_TIMEOUT_MINUTES, sandboxRunnerConfig } from './sandbox/runner.config';

/**
 * Deterministic failure (invalid source, ref or token): the scan fails
 * without retry (ADR-002 karar 3, 6; ADR-004 Karar 8).
 */
export class NonRetryableScanError extends Error {
  readonly permanent = true;
  constructor(message: string) {
    super(message);
    this.name = 'NonRetryableScanError';
  }
}

/** Why a scan job's `AbortController` was aborted (ADR-004 Karar 7). */
export type ScanAbortReason = 'timeout' | 'shutdown';

/**
 * The `reason` a scan job is aborted with. Code that honours the signal
 * (thread parser, clone, OSV lookup, result write) rethrows it as is.
 */
export class ScanAbortError extends Error {
  constructor(readonly abortReason: ScanAbortReason) {
    super(abortReason === 'timeout' ? 'Scan aborted: job time limit reached' : 'Scan aborted: application shutting down');
    this.name = 'ScanAbortError';
  }
}

/**
 * - `return-to-queue`: shutdown return (Karar 5): `queued`, `retry_count`
 *   unchanged, `next_attempt_at`/`worker_id` NULL, `error_message` unchanged.
 * - `permanent`: `failed` at once.
 * - `transient`: retried with backoff while attempts remain.
 */
export type ScanFailureClass = 'return-to-queue' | 'permanent' | 'transient';

/** Errors that carry `permanent = true` (`NonRetryableScanError`, parser thread errors, ...). */
export function isPermanentError(err: unknown): boolean {
  return !!err && typeof err === 'object' && (err as { permanent?: unknown }).permanent === true;
}

/** Abort reason of an aborted job signal, or null when it was not aborted by us. */
export function abortReasonOf(signal: AbortSignal | undefined): ScanAbortReason | null {
  if (!signal?.aborted) return null;
  const reason = signal.reason;
  return reason instanceof ScanAbortError ? reason.abortReason : null;
}

/**
 * ADR-004 Karar 8 table, first match wins. The job signal decides first: an
 * error thrown after an abort (killed clone, terminated thread, rolled back
 * write) is a consequence of the abort, not its own failure.
 *
 * | shutdown abort | return-to-queue |
 * | timeout abort | permanent |
 * | token / source / SCAN_ROOTS / ref (`NonRetryableScanError`) | permanent |
 * | parser thread crash / memory limit / `failed` result (`permanent = true`) | permanent |
 * | clone failure or clone timeout, database error, anything else | transient |
 *
 * (Git missing/older than 2.32 is a permanent error of REQ-003 AC-T-3:
 * `GitUnavailableError` in `gitVersion.ts` carries `permanent = true`.)
 */
export function classifyScanFailure(err: unknown, signal?: AbortSignal): ScanFailureClass {
  const aborted = abortReasonOf(signal);
  if (aborted === 'shutdown') return 'return-to-queue';
  if (aborted === 'timeout') return 'permanent';
  if (err instanceof ScanAbortError) return err.abortReason === 'shutdown' ? 'return-to-queue' : 'permanent';
  if (isPermanentError(err)) return 'permanent';
  return 'transient';
}

/**
 * Wait before the n-th retry in seconds (AC-P13-1, D-40):
 * `min(600, 30 * 2^(n-1))` -> 30, 60, 120, 240, 480, 600, 600, ... No jitter.
 * `n` must be an integer >= 1.
 */
export function backoffSeconds(n: number): number {
  if (!Number.isInteger(n) || n < 1) {
    throw new RangeError(`backoffSeconds: n must be an integer >= 1 (got ${String(n)})`);
  }
  const baseSeconds = sandboxRunnerConfig.retry.initialBackoffMs / 1000;
  const maxSeconds = sandboxRunnerConfig.retry.maxBackoffMs / 1000;
  return Math.min(maxSeconds, baseSeconds * 2 ** (n - 1));
}

/**
 * Next step after a failed attempt (AC-P13-2, AC-P13-3). `retryCount` is the
 * row's current `retry_count`, `maxAttempts` = `scan.max_retries` (total
 * attempts including the first). The failing attempt is number
 * `retryCount + 1`; a retry is possible only while that is below `maxAttempts`.
 */
export type RetryDecision =
  | { action: 'retry'; attempt: number; maxAttempts: number; delaySeconds: number }
  | { action: 'fail'; attempt: number; maxAttempts: number };

export function decideRetry(failureClass: 'permanent' | 'transient', retryCount: number, maxAttempts: number): RetryDecision {
  const attempt = retryCount + 1;
  if (failureClass === 'transient' && attempt < maxAttempts) {
    return { action: 'retry', attempt, maxAttempts, delaySeconds: backoffSeconds(attempt) };
  }
  return { action: 'fail', attempt, maxAttempts };
}

/** `error_message` of a scan stopped by the job time limit (AC-P13-6). */
export function timeoutMessage(timeoutMinutes: number): string {
  const minutes = Number.isInteger(timeoutMinutes) ? String(timeoutMinutes) : String(Number(timeoutMinutes.toFixed(2)));
  return `Tarama süre sınırını aştı (${minutes} dk).`;
}

/** `error_message` of a scan recovered as orphaned (AC-P12-11, ADR-004 Karar 9). */
export const ORPHAN_RECOVERY_MESSAGE = 'Uygulama tarama sürerken durdu; tarama kurtarıldı.';

/** Parsed `system_settings` values used by the queue. */
export interface ScanQueueSettings {
  /** `scan.max_retries`: total attempts including the first. */
  maxAttempts: number;
  /** `scan.timeout_minutes`: job time limit. */
  timeoutMinutes: number;
}

export const DEFAULT_TIMEOUT_MINUTES = 60;

/**
 * Reads `scan.max_retries` / `scan.timeout_minutes` rows (`{ key, value }`);
 * a missing, invalid or out-of-range value falls back to the default
 * (security review I-3): `scan.max_retries` is an integer 1–10,
 * `scan.timeout_minutes` is greater than 0 and at most 1440 (24 h; keeps the
 * job timer below the `setTimeout` limit). `warn` receives one message per
 * rejected value (the caller de-duplicates; the rows are read on every poll).
 */
export function parseScanQueueSettings(
  rows: ReadonlyArray<{ key: string; value: unknown }>,
  warn: (message: string) => void = () => undefined,
): ScanQueueSettings {
  const settings: ScanQueueSettings = {
    maxAttempts: sandboxRunnerConfig.retry.maxAttempts,
    timeoutMinutes: DEFAULT_TIMEOUT_MINUTES,
  };
  for (const row of rows) {
    // A JSON/text `null` is "not set", like a missing row.
    const raw = row.value === null ? undefined : typeof row.value === 'string' || typeof row.value === 'number' ? row.value : String(row.value);
    if (row.key === 'scan.max_retries') {
      settings.maxAttempts = boundedNumber(raw, settings.maxAttempts, {
        name: 'system_settings scan.max_retries',
        min: 1,
        max: MAX_SCAN_ATTEMPTS,
        integer: true,
        warn,
      });
    }
    if (row.key === 'scan.timeout_minutes') {
      settings.timeoutMinutes = boundedNumber(raw, settings.timeoutMinutes, {
        name: 'system_settings scan.timeout_minutes',
        min: 0,
        exclusiveMin: true,
        max: MAX_TIMEOUT_MINUTES,
        warn,
      });
    }
  }
  return settings;
}

/** `error_message` fallback of a waiting scan whose attempts are used up after `scan.max_retries` was lowered (I-3). */
export const ATTEMPTS_EXHAUSTED_MESSAGE = 'Deneme hakkı bitti (scan.max_retries düşürüldü); tarama yeniden denenmeyecek.';
