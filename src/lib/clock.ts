/**
 * Injectable application clock (REQ-005; ADR-007 Karar 1, 9).
 *
 * - `AppClock.now()`: wall clock in ms (HTTP-date `Retry-After`, cache
 *   expiry, `vulnerability_checked_at`, recheck run times).
 * - `AppClock.sleep(ms, signal)`: abortable wait; resolves early (never
 *   rejects) when `signal` aborts.
 * - `localDateString(ms)`: the process-local calendar date `YYYY-MM-DD`
 *   ("today" of ADR-007 Karar 9; passed to SQL as `$today::date` instead of
 *   `CURRENT_DATE`).
 *
 * Pure module (no imports). `RegistryClock` (src/enrichment/registryClient.ts)
 * is an alias of `AppClock`.
 */

export interface AppClock {
  /** Wall clock in ms. */
  now(): number;
  /** Waits `ms`; resolves early when `signal` aborts. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
}

export const systemClock: AppClock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve) => {
      if (signal.aborted) return resolve();
      const onAbort = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal.addEventListener('abort', onAbort, { once: true });
    }),
};

function pad(value: number, width: number): string {
  return String(value).padStart(width, '0');
}

/** Calendar date of `ms` in the process' local time zone, `YYYY-MM-DD` (ADR-007 Karar 9). */
export function localDateString(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1, 2)}-${pad(date.getDate(), 2)}`;
}
