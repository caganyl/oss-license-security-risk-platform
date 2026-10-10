/**
 * Range checks for numeric settings from the environment and from
 * `system_settings` (REQ-003 security review I-3).
 *
 * Without an upper bound a large value overflows `setTimeout` (above
 * 2^31-1 ms Node fires after 1 ms with a `TimeoutOverflowWarning`) or turns
 * a retry loop into a practically endless one; a negative value passed the old
 * `Number(x) || default` checks. A missing value silently takes the default;
 * an invalid or out-of-range value takes the default and logs one warning
 * that names the setting, not the value.
 *
 * No imports on purpose: the scanner configuration that uses it is also
 * loaded next to the parser thread code.
 */

/** Largest delay `setTimeout` accepts without overflowing. */
export const MAX_TIMER_MS = 2_147_483_647;

export interface BoundedNumberOptions {
  /** Setting name used in the warning (e.g. `WORKER_POLL_INTERVAL_MS`). */
  name: string;
  min: number;
  max: number;
  /** Only integers are accepted. */
  integer?: boolean;
  /** `min` itself is not allowed (e.g. "greater than 0"). */
  exclusiveMin?: boolean;
  /** Warning sink; default `console.warn`. */
  warn?: (message: string) => void;
}

/** `raw` as a number within the bounds, else `fallback` (warned unless `raw` is missing/blank). */
export function boundedNumber(raw: unknown, fallback: number, options: BoundedNumberOptions): number {
  if (raw === undefined || raw === null || (typeof raw === 'string' && raw.trim() === '')) return fallback;
  const value = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number(raw.trim()) : Number(raw);
  const aboveMin = options.exclusiveMin ? value > options.min : value >= options.min;
  const valid = Number.isFinite(value) && (!options.integer || Number.isInteger(value)) && aboveMin && value <= options.max;
  if (valid) return value;
  const range = `${options.exclusiveMin ? '>' : ''}${options.min}–${options.max}`;
  (options.warn ?? console.warn)(`${options.name} geçersiz veya sınır dışı (${range}); varsayılan ${fallback} kullanılıyor.`);
  return fallback;
}
