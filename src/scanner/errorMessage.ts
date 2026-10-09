/**
 * Single funnel for every text written to `scans.error_message` and for the
 * retry log line (REQ-003 AC-P13-8).
 *
 * Today it only turns a thrown value into text and shortens log lines. The
 * L-5 sanitizer of ADR-002 Ek E3 (`sanitizeErrorText`: secrets, absolute
 * paths, control characters, 2000 characters; REQ-003 AC-T-4) plugs in here,
 * so every writer is covered without touching the call sites.
 */

/** Text of a thrown value for `scans.error_message`. */
export function scanErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  try {
    return String(err);
  } catch {
    return 'Unknown error';
  }
}

/** Free text (e.g. the joined parse warnings) on its way to `scans.error_message`. */
export function scanErrorText(text: string): string {
  return text;
}

const LOG_MAX_CHARS = 300;

/** Shortened error for one log line (AC-P13-8). */
export function shortErrorForLog(text: string, max: number = LOG_MAX_CHARS): string {
  const oneLine = text.replace(/\s+/g, ' ').trim();
  const chars = Array.from(oneLine);
  return chars.length <= max ? oneLine : `${chars.slice(0, max).join('')}…`;
}
