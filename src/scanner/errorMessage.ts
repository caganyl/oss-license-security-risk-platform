import { sanitizeErrorText, type ErrorTextContext } from '../lib/errorText';

/**
 * Single funnel for every text written to `scans.error_message` and for the
 * retry log line (REQ-003 AC-P13-8). Every text goes through the L-5
 * sanitizer `sanitizeErrorText` (ADR-002 Ek E3; REQ-003 AC-T-4): secrets,
 * absolute paths, control characters, 2000 characters. The worker passes the
 * job context (token forms, workspace, SCAN_ROOTS, temp root).
 */
export type { ErrorTextContext };

/** Raw text of a thrown value (not sanitized; use `scanErrorText` before persisting). */
export function scanErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  try {
    return String(err);
  } catch {
    return 'Unknown error';
  }
}

/** Sanitized text on its way to `scans.error_message` (error, warning join, recovery message). */
export function scanErrorText(text: string, context: ErrorTextContext = {}): string {
  return sanitizeErrorText(text, context);
}

const LOG_MAX_CHARS = 300;

/** Shortened error for one log line (AC-P13-8); expects already sanitized text. */
export function shortErrorForLog(text: string, max: number = LOG_MAX_CHARS): string {
  const oneLine = text.replace(/\s+/g, ' ').trim();
  const chars = Array.from(oneLine);
  return chars.length <= max ? oneLine : `${chars.slice(0, max).join('')}…`;
}
