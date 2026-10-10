/**
 * Text decoding and cleanup of registry and archive text (REQ-004 AC-P15-8,
 * AC-P14-11; ADR-006 Karar 3, 8). Same code in the archive thread and on
 * the main thread.
 *
 * Boundary rule (ADR-006 Karar 1): loaded inside the archive thread, so it
 * imports only `node:buffer` and the import-free `src/lib/textSanitize.ts`.
 */
import { Buffer } from 'node:buffer';
import { sanitizeText } from '../lib/textSanitize';

export { sanitizeText };

/** Maximum derived declared license length in code points (ADR-006 Karar 3). */
export const MAX_DECLARED_LICENSE_CHARS = 1000;
/** Maximum stored PyPI long license text in UTF-8 bytes (ADR-006 Karar 3). */
export const MAX_LICENSE_TEXT_BYTES = 1024 * 1024;
/** Note appended to a cut long license text. */
export const TRUNCATED_NOTE = '\n[truncated]';

/**
 * Decodes file bytes (AC-P15-8): UTF-8 BOM dropped; UTF-16 LE/BE by BOM;
 * everything else UTF-8 with U+FFFD for invalid sequences (no Latin-1
 * fallback). Returns null when the decoded text contains NUL (binary file).
 */
export function decodeText(bytes: Uint8Array): string | null {
  let text: string;
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    text = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(bytes.subarray(3));
  } else if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    text = new TextDecoder('utf-16le', { fatal: false, ignoreBOM: true }).decode(bytes.subarray(2));
  } else if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    text = new TextDecoder('utf-16be', { fatal: false, ignoreBOM: true }).decode(bytes.subarray(2));
  } else {
    text = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(bytes);
  }
  if (text.includes('\u0000')) return null;
  return text;
}

/** Decoded and cleaned file text (ADR-006 Karar 8 steps 1–3), or null for a binary file. */
export function decodeAndSanitize(bytes: Uint8Array): string | null {
  const text = decodeText(bytes);
  return text === null ? null : sanitizeText(text);
}

/** Cuts to `max` code points without splitting a surrogate pair (no ellipsis). */
export function cutCodePoints(text: string, max: number): string {
  if (text.length <= max) return text;
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    if (count === max) return text.slice(0, i);
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const n = text.charCodeAt(i + 1);
      if (n >= 0xdc00 && n <= 0xdfff) i++;
    }
    count++;
  }
  return text;
}

/** Cleaned registry license declaration, at most `MAX_DECLARED_LICENSE_CHARS` code points; null when blank. */
export function cleanDeclaredLicense(raw: string): string | null {
  const cleaned = sanitizeText(raw).trim();
  if (cleaned.length === 0) return null;
  return cutCodePoints(cleaned, MAX_DECLARED_LICENSE_CHARS);
}

/**
 * Cleaned long license text (PyPI `info.license`, NOTICE fallback): at most
 * `MAX_LICENSE_TEXT_BYTES` UTF-8 bytes; a cut text ends with `[truncated]`.
 * Null when blank.
 */
export function cleanLicenseText(raw: string): string | null {
  const cleaned = sanitizeText(raw);
  if (cleaned.trim().length === 0) return null;
  if (Buffer.byteLength(cleaned, 'utf8') <= MAX_LICENSE_TEXT_BYTES) return cleaned;
  const budget = MAX_LICENSE_TEXT_BYTES - Buffer.byteLength(TRUNCATED_NOTE, 'utf8');
  // Cut on a character boundary: decoding a byte prefix may end in a partial
  // sequence, which becomes U+FFFD and is dropped below.
  const prefix = Buffer.from(cleaned, 'utf8').subarray(0, budget).toString('utf8').replace(/�$/, '');
  return `${prefix}${TRUNCATED_NOTE}`;
}
