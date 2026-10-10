/**
 * Output-specific escaping helpers (REQ-004 ADR-006 Karar 12, 13; contract
 * `docs/contracts/REQ-004-notice-and-outputs.md` sections 3.6 and 9).
 *
 * Every untrusted text is cleaned when stored (ADR-006 Karar 8); the outputs
 * apply `outputClean` again (pre-F3 data, defence in depth) and then the
 * target-specific rule below. Pure apart from the import-free sanitizer.
 */
import { sanitizeText } from './textSanitize';

/** NOTICE entry separator: 80 `=` (contract section 3.1). */
export const ENTRY_SEP = '='.repeat(80);
/** NOTICE file block separator: 80 `-` (contract section 3.1). */
export const FILE_SEP = '-'.repeat(80);

/** Common output rule: ADR-006 Karar 8 steps 2–3 applied again. */
export function outputClean(text: string | null | undefined): string {
  if (text === null || text === undefined) return '';
  return sanitizeText(text);
}

/**
 * Single-line value (contract section 9, steps 1–3): cleaned first (`\r\n`
 * and `\r` become `\n`, control/format characters removed), then every `\n`
 * and `\t` becomes one space. Target-specific escaping (step 4, e.g.
 * `excelSafeText`) is applied by the caller afterwards.
 */
export function singleLine(text: string | null | undefined): string {
  return outputClean(text).replace(/[\n\t]/g, ' ');
}

/**
 * NOTICE delimiter shield (contract section 3.6): a line of untrusted
 * multi-line text that starts with `ENTRY_SEP` or `FILE_SEP` gets one leading
 * space, so package text can never forge an entry or a file header.
 */
export function shieldNoticeLine(line: string): string {
  return line.startsWith(ENTRY_SEP) || line.startsWith(FILE_SEP) ? ` ${line}` : line;
}

/**
 * Multi-line untrusted NOTICE text -> output lines (contract section 3.5):
 * cleaned, trailing `\n` removed, split on `\n`, each line shielded; an empty
 * remainder is the single line `(empty)`.
 */
export function noticeTextLines(text: string | null | undefined): string[] {
  const cleaned = outputClean(text).replace(/\n+$/, '');
  if (cleaned.length === 0) return ['(empty)'];
  return cleaned.split('\n').map(shieldNoticeLine);
}

const TEXT_TAG_RE = /<(\/?)text>/gi;

/** SPDX tag-value single-line field (`PackageName`, `PackageVersion`, …): no line break survives. */
export function tagValueSingleLine(text: string | null | undefined): string {
  return singleLine(text);
}

/**
 * SPDX tag-value multi-line field: `<text>…</text>`; `<text>` and `</text>`
 * inside the value (any letter case) become `&lt;text&gt;` /
 * `&lt;/text&gt;`, so the value cannot leave its block (AC-P16-4).
 */
export function tagValueText(text: string | null | undefined): string {
  const escaped = outputClean(text).replace(TEXT_TAG_RE, (_m, slash: string) => `&lt;${slash}text&gt;`);
  return `<text>${escaped}</text>`;
}

/**
 * Removes characters that are not allowed in XML 1.0 (`#x9 #xA #xD
 * [#x20-#xD7FF] [#xE000-#xFFFD] [#x10000-#x10FFFF]`), lone surrogates
 * included. Linear.
 */
export function stripXmlInvalid(text: string): string {
  const parts: string[] = [];
  let keepFrom = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    let valid: boolean;
    let width = 1;
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = text.charCodeAt(i + 1);
      valid = n >= 0xdc00 && n <= 0xdfff;
      if (valid) width = 2;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      valid = false;
    } else {
      valid = c === 0x09 || c === 0x0a || c === 0x0d || (c >= 0x20 && c <= 0xfffd);
    }
    if (!valid) {
      if (keepFrom < i) parts.push(text.slice(keepFrom, i));
      keepFrom = i + 1;
    } else if (width === 2) {
      i++;
    }
  }
  if (keepFrom === 0) return text;
  if (keepFrom < text.length) parts.push(text.slice(keepFrom));
  return parts.join('');
}

const XML_ESCAPES: Readonly<Record<string, string>> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' };

/** CycloneDX XML text/attribute value: cleaned, XML-invalid characters removed, then `& < > " '` escaped. */
export function xmlText(text: string | null | undefined): string {
  return stripXmlInvalid(outputClean(text)).replace(/[&<>"']/g, (c) => XML_ESCAPES[c]);
}

/**
 * Excel formula-injection guard (ADR-006 Karar 13): a value starting with
 * `=`, `+`, `-`, `@`, `\t` or `\r` gets a leading `'`. The cell is still
 * written as plain text (never `{ formula }`).
 */
export function excelSafeText(text: string | null | undefined): string {
  const value = text ?? '';
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}
