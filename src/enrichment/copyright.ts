/**
 * Copyright line extraction from collected license files (REQ-004 AC-P15-9,
 * D-68; ADR-006 Karar 8).
 *
 * Linear by construction: lines are walked with `indexOf('\n')`, only the
 * first `MAX_INSPECTED_CHARS` code units of a line are inspected, and no
 * regular expression is used (a 2 MiB single line stays well under 1 s).
 * Import-free pure module (loaded in the archive thread, ADR-006 Karar 1).
 */

/** Code units of one line that are inspected. */
export const MAX_INSPECTED_CHARS = 4096;
/** Maximum length of one extracted line in code points. */
export const MAX_COPYRIGHT_LINE_CHARS = 300;
/** Maximum lines per package. */
export const MAX_COPYRIGHT_LINES = 50;

/** Template placeholders and license-text boilerplate that never name a real holder (lower case). */
const EXCLUDED_FRAGMENTS: readonly string[] = [
  'free software foundation',
  '<year>',
  '[year]',
  '{year}',
  'yyyy',
  '<name of author>',
  '<copyright holder',
  '[name of copyright owner]',
  '[fullname]',
  '{fullname}',
  '<owner>',
  '[yyyy]',
  'copyright holders and contributors',
  'copyright owner or contributors',
  'copyright notice',
  'copyright (c) <',
];

function isSpaceCode(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0b || c === 0x0c || c === 0xa0;
}

/** Index after leading whitespace and comment prefixes (`#`, `*`, `//`, `;`), scanned character by character. */
function skipPrefix(line: string): number {
  let i = 0;
  while (i < line.length) {
    const c = line.charCodeAt(i);
    if (isSpaceCode(c) || c === 0x23 /* # */ || c === 0x2a /* * */ || c === 0x3b /* ; */) {
      i++;
    } else if (c === 0x2f /* / */ && line.charCodeAt(i + 1) === 0x2f) {
      i += 2;
    } else {
      break;
    }
  }
  return i;
}

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

/** True when `line` holds a four-digit year 1970–2099 bounded by non-digits (hand-written scan). */
function hasYear(line: string): boolean {
  for (let i = 0; i + 3 < line.length; i++) {
    if (!isDigit(line.charCodeAt(i))) continue;
    if (i > 0 && isDigit(line.charCodeAt(i - 1))) continue;
    if (!isDigit(line.charCodeAt(i + 1)) || !isDigit(line.charCodeAt(i + 2)) || !isDigit(line.charCodeAt(i + 3))) {
      continue;
    }
    if (i + 4 < line.length && isDigit(line.charCodeAt(i + 4))) {
      i += 3; // part of a longer number
      continue;
    }
    const year = Number(line.slice(i, i + 4));
    if (year >= 1970 && year <= 2099) return true;
    i += 3;
  }
  return false;
}

/** Collapses whitespace runs to one space and trims (linear). */
function collapseSpaces(text: string): string {
  const parts: string[] = [];
  let word = '';
  for (const ch of text) {
    if (ch === ' ' || ch === '\t' || ch === ' ' || ch === '\v' || ch === '\f') {
      if (word.length > 0) {
        parts.push(word);
        word = '';
      }
    } else {
      word += ch;
    }
  }
  if (word.length > 0) parts.push(word);
  return parts.join(' ');
}

/** The copyright statement of one line (prefix removed, spaces collapsed, cut), or null. */
export function copyrightLineOf(rawLine: string): string | null {
  const line = rawLine.length > MAX_INSPECTED_CHARS ? rawLine.slice(0, MAX_INSPECTED_CHARS) : rawLine;
  const body = line.slice(skipPrefix(line));
  const lower = body.toLowerCase();
  if (!(lower.startsWith('copyright') || lower.startsWith('(c)') || body.startsWith('©'))) return null;
  if (!(hasYear(body) || body.includes('©') || lower.includes('(c)'))) return null;
  for (const fragment of EXCLUDED_FRAGMENTS) {
    if (lower.includes(fragment)) return null;
  }
  const collapsed = collapseSpaces(body);
  if (collapsed.length === 0) return null;
  const chars = Array.from(collapsed);
  return chars.length > MAX_COPYRIGHT_LINE_CHARS ? chars.slice(0, MAX_COPYRIGHT_LINE_CHARS).join('') : collapsed;
}

/**
 * Unique copyright lines of the given (already decoded and cleaned) texts in
 * first-seen order, at most `MAX_COPYRIGHT_LINES`.
 */
export function extractCopyrightLines(texts: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const text of texts) {
    let start = 0;
    while (start <= text.length && seen.size < MAX_COPYRIGHT_LINES) {
      const end = text.indexOf('\n', start);
      const stop = end === -1 ? text.length : end;
      const line = copyrightLineOf(text.slice(start, Math.min(stop, start + MAX_INSPECTED_CHARS)));
      if (line !== null) seen.add(line);
      if (end === -1) break;
      start = end + 1;
    }
    if (seen.size >= MAX_COPYRIGHT_LINES) break;
  }
  return [...seen];
}
