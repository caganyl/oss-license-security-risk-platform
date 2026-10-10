/**
 * NuGet identity and version rules (REQ-006 AC-P20-8, AC-P20-9, AC-P21-1;
 * ADR-008 Karar 4). Shared by the parser thread and the enrichment
 * (`src/enrichment/` may import this module, ADR-008 Karar 1).
 *
 * Every check is a hand-written single pass: no quantified or backtracking
 * regular expression touches untrusted text. No network, file or
 * environment access; the only import is the percent-encoding helper that
 * `npmPurl`/`pypiPurl` use.
 */
import { pyQuote } from './common';

export const NUGET_ID_MAX_CHARS = 100;
export const NUGET_VERSION_MAX_CHARS = 128;
const INT32_MAX = '2147483647';

/** Locale-independent lower case: only `A`–`Z` change (no Turkish dotless-i issue). */
export function asciiLower(value: string): string {
  let out: string | null = null;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0x41 && c <= 0x5a) {
      out ??= value.slice(0, i);
      out += String.fromCharCode(c + 0x20);
    } else if (out !== null) {
      out += value[i];
    }
  }
  return out ?? value;
}

function isIdWordChar(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
}

/**
 * `^[A-Za-z0-9_]+([.-][A-Za-z0-9_]+)*$`, 1–100 characters: every separator is
 * followed by at least one word character. Excludes `..`, `/`, `\`, `%`,
 * whitespace and `;` structurally.
 */
export function isValidNugetId(id: unknown): id is string {
  if (typeof id !== 'string' || id.length === 0 || id.length > NUGET_ID_MAX_CHARS) return false;
  let needWord = true;
  for (let i = 0; i < id.length; i++) {
    const c = id.charCodeAt(i);
    if (isIdWordChar(c)) {
      needWord = false;
    } else if ((c === 0x2e || c === 0x2d) && !needWord) {
      needWord = true;
    } else {
      return false;
    }
  }
  return !needWord;
}

function isAlnumHyphen(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x2d;
}

/** Dot-separated, non-empty `[0-9A-Za-z-]+` identifiers. */
function isDottedIdentifiers(value: string): boolean {
  if (value.length === 0) return false;
  let segment = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x2e) {
      if (segment === 0) return false;
      segment = 0;
    } else if (isAlnumHyphen(c)) {
      segment++;
    } else {
      return false;
    }
  }
  return segment > 0;
}

function isXmlWhitespace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function trimXml(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && isXmlWhitespace(value.charCodeAt(start))) start++;
  while (end > start && isXmlWhitespace(value.charCodeAt(end - 1))) end--;
  return value.slice(start, end);
}

/** Characters that make a version a range, a floating version or an MSBuild property. */
function isRejectedVersionChar(c: number): boolean {
  return (
    c === 0x5b || c === 0x5d || c === 0x28 || c === 0x29 || c === 0x2c || c === 0x2a || c === 0x24 || c === 0x40 || c === 0x25 ||
    c <= 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f)
  );
}

/** Numeric part without leading zeros, or null when not `[0-9]+` within 0..2 147 483 647. */
function numericPart(value: string): string | null {
  if (value.length === 0) return null;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return null;
  }
  let start = 0;
  while (start < value.length - 1 && value.charCodeAt(start) === 0x30) start++;
  const stripped = value.slice(start);
  if (stripped.length > INT32_MAX.length) return null;
  if (stripped.length === INT32_MAX.length && stripped > INT32_MAX) return null;
  return stripped;
}

export type NugetVersionClass = { kind: 'exact'; version: string } | { kind: 'unknown' };

/**
 * ADR-008 Karar 4 version classification: exact (normalized, pre-release
 * casing kept) or unknown (ranges, floating versions, `$(…)` properties,
 * empty or invalid values). MSBuild properties are never evaluated.
 */
export function classifyNugetVersion(raw: unknown): NugetVersionClass {
  if (typeof raw !== 'string') return { kind: 'unknown' };
  let value = trimXml(raw);
  if (value.length === 0 || value.length > NUGET_VERSION_MAX_CHARS) return { kind: 'unknown' };
  // `[x]` exact pin.
  if (value.length >= 2 && value.startsWith('[') && value.endsWith(']') && !value.includes(',')) {
    value = value.slice(1, -1);
  }
  if (value.length === 0) return { kind: 'unknown' };
  for (let i = 0; i < value.length; i++) {
    if (isRejectedVersionChar(value.charCodeAt(i))) return { kind: 'unknown' };
  }
  const plus = value.indexOf('+');
  if (plus !== -1) {
    if (!isDottedIdentifiers(value.slice(plus + 1))) return { kind: 'unknown' };
    value = value.slice(0, plus);
  }
  let prerelease: string | null = null;
  const dash = value.indexOf('-');
  if (dash !== -1) {
    prerelease = value.slice(dash + 1);
    if (!isDottedIdentifiers(prerelease)) return { kind: 'unknown' };
    value = value.slice(0, dash);
  }
  const rawParts = value.split('.');
  if (rawParts.length < 2 || rawParts.length > 4) return { kind: 'unknown' };
  const parts: string[] = [];
  for (const part of rawParts) {
    const normalized = numericPart(part);
    if (normalized === null) return { kind: 'unknown' };
    parts.push(normalized);
  }
  if (parts.length === 2) parts.push('0');
  if (parts.length === 4 && parts[3] === '0') parts.pop();
  const version = parts.join('.') + (prerelease === null ? '' : `-${prerelease}`);
  return { kind: 'exact', version };
}

/** Case-insensitive key of a NuGet identity: `(asciiLower(id), asciiLower(version ?? ''))`. */
export function nugetKey(id: string, version: string | null): string {
  return `${asciiLower(id)}\u0000${version === null ? '\u0001' : asciiLower(version)}`;
}

/** `pkg:nuget/<id>[@<version>]`; id casing kept, same percent encoding as `npmPurl`/`pypiPurl`. */
export function nugetPurl(id: string, version: string | null): string {
  const encoded = pyQuote(id, '');
  if (version) return `pkg:nuget/${encoded}@${pyQuote(version, '')}`;
  return `pkg:nuget/${encoded}`;
}
