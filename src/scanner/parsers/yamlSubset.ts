/**
 * Safe YAML subset reader (REQ-011 AC-P40-4, D-303; ADR-012 Karar 1).
 *
 * Reads exactly what `pnpm-lock.yaml` (v6, v9) and `pubspec.lock` need,
 * without a YAML library (no new dependency, D-303):
 * - block mappings and block sequences (indentation with spaces; `- key: v`
 *   items; a sequence may sit at its parent key's indentation);
 * - plain, single-quoted and double-quoted scalars on one line; literal
 *   (`|`) and folded (`>`) block scalars with the `-`/`+` chomping and an
 *   optional indentation digit;
 * - one-line flow collections of scalars (`{a: 1, b: 'x'}`, `[x64, arm64]`,
 *   `{}`, `[]`); a flow collection inside a flow collection is rejected;
 * - `#` comments, a leading UTF-8 BOM, one leading `---` document marker.
 *
 * Rejected with a `YamlSubsetError` (never silently misread): anchors (`&`),
 * aliases (`*`), tags (`!`), directives (`%`), a second document (`---`
 * after content) or `...`, complex keys (`?`), duplicate keys, tabs in the
 * indentation, multi-line plain or quoted scalars, reserved indicators
 * (`@`, `` ` ``) at the start of a plain scalar, and the limits below.
 *
 * Scalars: plain `null`, `Null`, `NULL`, `~` and an empty value are `null`;
 * plain `true`/`false` (also `True`, `TRUE`, ...) are booleans; everything
 * else, numbers included, stays a string (`lockfileVersion: 5.4` -> `'5.4'`,
 * `'9.0'` -> `'9.0'`), so callers never depend on YAML 1.1/1.2 number rules.
 *
 * Linear time: every line is visited a bounded number of times and each
 * scalar is scanned once with `indexOf`/character loops (no backtracking
 * regular expression). Mapping objects get their keys through
 * `Object.defineProperty`, so a `__proto__` key is an ordinary own property.
 * Error messages carry a fixed text and a line number, never document
 * content.
 *
 * Pure module: no imports (ADR-005 Karar 1 boundary).
 */

export type YamlValue = null | boolean | string | YamlValue[] | { [key: string]: YamlValue };

export type YamlErrorCode = 'syntax' | 'unsupported' | 'duplicate_key' | 'limit';

const MESSAGES: Readonly<Record<YamlErrorCode, string>> = {
  syntax: 'YAML ayrıştırılamadı.',
  unsupported: 'Desteklenmeyen YAML özelliği (çapa, takma ad, etiket veya çok belgeli akış).',
  duplicate_key: 'YAML içinde yinelenen anahtar.',
  limit: 'YAML boyut, derinlik veya düğüm sınırı aşıldı.',
};

/** Reader failure; `message` is a fixed Turkish text per code (no document content). */
export class YamlSubsetError extends Error {
  constructor(
    readonly code: YamlErrorCode,
    /** 1-based line number (0 = whole document). */
    readonly line: number,
  ) {
    super(MESSAGES[code]);
    this.name = 'YamlSubsetError';
  }
}

export interface YamlLimits {
  /** Maximum input length in UTF-16 code units. */
  maxChars: number;
  /** Maximum nesting of collections. */
  maxDepth: number;
  /** Maximum number of collection entries plus scalars. */
  maxNodes: number;
  /** Maximum number of physical lines (security review M-4: checked before splitting). */
  maxLines: number;
}

export const DEFAULT_YAML_LIMITS: Readonly<YamlLimits> = Object.freeze({
  maxChars: 32 * 1024 * 1024,
  maxDepth: 64,
  maxNodes: 2_000_000,
  maxLines: 2_000_000,
});

interface Line {
  /** 1-based line number. */
  no: number;
  indent: number;
  /** Text after the indentation (comments still in it). */
  text: string;
  /** Blank or comment-only. */
  blank: boolean;
}

function isBlankOrComment(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === ' ' || c === '\t') continue;
    return c === '#';
  }
  return true;
}

/** Same answer as `isBlankOrComment` on the line without its indentation and CR, without building it. */
function rawIsBlank(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === ' ' || c === '\t') continue;
    if (c === '\r' && i === value.length - 1) return true;
    return c === '#';
  }
  return true;
}

function defineKey(target: Record<string, YamlValue>, key: string, value: YamlValue): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function resolvePlain(text: string): YamlValue {
  switch (text) {
    case '':
    case '~':
    case 'null':
    case 'Null':
    case 'NULL':
      return null;
    case 'true':
    case 'True':
    case 'TRUE':
      return true;
    case 'false':
    case 'False':
    case 'FALSE':
      return false;
    default:
      return text;
  }
}

function hexValue(text: string, line: number): number {
  if (text.length === 0) throw new YamlSubsetError('syntax', line);
  let value = 0;
  for (let i = 0; i < text.length; i++) {
    const digit = parseInt(text[i], 16);
    if (Number.isNaN(digit)) throw new YamlSubsetError('syntax', line);
    value = value * 16 + digit;
  }
  return value;
}

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  '0': '\0',
  a: '\x07',
  b: '\b',
  t: '\t',
  '\t': '\t',
  n: '\n',
  v: '\v',
  f: '\f',
  r: '\r',
  e: '\x1b',
  ' ': ' ',
  '"': '"',
  '/': '/',
  '\\': '\\',
  N: '\x85',
  _: '\xa0',
  L: ' ',
  P: ' ',
};

class Reader {
  /** Physical lines (CR kept); a `Line` is built only when a parser step needs it. */
  private readonly raw: string[];
  /**
   * Content lines built so far (sparse). Blank and comment-only lines never
   * get a cached object (security review M-4: a file of 2M empty lines
   * costs one string array, not 2M objects); a block scalar that needs one
   * gets a transient object from `line()`.
   */
  private readonly cache: Array<Line | undefined>;
  private pos = 0;
  private nodes = 0;

  constructor(
    text: string,
    private readonly limits: YamlLimits,
  ) {
    // Count before splitting, so a huge run of newlines never becomes a huge array.
    let lineCount = 1;
    for (let at = text.indexOf('\n'); at !== -1; at = text.indexOf('\n', at + 1)) {
      if (++lineCount > limits.maxLines) throw new YamlSubsetError('limit', 0);
    }
    this.raw = text.split('\n');
    this.cache = new Array<Line | undefined>(this.raw.length);
    // A tab in the indentation of a content line is not allowed in YAML (checked over the whole text first).
    for (let i = 0; i < this.raw.length; i++) {
      if (!rawIsBlank(this.raw[i]) && this.line(i).text.startsWith('\t')) throw new YamlSubsetError('syntax', i + 1);
    }
    // Directives anywhere, and a document marker other than one leading `---`, are outside the subset.
    let seenContent = false;
    for (let i = 0; i < this.raw.length; i++) {
      if (rawIsBlank(this.raw[i])) continue;
      const line = this.line(i);
      if (line.indent === 0) {
        if (line.text.startsWith('%')) throw new YamlSubsetError('unsupported', line.no);
        if (isMarker(line.text, '...') || (seenContent && isMarker(line.text, '---'))) throw new YamlSubsetError('unsupported', line.no);
      }
      seenContent = true;
    }
  }

  private get length(): number {
    return this.raw.length;
  }

  /** The line at index `i` (cached for content lines, transient for blank ones). */
  private line(i: number): Line {
    const cached = this.cache[i];
    if (cached !== undefined) return cached;
    const value = this.raw[i];
    const lineText = value.endsWith('\r') ? value.slice(0, -1) : value;
    let indent = 0;
    while (indent < lineText.length && lineText[indent] === ' ') indent++;
    const rest = lineText.slice(indent);
    const blank = isBlankOrComment(rest);
    const line: Line = { no: i + 1, indent, text: rest, blank };
    if (!blank) this.cache[i] = line;
    return line;
  }

  private count(line: number): void {
    this.nodes++;
    if (this.nodes > this.limits.maxNodes) throw new YamlSubsetError('limit', line);
  }

  /** Next content line at or after `pos` (skips blank and comment-only lines), without consuming it. */
  private peek(): Line | null {
    while (this.pos < this.length && rawIsBlank(this.raw[this.pos])) this.pos++;
    return this.pos < this.length ? this.line(this.pos) : null;
  }

  document(): YamlValue {
    let first = this.peek();
    if (first === null) return null;
    if (first.indent === 0 && isMarker(first.text, '---')) {
      if (stripComment(first.text.slice(3), first.no).trim() !== '') throw new YamlSubsetError('unsupported', first.no);
      this.pos++;
      first = this.peek();
      if (first === null) return null;
    }
    if (first.indent !== 0) throw new YamlSubsetError('syntax', first.no);
    const value = this.node(0, 1);
    const rest = this.peek();
    if (rest !== null) {
      if (rest.indent === 0 && (isMarker(rest.text, '---') || isMarker(rest.text, '...'))) throw new YamlSubsetError('unsupported', rest.no);
      throw new YamlSubsetError('syntax', rest.no);
    }
    return value;
  }

  /** Block node whose first line is the current line, at exactly `indent`. */
  private node(indent: number, depth: number): YamlValue {
    if (depth > this.limits.maxDepth) throw new YamlSubsetError('limit', this.peek()?.no ?? 0);
    const line = this.peek() as Line;
    if (line.indent === 0 && (isMarker(line.text, '---') || isMarker(line.text, '...'))) throw new YamlSubsetError('unsupported', line.no);
    if (isSequenceItem(line.text)) return this.sequence(indent, depth);
    if (mappingKey(line.text, line.no) !== null) return this.mapping(indent, depth);
    // A lone scalar node (document or nested value written on its own line).
    this.pos++;
    const value = this.inlineValue(line.text, line, indent, depth);
    return value;
  }

  private mapping(indent: number, depth: number): Record<string, YamlValue> {
    const result: Record<string, YamlValue> = {};
    for (;;) {
      const line = this.peek();
      if (line === null || line.indent < indent) break;
      if (line.indent > indent) throw new YamlSubsetError('syntax', line.no);
      const entry = mappingKey(line.text, line.no);
      if (entry === null) throw new YamlSubsetError('syntax', line.no);
      if (Object.prototype.hasOwnProperty.call(result, entry.key)) throw new YamlSubsetError('duplicate_key', line.no);
      this.count(line.no);
      this.pos++;
      defineKey(result, entry.key, this.valueAfterIndicator(entry.rest, line, indent, depth, true));
    }
    return result;
  }

  private sequence(indent: number, depth: number): YamlValue[] {
    const result: YamlValue[] = [];
    for (;;) {
      const line = this.peek();
      if (line === null || line.indent < indent) break;
      if (line.indent > indent) throw new YamlSubsetError('syntax', line.no);
      // A same-indent non-item line ends a sequence written at its parent key's indentation; the caller checks it.
      if (!isSequenceItem(line.text)) break;
      this.count(line.no);
      // Text after `-` and its spaces; an inline mapping/sequence continues at that column.
      let offset = 1;
      while (offset < line.text.length && line.text[offset] === ' ') offset++;
      const rest = line.text.slice(offset);
      if (rest === '' || isBlankOrComment(rest)) {
        this.pos++;
        result.push(this.nestedOrNull(indent, depth, false));
        continue;
      }
      if (isSequenceItem(rest) || mappingKey(rest, line.no) !== null) {
        // Re-read the same line as a block node indented at the item's content column.
        this.cache[this.pos] = { no: line.no, indent: indent + offset, text: rest, blank: false };
        result.push(this.node(indent + offset, depth + 1));
        continue;
      }
      this.pos++;
      result.push(this.inlineValue(rest, line, indent, depth));
    }
    return result;
  }

  /** Value after `key:` (mapping) or after `-` when the rest is not a collection. */
  private valueAfterIndicator(rest: string, line: Line, indent: number, depth: number, inMapping: boolean): YamlValue {
    if (rest === '' || isBlankOrComment(rest)) return this.nestedOrNull(indent, depth, inMapping);
    return this.inlineValue(rest, line, indent, depth);
  }

  /** Block value on the following lines: deeper node, a same-indent sequence under a mapping key, or null. */
  private nestedOrNull(indent: number, depth: number, inMapping: boolean): YamlValue {
    const next = this.peek();
    if (next === null) return null;
    if (next.indent > indent) return this.node(next.indent, depth + 1);
    if (inMapping && next.indent === indent && isSequenceItem(next.text)) return this.sequence(indent, depth + 1);
    return null;
  }

  /** Scalar, flow collection or block scalar written after an indicator on line `line` (already consumed). */
  private inlineValue(text: string, line: Line, parentIndent: number, depth: number): YamlValue {
    const c = text[0];
    if (c === '&' || c === '*' || c === '!' || c === '%') throw new YamlSubsetError('unsupported', line.no);
    if (c === '?' && (text.length === 1 || text[1] === ' ')) throw new YamlSubsetError('unsupported', line.no);
    if (c === '@' || c === '`') throw new YamlSubsetError('syntax', line.no);
    this.count(line.no);
    if (c === '|' || c === '>') return this.blockScalar(text, line, parentIndent);
    if (c === '{' || c === '[') {
      if (depth + 1 > this.limits.maxDepth) throw new YamlSubsetError('limit', line.no);
      const { value, end } = flowCollection(text, 0, line.no, () => this.count(line.no));
      if (stripComment(text.slice(end), line.no).trim() !== '') throw new YamlSubsetError('syntax', line.no);
      this.assertNoContinuation(parentIndent, line);
      return value;
    }
    if (c === '"' || c === "'") {
      const { value, end } = quoted(text, 0, line.no);
      if (stripComment(text.slice(end), line.no).trim() !== '') throw new YamlSubsetError('syntax', line.no);
      this.assertNoContinuation(parentIndent, line);
      return value;
    }
    const plain = stripComment(text, line.no).trimEnd();
    // `a: b: c` or a trailing `:` is a mapping where a scalar is expected.
    if (plain.endsWith(':') || plain.includes(': ')) throw new YamlSubsetError('syntax', line.no);
    this.assertNoContinuation(parentIndent, line);
    return resolvePlain(plain);
  }

  /** A deeper content line right after a one-line value would be a multi-line scalar: rejected. */
  private assertNoContinuation(parentIndent: number, line: Line): void {
    void line;
    const next = this.peek();
    // `key: value` at indent n (or `- value` at n): a following line deeper than n would continue the scalar.
    if (next !== null && next.indent > parentIndent) throw new YamlSubsetError('syntax', next.no);
  }

  private blockScalar(header: string, line: Line, parentIndent: number): string {
    const folded = header[0] === '>';
    let chomp: 'clip' | 'strip' | 'keep' = 'clip';
    let explicitIndent = 0;
    let i = 1;
    for (; i < header.length && i <= 2; i++) {
      const ch = header[i];
      if ((ch === '-' || ch === '+') && chomp === 'clip') chomp = ch === '-' ? 'strip' : 'keep';
      else if (ch >= '1' && ch <= '9' && explicitIndent === 0) explicitIndent = ch.charCodeAt(0) - 0x30;
      else break;
    }
    if (stripComment(header.slice(i), line.no).trim() !== '') throw new YamlSubsetError('syntax', line.no);

    // Content lines: every following line that is blank or indented deeper than the parent.
    const body: string[] = [];
    let contentIndent = explicitIndent > 0 ? parentIndent + explicitIndent : 0;
    while (this.pos < this.length) {
      const l = this.line(this.pos);
      const isEmpty = l.text.trim() === '' && !l.text.includes('\t');
      if (!isEmpty && l.indent <= parentIndent) break;
      if (!isEmpty && contentIndent === 0) contentIndent = l.indent;
      if (!isEmpty && l.indent < contentIndent) throw new YamlSubsetError('syntax', l.no);
      // Raw text of the line from the content indentation on (blank lines may be shorter).
      const full = ' '.repeat(l.indent) + l.text;
      body.push(isEmpty ? '' : full.slice(contentIndent));
      this.pos++;
    }
    let trailing = 0;
    while (trailing < body.length && body[body.length - 1 - trailing] === '') trailing++;
    const content = body.slice(0, body.length - trailing);
    let text: string;
    if (folded) {
      text = '';
      for (let k = 0; k < content.length; k++) {
        const current = content[k];
        if (k === 0) {
          text = current;
          continue;
        }
        const previous = content[k - 1];
        const moreIndented = current.startsWith(' ') || previous.startsWith(' ');
        if (current === '') text += '\n';
        else if (previous === '' || moreIndented) text += (previous === '' ? '' : '\n') + current;
        else text += ` ${current}`;
      }
    } else {
      text = content.join('\n');
    }
    if (content.length === 0) return chomp === 'keep' ? '\n'.repeat(trailing) : '';
    if (chomp === 'strip') return text;
    if (chomp === 'keep') return `${text}\n${'\n'.repeat(trailing)}`;
    return `${text}\n`;
  }
}

function isMarker(text: string, marker: '---' | '...'): boolean {
  return text.startsWith(marker) && (text.length === 3 || text[3] === ' ' || text[3] === '\t');
}

function isSequenceItem(text: string): boolean {
  return text[0] === '-' && (text.length === 1 || text[1] === ' ');
}

/**
 * `key: rest` of a mapping entry line, or null when the line is not one.
 * Keys are plain (no leading indicator) or quoted on one line.
 */
function mappingKey(text: string, line: number): { key: string; rest: string } | null {
  const c = text[0];
  if (c === '"' || c === "'") {
    const { value, end } = quoted(text, 0, line);
    let j = end;
    while (j < text.length && text[j] === ' ') j++;
    if (text[j] !== ':' || (j + 1 < text.length && text[j + 1] !== ' ')) return null;
    if (typeof value !== 'string') return null;
    return { key: value, rest: text.slice(j + 1).replace(/^ +/, '') };
  }
  if (c === '?' && (text.length === 1 || text[1] === ' ')) throw new YamlSubsetError('unsupported', line);
  if (c === '-' && (text.length === 1 || text[1] === ' ')) return null;
  if (c === '#' || c === '{' || c === '[' || c === '|' || c === '>' || c === ',' || c === ']' || c === '}') return null;
  // First `:` followed by a space or the end of the line, before any ` #` comment.
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '#' && i > 0 && (text[i - 1] === ' ' || text[i - 1] === '\t')) return null;
    if (ch === ':' && (i + 1 === text.length || text[i + 1] === ' ')) {
      const key = text.slice(0, i).trimEnd();
      if (key === '') return null;
      const k0 = key[0];
      if (k0 === '&' || k0 === '*' || k0 === '!' || k0 === '%') throw new YamlSubsetError('unsupported', line);
      if (k0 === '@' || k0 === '`') throw new YamlSubsetError('syntax', line);
      return { key, rest: text.slice(i + 1).replace(/^ +/, '') };
    }
  }
  return null;
}

/** Removes a ` #` comment from plain text (a `#` at position 0 is a comment too). */
function stripComment(text: string, line: number): string {
  void line;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '#' && (i === 0 || text[i - 1] === ' ' || text[i - 1] === '\t')) return text.slice(0, i);
  }
  return text;
}

/** Quoted scalar starting at `start` (on one line); `end` is the index after the closing quote. */
function quoted(text: string, start: number, line: number): { value: string; end: number } {
  const q = text[start];
  let out = '';
  let i = start + 1;
  if (q === "'") {
    for (;;) {
      const close = text.indexOf("'", i);
      if (close === -1) throw new YamlSubsetError('syntax', line);
      out += text.slice(i, close);
      if (text[close + 1] === "'") {
        out += "'";
        i = close + 2;
        continue;
      }
      return { value: out, end: close + 1 };
    }
  }
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') return { value: out, end: i + 1 };
    if (ch !== '\\') {
      out += ch;
      i++;
      continue;
    }
    const esc = text[i + 1];
    if (esc === undefined) throw new YamlSubsetError('syntax', line);
    if (Object.prototype.hasOwnProperty.call(SIMPLE_ESCAPES, esc)) {
      out += SIMPLE_ESCAPES[esc];
      i += 2;
      continue;
    }
    const width = esc === 'x' ? 2 : esc === 'u' ? 4 : esc === 'U' ? 8 : 0;
    if (width === 0 || text.length < i + 2 + width) throw new YamlSubsetError('syntax', line);
    const code = hexValue(text.slice(i + 2, i + 2 + width), line);
    if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) throw new YamlSubsetError('syntax', line);
    out += String.fromCodePoint(code);
    i += 2 + width;
  }
  throw new YamlSubsetError('syntax', line);
}

/**
 * One-line flow collection of scalars starting at `start`. A nested `{`/`[`
 * is rejected (subset rule); `end` is the index after the closing bracket.
 */
function flowCollection(text: string, start: number, line: number, count: () => void): { value: YamlValue; end: number } {
  const isMap = text[start] === '{';
  const close = isMap ? '}' : ']';
  const map: Record<string, YamlValue> = {};
  const list: YamlValue[] = [];
  let i = start + 1;
  const skipSpaces = () => {
    while (i < text.length && text[i] === ' ') i++;
  };
  /** One scalar ending before `,`, `close` or (for a map key) `:`. */
  const scalar = (stopAtColon: boolean): YamlValue => {
    skipSpaces();
    const c = text[i];
    if (c === undefined) throw new YamlSubsetError('syntax', line);
    if (c === '{' || c === '[') throw new YamlSubsetError('syntax', line);
    if (c === '&' || c === '*' || c === '!' || c === '%' || c === '?') throw new YamlSubsetError('unsupported', line);
    if (c === '@' || c === '`') throw new YamlSubsetError('syntax', line);
    if (c === '"' || c === "'") {
      const q = quoted(text, i, line);
      i = q.end;
      skipSpaces();
      return q.value;
    }
    let j = i;
    while (j < text.length) {
      const ch = text[j];
      if (ch === ',' || ch === close || ch === '{' || ch === '[' || ch === ']' || ch === '}') break;
      if (stopAtColon && ch === ':' && (j + 1 === text.length || text[j + 1] === ' ' || text[j + 1] === ',' || text[j + 1] === close)) break;
      if (ch === '#' && j > 0 && text[j - 1] === ' ') throw new YamlSubsetError('syntax', line);
      j++;
    }
    const raw = text.slice(i, j).trimEnd();
    i = j;
    return resolvePlain(raw);
  };

  skipSpaces();
  if (text[i] === close) return { value: isMap ? map : list, end: i + 1 };
  for (;;) {
    count();
    if (isMap) {
      const key = scalar(true);
      if (typeof key !== 'string' && key !== null) throw new YamlSubsetError('syntax', line);
      const keyText = key === null ? '' : key;
      let value: YamlValue = null;
      if (text[i] === ':') {
        i++;
        skipSpaces();
        value = text[i] === ',' || text[i] === close ? null : scalar(false);
      }
      if (Object.prototype.hasOwnProperty.call(map, keyText)) throw new YamlSubsetError('duplicate_key', line);
      defineKey(map, keyText, value);
    } else {
      list.push(scalar(false));
    }
    skipSpaces();
    if (text[i] === ',') {
      i++;
      skipSpaces();
      // A trailing comma before the closing bracket is allowed in YAML flow collections.
      if (text[i] === close) return { value: isMap ? map : list, end: i + 1 };
      continue;
    }
    if (text[i] === close) return { value: isMap ? map : list, end: i + 1 };
    throw new YamlSubsetError('syntax', line);
  }
}

/**
 * Parses `text` (already decoded; a leading BOM is ignored). Throws
 * `YamlSubsetError` for anything outside the subset.
 */
export function parseYamlSubset(text: string, limits: Partial<YamlLimits> = {}): YamlValue {
  const effective: YamlLimits = { ...DEFAULT_YAML_LIMITS, ...limits };
  if (text.length > effective.maxChars) throw new YamlSubsetError('limit', 0);
  const body = text.startsWith('﻿') ? text.slice(1) : text;
  return new Reader(body, effective).document();
}
