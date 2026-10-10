/**
 * SPDX license expression validator and canonicalizer (REQ-004 AC-P16-3,
 * D-71, D-78; ADR-006 Karar 1, 13).
 *
 * Grammar (subset of SPDX 2.3 Annex D):
 *   expr     := and-expr ( OR and-expr )*
 *   and-expr := with-expr ( AND with-expr )*
 *   with-expr:= license-id [ "+" ] [ WITH exception-id ] | "(" expr ")"
 *
 * - Every license id must be in the caller's known id set (the normalizer's
 *   `SPDX_RISK_MAP` keys plus `licenses.spdx_id`); comparison is
 *   case-insensitive and the output uses the canonical spelling.
 * - `WITH` exceptions come from the fixed `SPDX_EXCEPTIONS` list.
 * - Operators may be written in any letter case on input; the output writes
 *   them in upper case. Parentheses are balanced, at most 16 levels deep.
 *
 * One tokenizer pass plus one state-machine pass over the tokens (no
 * recursion, no regular expression backtracking): linear in the input length.
 * Pure module (no imports, ADR-006 Karar 1).
 */

/** Maximum parenthesis nesting depth (AC-P16-3). */
export const MAX_SPDX_DEPTH = 16;

/** Allowed `WITH` exceptions (AC-P16-3 minimum list plus a few common ones). */
export const SPDX_EXCEPTIONS: readonly string[] = Object.freeze([
  'Classpath-exception-2.0',
  'LLVM-exception',
  'GCC-exception-3.1',
  'GCC-exception-2.0',
  'Autoconf-exception-3.0',
  'Autoconf-exception-2.0',
  'Bison-exception-2.2',
  'Font-exception-2.0',
  'Linux-syscall-note',
  'OpenSSL-exception',
]);

export type SpdxInvalidReason = 'empty' | 'syntax' | 'unknown_id' | 'unknown_exception' | 'unbalanced' | 'too_deep';

export type SpdxValidation = { valid: true; canonical: string } | { valid: false; reason: SpdxInvalidReason };

type Token = { kind: 'open' } | { kind: 'close' } | { kind: 'and' } | { kind: 'or' } | { kind: 'with' } | { kind: 'word'; text: string };

/** Characters of a license or exception id (`idstring` plus the `+` suffix). */
function isIdChar(c: number): boolean {
  return (
    (c >= 0x30 && c <= 0x39) || // 0-9
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) || // a-z
    c === 0x2d || // -
    c === 0x2e || // .
    c === 0x2b // +
  );
}

function isSpace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function tokenize(input: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const c = input.charCodeAt(i);
    if (isSpace(c)) {
      i++;
    } else if (c === 0x28) {
      tokens.push({ kind: 'open' });
      i++;
    } else if (c === 0x29) {
      tokens.push({ kind: 'close' });
      i++;
    } else if (isIdChar(c)) {
      let j = i + 1;
      while (j < input.length && isIdChar(input.charCodeAt(j))) j++;
      const word = input.slice(i, j);
      const upper = word.toUpperCase();
      if (upper === 'AND') tokens.push({ kind: 'and' });
      else if (upper === 'OR') tokens.push({ kind: 'or' });
      else if (upper === 'WITH') tokens.push({ kind: 'with' });
      else tokens.push({ kind: 'word', text: word });
      i = j;
    } else {
      return null;
    }
  }
  return tokens;
}

/** Case-insensitive lookup table `lower -> canonical spelling`. */
export function buildIdIndex(ids: Iterable<string>): Map<string, string> {
  const index = new Map<string, string>();
  for (const id of ids) {
    if (typeof id === 'string' && id.length > 0 && !index.has(id.toLowerCase())) index.set(id.toLowerCase(), id);
  }
  return index;
}

const EXCEPTION_INDEX = buildIdIndex(SPDX_EXCEPTIONS);

/** Canonical spelling of a license id (with an optional `+` suffix), or null. */
function canonicalLicenseId(word: string, ids: ReadonlyMap<string, string>): string | null {
  const plus = word.endsWith('+');
  const base = plus ? word.slice(0, -1) : word;
  if (base.length === 0 || base.includes('+')) return null;
  const canonical = ids.get(base.toLowerCase());
  return canonical === undefined ? null : plus ? `${canonical}+` : canonical;
}

/**
 * Validates `expression` and returns its canonical form: single spaces
 * between operands and operators, no space inside parentheses, canonical id
 * spelling, upper-case operators. `knownIds` is either an iterable of
 * canonical ids or an index built once with `buildIdIndex`.
 */
export function validateSpdxExpression(expression: string, knownIds: Iterable<string> | ReadonlyMap<string, string>): SpdxValidation {
  if (typeof expression !== 'string' || expression.trim() === '') return { valid: false, reason: 'empty' };
  const tokens = tokenize(expression);
  if (tokens === null) return { valid: false, reason: 'syntax' };
  const ids = knownIds instanceof Map ? (knownIds as ReadonlyMap<string, string>) : buildIdIndex(knownIds as Iterable<string>);

  const out: string[] = [];
  let depth = 0;
  // expectOperand: a license id or "(" must come next; afterId: the previous
  // token was a license id (only then may WITH follow).
  let expectOperand = true;
  let afterId = false;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (expectOperand) {
      if (token.kind === 'open') {
        depth++;
        if (depth > MAX_SPDX_DEPTH) return { valid: false, reason: 'too_deep' };
        out.push('(');
        continue;
      }
      if (token.kind !== 'word') return { valid: false, reason: token.kind === 'close' ? 'unbalanced' : 'syntax' };
      const id = canonicalLicenseId(token.text, ids);
      if (id === null) return { valid: false, reason: 'unknown_id' };
      out.push(id);
      expectOperand = false;
      afterId = true;
      continue;
    }
    switch (token.kind) {
      case 'and':
      case 'or':
        out.push(token.kind === 'and' ? ' AND ' : ' OR ');
        expectOperand = true;
        afterId = false;
        break;
      case 'close':
        depth--;
        if (depth < 0) return { valid: false, reason: 'unbalanced' };
        out.push(')');
        afterId = false;
        break;
      case 'with': {
        const next = tokens[i + 1];
        if (!afterId || next === undefined || next.kind !== 'word') return { valid: false, reason: 'syntax' };
        const exception = EXCEPTION_INDEX.get(next.text.toLowerCase());
        if (exception === undefined) return { valid: false, reason: 'unknown_exception' };
        out.push(` WITH ${exception}`);
        i++;
        afterId = false;
        break;
      }
      default:
        return { valid: false, reason: 'syntax' };
    }
  }
  if (depth !== 0) return { valid: false, reason: 'unbalanced' };
  if (expectOperand) return { valid: false, reason: 'syntax' };
  return { valid: true, canonical: out.join('') };
}

/** Canonical form of `expression`, or null when it is not a valid expression over `knownIds`. */
export function canonicalizeSpdxExpression(expression: string, knownIds: Iterable<string> | ReadonlyMap<string, string>): string | null {
  const result = validateSpdxExpression(expression, knownIds);
  return result.valid ? result.canonical : null;
}
