/**
 * Control and format character removal (ADR-002 Ek E3 step 1; REQ-004
 * ADR-006 Karar 8 step 3).
 *
 * Moved here from `errorText.ts` unchanged so that the archive thread
 * (`src/enrichment/text.ts`) can use the same scanner: this module has **no
 * imports** on purpose (ADR-006 Karar 1 boundary rule). `errorText.ts`
 * re-exports `stripControl`, so its behaviour and tests stay the same.
 */

const BEL = 0x07;
const LF = 0x0a;
const TAB = 0x09;
const ESC = 0x1b;
const DEL = 0x7f;
const BACKSLASH = 0x5c;
const C1_CSI = 0x9b;
const C1_ST = 0x9c;
/** `ESC` + one of `P X ] ^ _` opens a control string (DCS, SOS, OSC, PM, APC). */
const ESC_STRING_INTRODUCERS: ReadonlySet<number> = new Set([0x50, 0x58, 0x5d, 0x5e, 0x5f]);
/** 8-bit DCS, SOS, OSC, PM, APC. */
const C1_STRING_INTRODUCERS: ReadonlySet<number> = new Set([0x90, 0x98, 0x9d, 0x9e, 0x9f]);
const FORMAT_CHARS_RE = /\p{Cf}/gu;

/**
 * End (exclusive) of a CSI whose parameters start at `from`, or -1 when no
 * final byte follows. Parameter (0x30–0x3F) and intermediate (0x20–0x2F)
 * bytes are skipped; C0 controls other than `ESC` and `\n` (and DEL) do not
 * end the sequence, as in a terminal. The scan stops at the first other
 * character, so consecutive scans never overlap (linear).
 */
function csiEnd(text: string, from: number): number {
  for (let j = from; j < text.length; j++) {
    const c = text.charCodeAt(j);
    if (c >= 0x40 && c <= 0x7e) return j + 1;
    if (c >= 0x20 && c <= 0x3f) continue;
    if ((c < 0x20 && c !== ESC && c !== LF) || c === DEL) continue;
    return -1;
  }
  return -1;
}

/** End (exclusive) of a two-character `ESC` sequence (`ESC` [0x20–0x2F]* [0x30–0x7E]) starting after `ESC`, or -1. */
function escEnd(text: string, from: number): number {
  let j = from;
  while (j < text.length && text.charCodeAt(j) >= 0x20 && text.charCodeAt(j) <= 0x2f) j++;
  const c = text.charCodeAt(j);
  return c >= 0x30 && c <= 0x7e ? j + 1 : -1;
}

/**
 * Step 1 of the sanitizer: escape sequences, format characters, C0/DEL/C1.
 * A single forward pass (linear in the text length, also on hostile input).
 */
export function stripControl(input: string): string {
  const text = input.replace(FORMAT_CHARS_RE, '');
  const len = text.length;

  // A control string body started anywhere in [noEndFrom, noEndTo] has no
  // terminator before noEndTo: remembered so that many introducers on one
  // unterminated line are not rescanned (keeps the pass linear).
  let noEndFrom = -1;
  let noEndTo = -1;
  /** End (exclusive) of a control string body starting at `from` (BEL or ST), or -1 if unterminated before the line end. */
  const stringEnd = (from: number): number => {
    if (from >= noEndFrom && from <= noEndTo) return -1;
    for (let j = from; j < len; j++) {
      const c = text.charCodeAt(j);
      if (c === BEL || c === C1_ST) return j + 1;
      if (c === ESC && text.charCodeAt(j + 1) === BACKSLASH) return j + 2;
      if (c === ESC || c === LF) {
        noEndFrom = from;
        noEndTo = j;
        return -1;
      }
    }
    noEndFrom = from;
    noEndTo = len;
    return -1;
  };

  const parts: string[] = [];
  let keepFrom = 0;
  let i = 0;
  while (i < len) {
    const c = text.charCodeAt(i);
    let next = -1;
    if (c === ESC) {
      const n = text.charCodeAt(i + 1);
      if (n === 0x5b) next = csiEnd(text, i + 2);
      else if (ESC_STRING_INTRODUCERS.has(n)) next = stringEnd(i + 2);
      else next = escEnd(text, i + 1);
    } else if (c === C1_CSI) {
      next = csiEnd(text, i + 1);
    } else if (C1_STRING_INTRODUCERS.has(c)) {
      next = stringEnd(i + 1);
    } else if ((c >= 0x20 && c !== DEL && (c < 0x80 || c > 0x9f)) || c === LF || c === TAB) {
      i++;
      continue; // kept
    }
    // Dropped: a whole sequence, or (incomplete sequence, `\r`, other C0, DEL, C1) one character.
    if (keepFrom < i) parts.push(text.slice(keepFrom, i));
    i = next === -1 ? i + 1 : next;
    keepFrom = i;
  }
  if (keepFrom < len) parts.push(text.slice(keepFrom));
  return parts.join('');
}

/**
 * Replaces every unpaired UTF-16 surrogate with U+FFFD (ADR-006 Karar 8:
 * JSONB and XML safety). Linear; well-formed text is returned as is.
 */
export function replaceLoneSurrogates(text: string): string {
  let parts: string[] | null = null;
  let keepFrom = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0xd800 || c > 0xdfff) continue;
    if (c <= 0xdbff) {
      const n = text.charCodeAt(i + 1);
      if (n >= 0xdc00 && n <= 0xdfff) {
        i++;
        continue; // valid pair
      }
    }
    parts ??= [];
    parts.push(text.slice(keepFrom, i), '�');
    keepFrom = i + 1;
  }
  if (parts === null) return text;
  parts.push(text.slice(keepFrom));
  return parts.join('');
}

/**
 * Stored-text cleanup of ADR-006 Karar 8 steps 2–3: `\r\n` and lone `\r` ->
 * `\n`, then `stripControl`, then lone surrogates -> U+FFFD.
 */
export function sanitizeText(text: string): string {
  const input = typeof text === 'string' ? text : String(text);
  return replaceLoneSurrogates(stripControl(input.replace(/\r\n?/g, '\n')));
}
