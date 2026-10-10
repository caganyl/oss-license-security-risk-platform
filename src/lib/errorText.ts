import os from 'os';
import { redactSecrets } from './redact';

/**
 * L-5 sanitizer of persisted error texts (REQ-003 AC-T-4, D-48; ADR-002 Ek
 * E3). Every text written to `scans.error_message` / `reports.error_message`
 * and the retry log line goes through `sanitizeErrorText`.
 *
 * Order matters (ADR-002 Ek E3, revised after REQ-003 security review L-1):
 * 1. Control and format characters first, so that an escape sequence glued
 *    to a secret, or a control character splitting a secret or a path, can
 *    no longer hide it from steps 2–3:
 *    - escape sequences are removed whole, 7-bit and 8-bit forms: CSI
 *      (`ESC [` / `\x9b` … final byte), control strings OSC/DCS/SOS/PM/APC
 *      (`ESC ]`, `ESC P`, `ESC X`, `ESC ^`, `ESC _` / `\x9d` `\x90` `\x98`
 *      `\x9e` `\x9f` … BEL or ST) and two-character `ESC` sequences; an
 *      incomplete sequence loses only its introducing control character;
 *    - Unicode format characters (`\p{Cf}`: zero width, BOM, bidi
 *      embeddings/overrides/isolates) are removed (I-8);
 *    - `\r\n` -> `\n`; every other C0 (except `\n`, `\t`), DEL and C1 removed.
 * 2. Secrets: the given secret forms (raw token, Basic base64), secret env
 *    values and credential URLs (`redactSecrets`), `ossr_` API keys and
 *    well-known token shapes (also after `_`, a `%XX` escape or CSI
 *    parameters) and `Authorization`/`Bearer`/`Basic` values (any letter
 *    case) -> `[REDACTED]`.
 * 3. Paths, longest first, case-insensitive on Windows, `\` and `/` forms:
 *    workspace -> `<workspace>`, SCAN_ROOTS -> `<scan-root>`, temp roots ->
 *    `<temp>`, profile folder -> `<home>`.
 * 4. Length: at most `MAX_ERROR_TEXT_CHARS` code points, cut last so a
 *    half secret/path never escapes steps 2–3.
 *
 * Steps 2–3 also run once on the raw text before step 1: an escape sequence
 * whose final byte is the first character of a secret or a path (for example
 * `ESC [ 1 C:\Users\…`, where `C` ends the CSI) would otherwise remove that
 * character in step 1 and leave the rest unmatched. Placeholders hold no
 * secret, so whatever step 1 does to them afterwards cannot expose one.
 */

export const MAX_ERROR_TEXT_CHARS = 2000;
export const REDACTED = '[REDACTED]';

export interface ErrorTextContext {
  /** Exact secret strings (e.g. the clone token and its Basic base64 form). */
  secrets?: readonly string[];
  /** Job temp workspaces (`ossrisk-scan-*`) -> `<workspace>`. */
  workspaceDirs?: readonly string[];
  /** SCAN_ROOTS entries -> `<scan-root>`. */
  scanRoots?: readonly string[];
  /** Temp roots -> `<temp>`. Default `[os.tmpdir()]`; `[]` disables. */
  tempDirs?: readonly string[];
  /** Profile folder -> `<home>`. Default `os.homedir()`; `null` disables. */
  homeDir?: string | null;
  /** Environment whose secret values are masked (default `process.env`). */
  env?: NodeJS.ProcessEnv;
  /** Path comparison rules (default `process.platform`). */
  platform?: NodeJS.Platform;
  /** Code point limit (default `MAX_ERROR_TEXT_CHARS`); `Infinity` keeps the length (caller cuts later). */
  maxChars?: number;
}

/** Replaces every occurrence of the given secret forms with `[REDACTED]`, longest first. */
export function scrubSecrets(text: string, secrets: readonly string[]): string {
  let scrubbed = text;
  const ordered = [...new Set(secrets.filter((s) => typeof s === 'string' && s.length > 0))].sort((a, b) => b.length - a.length);
  for (const secret of ordered) scrubbed = scrubbed.split(secret).join(REDACTED);
  return scrubbed;
}

// Full `ossr_<16 hex>_<secret>` API keys (src/lib/apiKeys.ts); the display prefix alone is not secret.
const API_KEY_RE = /ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{8,}/g;

/**
 * Start boundary of a token shape, instead of `\b`: no ASCII letter/digit
 * before it (`_ghp_…` and `"ghp_…` match, `xghp_…` does not), or right after
 * a percent escape (`%3Aghp_…` in an echoed URL), or right after the
 * parameters of a CSI (`ESC [ 3 1 ghp_…` on the raw text, where `g` would be
 * eaten as the CSI final byte). Every alternative has a bounded length, so the
 * lookbehind costs a constant per position (no backtracking blow-up).
 */
const TOKEN_START = String.raw`(?:(?<![A-Za-z0-9])|(?<=%[0-9A-Fa-f]{2})|(?<=(?:\x1b\[|\x9b)[0-?]{0,16}))`;

// Provider token shapes and HTTP auth headers that may be echoed by git/libcurl.
const TOKEN_PATTERNS: readonly RegExp[] = [
  new RegExp(String.raw`${TOKEN_START}(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}`, 'g'),
  new RegExp(String.raw`${TOKEN_START}github_pat_[A-Za-z0-9_]{20,}`, 'g'),
  new RegExp(String.raw`${TOKEN_START}glpat-[A-Za-z0-9_-]{20,}`, 'g'),
  /(?<![A-Za-z0-9])(Authorization:\s*)(?:Basic|Bearer|token)\s+[^\s'"]+/gi,
  /(?<![A-Za-z0-9])(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}/gi,
  /(?<![A-Za-z0-9])(Basic\s+)[A-Za-z0-9+/=]{16,}/gi,
];

function maskSecrets(text: string, context: ErrorTextContext): string {
  let out = scrubSecrets(text, context.secrets ?? []);
  out = redactSecrets(out, context.env ?? process.env);
  out = out.replace(API_KEY_RE, REDACTED);
  for (const re of TOKEN_PATTERNS) {
    out = out.replace(re, (_match, keep?: string) => `${typeof keep === 'string' ? keep : ''}${REDACTED}`);
  }
  return out;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** `\`- and `/`-separated forms of a path (and the MSYS `/c/...` form of a drive path on Windows). */
function pathForms(dir: string, windows: boolean): string[] {
  const trimmed = dir.replace(/[\\/]+$/, '');
  if (trimmed.length === 0) return [];
  const forms = new Set<string>([trimmed]);
  if (windows) {
    const back = trimmed.replace(/\//g, '\\');
    const fwd = trimmed.replace(/\\/g, '/');
    forms.add(back);
    forms.add(fwd);
    const drive = /^([A-Za-z]):\//.exec(fwd);
    if (drive) forms.add(`/${drive[1].toLowerCase()}${fwd.slice(2)}`);
  } else {
    forms.add(trimmed.replace(/\\/g, '/'));
  }
  return [...forms];
}

// The path must end at a name boundary: `C:\Users\ab` must not eat `C:\Users\abc`.
const NAME_CHAR_LOOKAHEAD = '(?![\\p{L}\\p{N}._~$-])';

function maskPaths(text: string, context: ErrorTextContext): string {
  const windows = (context.platform ?? process.platform) === 'win32';
  const homeDir = context.homeDir === undefined ? safeHomedir() : context.homeDir;
  const groups: Array<[readonly string[], string]> = [
    [context.workspaceDirs ?? [], '<workspace>'],
    [context.scanRoots ?? [], '<scan-root>'],
    [context.tempDirs ?? [os.tmpdir()], '<temp>'],
    [homeDir ? [homeDir] : [], '<home>'],
  ];
  const entries: Array<{ form: string; placeholder: string }> = [];
  for (const [dirs, placeholder] of groups) {
    for (const dir of dirs) {
      if (typeof dir !== 'string' || dir.length < 2) continue;
      for (const form of pathForms(dir, windows)) entries.push({ form, placeholder });
    }
  }
  // Longest first: the workspace under %TEMP% under the profile gets the most specific placeholder.
  entries.sort((a, b) => b.form.length - a.form.length);
  let out = text;
  for (const { form, placeholder } of entries) {
    const re = new RegExp(escapeRegExp(form) + NAME_CHAR_LOOKAHEAD, windows ? 'giu' : 'gu');
    out = out.replace(re, placeholder);
  }
  return out;
}

function safeHomedir(): string | null {
  try {
    return os.homedir() || null;
  } catch {
    return null;
  }
}

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

/** Cuts to `max` code points (a surrogate pair is never split); the last kept character is `…`. */
export function truncateCodePoints(text: string, max: number = MAX_ERROR_TEXT_CHARS): string {
  const chars = Array.from(text);
  if (chars.length <= max) return text;
  return `${chars.slice(0, Math.max(0, max - 1)).join('')}…`;
}

/** L-5 sanitizer (ADR-002 Ek E3); pure apart from the `os`/`process.env` defaults. */
export function sanitizeErrorText(text: string, context: ErrorTextContext = {}): string {
  const input = typeof text === 'string' ? text : String(text);
  const max = context.maxChars ?? MAX_ERROR_TEXT_CHARS;
  const mask = (text: string) => maskPaths(maskSecrets(text, context), context);
  // Raw pre-pass (see the module comment), then steps 1–3, then the cut.
  const cleaned = mask(stripControl(mask(input)));
  return Number.isFinite(max) ? truncateCodePoints(cleaned, Math.max(1, Math.floor(max))) : cleaned;
}
