import os from 'os';
import { redactSecrets } from './redact';
import { stripControl } from './textSanitize';

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
  return out.replace(REDACTED_TAIL_RE, REDACTED);
}

/**
 * `[REDACTED]` directly followed by token characters swallows them. A secret
 * split by a control or format character (`ghp_<20>\r<rest>`, `Bearer
 * <16>\x00<rest>`, `…\x1b[0m<rest>`, U+200B) whose first part alone already
 * has the token shape is masked by the raw pre-pass; once step 1 removes the
 * separator, the rest is glued to the placeholder and no pattern sees it as a
 * token any more. Over-masking text that touches a placeholder is harmless.
 * A `.` is swallowed only inside a run, so a sentence-ending dot stays.
 */
const REDACTED_TAIL_RE = /\[REDACTED\](?:[A-Za-z0-9_+/=~-]|\.(?=[A-Za-z0-9_+/=~-]))+/g;

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

// Step 1 lives in the import-free `textSanitize.ts` (shared with the archive
// thread, ADR-006 Karar 8); re-exported so existing callers and tests stay.
export { stripControl };

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
