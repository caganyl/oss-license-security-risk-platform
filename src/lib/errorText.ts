import os from 'os';
import { redactSecrets } from './redact';

/**
 * L-5 sanitizer of persisted error texts (REQ-003 AC-T-4, D-48; ADR-002 Ek
 * E3). Every text written to `scans.error_message` / `reports.error_message`
 * and the retry log line goes through `sanitizeErrorText`.
 *
 * Order matters (ADR-002 Ek E3):
 * 1. Secrets: the given secret forms (raw token, Basic base64), secret env
 *    values and credential URLs (`redactSecrets`), `ossr_` API keys and
 *    well-known token shapes -> `[REDACTED]`.
 * 2. Paths, longest first, case-insensitive on Windows, `\` and `/` forms:
 *    workspace -> `<workspace>`, SCAN_ROOTS -> `<scan-root>`, temp roots ->
 *    `<temp>`, profile folder -> `<home>`.
 * 3. Control characters: ANSI CSI sequences removed, `\r\n` -> `\n`, every
 *    other C0 (except `\n`, `\t`), DEL and C1 removed.
 * 4. Length: at most `MAX_ERROR_TEXT_CHARS` code points, cut last so a
 *    half secret/path never escapes step 1–2.
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
// Provider token shapes and HTTP auth headers that may be echoed by git/libcurl.
const TOKEN_PATTERNS: readonly RegExp[] = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\b(Authorization:\s*)(?:Basic|Bearer|token)\s+[^\s'"]+/gi,
  /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}/g,
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

// eslint-disable-next-line no-control-regex
const ANSI_CSI_RE = /\x1b\[[0-?]*[ -/]*[@-~]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;

function stripControl(text: string): string {
  return text.replace(ANSI_CSI_RE, '').replace(/\r\n/g, '\n').replace(CONTROL_RE, '');
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
  const cleaned = stripControl(maskPaths(maskSecrets(input, context), context));
  return Number.isFinite(max) ? truncateCodePoints(cleaned, Math.max(1, Math.floor(max))) : cleaned;
}
