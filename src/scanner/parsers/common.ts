/**
 * Shared pieces of the dependency parsers (REQ-003 P-10, ADR-005 Karar 1, 3, 6, 7).
 *
 * The parsers are a line-by-line port of the legacy Python parsers
 * (`common.py`, frozen as golden output, REQ-003 D-26). Wherever JavaScript and Python
 * disagree (whitespace sets, `splitlines`, truthiness, `str()`, `quote`,
 * regex `\s`/`\d`/`$`), the Python behaviour is reproduced by an explicit
 * helper below; the parsers never use `trim`, `split('\n')`,
 * `encodeURIComponent`, JS truthiness or `String(null)` (ADR-005 uyarı 1).
 *
 * Boundary rule (ADR-005 Karar 1): this folder imports only `node:fs`,
 * `node:path`, `node:crypto`, `node:worker_threads`, the TOML library and
 * types. It never loads `dotenv`, the database or other runtime modules.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ScannedDependency, ScannedFile } from '../../types/scan';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Directory names that are never descended into (relative to the scan root, case-sensitive; D-28 b). */
export const SKIP_DIRS: ReadonlySet<string> = new Set([
  '.git',
  '.hg',
  '.svn',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  '.mypy_cache',
  '.pytest_cache',
  'node_modules',
  'dist',
  'build',
]);

export const NODEJS_MANIFEST_NAMES: readonly string[] = ['package.json', 'package-lock.json', 'yarn.lock'];
export const PYTHON_MANIFEST_NAMES: readonly string[] = [
  'requirements.txt',
  'requirements-dev.txt',
  'requirements-test.txt',
  'pyproject.toml',
  'poetry.lock',
];
const ALL_MANIFEST_NAMES: ReadonlySet<string> = new Set([...NODEJS_MANIFEST_NAMES, ...PYTHON_MANIFEST_NAMES]);

/** Per-file size limit (D-28 e, ADR-005 Karar 7). */
export const MAX_MANIFEST_BYTES = 32 * 1024 * 1024;

export const LINK_NOT_FOLLOWED_MESSAGE = 'Sembolik bağlantı veya junction izlenmedi.';
export const FILE_TOO_LARGE_MESSAGE = 'Dosya boyut sınırını aşıyor (32 MiB).';

// ---------------------------------------------------------------------------
// Result containers
// ---------------------------------------------------------------------------

export interface ParseErrorRecord {
  ecosystem: string;
  file: string;
  error: string;
}

/** Mutable accumulator of one ecosystem parser (Python `ParseResult`). */
export interface ParseResult {
  dependencies: ScannedDependency[];
  scan_files: ScannedFile[];
  parse_errors: ParseErrorRecord[];
}

export function emptyResult(): ParseResult {
  return { dependencies: [], scan_files: [], parse_errors: [] };
}

export function extendResult(target: ParseResult, other: ParseResult): void {
  target.dependencies.push(...other.dependencies);
  target.scan_files.push(...other.scan_files);
  target.parse_errors.push(...other.parse_errors);
}

// ---------------------------------------------------------------------------
// Python compatibility helpers (ADR-005 Karar 3)
// ---------------------------------------------------------------------------

/**
 * Python `str.isspace` set as a regex character-class body: Zs plus the
 * bidirectional classes WS, B and S. Unlike JS `\s` it contains
 * `\x1c-\x1f` and `\x85` and does not contain U+FEFF.
 */
export const PY_WS = '\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';

/**
 * The `PY_WS` set as a UTF-16 code unit test. Every member is a single BMP
 * code unit outside the surrogate range, so testing code units is the same as
 * testing code points.
 */
export function isPyWhitespace(code: number): boolean {
  return (
    (code >= 0x09 && code <= 0x0d) || // \t \n \x0b \x0c \r
    (code >= 0x1c && code <= 0x20) || // \x1c-\x1f and space
    code === 0x85 ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000
  );
}

/**
 * Python `str.strip()` without arguments.
 *
 * Index scan from both ends instead of a `[WS]+$` regex: a backtracking
 * engine retries the trailing alternative at every start position of a long
 * whitespace run that is not at the end, which is quadratic on untrusted
 * manifest lines (REQ-003 security review M-1). This is linear.
 */
export function pyStrip(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && isPyWhitespace(value.charCodeAt(start))) start++;
  while (end > start && isPyWhitespace(value.charCodeAt(end - 1))) end--;
  return start === 0 && end === value.length ? value : value.slice(start, end);
}

/** Python `str.rstrip()` without arguments (linear, see `pyStrip`). */
export function pyRstrip(value: string): string {
  let end = value.length;
  while (end > 0 && isPyWhitespace(value.charCodeAt(end - 1))) end--;
  return end === value.length ? value : value.slice(0, end);
}

/** Python `str.lstrip()` without arguments (linear). */
function pyLstripIndex(value: string, from: number): number {
  let i = from;
  while (i < value.length && isPyWhitespace(value.charCodeAt(i))) i++;
  return i;
}

const REQUIREMENT_NAME_CHAR = /^[A-Za-z0-9_.-]$/;

function isRequirementNameChar(ch: string): boolean {
  return REQUIREMENT_NAME_CHAR.test(ch);
}

/**
 * Linear equivalent of the Python requirement regex
 * `^\s*([A-Za-z0-9_.-]+)\s*(\[.*?\])?\s*(.*)$` (Python `\s` = `PY_WS`, `.` =
 * anything but `\n`, `$` = end or before a final `\n`). Returns
 * `[name, rest]` (groups 1 and 3) or `null`.
 *
 * The regex form backtracks cubically when the text holds a `\n` that the
 * last group cannot cross (e.g. a TOML requirement string with an embedded
 * newline, M-1). The first match of the backtracking engine is reproduced
 * exactly:
 * - leading whitespace and the name are maximal (giving any of them back
 *   never yields a match that the maximal choice does not yield first);
 * - after the name and its maximal whitespace run, the bracket is tried
 *   first and its lazy body ends at each `]` in turn (never across `\n`);
 *   after each candidate the maximal whitespace run is taken and the rest
 *   must hold no `\n` except a final one; then the bracket is skipped.
 */
export function matchRequirementLine(value: string): [string, string] | null {
  const len = value.length;
  const nameStart = pyLstripIndex(value, 0);
  let nameEnd = nameStart;
  while (nameEnd < len && isRequirementNameChar(value[nameEnd])) nameEnd++;
  if (nameEnd === nameStart) return null;
  const name = value.slice(nameStart, nameEnd);

  // `(.*)$`: the rest may hold a `\n` only as the very last character.
  const finalNewline = len > 0 && value.charCodeAt(len - 1) === 0x0a;
  // `lastIndexOf` clamps a negative start to 0, so the one-character text "\n" is handled apart.
  const lastInnerNewline = finalNewline ? (len >= 2 ? value.lastIndexOf('\n', len - 2) : -1) : value.lastIndexOf('\n');
  const restFrom = (t: number): string | null => {
    if (t <= lastInnerNewline) return null;
    return value.slice(t, finalNewline && t < len ? len - 1 : len);
  };

  const afterName = pyLstripIndex(value, nameEnd);
  if (afterName < len && value[afterName] === '[') {
    for (let j = afterName + 1; j < len && value[j] !== '\n'; j++) {
      if (value[j] !== ']') continue;
      const rest = restFrom(pyLstripIndex(value, j + 1));
      if (rest !== null) return [name, rest];
    }
  }
  // Bracket skipped: the character at `afterName` is not whitespace, so the
  // second whitespace group is empty and the rest starts there.
  const rest = restFrom(afterName);
  return rest === null ? null : [name, rest];
}

/** Python `str.strip(chars)` / `rstrip(chars)` with an explicit character set. */
export function pyStripChars(value: string, chars: string, side: 'both' | 'right' = 'both'): string {
  let start = 0;
  let end = value.length;
  if (side === 'both') {
    while (start < end && chars.includes(value[start])) start++;
  }
  while (end > start && chars.includes(value[end - 1])) end--;
  return value.slice(start, end);
}

const LINE_BREAKS = new Set(['\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85', ' ', ' ']);

/**
 * Python `str.splitlines()`: splits on `\r\n`, `\n`, `\r`, VT, FF, FS, GS, RS,
 * NEL, LS and PS; no trailing empty element.
 */
export function pySplitLines(value: string): string[] {
  const lines: string[] = [];
  let start = 0;
  let i = 0;
  while (i < value.length) {
    const ch = value[i];
    if (LINE_BREAKS.has(ch)) {
      lines.push(value.slice(start, i));
      i += ch === '\r' && value[i + 1] === '\n' ? 2 : 1;
      start = i;
    } else {
      i++;
    }
  }
  if (start < value.length) lines.push(value.slice(start));
  return lines;
}

/** Python universal newlines of `read_text`: `\r\n` and `\r` become `\n`. */
export function universalNewlines(value: string): string {
  return value.replace(/\r\n?/g, '\n');
}

/** Python `dict` as seen by the parsers: a plain object (not an array, `null` or a date). */
export function isPyDict(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Date);
}

/** Python truthiness: `None`, `False`, `0`, `''`, empty list and empty dict are false. */
export function pyTruthy(value: unknown): boolean {
  if (value === null || value === undefined || value === false) return false;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'bigint') return value !== BigInt(0);
  if (typeof value === 'string') return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (isPyDict(value)) return Object.keys(value).length > 0;
  return true;
}

/** Python-like type name used in error texts (never contains input data). */
function pyTypeName(value: unknown): string {
  if (value === null || value === undefined) return 'NoneType';
  if (Array.isArray(value)) return 'list';
  if (value instanceof Date) return 'datetime';
  if (typeof value === 'string') return 'str';
  if (typeof value === 'boolean') return 'bool';
  if (typeof value === 'number' || typeof value === 'bigint') return 'number';
  if (isPyDict(value)) return 'dict';
  return typeof value;
}

/** Raised where Python would raise `AttributeError`/`TypeError` (ADR-005 Karar 2). */
export class PyTypeError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'PyTypeError';
  }
}

/**
 * Python `str(x)` for the value types whose text form is identical in both
 * languages: text as is, `None`, `True`, `False`. Any other type (number,
 * date, list, dict) is a type-invalid manifest value and throws, so the
 * file ends up in `parse_errors` (ADR-005 Karar 2, REQ-003 riskler).
 */
export function pyStr(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return 'None';
  if (value === true) return 'True';
  if (value === false) return 'False';
  throw new PyTypeError(`Beklenmeyen değer tipi: metin bekleniyordu (${pyTypeName(value)}).`);
}

/** Python `dict.get(key, default)`; a non-dict receiver raises like `AttributeError`. */
export function pyGet(obj: unknown, key: string, fallback: unknown = null): unknown {
  if (!isPyDict(obj)) {
    throw new PyTypeError(`Beklenmeyen tip: sözlük bekleniyordu (${pyTypeName(obj)}).`);
  }
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : fallback;
}

/** Python `dict.items()`; a non-dict receiver raises like `AttributeError`. */
export function pyItems(obj: unknown): Array<[string, unknown]> {
  if (!isPyDict(obj)) {
    throw new PyTypeError(`Beklenmeyen tip: sözlük bekleniyordu (${pyTypeName(obj)}).`);
  }
  return Object.entries(obj);
}

/** Python `dict.values()`. */
export function pyValues(obj: unknown): unknown[] {
  return pyItems(obj).map(([, value]) => value);
}

/**
 * Python `for x in value` over a manifest value: list elements or dict keys.
 * Text (iterated character by character in Python) and every other type
 * throw (ADR-005 Karar 2).
 */
export function pyIter(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (isPyDict(value)) return Object.keys(value);
  throw new PyTypeError(`Beklenmeyen tip: liste bekleniyordu (${pyTypeName(value)}).`);
}

/** Code-point order comparison (Python `sorted` on `str`); JS default sort uses UTF-16 units. */
export function compareCodePoints(a: string, b: string): number {
  const ai = a[Symbol.iterator]();
  const bi = b[Symbol.iterator]();
  for (;;) {
    const x = ai.next();
    const y = bi.next();
    if (x.done || y.done) {
      if (x.done && y.done) return 0;
      return x.done ? -1 : 1;
    }
    const cx = x.value.codePointAt(0) as number;
    const cy = y.value.codePointAt(0) as number;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

// `String.prototype.isWellFormed` is not typed for ES2022 (ADR-005 uyarı 8).
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function hasLoneSurrogate(value: string): boolean {
  return LONE_SURROGATE_RE.test(value);
}

const ALWAYS_SAFE = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~');

/**
 * Python `urllib.parse.quote(value, safe)`: UTF-8 bytes; `A-Z a-z 0-9 _ . - ~`
 * and `safe` stay, every other byte becomes upper-case `%XX`. A lone
 * surrogate raises (Python `UnicodeEncodeError`).
 */
export function pyQuote(value: string, safe: string): string {
  if (hasLoneSurrogate(value)) {
    throw new PyTypeError('Metin UTF-8 olarak kodlanamadı (eşleşmeyen vekil karakter).');
  }
  let out = '';
  for (const byte of Buffer.from(value, 'utf8')) {
    const ch = String.fromCharCode(byte);
    if (byte < 0x80 && (ALWAYS_SAFE.has(ch) || safe.includes(ch))) {
      out += ch;
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// purl, dedupe, manifest dir
// ---------------------------------------------------------------------------

export function npmPurl(name: string, version: string | null): string {
  const encoded = pyQuote(name, '@/');
  if (version) return `pkg:npm/${encoded}@${pyQuote(version, '')}`;
  return `pkg:npm/${encoded}`;
}

/** PyPI name normalisation is only `_` -> `-` and lower case (D-27). */
export function pypiPurl(name: string, version: string | null): string {
  const normalized = name.replace(/_/g, '-').toLowerCase();
  if (version) return `pkg:pypi/${pyQuote(normalized, '')}@${pyQuote(version, '')}`;
  return `pkg:pypi/${pyQuote(normalized, '')}`;
}

/**
 * First record wins per `(ecosystem, lower(name), str(version),
 * str(manifest_path))`; `str(None) === "None"` (AC-P10-7).
 */
export function uniqueDependencies(dependencies: ScannedDependency[]): ScannedDependency[] {
  const seen = new Set<string>();
  const unique: ScannedDependency[] = [];
  for (const dep of dependencies) {
    const key = JSON.stringify([
      pyStr(dep.ecosystem),
      pyStr(dep.name).toLowerCase(),
      pyStr(dep.version),
      pyStr(dep.manifest_path),
    ]);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(dep);
  }
  return unique;
}

export function manifestDir(relPath: string, filename: string): string {
  if (relPath === filename) return '.';
  const suffix = `/${filename}`;
  return relPath.endsWith(suffix) ? relPath.slice(0, -suffix.length) : path.posix.dirname(relPath);
}

// ---------------------------------------------------------------------------
// File tree walk (ADR-005 Karar 6)
// ---------------------------------------------------------------------------

/** A regular manifest file inside the scan root (never a link). */
export interface WalkedFile {
  /** Absolute path, used only for reading; never written to output or errors. */
  absPath: string;
  /** Root-relative path with `/` separators. */
  relPath: string;
  /** Root-relative directory with `/` separators (`''` for the root). */
  relDir: string;
  name: string;
  size: number;
}

export interface FileLink {
  relPath: string;
  name: string;
}

export interface TreeWalk {
  rootDir: string;
  /** Manifest files by directory, then by file name (case-sensitive). */
  byDir: Map<string, Map<string, WalkedFile>>;
  /** Links (or reparse points resolving outside the root) with a manifest name. */
  fileLinks: FileLink[];
  /** `filesystem` records: skipped links without a manifest name (folder or file) and unreadable directories. */
  errors: ParseErrorRecord[];
}

function errnoCode(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]+$/.test(code) ? code : 'UNKNOWN';
}

function joinRel(dir: string, name: string): string {
  return dir === '' ? name : `${dir}/${name}`;
}

/** ADR-002 karar 4 prefix + separator rule; case-insensitive on Windows. */
function isInside(candidate: string, root: string): boolean {
  const norm = (p: string) => (process.platform === 'win32' ? p.toLowerCase() : p);
  const c = norm(candidate);
  const r = norm(root);
  if (c === r) return true;
  const prefix = r.endsWith(path.sep) ? r : r + path.sep;
  return c.startsWith(prefix);
}

function realOrResolved(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return path.resolve(p);
  }
}

/**
 * Single, stack-based walk of the scan root. Uses `lstat` for every entry:
 * symbolic links and junctions are never followed nor resolved (L-2),
 * `SKIP_DIRS` directories are never entered, and every regular manifest
 * file is re-checked with `realpath` against the root (second defence for
 * reparse points that are not reported as links).
 */
export function walkTree(rootDir: string): TreeWalk {
  const rootReal = realOrResolved(rootDir);
  const walk: TreeWalk = { rootDir, byDir: new Map(), fileLinks: [], errors: [] };
  const stack: Array<{ abs: string; rel: string }> = [{ abs: rootDir, rel: '' }];

  while (stack.length > 0) {
    const dir = stack.pop() as { abs: string; rel: string };
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir.abs, { withFileTypes: true });
    } catch (err) {
      walk.errors.push({
        ecosystem: 'filesystem',
        file: dir.rel === '' ? '.' : dir.rel,
        error: `Klasör okunamadı (${errnoCode(err)}).`,
      });
      continue;
    }

    for (const entry of entries) {
      const name = entry.name;
      const abs = path.join(dir.abs, name);
      const rel = joinRel(dir.rel, name);
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(abs);
      } catch {
        // Vanished or unreadable entry: a manifest name is reported by the
        // parser when it tries to read it; anything else is irrelevant.
        continue;
      }

      if (stat.isSymbolicLink()) {
        // The link target is never resolved, not even to learn whether it is
        // a folder: `stat`/`realpath` on a link to `\\host\share\…` opens an
        // SMB session and can send the user's NTLM hash (security review
        // L-2). Windows `lstat` reports junctions and folder/file symlinks
        // alike (no folder bit), so the record is chosen by name only:
        // - a manifest name -> record of its ecosystem (AC-P10-11);
        // - a SKIP_DIRS name -> silently skipped, as an unlinked folder would be;
        // - any other name -> one `filesystem` record. This includes file
        //   links with an unrelated name, which ADR-005 Karar 6 skipped
        //   silently; telling them apart from folder links would need the
        //   target (reported deviation, see the REQ-003 handoff).
        if (ALL_MANIFEST_NAMES.has(name)) {
          walk.fileLinks.push({ relPath: rel, name });
        } else if (!SKIP_DIRS.has(name)) {
          walk.errors.push({ ecosystem: 'filesystem', file: rel, error: LINK_NOT_FOLLOWED_MESSAGE });
        }
        continue;
      }

      if (stat.isDirectory()) {
        if (!SKIP_DIRS.has(name)) stack.push({ abs, rel });
        continue;
      }

      if (!stat.isFile() || !ALL_MANIFEST_NAMES.has(name)) continue;

      // Second defence (ADR-005 Karar 6), only for entries that `lstat`
      // reports as regular files, never for links: a folder reached through a
      // reparse point that libuv does not report as a link (e.g. a volume
      // mount point, which Windows only allows to local volumes) can still
      // place the file outside the root.
      if (!isInside(realOrResolved(abs), rootReal)) {
        walk.fileLinks.push({ relPath: rel, name });
        continue;
      }

      let files = walk.byDir.get(dir.rel);
      if (!files) {
        files = new Map();
        walk.byDir.set(dir.rel, files);
      }
      files.set(name, { absPath: abs, relPath: rel, relDir: dir.rel, name, size: stat.size });
    }
  }
  return walk;
}

/** Python `discover_manifests`: every regular file with this exact name, sorted by relative path. */
export function discoverManifests(walk: TreeWalk, filename: string): WalkedFile[] {
  const found: WalkedFile[] = [];
  for (const files of walk.byDir.values()) {
    const file = files.get(filename);
    if (file) found.push(file);
  }
  return found.sort((a, b) => compareCodePoints(a.relPath, b.relPath));
}

/** Sibling regular file in the same directory (`Path.is_file()` without following links). */
export function siblingFile(walk: TreeWalk, file: WalkedFile, name: string): WalkedFile | undefined {
  return walk.byDir.get(file.relDir)?.get(name);
}

/** `parse_errors` records for linked manifest files of one ecosystem. */
export function linkErrors(walk: TreeWalk, ecosystem: string, names: readonly string[]): ParseErrorRecord[] {
  return walk.fileLinks
    .filter((link) => names.includes(link.name))
    .map((link) => ({ ecosystem, file: link.relPath, error: LINK_NOT_FOLLOWED_MESSAGE }));
}

// ---------------------------------------------------------------------------
// File reading and errors (ADR-005 Karar 7)
// ---------------------------------------------------------------------------

/** File-level read error with a fixed, path-free message (D-28 c). */
export class ManifestReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestReadError';
  }
}

export interface ReadManifest {
  data: Buffer;
  record: ScannedFile;
}

/**
 * Reads a manifest once: the same buffer gives the hash/size record and the
 * text (no TOCTOU between them). Over 32 MiB the file is not read.
 */
export function readManifest(file: WalkedFile, ecosystem: 'nodejs' | 'python'): ReadManifest {
  if (file.size > MAX_MANIFEST_BYTES) {
    throw new ManifestReadError(`${file.relPath}: ${FILE_TOO_LARGE_MESSAGE}`);
  }
  let data: Buffer;
  try {
    data = fs.readFileSync(file.absPath);
  } catch (err) {
    throw new ManifestReadError(`${file.relPath}: Dosya okunamadı (${errnoCode(err)}).`);
  }
  if (data.length > MAX_MANIFEST_BYTES) {
    throw new ManifestReadError(`${file.relPath}: ${FILE_TOO_LARGE_MESSAGE}`);
  }
  return {
    data,
    record: {
      ecosystem,
      filename: file.name,
      file_path: file.relPath,
      file_hash: crypto.createHash('sha256').update(data).digest('hex'),
      size_bytes: data.length,
    },
  };
}

const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const LENIENT_UTF8 = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });

/** Python `read_text(encoding="utf-8")` (JSON, TOML): invalid UTF-8 is a file error; the BOM is kept. */
export function decodeStrict(data: Buffer, relPath: string): string {
  try {
    return STRICT_UTF8.decode(data);
  } catch {
    throw new ManifestReadError(`${relPath}: Dosya geçerli UTF-8 değil.`);
  }
}

/** Python `read_text(encoding="utf-8", errors="replace")` + universal newlines; the BOM is kept. */
export function decodeLenient(data: Buffer): string {
  return universalNewlines(LENIENT_UTF8.decode(data));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Replaces the scan root (both separators, case-insensitive on Windows) in
 * an error text. File system messages are never used (they carry absolute
 * paths); this is the last guard for library messages inside the thread
 * (ADR-005 Karar 7).
 *
 * `%TEMP%` and the profile folder (also required by ADR-005 Karar 7) are not
 * replaced here on purpose: the thread runs with `env: {}` and cannot see
 * them reliably. They are replaced on the main thread instead: the only way
 * a `parse_errors` text leaves the scan is the warning that
 * `ScanWorker` joins and passes through `scanErrorText` ->
 * `sanitizeErrorText` (workspace, SCAN_ROOTS, `os.tmpdir()`,
 * `os.homedir()`, secrets, control characters; ADR-002 Ek E3) before it is
 * written to `scans.error_message`. Any new consumer of `parse_errors` must
 * go through the same funnel.
 */
export function scrubRoot(text: string, rootDir: string): string {
  let out = text;
  const roots = new Set<string>();
  for (const p of [rootDir, path.resolve(rootDir), realOrResolved(rootDir)]) {
    if (!p) continue;
    roots.add(p);
    roots.add(p.replace(/\\/g, '/'));
    roots.add(p.replace(/\//g, '\\'));
  }
  const flags = process.platform === 'win32' ? 'gi' : 'g';
  for (const root of [...roots].sort((a, b) => b.length - a.length)) {
    if (root.length < 2) continue;
    out = out.replace(new RegExp(escapeRegExp(root), flags), '<scan-root>');
  }
  return out;
}

/** `parse_errors` record; `error` is never empty and never carries the root path. */
export function parseError(ecosystem: string, relPath: string, err: unknown, rootDir: string): ParseErrorRecord {
  let message = err instanceof Error ? err.message : typeof err === 'string' ? err : '';
  message = scrubRoot(message, rootDir);
  if (pyStrip(message) === '') message = err instanceof Error && err.name ? `Ayrıştırma hatası (${err.name}).` : 'Ayrıştırma hatası.';
  return { ecosystem, file: relPath, error: message };
}
