import fs from 'fs';
import path from 'path';
import { HttpError } from './httpError';

/**
 * Scan source classification (REQ-002 P-03 AC-P03-7, P-04; ADR-002 karar 2 + 4).
 *
 * Used twice for the same value: by the HTTP controllers before a project is
 * stored or a scan is queued (`400`), and by the scan worker right before it
 * touches the source (TOCTOU; rejection -> scan `failed`).
 */
export type ScanSource = { kind: 'remote'; url: string } | { kind: 'local'; path: string };

export type ScanSourceErrorCode = 'path_not_allowed' | 'repo_url_not_allowed';

/** Fixed contract messages; they never carry the path or SCAN_ROOTS content. */
export const PATH_NOT_ALLOWED_MESSAGE = 'Local path is not under an allowed scan root';
export const REPO_URL_NOT_ALLOWED_MESSAGE = 'Repository URL is not allowed; only https URLs are accepted';

export class ScanSourceError extends HttpError {
  declare readonly code: ScanSourceErrorCode;
  declare readonly statusCode: 400;

  constructor(code: ScanSourceErrorCode, message?: string) {
    super(400, message ?? (code === 'path_not_allowed' ? PATH_NOT_ALLOWED_MESSAGE : REPO_URL_NOT_ALLOWED_MESSAGE), code);
    this.name = 'ScanSourceError';
  }
}

const isWindows = process.platform === 'win32';

/**
 * Splits SCAN_ROOTS on `path.delimiter` (`;` on Windows, so drive letters do
 * not clash) and drops blank entries. Undefined/blank -> `[]`: local scanning
 * is closed by default (AC-P04-6).
 */
export function parseScanRoots(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * Canonicalises every root with `realpath.native` and fails loudly on a root
 * that is not an existing absolute directory. Called at server/worker start so
 * a typo in SCAN_ROOTS is an explicit startup error, not a silent rejection.
 */
export async function canonicalizeScanRoots(roots: readonly string[]): Promise<string[]> {
  const canonical: string[] = [];
  for (const root of roots) {
    const resolved = isLocalAbsolutePath(root) ? await canonicalDirectory(root) : null;
    if (!resolved) {
      throw new Error(`SCAN_ROOTS entry is not an existing absolute directory: ${root}`);
    }
    canonical.push(resolved);
  }
  return canonical;
}

/**
 * Classifies a repository URL or local path. https without user info ->
 * remote; drive-letter absolute path (POSIX absolute path off Windows) ->
 * local, only under a SCAN_ROOTS entry; anything else -> repo_url_not_allowed.
 */
export async function resolveScanSource(value: string, scanRoots: readonly string[]): Promise<ScanSource> {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim() || hasControlCharacter(value)) {
    throw new ScanSourceError('repo_url_not_allowed');
  }
  // Option injection (`-u…`) is rejected before any other interpretation.
  if (value.startsWith('-')) throw new ScanSourceError('repo_url_not_allowed');

  if (isLocalAbsolutePath(value)) {
    return { kind: 'local', path: await resolveAllowedLocalPath(value, scanRoots) };
  }
  return { kind: 'remote', url: assertRemoteUrl(value) };
}

/**
 * Synchronous remote URL check shared with the clone step: `https:` only, a
 * host, no user info (the token comes from the integration record only), no
 * whitespace. Returns the value unchanged.
 */
export function assertRemoteUrl(value: string): string {
  if (!/^https:\/\//i.test(value) || /\s/.test(value)) throw new ScanSourceError('repo_url_not_allowed');
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ScanSourceError('repo_url_not_allowed');
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username !== '' || parsed.password !== '') {
    throw new ScanSourceError('repo_url_not_allowed');
  }
  // `new URL` drops an empty user-info part (`https://@host`); reject it explicitly.
  const authority = value.slice('https://'.length).split(/[/?#]/, 1)[0];
  if (authority.includes('@')) throw new ScanSourceError('repo_url_not_allowed');
  return value;
}

/**
 * Drive-letter absolute path on Windows (`C:\…`, `C:/…`); UNC (`\\server\…`)
 * and device paths (`\\?\`, `\\.\`) are not local scan paths. Elsewhere a
 * single-slash absolute POSIX path.
 */
function isLocalAbsolutePath(value: string): boolean {
  if (isWindows) return /^[A-Za-z]:[\\/]/.test(value);
  return value.startsWith('/') && !value.startsWith('//');
}

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/** `fs.realpath.native` (the OS resolver; fs.promises has no native variant). */
function realpathNative(value: string): Promise<string> {
  return new Promise((resolve, reject) => {
    fs.realpath.native(value, (err, resolved) => (err ? reject(err) : resolve(resolved)));
  });
}

async function canonicalDirectory(value: string): Promise<string | null> {
  try {
    const real = await realpathNative(value);
    const stat = await fs.promises.stat(real);
    return stat.isDirectory() ? real : null;
  } catch {
    return null;
  }
}

async function resolveAllowedLocalPath(value: string, scanRoots: readonly string[]): Promise<string> {
  if (scanRoots.length === 0) throw new ScanSourceError('path_not_allowed');
  // realpath.native resolves `..`, symlinks, junctions, subst drives and 8.3 names.
  const candidate = await canonicalDirectory(value);
  if (!candidate) throw new ScanSourceError('path_not_allowed');

  for (const root of scanRoots) {
    if (!isLocalAbsolutePath(root)) continue;
    const canonicalRoot = await canonicalDirectory(root);
    if (canonicalRoot && isSameOrInside(candidate, canonicalRoot)) return candidate;
  }
  throw new ScanSourceError('path_not_allowed');
}

/** Prefix + separator rule, so root `…\kok\a` does not accept `…\kok\ab`. */
function isSameOrInside(candidate: string, root: string): boolean {
  const c = isWindows ? candidate.toLowerCase() : candidate;
  const r = isWindows ? root.toLowerCase() : root;
  if (c === r) return true;
  const prefix = r.endsWith(path.sep) ? r : r + path.sep;
  return c.startsWith(prefix);
}
