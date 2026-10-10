import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { boundedNumber } from '../lib/bounds';
import { sanitizeErrorText } from '../lib/errorText';
import { assertRemoteUrl } from '../lib/scanSource';
import { MAX_JOB_TIMEOUT_MS } from './sandbox/runner.config';

export { scrubSecrets } from '../lib/errorText';

/**
 * Scan workspace for remote repositories (REQ-002 P-03, ADR-002 karar 3): a
 * job-specific `ossrisk-scan-*` temp directory, a shallow `git clone` without
 * a shell, and cleanup on success and on failure.
 */

/**
 * Clone injection point of the scan worker. `signal` (optional, ADR-004
 * Karar 7) aborts the clone: the git process tree is killed and its `close`
 * awaited before the call rejects with `signal.reason`. Four-argument
 * implementations stay valid.
 */
export type CloneRepoFn = (
  url: string,
  ref: string | null,
  dest: string,
  token: string | null,
  signal?: AbortSignal,
) => Promise<void>;

export type WorkspaceLogger = Pick<Console, 'warn'>;

export const WORKSPACE_PREFIX = 'ossrisk-scan-';

const REF_RE = /^[A-Za-z0-9._/-]+$/;
const DEFAULT_CLONE_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_CAPTURED_STDERR = 64 * 1024;
const MAX_ERROR_DETAIL = 1024;

/** Thrown for a ref that could inject git options or is not a plain ref name. */
export class InvalidRefError extends Error {
  constructor() {
    super('Invalid git ref; allowed characters are A-Z a-z 0-9 . _ / - and it must not start with "-"');
    this.name = 'InvalidRefError';
  }
}

export function isValidRef(ref: string): boolean {
  return REF_RE.test(ref) && !ref.startsWith('-');
}

/** Per-job git isolation entries inside the workspace (ADR-002 Ek E1). */
export interface GitIsolationPaths {
  /** Empty file -> `GIT_CONFIG_GLOBAL`. */
  gitConfig: string;
  /** Empty folder -> `HOME` (no `.netrc`/`_netrc`, no `~/.gitconfig`). */
  home: string;
  /** `<home>/.config` -> `XDG_CONFIG_HOME` (need not exist). */
  xdgConfigHome: string;
  /** Empty folder -> `core.hooksPath`. */
  hooks: string;
}

/** `<workspace>/{gitconfig,home,home/.config,hooks}`; `workspace` is the parent of the clone target. */
export function gitIsolationPaths(workspace: string): GitIsolationPaths {
  const home = path.join(workspace, 'home');
  return {
    gitConfig: path.join(workspace, 'gitconfig'),
    home,
    xdgConfigHome: path.join(home, '.config'),
    hooks: path.join(workspace, 'hooks'),
  };
}

export interface GitCloneArgsOptions {
  /** `core.hooksPath` value. Default `<dirname(dest)>/hooks`. */
  hooksDir?: string;
  /** `win32` adds `http.sslBackend=schannel`. Default `process.platform`. */
  platform?: NodeJS.Platform;
}

/**
 * Pure argument array for `git clone`; the token never appears here. `--`
 * ends option parsing before the URL and destination.
 *
 * Hardening (D-18, AC-P03-8, AC-P03-10): the Git LFS filters are emptied and
 * made optional so no LFS process runs and no LFS object is downloaded from
 * an attacker-chosen endpoint, and HTTP redirects are not followed so the
 * clone (and a token header) never leaves the requested host.
 *
 * Isolation (N-1, ADR-002 Ek E1, AC-T-1): hooks come only from an empty
 * per-job folder, the askpass program is disabled, and on Windows the
 * Windows certificate store (schannel) is used because the system config
 * that points OpenSSL at Git's CA bundle is no longer read.
 */
export function buildGitCloneArgs(url: string, ref: string | null, dest: string, options: GitCloneArgsOptions = {}): string[] {
  const hooksDir = options.hooksDir ?? gitIsolationPaths(path.dirname(dest)).hooks;
  const platform = options.platform ?? process.platform;
  const args = [
    '-c', 'core.symlinks=false',
    '-c', 'core.longpaths=true',
    '-c', 'credential.helper=',
    '-c', 'filter.lfs.smudge=',
    '-c', 'filter.lfs.clean=',
    '-c', 'filter.lfs.process=',
    '-c', 'filter.lfs.required=false',
    '-c', 'http.followRedirects=false',
    '-c', `core.hooksPath=${hooksDir}`,
    '-c', 'core.askPass=',
  ];
  if (platform === 'win32') args.push('-c', 'http.sslBackend=schannel');
  args.push('clone', '--depth', '1', '--single-branch', '--no-tags');
  if (ref !== null) {
    if (!isValidRef(ref)) throw new InvalidRefError();
    args.push('--branch', ref);
  }
  args.push('--', url, dest);
  return args;
}

/** System variables passed to git unchanged (ADR-002 Ek E1 table, row 1). */
export const GIT_ENV_PASSTHROUGH: readonly string[] = [
  'PATH', 'PATHEXT', 'SystemRoot', 'windir', 'SystemDrive', 'ComSpec',
  'TEMP', 'TMP', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS',
];

/** Proxy variables passed to git unchanged, both letter cases (row 2; libcurl reads them). */
export const GIT_PROXY_ENV: readonly string[] = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'NO_PROXY', 'no_proxy'];

/**
 * Allowlisted part of the parent environment for any git process: only
 * `GIT_ENV_PASSTHROUGH` and `GIT_PROXY_ENV`, original key spelling kept
 * (Windows has `Path`). On `win32` names match case-insensitively. Nothing
 * else (`GIT_*`, `SSH_ASKPASS`, `CURL_CA_BUNDLE`, `USERPROFILE`, secrets) passes.
 */
export function buildGitBaseEnv(parentEnv: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): Record<string, string> {
  const windows = platform === 'win32';
  const allowed = [...GIT_ENV_PASSTHROUGH, ...GIT_PROXY_ENV];
  const allowedSet = new Set(windows ? allowed.map((n) => n.toUpperCase()) : allowed);
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(parentEnv)) {
    if (typeof value !== 'string') continue;
    if (allowedSet.has(windows ? key.toUpperCase() : key)) env[key] = value;
  }
  return env;
}

/** Token and the repository it is sent to (header scope and Basic user name). */
export interface GitCredential {
  url: string;
  token: string;
}

/** Basic-auth user name expected by the provider for a token (ADR-002 karar 3). */
function tokenUserFor(url: string): string {
  const host = new URL(url).hostname.toLowerCase();
  if (host === 'dev.azure.com' || host.endsWith('.visualstudio.com')) return '';
  if (host.includes('gitlab')) return 'oauth2';
  return 'x-access-token';
}

/**
 * `https://<host>[:port]/` origin of the clone URL, used as the URL subsection
 * of `http.<url>.extraHeader` so git sends the token only to that host
 * (D-18, AC-P03-9). `URL.host` keeps a non-default port.
 */
function headerScopeFor(url: string): string {
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.host}/`;
}

/** Basic base64 form of the token as sent in the header. */
function basicAuthValue(credential: GitCredential): string {
  return Buffer.from(`${tokenUserFor(credential.url)}:${credential.token}`, 'utf8').toString('base64');
}

/** Every form in which the token can appear in git output: raw and Basic base64. */
export function gitTokenSecretForms(credential: GitCredential | null): string[] {
  if (!credential || !credential.token) return [];
  return [credential.token, basicAuthValue(credential)];
}

/**
 * Complete, pure environment of the clone process (ADR-002 Ek E1, AC-T-1):
 * the allowlisted parent part plus the application's values. The parent
 * environment is never copied wholesale. With a credential, exactly one
 * host-scoped `http.<https://host/>.extraHeader` travels via GIT_CONFIG_*
 * (never argv); without one `GIT_CONFIG_COUNT=0`.
 */
export function buildGitEnv(
  parentEnv: NodeJS.ProcessEnv,
  workspace: string,
  credential: GitCredential | null,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  const paths = gitIsolationPaths(workspace);
  const env: Record<string, string> = {
    ...buildGitBaseEnv(parentEnv, platform),
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: paths.gitConfig,
    HOME: paths.home,
    XDG_CONFIG_HOME: paths.xdgConfigHome,
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'never',
    GIT_ALLOW_PROTOCOL: 'https',
    GIT_LFS_SKIP_SMUDGE: '1',
    GIT_CONFIG_COUNT: '0',
  };
  if (credential && credential.token) {
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = `http.${headerScopeFor(credential.url)}.extraHeader`;
    env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${basicAuthValue(credential)}`;
  }
  return env;
}

/**
 * Creates the empty isolation entries (`gitconfig`, `home/`, `hooks/`) when
 * the workspace folder exists (the worker's `withTempWorkspace` always
 * creates it). Without them git still stays isolated: a missing
 * `GIT_CONFIG_GLOBAL` file is read as empty and never falls back to `~`.
 */
async function prepareGitIsolation(workspace: string): Promise<void> {
  let isDir = false;
  try {
    isDir = (await fs.promises.stat(workspace)).isDirectory();
  } catch {
    return;
  }
  if (!isDir) return;
  const paths = gitIsolationPaths(workspace);
  await fs.promises.mkdir(paths.home, { recursive: true });
  await fs.promises.mkdir(paths.hooks, { recursive: true });
  await fs.promises.writeFile(paths.gitConfig, '', { flag: 'w' });
}

/**
 * Tail buffer of captured stderr: once the head was cut, the first (partial)
 * line is dropped so a token cut in half never escapes `scrubSecrets`
 * (ADR-002 Ek E3).
 */
function appendStderrTail(buffer: { text: string; truncated: boolean }, chunk: string): void {
  let text = buffer.text + chunk;
  if (text.length > MAX_CAPTURED_STDERR) {
    text = text.slice(-MAX_CAPTURED_STDERR);
    buffer.truncated = true;
  }
  buffer.text = text;
}

function finalStderr(buffer: { text: string; truncated: boolean }): string {
  if (!buffer.truncated) return buffer.text;
  const newline = buffer.text.indexOf('\n');
  return newline === -1 ? '' : buffer.text.slice(newline + 1);
}

/**
 * Real shallow clone with a single `spawn('git', args, { shell: false })`.
 * The environment is built from an allowlist (`buildGitEnv`), so no user or
 * system git config, credential helper, askpass, `.netrc` or inherited
 * `GIT_*` variable reaches the clone (N-1, AC-T-1). The token travels only
 * through git's environment configuration as one host-scoped
 * `http.<https://host/>.extraHeader` (GIT_CONFIG_*), never in the URL, the
 * argument list or `.git/config`; captured stderr is sanitized (raw and base64
 * token, workspace path; ADR-002 Ek E3). LFS smudge is skipped
 * (GIT_LFS_SKIP_SMUDGE) in addition to the emptied filters in `buildGitCloneArgs`.
 */
export const cloneRepo: CloneRepoFn = async (url, ref, dest, token, signal) => {
  signal?.throwIfAborted();
  assertRemoteUrl(url);
  const workspace = path.dirname(dest);
  const paths = gitIsolationPaths(workspace);
  const args = buildGitCloneArgs(url, ref, dest, { hooksDir: paths.hooks });
  const credential: GitCredential | null = token ? { url, token } : null;
  const secrets = gitTokenSecretForms(credential);
  const env = buildGitEnv(process.env, workspace, credential);
  await prepareGitIsolation(workspace);

  // Range-checked (I-3): a negative value used to time every clone out at once, a huge one overflowed the timer.
  const timeoutMs = boundedNumber(process.env.SCAN_CLONE_TIMEOUT_MS, DEFAULT_CLONE_TIMEOUT_MS, {
    name: 'SCAN_CLONE_TIMEOUT_MS',
    min: 1,
    max: MAX_JOB_TIMEOUT_MS,
    integer: true,
  });
  const child = spawn('git', args, {
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env,
  });

  const stderrBuffer = { text: '', truncated: false };
  child.stderr?.on('data', (chunk: Buffer) => {
    appendStderrTail(stderrBuffer, chunk.toString('utf8'));
  });

  let timedOut = false;
  let killing: Promise<void> | null = null;
  const kill = () => {
    killing ??= killProcessTree(child.pid, () => child.kill('SIGKILL'));
  };
  const timer = setTimeout(() => {
    timedOut = true;
    kill();
  }, timeoutMs);
  // Job abort (time limit or shutdown): same tree kill as the clone timeout.
  const onAbort = () => kill();
  signal?.addEventListener('abort', onAbort, { once: true });

  let exitCode: number | null;
  try {
    exitCode = await new Promise<number | null>((resolve, reject) => {
      child.once('error', (err) => {
        reject(new Error(`git could not be started: ${err.message}`));
      });
      child.once('close', (code) => {
        resolve(code);
      });
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
    // The workspace is removed after this call: wait for taskkill as well so
    // no git-remote-https.exe keeps a file lock (ADR-004 implementer warning 5).
    if (killing) await killing;
  }

  if (signal?.aborted) throw signal.reason;
  if (timedOut) throw new Error(`git clone timed out after ${Math.round(timeoutMs / 1000)} s`);
  if (exitCode !== 0) {
    // Sanitize the whole captured text first, then keep its tail (git's
    // `fatal:` line is last): a cut never splits a secret or a path.
    const sanitized = sanitizeErrorText(finalStderr(stderrBuffer), {
      secrets,
      workspaceDirs: [workspace],
      maxChars: Number.POSITIVE_INFINITY,
    }).trim();
    const detail = Array.from(sanitized).slice(-MAX_ERROR_DETAIL).join('');
    throw new Error(`git clone failed (exit code ${exitCode})${detail ? `: ${detail}` : ''}`);
  }
};

/**
 * On Windows `child.kill()` leaves `git-remote-https.exe` running and its file
 * locks break cleanup, so the whole tree is killed with taskkill (no shell).
 */
function killProcessTree(pid: number | undefined, fallback: () => void): Promise<void> {
  if (process.platform !== 'win32' || pid === undefined) {
    fallback();
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    const killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { shell: false, windowsHide: true, stdio: 'ignore' });
    killer.once('error', () => {
      fallback();
      resolve();
    });
    killer.once('close', () => resolve());
  });
}

/**
 * Runs `fn` in a fresh `<tmpRoot>/ossrisk-scan-XXXX` directory and always
 * removes it afterwards (success or failure). `fn`'s error is rethrown as-is;
 * a cleanup failure is only logged and never replaces the scan result.
 */
export async function withTempWorkspace<T>(
  fn: (dir: string) => Promise<T>,
  options: { tmpRoot?: string; logger?: WorkspaceLogger } = {},
): Promise<T> {
  const root = options.tmpRoot ?? os.tmpdir();
  const dir = await fs.promises.mkdtemp(path.join(root, WORKSPACE_PREFIX));
  try {
    return await fn(dir);
  } finally {
    await removeWorkspace(dir, options.logger ?? console);
  }
}

async function removeWorkspace(dir: string, logger: WorkspaceLogger): Promise<void> {
  const rm = () => fs.promises.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  try {
    await rm();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'EPERM' && code !== 'EACCES') {
      logger.warn(`Scan workspace cleanup failed (${code ?? 'unknown'}); it will be swept on the next worker start.`);
      return;
    }
    // Git pack files are read-only on Windows: make the tree writable and retry.
    try {
      await makeWritable(dir);
      await rm();
    } catch (retryErr) {
      const retryCode = (retryErr as NodeJS.ErrnoException).code ?? 'unknown';
      logger.warn(`Scan workspace cleanup failed (${retryCode}); it will be swept on the next worker start.`);
    }
  }
}

async function makeWritable(target: string): Promise<void> {
  const stat = await fs.promises.lstat(target);
  if (stat.isSymbolicLink()) return;
  await fs.promises.chmod(target, stat.isDirectory() ? 0o777 : 0o666);
  if (stat.isDirectory()) {
    for (const entry of await fs.promises.readdir(target)) {
      await makeWritable(path.join(target, entry));
    }
  }
}

/**
 * Removes `ossrisk-scan-*` leftovers older than `maxAgeMs` (cleanup that
 * failed because of file locks or a killed worker). Best effort.
 */
export async function sweepStaleWorkspaces(
  tmpRoot: string,
  maxAgeMs: number,
  logger: WorkspaceLogger = console,
): Promise<void> {
  let entries: string[];
  try {
    entries = await fs.promises.readdir(tmpRoot);
  } catch {
    return;
  }
  const cutoff = Date.now() - maxAgeMs;
  for (const name of entries) {
    if (!name.startsWith(WORKSPACE_PREFIX)) continue;
    const full = path.join(tmpRoot, name);
    try {
      const stat = await fs.promises.lstat(full);
      if (stat.isDirectory() && stat.mtimeMs < cutoff) await removeWorkspace(full, logger);
    } catch {
      // vanished in the meantime
    }
  }
}
