import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { assertRemoteUrl } from '../lib/scanSource';

/**
 * Scan workspace for remote repositories (REQ-002 P-03, ADR-002 karar 3): a
 * job-specific `ossrisk-scan-*` temp directory, a shallow `git clone` without
 * a shell, and cleanup on success and on failure.
 */

export type CloneRepoFn = (url: string, ref: string | null, dest: string, token: string | null) => Promise<void>;

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

/**
 * Pure argument array for `git clone`; the token never appears here. `--`
 * ends option parsing before the URL and destination.
 */
export function buildGitCloneArgs(url: string, ref: string | null, dest: string): string[] {
  const args = [
    '-c', 'core.symlinks=false',
    '-c', 'core.longpaths=true',
    '-c', 'credential.helper=',
    'clone', '--depth', '1', '--single-branch', '--no-tags',
  ];
  if (ref !== null) {
    if (!isValidRef(ref)) throw new InvalidRefError();
    args.push('--branch', ref);
  }
  args.push('--', url, dest);
  return args;
}

const SECRET_ENV_RE = /SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|ENCRYPTION_KEY|API_KEY|DATABASE_URL|PGPASS/i;

/**
 * Environment for child processes that handle untrusted repository content
 * (git, dependency parser): the parent environment minus database/encryption
 * secrets, which those processes never need.
 */
export function sanitizedChildEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !SECRET_ENV_RE.test(key)) env[key] = value;
  }
  return { ...env, ...extra };
}

/** Replaces every occurrence of the given secret forms with `[REDACTED]`. */
export function scrubSecrets(text: string, secrets: readonly string[]): string {
  let scrubbed = text;
  for (const secret of secrets) {
    if (secret) scrubbed = scrubbed.split(secret).join('[REDACTED]');
  }
  return scrubbed;
}

/** Basic-auth user name expected by the provider for a token (ADR-002 karar 3). */
function tokenUserFor(url: string): string {
  const host = new URL(url).hostname.toLowerCase();
  if (host === 'dev.azure.com' || host.endsWith('.visualstudio.com')) return '';
  if (host.includes('gitlab')) return 'oauth2';
  return 'x-access-token';
}

/**
 * Real shallow clone with `spawn('git', args, { shell: false })`. The token
 * travels only through git's environment configuration (`http.extraHeader`),
 * never in the URL, the argument list or `.git/config`; captured stderr is
 * scrubbed of both the raw and the base64 form.
 */
export const cloneRepo: CloneRepoFn = async (url, ref, dest, token) => {
  assertRemoteUrl(url);
  const args = buildGitCloneArgs(url, ref, dest);

  const gitEnv: Record<string, string> = {
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'never',
    GIT_ALLOW_PROTOCOL: 'https',
  };
  const secrets: string[] = [];
  if (token) {
    const basic = Buffer.from(`${tokenUserFor(url)}:${token}`, 'utf8').toString('base64');
    gitEnv.GIT_CONFIG_COUNT = '1';
    gitEnv.GIT_CONFIG_KEY_0 = 'http.extraHeader';
    gitEnv.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${basic}`;
    secrets.push(token, basic);
  }

  const timeoutMs = Number(process.env.SCAN_CLONE_TIMEOUT_MS) || DEFAULT_CLONE_TIMEOUT_MS;
  const child = spawn('git', args, {
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env: sanitizedChildEnv(gitEnv),
  });

  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => {
    stderr = (stderr + chunk.toString('utf8')).slice(-MAX_CAPTURED_STDERR);
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    killProcessTree(child.pid, () => child.kill('SIGKILL'));
  }, timeoutMs);

  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.once('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`git could not be started: ${err.message}`));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });

  if (timedOut) throw new Error(`git clone timed out after ${Math.round(timeoutMs / 1000)} s`);
  if (exitCode !== 0) {
    const detail = scrubSecrets(stderr, secrets).trim().slice(-MAX_ERROR_DETAIL);
    throw new Error(`git clone failed (exit code ${exitCode})${detail ? `: ${detail}` : ''}`);
  }
};

/**
 * On Windows `child.kill()` leaves `git-remote-https.exe` running and its file
 * locks break cleanup, so the whole tree is killed with taskkill (no shell).
 */
function killProcessTree(pid: number | undefined, fallback: () => void): void {
  if (process.platform !== 'win32' || pid === undefined) {
    fallback();
    return;
  }
  const killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { shell: false, windowsHide: true, stdio: 'ignore' });
  killer.once('error', fallback);
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
