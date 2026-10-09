import { spawn } from 'child_process';
import { buildGitBaseEnv } from './workspace';

/**
 * Git version check (REQ-003 AC-T-3, AC-P12-6; ADR-002 Ek E2, D-46).
 *
 * `git --version` runs once per process (no shell, allowlisted environment,
 * 10 s) and the result is cached. Git missing or older than 2.32 never stops
 * the start-up and never affects local folder scans; a remote (`https`) scan
 * then fails permanently with `GitUnavailableError` before any temp folder is
 * created. 2.32 is the first git that honours `GIT_CONFIG_GLOBAL`; older git
 * silently ignores it and the user's global config would reach the clone.
 */

export const MIN_GIT_MAJOR = 2;
export const MIN_GIT_MINOR = 32;
export const GIT_VERSION_TIMEOUT_MS = 10_000;

export interface GitVersionInfo {
  /** `git --version` ran and printed a parsable version. */
  found: boolean;
  /** Full version text after `git version ` (e.g. `2.47.1.windows.1`), or null. */
  version: string | null;
  major: number | null;
  minor: number | null;
  /** found && version >= 2.32. */
  supported: boolean;
}

/** Injected into the scan worker and the runtime (tests pass a fake). */
export type GitVersionProvider = () => Promise<GitVersionInfo>;

const NOT_FOUND: GitVersionInfo = Object.freeze({ found: false, version: null, major: null, minor: null, supported: false });

/** Parses `git --version` output (`^git version (\d+)\.(\d+)`); null/unparsable -> not found. */
export function parseGitVersion(output: string | null | undefined): GitVersionInfo {
  if (!output) return { ...NOT_FOUND };
  const match = /^git version ((\d+)\.(\d+)\S*)/.exec(output.trim());
  if (!match) return { ...NOT_FOUND };
  const major = Number(match[2]);
  const minor = Number(match[3]);
  const supported = major > MIN_GIT_MAJOR || (major === MIN_GIT_MAJOR && minor >= MIN_GIT_MINOR);
  return { found: true, version: match[1], major, minor, supported };
}

export interface ProbeGitOptions {
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  platform?: NodeJS.Platform;
}

/** Runs `git --version` once (never throws; missing git -> not found). */
export function probeGitVersion(options: ProbeGitOptions = {}): Promise<GitVersionInfo> {
  const timeoutMs = options.timeoutMs ?? GIT_VERSION_TIMEOUT_MS;
  const env = {
    ...buildGitBaseEnv(options.env ?? process.env, options.platform ?? process.platform),
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
  };
  return new Promise<GitVersionInfo>((resolve) => {
    let out = '';
    let settled = false;
    const finish = (value: GitVersionInfo) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn('git', ['--version'], { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], env });
    } catch {
      finish({ ...NOT_FOUND });
      return;
    }
    const timer = setTimeout(() => {
      child.kill();
      finish({ ...NOT_FOUND });
    }, timeoutMs);
    child.stdout?.on('data', (chunk: Buffer) => {
      if (out.length < 4096) out += chunk.toString('utf8');
    });
    child.once('error', () => {
      clearTimeout(timer);
      finish({ ...NOT_FOUND });
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      finish(code === 0 ? parseGitVersion(out) : { ...NOT_FOUND });
    });
  });
}

let cached: Promise<GitVersionInfo> | null = null;

/**
 * Process-wide cached `git --version` (default provider of the runtime and
 * the scan worker). Git installed later needs an application restart.
 */
export const getGitVersion: GitVersionProvider = () => {
  cached ??= probeGitVersion();
  return cached;
};

/** Clears the cache (tests). */
export function resetGitVersionCache(): void {
  cached = null;
}

/** `Uzak tarama için git 2.32 veya üstü gerekli (bulunan: <sürüm|yok>).` (ADR-002 Ek E2). */
export function gitRequirementMessage(info: GitVersionInfo): string {
  return `Uzak tarama için git ${MIN_GIT_MAJOR}.${MIN_GIT_MINOR} veya üstü gerekli (bulunan: ${info.found && info.version ? info.version : 'yok'}).`;
}

/** Remote scan without a usable git: permanent, no retry (AC-P13-4, AC-T-3). */
export class GitUnavailableError extends Error {
  readonly permanent = true;
  constructor(readonly info: GitVersionInfo) {
    super(gitRequirementMessage(info));
    this.name = 'GitUnavailableError';
  }
}

/** Throws `GitUnavailableError` unless the provider reports git >= 2.32. */
export async function assertGitForRemoteScan(provider: GitVersionProvider): Promise<void> {
  let info: GitVersionInfo;
  try {
    info = await provider();
  } catch {
    info = { ...NOT_FOUND };
  }
  if (!info.supported) throw new GitUnavailableError(info);
}

/** Start-up log line of step 5 (AC-P12-6); a warning when git is missing/too old. */
export function describeGitVersion(info: GitVersionInfo): { level: 'log' | 'warn'; message: string } {
  if (!info.found) {
    return {
      level: 'warn',
      message: `git bulunamadı; uzak (https) taramalar çalışmayacak, yerel klasör taramaları etkilenmez. Git for Windows ${MIN_GIT_MAJOR}.${MIN_GIT_MINOR} veya üstünü kurup uygulamayı yeniden başlatın.`,
    };
  }
  if (!info.supported) {
    return {
      level: 'warn',
      message: `git ${info.version} eski; uzak (https) taramalar için ${MIN_GIT_MAJOR}.${MIN_GIT_MINOR} veya üstü gerekli (yerel klasör taramaları etkilenmez).`,
    };
  }
  return { level: 'log', message: `git ${info.version} bulundu.` };
}
