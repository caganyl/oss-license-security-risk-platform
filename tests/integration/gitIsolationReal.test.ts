/**
 * REQ-003 · N-1 real isolation evidence (AC-T-1; D-47; ADR-002 Ek E1), no
 * network: a temporary "hostile" user configuration (global `.gitconfig`
 * with `http.proxy` and `url.<x>.insteadOf`, an XDG config, a file named by
 * the parent `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`)
 * is shown to be effective for a plain git process (negative control) and
 * invisible to a git process started with `buildGitEnv` (+ the `-c` values
 * of `buildGitCloneArgs`). Only `git config` runs; nothing is cloned.
 *
 * Needs git >= 2.32 (`GIT_CONFIG_GLOBAL`); skipped otherwise (AC-G-2).
 */
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseGitVersion } from '../../src/scanner/gitVersion';
import { buildGitBaseEnv, buildGitCloneArgs, buildGitEnv, gitIsolationPaths } from '../../src/scanner/workspace';

function hostGitSupported(): boolean {
  try {
    return parseGitVersion(execFileSync('git', ['--version'], { encoding: 'utf8', windowsHide: true })).supported;
  } catch {
    return false;
  }
}
const GIT_OK = hostGitSupported();

const BAD_PROXY = 'http://ossr-qa-bad-proxy.invalid:1';
const BAD_INSTEAD_OF = 'https://ossr-qa-evil.invalid/';
const BAD_XDG = 'ossr-qa-xdg-sentinel';
const BAD_PARENT_GLOBAL = 'ossr-qa-parent-global-sentinel';
const BAD_PARAMETERS = 'ossr-qa-parameters-sentinel';
const BAD_COUNT = 'ossr-qa-count-sentinel';
const ALL_BAD = [BAD_PROXY, BAD_INSTEAD_OF, 'ossr-qa-evil', BAD_XDG, BAD_PARENT_GLOBAL, BAD_PARAMETERS, BAD_COUNT];
/** Test-only token (not a secret). */
const FAKE_TOKEN = 'fake-test-token-0123456789';

let base = '';
let fakeHome = '';
let workspace = '';
let parentEnv: NodeJS.ProcessEnv = {};

function git(args: string[], env: Record<string, string>, cwd: string) {
  const r = spawnSync('git', args, { cwd, env, encoding: 'utf8', windowsHide: true, shell: false });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

beforeAll(() => {
  if (!GIT_OK) return;
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-gitiso-'));
  fakeHome = path.join(base, 'fake-home');
  fs.mkdirSync(path.join(fakeHome, '.config', 'git'), { recursive: true });
  fs.writeFileSync(
    path.join(fakeHome, '.gitconfig'),
    `[http]\n\tproxy = ${BAD_PROXY}\n\tsslVerify = false\n[url "${BAD_INSTEAD_OF}"]\n\tinsteadOf = https://github.com/\n[credential]\n\thelper = store\n[core]\n\taskPass = C:/ossr-qa/askpass.exe\n`,
  );
  fs.writeFileSync(path.join(fakeHome, '.config', 'git', 'config'), `[ossrqa]\n\txdg = ${BAD_XDG}\n`);
  const parentGlobal = path.join(base, 'parent-global.gitconfig');
  fs.writeFileSync(parentGlobal, `[ossrqa]\n\tparentglobal = ${BAD_PARENT_GLOBAL}\n`);

  workspace = path.join(base, 'ossrisk-scan-QA0001');
  const iso = gitIsolationPaths(workspace);
  fs.mkdirSync(iso.home, { recursive: true });
  fs.mkdirSync(iso.hooks, { recursive: true });
  fs.writeFileSync(iso.gitConfig, '');

  parentEnv = {
    ...process.env,
    HOME: fakeHome,
    USERPROFILE: fakeHome,
    XDG_CONFIG_HOME: path.join(fakeHome, '.config'),
    GIT_CONFIG_GLOBAL: parentGlobal,
    GIT_CONFIG_PARAMETERS: `'ossrqa.parameters'='${BAD_PARAMETERS}'`,
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'ossrqa.count',
    GIT_CONFIG_VALUE_0: BAD_COUNT,
    GIT_DIR: path.join(base, 'no-such-git-dir'),
  };
});
afterAll(() => {
  if (base) fs.rmSync(base, { recursive: true, force: true });
});

describe.skipIf(!GIT_OK)('AC-T-1: real git does not see the user/system configuration through buildGitEnv (no network)', () => {
  it('negative control: the hostile HOME/.gitconfig is effective for a git process with a plain HOME', () => {
    const env = { ...buildGitBaseEnv(process.env), HOME: fakeHome, GIT_CONFIG_NOSYSTEM: '1' };
    const r = git(['config', '--get', 'http.proxy'], env, base);
    expect(r.stdout.trim()).toBe(BAD_PROXY);
    expect(git(['config', '--get', 'ossrqa.xdg'], { ...env, XDG_CONFIG_HOME: path.join(fakeHome, '.config') }, base).stdout.trim()).toBe(BAD_XDG);
  });

  it('negative control: the parent GIT_CONFIG_* / GIT_CONFIG_PARAMETERS values are effective when passed through', () => {
    const env = { ...buildGitBaseEnv(process.env), GIT_CONFIG_NOSYSTEM: '1', ...pick(parentEnv, ['HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0']) };
    const list = git(['config', '--list'], env, base).stdout;
    expect(list).toContain(BAD_PARENT_GLOBAL);
    expect(list).toContain(BAD_PARAMETERS);
    expect(list).toContain(BAD_COUNT);
  });

  it('AC-T-1: with buildGitEnv no hostile value is visible (http.proxy, insteadOf, sslVerify, credential.helper, XDG, parent GIT_CONFIG_*); only the workspace gitconfig is a config origin', () => {
    const env = buildGitEnv(parentEnv, workspace, null);
    const list = git(['config', '--list', '--show-origin'], env, workspace);
    expect(list.status === 0 || list.status === 1, list.stderr).toBe(true);
    for (const bad of ALL_BAD) expect(list.stdout, bad).not.toContain(bad);
    expect(list.stdout.toLowerCase()).not.toContain(fakeHome.replace(/\\/g, '/').toLowerCase());
    expect(git(['config', '--get', 'http.proxy'], env, workspace).status).toBe(1);
    expect(git(['config', '--get', 'credential.helper'], env, workspace).status).toBe(1);
    expect(git(['config', '--get-urlmatch', 'url.insteadof', 'https://github.com/org/repo.git'], env, workspace).stdout).not.toContain('evil');
    // the global scope is the empty per-job file
    const globalOrigin = git(['config', '--global', '--list', '--show-origin'], env, workspace);
    expect(globalOrigin.stdout.trim()).toBe('');
    expect(git(['config', '--global', '--show-origin', '--get', 'http.proxy'], env, workspace).status).toBe(1);
  });

  it('AC-T-1: the -c values of buildGitCloneArgs are accepted by git and are the only command-line entries', () => {
    const env = buildGitEnv(parentEnv, workspace, null);
    const args = buildGitCloneArgs('https://github.com/org/repo.git', null, path.join(workspace, 'repo'));
    const head = args.slice(0, args.indexOf('clone'));
    const r = git([...head, 'config', '--list', '--show-origin'], env, workspace);
    expect(r.status, r.stderr).toBe(0);
    const lines = r.stdout.split(/\r?\n/).filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) expect(line.startsWith('command line:'), line).toBe(true);
    const keys = lines.map((l) => l.replace(/^command line:\s*/, ''));
    expect(keys).toEqual(expect.arrayContaining(['credential.helper=', 'core.askpass=', `core.hookspath=${gitIsolationPaths(workspace).hooks}`, 'http.followredirects=false']));
    if (process.platform === 'win32') expect(keys).toContain('http.sslbackend=schannel');
    for (const bad of ALL_BAD) expect(r.stdout).not.toContain(bad);
  });

  it('AC-T-1 / AC-P03-9: with a token git resolves exactly one extraHeader for the target host and none for another host', () => {
    const env = buildGitEnv(parentEnv, workspace, { url: 'https://github.com/org/repo.git', token: FAKE_TOKEN });
    const same = git(['config', '--get-urlmatch', 'http.extraheader', 'https://github.com/other/repo.git'], env, workspace);
    expect(same.status).toBe(0);
    expect(same.stdout.trim()).toMatch(/^Authorization: Basic [A-Za-z0-9+/]+=*$/);
    const other = git(['config', '--get-urlmatch', 'http.extraheader', 'https://gitlab.example.com/org/repo.git'], env, workspace);
    expect(other.status).toBe(1);
    expect(other.stdout.trim()).toBe('');
  });
});

function pick(env: NodeJS.ProcessEnv, keys: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of keys) if (typeof env[k] === 'string') out[k] = env[k] as string;
  return out;
}
