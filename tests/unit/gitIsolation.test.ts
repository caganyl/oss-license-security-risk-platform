/**
 * REQ-003 · N-1 clone isolation (AC-T-1, AC-T-2; D-47; ADR-002 Ek E1) and
 * L-5 clone error tail (AC-T-4; D-48; ADR-002 Ek E3).
 *
 * Part 1 — pure builders: `buildGitCloneArgs`, `buildGitBaseEnv`,
 * `buildGitEnv`, `gitIsolationPaths`, `gitTokenSecretForms`. The parent
 * environment is copied through an allowlist only; everything else
 * (`GIT_*`, `SSH_ASKPASS`, `HOME`, `USERPROFILE`, secrets, sentinels) is
 * dropped.
 *
 * Part 2 — `cloneRepo` against a fake `spawn` (child_process is mocked; no
 * git process, no network): the spawned environment is the allowlist even
 * when `process.env` carries hostile values, the per-job isolation entries
 * are created, the token never reaches argv, and the captured stderr is
 * sanitized before its 1024-character tail is kept (a cut never splits a
 * secret or a path).
 *
 * Test values are not secrets (tests/README.md "Kurallar").
 */
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  GIT_ENV_PASSTHROUGH,
  GIT_PROXY_ENV,
  buildGitBaseEnv,
  buildGitCloneArgs,
  buildGitEnv,
  cloneRepo,
  gitIsolationPaths,
  gitTokenSecretForms,
} from '../../src/scanner/workspace';

// ---------------------------------------------------------------------------
// fake spawn
// ---------------------------------------------------------------------------
interface SpawnCall {
  command: string;
  args: string[];
  env: Record<string, string | undefined>;
  shell: unknown;
}
interface SpawnPlan {
  exitCode: number;
  stderr: string[];
}

const spawnCalls: SpawnCall[] = [];
let plan: SpawnPlan = { exitCode: 0, stderr: [] };

function fakeSpawn(command: string, args: readonly string[] = [], options: { env?: Record<string, string | undefined>; shell?: unknown } = {}) {
  spawnCalls.push({ command, args: [...args], env: { ...(options.env ?? {}) }, shell: options.shell });
  const current = plan;
  const child = Object.assign(new EventEmitter(), {
    pid: undefined,
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    kill: () => true,
  });
  setImmediate(() => {
    for (const chunk of current.stderr) child.stderr.emit('data', Buffer.from(chunk, 'utf8'));
    child.emit('close', current.exitCode);
  });
  return child;
}

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, spawn: fakeSpawn, default: { ...actual, spawn: fakeSpawn } };
});
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, spawn: fakeSpawn, default: { ...actual, spawn: fakeSpawn } };
});

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------
/** Test-only token (not a secret). */
const FAKE_TOKEN = 'fake-test-token-0123456789';
const URL_GITHUB = 'https://github.com/org/repo.git';
const WS = path.join('C:\\tmp', 'ossrisk-scan-AbC123');
const DEST = path.join(WS, 'repo');

/** Application-owned keys of the clone environment (ADR-002 Ek E1 table, row 3). */
const APP_KEYS_NO_TOKEN = [
  'GIT_CONFIG_NOSYSTEM',
  'GIT_CONFIG_GLOBAL',
  'HOME',
  'XDG_CONFIG_HOME',
  'GIT_TERMINAL_PROMPT',
  'GCM_INTERACTIVE',
  'GIT_ALLOW_PROTOCOL',
  'GIT_LFS_SKIP_SMUDGE',
  'GIT_CONFIG_COUNT',
];
const APP_KEYS_TOKEN = [...APP_KEYS_NO_TOKEN, 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0'];

const SENTINEL = 'ossr-qa-sentinel-value';

/** Allowlisted system variables, Windows spelling (`Path`, `windir`). */
const SYSTEM_VARS: Record<string, string> = {
  Path: 'C:\\Windows\\system32;C:\\Program Files\\Git\\cmd',
  PATHEXT: '.COM;.EXE;.BAT;.CMD',
  SystemRoot: 'C:\\Windows',
  windir: 'C:\\Windows',
  SystemDrive: 'C:',
  ComSpec: 'C:\\Windows\\system32\\cmd.exe',
  TEMP: 'C:\\Users\\qa-user\\AppData\\Local\\Temp',
  TMP: 'C:\\Users\\qa-user\\AppData\\Local\\Temp',
  NUMBER_OF_PROCESSORS: '8',
  PROCESSOR_ARCHITECTURE: 'AMD64',
  OS: 'Windows_NT',
};
const PROXY_VARS: Record<string, string> = {
  HTTPS_PROXY: 'http://proxy.corp.example:8080',
  https_proxy: 'http://proxy-lower.corp.example:8080',
  HTTP_PROXY: 'http://proxy.corp.example:8081',
  http_proxy: 'http://proxy-lower.corp.example:8081',
  NO_PROXY: 'localhost,127.0.0.1,.corp.example',
  no_proxy: '.lower.corp.example',
};
/** Must never reach git (ADR-002 Ek E1: `GIT_*`, askpass, CA overrides, profile, secrets). */
const HOSTILE_VARS: Record<string, string> = {
  GIT_CONFIG_GLOBAL: '/x',
  GIT_CONFIG_SYSTEM: '/x-system',
  GIT_CONFIG_NOSYSTEM: '0',
  GIT_CONFIG_PARAMETERS: `'http.proxy'='http://${SENTINEL}.invalid'`,
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_KEY_0: 'http.sslVerify',
  GIT_CONFIG_VALUE_0: 'false',
  GIT_SSL_NO_VERIFY: '1',
  GIT_DIR: '/y',
  GIT_WORK_TREE: '/y-tree',
  GIT_SSH_COMMAND: `ssh -o ProxyCommand=${SENTINEL}`,
  GIT_SSH: `C:\\${SENTINEL}\\ssh.exe`,
  GIT_ASKPASS: `C:\\${SENTINEL}\\askpass.exe`,
  SSH_ASKPASS: `C:\\${SENTINEL}\\ssh-askpass.exe`,
  GIT_TRACE: '1',
  GIT_TRACE_CURL: '1',
  GIT_CURL_VERBOSE: '1',
  GIT_EXEC_PATH: `C:\\${SENTINEL}\\libexec`,
  GIT_TEMPLATE_DIR: `C:\\${SENTINEL}\\templates`,
  GIT_TERMINAL_PROMPT: '1',
  GIT_ALLOW_PROTOCOL: 'file:ext:ssh',
  GIT_LFS_SKIP_SMUDGE: '0',
  GCM_INTERACTIVE: 'always',
  CURL_CA_BUNDLE: `C:\\${SENTINEL}\\ca.pem`,
  SSL_CERT_FILE: `C:\\${SENTINEL}\\cert.pem`,
  SSL_CERT_DIR: `C:\\${SENTINEL}\\certs`,
  HOME: 'C:\\Users\\qa-user',
  XDG_CONFIG_HOME: 'C:\\Users\\qa-user\\.config',
  USERPROFILE: 'C:\\Users\\qa-user',
  HOMEDRIVE: 'C:',
  HOMEPATH: '\\Users\\qa-user',
  APPDATA: 'C:\\Users\\qa-user\\AppData\\Roaming',
  LOCALAPPDATA: 'C:\\Users\\qa-user\\AppData\\Local',
  ENCRYPTION_KEY: 'unit-test-key-A-not-secret',
  DATABASE_URL: 'postgres://localhost:5432/ossr_qa',
  NVD_API_KEY: 'qa-not-a-real-nvd-key',
  NODE_OPTIONS: `--require ${SENTINEL}.js`,
  OSSR_QA_SENTINEL: SENTINEL,
};
const PARENT_ENV: NodeJS.ProcessEnv = { ...SYSTEM_VARS, ...PROXY_VARS, ...HOSTILE_VARS };

const sorted = (keys: Iterable<string>) => [...keys].sort();

/** `-c key=value` pairs before the `clone` subcommand. */
function configPairs(args: string[]): string[] {
  const cloneAt = args.indexOf('clone');
  const head = cloneAt === -1 ? args : args.slice(0, cloneAt);
  return head.flatMap((a, i) => (a === '-c' ? [head[i + 1]] : []));
}

// ---------------------------------------------------------------------------
describe('AC-T-1: git arguments (buildGitCloneArgs, pure)', () => {
  it('AC-T-1: core.hooksPath=<workspace>/hooks, core.askPass= and credential.helper= come as -c before "clone"; --depth 1 --single-branch --no-tags -- <url> <dest>', () => {
    const args = buildGitCloneArgs(URL_GITHUB, 'main', DEST, { platform: 'linux' });
    const cloneAt = args.indexOf('clone');
    expect(cloneAt).toBeGreaterThan(0);
    const pairs = configPairs(args);
    expect(pairs).toContain(`core.hooksPath=${gitIsolationPaths(WS).hooks}`);
    expect(pairs).toContain('core.askPass=');
    expect(pairs).toContain('credential.helper=');
    // every -c value precedes the subcommand
    args.forEach((a, i) => {
      if (a === '-c') expect(i).toBeLessThan(cloneAt);
    });
    expect(args.slice(cloneAt)).toEqual(['clone', '--depth', '1', '--single-branch', '--no-tags', '--branch', 'main', '--', URL_GITHUB, DEST]);
  });

  it('AC-T-1: an explicit hooksDir wins over the default <dirname(dest)>/hooks', () => {
    const hooks = path.join('C:\\elsewhere', 'empty-hooks');
    expect(configPairs(buildGitCloneArgs(URL_GITHUB, null, DEST, { hooksDir: hooks, platform: 'linux' }))).toContain(`core.hooksPath=${hooks}`);
  });

  it('AC-T-1: http.sslBackend=schannel only for win32', () => {
    expect(configPairs(buildGitCloneArgs(URL_GITHUB, null, DEST, { platform: 'win32' }))).toContain('http.sslBackend=schannel');
    for (const platform of ['linux', 'darwin'] as const) {
      const pairs = configPairs(buildGitCloneArgs(URL_GITHUB, null, DEST, { platform }));
      expect(pairs.some((p) => p.toLowerCase().startsWith('http.sslbackend=')), platform).toBe(false);
    }
  });

  it('AC-T-2 / D-18: REQ-002 hardening kept (symlinks off, long paths, LFS filters emptied, filter optional, redirects not followed); no protocol.* setting (GIT_ALLOW_PROTOCOL rules)', () => {
    for (const platform of ['win32', 'linux'] as const) {
      const pairs = configPairs(buildGitCloneArgs(URL_GITHUB, null, DEST, { platform }));
      expect(pairs).toEqual(
        expect.arrayContaining([
          'core.symlinks=false',
          'core.longpaths=true',
          'filter.lfs.smudge=',
          'filter.lfs.clean=',
          'filter.lfs.process=',
          'filter.lfs.required=false',
          'http.followRedirects=false',
        ]),
      );
      expect(pairs.filter((p) => p.toLowerCase().startsWith('protocol.'))).toEqual([]);
      expect(pairs.filter((p) => p.toLowerCase().includes('extraheader'))).toEqual([]);
    }
  });
});

describe('AC-T-1: git environment is built from an allowlist (buildGitBaseEnv / buildGitEnv, pure)', () => {
  it('AC-T-1 (win32): only the system allowlist, both proxy spellings and the application values; GIT_CONFIG_GLOBAL, GIT_SSL_NO_VERIFY, GIT_DIR, SSH_ASKPASS, ENCRYPTION_KEY and every other parent value are dropped', () => {
    const env = buildGitEnv(PARENT_ENV, WS, null, 'win32');
    expect(sorted(Object.keys(env))).toEqual(sorted([...Object.keys(SYSTEM_VARS), ...Object.keys(PROXY_VARS), ...APP_KEYS_NO_TOKEN]));
    for (const [k, v] of Object.entries({ ...SYSTEM_VARS, ...PROXY_VARS })) expect(env[k], k).toBe(v);
    const values = Object.values(env).join('\n');
    expect(values).not.toContain(SENTINEL);
    expect(values).not.toContain(HOSTILE_VARS.ENCRYPTION_KEY);
    expect(values).not.toContain(HOSTILE_VARS.NVD_API_KEY);
    expect(values).not.toContain('C:\\Users\\qa-user\\AppData\\Roaming');
  });

  it('AC-T-1: application values (ADR-002 Ek E1 table, row 3) override any parent value', () => {
    const paths = gitIsolationPaths(WS);
    for (const platform of ['win32', 'linux'] as const) {
      const env = buildGitEnv(PARENT_ENV, WS, null, platform);
      expect(env, platform).toMatchObject({
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: paths.gitConfig,
        HOME: paths.home,
        XDG_CONFIG_HOME: paths.xdgConfigHome,
        GIT_TERMINAL_PROMPT: '0',
        GCM_INTERACTIVE: 'never',
        GIT_ALLOW_PROTOCOL: 'https',
        GIT_LFS_SKIP_SMUDGE: '1',
        GIT_CONFIG_COUNT: '0',
      });
      expect(env.GIT_CONFIG_KEY_0, platform).toBeUndefined();
      expect(env.GIT_CONFIG_VALUE_0, platform).toBeUndefined();
    }
  });

  it('AC-T-1: isolation paths live inside the job workspace (gitconfig file, home/, home/.config, hooks/)', () => {
    expect(gitIsolationPaths(WS)).toEqual({
      gitConfig: path.join(WS, 'gitconfig'),
      home: path.join(WS, 'home'),
      xdgConfigHome: path.join(WS, 'home', '.config'),
      hooks: path.join(WS, 'hooks'),
    });
  });

  it('AC-T-1 (win32): names match case-insensitively and keep their original spelling (Path, windir, Https_Proxy)', () => {
    const parent = { path: 'p', PathExt: '.EXE', SYSTEMROOT: 'C:\\Windows', WinDir: 'C:\\Windows', Https_Proxy: 'http://p:1', No_Proxy: 'x', git_dir: '/y', Home: 'C:\\h', userprofile: 'C:\\h' };
    expect(buildGitBaseEnv(parent, 'win32')).toEqual({ path: 'p', PathExt: '.EXE', SYSTEMROOT: 'C:\\Windows', WinDir: 'C:\\Windows', Https_Proxy: 'http://p:1', No_Proxy: 'x' });
  });

  it('AC-T-1 (linux/darwin): names match exactly; PATH passes, a mixed-case Path does not; both proxy spellings pass; no schannel', () => {
    const parent = { PATH: '/usr/bin', Path: 'ignored', HOME: '/home/qa', ...PROXY_VARS, GIT_DIR: '/y', SSH_ASKPASS: '/x', OSSR_QA_SENTINEL: SENTINEL };
    for (const platform of ['linux', 'darwin'] as const) {
      expect(buildGitBaseEnv(parent, platform), platform).toEqual({ PATH: '/usr/bin', ...PROXY_VARS });
    }
  });

  it('AC-T-1: the allowlist constants are exactly the ADR-002 Ek E1 rows 1 and 2', () => {
    expect(sorted(GIT_ENV_PASSTHROUGH)).toEqual(
      sorted(['PATH', 'PATHEXT', 'SystemRoot', 'windir', 'SystemDrive', 'ComSpec', 'TEMP', 'TMP', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS']),
    );
    expect(sorted(GIT_PROXY_ENV)).toEqual(sorted(['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'NO_PROXY', 'no_proxy']));
  });

  it('AC-T-1: non-string parent values are skipped', () => {
    const parent = { PATH: undefined, OS: 'Windows_NT' } as unknown as NodeJS.ProcessEnv;
    expect(buildGitBaseEnv(parent, 'win32')).toEqual({ OS: 'Windows_NT' });
  });
});

describe('AC-T-1 / AC-T-2 / AC-P03-9: the token travels only as one host-scoped extraHeader in the environment', () => {
  it.each([
    ['github.com', URL_GITHUB, 'http.https://github.com/.extraHeader', 'x-access-token'],
    ['gitlab host', 'https://gitlab.example.com/group/repo.git', 'http.https://gitlab.example.com/.extraHeader', 'oauth2'],
    ['Azure DevOps', 'https://dev.azure.com/org/project/_git/repo', 'http.https://dev.azure.com/.extraHeader', ''],
    ['non-default port', 'https://git.example.com:8443/team/repo.git', 'http.https://git.example.com:8443/.extraHeader', 'x-access-token'],
  ])('AC-T-1: %s -> GIT_CONFIG_COUNT=1, KEY_0 = %s, Basic user "%s"', (_label, url, key, user) => {
    const env = buildGitEnv(PARENT_ENV, WS, { url, token: FAKE_TOKEN }, 'win32');
    expect(sorted(Object.keys(env))).toEqual(sorted([...Object.keys(SYSTEM_VARS), ...Object.keys(PROXY_VARS), ...APP_KEYS_TOKEN]));
    expect(env.GIT_CONFIG_COUNT).toBe('1');
    expect(env.GIT_CONFIG_KEY_0).toBe(key);
    const value = env.GIT_CONFIG_VALUE_0;
    expect(value).toMatch(/^Authorization: Basic [A-Za-z0-9+/]+=*$/);
    const basic = value.replace(/^Authorization: Basic /, '');
    expect(Buffer.from(basic, 'base64').toString('utf8')).toBe(`${user}:${FAKE_TOKEN}`);
    // raw token in no environment value; base64 only in GIT_CONFIG_VALUE_0
    expect(Object.values(env).join('\n')).not.toContain(FAKE_TOKEN);
    expect(Object.entries(env).filter(([, v]) => v.includes(basic)).map(([k]) => k)).toEqual(['GIT_CONFIG_VALUE_0']);
    // and never in argv
    const args = buildGitCloneArgs(url, 'main', DEST, { platform: 'win32' }).join('\n');
    expect(args).not.toContain(FAKE_TOKEN);
    expect(args).not.toContain(basic);
  });

  it('AC-T-1: an empty token behaves like no token (GIT_CONFIG_COUNT=0)', () => {
    expect(buildGitEnv({}, WS, { url: URL_GITHUB, token: '' }, 'linux').GIT_CONFIG_COUNT).toBe('0');
  });

  it('L-5: gitTokenSecretForms = [raw token, Basic base64 of user:token]; none for no/empty token', () => {
    const forms = gitTokenSecretForms({ url: URL_GITHUB, token: FAKE_TOKEN });
    expect(forms).toEqual([FAKE_TOKEN, Buffer.from(`x-access-token:${FAKE_TOKEN}`, 'utf8').toString('base64')]);
    expect(buildGitEnv({}, WS, { url: URL_GITHUB, token: FAKE_TOKEN }, 'linux').GIT_CONFIG_VALUE_0).toBe(`Authorization: Basic ${forms[1]}`);
    expect(gitTokenSecretForms(null)).toEqual([]);
    expect(gitTokenSecretForms({ url: URL_GITHUB, token: '' })).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// cloneRepo with a fake spawn
// ---------------------------------------------------------------------------
const PROCESS_ENV_OVERRIDES: Record<string, string> = {
  GIT_DIR: '/y',
  GIT_CONFIG_GLOBAL: '/x',
  GIT_CONFIG_PARAMETERS: `'http.proxy'='http://${SENTINEL}.invalid'`,
  GIT_SSL_NO_VERIFY: '1',
  GIT_SSH_COMMAND: `ssh -o ProxyCommand=${SENTINEL}`,
  SSH_ASKPASS: `${SENTINEL}-askpass`,
  GIT_ASKPASS: `${SENTINEL}-askpass`,
  CURL_CA_BUNDLE: `${SENTINEL}.pem`,
  HOME: path.join(os.tmpdir(), `${SENTINEL}-home`),
  XDG_CONFIG_HOME: path.join(os.tmpdir(), `${SENTINEL}-xdg`),
  OSSR_QA_SENTINEL: SENTINEL,
};
const savedProcessEnv: Record<string, string | undefined> = {};
let workspace = '';

beforeEach(() => {
  spawnCalls.length = 0;
  plan = { exitCode: 0, stderr: [] };
  for (const [k, v] of Object.entries(PROCESS_ENV_OVERRIDES)) {
    savedProcessEnv[k] = process.env[k];
    process.env[k] = v;
  }
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'ossrisk-scan-'));
});
afterEach(() => {
  for (const [k, v] of Object.entries(savedProcessEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(workspace, { recursive: true, force: true });
});

async function cloneFailure(stderr: string[], token: string | null = FAKE_TOKEN): Promise<string> {
  plan = { exitCode: 128, stderr };
  const err = await cloneRepo(URL_GITHUB, 'main', path.join(workspace, 'repo'), token).then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(Error);
  return (err as Error).message;
}

const CONTROL_EXCEPT_NL_TAB = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/; // eslint-disable-line no-control-regex

describe('AC-T-1: cloneRepo spawns git with the allowlisted environment only', () => {
  it('AC-T-1: hostile process.env values (GIT_DIR, GIT_CONFIG_GLOBAL, GIT_CONFIG_PARAMETERS, SSH_ASKPASS, HOME, ...) never reach the git process; shell is off; isolation entries exist', async () => {
    const dest = path.join(workspace, 'repo');
    await cloneRepo(URL_GITHUB, 'main', dest, FAKE_TOKEN);
    const gitCalls = spawnCalls.filter((c) => /(^|[\\/])git(\.exe)?$/i.test(c.command));
    expect(gitCalls).toHaveLength(1);
    const call = gitCalls[0];
    expect(call.shell).toBe(false);

    const paths = gitIsolationPaths(workspace);
    const expected = buildGitEnv(process.env, workspace, { url: URL_GITHUB, token: FAKE_TOKEN });
    expect(call.env).toEqual(expected);
    expect(call.env).toMatchObject({ GIT_CONFIG_GLOBAL: paths.gitConfig, HOME: paths.home, XDG_CONFIG_HOME: paths.xdgConfigHome, GIT_CONFIG_NOSYSTEM: '1' });
    const keysUpper = Object.keys(call.env).map((k) => k.toUpperCase());
    for (const k of ['GIT_DIR', 'GIT_CONFIG_PARAMETERS', 'GIT_SSL_NO_VERIFY', 'GIT_SSH_COMMAND', 'SSH_ASKPASS', 'GIT_ASKPASS', 'CURL_CA_BUNDLE', 'OSSR_QA_SENTINEL', 'USERPROFILE', 'APPDATA', 'ENCRYPTION_KEY', 'DATABASE_URL']) {
      expect(keysUpper, k).not.toContain(k);
    }
    expect(Object.values(call.env).join('\n')).not.toContain(SENTINEL);

    // argv: isolation -c values, no token in any form
    expect(configPairs(call.args)).toContain(`core.hooksPath=${paths.hooks}`);
    expect(configPairs(call.args)).toContain('core.askPass=');
    const joined = call.args.join('\n');
    for (const form of gitTokenSecretForms({ url: URL_GITHUB, token: FAKE_TOKEN })) expect(joined).not.toContain(form);

    // the empty per-job entries were created (ADR-002 Ek E1 workspace layout)
    expect(fs.statSync(paths.gitConfig).isFile()).toBe(true);
    expect(fs.statSync(paths.gitConfig).size).toBe(0);
    expect(fs.statSync(paths.home).isDirectory()).toBe(true);
    expect(fs.readdirSync(paths.home)).toEqual([]);
    expect(fs.statSync(paths.hooks).isDirectory()).toBe(true);
    expect(fs.readdirSync(paths.hooks)).toEqual([]);
  });
});

describe('AC-T-4 / L-5: the clone error tail is sanitized before it is cut (1024 characters)', () => {
  it('AC-T-4: token (raw + Basic base64), workspace (both separators, other case), profile path, ANSI, NUL, BEL and 3000 characters -> none survive; detail ≤ 1024 code points', async () => {
    const dest = path.join(workspace, 'repo');
    const basic = Buffer.from(`x-access-token:${FAKE_TOKEN}`, 'utf8').toString('base64');
    const wsOther = process.platform === 'win32' ? workspace.replace(/\\/g, '/').toUpperCase() : workspace;
    const profile = path.join(os.homedir(), 'Desktop', 'notes.txt');
    const message = await cloneFailure([
      `${'x'.repeat(3000)}\n`,
      `Cloning into '${dest}'...\n`,
      `\x1b[31mfatal:\x1b[0m unable to access 'https://x-access-token:${FAKE_TOKEN}@github.com/org/repo.git/'\x07\n`,
      `trace: Authorization: Basic ${basic}\x00\n`,
      `warning: hooks at ${wsOther}/hooks ignored\n`,
      `hint: see ${profile}\r\n`,
      `fatal: repository '${dest}' not found\n`,
    ]);

    expect(message.startsWith('git clone failed (exit code 128): ')).toBe(true);
    const detail = message.slice('git clone failed (exit code 128): '.length);
    expect(Array.from(detail).length).toBeLessThanOrEqual(1024);
    expect(message).not.toContain(FAKE_TOKEN);
    expect(message).not.toContain(basic);
    const lower = message.toLowerCase();
    for (const p of [workspace, workspace.replace(/\\/g, '/'), os.homedir(), os.homedir().replace(/\\/g, '/')]) {
      expect(lower).not.toContain(p.toLowerCase());
    }
    expect(message).toContain('<workspace>');
    expect(message).toContain('[REDACTED]');
    expect(message).toMatch(/fatal: repository '<workspace>[\\/]repo' not found$/);
    expect(message).not.toMatch(CONTROL_EXCEPT_NL_TAB);
    expect(message).not.toContain('\r');
  });

  it('AC-T-4: a token that the raw 1024-character cut would split leaves no fragment', async () => {
    // Raw tail(1024) = last 6 token characters + 1018 filler: only a "sanitize first" order hides them.
    const message = await cloneFailure([`fatal: auth ${FAKE_TOKEN}${'y'.repeat(1018)}`]);
    expect(message).not.toContain(FAKE_TOKEN.slice(-6));
    expect(message).not.toContain('456789');
  });

  it('AC-T-4: a workspace path that the raw cut would split leaves no fragment of the folder name', async () => {
    const name = path.basename(workspace); // ossrisk-scan-XXXXXX
    const message = await cloneFailure([`fatal: could not create ${path.join(workspace, 'repo')}${'z'.repeat(1020)}`]);
    expect(message).not.toContain(name.slice(-6));
    expect(message).not.toContain('ossrisk-scan-');
  });

  it('AC-T-4: a successful clone throws nothing even with noisy stderr', async () => {
    plan = { exitCode: 0, stderr: [`Cloning into '${workspace}'...\n`] };
    await expect(cloneRepo(URL_GITHUB, null, path.join(workspace, 'repo'), null)).resolves.toBeUndefined();
  });
});
