/**
 * REQ-002 · P-03 (AC-P03-8, AC-P03-9, AC-P03-10) — D-18, security review M-2.
 * `cloneRepo` (src/scanner/workspace.ts) is run against a fake `spawn`
 * (child_process is mocked; no git process, no network). The test rebuilds
 * the effective git configuration of the clone from BOTH channels git reads:
 *   - `-c key=value` pairs before the `clone` subcommand (argument list)
 *   - GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n (environment)
 * so the implementation may put each setting in either channel, except that
 * the token may only travel through the environment (never in the args).
 * Expected set: tests/README.md "src/scanner/workspace.ts — P-03".
 */
import { EventEmitter } from 'node:events';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { loadSrc } from '../helpers/loadSrc';
import type { WorkspaceModule } from '../helpers/contracts';

interface SpawnCall {
  command: string;
  args: string[];
  env: Record<string, string | undefined>;
}

const spawnCalls: SpawnCall[] = [];

function fakeSpawn(command: string, args: readonly string[] = [], options: { env?: Record<string, string | undefined> } = {}) {
  spawnCalls.push({ command, args: [...args], env: { ...(options.env ?? {}) } });
  const child = Object.assign(new EventEmitter(), {
    pid: undefined,
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    kill: () => true,
  });
  setImmediate(() => child.emit('close', 0));
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

const loadWorkspace = () => loadSrc<WorkspaceModule>('src/scanner/workspace.ts', ['buildGitCloneArgs', 'cloneRepo']);

/** Test-only token (not a secret). */
const FAKE_TOKEN = 'fake-test-token-0123456789';
const URL_GITHUB = 'https://github.com/org/repo.git';
const DEST = 'C:\\tmp\\ossrisk-scan-x\\repo';

interface ConfigEntry {
  key: string;
  value: string;
  channel: 'args' | 'env';
}

/** Git config keys: section and variable are case-insensitive, the subsection (URL) is not. */
function normalizeKey(key: string): string {
  const first = key.indexOf('.');
  const last = key.lastIndexOf('.');
  if (first === -1) return key.toLowerCase();
  if (first === last) return key.toLowerCase();
  return `${key.slice(0, first).toLowerCase()}.${key.slice(first + 1, last)}.${key.slice(last + 1).toLowerCase()}`;
}

function effectiveConfig(call: SpawnCall): ConfigEntry[] {
  const entries: ConfigEntry[] = [];
  const cloneAt = call.args.indexOf('clone');
  const globalArgs = cloneAt === -1 ? call.args : call.args.slice(0, cloneAt);
  globalArgs.forEach((arg, i) => {
    if (arg !== '-c') return;
    const pair = globalArgs[i + 1] ?? '';
    const eq = pair.indexOf('=');
    entries.push({ key: normalizeKey(eq === -1 ? pair : pair.slice(0, eq)), value: eq === -1 ? 'true' : pair.slice(eq + 1), channel: 'args' });
  });
  const count = Number(call.env.GIT_CONFIG_COUNT ?? 0);
  for (let i = 0; i < count; i += 1) {
    const key = call.env[`GIT_CONFIG_KEY_${i}`];
    if (key !== undefined) entries.push({ key: normalizeKey(key), value: call.env[`GIT_CONFIG_VALUE_${i}`] ?? '', channel: 'env' });
  }
  return entries;
}

/** Last value wins, as in git. */
function configValue(entries: ConfigEntry[], key: string): string | undefined {
  const hits = entries.filter((e) => e.key === normalizeKey(key));
  return hits.length > 0 ? hits[hits.length - 1].value : undefined;
}

function extraHeaderEntries(entries: ConfigEntry[]): Array<ConfigEntry & { scope: string | null }> {
  return entries
    .filter((e) => e.key.startsWith('http.') && e.key.endsWith('.extraheader'))
    .map((e) => ({ ...e, scope: e.key === 'http.extraheader' ? null : e.key.slice('http.'.length, -'.extraheader'.length) }));
}

async function cloneAndCapture(url: string, token: string | null): Promise<SpawnCall> {
  const { cloneRepo } = await loadWorkspace();
  await cloneRepo(url, 'main', DEST, token);
  const gitCalls = spawnCalls.filter((c) => /(^|[\\/])git(\.exe)?$/i.test(c.command));
  expect(gitCalls, 'exactly one git process spawned by cloneRepo').toHaveLength(1);
  return gitCalls[0];
}

beforeEach(() => {
  spawnCalls.length = 0;
});

describe('P-03 clone hardening: LFS and filters disabled (AC-P03-8, D-18)', () => {
  it('AC-P03-8: GIT_LFS_SKIP_SMUDGE=1 in the git environment', async () => {
    const call = await cloneAndCapture(URL_GITHUB, null);
    expect(call.env.GIT_LFS_SKIP_SMUDGE).toBe('1');
  });

  it('AC-P03-8: filter.lfs.smudge / clean / process emptied and filter.lfs.required=false', async () => {
    const config = effectiveConfig(await cloneAndCapture(URL_GITHUB, null));
    expect(configValue(config, 'filter.lfs.smudge'), 'filter.lfs.smudge').toBe('');
    expect(configValue(config, 'filter.lfs.clean'), 'filter.lfs.clean').toBe('');
    expect(configValue(config, 'filter.lfs.process'), 'filter.lfs.process').toBe('');
    expect(configValue(config, 'filter.lfs.required'), 'filter.lfs.required').toBe('false');
  });

  it('AC-P03-8: the hardening also applies when a token is used', async () => {
    const call = await cloneAndCapture(URL_GITHUB, FAKE_TOKEN);
    const config = effectiveConfig(call);
    expect(call.env.GIT_LFS_SKIP_SMUDGE).toBe('1');
    expect(configValue(config, 'filter.lfs.process')).toBe('');
    expect(configValue(config, 'http.followRedirects')).toBe('false');
  });
});

describe('P-03 token header is host-scoped (AC-P03-9, D-18)', () => {
  it.each([
    ['github.com', URL_GITHUB],
    ['gitlab.example.com', 'https://gitlab.example.com/group/repo.git'],
  ])('AC-P03-9: %s — exactly one http.<https://host/>.extraHeader, no global http.extraHeader', async (host, url) => {
    const config = effectiveConfig(await cloneAndCapture(url, FAKE_TOKEN));
    const headers = extraHeaderEntries(config);
    expect(headers.filter((h) => h.scope === null), 'global (host-independent) http.extraHeader').toEqual([]);
    expect(headers, 'host-scoped extraHeader entries').toHaveLength(1);
    const scope = new URL(headers[0].scope!);
    expect(scope.protocol).toBe('https:');
    expect(scope.host).toBe(host);
    expect(headers[0].value).toMatch(/^Authorization: Basic [A-Za-z0-9+/]+=*$/);
  });

  it('AC-P03-9: the token travels only through the environment — never in args (raw or base64)', async () => {
    const call = await cloneAndCapture(URL_GITHUB, FAKE_TOKEN);
    const joinedArgs = call.args.join('\n');
    expect(joinedArgs).not.toContain(FAKE_TOKEN);
    const header = extraHeaderEntries(effectiveConfig(call))[0];
    expect(header?.channel, 'extraHeader channel').toBe('env');
    const basic = header?.value.replace(/^Authorization: Basic /, '') ?? '';
    expect(basic.length).toBeGreaterThan(0);
    expect(joinedArgs).not.toContain(basic);
    expect(Buffer.from(basic, 'base64').toString('utf8')).toContain(FAKE_TOKEN);
  });

  it('AC-P03-9: no token -> no extraHeader at all', async () => {
    expect(extraHeaderEntries(effectiveConfig(await cloneAndCapture(URL_GITHUB, null)))).toEqual([]);
  });
});

describe('P-03 redirects are not followed (AC-P03-10, D-18)', () => {
  it('AC-P03-10: http.followRedirects=false', async () => {
    const config = effectiveConfig(await cloneAndCapture(URL_GITHUB, null));
    expect(configValue(config, 'http.followRedirects')).toBe('false');
  });

  it('AC-P03-10: buildGitCloneArgs (pure) carries -c http.followRedirects=false before "clone"', async () => {
    const { buildGitCloneArgs } = await loadWorkspace();
    const args = buildGitCloneArgs(URL_GITHUB, null, DEST);
    const cloneAt = args.indexOf('clone');
    const configs = args.slice(0, cloneAt).flatMap((a, i, all) => (a === '-c' ? [all[i + 1]] : []));
    expect(configs.map((c) => normalizeKey(c.split('=')[0]) + '=' + c.split('=').slice(1).join('='))).toContain('http.followredirects=false');
  });
});
