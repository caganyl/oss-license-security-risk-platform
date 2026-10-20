/**
 * REQ-009 pure units: Azure DevOps URL rule and token user name (AC-P29-9),
 * GIT_WINDOWS_AUTH_HOSTS parsing and scoping (AC-P30-1…4), clone failure
 * classes (AC-P31-2/3), token encryption round trip (P-29) and
 * project.assets.json v4 (AC-P32-1/2).
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { encryptToken } from '../../src/lib/tokenCrypto';
import { NUGET_MESSAGES } from '../../src/scanner/parsers/common';
import { parseNugetAssets } from '../../src/scanner/parsers/nugetAssets';
import { decryptToken } from '../../src/scanner/worker';
import {
  GitCloneError,
  WINDOWS_AUTH_HOSTS_INVALID_MESSAGE,
  buildGitCloneArgs,
  buildGitEnv,
  classifyCloneFailure,
  gitTokenSecretForms,
  isAzureDevOpsUrl,
  parseWindowsAuthHosts,
  windowsAuthOriginFor,
} from '../../src/scanner/workspace';
import { isPermanentError } from '../../src/scanner/retryPolicy';
import { DOTNET_CASES_DIR } from '../helpers/nugetGolden';

const TFS_URL = 'https://tfs.example.local/Collection/Project/_git/Repo';
const FAKE_TOKEN = 'pat-test-value-not-a-real-token';

function basicUser(url: string): string {
  const [, basic] = gitTokenSecretForms({ url, token: FAKE_TOKEN });
  return Buffer.from(basic, 'base64').toString('utf8').split(':')[0];
}

function configPairs(args: string[]): string[] {
  const pairs: string[] = [];
  for (let i = 0; i < args.length - 1; i++) if (args[i] === '-c') pairs.push(args[i + 1]);
  return pairs;
}

describe('AC-P29-9: Azure DevOps URLs (cloud and on-premises) use an empty Basic user name', () => {
  it('dev.azure.com, *.visualstudio.com and any /_git/ path are Azure DevOps', () => {
    expect(isAzureDevOpsUrl('https://dev.azure.com/org/proj/_git/repo')).toBe(true);
    expect(isAzureDevOpsUrl('https://org.visualstudio.com/proj/_git/repo')).toBe(true);
    expect(isAzureDevOpsUrl(TFS_URL)).toBe(true);
    expect(isAzureDevOpsUrl('https://github.com/org/repo.git')).toBe(false);
  });

  it('token user: "" for Azure DevOps (incl. TFS), oauth2 for GitLab, x-access-token otherwise', () => {
    expect(basicUser(TFS_URL)).toBe('');
    expect(basicUser('https://dev.azure.com/org/proj/_git/repo')).toBe('');
    expect(basicUser('https://gitlab.example.com/g/r.git')).toBe('oauth2');
    expect(basicUser('https://github.com/org/repo.git')).toBe('x-access-token');
  });
});

describe('AC-P30-1: GIT_WINDOWS_AUTH_HOSTS parsing', () => {
  it('full host names, comma/whitespace separated, case-insensitive, trailing dot ignored; empty = off', () => {
    expect([...parseWindowsAuthHosts('TFS.Example.Local, git.sirket.local.\n  other-host')]).toEqual([
      'tfs.example.local', 'git.sirket.local', 'other-host',
    ]);
    expect(parseWindowsAuthHosts('').size).toBe(0);
    expect(parseWindowsAuthHosts(undefined).size).toBe(0);
  });

  it.each(['*.sirket.local', 'tfs.local:8080', 'https://tfs.local', 'tfs.local/path', 'bad_host', '-x.local'])(
    'rejects %s',
    (entry) => {
      expect(() => parseWindowsAuthHosts(entry)).toThrow(WINDOWS_AUTH_HOSTS_INVALID_MESSAGE);
    },
  );
});

describe('AC-P30-2…4: Windows identity is scoped to one listed origin and only without a token', () => {
  const hosts = parseWindowsAuthHosts('tfs.example.local');

  it('listed host and no token -> origin; token present or other host -> null', () => {
    expect(windowsAuthOriginFor(TFS_URL, hosts, false)).toBe('https://tfs.example.local/');
    // security review M1: only the default port; :443 normalizes to the default
    expect(windowsAuthOriginFor('https://tfs.example.local:8443/C/P/_git/R', hosts, false)).toBeNull();
    expect(windowsAuthOriginFor('https://tfs.example.local:443/C/P/_git/R', hosts, false)).toBe('https://tfs.example.local/');
    expect(windowsAuthOriginFor(TFS_URL, hosts, true)).toBeNull();
    expect(windowsAuthOriginFor('https://github.com/org/repo.git', hosts, false)).toBeNull();
    expect(windowsAuthOriginFor(TFS_URL, parseWindowsAuthHosts(''), false)).toBeNull();
  });

  it('clone args: helper + emptyAuth for the origin come after the empty credential.helper reset', () => {
    const args = buildGitCloneArgs(TFS_URL, null, '/tmp/ws/repo', { windowsAuthOrigin: 'https://tfs.example.local/', platform: 'linux' });
    const pairs = configPairs(args);
    const reset = pairs.indexOf('credential.helper=');
    const helper = pairs.indexOf('credential.https://tfs.example.local/.helper=manager');
    const emptyAuth = pairs.indexOf('http.https://tfs.example.local/.emptyAuth=true');
    expect(reset).toBeGreaterThanOrEqual(0);
    expect(helper).toBeGreaterThan(reset);
    expect(emptyAuth).toBeGreaterThan(reset);
    // no --branch without a ref (AC-P31-1)
    expect(args).not.toContain('--branch');
  });

  it('clone args without Windows identity are unchanged (AC-G-1)', () => {
    const pairs = configPairs(buildGitCloneArgs(TFS_URL, 'main', '/tmp/ws/repo', { platform: 'linux' }));
    expect(pairs.some((p) => p.includes('.helper=manager') || p.includes('emptyAuth'))).toBe(false);
  });

  it('env: profile variables pass only in Windows-identity mode; isolation stays', () => {
    const parent = { PATH: '/bin', USERPROFILE: 'C:\\Users\\u', APPDATA: 'a', LOCALAPPDATA: 'l', USERNAME: 'u', USERDOMAIN: 'd', GIT_DIR: 'x', SECRET_X: 's' };
    const off = buildGitEnv(parent, '/tmp/ws', null, 'win32');
    const on = buildGitEnv(parent, '/tmp/ws', null, 'win32', true);
    for (const k of ['USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'USERNAME', 'USERDOMAIN']) {
      expect(off[k]).toBeUndefined();
      expect(on[k]).toBe(parent[k as keyof typeof parent]);
    }
    for (const env of [off, on]) {
      expect(env.GIT_DIR).toBeUndefined();
      expect(env.SECRET_X).toBeUndefined();
      expect(env.GIT_CONFIG_NOSYSTEM).toBe('1');
      expect(env.GIT_TERMINAL_PROMPT).toBe('0');
      expect(env.GCM_INTERACTIVE).toBe('never');
      expect(env.GIT_CONFIG_COUNT).toBe('0');
    }
  });
});

describe('AC-P31-2/3: clone failure classes', () => {
  it.each([
    ["fatal: could not read Username for 'https://tfs.example.local': terminal prompts disabled", 'auth', true],
    ['fatal: Authentication failed for https://x/', 'auth', true],
    ['The requested URL returned error: 403', 'auth', true],
    ['warning: Could not find remote branch main to clone.\nfatal: Remote branch main not found in upstream origin', 'branch', true],
    ["remote: TF401019: The Git repository with name or identifier X does not exist\nfatal: repository 'https://x/' not found", 'repo', true],
    ['fatal: unable to access: SSL certificate problem: unable to get local issuer certificate', 'tls', true],
    ['fatal: unable to access: schannel: next InitializeSecurityContext failed', 'tls', true],
    ['fatal: unable to access: Could not resolve host: tfs.example.local', 'network', false],
    ['fatal: unable to access: Failed to connect to tfs.example.local port 443', 'network', false],
  ])('%s -> %s (permanent=%s)', (stderr, kind, permanent) => {
    const failure = classifyCloneFailure(stderr);
    expect(failure?.kind).toBe(kind);
    expect(failure?.permanent).toBe(permanent);
    const err = new GitCloneError(`${failure!.sentence} git clone failed (exit code 128): ${stderr}`, failure);
    expect(isPermanentError(err)).toBe(permanent);
  });

  it('unclassified -> null, transient, message unchanged', () => {
    expect(classifyCloneFailure('fatal: early EOF')).toBeNull();
    const err = new GitCloneError('git clone failed (exit code 128): fatal: early EOF', null);
    expect(isPermanentError(err)).toBe(false);
    expect(err.message).toBe('git clone failed (exit code 128): fatal: early EOF');
  });

  it('the auth sentence tells the user what to do', () => {
    expect(classifyCloneFailure('terminal prompts disabled')!.sentence).toBe(
      'Repository requires authentication: add a repo access token to the project, or list the host in GIT_WINDOWS_AUTH_HOSTS.',
    );
  });
});

describe('P-29: token encryption matches the worker decryption', () => {
  it('round trip; random IV; wrong key fails; no key throws', () => {
    const a = encryptToken(FAKE_TOKEN, 'unit-key-A');
    const b = encryptToken(FAKE_TOKEN, 'unit-key-A');
    expect(a.equals(b)).toBe(false);
    expect(a.toString('utf8')).not.toContain(FAKE_TOKEN);
    expect(decryptToken(a, 'unit-key-A')).toBe(FAKE_TOKEN);
    expect(() => decryptToken(a, 'unit-key-B')).toThrow();
    const saved = process.env.ENCRYPTION_KEY;
    delete process.env.ENCRYPTION_KEY;
    try {
      expect(() => encryptToken(FAKE_TOKEN)).toThrow(/ENCRYPTION_KEY/);
    } finally {
      if (saved !== undefined) process.env.ENCRYPTION_KEY = saved;
    }
  });
});

describe('AC-P32-1/2: project.assets.json version 4 (.NET 10 SDK)', () => {
  const v3 = fs.readFileSync(path.join(DOTNET_CASES_DIR, 'assets-v3', 'obj', 'project.assets.json'), 'utf8');
  const withVersion = (v: number) => new TextEncoder().encode(v3.replace(/"version": 3,/, `"version": ${v},`));

  it('version 4 yields exactly the v3 result', () => {
    expect(parseNugetAssets(withVersion(4))).toEqual(parseNugetAssets(withVersion(3)));
    expect(parseNugetAssets(withVersion(4)).entries.length).toBeGreaterThan(0);
  });

  it.each([2, 5])('version %s is still rejected', (v) => {
    expect(() => parseNugetAssets(withVersion(v))).toThrow(NUGET_MESSAGES.assetsVersion);
  });
});
