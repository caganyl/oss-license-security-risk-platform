/**
 * REQ-003 · AC-T-3 git version check (D-46, D-47; ADR-002 Ek E2):
 * `parseGitVersion`, `gitRequirementMessage`, `GitUnavailableError`,
 * `assertGitForRemoteScan`, `describeGitVersion` (src/scanner/gitVersion.ts)
 * and the runtime's step 5 `defaultCheckGit` (log only, never throws a
 * start-up error). The real `git --version` probe runs only when git is on
 * PATH (AC-G-2: no other tool is required).
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { defaultCheckGit } from '../../src/runtime';
import {
  GitUnavailableError,
  assertGitForRemoteScan,
  describeGitVersion,
  getGitVersion,
  gitRequirementMessage,
  parseGitVersion,
  probeGitVersion,
  resetGitVersionCache,
  type GitVersionInfo,
} from '../../src/scanner/gitVersion';

const NOT_FOUND: GitVersionInfo = { found: false, version: null, major: null, minor: null, supported: false };

function hostGit(): GitVersionInfo {
  try {
    return parseGitVersion(execFileSync('git', ['--version'], { encoding: 'utf8', windowsHide: true }));
  } catch {
    return NOT_FOUND;
  }
}
const HOST_GIT = hostGit();

describe('AC-T-3: parseGitVersion (^git version (\\d+)\\.(\\d+))', () => {
  it.each([
    ['git version 2.55.0.windows.1', { found: true, version: '2.55.0.windows.1', major: 2, minor: 55, supported: true }],
    ['git version 2.47.1.windows.1\n', { found: true, version: '2.47.1.windows.1', major: 2, minor: 47, supported: true }],
    ['git version 2.32.0', { found: true, version: '2.32.0', major: 2, minor: 32, supported: true }],
    ['git version 2.31.9', { found: true, version: '2.31.9', major: 2, minor: 31, supported: false }],
    ['git version 2.9.5', { found: true, version: '2.9.5', major: 2, minor: 9, supported: false }],
    ['git version 1.99.0', { found: true, version: '1.99.0', major: 1, minor: 99, supported: false }],
    ['git version 3.0.0', { found: true, version: '3.0.0', major: 3, minor: 0, supported: true }],
    ['  git version 2.40.1 (Apple Git-143)  ', { found: true, version: '2.40.1', major: 2, minor: 40, supported: true }],
  ])('%j', (output, expected) => {
    expect(parseGitVersion(output)).toEqual(expected);
  });

  it.each([[''], [null], [undefined], ['garbage'], ['version 2.40.0'], ['git version x.y'], ['git version 2'], ["'git' is not recognized as an internal or external command"]])(
    'not found: %j',
    (output) => {
      expect(parseGitVersion(output as string | null | undefined)).toEqual(NOT_FOUND);
    },
  );
});

describe('AC-T-3: requirement message, permanent error and remote-scan gate', () => {
  it('AC-T-3: gitRequirementMessage names the found version or "yok"', () => {
    expect(gitRequirementMessage(NOT_FOUND)).toBe('Uzak tarama için git 2.32 veya üstü gerekli (bulunan: yok).');
    expect(gitRequirementMessage(parseGitVersion('git version 2.31.9'))).toBe('Uzak tarama için git 2.32 veya üstü gerekli (bulunan: 2.31.9).');
  });

  it('AC-T-3 / AC-P13-4: GitUnavailableError is permanent and carries the message', () => {
    const err = new GitUnavailableError(NOT_FOUND);
    expect(err.permanent).toBe(true);
    expect(err.name).toBe('GitUnavailableError');
    expect(err.message).toBe(gitRequirementMessage(NOT_FOUND));
  });

  it('AC-T-3: assertGitForRemoteScan rejects for missing / too old / failing provider, resolves for >= 2.32', async () => {
    await expect(assertGitForRemoteScan(async () => NOT_FOUND)).rejects.toMatchObject({ name: 'GitUnavailableError', permanent: true, message: gitRequirementMessage(NOT_FOUND) });
    await expect(assertGitForRemoteScan(async () => parseGitVersion('git version 2.31.9'))).rejects.toThrow(/bulunan: 2\.31\.9/);
    await expect(
      assertGitForRemoteScan(async () => {
        throw new Error('spawn git ENOENT');
      }),
    ).rejects.toThrow(/bulunan: yok/);
    await expect(assertGitForRemoteScan(async () => parseGitVersion('git version 2.32.0'))).resolves.toBeUndefined();
  });

  it('AC-T-3: describeGitVersion — warning for missing/old, info for supported', () => {
    expect(describeGitVersion(NOT_FOUND)).toMatchObject({ level: 'warn', message: expect.stringMatching(/git bulunamadı.*yerel klasör taramaları etkilenmez/) });
    expect(describeGitVersion(parseGitVersion('git version 2.31.9'))).toMatchObject({ level: 'warn', message: expect.stringMatching(/git 2\.31\.9 eski/) });
    expect(describeGitVersion(parseGitVersion('git version 2.55.0.windows.1'))).toEqual({ level: 'log', message: 'git 2.55.0.windows.1 bulundu.' });
  });
});

describe('AC-T-3 / AC-P12-6 step 5: defaultCheckGit only logs', () => {
  it.each([
    ['missing', NOT_FOUND, 'warn'],
    ['2.31.9', parseGitVersion('git version 2.31.9'), 'warn'],
    ['2.55.0', parseGitVersion('git version 2.55.0'), 'log'],
  ] as const)('git %s -> one %s line, resolves', async (_label, info, level) => {
    const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
    await expect(defaultCheckGit(logger, async () => info)).resolves.toBeUndefined();
    expect(logger[level]).toHaveBeenCalledTimes(1);
    expect(logger.error).not.toHaveBeenCalled();
  });
});

describe('AC-T-3: real git --version probe (allowlisted environment, cached)', () => {
  it.skipIf(!HOST_GIT.found)('probeGitVersion matches the host git; getGitVersion is cached until resetGitVersionCache', async () => {
    const info = await probeGitVersion();
    expect(info).toEqual(HOST_GIT);
    resetGitVersionCache();
    const first = getGitVersion();
    expect(getGitVersion()).toBe(first);
    expect(await first).toEqual(HOST_GIT);
    resetGitVersionCache();
    expect(getGitVersion()).not.toBe(first);
    resetGitVersionCache();
  });

  it('probeGitVersion never throws: git not on PATH -> not found', async () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-nogit-'));
    try {
      const info = await probeGitVersion({ env: { PATH: empty, SystemRoot: process.env.SystemRoot ?? 'C:\\Windows' }, timeoutMs: 10_000 });
      expect(info).toEqual(NOT_FOUND);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });
});
