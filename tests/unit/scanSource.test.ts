/**
 * REQ-002 · P-04 (AC-P04-1…6) and P-03 (AC-P03-7) — source classification
 * ADR-002 karar 2 + 4, contract REQ-002-auth-api.md "P-04 — 400 davranışı".
 *
 * Expected module src/lib/scanSource.ts:
 *   parseScanRoots(value: string | undefined): string[]
 *   resolveScanSource(value: string, scanRoots: readonly string[]): Promise<ScanSource>
 *   class ScanSourceError extends Error { code: 'path_not_allowed' | 'repo_url_not_allowed'; statusCode: 400 }
 * Uses real temporary directories (and a junction on Windows); no network.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadSrc } from '../helpers/loadSrc';
import type { ScanSourceModule } from '../helpers/contracts';

const isWindows = process.platform === 'win32';
const loadScanSource = () =>
  loadSrc<ScanSourceModule>('src/lib/scanSource.ts', ['parseScanRoots', 'resolveScanSource', 'ScanSourceError']);

const tree: { base: string; root: string; proj: string; outside: string; link: string; file: string; kokA: string; kokAb: string } = {
  base: '', root: '', proj: '', outside: '', link: '', file: '', kokA: '', kokAb: '',
};

beforeAll(() => {
  tree.base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-roots-')));
  tree.root = path.join(tree.base, 'allowed');
  tree.proj = path.join(tree.root, 'proj');
  tree.outside = path.join(tree.base, 'outside');
  tree.link = path.join(tree.root, 'escape-link');
  tree.file = path.join(tree.root, 'file.txt');
  tree.kokA = path.join(tree.base, 'kok', 'a');
  tree.kokAb = path.join(tree.base, 'kok', 'ab');
  for (const dir of [tree.proj, tree.outside, tree.kokA, tree.kokAb]) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(tree.file, 'x');
  // 'junction' needs no admin rights on Windows; ignored elsewhere (dir symlink).
  fs.symlinkSync(tree.outside, tree.link, 'junction');
});

afterAll(() => {
  fs.rmSync(tree.base, { recursive: true, force: true });
});

async function expectRejected(value: string, roots: readonly string[], code: string): Promise<void> {
  const { resolveScanSource } = await loadScanSource();
  let error: unknown;
  try {
    await resolveScanSource(value, roots);
  } catch (err) {
    error = err;
  }
  expect(error, `expected ${code} for ${JSON.stringify(value)}`).toBeInstanceOf(Error);
  expect((error as { code?: string }).code).toBe(code);
  expect((error as { statusCode?: number }).statusCode).toBe(400);
  // contract: message carries neither the canonical path nor SCAN_ROOTS content
  const message = (error as Error).message;
  for (const root of roots) expect(message).not.toContain(root);
  expect(message).not.toContain(tree.base);
}

describe('P-04 SCAN_ROOTS parsing (AC-P04-1, AC-P04-6)', () => {
  it('AC-P04-6: undefined or blank SCAN_ROOTS -> no roots (default closed)', async () => {
    const { parseScanRoots } = await loadScanSource();
    expect(parseScanRoots(undefined)).toEqual([]);
    expect(parseScanRoots('')).toEqual([]);
    expect(parseScanRoots(`  ${path.delimiter} `)).toEqual([]);
  });

  it('AC-P04-1: SCAN_ROOTS is split on path.delimiter (";" on Windows, which does not clash with drive letters)', async () => {
    const { parseScanRoots } = await loadScanSource();
    expect(parseScanRoots([tree.root, tree.kokA].join(path.delimiter))).toEqual([tree.root, tree.kokA]);
  });
});

describe('P-04 local paths (AC-P04-2…6)', () => {
  it('AC-P04-2: a directory under an allowed root is accepted and canonicalised', async () => {
    const { resolveScanSource } = await loadScanSource();
    await expect(resolveScanSource(tree.proj, [tree.root])).resolves.toEqual({
      kind: 'local',
      path: fs.realpathSync.native(tree.proj),
    });
  });

  it('AC-P04-2: the root itself is accepted', async () => {
    const { resolveScanSource } = await loadScanSource();
    await expect(resolveScanSource(tree.root, [tree.root])).resolves.toMatchObject({ kind: 'local' });
  });

  it.runIf(isWindows)('AC-P04-2: Windows paths compare case-insensitively (upper-case variant accepted)', async () => {
    const { resolveScanSource } = await loadScanSource();
    const upper = tree.proj.toUpperCase();
    await expect(resolveScanSource(upper, [tree.root])).resolves.toMatchObject({ kind: 'local' });
    await expect(resolveScanSource(tree.proj, [tree.root.toLowerCase()])).resolves.toMatchObject({ kind: 'local' });
  });

  it('AC-P04-3: a directory outside every root -> path_not_allowed', async () => {
    await expectRejected(tree.outside, [tree.root], 'path_not_allowed');
  });

  it('AC-P04-4: ".." traversal out of the root -> path_not_allowed', async () => {
    const traversal = `${tree.root}${path.sep}proj${path.sep}..${path.sep}..${path.sep}outside`;
    await expectRejected(traversal, [tree.root], 'path_not_allowed');
  });

  it('AC-P04-4: junction/symlink inside the root pointing outside -> path_not_allowed', async () => {
    expect(fs.realpathSync.native(tree.link)).toBe(fs.realpathSync.native(tree.outside));
    await expectRejected(tree.link, [tree.root], 'path_not_allowed');
  });

  it('AC-P04-4: prefix trap — root ...\\kok\\a must not accept ...\\kok\\ab', async () => {
    await expectRejected(tree.kokAb, [tree.kokA], 'path_not_allowed');
  });

  it('AC-P04-3: non-existent path and a file (not a directory) -> path_not_allowed', async () => {
    await expectRejected(path.join(tree.root, 'does-not-exist'), [tree.root], 'path_not_allowed');
    await expectRejected(tree.file, [tree.root], 'path_not_allowed');
  });

  it('AC-P04-6: no SCAN_ROOTS -> even a real directory is rejected (path_not_allowed)', async () => {
    await expectRejected(tree.proj, [], 'path_not_allowed');
  });
});

describe('P-03 / P-04 remote and non-local sources (AC-P03-7, AC-P04-5)', () => {
  it('AC-P03-7: https URL without user info -> remote source', async () => {
    const { resolveScanSource } = await loadScanSource();
    await expect(resolveScanSource('https://github.com/org/repo.git', [])).resolves.toEqual({
      kind: 'remote',
      url: 'https://github.com/org/repo.git',
    });
  });

  const rejectedUrls: Array<[string, string]> = [
    ['http scheme', 'http://github.com/org/repo.git'],
    ['ssh:// URL', 'ssh://git@github.com/org/repo.git'],
    ['scp-like git@host:path', 'git@github.com:org/repo.git'],
    ['git:// scheme', 'git://github.com/org/repo.git'],
    ['file:// URL', 'file:///C:/repos/app'],
    ['ext:: transport', 'ext::sh -c touch% /tmp/pwned'],
    ['fd:: transport', 'fd::17'],
    ['option injection', '-uhttps://github.com/org/repo.git'],
    ['https with user:token', 'https://user:not-a-real-token@github.com/org/repo.git'],
    ['https with user only', 'https://user@github.com/org/repo.git'],
    ['UNC path', '\\\\server\\share\\repo'],
    ['device path \\\\?\\', '\\\\?\\C:\\repos\\app'],
    ['device path \\\\.\\', '\\\\.\\C:\\repos\\app'],
    ['relative path', 'repos/app'],
    ['dot (platform folder)', '.'],
    ['dot-relative path', './app'],
    ['parent-relative path', '..\\app'],
  ];

  it.each(rejectedUrls)('AC-P03-7 / AC-P04-5: %s -> repo_url_not_allowed', async (_label, value) => {
    await expectRejected(value, [tree.root], 'repo_url_not_allowed');
  });
});
