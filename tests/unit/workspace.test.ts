/**
 * REQ-002 · P-03 (AC-P03-3, AC-P03-4) — ADR-002 karar 3
 * Expected module src/scanner/workspace.ts:
 *   buildGitCloneArgs(url, ref, dest): string[]   (pure; no token parameter)
 *   withTempWorkspace(fn, { tmpRoot }): creates <tmpRoot>/ossrisk-scan-XXXX, always removes it
 *   cloneRepo(url, ref, dest, token): Promise<void>  (real git; not exercised here — no network)
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadSrc } from '../helpers/loadSrc';
import type { WorkspaceModule } from '../helpers/contracts';

const loadWorkspace = () =>
  loadSrc<WorkspaceModule>('src/scanner/workspace.ts', ['buildGitCloneArgs', 'withTempWorkspace', 'cloneRepo']);

describe('P-03 git clone argument array (AC-P03-3)', () => {
  const url = 'https://github.com/org/repo.git';
  const dest = path.join(os.tmpdir(), 'ossrisk-scan-x', 'repo');

  it('AC-P03-3: shallow, single-branch clone; "--" ends options before url and dest', async () => {
    const { buildGitCloneArgs } = await loadWorkspace();
    const args = buildGitCloneArgs(url, 'main', dest);
    const cloneAt = args.indexOf('clone');
    const dashdash = args.indexOf('--');
    expect(cloneAt).toBeGreaterThanOrEqual(0);
    expect(args.slice(cloneAt)).toEqual(expect.arrayContaining(['--depth', '1', '--single-branch', '--no-tags']));
    expect(args.slice(cloneAt, dashdash)).toEqual(expect.arrayContaining(['--branch', 'main']));
    expect(dashdash).toBeGreaterThan(cloneAt);
    expect(args.slice(dashdash + 1)).toEqual([url, dest]);
  });

  it('AC-P03-3: hardening config — symlinks off, no credential helper', async () => {
    const { buildGitCloneArgs } = await loadWorkspace();
    const args = buildGitCloneArgs(url, null, dest);
    const configs = args.flatMap((a, i) => (a === '-c' ? [args[i + 1]] : []));
    expect(configs).toEqual(expect.arrayContaining(['core.symlinks=false', 'credential.helper=']));
    expect(args).not.toContain('--branch');
  });

  it.each([['-uevil'], ['--upload-pack=touch x'], ['main;rm -rf'], ['a b']])(
    'AC-P03-3: invalid ref %j is rejected (no option injection)',
    async (ref) => {
      const { buildGitCloneArgs } = await loadWorkspace();
      expect(() => buildGitCloneArgs(url, ref, dest)).toThrow();
    },
  );

  it('AC-P03-3: valid refs such as feature/x-1.2 are accepted', async () => {
    const { buildGitCloneArgs } = await loadWorkspace();
    expect(buildGitCloneArgs(url, 'feature/x-1.2', dest)).toContain('feature/x-1.2');
  });
});

describe('P-03 temporary workspace lifecycle (AC-P03-3, AC-P03-4)', () => {
  let tmpRoot = '';
  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-test-tmproot-'));
  });
  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  const leftovers = () => fs.readdirSync(tmpRoot).filter((n) => n.startsWith('ossrisk-scan-'));

  it('AC-P03-3: job-specific ossrisk-scan-* directory under tmpRoot, never the platform folder', async () => {
    const { withTempWorkspace } = await loadWorkspace();
    let seen = '';
    await withTempWorkspace(async (dir) => {
      seen = dir;
      expect(fs.statSync(dir).isDirectory()).toBe(true);
    }, { tmpRoot });
    expect(path.dirname(seen)).toBe(tmpRoot);
    expect(path.basename(seen)).toMatch(/^ossrisk-scan-/);
    expect(path.resolve(seen)).not.toBe(path.resolve('.'));
  });

  it('AC-P03-4: removed after success', async () => {
    const { withTempWorkspace } = await loadWorkspace();
    const result = await withTempWorkspace(async (dir) => {
      fs.writeFileSync(path.join(dir, 'package.json'), '{}');
      return 42;
    }, { tmpRoot });
    expect(result).toBe(42);
    expect(leftovers()).toEqual([]);
  });

  it('AC-P03-4: removed after failure, and the original error is propagated', async () => {
    const { withTempWorkspace } = await loadWorkspace();
    await expect(
      withTempWorkspace(async (dir) => {
        fs.mkdirSync(path.join(dir, 'repo', 'nested'), { recursive: true });
        throw new Error('clone failed (simulated)');
      }, { tmpRoot }),
    ).rejects.toThrow('clone failed (simulated)');
    expect(leftovers()).toEqual([]);
  });

  it('AC-P03-4: removed even when it contains read-only files (git pack files on Windows)', async () => {
    const { withTempWorkspace } = await loadWorkspace();
    await withTempWorkspace(async (dir) => {
      const pack = path.join(dir, 'repo', '.git', 'objects', 'pack');
      fs.mkdirSync(pack, { recursive: true });
      const file = path.join(pack, 'pack-test.pack');
      fs.writeFileSync(file, 'x');
      fs.chmodSync(file, 0o444);
    }, { tmpRoot });
    expect(leftovers()).toEqual([]);
  });
});
