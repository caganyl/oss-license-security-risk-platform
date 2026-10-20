/**
 * REQ-010 r2 fixes found on the user's real project:
 * - D-285: OS root certificates are added to Node's CA list (corporate HTTPS
 *   inspection proxy), never replacing it, and can be turned off.
 * - D-286: framework build output folders (.next, .nuxt) are not scanned.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { trustSystemCertificates } from '../../src/lib/systemCa';
import { SKIP_DIRS } from '../../src/scanner/parsers/common';
import { parseManifests } from '../../src/scanner/parsers';

describe('D-285: trustSystemCertificates', () => {
  function fakeApi(bundled: string[], system: string[]) {
    const state = { set: null as string[] | null };
    return {
      state,
      api: {
        getCACertificates: (type: string) => (type === 'system' ? system : bundled),
        setDefaultCACertificates: (certs: string[]) => {
          state.set = certs;
        },
      },
    };
  }

  it('keeps the bundled roots and adds the system ones without duplicates', () => {
    const { api, state } = fakeApi(['A', 'B'], ['B', 'CORP']);
    expect(trustSystemCertificates({}, api)).toEqual({ added: 1 });
    expect(state.set).toEqual(['A', 'B', 'CORP']);
  });

  it('USE_SYSTEM_CA=off leaves the CA list untouched', () => {
    const { api, state } = fakeApi(['A'], ['CORP']);
    expect(trustSystemCertificates({ USE_SYSTEM_CA: 'OFF' }, api)).toEqual({ added: 0 });
    expect(state.set).toBeNull();
  });
});

describe('D-286: .next / .nuxt build output is skipped', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-r2-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  it('only the real package.json is read; generated copies under .next and .nuxt are not', () => {
    expect(SKIP_DIRS.has('.next')).toBe(true);
    expect(SKIP_DIRS.has('.nuxt')).toBe(true);
    const pkg = (deps: Record<string, string>) => JSON.stringify({ name: 'x', version: '1.0.0', dependencies: deps });
    fs.mkdirSync(path.join(root, 'ui', '.next', 'standalone'), { recursive: true });
    fs.mkdirSync(path.join(root, 'ui', '.nuxt'), { recursive: true });
    fs.writeFileSync(path.join(root, 'ui', 'package.json'), pkg({ react: '^18.0.0' }));
    fs.writeFileSync(path.join(root, 'ui', '.next', 'standalone', 'package.json'), pkg({ 'generated-only': '1.0.0' }));
    fs.writeFileSync(path.join(root, 'ui', '.nuxt', 'package.json'), pkg({ 'nuxt-generated': '1.0.0' }));
    const result = parseManifests(root, ['nodejs'], 'r2-scan');
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['ui/package.json']);
    expect(result.dependencies.map((d) => d.name)).toEqual(['react']);
  });
});
