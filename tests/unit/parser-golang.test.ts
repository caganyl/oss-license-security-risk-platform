/**
 * REQ-011 P-40 — Go (`go.mod`) parser: goldens (AC-P40-1), replace / indirect
 * rules (D-311), broken files (AC-P40-3) and versionless declarations (AC-P40-6).
 */
import { describe, expect, it } from 'vitest';
import type { ScannedDependency } from '../../src/types/scan';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['basic', 'replace-indirect', 'crlf', 'broken'] as const;

function byName(caseName: string): Map<string, ScannedDependency> {
  const result = parseEcosystemCase('golang', 'go', caseName);
  return new Map(result.dependencies.map((d) => [`${d.manifest_path}|${d.name}`, d]));
}

describe('REQ-011 AC-P40-1: Go goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('golang', 'go', c));
});

describe('REQ-011 P-40: go.mod rules', () => {
  it('require lines and blocks: // indirect (also "indirect;" and "//indirect") -> transitive, others direct; versions kept with v', () => {
    const deps = byName('basic');
    expect(deps.get('.|github.com/google/uuid')).toMatchObject({ version: 'v1.6.0', scope: 'direct', purl: 'pkg:golang/github.com/google/uuid@v1.6.0' });
    expect(deps.get('.|github.com/BurntSushi/toml')).toMatchObject({ version: 'v1.4.0', scope: 'direct', purl: 'pkg:golang/github.com/BurntSushi/toml@v1.4.0' });
    expect(deps.get('.|golang.org/x/net')).toMatchObject({ version: 'v0.0.0-20240416194518-5c4b8b1b7bcd', scope: 'transitive' });
    expect(deps.get('.|github.com/docker/docker')).toMatchObject({ version: 'v26.1.3+incompatible', purl: 'pkg:golang/github.com/docker/docker@v26.1.3%2Bincompatible' });
    expect(deps.get('.|gopkg.in/yaml.v3')).toMatchObject({ version: 'v3.0.1', scope: 'direct' });
    expect(deps.get('.|github.com/bytedance/sonic')?.scope).toBe('transitive');
    expect(deps.get('.|github.com/pelletier/go-toml/v2')).toMatchObject({ version: 'v2.2.2', scope: 'transitive' });
    expect(deps.get('.|golang.org/x/sys')?.scope).toBe('transitive');
    // exclude / retract / tool / toolchain lines never become dependencies.
    expect([...deps.keys()].some((k) => k.includes('golang.org/x/tools'))).toBe(false);
    expect(deps.size).toBe(10);
  });

  it('replace: local path skipped (./, ../, drive letter), module -> module uses the replacement, version-specific replace wins', () => {
    const deps = byName('replace-indirect');
    expect(deps.has('.|example.com/monorepo/internal/auth')).toBe(false);
    expect(deps.has('.|github.com/winpath/mod')).toBe(false);
    expect(deps.has('.|github.com/old/fork')).toBe(false);
    expect(deps.get('.|github.com/new/fork')).toMatchObject({ version: 'v1.3.1', scope: 'direct' });
    expect(deps.get('.|github.com/pinned/lib')).toMatchObject({ version: 'v1.0.2', scope: 'transitive' });
    // `lib2 v1.4.0 => ../lib2` does not match the required v1.5.0.
    expect(deps.get('.|github.com/pinned/lib2')).toMatchObject({ version: 'v1.5.0', scope: 'direct' });
    expect(deps.get('.|golang.org/x/crypto')).toMatchObject({ version: 'v0.24.0', scope: 'transitive' });
    expect(deps.get('tools|golang.org/x/tools')).toMatchObject({ version: 'v0.21.0', scope: 'transitive' });
  });

  it('AC-P40-6: a non-canonical version is version null + declared_range (never reaches OSV)', () => {
    const deps = byName('replace-indirect');
    expect(deps.get('legacy|github.com/hand/written')).toMatchObject({ version: null, declared_range: 'master', purl: 'pkg:golang/github.com/hand/written' });
    expect(deps.get('legacy|github.com/hand/semver')).toMatchObject({ version: null, declared_range: 'v1.2' });
  });

  it('CRLF line endings and a UTF-8 BOM are accepted', () => {
    const deps = byName('crlf');
    expect([...deps.values()].map((d) => [d.version, d.scope])).toEqual([
      ['v1.17.0', 'direct'],
      ['v1.8.0', 'direct'],
      ['v1.0.5', 'transitive'],
    ]);
  });

  it('AC-P40-3: each broken go.mod is one fixed Turkish record without a path or file content; other folders continue', () => {
    const result = parseEcosystemCase('golang', 'go', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'go', file: 'go.mod', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'go', file: 'args/go.mod', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'go', file: 'quote/go.mod', error: 'Beklenmeyen dosya yapısı.' },
    ]);
    expect(result.dependencies.map((d) => `${d.manifest_path}|${d.name}@${d.version}`)).toEqual(['ok|github.com/ok/dep@v0.3.0']);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['ok/go.mod']);
  });
});
