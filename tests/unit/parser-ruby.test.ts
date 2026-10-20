/**
 * REQ-011 P-40 — Ruby (`Gemfile.lock`) parser: goldens (AC-P40-1), GEM
 * sections only (GIT/PATH skipped, D-311), DEPENDENCIES -> direct, platform
 * suffix dropped from the version, broken files (AC-P40-3).
 */
import { describe, expect, it } from 'vitest';
import type { ScannedDependency } from '../../src/types/scan';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['lock-basic', 'platform-suffix', 'broken'] as const;

function brief(list: readonly ScannedDependency[]): string[] {
  return list.map((d) => `${d.manifest_path}|${d.name}@${d.version ?? '-'}|${d.scope}|${d.declared_range ?? '-'}`);
}

describe('REQ-011 AC-P40-1: Ruby goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('ruby', 'ruby', c));
});

describe('REQ-011 P-40: Gemfile.lock', () => {
  it('GEM specs only (every GEM remote); GIT and PATH gems skipped; DEPENDENCIES -> direct with the requirement, the rest transitive', () => {
    const result = parseEcosystemCase('ruby', 'ruby', 'lock-basic');
    expect(brief(result.dependencies)).toEqual([
      // second GEM section (private gem server); `acme-auth!` in DEPENDENCIES
      '.|acme-auth@2.1.0|direct|-',
      '.|concurrent-ruby@1.2.3|transitive|-',
      '.|i18n@1.14.4|transitive|-',
      // dependency of the PATH gem `billing`: resolved from GEM, not in DEPENDENCIES
      '.|money@6.19.0|transitive|-',
      '.|nio4r@2.7.1|transitive|-',
      '.|puma@6.4.2|direct|>= 5.0, < 7',
      '.|rack@3.0.10|transitive|-',
      '.|rspec-core@3.13.0|direct|-',
      '.|rspec-support@3.13.1|transitive|-',
      '.|zeitwerk@2.6.13|direct|~> 2.6',
      // CRLF file in a sub folder
      'api|rack@2.2.8.1|transitive|-',
      'api|sinatra@3.2.0|direct|~> 3.2',
    ]);
    const names = result.dependencies.map((d) => d.name);
    for (const skipped of ['rails', 'actionpack', 'billing']) expect(names).not.toContain(skipped);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['Gemfile.lock', 'api/Gemfile.lock']);
    expect(result.parse_errors).toEqual([]);
    expect(result.dependencies.find((d) => d.name === 'puma')).toMatchObject({ purl: 'pkg:gem/puma@6.4.2', manifest_file: 'Gemfile.lock', ecosystem: 'ruby', licenses: [] });
  });

  it('platform suffix (-x86_64-linux, -arm64-darwin, -java, -x64-mingw-ucrt) is dropped; platform variants of one release collapse', () => {
    const result = parseEcosystemCase('ruby', 'ruby', 'platform-suffix');
    expect(brief(result.dependencies)).toEqual([
      '.|ffi@1.16.3|direct|-',
      '.|jruby-openssl@0.14.2|direct|-',
      '.|mini_portile2@2.8.5|transitive|-',
      '.|nokogiri@1.15.4|direct|~> 1.15',
      // a different release for one platform stays a separate entry
      '.|nokogiri@1.16.0|direct|~> 1.15',
      '.|racc@1.7.3|transitive|-',
      '.|sqlite3@2.0.0.rc1|direct|>= 2.0.0.rc1',
    ]);
    for (const d of result.dependencies) expect(d.purl).not.toMatch(/linux|darwin|java|mingw/);
  });
});

describe('REQ-011 AC-P40-3: broken Gemfile.lock files', () => {
  it('one fixed Turkish record per file; malformed lines dropped with one record; other folders continue', () => {
    const result = parseEcosystemCase('ruby', 'ruby', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'ruby', file: 'a-conflict/Gemfile.lock', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'ruby', file: 'b-not-a-lock/Gemfile.lock', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'ruby', file: 'c-no-section/Gemfile.lock', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'ruby', file: 'd-invalid-entry/Gemfile.lock', error: 'Geçersiz paket girdileri atlandı.' },
    ]);
    expect(brief(result.dependencies)).toEqual(['d-invalid-entry|json@2.7.1|direct|-', 'd-invalid-entry|rake@13.1.0|direct|~> 13.0', 'e-ok|rack@3.0.10|direct|-']);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['d-invalid-entry/Gemfile.lock', 'e-ok/Gemfile.lock']);
    for (const e of result.parse_errors) expect(e.error).not.toMatch(/oops|secretgem|rack|[\\/:]/);
  });
});
