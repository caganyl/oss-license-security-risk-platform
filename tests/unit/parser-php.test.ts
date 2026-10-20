/**
 * REQ-011 P-40 PHP (Composer) parser: goldens (AC-P40-1) plus the rules the
 * goldens pin, spelled out (AC-P40-2 priority, AC-P40-3 broken files,
 * AC-P40-6 branch versions, AC-P40-7 lock licenses).
 */
import { describe, expect, it } from 'vitest';
import { composerLicenses } from '../../src/scanner/parsers/php';
import { PARSER_MESSAGES } from '../../src/scanner/parsers/kit';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['lock-licenses', 'lock-only', 'json-fallback', 'broken'] as const;

describe('AC-P40-1: PHP goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('php', 'php', c));
});

function byName(caseName: string) {
  const result = parseEcosystemCase('php', 'php', caseName);
  return { result, dep: (name: string) => result.dependencies.find((d) => d.name === name) };
}

describe('PHP composer.lock (AC-P40-2, AC-P40-6, AC-P40-7)', () => {
  it('composer.lock wins over composer.json; both records enter scan_files; scopes from require / packages-dev', () => {
    const { result, dep } = byName('lock-licenses');
    expect(result.parse_errors).toEqual([]);
    expect(result.scan_files.map((f) => f.filename)).toEqual(['composer.json', 'composer.lock']);
    expect(new Set(result.dependencies.map((d) => d.manifest_file))).toEqual(new Set(['composer.lock']));
    expect(dep('monolog/monolog')).toMatchObject({ version: '2.9.1', scope: 'direct', purl: 'pkg:composer/monolog/monolog@2.9.1' });
    expect(dep('psr/log')?.scope).toBe('transitive');
    expect(dep('symfony/polyfill-mbstring')?.scope).toBe('transitive');
    // `Symfony/Console` in require matches the lower-case lock name; `v` kept as written.
    expect(dep('symfony/console')).toMatchObject({ version: 'v6.4.1', scope: 'direct', purl: 'pkg:composer/symfony/console@v6.4.1' });
    expect(dep('phpunit/phpunit')?.scope).toBe('dev');
    expect(dep('sebastian/diff')).toMatchObject({ scope: 'dev', licenses: [] });
  });

  it('platform packages never become dependencies', () => {
    const names = parseEcosystemCase('php', 'php', 'lock-licenses').dependencies.map((d) => d.name);
    expect(names.filter((n) => !n.includes('/'))).toEqual([]);
  });

  it('branch versions (dev-*, *-dev) -> version null + declared_range, versionless purl', () => {
    const { dep } = byName('lock-licenses');
    expect(dep('acme/branch')).toMatchObject({ version: null, declared_range: 'dev-main', purl: 'pkg:composer/acme/branch', scope: 'direct' });
    expect(dep('acme/alias')).toMatchObject({ version: null, declared_range: '2.x-dev', purl: 'pkg:composer/acme/alias', scope: 'transitive' });
  });

  it('license array -> one OR-joined SPDX expression on licenses (lock hint)', () => {
    const { dep } = byName('lock-licenses');
    expect(dep('acme/dual')?.licenses).toEqual(['GPL-2.0-or-later OR MIT']);
    expect(dep('acme/compound')?.licenses).toEqual(['(LGPL-2.1-only AND MIT) OR Apache-2.0']);
    expect(dep('monolog/monolog')?.licenses).toEqual(['MIT']);
    expect(dep('symfony/polyfill-mbstring')?.licenses).toEqual(['MIT']);
    expect(dep('acme/branch')?.licenses).toEqual([]);
  });

  it('without composer.json every runtime package is direct; packages-dev null is empty', () => {
    const { result } = byName('lock-only');
    expect(result.dependencies.map((d) => [d.name, d.scope])).toEqual([
      ['guzzlehttp/guzzle', 'direct'],
      ['guzzlehttp/psr7', 'direct'],
    ]);
  });
});

describe('PHP composer.json fallback', () => {
  it('require -> direct, require-dev -> dev, all version null + declared_range, platform skipped', () => {
    const { result } = byName('json-fallback');
    expect(result.parse_errors).toEqual([]);
    expect(result.dependencies.map((d) => [d.name, d.version, d.scope, d.declared_range, d.purl])).toEqual([
      ['acme/tooling', null, 'direct', 'dev-develop', 'pkg:composer/acme/tooling'],
      ['guzzlehttp/guzzle', null, 'direct', '7.8.1', 'pkg:composer/guzzlehttp/guzzle'],
      ['laravel/framework', null, 'direct', '^10.0', 'pkg:composer/laravel/framework'],
      ['mockery/mockery', null, 'dev', '^1.6', 'pkg:composer/mockery/mockery'],
    ]);
  });
});

describe('PHP broken files (AC-P40-3)', () => {
  it('one fixed Turkish record per broken file; the next source / folder continues', () => {
    const result = parseEcosystemCase('php', 'php', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'php', file: 'a-broken-lock/composer.lock', error: PARSER_MESSAGES.json },
      { ecosystem: 'php', file: 'b-broken-json/composer.json', error: PARSER_MESSAGES.json },
      { ecosystem: 'php', file: 'c-lock-broken-json/composer.json', error: PARSER_MESSAGES.json },
      { ecosystem: 'php', file: 'd-invalid-entries/composer.lock', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'php', file: 'e-wrong-structure/composer.lock', error: PARSER_MESSAGES.structure },
      { ecosystem: 'php', file: 'e-wrong-structure/composer.json', error: PARSER_MESSAGES.structure },
    ]);
    for (const e of result.parse_errors) expect(e.error).not.toMatch(/[A-Za-z]:\\|\/Users\/|monolog|psr/);
    expect(result.dependencies.map((d) => [d.manifest_path, d.manifest_file, d.name, d.version, d.scope])).toEqual([
      // broken lock -> composer.json fallback
      ['a-broken-lock', 'composer.json', 'monolog/monolog', null, 'direct'],
      // broken composer.json next to a valid lock -> treated as missing (all direct)
      ['c-lock-broken-json', 'composer.lock', 'psr/container', '2.0.2', 'direct'],
      ['d-invalid-entries', 'composer.lock', 'psr/clock', '1.0.0', 'direct'],
    ]);
    expect(result.scan_files.map((f) => f.file_path)).toEqual([
      'a-broken-lock/composer.json',
      'c-lock-broken-json/composer.lock',
      'd-invalid-entries/composer.lock',
    ]);
  });
});

describe('composerLicenses (AC-P40-7)', () => {
  it('joins with OR, parenthesises compound items, ignores non-text and empty items', () => {
    expect(composerLicenses(['MIT'])).toEqual(['MIT']);
    expect(composerLicenses('MIT')).toEqual(['MIT']);
    expect(composerLicenses(['GPL-2.0-only', 'GPL-3.0-only'])).toEqual(['GPL-2.0-only OR GPL-3.0-only']);
    expect(composerLicenses(['MIT AND BSD-3-Clause', '(Apache-2.0 OR MIT)'])).toEqual(['(MIT AND BSD-3-Clause) OR (Apache-2.0 OR MIT)']);
    expect(composerLicenses(['MIT AND BSD-3-Clause'])).toEqual(['MIT AND BSD-3-Clause']);
    expect(composerLicenses([' MIT ', '', 3, null])).toEqual(['MIT']);
    expect(composerLicenses([])).toEqual([]);
    expect(composerLicenses(undefined)).toEqual([]);
    expect(composerLicenses({ id: 'MIT' })).toEqual([]);
  });
});
