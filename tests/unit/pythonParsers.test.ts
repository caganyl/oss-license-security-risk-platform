/**
 * REQ-002 · P-05 (AC-P05-2…4) and P-07 (AC-P07-1) at the parser level, plus
 * REQ-003 AC-P10-7 (dedupe and order). Since REQ-003 P-10 (ADR-005, D-31)
 * these run the TypeScript parsers (`src/scanner/parsers`, `parseManifests`)
 * directly on local fixtures; no Python interpreter is involved (AC-G-2).
 * The file name is kept from REQ-002 (AC-P10-16 "taşınır").
 * Parser output contract after P-05 (ADR-003 a):
 *   version: exact resolved version or null; declared_range: manifest range or null;
 *   purl carries a version only when version is exact.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import type { ScannedDependency } from '../../src/types/scan';
import { FIXTURES_DIR } from '../helpers/paths';

function runParsers(fixture: string, ecosystems = ['nodejs', 'python']): ScannedDependency[] {
  const result = parseManifests(path.join(FIXTURES_DIR, fixture), ecosystems, 'test');
  expect(result.status).toBe('completed');
  expect(result.parse_errors).toEqual([]);
  return result.dependencies;
}

const RANGE_CHARS = /[\^~<>=*,\s|!]/;

describe('P-05 parser output: exact version vs declared range', () => {
  let cache: ScannedDependency[] | undefined;
  const deps = () => (cache ??= runParsers('p05-ranges-no-lockfile'));
  const find = (name: string, manifestPath?: string) =>
    deps().filter((d) => d.name === name && (manifestPath === undefined || d.manifest_path === manifestPath));

  it('AC-P05-2 / AC-P05-4: npm ranges without a lock file -> version null, range kept per manifest', () => {
    expect(find('lodash', 'a')).toEqual([expect.objectContaining({ version: null, declared_range: '^4.17.0', purl: 'pkg:npm/lodash' })]);
    expect(find('lodash', 'b')).toEqual([expect.objectContaining({ version: null, declared_range: '~4.16.0', purl: 'pkg:npm/lodash' })]);
  });

  it('AC-P05-2: Python range -> version null, declared_range ">=2,<3"', () => {
    expect(find('requests')).toEqual([expect.objectContaining({ version: null, declared_range: '>=2,<3', purl: 'pkg:pypi/requests' })]);
  });

  it('AC-P05-2: Python requirement without specifier -> version null (no "unknown" sentinel)', () => {
    expect(find('six')).toEqual([expect.objectContaining({ version: null, purl: 'pkg:pypi/six' })]);
  });

  it('AC-P05-2: exact pin keeps the exact version and a versioned purl', () => {
    expect(find('flask')).toEqual([expect.objectContaining({ version: '3.0.0', purl: 'pkg:pypi/flask@3.0.0' })]);
  });

  it('AC-P05-2 / AC-P05-3: no dependency carries a range or sentinel as version; versionless purl when version is null', () => {
    expect(deps().length).toBeGreaterThan(0);
    for (const d of deps()) {
      if (d.version !== null) {
        expect(d.version, `${d.name}`).not.toMatch(RANGE_CHARS);
        expect(d.version).not.toBe('unknown');
      } else {
        expect(d.purl, `${d.name}`).not.toMatch(/@[^/]*$/);
      }
    }
  });
});

describe('P-07 parser scopes: development/test dependencies map to "dev"', () => {
  let cache: ScannedDependency[] | undefined;
  const deps = () => (cache ??= runParsers('p07-dev-scope'));
  const scopeOf = (name: string) => deps().filter((d) => d.name === name).map((d) => d.scope);

  it('AC-P07-1 (regression): npm devDependencies -> dev, dependencies -> direct', () => {
    expect(scopeOf('gpl-dev-tool')).toEqual(['dev']);
    expect(scopeOf('runtime-lib')).toEqual(['direct']);
  });

  it('AC-P07-1: requirements-dev.txt packages are parsed with scope dev (ADR-003 b)', () => {
    expect(scopeOf('pytest')).toEqual(['dev']);
    expect(scopeOf('requests')).toEqual(['direct']);
  });

  it('AC-P07-1 (regression): Poetry dev group -> dev, Poetry main dependency -> direct', () => {
    expect(scopeOf('black')).toEqual(['dev']);
    expect(scopeOf('httpx')).toEqual(['direct']);
  });
});

describe('AC-P10-7: dedupe key and processing order', () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p10-dedupe-'));
  afterAll(() => fs.rmSync(tmpBase, { recursive: true, force: true }));
  const root = (name: string, files: Record<string, string>) => {
    const dir = path.join(tmpBase, name);
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    return parseManifests(dir, ['nodejs', 'python'], 'dedupe').dependencies;
  };

  it('AC-P10-7: same package and version in requirements.txt and requirements-dev.txt -> one record with scope direct', () => {
    const deps = root('req-and-dev', { 'requirements.txt': 'requests==2.31.0\n', 'requirements-dev.txt': 'requests==2.31.0\npytest==8.0.0\n' });
    expect(deps.filter((d) => d.name === 'requests')).toEqual([
      expect.objectContaining({ version: '2.31.0', scope: 'direct', manifest_file: 'requirements.txt' }),
    ]);
    expect(deps.filter((d) => d.name === 'pytest')).toEqual([expect.objectContaining({ scope: 'dev' })]);
  });

  it('AC-P10-7: a different version in requirements-dev.txt keeps two records', () => {
    const deps = root('two-versions', { 'requirements.txt': 'requests==2.31.0\n', 'requirements-dev.txt': 'requests==2.32.0\n' });
    expect(deps.filter((d) => d.name === 'requests').map((d) => [d.version, d.scope])).toEqual([
      ['2.31.0', 'direct'],
      ['2.32.0', 'dev'],
    ]);
  });

  it('AC-P10-7: names are compared case-insensitively; first record wins', () => {
    const deps = root('case', { 'requirements.txt': 'Requests==2.31.0\nrequests==2.31.0\n' });
    expect(deps.filter((d) => d.name.toLowerCase() === 'requests')).toEqual([expect.objectContaining({ name: 'Requests' })]);
  });

  it('AC-P10-7 / ADR-005 Karar 2: str(None) collision — "foo==None" and a versionless "foo" in one folder give one record', () => {
    const deps = root('none-collision', { 'requirements.txt': 'foo==None\nfoo\n' });
    expect(deps.filter((d) => d.name === 'foo')).toEqual([expect.objectContaining({ version: 'None', declared_range: '==None' })]);
  });

  it('AC-P10-7: Python order requirements.txt -> pyproject.toml -> poetry.lock; the first scope wins', () => {
    const deps = root('py-order', {
      'requirements.txt': 'httpx==0.27.0\n',
      'pyproject.toml': '[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "0.27.0"\n',
      'poetry.lock': '[[package]]\nname = "httpx"\nversion = "0.27.0"\ncategory = "dev"\n',
    });
    expect(deps.filter((d) => d.name === 'httpx')).toEqual([
      expect.objectContaining({ manifest_file: 'requirements.txt', scope: 'direct' }),
    ]);
    expect(deps.some((d) => d.name === 'python')).toBe(false);
  });

  it('AC-P10-7: npm order package-lock.json -> yarn.lock; the shared (name, version) is kept once, from the lock', () => {
    const deps = root('npm-order', {
      'package.json': JSON.stringify({ dependencies: { 'left-pad': '^1.3.0' } }),
      'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/left-pad': { version: '1.3.0' } } }),
      'yarn.lock': 'left-pad@^1.3.0:\n  version "1.3.0"\n\nis-odd@^3.0.0:\n  version "3.0.1"\n',
    });
    expect(deps.filter((d) => d.name === 'left-pad')).toEqual([
      expect.objectContaining({ manifest_file: 'package-lock.json', version: '1.3.0', declared_range: '^1.3.0', scope: 'direct' }),
    ]);
    expect(deps.filter((d) => d.name === 'is-odd')).toEqual([
      expect.objectContaining({ manifest_file: 'yarn.lock', version: '3.0.1', scope: 'transitive' }),
    ]);
  });
});
