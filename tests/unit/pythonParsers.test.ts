/**
 * REQ-002 · P-05 (AC-P05-2…4) and P-07 (AC-P07-1) at the parser level.
 * Runs the real Python parsers (src/scanner/sandbox/parsers, F1 keeps them)
 * on local fixtures: `python -m src.scanner.sandbox.parsers.scan`.
 * Parser output contract after P-05 (ADR-003 a):
 *   version: exact resolved version or null; declared_range: manifest range or null;
 *   purl carries a version only when version is exact.
 * Python interpreter: PYTHON_BIN or `python` (Windows) / `python3`.
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR, REPO_ROOT } from '../helpers/paths';

interface Dep {
  ecosystem: string;
  name: string;
  version: string | null;
  declared_range?: string | null;
  purl: string;
  scope: string;
  manifest_file: string;
  manifest_path: string;
}

function runParsers(fixture: string, ecosystems = 'nodejs,python'): Dep[] {
  const python = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
  const res = spawnSync(
    python,
    ['-m', 'src.scanner.sandbox.parsers.scan', '--scan-id', 'test', '--work-dir', path.join(FIXTURES_DIR, fixture), '--ecosystems', ecosystems],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: { ...process.env, PYTHONPATH: REPO_ROOT, PYTHONDONTWRITEBYTECODE: '1' },
      timeout: 60_000,
    },
  );
  if (res.error) throw new Error(`cannot run Python (${python}): ${res.error.message} — set PYTHON_BIN`);
  if (res.status !== 0) throw new Error(`parser exited ${res.status}: ${res.stderr}`);
  const last = res.stdout.trim().split(/\r?\n/).pop() ?? '';
  return (JSON.parse(last) as { dependencies: Dep[] }).dependencies;
}

const RANGE_CHARS = /[\^~<>=*,\s|!]/;

describe('P-05 parser output: exact version vs declared range', () => {
  const deps = runParsersSafe('p05-ranges-no-lockfile');

  function runParsersSafe(fixture: string): () => Dep[] {
    let cache: Dep[] | undefined;
    return () => (cache ??= runParsers(fixture));
  }
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
  let cache: Dep[] | undefined;
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
