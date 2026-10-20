/**
 * REQ-011 P-39 — missing Python formats (AC-P39-4, AC-P39-5, AC-P40-3, D-305).
 *
 * Goldens: `tests/fixtures/python-extra/cases/<case>` -> `expected/<case>.json`
 * (exact `parseManifests(<case>, ['python'])` output, byte comparison through
 * `helpers/ecosystemGolden.ts`); the semantic checks below pin the rules the
 * goldens encode. The F4 files keep their frozen output (P-10 goldens; the
 * one deliberate change is `py-requirements-names`, D-305 / AC-P39-4).
 */
import { describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import { PARSER_MESSAGES } from '../../src/scanner/parsers/kit';
import type { SandboxScanResult, ScannedDependency } from '../../src/types/scan';
import { ecosystemCaseDir, expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const FIXTURE = 'python-extra';
const CASES = ['pipfile-lock', 'uv-lock', 'requirements-pattern', 'broken'];

const run = (caseName: string): SandboxScanResult => parseEcosystemCase(FIXTURE, 'python', caseName);
const pick = (deps: ScannedDependency[]) =>
  deps
    .map((d) => [d.manifest_path, d.manifest_file, d.name, d.version, d.scope, d.declared_range ?? null] as const)
    .sort((a, b) => (a.join('\u0000') < b.join('\u0000') ? -1 : 1));

describe('REQ-011 P-39: Python format goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden(FIXTURE, 'python', c));
});

describe('AC-P39-4: Pipfile.lock and uv.lock', () => {
  it('Pipfile.lock: default -> direct, develop -> dev, "==X" -> exact X, VCS/editable entries skipped, first section wins, PyPI purl normalisation', () => {
    const r = run('pipfile-lock');
    expect(r.parse_errors).toEqual([]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['Pipfile.lock']);
    expect(pick(r.dependencies)).toEqual([
      ['.', 'Pipfile.lock', 'Django', '5.0.6', 'direct', null],
      ['.', 'Pipfile.lock', 'certifi', '2024.6.2', 'direct', null],
      ['.', 'Pipfile.lock', 'loose', null, 'direct', '*'],
      ['.', 'Pipfile.lock', 'pluggy', '1.5.0', 'dev', null],
      ['.', 'Pipfile.lock', 'pytest', '8.2.2', 'dev', null],
      ['.', 'Pipfile.lock', 'requests', '2.32.3', 'direct', null],
      ['.', 'Pipfile.lock', 'typing_extensions', '4.12.2', 'direct', null],
    ]);
    const purls = new Map(r.dependencies.map((d) => [d.name, d.purl]));
    expect(purls.get('Django')).toBe('pkg:pypi/django@5.0.6');
    expect(purls.get('typing_extensions')).toBe('pkg:pypi/typing-extensions@4.12.2');
    expect(purls.get('loose')).toBe('pkg:pypi/loose');
  });

  it('uv.lock: project/local/VCS sources skipped; direct/optional/dev from the editable root (PEP 503 names), others transitive; forked versions kept', () => {
    const r = run('uv-lock');
    expect(r.parse_errors).toEqual([]);
    expect(pick(r.dependencies)).toEqual([
      ['.', 'uv.lock', 'anyio', '4.4.0', 'transitive', null],
      ['.', 'uv.lock', 'certifi', '2024.6.2', 'transitive', null],
      ['.', 'uv.lock', 'httpx', '0.27.0', 'direct', null],
      ['.', 'uv.lock', 'idna', '3.7', 'transitive', null],
      ['.', 'uv.lock', 'iniconfig', '2.0.0', 'transitive', null],
      ['.', 'uv.lock', 'numpy', '1.26.4', 'transitive', null],
      ['.', 'uv.lock', 'numpy', '2.0.0', 'transitive', null],
      ['.', 'uv.lock', 'pytest', '8.2.2', 'dev', null],
      ['.', 'uv.lock', 'rich', '13.7.1', 'optional', null],
      ['.', 'uv.lock', 'ruff', '0.4.9', 'dev', null],
      ['.', 'uv.lock', 'sniffio', '1.3.1', 'transitive', null],
      ['.', 'uv.lock', 'typing-extensions', '4.12.2', 'direct', null],
    ]);
    for (const skipped of ['demo-app', 'local-helper', 'vcs-lib']) expect(r.dependencies.some((d) => d.name === skipped), skipped).toBe(false);
  });
});

describe('AC-P39-5 / D-305: requirements*.txt pattern', () => {
  it('any requirements*.txt is read; names with dev/test (any case) are dev, others direct; the three F4 names keep their behaviour', () => {
    const r = run('requirements-pattern');
    expect(r.parse_errors).toEqual([]);
    expect(pick(r.dependencies)).toEqual([
      ['.', 'requirements-Dev-Tools.txt', 'black', '24.4.2', 'dev', '==24.4.2'],
      ['.', 'requirements-dev.txt', 'pytest', '8.2.2', 'dev', '==8.2.2'],
      ['.', 'requirements-prod.txt', 'gunicorn', '22.0.0', 'direct', '==22.0.0'],
      ['.', 'requirements.lock.txt', 'markupsafe', '2.1.5', 'direct', '==2.1.5'],
      ['.', 'requirements.txt', 'flask', '3.0.3', 'direct', '==3.0.3'],
      ['.', 'requirements_ci.txt', 'tox', null, 'direct', '>=4.15'],
      ['.', 'requirements_test.txt', 'coverage', '7.5.3', 'dev', '==7.5.3'],
      ['docs', 'requirements-docs.txt', 'sphinx', '7.3.7', 'direct', '==7.3.7'],
    ]);
    // dev-requirements.txt and requirements-prod.in are not the pattern; duplicates of earlier files are deduped (first file wins).
    expect(r.scan_files.map((f) => f.file_path).sort()).toEqual([
      'docs/requirements-docs.txt',
      'requirements-Dev-Tools.txt',
      'requirements-dev.txt',
      'requirements-prod.txt',
      'requirements.lock.txt',
      'requirements.txt',
      'requirements_ci.txt',
      'requirements_test.txt',
    ]);
  });
});

describe('AC-P40-3: broken new-format Python files', () => {
  it('one fixed Turkish record per broken file (no path, no library text); invalid entries skipped with one record; the other files are still read', () => {
    const r = run('broken');
    expect(r.parse_errors).toEqual([
      { ecosystem: 'python', file: 'pipfile-invalid-entry/Pipfile.lock', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'python', file: 'pipfile-json/Pipfile.lock', error: PARSER_MESSAGES.json },
      { ecosystem: 'python', file: 'pipfile-structure/Pipfile.lock', error: PARSER_MESSAGES.structure },
      { ecosystem: 'python', file: 'uv-invalid-entry/uv.lock', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'python', file: 'uv-not-utf8/uv.lock', error: 'Dosya geçerli UTF-8 değil.' },
      { ecosystem: 'python', file: 'uv-toml/uv.lock', error: PARSER_MESSAGES.toml },
      { ecosystem: 'python', file: 'uv-version/uv.lock', error: PARSER_MESSAGES.unsupportedVersion },
    ]);
    expect(pick(r.dependencies)).toEqual([
      ['pipfile-invalid-entry', 'Pipfile.lock', 'ok-pkg', '1.0.0', 'direct', null],
      ['uv-invalid-entry', 'uv.lock', 'ok-uv', '1.0.0', 'transitive', null],
      ['z-healthy', 'requirements-prod.txt', 'ok-req', '1.0.0', 'direct', '==1.0.0'],
    ]);
  });

  it('the new files are collected only when python is requested (D-304)', () => {
    const r = parseManifests(ecosystemCaseDir(FIXTURE, 'broken'), ['nodejs'], 'x');
    expect(r).toEqual({ scan_id: 'x', status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] });
  });
});
