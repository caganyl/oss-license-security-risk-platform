/**
 * Python parser: `requirements.txt`, `requirements-dev.txt`,
 * `requirements-test.txt`, `pyproject.toml` (PEP 621 and Poetry) and
 * `poetry.lock`. Line-by-line port of the legacy Python `python.py` (frozen
 * as golden output, REQ-003 D-26; P-10, ADR-005 Karar 2, 3, 4).
 */
import type { DependencyScope, ScannedDependency } from '../../types/scan';
import {
  PYTHON_MANIFEST_NAMES,
  PY_WS,
  decodeLenient,
  decodeStrict,
  discoverManifests,
  emptyResult,
  isPyDict,
  linkErrors,
  manifestDir,
  matchRequirementLine,
  parseError,
  pyGet,
  pyItems,
  pyIter,
  pySplitLines,
  pyStr,
  pyStrip,
  pyTruthy,
  pyValues,
  pypiPurl,
  readManifest,
  uniqueDependencies,
  type ParseResult,
  type TreeWalk,
  type WalkedFile,
} from './common';
import { parseTomlText } from './toml';

// Python regex semantics: `\s` is the `str.isspace` set, `.` is "anything
// but \n" and a trailing `$` also matches before a final "\n".
//
// The requirement line pattern (`^\s*([A-Za-z0-9_.-]+)\s*(\[.*?\])?\s*(.*)$`)
// is matched by the linear `matchRequirementLine` (common.ts): as a regex it
// backtracks cubically on a text with an embedded "\n" (security review M-1).
//
// The two patterns below stay regexes: each `[WS]*` borders a character class
// disjoint from `PY_WS`, so a failed attempt gives back at most one run once
// and the match is linear (also checked for M-1).
/** A requirement is pinned only by a single "==X" / "===X" clause without wildcards. */
const EXACT_PIN_RE = new RegExp(`^[${PY_WS}]*={2,3}[${PY_WS}]*([^,;*${PY_WS}]+)[${PY_WS}]*(?=\\n?$)`, 'u');
/** Poetry treats a bare version ("1.2.3") as an exact pin. */
const BARE_VERSION_RE = new RegExp(`^[${PY_WS}]*([0-9][0-9A-Za-z.+!-]*)[${PY_WS}]*(?=\\n?$)`, 'u');

/** Requirements files whose packages are development/test only (ADR-003 b). */
const REQUIREMENT_FILES: ReadonlyArray<readonly [string, DependencyScope]> = [
  ['requirements.txt', 'direct'],
  ['requirements-dev.txt', 'dev'],
  ['requirements-test.txt', 'dev'],
];

type Collector = (file: WalkedFile, data: Buffer, manifestPath: string) => ScannedDependency[];

export function parse(walk: TreeWalk): ParseResult {
  const result = emptyResult();
  result.parse_errors.push(...linkErrors(walk, 'python', PYTHON_MANIFEST_NAMES));

  const collect = (filename: string, collector: Collector) => {
    for (const file of discoverManifests(walk, filename)) {
      try {
        const manifest = readManifest(file, 'python');
        result.scan_files.push(manifest.record);
        result.dependencies.push(...collector(file, manifest.data, manifestDir(file.relPath, filename)));
      } catch (err) {
        result.parse_errors.push(parseError('python', file.relPath, err, walk.rootDir));
      }
    }
  };

  for (const [filename, scope] of REQUIREMENT_FILES) {
    collect(filename, (_file, data, manifestPath) => dependenciesFromRequirements(data, manifestPath, filename, scope));
  }
  collect('pyproject.toml', (file, data, manifestPath) => dependenciesFromPyproject(file, data, manifestPath));
  collect('poetry.lock', (file, data, manifestPath) => dependenciesFromPoetryLock(file, data, manifestPath));

  result.dependencies = uniqueDependencies(result.dependencies);
  return result;
}

function dependenciesFromRequirements(
  data: Buffer,
  manifestPath: string,
  manifestFile: string,
  scope: DependencyScope,
): ScannedDependency[] {
  const dependencies: ScannedDependency[] = [];
  for (const line of pySplitLines(decodeLenient(data))) {
    const parsed = parseRequirementLine(line);
    if (parsed) {
      const [name, specifier] = parsed;
      const [version, declaredRange] = versionFromSpecifier(specifier);
      dependencies.push(dependency(name, version, declaredRange, manifestPath, manifestFile, scope));
    }
  }
  return dependencies;
}

function dependenciesFromPyproject(file: WalkedFile, data: Buffer, manifestPath: string): ScannedDependency[] {
  const toml = parseTomlText(decodeStrict(data, file.relPath));
  const dependencies: ScannedDependency[] = [];

  const addRequirement = (requirement: unknown, scope: DependencyScope) => {
    const parsed = parseRequirementLine(pyStr(requirement));
    if (parsed) {
      const [name, specifier] = parsed;
      const [version, declaredRange] = versionFromSpecifier(specifier);
      dependencies.push(dependency(name, version, declaredRange, manifestPath, 'pyproject.toml', scope));
    }
  };

  const addPoetry = (name: string, specifier: unknown, scope: DependencyScope) => {
    const [version, declaredRange] = versionFromPoetrySpecifier(specifier);
    dependencies.push(dependency(name, version, declaredRange, manifestPath, 'pyproject.toml', scope));
  };

  const project = pyGet(toml, 'project', {});
  for (const requirement of pyIter(pyGet(project, 'dependencies', []))) {
    addRequirement(requirement, 'direct');
  }

  const optionalDependencies = pyGet(project, 'optional-dependencies', {});
  if (isPyDict(optionalDependencies)) {
    for (const groupDependencies of Object.values(optionalDependencies)) {
      for (const requirement of pyIter(groupDependencies)) {
        addRequirement(requirement, 'optional');
      }
    }
  }

  const poetry = pyGet(pyGet(toml, 'tool', {}), 'poetry', {});
  for (const [name, specifier] of pyItems(pyGet(poetry, 'dependencies', {}))) {
    if (name.toLowerCase() === 'python') continue;
    addPoetry(name, specifier, 'direct');
  }

  for (const [name, specifier] of pyItems(pyGet(poetry, 'dev-dependencies', {}))) {
    addPoetry(name, specifier, 'dev');
  }

  const groups = pyGet(poetry, 'group', {});
  if (isPyDict(groups)) {
    for (const group of pyValues(groups)) {
      for (const [name, specifier] of pyItems(pyGet(group, 'dependencies', {}))) {
        addPoetry(name, specifier, 'dev');
      }
    }
  }

  return dependencies;
}

function dependenciesFromPoetryLock(file: WalkedFile, data: Buffer, manifestPath: string): ScannedDependency[] {
  const toml = parseTomlText(decodeStrict(data, file.relPath));
  const dependencies: ScannedDependency[] = [];
  for (const pkg of pyIterPackages(pyGet(toml, 'package', []))) {
    const name = pyGet(pkg, 'name');
    const rawVersion = pyGet(pkg, 'version');
    const version = pyStrip(pyStr(pyTruthy(rawVersion) ? rawVersion : ''));
    if (pyTruthy(name) && version) {
      dependencies.push(
        dependency(
          pyStr(name),
          version,
          null,
          manifestPath,
          'poetry.lock',
          pyGet(pkg, 'category') === 'dev' ? 'dev' : 'transitive',
        ),
      );
    }
  }
  return dependencies;
}

/**
 * `for package in data.get("package", [])`: a text (characters) or a table
 * (keys) yields non-dict items, and `package.get` then fails in Python as
 * well; `pyGet` reproduces that failure for each item.
 */
function pyIterPackages(value: unknown): unknown[] {
  if (typeof value === 'string') return [...value];
  return pyIter(value);
}

function parseRequirementLine(rawLine: string): [string, string] | null {
  let line = pyStrip(rawLine.split('#', 1)[0]);
  if (
    !line ||
    line.startsWith('-') ||
    line.startsWith('git+') ||
    line.startsWith('http://') ||
    line.startsWith('https://') ||
    line.startsWith('.')
  ) {
    return null;
  }
  line = pyStrip(line.split(';', 1)[0]);
  const match = matchRequirementLine(line);
  if (!match) return null;
  return [match[0], pyStrip(match[1])];
}

/**
 * Returns (exact version or null, declared specifier or null) for a PEP 508
 * specifier. Only a single "==X" clause is an exact version.
 */
function versionFromSpecifier(rawSpecifier: string): [string | null, string | null] {
  const specifier = pyStrip(rawSpecifier);
  if (!specifier) return [null, null];
  const match = EXACT_PIN_RE.exec(specifier);
  return [match ? match[1] : null, specifier];
}

function versionFromPoetrySpecifier(rawSpecifier: unknown): [string | null, string | null] {
  let specifier = rawSpecifier;
  if (isPyDict(specifier)) specifier = pyGet(specifier, 'version');
  if (typeof specifier !== 'string' || !pyStrip(specifier)) return [null, null];
  const bare = BARE_VERSION_RE.exec(specifier);
  if (bare) return [bare[1], pyStrip(specifier)];
  return versionFromSpecifier(specifier);
}

/** `version` is an exact resolved version or null; the purl carries a version only then. */
function dependency(
  name: string,
  version: string | null,
  declaredRange: string | null,
  manifestPath: string,
  manifestFile: string,
  scope: DependencyScope,
): ScannedDependency {
  return {
    ecosystem: 'python',
    name,
    version,
    declared_range: declaredRange,
    purl: pypiPurl(name, version),
    manifest_file: manifestFile,
    manifest_path: manifestPath,
    scope,
  };
}
