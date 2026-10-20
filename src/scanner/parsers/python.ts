/**
 * Python parser: `requirements.txt`, `requirements-dev.txt`,
 * `requirements-test.txt`, `pyproject.toml` (PEP 621 and Poetry) and
 * `poetry.lock`. Line-by-line port of the legacy Python `python.py` (frozen
 * as golden output, REQ-003 D-26; P-10, ADR-005 Karar 2, 3, 4).
 *
 * REQ-011 P-39 adds, from the walk's `python` spec map (D-304): every other
 * `requirements*.txt` (D-305, AC-P39-5: a name containing `dev` or `test` ->
 * `dev`, else `direct`), `Pipfile.lock` and `uv.lock` (AC-P39-4). They are
 * read after the F4 files, so the F4 records win the dedupe and the F4
 * output is unchanged. A broken new-format file gives one fixed Turkish
 * record for that file (AC-P40-3); the other files are still read.
 */
import type { DependencyScope, ScannedDependency } from '../../types/scan';
import {
  ManifestReadError,
  PYTHON_MANIFEST_NAMES,
  PY_WS,
  compareCodePoints,
  decodeLenient,
  decodeStrict,
  discoverManifests,
  emptyResult,
  hasLoneSurrogate,
  isPyDict,
  isPyWhitespace,
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
  type ParseErrorRecord,
  type ParseResult,
  type TreeWalk,
  type WalkedFile,
} from './common';
import { PARSER_MESSAGES, ParserFileError } from './kit';
import { TomlSyntaxError, parseTomlText } from './toml';

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
  collectExtraFormats(walk, result);

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

// ---------------------------------------------------------------------------
// REQ-011 P-39: requirements*.txt pattern, Pipfile.lock, uv.lock
// ---------------------------------------------------------------------------

/** Longest accepted name / version of the new formats (same bounds as the parser kit). */
const EXTRA_MAX_NAME_LENGTH = 512;
const EXTRA_MAX_VERSION_LENGTH = 256;
/** Lock file names: the walk's `python` spec map holds these and the `requirements*.txt` files. */
const PIPFILE_LOCK = 'Pipfile.lock';
const UV_LOCK = 'uv.lock';
/** Pipfile.lock sections (AC-P39-4). */
const PIPFILE_SECTIONS: ReadonlyArray<readonly [string, DependencyScope]> = [
  ['default', 'direct'],
  ['develop', 'dev'],
];
/** uv sources of the project itself and its workspace members: their dependency lists are the roots. */
const UV_ROOT_SOURCES: readonly string[] = ['editable', 'virtual'];
/** uv sources that are not a registry release (project, local folder, VCS, direct URL): skipped. */
const UV_SKIPPED_SOURCES: readonly string[] = ['editable', 'virtual', 'path', 'directory', 'git', 'url'];

interface ExtraFileResult {
  dependencies: ScannedDependency[];
  /** At least one entry was skipped as invalid (one fixed record per file). */
  invalid: boolean;
}

type ExtraParser = (data: Buffer, file: WalkedFile, manifestPath: string) => ExtraFileResult;

/**
 * Reads the spec files of the walk (sorted by path; requirements files
 * first, then `Pipfile.lock`, then `uv.lock`, like the F4 order).
 */
function collectExtraFormats(walk: TreeWalk, result: ParseResult): void {
  const files: WalkedFile[] = [];
  for (const dirFiles of walk.specByDir?.get('python')?.values() ?? []) files.push(...dirFiles.values());
  files.sort((a, b) => compareCodePoints(a.relPath, b.relPath));
  const requirementsParser: ExtraParser = (data, file, manifestPath) => ({
    dependencies: dependenciesFromRequirements(data, manifestPath, file.name, extraRequirementsScope(file.name)),
    invalid: false,
  });
  for (const file of files) if (file.name !== PIPFILE_LOCK && file.name !== UV_LOCK) readExtraFile(file, result, requirementsParser);
  for (const file of files) if (file.name === PIPFILE_LOCK) readExtraFile(file, result, dependenciesFromPipfileLock);
  for (const file of files) if (file.name === UV_LOCK) readExtraFile(file, result, dependenciesFromUvLock);
}

/** D-305 / AC-P39-5: a `requirements*.txt` name containing `dev` or `test` (any case) is development only. */
function extraRequirementsScope(filename: string): DependencyScope {
  const lower = filename.toLowerCase();
  return lower.includes('dev') || lower.includes('test') ? 'dev' : 'direct';
}

function extraFileError(file: WalkedFile, message: string): ParseErrorRecord {
  return { ecosystem: 'python', file: file.relPath, error: message };
}

/** Fixed text of a new-format failure (AC-P40-3): never a library message, never a path. */
function extraFileMessage(err: unknown, file: WalkedFile): string {
  if (err instanceof ParserFileError) return err.message;
  if (err instanceof ManifestReadError) {
    const prefix = `${file.relPath}: `;
    return err.message.startsWith(prefix) ? err.message.slice(prefix.length) : PARSER_MESSAGES.structure;
  }
  if (err instanceof TomlSyntaxError) return PARSER_MESSAGES.toml;
  if (err instanceof SyntaxError) return PARSER_MESSAGES.json;
  return PARSER_MESSAGES.structure;
}

/** One new-format file: its record and entries on success, one fixed-text record on failure. */
function readExtraFile(file: WalkedFile, result: ParseResult, parse: ExtraParser): void {
  try {
    const { data, record } = readManifest(file, 'python');
    const parsed = parse(data, file, manifestDir(file.relPath, file.name));
    result.scan_files.push(record);
    result.dependencies.push(...parsed.dependencies);
    if (parsed.invalid) result.parse_errors.push(extraFileError(file, PARSER_MESSAGES.invalidEntry));
  } catch (err) {
    result.parse_errors.push(extraFileError(file, extraFileMessage(err, file)));
  }
}

/** Strict UTF-8 text without a leading BOM. */
function lockText(data: Buffer, file: WalkedFile): string {
  const text = decodeStrict(data, file.relPath);
  return text.startsWith('﻿') ? text.slice(1) : text;
}

/** Own property of a parsed document (never an inherited one). */
function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** A mapping, or null when absent; any other type is a structure error. */
function optionalDict(value: unknown): Record<string, unknown> | null {
  if (value === undefined || value === null) return null;
  if (!isPyDict(value)) throw new ParserFileError(PARSER_MESSAGES.structure);
  return value;
}

/** PyPI project name with the requirement-line characters (`[A-Za-z0-9_.-]`). */
function validPypiName(name: string): boolean {
  return name.length > 0 && name.length <= EXTRA_MAX_NAME_LENGTH && /^[A-Za-z0-9_.-]+$/.test(name);
}

function validExactVersion(version: string): boolean {
  if (version === '' || version.length > EXTRA_MAX_VERSION_LENGTH || hasLoneSurrogate(version)) return false;
  for (let i = 0; i < version.length; i++) {
    const c = version.charCodeAt(i);
    if (c <= 0x20 || (c >= 0x7f && c <= 0x9f) || isPyWhitespace(c)) return false;
  }
  return true;
}

/** PEP 503 comparison key (lower case, runs of `-`, `_`, `.` -> `-`); the stored name stays as written. */
function pep503Key(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * `Pipfile.lock` (JSON): `default` -> `direct`, `develop` -> `dev`
 * (AC-P39-4). `"version": "==X"` gives the exact version X (no declared
 * range: the lock pins it); any other text is kept as the declared range
 * with version null. Entries without `version` (VCS, path, editable) are
 * not registry releases and are skipped.
 */
function dependenciesFromPipfileLock(data: Buffer, file: WalkedFile, manifestPath: string): ExtraFileResult {
  const lock: unknown = JSON.parse(lockText(data, file));
  if (!isPyDict(lock)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const dependencies: ScannedDependency[] = [];
  let invalid = false;
  for (const [section, scope] of PIPFILE_SECTIONS) {
    for (const [name, entry] of Object.entries(optionalDict(own(lock, section)) ?? {})) {
      if (!isPyDict(entry)) {
        invalid = true;
        continue;
      }
      const version = own(entry, 'version');
      if (version === undefined) continue;
      if (typeof version !== 'string' || !validPypiName(name)) {
        invalid = true;
        continue;
      }
      const [exact, declared] = versionFromSpecifier(version);
      if (declared === null || (exact !== null && !validExactVersion(exact))) {
        invalid = true;
        continue;
      }
      dependencies.push(dependency(name, exact, exact === null ? declared : null, manifestPath, PIPFILE_LOCK, scope));
    }
  }
  return { dependencies, invalid };
}

/** Normalised names of a uv dependency list (`[{ name = "x", ... }, ...]`). */
function addUvNames(target: Set<string>, list: unknown): void {
  if (!Array.isArray(list)) return;
  for (const item of list) {
    const name = isPyDict(item) ? own(item, 'name') : undefined;
    if (typeof name === 'string') target.add(pep503Key(name));
  }
}

/** Every group list of a uv `optional-dependencies` / `dev-dependencies` table. */
function addUvGroups(target: Set<string>, groups: unknown): void {
  if (!isPyDict(groups)) return;
  for (const list of Object.values(groups)) addUvNames(target, list);
}

function hasAnySource(source: unknown, kinds: readonly string[]): boolean {
  return isPyDict(source) && kinds.some((kind) => own(source, kind) !== undefined);
}

/**
 * `uv.lock` (TOML, `version = 1`): `[[package]]` entries with `name`,
 * `version`, `source`. The project and workspace members (`editable` /
 * `virtual` source) are not packages but give the scopes: a package named
 * in their `dependencies` is `direct`, in `optional-dependencies`
 * `optional`, in `dev-dependencies` `dev` (first match in that order; names
 * compared by PEP 503), any other package `transitive` (like `poetry.lock`).
 * Local (`path`, `directory`), VCS (`git`) and direct-URL (`url`) packages are
 * not registry releases and are skipped.
 */
function dependenciesFromUvLock(data: Buffer, file: WalkedFile, manifestPath: string): ExtraFileResult {
  const lock = parseTomlText(lockText(data, file));
  if (own(lock, 'version') !== 1) throw new ParserFileError(PARSER_MESSAGES.unsupportedVersion);
  const packagesValue = own(lock, 'package');
  if (packagesValue !== undefined && !Array.isArray(packagesValue)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const packages: unknown[] = Array.isArray(packagesValue) ? packagesValue : [];

  const direct = new Set<string>();
  const optional = new Set<string>();
  const dev = new Set<string>();
  for (const pkg of packages) {
    if (!isPyDict(pkg) || !hasAnySource(own(pkg, 'source'), UV_ROOT_SOURCES)) continue;
    addUvNames(direct, own(pkg, 'dependencies'));
    addUvGroups(optional, own(pkg, 'optional-dependencies'));
    addUvGroups(dev, own(pkg, 'dev-dependencies'));
  }

  const dependencies: ScannedDependency[] = [];
  let invalid = false;
  for (const pkg of packages) {
    if (!isPyDict(pkg)) {
      invalid = true;
      continue;
    }
    if (hasAnySource(own(pkg, 'source'), UV_SKIPPED_SOURCES)) continue;
    const name = own(pkg, 'name');
    const rawVersion = own(pkg, 'version');
    const version = typeof rawVersion === 'string' ? pyStrip(rawVersion) : '';
    if (typeof name !== 'string' || !validPypiName(name) || !validExactVersion(version)) {
      invalid = true;
      continue;
    }
    const key = pep503Key(name);
    const scope: DependencyScope = direct.has(key) ? 'direct' : optional.has(key) ? 'optional' : dev.has(key) ? 'dev' : 'transitive';
    dependencies.push(dependency(name, version, null, manifestPath, UV_LOCK, scope));
  }
  return { dependencies, invalid };
}
