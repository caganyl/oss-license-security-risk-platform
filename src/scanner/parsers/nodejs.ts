/**
 * npm parser: `package.json`, `package-lock.json` (v1 `dependencies` tree,
 * v2/v3 `packages` map) and Yarn v1 `yarn.lock`. Line-by-line port of
 * the legacy Python `nodejs.py` (frozen as golden output, REQ-003 D-26;
 * P-10, ADR-005 Karar 2, 4).
 *
 * L-5 (REQ-005, ADR-007 Karar 12): with an optional `IntegrityCollector` the
 * lock parsers also report each locked entry's `integrity` value through that
 * side channel; dependency objects never get a new field (golden unchanged).
 *
 * REQ-011 P-39 adds `pnpm-lock.yaml` (v6, v9) and `bun.lock` (Bun >= 1.2
 * text lock, JSONC); `bun.lockb` (binary) is not read and gives one
 * "unsupported format" record. These files come from the walk's `nodejs`
 * spec map (D-304) and are used only next to a `package.json`, like the F4
 * lock files. Lock choice per folder (AC-P39-3, D-306):
 * `package-lock.json` > `pnpm-lock.yaml` > `yarn.lock` > `bun.lock`; a lock
 * file that is not chosen is neither read nor listed in `scan_files`. The F4
 * pair `package-lock.json` + `yarn.lock` keeps its frozen behaviour (both are
 * read, golden `npm-lock-and-yarn`, AC-G-1). A broken new-format lock gives
 * one fixed Turkish record for that file (AC-P40-3) and the folder falls back
 * to `package.json` alone, as without a lock file.
 */
import type { DependencyScope, ScannedDependency } from '../../types/scan';
import {
  ManifestReadError,
  NODEJS_MANIFEST_NAMES,
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
  npmPurl,
  parseError,
  pyGet,
  pyItems,
  pyRstrip,
  pySplitLines,
  pyStr,
  pyStrip,
  pyStripChars,
  pyTruthy,
  PyTypeError,
  readManifest,
  siblingFile,
  uniqueDependencies,
  type ParseErrorRecord,
  type ParseResult,
  type TreeWalk,
  type WalkedFile,
} from './common';
import { PARSER_MESSAGES, ParserFileError } from './kit';
import type { IntegrityCollector } from './lockIntegrityValue';
import { YamlSubsetError, parseYamlSubset } from './yamlSubset';

const PACKAGE_SECTIONS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'] as const;
type PackageSection = (typeof PACKAGE_SECTIONS)[number];

// Exact semver as written in lock files. Python `\d` matches every Unicode
// decimal digit (Nd), hence `\p{Nd}` with the `u` flag.
const EXACT_VERSION_RE = /^v?\p{Nd}+\.\p{Nd}+\.\p{Nd}+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?(?=\n?$)/u;
const SCOPED_YARN_NAME_RE = /^(@[^/]+\/[^@]+)/u;
const YARN_NAME_RE = /^([^@]+)/u;

/** Python dict keyed by arbitrary hashable values (`declared_scopes` may hold non-text keys). */
type ScopeMap = Map<unknown, DependencyScope>;

function readJson(data: Buffer, relPath: string): unknown {
  return JSON.parse(decodeStrict(data, relPath));
}

export function parse(walk: TreeWalk, collector?: IntegrityCollector): ParseResult {
  const result = emptyResult();
  result.parse_errors.push(...linkErrors(walk, 'nodejs', NODEJS_MANIFEST_NAMES));

  for (const packageJson of discoverManifests(walk, 'package.json')) {
    try {
      const packageFile = readManifest(packageJson, 'nodejs');
      result.scan_files.push(packageFile.record);

      const packageData = readJson(packageFile.data, packageJson.relPath);
      const manifestPath = manifestDir(packageJson.relPath, 'package.json');
      const declaredScopes = declaredScopesOf(packageData);
      const locked: ScannedDependency[] = [];

      // Lock files are looked up in the walk (regular files only): a linked
      // lock file is ignored and package.json is parsed on its own (ADR-005 Karar 6).
      const lockfile = siblingFile(walk, packageJson, 'package-lock.json');
      if (lockfile) {
        const lock = readManifest(lockfile, 'nodejs');
        result.scan_files.push(lock.record);
        locked.push(...dependenciesFromPackageLock(lock.data, lockfile, manifestPath, declaredScopes, collector));
      }

      // AC-P39-3: pnpm-lock.yaml only without package-lock.json; yarn.lock only without either.
      const pnpmLock = lockfile ? undefined : extraLockFile(walk, packageJson, 'pnpm-lock.yaml');

      const yarnLock = pnpmLock ? undefined : siblingFile(walk, packageJson, 'yarn.lock');
      if (yarnLock) {
        const yarn = readManifest(yarnLock, 'nodejs');
        result.scan_files.push(yarn.record);
        locked.push(...dependenciesFromYarnLock(yarn.data, manifestPath, declaredScopes, collector));
      }

      // New formats carry their own scopes and ranges (importers / workspaces); they are not
      // merged with package.json names like the F4 locks above.
      let extra: ScannedDependency[] | null = null;
      if (pnpmLock) {
        extra = readExtraLock(pnpmLock, result, collector, (data, file) => dependenciesFromPnpmLock(data, file, manifestPath));
      } else if (!lockfile && !yarnLock) {
        const bunLock = extraLockFile(walk, packageJson, 'bun.lock');
        const bunBinary = bunLock ? undefined : extraLockFile(walk, packageJson, 'bun.lockb');
        if (bunLock) {
          extra = readExtraLock(bunLock, result, collector, (data, file) => dependenciesFromBunLock(data, file, manifestPath));
        } else if (bunBinary) {
          // AC-P39-2: the binary lock is never read; package.json alone is used.
          result.parse_errors.push(extraLockError(bunBinary, PARSER_MESSAGES.unsupportedFormat));
        }
      }

      // With a lock file the version comes from the lock, the range from package.json.
      const declaredRanges = declaredRangesOf(packageData);
      for (const dependency of locked) {
        if (dependency.declared_range === null && declaredRanges.has(dependency.name)) {
          dependency.declared_range = declaredRanges.get(dependency.name) as string;
        }
      }
      result.dependencies.push(...locked);
      if (extra) result.dependencies.push(...extra);

      if (!lockfile && !yarnLock && !extra) {
        result.dependencies.push(...dependenciesFromPackageJson(packageData, manifestPath));
      }
    } catch (err) {
      result.parse_errors.push(parseError('nodejs', packageJson.relPath, err, walk.rootDir));
    }
  }

  result.dependencies = uniqueDependencies(result.dependencies);
  return result;
}

/** Without a lock file only the declared range is known: version stays null. */
function dependenciesFromPackageJson(packageData: unknown, manifestPath: string): ScannedDependency[] {
  const dependencies: ScannedDependency[] = [];
  for (const section of PACKAGE_SECTIONS) {
    const scope = scopeForSection(section);
    for (const [name, specifier] of pyItems(pyGet(packageData, section, {}))) {
      const stripped = pyStrip(pyStr(specifier));
      const declaredRange = stripped === '' ? null : stripped;
      const version = declaredRange && isExactVersion(declaredRange) ? declaredRange : null;
      dependencies.push(dependency(name, version, manifestPath, 'package.json', scope, null, declaredRange));
    }
  }
  return dependencies;
}

function dependenciesFromPackageLock(
  data: Buffer,
  lockfile: WalkedFile,
  manifestPath: string,
  declaredScopes: ScopeMap,
  collector?: IntegrityCollector,
): ScannedDependency[] {
  const lock = readJson(data, lockfile.relPath);
  const dependencies: ScannedDependency[] = [];

  const packages = pyGet(lock, 'packages');
  if (isPyDict(packages)) {
    for (const [packagePath, pkg] of Object.entries(packages)) {
      if (!packagePath || !isPyDict(pkg)) continue;
      const rawName = pyGet(pkg, 'name');
      const name = pyTruthy(rawName) ? rawName : nameFromNodeModulesPath(packagePath);
      const version = pyGet(pkg, 'version');
      if (pyTruthy(name) && pyTruthy(version)) {
        const nameText = pyStr(name);
        const dep = dependency(
          nameText,
          pyStr(version),
          manifestPath,
          'package-lock.json',
          declaredScopes.get(nameText) ?? lockScope(pkg),
          licensesOf(pkg),
        );
        dependencies.push(dep);
        collectIntegrity(collector, dep, pyGet(pkg, 'integrity'));
      }
    }
  }

  const legacyDependencies = pyGet(lock, 'dependencies');
  if (isPyDict(legacyDependencies)) {
    dependencies.push(...dependenciesFromLegacyLock(legacyDependencies, manifestPath, declaredScopes, 'transitive', collector));
  }

  return dependencies;
}

function dependenciesFromLegacyLock(
  entries: Record<string, unknown>,
  manifestPath: string,
  declaredScopes: ScopeMap,
  inheritedScope: DependencyScope = 'transitive',
  collector?: IntegrityCollector,
): ScannedDependency[] {
  const dependencies: ScannedDependency[] = [];
  for (const [name, pkg] of Object.entries(entries)) {
    if (!isPyDict(pkg)) continue;
    const version = pyGet(pkg, 'version');
    const scope = declaredScopes.get(name) ?? (pyTruthy(pyGet(pkg, 'dev')) ? 'dev' : inheritedScope);
    if (pyTruthy(version)) {
      const dep = dependency(name, pyStr(version), manifestPath, 'package-lock.json', scope, licensesOf(pkg));
      dependencies.push(dep);
      collectIntegrity(collector, dep, pyGet(pkg, 'integrity'));
    }
    const nested = pyGet(pkg, 'dependencies');
    if (isPyDict(nested)) {
      dependencies.push(...dependenciesFromLegacyLock(nested, manifestPath, declaredScopes, scope, collector));
    }
  }
  return dependencies;
}

function dependenciesFromYarnLock(
  data: Buffer,
  manifestPath: string,
  declaredScopes: ScopeMap,
  collector?: IntegrityCollector,
): ScannedDependency[] {
  const dependencies: ScannedDependency[] = [];
  let currentNames: string[] = [];
  let currentVersion: string | null = null;
  let currentIntegrity: string | null = null;

  const flush = () => {
    if (currentNames.length > 0 && currentVersion) {
      for (const name of currentNames) {
        const dep = dependency(name, currentVersion, manifestPath, 'yarn.lock', declaredScopes.get(name) ?? 'transitive');
        dependencies.push(dep);
        collectIntegrity(collector, dep, currentIntegrity);
      }
    }
  };

  for (const rawLine of pySplitLines(decodeLenient(data))) {
    const line = pyRstrip(rawLine);
    if (!line || line.startsWith('#')) continue;
    if (!line.startsWith(' ')) {
      flush();
      currentNames = namesFromYarnKey(line);
      currentVersion = null;
      currentIntegrity = null;
      continue;
    }
    const stripped = pyStrip(line);
    if (stripped.startsWith('version ')) {
      const rest = stripped.slice(stripped.indexOf(' ') + 1);
      currentVersion = pyStripChars(pyStrip(rest), '"');
    } else if (collector && stripped.startsWith('integrity ')) {
      const rest = stripped.slice(stripped.indexOf(' ') + 1);
      currentIntegrity = pyStripChars(pyStrip(rest), '"');
    }
  }
  flush();

  return dependencies;
}

/**
 * L-5 side channel: one record per emitted lock entry with an exact version
 * (the comparison key needs one). The collector checks the value bounds.
 */
function collectIntegrity(collector: IntegrityCollector | undefined, dep: ScannedDependency, integrity: unknown): void {
  if (!collector || dep.version === null) return;
  collector.add(dep.manifest_path, dep.name, dep.version, integrity);
}

function namesFromYarnKey(line: string): string[] {
  const key = pyStripChars(line, ':', 'right');
  const names: string[] = [];
  for (const part of splitYarnKey(key)) {
    const name = nameFromYarnDescriptor(pyStripChars(pyStrip(part), '"'));
    if (name) names.push(name);
  }
  return names;
}

function splitYarnKey(key: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  for (const char of key) {
    if (char === '"') quoted = !quoted;
    if (char === ',' && !quoted) {
      parts.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

function nameFromYarnDescriptor(descriptor: string): string | null {
  const match = descriptor.startsWith('@') ? SCOPED_YARN_NAME_RE.exec(descriptor) : YARN_NAME_RE.exec(descriptor);
  return match ? match[1] : null;
}

function nameFromNodeModulesPath(packagePath: string): string | null {
  const marker = 'node_modules/';
  if (!packagePath.includes(marker)) return null;
  const segments = packagePath.split(marker);
  const parts = segments[segments.length - 1].split('/');
  if (parts[0].startsWith('@') && parts.length > 1) return `${parts[0]}/${parts[1]}`;
  return parts[0];
}

/**
 * `version` is an exact resolved version or null (ADR-003 a); a non-exact
 * lock value (git URL, `file:` path, tag) is kept as `declared_range` instead.
 */
function dependency(
  name: string,
  version: string | null,
  manifestPath: string,
  manifestFile: string,
  scope: DependencyScope,
  licenses: string[] | null = null,
  declaredRange: string | null = null,
): ScannedDependency {
  let exactVersion = version;
  let range = declaredRange;
  if (exactVersion !== null && !isExactVersion(exactVersion)) {
    range = range || exactVersion;
    exactVersion = null;
  }
  const dep: ScannedDependency = {
    ecosystem: 'nodejs',
    name,
    version: exactVersion,
    declared_range: range,
    purl: npmPurl(name, exactVersion),
    manifest_file: manifestFile,
    manifest_path: manifestPath,
    scope,
  };
  if (licenses && licenses.length > 0) {
    dep.licenses = [...new Set(licenses)].sort(compareCodePoints);
  }
  return dep;
}

/**
 * Python iterates the section here (`for name in section`): a dict gives its
 * names, a list its elements, a text its characters. The text and list cases
 * fail later in `declaredRangesOf` exactly as in Python, so the lock files'
 * `scan_files` records are still written first.
 */
function declaredScopesOf(packageData: unknown): ScopeMap {
  const scopes: ScopeMap = new Map();
  for (const section of PACKAGE_SECTIONS) {
    const value = pyGet(packageData, section, {});
    let names: unknown[];
    if (isPyDict(value)) names = Object.keys(value);
    else if (Array.isArray(value)) names = value;
    else if (typeof value === 'string') names = [...value];
    else throw new PyTypeError('Beklenmeyen tip: bağımlılık bölümü sözlük olmalı.');
    for (const name of names) {
      if (typeof name === 'object' && name !== null) {
        throw new PyTypeError('Beklenmeyen tip: bağımlılık adı metin olmalı.');
      }
      scopes.set(name, scopeForSection(section));
    }
  }
  return scopes;
}

function declaredRangesOf(packageData: unknown): Map<string, string> {
  const ranges = new Map<string, string>();
  for (const section of PACKAGE_SECTIONS) {
    for (const [name, specifier] of pyItems(pyGet(packageData, section, {}))) {
      const value = pyStrip(pyStr(specifier));
      if (value) ranges.set(name, value);
    }
  }
  return ranges;
}

function scopeForSection(section: PackageSection): DependencyScope {
  switch (section) {
    case 'dependencies':
      return 'direct';
    case 'devDependencies':
      return 'dev';
    case 'peerDependencies':
      return 'peer';
    case 'optionalDependencies':
      return 'optional';
  }
}

function lockScope(pkg: Record<string, unknown>): DependencyScope {
  if (pyTruthy(pyGet(pkg, 'dev'))) return 'dev';
  if (pyTruthy(pyGet(pkg, 'peer'))) return 'peer';
  if (pyTruthy(pyGet(pkg, 'optional'))) return 'optional';
  return 'transitive';
}

function licensesOf(pkg: Record<string, unknown>): string[] {
  const licenseValue = pyGet(pkg, 'license');
  if (typeof licenseValue === 'string' && licenseValue) return [licenseValue];
  if (Array.isArray(licenseValue)) return licenseValue.filter(pyTruthy).map(pyStr);
  return [];
}

function isExactVersion(version: string): boolean {
  return EXACT_VERSION_RE.test(pyStrip(version));
}

// ---------------------------------------------------------------------------
// REQ-011 P-39: pnpm-lock.yaml (v6, v9), bun.lock, bun.lockb
// ---------------------------------------------------------------------------

/** Longest accepted package name / version of the new lock formats (same bounds as the parser kit). */
const EXTRA_MAX_NAME_LENGTH = 512;
const EXTRA_MAX_VERSION_LENGTH = 256;

/** Local references (workspace members, linked folders, local tarballs): not registry packages, skipped. */
const LOCAL_REF_PREFIXES: readonly string[] = ['link:', 'file:', 'workspace:', 'portal:', 'root:'];

/** pnpm importer sections; the first section naming a package decides its scope. */
const PNPM_IMPORTER_SECTIONS: ReadonlyArray<readonly [string, DependencyScope]> = [
  ['dependencies', 'direct'],
  ['optionalDependencies', 'optional'],
  ['devDependencies', 'dev'],
];

/** bun.lock root workspace sections (same scopes as the package.json sections). */
const BUN_WORKSPACE_SECTIONS: ReadonlyArray<readonly [string, DependencyScope]> = [
  ['dependencies', 'direct'],
  ['devDependencies', 'dev'],
  ['optionalDependencies', 'optional'],
  ['peerDependencies', 'peer'],
];

interface ExtraLockResult {
  dependencies: ScannedDependency[];
  /** Lock `integrity` value of each dependency (same index; L-5 side channel). */
  integrities: unknown[];
  /** At least one entry was skipped as invalid (one fixed record per file). */
  invalid: boolean;
}

/** Scope and declared range of a package the root project names itself. */
interface DeclaredEntry {
  scope: DependencyScope;
  specifier: string | null;
}

/** Spec file (REQ-011 D-304) next to `packageJson`; a linked or missing file gives undefined. */
function extraLockFile(walk: TreeWalk, packageJson: WalkedFile, name: string): WalkedFile | undefined {
  return walk.specByDir?.get('nodejs')?.get(packageJson.relDir)?.get(name);
}

function extraLockError(file: WalkedFile, message: string): ParseErrorRecord {
  return { ecosystem: 'nodejs', file: file.relPath, error: message };
}

/** Fixed text of a new-format failure (AC-P40-3): never a library message, never a path. */
function extraLockMessage(err: unknown, file: WalkedFile): string {
  if (err instanceof ParserFileError) return err.message;
  if (err instanceof ManifestReadError) {
    const prefix = `${file.relPath}: `;
    return err.message.startsWith(prefix) ? err.message.slice(prefix.length) : PARSER_MESSAGES.structure;
  }
  if (err instanceof YamlSubsetError) return err.code === 'unsupported' ? PARSER_MESSAGES.yamlUnsupported : PARSER_MESSAGES.yaml;
  if (err instanceof SyntaxError) return PARSER_MESSAGES.json;
  return PARSER_MESSAGES.structure;
}

/**
 * Reads one new-format lock file. Success: its `scan_files` record is added
 * and the entries are returned. Failure: one fixed-text record for the file
 * and null (the caller then uses package.json alone).
 */
function readExtraLock(
  file: WalkedFile,
  result: ParseResult,
  collector: IntegrityCollector | undefined,
  parse: (data: Buffer, file: WalkedFile) => ExtraLockResult,
): ScannedDependency[] | null {
  try {
    const { data, record } = readManifest(file, 'nodejs');
    const parsed = parse(data, file);
    result.scan_files.push(record);
    if (parsed.invalid) result.parse_errors.push(extraLockError(file, PARSER_MESSAGES.invalidEntry));
    // L-5 records only for a file that was read completely.
    parsed.dependencies.forEach((dep, i) => collectIntegrity(collector, dep, parsed.integrities[i]));
    return parsed.dependencies;
  } catch (err) {
    result.parse_errors.push(extraLockError(file, extraLockMessage(err, file)));
    return null;
  }
}

/** Strict UTF-8 text without a leading BOM. */
function lockText(data: Buffer, file: WalkedFile): string {
  const text = decodeStrict(data, file.relPath);
  return text.startsWith('﻿') ? text.slice(1) : text;
}

/** Own property of a parsed document (never an inherited one such as `constructor`). */
function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** A mapping, or null when absent; any other type is a structure error. */
function optionalDict(value: unknown): Record<string, unknown> | null {
  if (value === undefined || value === null) return null;
  if (!isPyDict(value)) throw new ParserFileError(PARSER_MESSAGES.structure);
  return value;
}

function hasControlOrSpace(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x20 || (c >= 0x7f && c <= 0x9f) || isPyWhitespace(c)) return true;
  }
  return false;
}

function validExtraEntry(name: string, ref: string): boolean {
  return (
    name !== '' &&
    name.length <= EXTRA_MAX_NAME_LENGTH &&
    !hasControlOrSpace(name) &&
    ref !== '' &&
    ref.length <= EXTRA_MAX_VERSION_LENGTH &&
    !hasControlOrSpace(ref) &&
    !hasLoneSurrogate(name) &&
    !hasLoneSurrogate(ref)
  );
}

function isLocalRef(ref: string): boolean {
  return LOCAL_REF_PREFIXES.some((prefix) => ref.startsWith(prefix));
}

/** `name@version` -> [name, version]; a scoped name keeps its leading `@`. Null without both parts. */
function splitNameAtVersion(text: string): [string, string] | null {
  const at = text.indexOf('@', text.startsWith('@') ? 1 : 0);
  if (at <= 0 || at === text.length - 1) return null;
  return [text.slice(0, at), text.slice(at + 1)];
}

/** Drops pnpm's peer suffix: `18.2.0(react@18.2.0)` -> `18.2.0`. */
function withoutPeerSuffix(ref: string): string {
  const paren = ref.indexOf('(');
  return paren === -1 ? ref : ref.slice(0, paren);
}

/**
 * Snapshot key of a pnpm v9 reference: `1.2.3(peer@1)` -> `name@1.2.3(peer@1)`;
 * an npm alias (`real@1.2.3`) is already a key. Null for a local reference.
 */
function pnpmRefKey(name: string, ref: string): string | null {
  if (isLocalRef(ref)) return null;
  const base = withoutPeerSuffix(ref);
  return base.indexOf('@', base.startsWith('@') ? 1 : 0) > 0 ? ref : `${name}@${ref}`;
}

/**
 * pnpm v6 package path -> [name, version]: `/name@1.2.3(peer@1)` (v6) or
 * `/name/1.2.3_peer@1` (older path form); scoped names (`/@scope/name...`)
 * included. Null when neither form matches.
 */
function pnpmV6Key(key: string): [string, string] | null {
  const path = withoutPeerSuffix(key.startsWith('/') ? key.slice(1) : key);
  let from = 0;
  if (path.startsWith('@')) {
    const slash = path.indexOf('/');
    if (slash <= 1) return null;
    from = slash + 1;
  }
  for (let i = from + 1; i < path.length; i++) {
    const c = path[i];
    if (c !== '@' && c !== '/') continue;
    let version = path.slice(i + 1);
    if (c === '/') {
      const underscore = version.indexOf('_');
      if (underscore !== -1) version = version.slice(0, underscore);
    }
    return version === '' ? null : [path.slice(0, i), version];
  }
  return null;
}

/** Package id (`name@version`, no peer suffix) of an importer reference; null for a local one. */
function pnpmImporterId(name: string, ref: string, v6: boolean): string | null {
  if (v6 && ref.startsWith('/')) {
    const parsed = pnpmV6Key(ref);
    return parsed ? `${parsed[0]}@${parsed[1]}` : null;
  }
  const key = pnpmRefKey(name, ref);
  return key === null ? null : withoutPeerSuffix(key);
}

/** Snapshot keys of the packages an importer section names (v9 reachability roots). */
function pnpmSectionKeys(importer: Record<string, unknown>, sections: readonly string[]): string[] {
  const keys: string[] = [];
  for (const section of sections) {
    const entries = optionalDict(own(importer, section));
    if (!entries) continue;
    for (const [name, spec] of Object.entries(entries)) {
      const ref = isPyDict(spec) ? own(spec, 'version') : spec;
      const key = typeof ref === 'string' ? pnpmRefKey(name, ref) : null;
      if (key !== null) keys.push(key);
    }
  }
  return keys;
}

/** Package ids reachable from `roots` through the v9 `snapshots` graph (iterative, each key once). */
function pnpmReachable(snapshots: Record<string, unknown>, roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const ids = new Set<string>();
  const stack = [...roots];
  while (stack.length > 0) {
    const key = stack.pop() as string;
    if (seen.has(key)) continue;
    seen.add(key);
    ids.add(withoutPeerSuffix(key));
    const snapshot = own(snapshots, key);
    if (!isPyDict(snapshot)) continue;
    for (const section of ['dependencies', 'optionalDependencies']) {
      const deps = own(snapshot, section);
      if (!isPyDict(deps)) continue;
      for (const [name, ref] of Object.entries(deps)) {
        const next = typeof ref === 'string' ? pnpmRefKey(name, ref) : null;
        if (next !== null && !seen.has(next)) stack.push(next);
      }
    }
  }
  return ids;
}

/** v6 `dev` / `optional` flags of a package (as `lockScope` for package-lock.json). */
function pnpmV6Scope(value: unknown): DependencyScope {
  if (!isPyDict(value)) return 'transitive';
  if (own(value, 'dev') === true) return 'dev';
  if (own(value, 'optional') === true) return 'optional';
  return 'transitive';
}

/**
 * `pnpm-lock.yaml` v6 (`lockfileVersion: '6.x'`, `packages` keys
 * `/name@version(peer)` or `/name/version`) and v9 (`'9.x'`, `importers` +
 * `packages` keys `name@version` + `snapshots`). Every registry package gets
 * its exact version (peer suffix dropped). Scope: the root importer (`.`;
 * v6 without workspaces: the top level) gives `direct` / `optional` / `dev`
 * and the declared range (`specifier`); other packages are `dev` when only
 * development roots reach them (v6: pnpm's `dev: true`; v9: the snapshot
 * graph from the dev and production roots of all importers), else
 * `transitive`. Local packages (`link:`, `file:`) are skipped.
 */
function dependenciesFromPnpmLock(data: Buffer, file: WalkedFile, manifestPath: string): ExtraLockResult {
  const lock = parseYamlSubset(lockText(data, file));
  if (!isPyDict(lock)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const lockfileVersion = own(lock, 'lockfileVersion');
  const major = typeof lockfileVersion === 'string' ? lockfileVersion.split('.', 1)[0] : '';
  if (major !== '6' && major !== '9') throw new ParserFileError(PARSER_MESSAGES.unsupportedVersion);
  const v6 = major === '6';

  const importers = optionalDict(own(lock, 'importers'));
  const rootImporter = importers ? optionalDict(own(importers, '.')) : v6 ? lock : null;
  const declared = new Map<string, DeclaredEntry>();
  if (rootImporter) {
    for (const [section, scope] of PNPM_IMPORTER_SECTIONS) {
      const entries = optionalDict(own(rootImporter, section));
      if (!entries) continue;
      for (const [name, spec] of Object.entries(entries)) {
        const ref = isPyDict(spec) ? own(spec, 'version') : spec;
        const specifier = isPyDict(spec) ? own(spec, 'specifier') : null;
        const id = typeof ref === 'string' ? pnpmImporterId(name, ref, v6) : null;
        if (id === null || declared.has(id)) continue;
        const range = typeof specifier === 'string' ? pyStrip(specifier) : '';
        declared.set(id, { scope, specifier: range === '' ? null : range });
      }
    }
  }

  let devOnly: (id: string) => boolean = () => false;
  if (!v6) {
    const snapshots = optionalDict(own(lock, 'snapshots')) ?? {};
    const prodRoots: string[] = [];
    const devRoots: string[] = [];
    for (const importer of importers ? Object.values(importers) : []) {
      if (!isPyDict(importer)) continue;
      prodRoots.push(...pnpmSectionKeys(importer, ['dependencies', 'optionalDependencies']));
      devRoots.push(...pnpmSectionKeys(importer, ['devDependencies']));
    }
    const prod = pnpmReachable(snapshots, prodRoots);
    const dev = pnpmReachable(snapshots, devRoots);
    devOnly = (id) => dev.has(id) && !prod.has(id);
  }

  const dependencies: ScannedDependency[] = [];
  const integrities: unknown[] = [];
  let invalid = false;
  for (const [key, value] of Object.entries(optionalDict(own(lock, 'packages')) ?? {})) {
    let name: string;
    let ref: string;
    if (v6 && !key.startsWith('/')) {
      // Git / tarball package: the key is its source, `name` is in the entry; no registry version.
      const entryName = isPyDict(value) ? own(value, 'name') : undefined;
      if (typeof entryName !== 'string') {
        invalid ||= !isLocalRef(key);
        continue;
      }
      name = entryName;
      ref = key;
    } else {
      const parsed = v6 ? pnpmV6Key(key) : splitNameAtVersion(key);
      if (!parsed) {
        invalid = true;
        continue;
      }
      [name, ref] = parsed;
      ref = withoutPeerSuffix(ref);
    }
    if (isLocalRef(ref)) continue;
    if (!validExtraEntry(name, ref)) {
      invalid = true;
      continue;
    }
    const id = `${name}@${ref}`;
    const entry = declared.get(id);
    const scope = entry?.scope ?? (v6 ? pnpmV6Scope(value) : devOnly(id) ? 'dev' : 'transitive');
    dependencies.push(dependency(name, ref, manifestPath, 'pnpm-lock.yaml', scope, null, entry?.specifier ?? null));
    const resolution = isPyDict(value) ? own(value, 'resolution') : undefined;
    integrities.push(isPyDict(resolution) ? own(resolution, 'integrity') : undefined);
  }
  return { dependencies, integrities, invalid };
}

/**
 * JSONC -> JSON for `bun.lock` without evaluating anything: `//` and
 * `/* *\/` comments outside strings are removed (a block comment becomes a
 * space, so it never joins two tokens), then every comma followed only by
 * whitespace and `}` / `]` is dropped. Two linear passes; strings (with
 * escapes) are copied untouched. An unterminated block comment is a syntax
 * error.
 */
function stripJsonc(text: string): string {
  const withoutComments: string[] = [];
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      i = skipJsonString(text, i);
      continue;
    }
    if (c === 0x2f && text.charCodeAt(i + 1) === 0x2f) {
      withoutComments.push(text.slice(start, i));
      const newline = text.indexOf('\n', i + 2);
      i = newline === -1 ? text.length : newline;
      start = i;
      continue;
    }
    if (c === 0x2f && text.charCodeAt(i + 1) === 0x2a) {
      withoutComments.push(text.slice(start, i), ' ');
      const end = text.indexOf('*/', i + 2);
      if (end === -1) throw new SyntaxError('unterminated comment');
      i = end + 2;
      start = i;
      continue;
    }
    i++;
  }
  withoutComments.push(text.slice(start));
  const json = withoutComments.join('');

  const out: string[] = [];
  start = 0;
  i = 0;
  while (i < json.length) {
    const c = json.charCodeAt(i);
    if (c === 0x22) {
      i = skipJsonString(json, i);
      continue;
    }
    if (c === 0x2c) {
      let j = i + 1;
      while (j < json.length && isJsonSpace(json.charCodeAt(j))) j++;
      const next = json.charCodeAt(j);
      if (next === 0x7d || next === 0x5d) {
        out.push(json.slice(start, i));
        start = i + 1;
      }
      i = j;
      continue;
    }
    i++;
  }
  out.push(json.slice(start));
  return out.join('');
}

/** Index after the JSON string starting at `start` (the opening quote); the text end when unterminated. */
function skipJsonString(text: string, start: number): number {
  let i = start + 1;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x5c) {
      i += 2;
      continue;
    }
    i++;
    if (c === 0x22) return i;
  }
  return text.length;
}

function isJsonSpace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d;
}

/**
 * `bun.lock` (Bun >= 1.2 text lock, `lockfileVersion` 0 or 1): every entry
 * of `packages` is `key: ["name@version", ...]`. The root workspace (`""`)
 * names its packages by the top-level key: those get the section scope and
 * range; nested keys (`parent/name`) and everything else are `transitive`.
 * Workspace, link and file packages are skipped.
 */
function dependenciesFromBunLock(data: Buffer, file: WalkedFile, manifestPath: string): ExtraLockResult {
  const lock: unknown = JSON.parse(stripJsonc(lockText(data, file)));
  if (!isPyDict(lock)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const lockfileVersion = own(lock, 'lockfileVersion');
  if (lockfileVersion !== 0 && lockfileVersion !== 1) throw new ParserFileError(PARSER_MESSAGES.unsupportedVersion);

  const workspaces = optionalDict(own(lock, 'workspaces'));
  const rootWorkspace = workspaces ? optionalDict(own(workspaces, '')) : null;
  const declared = new Map<string, DeclaredEntry>();
  if (rootWorkspace) {
    for (const [section, scope] of BUN_WORKSPACE_SECTIONS) {
      const entries = optionalDict(own(rootWorkspace, section));
      if (!entries) continue;
      for (const [name, range] of Object.entries(entries)) {
        if (declared.has(name)) continue;
        const specifier = typeof range === 'string' ? pyStrip(range) : '';
        declared.set(name, { scope, specifier: specifier === '' ? null : specifier });
      }
    }
  }

  const dependencies: ScannedDependency[] = [];
  const integrities: unknown[] = [];
  let invalid = false;
  for (const [key, value] of Object.entries(optionalDict(own(lock, 'packages')) ?? {})) {
    const ident: unknown = Array.isArray(value) ? value[0] : undefined;
    const parsed = typeof ident === 'string' ? splitNameAtVersion(ident) : null;
    if (!parsed) {
      invalid = true;
      continue;
    }
    const [name, ref] = parsed;
    if (isLocalRef(ref)) continue;
    if (!validExtraEntry(name, ref)) {
      invalid = true;
      continue;
    }
    const entry = declared.get(key);
    dependencies.push(dependency(name, ref, manifestPath, 'bun.lock', entry?.scope ?? 'transitive', null, entry?.specifier ?? null));
    // npm entries are [ident, registry, info, integrity].
    integrities.push(Array.isArray(value) ? value[3] : undefined);
  }
  return { dependencies, integrities, invalid };
}
