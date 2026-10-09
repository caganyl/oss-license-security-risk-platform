/**
 * npm parser: `package.json`, `package-lock.json` (v1 `dependencies` tree,
 * v2/v3 `packages` map) and Yarn v1 `yarn.lock`. Line-by-line port of
 * the legacy Python `nodejs.py` (frozen as golden output, REQ-003 D-26;
 * P-10, ADR-005 Karar 2, 4).
 */
import type { DependencyScope, ScannedDependency } from '../../types/scan';
import {
  NODEJS_MANIFEST_NAMES,
  compareCodePoints,
  decodeLenient,
  decodeStrict,
  discoverManifests,
  emptyResult,
  isPyDict,
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
  type ParseResult,
  type TreeWalk,
  type WalkedFile,
} from './common';

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

export function parse(walk: TreeWalk): ParseResult {
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
        locked.push(...dependenciesFromPackageLock(lock.data, lockfile, manifestPath, declaredScopes));
      }

      const yarnLock = siblingFile(walk, packageJson, 'yarn.lock');
      if (yarnLock) {
        const yarn = readManifest(yarnLock, 'nodejs');
        result.scan_files.push(yarn.record);
        locked.push(...dependenciesFromYarnLock(yarn.data, manifestPath, declaredScopes));
      }

      // With a lock file the version comes from the lock, the range from package.json.
      const declaredRanges = declaredRangesOf(packageData);
      for (const dependency of locked) {
        if (dependency.declared_range === null && declaredRanges.has(dependency.name)) {
          dependency.declared_range = declaredRanges.get(dependency.name) as string;
        }
      }
      result.dependencies.push(...locked);

      if (!lockfile && !yarnLock) {
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
        dependencies.push(
          dependency(
            nameText,
            pyStr(version),
            manifestPath,
            'package-lock.json',
            declaredScopes.get(nameText) ?? lockScope(pkg),
            licensesOf(pkg),
          ),
        );
      }
    }
  }

  const legacyDependencies = pyGet(lock, 'dependencies');
  if (isPyDict(legacyDependencies)) {
    dependencies.push(...dependenciesFromLegacyLock(legacyDependencies, manifestPath, declaredScopes));
  }

  return dependencies;
}

function dependenciesFromLegacyLock(
  entries: Record<string, unknown>,
  manifestPath: string,
  declaredScopes: ScopeMap,
  inheritedScope: DependencyScope = 'transitive',
): ScannedDependency[] {
  const dependencies: ScannedDependency[] = [];
  for (const [name, pkg] of Object.entries(entries)) {
    if (!isPyDict(pkg)) continue;
    const version = pyGet(pkg, 'version');
    const scope = declaredScopes.get(name) ?? (pyTruthy(pyGet(pkg, 'dev')) ? 'dev' : inheritedScope);
    if (pyTruthy(version)) {
      dependencies.push(dependency(name, pyStr(version), manifestPath, 'package-lock.json', scope, licensesOf(pkg)));
    }
    const nested = pyGet(pkg, 'dependencies');
    if (isPyDict(nested)) {
      dependencies.push(...dependenciesFromLegacyLock(nested, manifestPath, declaredScopes, scope));
    }
  }
  return dependencies;
}

function dependenciesFromYarnLock(data: Buffer, manifestPath: string, declaredScopes: ScopeMap): ScannedDependency[] {
  const dependencies: ScannedDependency[] = [];
  let currentNames: string[] = [];
  let currentVersion: string | null = null;

  const flush = () => {
    if (currentNames.length > 0 && currentVersion) {
      for (const name of currentNames) {
        dependencies.push(
          dependency(name, currentVersion, manifestPath, 'yarn.lock', declaredScopes.get(name) ?? 'transitive'),
        );
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
      continue;
    }
    const stripped = pyStrip(line);
    if (stripped.startsWith('version ')) {
      const rest = stripped.slice(stripped.indexOf(' ') + 1);
      currentVersion = pyStripChars(pyStrip(rest), '"');
    }
  }
  flush();

  return dependencies;
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
