/**
 * Registry coordinates of a scanned package (REQ-004 AC-P14-4, AC-P14-5;
 * ADR-006 Karar 1, 3).
 *
 * - ecosystem mapping: project ecosystem `nodejs` -> registry `npm`,
 *   `python` -> `pypi`;
 * - name/version validation before any request (`invalid_coordinates`);
 * - request names: npm scoped `@scope%2Fname` (one path segment), PyPI
 *   PEP 503 (lower case; runs of `-`, `_`, `.` -> `-`). Used for the request
 *   and the cache key only; `packages.purl` and fingerprints are unchanged.
 *
 * - NuGet (REQ-006, ADR-008 Karar 8): `dotnet` -> `nuget`; id and version
 *   follow `nugetIdentity.ts` (the only parser-folder import allowed here);
 *   the request name and version are ASCII lower case.
 *
 * - deps.dev / pub.dev (REQ-011 P-43, ADR-012 Karar 3, D-317): `java`,
 *   `go`, `rust`, `ruby` -> `depsdev` (one origin, four deps.dev systems);
 *   `dart` -> `pubdev`. The deps.dev request name carries its system:
 *   `MAVEN:group:artifact`, `GO:module/path`, `CARGO:crate`, `RUBYGEMS:gem`
 *   (also the `registry_package_cache.name` value, so a crate and a gem of
 *   the same name never share a cache row); pub.dev names as they are.
 *   `php` (license from `composer.lock`, D-319) and `swift` (no source,
 *   D-320) have no registry: `registryEcosystemOf` returns null and the
 *   worker records them through `noRegistryEcosystem` (status `disabled`).
 *
 * Pure module (only the pure NuGet identity rules, ADR-008 Karar 1).
 */
import { asciiLower, classifyNugetVersion, isValidNugetId } from '../scanner/parsers/nugetIdentity';

export { asciiLower, classifyNugetVersion, isValidNugetId } from '../scanner/parsers/nugetIdentity';

export type RegistryEcosystem = 'npm' | 'pypi' | 'nuget' | 'depsdev' | 'pubdev';

/** deps.dev system of a project ecosystem (REQ-011 AC-P43-1). */
export type DepsDevSystem = 'MAVEN' | 'GO' | 'CARGO' | 'RUBYGEMS';

export const DEPSDEV_SYSTEM_OF_PROJECT: Readonly<Record<string, DepsDevSystem>> = Object.freeze({
  java: 'MAVEN',
  go: 'GO',
  rust: 'CARGO',
  ruby: 'RUBYGEMS',
});

const DEPSDEV_SYSTEMS: ReadonlySet<string> = new Set(Object.values(DEPSDEV_SYSTEM_OF_PROJECT));

/**
 * Project ecosystems that are scanned but have no registry license source
 * (REQ-011 D-319 PHP: `composer.lock` license; D-320 Swift: none). The
 * worker stores them with status `disabled` ("no enricher", contract 4.2),
 * so a lock hint becomes `lockfile (unverified)` and a row is never the
 * pre-F3 `NULL`/`NULL` pair.
 */
export const NO_REGISTRY_ECOSYSTEMS: ReadonlySet<string> = new Set(['php', 'swift']);

/** True for a scanned ecosystem without a registry license source (`php`, `swift`). */
export function noRegistryEcosystem(ecosystem: string): boolean {
  return NO_REGISTRY_ECOSYSTEMS.has(ecosystem);
}

/** Registry of a project ecosystem, or null when the ecosystem has no registry enrichment. */
export function registryEcosystemOf(ecosystem: string): RegistryEcosystem | null {
  if (ecosystem === 'nodejs') return 'npm';
  if (ecosystem === 'python') return 'pypi';
  if (ecosystem === 'dotnet') return 'nuget';
  if (Object.prototype.hasOwnProperty.call(DEPSDEV_SYSTEM_OF_PROJECT, ecosystem)) return 'depsdev';
  if (ecosystem === 'dart') return 'pubdev';
  return null;
}

const NPM_MAX_NAME = 214;
const VERSION_MAX = 128;
const PYPI_NAME_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;
// URL-safe characters of one npm name component (encodeURIComponent leaves them as is).
const NPM_COMPONENT_RE = /^[A-Za-z0-9\-._~!'()*]+$/;

function validNpmComponent(component: string): boolean {
  return component.length > 0 && NPM_COMPONENT_RE.test(component) && !component.startsWith('.') && !component.startsWith('_');
}

/** npm name rule of AC-P14-4: <= 214 characters, `@scope/name` or `name`, URL-safe components, no leading `.`/`_`. */
export function isValidNpmName(name: string): boolean {
  if (typeof name !== 'string' || name.length === 0 || name.length > NPM_MAX_NAME) return false;
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash === -1 || name.indexOf('/', slash + 1) !== -1) return false;
    return validNpmComponent(name.slice(1, slash)) && validNpmComponent(name.slice(slash + 1));
  }
  return !name.includes('/') && validNpmComponent(name);
}

/** PyPI name rule of AC-P14-4. */
export function isValidPypiName(name: string): boolean {
  return typeof name === 'string' && PYPI_NAME_RE.test(name);
}

const NEW_NAME_MAX = 512;
// Same linear patterns as the OSV coordinate (`src/vulnerability/osvCoordinates.ts`, REQ-011 AC-P41-1).
const MAVEN_NAME_RE = /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/;
const GO_MODULE_RE = /^[A-Za-z0-9][A-Za-z0-9_~+-]*(?:\.[A-Za-z0-9_~+-]+)+(?:\/[A-Za-z0-9._~+-]+)*$/;
const CRATE_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const GEM_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;
const PUB_NAME_RE = /^[a-z0-9_]{1,64}$/;

/** Package name rule of one deps.dev system (REQ-011): Maven `group:artifact`, Go module path, crate, gem. */
export function isValidDepsDevName(system: DepsDevSystem, name: string): boolean {
  if (typeof name !== 'string' || name.length === 0 || name.length > NEW_NAME_MAX) return false;
  switch (system) {
    case 'MAVEN':
      return MAVEN_NAME_RE.test(name);
    case 'GO':
      return GO_MODULE_RE.test(name) && !name.split('/').some((segment) => segment === '.' || segment === '..');
    case 'CARGO':
      return CRATE_NAME_RE.test(name);
    case 'RUBYGEMS':
      return GEM_NAME_RE.test(name);
    default: {
      const unreachable: never = system;
      throw new Error(`unsupported deps.dev system: ${String(unreachable)}`);
    }
  }
}

/** pub.dev package name rule (lower-case letters, digits, `_`). */
export function isValidPubName(name: string): boolean {
  return typeof name === 'string' && PUB_NAME_RE.test(name);
}

/** deps.dev request name `SYSTEM:name` (also the cache row name). */
export function depsDevRequestName(system: DepsDevSystem, name: string): string {
  return `${system}:${name}`;
}

/** `[system, name]` of a deps.dev request name, or null when it does not start with a known system. */
export function splitDepsDevRequestName(requestName: string): [DepsDevSystem, string] | null {
  const colon = requestName.indexOf(':');
  if (colon <= 0) return null;
  const system = requestName.slice(0, colon);
  return DEPSDEV_SYSTEMS.has(system) ? [system as DepsDevSystem, requestName.slice(colon + 1)] : null;
}

/** Version rule of AC-P14-4: <= 128 characters; no `/`, `\`, `?`, `#`, `%`, whitespace, control character or `..`. */
export function isValidVersion(version: string): boolean {
  if (typeof version !== 'string' || version.length === 0 || version.length > VERSION_MAX) return false;
  if (version.includes('..')) return false;
  for (let i = 0; i < version.length; i++) {
    const c = version.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f)) return false;
    if (c === 0x2f || c === 0x5c || c === 0x3f || c === 0x23 || c === 0x25) return false;
    if (/\s/.test(version[i])) return false;
  }
  return true;
}

/** PEP 503 normalized name. */
export function pep503Name(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * Request name: npm as-is (scoped names keep `@scope/name`; the path segment
 * is built by `npmPathSegment`), PyPI PEP 503, NuGet ASCII lower case,
 * pub.dev as-is. deps.dev: `name` must already be the `SYSTEM:name` form
 * (`registryRequestName` / `checkCoordinates` build it from the project
 * ecosystem); it is returned unchanged.
 */
export function requestName(ecosystem: RegistryEcosystem, name: string): string {
  // Exhaustive (ADR-008 Karar 1): a new registry is a compile error here, never a silent default.
  switch (ecosystem) {
    case 'npm':
      return name;
    case 'pypi':
      return pep503Name(name);
    case 'nuget':
      return asciiLower(name);
    case 'depsdev':
    case 'pubdev':
      return name;
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported registry ecosystem: ${String(unreachable)}`);
    }
  }
}

/**
 * Request name of a package of a project ecosystem (deps.dev names get
 * their `SYSTEM:` prefix), or null when the ecosystem has no registry.
 */
export function registryRequestName(ecosystem: string, name: string): string | null {
  const registry = registryEcosystemOf(ecosystem);
  if (registry === null) return null;
  if (registry === 'depsdev') return depsDevRequestName(DEPSDEV_SYSTEM_OF_PROJECT[ecosystem], name);
  return requestName(registry, name);
}

function isValidRegistryName(ecosystem: RegistryEcosystem, name: string): boolean {
  switch (ecosystem) {
    case 'npm':
      return isValidNpmName(name);
    case 'pypi':
      return isValidPypiName(name);
    case 'nuget':
      return isValidNugetId(name);
    case 'pubdev':
      return isValidPubName(name);
    case 'depsdev': {
      const split = splitDepsDevRequestName(name);
      return split !== null && isValidDepsDevName(split[0], split[1]);
    }
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported registry ecosystem: ${String(unreachable)}`);
    }
  }
}

/** npm request path segment: `@scope%2Fname` for scoped names, the name itself otherwise (AC-P14-5). */
export function npmPathSegment(name: string): string {
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

export type CoordinateCheck =
  | { kind: 'ok'; ecosystem: RegistryEcosystem; requestName: string; version: string }
  | { kind: 'version_unknown' }
  | { kind: 'invalid_coordinates' }
  | { kind: 'unsupported' };

/** Classifies a package before any request (AC-P14-4): unsupported ecosystem, unknown version, invalid name/version, or its request coordinates. */
export function checkCoordinates(ecosystem: string, name: string, version: string | null | undefined): CoordinateCheck {
  const registry = registryEcosystemOf(ecosystem);
  if (registry === null) return { kind: 'unsupported' };
  if (version === null || version === undefined) return { kind: 'version_unknown' };
  if (registry === 'nuget') {
    // ADR-008 Karar 8: valid id, an exact normalized version and the F3 version rule; both ASCII lower case.
    const classified = classifyNugetVersion(version);
    if (!isValidNugetId(name) || classified.kind !== 'exact' || !isValidVersion(classified.version)) return { kind: 'invalid_coordinates' };
    return { kind: 'ok', ecosystem: 'nuget', requestName: asciiLower(name), version: asciiLower(classified.version) };
  }
  // deps.dev: validated and keyed as `SYSTEM:name` (REQ-011 AC-P43-1).
  const candidate = registry === 'depsdev' ? depsDevRequestName(DEPSDEV_SYSTEM_OF_PROJECT[ecosystem], name) : name;
  const validName = isValidRegistryName(registry, candidate);
  if (!validName || !isValidVersion(version)) return { kind: 'invalid_coordinates' };
  return { kind: 'ok', ecosystem: registry, requestName: requestName(registry, candidate), version };
}

/** In-process key of one registry identity (dedupe map, outcome map). */
export function coordinateKey(ecosystem: RegistryEcosystem, requestName: string, version: string): string {
  return `${ecosystem}\u0000${requestName}\u0000${version}`;
}
