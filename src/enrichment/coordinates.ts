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
 * Pure module (no imports, ADR-006 Karar 1).
 */

export type RegistryEcosystem = 'npm' | 'pypi';

/** Registry of a project ecosystem, or null when the ecosystem has no registry enrichment. */
export function registryEcosystemOf(ecosystem: string): RegistryEcosystem | null {
  if (ecosystem === 'nodejs') return 'npm';
  if (ecosystem === 'python') return 'pypi';
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

/** Request name: npm as-is (scoped names keep `@scope/name`; the path segment is built by `npmPathSegment`), PyPI PEP 503. */
export function requestName(ecosystem: RegistryEcosystem, name: string): string {
  return ecosystem === 'pypi' ? pep503Name(name) : name;
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
  const validName = registry === 'npm' ? isValidNpmName(name) : isValidPypiName(name);
  if (!validName || !isValidVersion(version)) return { kind: 'invalid_coordinates' };
  return { kind: 'ok', ecosystem: registry, requestName: requestName(registry, name), version };
}

/** In-process key of one registry identity (dedupe map, outcome map). */
export function coordinateKey(ecosystem: RegistryEcosystem, requestName: string, version: string): string {
  return `${ecosystem}\u0000${requestName}\u0000${version}`;
}
