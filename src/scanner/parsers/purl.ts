/**
 * Package URL builders of the REQ-011 ecosystems (P-42, AC-P42-1; purl-spec
 * PURL-TYPES), plus the dispatcher every parser-kit dependency goes through.
 *
 * Encoding: each namespace segment, the name and the version are
 * percent-encoded with the same rule as the npm/PyPI builders (`pyQuote`:
 * UTF-8, `A-Z a-z 0-9 _ . - ~` kept, everything else `%XX`), so `+` in a
 * version becomes `%2B` everywhere. An empty or null version gives a
 * versionless purl (ADR-003 a: a version only when it is exact).
 *
 * | ecosystem | package name in `ScannedDependency.name` | purl |
 * | --- | --- | --- |
 * | java  | `group:artifact`                 | `pkg:maven/<group>/<artifact>@v` |
 * | go    | module path (`github.com/a/b`)   | `pkg:golang/<module path>@v` (case kept) |
 * | php   | `vendor/name`                    | `pkg:composer/<vendor>/<name>@v` (lower case) |
 * | rust  | crate name                       | `pkg:cargo/<name>@v` |
 * | ruby  | gem name                         | `pkg:gem/<name>@v` |
 * | dart  | package name                     | `pkg:pub/<name>@v` (lower case) |
 * | swift | `host/owner/repo` identity       | `pkg:swift/<host>/<owner>/<repo>@v` |
 *
 * A name that does not have the required shape (for example a Maven name
 * without `:`) throws `PurlError`; the parser kit then drops the entry with
 * the fixed "invalid entries skipped" record.
 *
 * Imports only `./` modules (ADR-005 Karar 1 boundary).
 */
import type { ScanEcosystem } from '../../types/scan';
import { npmPurl, pyQuote, pypiPurl } from './common';
import { asciiLower, nugetPurl } from './nugetIdentity';

/** A package name that cannot form a purl of its ecosystem (fixed message, no input text). */
export class PurlError extends Error {
  constructor() {
    super('Paket adı bu ekosistemin PURL biçimine uymuyor.');
    this.name = 'PurlError';
  }
}

function encodeSegments(segments: readonly string[]): string {
  if (segments.length === 0 || segments.some((segment) => segment === '')) throw new PurlError();
  return segments.map((segment) => pyQuote(segment, '')).join('/');
}

function withVersion(base: string, version: string | null): string {
  return version ? `${base}@${pyQuote(version, '')}` : base;
}

/** `group:artifact` -> `pkg:maven/<group>/<artifact>[@version]` (D-308). */
export function mavenPurl(name: string, version: string | null): string {
  const colon = name.indexOf(':');
  if (colon <= 0 || colon === name.length - 1 || name.indexOf(':', colon + 1) !== -1) throw new PurlError();
  return withVersion(`pkg:maven/${encodeSegments([name.slice(0, colon), name.slice(colon + 1)])}`, version);
}

/** Go module path -> `pkg:golang/<segments>[@version]`; the module path case is kept (no `!` case-encoding). */
export function golangPurl(modulePath: string, version: string | null): string {
  return withVersion(`pkg:golang/${encodeSegments(modulePath.split('/'))}`, version);
}

/** `vendor/name` -> `pkg:composer/<vendor>/<name>[@version]`, ASCII lower case (Packagist names are case-insensitive). */
export function composerPurl(name: string, version: string | null): string {
  const segments = asciiLower(name).split('/');
  if (segments.length !== 2) throw new PurlError();
  return withVersion(`pkg:composer/${encodeSegments(segments)}`, version);
}

/** Crate name -> `pkg:cargo/<name>[@version]`. */
export function cargoPurl(name: string, version: string | null): string {
  if (name.includes('/')) throw new PurlError();
  return withVersion(`pkg:cargo/${encodeSegments([name])}`, version);
}

/** Gem name -> `pkg:gem/<name>[@version]`. */
export function gemPurl(name: string, version: string | null): string {
  if (name.includes('/')) throw new PurlError();
  return withVersion(`pkg:gem/${encodeSegments([name])}`, version);
}

/** Dart package name -> `pkg:pub/<name>[@version]`, ASCII lower case. */
export function pubPurl(name: string, version: string | null): string {
  if (name.includes('/')) throw new PurlError();
  return withVersion(`pkg:pub/${encodeSegments([asciiLower(name)])}`, version);
}

/** `host/owner/repo` (at least three segments) -> `pkg:swift/<host>/<owner>/<repo>[@version]`. */
export function swiftPurl(identity: string, version: string | null): string {
  const segments = identity.split('/');
  if (segments.length < 3) throw new PurlError();
  return withVersion(`pkg:swift/${encodeSegments(segments)}`, version);
}

/**
 * SwiftPM repository location (`Package.resolved` `location` / `repositoryURL`)
 * -> `host/owner/repo` identity, or null for a local path or an unusable URL.
 * Accepts `https://`, `http://`, `ssh://` and scp-like `git@host:owner/repo`;
 * drops user info, a port, a trailing `/` and `.git`; the host is lower-cased.
 * This identity is also the OSV `SwiftURL` package name (ADR-012 Karar 2).
 */
export function swiftPackageIdentity(location: string): string | null {
  let rest = location.trim();
  if (rest === '' || rest.length > 512 || /[\s?#\\]/.test(rest)) return null;
  const scheme = /^(https?|ssh|git):\/\//i.exec(rest);
  if (scheme) {
    rest = rest.slice(scheme[0].length);
  } else {
    // scp-like `user@host:owner/repo`; anything else (a path, `file://`) is not a registry package.
    const scp = /^[^/@:]+@([^/:]+):(.+)$/.exec(rest);
    if (!scp) return null;
    rest = `${scp[1]}/${scp[2]}`;
  }
  const at = rest.indexOf('@');
  const slash = rest.indexOf('/');
  if (at !== -1 && (slash === -1 || at < slash)) rest = rest.slice(at + 1);
  const firstSlash = rest.indexOf('/');
  if (firstSlash <= 0) return null;
  let host = asciiLower(rest.slice(0, firstSlash));
  const colon = host.indexOf(':');
  if (colon !== -1) host = host.slice(0, colon);
  let path = rest.slice(firstSlash + 1);
  while (path.endsWith('/')) path = path.slice(0, -1);
  if (asciiLower(path).endsWith('.git')) path = path.slice(0, -4);
  const segments = path.split('/');
  if (host === '' || !/^[a-z0-9.-]+$/.test(host) || segments.length < 2 || segments.some((s) => s === '' || s === '.' || s === '..')) return null;
  return `${host}/${segments.join('/')}`;
}

/**
 * purl of a dependency of a supported ecosystem (the parser kit calls it for
 * every entry; ADR-003 a: pass `null` unless the version is exact).
 */
export function purlFor(ecosystem: ScanEcosystem, name: string, version: string | null): string {
  switch (ecosystem) {
    case 'nodejs':
      return npmPurl(name, version);
    case 'python':
      return pypiPurl(name, version);
    case 'dotnet':
      return nugetPurl(name, version);
    case 'java':
      return mavenPurl(name, version);
    case 'go':
      return golangPurl(name, version);
    case 'php':
      return composerPurl(name, version);
    case 'rust':
      return cargoPurl(name, version);
    case 'ruby':
      return gemPurl(name, version);
    case 'dart':
      return pubPurl(name, version);
    case 'swift':
      return swiftPurl(name, version);
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported ecosystem: ${String(unreachable)}`);
    }
  }
}
