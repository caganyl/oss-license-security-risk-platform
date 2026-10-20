/**
 * deps.dev license lookup for Go, Maven, Cargo and RubyGems packages
 * (REQ-011 P-43, AC-P43-1, AC-P43-3; ADR-012 Karar 3, D-317).
 *
 * `GET https://api.deps.dev/v3/systems/<SYSTEM>/packages/<name>/versions/<version>`
 * with the name and the version each URL-encoded as ONE path segment
 * (Maven `group:artifact` -> `group%3Aartifact`, Go `github.com/a/b` ->
 * `github.com%2Fa%2Fb`, `+` -> `%2B`). Only the `licenses` field is read:
 * an array of SPDX expressions, one per license deps.dev found for the
 * version. They are combined into one expression with ` AND ` (every listed
 * license applies; compound items are parenthesized); deps.dev's
 * `non-standard` marker (a license it could not map to SPDX) and
 * `NOASSERTION` are dropped. Nothing left -> no declared license (status
 * `no_license`). No archive is downloaded for these ecosystems (D-321).
 *
 * Network access goes through the injected `RegistrySession` only
 * (`metadata-depsdev` purpose: fixed origin, exact path, no redirect, 1 MiB).
 */
import { type DepsDevSystem, coordinateKey, splitDepsDevRequestName } from './coordinates';
import type { RegistrySession } from './registryClient';
import { cleanDeclaredLicense } from './text';
import type { MetadataOutcome } from './types';

/** Maximum `licenses` items read. */
export const MAX_DEPSDEV_LICENSES = 16;

/** deps.dev markers that are not a license (compared case-insensitively). */
const NOT_A_LICENSE: ReadonlySet<string> = new Set(['non-standard', 'noassertion']);

/** Thrown inside extraction when a field has an unexpected type. */
class FieldTypeError extends Error {
  constructor() {
    super('unexpected field type');
    this.name = 'FieldTypeError';
  }
}

/** Request URL of one deps.dev package version (name and version are single encoded path segments). */
export function depsDevVersionUrl(origin: string, system: DepsDevSystem, name: string, version: string): string {
  return `${origin}/v3/systems/${system}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`;
}

/** One SPDX expression from the `licenses` array of a deps.dev version document; null = none. */
export function depsDevDeclaredLicense(doc: Record<string, unknown>): string | null {
  const licenses = doc.licenses;
  if (licenses === undefined || licenses === null) return null;
  if (!Array.isArray(licenses)) throw new FieldTypeError();
  const items: string[] = [];
  for (const item of licenses.slice(0, MAX_DEPSDEV_LICENSES)) {
    if (typeof item !== 'string') continue;
    const cleaned = cleanDeclaredLicense(item.replace(/\s+/g, ' '));
    if (cleaned === null || NOT_A_LICENSE.has(cleaned.toLowerCase())) continue;
    if (!items.includes(cleaned)) items.push(cleaned);
  }
  if (items.length === 0) return null;
  if (items.length === 1) return items[0];
  return cleanDeclaredLicense(items.map((item) => (/\s/.test(item) ? `(${item})` : item)).join(' AND '));
}

/** Metadata of one deps.dev version document; `error` when a field type does not match. */
export function extractDepsDevMetadata(doc: Record<string, unknown>): MetadataOutcome {
  try {
    return { kind: 'found', metadata: { declaredLicense: depsDevDeclaredLicense(doc), licenseText: null, archiveCandidates: [] } };
  } catch (err) {
    if (err instanceof FieldTypeError) return { kind: 'error', code: 'FIELD_TYPE' };
    throw err;
  }
}

/** Looks up a package version on deps.dev (`requestName` = `SYSTEM:name` from `checkCoordinates`). */
export async function fetchDepsDevMetadata(session: RegistrySession, requestName: string, version: string, signal: AbortSignal): Promise<MetadataOutcome> {
  const split = splitDepsDevRequestName(requestName);
  // Unreachable through `checkCoordinates`; no request for a malformed key.
  if (split === null) return { kind: 'error', code: 'URL_NOT_ALLOWED' };
  const [system, name] = split;
  const result = await session.getJson(depsDevVersionUrl(session.endpoints.depsdev, system, name, version), 'metadata-depsdev', {
    signal,
    dedupeKey: coordinateKey('depsdev', requestName, version),
  });
  if (result.kind !== 'ok') return result;
  return extractDepsDevMetadata(result.json);
}
