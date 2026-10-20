/**
 * pub.dev license lookup for Dart/Flutter packages (REQ-011 P-43,
 * AC-P43-2, AC-P43-3; ADR-012 Karar 3).
 *
 * `GET https://pub.dev/api/packages/<name>/score`; only the `tags` array is
 * read. Every `license:<id>` tag whose id looks like an SPDX identifier is
 * a license of the package; pub.dev's classification tags
 * (`license:fsf-libre`, `license:osi-approved`, `license:unknown`) are not
 * licenses and are ignored. Several ids are combined with ` AND `; pub.dev
 * writes ids in lower case (`license:bsd-3-clause`), the worker's license
 * normalizer gives the canonical SPDX spelling. No license id -> no
 * declared license (status `no_license`). No archive is downloaded (D-321).
 *
 * The score document describes the package's latest version (pub.dev has no
 * per-version score endpoint): the license is cached per (name, version) of
 * the scan, and one request serves every version of a name in a scan
 * (in-flight dedupe by name).
 *
 * Network access goes through the injected `RegistrySession` only
 * (`metadata-pubdev` purpose: fixed origin, exact path, no redirect, 1 MiB).
 */
import { coordinateKey } from './coordinates';
import type { RegistrySession } from './registryClient';
import { cleanDeclaredLicense } from './text';
import type { MetadataOutcome } from './types';

/** Maximum `tags` items read. */
export const MAX_PUBDEV_TAGS = 256;
/** Maximum distinct license ids combined. */
export const MAX_PUBDEV_LICENSES = 16;

const LICENSE_TAG_PREFIX = 'license:';
/** pub.dev license classification tags (not license ids). */
const META_LICENSE_TAGS: ReadonlySet<string> = new Set(['fsf-libre', 'osi-approved', 'unknown']);
/** SPDX identifier characters (idstring: letters, digits, `.`, `-`; `+` suffix), linear. */
const SPDX_ID_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,63}\+?$/;

/** Thrown inside extraction when a field has an unexpected type. */
class FieldTypeError extends Error {
  constructor() {
    super('unexpected field type');
    this.name = 'FieldTypeError';
  }
}

/** Request URL of the score document of a pub.dev package. */
export function pubDevScoreUrl(origin: string, name: string): string {
  return `${origin}/api/packages/${encodeURIComponent(name)}/score`;
}

/** One SPDX expression from the `license:<id>` tags of a pub.dev score document; null = none. */
export function pubDevDeclaredLicense(doc: Record<string, unknown>): string | null {
  const tags = doc.tags;
  if (tags === undefined || tags === null) return null;
  if (!Array.isArray(tags)) throw new FieldTypeError();
  const ids: string[] = [];
  for (const tag of tags.slice(0, MAX_PUBDEV_TAGS)) {
    if (typeof tag !== 'string' || !tag.startsWith(LICENSE_TAG_PREFIX)) continue;
    const id = tag.slice(LICENSE_TAG_PREFIX.length).trim();
    if (!SPDX_ID_RE.test(id) || META_LICENSE_TAGS.has(id.toLowerCase())) continue;
    if (!ids.some((known) => known.toLowerCase() === id.toLowerCase())) ids.push(id);
    if (ids.length === MAX_PUBDEV_LICENSES) break;
  }
  return ids.length === 0 ? null : cleanDeclaredLicense(ids.join(' AND '));
}

/** Metadata of one pub.dev score document; `error` when a field type does not match. */
export function extractPubDevMetadata(doc: Record<string, unknown>): MetadataOutcome {
  try {
    return { kind: 'found', metadata: { declaredLicense: pubDevDeclaredLicense(doc), licenseText: null, archiveCandidates: [] } };
  } catch (err) {
    if (err instanceof FieldTypeError) return { kind: 'error', code: 'FIELD_TYPE' };
    throw err;
  }
}

/** Looks up the license of a pub.dev package (`version` only keys the cache row). */
export async function fetchPubDevMetadata(session: RegistrySession, name: string, version: string, signal: AbortSignal): Promise<MetadataOutcome> {
  void version;
  const result = await session.getJson(pubDevScoreUrl(session.endpoints.pubdev, name), 'metadata-pubdev', {
    signal,
    // One score document per name: every version of the name in a scan shares the request.
    dedupeKey: coordinateKey('pubdev', name, ''),
  });
  if (result.kind !== 'ok') return result;
  return extractPubDevMetadata(result.json);
}
