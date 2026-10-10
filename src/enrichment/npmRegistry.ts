/**
 * npm version document lookup and field extraction (REQ-004 AC-P14-1,
 * AC-P14-5, AC-P14-11, AC-P15-2; ADR-006 Karar 3, 6).
 *
 * `GET <npm>/<request name>/<version>`; a scoped name is one path segment
 * (`@scope%2Fname`). Only for scoped names, a `404` falls back to the full
 * package document (`versions[<version>]`, same 8 MiB cap): document without
 * the version -> not found; too large -> error. Network access goes through
 * the injected `RegistrySession` only.
 */
import { coordinateKey, npmPathSegment } from './coordinates';
import { npmExpectedDigest } from './integrity';
import type { RegistrySession } from './registryClient';
import { cleanDeclaredLicense } from './text';
import type { ArchiveCandidate, MetadataOutcome, RegistryMetadata } from './types';

/** Maximum `licenses` array items read. */
export const MAX_NPM_LICENSES = 16;

/** Thrown inside extraction when a field has an unexpected type (AC-P14-11). */
class FieldTypeError extends Error {
  constructor() {
    super('unexpected field type');
    this.name = 'FieldTypeError';
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Raw npm license declaration of a version document, in AC-P14-1 order; null = none. */
export function npmDeclaredLicense(doc: Record<string, unknown>): string | null {
  const license = doc.license;
  if (typeof license === 'string') {
    const cleaned = cleanDeclaredLicense(license);
    if (cleaned !== null) return cleaned;
  } else if (isObject(license)) {
    if (typeof license.type === 'string') {
      const cleaned = cleanDeclaredLicense(license.type);
      if (cleaned !== null) return cleaned;
    } else if (license.type !== undefined && license.type !== null) {
      throw new FieldTypeError();
    }
  } else if (license !== undefined && license !== null) {
    throw new FieldTypeError();
  }

  const licenses = doc.licenses;
  if (licenses === undefined || licenses === null) return null;
  if (!Array.isArray(licenses)) throw new FieldTypeError();
  const types: string[] = [];
  for (const item of licenses.slice(0, MAX_NPM_LICENSES)) {
    if (!isObject(item) || typeof item.type !== 'string') continue;
    const cleaned = cleanDeclaredLicense(item.type);
    if (cleaned !== null && !types.includes(cleaned)) types.push(cleaned);
  }
  if (types.length === 0) return null;
  return cleanDeclaredLicense(types.join(' OR '));
}

/** Archive candidate from `dist` (tarball under `<npm origin>/`, sha512 integrity or sha1 shasum); empty when none. */
export function npmArchiveCandidates(doc: Record<string, unknown>, npmOrigin: string): ArchiveCandidate[] {
  const dist = doc.dist;
  if (dist === undefined || dist === null) return [];
  if (!isObject(dist)) throw new FieldTypeError();
  const { tarball, integrity, shasum } = dist;
  for (const field of [tarball, integrity, shasum]) {
    if (field !== undefined && field !== null && typeof field !== 'string') throw new FieldTypeError();
  }
  if (typeof tarball !== 'string' || !tarball.startsWith(`${npmOrigin}/`)) return [];
  const expected = npmExpectedDigest(integrity, shasum);
  if (expected === null) return [];
  const filename = tarball.slice(tarball.lastIndexOf('/') + 1) || null;
  return [{ url: tarball, algorithm: expected.algorithm, digests: [...expected.values], size: null, filename }];
}

/** Metadata of one npm version document; `error` when a field type does not match. */
export function extractNpmMetadata(doc: Record<string, unknown>, npmOrigin: string): MetadataOutcome {
  try {
    const metadata: RegistryMetadata = {
      declaredLicense: npmDeclaredLicense(doc),
      licenseText: null,
      archiveCandidates: npmArchiveCandidates(doc, npmOrigin),
    };
    return { kind: 'found', metadata };
  } catch (err) {
    if (err instanceof FieldTypeError) return { kind: 'error', code: 'FIELD_TYPE' };
    throw err;
  }
}

/** Looks up `name@version` on the npm registry (request name = package name). */
export async function fetchNpmMetadata(session: RegistrySession, name: string, version: string, signal: AbortSignal): Promise<MetadataOutcome> {
  const origin = session.endpoints.npm;
  const segment = npmPathSegment(name);
  const result = await session.getJson(`${origin}/${segment}/${encodeURIComponent(version)}`, 'metadata-npm', {
    signal,
    dedupeKey: coordinateKey('npm', name, version),
  });
  if (result.kind === 'ok') return extractNpmMetadata(result.json, origin);
  if (result.kind !== 'not_found' || !name.startsWith('@')) return result;

  // Scoped fallback (ADR-006 Karar 3): the full package document.
  const full = await session.getJson(`${origin}/${segment}`, 'metadata-npm', { signal, dedupeKey: `npm-document\u0000${name}` });
  if (full.kind !== 'ok') return full;
  const versions = full.json.versions;
  if (versions === undefined || versions === null) return { kind: 'not_found' };
  if (!isObject(versions)) return { kind: 'error', code: 'FIELD_TYPE' };
  const doc = Object.prototype.hasOwnProperty.call(versions, version) ? versions[version] : undefined;
  if (doc === undefined) return { kind: 'not_found' };
  if (!isObject(doc)) return { kind: 'error', code: 'FIELD_TYPE' };
  return extractNpmMetadata(doc, origin);
}
