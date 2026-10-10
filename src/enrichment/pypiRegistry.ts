/**
 * PyPI version JSON lookup and field extraction (REQ-004 AC-P14-2,
 * AC-P14-3, AC-P14-5, AC-P14-11, AC-P15-3; ADR-006 Karar 3, 6; D-53).
 *
 * `GET <pypi>/pypi/<PEP 503 name>/<version>/json`. License precedence of
 * `info`:
 *   (1) `license_expression` (PEP 639) when set;
 *   (2) `license` when single-line, <= 200 characters and recognized by the
 *       normalizer (known SPDX id or valid expression);
 *   (3) `License ::` classifiers (AC-P14-3, joined with ` AND `);
 *   (4) `license` as raw text when single-line and <= 200 characters;
 *   otherwise no license. A multi-line or longer `license` is never an id;
 * it is kept (<= 1 MiB) as the NOTICE fallback text.
 * `info.author`, `maintainers` etc. are not read (D-68).
 */
import { isRecognizedLicense, licenseFromClassifiers } from '../analysis/licenseNormalizer';
import { coordinateKey, pep503Name } from './coordinates';
import { pypiExpectedDigest } from './integrity';
import type { RegistrySession } from './registryClient';
import { cleanDeclaredLicense, cleanLicenseText, sanitizeText } from './text';
import type { ArchiveCandidate, MetadataOutcome } from './types';

/** Longest `license` value that may be a license id (AC-P14-2). */
export const MAX_SHORT_LICENSE_CHARS = 200;
/** Largest candidate archive (AC-P15-5). */
const MAX_CANDIDATE_BYTES = 64 * 1024 * 1024;
/** Candidates kept in the cache (ADR-006 Karar 6). */
export const MAX_STORED_CANDIDATES = 32;

class FieldTypeError extends Error {
  constructor() {
    super('unexpected field type');
    this.name = 'FieldTypeError';
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') throw new FieldTypeError();
  return value;
}

/** The short form of `license` (single line, <= 200 code points after cleanup), or null. */
function shortLicense(license: string | null): string | null {
  if (license === null) return null;
  const cleaned = sanitizeText(license).trim();
  if (cleaned.length === 0 || cleaned.includes('\n') || Array.from(cleaned).length > MAX_SHORT_LICENSE_CHARS) return null;
  return cleaned;
}

/** License declaration and NOTICE fallback text of a PyPI `info` object (AC-P14-2). */
export function pypiLicenseFields(info: Record<string, unknown>): { declaredLicense: string | null; licenseText: string | null } {
  const expression = optionalString(info.license_expression);
  const license = optionalString(info.license);
  const classifiers = info.classifiers;
  if (classifiers !== undefined && classifiers !== null && !Array.isArray(classifiers)) throw new FieldTypeError();

  const short = shortLicense(license);
  const licenseText = license !== null && short === null ? cleanLicenseText(license) : null;

  const fromExpression = expression !== null ? cleanDeclaredLicense(expression) : null;
  if (fromExpression !== null) return { declaredLicense: fromExpression, licenseText };
  if (short !== null && isRecognizedLicense(short)) return { declaredLicense: cleanDeclaredLicense(short), licenseText };
  const fromClassifiers = Array.isArray(classifiers) ? licenseFromClassifiers(classifiers) : null;
  if (fromClassifiers !== null) return { declaredLicense: cleanDeclaredLicense(fromClassifiers), licenseText };
  if (short !== null) return { declaredLicense: cleanDeclaredLicense(short), licenseText };
  return { declaredLicense: null, licenseText };
}

type CandidateGroup = 0 | 1 | 2 | 3; // none-any wheel, other wheel, sdist .tar.gz, sdist .zip

function candidateGroup(packagetype: string, filename: string): CandidateGroup | null {
  const lower = filename.toLowerCase();
  if (packagetype === 'bdist_wheel' && lower.endsWith('.whl')) return lower.endsWith('-none-any.whl') ? 0 : 1;
  if (packagetype === 'sdist' && lower.endsWith('.tar.gz')) return 2;
  if (packagetype === 'sdist' && lower.endsWith('.zip')) return 3;
  return null;
}

function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Archive candidates of `urls` (AC-P15-3): only `<files origin>/` URLs with a
 * 64-hex sha256, wheel or sdist with a `.whl`/`.tar.gz`/`.zip` name, size
 * <= 64 MiB. Order: `-none-any.whl`, other wheels by size, sdist `.tar.gz`
 * by size, sdist `.zip` by size (ties by file name code points). At most 32.
 */
export function pypiArchiveCandidates(urls: unknown, filesOrigin: string): ArchiveCandidate[] {
  if (urls === undefined || urls === null) return [];
  if (!Array.isArray(urls)) throw new FieldTypeError();
  const ranked: Array<{ group: CandidateGroup; candidate: ArchiveCandidate }> = [];
  for (const item of urls) {
    if (!isObject(item)) continue;
    const { url, packagetype, digests, size } = item;
    if (typeof url !== 'string' || !url.startsWith(`${filesOrigin}/`) || typeof packagetype !== 'string') continue;
    const filename = typeof item.filename === 'string' ? item.filename : url.slice(url.lastIndexOf('/') + 1);
    const group = candidateGroup(packagetype, filename);
    if (group === null) continue;
    const expected = pypiExpectedDigest(isObject(digests) ? digests.sha256 : undefined);
    if (expected === null) continue;
    const declaredSize = typeof size === 'number' && Number.isInteger(size) && size >= 0 ? size : null;
    if (declaredSize !== null && declaredSize > MAX_CANDIDATE_BYTES) continue;
    ranked.push({ group, candidate: { url, algorithm: 'sha256', digests: [...expected.values], size: declaredSize, filename } });
  }
  ranked.sort(
    (a, b) =>
      a.group - b.group ||
      (a.candidate.size ?? Number.MAX_SAFE_INTEGER) - (b.candidate.size ?? Number.MAX_SAFE_INTEGER) ||
      compareCodePoints(a.candidate.filename ?? '', b.candidate.filename ?? ''),
  );
  return ranked.slice(0, MAX_STORED_CANDIDATES).map((r) => r.candidate);
}

/** Metadata of one PyPI version JSON; `error` when a field type does not match. */
export function extractPypiMetadata(doc: Record<string, unknown>, filesOrigin: string): MetadataOutcome {
  try {
    if (!isObject(doc.info)) throw new FieldTypeError();
    const { declaredLicense, licenseText } = pypiLicenseFields(doc.info);
    return { kind: 'found', metadata: { declaredLicense, licenseText, archiveCandidates: pypiArchiveCandidates(doc.urls, filesOrigin) } };
  } catch (err) {
    if (err instanceof FieldTypeError) return { kind: 'error', code: 'FIELD_TYPE' };
    throw err;
  }
}

/** Looks up `name==version` on PyPI (the request uses the PEP 503 name). */
export async function fetchPypiMetadata(session: RegistrySession, name: string, version: string, signal: AbortSignal): Promise<MetadataOutcome> {
  const requestName = pep503Name(name);
  const url = `${session.endpoints.pypi}/pypi/${encodeURIComponent(requestName)}/${encodeURIComponent(version)}/json`;
  const result = await session.getJson(url, 'metadata-pypi', { signal, dedupeKey: coordinateKey('pypi', requestName, version) });
  if (result.kind !== 'ok') return result;
  return extractPypiMetadata(result.json, session.endpoints.files);
}
