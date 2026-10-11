/**
 * NuGet `.nuspec` lookup and license extraction (REQ-006 AC-P21-1…7,
 * AC-P21-15; ADR-008 Karar 8, 9; D-132…D-134).
 *
 * `GET <nuget>/v3-flatcontainer/<id>/<ver>/<id>.nuspec` (lower-case id and
 * version, `metadata-nuget`: <= 3 same-origin redirects, 1 MiB). The body is
 * parsed on the main thread with the safe XML reader (no DTD, no entities).
 * Root `package`, child `metadata`, and `asciiLower(metadata/id)` equal to the
 * requested id, else `BAD_NUSPEC` (not cached).
 *
 * License precedence: `<license type="expression">` > `<license
 * type="file">` (no expression, `licenseUnclassified = 'file'`) >
 * `<licenseUrl>` (`classifyLicenseUrl`; never fetched) > none. The archive
 * candidate is never taken from the registry: it comes from the scan's
 * lock/assets hash (`index.ts`), so `archiveCandidates` is empty.
 *
 * Network access only through the session (ADR-008 Karar 1).
 */
import { ENRICHMENT_LIMITS } from '../scanner/sandbox/runner.config';
import { type XmlElement, parseXml } from '../scanner/parsers/xmlReader';
import { normalizeArchivePath } from './archive/licenseFiles';
import { asciiLower, coordinateKey, isValidNugetId } from './coordinates';
import { classifyLicenseUrl } from './nugetLicenseUrls';
import type { RegistrySession } from './registryClient';
import { cleanDeclaredLicense } from './text';
import type { LicenseUnclassified, MetadataOutcome, RegistryMetadata } from './types';

/** Longest declared `type="file"` path kept (ADR-008 Karar 9). */
const MAX_LICENSE_FILE_PATH = 256;

/** `.nuspec` URL of a lower-case id/version (one path segment each). */
export function nuspecUrl(origin: string, lowerId: string, lowerVersion: string): string {
  const id = encodeURIComponent(lowerId);
  return `${origin}/v3-flatcontainer/${id}/${encodeURIComponent(lowerVersion)}/${id}.nuspec`;
}

/** `.nupkg` URL of a lower-case id/version (`archive-nuget`). */
export function nupkgUrl(origin: string, lowerId: string, lowerVersion: string): string {
  const id = encodeURIComponent(lowerId);
  const ver = encodeURIComponent(lowerVersion);
  return `${origin}/v3-flatcontainer/${id}/${ver}/${id}.${ver}.nupkg`;
}

function child(element: XmlElement, localName: string): XmlElement | undefined {
  return element.children.find((c) => c.localName === localName);
}

function attribute(element: XmlElement, name: string): string | undefined {
  return element.attributes.find(([key]) => key === name)?.[1];
}

/** Normalized declared license file path, or null (ADR-008 Karar 9 step 2). */
function declaredFilePath(raw: string): string | null {
  const value = raw.trim().replace(/\\/g, '/');
  if (value.length === 0 || value.length > MAX_LICENSE_FILE_PATH) return null;
  return normalizeArchivePath(value);
}

/** License fields of a `<metadata>` element (ADR-008 Karar 9). */
export function nuspecLicenseFields(metadata: XmlElement): Pick<RegistryMetadata, 'declaredLicense' | 'licenseUnclassified' | 'licenseFilePath'> {
  // The first `license` element in document order decides; another `type` or an empty value is "no license element".
  const license = child(metadata, 'license');
  if (license !== undefined) {
    const type = attribute(license, 'type');
    if (type === 'expression') {
      const expression = cleanDeclaredLicense(license.text);
      if (expression !== null) return { declaredLicense: expression, licenseUnclassified: null, licenseFilePath: null };
    } else if (type === 'file' && license.text.trim() !== '') {
      return { declaredLicense: null, licenseUnclassified: 'file', licenseFilePath: declaredFilePath(license.text) };
    }
  }
  const licenseUrl = child(metadata, 'licenseUrl');
  if (licenseUrl !== undefined && licenseUrl.text.trim() !== '') {
    const classified = classifyLicenseUrl(licenseUrl.text);
    if (classified.kind === 'expression') return { declaredLicense: classified.value, licenseUnclassified: null, licenseFilePath: null };
    if (classified.kind === 'unclassified') {
      const reason: LicenseUnclassified = 'url';
      return { declaredLicense: null, licenseUnclassified: reason, licenseFilePath: null };
    }
  }
  return { declaredLicense: null, licenseUnclassified: null, licenseFilePath: null };
}

/** Metadata of one `.nuspec` body; `BAD_NUSPEC` for XML errors, a wrong root/shape or another id. */
export function extractNuspecMetadata(body: Uint8Array, lowerId: string): MetadataOutcome {
  if (body.length > ENRICHMENT_LIMITS.client.nuspecMaxBytes) return { kind: 'error', code: 'TOO_LARGE' };
  let root: XmlElement;
  try {
    root = parseXml(body);
  } catch {
    return { kind: 'error', code: 'BAD_NUSPEC' };
  }
  if (root.localName !== 'package') return { kind: 'error', code: 'BAD_NUSPEC' };
  const metadata = child(root, 'metadata');
  if (metadata === undefined) return { kind: 'error', code: 'BAD_NUSPEC' };
  const id = child(metadata, 'id')?.text.trim() ?? '';
  if (asciiLower(id) !== lowerId) return { kind: 'error', code: 'BAD_NUSPEC' };
  return {
    kind: 'found',
    metadata: {
      ...nuspecLicenseFields(metadata),
      licenseText: null,
      archiveCandidates: [],
      canonicalName: isValidNugetId(id) ? id : null,
    },
  };
}

/** Looks up `id==version` on the NuGet flat container (`lowerId`/`lowerVersion` from `checkCoordinates`). */
export async function fetchNugetMetadata(session: RegistrySession, lowerId: string, lowerVersion: string, signal: AbortSignal): Promise<MetadataOutcome> {
  const url = nuspecUrl(session.endpoints.nuget, lowerId, lowerVersion);
  const result = await session.getText(url, 'metadata-nuget', { signal, dedupeKey: coordinateKey('nuget', lowerId, lowerVersion) });
  if (result.kind !== 'ok') return result;
  return extractNuspecMetadata(result.body, lowerId);
}
