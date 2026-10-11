/**
 * REQ-006 · NuGet flat-container helpers on top of the loopback fake registry
 * (helpers/fakeRegistry; ADR-008 "Test stratejisi"; AC-P21-2/4/9, AC-G-2).
 *
 * - `nuspecXml(...)` builds a `.nuspec` body (license expression / file /
 *   licenseUrl variants, custom root or id for `BAD_NUSPEC` cases).
 * - `buildNupkg(...)` builds a `.nupkg` (zip) at test time; `signed: true`
 *   inserts a `.signature.p7s` entry (anywhere, default last, like nuget.org).
 * - `independentContentHash(...)` is the test oracle of the NuGet signed
 *   content hash: `buildZip` is deterministic, so the zip of the same entries
 *   WITHOUT the signature entry is byte-for-byte the archive "as if the
 *   signature had never been added" (offsets shifted, counts reduced). Its
 *   SHA-512 is computed independently of `src/enrichment/archive/nupkgHash.ts`.
 * - `addNugetPackage(...)` routes `/v3-flatcontainer/{id}/{ver}/{id}.nuspec`
 *   and `{id}.{ver}.nupkg` (lower-case id/version) and returns the paths, so a
 *   test can count requests, add redirects, oversize or error responses with
 *   `reg.route(path, ...)`.
 *
 * Nothing binary is committed; no request ever leaves 127.0.0.1.
 */
import { buildZip, sha512b64, type ZipEntrySpec } from './archiveBuilder';
import type { FakeRegistry, FakeResponse } from './fakeRegistry';

/**
 * Real nuget.org lock `contentHash` values (main-session evidence, REQ-006
 * AC-P21-16): `nugetSignedContentHash` of the downloaded, repository-signed
 * Newtonsoft.Json packages equals these values while their raw SHA-512 does
 * not. Documentation constants only — tests never download them.
 */
export const REAL_SIGNED_CONTENT_HASHES = {
  'Newtonsoft.Json@13.0.3': 'HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ==',
  'Newtonsoft.Json@13.0.1': 'ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A==',
} as const;

export interface NuspecSpec {
  id: string;
  version?: string;
  /** `<license type="expression">` value. */
  expression?: string;
  /** `<license type="file">` value. */
  file?: string;
  /** `<license type="...">` with another type. */
  licenseType?: string;
  licenseUrl?: string;
  /** Replace the root element name (BAD_NUSPEC). */
  root?: string;
  /** Omit `<metadata>` (BAD_NUSPEC). */
  noMetadata?: boolean;
  /** Raw text inserted before the root element (e.g. a DOCTYPE). */
  prolog?: string;
  /** Extra raw XML inside `<metadata>` (padding for size tests). */
  extra?: string;
}

const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function nuspecXml(spec: NuspecSpec): string {
  const root = spec.root ?? 'package';
  const parts: string[] = [`<id>${esc(spec.id)}</id>`, `<version>${esc(spec.version ?? '1.0.0')}</version>`, '<authors>QA</authors>'];
  if (spec.expression !== undefined) parts.push(`<license type="expression">${esc(spec.expression)}</license>`);
  if (spec.file !== undefined) parts.push(`<license type="file">${esc(spec.file)}</license>`);
  if (spec.licenseType !== undefined) parts.push(`<license type="${spec.licenseType}">MIT</license>`);
  if (spec.licenseUrl !== undefined) parts.push(`<licenseUrl>${esc(spec.licenseUrl)}</licenseUrl>`);
  if (spec.extra !== undefined) parts.push(spec.extra);
  const metadata = spec.noMetadata ? '' : `<metadata>${parts.join('')}</metadata>`;
  return `<?xml version="1.0" encoding="utf-8"?>${spec.prolog ?? ''}<${root} xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">${metadata}</${root}>`;
}

export const SIGNATURE_ENTRY: ZipEntrySpec = { name: '.signature.p7s', data: Buffer.from('3082fake-pkcs7-signature-bytes', 'latin1'), method: 0 };

export interface NupkgSpec {
  /** Content entries (a `.nuspec` + LICENSE by default). */
  entries?: ZipEntrySpec[];
  /** Insert the `.signature.p7s` entry. */
  signed?: boolean;
  /** Position of the signature entry (default: last). */
  signatureIndex?: number;
}

export function nupkgEntries(id: string, spec: NupkgSpec = {}): ZipEntrySpec[] {
  const content = spec.entries ?? [
    { name: `${id}.nuspec`, data: nuspecXml({ id }) },
    { name: 'LICENSE.txt', data: `MIT License\n\nCopyright (c) 2024 ${id} authors\n` },
    { name: 'lib/net8.0/x.dll', data: Buffer.alloc(64, 7) },
  ];
  if (!spec.signed) return content;
  const at = spec.signatureIndex ?? content.length;
  return [...content.slice(0, at), SIGNATURE_ENTRY, ...content.slice(at)];
}

export function buildNupkg(id: string, spec: NupkgSpec = {}): Buffer {
  return buildZip(nupkgEntries(id, spec));
}

/** Test oracle: SHA-512 (base64) of the same archive without the signature entry. */
export function independentContentHash(entries: readonly ZipEntrySpec[]): string {
  return sha512b64(buildZip(entries.filter((e) => e.name !== SIGNATURE_ENTRY.name)));
}

export interface NugetPackageRoutes {
  nuspecPath: string;
  nupkgPath: string;
}

export function nugetPaths(id: string, version: string): NugetPackageRoutes {
  const lid = id.toLowerCase();
  const lv = version.toLowerCase();
  return { nuspecPath: `/v3-flatcontainer/${lid}/${lv}/${lid}.nuspec`, nupkgPath: `/v3-flatcontainer/${lid}/${lv}/${lid}.${lv}.nupkg` };
}

/** Routes a NuGet package on the fake registry; `nuspec`/`nupkg` may be bodies or full responses. */
export function addNugetPackage(
  reg: FakeRegistry,
  id: string,
  version: string,
  spec: { nuspec?: string | FakeResponse; nupkg?: Buffer | FakeResponse | null },
): NugetPackageRoutes {
  const paths = nugetPaths(id, version);
  if (spec.nuspec !== undefined) {
    reg.route(paths.nuspecPath, typeof spec.nuspec === 'string' ? { body: spec.nuspec, headers: { 'content-type': 'application/xml' } } : spec.nuspec);
  }
  if (spec.nupkg !== undefined && spec.nupkg !== null) {
    reg.route(paths.nupkgPath, Buffer.isBuffer(spec.nupkg) ? { body: spec.nupkg, headers: { 'content-type': 'application/octet-stream' } } : spec.nupkg);
  }
  return paths;
}

/** One `packages.lock.json` (v2) with `net8.0` Direct entries; `hash: null` omits `contentHash`. */
export function packagesLockJson(entries: Array<{ id: string; version: string; hash: string | null }>): string {
  const deps: Record<string, Record<string, string>> = {};
  for (const e of entries) {
    const entry: Record<string, string> = { type: 'Direct', requested: `[${e.version}, )`, resolved: e.version };
    if (e.hash !== null) entry.contentHash = e.hash;
    deps[e.id] = entry;
  }
  return `${JSON.stringify({ version: 2, dependencies: { 'net8.0': deps } }, null, 2)}\n`;
}
