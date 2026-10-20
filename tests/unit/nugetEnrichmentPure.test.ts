/**
 * REQ-006 · Pure NuGet enrichment and OSV rules (no network, no database).
 *
 * - AC-P21-9 r2: `nugetSignedContentHash` against an independent oracle
 *   (helpers/fakeNuget `independentContentHash`: the deterministic zip of the
 *   same entries without `.signature.p7s`), signature first/middle/last;
 *   unsigned, double-signed, ZIP64 and corrupted archives are "not computable".
 * - AC-P21-4/5/6/15: `.nuspec` extraction (precedence, `BAD_NUSPEC`, DOCTYPE,
 *   1 MiB cap, canonical `<id>`), `licenseUrl` table.
 * - AC-NV-1/2/4: OSV candidate queries (NuGet ecosystem/name casing, no
 *   dotnet -> PyPI), case-insensitive `affected` selection, F4 query shape.
 */
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { nugetSignedContentHash } from '../../src/enrichment/archive/nupkgHash';
import { classifyLicenseUrl } from '../../src/enrichment/nugetLicenseUrls';
import { extractNuspecMetadata, nupkgUrl, nuspecUrl } from '../../src/enrichment/nugetRegistry';
import { ENRICHMENT_LIMITS } from '../../src/scanner/sandbox/runner.config';
import { type LookupDependency, candidateQueries } from '../../src/vulnerability/lookup';
import { normalizeOsvVulnerability } from '../../src/vulnerability/normalize';
import { buildZip, sha512b64 } from '../helpers/archiveBuilder';
import { REAL_SIGNED_CONTENT_HASHES, SIGNATURE_ENTRY, buildNupkg, independentContentHash, nupkgEntries, nuspecXml } from '../helpers/fakeNuget';

const MAX = 10_000;
const utf8 = (s: string) => new TextEncoder().encode(s);

describe('AC-P21-9 r2: NuGet signed content hash (ADR-008 Karar 10.3)', () => {
  it.each([0, 1, 3])('AC-P21-9: signature entry at index %i -> content hash equals the independent oracle, raw SHA-512 differs', (signatureIndex) => {
    const entries = nupkgEntries('Acme.Signed', { signed: true, signatureIndex });
    const buf = buildZip(entries);
    const expected = `sha512-${independentContentHash(entries)}`;
    expect(nugetSignedContentHash(buf, MAX)).toBe(expected);
    expect(`sha512-${sha512b64(buf)}`).not.toBe(expected);
  });

  it('AC-P21-9: an unsigned .nupkg is "not computable" (null) -> only the raw hash path applies', () => {
    expect(nugetSignedContentHash(buildNupkg('Acme.Unsigned'), MAX)).toBeNull();
  });

  it('AC-P21-9: two root .signature.p7s entries, ZIP64 EOCD, non-zip and truncated buffers -> null', () => {
    const content = nupkgEntries('Acme.X');
    expect(nugetSignedContentHash(buildZip([...content, SIGNATURE_ENTRY, SIGNATURE_ENTRY]), MAX)).toBeNull();
    expect(nugetSignedContentHash(buildZip([...content, SIGNATURE_ENTRY], { zip64Eocd: true }), MAX)).toBeNull();
    expect(nugetSignedContentHash(Buffer.from('not a zip at all'), MAX)).toBeNull();
    const signed = buildNupkg('Acme.X', { signed: true });
    expect(nugetSignedContentHash(signed.subarray(0, signed.length - 5), MAX)).toBeNull();
  });

  it('AC-P21-9: a nested "lib/.signature.p7s" is not the signature entry (null for an otherwise unsigned package)', () => {
    expect(nugetSignedContentHash(buildZip([...nupkgEntries('Acme.N'), { ...SIGNATURE_ENTRY, name: 'lib/.signature.p7s' }]), MAX)).toBeNull();
  });

  it('AC-P21-9: a corrupted content byte changes the content hash (-> mismatch against the lock value)', () => {
    const entries = nupkgEntries('Acme.C', { signed: true });
    const buf = Buffer.from(buildZip(entries));
    const good = `sha512-${independentContentHash(entries)}`;
    buf[40] ^= 0xff; // inside the first entry's data
    const value = nugetSignedContentHash(buf, MAX);
    expect(value).not.toBe(good);
  });

  it('AC-P21-16 (documentation): recorded real nuget.org contentHash values are well-formed sha512 base64 (not downloaded)', () => {
    for (const value of Object.values(REAL_SIGNED_CONTENT_HASHES)) {
      expect(value).toMatch(/^[A-Za-z0-9+/]{86}==$/);
      expect(Buffer.from(value, 'base64')).toHaveLength(64);
    }
  });
});

describe('AC-P21-2: flat container URLs (lower-case id and version, one segment each)', () => {
  it('AC-P21-2: nuspec and nupkg URLs', () => {
    expect(nuspecUrl('https://api.nuget.org', 'newtonsoft.json', '13.0.3')).toBe('https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec');
    expect(nupkgUrl('https://api.nuget.org', 'newtonsoft.json', '13.0.3-beta1')).toBe('https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3-beta1/newtonsoft.json.13.0.3-beta1.nupkg');
  });
});

describe('AC-P21-5 / AC-P21-4: .nuspec extraction', () => {
  // nuspecXml's default <version> is 1.0.0 (L-3: the nuspec version must equal the requested one).
  const extract = (xml: string, lowerId = 'acme.pkg') => extractNuspecMetadata(utf8(xml), lowerId, '1.0.0');

  it('AC-P21-5: type="expression" -> declared license; canonical <id> keeps its casing', () => {
    const out = extract(nuspecXml({ id: 'Acme.Pkg', expression: 'MIT OR Apache-2.0', licenseUrl: 'https://licenses.nuget.org/ISC' }));
    expect(out).toEqual({ kind: 'found', metadata: expect.objectContaining({ declaredLicense: 'MIT OR Apache-2.0', licenseUnclassified: null, canonicalName: 'Acme.Pkg', archiveCandidates: [] }) });
  });

  it('AC-P21-5: type="file" -> no declared license, licenseUnclassified "file", normalized path kept; "../LICENSE" not matched', () => {
    expect(extract(nuspecXml({ id: 'Acme.Pkg', file: 'docs\\EULA.md', licenseUrl: 'https://licenses.nuget.org/MIT' }))).toEqual({
      kind: 'found',
      metadata: expect.objectContaining({ declaredLicense: null, licenseUnclassified: 'file', licenseFilePath: 'docs/EULA.md' }),
    });
    const traversal = extract(nuspecXml({ id: 'Acme.Pkg', file: '../LICENSE' }));
    expect(traversal).toEqual({ kind: 'found', metadata: expect.objectContaining({ licenseUnclassified: 'file', licenseFilePath: null }) });
  });

  it('AC-P21-5: an unknown license type is "no license element" -> licenseUrl decides', () => {
    expect(extract(nuspecXml({ id: 'Acme.Pkg', licenseType: 'weird', licenseUrl: 'https://licenses.nuget.org/MIT' }))).toEqual({
      kind: 'found',
      metadata: expect.objectContaining({ declaredLicense: 'MIT', licenseUnclassified: null }),
    });
  });

  it('AC-P21-6: unknown licenseUrl -> licenseUnclassified "url"; aka.ms placeholder -> nothing (no_license)', () => {
    expect(extract(nuspecXml({ id: 'Acme.Pkg', licenseUrl: 'https://example.com/eula.html' }))).toEqual({ kind: 'found', metadata: expect.objectContaining({ declaredLicense: null, licenseUnclassified: 'url' }) });
    expect(extract(nuspecXml({ id: 'Acme.Pkg', licenseUrl: 'https://aka.ms/deprecateLicenseUrl' }))).toEqual({ kind: 'found', metadata: expect.objectContaining({ declaredLicense: null, licenseUnclassified: null }) });
  });

  it('AC-P21-4: BAD_NUSPEC for a wrong root, missing metadata, another id, malformed XML and a DOCTYPE', () => {
    const bad = { kind: 'error', code: 'BAD_NUSPEC' };
    expect(extract(nuspecXml({ id: 'Acme.Pkg', root: 'pkg' }))).toEqual(bad);
    expect(extract(nuspecXml({ id: 'Acme.Pkg', noMetadata: true }))).toEqual(bad);
    expect(extract(nuspecXml({ id: 'Other.Pkg', expression: 'MIT' }))).toEqual(bad);
    expect(extract('<package><metadata><id>Acme.Pkg</id>')).toEqual(bad);
    expect(extract(nuspecXml({ id: 'Acme.Pkg', expression: 'MIT', prolog: '<!DOCTYPE package [<!ENTITY x "MIT">]>' }))).toEqual(bad);
  });

  it('AC-P21-4: 1 MiB cap (limit constant; one byte over -> TOO_LARGE, never parsed)', () => {
    expect(ENRICHMENT_LIMITS.client.nuspecMaxBytes).toBe(1024 * 1024);
    const base = nuspecXml({ id: 'Acme.Pkg', expression: 'MIT', extra: '<!--X-->' });
    const pad = ENRICHMENT_LIMITS.client.nuspecMaxBytes - Buffer.byteLength(base) + 1;
    const over = base.replace('<!--X-->', `<!--${'x'.repeat(pad + 1)}-->`);
    expect(Buffer.byteLength(over)).toBeGreaterThan(ENRICHMENT_LIMITS.client.nuspecMaxBytes);
    expect(extract(over)).toEqual({ kind: 'error', code: 'TOO_LARGE' });
    expect(extract(base)).toEqual({ kind: 'found', metadata: expect.objectContaining({ declaredLicense: 'MIT' }) });
  });

  it('AC-P21-15: control characters in the expression are not stored as is', () => {
    const out = extract(nuspecXml({ id: 'Acme.Pkg', expression: `MIT\u0007‮` }));
    expect(out.kind).toBe('found');
    const declared = (out as { metadata: { declaredLicense: string | null } }).metadata.declaredLicense ?? '';
    expect([...declared].some((c) => c.charCodeAt(0) < 0x20 || c === '‮')).toBe(false);
  });
});

describe('REQ-006 security review L-3: the .nuspec <version> must be the requested version', () => {
  const bad = { kind: 'error', code: 'BAD_NUSPEC' };
  const found = { kind: 'found', metadata: expect.objectContaining({ declaredLicense: 'MIT', canonicalName: 'Acme.Pkg' }) };
  const withVersion = (version: string | null, lowerVersion: string) => extractNuspecMetadata(utf8(nuspecXml({ id: 'Acme.Pkg', version, expression: 'MIT' })), 'acme.pkg', lowerVersion);

  it.each([
    ['1.0.0', '1.0.0'],
    ['1.0', '1.0.0'],
    ['1.0.0.0', '1.0.0'],
    ['01.00.000', '1.0.0'],
    ['1.0.0+build.5', '1.0.0'],
    ['  1.0.0  ', '1.0.0'],
    ['1.0.0-BETA', '1.0.0-beta'],
    ['1.0.0-beta', '1.0.0-beta'],
    ['1.0.0-Beta.1+sha.abc', '1.0.0-beta.1'],
    ['1.2.3.4', '1.2.3.4'],
  ])('L-3: nuspec <version>%s</version> equals the requested %s after NuGet normalization -> found', (version, lowerVersion) => {
    expect(withVersion(version, lowerVersion)).toEqual(found);
  });

  it.each([
    ['1.0.1', '1.0.0'],
    ['2.0.0', '1.0.0'],
    ['1.0.0.1', '1.0.0'],
    ['1.0.0-beta', '1.0.0'],
    ['1.0.0', '1.0.0-beta'],
    ['1.0.0-beta.2', '1.0.0-beta.1'],
    ['1.0.*', '1.0.0'],
    ['[1.0.0,2.0.0)', '1.0.0'],
    ['$(Version)', '1.0.0'],
    ['', '1.0.0'],
    ['   ', '1.0.0'],
    ['not-a-version', '1.0.0'],
  ])('L-3: nuspec <version>%s</version> for requested %s -> BAD_NUSPEC', (version, lowerVersion) => {
    expect(withVersion(version, lowerVersion)).toEqual(bad);
  });

  it('L-3: a nuspec without a <version> element -> BAD_NUSPEC', () => {
    expect(withVersion(null, '1.0.0')).toEqual(bad);
  });

  it('L-3: the id rule still applies first (right version, other id -> BAD_NUSPEC)', () => {
    expect(extractNuspecMetadata(utf8(nuspecXml({ id: 'Other.Pkg', version: '1.0.0', expression: 'MIT' })), 'acme.pkg', '1.0.0')).toEqual(bad);
  });
});

describe('AC-P21-6: licenseUrl table (never fetched; pure classification)', () => {
  it.each([
    ['https://licenses.nuget.org/MIT', { kind: 'expression', value: 'MIT' }],
    ['http://licenses.nuget.org/Apache-2.0%20OR%20MIT', { kind: 'expression', value: 'Apache-2.0 OR MIT' }],
    ['https://licenses.nuget.org/Not-A-License', { kind: 'unclassified' }],
    ['https://aka.ms/deprecateLicenseUrl', { kind: 'ignore' }],
    ['https://opensource.org/licenses/MIT', { kind: 'expression', value: 'MIT' }],
    ['http://www.opensource.org/licenses/mit-license.php', { kind: 'expression', value: 'MIT' }],
    ['https://www.apache.org/licenses/LICENSE-2.0.html', { kind: 'expression', value: 'Apache-2.0' }],
    ['https://www.apache.org/licenses/LICENSE-2.0.txt', { kind: 'expression', value: 'Apache-2.0' }],
    ['https://opensource.org/licenses/BSD-3-Clause/', { kind: 'expression', value: 'BSD-3-Clause' }],
    ['https://spdx.org/licenses/MIT.html', { kind: 'expression', value: 'MIT' }],
    ['https://spdx.org/licenses/BSD-2-Clause', { kind: 'expression', value: 'BSD-2-Clause' }],
    ['https://www.mozilla.org/MPL/2.0/', { kind: 'expression', value: 'MPL-2.0' }],
    ['https://github.com/acme/pkg/blob/main/LICENSE', { kind: 'unclassified' }],
    ['https://opensource.org/licenses/MIT?x=1', { kind: 'unclassified' }],
    ['ftp://opensource.org/licenses/MIT', { kind: 'unclassified' }],
    ['not a url', { kind: 'unclassified' }],
  ])('AC-P21-6: %s', (url, expected) => {
    expect(classifyLicenseUrl(url)).toEqual(expected);
  });
});

describe('AC-NV-1 / AC-NV-4: OSV candidate queries', () => {
  const dep = (ecosystem: string, name: string, version: string) => ({ ecosystem, name, version }) as LookupDependency;

  it('AC-NV-1: NuGet query uses ecosystem "NuGet", the .nuspec <id> when known, else the first-seen casing; never lower-cased', () => {
    const deps = [dep('dotnet', 'newtonsoft.json', '13.0.3'), dep('dotnet', 'NEWTONSOFT.JSON', '13.0.3'), dep('dotnet', 'Serilog', '3.1.1')];
    const plain = candidateQueries(deps);
    expect(plain.map((q) => [q.ecosystem, q.name, q.version])).toEqual([['NuGet', 'newtonsoft.json', '13.0.3'], ['NuGet', 'Serilog', '3.1.1']]);
    const key = plain[0].key;
    const canonical = candidateQueries(deps, new Map([[key, 'Newtonsoft.Json']]));
    expect(canonical.map((q) => q.name)).toEqual(['Newtonsoft.Json', 'Serilog']);
  });

  it('AC-NV-1: exhaustive ecosystem mapping — dotnet never becomes PyPI, unsupported ecosystems are skipped', () => {
    // REQ-011 D-301: rust is queried as crates.io now; `container` is an enum value that is never sent to OSV.
    const qs = candidateQueries([
      dep('dotnet', 'Requests', '2.31.0'),
      dep('python', 'Requests', '2.31.0'),
      dep('nodejs', 'left-pad', '1.3.0'),
      dep('rust', 'serde', '1.0.0'),
      dep('container', 'alpine', '3.19'),
    ]);
    expect(qs.map((q) => `${q.ecosystem}|${q.name}`).sort()).toEqual(['NuGet|Requests', 'PyPI|requests', 'crates.io|serde', 'npm|left-pad']);
  });

  it('AC-NV-4: npm/PyPI-only queries are identical with or without a canonical-name map (F4 shape)', () => {
    const deps = [dep('nodejs', '@scope/a', '1.0.0'), dep('python', 'Django_Rest', '3.0')];
    const a = candidateQueries(deps);
    const b = candidateQueries(deps, new Map([[a[0].key, 'X']]));
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
    expect(a.map((q) => ({ package: { ecosystem: q.ecosystem, name: q.name }, version: q.version }))).toEqual([
      { package: { ecosystem: 'npm', name: '@scope/a' }, version: '1.0.0' },
      { package: { ecosystem: 'PyPI', name: 'django-rest' }, version: '3.0' },
    ]);
  });
});

describe('AC-NV-2: case-insensitive NuGet affected selection', () => {
  it('AC-NV-2: OSV "newtonsoft.json" NuGet entry is chosen for scanned "Newtonsoft.Json" (not an earlier NuGet entry of another package)', () => {
    const vuln = {
      id: 'GHSA-nuget-0001',
      summary: 's',
      modified: '2026-01-01T00:00:00Z',
      affected: [
        { package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json.Bson' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
        { package: { ecosystem: 'NuGet', name: 'newtonsoft.json' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '13.0.4' }] }] },
      ],
    };
    const out = normalizeOsvVulnerability(vuln as never, { ecosystem: 'dotnet', name: 'Newtonsoft.Json' }) as unknown as { fixedVersion: string | null; affectedPackage: string };
    expect(out.fixedVersion).toBe('13.0.4');
    expect(out.affectedPackage).toBe('Newtonsoft.Json');
  });

  it('AC-NV-2: npm keeps the F4 chain (case-sensitive; an upper-case OSV name does not win over the ecosystem fallback order)', () => {
    const vuln = {
      id: 'GHSA-npm-0001',
      modified: '2026-01-01T00:00:00Z',
      affected: [
        { package: { ecosystem: 'npm', name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] },
        { package: { ecosystem: 'npm', name: 'LEFT-PAD' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] },
      ],
    };
    const out = normalizeOsvVulnerability(vuln as never, { ecosystem: 'nodejs', name: 'left-pad' }) as unknown as { fixedVersion: string | null };
    expect(out.fixedVersion).toBe('1.0.1');
  });
});

it('AC-P21-9 helper self-check: the oracle is not the raw hash of the signed archive', () => {
  const entries = nupkgEntries('Acme.Self', { signed: true });
  expect(independentContentHash(entries)).not.toBe(crypto.createHash('sha512').update(buildZip(entries)).digest('base64'));
});
