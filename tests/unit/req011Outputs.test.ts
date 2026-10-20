/**
 * REQ-011 P-42 outputs (AC-P42-1, AC-P42-2; D-314): finding fingerprints of
 * the new purl types are stable, SBOM writers and labels accept the new
 * ecosystem values.
 */
import { describe, expect, it } from 'vitest';
import { KNOWN_SPDX_IDS } from '../../src/analysis/licenseNormalizer';
import { computeFindingFingerprint, purlBase } from '../../src/analysis/findingFingerprint';
import { buildIdIndex } from '../../src/lib/spdxExpression';
import { ecosystemLabel } from '../../src/notice/noticeService';
import { pdfEcosystemLabel } from '../../src/reports/dependencyPdf';
import { generateCycloneDxJson, generateCycloneDxXml } from '../../src/sbom/formats/cyclonedx';
import { generateSpdxJson, generateSpdxTagValue } from '../../src/sbom/formats/spdx';
import type { SbomDependency, SbomScanData } from '../../src/sbom/sbomService';
import { purlFor } from '../../src/scanner/parsers/purl';
import { SCAN_ECOSYSTEMS, type ScanEcosystem } from '../../src/types/scan';

const PROJECT = '11111111-2222-4333-8444-555555555555';
const SAMPLES: Record<ScanEcosystem, [string, string]> = {
  nodejs: ['@scope/pkg', '1.0.0'],
  python: ['Foo_Bar', '1.0'],
  dotnet: ['Newtonsoft.Json', '13.0.1'],
  java: ['org.Apache.Commons:Commons-Lang3', '3.12.0'],
  go: ['github.com/Azure/go-autorest', 'v11.1.2+incompatible'],
  php: ['Symfony/Console', 'v6.4.1'],
  rust: ['serde_json', '1.0.108'],
  ruby: ['nokogiri', '1.15.4'],
  dart: ['flutter_bloc', '8.1.3'],
  swift: ['github.com/apple/swift-nio', '2.62.0'],
};

describe('D-314 / AC-P42-1: finding fingerprints of the new purl types', () => {
  it('purlBase drops the version and lower-cases (Maven and Packagist names are case-insensitive)', () => {
    expect(purlBase('pkg:maven/org.Apache.Commons/Commons-Lang3@3.12.0')).toBe('pkg:maven/org.apache.commons/commons-lang3');
    expect(purlBase('pkg:composer/symfony/console@v6.4.1')).toBe('pkg:composer/symfony/console');
    expect(purlBase('pkg:golang/github.com/Azure/go-autorest@v11.1.2%2Bincompatible')).toBe('pkg:golang/github.com/azure/go-autorest');
    expect(purlBase('pkg:swift/github.com/apple/swift-nio@2.62.0')).toBe('pkg:swift/github.com/apple/swift-nio');
    expect(purlBase('pkg:cargo/serde_json@1.0.108')).toBe('pkg:cargo/serde_json');
    // npm / PyPI / NuGet unchanged.
    expect(purlBase('pkg:npm/@scope/pkg@1.0.0')).toBe('pkg:npm/@scope/pkg');
    expect(purlBase('pkg:pypi/foo_bar.baz@1.0')).toBe('pkg:pypi/foo-bar-baz');
    expect(purlBase('pkg:nuget/Newtonsoft.Json@13.0.1')).toBe('pkg:nuget/newtonsoft.json');
  });

  it('the same package in two scans (and in another name casing for Maven/Packagist) gives the same fingerprint', () => {
    for (const eco of SCAN_ECOSYSTEMS) {
      const [name, version] = SAMPLES[eco];
      const purl = purlFor(eco, name, version);
      const input = { projectId: PROJECT, purl, version, findingType: 'security' as const, vulnerability: { id: 'x', osvId: 'OSV-2026-1' } };
      expect(computeFindingFingerprint(input), eco).toBe(computeFindingFingerprint({ ...input }));
      expect(computeFindingFingerprint(input), eco).toMatch(/^[0-9a-f]{64}$/);
    }
    const license = (eco: ScanEcosystem, name: string) =>
      computeFindingFingerprint({ projectId: PROJECT, purl: purlFor(eco, name, '1'), version: '1', findingType: 'license', normalizedLicense: 'MIT' });
    expect(license('java', 'org.Apache:Lib')).toBe(license('java', 'org.apache:lib'));
    expect(license('php', 'Acme/Lib')).toBe(license('php', 'acme/lib'));
  });
});

describe('AC-P42-2: SBOM writers and labels with the new ecosystem values', () => {
  const deps: SbomDependency[] = SCAN_ECOSYSTEMS.map((eco, i) => {
    const [name, version] = SAMPLES[eco];
    return {
      id: `d${i}`,
      packageId: `p${i}`,
      ecosystem: eco,
      name,
      version,
      purl: purlFor(eco, name, version),
      scope: 'direct',
      manifestFile: 'm',
      manifestPath: '.',
      depth: 0,
      description: null,
      homepageUrl: null,
      author: null,
      licenseExpression: eco === 'php' ? 'MIT OR Apache-2.0' : null,
      licenseSource: eco === 'php' ? 'lockfile (unverified)' : 'none',
      copyrightLines: [],
      licenses: [],
      vulnerabilities: [],
    };
  });
  const data: SbomScanData = {
    scan: { id: '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f', ref: 'main', completedAt: new Date(0), createdAt: new Date(0), totalDependencies: deps.length },
    project: { id: PROJECT, name: 'req011', description: null, repoUrl: null },
    dependencies: deps,
    knownLicenseIds: buildIdIndex([...KNOWN_SPDX_IDS]),
  };

  it('SPDX JSON / tag-value and CycloneDX JSON / XML are produced with valid, unique SPDX ids and every purl', () => {
    const spdx = JSON.parse(generateSpdxJson(data)) as { packages: Array<{ SPDXID: string; externalRefs?: Array<{ referenceLocator: string }> }> };
    const ids = spdx.packages.map((p) => p.SPDXID);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^SPDXRef-[A-Za-z0-9.+-]+$/);
    const locators = spdx.packages.flatMap((p) => (p.externalRefs ?? []).map((r) => r.referenceLocator));
    for (const d of deps) expect(locators).toContain(d.purl);
    expect(generateSpdxTagValue(data)).toContain('pkg:swift/github.com/apple/swift-nio@2.62.0');
    const cdx = JSON.parse(generateCycloneDxJson(data)) as { components: Array<{ purl: string }> };
    expect(cdx.components.map((c) => c.purl).sort()).toEqual(deps.map((d) => d.purl).sort());
    expect(generateCycloneDxXml(data)).toContain('pkg:maven/org.Apache.Commons/Commons-Lang3@3.12.0');
  });

  it('NOTICE labels: npm/pypi/nuget mapped, the new ecosystems as their enum value (contract 3.3)', () => {
    expect(SCAN_ECOSYSTEMS.map((e) => ecosystemLabel(e))).toEqual(['npm', 'pypi', 'nuget', 'java', 'go', 'php', 'rust', 'ruby', 'dart', 'swift']);
    expect(ecosystemLabel('__proto__')).toBe('__proto__');
  });

  it('PDF labels: readable package system names', () => {
    expect(SCAN_ECOSYSTEMS.map((e) => pdfEcosystemLabel(e))).toEqual(['npm', 'PyPI', 'NuGet', 'Maven', 'Go', 'Composer', 'Cargo', 'RubyGems', 'Pub', 'SwiftPM']);
    expect(pdfEcosystemLabel('container')).toBe('container');
    expect(pdfEcosystemLabel(null)).toBe('-');
  });
});
