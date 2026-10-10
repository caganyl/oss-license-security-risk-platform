import crypto from 'crypto';
import type { SbomScanData, SbomDependency } from '../sbomService';
import { outputClean, singleLine, tagValueSingleLine, tagValueText } from '../../lib/outputText';
import { sbomLicenseInfo } from '../licenseInfo';

// SPDX IDs allow: letters, digits, '.', '-', '+'
function toSpdxId(ecosystem: string, name: string, version: string, purl: string): string {
  const hash = crypto.createHash('sha256').update(purl).digest('hex').substring(0, 8);
  const safeName = name.replace(/[^a-zA-Z0-9.\-+]/g, '-').substring(0, 32);
  const safeVer = version.replace(/[^a-zA-Z0-9.\-+]/g, '-').substring(0, 16);
  return `SPDXRef-${ecosystem}-${safeName}-${safeVer}-${hash}`;
}

interface SpdxLicenseFields {
  /** `licenseDeclared`: canonical expression or `NOASSERTION`. */
  declared: string;
  /** `licenseComments` lines joined with `\n`, or null (field not written). */
  comments: string | null;
  /** `copyrightText`: lines joined with `\n`, or null for `NOASSERTION`. */
  copyright: string | null;
}

/**
 * REQ-004 contract section 6.1: `licenseConcluded` is always `NOASSERTION`;
 * `licenseDeclared` is the canonical effective expression or `NOASSERTION`;
 * `licenseComments` carries (a) the invalid raw value and (b) the lockfile
 * source; `copyrightText` the extracted copyright lines.
 */
function spdxLicenseFields(dep: SbomDependency, data: SbomScanData): SpdxLicenseFields {
  const info = sbomLicenseInfo(dep, data.knownLicenseIds);
  const comments: string[] = [];
  if (info.invalid) comments.push(`Declared license is not a valid SPDX expression: ${singleLine(info.declared)}`);
  if (info.lockfileSource) comments.push('License source: lockfile (unverified)');
  const copyrightLines = info.copyrightLines.map((line) => singleLine(line)).filter((line) => line.trim() !== '');
  return {
    declared: info.canonical ?? 'NOASSERTION',
    comments: comments.length > 0 ? comments.join('\n') : null,
    copyright: copyrightLines.length > 0 ? copyrightLines.join('\n') : null,
  };
}

export function generateSpdxJson(data: SbomScanData): string {
  const { scan, project, dependencies } = data;
  const DOC = 'SPDXRef-DOCUMENT';
  const ROOT = 'SPDXRef-ROOT';

  const packages: object[] = [{
    SPDXID: ROOT,
    name: project.name,
    versionInfo: scan.ref ?? 'NOASSERTION',
    downloadLocation: project.repoUrl ?? 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    externalRefs: [],
  }];

  const relationships: object[] = [{
    spdxElementId: DOC,
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: ROOT,
  }];

  const seen = new Set<string>();
  for (const dep of dependencies) {
    if (seen.has(dep.purl)) continue;
    seen.add(dep.purl);

    const id = toSpdxId(dep.ecosystem, dep.name, dep.version, dep.purl);
    const lic = spdxLicenseFields(dep, data);
    const pkg: Record<string, unknown> = {
      SPDXID: id,
      name: outputClean(dep.name),
      versionInfo: outputClean(dep.version),
      downloadLocation: dep.homepageUrl ?? 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: lic.declared,
      ...(lic.comments !== null ? { licenseComments: lic.comments } : {}),
      copyrightText: lic.copyright ?? 'NOASSERTION',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: dep.purl,
      }],
    };
    if (dep.author) pkg.supplier = `Organization: ${dep.author}`;
    if (dep.homepageUrl) pkg.homepage = dep.homepageUrl;
    if (dep.description) pkg.comment = dep.description;

    packages.push(pkg);
    relationships.push({
      spdxElementId: ROOT,
      relationshipType: dep.depth === 0 ? 'CONTAINS' : 'DEPENDENCY_OF',
      relatedSpdxElement: id,
    });
  }

  return JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: DOC,
    name: `SBOM-${project.name}-${scan.id}`,
    documentNamespace: `https://platform.example.com/sbom/spdx/${scan.id}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: [
        'Tool: OSS License & Security Risk Platform',
        `Organization: ${project.name}`,
      ],
      licenseListVersion: '3.21',
    },
    packages,
    relationships,
  }, null, 2);
}

export function generateSpdxTagValue(data: SbomScanData): string {
  const { scan, project, dependencies } = data;
  const DOC = 'SPDXRef-DOCUMENT';
  const ROOT = 'SPDXRef-ROOT';
  const lines: string[] = [];
  // Single-line fields never carry a line break (contract section 6.1, AC-P16-4).
  const sl = tagValueSingleLine;

  lines.push('SPDXVersion: SPDX-2.3');
  lines.push('DataLicense: CC0-1.0');
  lines.push(`SPDXID: ${DOC}`);
  lines.push(`DocumentName: ${sl(`SBOM-${project.name}-${scan.id}`)}`);
  lines.push(`DocumentNamespace: https://platform.example.com/sbom/spdx/${scan.id}`);
  lines.push('Creator: Tool: OSS License & Security Risk Platform');
  lines.push(`Creator: ${sl(`Organization: ${project.name}`)}`);
  lines.push(`Created: ${new Date().toISOString()}`);
  lines.push('LicenseListVersion: 3.21');
  lines.push('');

  lines.push(`PackageName: ${sl(project.name)}`);
  lines.push(`SPDXID: ${ROOT}`);
  lines.push(`PackageVersion: ${sl(scan.ref ?? 'NOASSERTION')}`);
  lines.push(`PackageDownloadLocation: ${sl(project.repoUrl ?? 'NOASSERTION')}`);
  lines.push('FilesAnalyzed: false');
  lines.push('PackageLicenseConcluded: NOASSERTION');
  lines.push('PackageLicenseDeclared: NOASSERTION');
  lines.push('PackageCopyrightText: NOASSERTION');
  lines.push('');

  const seen = new Set<string>();
  const idByPurl = new Map<string, string>();

  for (const dep of dependencies) {
    if (seen.has(dep.purl)) continue;
    seen.add(dep.purl);

    const id = toSpdxId(dep.ecosystem, dep.name, dep.version, dep.purl);
    idByPurl.set(dep.purl, id);
    const lic = spdxLicenseFields(dep, data);

    lines.push(`PackageName: ${sl(dep.name)}`);
    lines.push(`SPDXID: ${sl(id)}`);
    lines.push(`PackageVersion: ${sl(dep.version)}`);
    lines.push(`PackageDownloadLocation: ${sl(dep.homepageUrl ?? 'NOASSERTION')}`);
    lines.push('FilesAnalyzed: false');
    lines.push('PackageLicenseConcluded: NOASSERTION');
    lines.push(`PackageLicenseDeclared: ${sl(lic.declared)}`);
    if (lic.comments !== null) lines.push(`PackageLicenseComments: ${tagValueText(lic.comments)}`);
    lines.push(`PackageCopyrightText: ${lic.copyright !== null ? tagValueText(lic.copyright) : 'NOASSERTION'}`);
    lines.push(`ExternalRef: ${sl(`PACKAGE-MANAGER purl ${dep.purl}`)}`);
    if (dep.author) lines.push(`PackageSupplier: ${sl(`Organization: ${dep.author}`)}`);
    if (dep.homepageUrl) lines.push(`PackageHomePage: ${sl(dep.homepageUrl)}`);
    lines.push('');
  }

  lines.push(`Relationship: ${DOC} DESCRIBES ${ROOT}`);
  for (const dep of dependencies) {
    const id = idByPurl.get(dep.purl);
    if (!id) continue;
    const rel = dep.depth === 0 ? 'CONTAINS' : 'DEPENDENCY_OF';
    lines.push(`Relationship: ${ROOT} ${rel} ${sl(id)}`);
  }

  return lines.join('\n');
}
