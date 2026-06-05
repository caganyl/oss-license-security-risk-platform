import crypto from 'crypto';
import type { SbomScanData, SbomLicense } from '../sbomService';

// SPDX IDs allow: letters, digits, '.', '-', '+'
function toSpdxId(ecosystem: string, name: string, version: string, purl: string): string {
  const hash = crypto.createHash('sha256').update(purl).digest('hex').substring(0, 8);
  const safeName = name.replace(/[^a-zA-Z0-9.\-+]/g, '-').substring(0, 32);
  const safeVer = version.replace(/[^a-zA-Z0-9.\-+]/g, '-').substring(0, 16);
  return `SPDXRef-${ecosystem}-${safeName}-${safeVer}-${hash}`;
}

function licenseExpression(licenses: SbomLicense[]): string {
  const ids = Array.from(new Set(
    licenses
      .map(l => l.normalizedLicense || l.detectedLicense)
      .filter((x): x is string => x != null && x.trim().length > 0),
  ));
  return ids.length > 0 ? ids.join(' AND ') : 'NOASSERTION';
}

// Wraps multi-line values in SPDX <text>...</text> blocks
function spdxValue(value: string): string {
  return value.includes('\n') ? `<text>${value}</text>` : value;
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
    const licExpr = licenseExpression(dep.licenses);
    const pkg: Record<string, unknown> = {
      SPDXID: id,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: dep.homepageUrl ?? 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: licExpr,
      licenseDeclared: licExpr,
      copyrightText: dep.copyrightText ?? 'NOASSERTION',
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

  lines.push('SPDXVersion: SPDX-2.3');
  lines.push('DataLicense: CC0-1.0');
  lines.push(`SPDXID: ${DOC}`);
  lines.push(`DocumentName: SBOM-${project.name}-${scan.id}`);
  lines.push(`DocumentNamespace: https://platform.example.com/sbom/spdx/${scan.id}`);
  lines.push('Creator: Tool: OSS License & Security Risk Platform');
  lines.push(`Creator: Organization: ${project.name}`);
  lines.push(`Created: ${new Date().toISOString()}`);
  lines.push('LicenseListVersion: 3.21');
  lines.push('');

  lines.push(`PackageName: ${project.name}`);
  lines.push(`SPDXID: ${ROOT}`);
  lines.push(`PackageVersion: ${scan.ref ?? 'NOASSERTION'}`);
  lines.push(`PackageDownloadLocation: ${project.repoUrl ?? 'NOASSERTION'}`);
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

    const licExpr = licenseExpression(dep.licenses);
    const copyright = dep.copyrightText ?? 'NOASSERTION';

    lines.push(`PackageName: ${dep.name}`);
    lines.push(`SPDXID: ${id}`);
    lines.push(`PackageVersion: ${dep.version}`);
    lines.push(`PackageDownloadLocation: ${dep.homepageUrl ?? 'NOASSERTION'}`);
    lines.push('FilesAnalyzed: false');
    lines.push(`PackageLicenseConcluded: ${licExpr}`);
    lines.push(`PackageLicenseDeclared: ${licExpr}`);
    lines.push(`PackageCopyrightText: ${spdxValue(copyright)}`);
    lines.push(`ExternalRef: PACKAGE-MANAGER purl ${dep.purl}`);
    if (dep.author) lines.push(`PackageSupplier: Organization: ${dep.author}`);
    if (dep.homepageUrl) lines.push(`PackageHomePage: ${dep.homepageUrl}`);
    lines.push('');
  }

  lines.push(`Relationship: ${DOC} DESCRIBES ${ROOT}`);
  for (const dep of dependencies) {
    const id = idByPurl.get(dep.purl);
    if (!id) continue;
    const rel = dep.depth === 0 ? 'CONTAINS' : 'DEPENDENCY_OF';
    lines.push(`Relationship: ${ROOT} ${rel} ${id}`);
  }

  return lines.join('\n');
}
