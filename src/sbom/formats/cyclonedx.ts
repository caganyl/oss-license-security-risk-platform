import crypto from 'crypto';
import type { SbomScanData, SbomDependency, SbomVulnerability } from '../sbomService';

const SCOPE_MAP: Record<string, string> = {
  direct:     'required',
  transitive: 'required',
  dev:        'optional',
  peer:       'optional',
  optional:   'optional',
};

interface CdxLicenseEntry {
  license?: { id: string } | { name: string };
  expression?: string;
}

function buildCdxLicenses(dep: SbomDependency): CdxLicenseEntry[] {
  const seen = new Set<string>();
  const entries: CdxLicenseEntry[] = [];

  for (const l of dep.licenses) {
    const lic = l.normalizedLicense ?? l.detectedLicense;
    if (!lic || seen.has(lic)) continue;
    seen.add(lic);

    if (/\b(AND|OR|WITH)\b/i.test(lic)) {
      entries.push({ expression: lic });
    } else if (/^[a-zA-Z0-9][a-zA-Z0-9.\-+]*$/.test(lic)) {
      entries.push({ license: { id: lic } });
    } else {
      entries.push({ license: { name: lic } });
    }
  }
  return entries;
}

interface CdxVulnEntry {
  id: string;
  source: { name: string };
  ratings?: Array<{ severity: string; score?: number; vector?: string }>;
  description?: string;
  recommendation?: string;
  affects: Array<{ ref: string }>;
}

function buildVulnerabilities(dependencies: SbomDependency[]): CdxVulnEntry[] {
  const vulnMap = new Map<string, { v: SbomVulnerability; refs: Set<string> }>();

  for (const dep of dependencies) {
    for (const v of dep.vulnerabilities) {
      const id = v.cveId ?? v.ghsaId ?? v.osvId;
      if (!id) continue;
      const entry = vulnMap.get(id);
      if (entry) {
        entry.refs.add(dep.purl);
      } else {
        vulnMap.set(id, { v, refs: new Set([dep.purl]) });
      }
    }
  }

  return Array.from(vulnMap.entries()).map(([id, { v, refs }]) => {
    const result: CdxVulnEntry = {
      id,
      source: {
        name: id.startsWith('CVE-') ? 'NVD'
          : id.startsWith('GHSA-') ? 'GitHub Advisory Database'
          : 'OSV',
      },
      affects: Array.from(refs).map(ref => ({ ref })),
    };

    if (v.severity) {
      const rating: { severity: string; score?: number; vector?: string } = { severity: v.severity };
      if (v.cvssScore != null) rating.score = v.cvssScore;
      if (v.cvssVector) rating.vector = v.cvssVector;
      result.ratings = [rating];
    }
    if (v.description) result.description = v.description;
    if (v.fixVersion) result.recommendation = `Upgrade to ${v.fixVersion}`;

    return result;
  });
}

// =============================================================================
// CycloneDX 1.5 JSON
// =============================================================================

export function generateCycloneDxJson(data: SbomScanData): string {
  const { scan, project, dependencies } = data;

  const seen = new Set<string>();
  const components: object[] = [];

  for (const dep of dependencies) {
    if (seen.has(dep.purl)) continue;
    seen.add(dep.purl);

    const component: Record<string, unknown> = {
      type: 'library',
      'bom-ref': dep.purl,
      name: dep.name,
      version: dep.version,
      purl: dep.purl,
    };

    if (dep.description) component.description = dep.description;
    if (dep.author) component.author = dep.author;

    const cdxLicenses = buildCdxLicenses(dep);
    if (cdxLicenses.length > 0) component.licenses = cdxLicenses;

    if (SCOPE_MAP[dep.scope]) component.scope = SCOPE_MAP[dep.scope];

    components.push(component);
  }

  const vulnerabilities = buildVulnerabilities(dependencies);

  const doc: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'OSS License & Security Risk Platform', version: '1.0.0' }],
      component: {
        type: 'application',
        'bom-ref': project.id,
        name: project.name,
        ...(scan.ref ? { version: scan.ref } : {}),
        ...(project.description ? { description: project.description } : {}),
      },
    },
    components,
  };

  if (vulnerabilities.length > 0) doc.vulnerabilities = vulnerabilities;

  return JSON.stringify(doc, null, 2);
}

// =============================================================================
// CycloneDX 1.5 XML
// =============================================================================

function xe(value: string | null | undefined): string {
  if (!value) return '';
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function generateCycloneDxXml(data: SbomScanData): string {
  const { scan, project, dependencies } = data;
  const lines: string[] = [];

  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1" serialNumber="urn:uuid:${crypto.randomUUID()}">`);

  lines.push('  <metadata>');
  lines.push(`    <timestamp>${new Date().toISOString()}</timestamp>`);
  lines.push('    <tools>');
  lines.push('      <tool>');
  lines.push('        <name>OSS License &amp; Security Risk Platform</name>');
  lines.push('      </tool>');
  lines.push('    </tools>');
  lines.push(`    <component type="application" bom-ref="${xe(project.id)}">`);
  lines.push(`      <name>${xe(project.name)}</name>`);
  if (scan.ref) lines.push(`      <version>${xe(scan.ref)}</version>`);
  if (project.description) lines.push(`      <description>${xe(project.description)}</description>`);
  lines.push('    </component>');
  lines.push('  </metadata>');

  lines.push('  <components>');
  const seen = new Set<string>();
  for (const dep of dependencies) {
    if (seen.has(dep.purl)) continue;
    seen.add(dep.purl);

    lines.push(`    <component type="library" bom-ref="${xe(dep.purl)}">`);
    lines.push(`      <name>${xe(dep.name)}</name>`);
    lines.push(`      <version>${xe(dep.version)}</version>`);
    if (dep.description) lines.push(`      <description>${xe(dep.description)}</description>`);
    if (dep.author) lines.push(`      <author>${xe(dep.author)}</author>`);
    lines.push(`      <purl>${xe(dep.purl)}</purl>`);

    const cdxLicenses = buildCdxLicenses(dep);
    if (cdxLicenses.length > 0) {
      lines.push('      <licenses>');
      for (const entry of cdxLicenses) {
        if (entry.expression) {
          lines.push(`        <expression>${xe(entry.expression)}</expression>`);
        } else if (entry.license && 'id' in entry.license) {
          lines.push('        <license>');
          lines.push(`          <id>${xe(entry.license.id)}</id>`);
          lines.push('        </license>');
        } else if (entry.license && 'name' in entry.license) {
          lines.push('        <license>');
          lines.push(`          <name>${xe(entry.license.name)}</name>`);
          lines.push('        </license>');
        }
      }
      lines.push('      </licenses>');
    }

    if (SCOPE_MAP[dep.scope]) lines.push(`      <scope>${SCOPE_MAP[dep.scope]}</scope>`);
    lines.push('    </component>');
  }
  lines.push('  </components>');

  const vulns = buildVulnerabilities(dependencies);
  if (vulns.length > 0) {
    lines.push('  <vulnerabilities>');
    for (const v of vulns) {
      lines.push(`    <vulnerability bom-ref="${xe(v.id)}">`);
      lines.push(`      <id>${xe(v.id)}</id>`);
      lines.push('      <source>');
      lines.push(`        <name>${xe(v.source.name)}</name>`);
      lines.push('      </source>');

      if (v.ratings && v.ratings.length > 0) {
        lines.push('      <ratings>');
        for (const r of v.ratings) {
          lines.push('        <rating>');
          lines.push(`          <severity>${xe(r.severity)}</severity>`);
          if (r.score != null) lines.push(`          <score>${r.score}</score>`);
          if (r.vector) lines.push(`          <vector>${xe(r.vector)}</vector>`);
          lines.push('        </rating>');
        }
        lines.push('      </ratings>');
      }

      if (v.description) lines.push(`      <description>${xe(v.description)}</description>`);
      if (v.recommendation) lines.push(`      <recommendation>${xe(v.recommendation)}</recommendation>`);

      lines.push('      <affects>');
      for (const a of v.affects) {
        lines.push('        <target>');
        lines.push(`          <ref>${xe(a.ref)}</ref>`);
        lines.push('        </target>');
      }
      lines.push('      </affects>');

      lines.push('    </vulnerability>');
    }
    lines.push('  </vulnerabilities>');
  }

  lines.push('</bom>');
  return lines.join('\n') + '\n';
}
