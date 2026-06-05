import crypto from 'crypto';
import path from 'path';
import fs from 'fs/promises';
import type { Pool } from 'pg';
import { generateSpdxJson, generateSpdxTagValue } from './formats/spdx';
import { generateCycloneDxJson, generateCycloneDxXml } from './formats/cyclonedx';

export type SbomFormat = 'spdx_json' | 'spdx_tag_value' | 'cyclonedx_json' | 'cyclonedx_xml';

export interface SbomLicense {
  detectedLicense: string | null;
  normalizedLicense: string | null;
  riskLevel: string;
}

export interface SbomVulnerability {
  cveId: string | null;
  ghsaId: string | null;
  osvId: string | null;
  title: string;
  description: string | null;
  severity: string;
  cvssScore: number | null;
  cvssVector: string | null;
  fixVersion: string | null;
  affectedVersions: string | null;
  publishedAt: Date | null;
}

export interface SbomDependency {
  id: string;
  packageId: string;
  ecosystem: string;
  name: string;
  version: string;
  purl: string;
  scope: string;
  manifestFile: string;
  manifestPath: string;
  depth: number;
  description: string | null;
  homepageUrl: string | null;
  author: string | null;
  copyrightText: string | null;
  licenses: SbomLicense[];
  vulnerabilities: SbomVulnerability[];
}

export interface SbomScanData {
  scan: {
    id: string;
    ref: string | null;
    completedAt: Date | null;
    createdAt: Date;
    totalDependencies: number;
  };
  project: {
    id: string;
    name: string;
    description: string | null;
    repoUrl: string | null;
  };
  dependencies: SbomDependency[];
}

export interface SbomDocumentRecord {
  id: string;
  scanId: string;
  format: SbomFormat;
  specVersion: string;
  storageKey: string;
  fileSizeBytes: number;
  checksumSha256: string;
  documentId: string;
  generatedBy: string | null;
  generatedAt: Date;
}

const FORMAT_META: Record<SbomFormat, { specVersion: string; ext: string; mimeType: string }> = {
  spdx_json:      { specVersion: '2.3', ext: 'spdx.json', mimeType: 'application/spdx+json' },
  spdx_tag_value: { specVersion: '2.3', ext: 'spdx',      mimeType: 'text/spdx' },
  cyclonedx_json: { specVersion: '1.5', ext: 'cdx.json',  mimeType: 'application/vnd.cyclonedx+json' },
  cyclonedx_xml:  { specVersion: '1.5', ext: 'cdx.xml',   mimeType: 'application/vnd.cyclonedx+xml' },
};

export const VALID_FORMATS = new Set<SbomFormat>(Object.keys(FORMAT_META) as SbomFormat[]);

export class SbomService {
  constructor(private readonly db: Pool) {}

  async generate(
    scanId: string,
    format: SbomFormat,
    requestedBy?: string,
  ): Promise<SbomDocumentRecord> {
    const data = await this.loadScanData(scanId);
    const content = this.renderContent(data, format);
    const checksum = crypto.createHash('sha256').update(content).digest('hex');
    const sizeBytes = Buffer.byteLength(content, 'utf8');

    const outputDir = process.env.SBOM_OUTPUT_DIR ?? path.join(process.cwd(), 'sbom-output');
    await fs.mkdir(outputDir, { recursive: true });

    const meta = FORMAT_META[format];
    const filename = `sbom-${scanId}-${format}.${meta.ext}`;
    const storageKey = path.join(outputDir, filename);
    await fs.writeFile(storageKey, content, 'utf8');

    const docId = `sbom-${scanId}-${format}`;
    const insertResult = await this.db.query<{ id: string }>(
      `INSERT INTO sbom_documents
         (scan_id, format, spec_version, storage_key, file_size_bytes, checksum_sha256, document_id, generated_by)
       VALUES ($1, $2::sbom_format, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [scanId, format, meta.specVersion, storageKey, sizeBytes, checksum, docId, requestedBy ?? null],
    );
    const sbomId = insertResult.rows[0].id;

    await this.db.query(
      `INSERT INTO audit_logs (action, actor_id, entity_type, entity_id, occurred_at)
       VALUES ('sbom_generated', $1, 'sbom_document', $2, NOW())`,
      [requestedBy ?? null, sbomId],
    );

    return {
      id: sbomId,
      scanId,
      format,
      specVersion: meta.specVersion,
      storageKey,
      fileSizeBytes: sizeBytes,
      checksumSha256: checksum,
      documentId: docId,
      generatedBy: requestedBy ?? null,
      generatedAt: new Date(),
    };
  }

  async listByScan(scanId: string): Promise<SbomDocumentRecord[]> {
    const result = await this.db.query<{
      id: string; scan_id: string; format: SbomFormat; spec_version: string;
      storage_key: string; file_size_bytes: number; checksum_sha256: string;
      document_id: string; generated_by: string | null; generated_at: Date;
    }>(
      `SELECT id, scan_id, format, spec_version, storage_key, file_size_bytes,
              checksum_sha256, document_id, generated_by, generated_at
       FROM sbom_documents
       WHERE scan_id = $1
       ORDER BY generated_at DESC`,
      [scanId],
    );
    return result.rows.map(toRecord);
  }

  async readDocument(sbomId: string): Promise<{ record: SbomDocumentRecord; content: Buffer; mimeType: string }> {
    const result = await this.db.query<{
      id: string; scan_id: string; format: SbomFormat; spec_version: string;
      storage_key: string; file_size_bytes: number; checksum_sha256: string;
      document_id: string; generated_by: string | null; generated_at: Date;
    }>(
      `SELECT id, scan_id, format, spec_version, storage_key, file_size_bytes,
              checksum_sha256, document_id, generated_by, generated_at
       FROM sbom_documents WHERE id = $1`,
      [sbomId],
    );

    if (result.rows.length === 0) {
      throw Object.assign(new Error('SBOM document not found'), { statusCode: 404 });
    }

    const row = result.rows[0];
    let content: Buffer;
    try {
      content = await fs.readFile(row.storage_key);
    } catch {
      throw Object.assign(new Error('SBOM file not found in storage'), { statusCode: 404 });
    }

    return {
      record: toRecord(row),
      content,
      mimeType: FORMAT_META[row.format]?.mimeType ?? 'application/octet-stream',
    };
  }

  private renderContent(data: SbomScanData, format: SbomFormat): string {
    switch (format) {
      case 'spdx_json':      return generateSpdxJson(data);
      case 'spdx_tag_value': return generateSpdxTagValue(data);
      case 'cyclonedx_json': return generateCycloneDxJson(data);
      case 'cyclonedx_xml':  return generateCycloneDxXml(data);
    }
  }

  private async loadScanData(scanId: string): Promise<SbomScanData> {
    const scanResult = await this.db.query<{
      id: string; ref: string | null; completed_at: Date | null; created_at: Date;
      total_dependencies: number;
      project_id: string; project_name: string; project_description: string | null; repo_url: string | null;
    }>(
      `SELECT s.id, s.ref, s.completed_at, s.created_at, s.total_dependencies,
              p.id AS project_id, p.name AS project_name, p.description AS project_description, p.repo_url
       FROM scans s
       JOIN projects p ON p.id = s.project_id
       WHERE s.id = $1 AND s.status = 'completed'`,
      [scanId],
    );

    if (scanResult.rows.length === 0) {
      throw Object.assign(new Error('Scan not found or not yet completed'), { statusCode: 404 });
    }
    const sr = scanResult.rows[0];

    const depsResult = await this.db.query<{
      scan_dep_id: string; scope: string; manifest_file: string; manifest_path: string; depth: number;
      package_id: string; ecosystem: string; name: string; version: string; purl: string;
      description: string | null; homepage_url: string | null; author: string | null; copyright_text: string | null;
    }>(
      `SELECT sd.id AS scan_dep_id, sd.scope, sd.manifest_file, sd.manifest_path, sd.depth,
              p.id AS package_id, p.ecosystem::text, p.name, p.version, p.purl,
              p.description, p.homepage_url, p.author, p.copyright_text
       FROM scan_dependencies sd
       JOIN packages p ON p.id = sd.package_id
       WHERE sd.scan_id = $1
       ORDER BY p.name, p.version`,
      [scanId],
    );

    const licResult = await this.db.query<{
      scan_dependency_id: string;
      detected_license: string | null; normalized_license: string | null; risk_level: string;
    }>(
      `SELECT f.scan_dependency_id, lf.detected_license, lf.normalized_license, lf.risk_level::text
       FROM findings f
       JOIN license_findings lf ON lf.finding_id = f.id
       WHERE f.scan_id = $1`,
      [scanId],
    );

    const vulnResult = await this.db.query<{
      scan_dependency_id: string;
      cve_id: string | null; ghsa_id: string | null; osv_id: string | null;
      title: string; description: string | null; severity: string;
      cvss_score: string | null; cvss_vector: string | null;
      fix_version: string | null; affected_versions: string | null; published_at: Date | null;
    }>(
      `SELECT f.scan_dependency_id, v.cve_id, v.ghsa_id, v.osv_id,
              v.title, v.description, sf.severity::text,
              sf.cvss_score::text, v.cvss_vector, sf.fix_version,
              v.affected_versions, v.published_at
       FROM findings f
       JOIN security_findings sf ON sf.finding_id = f.id
       JOIN vulnerabilities v ON v.id = sf.vulnerability_id
       WHERE f.scan_id = $1`,
      [scanId],
    );

    const licensesByDep = new Map<string, SbomLicense[]>();
    for (const row of licResult.rows) {
      const arr = licensesByDep.get(row.scan_dependency_id) ?? [];
      arr.push({
        detectedLicense: row.detected_license,
        normalizedLicense: row.normalized_license,
        riskLevel: row.risk_level,
      });
      licensesByDep.set(row.scan_dependency_id, arr);
    }

    const vulnsByDep = new Map<string, SbomVulnerability[]>();
    for (const row of vulnResult.rows) {
      const arr = vulnsByDep.get(row.scan_dependency_id) ?? [];
      arr.push({
        cveId: row.cve_id,
        ghsaId: row.ghsa_id,
        osvId: row.osv_id,
        title: row.title,
        description: row.description,
        severity: row.severity,
        cvssScore: row.cvss_score != null ? parseFloat(row.cvss_score) : null,
        cvssVector: row.cvss_vector,
        fixVersion: row.fix_version,
        affectedVersions: row.affected_versions,
        publishedAt: row.published_at,
      });
      vulnsByDep.set(row.scan_dependency_id, arr);
    }

    return {
      scan: {
        id: sr.id,
        ref: sr.ref,
        completedAt: sr.completed_at,
        createdAt: sr.created_at,
        totalDependencies: sr.total_dependencies,
      },
      project: {
        id: sr.project_id,
        name: sr.project_name,
        description: sr.project_description,
        repoUrl: sr.repo_url,
      },
      dependencies: depsResult.rows.map(r => ({
        id: r.scan_dep_id,
        packageId: r.package_id,
        ecosystem: r.ecosystem,
        name: r.name,
        version: r.version,
        purl: r.purl,
        scope: r.scope,
        manifestFile: r.manifest_file,
        manifestPath: r.manifest_path,
        depth: r.depth,
        description: r.description,
        homepageUrl: r.homepage_url,
        author: r.author,
        copyrightText: r.copyright_text,
        licenses: licensesByDep.get(r.scan_dep_id) ?? [],
        vulnerabilities: vulnsByDep.get(r.scan_dep_id) ?? [],
      })),
    };
  }
}

function toRecord(row: {
  id: string; scan_id: string; format: SbomFormat; spec_version: string;
  storage_key: string; file_size_bytes: number; checksum_sha256: string;
  document_id: string; generated_by: string | null; generated_at: Date;
}): SbomDocumentRecord {
  return {
    id: row.id,
    scanId: row.scan_id,
    format: row.format,
    specVersion: row.spec_version,
    storageKey: row.storage_key,
    fileSizeBytes: row.file_size_bytes,
    checksumSha256: row.checksum_sha256,
    documentId: row.document_id,
    generatedBy: row.generated_by,
    generatedAt: row.generated_at,
  };
}
