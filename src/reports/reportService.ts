import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import PDFDocument from 'pdfkit';
import ExcelJS from 'exceljs';
import type { Pool } from 'pg';
import { sanitizeErrorText } from '../lib/errorText';

export type ReportType =
  | 'executive_summary'
  | 'project_report'
  | 'license_inventory'
  | 'audit_evidence'
  | 'vulnerability_report';

export type ReportFormat = 'pdf' | 'excel';
export type ReportStatus = 'pending' | 'generating' | 'ready' | 'failed';

export interface ReportRecord {
  id: string;
  projectId: string | null;
  reportType: ReportType;
  format: ReportFormat;
  status: ReportStatus;
  parameters: Record<string, unknown>;
  storageKey: string | null;
  fileSizeBytes: number | null;
  checksumSha256: string | null;
  errorMessage: string | null;
  requestedBy: string;
  requestedAt: Date;
  completedAt: Date | null;
}

interface ReportLicenseFinding {
  detectedLicense: string | null;
  normalizedLicense: string | null;
  riskLevel: string;
  appliedPolicy: string | null;
  status: string;
  suppressed: boolean;
}

interface ReportSecurityFinding {
  advisoryId: string;
  title: string;
  severity: string;
  cvssScore: number | null;
  fixVersion: string | null;
  fixAvailable: boolean;
  status: string;
  suppressed: boolean;
  publishedAt: Date | null;
}

interface ReportDependency {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  purl: string;
  scope: string;
  manifestFile: string;
  manifestPath: string;
  depth: number;
  licenses: ReportLicenseFinding[];
  vulnerabilities: ReportSecurityFinding[];
}

interface ReportData {
  generatedAt: Date;
  scan: {
    id: string;
    ref: string | null;
    trigger: string;
    completedAt: Date | null;
    createdAt: Date;
    totalDependencies: number;
    totalVulnerabilities: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
    lowVulns: number;
    licenseViolations: number;
  };
  project: {
    id: string;
    name: string;
    description: string | null;
    criticality: string;
    repoUrl: string | null;
  };
  dependencies: ReportDependency[];
}

const VALID_REPORT_TYPES = new Set<ReportType>([
  'executive_summary',
  'project_report',
  'license_inventory',
  'audit_evidence',
  'vulnerability_report',
]);

const FORMAT_META: Record<ReportFormat, { ext: string; mimeType: string }> = {
  pdf: {
    ext: 'pdf',
    mimeType: 'application/pdf',
  },
  excel: {
    ext: 'xlsx',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  },
};

export const VALID_REPORT_FORMATS = new Set<ReportFormat>(Object.keys(FORMAT_META) as ReportFormat[]);
export { VALID_REPORT_TYPES };

export class ReportService {
  constructor(private readonly db: Pool) {}

  async generate(
    scanId: string,
    reportType: ReportType,
    format: ReportFormat,
    requestedBy: string,
  ): Promise<ReportRecord> {
    if (!VALID_REPORT_TYPES.has(reportType)) {
      throw Object.assign(new Error(`reportType must be one of: ${[...VALID_REPORT_TYPES].join(', ')}`), {
        statusCode: 400,
      });
    }
    if (!VALID_REPORT_FORMATS.has(format)) {
      throw Object.assign(new Error(`format must be one of: ${[...VALID_REPORT_FORMATS].join(', ')}`), {
        statusCode: 400,
      });
    }

    const data = await this.loadReportData(scanId);
    const parameters = { scanId, reportType };
    const reportId = await this.createReportRecord(data.project.id, reportType, format, parameters, requestedBy);

    const result = await this.db.query<ReportRow>(
      `SELECT ${REPORT_COLUMNS}
       FROM reports
       WHERE id = $1`,
      [reportId],
    );

    return toRecord(result.rows[0]);
  }

  async processReport(reportId: string): Promise<ReportRecord> {
    const reportResult = await this.db.query<ReportRow>(
      `SELECT ${REPORT_COLUMNS}
       FROM reports
       WHERE id = $1`,
      [reportId],
    );

    if (reportResult.rows.length === 0) {
      throw new Error(`Report ${reportId} not found`);
    }

    const record = toRecord(reportResult.rows[0]);
    const scanId = record.parameters.scanId as string;

    try {
      const data = await this.loadReportData(scanId);
      const content = await this.renderContent(data, record.reportType, record.format);
      const checksum = crypto.createHash('sha256').update(content).digest('hex');
      const outputDir = process.env.REPORT_OUTPUT_DIR ?? path.join(process.cwd(), 'report-output');
      await fs.mkdir(outputDir, { recursive: true });

      const filename = `report-${scanId}-${record.reportType}.${FORMAT_META[record.format].ext}`;
      const storageKey = path.join(outputDir, filename);
      await fs.writeFile(storageKey, content);

      const result = await this.db.query<ReportRow>(
        `UPDATE reports
         SET status = 'ready',
             storage_key = $2,
             file_size_bytes = $3,
             checksum_sha256 = $4,
             completed_at = NOW(),
             error_message = NULL
         WHERE id = $1
         RETURNING ${REPORT_COLUMNS}`,
        [reportId, storageKey, content.length, checksum],
      );

      await this.db.query(
        `INSERT INTO audit_logs (action, actor_id, entity_type, entity_id, occurred_at)
         VALUES ('report_generated', $1, 'report', $2, NOW())`,
        [record.requestedBy, reportId],
      );

      return toRecord(result.rows[0]);
    } catch (err) {
      // L-5 (ADR-002 Ek E3): no secret, absolute path or control character in error_message.
      const message = sanitizeErrorText(err instanceof Error ? err.message : 'Report generation failed');
      const result = await this.db.query<ReportRow>(
        `UPDATE reports
         SET status = 'failed', error_message = $2, completed_at = NOW()
         WHERE id = $1
         RETURNING ${REPORT_COLUMNS}`,
        [reportId, message],
      );
      throw Object.assign(new Error(message), { statusCode: 500, report: toRecord(result.rows[0]) });
    }
  }

  async listByScan(scanId: string): Promise<ReportRecord[]> {
    const result = await this.db.query<ReportRow>(
      `SELECT ${REPORT_COLUMNS}
       FROM reports
       WHERE parameters->>'scanId' = $1
       ORDER BY requested_at DESC`,
      [scanId],
    );
    return result.rows.map(toRecord);
  }

  async readReport(reportId: string): Promise<{ record: ReportRecord; content: Buffer; mimeType: string }> {
    const result = await this.db.query<ReportRow>(
      `SELECT ${REPORT_COLUMNS}
       FROM reports
       WHERE id = $1`,
      [reportId],
    );

    if (result.rows.length === 0) {
      throw Object.assign(new Error('Report not found'), { statusCode: 404 });
    }

    const record = toRecord(result.rows[0]);
    if (record.status !== 'ready' || !record.storageKey) {
      throw Object.assign(new Error('Report is not ready for download'), { statusCode: 400 });
    }

    let content: Buffer;
    try {
      content = await fs.readFile(record.storageKey);
    } catch {
      throw Object.assign(new Error('Report file not found in storage'), { statusCode: 404 });
    }

    return {
      record,
      content,
      mimeType: FORMAT_META[record.format]?.mimeType ?? 'application/octet-stream',
    };
  }

  private async createReportRecord(
    projectId: string,
    reportType: ReportType,
    format: ReportFormat,
    parameters: Record<string, unknown>,
    requestedBy: string,
  ): Promise<string> {
    const result = await this.db.query<{ id: string }>(
      `INSERT INTO reports (project_id, report_type, format, status, parameters, requested_by)
       VALUES ($1, $2::report_type, $3::report_format, 'pending', $4::jsonb, $5)
       RETURNING id`,
      [projectId, reportType, format, JSON.stringify(parameters), requestedBy],
    );
    return result.rows[0].id;
  }

  private async renderContent(data: ReportData, reportType: ReportType, format: ReportFormat): Promise<Buffer> {
    if (format === 'pdf') {
      return renderPdfReport(data, reportType);
    }
    return renderExcelReport(data, reportType);
  }

  private async loadReportData(scanId: string): Promise<ReportData> {
    const scanResult = await this.db.query<{
      id: string;
      ref: string | null;
      trigger: string;
      completed_at: Date | null;
      created_at: Date;
      total_dependencies: number;
      total_vulnerabilities: number;
      critical_vulns: number;
      high_vulns: number;
      medium_vulns: number;
      low_vulns: number;
      license_violations: number;
      project_id: string;
      project_name: string;
      project_description: string | null;
      project_criticality: string;
      repo_url: string | null;
    }>(
      `SELECT s.id, s.ref, s.trigger::text, s.completed_at, s.created_at,
              s.total_dependencies, s.total_vulnerabilities, s.critical_vulns,
              s.high_vulns, s.medium_vulns, s.low_vulns, s.license_violations,
              p.id AS project_id, p.name AS project_name, p.description AS project_description,
              p.criticality::text AS project_criticality, p.repo_url
       FROM scans s
       JOIN projects p ON p.id = s.project_id
       WHERE s.id = $1 AND s.status = 'completed'`,
      [scanId],
    );

    if (scanResult.rows.length === 0) {
      throw Object.assign(new Error('Scan not found or not yet completed'), { statusCode: 404 });
    }

    const dependencyRows = await this.db.query<{
      scan_dependency_id: string;
      ecosystem: string;
      name: string;
      version: string;
      purl: string;
      scope: string;
      manifest_file: string;
      manifest_path: string;
      depth: number;
    }>(
      `SELECT sd.id AS scan_dependency_id, p.ecosystem::text, p.name, p.version, p.purl,
              sd.scope::text, sd.manifest_file, sd.manifest_path, sd.depth
       FROM scan_dependencies sd
       JOIN packages p ON p.id = sd.package_id
       WHERE sd.scan_id = $1
       ORDER BY p.name, p.version`,
      [scanId],
    );

    const licenseRows = await this.db.query<{
      scan_dependency_id: string;
      detected_license: string | null;
      normalized_license: string | null;
      risk_level: string;
      applied_policy: string | null;
      status: string;
      suppressed: boolean;
    }>(
      `SELECT f.scan_dependency_id, lf.detected_license, lf.normalized_license,
              lf.risk_level::text, lf.applied_policy::text, f.status::text, f.suppressed
       FROM findings f
       JOIN license_findings lf ON lf.finding_id = f.id
       WHERE f.scan_id = $1`,
      [scanId],
    );

    const vulnerabilityRows = await this.db.query<{
      scan_dependency_id: string;
      advisory_id: string;
      title: string;
      severity: string;
      cvss_score: string | null;
      fix_version: string | null;
      fix_available: boolean;
      status: string;
      suppressed: boolean;
      published_at: Date | null;
    }>(
      `SELECT f.scan_dependency_id,
              COALESCE(v.cve_id, v.ghsa_id, v.osv_id, v.id::text) AS advisory_id,
              v.title, sf.severity::text, sf.cvss_score::text, sf.fix_version,
              sf.fix_available, f.status::text, f.suppressed, v.published_at
       FROM findings f
       JOIN security_findings sf ON sf.finding_id = f.id
       JOIN vulnerabilities v ON v.id = sf.vulnerability_id
       WHERE f.scan_id = $1`,
      [scanId],
    );

    const licensesByDependency = new Map<string, ReportLicenseFinding[]>();
    for (const row of licenseRows.rows) {
      const entries = licensesByDependency.get(row.scan_dependency_id) ?? [];
      entries.push({
        detectedLicense: row.detected_license,
        normalizedLicense: row.normalized_license,
        riskLevel: row.risk_level,
        appliedPolicy: row.applied_policy,
        status: row.status,
        suppressed: row.suppressed,
      });
      licensesByDependency.set(row.scan_dependency_id, entries);
    }

    const vulnerabilitiesByDependency = new Map<string, ReportSecurityFinding[]>();
    for (const row of vulnerabilityRows.rows) {
      const entries = vulnerabilitiesByDependency.get(row.scan_dependency_id) ?? [];
      entries.push({
        advisoryId: row.advisory_id,
        title: row.title,
        severity: row.severity,
        cvssScore: row.cvss_score != null ? Number(row.cvss_score) : null,
        fixVersion: row.fix_version,
        fixAvailable: row.fix_available,
        status: row.status,
        suppressed: row.suppressed,
        publishedAt: row.published_at,
      });
      vulnerabilitiesByDependency.set(row.scan_dependency_id, entries);
    }

    const scan = scanResult.rows[0];
    return {
      generatedAt: new Date(),
      scan: {
        id: scan.id,
        ref: scan.ref,
        trigger: scan.trigger,
        completedAt: scan.completed_at,
        createdAt: scan.created_at,
        totalDependencies: scan.total_dependencies,
        totalVulnerabilities: scan.total_vulnerabilities,
        criticalVulns: scan.critical_vulns,
        highVulns: scan.high_vulns,
        mediumVulns: scan.medium_vulns,
        lowVulns: scan.low_vulns,
        licenseViolations: scan.license_violations,
      },
      project: {
        id: scan.project_id,
        name: scan.project_name,
        description: scan.project_description,
        criticality: scan.project_criticality,
        repoUrl: scan.repo_url,
      },
      dependencies: dependencyRows.rows.map((row) => ({
        id: row.scan_dependency_id,
        ecosystem: row.ecosystem,
        name: row.name,
        version: row.version,
        purl: row.purl,
        scope: row.scope,
        manifestFile: row.manifest_file,
        manifestPath: row.manifest_path,
        depth: row.depth,
        licenses: licensesByDependency.get(row.scan_dependency_id) ?? [],
        vulnerabilities: vulnerabilitiesByDependency.get(row.scan_dependency_id) ?? [],
      })),
    };
  }
}

async function renderPdfReport(data: ReportData, reportType: ReportType): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 48, size: 'A4', bufferPages: true });
  const chunks: Buffer[] = [];

  doc.on('data', (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
  });

  doc.fontSize(18).text(reportTitle(reportType), { underline: false });
  doc.moveDown(0.5);
  doc.fontSize(11).text(`Project: ${data.project.name}`);
  doc.text(`Scan: ${data.scan.id}`);
  doc.text(`Generated: ${formatDate(data.generatedAt)}`);
  if (data.project.repoUrl) doc.text(`Repository: ${data.project.repoUrl}`);
  doc.moveDown();

  writePdfSection(doc, 'Summary');
  writePdfKeyValues(doc, [
    ['Criticality', data.project.criticality],
    ['Ref', data.scan.ref ?? 'n/a'],
    ['Trigger', data.scan.trigger],
    ['Completed', formatDate(data.scan.completedAt)],
    ['Dependencies', String(data.scan.totalDependencies)],
    ['Vulnerabilities', String(data.scan.totalVulnerabilities)],
    ['Critical / High', `${data.scan.criticalVulns} / ${data.scan.highVulns}`],
    ['License violations', String(data.scan.licenseViolations)],
  ]);

  if (reportType !== 'license_inventory') {
    writePdfSection(doc, 'Security Findings');
    const vulnerabilities = data.dependencies.flatMap((dep) =>
      dep.vulnerabilities.map((vuln) => ({ dep, vuln })),
    );
    writePdfRows(
      doc,
      vulnerabilities.slice(0, 40).map(({ dep, vuln }) => [
        `${dep.name}@${dep.version}`,
        vuln.advisoryId,
        vuln.severity,
        vuln.fixVersion ?? 'n/a',
        vuln.status,
      ]),
      ['Package', 'Advisory', 'Severity', 'Fix', 'Status'],
    );
  }

  if (reportType !== 'vulnerability_report') {
    writePdfSection(doc, 'License Findings');
    const licenses = data.dependencies.flatMap((dep) =>
      dep.licenses.map((license) => ({ dep, license })),
    );
    writePdfRows(
      doc,
      licenses.slice(0, 40).map(({ dep, license }) => [
        `${dep.name}@${dep.version}`,
        license.normalizedLicense ?? license.detectedLicense ?? 'unknown',
        license.riskLevel,
        license.appliedPolicy ?? 'n/a',
        license.status,
      ]),
      ['Package', 'License', 'Risk', 'Policy', 'Status'],
    );
  }

  if (reportType === 'project_report' || reportType === 'audit_evidence') {
    writePdfSection(doc, 'Dependency Inventory');
    writePdfRows(
      doc,
      data.dependencies.slice(0, 50).map((dep) => [
        `${dep.name}@${dep.version}`,
        dep.ecosystem,
        dep.scope,
        dep.manifestPath,
        String(dep.depth),
      ]),
      ['Package', 'Eco', 'Scope', 'Manifest', 'Depth'],
    );
  }

  doc.end();
  return done;
}

async function renderExcelReport(data: ReportData, reportType: ReportType): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'OSS License & Security Risk Platform';
  workbook.created = data.generatedAt;
  workbook.modified = data.generatedAt;

  const summary = workbook.addWorksheet('Summary');
  summary.columns = [{ header: 'Metric', key: 'metric', width: 28 }, { header: 'Value', key: 'value', width: 48 }];
  summary.addRows([
    { metric: 'Report Type', value: reportTitle(reportType) },
    { metric: 'Project', value: data.project.name },
    { metric: 'Project Criticality', value: data.project.criticality },
    { metric: 'Repository', value: data.project.repoUrl ?? '' },
    { metric: 'Scan ID', value: data.scan.id },
    { metric: 'Reference', value: data.scan.ref ?? '' },
    { metric: 'Completed At', value: formatDate(data.scan.completedAt) },
    { metric: 'Generated At', value: formatDate(data.generatedAt) },
    { metric: 'Total Dependencies', value: data.scan.totalDependencies },
    { metric: 'Total Vulnerabilities', value: data.scan.totalVulnerabilities },
    { metric: 'Critical Vulnerabilities', value: data.scan.criticalVulns },
    { metric: 'High Vulnerabilities', value: data.scan.highVulns },
    { metric: 'Medium Vulnerabilities', value: data.scan.mediumVulns },
    { metric: 'Low Vulnerabilities', value: data.scan.lowVulns },
    { metric: 'License Violations', value: data.scan.licenseViolations },
  ]);

  addDependencyWorksheet(workbook, data);
  addLicenseWorksheet(workbook, data);
  addVulnerabilityWorksheet(workbook, data);

  for (const sheet of workbook.worksheets) {
    sheet.getRow(1).font = { bold: true };
    sheet.views = [{ state: 'frozen', ySplit: 1 }];
    if (sheet.columnCount > 0) {
      sheet.autoFilter = {
        from: { row: 1, column: 1 },
        to: { row: 1, column: sheet.columnCount },
      };
    }
  }

  const bytes = await workbook.xlsx.writeBuffer();
  return Buffer.from(bytes);
}

function addDependencyWorksheet(workbook: ExcelJS.Workbook, data: ReportData): void {
  const sheet = workbook.addWorksheet('Dependencies');
  sheet.columns = [
    { header: 'Name', key: 'name', width: 32 },
    { header: 'Version', key: 'version', width: 18 },
    { header: 'Ecosystem', key: 'ecosystem', width: 14 },
    { header: 'Scope', key: 'scope', width: 14 },
    { header: 'Manifest', key: 'manifest', width: 36 },
    { header: 'Depth', key: 'depth', width: 10 },
    { header: 'PURL', key: 'purl', width: 72 },
  ];
  sheet.addRows(data.dependencies.map((dep) => ({
    name: dep.name,
    version: dep.version,
    ecosystem: dep.ecosystem,
    scope: dep.scope,
    manifest: dep.manifestPath || dep.manifestFile,
    depth: dep.depth,
    purl: dep.purl,
  })));
}

function addLicenseWorksheet(workbook: ExcelJS.Workbook, data: ReportData): void {
  const sheet = workbook.addWorksheet('Licenses');
  sheet.columns = [
    { header: 'Package', key: 'packageName', width: 36 },
    { header: 'Version', key: 'version', width: 18 },
    { header: 'Detected License', key: 'detectedLicense', width: 24 },
    { header: 'Normalized License', key: 'normalizedLicense', width: 24 },
    { header: 'Risk', key: 'riskLevel', width: 14 },
    { header: 'Policy', key: 'policy', width: 18 },
    { header: 'Status', key: 'status', width: 18 },
    { header: 'Suppressed', key: 'suppressed', width: 12 },
  ];

  sheet.addRows(data.dependencies.flatMap((dep) =>
    dep.licenses.map((license) => ({
      packageName: dep.name,
      version: dep.version,
      detectedLicense: license.detectedLicense ?? '',
      normalizedLicense: license.normalizedLicense ?? '',
      riskLevel: license.riskLevel,
      policy: license.appliedPolicy ?? '',
      status: license.status,
      suppressed: license.suppressed ? 'yes' : 'no',
    })),
  ));
}

function addVulnerabilityWorksheet(workbook: ExcelJS.Workbook, data: ReportData): void {
  const sheet = workbook.addWorksheet('Vulnerabilities');
  sheet.columns = [
    { header: 'Package', key: 'packageName', width: 36 },
    { header: 'Version', key: 'version', width: 18 },
    { header: 'Advisory', key: 'advisory', width: 24 },
    { header: 'Title', key: 'title', width: 56 },
    { header: 'Severity', key: 'severity', width: 14 },
    { header: 'CVSS', key: 'cvss', width: 10 },
    { header: 'Fix Version', key: 'fixVersion', width: 18 },
    { header: 'Fix Available', key: 'fixAvailable', width: 14 },
    { header: 'Status', key: 'status', width: 18 },
    { header: 'Suppressed', key: 'suppressed', width: 12 },
    { header: 'Published At', key: 'publishedAt', width: 24 },
  ];

  sheet.addRows(data.dependencies.flatMap((dep) =>
    dep.vulnerabilities.map((vuln) => ({
      packageName: dep.name,
      version: dep.version,
      advisory: vuln.advisoryId,
      title: vuln.title,
      severity: vuln.severity,
      cvss: vuln.cvssScore ?? '',
      fixVersion: vuln.fixVersion ?? '',
      fixAvailable: vuln.fixAvailable ? 'yes' : 'no',
      status: vuln.status,
      suppressed: vuln.suppressed ? 'yes' : 'no',
      publishedAt: formatDate(vuln.publishedAt),
    })),
  ));
}

function writePdfSection(doc: PDFKit.PDFDocument, title: string): void {
  doc.moveDown(0.8);
  doc.fontSize(14).text(title);
  doc.moveDown(0.3);
}

function writePdfKeyValues(doc: PDFKit.PDFDocument, rows: Array<[string, string]>): void {
  doc.fontSize(10);
  for (const [key, value] of rows) {
    doc.text(`${key}: ${value}`);
  }
}

function writePdfRows(doc: PDFKit.PDFDocument, rows: string[][], headers: string[]): void {
  doc.fontSize(9).text(headers.join(' | '));
  doc.moveDown(0.2);

  if (rows.length === 0) {
    doc.text('No records found.');
    return;
  }

  for (const row of rows) {
    if (doc.y > 740) doc.addPage();
    doc.text(row.map((value) => truncate(value, 28)).join(' | '));
  }
}

function reportTitle(reportType: ReportType): string {
  return reportType
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function formatDate(value: Date | null): string {
  return value ? value.toISOString() : 'n/a';
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 3)}...` : value;
}

const REPORT_COLUMNS = `id, project_id,
                        report_type::text AS report_type,
                        format::text AS format,
                        status::text AS status,
                        parameters, storage_key, file_size_bytes, checksum_sha256,
                        error_message, requested_by, requested_at, completed_at`;

interface ReportRow {
  id: string;
  project_id: string | null;
  report_type: ReportType;
  format: ReportFormat;
  status: ReportStatus;
  parameters: Record<string, unknown>;
  storage_key: string | null;
  file_size_bytes: string | number | null;
  checksum_sha256: string | null;
  error_message: string | null;
  requested_by: string;
  requested_at: Date;
  completed_at: Date | null;
}

function toRecord(row: ReportRow): ReportRecord {
  return {
    id: row.id,
    projectId: row.project_id,
    reportType: row.report_type,
    format: row.format,
    status: row.status,
    parameters: row.parameters,
    storageKey: row.storage_key,
    fileSizeBytes: row.file_size_bytes == null ? null : Number(row.file_size_bytes),
    checksumSha256: row.checksum_sha256,
    errorMessage: row.error_message,
    requestedBy: row.requested_by,
    requestedAt: row.requested_at,
    completedAt: row.completed_at,
  };
}
