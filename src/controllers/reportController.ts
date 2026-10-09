import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { sendError } from '../lib/httpError';
import {
  ReportService,
  VALID_REPORT_FORMATS,
  VALID_REPORT_TYPES,
} from '../reports/reportService';
import type { ReportFormat, ReportRecord, ReportType } from '../reports/reportService';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value: string | undefined): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

function handleError(err: unknown, res: Response, next: NextFunction): void {
  const error = err as Error & { statusCode?: number; report?: ReportRecord };
  if (error.statusCode) {
    // 5xx messages are replaced by a fixed text inside sendError (AC-G-8).
    sendError(res, error.statusCode, error.message, undefined, error.report ? { report: toResponse(error.report) } : {});
    return;
  }
  next(err);
}

export class ReportController {
  private readonly service: ReportService;

  constructor(db: Pool) {
    this.service = new ReportService(db);
  }

  generate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { scanId } = req.params;
      if (!isUuid(scanId)) {
        throw Object.assign(new Error('scanId must be a valid UUID'), { statusCode: 400 });
      }
      if (!req.user?.id) {
        throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
      }

      const rawType: unknown = req.body?.reportType;
      if (typeof rawType !== 'string' || !VALID_REPORT_TYPES.has(rawType as ReportType)) {
        throw Object.assign(
          new Error(`reportType must be one of: ${[...VALID_REPORT_TYPES].join(', ')}`),
          { statusCode: 400 },
        );
      }

      const rawFormat: unknown = req.body?.format;
      if (typeof rawFormat !== 'string' || !VALID_REPORT_FORMATS.has(rawFormat as ReportFormat)) {
        throw Object.assign(
          new Error(`format must be one of: ${[...VALID_REPORT_FORMATS].join(', ')}`),
          { statusCode: 400 },
        );
      }

      const report = await this.service.generate(
        scanId,
        rawType as ReportType,
        rawFormat as ReportFormat,
        req.user.id,
      );

      res.status(202).json({ data: toResponse(report) });
    } catch (err) {
      handleError(err, res, next);
    }
  };

  list = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { scanId } = req.params;
      if (!isUuid(scanId)) {
        throw Object.assign(new Error('scanId must be a valid UUID'), { statusCode: 400 });
      }

      const reports = await this.service.listByScan(scanId);
      res.json({ data: reports.map(toResponse) });
    } catch (err) {
      handleError(err, res, next);
    }
  };

  download = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;
      if (!isUuid(id)) {
        throw Object.assign(new Error('id must be a valid UUID'), { statusCode: 400 });
      }

      const { record, content } = await this.service.readReport(id);
      const ext = record.format === 'excel' ? 'xlsx' : record.format;
      const scanId = typeof record.parameters.scanId === 'string' ? record.parameters.scanId : record.id;
      const filename = `report-${scanId}-${record.reportType}.${ext}`;

      res.attachment(filename);
      res.setHeader('Content-Length', content.length);
      if (record.checksumSha256) {
        res.setHeader('X-Checksum-SHA256', record.checksumSha256);
      }
      res.send(content);
    } catch (err) {
      handleError(err, res, next);
    }
  };
}

function toResponse(report: ReportRecord) {
  return {
    id: report.id,
    projectId: report.projectId,
    reportType: report.reportType,
    format: report.format,
    status: report.status,
    parameters: report.parameters,
    fileSizeBytes: report.fileSizeBytes,
    checksumSha256: report.checksumSha256,
    errorMessage: report.errorMessage,
    requestedBy: report.requestedBy,
    requestedAt: report.requestedAt,
    completedAt: report.completedAt,
  };
}
