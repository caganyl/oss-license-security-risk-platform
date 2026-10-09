import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { sendError } from '../lib/httpError';
import { SbomService, VALID_FORMATS } from '../sbom/sbomService';
import type { SbomFormat, SbomDocumentRecord } from '../sbom/sbomService';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value: string | undefined): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

function handleError(err: unknown, res: Response, next: NextFunction): void {
  const error = err as Error & { statusCode?: number };
  if (error.statusCode) {
    sendError(res, error.statusCode, error.message);
    return;
  }
  next(err);
}

export class SbomController {
  private readonly service: SbomService;

  constructor(db: Pool) {
    this.service = new SbomService(db);
  }

  generate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { scanId } = req.params;
      if (!isUuid(scanId)) {
        throw Object.assign(new Error('scanId must be a valid UUID'), { statusCode: 400 });
      }

      const rawFormat: unknown = req.body?.format;
      if (typeof rawFormat !== 'string' || !VALID_FORMATS.has(rawFormat as SbomFormat)) {
        throw Object.assign(
          new Error(`format must be one of: ${[...VALID_FORMATS].join(', ')}`),
          { statusCode: 400 },
        );
      }

      const doc = await this.service.generate(
        scanId,
        rawFormat as SbomFormat,
        req.user?.id,
      );

      res.status(201).json({ data: toResponse(doc) });
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

      const docs = await this.service.listByScan(scanId);
      res.json({ data: docs.map(toResponse) });
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

      const { record, content } = await this.service.readDocument(id);
      const downloadExt =
        record.format === 'spdx_json' || record.format === 'cyclonedx_json' ? 'json'
        : record.format === 'cyclonedx_xml' ? 'xml'
        : record.format === 'spdx_tag_value' ? 'txt'
        : 'json';
      const filename = `sbom-${record.scanId}-${record.format}.${downloadExt}`;

      res.attachment(filename);
      res.setHeader('Content-Length', content.length);
      res.setHeader('X-Checksum-SHA256', record.checksumSha256);
      res.send(content);
    } catch (err) {
      handleError(err, res, next);
    }
  };

  downloadDirect = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { scanId } = req.params;
      if (!isUuid(scanId)) {
        throw Object.assign(new Error('scanId must be a valid UUID'), { statusCode: 400 });
      }

      const existing = await this.service.listByScan(scanId);
      const cyclonedx = existing.find(d => d.format === 'cyclonedx_json');

      let doc;
      if (cyclonedx) {
        doc = cyclonedx;
      } else {
        doc = await this.service.generate(scanId, 'cyclonedx_json', req.user?.id);
      }

      const { content } = await this.service.readDocument(doc.id);
      const downloadExt =
        doc.format === 'spdx_json' || doc.format === 'cyclonedx_json' ? 'json'
        : doc.format === 'cyclonedx_xml' ? 'xml'
        : doc.format === 'spdx_tag_value' ? 'txt'
        : 'json';
      const filename = `sbom-${scanId}-${doc.format}.${downloadExt}`;

      res.attachment(filename);
      res.setHeader('Content-Length', content.length);
      res.setHeader('X-Checksum-SHA256', doc.checksumSha256);
      res.send(content);
    } catch (err) {
      handleError(err, res, next);
    }
  };
}

function toResponse(doc: SbomDocumentRecord) {
  return {
    id: doc.id,
    scanId: doc.scanId,
    format: doc.format,
    specVersion: doc.specVersion,
    fileSizeBytes: doc.fileSizeBytes,
    checksumSha256: doc.checksumSha256,
    documentId: doc.documentId,
    generatedBy: doc.generatedBy,
    generatedAt: doc.generatedAt,
  };
}
