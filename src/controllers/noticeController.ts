import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { sendError } from '../lib/httpError';
import { NoticeService } from '../notice/noticeService';

/** Same validation as `SbomController` (REQ-004 contract section 2.2). */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * `GET /api/scans/{scanId}/notice` (REQ-004 P-15, ADR-006 Karar 12). Headers
 * are written only after the whole body is generated, so an error response
 * never carries `Content-Disposition` (contract section 2.3).
 */
export class NoticeController {
  private readonly service: NoticeService;

  constructor(db: Pool) {
    this.service = new NoticeService(db);
  }

  download = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { scanId } = req.params;
      if (typeof scanId !== 'string' || !UUID_RE.test(scanId)) {
        sendError(res, 400, 'scanId must be a valid UUID');
        return;
      }

      const notice = await this.service.generate(scanId.toLowerCase());

      res.status(200);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="NOTICE-${notice.scanId}.txt"`);
      res.setHeader('Content-Length', notice.body.length);
      res.setHeader('X-Checksum-SHA256', notice.sha256);
      res.setHeader('Cache-Control', 'no-store');
      res.send(notice.body);
    } catch (err) {
      const error = err as Error & { statusCode?: number };
      if (error.statusCode === 404) {
        sendError(res, 404, error.message);
        return;
      }
      // Anything else: the global handler answers 500 without the raw error text.
      next(err);
    }
  };
}
