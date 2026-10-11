import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Pool } from 'pg';
import { INTERNAL_ERROR_MESSAGE, sendError } from '../lib/httpError';
import { EXPORT_RETRY_AFTER_SECONDS, type ExportLimiter } from '../reports/exportLimiter';
import { ReportService, type ExportKind } from '../reports/reportService';
import { exportWorkerConfig } from '../reports/worker.config';

/** Same validation and text as `NoticeController` (REQ-007 contract 6.5). */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * One-click exports `GET /api/scans/{scanId}/exports/<kind>` (REQ-007 P-24,
 * ADR-009 Karar 7). Evaluation order after the global Host and
 * authentication checks and the route's RBAC guard (contract 6.5):
 * UUID (400) -> export slot (429) -> scan lookup (404) -> render (200/500).
 * A busy server answers 429 even for an unknown scan, without a DB query.
 *
 * Headers are written only once the whole body exists, so an error response
 * never carries `Content-Disposition`. Side-effect free like NOTICE.
 */
export class ExportController {
  private readonly service: ReportService;

  constructor(
    db: Pool,
    private readonly limiter: ExportLimiter,
    private readonly timeoutMs: number = exportWorkerConfig.timeoutMs,
  ) {
    this.service = new ReportService(db);
  }

  download(kind: ExportKind): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const { scanId } = req.params;
      if (typeof scanId !== 'string' || !UUID_RE.test(scanId)) {
        sendError(res, 400, 'scanId must be a valid UUID');
        return;
      }

      const release = this.limiter.tryAcquire();
      if (!release) {
        res.setHeader('Retry-After', String(EXPORT_RETRY_AFTER_SECONDS));
        res.setHeader('Cache-Control', 'no-store');
        sendError(res, 429, 'Too many exports in progress; retry shortly', 'export_busy');
        return;
      }

      // A client that disconnects does not stop rendering (it cannot be
      // interrupted); the slot is still released and nothing is written.
      let clientGone = false;
      res.once('close', () => {
        clientGone = true;
      });
      const timeout = new AbortController();
      const timer = setTimeout(() => timeout.abort(new Error('Export generation timed out')), this.timeoutMs);

      try {
        const output = await this.service.renderExport(scanId.toLowerCase(), kind, timeout.signal);
        if (clientGone) return;
        res.status(200);
        res.setHeader('Content-Type', output.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${output.filename}"`);
        res.setHeader('Content-Length', output.body.length);
        res.setHeader('X-Checksum-SHA256', output.sha256);
        res.setHeader('Cache-Control', 'no-store');
        // `end`, not `send`: no ETag and no Content-Type rewrite (contract 6.4).
        res.end(output.body);
      } catch (err) {
        if (clientGone) return;
        const error = err as Error & { statusCode?: number };
        if (error.statusCode === 404) {
          sendError(res, 404, error.message);
          return;
        }
        if (timeout.signal.aborted) {
          // Detail only in the server log; the scan id is a validated UUID (L-5).
          console.error(`Export ${kind} for scan ${scanId.toLowerCase()} exceeded ${this.timeoutMs} ms`);
          res.setHeader('Cache-Control', 'no-store');
          sendError(res, 500, INTERNAL_ERROR_MESSAGE, 'internal_error');
          return;
        }
        // Anything else: the global handler answers 500 without the raw error text.
        next(err);
      } finally {
        clearTimeout(timer);
        release();
      }
    };
  }
}
