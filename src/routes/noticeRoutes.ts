import { Router } from 'express';
import type { Pool } from 'pg';
import { NoticeController } from '../controllers/noticeController';
import { guard } from '../middleware/rbac';

/**
 * NOTICE download route (REQ-004 P-15, ADR-006 Karar 12).
 *
 *   GET /api/scans/:scanId/notice   NOTICE.txt of a completed scan (reports:read)
 *
 * Mounted after the global authentication middleware, like the SBOM routes.
 */
export function createNoticeRouter(db: Pool): Router {
  const router = Router();
  const controller = new NoticeController(db);

  router.get('/scans/:scanId/notice', guard('reports:read'), controller.download);

  return router;
}

export default createNoticeRouter;
