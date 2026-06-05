import { Router } from 'express';
import type { Pool } from 'pg';
import { ReportController } from '../controllers/reportController';
import { guard } from '../middleware/rbac';

/**
 * Compliance report generation and download routes.
 *
 * Mount from the application entrypoint:
 *
 *   app.use('/api', createReportRouter(pool));
 *
 * Endpoints:
 *   POST   /api/scans/:scanId/reports         generate a PDF or Excel report
 *   GET    /api/scans/:scanId/reports         list generated reports for a scan
 *   GET    /api/reports/:id/download          download a ready report
 */
export function createReportRouter(db: Pool): Router {
  const router = Router();
  const controller = new ReportController(db);

  router.post('/scans/:scanId/reports', guard('reports:generate'), controller.generate);
  router.get('/scans/:scanId/reports',  guard('reports:read'),     controller.list);
  router.get('/reports/:id/download',   guard('reports:read'),     controller.download);

  return router;
}

export default createReportRouter;
