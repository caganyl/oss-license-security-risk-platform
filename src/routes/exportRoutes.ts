import { Router } from 'express';
import type { Pool } from 'pg';
import { ExportController } from '../controllers/exportController';
import { guard } from '../middleware/rbac';
import type { ExportLimiter } from '../reports/exportLimiter';

/**
 * One-click export routes (REQ-007 P-24, ADR-009 Karar 7; contract
 * `docs/contracts/REQ-007-cli-and-exports.md` section 6).
 *
 *   GET /api/scans/:scanId/exports/project-report.pdf       project PDF       (reports:read)
 *   GET /api/scans/:scanId/exports/license-inventory.xlsx   license Excel     (reports:read)
 *   GET /api/scans/:scanId/exports/license-inventory.csv    license CSV       (reports:read)
 *
 * Three explicit routes, no file-name parameter: any other suffix falls to
 * the `/api` 404. Mounted after the global authentication middleware, like
 * the NOTICE route; `limiter` belongs to the `createApp` instance.
 */
export function createExportRouter(db: Pool, limiter: ExportLimiter): Router {
  const router = Router();
  const controller = new ExportController(db, limiter);

  router.get('/scans/:scanId/exports/project-report.pdf', guard('reports:read'), controller.download('project-report.pdf'));
  router.get(
    '/scans/:scanId/exports/license-inventory.xlsx',
    guard('reports:read'),
    controller.download('license-inventory.xlsx'),
  );
  router.get('/scans/:scanId/exports/license-inventory.csv', guard('reports:read'), controller.download('license-inventory.csv'));
  // REQ-008 contract 3.7: web scan outputs (same limiter and error order).
  router.get('/scans/:scanId/exports/web-report.pdf', guard('reports:read'), controller.download('web-report.pdf'));
  router.get('/scans/:scanId/exports/web-findings.csv', guard('reports:read'), controller.download('web-findings.csv'));

  return router;
}

export default createExportRouter;
