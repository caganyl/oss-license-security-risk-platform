import { Router } from 'express';
import type { Pool } from 'pg';
import { SbomController } from '../controllers/sbomController';
import { guard } from '../middleware/rbac';

/**
 * SBOM generation and download routes.
 *
 * Mount from the application entrypoint:
 *
 *   app.use('/api', createSbomRouter(pool));
 *
 * Endpoints:
 *   POST   /api/scans/:scanId/sbom         generate a new SBOM document
 *   GET    /api/scans/:scanId/sbom         list SBOM documents for a scan
 *   GET    /api/sbom/:id/download          download a specific SBOM document
 */
export function createSbomRouter(db: Pool): Router {
  const router = Router();
  const controller = new SbomController(db);

  router.post('/scans/:scanId/sbom', guard('sbom:generate'), controller.generate);
  router.get('/scans/:scanId/sbom',  guard('sbom:read'),     controller.list);
  router.get('/sbom/:id/download',   guard('sbom:read'),     controller.download);

  return router;
}

export default createSbomRouter;
