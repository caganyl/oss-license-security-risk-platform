import { Router } from 'express';
import type { Pool } from 'pg';
import { ScanController } from '../controllers/scanController';
import { guard } from '../middleware/rbac';

export function createScanRouter(db: Pool, scanRoots: readonly string[] = []): Router {
  const router = Router();
  const controller = new ScanController(db, scanRoots);

  router.get('/scans', guard('scans:read'), controller.listScans);
  router.post('/scans', guard('scans:write'), controller.createScan);
  router.get('/scans/:id', guard('scans:read'), controller.getScan);
  router.get('/scans/:id/findings', guard('findings:read'), controller.getScanFindings);

  return router;
}

export default createScanRouter;
