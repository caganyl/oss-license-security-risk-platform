import { Router, type NextFunction, type Request, type Response } from 'express';
import type { Pool } from 'pg';
import { guard } from '../middleware/rbac';
import { loadWebScanResult } from '../webscan/report';

/**
 * `GET /api/scans/:id/web-findings` (REQ-008 AC-P27-1, contract 3.6):
 * findings, components, score and grade of a completed web scan.
 */
export function createWebFindingsRouter(db: Pool): Router {
  const router = Router();
  router.get('/scans/:id/web-findings', guard('findings:read'), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = String(req.params.id ?? '').toLowerCase();
      res.setHeader('Cache-Control', 'no-store');
      res.json({ data: await loadWebScanResult(db, id) });
    } catch (err) {
      next(err);
    }
  });
  return router;
}

export default createWebFindingsRouter;
