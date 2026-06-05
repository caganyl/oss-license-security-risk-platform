import { Router } from 'express';
import type { Pool } from 'pg';
import { WorkflowController } from '../controllers/workflowController';
import { guard } from '../middleware/rbac';

/**
 * Finding remediation workflow routes.
 *
 * Mount under `/findings` or `/api/findings` from the application entrypoint:
 *
 *   app.use('/api/findings', createWorkflowRouter(pool));
 */
export function createWorkflowRouter(db: Pool): Router {
  const router = Router();
  const controller = new WorkflowController(db);

  router.get('/:id/workflow', guard('findings:read'), controller.getWorkflow);
  router.post('/:id/assign', guard('findings:write'), controller.assignFinding);
  router.post('/:id/unassign', guard('findings:write'), controller.unassignFinding);
  router.post('/:id/resolve', guard('findings:write'), controller.resolveFinding);
  router.post('/:id/accept-risk', guard('reviews:write'), controller.acceptRisk);
  router.post('/:id/false-positive', guard('reviews:write'), controller.markFalsePositive);
  router.post('/:id/wont-fix', guard('reviews:write'), controller.wontFix);
  router.post('/:id/reopen', guard('findings:write'), controller.reopenFinding);
  router.post('/:id/comments', guard('comments:write'), controller.addComment);

  return router;
}

export default createWorkflowRouter;
