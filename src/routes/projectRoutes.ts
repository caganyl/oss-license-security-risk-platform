import { Router } from 'express';
import type { Pool } from 'pg';
import { ProjectController } from '../controllers/projectController';
import { guard } from '../middleware/rbac';
import type { HostAllowlist } from '../webscan/allowlist';

export function createProjectRouter(db: Pool, scanRoots: readonly string[] = [], webAllowlist?: HostAllowlist): Router {
  const router = Router();
  const controller = new ProjectController(db, scanRoots, webAllowlist);

  router.get('/projects', guard('projects:read'), controller.listProjects);
  router.post('/projects', guard('projects:write'), controller.createProject);
  router.patch('/projects/:id', guard('projects:write'), controller.updateProject);

  return router;
}

export default createProjectRouter;
