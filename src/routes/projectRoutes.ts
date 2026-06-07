import { Router } from 'express';
import type { Pool } from 'pg';
import { ProjectController } from '../controllers/projectController';
import { guard } from '../middleware/rbac';

export function createProjectRouter(db: Pool): Router {
  const router = Router();
  const controller = new ProjectController(db);

  router.get('/projects', guard('projects:read'), controller.listProjects);
  router.post('/projects', guard('projects:write'), controller.createProject);

  return router;
}

export default createProjectRouter;
