import { Router } from 'express';
import type { Pool } from 'pg';
import { UserController } from '../controllers/userController';
import { guard } from '../middleware/rbac';

/**
 * User management API routes.
 *
 * Mount under `/users` or `/api/users` from the application entrypoint:
 *
 *   app.use('/api/users', createUserRouter(pool));
 */
export function createUserRouter(db: Pool): Router {
  const router = Router();
  const controller = new UserController(db);

  router.get('/', guard('users:read'), controller.listUsers);
  router.post('/', guard('users:write'), controller.createUser);
  router.get('/:id', guard('users:read'), controller.getUser);
  router.patch('/:id', guard('users:write'), controller.updateUser);
  router.put('/:id/roles', guard('roles:write'), controller.updateUserRoles);
  router.delete('/:id', guard('users:delete'), controller.deleteUser);

  return router;
}

export default createUserRouter;
