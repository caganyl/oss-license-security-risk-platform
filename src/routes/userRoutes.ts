import { Router } from 'express';
import type { Pool } from 'pg';
import { UserController } from '../controllers/userController';
import { requireSession } from '../middleware/authenticate';
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

  // K11 / AC-P01-18: user management is cookie-only. A leaked CI API key must
  // not list, create, re-role or delete users, so every route rejects Bearer
  // authentication with 403 before RBAC or the controller runs. (When an
  // Authorization header is present, authenticate() ignores the cookie, so a
  // Bearer + cookie request is also rejected here.)
  router.use(requireSession());

  router.get('/', guard('users:read'), controller.listUsers);
  router.post('/', guard('users:write'), controller.createUser);
  router.get('/:id', guard('users:read'), controller.getUser);
  router.patch('/:id', guard('users:write'), controller.updateUser);
  router.put('/:id/roles', guard('roles:write'), controller.updateUserRoles);
  router.delete('/:id', guard('users:delete'), controller.deleteUser);

  return router;
}

export default createUserRouter;
