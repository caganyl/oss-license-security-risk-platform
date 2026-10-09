import { Router } from 'express';
import type { RequestHandler } from 'express';
import type { AuthController } from '../controllers/authController';
import { requireSession } from '../middleware/authenticate';

/**
 * Exempt endpoints (ADR-001 karar 9). Mounted on `/api` before the
 * authentication middleware; both still require an allowed Origin.
 */
export function createPublicAuthRouter(
  controller: AuthController,
  sameOrigin: RequestHandler,
  jsonBody: RequestHandler,
): Router {
  const router = Router();
  router.post('/auth/setup', sameOrigin, jsonBody, controller.setup);
  router.post('/auth/login', sameOrigin, jsonBody, controller.login);
  return router;
}

/** Authenticated auth endpoints, mounted on `/api/auth` after authentication. */
export function createAuthRouter(controller: AuthController): Router {
  const router = Router();
  const sessionOnly = requireSession();
  router.get('/me', controller.me);
  router.post('/logout', sessionOnly, controller.logout);
  router.get('/api-keys', sessionOnly, controller.listApiKeys);
  router.post('/api-keys', sessionOnly, controller.createApiKey);
  router.delete('/api-keys/:id', sessionOnly, controller.revokeApiKey);
  return router;
}

export default createAuthRouter;
