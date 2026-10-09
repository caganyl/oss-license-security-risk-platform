import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { Permission, RoleName } from '../types/auth';
import { hasPermission, hasRole } from '../config/permissions';
import { sendError } from '../lib/httpError';

/**
 * Guards a route to authenticated users only.
 *
 * Expects `req.user` to have been populated by the authentication
 * middleware that runs before this one. Returns 401 if the user is
 * not authenticated.
 */
export function requireAuth(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendError(res, 401, 'Authentication required', 'unauthenticated');
      return;
    }
    next();
  };
}

/**
 * Guards a route to users that hold at least one of the listed roles.
 *
 * Must be placed after `requireAuth()` in the middleware chain.
 *
 * @example
 * router.delete('/users/:id', requireAuth(), requireRole('admin'), handler);
 */
export function requireRole(...roles: RoleName[]): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendError(res, 401, 'Authentication required', 'unauthenticated');
      return;
    }

    if (!hasRole(req.user.roles, roles)) {
      sendError(res, 403, `One of the following roles is required: ${roles.join(', ')}`, 'forbidden');
      return;
    }

    next();
  };
}

/**
 * Guards a route to users whose role(s) grant the specified permission.
 *
 * Must be placed after `requireAuth()` in the middleware chain.
 * `admin` is a super-role and bypasses all permission checks.
 *
 * @example
 * router.post('/scans', requireAuth(), requirePermission('scans:write'), handler);
 * router.get('/audit-logs', requireAuth(), requirePermission('audit_logs:read'), handler);
 */
export function requirePermission(permission: Permission): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendError(res, 401, 'Authentication required', 'unauthenticated');
      return;
    }

    if (!hasPermission(req.user.roles, permission)) {
      sendError(res, 403, `Permission "${permission}" is required`, 'forbidden', {
        required: permission,
        userRoles: req.user.roles,
      });
      return;
    }

    next();
  };
}

/**
 * Convenience guard: requires authentication AND the specified permission
 * in a single middleware (eliminates boilerplate on every route).
 *
 * @example
 * router.post('/projects', guard('projects:write'), handler);
 */
export function guard(permission: Permission): RequestHandler[] {
  return [requireAuth(), requirePermission(permission)];
}
