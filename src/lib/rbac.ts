import type { AuthenticatedUser, Permission, RoleName } from '../types/auth';
import { hasPermission, hasRole } from '../config/permissions';

/**
 * Checks whether a user holds a permission. Throws an error (to be
 * caught by middleware) instead of returning boolean so it can carry
 * an HTTP status code.
 */
export function assertPermission(user: AuthenticatedUser, permission: Permission): void {
  if (!hasPermission(user.roles, permission)) {
    const err = new Error(
      `Forbidden: role(s) [${user.roles.join(', ')}] lack permission "${permission}"`,
    );
    (err as NodeJS.ErrnoException).code = 'FORBIDDEN';
    throw err;
  }
}

/**
 * Checks whether a user holds at least one of the required roles.
 */
export function assertRole(user: AuthenticatedUser, required: RoleName[]): void {
  if (!hasRole(user.roles, required)) {
    const err = new Error(
      `Forbidden: user does not have any of the required roles [${required.join(', ')}]`,
    );
    (err as NodeJS.ErrnoException).code = 'FORBIDDEN';
    throw err;
  }
}

export { hasPermission, hasRole };
