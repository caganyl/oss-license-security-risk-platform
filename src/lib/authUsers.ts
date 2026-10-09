import type { Pool } from 'pg';
import type { AuthMethod, AuthenticatedUser, RoleName } from '../types/auth';

/** True while no user holds a password (first start or after the recovery SQL step). */
export async function isSetupRequired(db: Pool): Promise<boolean> {
  const result = await db.query<{ done: boolean }>(
    'SELECT EXISTS (SELECT 1 FROM users WHERE password_hash IS NOT NULL) AS done',
  );
  return !result.rows[0]?.done;
}

/**
 * Builds `req.user` from the database (ADR-001 karar 8): only active,
 * non-deleted users; roles come from user_roles. Returns null otherwise.
 */
export async function loadAuthenticatedUser(
  db: Pool,
  userId: string,
  authMethod: AuthMethod,
  sessionId: string,
): Promise<AuthenticatedUser | null> {
  const result = await db.query<{ id: string; email: string; display_name: string; roles: string[] }>(
    `SELECT u.id, u.email, u.display_name,
            COALESCE(array_agg(r.name::text ORDER BY r.name::text) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
      WHERE u.id = $1 AND u.status = 'active' AND u.deleted_at IS NULL
      GROUP BY u.id`,
    [userId],
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    roles: row.roles as RoleName[],
    sessionId,
    authMethod,
  };
}
