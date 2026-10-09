/**
 * Auth types — mirrors the role_name enum and user_roles table in the DB schema.
 */

export type RoleName =
  | 'admin'
  | 'security_analyst'
  | 'legal_reviewer'
  | 'developer'
  | 'manager';

export type Resource =
  | 'users'
  | 'roles'
  | 'projects'
  | 'integrations'
  | 'scans'
  | 'findings'
  | 'reviews'
  | 'comments'
  | 'policies'
  | 'sbom'
  | 'reports'
  | 'audit_logs'
  | 'settings';

export type Action = 'read' | 'write' | 'delete' | 'generate' | 'cancel' | 'suppress';

export type Permission = `${Resource}:${Action}`;

/** How the request proved its identity (ADR-001 karar 8). */
export type AuthMethod = 'session' | 'api_key';

export interface AuthenticatedUser {
  id: string;
  email: string;
  displayName: string;
  roles: RoleName[];
  /** `sessions.id` for cookie sessions, `apikey:<api_keys.id>` for Bearer keys. */
  sessionId: string;
  authMethod: AuthMethod;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}
