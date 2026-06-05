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

export interface AuthenticatedUser {
  id: string;
  email: string;
  displayName: string;
  roles: RoleName[];
  sessionId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}
