import type { Permission, RoleName } from '../types/auth';

/**
 * Role-permission matrix.
 *
 * Permissions use the format `resource:action` and map directly onto
 * the platform's database entities and the audit_action enum.
 *
 * admin is a super-role: any permission check against admin always passes,
 * so its entry here exists only for documentation completeness.
 */
export const ROLE_PERMISSIONS: Record<RoleName, ReadonlySet<Permission>> = {
  admin: new Set<Permission>([
    'users:read', 'users:write', 'users:delete',
    'roles:read', 'roles:write', 'roles:delete',
    'projects:read', 'projects:write', 'projects:delete',
    'integrations:read', 'integrations:write', 'integrations:delete',
    'scans:read', 'scans:write', 'scans:cancel',
    'findings:read', 'findings:write', 'findings:suppress', 'findings:delete',
    'reviews:read', 'reviews:write',
    'comments:read', 'comments:write', 'comments:delete',
    'policies:read', 'policies:write', 'policies:delete',
    'sbom:read', 'sbom:generate',
    'reports:read', 'reports:generate', 'reports:delete',
    'audit_logs:read',
    'settings:read', 'settings:write',
  ]),

  security_analyst: new Set<Permission>([
    'projects:read',
    'integrations:read',
    'scans:read', 'scans:write', 'scans:cancel',
    'findings:read', 'findings:write', 'findings:suppress',
    'reviews:read', 'reviews:write',
    'comments:read', 'comments:write',
    'policies:read',
    'sbom:read', 'sbom:generate',
    'reports:read', 'reports:generate',
    'audit_logs:read',
  ]),

  legal_reviewer: new Set<Permission>([
    'projects:read',
    'scans:read',
    // legal reviewers act on license findings only; route-level guards
    // enforce the finding_type constraint — RBAC just gates the resource
    'findings:read', 'findings:write',
    'reviews:read', 'reviews:write',
    'comments:read', 'comments:write',
    'policies:read', 'policies:write',
    'sbom:read',
    'reports:read', 'reports:generate',
  ]),

  developer: new Set<Permission>([
    'projects:read',
    'integrations:read',
    'scans:read', 'scans:write',
    'findings:read',
    'reviews:read',
    'comments:read', 'comments:write',
    'policies:read',
    'sbom:read',
    'reports:read',
  ]),

  manager: new Set<Permission>([
    'users:read',
    'projects:read',
    'integrations:read',
    'scans:read',
    'findings:read',
    'reviews:read',
    'comments:read',
    'policies:read',
    'sbom:read',
    'reports:read', 'reports:generate',
    'audit_logs:read',
    'settings:read',
  ]),
};

/** Returns true if any of the user's roles grants the permission. */
export function hasPermission(roles: RoleName[], permission: Permission): boolean {
  if (roles.includes('admin')) return true;
  return roles.some((role) => ROLE_PERMISSIONS[role].has(permission));
}

/** Returns true if the user holds at least one of the required roles. */
export function hasRole(userRoles: RoleName[], required: RoleName[]): boolean {
  return required.some((r) => userRoles.includes(r));
}
