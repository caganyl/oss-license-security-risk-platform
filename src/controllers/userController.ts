import type { NextFunction, Request, Response } from 'express';
import type { Pool, PoolClient, QueryResult } from 'pg';
import type { RoleName } from '../types/auth';

type UserStatus = 'active' | 'inactive' | 'pending';

const ALLOWED_STATUSES = new Set<UserStatus>(['active', 'inactive', 'pending']);
const ALLOWED_ROLES = new Set<RoleName>([
  'admin',
  'security_analyst',
  'legal_reviewer',
  'developer',
  'manager',
]);

interface UserRow {
  id: string;
  email: string;
  display_name: string;
  avatar_url: string | null;
  status: UserStatus;
  sso_provider: string | null;
  sso_subject: string | null;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
  roles: RoleName[];
}

interface UserResponse {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  status: UserStatus;
  ssoProvider: string | null;
  ssoSubject: string | null;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
  roles: RoleName[];
}

type AuditAction = 'user_created' | 'user_updated' | 'user_deleted';

interface AuditInput {
  action: AuditAction;
  actorId?: string;
  actorEmail?: string;
  entityId: string;
  oldData?: unknown;
  newData?: unknown;
  req: Request;
}

function toUserResponse(row: UserRow): UserResponse {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    avatarUrl: row.avatar_url,
    status: row.status,
    ssoProvider: row.sso_provider,
    ssoSubject: row.sso_subject,
    mfaEnabled: row.mfa_enabled,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    roles: row.roles ?? [],
  };
}

function parseRoles(value: unknown): RoleName[] {
  if (!Array.isArray(value)) {
    throw Object.assign(new Error('roles must be an array'), { statusCode: 400 });
  }

  const roles = [...new Set(value)];
  for (const role of roles) {
    if (typeof role !== 'string' || !ALLOWED_ROLES.has(role as RoleName)) {
      throw Object.assign(new Error(`Invalid role: ${String(role)}`), { statusCode: 400 });
    }
  }

  return roles as RoleName[];
}

function validateEmail(email: unknown): string {
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw Object.assign(new Error('A valid email is required'), { statusCode: 400 });
  }
  return email.trim().toLowerCase();
}

function validateDisplayName(displayName: unknown): string {
  if (typeof displayName !== 'string' || displayName.trim().length === 0) {
    throw Object.assign(new Error('displayName is required'), { statusCode: 400 });
  }
  return displayName.trim();
}

function validateStatus(status: unknown): UserStatus {
  if (typeof status !== 'string' || !ALLOWED_STATUSES.has(status as UserStatus)) {
    throw Object.assign(new Error('status must be active, inactive, or pending'), {
      statusCode: 400,
    });
  }
  return status as UserStatus;
}

function parsePagination(value: unknown, fallback: number, max?: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw Object.assign(new Error('limit and offset must be non-negative integers'), {
      statusCode: 400,
    });
  }
  return max ? Math.min(parsed, max) : parsed;
}

function handleControllerError(err: unknown, res: Response, next: NextFunction): void {
  const error = err as Error & { code?: string; statusCode?: number; detail?: string };

  if (error.code === '23505') {
    res.status(409).json({
      error: 'Conflict',
      message: 'A user with that email or SSO identity already exists',
    });
    return;
  }

  if (error.statusCode) {
    res.status(error.statusCode).json({
      error: error.statusCode === 404 ? 'Not Found' : 'Bad Request',
      message: error.message,
    });
    return;
  }

  next(err);
}

export class UserController {
  constructor(private readonly db: Pool) {}

  listUsers = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
      const status = typeof req.query.status === 'string' ? req.query.status : undefined;
      const limit = parsePagination(req.query.limit, 50, 100);
      const offset = parsePagination(req.query.offset, 0);

      if (status && !ALLOWED_STATUSES.has(status as UserStatus)) {
        throw Object.assign(new Error('status must be active, inactive, or pending'), {
          statusCode: 400,
        });
      }

      const values: unknown[] = [];
      const filters = ['u.deleted_at IS NULL'];

      if (search) {
        values.push(`%${search}%`);
        filters.push(`(u.email ILIKE $${values.length} OR u.display_name ILIKE $${values.length})`);
      }

      if (status) {
        values.push(status);
        filters.push(`u.status = $${values.length}`);
      }

      values.push(limit, offset);
      const result = await this.db.query<UserRow>(
        `
          SELECT
            u.id,
            u.email,
            u.display_name,
            u.avatar_url,
            u.status,
            u.sso_provider,
            u.sso_subject,
            u.mfa_enabled,
            u.last_login_at,
            u.created_at,
            u.updated_at,
            COALESCE(
              array_agg(r.name::text ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL),
              '{}'
            ) AS roles
          FROM users u
          LEFT JOIN user_roles ur ON ur.user_id = u.id
          LEFT JOIN roles r ON r.id = ur.role_id
          WHERE ${filters.join(' AND ')}
          GROUP BY u.id
          ORDER BY u.created_at DESC
          LIMIT $${values.length - 1}
          OFFSET $${values.length}
        `,
        values,
      );

      res.json({ data: result.rows.map(toUserResponse), limit, offset });
    } catch (err) {
      handleControllerError(err, res, next);
    }
  };

  getUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = await this.fetchUser(req.params.id);
      if (!user) {
        throw Object.assign(new Error('User not found'), { statusCode: 404 });
      }
      res.json({ data: toUserResponse(user) });
    } catch (err) {
      handleControllerError(err, res, next);
    }
  };

  createUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      const email = validateEmail(req.body.email);
      const displayName = validateDisplayName(req.body.displayName);
      const status = req.body.status ? validateStatus(req.body.status) : 'pending';
      const roles = req.body.roles ? parseRoles(req.body.roles) : [];

      const result = await client.query<{ id: string }>(
        `
          INSERT INTO users (
            email,
            display_name,
            avatar_url,
            status,
            sso_provider,
            sso_subject,
            mfa_enabled
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING id
        `,
        [
          email,
          displayName,
          req.body.avatarUrl ?? null,
          status,
          req.body.ssoProvider ?? null,
          req.body.ssoSubject ?? null,
          Boolean(req.body.mfaEnabled ?? false),
        ],
      );

      const userId = result.rows[0].id;
      await this.replaceRoles(client, userId, roles, req.user?.id);
      const user = await this.fetchUser(userId, client);

      await this.insertAudit(client, {
        action: 'user_created',
        actorId: req.user?.id,
        actorEmail: req.user?.email,
        entityId: userId,
        newData: user,
        req,
      });

      await client.query('COMMIT');
      res.status(201).json({ data: toUserResponse(user as UserRow) });
    } catch (err) {
      await client.query('ROLLBACK');
      handleControllerError(err, res, next);
    } finally {
      client.release();
    }
  };

  updateUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      const existing = await this.fetchUser(req.params.id, client);
      if (!existing) {
        throw Object.assign(new Error('User not found'), { statusCode: 404 });
      }

      const updates: string[] = [];
      const values: unknown[] = [];

      if (req.body.email !== undefined) {
        values.push(validateEmail(req.body.email));
        updates.push(`email = $${values.length}`);
      }

      if (req.body.displayName !== undefined) {
        values.push(validateDisplayName(req.body.displayName));
        updates.push(`display_name = $${values.length}`);
      }

      if (req.body.avatarUrl !== undefined) {
        values.push(req.body.avatarUrl);
        updates.push(`avatar_url = $${values.length}`);
      }

      if (req.body.status !== undefined) {
        values.push(validateStatus(req.body.status));
        updates.push(`status = $${values.length}`);
      }

      if (req.body.ssoProvider !== undefined) {
        values.push(req.body.ssoProvider);
        updates.push(`sso_provider = $${values.length}`);
      }

      if (req.body.ssoSubject !== undefined) {
        values.push(req.body.ssoSubject);
        updates.push(`sso_subject = $${values.length}`);
      }

      if (req.body.mfaEnabled !== undefined) {
        values.push(Boolean(req.body.mfaEnabled));
        updates.push(`mfa_enabled = $${values.length}`);
      }

      if (updates.length > 0) {
        values.push(req.params.id);
        await client.query(
          `
            UPDATE users
            SET ${updates.join(', ')}, updated_at = NOW()
            WHERE id = $${values.length} AND deleted_at IS NULL
          `,
          values,
        );
      }

      if (req.body.roles !== undefined) {
        await this.replaceRoles(client, req.params.id, parseRoles(req.body.roles), req.user?.id);
      }

      const updated = await this.fetchUser(req.params.id, client);
      await this.insertAudit(client, {
        action: 'user_updated',
        actorId: req.user?.id,
        actorEmail: req.user?.email,
        entityId: req.params.id,
        oldData: existing,
        newData: updated,
        req,
      });

      await client.query('COMMIT');
      res.json({ data: toUserResponse(updated as UserRow) });
    } catch (err) {
      await client.query('ROLLBACK');
      handleControllerError(err, res, next);
    } finally {
      client.release();
    }
  };

  deleteUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      const existing = await this.fetchUser(req.params.id, client);
      if (!existing) {
        throw Object.assign(new Error('User not found'), { statusCode: 404 });
      }

      await client.query(
        `
          UPDATE users
          SET deleted_at = NOW(), status = 'inactive', updated_at = NOW()
          WHERE id = $1 AND deleted_at IS NULL
        `,
        [req.params.id],
      );

      await this.insertAudit(client, {
        action: 'user_deleted',
        actorId: req.user?.id,
        actorEmail: req.user?.email,
        entityId: req.params.id,
        oldData: existing,
        req,
      });

      await client.query('COMMIT');
      res.status(204).send();
    } catch (err) {
      await client.query('ROLLBACK');
      handleControllerError(err, res, next);
    } finally {
      client.release();
    }
  };

  updateUserRoles = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      const existing = await this.fetchUser(req.params.id, client);
      if (!existing) {
        throw Object.assign(new Error('User not found'), { statusCode: 404 });
      }

      await this.replaceRoles(client, req.params.id, parseRoles(req.body.roles), req.user?.id);

      const updated = await this.fetchUser(req.params.id, client);
      await this.insertAudit(client, {
        action: 'user_updated',
        actorId: req.user?.id,
        actorEmail: req.user?.email,
        entityId: req.params.id,
        oldData: existing,
        newData: updated,
        req,
      });

      await client.query('COMMIT');
      res.json({ data: toUserResponse(updated as UserRow) });
    } catch (err) {
      await client.query('ROLLBACK');
      handleControllerError(err, res, next);
    } finally {
      client.release();
    }
  };

  private async fetchUser(id: string, client: Pool | PoolClient = this.db): Promise<UserRow | null> {
    const result = await client.query<UserRow>(
      `
        SELECT
          u.id,
          u.email,
          u.display_name,
          u.avatar_url,
          u.status,
          u.sso_provider,
          u.sso_subject,
          u.mfa_enabled,
          u.last_login_at,
          u.created_at,
          u.updated_at,
          COALESCE(
            array_agg(r.name::text ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL),
            '{}'
          ) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id
        WHERE u.id = $1 AND u.deleted_at IS NULL
        GROUP BY u.id
      `,
      [id],
    );

    return result.rows[0] ?? null;
  }

  private async replaceRoles(
    client: PoolClient,
    userId: string,
    roles: RoleName[],
    grantedBy?: string,
  ): Promise<QueryResult[]> {
    await client.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);

    if (roles.length === 0) {
      return [];
    }

    const results: QueryResult[] = [];
    for (const role of roles) {
      results.push(
        await client.query(
          `
            INSERT INTO user_roles (user_id, role_id, granted_by)
            SELECT $1, id, $3
            FROM roles
            WHERE name = $2
          `,
          [userId, role, grantedBy ?? null],
        ),
      );
    }

    return results;
  }

  private async insertAudit(client: PoolClient, input: AuditInput): Promise<void> {
    await client.query(
      `
        INSERT INTO audit_logs (
          action,
          actor_id,
          actor_email,
          entity_type,
          entity_id,
          old_data,
          new_data,
          ip_address,
          user_agent,
          request_id
        )
        VALUES ($1, $2, $3, 'user', $4, $5, $6, $7, $8, $9)
      `,
      [
        input.action,
        input.actorId ?? null,
        input.actorEmail ?? null,
        input.entityId,
        input.oldData ? JSON.stringify(input.oldData) : null,
        input.newData ? JSON.stringify(input.newData) : null,
        input.req.ip,
        input.req.get('user-agent') ?? null,
        input.req.get('x-request-id') ?? null,
      ],
    );
  }
}
