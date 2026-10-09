import type { NextFunction, Request, Response } from 'express';
import type { Pool, PoolClient } from 'pg';
import { issueApiKey, listApiKeys, revokeApiKey } from '../lib/apiKeys';
import { isSetupRequired } from '../lib/authUsers';
import { HttpError, sendError } from '../lib/httpError';
import { LoginThrottle } from '../lib/loginThrottle';
import { PASSWORD_MAX_LENGTH, hashPassword, passwordPolicyViolation, verifyPassword } from '../lib/password';
import {
  clearSessionCookie,
  createSession,
  deleteExpiredSessions,
  deleteSession,
  setSessionCookie,
} from '../lib/sessions';

/** Identity of the user created by setup on an empty database (single local user). */
const LOCAL_USER_EMAIL = 'admin@localhost';
const LOCAL_USER_DISPLAY_NAME = 'Administrator';
const SETUP_STATE_INVALID_MESSAGE = 'Setup cannot proceed: user state requires manual repair (see db/README.md)';
const API_KEY_NAME_MAX_LENGTH = 100;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const setupAlreadyDone = () => new HttpError(409, 'Initial password has already been set', 'setup_already_done');
const setupStateInvalid = () => new HttpError(500, SETUP_STATE_INVALID_MESSAGE, 'setup_state_invalid');

function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: unknown })?.code === '23505';
}

/**
 * Local single-user authentication (REQ-002 P-01, ADR-001, contract 0.2.2).
 * Passwords, cookies and keys are never logged; request bodies of login and
 * setup are not logged either.
 */
export class AuthController {
  constructor(
    private readonly db: Pool,
    private readonly throttle: LoginThrottle,
  ) {}

  /**
   * POST /api/auth/setup — ADR-001 karar 2. One transaction: lock candidates,
   * pick the branch, store the hash and open the session (auto login).
   */
  setup = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const password: unknown = req.body?.password;
      const violation = passwordPolicyViolation(password);
      if (violation) throw new HttpError(400, violation, 'invalid_password');
      // Hash before taking row locks: scrypt is deliberately slow.
      const passwordHash = await hashPassword(password as string);

      const client = await this.db.connect();
      let token: string;
      try {
        await client.query('BEGIN');
        token = await this.runSetupTransaction(client, passwordHash);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        // Concurrent setup lost the race on the single-password index or users.email.
        throw isUniqueViolation(err) ? setupAlreadyDone() : err;
      } finally {
        client.release();
      }

      setSessionCookie(res, token);
      // Contract: no body; the recovery and first-start branches look the same to the client.
      res.status(201).end();
    } catch (err) {
      next(err);
    }
  };

  private async runSetupTransaction(client: PoolClient, passwordHash: string): Promise<string> {
    // 1. Lock password-less active admins; a concurrent setup waits here and
    //    re-evaluates the row (no longer a candidate) after the first commits.
    const candidates = await client.query<{ id: string }>(
      `SELECT u.id FROM users u
         JOIN user_roles ur ON ur.user_id = u.id
         JOIN roles r ON r.id = ur.role_id
        WHERE r.name = 'admin' AND u.password_hash IS NULL
          AND u.status = 'active' AND u.deleted_at IS NULL
        FOR UPDATE OF u`,
    );
    // 2. Read after the lock: a password holder means setup is closed.
    const state = await client.query<{ has_password: boolean; user_count: number; admin_role_id: string | null }>(
      `SELECT EXISTS (SELECT 1 FROM users WHERE password_hash IS NOT NULL) AS has_password,
              (SELECT count(*)::int FROM users) AS user_count,
              (SELECT id FROM roles WHERE name = 'admin') AS admin_role_id`,
    );
    const { has_password: hasPassword, user_count: userCount, admin_role_id: adminRoleId } = state.rows[0];
    if (hasPassword) throw setupAlreadyDone();

    let userId: string;
    if (!adminRoleId) {
      console.error('Setup refused: admin role row is missing');
      throw setupStateInvalid();
    } else if (candidates.rows.length === 1) {
      // 3. Recovery: the password goes to the same user (id, roles, keys kept).
      userId = candidates.rows[0].id;
      await client.query(
        `UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id = $1`,
        [userId, passwordHash],
      );
    } else if (candidates.rows.length === 0 && userCount === 0) {
      // 4. First start: create the single local user with the admin role.
      const inserted = await client.query<{ id: string }>(
        `INSERT INTO users (email, display_name, status, password_hash, password_changed_at)
         VALUES ($1, $2, 'active', $3, now()) RETURNING id`,
        [LOCAL_USER_EMAIL, LOCAL_USER_DISPLAY_NAME, passwordHash],
      );
      userId = inserted.rows[0].id;
      await client.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [userId, adminRoleId]);
    } else {
      // 5. Several candidates, or users exist but none qualifies: manual repair.
      console.error(
        `Setup refused: invalid user state (candidates=${candidates.rows.length}, users=${userCount})`,
      );
      throw setupStateInvalid();
    }
    return createSession(client, userId);
  }

  /** POST /api/auth/login — 204 + cookie; 401 invalid_credentials; 429 after 5 failures. */
  login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (await isSetupRequired(this.db)) {
        throw new HttpError(401, 'Initial password setup required', 'setup_required');
      }
      const retryAfter = this.throttle.retryAfterSeconds();
      if (retryAfter > 0) {
        res.setHeader('Retry-After', String(retryAfter));
        sendError(res, 429, 'Too many failed attempts', 'too_many_attempts');
        return;
      }

      const password: unknown = req.body?.password;
      const user = await this.db.query<{ id: string; password_hash: string }>(
        `SELECT id, password_hash FROM users
          WHERE password_hash IS NOT NULL AND status = 'active' AND deleted_at IS NULL`,
      );
      const row = user.rows[0];
      // Over-long or non-string passwords are rejected without running scrypt.
      const valid =
        typeof password === 'string' &&
        password.length <= PASSWORD_MAX_LENGTH &&
        row !== undefined &&
        (await verifyPassword(password, row.password_hash));
      if (!valid) {
        this.throttle.recordFailure();
        throw new HttpError(401, 'Invalid credentials', 'invalid_credentials');
      }

      this.throttle.reset();
      await deleteExpiredSessions(this.db);
      const token = await createSession(this.db, row.id);
      await this.db.query('UPDATE users SET last_login_at = now() WHERE id = $1', [row.id]);
      setSessionCookie(res, token);
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  };

  /** POST /api/auth/logout — closes only the calling session (ADR-001 karar 3). */
  logout = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await deleteSession(this.db, req.user!.sessionId);
      clearSessionCookie(res);
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  };

  /** GET /api/auth/me — the authenticated user without session details. */
  me = (req: Request, res: Response): void => {
    const { id, email, displayName, roles } = req.user!;
    res.json({ data: { id, email, displayName, roles } });
  };

  /** POST /api/auth/api-keys — new key, previous active key revoked; plain key shown once. */
  createApiKey = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const name: unknown = req.body?.name;
      if (name !== undefined && name !== null) {
        if (typeof name !== 'string' || name.length > API_KEY_NAME_MAX_LENGTH) {
          throw new HttpError(400, `name must be a string of at most ${API_KEY_NAME_MAX_LENGTH} characters`, 'invalid_request');
        }
      }
      const created = await issueApiKey(this.db, req.user!.id, typeof name === 'string' && name !== '' ? name : null);
      res.setHeader('Cache-Control', 'no-store');
      res.status(201).json({ data: created });
    } catch (err) {
      next(err);
    }
  };

  /** GET /api/auth/api-keys — metadata only (revoked keys included). */
  listApiKeys = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      res.json({ data: await listApiKeys(this.db, req.user!.id) });
    } catch (err) {
      next(err);
    }
  };

  /** DELETE /api/auth/api-keys/:id — idempotent revoke; unknown/foreign/invalid id -> 404. */
  revokeApiKey = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;
      if (!UUID_RE.test(id) || !(await revokeApiKey(this.db, req.user!.id, id))) {
        throw new HttpError(404, 'API key not found', 'not_found');
      }
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  };
}
