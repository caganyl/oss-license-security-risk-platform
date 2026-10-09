import crypto from 'crypto';
import type { Response } from 'express';
import type { Pool, PoolClient } from 'pg';

/**
 * Server-side browser sessions (ADR-001 karar 3/4, contract K4).
 * The cookie carries 32 random bytes; only their SHA-256 hex digest is stored.
 * Validity is evaluated with the DB clock so tests (and operators) can move
 * last_seen_at / expires_at directly.
 */
export const SESSION_COOKIE = 'ossrisk_session';
export const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const IDLE_LIMIT = "interval '12 hours'";
const ABSOLUTE_LIMIT = "interval '7 days'";
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

type Queryable = Pool | PoolClient;

export const sha256Hex = (value: string): string => crypto.createHash('sha256').update(value, 'utf8').digest('hex');

/** Creates a session row and returns the raw cookie token (never stored). */
export async function createSession(db: Queryable, userId: string): Promise<string> {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.query(
    `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + ${ABSOLUTE_LIMIT})`,
    [userId, sha256Hex(token)],
  );
  return token;
}

/**
 * Resolves a cookie token to a live session and refreshes last_seen_at.
 * The absolute limit (expires_at) is never extended. Returns null when the
 * token is malformed, unknown, idle for 12 hours, past expires_at, or the
 * user is inactive/deleted.
 */
export async function touchSession(db: Pool, token: string): Promise<{ sessionId: string; userId: string } | null> {
  if (!TOKEN_RE.test(token)) return null;
  const result = await db.query<{ id: string; user_id: string }>(
    `UPDATE sessions s SET last_seen_at = now()
       FROM users u
      WHERE s.token_hash = $1
        AND s.expires_at > now()
        AND s.last_seen_at > now() - ${IDLE_LIMIT}
        AND u.id = s.user_id AND u.status = 'active' AND u.deleted_at IS NULL
      RETURNING s.id, s.user_id`,
    [sha256Hex(token)],
  );
  const row = result.rows[0];
  return row ? { sessionId: row.id, userId: row.user_id } : null;
}

export async function deleteSession(db: Pool, sessionId: string): Promise<void> {
  await db.query('DELETE FROM sessions WHERE id = $1', [sessionId]);
}

/** Housekeeping on login (ADR-001 karar 3): drop sessions that can no longer be used. */
export async function deleteExpiredSessions(db: Queryable): Promise<void> {
  await db.query(`DELETE FROM sessions WHERE expires_at <= now() OR last_seen_at <= now() - ${IDLE_LIMIT}`);
}

/** Minimal Cookie header parser (no cookie-parser dependency, ADR-001 karar 3). */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

// Built by hand so the attributes are exactly the contract's (no Secure, no Domain).
export function setSessionCookie(res: Response, token: string): void {
  res.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}`);
}

export function clearSessionCookie(res: Response): void {
  res.append('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}
