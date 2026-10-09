import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Pool } from 'pg';
import { touchApiKey } from '../lib/apiKeys';
import { isSetupRequired, loadAuthenticatedUser } from '../lib/authUsers';
import { sendError } from '../lib/httpError';
import { SESSION_COOKIE, readCookie, touchSession } from '../lib/sessions';
import type { AuthenticatedUser } from '../types/auth';

async function resolveUser(db: Pool, req: Request): Promise<AuthenticatedUser | null> {
  const authorization = req.headers.authorization;
  // When an Authorization header is present only the Bearer key counts; the
  // cookie is ignored so a bad key can never fall back to a browser session.
  if (authorization !== undefined) {
    const match = /^Bearer ([^\s]+)$/i.exec(authorization.trim());
    if (!match) return null;
    const key = await touchApiKey(db, match[1]);
    return key ? loadAuthenticatedUser(db, key.userId, 'api_key', `apikey:${key.keyId}`) : null;
  }
  const token = readCookie(req.headers.cookie, SESSION_COOKIE);
  if (!token) return null;
  const session = await touchSession(db, token);
  return session ? loadAuthenticatedUser(db, session.userId, 'session', session.sessionId) : null;
}

/**
 * Populates `req.user` from a session cookie or `Authorization: Bearer <key>`
 * (query-string keys are never read). Without valid credentials the request
 * ends with 401: `setup_required` while no password exists, otherwise
 * `unauthenticated`. There is no fallback identity (AC-P01-7).
 */
export function authenticate(db: Pool): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = await resolveUser(db, req);
      if (user) {
        req.user = user;
        next();
        return;
      }
      if (await isSetupRequired(db)) {
        sendError(res, 401, 'Initial password setup required', 'setup_required');
      } else {
        sendError(res, 401, 'Authentication required', 'unauthenticated');
      }
    } catch (err) {
      next(err);
    }
  };
}

/** Key management and logout are cookie-only: a leaked CI key cannot mint, list or revoke keys. */
export function requireSession(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.user?.authMethod !== 'session') {
      sendError(res, 403, 'This endpoint requires a browser session', 'forbidden');
      return;
    }
    next();
  };
}
