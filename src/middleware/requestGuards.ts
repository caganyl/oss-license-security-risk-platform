import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { sendError } from '../lib/httpError';

/**
 * Host and Origin allow-lists (ADR-001 karar 5, contract "CSRF / Host kuralı").
 * Both are derived from the configured port — not from the socket — so DNS
 * rebinding and cross-site form posts cannot reach the local API.
 */
export interface AllowedOrigins {
  hosts: ReadonlySet<string>;
  origins: ReadonlySet<string>;
}

function hostWithPort(host: string, port: number): string {
  const bare = host.replace(/^\[|\]$/g, '').toLowerCase();
  return bare.includes(':') ? `[${bare}]:${port}` : `${bare}:${port}`;
}

export function buildAllowedOrigins(port: number, host: string): AllowedOrigins {
  const hosts = new Set(['127.0.0.1', 'localhost', '::1', host].map((h) => hostWithPort(h, port)));
  const origins = new Set([...hosts].map((h) => `http://${h}`));
  return { hosts, origins };
}

/** First middleware: every request (static files and /health included) needs an allowed Host. */
export function requireAllowedHost(allowed: AllowedOrigins): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const host = (req.headers.host ?? '').toLowerCase();
    if (!allowed.hosts.has(host)) {
      sendError(res, 403, 'Host not allowed', 'host_rejected');
      return;
    }
    next();
  };
}

function requestOrigin(req: Request): string | null {
  const origin = req.headers.origin;
  if (origin !== undefined) return origin;
  const referer = req.headers.referer;
  if (!referer) return null;
  try {
    return new URL(referer).origin;
  } catch {
    return null;
  }
}

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Origin (or Referer origin) must be allowed. `Origin: null` and a missing
 * Origin+Referer are rejected. Used unconditionally on login/setup.
 */
export function requireSameOrigin(allowed: AllowedOrigins): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = requestOrigin(req);
    if (origin === null || !allowed.origins.has(origin.toLowerCase())) {
      sendError(res, 403, 'Origin not allowed', 'origin_rejected');
      return;
    }
    next();
  };
}

/**
 * CSRF guard for authenticated routes: cookie-authenticated state-changing
 * requests need an allowed Origin. Bearer requests are exempt (a browser cannot
 * attach Authorization cross-site without a preflight, and no CORS is served).
 */
export function requireSameOriginForSessionWrites(allowed: AllowedOrigins): RequestHandler {
  const check = requireSameOrigin(allowed);
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.user?.authMethod !== 'session' || !UNSAFE_METHODS.has(req.method)) {
      next();
      return;
    }
    check(req, res, next);
  };
}
