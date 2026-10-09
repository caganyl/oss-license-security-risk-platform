import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * Content-Security-Policy of the single-page UI (contract K13, D-17,
 * AC-P02-6/7). Everything is same-origin: the page script is `/app.js`, lucide
 * is vendored, fonts are local. `'unsafe-inline'` is allowed only for styles.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

/**
 * Security headers on every response (contract K13), registered first in the
 * middleware chain so that Host rejections, static files, `/health`, API
 * errors and the HTML page all carry them. The CSP is sent on every response
 * as well: it is required on HTML and harmless on JSON. No dependency
 * (helmet) is used on purpose.
 */
export function securityHeaders(): RequestHandler {
  return (_req: Request, res: Response, next: NextFunction): void => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    next();
  };
}
