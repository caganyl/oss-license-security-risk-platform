import type { ErrorRequestHandler, Request, RequestHandler, Response, NextFunction } from 'express';
import { HttpError, sendError } from '../lib/httpError';
import type { ErrorCode } from '../lib/httpError';

const CONTRACT_CODE_RE = /^[a-z][a-z_]*$/;

interface ErrorLike {
  name?: string;
  message?: string;
  statusCode?: unknown;
  status?: unknown;
  code?: unknown;
  type?: unknown;
}

/** Unknown `/api` route -> 404 not_found (AC-G-8). */
export function apiNotFound(): RequestHandler {
  return (_req: Request, res: Response): void => {
    sendError(res, 404, 'Route not found', 'not_found');
  };
}

/**
 * Central JSON error handler (contract K9). Every error leaves as
 * `{ error, message, code }`; 5xx bodies carry a fixed message and the server
 * log gets only the error class/code, never raw DB text or request secrets.
 */
export function errorHandler(): ErrorRequestHandler {
  // Express recognises error handlers by arity, so `next` must stay declared.
  return (err: unknown, req: Request, res: Response, next: NextFunction): void => {
    if (res.headersSent) {
      next(err);
      return;
    }
    const e = (err ?? {}) as ErrorLike;

    if (err instanceof HttpError) {
      sendError(res, err.statusCode, err.message, err.code);
      return;
    }
    // body-parser errors
    if (e.type === 'entity.parse.failed') {
      sendError(res, 400, 'Malformed JSON body', 'invalid_request');
      return;
    }
    if (e.type === 'entity.too.large') {
      sendError(res, 413, 'Request body too large', 'payload_too_large');
      return;
    }

    const status = Number(e.statusCode ?? e.status);
    if (Number.isInteger(status) && status >= 400 && status < 500) {
      const code =
        typeof e.code === 'string' && CONTRACT_CODE_RE.test(e.code) ? (e.code as ErrorCode) : undefined;
      sendError(res, status, typeof e.message === 'string' && e.message ? e.message : 'Bad request', code);
      return;
    }

    const detail = [e.name, typeof e.code === 'string' ? e.code : undefined].filter(Boolean).join(':');
    console.error(`Unhandled error on ${req.method} ${req.path}: ${detail || 'unknown'}`);
    sendError(res, 500, 'Internal server error', 'internal_error');
  };
}
