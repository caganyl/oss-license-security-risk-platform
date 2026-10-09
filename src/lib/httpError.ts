import { STATUS_CODES } from 'http';
import type { Response } from 'express';

/**
 * Machine-readable error codes of the REQ-002 auth contract
 * (docs/contracts/REQ-002-auth-api.md, "code kataloğu").
 */
export type ErrorCode =
  | 'invalid_request'
  | 'invalid_password'
  | 'path_not_allowed'
  | 'repo_url_not_allowed'
  | 'unauthenticated'
  | 'setup_required'
  | 'invalid_credentials'
  | 'origin_rejected'
  | 'host_rejected'
  | 'forbidden'
  | 'not_found'
  | 'setup_already_done'
  | 'conflict'
  | 'payload_too_large'
  | 'too_many_attempts'
  | 'internal_error'
  | 'setup_state_invalid';

export const INTERNAL_ERROR_MESSAGE = 'Internal server error';

/**
 * An error whose status, message and code are safe to send to the client as-is.
 * Throw it from handlers; the central error handler (middleware/errorHandler)
 * turns it into the contract body `{ error, message, code }`.
 */
export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    readonly code: ErrorCode = defaultErrorCode(statusCode),
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

/** Default code for errors thrown without one (`throw {statusCode}` in existing code). */
export function defaultErrorCode(status: number): ErrorCode {
  switch (status) {
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 413:
      return 'payload_too_large';
    case 429:
      return 'too_many_attempts';
    default:
      return status >= 500 ? 'internal_error' : 'invalid_request';
  }
}

/** HTTP reason phrase used as the `error` field (e.g. 404 -> "Not Found"). */
export function statusLabel(status: number): string {
  return STATUS_CODES[status] ?? 'Error';
}

/**
 * Writes the contract error body. 5xx messages are always replaced by a fixed
 * text so raw DB/system messages never reach the client (AC-G-8).
 */
export function sendError(
  res: Response,
  status: number,
  message: string,
  code: ErrorCode = defaultErrorCode(status),
  extra: Record<string, unknown> = {},
): void {
  const safeMessage = status >= 500 && code === 'internal_error' ? INTERNAL_ERROR_MESSAGE : message;
  res.status(status).json({ ...extra, error: statusLabel(status), message: safeMessage, code });
}
