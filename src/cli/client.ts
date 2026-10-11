/**
 * Minimal HTTP client of the CLI (REQ-007 contract 2.1, 3.1, 5.2; ADR-009
 * Karar 2).
 *
 * - `node:http` / `node:https` with a fresh `Agent({ keepAlive: false })` per
 *   request: no `fetch`, no global agent, so `HTTP(S)_PROXY` and
 *   `NODE_USE_ENV_PROXY` never apply. TLS verification cannot be disabled.
 * - 30 s total per request (`setTimeout` + `destroy`), 32 MiB body cap
 *   (`Content-Length` pre-check and stream counter), redirects never followed.
 * - Only idempotent GETs are retried (3 consecutive transient failures →
 *   exit 3); POSTs are sent once.
 * - Errors carry only method, path, status and the server `code`; never
 *   headers, the key, cookies or the request options object.
 */
import * as http from 'node:http';
import * as https from 'node:https';
import type { IncomingHttpHeaders } from 'node:http';
import { CliError, EXIT_AUTH, EXIT_RUNTIME, EXIT_USAGE } from './exitCodes';
import type { Target } from './config';
import { cleanText } from './output';

export const REQUEST_TIMEOUT_MS = 30_000;
export const MAX_BODY_BYTES = 32 * 1024 * 1024;
export const RETRY_DELAY_MS = 2_000;
export const MAX_CONSECUTIVE_TRANSIENT = 3;

export interface HttpRequestSpec {
  method: 'GET' | 'POST';
  path: string;
  headers: Record<string, string>;
  body: string | null;
}

export interface HttpResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

export class TransportError extends Error {
  constructor(readonly kind: 'connection' | 'timeout' | 'too_large') {
    super(kind);
    this.name = 'TransportError';
  }
}

export type RequestFn = (target: Target, spec: HttpRequestSpec) => Promise<HttpResponse>;

/** Real transport (injected through `main(deps)`). */
export const nodeRequest: RequestFn = (target, spec) => {
  const mod = target.protocol === 'https:' ? https : http;
  const agent = new mod.Agent({ keepAlive: false });
  return new Promise<HttpResponse>((resolve, reject) => {
    let settled = false;
    // Mutable holder: the callbacks below run only after both fields are set.
    const io: { timer?: NodeJS.Timeout; req?: http.ClientRequest } = {};
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      if (io.timer) clearTimeout(io.timer);
      action();
      agent.destroy();
    };
    const abort = (kind: TransportError['kind']): void => {
      finish(() => reject(new TransportError(kind)));
      io.req?.destroy();
    };
    const headers: Record<string, string> = { ...spec.headers };
    if (spec.body !== null) headers['Content-Length'] = String(Buffer.byteLength(spec.body));
    // Explicit `true` so an inherited NODE_TLS_REJECT_UNAUTHORIZED=0 cannot turn
    // certificate verification off (contract 2.1; REQ-007 security review L-1).
    const tls = target.protocol === 'https:' ? { rejectUnauthorized: true } : {};
    const req = mod.request(
      { protocol: target.protocol, hostname: target.connectHost, port: target.port, method: spec.method, path: spec.path, headers, agent, ...tls },
      (res) => {
        const declared = Number(res.headers['content-length']);
        if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
          abort('too_large');
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_BODY_BYTES) abort('too_large');
          else chunks.push(chunk);
        });
        res.on('end', () =>
          finish(() => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) })),
        );
        res.on('error', () => abort('connection'));
        res.on('aborted', () => abort('connection'));
      },
    );
    io.req = req;
    io.timer = setTimeout(() => abort('timeout'), REQUEST_TIMEOUT_MS);
    req.on('error', () => abort('connection'));
    if (spec.body !== null) req.write(spec.body);
    req.end();
  });
};

/** Server error `code` from a JSON error body, when it looks like a code. */
export function serverCode(res: HttpResponse): string | null {
  const body = tryJson(res);
  const code = body && typeof body === 'object' ? (body as Record<string, unknown>).code : undefined;
  return typeof code === 'string' && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
}

/** Server error `message`, sanitized (contract 5.5). */
export function serverMessage(res: HttpResponse): string | null {
  const body = tryJson(res);
  const message = body && typeof body === 'object' ? (body as Record<string, unknown>).message : undefined;
  return typeof message === 'string' && message.length > 0 ? cleanText(message) : null;
}

function tryJson(res: HttpResponse): unknown {
  try {
    return JSON.parse(res.body.toString('utf8'));
  } catch {
    return null;
  }
}

/** Parses a JSON body; anything else is exit 3 (`unexpected_response`). */
export function parseJson(method: string, path: string, res: HttpResponse): unknown {
  try {
    return JSON.parse(res.body.toString('utf8'));
  } catch {
    throw new CliError('unexpected_response', EXIT_RUNTIME, `${method} ${path} returned a body that is not JSON`);
  }
}

/** Generic HTTP → exit code mapping (contract 5.2) for a non-2xx response. */
export function mapHttpError(method: string, path: string, res: HttpResponse): CliError {
  const status = res.status;
  const code = serverCode(res);
  const codePart = code ? ` (${code})` : '';
  if (status >= 300 && status < 400) {
    return new CliError('redirect', EXIT_RUNTIME, 'server responded with a redirect; not followed');
  }
  if (status === 403 && (code === 'host_rejected' || code === 'origin_rejected')) {
    return new CliError('server_address_rejected', EXIT_USAGE, `server rejected the address or port (${code}); check --url`);
  }
  if (status === 401) return new CliError('unauthorized', EXIT_AUTH, `${method} ${path} failed: HTTP 401${codePart}`);
  if (status === 403) return new CliError('forbidden', EXIT_AUTH, `${method} ${path} failed: HTTP 403${codePart}`);
  return new CliError('unexpected_response', EXIT_RUNTIME, `${method} ${path} failed: HTTP ${status}${codePart}`);
}

export function isOk(res: HttpResponse): boolean {
  return res.status >= 200 && res.status < 300;
}

export interface CallOptions {
  body?: unknown;
  bearer?: string;
  cookie?: string;
  /** Send `Origin` (session write requests of bootstrap only). */
  origin?: boolean;
  /** Message for a body over 32 MiB. */
  tooLargeMessage?: string;
}

export class ApiClient {
  constructor(
    private readonly target: Target,
    private readonly request: RequestFn,
    private readonly version: string,
    private readonly sleep: (ms: number) => Promise<void>,
  ) {}

  private spec(method: 'GET' | 'POST', path: string, opts: CallOptions): HttpRequestSpec {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': `oss-risk-cli/${this.version}`,
    };
    if (this.target.hostHeader !== null) headers.Host = this.target.hostHeader;
    if (opts.origin) headers.Origin = this.target.origin;
    if (opts.bearer !== undefined) headers.Authorization = `Bearer ${opts.bearer}`;
    if (opts.cookie !== undefined) headers.Cookie = opts.cookie;
    let body: string | null = null;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    return { method, path, headers, body };
  }

  private tooLarge(method: string, path: string, opts: CallOptions): CliError {
    return new CliError('response_too_large', EXIT_RUNTIME, opts.tooLargeMessage ?? `${method} ${path} response exceeds 32 MiB`);
  }

  /** One attempt, never retried (POST). Any status is returned to the caller. */
  async post(path: string, opts: CallOptions = {}): Promise<HttpResponse> {
    try {
      return await this.request(this.target, this.spec('POST', path, opts));
    } catch (err) {
      if (!(err instanceof TransportError)) throw err;
      if (err.kind === 'too_large') throw this.tooLarge('POST', path, opts);
      throw new CliError(
        'network_error',
        EXIT_RUNTIME,
        `POST ${path} failed: ${err.kind === 'timeout' ? 'request timed out' : 'connection failed'}`,
      );
    }
  }

  /**
   * Idempotent GET with retries: connection error, 30 s timeout and 5xx are
   * transient; 3 in a row → exit 3. Non-5xx responses are returned as is.
   */
  async get(path: string, opts: CallOptions = {}): Promise<HttpResponse> {
    let failures = 0;
    for (;;) {
      let reason: string;
      try {
        const res = await this.request(this.target, this.spec('GET', path, opts));
        if (res.status < 500) return res;
        reason = `HTTP ${res.status}`;
      } catch (err) {
        if (!(err instanceof TransportError)) throw err;
        if (err.kind === 'too_large') throw this.tooLarge('GET', path, opts);
        reason = err.kind === 'timeout' ? 'request timed out' : 'connection failed';
      }
      failures++;
      if (failures >= MAX_CONSECUTIVE_TRANSIENT) {
        throw new CliError('network_error', EXIT_RUNTIME, `GET ${path} failed ${failures} times in a row (${reason})`);
      }
      await this.sleep(RETRY_DELAY_MS);
    }
  }

  /** GET that must answer 2xx with a JSON body. */
  async getJson(path: string, opts: CallOptions = {}): Promise<unknown> {
    const res = await this.get(path, opts);
    if (!isOk(res)) throw mapHttpError('GET', path, res);
    return parseJson('GET', path, res);
  }
}
