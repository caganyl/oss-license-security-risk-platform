/**
 * REQ-007 P-22 · Injected dependencies for `main(deps)` of the CLI
 * (`src/cli/main.ts`): a scripted fake API (the `RequestFn`), a fake clock
 * whose `sleep` advances time, an in-memory key file store and output
 * collectors. No network, no real waits, no files.
 *
 * The same `FakeApi.handle` also backs a loopback HTTP server
 * (`serveFakeApi`) for the transport and sub-process tests.
 *
 * Test data only: the API keys below are generated per test run and are not
 * real secrets.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import type { HttpRequestSpec, HttpResponse, RequestFn } from '../../src/cli/client';
import { TransportError } from '../../src/cli/client';
import { KeyFileTooLargeError, type Target } from '../../src/cli/config';
import type { CliDeps, KeyFileHandle } from '../../src/cli/main';

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** A well-formed, random `ossr_<16 hex>_<43 base64url>` key (test value only). */
export function makeApiKey(): { key: string; prefix: string; secret: string } {
  const prefix = `ossr_${randomBytes(8).toString('hex')}`;
  const bytes = randomBytes(43);
  let secret = '';
  for (const b of bytes) secret += B64URL[b % 64];
  return { key: `${prefix}_${secret}`, prefix, secret };
}

export const PROJECT_ID = '0b6e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
export const SCAN_ID = '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f';
export const NEW_PROJECT_ID = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

export type Reply = { status: number; body?: unknown; rawBody?: Buffer | string; headers?: Record<string, string | string[]> } | TransportError;

export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string | null;
}

export type Handler = (req: RecordedRequest, nth: number) => Reply;

/** Builds a finding row in the shape of `GET /api/scans/{id}/findings`. */
export function finding(over: Record<string, unknown>): Record<string, unknown> {
  return {
    finding_type: 'security',
    status: 'open',
    severity: 'high',
    cve_id: null,
    ghsa_id: null,
    risk_level: null,
    applied_policy: null,
    normalized_license: null,
    detected_license: null,
    package_name: 'pkg',
    package_version: '1.0.0',
    ...over,
  };
}

/**
 * Scripted API. Default routes answer a successful scan of `PROJECT_ID`
 * (`name` = `demo`); `on(method, pathPattern, handler)` overrides a route.
 * Every request is recorded (`requests`).
 */
export class FakeApi {
  readonly requests: RecordedRequest[] = [];
  private readonly routes: Array<{ method: string; pattern: RegExp; handler: Handler; count: number }> = [];

  projects: unknown[] = [{ id: PROJECT_ID, name: 'demo' }];
  /** Successive scan statuses answered by `GET /api/scans/{id}` (the last one repeats). */
  scanStatuses: string[] = ['running', 'completed'];
  scanErrorMessage: string | null = null;
  findings: unknown[] = [];
  vulnStatus: string | null = 'complete';
  /** Key created by `POST /api/auth/api-keys`. */
  createdKey = makeApiKey().key;
  sessionCookieValue = 'qa-session-cookie-value-0001';

  constructor() {
    this.on('GET', /^\/api\/projects$/, () => ({ status: 200, body: { data: this.projects } }));
    this.on('POST', /^\/api\/scans$/, () => ({
      status: 201,
      body: { data: { id: SCAN_ID, project_id: PROJECT_ID, status: 'pending', project_name: 'demo' } },
    }));
    let polls = 0;
    this.on('GET', /^\/api\/scans\/[^/]+$/, () => {
      const status = this.scanStatuses[Math.min(polls, this.scanStatuses.length - 1)];
      polls++;
      return {
        status: 200,
        body: {
          data: {
            id: SCAN_ID,
            project_id: PROJECT_ID,
            project_name: 'demo',
            status,
            total_dependencies: 12,
            error_message: status === 'completed' ? null : this.scanErrorMessage,
          },
        },
      };
    });
    this.on('GET', /^\/api\/scans\/[^/]+\/findings$/, () => ({ status: 200, body: { data: this.findings } }));
    this.on('GET', /^\/api\/vulnerability-data\/status$/, () => ({
      status: 200,
      body: { data: { projects: [{ project_id: PROJECT_ID, latest_scan_id: SCAN_ID, vulnerability_data_status: this.vulnStatus }] } },
    }));
    this.on('POST', /^\/api\/auth\/setup$/, () => ({
      status: 201,
      body: { data: { ok: true } },
      headers: { 'set-cookie': [`ossrisk_session=${this.sessionCookieValue}; Path=/; HttpOnly; SameSite=Strict`] },
    }));
    this.on('POST', /^\/api\/auth\/api-keys$/, () => ({
      status: 201,
      body: { data: { id: 'k1', name: 'bootstrap', key: this.createdKey, keyPrefix: this.createdKey.slice(0, 21) } },
    }));
    this.on('POST', /^\/api\/projects$/, () => ({ status: 201, body: { data: { id: NEW_PROJECT_ID, name: 'x' } } }));
    this.on('POST', /^\/api\/auth\/logout$/, () => ({ status: 204 }));
  }

  /** Later registrations win. */
  on(method: string, pattern: RegExp, handler: Handler): this {
    this.routes.unshift({ method, pattern, handler, count: 0 });
    return this;
  }

  handle(req: RecordedRequest): Reply {
    this.requests.push(req);
    const route = this.routes.find((r) => r.method === req.method && r.pattern.test(req.path));
    if (!route) return { status: 404, body: { error: 'Not Found', message: 'no fake route', code: 'not_found' } };
    return route.handler(req, route.count++);
  }

  /** `RequestFn` for `main(deps)`. */
  readonly request: RequestFn = async (_target: Target, spec: HttpRequestSpec): Promise<HttpResponse> => {
    const reply = this.handle({ method: spec.method, path: spec.path, headers: { ...spec.headers }, body: spec.body });
    if (reply instanceof TransportError) throw reply;
    return toResponse(reply);
  };

  paths(): string[] {
    return this.requests.map((r) => `${r.method} ${r.path}`);
  }
}

function toResponse(reply: Exclude<Reply, TransportError>): HttpResponse {
  const body =
    reply.rawBody !== undefined
      ? Buffer.isBuffer(reply.rawBody)
        ? reply.rawBody
        : Buffer.from(reply.rawBody, 'utf8')
      : reply.body === undefined
        ? Buffer.alloc(0)
        : Buffer.from(JSON.stringify(reply.body), 'utf8');
  const headers: http.IncomingHttpHeaders = {};
  for (const [k, v] of Object.entries(reply.headers ?? {})) (headers as Record<string, unknown>)[k.toLowerCase()] = v;
  return { status: reply.status, headers, body };
}

export interface Collector {
  write(chunk: string): boolean;
  text(): string;
}

export function collector(): Collector {
  const parts: string[] = [];
  return {
    write(chunk: string) {
      parts.push(chunk);
      return true;
    },
    text: () => parts.join(''),
  };
}

export interface FakeFs {
  files: Map<string, string>;
  /** Mode reported by `KeyFileHandle.mode()` (POSIX check). */
  mode: number;
  opened: string[];
  unlinked: string[];
}

export interface TestDeps extends CliDeps {
  out: Collector;
  err: Collector;
  fs: FakeFs;
  sleeps: number[];
  clock: { now: number };
}

/** `CliDeps` with the fake API and in-memory key files; `over` replaces fields. */
export function makeDeps(argv: readonly string[], api: FakeApi, over: Partial<CliDeps> = {}): TestDeps {
  const out = collector();
  const err = collector();
  const fakeFs: FakeFs = { files: new Map(), mode: 0o100600, opened: [], unlinked: [] };
  const sleeps: number[] = [];
  const clock = { now: Date.parse('2026-10-11T08:00:00.000Z') };
  const deps: TestDeps = {
    argv,
    env: {},
    stdout: out,
    stderr: err,
    version: '1.0.0',
    platform: 'win32',
    now: () => clock.now,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      clock.now += ms;
    },
    readKeyFile: async (file: string, maxBytes: number) => {
      const content = fakeFs.files.get(file);
      if (content === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      const buf = Buffer.from(content, 'utf8');
      if (buf.length > maxBytes) throw new KeyFileTooLargeError();
      return buf;
    },
    openExclusive: async (file: string): Promise<KeyFileHandle> => {
      if (fakeFs.files.has(file)) throw Object.assign(new Error('EEXIST'), { code: 'EEXIST' });
      fakeFs.files.set(file, '');
      fakeFs.opened.push(file);
      return {
        mode: async () => fakeFs.mode,
        writeAll: async (text: string) => {
          fakeFs.files.set(file, (fakeFs.files.get(file) ?? '') + text);
        },
        sync: async () => undefined,
        close: async () => undefined,
      };
    },
    unlink: async (file: string) => {
      fakeFs.unlinked.push(file);
      fakeFs.files.delete(file);
    },
    resolvePath: (p: string) => path.resolve(p),
    randomBytes: (size: number) => Buffer.alloc(size, 0x5a),
    request: api.request,
    out,
    err,
    fs: fakeFs,
    sleeps,
    clock,
    ...over,
  };
  return deps;
}

export interface FakeApiServer {
  origin: string;
  port: number;
  /** Raw `Host` header of every request. */
  hosts: string[];
  connections: number;
  close(): Promise<void>;
}

/** Serves `FakeApi.handle` on 127.0.0.1 (random port). A `TransportError` reply destroys the socket. */
export async function serveFakeApi(api: FakeApi): Promise<FakeApiServer> {
  const hosts: string[] = [];
  const state = { connections: 0 };
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      hosts.push(String(req.headers.host ?? ''));
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
      const body = chunks.length ? Buffer.concat(chunks).toString('utf8') : null;
      const reply = api.handle({ method: req.method ?? 'GET', path: req.url ?? '/', headers, body });
      if (reply instanceof TransportError) {
        req.socket.destroy();
        return;
      }
      const resp = toResponse(reply);
      res.writeHead(resp.status, { 'Content-Type': 'application/json', ...(reply.headers ?? {}) });
      res.end(resp.body);
    });
  });
  server.on('connection', () => {
    state.connections++;
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    hosts,
    get connections() {
      return state.connections;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** A TCP listener that only counts connections (proxy / redirect trap). */
export async function startTrap(): Promise<{ origin: string; port: number; readonly connections: number; close(): Promise<void> }> {
  const state = { connections: 0 };
  const server = http.createServer((_req, res) => {
    res.writeHead(502);
    res.end();
  });
  server.on('connection', () => {
    state.connections++;
  });
  server.on('connect', (_req, socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    get connections() {
      return state.connections;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
