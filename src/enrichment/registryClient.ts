/**
 * HTTP layer of registry enrichment (REQ-004 AC-P14-9…13, AC-P15-2/3/5;
 * ADR-006 Karar 4, 5). The only module of `src/enrichment/` that opens
 * network connections; `npmRegistry.ts`/`pypiRegistry.ts` get a session.
 *
 * - Fixed endpoint set (`PRODUCTION_ENDPOINTS`), frozen in code. Tests may
 *   inject endpoints from code only (`assertInjectableEndpoint`: the three
 *   production origins, or `http://127.0.0.1:<port>` / `http://[::1]:<port>`);
 *   nothing reads them from the environment, settings or registry data.
 * - `assertAllowedUrl` runs before the first request **and every redirect
 *   hop**: no credentials, exact origin of the purpose's endpoint, archive
 *   URLs under `<origin>/`. Metadata follows at most 3 same-origin redirects;
 *   archives follow none (`download_failed`).
 * - Fixed headers (no cookie, `Authorization`, token or API key). Metadata
 *   accepts gzip; archives require identity (integrity covers the served bytes).
 * - Streamed size caps (metadata 8 MiB, archive 64 MiB): `Content-Length`
 *   first, then counted bytes (gzip: network and decompressed bytes).
 * - Per-attempt total timeout `REGISTRY_TIMEOUT_MS`; archives
 *   `max(REGISTRY_TIMEOUT_MS, 60 s)`.
 * - Retries: network error, timeout, 429, 5xx -> at most 2 more attempts
 *   after 1 s and 2 s; `Retry-After` <= 30 s raises the wait, a longer or
 *   unparseable one gives up (`error`, never cached). 404/410 -> not found.
 * - Errors are classified by `err.code` only; an error message is never
 *   kept (it may contain the proxy URL and its credentials).
 * - Per-scan, per-host circuit breaker (`RegistrySession`): 5 consecutive
 *   failed network attempts close the host for that scan; any HTTP response
 *   resets the counter.
 * - Process-wide concurrency semaphore (`REGISTRY_CONCURRENCY`) shared by
 *   metadata and archive requests of all scans; in-flight dedupe by key with
 *   reference counting (the shared request is aborted only when every
 *   waiter aborted; each waiter races its own signal).
 * - Proxy: our `shouldUseProxy` decides per request; the proxy agent uses
 *   Node's `proxyEnv` (`^22.21.0 || >=24.5.0`). An invalid proxy value, or a
 *   proxy on a Node without `proxyEnv`, opens no registry connection at all.
 *   Loopback (test) endpoints never use the proxy.
 * - TLS: Node's default CA store plus `NODE_EXTRA_CA_CERTS`; certificate
 *   checks are never disabled.
 */
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { URL } from 'node:url';
import zlib from 'node:zlib';
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import { ENRICHMENT_LIMITS } from '../scanner/sandbox/runner.config';
import { createDigestStream, type DigestAlgorithm } from './integrity';
import { nodeSupportsProxyEnv, resolveProxy, shouldUseProxy, type ProxySettings } from './proxy';

// ---------------------------------------------------------------------------
// Endpoints and URL allowlist
// ---------------------------------------------------------------------------

export interface RegistryEndpoints {
  npm: string;
  pypi: string;
  files: string;
}

export const PRODUCTION_ENDPOINTS: Readonly<RegistryEndpoints> = Object.freeze({
  npm: 'https://registry.npmjs.org',
  pypi: 'https://pypi.org',
  files: 'https://files.pythonhosted.org',
});

const PRODUCTION_ORIGINS: ReadonlySet<string> = new Set(Object.values(PRODUCTION_ENDPOINTS));

export type RequestPurpose = 'metadata-npm' | 'metadata-pypi' | 'archive-npm' | 'archive-pypi';

const PURPOSE_ENDPOINT: Readonly<Record<RequestPurpose, keyof RegistryEndpoints>> = {
  'metadata-npm': 'npm',
  'metadata-pypi': 'pypi',
  'archive-npm': 'npm',
  'archive-pypi': 'files',
};

/** A URL outside the allowlist; no request is made. */
export class RegistryUrlError extends Error {
  readonly code = 'URL_NOT_ALLOWED';
  constructor(message: string) {
    super(message);
    this.name = 'RegistryUrlError';
  }
}

function isLoopbackHttp(url: URL): boolean {
  return url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === '[::1]');
}

/**
 * Validates an endpoint injected from code (tests only) and returns its
 * origin: one of the three production origins, or a loopback `http:` origin
 * (any port). Path, query, fragment and credentials are rejected.
 */
export function assertInjectableEndpoint(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RegistryUrlError('Kayıt defteri uç noktası geçerli bir URL değil.');
  }
  if (url.username || url.password) throw new RegistryUrlError('Kayıt defteri uç noktası kullanıcı bilgisi içeremez.');
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
    throw new RegistryUrlError('Kayıt defteri uç noktası yol veya sorgu içeremez.');
  }
  if (url.protocol === 'https:' && PRODUCTION_ORIGINS.has(url.origin)) return url.origin;
  if (isLoopbackHttp(url)) return url.origin;
  throw new RegistryUrlError('Kayıt defteri uç noktası izin listesinde değil.');
}

/** Effective endpoint set: production values, or validated injected ones. */
export function resolveEndpoints(injected?: Partial<RegistryEndpoints>): RegistryEndpoints {
  return {
    npm: injected?.npm !== undefined ? assertInjectableEndpoint(injected.npm) : PRODUCTION_ENDPOINTS.npm,
    pypi: injected?.pypi !== undefined ? assertInjectableEndpoint(injected.pypi) : PRODUCTION_ENDPOINTS.pypi,
    files: injected?.files !== undefined ? assertInjectableEndpoint(injected.files) : PRODUCTION_ENDPOINTS.files,
  };
}

/**
 * Request-time allowlist (every request and every redirect hop): parsed with
 * `new URL`, no credentials, exact origin of the purpose's endpoint (default
 * port normalized by `URL.origin`), `https:` unless the endpoint is a
 * loopback test origin; archive URLs must lie under `<origin>/`.
 */
export function assertAllowedUrl(target: string | URL, purpose: RequestPurpose, endpoints: RegistryEndpoints): URL {
  let url: URL;
  try {
    url = new URL(String(target));
  } catch {
    throw new RegistryUrlError('Kayıt defteri URL’si geçersiz.');
  }
  if (url.username || url.password) throw new RegistryUrlError('Kayıt defteri URL’si kullanıcı bilgisi içeremez.');
  const origin = new URL(endpoints[PURPOSE_ENDPOINT[purpose]]).origin;
  if (url.origin !== origin) throw new RegistryUrlError('Kayıt defteri URL’si izin verilen kökende değil.');
  if (url.protocol !== 'https:' && !isLoopbackHttp(url)) throw new RegistryUrlError('Kayıt defteri URL’si https olmalı.');
  if (purpose.startsWith('archive-') && !url.href.startsWith(`${origin}/`)) {
    throw new RegistryUrlError('Arşiv URL’si izin verilen önekte değil.');
  }
  return url;
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/**
 * Failure codes: Node `err.code` values (`ENOTFOUND`, `ECONNRESET`,
 * `ERR_TLS_*`, `CERT_*`, …) or fixed codes of this layer (`TIMEOUT`,
 * `HTTP_<status>`, `TOO_LARGE`, `BAD_ENCODING`, `BAD_CONTENT_TYPE`,
 * `BAD_JSON`, `REDIRECT`, `REDIRECT_LIMIT`, `RETRY_AFTER`, `URL_NOT_ALLOWED`,
 * `CIRCUIT_OPEN`, `PROXY_UNAVAILABLE`). Never a message.
 */
export type FailureCode = string;

export type JsonFetchResult =
  | { kind: 'ok'; json: Record<string, unknown> }
  | { kind: 'not_found' }
  | { kind: 'unreachable'; code: FailureCode }
  | { kind: 'error'; code: FailureCode };

export type ArchiveFetchResult =
  | { kind: 'ok'; body: Buffer; digest: string; size: number }
  | { kind: 'download_failed'; code: FailureCode }
  | { kind: 'limit_exceeded'; code: 'archive_size' };

/** Network-level attempt (`net`) or HTTP response (`http`), in order: drives the circuit breaker. */
type AttemptTrace = Array<'net' | 'http'>;

interface Shared<T> {
  result: T;
  trace: AttemptTrace;
  host: string;
}

// ---------------------------------------------------------------------------
// Options and helpers
// ---------------------------------------------------------------------------

export interface RegistryClock {
  /** Wall clock in ms (HTTP-date `Retry-After`). */
  now(): number;
  /** Waits `ms`; resolves early when `signal` aborts. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
}

export const systemClock: RegistryClock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve) => {
      if (signal.aborted) return resolve();
      const onAbort = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal.addEventListener('abort', onAbort, { once: true });
    }),
};

export interface RegistryClientLimits {
  metadataMaxBytes: number;
  archiveMaxBytes: number;
  archiveMinTimeoutMs: number;
  maxRetries: number;
  retryBackoffMs: readonly number[];
  maxRetryAfterMs: number;
  maxRedirects: number;
  failureThreshold: number;
}

export interface RegistryClientOptions {
  /** `REGISTRY_TIMEOUT_MS`: total time of one attempt. */
  timeoutMs: number;
  /** `REGISTRY_CONCURRENCY`: process-wide request slots. */
  concurrency: number;
  /** Code-level injection for tests only (validated by `assertInjectableEndpoint`). */
  endpoints?: Partial<RegistryEndpoints>;
  /** Proxy environment (default `process.env`). */
  env?: Readonly<Record<string, string | undefined>>;
  /** Node version used for the `proxyEnv` check (default `process.versions.node`). */
  nodeVersion?: string;
  clock?: RegistryClock;
  limits?: Partial<RegistryClientLimits>;
  /** Warning sink (only setting names are logged); default `console.warn`. */
  warn?: (message: string) => void;
}

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' && /^[0-9A-Za-z.+-]{1,32}$/.test(pkg.version) ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

let userAgentCache: string | undefined;
function userAgent(): string {
  userAgentCache ??= `oss-risk-platform/${readPackageVersion()} (license-enrichment)`;
  return userAgentCache;
}

function errorCode(err: unknown): FailureCode {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code) ? code : 'NETWORK_ERROR';
}

function abortReason(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const err = new Error('Kayıt defteri isteği iptal edildi.');
  err.name = 'AbortError';
  return err;
}

/**
 * `Retry-After` in ms (delta seconds or HTTP-date), `null` when absent,
 * `NaN` when unparseable.
 */
export function parseRetryAfter(value: string | string[] | undefined, now: number): number | null {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined || raw.trim() === '') return null;
  const trimmed = raw.trim();
  if (/^\d{1,10}$/.test(trimmed)) return Number(trimmed) * 1000;
  const date = Date.parse(trimmed);
  return Number.isNaN(date) ? Number.NaN : Math.max(0, date - now);
}

/** Process-wide counting semaphore; waiting is abortable. */
class Semaphore {
  private active = 0;
  private readonly queue: Array<() => void> = [];
  constructor(private readonly max: number) {}

  acquire(signal: AbortSignal): Promise<boolean> {
    if (signal.aborted) return Promise.resolve(false);
    if (this.active < this.max) {
      this.active++;
      return Promise.resolve(true);
    }
    return new Promise<boolean>((resolve) => {
      const grant = () => {
        signal.removeEventListener('abort', onAbort);
        this.active++;
        resolve(true);
      };
      const onAbort = () => {
        const index = this.queue.indexOf(grant);
        if (index !== -1) this.queue.splice(index, 1);
        resolve(false);
      };
      this.queue.push(grant);
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }

  release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) next();
  }
}

// ---------------------------------------------------------------------------
// One attempt
// ---------------------------------------------------------------------------

interface AttemptSpec {
  url: URL;
  accept: string;
  encoding: 'gzip' | 'identity';
  maxBytes: number;
  timeoutMs: number;
  signal: AbortSignal;
  algorithm?: DigestAlgorithm;
  /** Body is read only for these statuses; other responses are destroyed unread. */
  readBody: (status: number) => boolean;
}

type AttemptOutcome =
  | { type: 'aborted' }
  | { type: 'network'; code: FailureCode }
  | { type: 'response'; status: number; headers: IncomingHttpHeaders; body: Buffer | null; digest: string | null }
  | { type: 'too_large' }
  | { type: 'bad_encoding' };

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export interface JsonRequestOptions {
  signal: AbortSignal;
  /** In-flight dedupe key (default: purpose + URL). */
  dedupeKey?: string;
}

export interface ArchiveRequestOptions {
  signal: AbortSignal;
  algorithm: DigestAlgorithm;
  /** In-flight dedupe key, e.g. `(ecosystem, name, version, digest)` (default: purpose + URL). */
  dedupeKey?: string;
}

/** Per-scan view of the client: carries the per-host circuit breaker (ADR-006 Karar 4). */
export interface RegistrySession {
  readonly endpoints: RegistryEndpoints;
  getJson(target: string, purpose: 'metadata-npm' | 'metadata-pypi', options: JsonRequestOptions): Promise<JsonFetchResult>;
  getArchive(target: string, purpose: 'archive-npm' | 'archive-pypi', options: ArchiveRequestOptions): Promise<ArchiveFetchResult>;
  /** True when the host's consecutive failure threshold was reached in this scan. */
  isHostClosed(host: string): boolean;
}

export interface RegistryClient {
  readonly endpoints: RegistryEndpoints;
  /** New per-scan session (own failure counters, shared semaphore and dedupe map). */
  session(): RegistrySession;
  /** Destroys pooled sockets (shutdown, tests). */
  close(): void;
}

type ProxyAgentOptions = https.AgentOptions & { proxyEnv?: Record<string, string> };

export function createRegistryClient(options: RegistryClientOptions): RegistryClient {
  const endpoints = resolveEndpoints(options.endpoints);
  const limits: RegistryClientLimits = { ...ENRICHMENT_LIMITS.client, ...options.limits };
  const clock = options.clock ?? systemClock;
  const warn = options.warn ?? ((message: string) => console.warn(message));
  const semaphore = new Semaphore(Math.max(1, Math.floor(options.concurrency)));
  const inflight = new Map<string, { controller: AbortController; waiters: number; promise: Promise<unknown> }>();

  const agentOptions: https.AgentOptions = { keepAlive: true, maxSockets: Math.max(1, Math.floor(options.concurrency)) };
  const directAgent = new https.Agent(agentOptions);
  const loopbackAgent = new http.Agent({ keepAlive: true, maxSockets: agentOptions.maxSockets });
  const proxy: ProxySettings = resolveProxy(options.env ?? process.env);
  let proxyAgent: https.Agent | null = null;
  let proxyBlocked = false;
  let noProxy = '';
  if (proxy.mode === 'invalid') {
    proxyBlocked = true;
    warn(`${proxy.setting} geçerli bir http(s) URL'si değil; kayıt defteri zenginleştirmesi bağlantı açmayacak.`);
  } else if (proxy.mode === 'proxy') {
    if (nodeSupportsProxyEnv(options.nodeVersion ?? process.versions.node)) {
      const proxyOptions: ProxyAgentOptions = { ...agentOptions, proxyEnv: { HTTPS_PROXY: proxy.proxyUrl } };
      proxyAgent = new https.Agent(proxyOptions);
      noProxy = proxy.noProxy;
    } else {
      proxyBlocked = true;
      warn("HTTPS_PROXY tanımlı ancak bu Node sürümü vekil desteği vermiyor (^22.21.0 || >=24.5.0); kayıt defteri zenginleştirmesi bağlantı açmayacak.");
    }
  }

  /** Agent of one request, or null when no connection may be opened (proxy error mode). */
  function agentFor(url: URL): http.Agent | null {
    if (isLoopbackHttp(url)) return loopbackAgent;
    if (proxyBlocked) return null;
    if (proxyAgent && shouldUseProxy(url, noProxy)) return proxyAgent;
    return directAgent;
  }

  function attempt(spec: AttemptSpec): Promise<AttemptOutcome> {
    return new Promise<AttemptOutcome>((resolve) => {
      const agent = agentFor(spec.url);
      if (agent === null) return resolve({ type: 'network', code: 'PROXY_UNAVAILABLE' });
      const combined = AbortSignal.any([AbortSignal.timeout(spec.timeoutMs), spec.signal]);
      let settled = false;
      // Assigned below; `finish` may run before (already aborted), hence `let` with null.
      let req: http.ClientRequest | null = null;
      let res: IncomingMessage | null = null;
      let gunzip: zlib.Gunzip | null = null;
      const finish = (outcome: AttemptOutcome) => {
        if (settled) return;
        settled = true;
        combined.removeEventListener('abort', onAbort);
        if (outcome.type !== 'response' || outcome.body === null) {
          gunzip?.destroy();
          res?.destroy();
          req?.destroy();
        }
        resolve(outcome);
      };
      const onAbort = () => finish(spec.signal.aborted ? { type: 'aborted' } : { type: 'network', code: 'TIMEOUT' });
      if (combined.aborted) return onAbort();
      combined.addEventListener('abort', onAbort, { once: true });

      const headers = Object.freeze({ 'User-Agent': userAgent(), Accept: spec.accept, 'Accept-Encoding': spec.encoding });
      const request = spec.url.protocol === 'http:' ? http.request : https.request;
      req = request(spec.url, { method: 'GET', agent, headers }, (response) => {
        res = response;
        const status = response.statusCode ?? 0;
        if (!spec.readBody(status)) {
          finish({ type: 'response', status, headers: response.headers, body: null, digest: null });
          return;
        }
        const declared = Number(response.headers['content-length']);
        if (Number.isFinite(declared) && declared > spec.maxBytes) return finish({ type: 'too_large' });
        const encoding = String(response.headers['content-encoding'] ?? 'identity').trim().toLowerCase() || 'identity';
        if (encoding !== 'identity' && !(encoding === 'gzip' && spec.encoding === 'gzip')) return finish({ type: 'bad_encoding' });

        const digest = spec.algorithm ? createDigestStream(spec.algorithm) : null;
        const chunks: Buffer[] = [];
        let networkBytes = 0;
        let bodyBytes = 0;
        const done = () =>
          finish({ type: 'response', status, headers: response.headers, body: Buffer.concat(chunks), digest: digest ? digest.digest() : null });
        response.on('data', (chunk: Buffer) => {
          networkBytes += chunk.length;
          if (networkBytes > spec.maxBytes) return finish({ type: 'too_large' });
          digest?.update(chunk);
          if (!gunzip) chunks.push(chunk);
        });
        response.on('error', (err) => finish({ type: 'network', code: errorCode(err) }));
        response.on('close', () => {
          if (!response.complete) finish({ type: 'network', code: 'ECONNRESET' });
        });
        if (encoding === 'gzip') {
          gunzip = zlib.createGunzip();
          gunzip.on('data', (chunk: Buffer) => {
            bodyBytes += chunk.length;
            if (bodyBytes > spec.maxBytes) return finish({ type: 'too_large' });
            chunks.push(chunk);
          });
          gunzip.on('error', () => finish({ type: 'bad_encoding' }));
          gunzip.on('end', done);
          response.pipe(gunzip);
        } else {
          response.on('end', done);
        }
      });
      req.on('error', (err) => finish({ type: 'network', code: errorCode(err) }));
      req.end();
    });
  }

  /** One attempt holding a semaphore slot; `null` when aborted while waiting. */
  async function slotAttempt(spec: AttemptSpec): Promise<AttemptOutcome> {
    if (!(await semaphore.acquire(spec.signal))) return { type: 'aborted' };
    try {
      return await attempt(spec);
    } finally {
      semaphore.release();
    }
  }

  /**
   * Retry wait after a 429/5xx: backoff raised by `Retry-After`; null = give
   * up (`Retry-After` > 30 s or unparseable).
   */
  function retryWait(retry: number, headers: IncomingHttpHeaders): number | null {
    const backoff = limits.retryBackoffMs[Math.min(retry, limits.retryBackoffMs.length - 1)] ?? 1000;
    const retryAfter = parseRetryAfter(headers['retry-after'], clock.now());
    if (retryAfter === null) return backoff;
    if (Number.isNaN(retryAfter) || retryAfter > limits.maxRetryAfterMs) return null;
    return Math.max(backoff, retryAfter);
  }

  async function runJson(start: URL, purpose: 'metadata-npm' | 'metadata-pypi', signal: AbortSignal): Promise<Shared<JsonFetchResult | null>> {
    const trace: AttemptTrace = [];
    const host = start.host;
    let current = start;
    let redirects = 0;
    let retry = 0;
    for (;;) {
      const outcome = await slotAttempt({
        url: current,
        accept: 'application/json',
        encoding: 'gzip',
        maxBytes: limits.metadataMaxBytes,
        timeoutMs: options.timeoutMs,
        signal,
        readBody: (status) => status === 200,
      });
      if (outcome.type === 'aborted') return { result: null, trace, host };
      if (outcome.type === 'network') {
        trace.push('net');
        if (retry < limits.maxRetries && outcome.code !== 'PROXY_UNAVAILABLE') {
          await clock.sleep(limits.retryBackoffMs[Math.min(retry, limits.retryBackoffMs.length - 1)] ?? 1000, signal);
          if (signal.aborted) return { result: null, trace, host };
          retry++;
          continue;
        }
        return { result: { kind: 'unreachable', code: outcome.code }, trace, host };
      }
      trace.push('http');
      if (outcome.type === 'too_large') return { result: { kind: 'error', code: 'TOO_LARGE' }, trace, host };
      if (outcome.type === 'bad_encoding') return { result: { kind: 'error', code: 'BAD_ENCODING' }, trace, host };
      const { status, headers, body } = outcome;
      if (REDIRECT_STATUSES.has(status)) {
        if (redirects >= limits.maxRedirects) return { result: { kind: 'error', code: 'REDIRECT_LIMIT' }, trace, host };
        const location = headers.location;
        if (typeof location !== 'string' || location === '') return { result: { kind: 'error', code: 'REDIRECT' }, trace, host };
        try {
          const next = assertAllowedUrl(new URL(location, current), purpose, endpoints);
          if (next.origin !== current.origin) return { result: { kind: 'error', code: 'REDIRECT' }, trace, host };
          current = next;
        } catch {
          return { result: { kind: 'error', code: 'URL_NOT_ALLOWED' }, trace, host };
        }
        redirects++;
        continue;
      }
      if (status === 404 || status === 410) return { result: { kind: 'not_found' }, trace, host };
      if (status === 429 || status >= 500) {
        if (retry >= limits.maxRetries) return { result: { kind: 'error', code: `HTTP_${status}` }, trace, host };
        const wait = retryWait(retry, headers);
        if (wait === null) return { result: { kind: 'error', code: 'RETRY_AFTER' }, trace, host };
        await clock.sleep(wait, signal);
        if (signal.aborted) return { result: null, trace, host };
        retry++;
        continue;
      }
      if (status !== 200 || body === null) return { result: { kind: 'error', code: `HTTP_${status}` }, trace, host };
      if (!String(headers['content-type'] ?? '').toLowerCase().includes('json')) {
        return { result: { kind: 'error', code: 'BAD_CONTENT_TYPE' }, trace, host };
      }
      try {
        const parsed: unknown = JSON.parse(new TextDecoder('utf-8').decode(body));
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          return { result: { kind: 'error', code: 'BAD_JSON' }, trace, host };
        }
        return { result: { kind: 'ok', json: parsed as Record<string, unknown> }, trace, host };
      } catch {
        return { result: { kind: 'error', code: 'BAD_JSON' }, trace, host };
      }
    }
  }

  async function runArchive(url: URL, algorithm: DigestAlgorithm, signal: AbortSignal): Promise<Shared<ArchiveFetchResult | null>> {
    const trace: AttemptTrace = [];
    const host = url.host;
    let retry = 0;
    for (;;) {
      const outcome = await slotAttempt({
        url,
        accept: 'application/octet-stream',
        encoding: 'identity',
        maxBytes: limits.archiveMaxBytes,
        timeoutMs: Math.max(options.timeoutMs, limits.archiveMinTimeoutMs),
        signal,
        algorithm,
        readBody: (status) => status === 200,
      });
      if (outcome.type === 'aborted') return { result: null, trace, host };
      if (outcome.type === 'network') {
        trace.push('net');
        if (retry < limits.maxRetries && outcome.code !== 'PROXY_UNAVAILABLE') {
          await clock.sleep(limits.retryBackoffMs[Math.min(retry, limits.retryBackoffMs.length - 1)] ?? 1000, signal);
          if (signal.aborted) return { result: null, trace, host };
          retry++;
          continue;
        }
        return { result: { kind: 'download_failed', code: outcome.code }, trace, host };
      }
      trace.push('http');
      if (outcome.type === 'too_large') return { result: { kind: 'limit_exceeded', code: 'archive_size' }, trace, host };
      if (outcome.type === 'bad_encoding') return { result: { kind: 'download_failed', code: 'BAD_ENCODING' }, trace, host };
      const { status, headers, body, digest } = outcome;
      if (status >= 300 && status < 400) return { result: { kind: 'download_failed', code: 'REDIRECT' }, trace, host };
      if (status === 429 || status >= 500) {
        if (retry >= limits.maxRetries) return { result: { kind: 'download_failed', code: `HTTP_${status}` }, trace, host };
        const wait = retryWait(retry, headers);
        if (wait === null) return { result: { kind: 'download_failed', code: 'RETRY_AFTER' }, trace, host };
        await clock.sleep(wait, signal);
        if (signal.aborted) return { result: null, trace, host };
        retry++;
        continue;
      }
      if (status !== 200 || body === null || digest === null) {
        return { result: { kind: 'download_failed', code: `HTTP_${status}` }, trace, host };
      }
      return { result: { kind: 'ok', body, digest, size: body.length }, trace, host };
    }
  }

  /** Joins (or starts) the shared in-flight request of `key`; rejects with the waiter's abort reason. */
  function joinShared<T>(key: string, start: (signal: AbortSignal) => Promise<T>, signal: AbortSignal): Promise<T> {
    if (signal.aborted) return Promise.reject(abortReason(signal));
    let entry = inflight.get(key);
    if (!entry) {
      const controller = new AbortController();
      const created = { controller, waiters: 0, promise: Promise.resolve() as Promise<unknown> };
      created.promise = start(controller.signal).finally(() => {
        if (inflight.get(key) === created) inflight.delete(key);
      });
      inflight.set(key, created);
      entry = created;
    }
    const shared = entry;
    shared.waiters++;
    return new Promise<T>((resolve, reject) => {
      const onAbort = () => {
        shared.waiters--;
        if (shared.waiters === 0) {
          if (inflight.get(key) === shared) inflight.delete(key);
          shared.controller.abort();
        }
        reject(abortReason(signal));
      };
      signal.addEventListener('abort', onAbort, { once: true });
      shared.promise.then(
        (value) => {
          if (signal.aborted) return;
          signal.removeEventListener('abort', onAbort);
          shared.waiters--;
          resolve(value as T);
        },
        (err: unknown) => {
          if (signal.aborted) return;
          signal.removeEventListener('abort', onAbort);
          shared.waiters--;
          reject(err);
        },
      );
    });
  }

  function session(): RegistrySession {
    const failures = new Map<string, number>();
    const isHostClosed = (host: string) => (failures.get(host) ?? 0) >= limits.failureThreshold;
    const record = (host: string, trace: AttemptTrace) => {
      for (const step of trace) failures.set(host, step === 'net' ? (failures.get(host) ?? 0) + 1 : 0);
    };

    return {
      endpoints,
      isHostClosed,
      async getJson(target, purpose, requestOptions) {
        let url: URL;
        try {
          url = assertAllowedUrl(target, purpose, endpoints);
        } catch {
          return { kind: 'error', code: 'URL_NOT_ALLOWED' };
        }
        if (isHostClosed(url.host)) return { kind: 'unreachable', code: 'CIRCUIT_OPEN' };
        const key = requestOptions.dedupeKey ?? `${purpose} ${url.href}`;
        const shared = await joinShared(`json ${key}`, (signal) => runJson(url, purpose, signal), requestOptions.signal);
        record(shared.host, shared.trace);
        if (shared.result === null) throw abortReason(requestOptions.signal);
        return shared.result;
      },
      async getArchive(target, purpose, requestOptions) {
        let url: URL;
        try {
          url = assertAllowedUrl(target, purpose, endpoints);
        } catch {
          return { kind: 'download_failed', code: 'URL_NOT_ALLOWED' };
        }
        if (isHostClosed(url.host)) return { kind: 'download_failed', code: 'CIRCUIT_OPEN' };
        const key = requestOptions.dedupeKey ?? `${purpose} ${url.href}`;
        const shared = await joinShared(
          `archive ${requestOptions.algorithm} ${key}`,
          (signal) => runArchive(url, requestOptions.algorithm, signal),
          requestOptions.signal,
        );
        record(shared.host, shared.trace);
        if (shared.result === null) throw abortReason(requestOptions.signal);
        return shared.result;
      },
    };
  }

  return {
    endpoints,
    session,
    close() {
      directAgent.destroy();
      loopbackAgent.destroy();
      proxyAgent?.destroy();
    },
  };
}
