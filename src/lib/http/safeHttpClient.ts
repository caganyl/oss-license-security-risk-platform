/**
 * Shared safe HTTP core (REQ-004 AC-P14-9…13, AC-P15-2/3/5; REQ-005 AC-P17-*;
 * ADR-006 Karar 4, 5 and dated note; ADR-007 Karar 1, 2 / D-87).
 *
 * The only module under `src/` that opens network connections. The registry
 * client (`src/enrichment/registryClient.ts`) and the vulnerability client
 * (`src/vulnerability/client.ts`) are separate instances of this core (own
 * semaphore, agents and in-flight map).
 *
 * - Fixed origin set and a **purpose table** frozen at creation: the caller
 *   gives only a purpose name, a URL and (POST) a body. Headers cannot be
 *   extended from outside; `extraHeaders` of a purpose is added only to a
 *   request whose URL passed that purpose's origin check.
 * - Allowlist on every request and every redirect hop: no credentials, exact
 *   origin of the purpose, `https:` unless the origin is a loopback test
 *   origin, the purpose's path rule. Redirects: none (3xx -> `REDIRECT`) or
 *   at most N same-origin hops.
 * - Streamed size caps (`Content-Length` first, then counted network and
 *   decompressed bytes); per-attempt total timeout.
 * - Retries: network error, timeout, 429, 5xx -> at most `maxRetries` more
 *   attempts after the backoff waits; `Retry-After` <= `maxRetryAfterMs`
 *   raises the wait, a longer or unparseable one gives up (`RETRY_AFTER`).
 *   POST bodies are serialized once and re-sent unchanged.
 * - Errors are classified by `err.code` only; an error message is never kept
 *   (it may contain the proxy URL and its credentials, or a header value).
 * - Per-session, per-host circuit breaker: `failureThreshold` consecutive
 *   failed attempts (network failure or `429`/`5xx` response, retries
 *   included) close the host for the session; any other HTTP response resets
 *   the counter. Counted per attempt and checked before every attempt
 *   (REQ-005 security review L-4), so a host answering `503` forever opens
 *   the circuit and its pending retries stop.
 * - Process-wide (per instance) concurrency semaphore; in-flight dedupe by key
 *   with reference counting (the shared request is aborted only when every
 *   waiter aborted; each waiter races its own signal).
 * - Proxy: `shouldUseProxy` decides per request; the proxy agent uses Node's
 *   `proxyEnv`. An invalid proxy value, or a proxy on a Node without
 *   `proxyEnv`, opens no connection at all (`PROXY_UNAVAILABLE`). Loopback
 *   (test) origins never use the proxy.
 * - TLS: Node's default CA store plus `NODE_EXTRA_CA_CERTS`; certificate
 *   checks are never disabled.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { URL } from 'node:url';
import zlib from 'node:zlib';
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import { systemClock, type AppClock } from '../clock';
import { createDigestStream, type DigestAlgorithm } from '../../enrichment/integrity';
import { isLoopbackHttp } from './endpoints';
import { nodeSupportsProxyEnv, resolveProxy, shouldUseProxy, type ProxySettings } from './proxy';

// ---------------------------------------------------------------------------
// Purpose table
// ---------------------------------------------------------------------------

export interface SafeHttpPurpose {
  /** Key of the purpose's origin in the client's origin set. */
  originKey: string;
  method: 'GET' | 'POST';
  /** `none`: any 3xx is the error `REDIRECT`; otherwise at most `sameOriginMax` same-origin hops (301/302/303/307/308). */
  redirect: 'none' | { sameOriginMax: number };
  maxBytes: number;
  accept: string;
  acceptEncoding: 'gzip' | 'identity';
  /** POST only. */
  contentType?: string;
  /** Path/query rule of the purpose (after the origin check). */
  pathRule(url: URL, origin: string): boolean;
  /** Extra headers, added only to a request whose URL passed this purpose's origin check. */
  extraHeaders?(): Record<string, string>;
  /** Attempt timeout floor: `max(timeoutMs, minTimeoutMs)` (archives). */
  minTimeoutMs?: number;
  /**
   * Called before every attempt (retries included), e.g. a rate limiter slot
   * (ADR-007 Karar 6). Resolves false when `signal` aborted while waiting.
   */
  beforeAttempt?(signal: AbortSignal): Promise<boolean>;
  /**
   * Called after every attempt that got an HTTP response (retries included),
   * before the retry decision, e.g. to pause a rate limiter on `429`
   * (security re-verification Y-2). Must not throw; reads headers only.
   */
  onResponse?(status: number, headers: IncomingHttpHeaders): void;
  /** In-flight dedupe key prefix kind: `json` or `binary` (streamed digest). */
  kind: 'json' | 'binary';
}

export interface SafeHttpLimits {
  maxRetries: number;
  retryBackoffMs: readonly number[];
  maxRetryAfterMs: number;
  failureThreshold: number;
}

export interface SafeHttpClientOptions {
  /** Validated origins by key (`https://…` production or loopback test origins). */
  origins: Readonly<Record<string, string>>;
  purposes: Readonly<Record<string, SafeHttpPurpose>>;
  /** Total time of one attempt. */
  timeoutMs: number;
  /** Request slots of this instance. */
  concurrency: number;
  limits: SafeHttpLimits;
  /** Suffix of the `User-Agent` (`license-enrichment`, `vulnerability-lookup`). */
  userAgentSuffix: string;
  /** Subject of the proxy warnings, e.g. `kayıt defteri zenginleştirmesi`. */
  proxyWarningSubject: string;
  /** Proxy environment (default `process.env`). */
  env?: Readonly<Record<string, string | undefined>>;
  /** Node version used for the `proxyEnv` check (default `process.versions.node`). */
  nodeVersion?: string;
  clock?: AppClock;
  /** Warning sink (only setting names are logged); default `console.warn`. */
  warn?: (message: string) => void;
}

/**
 * Failure codes: Node `err.code` values or fixed codes of this layer
 * (`TIMEOUT`, `HTTP_<status>`, `BAD_ENCODING`, `REDIRECT`, `REDIRECT_LIMIT`,
 * `RETRY_AFTER`, `URL_NOT_ALLOWED`, `CIRCUIT_OPEN`, `PROXY_UNAVAILABLE`,
 * `NETWORK_ERROR`). Never a message.
 */
export type FailureCode = string;

export type SafeHttpResult =
  | { kind: 'ok'; headers: IncomingHttpHeaders; body: Buffer; digest: string | null }
  | { kind: 'not_found'; status: number }
  | { kind: 'unreachable'; code: FailureCode }
  | { kind: 'too_large' }
  | { kind: 'error'; code: FailureCode };

export interface SafeHttpRequestOptions {
  signal: AbortSignal;
  /** POST body (serialized once; re-sent unchanged on retries). */
  body?: Buffer;
  /** In-flight dedupe key (default: purpose + URL [+ body hash]). */
  dedupeKey?: string;
  /** Streamed digest of the body (`binary` purposes). */
  algorithm?: DigestAlgorithm;
}

export interface SafeHttpSession {
  /** Throws the waiter's abort reason when `signal` aborts. */
  request(purpose: string, target: string, options: SafeHttpRequestOptions): Promise<SafeHttpResult>;
  /** True when the host's consecutive failure threshold was reached in this session. */
  isHostClosed(host: string): boolean;
}

export interface SafeHttpClient {
  readonly origins: Readonly<Record<string, string>>;
  /** New session (own failure counters, shared semaphore and dedupe map). */
  session(): SafeHttpSession;
  /** Destroys pooled sockets (shutdown, tests). */
  close(): void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' && /^[0-9A-Za-z.+-]{1,32}$/.test(pkg.version) ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

let packageVersionCache: string | undefined;
function packageVersion(): string {
  packageVersionCache ??= readPackageVersion();
  return packageVersionCache;
}

function errorCode(err: unknown): FailureCode {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code) ? code : 'NETWORK_ERROR';
}

export function abortReason(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const err = new Error('HTTP isteği iptal edildi.');
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

/**
 * JSON object of an `ok` result: `application/json`-like content type and a
 * top-level object, otherwise `BAD_CONTENT_TYPE` / `BAD_JSON`.
 */
export function parseJsonBody(result: { headers: IncomingHttpHeaders; body: Buffer }):
  | { ok: true; json: Record<string, unknown> }
  | { ok: false; code: 'BAD_CONTENT_TYPE' | 'BAD_JSON' } {
  if (!String(result.headers['content-type'] ?? '').toLowerCase().includes('json')) return { ok: false, code: 'BAD_CONTENT_TYPE' };
  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8').decode(result.body));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { ok: false, code: 'BAD_JSON' };
    return { ok: true, json: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, code: 'BAD_JSON' };
  }
}

/** Counting semaphore; waiting is abortable. */
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
  method: 'GET' | 'POST';
  headers: Readonly<Record<string, string>>;
  body: Buffer | undefined;
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

/**
 * Per attempt, in order: drives the circuit breaker. `net` = network-level
 * failure, `fail` = `429`/`5xx` response (a failed attempt, REQ-005 security
 * review L-4), `http` = any other HTTP response (resets the counter).
 */
type AttemptStep = 'net' | 'fail' | 'http';
type AttemptTrace = AttemptStep[];

/** Circuit breaker of the session that started a shared request: checked before and updated after every attempt. */
interface AttemptBreaker {
  isOpen(host: string): boolean;
  record(host: string, step: AttemptStep): void;
}

interface Shared {
  result: SafeHttpResult | null;
  trace: AttemptTrace;
  host: string;
  /** Breaker updated live by `run` (its session does not replay `trace`). */
  breaker: AttemptBreaker;
}

type ProxyAgentOptions = https.AgentOptions & { proxyEnv?: Record<string, string> };

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export function createSafeHttpClient(options: SafeHttpClientOptions): SafeHttpClient {
  const origins = Object.freeze({ ...options.origins });
  const purposes: Readonly<Record<string, SafeHttpPurpose>> = Object.freeze({ ...options.purposes });
  const limits = options.limits;
  const clock = options.clock ?? systemClock;
  const warn = options.warn ?? ((message: string) => console.warn(message));
  const userAgent = `oss-risk-platform/${packageVersion()} (${options.userAgentSuffix})`;
  const slots = Math.max(1, Math.floor(options.concurrency));
  const semaphore = new Semaphore(slots);
  const inflight = new Map<string, { controller: AbortController; waiters: number; promise: Promise<unknown> }>();

  const agentOptions: https.AgentOptions = { keepAlive: true, maxSockets: slots };
  const directAgent = new https.Agent(agentOptions);
  const loopbackAgent = new http.Agent({ keepAlive: true, maxSockets: slots });
  const proxy: ProxySettings = resolveProxy(options.env ?? process.env);
  let proxyAgent: https.Agent | null = null;
  let proxyBlocked = false;
  let noProxy = '';
  if (proxy.mode === 'invalid') {
    proxyBlocked = true;
    warn(`${proxy.setting} geçerli bir http(s) URL'si değil; ${options.proxyWarningSubject} bağlantı açmayacak.`);
  } else if (proxy.mode === 'proxy') {
    if (nodeSupportsProxyEnv(options.nodeVersion ?? process.versions.node)) {
      const proxyOptions: ProxyAgentOptions = { ...agentOptions, proxyEnv: { HTTPS_PROXY: proxy.proxyUrl } };
      proxyAgent = new https.Agent(proxyOptions);
      noProxy = proxy.noProxy;
    } else {
      proxyBlocked = true;
      warn(`HTTPS_PROXY tanımlı ancak bu Node sürümü vekil desteği vermiyor (^22.21.0 || >=24.5.0); ${options.proxyWarningSubject} bağlantı açmayacak.`);
    }
  }

  /** Request-time allowlist of one purpose (every request and every redirect hop). */
  function allowedUrl(target: string | URL, purposeName: string): URL | null {
    const purpose = purposes[purposeName];
    if (!purpose) return null;
    const originValue = origins[purpose.originKey];
    if (originValue === undefined) return null;
    let url: URL;
    try {
      url = new URL(String(target));
    } catch {
      return null;
    }
    if (url.username || url.password) return null;
    const origin = new URL(originValue).origin;
    if (url.origin !== origin) return null;
    if (url.protocol !== 'https:' && !isLoopbackHttp(url)) return null;
    if (!purpose.pathRule(url, origin)) return null;
    return url;
  }

  /** Agent of one request, or null when no connection may be opened (proxy error mode). */
  function agentFor(url: URL): http.Agent | null {
    if (isLoopbackHttp(url)) return loopbackAgent;
    if (proxyBlocked) return null;
    if (proxyAgent && shouldUseProxy(url, noProxy)) return proxyAgent;
    return directAgent;
  }

  /** Frozen headers of a request to an already allowed `url` of `purpose`. */
  function headersFor(purpose: SafeHttpPurpose, url: URL, body: Buffer | undefined): Readonly<Record<string, string>> {
    const headers: Record<string, string> = { 'User-Agent': userAgent, Accept: purpose.accept, 'Accept-Encoding': purpose.acceptEncoding };
    if (purpose.method === 'POST') {
      headers['Content-Type'] = purpose.contentType ?? 'application/json';
      headers['Content-Length'] = String(body?.length ?? 0);
    }
    // Origin check before any extra header (ADR-007 Karar 2): only the purpose's own origin.
    const own = origins[purpose.originKey];
    if (purpose.extraHeaders && own !== undefined && url.origin === new URL(own).origin) {
      for (const [name, value] of Object.entries(purpose.extraHeaders())) {
        if (!(name in headers)) headers[name] = value;
      }
    }
    return Object.freeze(headers);
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

      const request = spec.url.protocol === 'http:' ? http.request : https.request;
      req = request(spec.url, { method: spec.method, agent, headers: spec.headers }, (response) => {
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
      req.end(spec.body);
    });
  }

  /** One attempt holding a semaphore slot; `aborted` when aborted while waiting. */
  async function slotAttempt(spec: AttemptSpec): Promise<AttemptOutcome> {
    if (!(await semaphore.acquire(spec.signal))) return { type: 'aborted' };
    try {
      return await attempt(spec);
    } finally {
      semaphore.release();
    }
  }

  function backoff(retry: number): number {
    return limits.retryBackoffMs[Math.min(retry, limits.retryBackoffMs.length - 1)] ?? 1000;
  }

  /** Retry wait after a 429/5xx: backoff raised by `Retry-After`; null = give up. */
  function retryWait(retry: number, headers: IncomingHttpHeaders): number | null {
    const base = backoff(retry);
    const retryAfter = parseRetryAfter(headers['retry-after'], clock.now());
    if (retryAfter === null) return base;
    if (Number.isNaN(retryAfter) || retryAfter > limits.maxRetryAfterMs) return null;
    return Math.max(base, retryAfter);
  }

  async function run(
    start: URL,
    purposeName: string,
    body: Buffer | undefined,
    algorithm: DigestAlgorithm | undefined,
    signal: AbortSignal,
    breaker: AttemptBreaker,
  ): Promise<Shared> {
    const purpose = purposes[purposeName];
    const steps: AttemptTrace = [];
    const host = start.host;
    // L-4: the breaker counts every attempt (retries included) as it happens.
    const trace = {
      push(step: AttemptStep): void {
        steps.push(step);
        breaker.record(host, step);
      },
    };
    const done = (result: SafeHttpResult | null): Shared => ({ result, trace: steps, host, breaker });
    let current = start;
    let redirects = 0;
    let retry = 0;
    for (;;) {
      // L-4: checked before every attempt, so retries stop once the host closed.
      if (breaker.isOpen(host)) return done({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
      if (purpose.beforeAttempt && !(await purpose.beforeAttempt(signal))) return { result: null, trace: steps, host, breaker };
      const outcome = await slotAttempt({
        url: current,
        method: purpose.method,
        headers: headersFor(purpose, current, body),
        body,
        encoding: purpose.acceptEncoding,
        maxBytes: purpose.maxBytes,
        timeoutMs: Math.max(options.timeoutMs, purpose.minTimeoutMs ?? 0),
        signal,
        algorithm,
        readBody: (status) => status === 200,
      });
      if (outcome.type === 'aborted') return { result: null, trace: steps, host, breaker };
      if (outcome.type === 'network') {
        trace.push('net');
        if (retry < limits.maxRetries && outcome.code !== 'PROXY_UNAVAILABLE') {
          await clock.sleep(backoff(retry), signal);
          if (signal.aborted) return { result: null, trace: steps, host, breaker };
          retry++;
          continue;
        }
        return { result: { kind: 'unreachable', code: outcome.code }, trace: steps, host, breaker };
      }
      trace.push(outcome.type === 'response' && (outcome.status === 429 || outcome.status >= 500) ? 'fail' : 'http');
      if (outcome.type === 'too_large') return { result: { kind: 'too_large' }, trace: steps, host, breaker };
      if (outcome.type === 'bad_encoding') return { result: { kind: 'error', code: 'BAD_ENCODING' }, trace: steps, host, breaker };
      const { status, headers } = outcome;
      purpose.onResponse?.(status, headers);
      if (purpose.redirect === 'none') {
        if (status >= 300 && status < 400) return { result: { kind: 'error', code: 'REDIRECT' }, trace: steps, host, breaker };
      } else if (REDIRECT_STATUSES.has(status)) {
        if (redirects >= purpose.redirect.sameOriginMax) return { result: { kind: 'error', code: 'REDIRECT_LIMIT' }, trace: steps, host, breaker };
        const location = headers.location;
        if (typeof location !== 'string' || location === '') return { result: { kind: 'error', code: 'REDIRECT' }, trace: steps, host, breaker };
        let next: URL | null = null;
        try {
          next = allowedUrl(new URL(location, current), purposeName);
        } catch {
          next = null;
        }
        if (next === null) return { result: { kind: 'error', code: 'URL_NOT_ALLOWED' }, trace: steps, host, breaker };
        if (next.origin !== current.origin) return { result: { kind: 'error', code: 'REDIRECT' }, trace: steps, host, breaker };
        current = next;
        redirects++;
        continue;
      }
      if (status === 404 || status === 410) return { result: { kind: 'not_found', status }, trace: steps, host, breaker };
      if (status === 429 || status >= 500) {
        if (retry >= limits.maxRetries) return { result: { kind: 'error', code: `HTTP_${status}` }, trace: steps, host, breaker };
        const wait = retryWait(retry, headers);
        if (wait === null) return { result: { kind: 'error', code: 'RETRY_AFTER' }, trace: steps, host, breaker };
        await clock.sleep(wait, signal);
        if (signal.aborted) return { result: null, trace: steps, host, breaker };
        retry++;
        continue;
      }
      if (status !== 200 || outcome.body === null || (algorithm !== undefined && outcome.digest === null)) {
        return { result: { kind: 'error', code: `HTTP_${status}` }, trace: steps, host, breaker };
      }
      return { result: { kind: 'ok', headers, body: outcome.body, digest: outcome.digest }, trace: steps, host, breaker };
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

  function session(): SafeHttpSession {
    const failures = new Map<string, number>();
    const isHostClosed = (host: string) => (failures.get(host) ?? 0) >= limits.failureThreshold;
    const breaker: AttemptBreaker = {
      isOpen: isHostClosed,
      record(host, step) {
        failures.set(host, step === 'http' ? 0 : (failures.get(host) ?? 0) + 1);
      },
    };
    /** Replays the trace of a shared request started by another session. */
    const record = (host: string, trace: AttemptTrace) => {
      for (const step of trace) breaker.record(host, step);
    };

    return {
      isHostClosed,
      async request(purposeName, target, requestOptions) {
        const purpose = purposes[purposeName];
        const url = allowedUrl(target, purposeName);
        if (!purpose || url === null) return { kind: 'error', code: 'URL_NOT_ALLOWED' };
        if (purpose.method === 'GET' && requestOptions.body !== undefined) return { kind: 'error', code: 'URL_NOT_ALLOWED' };
        if (isHostClosed(url.host)) return { kind: 'unreachable', code: 'CIRCUIT_OPEN' };
        const body = purpose.method === 'POST' ? (requestOptions.body ?? Buffer.alloc(0)) : undefined;
        const base =
          requestOptions.dedupeKey ??
          (body !== undefined ? `${purposeName} ${url.href} ${crypto.createHash('sha256').update(body).digest('hex')}` : `${purposeName} ${url.href}`);
        const key = purpose.kind === 'binary' ? `archive ${requestOptions.algorithm ?? 'none'} ${base}` : `json ${base}`;
        const shared = await joinShared(key, (signal) => run(url, purposeName, body, requestOptions.algorithm, signal, breaker), requestOptions.signal);
        if (shared.breaker !== breaker) record(shared.host, shared.trace);
        if (shared.result === null) throw abortReason(requestOptions.signal);
        return shared.result;
      },
    };
  }

  return {
    origins,
    session,
    close() {
      directAgent.destroy();
      loopbackAgent.destroy();
      proxyAgent?.destroy();
    },
  };
}
