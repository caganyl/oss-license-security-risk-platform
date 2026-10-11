/**
 * HTTP layer of registry enrichment (REQ-004 AC-P14-9…13, AC-P15-2/3/5;
 * ADR-006 Karar 4, 5): a thin adapter over the shared safe HTTP core
 * (`src/lib/http/safeHttpClient.ts`, ADR-007 Karar 1, 2). Public API and
 * behaviour are unchanged; `npmRegistry.ts`/`pypiRegistry.ts` get a session.
 *
 * - Fixed endpoint set (`PRODUCTION_ENDPOINTS`), frozen in code. Tests may
 *   inject endpoints from code only (`assertInjectableEndpoint`: the three
 *   production origins, or `http://127.0.0.1:<port>` / `http://[::1]:<port>`);
 *   nothing reads them from the environment, settings or registry data.
 * - `assertAllowedUrl` semantics run before the first request **and every
 *   redirect hop** (core purpose table): no credentials, exact origin of the
 *   purpose's endpoint, archive URLs under `<origin>/`. Metadata follows at
 *   most 3 same-origin redirects; archives follow none (`download_failed`).
 * - Fixed headers (no cookie, `Authorization`, token or API key). Metadata
 *   accepts gzip; archives require identity (integrity covers the served bytes).
 * - Streamed size caps (metadata 8 MiB, archive 64 MiB); per-attempt total
 *   timeout `REGISTRY_TIMEOUT_MS`; archives `max(REGISTRY_TIMEOUT_MS, 60 s)`.
 * - Retries, `Retry-After`, `err.code` classification, per-scan per-host
 *   circuit breaker, process-wide semaphore (`REGISTRY_CONCURRENCY`),
 *   in-flight dedupe, proxy and TLS rules: see the core.
 */
import { URL } from 'node:url';
import { ENRICHMENT_LIMITS } from '../scanner/sandbox/runner.config';
import { systemClock as appSystemClock, type AppClock } from '../lib/clock';
import { assertInjectableOrigin, isLoopbackHttp } from '../lib/http/endpoints';
import {
  createSafeHttpClient,
  parseJsonBody,
  parseRetryAfter as coreParseRetryAfter,
  type SafeHttpPurpose,
} from '../lib/http/safeHttpClient';
import type { DigestAlgorithm } from './integrity';

// ---------------------------------------------------------------------------
// Endpoints and URL allowlist
// ---------------------------------------------------------------------------

export interface RegistryEndpoints {
  npm: string;
  pypi: string;
  files: string;
  /** NuGet flat container origin (REQ-006, ADR-008 Karar 8). */
  nuget: string;
}

export const PRODUCTION_ENDPOINTS: Readonly<RegistryEndpoints> = Object.freeze({
  npm: 'https://registry.npmjs.org',
  pypi: 'https://pypi.org',
  files: 'https://files.pythonhosted.org',
  nuget: 'https://api.nuget.org',
});

const PRODUCTION_ORIGINS: ReadonlySet<string> = new Set(Object.values(PRODUCTION_ENDPOINTS));

export type RequestPurpose = 'metadata-npm' | 'metadata-pypi' | 'metadata-nuget' | 'archive-npm' | 'archive-pypi' | 'archive-nuget';

const PURPOSE_ENDPOINT: Readonly<Record<RequestPurpose, keyof RegistryEndpoints>> = {
  'metadata-npm': 'npm',
  'metadata-pypi': 'pypi',
  'metadata-nuget': 'nuget',
  'archive-npm': 'npm',
  'archive-pypi': 'files',
  'archive-nuget': 'nuget',
};

const FLAT_CONTAINER = 'v3-flatcontainer';

/** `[id, ver, file]` of `/v3-flatcontainer/<id>/<ver>/<file>` (no query, no fragment), else null. */
function flatContainerParts(url: URL): [string, string, string] | null {
  if (url.search !== '' || url.hash !== '') return null;
  const parts = url.pathname.split('/');
  if (parts.length !== 5 || parts[0] !== '' || parts[1] !== FLAT_CONTAINER) return null;
  const [, , id, ver, file] = parts;
  return id.length > 0 && ver.length > 0 ? [id, ver, file] : null;
}

/** First `metadata-nuget` request: exactly `/v3-flatcontainer/<id>/<ver>/<id>.nuspec` (ADR-008 Karar 8). */
export function isNuspecPath(url: URL): boolean {
  const parts = flatContainerParts(url);
  return parts !== null && parts[2] === `${parts[0]}.nuspec`;
}

/** `archive-nuget`: exactly `/v3-flatcontainer/<id>/<ver>/<id>.<ver>.nupkg` (ADR-008 Karar 8). */
export function isNupkgPath(url: URL): boolean {
  const parts = flatContainerParts(url);
  return parts !== null && parts[2] === `${parts[0]}.${parts[1]}.nupkg`;
}

/** A URL outside the allowlist; no request is made. */
export class RegistryUrlError extends Error {
  readonly code = 'URL_NOT_ALLOWED';
  constructor(message: string) {
    super(message);
    this.name = 'RegistryUrlError';
  }
}

/**
 * Validates an endpoint injected from code (tests only) and returns its
 * origin: one of the three production origins, or a loopback `http:` origin
 * (any port). Path, query, fragment and credentials are rejected.
 */
export function assertInjectableEndpoint(value: string): string {
  return assertInjectableOrigin(value, PRODUCTION_ORIGINS, { label: 'Kayıt defteri', makeError: (m) => new RegistryUrlError(m) });
}

/** Effective endpoint set: production values, or validated injected ones. */
export function resolveEndpoints(injected?: Partial<RegistryEndpoints>): RegistryEndpoints {
  return {
    npm: injected?.npm !== undefined ? assertInjectableEndpoint(injected.npm) : PRODUCTION_ENDPOINTS.npm,
    pypi: injected?.pypi !== undefined ? assertInjectableEndpoint(injected.pypi) : PRODUCTION_ENDPOINTS.pypi,
    files: injected?.files !== undefined ? assertInjectableEndpoint(injected.files) : PRODUCTION_ENDPOINTS.files,
    nuget: injected?.nuget !== undefined ? assertInjectableEndpoint(injected.nuget) : PRODUCTION_ENDPOINTS.nuget,
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

/** `metadata-nuget` result (ADR-008 Karar 8): the raw body; content type is not checked, the XML reader validates it. */
export type TextFetchResult =
  | { kind: 'ok'; body: Buffer }
  | { kind: 'not_found' }
  | { kind: 'unreachable'; code: FailureCode }
  | { kind: 'error'; code: FailureCode };

export type ArchiveFetchResult =
  | { kind: 'ok'; body: Buffer; digest: string; size: number }
  | { kind: 'download_failed'; code: FailureCode }
  | { kind: 'limit_exceeded'; code: 'archive_size' };

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Alias of the application clock (ADR-007 Karar 1). */
export type RegistryClock = AppClock;

export const systemClock: RegistryClock = appSystemClock;

export interface RegistryClientLimits {
  metadataMaxBytes: number;
  /** NuGet `.nuspec` cap (decompressed body). */
  nuspecMaxBytes: number;
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

/**
 * `Retry-After` in ms (delta seconds or HTTP-date), `null` when absent,
 * `NaN` when unparseable.
 */
export function parseRetryAfter(value: string | string[] | undefined, now: number): number | null {
  return coreParseRetryAfter(value, now);
}

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
  /** NuGet `.nuspec` (ADR-008 Karar 8); the first target must be the exact nuspec path, else `URL_NOT_ALLOWED` without a request. */
  getText(target: string, purpose: 'metadata-nuget', options: JsonRequestOptions): Promise<TextFetchResult>;
  getArchive(target: string, purpose: 'archive-npm' | 'archive-pypi' | 'archive-nuget', options: ArchiveRequestOptions): Promise<ArchiveFetchResult>;
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

function registryPurposes(limits: RegistryClientLimits): Record<RequestPurpose, SafeHttpPurpose> {
  const anyPath = () => true;
  const underOrigin = (url: URL, origin: string) => url.href.startsWith(`${origin}/`);
  const metadata = (originKey: keyof RegistryEndpoints): SafeHttpPurpose => ({
    originKey,
    method: 'GET',
    redirect: { sameOriginMax: limits.maxRedirects },
    maxBytes: limits.metadataMaxBytes,
    accept: 'application/json',
    acceptEncoding: 'gzip',
    pathRule: anyPath,
    kind: 'json',
  });
  const archive = (originKey: keyof RegistryEndpoints): SafeHttpPurpose => ({
    originKey,
    method: 'GET',
    redirect: 'none',
    maxBytes: limits.archiveMaxBytes,
    accept: 'application/octet-stream',
    acceptEncoding: 'identity',
    pathRule: underOrigin,
    minTimeoutMs: limits.archiveMinTimeoutMs,
    kind: 'binary',
  });
  // NuGet (ADR-008 Karar 8): redirect hops stay under `/v3-flatcontainer/` without a query;
  // the first request's exact nuspec path is checked by `getText` before the core runs.
  const underFlatContainer = (url: URL, origin: string) =>
    url.href.startsWith(`${origin}/${FLAT_CONTAINER}/`) && url.search === '' && url.hash === '';
  return {
    'metadata-npm': metadata('npm'),
    'metadata-pypi': metadata('pypi'),
    'metadata-nuget': {
      originKey: 'nuget',
      method: 'GET',
      redirect: { sameOriginMax: limits.maxRedirects },
      maxBytes: limits.nuspecMaxBytes,
      accept: 'application/xml, text/xml;q=0.9, */*;q=0.1',
      acceptEncoding: 'gzip',
      pathRule: underFlatContainer,
      kind: 'text',
    },
    'archive-npm': archive('npm'),
    'archive-pypi': archive('files'),
    'archive-nuget': { ...archive('nuget'), pathRule: (url: URL, origin: string) => underOrigin(url, origin) && isNupkgPath(url) },
  };
}

export function createRegistryClient(options: RegistryClientOptions): RegistryClient {
  const endpoints = resolveEndpoints(options.endpoints);
  const limits: RegistryClientLimits = { ...ENRICHMENT_LIMITS.client, ...options.limits };
  const core = createSafeHttpClient({
    origins: { npm: endpoints.npm, pypi: endpoints.pypi, files: endpoints.files, nuget: endpoints.nuget },
    purposes: registryPurposes(limits),
    timeoutMs: options.timeoutMs,
    concurrency: options.concurrency,
    limits: {
      maxRetries: limits.maxRetries,
      retryBackoffMs: limits.retryBackoffMs,
      maxRetryAfterMs: limits.maxRetryAfterMs,
      failureThreshold: limits.failureThreshold,
    },
    userAgentSuffix: 'license-enrichment',
    proxyWarningSubject: 'kayıt defteri zenginleştirmesi',
    env: options.env,
    nodeVersion: options.nodeVersion,
    clock: options.clock ?? systemClock,
    warn: options.warn,
  });

  function session(): RegistrySession {
    const inner = core.session();
    return {
      endpoints,
      isHostClosed: (host) => inner.isHostClosed(host),
      async getJson(target, purpose, requestOptions) {
        const result = await inner.request(purpose, target, { signal: requestOptions.signal, dedupeKey: requestOptions.dedupeKey });
        switch (result.kind) {
          case 'ok': {
            const parsed = parseJsonBody(result);
            return parsed.ok ? { kind: 'ok', json: parsed.json } : { kind: 'error', code: parsed.code };
          }
          case 'not_found':
            return { kind: 'not_found' };
          case 'unreachable':
            return { kind: 'unreachable', code: result.code };
          case 'too_large':
            return { kind: 'error', code: 'TOO_LARGE' };
          default:
            return { kind: 'error', code: result.code };
        }
      },
      async getText(target, purpose, requestOptions) {
        let first: URL;
        try {
          first = new URL(target);
        } catch {
          return { kind: 'error', code: 'URL_NOT_ALLOWED' };
        }
        if (!isNuspecPath(first)) return { kind: 'error', code: 'URL_NOT_ALLOWED' };
        const result = await inner.request(purpose, target, { signal: requestOptions.signal, dedupeKey: requestOptions.dedupeKey });
        switch (result.kind) {
          case 'ok':
            return { kind: 'ok', body: result.body };
          case 'not_found':
            return { kind: 'not_found' };
          case 'unreachable':
            return { kind: 'unreachable', code: result.code };
          case 'too_large':
            return { kind: 'error', code: 'TOO_LARGE' };
          default:
            return { kind: 'error', code: result.code };
        }
      },
      async getArchive(target, purpose, requestOptions) {
        const result = await inner.request(purpose, target, {
          signal: requestOptions.signal,
          algorithm: requestOptions.algorithm,
          dedupeKey: requestOptions.dedupeKey,
        });
        switch (result.kind) {
          case 'ok':
            return result.digest === null
              ? { kind: 'download_failed', code: 'HTTP_200' }
              : { kind: 'ok', body: result.body, digest: result.digest, size: result.body.length };
          case 'not_found':
            return { kind: 'download_failed', code: `HTTP_${result.status}` };
          case 'too_large':
            return { kind: 'limit_exceeded', code: 'archive_size' };
          default:
            return { kind: 'download_failed', code: result.code };
        }
      },
    };
  }

  return { endpoints, session, close: () => core.close() };
}
