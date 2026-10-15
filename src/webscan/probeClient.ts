/**
 * Probe client of the web scanner (REQ-008 AC-P25-8, AC-P26-1…3; ADR-010
 * Karar 4, D-216, D-217).
 *
 * - `GET` only; fixed `User-Agent`; never `Cookie` or `Authorization`; the
 *   only optional caller header is `Origin` (CORS probe).
 * - Every request URL is checked against the allowlist first.
 * - Redirects are never followed here (the response is returned as is);
 *   `fetchMainPage` follows same-host redirects of the main page only.
 * - Bodies of every status are read up to the caller's byte cap; reading stops
 *   at the cap (`truncated: true`), decompressed bytes included.
 * - Per-request timeout, per-scan request budget, small concurrency limit.
 * - TLS: Node's CA store + `NODE_EXTRA_CA_CERTS`; certificate validation is
 *   always on. Errors are classified by `err.code` only.
 * - Proxy: https targets use `HTTPS_PROXY`/`NO_PROXY` (shared `proxy.ts`
 *   rules); http targets always go direct.
 * - The job `AbortSignal` aborts a request; its reason is rethrown.
 */
import dns from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { nodeSupportsProxyEnv, resolveProxy, shouldUseProxy } from '../lib/http/proxy';
import { guardProxyTunnelErrors } from '../lib/http/safeHttpClient';
import { type HostAllowlist, canonicalHost, isAllowedRequestUrl } from './allowlist';
import { isCertificateError } from './checks/transport';
import type { ProbeOutcome, ProbeResponse, ProbeTlsInfo } from './types';

export const DEFAULT_PROBE_TIMEOUT_MS = 15_000;
export const MAX_REQUESTS_PER_SCAN = 120;
export const PROBE_CONCURRENCY = 3;
export const MAX_MAIN_PAGE_REDIRECTS = 5;
export const BUDGET_EXHAUSTED = 'BUDGET_EXHAUSTED';
/**
 * Media ranges built without a literal slash-star sequence: the static
 * source guards strip block comments by regex and a literal would hide the
 * rest of this file from them (tests/security/f4Static.test.ts).
 */
const ANY_MEDIA = ['*', '*'].join('/');
const PAGE_ACCEPT = `text/html,application/xhtml+xml,${ANY_MEDIA};q=0.8`;

export interface ProbeRequestOptions {
  signal: AbortSignal;
  maxBytes: number;
  /** `Origin` header of the CORS probe; nothing else can be added. */
  origin?: string;
  accept?: string;
}

export interface ProbeStats {
  /** Requests actually sent (budget counter). */
  requests: number;
  budgetExhausted: boolean;
  /** Network-level failures (excluding budget refusals). */
  failures: number;
  /** True when a https request went through the proxy (legacy TLS probe is skipped then). */
  proxied: boolean;
}

export interface ProbeClient {
  request(url: string, options: ProbeRequestOptions): Promise<ProbeOutcome>;
  /** Whether https requests to this URL would go through the proxy. */
  usesProxy(url: string): boolean;
  readonly stats: ProbeStats;
  close(): void;
}

export interface ProbeClientOptions {
  allowlist: HostAllowlist;
  timeoutMs?: number;
  maxRequests?: number;
  concurrency?: number;
  env?: Readonly<Record<string, string | undefined>>;
  nodeVersion?: string;
}

/**
 * Addresses a host name may never resolve to unless that IP itself is
 * allowlisted (security review L-6: DNS names under a wildcard pointing at
 * loopback, link-local / cloud metadata or the unspecified address). Private
 * ranges (10/8, 172.16/12, 192.168/16) stay allowed: internal systems are the
 * intended targets.
 */
export function isRestrictedAddress(address: string): boolean {
  const ip = address.toLowerCase().replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, '');
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 127 || a === 0 || (a === 169 && b === 254);
  }
  if (net.isIPv6(ip)) {
    return ip === '::1' || ip === '::' || /^fe[89ab][0-9a-f]:/.test(ip);
  }
  return true;
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void;

/** `lookup` of the probe sockets: resolves, then refuses restricted addresses that are not allowlisted. */
export function guardedLookup(allowlist: HostAllowlist) {
  return (hostname: string, options: dns.LookupOptions, callback: LookupCallback): void => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) {
        callback(err, '', 4);
        return;
      }
      const list = (addresses as dns.LookupAddress[]).filter(
        (a) => !isRestrictedAddress(a.address) || allowlist.allows(a.address) || (canonicalHost(hostname) === 'localhost' && allowlist.allows('localhost')),
      );
      if (list.length === 0) {
        const refused = Object.assign(new Error('address not allowed'), { code: 'ADDRESS_NOT_ALLOWED' }) as NodeJS.ErrnoException;
        callback(refused, '', 4);
        return;
      }
      if (options.all) callback(null, list);
      else callback(null, list[0].address, list[0].family);
    });
  };
}

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' && /^[0-9A-Za-z.+-]{1,32}$/.test(pkg.version) ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

let userAgentCache: string | undefined;
export function webScanUserAgent(): string {
  userAgentCache ??= `oss-risk-platform/${readPackageVersion()} (web-scan)`;
  return userAgentCache;
}

function errorCode(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code) ? code : 'NETWORK_ERROR';
}

class Semaphore {
  private active = 0;
  private readonly queue: Array<() => void> = [];
  constructor(private readonly max: number) {}
  async acquire(signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    if (this.active < this.max) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const grant = () => {
        signal.removeEventListener('abort', onAbort);
        this.active++;
        resolve();
      };
      const onAbort = () => {
        const i = this.queue.indexOf(grant);
        if (i !== -1) this.queue.splice(i, 1);
        reject(signal.reason);
      };
      this.queue.push(grant);
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }
  release(): void {
    this.active--;
    this.queue.shift()?.();
  }
}

function tlsInfoOf(socket: unknown): ProbeTlsInfo | null {
  const tls = socket as Partial<TLSSocket> | null;
  if (!tls || typeof tls.getPeerCertificate !== 'function') return null;
  try {
    const cert = tls.getPeerCertificate(false);
    const validTo = cert && typeof cert.valid_to === 'string' && Number.isFinite(Date.parse(cert.valid_to)) ? new Date(Date.parse(cert.valid_to)).toISOString() : null;
    const issuerCn = cert?.issuer && typeof cert.issuer === 'object' ? (cert.issuer as { CN?: unknown; O?: unknown }) : null;
    const issuerRaw = issuerCn ? (typeof issuerCn.CN === 'string' ? issuerCn.CN : typeof issuerCn.O === 'string' ? issuerCn.O : null) : null;
    const protocol = typeof tls.getProtocol === 'function' ? tls.getProtocol() : null;
    return { protocol: protocol ?? null, validTo, issuer: issuerRaw ? issuerRaw.slice(0, 200) : null };
  } catch {
    return null;
  }
}

export function createProbeClient(options: ProbeClientOptions): ProbeClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const maxRequests = options.maxRequests ?? MAX_REQUESTS_PER_SCAN;
  const concurrency = Math.max(1, options.concurrency ?? PROBE_CONCURRENCY);
  const semaphore = new Semaphore(concurrency);
  const stats: ProbeStats = { requests: 0, budgetExhausted: false, failures: 0, proxied: false };
  const userAgent = webScanUserAgent();

  const lookup = guardedLookup(options.allowlist);
  const httpAgent = new http.Agent({ keepAlive: true, maxSockets: concurrency });
  // Security review L-7: explicit, so NODE_TLS_REJECT_UNAUTHORIZED=0 cannot turn validation off.
  const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: concurrency, rejectUnauthorized: true });
  const proxy = resolveProxy(options.env ?? process.env);
  let proxyAgent: https.Agent | null = null;
  let proxyBlocked = false;
  let noProxy = '';
  if (proxy.mode === 'invalid') {
    proxyBlocked = true;
  } else if (proxy.mode === 'proxy') {
    if (nodeSupportsProxyEnv(options.nodeVersion ?? process.versions.node)) {
      const agentOptions: https.AgentOptions & { proxyEnv?: Record<string, string> } = {
        keepAlive: true,
        maxSockets: concurrency,
        rejectUnauthorized: true,
        proxyEnv: { HTTPS_PROXY: proxy.proxyUrl },
      };
      proxyAgent = guardProxyTunnelErrors(new https.Agent(agentOptions));
      noProxy = proxy.noProxy;
    } else {
      proxyBlocked = true;
    }
  }

  const isLoopback = (url: URL) => {
    const h = canonicalHost(url.hostname);
    return h === 'localhost' || h === '::1' || h.startsWith('127.');
  };
  const usesProxy = (url: URL) => url.protocol === 'https:' && proxyAgent !== null && !isLoopback(url) && shouldUseProxy(url, noProxy);

  function agentFor(url: URL): http.Agent | null {
    if (url.protocol === 'http:') return httpAgent;
    if (isLoopback(url)) return httpsAgent;
    if (proxyBlocked) return null;
    return usesProxy(url) ? proxyAgent : httpsAgent;
  }

  function once(url: URL, opts: ProbeRequestOptions): Promise<ProbeOutcome> {
    return new Promise<ProbeOutcome>((resolve, reject) => {
      const agent = agentFor(url);
      if (agent === null) {
        resolve({ ok: false, failure: { url: url.href, code: 'PROXY_UNAVAILABLE', tlsCertificate: false } });
        return;
      }
      if (agent === proxyAgent) stats.proxied = true;
      const combined = AbortSignal.any([AbortSignal.timeout(timeoutMs), opts.signal]);
      let settled = false;
      let req: http.ClientRequest | null = null;
      let res: http.IncomingMessage | null = null;
      let decoder: zlib.Gunzip | zlib.Inflate | null = null;
      const finish = (outcome: ProbeOutcome | { abort: unknown }) => {
        if (settled) return;
        settled = true;
        combined.removeEventListener('abort', onAbort);
        decoder?.destroy();
        res?.destroy();
        req?.destroy();
        if ('abort' in outcome) reject(outcome.abort);
        else resolve(outcome);
      };
      const fail = (code: string) => finish({ ok: false, failure: { url: url.href, code, tlsCertificate: isCertificateError(code) } });
      const onAbort = () => (opts.signal.aborted ? finish({ abort: opts.signal.reason }) : fail('TIMEOUT'));
      if (combined.aborted) return onAbort();
      combined.addEventListener('abort', onAbort, { once: true });

      const headers: Record<string, string> = {
        'User-Agent': userAgent,
        Accept: opts.accept ?? ANY_MEDIA,
        'Accept-Encoding': 'gzip, deflate',
      };
      if (opts.origin !== undefined) headers.Origin = opts.origin;
      const request = url.protocol === 'http:' ? http.request : https.request;
      // Direct connections resolve through the guarded lookup (L-6); a proxied
      // request is resolved by the proxy (the allowlist host check still applies).
      const requestOptions: https.RequestOptions = { method: 'GET', agent, headers, ...(agent === proxyAgent ? {} : { lookup }) };
      if (url.protocol === 'https:') requestOptions.rejectUnauthorized = true;
      req = request(url, requestOptions, (response) => {
        res = response;
        const tls = tlsInfoOf(response.socket);
        const chunks: Buffer[] = [];
        let bytes = 0;
        let truncated = false;
        const complete = () => {
          const out: ProbeResponse = {
            url: url.href,
            status: response.statusCode ?? 0,
            headers: response.headers as ProbeResponse['headers'],
            body: Buffer.concat(chunks),
            truncated,
            tls,
          };
          finish({ ok: true, response: out });
        };
        const push = (chunk: Buffer) => {
          if (truncated) return;
          const room = opts.maxBytes - bytes;
          if (chunk.length >= room) {
            chunks.push(chunk.subarray(0, Math.max(0, room)));
            bytes = opts.maxBytes;
            truncated = true;
            complete();
            return;
          }
          chunks.push(chunk);
          bytes += chunk.length;
        };
        const encoding = String(response.headers['content-encoding'] ?? '').trim().toLowerCase();
        if (encoding === 'gzip' || encoding === 'x-gzip' || encoding === 'deflate') {
          decoder = encoding === 'deflate' ? zlib.createInflate() : zlib.createGunzip();
          decoder.on('data', push);
          // A broken or cut stream keeps what was decoded so far.
          decoder.on('error', () => complete());
          decoder.on('end', complete);
          response.pipe(decoder);
        } else {
          response.on('data', push);
          response.on('end', complete);
        }
        response.on('error', () => (chunks.length > 0 ? complete() : fail('ECONNRESET')));
        response.on('close', () => {
          if (!response.complete && !settled) {
            if (chunks.length > 0) complete();
            else fail('ECONNRESET');
          }
        });
      });
      req.on('error', (err) => fail(errorCode(err)));
      req.end();
    });
  }

  return {
    stats,
    usesProxy(target: string) {
      try {
        return usesProxy(new URL(target));
      } catch {
        return false;
      }
    },
    async request(target, opts) {
      opts.signal.throwIfAborted();
      let url: URL;
      try {
        url = new URL(target);
      } catch {
        return { ok: false, failure: { url: String(target).slice(0, 2048), code: 'URL_NOT_ALLOWED', tlsCertificate: false } };
      }
      // AC-P25-8: every request host is checked, redirect targets included.
      if (!isAllowedRequestUrl(url, options.allowlist)) return { ok: false, failure: { url: url.href, code: 'URL_NOT_ALLOWED', tlsCertificate: false } };
      if (stats.requests >= maxRequests) {
        stats.budgetExhausted = true;
        return { ok: false, failure: { url: url.href, code: BUDGET_EXHAUSTED, tlsCertificate: false } };
      }
      stats.requests++;
      await semaphore.acquire(opts.signal);
      try {
        const outcome = await once(url, opts);
        if (!outcome.ok) stats.failures++;
        return outcome;
      } finally {
        semaphore.release();
      }
    },
    close() {
      httpAgent.destroy();
      httpsAgent.destroy();
      proxyAgent?.destroy();
    },
  };
}

export interface MainPageResult {
  /** Every response of the chain, first request first. */
  chain: ProbeResponse[];
  /** Last response (2xx/4xx/5xx or a redirect that was not followed). */
  final: ProbeResponse | null;
  /** Failure of the first request that got no response. */
  failure: Extract<ProbeOutcome, { ok: false }> | null;
  /** The chain stopped at a redirect to another host. */
  crossHostRedirect: boolean;
}

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/**
 * Security review L-5: the main page follows a redirect only to the same
 * origin, or between http and https of the same host on the default ports
 * (http://h/ <-> https://h/). Any other port or host is not followed.
 */
export function isFollowableRedirect(from: URL, to: URL): boolean {
  if (to.protocol !== 'http:' && to.protocol !== 'https:') return false;
  if (to.origin === from.origin) return true;
  return canonicalHost(to.hostname) === canonicalHost(from.hostname) && from.port === '' && to.port === '';
}

/** Main page with same-host redirects (at most 5, http -> https allowed; AC-P26-3, D-215). */
export async function fetchMainPage(client: ProbeClient, target: string, signal: AbortSignal, maxBytes: number): Promise<MainPageResult> {
  const chain: ProbeResponse[] = [];
  let current = target;
  for (let hop = 0; hop <= MAX_MAIN_PAGE_REDIRECTS; hop++) {
    const outcome = await client.request(current, { signal, maxBytes, accept: PAGE_ACCEPT });
    if (!outcome.ok) return { chain, final: chain.at(-1) ?? null, failure: outcome, crossHostRedirect: false };
    const response = outcome.response;
    chain.push(response);
    if (!REDIRECT_STATUSES.has(response.status)) return { chain, final: response, failure: null, crossHostRedirect: false };
    const location = response.headers.location;
    const value = Array.isArray(location) ? location[0] : location;
    if (typeof value !== 'string' || value.trim() === '') return { chain, final: response, failure: null, crossHostRedirect: false };
    let next: URL;
    try {
      next = new URL(value.trim(), current);
    } catch {
      return { chain, final: response, failure: null, crossHostRedirect: false };
    }
    if (!isFollowableRedirect(new URL(current), next)) {
      return { chain, final: response, failure: null, crossHostRedirect: true };
    }
    next.hash = '';
    current = next.href;
  }
  return { chain, final: chain.at(-1) ?? null, failure: null, crossHostRedirect: false };
}
