/**
 * Corporate proxy settings of the registry client (REQ-004 AC-P14-12, D-59;
 * ADR-006 Karar 5).
 *
 * Only `HTTPS_PROXY`/`https_proxy` and `NO_PROXY`/`no_proxy` are read
 * (`HTTP_PROXY`/`ALL_PROXY` are not: every registry endpoint is HTTPS). The
 * per-request decision is made by the pure `shouldUseProxy`; the proxy agent
 * itself never gets `NO_PROXY`, so this function is the single source of
 * truth. The proxy URL may carry credentials: it is never logged or written
 * to an error text.
 *
 * Pure module (only `node:url`, ADR-006 Karar 1).
 */
import { URL } from 'node:url';

export type ProxySettings =
  | { mode: 'direct' }
  | { mode: 'proxy'; proxyUrl: string; noProxy: string }
  /** The proxy value is not a valid http(s) URL: no registry connection is opened at all. */
  | { mode: 'invalid'; setting: 'HTTPS_PROXY' };

function firstSet(env: Readonly<Record<string, string | undefined>>, names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = env[name];
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
  }
  return undefined;
}

/** Proxy settings from the environment: `https_proxy` then `HTTPS_PROXY`; `no_proxy` then `NO_PROXY`. */
export function resolveProxy(env: Readonly<Record<string, string | undefined>>): ProxySettings {
  const proxy = firstSet(env, ['https_proxy', 'HTTPS_PROXY']);
  if (proxy === undefined) return { mode: 'direct' };
  let parsed: URL;
  try {
    parsed = new URL(proxy);
  } catch {
    return { mode: 'invalid', setting: 'HTTPS_PROXY' };
  }
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.hostname === '') {
    return { mode: 'invalid', setting: 'HTTPS_PROXY' };
  }
  return { mode: 'proxy', proxyUrl: proxy, noProxy: firstSet(env, ['no_proxy', 'NO_PROXY']) ?? '' };
}

function defaultPort(protocol: string): string {
  return protocol === 'http:' ? '80' : '443';
}

/** Host without IPv6 brackets, lower case. */
function bareHost(host: string): string {
  const lower = host.toLowerCase();
  return lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;
}

/** Splits a NO_PROXY entry into host and optional port (`host:443`, `[::1]:8443`, `::1`). */
function splitEntry(entry: string): { host: string; port: string | null } {
  if (entry.startsWith('[')) {
    const close = entry.indexOf(']');
    if (close === -1) return { host: entry, port: null };
    const rest = entry.slice(close + 1);
    return { host: entry.slice(0, close + 1), port: rest.startsWith(':') && rest.length > 1 ? rest.slice(1) : null };
  }
  const colon = entry.lastIndexOf(':');
  // More than one colon without brackets: an IPv6 literal, no port.
  if (colon === -1 || entry.indexOf(':') !== colon) return { host: entry, port: null };
  return { host: entry.slice(0, colon), port: entry.slice(colon + 1) || null };
}

function isIpLiteral(host: string): boolean {
  return host.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/**
 * Whether a request to `targetUrl` goes through the proxy, given the
 * NO_PROXY list (AC-P14-12): entries separated by commas and/or whitespace,
 * blanks skipped, case-insensitive. `*` -> never proxy. An entry is `host`,
 * `.domain`, `*.domain` or `domain`; `domain`/`.domain` match the target
 * itself or a label-boundary suffix (`example.com` matches `a.example.com`,
 * not `badexample.com`). An optional `:port` must equal the target's
 * effective port. IP literals match exactly; CIDR is not supported.
 */
export function shouldUseProxy(targetUrl: string | URL, noProxyList: string): boolean {
  let target: URL;
  try {
    target = typeof targetUrl === 'string' ? new URL(targetUrl) : targetUrl;
  } catch {
    return false;
  }
  const host = bareHost(target.hostname);
  const port = target.port || defaultPort(target.protocol);
  const entries = (noProxyList ?? '').split(/[\s,]+/).filter((e) => e.length > 0);
  for (const rawEntry of entries) {
    const entry = rawEntry.toLowerCase();
    if (entry === '*') return false;
    const { host: entryHostRaw, port: entryPort } = splitEntry(entry);
    if (entryPort !== null && entryPort !== port) continue;
    let entryHost = bareHost(entryHostRaw);
    if (entryHost.startsWith('*.')) entryHost = entryHost.slice(1);
    if (entryHost.length === 0 || entryHost === '.') continue;
    if (isIpLiteral(entryHost) || isIpLiteral(host)) {
      if (entryHost === host) return false;
      continue;
    }
    const domain = entryHost.startsWith('.') ? entryHost.slice(1) : entryHost;
    if (host === domain || host.endsWith(`.${domain}`)) return false;
  }
  return true;
}

/** Node versions whose `https.Agent` supports `proxyEnv` (`^22.21.0 || >=24.5.0`, ADR-006 Karar 5). */
export function nodeSupportsProxyEnv(version: string): boolean {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return false;
  const [major, minor] = [Number(match[1]), Number(match[2])];
  if (major === 22) return minor >= 21;
  if (major === 24) return minor >= 5;
  return major > 24;
}
