/**
 * Web scan target rules (REQ-008 P-25; ADR-010 Karar 3; contract section 1).
 *
 * - `WEB_SCAN_ALLOWED_HOSTS`: the hosts the web scanner may contact. Empty =
 *   web scanning closed. An invalid entry is a start-up error that names the
 *   variable, never the value.
 * - `normalizeWebUrl`: the `webUrl` rule of AC-P25-3, used by the API before
 *   anything is stored and by the worker before the first request (TOCTOU).
 *
 * Pure module (`node:net` for IP literal checks only).
 */
import net from 'node:net';
import { HttpError } from '../lib/httpError';

export const WEB_URL_MAX_LENGTH = 2048;
export const ALLOWED_HOSTS_INVALID_MESSAGE = 'WEB_SCAN_ALLOWED_HOSTS geçersiz bir girdi içeriyor.';
export const WEB_URL_INVALID_MESSAGE = 'Web URL is invalid; use an http or https address without user info or fragment';
export const WEB_URL_NOT_ALLOWED_MESSAGE = 'Web URL host is not in WEB_SCAN_ALLOWED_HOSTS';

export type WebUrlErrorCode = 'web_url_invalid' | 'web_url_not_allowed';

/** 400 error of the web URL rules; the message never carries the URL or the allowlist. */
export class WebUrlError extends HttpError {
  declare readonly code: WebUrlErrorCode;
  constructor(code: WebUrlErrorCode) {
    super(400, code === 'web_url_invalid' ? WEB_URL_INVALID_MESSAGE : WEB_URL_NOT_ALLOWED_MESSAGE, code);
    this.name = 'WebUrlError';
  }
}

interface AllowEntry {
  kind: 'exact' | 'suffix';
  /** Lower-case host (IPv6 without brackets); for `suffix` the domain without `*.`. */
  value: string;
}

export interface HostAllowlist {
  /** True when no host is allowed (web scanning closed). */
  readonly empty: boolean;
  allows(host: string): boolean;
}

const LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

function isHostname(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  return value.split('.').every((label) => LABEL_RE.test(label));
}

/** Lower case, IPv6 brackets removed, one trailing dot removed. */
export function canonicalHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

/**
 * Parses `WEB_SCAN_ALLOWED_HOSTS`. Throws `Error(ALLOWED_HOSTS_INVALID_MESSAGE)`
 * on any invalid entry (scheme, port, path, bare `*`, `*.tld`, bad label).
 */
export function parseAllowedHosts(value: string | undefined): HostAllowlist {
  const entries: AllowEntry[] = [];
  const raw = (value ?? '').split(/[\s,]+/).filter((e) => e.length > 0);
  for (const item of raw) {
    const lower = item.toLowerCase();
    if (/[/@?#]/.test(lower) || lower.includes('://')) throw new Error(ALLOWED_HOSTS_INVALID_MESSAGE);
    if (lower.startsWith('[')) {
      if (!lower.endsWith(']')) throw new Error(ALLOWED_HOSTS_INVALID_MESSAGE);
      const ip = lower.slice(1, -1);
      if (!net.isIPv6(ip)) throw new Error(ALLOWED_HOSTS_INVALID_MESSAGE);
      entries.push({ kind: 'exact', value: ip });
      continue;
    }
    if (lower.startsWith('*.')) {
      const domain = canonicalHost(lower.slice(2));
      // `*.com` (single label) and nested wildcards are refused.
      if (!isHostname(domain) || !domain.includes('.') || domain.includes('*')) throw new Error(ALLOWED_HOSTS_INVALID_MESSAGE);
      entries.push({ kind: 'suffix', value: domain });
      continue;
    }
    if (lower.includes(':') || lower.includes('*')) throw new Error(ALLOWED_HOSTS_INVALID_MESSAGE);
    const host = canonicalHost(lower);
    if (!(net.isIPv4(host) || isHostname(host))) throw new Error(ALLOWED_HOSTS_INVALID_MESSAGE);
    entries.push({ kind: 'exact', value: host });
  }
  return {
    empty: entries.length === 0,
    allows(host: string): boolean {
      const h = canonicalHost(host);
      if (h.length === 0) return false;
      for (const entry of entries) {
        if (entry.kind === 'exact' && entry.value === h) return true;
        if (entry.kind === 'suffix' && !net.isIP(h) && h.endsWith(`.${entry.value}`)) return true;
      }
      return false;
    },
  };
}

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * AC-P25-3: returns `new URL(value).href` or throws `WebUrlError`. The
 * allowlist check runs only after the syntax rule passed.
 */
export function normalizeWebUrl(value: unknown, allowlist: HostAllowlist): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > WEB_URL_MAX_LENGTH) throw new WebUrlError('web_url_invalid');
  if (value !== value.trim() || hasControlCharacter(value) || /\s/.test(value) || value.includes('#')) {
    throw new WebUrlError('web_url_invalid');
  }
  if (!/^https?:\/\//i.test(value)) throw new WebUrlError('web_url_invalid');
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new WebUrlError('web_url_invalid');
  }
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.hostname === '') throw new WebUrlError('web_url_invalid');
  if (parsed.username !== '' || parsed.password !== '') throw new WebUrlError('web_url_invalid');
  // `new URL` drops an empty user-info part (`https://@host`); reject it explicitly.
  const authority = value.replace(/^https?:\/\//i, '').split(/[/?#]/, 1)[0];
  if (authority.includes('@')) throw new WebUrlError('web_url_invalid');
  const href = parsed.href;
  if (href.length > WEB_URL_MAX_LENGTH) throw new WebUrlError('web_url_invalid');
  if (!allowlist.allows(parsed.hostname)) throw new WebUrlError('web_url_not_allowed');
  return href;
}

/** True when `url` parses, is http(s) and its host is allowed (prob client per-request gate, AC-P25-8). */
export function isAllowedRequestUrl(url: string | URL, allowlist: HostAllowlist): boolean {
  let parsed: URL;
  try {
    parsed = typeof url === 'string' ? new URL(url) : url;
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  if (parsed.username !== '' || parsed.password !== '') return false;
  return allowlist.allows(parsed.hostname);
}

/** `scheme://host[:port]/path` without query and fragment (finding locations, contract 2.3). */
export function locationOf(url: string | URL): string {
  try {
    const u = typeof url === 'string' ? new URL(url) : new URL(url.href);
    u.search = '';
    u.hash = '';
    u.username = '';
    u.password = '';
    return u.href.slice(0, WEB_URL_MAX_LENGTH);
  } catch {
    return '';
  }
}
