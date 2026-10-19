/**
 * Response header rules: HSTS, CSP, clickjacking, nosniff, Referrer-Policy,
 * Permissions-Policy, version disclosure, cookies and CORS (REQ-008 P-26;
 * contract section 4.1). Pure functions over a `ProbeResponse`.
 */
import { locationOf } from '../allowlist';
import { finding } from '../rules';
import type { ProbeResponse, WebFindingDraft } from '../types';

export const HSTS_MIN_SECONDS = 15_552_000;

/** First value of a header (a repeated header is joined with ', ' by Node except set-cookie). */
export function headerValue(response: Pick<ProbeResponse, 'headers'>, name: string): string | null {
  const raw = response.headers[name.toLowerCase()];
  if (raw === undefined) return null;
  const value = Array.isArray(raw) ? raw.join(', ') : raw;
  return value;
}

export function isHtml(response: Pick<ProbeResponse, 'headers'>): boolean {
  const type = (headerValue(response, 'content-type') ?? '').toLowerCase();
  return type.includes('text/html') || type.includes('application/xhtml');
}

/** `max-age` of an HSTS value; null when missing/invalid. */
export function hstsMaxAge(value: string): number | null {
  const m = /(?:^|;)\s*max-age\s*=\s*"?(\d{1,12})"?\s*(?:;|$)/i.exec(value);
  return m ? Number(m[1]) : null;
}

/** CSP directives (lower-case name -> tokens); the first occurrence of a directive wins. */
export function parseCsp(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter((t) => t.length > 0);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1));
  }
  return directives;
}

/** Weak script sources of a CSP (contract 4.1): returned tokens, empty = not weak. */
export function weakScriptSources(directives: Map<string, string[]>): string[] {
  const sources = directives.get('script-src') ?? directives.get('default-src');
  if (!sources) return [];
  const lower = sources.map((s) => s.toLowerCase());
  const weak: string[] = [];
  const hasNonceOrHash = lower.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(s) || s === "'strict-dynamic'");
  if (lower.includes("'unsafe-inline'") && !hasNonceOrHash) weak.push("'unsafe-inline'");
  if (lower.includes("'unsafe-eval'")) weak.push("'unsafe-eval'");
  for (const s of lower) {
    if (s === '*' || s === 'http:' || s === 'https:' || s === 'data:') weak.push(s);
  }
  return [...new Set(weak)];
}

/** Rules on the main page's final response (headers only). */
export function checkSecurityHeaders(page: ProbeResponse): WebFindingDraft[] {
  const out: WebFindingDraft[] = [];
  const location = locationOf(page.url);
  const https = page.url.startsWith('https:');
  const html = isHtml(page);

  if (https) {
    const hsts = headerValue(page, 'strict-transport-security');
    const maxAge = hsts === null ? null : hstsMaxAge(hsts);
    if (maxAge === null) {
      out.push(finding('WEB-HDR-001', { location, evidence: hsts === null ? 'Başlık yok' : 'max-age okunamadı' }));
    } else if (maxAge < HSTS_MIN_SECONDS) {
      out.push(finding('WEB-HDR-002', { location, evidence: `max-age=${maxAge}` }));
    }
  }

  const nosniff = (headerValue(page, 'x-content-type-options') ?? '').toLowerCase();
  if (!/\bnosniff\b/.test(nosniff)) out.push(finding('WEB-HDR-006', { location, evidence: 'Başlık yok' }));

  if (html) {
    const csp = headerValue(page, 'content-security-policy');
    const directives = csp === null ? new Map<string, string[]>() : parseCsp(csp);
    if (csp === null) {
      const reportOnly = headerValue(page, 'content-security-policy-report-only') !== null;
      out.push(finding('WEB-HDR-003', { location, evidence: reportOnly ? 'Yalnız Content-Security-Policy-Report-Only var (zorlanmıyor)' : 'Başlık yok' }));
    } else {
      const weak = weakScriptSources(directives);
      if (weak.length > 0) out.push(finding('WEB-HDR-004', { location, evidence: `Gevşek kaynaklar: ${weak.join(' ')}` }));
    }
    const xfo = (headerValue(page, 'x-frame-options') ?? '').trim().toLowerCase();
    const xfoOk = xfo === 'deny' || xfo === 'sameorigin';
    if (!xfoOk && !directives.has('frame-ancestors')) {
      out.push(finding('WEB-HDR-005', { location, evidence: xfo === '' ? 'X-Frame-Options ve CSP frame-ancestors yok' : `X-Frame-Options geçersiz: ${xfo}` }));
    }
    if (headerValue(page, 'referrer-policy') === null) out.push(finding('WEB-HDR-007', { location, evidence: 'Başlık yok' }));
    if (headerValue(page, 'permissions-policy') === null) out.push(finding('WEB-HDR-008', { location, evidence: 'Başlık yok' }));
  }
  return out;
}

/** Version disclosure headers of the main page (WEB-INF-001…003). */
export function checkDisclosureHeaders(page: ProbeResponse): WebFindingDraft[] {
  const out: WebFindingDraft[] = [];
  const location = locationOf(page.url);
  const server = headerValue(page, 'server');
  if (server !== null && /\d+\.\d+/.test(server)) {
    out.push(finding('WEB-INF-001', { location, evidence: `Server: ${server}`, key: 'server' }));
  }
  const powered = headerValue(page, 'x-powered-by');
  if (powered !== null && powered.trim() !== '') {
    out.push(finding('WEB-INF-002', { location, evidence: `X-Powered-By: ${powered}`, key: 'x-powered-by' }));
  }
  const parts: string[] = [];
  const aspnet = headerValue(page, 'x-aspnet-version');
  const mvc = headerValue(page, 'x-aspnetmvc-version');
  if (aspnet !== null) parts.push(`X-AspNet-Version: ${aspnet}`);
  if (mvc !== null) parts.push(`X-AspNetMvc-Version: ${mvc}`);
  if (parts.length > 0) out.push(finding('WEB-INF-003', { location, evidence: parts.join('; '), key: 'aspnet-version' }));
  return out;
}

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

/** Name and flags of one `Set-Cookie` value; the cookie value is never kept (AC-P26-8). */
export function parseSetCookie(header: string): ParsedCookie | null {
  const parts = header.split(';');
  const first = parts[0] ?? '';
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  if (name === '' || name.length > 200) return null;
  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  for (const raw of parts.slice(1)) {
    const attr = raw.trim();
    const lower = attr.toLowerCase();
    if (lower === 'secure') secure = true;
    else if (lower === 'httponly') httpOnly = true;
    else if (lower.startsWith('samesite')) {
      const value = attr.split('=')[1];
      sameSite = value ? value.trim().toLowerCase() : '';
    }
  }
  return { name, secure, httpOnly, sameSite };
}

const SESSION_COOKIE_RE = /^(asp\.net_sessionid|\.aspnetcore\..*|\.aspxauth|jsessionid|phpsessid|connect\.sid)$|session|sess|auth|token|jwt/i;

/** REQ-008 D-239. */
export function isSessionCookie(name: string): boolean {
  return SESSION_COOKIE_RE.test(name);
}

/** Cookie rules over every response of the main page chain; one finding per cookie name and rule (D-238). */
export function checkCookies(responses: readonly ProbeResponse[]): WebFindingDraft[] {
  const out: WebFindingDraft[] = [];
  const seen = new Set<string>();
  for (const response of responses) {
    const https = response.url.startsWith('https:');
    const raw = response.headers['set-cookie'];
    const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      const cookie = parseSetCookie(value);
      if (!cookie) continue;
      const location = locationOf(response.url);
      const push = (ruleId: string, evidence: string, severity?: 'low' | 'medium') => {
        const key = `${ruleId}|${cookie.name}`;
        if (seen.has(key)) return;
        seen.add(key);
        out.push(finding(ruleId, { location, evidence, key: `cookie:${cookie.name}`, severity }));
      };
      // `SameSite=None` without Secure is rejected by browsers; it is covered by the Secure rule.
      if (https && !cookie.secure) push('WEB-CKE-001', `Çerez: ${cookie.name}`);
      if (!cookie.httpOnly) push('WEB-CKE-002', `Çerez: ${cookie.name}`, isSessionCookie(cookie.name) ? 'medium' : 'low');
      if (cookie.sameSite === null || cookie.sameSite === '') push('WEB-CKE-003', `Çerez: ${cookie.name}`);
    }
  }
  return out;
}

export const CORS_PROBE_ORIGIN = 'https://oss-risk-cors-probe.invalid';

/**
 * CORS rules from the two probe responses (contract 4.1): `foreign` was sent
 * with `Origin: https://oss-risk-cors-probe.invalid`, `nullOrigin` with
 * `Origin: null`. At most one finding (the most severe).
 */
export function checkCors(foreign: ProbeResponse | null, nullOrigin: ProbeResponse | null): WebFindingDraft[] {
  const evaluate = (response: ProbeResponse | null, sent: string) => {
    if (!response) return null;
    const acao = (headerValue(response, 'access-control-allow-origin') ?? '').trim();
    const acac = (headerValue(response, 'access-control-allow-credentials') ?? '').trim().toLowerCase() === 'true';
    if (acao === '') return null;
    const reflected = acao.toLowerCase() === sent.toLowerCase();
    return { response, acao, acac, reflected };
  };
  const results = [evaluate(foreign, CORS_PROBE_ORIGIN), evaluate(nullOrigin, 'null')].filter((r) => r !== null);
  const credentialed = results.find((r) => r.reflected && r.acac);
  if (credentialed) {
    return [finding('WEB-CORS-001', {
      location: locationOf(credentialed.response.url),
      evidence: `Access-Control-Allow-Origin: ${credentialed.acao}; Access-Control-Allow-Credentials: true`,
      key: 'cors',
    })];
  }
  const open = results.find((r) => r.reflected || r.acao === '*');
  if (open) {
    return [finding('WEB-CORS-002', {
      location: locationOf(open.response.url),
      evidence: `Access-Control-Allow-Origin: ${open.acao}`,
      key: 'cors',
    })];
  }
  return [];
}
