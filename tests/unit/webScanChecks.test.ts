/**
 * REQ-008 AC-P26-5: every built-in rule has a positive and a negative case;
 * AC-P26-6 (content validation, soft-404), AC-P26-8 (evidence never carries
 * cookie values or config contents). Contract sections 4.1–4.3.
 */
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  checkPageContent,
  detectDirectoryListing,
  detectErrorPage,
} from '../../src/webscan/checks/content';
import { EXPOSURE_PROBES, evaluateProbe, probeBases, validateAppSettings, validateDotEnv } from '../../src/webscan/checks/exposure';
import {
  checkCookies,
  checkCors,
  checkDisclosureHeaders,
  checkSecurityHeaders,
  CORS_PROBE_ORIGIN,
  isSessionCookie,
  parseCsp,
  weakScriptSources,
} from '../../src/webscan/checks/headers';
import {
  certificateFinding,
  checkCertificateExpiry,
  checkHttpRedirect,
  checkLegacyProtocol,
  checkPlainHttp,
  isCertificateError,
} from '../../src/webscan/checks/transport';
import { extractTags } from '../../src/webscan/html';
import type { ProbeResponse } from '../../src/webscan/types';

function resp(url: string, headers: Record<string, string | string[]> = {}, body = '', status = 200): ProbeResponse {
  const lower: ProbeResponse['headers'] = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return { url, status, headers: lower, body: Buffer.from(body), truncated: false, tls: null };
}

const HTML = { 'content-type': 'text/html; charset=utf-8' };
const SECURE_HEADERS = {
  ...HTML,
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
};
const ids = (findings: Array<{ ruleId: string }>) => findings.map((f) => f.ruleId).sort();

describe('security headers (WEB-HDR-001…008)', () => {
  it('negative: a fully hardened https HTML page has no header finding', () => {
    expect(checkSecurityHeaders(resp('https://app.local/', SECURE_HEADERS))).toEqual([]);
  });

  it('positive: a bare https HTML page triggers HSTS, CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy', () => {
    expect(ids(checkSecurityHeaders(resp('https://app.local/', HTML)))).toEqual(
      ['WEB-HDR-001', 'WEB-HDR-003', 'WEB-HDR-005', 'WEB-HDR-006', 'WEB-HDR-007', 'WEB-HDR-008'],
    );
  });

  it('HSTS rules only on https; short max-age -> WEB-HDR-002', () => {
    expect(ids(checkSecurityHeaders(resp('http://app.local/', { ...SECURE_HEADERS, 'strict-transport-security': '' })))).toEqual([]);
    expect(ids(checkSecurityHeaders(resp('https://app.local/', { ...SECURE_HEADERS, 'strict-transport-security': 'max-age=600' })))).toEqual(['WEB-HDR-002']);
    expect(ids(checkSecurityHeaders(resp('https://app.local/', { ...SECURE_HEADERS, 'strict-transport-security': 'includeSubDomains' })))).toEqual(['WEB-HDR-001']);
  });

  it('CSP / clickjacking / Referrer / Permissions rules only for HTML; nosniff always', () => {
    expect(ids(checkSecurityHeaders(resp('https://app.local/api', { 'content-type': 'application/json', 'strict-transport-security': 'max-age=31536000' })))).toEqual(['WEB-HDR-006']);
  });

  it('Report-Only CSP is not enforcement (evidence says so)', () => {
    const f = checkSecurityHeaders(resp('https://app.local/', { ...SECURE_HEADERS, 'content-security-policy': undefined as unknown as string, 'content-security-policy-report-only': "default-src 'self'" }))
      .find((x) => x.ruleId === 'WEB-HDR-003');
    expect(f?.evidence).toMatch(/Report-Only/);
  });

  it('weak CSP (WEB-HDR-004): unsafe-inline without nonce/hash, unsafe-eval, wildcards; nonce makes unsafe-inline acceptable', () => {
    expect(weakScriptSources(parseCsp("script-src 'self' 'unsafe-inline'"))).toEqual(["'unsafe-inline'"]);
    expect(weakScriptSources(parseCsp("script-src 'self' 'unsafe-inline' 'nonce-abc'"))).toEqual([]);
    expect(weakScriptSources(parseCsp("default-src * 'unsafe-eval'"))).toEqual(["'unsafe-eval'", '*']);
    expect(weakScriptSources(parseCsp("default-src 'self'; script-src https: data:"))).toEqual(['https:', 'data:']);
    const weak = checkSecurityHeaders(resp('https://app.local/', { ...SECURE_HEADERS, 'content-security-policy': "script-src 'unsafe-inline'; frame-ancestors 'none'" }));
    expect(ids(weak)).toEqual(['WEB-HDR-004']);
  });

  it('clickjacking: X-Frame-Options DENY/SAMEORIGIN or frame-ancestors suffices; an invalid XFO value does not', () => {
    const noFa = { ...SECURE_HEADERS, 'content-security-policy': "default-src 'self'" };
    expect(ids(checkSecurityHeaders(resp('https://app.local/', { ...noFa, 'x-frame-options': 'DENY' })))).toEqual([]);
    expect(ids(checkSecurityHeaders(resp('https://app.local/', { ...noFa, 'x-frame-options': 'ALLOW-FROM https://x' })))).toEqual(['WEB-HDR-005']);
  });
});

describe('disclosure headers (WEB-INF-001…003)', () => {
  it('positive: versioned Server, X-Powered-By, ASP.NET version headers', () => {
    const f = checkDisclosureHeaders(resp('https://app.local/', { server: 'Microsoft-IIS/10.0', 'x-powered-by': 'ASP.NET', 'x-aspnet-version': '4.0.30319', 'x-aspnetmvc-version': '5.2' }));
    expect(ids(f)).toEqual(['WEB-INF-001', 'WEB-INF-002', 'WEB-INF-003']);
    expect(f.find((x) => x.ruleId === 'WEB-INF-003')?.evidence).toBe('X-AspNet-Version: 4.0.30319; X-AspNetMvc-Version: 5.2');
  });

  it('negative: a Server header without a version, no X-Powered-By', () => {
    expect(checkDisclosureHeaders(resp('https://app.local/', { server: 'nginx' }))).toEqual([]);
  });
});

describe('cookies (WEB-CKE-001…003)', () => {
  it('positive: missing Secure (https), HttpOnly, SameSite; session cookie HttpOnly is medium; the value never appears', () => {
    const f = checkCookies([resp('https://app.local/', { 'set-cookie': ['ASP.NET_SessionId=top-secret-value; path=/', 'theme=dark; Secure; HttpOnly'] })]);
    expect(f.map((x) => `${x.ruleId}:${x.severity}:${x.evidence}`).sort()).toEqual([
      'WEB-CKE-001:medium:Çerez: ASP.NET_SessionId',
      'WEB-CKE-002:medium:Çerez: ASP.NET_SessionId',
      'WEB-CKE-003:low:Çerez: ASP.NET_SessionId',
      'WEB-CKE-003:low:Çerez: theme',
    ]);
    expect(JSON.stringify(f)).not.toContain('top-secret-value');
  });

  it('negative: fully flagged cookie; Secure rule not applied on http; one finding per cookie name across the chain', () => {
    expect(checkCookies([resp('https://app.local/', { 'set-cookie': ['a=1; Secure; HttpOnly; SameSite=Lax'] })])).toEqual([]);
    expect(ids(checkCookies([resp('http://app.local/', { 'set-cookie': ['a=1; HttpOnly; SameSite=Strict'] })]))).toEqual([]);
    const chain = [resp('https://app.local/', { 'set-cookie': ['pref=1; Secure; SameSite=Lax'] }), resp('https://app.local/Login', { 'set-cookie': ['pref=2; Secure; SameSite=Lax'] })];
    expect(ids(checkCookies(chain))).toEqual(['WEB-CKE-002']);
  });

  it('D-239 session cookie names', () => {
    for (const n of ['ASP.NET_SessionId', '.AspNetCore.Cookies', '.ASPXAUTH', 'JSESSIONID', 'PHPSESSID', 'connect.sid', 'auth_token', 'MySession', 'jwt']) {
      expect(isSessionCookie(n), n).toBe(true);
    }
    expect(isSessionCookie('theme')).toBe(false);
  });
});

describe('CORS (WEB-CORS-001/002)', () => {
  const page = 'https://app.local/';
  it('reflected origin with credentials -> high', () => {
    const f = checkCors(resp(page, { 'access-control-allow-origin': CORS_PROBE_ORIGIN, 'access-control-allow-credentials': 'true' }), null);
    expect(f.map((x) => `${x.ruleId}:${x.severity}`)).toEqual(['WEB-CORS-001:high']);
  });
  it('null origin with credentials -> high', () => {
    const f = checkCors(resp(page), resp(page, { 'access-control-allow-origin': 'null', 'access-control-allow-credentials': 'true' }));
    expect(ids(f)).toEqual(['WEB-CORS-001']);
  });
  it('wildcard or reflection without credentials -> low', () => {
    expect(ids(checkCors(resp(page, { 'access-control-allow-origin': '*' }), null))).toEqual(['WEB-CORS-002']);
    expect(ids(checkCors(resp(page, { 'access-control-allow-origin': CORS_PROBE_ORIGIN }), null))).toEqual(['WEB-CORS-002']);
  });
  it('negative: no header or a fixed other origin', () => {
    expect(checkCors(resp(page), resp(page))).toEqual([]);
    expect(checkCors(resp(page, { 'access-control-allow-origin': 'https://trusted.local' }), null)).toEqual([]);
  });
});

describe('transport (WEB-TLS-001…005)', () => {
  it('WEB-TLS-001 only for http pages', () => {
    expect(ids(checkPlainHttp(resp('http://app.local/')))).toEqual(['WEB-TLS-001']);
    expect(checkPlainHttp(resp('https://app.local/'))).toEqual([]);
  });

  it('WEB-TLS-002: 2xx over http, or a redirect to http; https redirect and connection failure are fine', () => {
    expect(ids(checkHttpRedirect(resp('http://app.local/', {}, 'hi', 200)))).toEqual(['WEB-TLS-002']);
    expect(ids(checkHttpRedirect(resp('http://app.local/', { location: 'http://app.local/x' }, '', 302)))).toEqual(['WEB-TLS-002']);
    expect(checkHttpRedirect(resp('http://app.local/', { location: 'https://app.local/' }, '', 301))).toEqual([]);
    expect(checkHttpRedirect(null)).toEqual([]);
  });

  it('WEB-TLS-003 classification and finding', () => {
    expect(isCertificateError('CERT_HAS_EXPIRED')).toBe(true);
    expect(isCertificateError('ERR_TLS_CERT_ALTNAME_INVALID')).toBe(true);
    expect(isCertificateError('ECONNREFUSED')).toBe(false);
    expect(certificateFinding('https://app.local/', 'DEPTH_ZERO_SELF_SIGNED_CERT').evidence).toBe('Hata kodu: DEPTH_ZERO_SELF_SIGNED_CERT');
  });

  it('WEB-TLS-004: expiry within 30 days only', () => {
    const now = Date.parse('2026-10-15T00:00:00Z');
    const soon = { protocol: 'TLSv1.3', validTo: '2026-11-01T00:00:00.000Z', issuer: 'CA' };
    const later = { ...soon, validTo: '2027-01-01T00:00:00.000Z' };
    expect(checkCertificateExpiry('https://app.local/', soon, now)[0]?.evidence).toBe('Bitiş: 2026-11-01 (17 gün)');
    expect(checkCertificateExpiry('https://app.local/', later, now)).toEqual([]);
    expect(checkCertificateExpiry('https://app.local/', null, now)).toEqual([]);
  });

  it('WEB-TLS-005 only when a legacy protocol was accepted', () => {
    expect(ids(checkLegacyProtocol('https://app.local/', 'TLSv1'))).toEqual(['WEB-TLS-005']);
    expect(checkLegacyProtocol('https://app.local/', null)).toEqual([]);
  });
});

describe('page content (WEB-CNT-001…003)', () => {
  const page = 'https://app.local/home';
  it('positive: http script/stylesheet/iframe, cross-origin script without SRI, http form action', () => {
    const html = `<html><head>
      <script src="http://cdn.example/a.js"></script>
      <link rel="stylesheet" href="http://cdn.example/a.css">
      <script src="https://cdn.example/b.js"></script>
      </head><body><iframe src="http://x.example/"></iframe><form action="http://app.local/login"></form></body></html>`;
    const f = checkPageContent(extractTags(html), page);
    expect(ids(f)).toEqual(['WEB-CNT-001', 'WEB-CNT-002', 'WEB-CNT-003']);
    expect(f.find((x) => x.ruleId === 'WEB-CNT-001')?.evidence).toMatch(/^3 adres:/);
  });

  it('negative: same-origin / relative resources, SRI on CDN scripts, https forms, commented-out markup', () => {
    const html = `<script src="/js/app.js"></script><script src="https://cdn.example/b.js" integrity="sha384-x" crossorigin="anonymous"></script>
      <!-- <script src="http://old.example/x.js"></script> --><form action="/login"></form><link rel="icon" href="http://x/f.ico">`;
    expect(checkPageContent(extractTags(html), page)).toEqual([]);
  });

  it('mixed content rules apply to https pages only', () => {
    expect(ids(checkPageContent(extractTags('<script src="http://cdn.example/a.js" integrity="x"></script>'), 'http://app.local/'))).toEqual([]);
  });

  it('<base href> is honoured', () => {
    const f = checkPageContent(extractTags('<base href="http://static.example/"><script src="x.js"></script>'), page);
    expect(ids(f)).toEqual(['WEB-CNT-001', 'WEB-CNT-002']);
  });
});

describe('error pages and directory listings (WEB-INF-004/005, contract 4.2)', () => {
  it.each([
    ["<h1>Server Error in '/' Application.</h1>", 'aspnet-ysod'],
    ['An unhandled exception occurred while processing the request.', 'aspnetcore-developer-page'],
    ['<b>Stack Trace:</b> at System.Web.HttpRuntime', 'stack-trace-dotnet'],
    ['Version Information: Microsoft .NET Framework Version:4.0; ASP.NET Version:4.8', 'aspnet-version-info'],
    ['Traceback (most recent call last):', 'python-traceback'],
    ['<title>Werkzeug Debugger</title>', 'werkzeug-debugger'],
    ['Whoops! There was an error.', 'laravel-whoops'],
    ['java.lang.NullPointerException\n\tat com.acme.Foo.bar(Foo.java:1)', 'java-exception'],
    ["SQLSTATE[42S02]: Base table not found", 'sql-error'],
    ["Unclosed quotation mark after the character string ''.", 'sql-error'],
  ])('%j -> %s', (text, label) => {
    expect(detectErrorPage(text)).toBe(label);
  });

  it('negative: an ordinary 404 page', () => {
    expect(detectErrorPage('<h1>404 - File or directory not found.</h1>')).toBeNull();
  });

  it('directory listings', () => {
    expect(detectDirectoryListing('<title>Index of /uploads</title>')).toBe('dir-apache-nginx');
    expect(detectDirectoryListing('<pre>[To Parent Directory]</pre>')).toBe('dir-iis');
    expect(detectDirectoryListing('<title>Directory listing for /</title>')).toBe('dir-python');
    expect(detectDirectoryListing('<title>Home</title>')).toBeNull();
  });
});

describe('sensitive file probes (WEB-EXP-001…007, AC-P26-6, AC-P26-8)', () => {
  const sha = (s: string) => crypto.createHash('sha256').update(Buffer.from(s)).digest('hex');
  const probe = (path: string) => {
    const p = EXPOSURE_PROBES.find((x) => x.path === path);
    if (!p) throw new Error(path);
    return p;
  };
  const evalBody = (path: string, body: string | Buffer, status = 200, soft: string | null = null) => {
    const r: ProbeResponse = { url: `https://app.local/${path}`, status, headers: {}, body: Buffer.isBuffer(body) ? body : Buffer.from(body), truncated: false, tls: null };
    return evaluateProbe(probe(path), r, crypto.createHash('sha256').update(r.body).digest('hex'), soft);
  };

  it.each([
    ['.git/HEAD', 'ref: refs/heads/main\n', 'WEB-EXP-001'],
    ['.git/HEAD', `${'a'.repeat(40)}\n`, 'WEB-EXP-001'],
    ['.env', 'DB_HOST=db\nDB_PASSWORD=super-secret\n# comment\n', 'WEB-EXP-002'],
    ['appsettings.json', '{"ConnectionStrings":{"Db":"Password=super-secret"}}', 'WEB-EXP-003'],
    ['web.config', '<?xml version="1.0"?><configuration></configuration>', 'WEB-EXP-003'],
    ['elmah.axd', '<title>Error Log for /LM/W3SVC/1</title>', 'WEB-EXP-004'],
    ['trace.axd', '<h1>Application Trace</h1>', 'WEB-EXP-004'],
    ['.svn/entries', '12\n\ndir\n', 'WEB-EXP-005'],
    ['.hg/requires', 'revlogv1\nstore\n', 'WEB-EXP-005'],
    ['server-status', '<h1>Apache Server Status for app</h1>', 'WEB-EXP-006'],
    ['phpinfo.php', '<title>phpinfo()</title> PHP Version 8.1', 'WEB-EXP-006'],
    ['swagger/index.html', '<div id="swagger-ui"></div>', 'WEB-EXP-007'],
    ['swagger/v1/swagger.json', '{"openapi":"3.0.1"}', 'WEB-EXP-007'],
  ])('positive: %s', (path, body, rule) => {
    const f = evalBody(path, body);
    expect(f?.ruleId).toBe(rule);
    expect(JSON.stringify(f)).not.toContain('super-secret');
  });

  it('.DS_Store magic bytes', () => {
    expect(evalBody('.DS_Store', Buffer.concat([Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31]), Buffer.alloc(8)]))?.ruleId).toBe('WEB-EXP-005');
    expect(evalBody('.DS_Store', 'not a ds store')).toBeNull();
  });

  it('negative: non-200, HTML catch-all pages, soft-404 body, JSON without config keys', () => {
    expect(evalBody('.git/HEAD', 'ref: refs/heads/main', 404)).toBeNull();
    expect(evalBody('.env', '<!doctype html><html><body>Home</body></html>')).toBeNull();
    expect(evalBody('.env', 'Hello world\nThis is a page\nA=1')).toBeNull();
    expect(evalBody('appsettings.json', '{"name":"x"}')).toBeNull();
    expect(evalBody('appsettings.json', 'not json')).toBeNull();
    const catchAll = 'ref: refs/heads/main\n';
    expect(evalBody('.git/HEAD', catchAll, 200, sha(catchAll))).toBeNull();
  });

  it('evidence carries key names only (first five)', () => {
    expect(validateDotEnv(Buffer.from('A=1\nB=2\nC=3\nD=4\nE=5\nF=secret-value'))).toBe('6 anahtar; ör. A, B, C, D, E');
    expect(validateAppSettings(Buffer.from('{"Logging":{},"Jwt":{"Key":"k"}}'))).toBe('Üst düzey anahtarlar: Logging, Jwt');
  });

  it('D-220: probe bases (origin root and the target folder)', () => {
    expect(probeBases('https://app.local/')).toEqual(['https://app.local/']);
    expect(probeBases('https://app.local/Portal/Login.aspx?x=1')).toEqual(['https://app.local/', 'https://app.local/Portal/']);
    expect(probeBases('https://app.local/Portal')).toEqual(['https://app.local/', 'https://app.local/Portal/']);
    expect(probeBases('https://app.local:8443/a/b/')).toEqual(['https://app.local:8443/', 'https://app.local:8443/a/b/']);
  });
});
