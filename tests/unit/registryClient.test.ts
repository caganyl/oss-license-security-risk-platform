/**
 * REQ-004 · Registry HTTP client against the loopback fake registry
 * (AC-P14-9…13, AC-P15-2/3/5; ADR-006 Karar 4, 5). No real network: the
 * client accepts only `http://127.0.0.1:<port>` test endpoints and the
 * network guard fails any other connection.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  PRODUCTION_ENDPOINTS,
  RegistryUrlError,
  assertAllowedUrl,
  assertInjectableEndpoint,
  createRegistryClient,
  parseRetryAfter,
  type RegistryClient,
  type RegistryClientOptions,
  type RegistryClock,
} from '../../src/enrichment/registryClient';
import { nodeSupportsProxyEnv, resolveProxy, shouldUseProxy } from '../../src/enrichment/proxy';
import { sha512b64 } from '../helpers/archiveBuilder';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 20_000 });

let reg: FakeRegistry;
let other: FakeRegistry | null = null;
const clients: RegistryClient[] = [];
let sleeps: number[] = [];
const fastClock: RegistryClock = {
  now: () => Date.now(),
  sleep: async (ms) => {
    sleeps.push(ms);
  },
};

beforeEach(async () => {
  reg = await startFakeRegistry();
  sleeps = [];
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  await reg.close();
  if (other) await other.close();
  other = null;
});

function client(opts: Partial<RegistryClientOptions> = {}): RegistryClient {
  const c = createRegistryClient({
    timeoutMs: 2_000,
    concurrency: 4,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin },
    clock: fastClock,
    env: {},
    warn: () => undefined,
    ...opts,
  });
  clients.push(c);
  return c;
}
const signal = () => new AbortController().signal;
const getJson = (c: RegistryClient, path: string) => c.session().getJson(`${reg.origin}${path}`, 'metadata-npm', { signal: signal() });

describe('AC-P14-9: fixed endpoints and URL allowlist', () => {
  it('AC-P14-9: injectable endpoints are only the production origins or loopback http (no path, query, credentials)', () => {
    expect(assertInjectableEndpoint('https://registry.npmjs.org')).toBe('https://registry.npmjs.org');
    expect(assertInjectableEndpoint('http://127.0.0.1:4873/')).toBe('http://127.0.0.1:4873');
    expect(assertInjectableEndpoint('http://[::1]:4873')).toBe('http://[::1]:4873');
    for (const bad of ['http://registry.npmjs.org', 'https://evil.example', 'http://127.0.0.1:1/npm', 'http://127.0.0.1:1/?q=1', 'http://u:p@127.0.0.1:1', 'http://localhost:1', 'not a url']) {
      expect(() => assertInjectableEndpoint(bad), bad).toThrow(RegistryUrlError);
    }
  });

  it('AC-P14-9: request URLs must be https on the exact origin of their purpose; archives under <origin>/', () => {
    const ep = { ...PRODUCTION_ENDPOINTS };
    expect(assertAllowedUrl('https://registry.npmjs.org/left-pad/1.3.0', 'metadata-npm', ep).href).toContain('left-pad');
    expect(assertAllowedUrl('https://files.pythonhosted.org/packages/a.whl', 'archive-pypi', ep).host).toBe('files.pythonhosted.org');
    for (const [url, purpose] of [
      ['http://registry.npmjs.org/x/1.0.0', 'metadata-npm'],
      ['https://registry.npmjs.org.evil.com/x', 'metadata-npm'],
      ['https://user:pw@registry.npmjs.org/x', 'metadata-npm'],
      ['https://registry.npmjs.org:8443/x', 'metadata-npm'],
      ['https://pypi.org/packages/a.whl', 'archive-pypi'],
      ['https://files.pythonhosted.org/x', 'metadata-pypi'],
    ] as const) {
      expect(() => assertAllowedUrl(url, purpose, ep), url).toThrow(RegistryUrlError);
    }
  });

  it('AC-P14-9: a disallowed URL makes no request (URL_NOT_ALLOWED)', async () => {
    const c = client();
    const s = c.session();
    expect(await s.getJson('https://evil.example/x', 'metadata-npm', { signal: signal() })).toEqual({ kind: 'error', code: 'URL_NOT_ALLOWED' });
    expect(await s.getArchive('https://evil.example/x.tgz', 'archive-npm', { signal: signal(), algorithm: 'sha512' })).toEqual({ kind: 'download_failed', code: 'URL_NOT_ALLOWED' });
    expect(reg.total()).toBe(0);
  });

  it('AC-P14-9: fixed headers only (User-Agent, Accept, Accept-Encoding); no cookie/authorization', async () => {
    reg.route('/a/1.0.0', { body: { ok: true } });
    expect((await getJson(client(), '/a/1.0.0')).kind).toBe('ok');
    const h = reg.requests[0].headers;
    expect(h['user-agent']).toMatch(/^oss-risk-platform\/\S+ \(license-enrichment\)$/);
    expect(h.accept).toBe('application/json');
    expect(h['accept-encoding']).toBe('gzip');
    expect(h.authorization).toBeUndefined();
    expect(h.cookie).toBeUndefined();
  });
});

describe('AC-P14-9: redirects are re-checked on every hop', () => {
  it('AC-P14-9: a same-origin metadata redirect is followed', async () => {
    reg.route('/a/1.0.0', { status: 302, headers: { location: '/b/1.0.0' } });
    reg.route('/b/1.0.0', { body: { name: 'b' } });
    expect(await getJson(client(), '/a/1.0.0')).toEqual({ kind: 'ok', json: { name: 'b' } });
  });

  it('AC-P14-9: a cross-host redirect is refused before connecting (other server sees no request)', async () => {
    other = await startFakeRegistry();
    other.route('/x', { body: { stolen: true } });
    reg.route('/a/1.0.0', { status: 301, headers: { location: `${other.origin}/x` } });
    expect(await getJson(client(), '/a/1.0.0')).toEqual({ kind: 'error', code: 'URL_NOT_ALLOWED' });
    expect(other.total()).toBe(0);
  });

  it('AC-P14-9: more than 3 redirects -> REDIRECT_LIMIT; missing Location -> REDIRECT', async () => {
    for (let i = 0; i < 5; i++) reg.route(`/r${i}`, { status: 307, headers: { location: `/r${i + 1}` } });
    expect(await getJson(client(), '/r0')).toEqual({ kind: 'error', code: 'REDIRECT_LIMIT' });
    expect(reg.total()).toBe(4);
    reg.route('/n', { status: 302 });
    expect(await getJson(client(), '/n')).toEqual({ kind: 'error', code: 'REDIRECT' });
  });

  it('AC-P15-2: archive downloads follow no redirect (download_failed REDIRECT)', async () => {
    reg.route('/p/-/p-1.tgz', { status: 302, headers: { location: '/p/-/q.tgz' } });
    reg.route('/p/-/q.tgz', { body: Buffer.from('x') });
    const r = await client().session().getArchive(`${reg.origin}/p/-/p-1.tgz`, 'archive-npm', { signal: signal(), algorithm: 'sha512' });
    expect(r).toEqual({ kind: 'download_failed', code: 'REDIRECT' });
    expect(reg.count('/p/-/q.tgz')).toBe(0);
  });
});

describe('AC-P14-10: status mapping, retries and backoff', () => {
  it('AC-P14-10: 404 and 410 are not_found without retry', async () => {
    reg.route('/gone/1', { status: 410 });
    const c = client();
    expect(await getJson(c, '/missing/1')).toEqual({ kind: 'not_found' });
    expect(await getJson(c, '/gone/1')).toEqual({ kind: 'not_found' });
    expect(reg.total()).toBe(2);
    expect(sleeps).toEqual([]);
  });

  it('AC-P14-10: 5xx retries twice after 1 s and 2 s, then succeeds', async () => {
    reg.route('/a/1', [{ status: 503 }, { status: 500 }, { body: { ok: 1 } }]);
    expect(await getJson(client(), '/a/1')).toEqual({ kind: 'ok', json: { ok: 1 } });
    expect(reg.count('/a/1')).toBe(3);
    expect(sleeps).toEqual([1000, 2000]);
  });

  it('AC-P14-10: three 5xx -> error HTTP_503 (3 attempts total)', async () => {
    reg.route('/a/1', { status: 503 });
    expect(await getJson(client(), '/a/1')).toEqual({ kind: 'error', code: 'HTTP_503' });
    expect(reg.count('/a/1')).toBe(3);
  });

  it('AC-P14-10: 429 Retry-After <= 30 s raises the wait; > 30 s or unparseable gives up after one request', async () => {
    reg.route('/a/1', [{ status: 429, headers: { 'retry-after': '5' } }, { body: { ok: 1 } }]);
    expect((await getJson(client(), '/a/1')).kind).toBe('ok');
    expect(sleeps).toEqual([5000]);
    reg.route('/b/1', { status: 429, headers: { 'retry-after': '60' } });
    expect(await getJson(client(), '/b/1')).toEqual({ kind: 'error', code: 'RETRY_AFTER' });
    expect(reg.count('/b/1')).toBe(1);
    reg.route('/c/1', { status: 503, headers: { 'retry-after': 'soon' } });
    expect(await getJson(client(), '/c/1')).toEqual({ kind: 'error', code: 'RETRY_AFTER' });
  });

  it('AC-P14-10: parseRetryAfter handles delta seconds, HTTP-date and garbage', () => {
    expect(parseRetryAfter('7', 0)).toBe(7000);
    expect(parseRetryAfter(undefined, 0)).toBeNull();
    expect(parseRetryAfter(new Date(10_000).toUTCString(), 0)).toBe(10_000);
    expect(parseRetryAfter('later', 0)).toBeNaN();
  });

  it('AC-P14-10: network errors retry, then unreachable with an err.code (never a message)', async () => {
    reg.route('/a/1', { reset: true });
    const r = await getJson(client(), '/a/1');
    expect(r.kind).toBe('unreachable');
    expect((r as { code: string }).code).toMatch(/^[A-Z0-9_]+$/);
    expect(reg.count('/a/1')).toBe(3);
  });

  it('AC-P14-10: per-attempt timeout -> TIMEOUT (unreachable)', async () => {
    reg.route('/slow/1', { hang: true });
    const r = await getJson(client({ timeoutMs: 150 }), '/slow/1');
    expect(r).toEqual({ kind: 'unreachable', code: 'TIMEOUT' });
  });

  it('AC-P14-11: non-JSON content type, bad JSON and JSON arrays are errors', async () => {
    reg.route('/h/1', { body: '<html>', headers: { 'content-type': 'text/html' } });
    reg.route('/j/1', { body: '{bad', headers: { 'content-type': 'application/json' } });
    reg.route('/k/1', { body: '[1]', headers: { 'content-type': 'application/json' } });
    const c = client();
    expect(await getJson(c, '/h/1')).toEqual({ kind: 'error', code: 'BAD_CONTENT_TYPE' });
    expect(await getJson(c, '/j/1')).toEqual({ kind: 'error', code: 'BAD_JSON' });
    expect(await getJson(c, '/k/1')).toEqual({ kind: 'error', code: 'BAD_JSON' });
  });
});

describe('AC-P14-13 / AC-P15-5: size caps', () => {
  const limits = { metadataMaxBytes: 1024, archiveMaxBytes: 2048 };

  it('AC-P14-13: Content-Length over the cap, chunked over the cap and a gzip bomb are TOO_LARGE', async () => {
    const big = { pad: 'x'.repeat(4096) };
    reg.route('/cl/1', { body: big });
    reg.route('/ch/1', { body: big, chunked: true });
    reg.route('/gz/1', { body: { pad: 'a'.repeat(200_000) }, gzip: true, chunked: true });
    reg.route('/okgz/1', { body: { v: 1 }, gzip: true });
    const c = client({ limits });
    expect(await getJson(c, '/cl/1')).toEqual({ kind: 'error', code: 'TOO_LARGE' });
    expect(await getJson(c, '/ch/1')).toEqual({ kind: 'error', code: 'TOO_LARGE' });
    expect(await getJson(c, '/gz/1')).toEqual({ kind: 'error', code: 'TOO_LARGE' });
    expect(await getJson(c, '/okgz/1')).toEqual({ kind: 'ok', json: { v: 1 } });
  });

  it('AC-P15-5: archive over the cap -> limit_exceeded; Content-Encoding on an archive -> download_failed', async () => {
    reg.route('/p/-/big.tgz', { body: Buffer.alloc(4096, 1), chunked: true });
    reg.route('/p/-/enc.tgz', { body: Buffer.alloc(10, 1), gzip: true });
    const s = client({ limits }).session();
    expect(await s.getArchive(`${reg.origin}/p/-/big.tgz`, 'archive-npm', { signal: signal(), algorithm: 'sha512' })).toEqual({ kind: 'limit_exceeded', code: 'archive_size' });
    expect(await s.getArchive(`${reg.origin}/p/-/enc.tgz`, 'archive-npm', { signal: signal(), algorithm: 'sha512' })).toEqual({ kind: 'download_failed', code: 'BAD_ENCODING' });
  });

  it('AC-P15-2: a downloaded archive carries its streamed digest and size; Accept-Encoding identity', async () => {
    const body = Buffer.from('tarball-bytes');
    reg.route('/p/-/p-1.tgz', { body });
    const r = await client().session().getArchive(`${reg.origin}/p/-/p-1.tgz`, 'archive-npm', { signal: signal(), algorithm: 'sha512' });
    expect(r).toMatchObject({ kind: 'ok', digest: sha512b64(body), size: body.length });
    expect(reg.requests[0].headers['accept-encoding']).toBe('identity');
  });
});

describe('AC-P14-10: circuit breaker, dedupe, concurrency', () => {
  it('AC-P14-10: 5 consecutive failed network attempts close the host for that session only', async () => {
    reg.route('/a/1', { reset: true });
    reg.route('/b/1', { reset: true });
    reg.route('/c/1', { body: { ok: 1 } });
    const c = client();
    const s = c.session();
    const host = new URL(reg.origin).host;
    await s.getJson(`${reg.origin}/a/1`, 'metadata-npm', { signal: signal() });
    expect(s.isHostClosed(host)).toBe(false);
    await s.getJson(`${reg.origin}/b/1`, 'metadata-npm', { signal: signal() });
    expect(s.isHostClosed(host)).toBe(true);
    const before = reg.total();
    expect(await s.getJson(`${reg.origin}/c/1`, 'metadata-npm', { signal: signal() })).toEqual({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
    expect(reg.total()).toBe(before);
    // A new scan session starts closed-counter free.
    expect((await c.session().getJson(`${reg.origin}/c/1`, 'metadata-npm', { signal: signal() })).kind).toBe('ok');
  });

  it('AC-P14-10: any HTTP response resets the failure counter', async () => {
    reg.route('/a/1', [{ reset: true }, { reset: true }, { status: 404 }]);
    reg.route('/b/1', [{ reset: true }, { reset: true }, { status: 404 }]);
    const s = client().session();
    await s.getJson(`${reg.origin}/a/1`, 'metadata-npm', { signal: signal() });
    await s.getJson(`${reg.origin}/b/1`, 'metadata-npm', { signal: signal() });
    expect(s.isHostClosed(new URL(reg.origin).host)).toBe(false);
  });

  it('AC-P14-10: concurrent requests with the same key share one HTTP request (in-flight dedupe)', async () => {
    reg.route('/a/1', { body: { ok: 1 }, delayMs: 150 });
    const c = client();
    const results = await Promise.all([c.session(), c.session(), c.session()].map((s) => s.getJson(`${reg.origin}/a/1`, 'metadata-npm', { signal: signal(), dedupeKey: 'k' })));
    expect(results.every((r) => r.kind === 'ok')).toBe(true);
    expect(reg.count('/a/1')).toBe(1);
  });

  it('AC-P14-10: one waiter aborting does not abort the shared request for the others', async () => {
    reg.route('/a/1', { body: { ok: 1 }, delayMs: 200 });
    const c = client();
    const ac = new AbortController();
    const p1 = c.session().getJson(`${reg.origin}/a/1`, 'metadata-npm', { signal: ac.signal, dedupeKey: 'k' });
    const p2 = c.session().getJson(`${reg.origin}/a/1`, 'metadata-npm', { signal: signal(), dedupeKey: 'k' });
    setTimeout(() => ac.abort(), 30);
    await expect(p1).rejects.toBeDefined();
    expect((await p2).kind).toBe('ok');
    expect(reg.count('/a/1')).toBe(1);
  });

  it('AC-P14-10: REGISTRY_CONCURRENCY bounds simultaneous requests process-wide', async () => {
    for (let i = 0; i < 6; i++) reg.route(`/p${i}/1`, { body: { i }, delayMs: 80 });
    const c = client({ concurrency: 2 });
    await Promise.all(Array.from({ length: 6 }, (_, i) => c.session().getJson(`${reg.origin}/p${i}/1`, 'metadata-npm', { signal: signal() })));
    expect(reg.total()).toBe(6);
    expect(reg.maxActive).toBeLessThanOrEqual(2);
  });
});

describe('AC-P14-12: proxy (D-59)', () => {
  it('AC-P14-12: NO_PROXY forms (host, .domain, *.domain, port, IPv6, *, separators, case)', () => {
    const t = 'https://registry.npmjs.org/x';
    expect(shouldUseProxy(t, '')).toBe(true);
    expect(shouldUseProxy(t, '*')).toBe(false);
    expect(shouldUseProxy(t, 'registry.npmjs.org')).toBe(false);
    expect(shouldUseProxy(t, 'REGISTRY.NPMJS.ORG')).toBe(false);
    expect(shouldUseProxy(t, 'npmjs.org')).toBe(false);
    expect(shouldUseProxy(t, '.npmjs.org')).toBe(false);
    expect(shouldUseProxy(t, '*.npmjs.org')).toBe(false);
    expect(shouldUseProxy(t, 'badnpmjs.org')).toBe(true);
    expect(shouldUseProxy(t, 'js.org')).toBe(true);
    expect(shouldUseProxy(t, 'npmjs.org:443')).toBe(false);
    expect(shouldUseProxy(t, 'npmjs.org:8443')).toBe(true);
    expect(shouldUseProxy(t, ' foo.com ,\tnpmjs.org ')).toBe(false);
    expect(shouldUseProxy(t, 'foo.com bar.com')).toBe(true);
    expect(shouldUseProxy('https://[::1]:8443/x', '[::1]:8443')).toBe(false);
    expect(shouldUseProxy('https://[::1]:8443/x', '[::1]:9999')).toBe(true);
    expect(shouldUseProxy('https://[::1]/x', '::1')).toBe(false);
    expect(shouldUseProxy('https://10.0.0.5/x', '10.0.0.0/8')).toBe(true); // CIDR not supported
    expect(shouldUseProxy('https://10.0.0.5/x', '10.0.0.5')).toBe(false);
  });

  it('AC-P14-12: only HTTPS_PROXY/https_proxy and NO_PROXY/no_proxy are read; invalid value -> invalid mode', () => {
    expect(resolveProxy({ HTTP_PROXY: 'http://p:1', ALL_PROXY: 'http://p:1' })).toEqual({ mode: 'direct' });
    expect(resolveProxy({ HTTPS_PROXY: 'http://p:1', NO_PROXY: 'a' })).toEqual({ mode: 'proxy', proxyUrl: 'http://p:1', noProxy: 'a' });
    expect(resolveProxy({ https_proxy: 'http://lower:1', HTTPS_PROXY: 'http://upper:1' })).toMatchObject({ proxyUrl: 'http://lower:1' });
    expect(resolveProxy({ HTTPS_PROXY: 'socks5://p:1' })).toEqual({ mode: 'invalid', setting: 'HTTPS_PROXY' });
    expect(resolveProxy({ HTTPS_PROXY: 'garbage' })).toEqual({ mode: 'invalid', setting: 'HTTPS_PROXY' });
    expect(nodeSupportsProxyEnv('v22.21.0')).toBe(true);
    expect(nodeSupportsProxyEnv('22.20.9')).toBe(false);
    expect(nodeSupportsProxyEnv('24.4.0')).toBe(false);
    expect(nodeSupportsProxyEnv('24.5.0')).toBe(true);
    expect(nodeSupportsProxyEnv('26.0.0')).toBe(true);
  });

  it('AC-P14-12: invalid proxy or proxy on an old Node opens no connection; the proxy value (credentials) is never logged', async () => {
    for (const opts of [
      { env: { HTTPS_PROXY: 'ftp://secretuser:secretpw@proxy.local' } },
      { env: { HTTPS_PROXY: 'http://secretuser:secretpw@proxy.local:8080' }, nodeVersion: '22.20.0' },
    ]) {
      const warnings: string[] = [];
      const c = createRegistryClient({ timeoutMs: 1000, concurrency: 1, clock: fastClock, warn: (m) => warnings.push(m), ...opts });
      clients.push(c);
      const r = await c.session().getJson('https://registry.npmjs.org/left-pad/1.3.0', 'metadata-npm', { signal: signal() });
      expect(r).toEqual({ kind: 'unreachable', code: 'PROXY_UNAVAILABLE' });
      expect(warnings.length).toBe(1);
      expect(warnings.join('\n')).not.toMatch(/secretuser|secretpw|proxy\.local/);
    }
  });
});
