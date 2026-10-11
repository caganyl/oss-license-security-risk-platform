/**
 * REQ-006 · AC-P21-3 (D-138): the NuGet purposes (`metadata-nuget`,
 * `archive-nuget`) follow the shared F3 registry client rules — the proxy
 * decision (closed-fail on an invalid `HTTPS_PROXY`, no connection) and the
 * per-scan, per-host circuit breaker, where the NuGet origin is its own host.
 *
 * Same patterns as unit/registryClient.test.ts (AC-P14-10, AC-P14-12). Two
 * loopback fake registries on different ports stand in for the NuGet origin
 * and the npm/PyPI origins, so "another host" is real (`127.0.0.1:<port>`
 * differs). No request leaves 127.0.0.1; the proxy cases use the production
 * `https://api.nuget.org` URL and the network guard proves no connection.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PRODUCTION_ENDPOINTS, createRegistryClient, type RegistryClient, type RegistryClientOptions, type RegistryClock } from '../../src/enrichment/registryClient';
import { resolveProxy, shouldUseProxy } from '../../src/enrichment/proxy';
import { takeNetworkViolations } from '../setup/networkGuard';
import { nugetPaths, nuspecXml } from '../helpers/fakeNuget';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 20_000 });

let reg: FakeRegistry; // npm / PyPI / files origin
let nug: FakeRegistry; // NuGet flat-container origin
const clients: RegistryClient[] = [];
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };
const signal = () => new AbortController().signal;

beforeEach(async () => {
  reg = await startFakeRegistry();
  nug = await startFakeRegistry();
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  await reg.close();
  await nug.close();
  // No case below may open a non-loopback connection.
  expect(takeNetworkViolations()).toEqual([]);
});

function client(opts: Partial<RegistryClientOptions> = {}): RegistryClient {
  const c = createRegistryClient({
    timeoutMs: 2_000,
    concurrency: 4,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin, nuget: nug.origin },
    clock: fastClock,
    env: {},
    warn: () => undefined,
    ...opts,
  });
  clients.push(c);
  return c;
}

const nuspecUrl = (origin: string, id: string, version: string) => `${origin}${nugetPaths(id, version).nuspecPath}`;

describe('AC-P21-3: proxy decision for api.nuget.org (F3 rule, closed-fail)', () => {
  it('AC-P21-3: shouldUseProxy / resolveProxy treat api.nuget.org like the other registry hosts', () => {
    const nuspec = `${PRODUCTION_ENDPOINTS.nuget}/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`;
    const nupkg = `${PRODUCTION_ENDPOINTS.nuget}/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg`;
    expect(PRODUCTION_ENDPOINTS.nuget).toBe('https://api.nuget.org');
    for (const url of [nuspec, nupkg]) {
      expect(shouldUseProxy(url, ''), url).toBe(true);
      expect(shouldUseProxy(url, 'api.nuget.org')).toBe(false);
      expect(shouldUseProxy(url, 'API.NUGET.ORG')).toBe(false);
      expect(shouldUseProxy(url, 'nuget.org')).toBe(false);
      expect(shouldUseProxy(url, '.nuget.org')).toBe(false);
      expect(shouldUseProxy(url, '*.nuget.org')).toBe(false);
      expect(shouldUseProxy(url, 'nuget.org:443')).toBe(false);
      expect(shouldUseProxy(url, 'nuget.org:8443')).toBe(true);
      expect(shouldUseProxy(url, 'registry.npmjs.org,pypi.org')).toBe(true);
      expect(shouldUseProxy(url, 'evilnuget.org')).toBe(true);
    }
    expect(resolveProxy({ HTTPS_PROXY: 'http://proxy.corp:3128', NO_PROXY: 'api.nuget.org' })).toEqual({ mode: 'proxy', proxyUrl: 'http://proxy.corp:3128', noProxy: 'api.nuget.org' });
  });

  it('AC-P21-3: invalid HTTPS_PROXY (or a proxy on an old Node) -> metadata-nuget and archive-nuget return PROXY_UNAVAILABLE, open no connection, never log the value', async () => {
    for (const opts of [
      { env: { HTTPS_PROXY: 'garbage-secretuser:secretpw' } },
      { env: { HTTPS_PROXY: 'socks5://secretuser:secretpw@proxy.local:1080' } },
      { env: { HTTPS_PROXY: 'http://secretuser:secretpw@proxy.local:8080' }, nodeVersion: '22.20.0' },
    ]) {
      const warnings: string[] = [];
      // Production endpoints (no injection): the target really is api.nuget.org.
      const c = createRegistryClient({ timeoutMs: 1_000, concurrency: 1, clock: fastClock, warn: (m) => warnings.push(m), ...opts });
      clients.push(c);
      const s = c.session();
      const meta = await s.getText(`${PRODUCTION_ENDPOINTS.nuget}/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`, 'metadata-nuget', { signal: signal() });
      expect(meta, JSON.stringify(opts)).toEqual({ kind: 'unreachable', code: 'PROXY_UNAVAILABLE' });
      const archive = await s.getArchive(`${PRODUCTION_ENDPOINTS.nuget}/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg`, 'archive-nuget', { signal: signal(), algorithm: 'sha512' });
      expect(archive).toEqual({ kind: 'download_failed', code: 'PROXY_UNAVAILABLE' });
      expect(warnings.length).toBeGreaterThanOrEqual(1);
      expect(warnings.join('\n')).not.toMatch(/secretuser|secretpw|proxy\.local|garbage/);
      // The guard saw no connection attempt to api.nuget.org (or the proxy host).
      expect(takeNetworkViolations()).toEqual([]);
    }
  });

  it('AC-P21-3: loopback (test) NuGet origins never use the proxy, even with HTTPS_PROXY set', async () => {
    nug.route(nugetPaths('Acme.Proxy', '1.0.0').nuspecPath, { body: nuspecXml({ id: 'Acme.Proxy', version: '1.0.0', expression: 'MIT' }) });
    const c = client({ env: { HTTPS_PROXY: 'http://proxy.invalid:3128' } });
    const r = await c.session().getText(nuspecUrl(nug.origin, 'Acme.Proxy', '1.0.0'), 'metadata-nuget', { signal: signal() });
    expect(r.kind).toBe('ok');
    expect(nug.total()).toBe(1);
  });
});

describe('AC-P21-3: circuit breaker — the NuGet origin is its own host', () => {
  it('AC-P21-3: 5 consecutive failed attempts (no retries) close the NuGet host for the session; npm and PyPI stay open; a new session starts closed-free', async () => {
    for (let i = 0; i < 6; i++) nug.route(nugetPaths(`Acme.Fail${i}`, '1.0.0').nuspecPath, { status: 503 });
    reg.addNpmPackage('left-pad', '1.3.0', { license: 'MIT', tarball: null });
    reg.addPypiPackage('requests', '2.31.0', { info: { name: 'requests', version: '2.31.0', license: 'Apache-2.0' } });
    const c = client({ limits: { maxRetries: 0 } as RegistryClientOptions['limits'] });
    const s = c.session();
    const nugetHost = new URL(nug.origin).host;
    const otherHost = new URL(reg.origin).host;
    expect(nugetHost).not.toBe(otherHost);

    for (let i = 0; i < 4; i++) {
      const r = await s.getText(nuspecUrl(nug.origin, `Acme.Fail${i}`, '1.0.0'), 'metadata-nuget', { signal: signal() });
      expect(r.kind, `attempt ${i + 1}`).not.toBe('ok');
      expect(s.isHostClosed(nugetHost), `after ${i + 1} failures`).toBe(false);
    }
    await s.getText(nuspecUrl(nug.origin, 'Acme.Fail4', '1.0.0'), 'metadata-nuget', { signal: signal() });
    expect(s.isHostClosed(nugetHost)).toBe(true);
    expect(nug.total()).toBe(5);

    // Closed: no further request to the NuGet origin, metadata or archive.
    expect(await s.getText(nuspecUrl(nug.origin, 'Acme.Fail5', '1.0.0'), 'metadata-nuget', { signal: signal() })).toEqual({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
    expect(await s.getArchive(`${nug.origin}${nugetPaths('Acme.Fail5', '1.0.0').nupkgPath}`, 'archive-nuget', { signal: signal(), algorithm: 'sha512' })).toEqual({ kind: 'download_failed', code: 'CIRCUIT_OPEN' });
    expect(nug.total()).toBe(5);

    // npm / PyPI (another host) are unaffected in the same session.
    expect(s.isHostClosed(otherHost)).toBe(false);
    expect((await s.getJson(`${reg.origin}/left-pad/1.3.0`, 'metadata-npm', { signal: signal() })).kind).toBe('ok');
    expect((await s.getJson(`${reg.origin}/pypi/requests/2.31.0/json`, 'metadata-pypi', { signal: signal() })).kind).toBe('ok');
    expect(reg.total()).toBe(2);

    // Per scan: a new session reaches the NuGet origin again.
    nug.route(nugetPaths('Acme.Fail5', '1.0.0').nuspecPath, { body: nuspecXml({ id: 'Acme.Fail5', version: '1.0.0', expression: 'MIT' }) });
    expect((await c.session().getText(nuspecUrl(nug.origin, 'Acme.Fail5', '1.0.0'), 'metadata-nuget', { signal: signal() })).kind).toBe('ok');
  });

  it('AC-P21-3: with the default 2 retries every attempt counts — the 5th failed attempt closes the host and stops the pending retry', async () => {
    nug.route(nugetPaths('Acme.A', '1.0.0').nuspecPath, { status: 503 });
    nug.route(nugetPaths('Acme.B', '1.0.0').nuspecPath, { reset: true });
    nug.route(nugetPaths('Acme.C', '1.0.0').nuspecPath, { status: 503 });
    const s = client().session();
    await s.getText(nuspecUrl(nug.origin, 'Acme.A', '1.0.0'), 'metadata-nuget', { signal: signal() }); // 3 attempts (1 + 2 retries)
    expect(nug.count(nugetPaths('Acme.A', '1.0.0').nuspecPath)).toBe(3);
    expect(s.isHostClosed(new URL(nug.origin).host)).toBe(false);
    await s.getText(nuspecUrl(nug.origin, 'Acme.B', '1.0.0'), 'metadata-nuget', { signal: signal() }); // attempts 4, 5 -> closed
    expect(nug.count(nugetPaths('Acme.B', '1.0.0').nuspecPath)).toBe(2);
    expect(s.isHostClosed(new URL(nug.origin).host)).toBe(true);
    expect(await s.getText(nuspecUrl(nug.origin, 'Acme.C', '1.0.0'), 'metadata-nuget', { signal: signal() })).toEqual({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
    expect(nug.total()).toBe(5);
  });

  it('AC-P21-3: an npm host failing 5 times does not close the NuGet host', async () => {
    reg.route('/a/1', { reset: true });
    reg.route('/b/1', { reset: true });
    nug.route(nugetPaths('Acme.Ok', '1.0.0').nuspecPath, { body: nuspecXml({ id: 'Acme.Ok', version: '1.0.0', expression: 'MIT' }) });
    const s = client().session();
    await s.getJson(`${reg.origin}/a/1`, 'metadata-npm', { signal: signal() });
    await s.getJson(`${reg.origin}/b/1`, 'metadata-npm', { signal: signal() });
    expect(s.isHostClosed(new URL(reg.origin).host)).toBe(true);
    expect(s.isHostClosed(new URL(nug.origin).host)).toBe(false);
    expect((await s.getText(nuspecUrl(nug.origin, 'Acme.Ok', '1.0.0'), 'metadata-nuget', { signal: signal() })).kind).toBe('ok');
  });
});
