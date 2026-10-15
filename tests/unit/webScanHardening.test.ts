/**
 * REQ-008 security review fixes: H-1 (linear HTML/error scanning on hostile
 * bodies), M-2 (ZAP scope regex), M-4 (ZAP lock wait honours the job signal),
 * L-5 (main page redirects: same origin or http<->https on default ports),
 * L-6 (DNS answers pointing at loopback / link-local / unspecified refused
 * unless that IP is allowlisted).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseAllowedHosts } from '../../src/webscan/allowlist';
import { detectErrorPage } from '../../src/webscan/checks/content';
import { extractTags, stripComments } from '../../src/webscan/html';
import { guardedLookup, isFollowableRedirect, isRestrictedAddress } from '../../src/webscan/probeClient';
import { createZapConnector, scopeRegex } from '../../src/webscan/zap';

const MiB = 1024 * 1024;

describe('H-1: hostile 2 MiB bodies are scanned in linear time', () => {
  it.each([
    ['newline flood after a Java exception name', 'java.lang.FooException' + '\n'.repeat(2 * MiB)],
    ['<script flood without >', '<script'.repeat((2 * MiB) / 7)],
    ['<!-- flood', '<!--'.repeat((2 * MiB) / 4)],
    ['< flood', '<'.repeat(2 * MiB)],
  ])('%s', (_label, body) => {
    const start = performance.now();
    extractTags(body);
    detectErrorPage(body);
    expect(performance.now() - start).toBeLessThan(2000);
  });

  it('tag scanner semantics: names, unterminated tags, comments, attribute cap', () => {
    expect(extractTags('<SCRIPT src="a.js"></SCRIPT><scripts src="b.js"><scriptx src="c"><script/>').map((t) => [t.name, t.attrs.src])).toEqual([
      ['script', 'a.js'],
      ['script', undefined],
    ]);
    expect(extractTags('<script src="a.js"><script src="never-closed.js"')).toHaveLength(1);
    expect(stripComments('a<!-- x -->b<!-- open')).toBe('a b ');
    expect(extractTags(`<script ${'x'.repeat(10_000)} src="late.js">`)[0].attrs.src).toBeUndefined();
  });

  it('java stack trace with indentation still matches', () => {
    expect(detectErrorPage('java.lang.IllegalStateException: x\n    at com.acme.Svc.run(Svc.java:10)')).toBe('java-exception');
  });
});

describe('L-5: main page redirect rule', () => {
  const u = (s: string) => new URL(s);
  it.each([
    ['http://app.local/', 'https://app.local/login', true],
    ['https://app.local/', 'http://app.local/', true],
    ['https://app.local:8443/', 'https://app.local:8443/x', true],
    ['https://app.local/', 'https://app.local:8443/', false],
    ['http://app.local:8080/', 'https://app.local/', false],
    ['https://app.local/', 'https://other.local/', false],
    ['https://app.local/', 'ftp://app.local/', false],
  ])('%s -> %s : %s', (from, to, ok) => {
    expect(isFollowableRedirect(u(from), u(to))).toBe(ok);
  });
});

describe('L-6: restricted resolved addresses', () => {
  it.each([
    ['127.0.0.1', true], ['127.9.9.9', true], ['0.0.0.0', true], ['169.254.169.254', true], ['::1', true], ['::', true],
    ['fe80::1', true], ['::ffff:127.0.0.1', true], ['10.1.2.3', false], ['192.168.1.5', false], ['172.16.0.1', false], ['8.8.8.8', false], ['fd00::1', false],
  ])('%s -> %s', (addr, restricted) => {
    expect(isRestrictedAddress(addr)).toBe(restricted);
  });

  const resolve = (allow: string, host: string) =>
    new Promise<{ code?: string; address?: unknown }>((done) => {
      guardedLookup(parseAllowedHosts(allow))(host, {}, (err, address) => done(err ? { code: err.code } : { address }));
    });

  it('a name resolving to loopback is refused unless the IP (or localhost itself) is allowlisted', async () => {
    expect((await resolve('*.example.test,app.local', 'localhost')).code).toBe('ADDRESS_NOT_ALLOWED');
    expect((await resolve('127.0.0.1', 'localhost')).address).toMatch(/^(127\.0\.0\.1|::1)$/);
    expect((await resolve('localhost', 'localhost')).address).toMatch(/^(127\.0\.0\.1|::1)$/);
  });
});

describe('M-2: ZAP scope regex', () => {
  it('matches the target host on any port and scheme only', () => {
    const re = new RegExp(scopeRegex('https://portal.sirket.local/app/'));
    expect(re.test('https://portal.sirket.local/x')).toBe(true);
    expect(re.test('http://portal.sirket.local:8080/')).toBe(true);
    expect(re.test('https://portal.sirket.local.evil.example/')).toBe(false);
    expect(re.test('https://portalXsirket.local/')).toBe(false);
    expect(re.test('http://169.254.169.254/latest/meta-data')).toBe(false);
  });
});

describe('M-4: a queued ZAP run stops at its job signal', () => {
  let server: http.Server;
  let origin = '';
  beforeAll(async () => {
    // Every call hangs for 3 s: the first run holds the lock.
    server = http.createServer((_rq, rs) => setTimeout(() => {
      rs.setHeader('Content-Type', 'application/json');
      rs.end('{"version":"x"}');
    }, 3000));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  });

  it('the second run rejects with its own abort reason without waiting for the first', async () => {
    const zap = createZapConnector({ config: { origin, apiKey: null }, env: {} });
    const first = new AbortController();
    const second = new AbortController();
    const base = { targetUrl: 'http://127.0.0.1/', mode: 'passive' as const, scanId: 's', deadlineMs: performance.now() + 600_000, allowlist: parseAllowedHosts('127.0.0.1') };
    const running = zap.run({ ...base, signal: first.signal });
    const queued = zap.run({ ...base, signal: second.signal });
    const start = performance.now();
    setTimeout(() => second.abort(new Error('job limit')), 50);
    await expect(queued).rejects.toThrow('job limit');
    expect(performance.now() - start).toBeLessThan(1000);
    first.abort(new Error('done'));
    await expect(running).rejects.toThrow('done');
    zap.close();
  });
});
