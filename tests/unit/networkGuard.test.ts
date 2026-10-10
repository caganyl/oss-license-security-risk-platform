/**
 * REQ-004 AC-G-2 / D-75 (ADR-006 test strategy): self-test of the Vitest
 * network guard (tests/setup/networkGuard.ts, registered as `setupFiles`).
 *
 * Non-loopback targets use TEST-NET-3 (203.0.113.0/24, RFC 5737, never
 * routed) or names that are blocked before any lookup, so even a broken
 * guard would not reach a real host from here.
 */
import dns from 'node:dns';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { afterEach, describe, expect, it } from 'vitest';
import { NETWORK_BLOCKED_CODE, isLoopbackHost, takeNetworkViolations } from '../setup/networkGuard';

const UNROUTED = '203.0.113.7';

/** Resolves with the socket's first error (or 'connected'). */
function outcome(socket: net.Socket, connectEvent = 'connect'): Promise<NodeJS.ErrnoException | 'connected'> {
  return new Promise((resolve) => {
    socket.once('error', (e: NodeJS.ErrnoException) => resolve(e));
    socket.once(connectEvent, () => {
      socket.destroy();
      resolve('connected');
    });
  });
}

function listen(server: net.Server, host?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    const done = () => {
      const addr = server.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    };
    if (host === undefined) server.listen(0, done);
    else server.listen(0, host, done);
  });
}

const closeServer = (server: net.Server) => new Promise<void>((resolve) => server.close(() => resolve()));

describe('network guard: defaults', () => {
  it('REGISTRY_ENRICHMENT is off unless a test sets it', () => {
    expect(process.env.REGISTRY_ENRICHMENT).toBe('off');
  });

  it('isLoopbackHost: loopback / local-only hosts allowed, everything else not', () => {
    for (const h of [undefined, '', 'localhost', 'LOCALHOST', '127.0.0.1', '127.1.2.3', '::1', '[::1]', '::ffff:127.0.0.1', '0.0.0.0', '::']) {
      expect(isLoopbackHost(h), String(h)).toBe(true);
    }
    for (const h of ['registry.npmjs.org', 'pypi.org', UNROUTED, '10.0.0.1', '192.168.1.1', '::ffff:10.0.0.1', '2001:db8::1', 'localhost.evil.example', '128.0.0.1']) {
      expect(isLoopbackHost(h), h).toBe(false);
    }
  });
});

describe('network guard: non-loopback attempts are rejected and recorded', () => {
  afterEach(() => {
    // Every case below leaves exactly its own record; nothing else may leak.
    expect(takeNetworkViolations()).toEqual([]);
  });

  it('net.connect (port, host) and net.createConnection ({ host, port })', async () => {
    const a = await outcome(net.connect(443, UNROUTED));
    expect(a).not.toBe('connected');
    expect((a as NodeJS.ErrnoException).code).toBe(NETWORK_BLOCKED_CODE);
    const b = await outcome(net.createConnection({ host: 'registry.npmjs.org', port: 443 }));
    expect((b as NodeJS.ErrnoException).code).toBe(NETWORK_BLOCKED_CODE);
    expect(takeNetworkViolations()).toEqual([`connect to ${UNROUTED}:443`, 'connect to registry.npmjs.org:443']);
  });

  it('new net.Socket().connect and tls.connect', async () => {
    const a = await outcome(new net.Socket().connect({ host: UNROUTED, port: 80 }));
    expect((a as NodeJS.ErrnoException).code).toBe(NETWORK_BLOCKED_CODE);
    const b = await outcome(tls.connect({ host: UNROUTED, port: 443, servername: 'example.invalid' }), 'secureConnect');
    expect((b as NodeJS.ErrnoException).code).toBe(NETWORK_BLOCKED_CODE);
    expect(takeNetworkViolations()).toHaveLength(2);
  });

  it('https GET https://registry.npmjs.org/ fails with the guard error', async () => {
    const err = await new Promise<NodeJS.ErrnoException | 'response'>((resolve) => {
      const req = https.get('https://registry.npmjs.org/', { agent: false }, (res) => {
        res.resume();
        resolve('response');
      });
      req.once('error', (e: NodeJS.ErrnoException) => resolve(e));
    });
    expect(err).not.toBe('response');
    expect((err as NodeJS.ErrnoException).code).toBe(NETWORK_BLOCKED_CODE);
    expect(takeNetworkViolations()).toEqual(['connect to registry.npmjs.org:443']);
  });

  it('fetch (undici) to a non-loopback URL rejects', async () => {
    await expect(fetch('https://pypi.org/pypi/requests/json')).rejects.toThrow();
    const seen = takeNetworkViolations();
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((v) => v.includes('pypi.org'))).toBe(true);
  });

  it('dns.lookup and dns.promises.lookup refuse non-loopback names', async () => {
    const err = await new Promise<NodeJS.ErrnoException | null>((resolve) => dns.lookup('registry.npmjs.org', (e) => resolve(e)));
    expect(err?.code).toBe(NETWORK_BLOCKED_CODE);
    await expect(dns.promises.lookup('pypi.org')).rejects.toMatchObject({ code: NETWORK_BLOCKED_CODE });
    expect(takeNetworkViolations()).toEqual(['dns.lookup registry.npmjs.org', 'dns.promises.lookup pypi.org']);
  });
});

describe('network guard: loopback and local IPC keep working', () => {
  afterEach(() => {
    expect(takeNetworkViolations()).toEqual([]);
  });

  it('127.0.0.1, localhost and a plain port reach a local TCP server', async () => {
    const server = net.createServer((s) => s.on('error', () => undefined).end()) /* client destroys at once: Windows RST -> ECONNRESET on the server side */;
    const port = await listen(server, '127.0.0.1');
    try {
      expect(await outcome(net.connect(port, '127.0.0.1'))).toBe('connected');
      expect(await outcome(net.connect({ host: '127.0.0.1', port }))).toBe('connected');
    } finally {
      await closeServer(server);
    }
    const any = net.createServer((s) => s.on('error', () => undefined).end()) /* client destroys at once: Windows RST -> ECONNRESET on the server side */;
    const anyPort = await listen(any);
    try {
      expect(await outcome(net.connect({ host: 'localhost', port: anyPort }))).toBe('connected');
      expect(await outcome(net.connect(anyPort))).toBe('connected');
    } finally {
      await closeServer(any);
    }
  });

  it('::1 works when the host has IPv6 loopback', async () => {
    const server = net.createServer((s) => s.on('error', () => undefined).end()) /* client destroys at once: Windows RST -> ECONNRESET on the server side */;
    let port: number;
    try {
      port = await listen(server, '::1');
    } catch {
      return; // no IPv6 loopback on this machine; nothing to prove
    }
    try {
      expect(await outcome(net.connect({ host: '::1', port }))).toBe('connected');
    } finally {
      await closeServer(server);
    }
  });

  it('http GET to a loopback server and dns.lookup(localhost) succeed', async () => {
    const server = http.createServer((_req, res) => res.end('ok'));
    const port = await listen(server, '127.0.0.1');
    try {
      const body = await new Promise<string>((resolve, reject) => {
        http
          .get({ host: '127.0.0.1', port, path: '/', agent: false }, (res) => {
            let text = '';
            res.setEncoding('utf8');
            res.on('data', (c: string) => (text += c));
            res.on('end', () => resolve(text));
          })
          .on('error', reject);
      });
      expect(body).toBe('ok');
      const res = await fetch(`http://127.0.0.1:${port}/`);
      expect(await res.text()).toBe('ok');
    } finally {
      await closeServer(server);
    }
    await expect(dns.promises.lookup('localhost')).resolves.toMatchObject({ address: expect.any(String) });
  });

  it('Unix socket / Windows named pipe paths are not blocked', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-netguard-'));
    const pipe =
      process.platform === 'win32' ? `\\\\.\\pipe\\ossr-netguard-${process.pid}-${Date.now()}` : path.join(tmp, 's.sock');
    const server = net.createServer((s) => s.on('error', () => undefined).end()) /* client destroys at once: Windows RST -> ECONNRESET on the server side */;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(pipe, () => resolve());
    });
    try {
      expect(await outcome(net.connect(pipe))).toBe('connected');
      expect(await outcome(net.connect({ path: pipe }))).toBe('connected');
    } finally {
      await closeServer(server);
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
