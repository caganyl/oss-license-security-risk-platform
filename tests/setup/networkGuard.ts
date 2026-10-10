/**
 * REQ-004 · Vitest `setupFiles` entry: network guard and safe defaults
 * (AC-G-2, D-75; ADR-006 "Test stratejisi").
 *
 * 1. `REGISTRY_ENRICHMENT` is forced to `off` for every test file. The value
 *    is set unconditionally (not `??=`): a developer shell with
 *    `REGISTRY_ENRICHMENT=on` must not turn the suite into a networked run.
 *    A test that needs enrichment sets the variable itself (e.g.
 *    `vi.stubEnv('REGISTRY_ENRICHMENT', 'on')`) and points the enricher at
 *    the loopback fake registry.
 * 2. Every outbound TCP/TLS connection attempt to a non-loopback host is
 *    blocked: `net.Socket.prototype.connect` is wrapped (this covers
 *    `net.connect`/`net.createConnection`, `tls.connect`, `http(s).request`,
 *    `fetch`/undici and `pg`, which all end up there), and `dns.lookup` /
 *    `dns.promises.lookup` refuse non-loopback names. A blocked attempt
 *    destroys the socket with `ERR_TEST_NETWORK_BLOCKED` (the code under test
 *    sees an ordinary connection error) and is recorded; the `afterEach` /
 *    `afterAll` hooks below then fail the test loudly, so a swallowed error
 *    cannot hide a real network call.
 *
 * Allowed: 127.0.0.0/8, ::1 (also IPv4-mapped 127.x), `localhost`, the
 * unspecified addresses (`0.0.0.0`, `::`; they never leave the host) and
 * Unix socket / Windows named pipe paths. embedded-postgres (127.0.0.1),
 * supertest (127.0.0.1) and local HTTP servers are unaffected.
 *
 * Not covered by design: worker threads and child processes do not load
 * setup files. The parser and archive threads import no network module
 * (static import guards in tests/security/staticCode.test.ts); git tests use
 * local `file://` repositories.
 *
 * Tests that intentionally trigger a blocked attempt (the guard self-test)
 * call `takeNetworkViolations()` to consume the record before `afterEach`.
 */
import dns from 'node:dns';
import net from 'node:net';
import { afterAll, afterEach } from 'vitest';

/** Error code of a blocked connection / lookup. */
export const NETWORK_BLOCKED_CODE = 'ERR_TEST_NETWORK_BLOCKED';

interface GuardState {
  installed: boolean;
  violations: string[];
}

// Builtins are shared by every test file of a Vitest worker while this setup
// module may be evaluated once per file: patch once, keep state on globalThis.
const STATE_KEY = Symbol.for('ossr.tests.networkGuard');
const globalRef = globalThis as unknown as Record<symbol, GuardState | undefined>;
const state: GuardState = (globalRef[STATE_KEY] ??= { installed: false, violations: [] });

/** True for loopback / local-only hosts (no brackets, case-insensitive). */
export function isLoopbackHost(host: string | undefined | null): boolean {
  if (host === undefined || host === null || host === '') return true; // Node default: localhost
  const h = host.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  if (h === 'localhost' || h === 'localhost.') return true;
  if (net.isIPv4(h)) return h.startsWith('127.') || h === '0.0.0.0';
  if (net.isIPv6(h)) {
    if (h === '::1' || h === '0:0:0:0:0:0:0:1' || h === '::') return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
    return mapped !== null && mapped[1].startsWith('127.');
  }
  return false;
}

/** Returns and clears the blocked attempts recorded so far. */
export function takeNetworkViolations(): string[] {
  return state.violations.splice(0, state.violations.length);
}

function blockedError(what: string): NodeJS.ErrnoException {
  const err: NodeJS.ErrnoException = new Error(`network guard: ${what} blocked (tests must not reach non-loopback hosts)`);
  err.code = NETWORK_BLOCKED_CODE;
  return err;
}

function record(what: string): NodeJS.ErrnoException {
  state.violations.push(what);
  // Loud even if the caller swallows the error.
  process.stderr.write(`[networkGuard] BLOCKED ${what}\n`);
  return blockedError(what);
}

interface ConnectTarget {
  host?: string;
  port?: unknown;
  path?: string;
}

/** Target of a `Socket#connect` call in any of its forms (incl. net's internal normalized array). */
function targetOf(args: unknown[]): ConnectTarget {
  let first = args[0];
  if (Array.isArray(first)) first = first[0]; // net.connect -> socket.connect(normalizedArgs)
  if (first !== null && typeof first === 'object') {
    const o = first as { host?: unknown; hostname?: unknown; port?: unknown; path?: unknown };
    const host = typeof o.host === 'string' ? o.host : typeof o.hostname === 'string' ? o.hostname : undefined;
    return { host, port: o.port, path: typeof o.path === 'string' && o.path !== '' ? o.path : undefined };
  }
  if (typeof first === 'string' && !/^\d+$/.test(first)) return { path: first }; // IPC path
  return { port: first, host: typeof args[1] === 'string' ? args[1] : undefined };
}

/** Copies symbol-keyed properties (e.g. Node's custom promisify args) to the wrapper. */
function copySymbols(from: object, to: object): void {
  for (const key of Object.getOwnPropertySymbols(from)) {
    const descriptor = Object.getOwnPropertyDescriptor(from, key);
    if (descriptor) Object.defineProperty(to, key, descriptor);
  }
}

function install(): void {
  if (state.installed) return;
  state.installed = true;

  const originalConnect = net.Socket.prototype.connect;
  const guardedConnect = function (this: net.Socket, ...args: unknown[]): net.Socket {
    const target = targetOf(args);
    if (target.path === undefined && !isLoopbackHost(target.host)) {
      const err = record(`connect to ${String(target.host)}:${String(target.port)}`);
      process.nextTick(() => this.destroy(err));
      return this;
    }
    return (originalConnect as (...a: unknown[]) => net.Socket).apply(this, args);
  };
  net.Socket.prototype.connect = guardedConnect as typeof net.Socket.prototype.connect;

  const originalLookup = dns.lookup;
  const guardedLookup = function (hostname: string, ...rest: unknown[]): void {
    if (!isLoopbackHost(hostname)) {
      const err = record(`dns.lookup ${String(hostname)}`);
      const callback = rest[rest.length - 1];
      if (typeof callback === 'function') process.nextTick(() => (callback as (e: Error) => void)(err));
      return;
    }
    (originalLookup as (...a: unknown[]) => void)(hostname, ...rest);
  };
  copySymbols(originalLookup, guardedLookup); // keeps util.promisify(dns.lookup) -> { address, family }
  dns.lookup = guardedLookup as typeof dns.lookup;

  const originalPromisesLookup = dns.promises.lookup;
  const guardedPromisesLookup = function (hostname: string, ...rest: unknown[]): Promise<unknown> {
    if (!isLoopbackHost(hostname)) return Promise.reject(record(`dns.promises.lookup ${String(hostname)}`));
    return (originalPromisesLookup as (...a: unknown[]) => Promise<unknown>)(hostname, ...rest);
  };
  dns.promises.lookup = guardedPromisesLookup as typeof dns.promises.lookup;
}

install();
process.env.REGISTRY_ENRICHMENT = 'off';

function failOnViolations(phase: string): void {
  const seen = takeNetworkViolations();
  if (seen.length > 0) {
    throw new Error(`network guard: ${seen.length} non-loopback network attempt(s) ${phase}:\n  ${seen.join('\n  ')}`);
  }
}

afterEach(() => failOnViolations('during this test'));
afterAll(() => failOnViolations('in this file outside a test'));
