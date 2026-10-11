/**
 * Origin checks of code-injected endpoints (ADR-006 Karar 4 `assertInjectableEndpoint`,
 * generalized by ADR-007 Karar 1, 2 / D-88).
 *
 * An injected endpoint (tests only, never from the environment) is accepted
 * when it is one of the given production origins over `https:`, or a
 * loopback `http:` origin (`http://127.0.0.1:<port>` / `http://[::1]:<port>`).
 * Path, query, fragment and credentials are rejected.
 *
 * Pure module (only `node:url`).
 */
import { URL } from 'node:url';

/** A URL outside an allowlist; no request is made. */
export class SafeHttpUrlError extends Error {
  readonly code = 'URL_NOT_ALLOWED';
  constructor(message: string) {
    super(message);
    this.name = 'SafeHttpUrlError';
  }
}

export function isLoopbackHttp(url: URL): boolean {
  return url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === '[::1]');
}

export interface InjectableOriginOptions {
  /** Subject of the error messages, e.g. `Kayıt defteri` (default `HTTP`). */
  label?: string;
  /** Error factory (default `SafeHttpUrlError`). */
  makeError?: (message: string) => Error;
}

/** Validates a code-injected endpoint and returns its origin (throws otherwise). */
export function assertInjectableOrigin(
  value: string,
  productionOrigins: ReadonlySet<string> | readonly string[],
  options: InjectableOriginOptions = {},
): string {
  const label = options.label ?? 'HTTP';
  const fail = (message: string): never => {
    throw (options.makeError ?? ((m: string) => new SafeHttpUrlError(m)))(message);
  };
  const allowed = productionOrigins instanceof Set ? productionOrigins : new Set(productionOrigins as readonly string[]);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fail(`${label} uç noktası geçerli bir URL değil.`);
  }
  if (url.username || url.password) fail(`${label} uç noktası kullanıcı bilgisi içeremez.`);
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
    fail(`${label} uç noktası yol veya sorgu içeremez.`);
  }
  if (url.protocol === 'https:' && allowed.has(url.origin)) return url.origin;
  if (isLoopbackHttp(url)) return url.origin;
  return fail(`${label} uç noktası izin listesinde değil.`);
}
