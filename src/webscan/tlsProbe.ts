/**
 * Legacy TLS protocol probe (REQ-008 D-218; ADR-010 Karar 5).
 *
 * One handshake limited to TLS 1.0–1.1. No application data is written or
 * read; the socket is destroyed right after the handshake. Certificate
 * validation is off for this handshake only: it measures protocol
 * acceptance, nothing received is trusted or kept. A client-side failure
 * (OpenSSL build without the old protocols) is indistinguishable from a
 * refusal and gives `null` (no finding).
 */
import net from 'node:net';
import tls from 'node:tls';
import { type HostAllowlist, isAllowedRequestUrl } from './allowlist';
import { guardedLookup } from './probeClient';

export const LEGACY_PROBE_TIMEOUT_MS = 10_000;

/** `'TLSv1'` / `'TLSv1.1'` when the server accepted a legacy handshake, else null. */
export function probeLegacyTls(target: string, allowlist: HostAllowlist, signal: AbortSignal, timeoutMs: number = LEGACY_PROBE_TIMEOUT_MS): Promise<string | null> {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return Promise.resolve(null);
  }
  if (url.protocol !== 'https:' || !isAllowedRequestUrl(url, allowlist)) return Promise.resolve(null);
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1');
  const port = url.port ? Number(url.port) : 443;
  return new Promise<string | null>((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    let done = false;
    let socket: tls.TLSSocket | null = null;
    const finish = (value: string | null, abort?: unknown) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      socket?.destroy();
      if (abort !== undefined) reject(abort);
      else resolve(value);
    };
    const onAbort = () => finish(null, signal.reason);
    const timer = setTimeout(() => finish(null), timeoutMs);
    signal.addEventListener('abort', onAbort, { once: true });
    try {
      socket = tls.connect({
        host,
        port,
        servername: net.isIP(host) ? undefined : host,
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.1',
        ciphers: 'DEFAULT:@SECLEVEL=0',
        rejectUnauthorized: false,
        // Same address rule as the probe client (security review L-6).
        lookup: guardedLookup(allowlist),
      });
    } catch {
      finish(null);
      return;
    }
    socket.once('secureConnect', () => {
      const protocol = socket?.getProtocol() ?? null;
      finish(protocol === 'TLSv1' || protocol === 'TLSv1.1' ? protocol : null);
    });
    socket.once('error', () => finish(null));
    socket.once('close', () => finish(null));
  });
}
