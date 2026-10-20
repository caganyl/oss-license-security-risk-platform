import tls from 'tls';

/** Node ≥ 22.19 / 24.5 TLS CA API (the pinned @types/node predates it; engines guarantee it at run time). */
interface CaApi {
  getCACertificates(type: 'default' | 'system' | 'bundled' | 'extra'): string[];
  setDefaultCACertificates(certs: string[]): void;
}

const nodeTls = tls as unknown as CaApi;

/**
 * Adds the operating system's trusted root certificates (Windows certificate
 * store, macOS keychain, Linux system bundle) to Node's default CA list
 * (REQ-010 r2, D-285). Corporate proxies that inspect HTTPS re-sign traffic
 * with a company root CA that the OS trusts but Node's bundled list does not;
 * without this every OSV/NVD/registry request failed with
 * UNABLE_TO_GET_ISSUER_CERT and scans showed "no vulnerabilities".
 *
 * Certificate validation stays on (nothing is disabled); only trust anchors
 * the OS already trusts are added. `USE_SYSTEM_CA=off` keeps Node's list.
 */
export function trustSystemCertificates(
  env: Readonly<Record<string, string | undefined>> = process.env,
  api: CaApi = nodeTls,
): { added: number } {
  if ((env.USE_SYSTEM_CA ?? '').trim().toLowerCase() === 'off') return { added: 0 };
  const bundled = api.getCACertificates('default');
  const merged = [...new Set([...bundled, ...api.getCACertificates('system')])];
  api.setDefaultCACertificates(merged);
  return { added: merged.length - bundled.length };
}
