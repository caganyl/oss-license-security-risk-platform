/**
 * Transport rules WEB-TLS-001…005 (REQ-008 P-26, AC-P26-4; contract 4.1).
 * Pure functions over probe results.
 */
import { locationOf } from '../allowlist';
import { finding } from '../rules';
import type { ProbeResponse, ProbeTlsInfo, WebFindingDraft } from '../types';

export const CERT_EXPIRY_WARNING_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Node / OpenSSL codes of a certificate validation failure (WEB-TLS-003). */
const CERT_ERROR_CODES: ReadonlySet<string> = new Set([
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'CERT_REVOKED',
  'CERT_UNTRUSTED',
  'CERT_REJECTED',
  'CERT_SIGNATURE_FAILURE',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_DECRYPT_CERT_SIGNATURE',
  'INVALID_CA',
  'PATH_LENGTH_EXCEEDED',
  'INVALID_PURPOSE',
  'HOSTNAME_MISMATCH',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'ERR_TLS_CERT_ALTNAME_FORMAT',
]);

export function isCertificateError(code: string): boolean {
  return CERT_ERROR_CODES.has(code);
}

/** WEB-TLS-001: the target (final page) is served over plain HTTP. */
export function checkPlainHttp(page: ProbeResponse): WebFindingDraft[] {
  if (!page.url.startsWith('http:')) return [];
  return [finding('WEB-TLS-001', { location: locationOf(page.url), evidence: 'Sayfa http:// ile yanıt verdi', key: 'plain-http' })];
}

/**
 * WEB-TLS-002: the `http://` variant of an https target answered 2xx without
 * redirecting to https. `variant` null = connection failed (no finding).
 */
export function checkHttpRedirect(variant: ProbeResponse | null): WebFindingDraft[] {
  if (!variant) return [];
  if (variant.status >= 200 && variant.status < 300) {
    return [finding('WEB-TLS-002', { location: locationOf(variant.url), evidence: `HTTP ${variant.status} (yönlendirme yok)`, key: 'http-redirect' })];
  }
  if (variant.status >= 300 && variant.status < 400) {
    const target = variant.headers.location;
    const value = Array.isArray(target) ? target[0] : target;
    if (typeof value === 'string' && /^http:\/\//i.test(value.trim())) {
      return [finding('WEB-TLS-002', { location: locationOf(variant.url), evidence: `HTTP ${variant.status} → http:// (HTTPS'e değil)`, key: 'http-redirect' })];
    }
  }
  return [];
}

/** WEB-TLS-003 from a failed https request. */
export function certificateFinding(url: string, code: string): WebFindingDraft {
  return finding('WEB-TLS-003', { location: locationOf(url), evidence: `Hata kodu: ${code}`, key: 'certificate' });
}

/** WEB-TLS-004: the peer certificate expires within 30 days of `now`. */
export function checkCertificateExpiry(url: string, tls: ProbeTlsInfo | null, now: number): WebFindingDraft[] {
  if (!tls?.validTo) return [];
  const end = Date.parse(tls.validTo);
  if (!Number.isFinite(end)) return [];
  const days = Math.floor((end - now) / DAY_MS);
  if (days > CERT_EXPIRY_WARNING_DAYS) return [];
  return [finding('WEB-TLS-004', {
    location: locationOf(url),
    evidence: `Bitiş: ${new Date(end).toISOString().slice(0, 10)} (${Math.max(0, days)} gün)`,
    key: 'certificate-expiry',
  })];
}

/** WEB-TLS-005 from the legacy protocol handshake result (`null` = not measured). */
export function checkLegacyProtocol(url: string, accepted: string | null): WebFindingDraft[] {
  if (!accepted) return [];
  return [finding('WEB-TLS-005', { location: locationOf(url), evidence: `Kabul edilen protokol: ${accepted}`, key: 'legacy-tls' })];
}
