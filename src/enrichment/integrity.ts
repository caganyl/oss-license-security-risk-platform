/**
 * Archive integrity (REQ-004 AC-P15-2, AC-P15-3; ADR-006 Karar 6).
 *
 * - npm: `dist.integrity` is SRI text (several space-separated items may be
 *   present); its `sha512-<base64>` items are the expected digests. Without a
 *   sha512 item `dist.shasum` (40 hex, SHA-1) is accepted.
 * - PyPI: `digests.sha256` (64 hex).
 *
 * The hash is computed incrementally while the archive streams in
 * (`createDigestStream`); the buffer is handed to the archive thread only
 * after `verifyDigest` succeeded (integrity before parsing).
 */
import crypto from 'node:crypto';

export type DigestAlgorithm = 'sha512' | 'sha1' | 'sha256';

/** Expected digest of one archive: algorithm and the accepted values (normalized encoding). */
export interface ExpectedDigest {
  algorithm: DigestAlgorithm;
  /** sha512: base64 values; sha1/sha256: one lower-case hex value. */
  values: readonly string[];
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const HEX40_RE = /^[0-9a-fA-F]{40}$/;
const HEX64_RE = /^[0-9a-fA-F]{64}$/;

/** sha512 base64 values of an SRI string (options after `?` are ignored); empty when none. */
export function parseSriSha512(integrity: unknown): string[] {
  if (typeof integrity !== 'string') return [];
  const values: string[] = [];
  for (const item of integrity.trim().split(/\s+/)) {
    if (!item.toLowerCase().startsWith('sha512-')) continue;
    const value = item.slice('sha512-'.length).split('?')[0];
    // A sha512 digest is 64 bytes = 88 base64 characters with padding.
    if (BASE64_RE.test(value) && Buffer.from(value, 'base64').length === 64) values.push(value);
  }
  return values;
}

/** Expected digest of an npm version document's `dist` (sha512 from `integrity`, else sha1 `shasum`), or null. */
export function npmExpectedDigest(integrity: unknown, shasum: unknown): ExpectedDigest | null {
  const sha512 = parseSriSha512(integrity);
  if (sha512.length > 0) return { algorithm: 'sha512', values: sha512 };
  if (typeof shasum === 'string' && HEX40_RE.test(shasum)) return { algorithm: 'sha1', values: [shasum.toLowerCase()] };
  return null;
}

/** Expected digest of a PyPI file (`digests.sha256`), or null. */
export function pypiExpectedDigest(sha256: unknown): ExpectedDigest | null {
  if (typeof sha256 === 'string' && HEX64_RE.test(sha256)) return { algorithm: 'sha256', values: [sha256.toLowerCase()] };
  return null;
}

/** Incremental hash of streamed bytes, finished into the encoding `ExpectedDigest` uses. */
export interface DigestStream {
  update(chunk: Uint8Array): void;
  /** Digest in the normalized encoding (sha512 base64, otherwise lower-case hex). Call once. */
  digest(): string;
}

export function createDigestStream(algorithm: DigestAlgorithm): DigestStream {
  const hash = crypto.createHash(algorithm);
  return {
    update: (chunk) => {
      hash.update(chunk);
    },
    digest: () => hash.digest(algorithm === 'sha512' ? 'base64' : 'hex'),
  };
}

/** True when `actual` (from `DigestStream.digest`) equals one of the expected values (constant-time per value). */
export function verifyDigest(expected: ExpectedDigest, actual: string): boolean {
  const actualBytes = Buffer.from(actual);
  let match = false;
  for (const value of expected.values) {
    const valueBytes = Buffer.from(value);
    if (valueBytes.length === actualBytes.length && crypto.timingSafeEqual(valueBytes, actualBytes)) match = true;
  }
  return match;
}

/** Cache key form of a verified digest: `sha512-<b64>`, `sha1-<hex>` or `sha256-<hex>` (`registry_archive_cache.archive_digest`). */
export function digestKey(algorithm: DigestAlgorithm, value: string): string {
  return `${algorithm}-${value}`;
}
