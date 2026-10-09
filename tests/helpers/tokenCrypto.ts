import crypto from 'node:crypto';

/**
 * Encrypts like the platform stores integrations.access_token_enc
 * (ADR-002): AES-256-GCM, key = SHA-256(ENCRYPTION_KEY), buffer layout
 * IV(12) | tag(16) | ciphertext.
 */
export function encryptToken(plain: string, keyString: string): Buffer {
  const key = crypto.createHash('sha256').update(keyString).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

/** Every textual form of a buffer that must never leak into messages/logs. */
export function leakForms(buf: Buffer, plain: string): string[] {
  return [plain, buf.toString('utf8'), buf.toString('hex'), buf.toString('base64')].filter((s) => s.length >= 8);
}

/** Non-secret test values (not real credentials). */
export const TEST_TOKEN = 'tok-test-PLAINTEXT-not-a-real-token-123';
export const TEST_SHORT_TOKEN = 'tok-plain-under-28'; // 18 bytes < 28 (case c)
export const TEST_KEY_A = 'unit-test-key-A-not-secret';
export const TEST_KEY_B = 'unit-test-key-B-not-secret';
