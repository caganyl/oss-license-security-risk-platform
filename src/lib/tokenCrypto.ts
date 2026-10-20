import crypto from 'crypto';

/**
 * Encrypts a repository access token for `integrations.access_token_enc`
 * (REQ-009 P-29). Same scheme the worker's `decryptToken` reads (ADR-002
 * karar 6): AES-256-GCM, key = SHA-256(ENCRYPTION_KEY), layout
 * `IV(12) | tag(16) | ciphertext`. Without a key it throws; the token is
 * never stored in plain text.
 */
export function encryptToken(token: string, keyString?: string): Buffer {
  const keyMaterial = keyString || process.env.ENCRYPTION_KEY;
  if (!keyMaterial) throw new Error('ENCRYPTION_KEY is not set; repository tokens cannot be stored');
  const key = crypto.createHash('sha256').update(keyMaterial).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}
