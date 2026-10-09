import crypto from 'crypto';

/** ADR-001 karar 1 / K5: length limits, measured with `string.length`, never trimmed. */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 1024;

const SCRYPT_N = 2 ** 17;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 64;
const SALT_BYTES = 16;
// N=2^17, r=8 needs ~128 MiB; Node's 32 MiB default would reject it.
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

function scrypt(password: string, salt: Buffer, n: number, r: number, p: number, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N: n, r, p, maxmem: SCRYPT_MAXMEM }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/**
 * Returns the setup validation message for an invalid password, or null when
 * the value is acceptable (contract: fixed messages, code invalid_password).
 */
export function passwordPolicyViolation(value: unknown): string | null {
  if (typeof value !== 'string') return 'Password is required';
  if (value.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  if (value.length > PASSWORD_MAX_LENGTH) return `Password must be at most ${PASSWORD_MAX_LENGTH} characters`;
  return null;
}

/** Hashes with async scrypt; format `scrypt$<N>$<r>$<p>$<salt_b64>$<hash_b64>` (ADR-001 karar 1). */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = await scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH);
  return ['scrypt', SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.toString('base64'), hash.toString('base64')].join('$');
}

/**
 * Verifies a password against a stored hash in constant time. Parameters are
 * read from the stored value so they can be raised later without a migration.
 * Returns false (never throws) for malformed stored values.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [n, r, p] = parts.slice(1, 4).map(Number);
  if (![n, r, p].every((v) => Number.isInteger(v) && v > 0)) return false;
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  if (salt.length === 0 || expected.length === 0) return false;
  const actual = await scrypt(password, salt, n, r, p, expected.length);
  return crypto.timingSafeEqual(actual, expected);
}
