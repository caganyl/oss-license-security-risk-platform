/**
 * REQ-002 · P-09 · AC-P09-5, D-14, ADR-002 karar 6
 * decryptToken must never return the buffer as plain text. Expected export:
 * `export function decryptToken(encrypted: Buffer | null | undefined, keyString?: string): string | null`
 * from src/scanner/worker.ts (today it exists but is not exported).
 * Worker-level consequences (scan failed, no clone) are in
 * tests/integration/worker.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadSrc } from '../helpers/loadSrc';
import type { WorkerModule } from '../helpers/contracts';
import {
  TEST_KEY_A,
  TEST_KEY_B,
  TEST_SHORT_TOKEN,
  TEST_TOKEN,
  encryptToken,
  leakForms,
} from '../helpers/tokenCrypto';

const loadWorker = () => loadSrc<WorkerModule>('src/scanner/worker.ts', ['decryptToken']);

function expectThrowsWithoutLeak(fn: () => unknown, buf: Buffer, plain: string): void {
  let thrown: unknown;
  let returned: unknown;
  try {
    returned = fn();
  } catch (err) {
    thrown = err;
  }
  expect(returned, 'decryptToken returned a value instead of throwing').toBeUndefined();
  expect(thrown).toBeInstanceOf(Error);
  const text = `${(thrown as Error).message}\n${(thrown as Error).stack ?? ''}`;
  for (const form of leakForms(buf, plain)) expect(text).not.toContain(form);
}

describe('P-09 decryptToken (AC-P09-5 / D-14)', () => {
  let savedKey: string | undefined;
  beforeEach(() => {
    savedKey = process.env.ENCRYPTION_KEY;
  });
  afterEach(() => {
    if (savedKey === undefined) delete process.env.ENCRYPTION_KEY;
    else process.env.ENCRYPTION_KEY = savedKey;
  });

  it('control: decrypts a token encrypted with ENCRYPTION_KEY', async () => {
    const { decryptToken } = await loadWorker();
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    expect(decryptToken(encryptToken(TEST_TOKEN, TEST_KEY_A))).toBe(TEST_TOKEN);
  });

  it('AC-P09-5 (a): ENCRYPTION_KEY undefined -> throws, never returns the buffer text', async () => {
    const { decryptToken } = await loadWorker();
    delete process.env.ENCRYPTION_KEY;
    const enc = encryptToken(TEST_TOKEN, TEST_KEY_A);
    expectThrowsWithoutLeak(() => decryptToken(enc), enc, TEST_TOKEN);
    // a plaintext-stored token must not come back either
    const plain = Buffer.from(TEST_TOKEN, 'utf8');
    expectThrowsWithoutLeak(() => decryptToken(plain), plain, TEST_TOKEN);
  });

  it('AC-P09-5 (a): ENCRYPTION_KEY empty string -> throws', async () => {
    const { decryptToken } = await loadWorker();
    process.env.ENCRYPTION_KEY = '';
    const enc = encryptToken(TEST_TOKEN, TEST_KEY_A);
    expectThrowsWithoutLeak(() => decryptToken(enc), enc, TEST_TOKEN);
  });

  it('AC-P09-5 (b): >= 28-byte buffer encrypted with a different key -> throws (catch branch)', async () => {
    const { decryptToken } = await loadWorker();
    process.env.ENCRYPTION_KEY = TEST_KEY_B;
    const enc = encryptToken(TEST_TOKEN, TEST_KEY_A);
    expect(enc.length).toBeGreaterThanOrEqual(28);
    expectThrowsWithoutLeak(() => decryptToken(enc), enc, TEST_TOKEN);
  });

  it('AC-P09-5 (b): tampered ciphertext -> throws', async () => {
    const { decryptToken } = await loadWorker();
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    const enc = encryptToken(TEST_TOKEN, TEST_KEY_A);
    enc[enc.length - 1] ^= 0xff;
    expectThrowsWithoutLeak(() => decryptToken(enc), enc, TEST_TOKEN);
  });

  it('AC-P09-5 (b): >= 28-byte plaintext-stored token -> throws (no utf8 fallback)', async () => {
    const { decryptToken } = await loadWorker();
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    const plain = Buffer.from(TEST_TOKEN, 'utf8');
    expect(plain.length).toBeGreaterThanOrEqual(28);
    expectThrowsWithoutLeak(() => decryptToken(plain), plain, TEST_TOKEN);
  });

  it('AC-P09-5 (c): buffer shorter than 28 bytes -> throws, never returns the buffer text', async () => {
    const { decryptToken } = await loadWorker();
    process.env.ENCRYPTION_KEY = TEST_KEY_A;
    const short = Buffer.from(TEST_SHORT_TOKEN, 'utf8');
    expect(short.length).toBeLessThan(28);
    expectThrowsWithoutLeak(() => decryptToken(short), short, TEST_SHORT_TOKEN);
  });

  it('AC-P09-5: no token (null / undefined / empty buffer) -> null, no error, even without ENCRYPTION_KEY', async () => {
    const { decryptToken } = await loadWorker();
    delete process.env.ENCRYPTION_KEY;
    expect(decryptToken(null)).toBeNull();
    expect(decryptToken(undefined)).toBeNull();
    expect(decryptToken(Buffer.alloc(0))).toBeNull();
  });
});
