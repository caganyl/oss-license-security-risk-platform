/**
 * REQ-003 security review L-1 / M-1 sweep: `redactSecrets` in src/lib/redact.ts.
 * - The credential-URL pattern has a bounded scheme and no `\b`: a long
 *   "a.a.a.…" run is linear, and `x_https://user@host` is masked.
 * All values are fake (tests/README.md "Kurallar").
 */
import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import { redactSecrets } from '../../src/lib/redact';

describe('L-1 / M-1 sweep: redactSecrets credential URLs', () => {
  it('L-1: a URL after "_" (x_https://u@h) has its user info masked', () => {
    expect(redactSecrets('x_https://u@h/x', {})).toBe('x_https://[REDACTED]@h/x');
    expect(redactSecrets('x_https://qa-user:not-a-real-pass@git.example.test/r', {})).toBe('x_https://[REDACTED]@git.example.test/r');
  });

  it('regression: plain credential URLs and secret env values are still masked', () => {
    expect(redactSecrets('postgres://qa:not-a-real-pass@localhost:5432/x', {})).toBe('postgres://[REDACTED]@localhost:5432/x');
    expect(redactSecrets('key=unit-test-key-not-secret', { ENCRYPTION_KEY: 'unit-test-key-not-secret' })).toBe('key=[REDACTED]');
  });

  // Required < 1 s; asserted < 2 s for CI headroom (the former unbounded scheme was
  // quadratic on this input).
  it.each([
    ['64k x "a."', 'a.'.repeat(65_536)],
    ['64k x "a." + "://"', `${'a.'.repeat(65_536)}://`],
    ['64k x "a+" + ":/"', `${'a+'.repeat(65_536)}:/`],
  ])('M-1 sweep: %s is redacted in linear time', (_label, input) => {
    const start = performance.now();
    const out = redactSecrets(input, {});
    const ms = performance.now() - start;
    expect(out.length).toBeGreaterThan(0);
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(2_000);
  });
});
