/**
 * REQ-003 · P-13 pure retry/timeout policy (src/scanner/retryPolicy.ts):
 * AC-P13-1 backoff table, AC-P13-3/4/5 classification and decision,
 * AC-P13-6 timeout message (ADR-004 Karar 7, 8; D-40, D-41, D-42).
 */
import { describe, expect, it } from 'vitest';
import { GitUnavailableError } from '../../src/scanner/gitVersion';
import { ParserCrashedError, ParserFailedError, ParserMemoryLimitError } from '../../src/scanner/parsers/threadParser';
import {
  NonRetryableScanError,
  ScanAbortError,
  abortReasonOf,
  backoffSeconds,
  classifyScanFailure,
  decideRetry,
  parseScanQueueSettings,
  timeoutMessage,
} from '../../src/scanner/retryPolicy';

describe('AC-P13-1 / D-40: backoffSeconds(n) = min(600, 30 * 2^(n-1)), no jitter', () => {
  it('30, 60, 120, 240, 480, 600, 600, … and capped for large n', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 8, 20].map(backoffSeconds)).toEqual([30, 60, 120, 240, 480, 600, 600, 600, 600]);
    expect(backoffSeconds(1000)).toBe(600);
  });

  it('deterministic: the same n always gives the same value', () => {
    const values = new Set(Array.from({ length: 50 }, () => backoffSeconds(3)));
    expect([...values]).toEqual([120]);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])('n = %s -> RangeError', (n) => {
    expect(() => backoffSeconds(n)).toThrow(RangeError);
  });
});

describe('ADR-004 Karar 8: failure classification', () => {
  const aborted = (reason: 'timeout' | 'shutdown') => {
    const c = new AbortController();
    c.abort(new ScanAbortError(reason));
    return c.signal;
  };

  it('shutdown abort -> return-to-queue; timeout abort -> permanent; the signal wins over the thrown error', () => {
    expect(classifyScanFailure(new Error('clone killed'), aborted('shutdown'))).toBe('return-to-queue');
    expect(classifyScanFailure(new Error('clone killed'), aborted('timeout'))).toBe('permanent');
    expect(classifyScanFailure(new NonRetryableScanError('x'), aborted('shutdown'))).toBe('return-to-queue');
    expect(classifyScanFailure(new ScanAbortError('shutdown'))).toBe('return-to-queue');
    expect(classifyScanFailure(new ScanAbortError('timeout'))).toBe('permanent');
    expect(abortReasonOf(aborted('timeout'))).toBe('timeout');
    const foreign = new AbortController();
    foreign.abort(new Error('not ours'));
    expect(abortReasonOf(foreign.signal)).toBeNull();
    expect(classifyScanFailure(new Error('x'), foreign.signal)).toBe('transient');
  });

  it('AC-P13-4: token/source/ref, parser crash/memory/failed result and missing git are permanent', () => {
    const info = { found: false, version: null, major: null, minor: null, supported: false };
    for (const err of [
      new NonRetryableScanError('Integration token could not be decrypted'),
      new ParserMemoryLimitError(512),
      new ParserCrashedError('thread exited'),
      new ParserFailedError('failed result'),
      new GitUnavailableError(info),
    ]) {
      expect(classifyScanFailure(err), err.name).toBe('permanent');
    }
  });

  it('AC-P13-5: clone failures (auth/not found alike), clone timeout, database errors and unknown values are transient', () => {
    for (const err of [
      new Error('fatal: Authentication failed'),
      new Error('fatal: repository not found'),
      Object.assign(new Error('clone timed out'), { code: 'ETIMEDOUT' }),
      Object.assign(new Error('terminating connection'), { code: '57P01' }),
      'a string',
      undefined,
    ]) {
      expect(classifyScanFailure(err)).toBe('transient');
    }
  });
});

describe('AC-P13-2 / AC-P13-3: decideRetry (maxAttempts = total attempts incl. the first)', () => {
  it('with max 3: attempts 1 and 2 retry after 30 s and 60 s, attempt 3 fails', () => {
    expect(decideRetry('transient', 0, 3)).toEqual({ action: 'retry', attempt: 1, maxAttempts: 3, delaySeconds: 30 });
    expect(decideRetry('transient', 1, 3)).toEqual({ action: 'retry', attempt: 2, maxAttempts: 3, delaySeconds: 60 });
    expect(decideRetry('transient', 2, 3)).toEqual({ action: 'fail', attempt: 3, maxAttempts: 3 });
  });

  it('max 1 never retries; permanent never retries', () => {
    expect(decideRetry('transient', 0, 1)).toEqual({ action: 'fail', attempt: 1, maxAttempts: 1 });
    expect(decideRetry('permanent', 0, 5)).toEqual({ action: 'fail', attempt: 1, maxAttempts: 5 });
  });
});

describe('AC-P13-6: timeout message and settings', () => {
  it('Tarama süre sınırını aştı (<dk> dk). with whole and fractional minutes', () => {
    expect(timeoutMessage(60)).toBe('Tarama süre sınırını aştı (60 dk).');
    expect(timeoutMessage(0.01)).toBe('Tarama süre sınırını aştı (0.01 dk).');
    expect(timeoutMessage(1.5)).toBe('Tarama süre sınırını aştı (1.5 dk).');
  });

  it('parseScanQueueSettings: valid values win, invalid ones fall back to the defaults (3 attempts, 60 min)', () => {
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: 5 }, { key: 'scan.timeout_minutes', value: 0.5 }])).toEqual({
      maxAttempts: 5,
      timeoutMinutes: 0.5,
    });
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: 0 }, { key: 'scan.timeout_minutes', value: -1 }])).toEqual({
      maxAttempts: 3,
      timeoutMinutes: 60,
    });
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: '2.5' }])).toMatchObject({ maxAttempts: 3 });
  });
});
