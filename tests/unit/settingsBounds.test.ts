/**
 * REQ-003 security review I-3 (range checks of numeric settings) and I-1
 * (PORT validation), pure parts:
 * - `boundedNumber` / `MAX_TIMER_MS` (src/lib/bounds.ts);
 * - `parseScanQueueSettings` upper bounds (src/scanner/retryPolicy.ts);
 * - environment overrides read when runner.config.ts / reports/worker.config.ts
 *   are loaded (modules re-imported after `vi.resetModules()` with `vi.stubEnv`);
 * - `assertValidPortEnv` / `resolvePort` (src/config/env.ts).
 * The runtime refusal (RuntimeStartupError, exit 1) is in
 * tests/integration/runtime.test.ts, the claim-time cleanup of exhausted scans
 * in tests/integration/scanRetry.test.ts.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { INVALID_PORT_MESSAGE, assertValidPortEnv, resolvePort } from '../../src/config/env';
import { MAX_TIMER_MS, boundedNumber } from '../../src/lib/bounds';
import { DEFAULT_TIMEOUT_MINUTES, parseScanQueueSettings } from '../../src/scanner/retryPolicy';
import { MAX_JOB_TIMEOUT_MS, MAX_SCAN_ATTEMPTS, MAX_TIMEOUT_MINUTES } from '../../src/scanner/sandbox/runner.config';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.resetModules();
});

describe('I-3: boundedNumber (src/lib/bounds.ts)', () => {
  const opts = (warn: (m: string) => void, extra: Partial<Parameters<typeof boundedNumber>[2]> = {}) => ({ name: 'QA_SETTING', min: 1, max: 10, integer: true, warn, ...extra });

  it('I-3: values inside the bounds are returned (number or trimmed numeric string), no warning', () => {
    const warn = vi.fn();
    expect(boundedNumber(1, 5, opts(warn))).toBe(1);
    expect(boundedNumber(10, 5, opts(warn))).toBe(10);
    expect(boundedNumber(' 7 ', 5, opts(warn))).toBe(7);
    expect(warn).not.toHaveBeenCalled();
  });

  it('I-3: missing or blank -> fallback without a warning', () => {
    const warn = vi.fn();
    for (const raw of [undefined, null, '', '   ']) expect(boundedNumber(raw, 5, opts(warn))).toBe(5);
    expect(warn).not.toHaveBeenCalled();
  });

  it.each([[0], [11], [-1], ['abc'], ['2.5'], [2.5], [Number.NaN], [Number.POSITIVE_INFINITY], ['1e309']])(
    'I-3: out of range or invalid %j -> fallback and one warning naming the setting, not the value',
    (raw) => {
      const warn = vi.fn();
      expect(boundedNumber(raw, 5, opts(warn))).toBe(5);
      expect(warn).toHaveBeenCalledTimes(1);
      const message = String(warn.mock.calls[0][0]);
      expect(message).toContain('QA_SETTING');
      expect(message).toContain('varsayılan 5');
      if (typeof raw === 'string' && raw !== '') expect(message).not.toContain(raw);
    },
  );

  it('I-3: a JSON boolean from system_settings is invalid (parseScanQueueSettings stringifies non-string/number values)', () => {
    const warn = vi.fn();
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: true }], warn)).toMatchObject({ maxAttempts: 3 });
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('I-3: exclusiveMin refuses the minimum itself; non-integers are allowed without `integer`', () => {
    const warn = vi.fn();
    expect(boundedNumber(0, 60, { name: 'T', min: 0, max: 1440, exclusiveMin: true, warn })).toBe(60);
    expect(boundedNumber(0.5, 60, { name: 'T', min: 0, max: 1440, exclusiveMin: true, warn })).toBe(0.5);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('>0–1440');
  });

  it('I-3: default sink is console.warn', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    expect(boundedNumber('-5', 3, { name: 'QA_DEFAULT_SINK', min: 1, max: 10 })).toBe(3);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('I-3: every derived timer bound stays below the setTimeout limit', () => {
    expect(MAX_TIMER_MS).toBe(2 ** 31 - 1);
    expect(MAX_JOB_TIMEOUT_MS).toBeLessThanOrEqual(MAX_TIMER_MS);
    expect(MAX_TIMEOUT_MINUTES * 60_000).toBeLessThanOrEqual(MAX_TIMER_MS);
  });
});

describe('I-3: parseScanQueueSettings upper bounds (scan.max_retries 1–10, scan.timeout_minutes >0–1440)', () => {
  it('I-3: the bounds themselves are accepted', () => {
    const warn = vi.fn();
    expect(MAX_SCAN_ATTEMPTS).toBe(10);
    expect(MAX_TIMEOUT_MINUTES).toBe(1440);
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: 10 }, { key: 'scan.timeout_minutes', value: 1440 }], warn)).toEqual({
      maxAttempts: 10,
      timeoutMinutes: 1440,
    });
    expect(warn).not.toHaveBeenCalled();
  });

  it('I-3: scan.max_retries 11 and scan.timeout_minutes 1441 -> defaults (3, 60) and one warning each', () => {
    const warn = vi.fn();
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: 11 }, { key: 'scan.timeout_minutes', value: 1441 }], warn)).toEqual({
      maxAttempts: 3,
      timeoutMinutes: DEFAULT_TIMEOUT_MINUTES,
    });
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls.map((c) => String(c[0]))).toEqual([
      expect.stringContaining('scan.max_retries'),
      expect.stringContaining('scan.timeout_minutes'),
    ]);
  });

  it('I-3: string values from jsonb/text rows are bounded the same way; null is "not set" (no warning)', () => {
    const warn = vi.fn();
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: '11' }, { key: 'scan.timeout_minutes', value: '100000' }], warn)).toEqual({
      maxAttempts: 3,
      timeoutMinutes: 60,
    });
    expect(warn).toHaveBeenCalledTimes(2);
    const quiet = vi.fn();
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: null }], quiet)).toEqual({ maxAttempts: 3, timeoutMinutes: 60 });
    expect(quiet).not.toHaveBeenCalled();
  });

  it('I-3: without a warn callback nothing throws', () => {
    expect(parseScanQueueSettings([{ key: 'scan.max_retries', value: 99 }])).toMatchObject({ maxAttempts: 3 });
  });
});

describe('I-3: environment overrides out of range -> defaults with a warning (read at module load)', () => {
  async function loadRunnerConfig(env: Record<string, string>) {
    for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.resetModules();
    const mod = await import('../../src/scanner/sandbox/runner.config');
    return { config: mod.sandboxRunnerConfig, warnings: warn.mock.calls.map((c) => String(c[0])) };
  }

  it('I-3: SCAN_TIMEOUT_MS, SCAN_MAX_RETRIES, WORKER_MAX_CONCURRENT, WORKER_POLL_INTERVAL_MS out of range -> defaults; one warning each', async () => {
    const { config, warnings } = await loadRunnerConfig({
      SCAN_TIMEOUT_MS: String(MAX_TIMER_MS + 1),
      SCAN_MAX_RETRIES: '11',
      WORKER_MAX_CONCURRENT: '0',
      WORKER_POLL_INTERVAL_MS: '-5',
    });
    expect(config.scan.timeoutMs).toBe(60 * 60 * 1000);
    expect(config.retry.maxAttempts).toBe(3);
    expect(config.worker.maxConcurrentScans).toBe(4);
    expect(config.worker.pollIntervalMs).toBe(5_000);
    for (const name of ['SCAN_TIMEOUT_MS', 'SCAN_MAX_RETRIES', 'WORKER_MAX_CONCURRENT', 'WORKER_POLL_INTERVAL_MS']) {
      expect(warnings.filter((w) => w.startsWith(`${name} `)), name).toHaveLength(1);
    }
  });

  it('I-3: in-range environment values are used', async () => {
    const { config, warnings } = await loadRunnerConfig({ SCAN_MAX_RETRIES: '10', WORKER_MAX_CONCURRENT: '32', WORKER_POLL_INTERVAL_MS: '250' });
    expect(config.retry.maxAttempts).toBe(10);
    expect(config.worker.maxConcurrentScans).toBe(32);
    expect(config.worker.pollIntervalMs).toBe(250);
    expect(warnings).toEqual([]);
  });

  it('I-3: EXPORT_WORKER_* out of range -> defaults (4, 5000, 10 min) with warnings', async () => {
    vi.stubEnv('EXPORT_WORKER_MAX_CONCURRENT', '33');
    vi.stubEnv('EXPORT_WORKER_POLL_INTERVAL_MS', 'abc');
    vi.stubEnv('EXPORT_WORKER_TIMEOUT_MS', String(MAX_JOB_TIMEOUT_MS + 1));
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.resetModules();
    const { exportWorkerConfig } = await import('../../src/reports/worker.config');
    expect(exportWorkerConfig).toEqual({ maxConcurrentExports: 4, pollIntervalMs: 5000, timeoutMs: 10 * 60 * 1000 });
    const warnings = warn.mock.calls.map((c) => String(c[0]));
    for (const name of ['EXPORT_WORKER_MAX_CONCURRENT', 'EXPORT_WORKER_POLL_INTERVAL_MS', 'EXPORT_WORKER_TIMEOUT_MS']) {
      expect(warnings.filter((w) => w.startsWith(`${name} `)), name).toHaveLength(1);
    }
  });
});

describe('I-1: PORT validation (src/config/env.ts)', () => {
  it('I-1: the message is fixed', () => {
    expect(INVALID_PORT_MESSAGE).toBe('PORT geçersiz: 1 ile 65535 arasında bir tam sayı olmalı.');
  });

  it.each([['0'], ['70000'], ['65536'], ['abc'], ['-1'], ['3001.5'], ['1e3'], ['0x10']])('I-1: PORT=%s is refused with the fixed message (value not echoed)', (value) => {
    expect(() => assertValidPortEnv({ PORT: value })).toThrow(INVALID_PORT_MESSAGE);
  });

  it.each([[undefined], [''], ['   '], ['1'], ['3001'], ['65535'], [' 8080 ']])('I-1: PORT=%j is accepted', (value) => {
    expect(() => assertValidPortEnv(value === undefined ? {} : { PORT: value })).not.toThrow();
  });

  it('I-1: resolvePort: unset or invalid PORT -> 3001; a valid PORT is used; an injected port wins (also 0 for tests)', () => {
    expect(resolvePort(undefined, {})).toBe(3001);
    expect(resolvePort(undefined, { PORT: '0' })).toBe(3001);
    expect(resolvePort(undefined, { PORT: '70000' })).toBe(3001);
    expect(resolvePort(undefined, { PORT: '8080' })).toBe(8080);
    expect(resolvePort(0, { PORT: '8080' })).toBe(0);
    expect(resolvePort(4000, {})).toBe(4000);
  });
});
