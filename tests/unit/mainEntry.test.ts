/**
 * REQ-003 D-52 / REQ-002 AC-P09-3 at the process entry point (`src/main.ts`,
 * `npm start`): without DATABASE_URL the process refuses to start with an
 * explicit message and exit code 1, and never falls back to a default.
 *
 * `dotenv/config` is mocked so the developer's `.env` is never read (no
 * secret enters the test, and no development database can be reached). The
 * signal/fatal handlers `main()` installs on the real `process` are removed
 * after each test.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('dotenv/config', () => ({}));

import { main } from '../../src/main';

const EVENTS = ['SIGINT', 'SIGTERM', 'SIGBREAK', 'SIGHUP', 'unhandledRejection', 'uncaughtException'] as const;
let before = new Map<string, Array<(...a: unknown[]) => void>>();
let savedUrl: string | undefined;

beforeEach(() => {
  savedUrl = process.env.DATABASE_URL;
  before = new Map(EVENTS.map((e) => [e, process.listeners(e as NodeJS.Signals) as Array<(...a: unknown[]) => void>]));
});
afterEach(() => {
  for (const e of EVENTS) {
    const kept = before.get(e) ?? [];
    for (const l of process.listeners(e as NodeJS.Signals) as Array<(...a: unknown[]) => void>) {
      if (!kept.includes(l)) process.removeListener(e, l);
    }
  }
  if (savedUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = savedUrl;
  vi.restoreAllMocks();
});

describe('D-52 / AC-P09-3: main() without DATABASE_URL', () => {
  it.each([[undefined], [''], ['   ']])('DATABASE_URL=%j -> one explicit error line naming the variable, exit(1) once, env not filled in', async (value) => {
    if (value === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = value;
    const errors: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      errors.push(a.map(String).join(' '));
    });
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const exit = vi.fn<(code: number) => void>();

    await main(exit);

    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/Missing required environment variable\(s\): DATABASE_URL\b/);
    expect(errors[0]).toMatch(/\.env\.example/);
    // no insecure default was substituted
    expect(process.env.DATABASE_URL ?? '').toBe(value ?? '');
  });
});
