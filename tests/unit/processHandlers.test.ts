/**
 * REQ-003 · AC-P12-9 / AC-P12-10 (ADR-004 Karar 5, 6): installProcessHandlers
 * with a fake process (EventEmitter) and a stub runtime. The integration
 * counterpart with the real runtime is in tests/integration/runtime.test.ts.
 */
import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import { SHUTDOWN_SIGNALS, installProcessHandlers, type ProcessLike, type ShutdownReason } from '../../src/runtime';

const SECRET_URL = 'postgres://app:Qa-Not-A-Real-Secret-42@db.internal:5432/ossr';

function setup(shutdownCode = 0) {
  const proc = Object.assign(new EventEmitter(), { env: { DATABASE_URL: SECRET_URL } }) as unknown as ProcessLike & EventEmitter;
  let shuttingDown = false;
  let finish: (code: number) => void = () => undefined;
  const shutdown = vi.fn((reason: ShutdownReason) => {
    void reason;
    shuttingDown = true;
    return new Promise<number>((resolve) => {
      finish = resolve;
    });
  });
  const runtime = {
    shutdown,
    get shuttingDown() {
      return shuttingDown;
    },
  };
  const exit = vi.fn<(code: number) => void>();
  const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
  const uninstall = installProcessHandlers(runtime, proc, exit, logger);
  return { proc, shutdown, exit, logger, uninstall, finish: (code = shutdownCode) => finish(code) };
}

describe('AC-P12-10: shutdown signals', () => {
  it('SIGINT, SIGTERM, SIGBREAK and SIGHUP are handled', () => {
    expect([...SHUTDOWN_SIGNALS].sort()).toEqual(['SIGBREAK', 'SIGHUP', 'SIGINT', 'SIGTERM']);
  });

  it.each([...SHUTDOWN_SIGNALS])('%s -> shutdown("signal") -> exit with its code (0)', async (signal) => {
    const h = setup();
    h.proc.emit(signal);
    expect(h.shutdown).toHaveBeenCalledWith('signal');
    expect(h.exit).not.toHaveBeenCalled(); // waits for the shutdown
    h.finish(0);
    await vi.waitFor(() => expect(h.exit).toHaveBeenCalledWith(0));
    expect(h.logger.log).toHaveBeenCalledWith(`${signal} alındı.`);
  });

  it('a second signal while shutting down -> exit(1) at once, shutdown not started twice', async () => {
    const h = setup();
    h.proc.emit('SIGINT');
    h.proc.emit('SIGINT');
    expect(h.exit).toHaveBeenCalledWith(1);
    expect(h.shutdown).toHaveBeenCalledTimes(1);
    h.finish(0);
    await vi.waitFor(() => expect(h.exit).toHaveBeenCalledTimes(2));
  });

  it('the returned function removes every listener', () => {
    const h = setup();
    h.uninstall();
    for (const e of [...SHUTDOWN_SIGNALS, 'unhandledRejection', 'uncaughtException']) expect(h.proc.listenerCount(e)).toBe(0);
  });
});

describe('AC-P12-9: process-level errors', () => {
  it.each(['unhandledRejection', 'uncaughtException'])('%s -> one redacted log entry, shutdown("fatal"), exit(1)', async (event) => {
    const h = setup(1);
    const err = Object.assign(new Error(`connect failed for ${SECRET_URL}`), { code: 'ECONNREFUSED' });
    h.proc.emit(event, err);
    expect(h.logger.error).toHaveBeenCalledTimes(1);
    const line = String(h.logger.error.mock.calls[0][0]);
    expect(line.startsWith(`${event}: Error (ECONNREFUSED): connect failed for `)).toBe(true);
    expect(line).not.toContain('Qa-Not-A-Real-Secret-42');
    expect(line).not.toContain('app:');
    expect(line).toContain('[REDACTED]');
    expect(h.shutdown).toHaveBeenCalledWith('fatal');
    h.finish(1);
    await vi.waitFor(() => expect(h.exit).toHaveBeenCalledWith(1));
  });

  it('a non-Error rejection reason is logged as a single redacted line', () => {
    const h = setup(1);
    h.proc.emit('unhandledRejection', `oops ${SECRET_URL}`);
    const line = String(h.logger.error.mock.calls[0][0]);
    expect(line.split('\n')).toHaveLength(1);
    expect(line).toMatch(/^unhandledRejection: non-Error value: oops /);
    expect(line).not.toContain('Qa-Not-A-Real-Secret-42');
  });

  it('a fatal error during a signal shutdown exits 1 at once', () => {
    const h = setup();
    h.proc.emit('SIGTERM');
    h.proc.emit('uncaughtException', new Error('late'));
    expect(h.exit).toHaveBeenCalledWith(1);
    expect(h.shutdown).toHaveBeenCalledTimes(1);
  });

  it('a rejected shutdown still exits 1', async () => {
    const proc = new EventEmitter() as unknown as ProcessLike & EventEmitter;
    const exit = vi.fn<(code: number) => void>();
    installProcessHandlers({ shutdown: () => Promise.reject(new Error('x')), shuttingDown: false }, proc, exit, {
      log: () => undefined,
      warn: () => undefined,
      error: () => undefined,
    });
    proc.emit('SIGHUP');
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));
  });
});
