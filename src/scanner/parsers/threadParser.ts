/**
 * Main-thread side of the parser thread (REQ-003 AC-P10-14, ADR-005 Karar 5).
 *
 * One `Worker` per scan (no pool), started with `env: {}`, empty
 * `argv`/`execArgv` and memory/stack `resourceLimits`. The thread has no
 * timer of its own: the caller's `AbortSignal` (scan timeout, shutdown)
 * terminates it. The thread is always terminated and that promise awaited
 * before the call settles: on Windows open file handles would otherwise
 * block removing the temp workspace (ADR-005 uyarı 6).
 */
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import type { RunParserFn, SandboxScanResult } from '../../types/scan';
import type { ParserThreadInput, ParserThreadResponse } from './thread';

export interface ParserResourceLimits {
  maxOldGenerationSizeMb: number;
  maxYoungGenerationSizeMb: number;
  stackSizeMb: number;
}

export interface ThreadParserOptions {
  /** Memory/stack limits of the thread (values live in `runner.config.ts`). */
  resourceLimits: ParserResourceLimits;
  /**
   * Thread entry script. Default: compiled `thread.js` next to this module
   * (`dist/scanner/parsers/thread.js`); from `.ts` sources a `ts-node`
   * bootstrap of `thread.ts` (see `sourceModeBootstrap`). Thread behaviour
   * tests inject a plain CommonJS script here.
   */
  threadScript?: string;
}

/** The thread reported an unexpected internal error or an invalid result (permanent). */
export class ParserFailedError extends Error {
  readonly permanent = true;
  constructor(message: string) {
    super(message);
    this.name = 'ParserFailedError';
  }
}

/** The thread exceeded its heap limit (`ERR_WORKER_OUT_OF_MEMORY`; permanent). */
export class ParserMemoryLimitError extends Error {
  readonly permanent = true;
  constructor(limitMb: number) {
    super(`ayrıştırıcı bellek sınırını aştı (${limitMb} MB)`);
    this.name = 'ParserMemoryLimitError';
  }
}

/** The thread crashed or exited without a result (permanent). */
export class ParserCrashedError extends Error {
  readonly permanent = true;
  constructor(message: string) {
    super(message);
    this.name = 'ParserCrashedError';
  }
}

export function defaultThreadScript(): string {
  return path.join(__dirname, 'thread.js');
}

/**
 * When this module runs from its `.ts` source (`ts-node` dev scripts,
 * Vitest) there is no compiled `thread.js`; the thread then registers the
 * `ts-node` dev dependency itself (no `execArgv` needed) and loads
 * `thread.ts`. Compiled builds (`dist/`) never take this path.
 */
function sourceModeBootstrap(): string | null {
  if (!__filename.endsWith('.ts')) return null;
  let tsNode = 'ts-node';
  try {
    tsNode = require.resolve('ts-node');
  } catch {
    // Fall back to normal resolution from the working directory.
  }
  const entry = path.join(__dirname, 'thread.ts');
  return `require(${JSON.stringify(tsNode)}).register({ transpileOnly: true });\nrequire(${JSON.stringify(entry)});`;
}

type Outcome =
  | { kind: 'message'; message: unknown }
  | { kind: 'error'; error: unknown }
  | { kind: 'exit'; code: number }
  | { kind: 'abort' };

function abortReason(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const err = new Error('Ayrıştırma iptal edildi.');
  err.name = 'AbortError';
  return err;
}

function isValidResult(value: unknown, scanId: string): value is SandboxScanResult {
  if (typeof value !== 'object' || value === null) return false;
  const result = value as Partial<SandboxScanResult>;
  return (
    result.scan_id === scanId &&
    Array.isArray(result.dependencies) &&
    Array.isArray(result.scan_files) &&
    Array.isArray(result.parse_errors) &&
    typeof result.total_deps === 'number'
  );
}

function mapOutcome(outcome: Outcome, scanId: string, options: ThreadParserOptions): SandboxScanResult {
  switch (outcome.kind) {
    case 'message': {
      const message = outcome.message as Partial<ParserThreadResponse> | null;
      if (message && message.ok === true && isValidResult(message.result, scanId)) return message.result;
      if (message && message.ok === false) {
        throw new ParserFailedError(`Ayrıştırıcı beklenmeyen bir hatayla durdu (${String(message.error ?? '')}).`);
      }
      throw new ParserFailedError('Ayrıştırıcı geçersiz bir sonuç döndürdü.');
    }
    case 'error': {
      const code = (outcome.error as NodeJS.ErrnoException | null)?.code;
      if (code === 'ERR_WORKER_OUT_OF_MEMORY') {
        throw new ParserMemoryLimitError(options.resourceLimits.maxOldGenerationSizeMb);
      }
      // The error message may carry absolute paths (e.g. a missing script): only its kind is kept.
      const kind = typeof code === 'string' ? code : outcome.error instanceof Error ? outcome.error.name : 'Error';
      throw new ParserCrashedError(`Ayrıştırıcı iş parçacığı çöktü (${kind}).`);
    }
    case 'exit':
      throw new ParserCrashedError(`Ayrıştırıcı iş parçacığı sonuç vermeden çıktı (kod ${outcome.code}).`);
    case 'abort':
      throw new Error('unreachable: abort is handled by the caller');
  }
}

/** Runs `parseManifests` for one scan in a fresh thread. */
export async function runParserInThread(
  rootDir: string,
  ecosystems: string[],
  scanId: string,
  signal: AbortSignal | undefined,
  options: ThreadParserOptions,
): Promise<SandboxScanResult> {
  if (signal?.aborted) throw abortReason(signal);

  const workerData: ParserThreadInput = { rootDir, ecosystems: [...ecosystems], scanId };
  const bootstrap = options.threadScript ? null : sourceModeBootstrap();
  const worker = new Worker(bootstrap ?? options.threadScript ?? defaultThreadScript(), {
    eval: bootstrap !== null,
    workerData,
    resourceLimits: { ...options.resourceLimits },
    env: {},
    argv: [],
    execArgv: [],
  });

  let onAbort: (() => void) | undefined;
  const outcome = await new Promise<Outcome>((resolve) => {
    let settled = false;
    const settle = (value: Outcome) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    // Listeners stay registered until the thread is gone, so a late
    // 'error' after the result never becomes an unhandled event.
    worker.on('message', (message: unknown) => settle({ kind: 'message', message }));
    worker.on('error', (error: unknown) => settle({ kind: 'error', error }));
    worker.on('exit', (code: number) => settle({ kind: 'exit', code }));
    if (signal) {
      onAbort = () => settle({ kind: 'abort' });
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });

  if (signal && onAbort) signal.removeEventListener('abort', onAbort);
  await worker.terminate();
  worker.removeAllListeners();

  if (outcome.kind === 'abort') throw abortReason(signal as AbortSignal);
  return mapOutcome(outcome, scanId, options);
}

/** `RunParserFn` that parses each scan in its own `worker_threads` thread. */
export function createThreadParser(options: ThreadParserOptions): RunParserFn {
  return (workDir, ecosystems, scanId, signal) => runParserInThread(workDir, ecosystems, scanId, signal, options);
}
