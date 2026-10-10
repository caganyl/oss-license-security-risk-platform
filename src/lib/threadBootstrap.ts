/**
 * Shared `worker_threads` entry selection (ADR-006 Karar 1, ADR-005 Karar 5
 * note): used by the parser thread (`src/scanner/parsers/threadParser.ts`)
 * and the archive thread (`src/enrichment/archive/archiveThread.ts`).
 *
 * Compiled builds (`dist/`) start the compiled `.js` entry with `env: {}`.
 * When the code runs from its `.ts` sources (`ts-node` dev scripts, Vitest)
 * there is no compiled entry; the thread then registers the `ts-node` dev
 * dependency itself (no `execArgv` needed) and loads the `.ts` entry.
 *
 * Main-thread side only: thread entry modules never import this file. Only
 * `node:path` is imported (no runtime module of `src/`).
 */
import path from 'node:path';

/**
 * Thread environment of the source-mode bootstrap. ts-node loads
 * `v8-compile-cache-lib`, which writes its cache under `os.tmpdir()`; with
 * `env: {}` Windows has no TEMP/TMP/SystemRoot, `os.tmpdir()` returns
 * `undefined\temp` and the cache lands in the working directory. Disabling
 * the cache is the narrowest fix: one non-secret flag, no inherited value.
 * Compiled builds keep `env: {}` (nothing there calls `os.tmpdir()`).
 */
export const SOURCE_MODE_THREAD_ENV: Readonly<Record<string, string>> = Object.freeze({ DISABLE_V8_COMPILE_CACHE: '1' });

/** How to start a thread: the `Worker` filename/code, its `eval` flag and its environment. */
export interface ThreadEntry {
  script: string;
  eval: boolean;
  env: Record<string, string>;
}

/** True when this module itself runs from its `.ts` source (never in `dist/`). */
export function isSourceMode(): boolean {
  return __filename.endsWith('.ts');
}

/** `ts-node` bootstrap code that loads `sourceTs` inside the thread. */
export function sourceModeBootstrap(sourceTs: string): string {
  let tsNode = 'ts-node';
  try {
    tsNode = require.resolve('ts-node');
  } catch {
    // Fall back to normal resolution from the working directory.
  }
  const entry = path.resolve(sourceTs);
  return `require(${JSON.stringify(tsNode)}).register({ transpileOnly: true });\nrequire(${JSON.stringify(entry)});`;
}

/**
 * Entry of a thread whose compiled script is `compiledJs` and whose source is
 * `sourceTs` (both absolute, usually next to the calling module).
 */
export function threadEntry(compiledJs: string, sourceTs: string): ThreadEntry {
  if (isSourceMode()) {
    return { script: sourceModeBootstrap(sourceTs), eval: true, env: { ...SOURCE_MODE_THREAD_ENV } };
  }
  return { script: compiledJs, eval: false, env: {} };
}
