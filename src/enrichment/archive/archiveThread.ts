/**
 * Main-thread side of the archive thread (REQ-004 AC-P15-4, AC-P15-10;
 * ADR-006 Karar 7).
 *
 * - One `Worker` per archive, at most `maxThreads` (2) at a time process-wide;
 *   `resourceLimits` 512/64/4 MiB, `env: {}` (source mode: only
 *   `DISABLE_V8_COMPILE_CACHE=1`), empty `argv`/`execArgv`.
 * - The verified archive bytes are transferred (no copy).
 * - 60 s timer and the enrichment signal both `terminate()` the thread; the
 *   `terminate()` promise is always awaited.
 * - The reply is re-validated here. Every failure (bad reply, `error`,
 *   message-less `exit`, `ERR_WORKER_OUT_OF_MEMORY`, timeout) is
 *   `processing_failed` and is never cached.
 *
 * Main thread only (imports `node:path` and `src/lib/threadBootstrap.ts`).
 */
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { threadEntry } from '../../lib/threadBootstrap';
import type { ArchiveKind } from './extract';
import type { ArchiveLimits, ExtractResult, LicenseFile } from './licenseFiles';
import type { ArchiveThreadData } from './thread';

export interface ArchiveThreadOptions {
  limits: ArchiveLimits;
  threadTimeoutMs: number;
  maxThreads: number;
  resourceLimits?: { maxOldGenerationSizeMb: number; maxYoungGenerationSizeMb: number; stackSizeMb: number };
  /** Test hook: thread script (compiled `.js`) instead of the default entry. */
  threadScript?: string;
}

export const ARCHIVE_THREAD_RESOURCE_LIMITS = Object.freeze({ maxOldGenerationSizeMb: 512, maxYoungGenerationSizeMb: 64, stackSizeMb: 4 });

export type ArchiveThreadOutcome =
  | { kind: 'ok'; result: ExtractResult }
  /** `processing_failed`; `code` is a fixed class (`OOM`, `CRASH`, `EXIT`, `TIMEOUT`, `BAD_RESULT`, `FAILED`). */
  | { kind: 'failed'; code: string }
  /** The signal aborted; the caller decides (budget vs job abort). */
  | { kind: 'aborted' };

const OUTCOMES: ReadonlySet<string> = new Set(['collected', 'no_license_file', 'unsupported_format', 'limit_exceeded']);
const DETAIL_RE = /^[a-z0-9_]{1,32}$/;

/** Structure and limit check of a thread reply (the thread is untrusted with respect to its limits). */
export function validateExtractResult(value: unknown, limits: ArchiveLimits): ExtractResult | null {
  if (typeof value !== 'object' || value === null) return null;
  const r = value as Record<string, unknown>;
  if (typeof r.outcome !== 'string' || !OUTCOMES.has(r.outcome)) return null;
  if (r.outcomeDetail !== null && (typeof r.outcomeDetail !== 'string' || !DETAIL_RE.test(r.outcomeDetail))) return null;
  if (!Array.isArray(r.licenseFiles) || r.licenseFiles.length > limits.maxFiles) return null;
  if (!Array.isArray(r.copyrightLines) || r.copyrightLines.length > 50 || !r.copyrightLines.every((l) => typeof l === 'string')) return null;
  const files: LicenseFile[] = [];
  let textBytes = 0;
  for (const item of r.licenseFiles as unknown[]) {
    if (typeof item !== 'object' || item === null) return null;
    const f = item as Record<string, unknown>;
    if (typeof f.path !== 'string' || f.path.length === 0 || f.path.length > 4096) return null;
    if (typeof f.text === 'string') {
      textBytes += Buffer.byteLength(f.text, 'utf8');
      files.push({ path: f.path, text: f.text });
    } else if (f.omitted === 'file_too_large' || f.omitted === 'package_text_limit') {
      files.push({ path: f.path, omitted: f.omitted });
    } else {
      return null;
    }
  }
  // Decoding may grow text (U+FFFD is 3 bytes for 1 invalid byte): allow 3x the raw cap.
  if (textBytes > limits.maxPackageTextBytes * 3) return null;
  if (r.outcome !== 'collected' && files.length > 0) return null;
  return {
    outcome: r.outcome as ExtractResult['outcome'],
    outcomeDetail: (r.outcomeDetail as string | null) ?? null,
    licenseFiles: files,
    copyrightLines: [...(r.copyrightLines as string[])],
  };
}

// Process-wide slot counter of archive threads (ADR-006 Karar 7).
let activeThreads = 0;
const waiting: Array<() => void> = [];

function acquireSlot(max: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(false);
  if (activeThreads < max) {
    activeThreads++;
    return Promise.resolve(true);
  }
  return new Promise<boolean>((resolve) => {
    const grant = () => {
      signal.removeEventListener('abort', onAbort);
      activeThreads++;
      resolve(true);
    };
    const onAbort = () => {
      const i = waiting.indexOf(grant);
      if (i !== -1) waiting.splice(i, 1);
      resolve(false);
    };
    waiting.push(grant);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

function releaseSlot(): void {
  activeThreads--;
  const next = waiting.shift();
  if (next) next();
}

/** An `ArrayBuffer` holding exactly `bytes` (copied when `bytes` is a view into a larger/pooled buffer). */
function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && bytes.buffer instanceof ArrayBuffer) {
    return bytes.buffer;
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

type RawOutcome =
  | { kind: 'message'; message: unknown }
  | { kind: 'error'; error: unknown }
  | { kind: 'exit'; code: number }
  | { kind: 'timeout' }
  | { kind: 'abort' };

/** Extracts the license files of one verified archive in a fresh thread. */
export async function runArchiveInThread(
  input: { kind: ArchiveKind; filename: string | null; bytes: Uint8Array },
  signal: AbortSignal,
  options: ArchiveThreadOptions,
): Promise<ArchiveThreadOutcome> {
  if (!(await acquireSlot(options.maxThreads, signal))) return { kind: 'aborted' };
  try {
    if (signal.aborted) return { kind: 'aborted' };
    const entry = options.threadScript
      ? { script: options.threadScript, eval: false, env: {} }
      : threadEntry(path.join(__dirname, 'thread.js'), path.join(__dirname, 'thread.ts'));
    const workerData: ArchiveThreadData = { kind: input.kind, filename: input.filename, limits: { ...options.limits } };
    const worker = new Worker(entry.script, {
      eval: entry.eval,
      workerData,
      resourceLimits: { ...(options.resourceLimits ?? ARCHIVE_THREAD_RESOURCE_LIMITS) },
      env: entry.env,
      argv: [],
      execArgv: [],
    });

    let timer: NodeJS.Timeout | undefined;
    let onAbort: (() => void) | undefined;
    const outcome = await new Promise<RawOutcome>((resolve) => {
      let settled = false;
      const settle = (value: RawOutcome) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      worker.on('message', (message: unknown) => settle({ kind: 'message', message }));
      worker.on('error', (error: unknown) => settle({ kind: 'error', error }));
      worker.on('exit', (code: number) => settle({ kind: 'exit', code }));
      timer = setTimeout(() => settle({ kind: 'timeout' }), options.threadTimeoutMs);
      onAbort = () => settle({ kind: 'abort' });
      signal.addEventListener('abort', onAbort, { once: true });
      const buffer = ownedArrayBuffer(input.bytes);
      worker.postMessage(buffer, [buffer]);
    });

    if (timer) clearTimeout(timer);
    if (onAbort) signal.removeEventListener('abort', onAbort);
    await worker.terminate();
    worker.removeAllListeners();

    switch (outcome.kind) {
      case 'abort':
        return { kind: 'aborted' };
      case 'timeout':
        return { kind: 'failed', code: 'TIMEOUT' };
      case 'exit':
        return { kind: 'failed', code: 'EXIT' };
      case 'error': {
        const code = (outcome.error as NodeJS.ErrnoException | null)?.code;
        return { kind: 'failed', code: code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'OOM' : 'CRASH' };
      }
      case 'message': {
        const message = outcome.message as { ok?: unknown; result?: unknown } | null;
        if (!message || message.ok !== true) return { kind: 'failed', code: 'FAILED' };
        const result = validateExtractResult(message.result, options.limits);
        return result === null ? { kind: 'failed', code: 'BAD_RESULT' } : { kind: 'ok', result };
      }
    }
  } finally {
    releaseSlot();
  }
}
