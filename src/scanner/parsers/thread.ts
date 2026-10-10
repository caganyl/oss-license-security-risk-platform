/**
 * Parser thread entry (REQ-003 AC-P10-14, ADR-005 Karar 5).
 *
 * Started by `threadParser.ts` with `env: {}` (no secrets), `resourceLimits`
 * and `workerData = { rootDir, ecosystems, scanId }`. Runs `parseManifests`
 * once, posts `{ ok: true, result }` (or `{ ok: false, error }` for an
 * unexpected internal error) and exits on its own.
 */
import { isMainThread, parentPort, workerData } from 'node:worker_threads';
import type { SandboxScanResult } from '../../types/scan';
import { scrubRoot } from './common';
import { parseManifests } from './index';

export interface ParserThreadInput {
  rootDir: string;
  ecosystems: string[];
  scanId: string;
}

export type ParserThreadResponse = { ok: true; result: SandboxScanResult } | { ok: false; error: string };

function run(): void {
  if (isMainThread || !parentPort) return;
  const input = workerData as ParserThreadInput;
  let response: ParserThreadResponse;
  try {
    response = { ok: true, result: parseManifests(input.rootDir, input.ecosystems, input.scanId) };
  } catch (err) {
    const name = err instanceof Error ? err.name : 'Error';
    const message = err instanceof Error ? scrubRoot(err.message, input.rootDir) : '';
    response = { ok: false, error: `${name}: ${message}`.slice(0, 500) };
  }
  parentPort.postMessage(response);
}

run();
