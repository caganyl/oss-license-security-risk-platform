/**
 * Parser thread entry (REQ-003 AC-P10-14, ADR-005 Karar 5).
 *
 * Started by `threadParser.ts` with `env: {}` (no secrets), `resourceLimits`
 * and `workerData = { rootDir, ecosystems, scanId }`. Runs `parseManifests`
 * once, posts `{ ok: true, result, sideChannel }` (or `{ ok: false, error }`
 * for an unexpected internal error) and exits on its own.
 *
 * `sideChannel.npmIntegrity` (REQ-005 L-5, ADR-007 Karar 12) carries the npm
 * lockfile `integrity` values collected next to `result`; `result` itself is
 * the unchanged golden shape. Values are bounded by the collector (text,
 * ≤ 1024 SRI characters) and the list by the dependency count.
 */
import { isMainThread, parentPort, workerData } from 'node:worker_threads';
import type { SandboxScanResult } from '../../types/scan';
import { scrubRoot } from './common';
import { parseManifests } from './index';
import { IntegrityCollector, type LockIntegrityRecord } from './lockIntegrityValue';

export interface ParserThreadInput {
  rootDir: string;
  ecosystems: string[];
  scanId: string;
}

export interface ParserSideChannel {
  npmIntegrity: LockIntegrityRecord[];
}

export type ParserThreadResponse =
  | { ok: true; result: SandboxScanResult; sideChannel?: ParserSideChannel }
  | { ok: false; error: string };

function run(): void {
  if (isMainThread || !parentPort) return;
  const input = workerData as ParserThreadInput;
  let response: ParserThreadResponse;
  try {
    const integrityCollector = new IntegrityCollector();
    const result = parseManifests(input.rootDir, input.ecosystems, input.scanId, { integrityCollector });
    response = { ok: true, result, sideChannel: { npmIntegrity: integrityCollector.records.slice(0, result.dependencies.length) } };
  } catch (err) {
    const name = err instanceof Error ? err.name : 'Error';
    const message = err instanceof Error ? scrubRoot(err.message, input.rootDir) : '';
    response = { ok: false, error: `${name}: ${message}`.slice(0, 500) };
  }
  parentPort.postMessage(response);
}

run();
