/**
 * REQ-006 · AC-P20-16 NuGet integrity side channel through the parser thread
 * (ADR-008 Karar 6, D-129): `nugetIntegrity` is present only when non-empty,
 * is re-validated on the main thread, and the F4 reply shape is unchanged for
 * scans without NuGet. Probe scripts are written to a temp folder only.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { isNugetLockIntegrity } from '../../src/scanner/parsers/lockIntegrityValue';
import { runParserInThreadWithSideChannel, type ParserResourceLimits } from '../../src/scanner/parsers/threadParser';
import { sandboxRunnerConfig } from '../../src/scanner/sandbox/runner.config';
import { SAMPLE_SOLUTION, parseDotnet } from '../helpers/nugetGolden';
import { FORMATS_DIR } from '../helpers/parserGolden';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 60_000 });

const LIMITS: ParserResourceLimits = { ...sandboxRunnerConfig.parser.resourceLimits };
const VALID = `sha512-${'ABCDEFGHIJ'.repeat(8)}KLMNOP==`;
const VALID2 = `sha512-Z${'ABCDEFGHIJ'.repeat(8).slice(1)}KLMNOP==`;
let tmp = '';

const probe = (name: string, sideChannel: unknown, deps = 3): string => {
  const file = path.join(tmp, name);
  fs.writeFileSync(
    file,
    `const { parentPort, workerData } = require('node:worker_threads');
parentPort.postMessage({ ok: true, result: { scan_id: workerData.scanId, status: 'completed', total_deps: ${deps},
  dependencies: Array.from({ length: ${deps} }, () => ({})), scan_files: [], parse_errors: [] },
  sideChannel: ${JSON.stringify(sideChannel)} });`,
  );
  return file;
};

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-nuget-side-'));
});
afterAll(() => {
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

describe('AC-P20-16: real parser thread', () => {
  it('AC-P20-16: a dotnet scan returns validated nugetIntegrity records next to the unchanged result', async () => {
    const out = await runParserInThreadWithSideChannel(SAMPLE_SOLUTION, ['dotnet'], 'side-scan', undefined, { resourceLimits: LIMITS });
    expect(JSON.stringify(out.result)).toBe(JSON.stringify(parseDotnet(SAMPLE_SOLUTION, 'side-scan')));
    expect(out.lockIntegrity).toEqual([]);
    expect(out.nugetIntegrity?.length).toBeGreaterThan(0);
    expect(out.nugetIntegrity!.length).toBeLessThanOrEqual(out.result.dependencies.length);
    for (const r of out.nugetIntegrity!) expect(isNugetLockIntegrity(r.integrity)).toBe(true);
    expect(out.nugetIntegrity).toContainEqual({ manifestPath: 'src/App', name: 'Newtonsoft.Json', version: '13.0.3', integrity: VALID });
  });

  it('AC-P20-16 / AC-G-6: a scan without NuGet keeps the F4 reply shape (no nugetIntegrity key)', async () => {
    const out = await runParserInThreadWithSideChannel(path.join(FORMATS_DIR, 'npm-lock-v2'), ['nodejs', 'python'], 'f4-scan', undefined, { resourceLimits: LIMITS });
    expect(Object.keys(out).sort()).toEqual(['lockIntegrity', 'result']);
    const out2 = await runParserInThreadWithSideChannel(path.join(FORMATS_DIR, 'npm-lock-v2'), ['nodejs', 'python', 'dotnet'], 'f4-scan', undefined, { resourceLimits: LIMITS });
    expect(Object.keys(out2).sort()).toEqual(['lockIntegrity', 'result']);
  });
});

describe('AC-P20-16: main-thread re-validation of the thread reply', () => {
  const run = (script: string) => runParserInThreadWithSideChannel(tmp, ['dotnet'], 'probe-scan', undefined, { resourceLimits: LIMITS, threadScript: script });

  it('AC-P20-16: malformed records are dropped; the list is capped at the dependency count', async () => {
    const out = await run(
      probe('mixed.js', {
        npmIntegrity: [],
        nugetIntegrity: [
          { manifestPath: '.', name: 'A', version: '1.0.0', integrity: VALID },
          { manifestPath: '.', name: 'B', version: '1.0.0', integrity: 'sha512-short' },
          { manifestPath: 1, name: 'C', version: '1.0.0', integrity: VALID },
          { manifestPath: '.', name: 'D', version: '1.0.0', integrity: `sha256-${'A'.repeat(43)}=` },
          { manifestPath: '.', name: 'E', version: '1.0.0', integrity: VALID2 },
        ],
      }, 5),
    );
    expect(out.nugetIntegrity).toEqual([
      { manifestPath: '.', name: 'A', version: '1.0.0', integrity: VALID },
      { manifestPath: '.', name: 'E', version: '1.0.0', integrity: VALID2 },
    ]);
    const capped = await run(probe('capped.js', { npmIntegrity: [], nugetIntegrity: [{ manifestPath: '.', name: 'X', version: '1.0.0', integrity: 'bad' }, { manifestPath: '.', name: 'A', version: '1.0.0', integrity: VALID }] }, 1));
    expect(Object.keys(capped).sort()).toEqual(['lockIntegrity', 'result']);
  });

  it('AC-P20-16: an empty, missing or non-array nugetIntegrity adds no key', async () => {
    for (const [name, channel] of [
      ['empty.js', { npmIntegrity: [], nugetIntegrity: [] }],
      ['missing.js', { npmIntegrity: [] }],
      ['object.js', { npmIntegrity: [], nugetIntegrity: { 0: { manifestPath: '.', name: 'A', version: '1', integrity: VALID } } }],
    ] as const) {
      const out = await run(probe(name, channel));
      expect(Object.keys(out).sort(), name).toEqual(['lockIntegrity', 'result']);
    }
  });
});
