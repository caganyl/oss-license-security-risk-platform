/**
 * REQ-003 · P-10 parser thread (AC-P10-14, ADR-005 Karar 5): threadParser.ts.
 *
 * Three kinds of thread script are used:
 *   - the default source-mode bootstrap (ts-node loads thread.ts; Vitest runs
 *     from sources) — normal run and the `undefined/` regression;
 *   - the real parsers transpiled with `typescript` into a temp folder
 *     (compiled `thread.js`, the production shape) — normal run and the
 *     memory limit with a large input;
 *   - plain CommonJS probe scripts written to a temp folder — abort,
 *     environment isolation, crash/failure mapping.
 * Nothing is written inside the repository.
 */
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import {
  ParserCrashedError,
  ParserFailedError,
  ParserMemoryLimitError,
  createThreadParser,
  defaultThreadScript,
  runParserInThread,
  type ParserResourceLimits,
} from '../../src/scanner/parsers/threadParser';
import { sandboxRunnerConfig } from '../../src/scanner/sandbox/runner.config';
import { FORMATS_DIR } from '../helpers/parserGolden';
import { REPO_ROOT } from '../helpers/paths';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 60_000 });

const LIMITS: ParserResourceLimits = { ...sandboxRunnerConfig.parser.resourceLimits };
const FIXTURE = path.join(FORMATS_DIR, 'npm-lock-v2');

let tmpBase = '';
let probeDir = '';
let compiledThread = '';
const undefinedDirs = () => [path.join(REPO_ROOT, 'undefined'), path.join(process.cwd(), 'undefined')];
let undefinedBefore: boolean[] = [];

/** Main-thread-only import of threadParser.ts (ADR-006 Karar 16; ADR-005 Karar 1 note). */
const THREAD_BOOTSTRAP = '../../lib/threadBootstrap';

/**
 * Transpiles src/scanner/parsers/*.ts to CommonJS in `outDir` (the production
 * layout `<out>/scanner/parsers`); `smol-toml` resolved from the repo. When
 * threadParser.ts imports `../../lib/threadBootstrap`, that file is compiled
 * to `<out>/lib/threadBootstrap.js`, so the relative require keeps working.
 */
function compileParsers(outDir: string): string {
  const srcDir = path.join(REPO_ROOT, 'src', 'scanner', 'parsers');
  const parsersOut = path.join(outDir, 'scanner', 'parsers');
  fs.mkdirSync(parsersOut, { recursive: true });
  const smolToml = createRequire(path.join(REPO_ROOT, 'package.json')).resolve('smol-toml');
  const transpile = (file: string) =>
    ts.transpileModule(fs.readFileSync(file, 'utf8'), {
      fileName: path.basename(file),
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    }).outputText;
  let needsBootstrap = false;
  for (const name of fs.readdirSync(srcDir).filter((n) => n.endsWith('.ts'))) {
    const outputText = transpile(path.join(srcDir, name));
    const requires = [...outputText.matchAll(/require\("([^"]+)"\)/g)].map((m) => m[1]);
    const unexpected = requires.filter(
      (r) => !r.startsWith('node:') && !r.startsWith('./') && r !== 'smol-toml' && !(name === 'threadParser.ts' && r === THREAD_BOOTSTRAP),
    );
    if (unexpected.length > 0) throw new Error(`${name}: unexpected runtime import(s) ${unexpected.join(', ')}`);
    if (requires.includes(THREAD_BOOTSTRAP)) needsBootstrap = true;
    const js = outputText.replace(/require\("smol-toml"\)/g, `require(${JSON.stringify(smolToml)})`);
    fs.writeFileSync(path.join(parsersOut, name.replace(/\.ts$/, '.js')), js);
  }
  if (needsBootstrap) {
    const bootstrapJs = transpile(path.join(REPO_ROOT, 'src', 'lib', 'threadBootstrap.ts'));
    const requires = [...bootstrapJs.matchAll(/require\("([^"]+)"\)/g)].map((m) => m[1]);
    if (requires.some((r) => !r.startsWith('node:'))) throw new Error(`threadBootstrap.ts: unexpected runtime import(s) ${requires.join(', ')}`);
    fs.mkdirSync(path.join(outDir, 'lib'), { recursive: true });
    fs.writeFileSync(path.join(outDir, 'lib', 'threadBootstrap.js'), bootstrapJs);
  }
  return path.join(parsersOut, 'thread.js');
}

const PROBES: Record<string, string> = {
  // Reports what the thread can see: environment, argv/execArgv, resource limits, input.
  'env-probe.js': `
const { parentPort, workerData, resourceLimits } = require('node:worker_threads');
const env = Object.keys(process.env);
parentPort.postMessage({ ok: true, result: {
  scan_id: workerData.scanId, status: 'completed', total_deps: 0, dependencies: [], scan_files: [],
  parse_errors: [{ ecosystem: 'probe', file: 'info', error: JSON.stringify({
    env, execArgv: process.execArgv, argv: process.argv.slice(2), resourceLimits, workerData }) }],
} });`,
  // Non-cooperative busy loop that keeps writing a heartbeat into the root.
  'hang.js': `
const fs = require('node:fs'); const path = require('node:path');
const { workerData } = require('node:worker_threads');
let n = 0;
for (;;) {
  fs.writeFileSync(path.join(workerData.rootDir, 'beat'), String(++n));
  const until = Date.now() + 10; while (Date.now() < until) { /* busy */ }
}`,
  'oom.js': `
const keep = [];
for (;;) keep.push(new Array(100000).fill({ x: Math.random() }));`,
  'fail.js': `
require('node:worker_threads').parentPort.postMessage({ ok: false, error: 'TypeError: boom' });`,
  'wrong-scan-id.js': `
require('node:worker_threads').parentPort.postMessage({ ok: true, result: {
  scan_id: 'someone-else', status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] } });`,
  'not-a-result.js': `
require('node:worker_threads').parentPort.postMessage({ ok: true, result: { scan_id: require('node:worker_threads').workerData.scanId } });`,
  'exit.js': `process.exit(3);`,
  'throw.js': `throw new Error('cannot open C:\\\\Users\\\\someone\\\\secret\\\\file');`,
};
const probe = (name: string) => path.join(probeDir, name);

beforeAll(() => {
  undefinedBefore = undefinedDirs().map((d) => fs.existsSync(d));
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p10-thread-'));
  probeDir = path.join(tmpBase, 'probes');
  fs.mkdirSync(probeDir);
  for (const [name, body] of Object.entries(PROBES)) fs.writeFileSync(probe(name), body);
  const compiledDir = path.join(tmpBase, 'compiled');
  fs.mkdirSync(compiledDir);
  compiledThread = compileParsers(compiledDir);
});

afterAll(() => {
  if (tmpBase) fs.rmSync(tmpBase, { recursive: true, force: true });
});

const expected = () => JSON.parse(JSON.stringify(parseManifests(FIXTURE, ['nodejs', 'python'], 'thread-scan')));

// ---------------------------------------------------------------------------
describe('AC-P10-14: normal run in a worker thread', () => {
  it('AC-P10-14: the configured limits are 512 MiB old generation (plus young/stack limits)', () => {
    expect(LIMITS).toEqual({ maxOldGenerationSizeMb: 512, maxYoungGenerationSizeMb: 64, stackSizeMb: 4 });
  });

  it('AC-P10-1 / AC-P10-14: default thread (source-mode bootstrap) returns exactly what parseManifests returns', async () => {
    const runParser = createThreadParser({ resourceLimits: LIMITS });
    const result = await runParser(FIXTURE, ['nodejs', 'python'], 'thread-scan');
    expect(result).toEqual(expected());
    expect(result.total_deps).toBeGreaterThan(0);
  });

  it('regression: the source-mode thread leaves no undefined/ folder in the repository or working directory', async () => {
    await createThreadParser({ resourceLimits: LIMITS })(FIXTURE, ['nodejs'], 'thread-scan');
    undefinedDirs().forEach((dir, i) => {
      if (!undefinedBefore[i]) expect(fs.existsSync(dir), dir).toBe(false);
    });
  });

  it('AC-P10-14: compiled thread.js (production shape) returns the same result; a live signal does not disturb it', async () => {
    const controller = new AbortController();
    const result = await runParserInThread(FIXTURE, ['nodejs', 'python'], 'thread-scan', controller.signal, {
      resourceLimits: LIMITS,
      threadScript: compiledThread,
    });
    expect(result).toEqual(expected());
  });

  it('defaultThreadScript() is thread.js next to threadParser', () => {
    const script = defaultThreadScript();
    expect(path.basename(script)).toBe('thread.js');
    expect(path.dirname(script)).toBe(path.join(REPO_ROOT, 'src', 'scanner', 'parsers'));
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-14: environment isolation (env: {})', () => {
  it('AC-P10-14: the thread sees none of the parent environment variables, no argv/execArgv; it gets the configured limits and only its input', async () => {
    const sentinel = 'OSSR_P10_THREAD_SENTINEL';
    const saved = process.env[sentinel];
    process.env[sentinel] = 'visible-in-parent';
    try {
      const result = await runParserInThread(FIXTURE, ['nodejs'], 'env-scan', undefined, {
        resourceLimits: LIMITS,
        threadScript: probe('env-probe.js'),
      });
      const info = JSON.parse(result.parse_errors[0].error) as {
        env: string[];
        execArgv: string[];
        argv: string[];
        resourceLimits: ParserResourceLimits;
        workerData: unknown;
      };
      expect(Object.keys(process.env).length).toBeGreaterThan(1);
      expect(info.env).toEqual([]);
      expect(info.env).not.toContain(sentinel);
      expect(info.execArgv).toEqual([]);
      expect(info.argv).toEqual([]);
      expect(info.resourceLimits).toEqual(expect.objectContaining(LIMITS));
      expect(info.workerData).toEqual({ rootDir: FIXTURE, ecosystems: ['nodejs'], scanId: 'env-scan' });
    } finally {
      if (saved === undefined) delete process.env[sentinel];
      else process.env[sentinel] = saved;
    }
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-14: cancellation through AbortSignal', () => {
  it('an already aborted signal rejects with its reason and starts no thread', async () => {
    const reason = new Error('scan timeout (pre-aborted)');
    const root = fs.mkdtempSync(path.join(tmpBase, 'pre-'));
    await expect(
      runParserInThread(root, ['nodejs'], 's', AbortSignal.abort(reason), { resourceLimits: LIMITS, threadScript: probe('hang.js') }),
    ).rejects.toBe(reason);
    await new Promise((r) => setTimeout(r, 200));
    expect(fs.existsSync(path.join(root, 'beat'))).toBe(false);
  });

  it('aborting a running, non-cooperative thread rejects with the reason and the thread is terminated', async () => {
    const root = fs.mkdtempSync(path.join(tmpBase, 'run-'));
    const controller = new AbortController();
    const reason = new Error('scan timeout');
    const pending = runParserInThread(root, ['nodejs'], 's', controller.signal, { resourceLimits: LIMITS, threadScript: probe('hang.js') });
    const beat = path.join(root, 'beat');
    const started = Date.now();
    while (!fs.existsSync(beat) && Date.now() - started < 20_000) await new Promise((r) => setTimeout(r, 20));
    expect(fs.existsSync(beat)).toBe(true);
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
    const first = fs.readFileSync(beat, 'utf8');
    await new Promise((r) => setTimeout(r, 300));
    expect(fs.readFileSync(beat, 'utf8')).toBe(first);
  });

  it('abort without an explicit reason rejects with an AbortError; AbortSignal.timeout rejects with a TimeoutError', async () => {
    const opts = { resourceLimits: LIMITS, threadScript: probe('hang.js') };
    const controller = new AbortController();
    const pending = runParserInThread(fs.mkdtempSync(path.join(tmpBase, 'ab-')), ['nodejs'], 's', controller.signal, opts);
    setTimeout(() => controller.abort(), 200);
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    await expect(
      runParserInThread(fs.mkdtempSync(path.join(tmpBase, 'to-')), ['nodejs'], 's', AbortSignal.timeout(300), opts),
    ).rejects.toMatchObject({ name: 'TimeoutError' });
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-14: failure mapping (all permanent)', () => {
  it('memory limit: a small heap limit and a large real input -> ParserMemoryLimitError (compiled real thread)', async () => {
    const root = fs.mkdtempSync(path.join(tmpBase, 'big-'));
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ dependencies: { 'pkg-0': '^1.0.0' } }));
    const entries: string[] = [];
    for (let i = 0; i < 250_000; i++) entries.push(`"node_modules/pkg-${i}":{"version":"1.0.${i}","license":"MIT","dev":true}`);
    const lock = `{"lockfileVersion":3,"packages":{${entries.join(',')}}}`;
    fs.writeFileSync(path.join(root, 'package-lock.json'), lock);
    expect(Buffer.byteLength(lock)).toBeLessThan(32 * 1024 * 1024); // under the per-file limit: the heap limit must act

    const limits = { maxOldGenerationSizeMb: 24, maxYoungGenerationSizeMb: 8, stackSizeMb: 4 };
    const err = await runParserInThread(root, ['nodejs'], 'oom-scan', undefined, { resourceLimits: limits, threadScript: compiledThread }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ParserMemoryLimitError);
    expect((err as ParserMemoryLimitError).permanent).toBe(true);
    expect((err as Error).message).toContain('24 MB');
  });

  it('memory limit: an allocating thread -> ParserMemoryLimitError with the configured limit in the message', async () => {
    const limits = { maxOldGenerationSizeMb: 32, maxYoungGenerationSizeMb: 8, stackSizeMb: 4 };
    const err = await runParserInThread(tmpBase, ['nodejs'], 's', undefined, { resourceLimits: limits, threadScript: probe('oom.js') }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ParserMemoryLimitError);
    expect((err as ParserMemoryLimitError).permanent).toBe(true);
    expect((err as Error).message).toBe('ayrıştırıcı bellek sınırını aştı (32 MB)');
  });

  it('missing thread script -> ParserCrashedError (permanent) without the absolute path in the message', async () => {
    const missing = path.join(tmpBase, 'does-not-exist', 'thread.js');
    const err = await runParserInThread(tmpBase, ['nodejs'], 's', undefined, { resourceLimits: LIMITS, threadScript: missing }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ParserCrashedError);
    expect((err as ParserCrashedError).permanent).toBe(true);
    expect((err as Error).message).not.toContain(tmpBase);
    expect((err as Error).message.toLowerCase()).not.toContain(os.tmpdir().toLowerCase());
  });

  it.each([
    ['throw.js', 'ParserCrashedError', ParserCrashedError],
    ['exit.js', 'ParserCrashedError', ParserCrashedError],
    ['fail.js', 'ParserFailedError', ParserFailedError],
    ['wrong-scan-id.js', 'ParserFailedError', ParserFailedError],
    ['not-a-result.js', 'ParserFailedError', ParserFailedError],
  ] as const)('%s -> %s (permanent)', async (script, _label, errorClass) => {
    const err = await runParserInThread(tmpBase, ['nodejs'], 'map-scan', undefined, { resourceLimits: LIMITS, threadScript: probe(script) }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(errorClass);
    expect((err as { permanent?: unknown }).permanent).toBe(true);
    expect((err as Error).message).not.toMatch(/secret/);
  });

  it('a crashed thread does not affect the next parse', async () => {
    await expect(
      runParserInThread(tmpBase, ['nodejs'], 's', undefined, { resourceLimits: LIMITS, threadScript: probe('throw.js') }),
    ).rejects.toBeInstanceOf(ParserCrashedError);
    const result = await runParserInThread(FIXTURE, ['nodejs', 'python'], 'thread-scan', undefined, {
      resourceLimits: LIMITS,
      threadScript: compiledThread,
    });
    expect(result).toEqual(expected());
  });
});
