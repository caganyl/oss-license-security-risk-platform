/**
 * REQ-007 P-22 · Compiled `oss-risk` CLI for the sub-process tests.
 *
 * `npm run build` is not a test prerequisite (and `dist/` may be stale), so
 * the CLI is transpiled with `typescript` into a temp folder that mirrors the
 * repository layout (`<out>/src/cli/**`, `<out>/src/lib/*`, `<out>/package.json`),
 * like `integration/migrateTool.test.ts` does for the migrate tool. The
 * module graph is walked from `src/cli/index.ts` through relative imports
 * only; any other specifier than `node:*` is recorded (and refused by
 * `compileCli`) — the same graph backs the AC-P22-1 import boundary test.
 *
 * `index.js` resolves `package.json` as `path.join(__dirname, '..', '..')`,
 * which is `<out>` here and the repository root for `dist/cli/index.js`.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { REPO_ROOT } from './paths';

const IMPORT_RE = /(?:^|[\s;])(?:import|export)\s+(?:type\s+)?(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)/g;

export interface CliModuleGraph {
  /** Repository-relative POSIX paths of the TypeScript sources (entry first). */
  files: string[];
  /** Non-relative import specifiers per file (`node:*` included). */
  externalImports: Array<{ file: string; specifier: string }>;
}

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

/** Walks `src/cli/index.ts` and its relative imports (type-only imports included). */
export function cliModuleGraph(): CliModuleGraph {
  const files: string[] = [];
  const externalImports: CliModuleGraph['externalImports'] = [];
  const queue = ['src/cli/index.ts'];
  while (queue.length > 0) {
    const rel = queue.shift() as string;
    if (files.includes(rel)) continue;
    files.push(rel);
    const text = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
    for (const m of text.matchAll(IMPORT_RE)) {
      const spec = m[1] ?? m[2];
      if (spec.startsWith('.')) {
        const target = toPosix(path.posix.normalize(path.posix.join(path.posix.dirname(rel), spec)));
        const candidates = [`${target}.ts`, `${target}/index.ts`];
        const found = candidates.find((c) => fs.existsSync(path.join(REPO_ROOT, c)));
        if (!found) throw new Error(`${rel}: cannot resolve ${spec}`);
        queue.push(found);
      } else {
        externalImports.push({ file: rel, specifier: spec });
      }
    }
  }
  return { files, externalImports };
}

export interface CompiledCli {
  /** Temp folder that mirrors the repository layout. */
  root: string;
  /** `<root>/src/cli/index.js`. */
  indexJs: string;
}

/** Transpiles the CLI module graph to CommonJS under `outRoot` (created by the caller). */
export function compileCli(outRoot: string): CompiledCli {
  const graph = cliModuleGraph();
  const foreign = graph.externalImports.filter((i) => !i.specifier.startsWith('node:'));
  if (foreign.length > 0) {
    throw new Error(`CLI imports outside node:* built-ins: ${foreign.map((i) => `${i.file} -> ${i.specifier}`).join(', ')}`);
  }
  for (const rel of graph.files) {
    const source = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
    const out = ts.transpileModule(source, {
      fileName: path.basename(rel),
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    });
    const dest = path.join(outRoot, ...rel.replace(/\.ts$/, '.js').split('/'));
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, out.outputText);
  }
  fs.copyFileSync(path.join(REPO_ROOT, 'package.json'), path.join(outRoot, 'package.json'));
  return { root: outRoot, indexJs: path.join(outRoot, 'src', 'cli', 'index.js') };
}

/** Environment variables a child process may inherit (no OSS_RISK_*, proxy or developer settings). */
const INHERITED_ENV = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LANG'];

export function baseChildEnv(extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of INHERITED_ENV) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  for (const [k, v] of Object.entries(extra)) {
    if (v !== undefined) env[k] = v;
  }
  return env;
}

export interface CliRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Runs `node <indexJs> ...args` asynchronously (the in-process test server
 * must keep serving while the CLI waits), with an explicit environment.
 */
export function runCliProcess(
  indexJs: string,
  args: readonly string[],
  options: { env?: NodeJS.ProcessEnv; cwd?: string; nodeArgs?: readonly string[]; timeoutMs?: number } = {},
): Promise<CliRun> {
  return new Promise<CliRun>((resolve, reject) => {
    const child = spawn(process.execPath, [...(options.nodeArgs ?? []), indexJs, ...args], {
      cwd: options.cwd ?? path.dirname(indexJs),
      env: options.env ?? baseChildEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => out.push(c));
    child.stderr.on('data', (c: Buffer) => err.push(c));
    const timer = setTimeout(() => child.kill(), options.timeoutMs ?? 90_000);
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}
