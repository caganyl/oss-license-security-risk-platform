/**
 * REQ-007 P-22 · CLI transport and process boundary without a database
 * (contract 2.1, 3.1, 5.2; ADR-009 Karar 1–2):
 *
 * - `nodeRequest` against loopback servers: explicit Host, redirect not
 *   followed (trap server gets no connection), 32 MiB cap (declared and
 *   streamed), 30 s request time limit with fake timers.
 * - `main(deps)` with the real transport: a non-loopback `http:` address is
 *   refused with zero connection attempts (network guard record stays empty).
 * - The compiled CLI as a real `node` process (`helpers/cliBuild.ts`):
 *   `HTTP(S)_PROXY` + `NODE_USE_ENV_PROXY=1` are ignored, `.env` in the
 *   working folder is not read, no module outside the CLI graph is loaded
 *   (no `pg`/`express`/`dotenv`/`exceljs`/`pdfkit`), `--version`/`--help`,
 *   one valid JSON object per exit code, key never printed.
 */
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { MAX_BODY_BYTES, REQUEST_TIMEOUT_MS, TransportError, nodeRequest } from '../../src/cli/client';
import { resolveTarget } from '../../src/cli/config';
import { main } from '../../src/cli/main';
import { baseChildEnv, cliModuleGraph, compileCli, runCliProcess, type CliRun } from '../helpers/cliBuild';
import { FakeApi, PROJECT_ID, finding, makeApiKey, makeDeps, serveFakeApi, startTrap, type FakeApiServer } from '../helpers/cliFakes';
import { parseSingleJson, validateCliJson } from '../helpers/cliJsonSchema';
import { REPO_ROOT } from '../helpers/paths';
import { takeNetworkViolations } from '../setup/networkGuard';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 60_000 });

const KEY = makeApiKey();
let tmpBase = '';

beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-cli-'));
});
afterAll(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

type RawHandler = (req: http.IncomingMessage, res: http.ServerResponse) => void;
const servers: http.Server[] = [];
afterEach(async () => {
  vi.useRealTimers();
  for (const s of servers.splice(0)) {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
});

async function rawServer(handler: RawHandler): Promise<{ port: number; requests: http.IncomingMessage[] }> {
  const requests: http.IncomingMessage[] = [];
  const server = http.createServer((req, res) => {
    requests.push(req);
    handler(req, res);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: (server.address() as AddressInfo).port, requests };
}

/** Source text without block and line comments (rough; enough for these keyword checks). */
const codeOnly = (text: string): string => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const GET = (p: string) => ({ method: 'GET' as const, path: p, headers: { Accept: 'application/json' }, body: null });

describe('AC-P22-4 / AC-P22-18: nodeRequest against loopback servers', () => {
  it('AC-P22-4: explicit Host header <hostname>:<port> for 127.0.0.1 and localhost', async () => {
    const srv = await rawServer((_q, s) => s.end('{}'));
    for (const host of ['127.0.0.1', 'localhost']) {
      const target = resolveTarget(`http://${host}:${srv.port}`, {}, 'scan');
      const res = await nodeRequest(target, { ...GET('/x'), headers: { Host: target.hostHeader! } });
      expect(res.status).toBe(200);
    }
    expect(srv.requests.map((r) => r.headers.host)).toEqual([`127.0.0.1:${srv.port}`, `localhost:${srv.port}`]);
  });

  it('AC-P22-4: 302 is returned as is; the Location target gets no connection', async () => {
    const trap = await startTrap();
    try {
      const srv = await rawServer((_q, s) => {
        s.writeHead(302, { Location: `${trap.origin}/stolen` });
        s.end();
      });
      const res = await nodeRequest(resolveTarget(`http://127.0.0.1:${srv.port}`, {}, 'scan'), GET('/api/projects'));
      expect(res.status).toBe(302);
      await new Promise((r) => setTimeout(r, 100));
      expect(trap.connections).toBe(0);
    } finally {
      await trap.close();
    }
  });

  it('AC-P22-18: declared Content-Length above 32 MiB -> too_large without reading the body', async () => {
    const srv = await rawServer((_q, s) => {
      s.writeHead(200, { 'Content-Length': String(MAX_BODY_BYTES + 1), 'Content-Type': 'application/json' });
      s.write('[');
    });
    await expect(nodeRequest(resolveTarget(`http://127.0.0.1:${srv.port}`, {}, 'scan'), GET('/f'))).rejects.toMatchObject({ kind: 'too_large' });
  });

  it('AC-P22-18: streamed (chunked) body above 32 MiB -> too_large; exactly 32 MiB is accepted', async () => {
    const chunk = Buffer.alloc(1024 * 1024, 0x61);
    const srv = await rawServer((q, s) => {
      const total = q.url === '/big' ? MAX_BODY_BYTES + 1 : MAX_BODY_BYTES;
      s.writeHead(200, { 'Content-Type': 'application/json' });
      let sent = 0;
      const pump = (): void => {
        while (sent < total) {
          const n = Math.min(chunk.length, total - sent);
          sent += n;
          if (!s.write(chunk.subarray(0, n))) {
            s.once('drain', pump);
            return;
          }
        }
        s.end();
      };
      s.on('error', () => undefined);
      pump();
    });
    const target = resolveTarget(`http://127.0.0.1:${srv.port}`, {}, 'scan');
    await expect(nodeRequest(target, GET('/big'))).rejects.toMatchObject({ kind: 'too_large' });
    const ok = await nodeRequest(target, GET('/exact'));
    expect(ok.body.length).toBe(MAX_BODY_BYTES);
  });

  it('AC-P22-18: 30 s request time limit (fake timers): pending at 29 999 ms, TransportError timeout at 30 000 ms', async () => {
    const srv = await rawServer(() => undefined); // never answers
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const p = nodeRequest(resolveTarget(`http://127.0.0.1:${srv.port}`, {}, 'scan'), GET('/hang'));
    let settled: unknown = 'pending';
    p.then(
      () => (settled = 'resolved'),
      (e: unknown) => (settled = e),
    );
    // Only setTimeout/clearTimeout are faked: wait for the real socket I/O with setImmediate (≤ 10 s wall clock).
    const deadline = Date.now() + 10_000;
    while (srv.requests.length === 0 && Date.now() < deadline) await new Promise((r) => setImmediate(r));
    expect(srv.requests).toHaveLength(1);
    expect(REQUEST_TIMEOUT_MS).toBe(30_000);
    vi.advanceTimersByTime(29_999);
    await new Promise((r) => setImmediate(r));
    expect(settled).toBe('pending');
    vi.advanceTimersByTime(1);
    await expect(p).rejects.toBeInstanceOf(TransportError);
    expect((settled as TransportError).kind).toBe('timeout');
  });
});

describe('AC-P22-4 / AC-P22-12: main() with the real transport', () => {
  it('AC-P22-4: http://example.com -> 2 and zero connection attempts (network guard has no record)', async () => {
    takeNetworkViolations();
    for (const argv of [
      ['scan', '--project', 'demo', '--url', 'http://example.com'],
      ['bootstrap', '--new-database', '--key-file', path.join(tmpBase, 'never.key'), '--url', 'http://example.com'],
    ]) {
      const deps = makeDeps(argv, new FakeApi(), { env: { OSS_RISK_API_KEY: KEY.key }, request: nodeRequest });
      expect(await main(deps)).toBe(2);
    }
    expect(takeNetworkViolations()).toEqual([]);
    expect(fs.existsSync(path.join(tmpBase, 'never.key'))).toBe(false);
  });

  it('AC-P22-12: full scan over loopback HTTP -> 0; 302 on the project list -> 3 and the redirect target is never contacted', async () => {
    const api = new FakeApi();
    const server = await serveFakeApi(api);
    const trap = await startTrap();
    try {
      const deps = makeDeps(['scan', '--project', 'demo', '--url', server.origin], api, { env: { OSS_RISK_API_KEY: KEY.key }, request: nodeRequest });
      expect(await main(deps)).toBe(0);
      expect(server.hosts.every((h) => h === `127.0.0.1:${server.port}`)).toBe(true);
      api.on('GET', /^\/api\/projects$/, () => ({ status: 302, headers: { Location: `${trap.origin}/x` } }));
      const again = makeDeps(['scan', '--project', 'demo', '--url', server.origin], api, { env: { OSS_RISK_API_KEY: KEY.key }, request: nodeRequest });
      expect(await main(again)).toBe(3);
      expect(again.err.text()).toContain('server responded with a redirect; not followed');
      await new Promise((r) => setTimeout(r, 100));
      expect(trap.connections).toBe(0);
    } finally {
      await trap.close();
      await server.close();
    }
  });
});

describe('AC-P22-1 / ADR-009 Karar 1: entry point and import boundary (static)', () => {
  it('AC-P22-1: package.json bin, shebang first line, no process.exit() in src/cli', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    expect(pkg.bin).toEqual({ 'oss-risk': 'dist/cli/index.js' });
    expect(fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli', 'index.ts'), 'utf8').split(/\r?\n/)[0]).toBe('#!/usr/bin/env node');
    for (const rel of cliModuleGraph().files) {
      expect(codeOnly(fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8')), rel).not.toMatch(/process\.exit\(/);
    }
  });

  it('AC-P22-1: module graph = src/cli/** + src/lib/outputText.ts + src/lib/textSanitize.ts; only node:* built-ins outside', () => {
    const graph = cliModuleGraph();
    for (const f of graph.files) {
      expect(f.startsWith('src/cli/') || f === 'src/lib/outputText.ts' || f === 'src/lib/textSanitize.ts', f).toBe(true);
    }
    expect(graph.files).toContain('src/lib/outputText.ts');
    expect(graph.externalImports.filter((i) => !i.specifier.startsWith('node:'))).toEqual([]);
    // Every file under src/cli belongs to the graph (no stray module that could import something else).
    const all: string[] = [];
    const walk = (dir: string): void => {
      for (const e of fs.readdirSync(path.join(REPO_ROOT, dir), { withFileTypes: true })) {
        const rel = `${dir}/${e.name}`;
        if (e.isDirectory()) walk(rel);
        else if (rel.endsWith('.ts')) all.push(rel);
      }
    };
    walk('src/cli');
    expect(all.filter((f) => !graph.files.includes(f))).toEqual([]);
  });

  it('AC-P22-1: the CLI sources do not use fetch, the global agent or NODE_TLS_REJECT_UNAUTHORIZED', () => {
    for (const rel of cliModuleGraph().files) {
      const text = codeOnly(fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8'));
      expect(text, rel).not.toMatch(/\bfetch\(|globalAgent|rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|dotenv/);
    }
  });
});

describe('AC-P22-1 / AC-P22-2 / AC-P22-4 / AC-G-8: compiled CLI as a real node process', () => {
  let cli = '';
  let api: FakeApi;
  let server: FakeApiServer;
  const allOutput: string[] = [];

  beforeAll(async () => {
    cli = compileCli(fs.mkdtempSync(path.join(tmpBase, 'compiled-'))).indexJs;
    api = new FakeApi();
    server = await serveFakeApi(api);
  });
  afterAll(async () => {
    await server?.close();
    const text = allOutput.join('\n');
    expect(text).not.toContain(KEY.key);
    expect(text).not.toContain(KEY.secret);
    expect(text).not.toContain('[redacted]');
  });

  async function cliRun(args: string[], env: Record<string, string> = {}, cwd?: string, nodeArgs?: string[]): Promise<CliRun> {
    const r = await runCliProcess(cli, args, { env: baseChildEnv(env), cwd, nodeArgs });
    allOutput.push(r.stdout, r.stderr);
    expect(r.stdout + r.stderr).not.toContain(KEY.secret);
    return r;
  }

  it('AC-P22-2: --version prints the package.json version; --help prints usage; both exit 0', async () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    const v = await cliRun(['--version']);
    expect(v).toMatchObject({ code: 0, stdout: `${pkg.version}\n`, stderr: '' });
    expect(pkg.version).toBe('1.0.0');
    const h = await cliRun(['scan', '-h']);
    expect(h.code).toBe(0);
    expect(h.stdout).toMatch(/^Usage: oss-risk scan /);
  });

  it('AC-P22-4: HTTP_PROXY/HTTPS_PROXY/NODE_USE_ENV_PROXY point at a trap -> scan still talks directly; trap gets 0 connections', async () => {
    const trap = await startTrap();
    try {
      const proxyEnv = {
        HTTP_PROXY: trap.origin,
        HTTPS_PROXY: trap.origin,
        http_proxy: trap.origin,
        https_proxy: trap.origin,
        ALL_PROXY: trap.origin,
        NODE_USE_ENV_PROXY: '1',
        NO_PROXY: '',
      };
      const before = api.requests.length;
      const ok = await cliRun(['scan', '--project', 'demo', '--url', server.origin], { ...proxyEnv, OSS_RISK_API_KEY: KEY.key });
      expect(ok.code).toBe(0);
      expect(api.requests.length).toBeGreaterThan(before);
      const refused = await cliRun(['scan', '--project', 'demo', '--url', 'http://example.com'], { ...proxyEnv, OSS_RISK_API_KEY: KEY.key });
      expect(refused.code).toBe(2);
      // Node 22 prints its own "[UNDICI-EHPA] EnvHttpProxyAgent is experimental"
      // process warning when NODE_USE_ENV_PROXY is set (Node 26 does not); that is
      // the runtime, not CLI output, so it is dropped before the exact comparison.
      const cliStderr = refused.stderr
        .split('\n')
        .filter((l) => !/^\(node:\d+\) /.test(l) && !l.startsWith('(Use `node --trace-warnings'))
        .join('\n');
      expect(cliStderr).toBe('oss-risk: error: a non-loopback server address must use https\n');
      await new Promise((r) => setTimeout(r, 100));
      expect(trap.connections).toBe(0);
    } finally {
      await trap.close();
    }
  });

  it('AC-P22-1: a .env file in the working folder is not read (key and URL from .env ignored) -> 2, no request', async () => {
    const cwd = fs.mkdtempSync(path.join(tmpBase, 'dotenv-'));
    fs.writeFileSync(path.join(cwd, '.env'), `OSS_RISK_API_KEY=${KEY.key}\nOSS_RISK_URL=${server.origin}\n`);
    const before = api.requests.length;
    const r = await cliRun(['scan', '--project', 'demo'], {}, cwd);
    expect(r.code).toBe(2);
    expect(r.stderr).toBe('oss-risk: error: set exactly one of OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE\n');
    expect(api.requests.length).toBe(before);
  });

  it('AC-P22-1: loaded modules are only the compiled CLI files (no pg, express, dotenv, exceljs, pdfkit, nothing from node_modules)', async () => {
    const dir = fs.mkdtempSync(path.join(tmpBase, 'preload-'));
    const report = path.join(dir, 'modules.json');
    const preload = path.join(dir, 'preload.js');
    fs.writeFileSync(
      preload,
      `const fs = require('node:fs');\nprocess.on('exit', () => fs.writeFileSync(${JSON.stringify(report)}, JSON.stringify(Object.keys(require.cache))));\n`,
    );
    const r = await cliRun(['scan', '--project', 'demo', '--url', server.origin], { OSS_RISK_API_KEY: KEY.key }, undefined, ['--require', preload]);
    expect(r.code).toBe(0);
    const loaded = JSON.parse(fs.readFileSync(report, 'utf8')) as string[];
    const cliRoot = path.resolve(cli, '..', '..', '..');
    const foreign = loaded.filter((m) => m !== preload && !path.resolve(m).startsWith(cliRoot + path.sep));
    expect(foreign).toEqual([]);
    expect(loaded.some((m) => /[\\/]node_modules[\\/]/.test(m))).toBe(false);
    expect(loaded.some((m) => m.endsWith(path.join('src', 'cli', 'commands', 'scan.js')))).toBe(true);
  });

  it('AC-P22-15 / AC-P22-12: one valid JSON object (single trailing newline, empty stderr) for exit codes 0–5', async () => {
    const scenarios: Array<[number, () => void]> = [
      [0, () => undefined],
      [1, () => (api.findings = [finding({ severity: 'critical' })])],
      [5, () => (api.vulnStatus = 'unavailable')],
      [3, () => (api.scanStatuses = ['failed'])],
      [4, () => api.on('GET', /^\/api\/projects$/, () => ({ status: 401, body: { code: 'unauthenticated', message: 'x', error: 'x' } }))],
    ];
    for (const [exit, arrange] of scenarios) {
      api = new FakeApi();
      arrange();
      await server.close();
      server = await serveFakeApi(api);
      const r = await cliRun(['scan', '--project', 'demo', '--url', server.origin, '--format', 'json'], { OSS_RISK_API_KEY: KEY.key });
      expect(r.code, `exit ${exit}: ${r.stdout}`).toBe(exit);
      expect(r.stderr).toBe('');
      const json = parseSingleJson(r.stdout) as { exitCode: number; project: { id: string } | null };
      expect(validateCliJson(json)).toEqual([]);
      expect(json.exitCode).toBe(exit);
      if (exit !== 4) expect(json.project?.id).toBe(PROJECT_ID);
    }
    const usage = await cliRun(['scan', '--format', 'json', '--project', 'demo', '--timeout', '3'], { OSS_RISK_API_KEY: KEY.key });
    expect(usage.code).toBe(2);
    expect(validateCliJson(parseSingleJson(usage.stdout))).toEqual([]);
  });
});
