/**
 * REQ-007 P-22 · End to end: the compiled `oss-risk` CLI as a real `node`
 * process against the real server (`listenApp`, embedded PostgreSQL), with
 * the scan worker driven by the test (`ScanWorker.runOnce`, injected parser
 * result, no network). Contract section 11 "Uçtan uca".
 *
 * Order matters inside the file (one database): `bootstrap --new-database`
 * initialises the empty database first and its key file is used by every
 * `scan` scenario afterwards.
 *
 * Every CLI run is checked for AC-G-8 (no key, no secret part, no 43-char
 * base64url run such as the bootstrap password or the session token); the
 * server's console output is captured and checked for the key as well.
 */
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createApp, listenApp } from '../../src/app';
import { systemClock } from '../../src/lib/clock';
import { ScanWorker } from '../../src/scanner/worker';
import type { RunParserFn, SandboxScanResult } from '../../src/types/scan';
import type { VulnerabilityClient } from '../../src/vulnerability/client';
import { baseChildEnv, compileCli, runCliProcess, type CliRun } from '../helpers/cliBuild';
import { makeApiKey, startTrap } from '../helpers/cliFakes';
import { parseSingleJson, validateCliJson } from '../helpers/cliJsonSchema';
import { useTestDatabase } from '../helpers/db';
import { makeF4Lookup } from '../helpers/f4Seed';
import { API_KEY_RE } from '../helpers/http';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64URL_43 = /[A-Za-z0-9_-]{43}/;

let tmp = '';
let roots = '';
let selfDir = '';
let cli = '';
let server: http.Server;
let origin = '';
let serverRequests = 0;
let keyFile = '';
let apiKey = '';
let projectId = '';
const consoleLines: string[] = [];
const allOutput: string[] = [];
const clients: VulnerabilityClient[] = [];
const workerLogs: string[] = [];

type Dep = SandboxScanResult['dependencies'][number];
const npmDep = (name: string, version: string, licenses: string[]): Dep =>
  ({ ecosystem: 'nodejs', name, version, purl: `pkg:npm/${name}@${version}`, scope: 'direct', licenses, manifest_file: 'package-lock.json', manifest_path: '.' }) as Dep;
/** `left-pad` has no license -> NOASSERTION `unknown` license finding (level high); `clean` is MIT. */
const DEPS: Dep[] = [npmDep('left-pad', '1.3.0', []), npmDep('clean', '2.0.0', ['MIT'])];
const runParser: RunParserFn = async (_dir, _eco, scanId) => ({ scan_id: scanId, status: 'completed', total_deps: DEPS.length, dependencies: DEPS, scan_files: [], parse_errors: [] });

beforeAll(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-cli-e2e-'));
  roots = path.join(tmp, 'roots');
  selfDir = path.join(roots, 'self');
  fs.mkdirSync(selfDir, { recursive: true });
  fs.mkdirSync(path.join(tmp, 'outside'));
  cli = compileCli(path.join(tmp, 'compiled')).indexJs;
  for (const m of ['log', 'warn', 'error', 'info'] as const) {
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
      consoleLines.push(a.map(String).join(' '));
    });
  }
  server = await listenApp({ db: db.pool, port: 0, host: '127.0.0.1', scanRoots: [roots] }, {});
  server.on('request', () => {
    serverRequests++;
  });
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  keyFile = path.join(tmp, 'ci.key');
});

afterAll(async () => {
  for (const c of clients.splice(0)) c.close();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  vi.restoreAllMocks();
  if (apiKey) {
    const everything = [...allOutput, ...consoleLines, ...workerLogs].join('\n');
    expect(everything).not.toContain(apiKey);
    expect(everything).not.toContain(apiKey.slice(-43));
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

function checkSecrets(r: CliRun): void {
  const text = r.stdout + r.stderr;
  allOutput.push(text);
  if (apiKey) {
    expect(text).not.toContain(apiKey);
    expect(text).not.toContain(apiKey.slice(-43));
  }
  expect(text).not.toMatch(B64URL_43);
  expect(text).not.toContain('[redacted]');
}

async function cliRun(args: string[], env: Record<string, string> = {}): Promise<CliRun> {
  const r = await runCliProcess(cli, args, { env: baseChildEnv(env), cwd: tmp });
  checkSecrets(r);
  return r;
}

/**
 * Runs the CLI while the test drives a scan worker (`runOnce` every 50 ms)
 * until the process exits. `lookup`: 'disabled' -> `vulnerability_data_status`
 * = disabled; 'none' -> no engine, the status stays NULL (`not_checked`).
 */
async function scanWithWorker(args: string[], lookup: 'disabled' | 'none', env: Record<string, string> = {}): Promise<CliRun> {
  const worker = new ScanWorker({
    db: db.pool,
    tmpRoot: tmp,
    scanRoots: [roots],
    runParser,
    runId: `cli-e2e-${Math.random().toString(36).slice(2)}`,
    cloneRepo: async () => {
      throw new Error('no clone in this test');
    },
    gitVersion: null,
    logger: { log: (...a: unknown[]) => workerLogs.push(a.join(' ')), warn: (...a: unknown[]) => workerLogs.push(a.join(' ')), error: (...a: unknown[]) => workerLogs.push(a.join(' ')) },
    ...(lookup === 'disabled'
      ? { vulnerabilityLookup: makeF4Lookup(db, 'http://127.0.0.1:9', systemClock, workerLogs, clients, { lookupEnabled: false, recheckEnabled: false }) }
      : {}),
  });
  let done = false;
  const child = cliRun(args, { OSS_RISK_API_KEY_FILE: keyFile, ...env }).finally(() => {
    done = true;
  });
  while (!done) {
    await worker.runOnce();
    await new Promise((r) => setTimeout(r, 50));
  }
  return child;
}

const latestScan = async () =>
  (await db.query<{ id: string; status: string; vds: string | null }>(
    `SELECT id::text AS id, status::text AS status, vulnerability_data_status AS vds FROM scans WHERE project_id = $1 ORDER BY created_at DESC LIMIT 1`,
    [projectId],
  ))[0];

describe('AC-P22-17: bootstrap --new-database against the real server (empty database)', () => {
  it('AC-P22-17: without --new-database -> 2, zero requests, no file', async () => {
    const before = serverRequests;
    const r = await cliRun(['bootstrap', '--key-file', keyFile, '--url', origin]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('bootstrap requires --new-database');
    expect(serverRequests).toBe(before);
    expect(fs.existsSync(keyFile)).toBe(false);
  });

  it('AC-P22-17: non-loopback address -> 2, zero requests, no file', async () => {
    const before = serverRequests;
    const r = await cliRun(['bootstrap', '--new-database', '--key-file', keyFile, '--url', 'https://oss-risk.example.test']);
    expect(r.code).toBe(2);
    expect(serverRequests).toBe(before);
    expect(fs.existsSync(keyFile)).toBe(false);
  });

  it('AC-P22-17: empty database -> 0; key file holds only the key (no newline, 0600 on POSIX); project created from the absolute path', async () => {
    const r = await cliRun(['bootstrap', '--new-database', '--key-file', keyFile, '--url', origin, '--project-name', 'e2e-self', '--project-path', selfDir]);
    expect(r.code, r.stderr).toBe(0);
    apiKey = fs.readFileSync(keyFile, 'utf8');
    expect(apiKey).toMatch(API_KEY_RE);
    expect(apiKey.endsWith('\n')).toBe(false);
    if (process.platform !== 'win32') expect(fs.statSync(keyFile).mode & 0o077).toBe(0);
    const lines = r.stdout.split('\n');
    expect(lines[0]).toBe(`API key written to ${keyFile}`);
    expect(lines[1]).toMatch(/^Project ID: [0-9a-f-]{36}$/);
    expect(lines.slice(2)).toEqual(['']);
    projectId = lines[1].slice('Project ID: '.length);
    expect(projectId).toMatch(UUID_RE);
    const [p] = await db.query<{ name: string; repo_url: string }>(`SELECT name, repo_url FROM projects WHERE id = $1`, [projectId]);
    expect(p.name).toBe('e2e-self');
    expect(path.resolve(p.repo_url)).toBe(path.resolve(selfDir));
    expect(r.stderr).toBe(`oss-risk: initialising server ${origin}\n`);
    // The session was logged out: no active session row remains.
    expect(await db.query(`SELECT 1 FROM sessions WHERE expires_at > NOW()`)).toHaveLength(0);
  });

  it('AC-P22-17: database already initialised -> 4 ("database already initialised …"), no key file created', async () => {
    const second = path.join(tmp, 'second.key');
    const r = await cliRun(['bootstrap', '--new-database', '--key-file', second, '--url', origin]);
    expect(r.code).toBe(4);
    expect(r.stderr).toContain('oss-risk: error: database already initialised; bootstrap only works on an empty database\n');
    expect(fs.existsSync(second)).toBe(false);
  });

  it('AC-P22-17: existing key file -> 2, zero requests, file unchanged', async () => {
    const before = serverRequests;
    const r = await cliRun(['bootstrap', '--new-database', '--key-file', keyFile, '--url', origin]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('key file already exists');
    expect(serverRequests).toBe(before);
    expect(fs.readFileSync(keyFile, 'utf8')).toBe(apiKey);
  });
});

describe('AC-P22-11 / AC-P22-12: scan end to end (compiled CLI, real server, worker driven by the test)', () => {
  it('AC-P22-11: open unknown-license (high) finding -> --fail-on high exits 1; default threshold also 1; disabled warning', async () => {
    const r = await scanWithWorker(['scan', '--project', 'e2e-self', '--url', origin, '--fail-on', 'high'], 'disabled');
    expect(r.code, r.stderr).toBe(1);
    expect(r.stdout).toMatch(/^ {2}left-pad@1\.3\.0 {2}license {2}high {2}\S+$/m);
    expect(r.stdout).toContain('Vulnerability data: disabled\n');
    expect(r.stdout.trimEnd().split('\n').at(-1)).toBe('Result: FAIL');
    expect(r.stderr).toContain('oss-risk: warning: vulnerability lookup is disabled on the server; security findings were not checked\n');
    expect((await latestScan()).status).toBe('completed');
    const dflt = await scanWithWorker(['scan', '--project', 'e2e-self', '--url', origin], 'disabled');
    expect(dflt.code).toBe(1);
    expect(dflt.stdout).toContain('Fail on: high\n');
  });

  it('AC-P22-11: the finding marked false_positive -> new scan carries the decision -> 0', async () => {
    const scan = await latestScan();
    const [f] = await db.query<{ id: string }>(
      `SELECT f.id::text AS id FROM findings f WHERE f.scan_id = $1 AND f.finding_type = 'license' AND f.status = 'open'`,
      [scan.id],
    );
    expect(f).toBeDefined();
    const res = await fetch(`${origin}/api/findings/${f.id}/false-positive`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes: 'QA: not a real risk (REQ-007 AC-P22-11)' }),
    });
    expect(res.status, await res.clone().text()).toBeLessThan(300);
    const r = await scanWithWorker(['scan', '--project', 'e2e-self', '--url', origin, '--fail-on', 'high'], 'disabled');
    expect(r.code, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toContain('Findings at or above high: 0\n');
    expect(r.stdout.trimEnd().split('\n').at(-1)).toBe('Result: PASS');
    const [carried] = await db.query<{ status: string }>(
      `SELECT status::text AS status FROM findings WHERE scan_id = $1 AND finding_type = 'license'`,
      [(await latestScan()).id],
    );
    expect(carried.status).toBe('false_positive');
  });

  it('AC-P22-12 (0) / AC-P22-4: by project id, --fail-on critical, proxy variables pointing at a trap -> 0, trap untouched', async () => {
    const trap = await startTrap();
    try {
      const r = await scanWithWorker(['scan', '--project', projectId, '--url', origin, '--fail-on', 'critical'], 'disabled', {
        HTTP_PROXY: trap.origin,
        HTTPS_PROXY: trap.origin,
        http_proxy: trap.origin,
        NODE_USE_ENV_PROXY: '1',
      });
      expect(r.code, r.stderr).toBe(0);
      expect(r.stdout).toContain(`Project: e2e-self (${projectId})\n`);
      expect(trap.connections).toBe(0);
    } finally {
      await trap.close();
    }
  });

  it('AC-P22-12 (5) / AC-P22-13 / AC-P22-15: no vulnerability data (status NULL -> not_checked) -> 5, JSON valid, stderr empty', async () => {
    const r = await scanWithWorker(['scan', '--project', 'e2e-self', '--url', origin, '--fail-on', 'critical', '--format', 'json'], 'none');
    expect(r.code, r.stdout).toBe(5);
    expect(r.stderr).toBe('');
    const json = parseSingleJson(r.stdout) as Record<string, unknown>;
    expect(validateCliJson(json)).toEqual([]);
    const scan = await latestScan();
    expect(scan.vds).toBeNull();
    expect(json).toMatchObject({
      result: 'incomplete',
      exitCode: 5,
      project: { id: projectId, name: 'e2e-self' },
      scan: { id: scan.id, status: 'completed', totalDependencies: 2 },
      failOn: 'critical',
      vulnerabilityDataStatus: 'not_checked',
      error: null,
    });
    expect(json.warnings).toEqual([`vulnerability data is not_checked for scan ${scan.id}; security findings may be missing`]);
    const allowed = await scanWithWorker(['scan', '--project', 'e2e-self', '--url', origin, '--fail-on', 'critical', '--allow-incomplete'], 'none');
    expect(allowed.code).toBe(0);
  });

  it('AC-P22-12 (3) / AC-P22-7: scan ends failed -> 3 with the folded error_message', async () => {
    const child = cliRun(['scan', '--project', 'e2e-self', '--url', origin], { OSS_RISK_API_KEY_FILE: keyFile });
    let scanId: string | undefined;
    for (let i = 0; i < 200 && !scanId; i++) {
      const [row] = await db.query<{ id: string }>(`SELECT id::text AS id FROM scans WHERE project_id = $1 AND status = 'pending'`, [projectId]);
      scanId = row?.id;
      if (!scanId) await new Promise((r) => setTimeout(r, 50));
    }
    expect(scanId).toBeDefined();
    await db.query(`UPDATE scans SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1`, [scanId, 'qa failure\nsecond line']);
    const r = await child;
    expect(r.code).toBe(3);
    expect(r.stderr).toContain(`oss-risk: error: scan ${scanId} ended with status failed: qa failure second line\n`);
    expect(r.stdout).toBe('');
  });

  it('AC-P22-12 (4): well-formed but unknown API key -> 401 -> 4', async () => {
    const r = await cliRun(['scan', '--project', 'e2e-self', '--url', origin], { OSS_RISK_API_KEY: makeApiKey().key });
    expect(r.code).toBe(4);
    expect(r.stderr).toMatch(/^oss-risk: error: GET \/api\/projects failed: HTTP 401/m);
  });

  it('AC-P22-12 (2) / AC-P22-5: project not found; source outside SCAN_ROOTS -> 400 -> 2; no scan row', async () => {
    const nf = await cliRun(['scan', '--project', 'no-such-project', '--url', origin], { OSS_RISK_API_KEY_FILE: keyFile });
    expect(nf.code).toBe(2);
    expect(nf.stderr).toBe('oss-risk: error: project not found\n');
    const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ('outside', $1) RETURNING id::text AS id`, [path.join(tmp, 'outside')]);
    const rej = await cliRun(['scan', '--project', 'outside', '--url', origin], { OSS_RISK_API_KEY_FILE: keyFile });
    expect(rej.code).toBe(2);
    expect(rej.stderr).toMatch(/^oss-risk: error: project rejected by the server/m);
    expect(await db.query(`SELECT 1 FROM scans WHERE project_id = $1`, [p.id])).toHaveLength(0);
  });

  it('AC-P22-12 (2, N-1): server built for another port -> 403 host_rejected -> 2 with the address hint', async () => {
    const wrong = http.createServer(createApp({ db: db.pool, port: 3001, host: '127.0.0.1', scanRoots: [roots] }));
    await new Promise<void>((resolve) => wrong.listen(0, '127.0.0.1', resolve));
    try {
      const port = (wrong.address() as AddressInfo).port;
      expect(port).not.toBe(3001);
      const r = await cliRun(['scan', '--project', 'e2e-self', '--url', `http://127.0.0.1:${port}`], { OSS_RISK_API_KEY_FILE: keyFile });
      expect(r.code).toBe(2);
      expect(r.stderr).toBe('oss-risk: error: server rejected the address or port (host_rejected); check --url\n');
    } finally {
      wrong.closeAllConnections();
      await new Promise<void>((resolve) => wrong.close(() => resolve()));
    }
  });
});
