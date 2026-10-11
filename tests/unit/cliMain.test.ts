/**
 * REQ-007 P-22 · `main(deps)` of the CLI with injected dependencies
 * (contract sections 2–5, 3.3): a scripted fake API, a fake clock whose
 * `sleep` advances time, in-memory key files. Every run is checked for the
 * AC-G-8 rule (no key, no secret part `S`, no password, no session cookie
 * value, and the redaction fallback never fired).
 */
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { TransportError } from '../../src/cli/client';
import { main } from '../../src/cli/main';
import { FakeApi, NEW_PROJECT_ID, PROJECT_ID, SCAN_ID, finding, makeApiKey, makeDeps, type TestDeps } from '../helpers/cliFakes';
import { parseSingleJson, validateCliJson } from '../helpers/cliJsonSchema';

const KEY = makeApiKey();
const KEY_ENV = { OSS_RISK_API_KEY: KEY.key };
/** `randomBytes(32)` of the fake deps is 32 × 0x5a; the password is its base64url form. */
const PASSWORD = Buffer.alloc(32, 0x5a).toString('base64url');

const runs: TestDeps[] = [];
const secretsOf = (api: FakeApi) => [KEY.key, KEY.secret, api.createdKey, api.createdKey.slice(-43), PASSWORD, api.sessionCookieValue];

async function run(argv: string[], api = new FakeApi(), over: Partial<TestDeps> = {}) {
  const deps = makeDeps(argv, api, { env: KEY_ENV, ...over });
  runs.push(deps);
  const code = await main(deps);
  const stdout = deps.out.text();
  const stderr = deps.err.text();
  for (const s of secretsOf(api)) {
    expect(stdout).not.toContain(s);
    expect(stderr).not.toContain(s);
  }
  expect(stdout + stderr).not.toContain('[redacted]');
  return { code, stdout, stderr, api, deps };
}

afterEach(() => {
  runs.length = 0;
});

const SCAN = ['scan', '--project', 'demo'];

describe('AC-P22-2: help, version and usage errors through main()', () => {
  it('AC-P22-2: --help / -h / <command> --help -> stdout, 0, no request and no key needed', async () => {
    for (const [argv, first] of [
      [['--help'], 'Usage: oss-risk <command> [options]'],
      [['-h'], 'Usage: oss-risk <command> [options]'],
      [['scan', '--help'], 'Usage: oss-risk scan --project <id|name> [options]'],
      [['bootstrap', '-h'], 'Usage: oss-risk bootstrap --new-database --key-file <path> [options]'],
    ] as const) {
      const r = await run([...argv], new FakeApi(), { env: {} });
      expect(r.code).toBe(0);
      expect(r.stdout.startsWith(first)).toBe(true);
      expect(r.stderr).toBe('');
      expect(r.api.requests).toHaveLength(0);
      expect(r.deps.fs.opened).toHaveLength(0);
    }
  });

  it('AC-P22-2: --version / -V -> "1.0.0\\n", 0, no request', async () => {
    for (const flag of ['--version', '-V']) {
      const r = await run([flag], new FakeApi(), { env: {} });
      expect(r.code).toBe(0);
      expect(r.stdout).toBe('1.0.0\n');
      expect(r.api.requests).toHaveLength(0);
    }
  });

  it('AC-P22-2: usage error -> 2, one stderr line with the help hint, stdout empty, no request', async () => {
    const r = await run(['scan', '--project', 'demo', '--bogus']);
    expect(r.code).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toBe('oss-risk: error: unknown option --bogus (see: oss-risk scan --help)\n');
    expect(r.api.requests).toHaveLength(0);
    const general = await run(['frob']);
    expect(general.stderr).toBe('oss-risk: error: unknown command (see: oss-risk --help)\n');
  });

  it('AC-P22-3: --api-key value -> 2 with the fixed text; the value appears nowhere', async () => {
    const r = await run(['scan', '--project', 'demo', `--api-key=${KEY.key}`]);
    expect(r.code).toBe(2);
    expect(r.stderr).toBe(
      'oss-risk: error: API key must be provided via OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE (see: oss-risk scan --help)\n',
    );
    expect(r.api.requests).toHaveLength(0);
  });

  it('AC-P22-15: usage error after --format json -> JSON error object on stdout, stderr empty, valid schema', async () => {
    const r = await run(['scan', '--format', 'json', '--fail-on', 'critical', '--timeout', '5']);
    expect(r.code).toBe(2);
    expect(r.stderr).toBe('');
    const json = parseSingleJson(r.stdout) as Record<string, unknown>;
    expect(validateCliJson(json)).toEqual([]);
    expect(json).toMatchObject({ result: 'error', exitCode: 2, failOn: 'critical', project: null, scan: null, error: { code: 'usage_error' } });
  });
});

describe('AC-P22-3 / AC-P22-4: configuration errors before any request', () => {
  it.each([
    ['both key sources', { OSS_RISK_API_KEY: KEY.key, OSS_RISK_API_KEY_FILE: '/k' }, []],
    ['no key', {}, []],
    ['bad key format', { OSS_RISK_API_KEY: 'ossr_0123_short' }, []],
    ['http non-loopback', KEY_ENV, ['--url', 'http://example.com']],
    ['credentials in URL', KEY_ENV, ['--url', 'http://u:p@127.0.0.1:3001']],
    ['OSS_RISK_URL with path', { ...KEY_ENV, OSS_RISK_URL: 'http://127.0.0.1:3001/api' }, []],
  ])('AC-P22-3 / AC-P22-4: %s -> 2 and zero requests', async (_n, env, extra) => {
    const r = await run([...SCAN, ...extra], new FakeApi(), { env });
    expect(r.code).toBe(2);
    expect(r.api.requests).toHaveLength(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(/^oss-risk: error: [^\n]+\n$/);
    expect(r.stderr).not.toContain('ossr_0123_short');
  });

  it('AC-P22-3: key file is read (trimmed) and sent only as Authorization: Bearer', async () => {
    const api = new FakeApi();
    const deps = makeDeps(SCAN, api, { env: { OSS_RISK_API_KEY_FILE: '/keys/ci.key' } });
    deps.fs.files.set('/keys/ci.key', `${KEY.key}\n`);
    expect(await main(deps)).toBe(0);
    for (const r of api.requests) {
      expect(r.headers.Authorization).toBe(`Bearer ${KEY.key}`);
      expect(r.path).not.toContain(KEY.secret);
      expect(r.body ?? '').not.toContain(KEY.secret);
      expect(r.headers.Origin).toBeUndefined();
      expect(r.headers.Cookie).toBeUndefined();
    }
  });
});

describe('AC-P22-5 / AC-P22-6: project resolution and scan start', () => {
  it('AC-P22-5 / AC-P22-6: name -> GET /api/projects, exact (trimmed) match; POST body only {projectId}; Host header explicit', async () => {
    const r = await run(['scan', '--project', '  demo  ']);
    expect(r.code).toBe(0);
    expect(r.api.paths().slice(0, 2)).toEqual(['GET /api/projects', 'POST /api/scans']);
    const post = r.api.requests[1];
    expect(JSON.parse(post.body!)).toEqual({ projectId: PROJECT_ID });
    expect(post.headers['Content-Type']).toBe('application/json');
    for (const req of r.api.requests) expect(req.headers.Host).toBe('127.0.0.1:3001');
  });

  it('AC-P22-5: UUID -> used as id, no project list request', async () => {
    const r = await run(['scan', '--project', PROJECT_ID.toUpperCase()]);
    expect(r.code).toBe(0);
    expect(r.api.paths()).not.toContain('GET /api/projects');
  });

  it('AC-P22-5: zero matches (also case differs) -> 2 "project not found"; two -> 2 ambiguous; no POST', async () => {
    const api = new FakeApi();
    api.projects = [{ id: PROJECT_ID, name: 'Demo' }];
    const none = await run(SCAN, api);
    expect(none.code).toBe(2);
    expect(none.stderr).toBe('oss-risk: error: project not found\n');
    expect(api.paths()).toEqual(['GET /api/projects']);
    const api2 = new FakeApi();
    api2.projects = [{ id: PROJECT_ID, name: 'demo' }, { id: NEW_PROJECT_ID, name: 'demo' }];
    const two = await run(SCAN, api2);
    expect(two.code).toBe(2);
    expect(two.stderr).toBe('oss-risk: error: project name is ambiguous; use the project id\n');
  });

  it('AC-P22-5: POST /api/scans 400 (source rejected) -> 2 with the sanitized server message; 404 -> 2; never retried', async () => {
    const api = new FakeApi().on('POST', /^\/api\/scans$/, () => ({
      status: 400,
      body: { error: 'Bad Request', message: 'Project has no repository URL\u001b[31m or local path\nx', code: 'project_source_missing' },
    }));
    const r = await run(SCAN, api);
    expect(r.code).toBe(2);
    expect(r.stderr).not.toContain('\u001b');
    expect(r.stderr.split('\n')).toHaveLength(2);
    expect(r.stderr).toMatch(/^oss-risk: error: project rejected by the server: Project has no repository URL/);
    expect(api.paths().filter((p) => p === 'POST /api/scans')).toHaveLength(1);
    const api404 = new FakeApi().on('POST', /^\/api\/scans$/, () => ({ status: 404, body: { code: 'not_found', message: 'x', error: 'x' } }));
    expect((await run(SCAN, api404)).code).toBe(2);
    const api500 = new FakeApi().on('POST', /^\/api\/scans$/, () => ({ status: 503 }));
    const r500 = await run(SCAN, api500);
    expect(r500.code).toBe(3);
    expect(api500.paths().filter((p) => p === 'POST /api/scans')).toHaveLength(1);
  });
});

describe('AC-P22-7: waiting (contract 4.1 step 4, injected clock)', () => {
  it('AC-P22-7: polls every 2 s; status line once per change; queued line', async () => {
    const api = new FakeApi();
    api.scanStatuses = ['pending', 'running', 'running', 'completed'];
    const r = await run(SCAN, api);
    expect(r.code).toBe(0);
    expect(r.deps.sleeps).toEqual([2000, 2000, 2000]);
    expect(r.stderr.split('\n').filter((l) => l.includes(' status '))).toEqual([
      `oss-risk: scan ${SCAN_ID} status pending`,
      `oss-risk: scan ${SCAN_ID} status running`,
      `oss-risk: scan ${SCAN_ID} status completed`,
    ]);
    expect(r.stderr).toContain(`oss-risk: scan ${SCAN_ID} queued for project demo\n`);
  });

  it('AC-P22-7: --timeout 10 elapses without a terminal status -> 3 with the fixed text, no real wait', async () => {
    const api = new FakeApi();
    api.scanStatuses = ['running'];
    const r = await run([...SCAN, '--timeout', '10'], api);
    expect(r.code).toBe(3);
    expect(r.stderr).toContain(`oss-risk: error: timed out waiting for scan ${SCAN_ID}; the scan continues on the server\n`);
    expect(r.deps.sleeps.every((ms) => ms === 2000)).toBe(true);
    expect(r.deps.sleeps.length).toBe(5);
    expect(r.stdout).toBe('');
  });

  it('AC-P22-7: 3 consecutive 503 -> 3; 2 × 503 then success -> continues; a success resets the counter', async () => {
    const three = new FakeApi().on('GET', /^\/api\/scans\/[^/]+$/, () => ({ status: 503 }));
    const r3 = await run(SCAN, three);
    expect(r3.code).toBe(3);
    expect(three.paths().filter((p) => p.startsWith(`GET /api/scans/${SCAN_ID}`))).toHaveLength(3);
    expect(r3.stderr).toContain('failed 3 times in a row');

    const two = new FakeApi();
    const base = two;
    let n = 0;
    two.on('GET', /^\/api\/scans\/[^/]+$/, () => {
      n++;
      // 503, 503, ok(running), 503, connection error, ok(completed): never 3 in a row.
      if (n === 1 || n === 2 || n === 4) return { status: 503 };
      if (n === 5) return new TransportError('connection');
      return { status: 200, body: { data: { id: SCAN_ID, project_id: PROJECT_ID, project_name: 'demo', status: n >= 6 ? 'completed' : 'running', total_dependencies: 1 } } };
    });
    const r2 = await run(SCAN, base);
    expect(r2.code).toBe(0);
    expect(n).toBe(6);
    // Retry delay 2 s between transient failures (contract 4.1).
    expect(r2.deps.sleeps).toEqual([2000, 2000, 2000, 2000, 2000]);
  });

  it('AC-P22-7: failed / cancelled / timeout terminal status -> 3, error_message folded and capped at 500 code points', async () => {
    for (const status of ['failed', 'cancelled', 'timeout']) {
      const api = new FakeApi();
      api.scanStatuses = [status];
      api.scanErrorMessage = `boom\u001b[2J\nline2 ${'x'.repeat(700)}`;
      const r = await run(SCAN, api);
      expect(r.code).toBe(3);
      const line = r.stderr.split('\n').find((l) => l.startsWith('oss-risk: error:'))!;
      expect(line.startsWith(`oss-risk: error: scan ${SCAN_ID} ended with status ${status}: boom`)).toBe(true);
      expect(line).not.toContain('\u001b');
      const detail = line.slice(line.indexOf(': boom') + 2);
      expect([...detail].length).toBe(500);
      expect(r.stdout).toBe('');
    }
    const noMsg = new FakeApi();
    noMsg.scanStatuses = ['failed'];
    expect((await run(SCAN, noMsg)).stderr).toContain(`oss-risk: error: scan ${SCAN_ID} ended with status failed\n`);
  });
});

describe('AC-P22-12: exit code per HTTP response (contract 5.2)', () => {
  it.each([
    ['403 host_rejected', { status: 403, body: { code: 'host_rejected', message: 'Host not allowed', error: 'Forbidden' } }, 2, 'server_address_rejected'],
    ['403 origin_rejected', { status: 403, body: { code: 'origin_rejected', message: 'x', error: 'Forbidden' } }, 2, 'server_address_rejected'],
    ['403 forbidden', { status: 403, body: { code: 'forbidden', message: 'x', error: 'Forbidden' } }, 4, 'forbidden'],
    ['403 without code', { status: 403 }, 4, 'forbidden'],
    ['401', { status: 401, body: { code: 'unauthenticated', message: 'x', error: 'x' } }, 4, 'unauthorized'],
    ['429', { status: 429 }, 3, 'unexpected_response'],
    ['302', { status: 302, headers: { location: 'http://127.0.0.1:9/elsewhere' } }, 3, 'redirect'],
    ['404 on a GET', { status: 404 }, 3, 'unexpected_response'],
    ['200 non-JSON', { status: 200, rawBody: '<html>' }, 3, 'unexpected_response'],
    ['200 data not an array', { status: 200, body: { data: {} } }, 3, 'unexpected_response'],
  ] as const)('AC-P22-12: GET /api/projects %s -> %i (%s), JSON valid', async (_n, reply, exit, code) => {
    const api = new FakeApi().on('GET', /^\/api\/projects$/, () => reply as never);
    const r = await run([...SCAN, '--format', 'json'], api);
    expect(r.code).toBe(exit);
    expect(r.stderr).toBe('');
    const json = parseSingleJson(r.stdout) as { error: { code: string; message: string }; exitCode: number };
    expect(validateCliJson(json)).toEqual([]);
    expect(json.error.code).toBe(code);
    expect(json.exitCode).toBe(exit);
    if (exit === 2) expect(json.error.message).toBe(`server rejected the address or port (${(reply as { body: { code: string } }).body.code}); check --url`);
    if (code === 'redirect') {
      expect(json.error.message).toBe('server responded with a redirect; not followed');
      expect(r.api.requests).toHaveLength(1);
    }
  });

  it('AC-P22-12: POST /api/scans 409 / 413 -> 3; findings 401 -> 4; findings 403 -> 4', async () => {
    for (const status of [409, 413]) {
      const api = new FakeApi().on('POST', /^\/api\/scans$/, () => ({ status }));
      expect((await run(SCAN, api)).code).toBe(3);
    }
    for (const status of [401, 403]) {
      const api = new FakeApi().on('GET', /\/findings$/, () => ({ status, body: { code: status === 401 ? 'unauthenticated' : 'forbidden', message: 'x', error: 'x' } }));
      expect((await run(SCAN, api)).code).toBe(4);
    }
  });

  it('AC-P22-18: transport too_large on findings -> 3 "findings response exceeds 32 MiB"; POST connection error -> 3', async () => {
    const api = new FakeApi().on('GET', /\/findings$/, () => new TransportError('too_large'));
    const r = await run(SCAN, api);
    expect(r.code).toBe(3);
    expect(r.stderr).toContain('oss-risk: error: findings response exceeds 32 MiB\n');
    const post = new FakeApi().on('POST', /^\/api\/scans$/, () => new TransportError('timeout'));
    const rp = await run(SCAN, post);
    expect(rp.code).toBe(3);
    expect(rp.stderr).toContain('POST /api/scans failed: request timed out');
  });

  it('AC-P22-12: one scenario per exit code 0–5 with --format json (schema valid, exitCode = process code)', async () => {
    const cases: Array<[number, (api: FakeApi) => void, string[]]> = [
      [0, () => undefined, []],
      [1, (a) => (a.findings = [finding({ severity: 'critical' })]), []],
      [2, () => undefined, ['--timeout', '1']],
      [3, (a) => (a.scanStatuses = ['failed']), []],
      [4, (a) => a.on('GET', /^\/api\/projects$/, () => ({ status: 401 })), []],
      [5, (a) => (a.vulnStatus = 'partial'), []],
    ];
    for (const [exit, setup, extra] of cases) {
      const api = new FakeApi();
      setup(api);
      const r = await run([...SCAN, '--format', 'json', ...extra], api);
      expect(r.code, `exit ${exit}`).toBe(exit);
      expect(r.stderr).toBe('');
      const json = parseSingleJson(r.stdout) as { exitCode: number };
      expect(validateCliJson(json)).toEqual([]);
      expect(json.exitCode).toBe(exit);
    }
  });
});

describe('AC-P22-13: vulnerability data status (contract 4.4, N-8)', () => {
  it('AC-P22-13: status endpoint read also with --fail-on none; disabled warning; exit 0', async () => {
    const api = new FakeApi();
    api.vulnStatus = 'disabled';
    const r = await run([...SCAN, '--fail-on', 'none'], api);
    expect(r.code).toBe(0);
    expect(api.paths()).toContain('GET /api/vulnerability-data/status');
    expect(r.stderr).toContain('oss-risk: warning: vulnerability lookup is disabled on the server; security findings were not checked\n');
    expect(r.stdout).toContain('Vulnerability data: disabled\n');
  });

  it('AC-P22-13: status endpoint 401 / 403 / 5xx×3 / non-JSON -> unknown -> 5 (never 3/4); --allow-incomplete -> 0', async () => {
    const replies = [{ status: 401 }, { status: 403, body: { code: 'forbidden' } }, { status: 503 }, { status: 200, rawBody: 'nope' }];
    for (const reply of replies) {
      const api = new FakeApi().on('GET', /^\/api\/vulnerability-data\/status$/, () => reply);
      const r = await run([...SCAN, '--format', 'json'], api);
      expect(r.code).toBe(5);
      expect(JSON.parse(r.stdout)).toMatchObject({ vulnerabilityDataStatus: 'unknown', result: 'incomplete' });
      const allowed = new FakeApi().on('GET', /^\/api\/vulnerability-data\/status$/, () => reply);
      expect((await run([...SCAN, '--allow-incomplete'], allowed)).code).toBe(0);
    }
  });

  it('AC-P22-13: four statuses + no matching latest_scan_id', async () => {
    for (const [status, exit] of [['complete', 0], ['disabled', 0], ['partial', 5], ['unavailable', 5], [null, 5]] as const) {
      const api = new FakeApi();
      api.vulnStatus = status;
      expect((await run(SCAN, api)).code, String(status)).toBe(exit);
    }
    const other = new FakeApi().on('GET', /^\/api\/vulnerability-data\/status$/, () => ({
      status: 200,
      body: { data: { projects: [{ latest_scan_id: NEW_PROJECT_ID, vulnerability_data_status: 'complete' }] } },
    }));
    const r = await run([...SCAN, '--format', 'json'], other);
    expect(r.code).toBe(5);
    expect(JSON.parse(r.stdout).vulnerabilityDataStatus).toBe('unknown');
  });

  it('AC-P22-12: breach + incomplete data -> 1 (priority 1 over 5)', async () => {
    const api = new FakeApi();
    api.vulnStatus = 'unavailable';
    api.findings = [finding({ finding_type: 'license', risk_level: 'unknown' })];
    const r = await run(SCAN, api);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('Result: FAIL\n');
  });
});

describe('AC-P22-14 / AC-P22-15 / AC-P22-16: output of a completed scan', () => {
  it('AC-P22-14: text stdout summary in contract order, progress and warnings only on stderr', async () => {
    const api = new FakeApi();
    api.findings = [
      finding({ severity: 'critical', package_name: 'left-pad', package_version: '1.3.0', cve_id: 'CVE-2026-0001' }),
      finding({ finding_type: 'license', risk_level: 'low', package_name: 'a', package_version: '1.0.0', normalized_license: 'MIT' }),
    ];
    const r = await run(SCAN, api);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe(
      [
        `Project: demo (${PROJECT_ID})`,
        `Scan: ${SCAN_ID}`,
        'Status: completed',
        'Dependencies: 12',
        'Security findings: critical=1 high=0 medium=0 low=0',
        'License findings: critical=0 high=0 medium=0 low=1',
        'Vulnerability data: complete',
        'Fail on: high',
        'Findings at or above high: 1',
        '  left-pad@1.3.0  security  critical  CVE-2026-0001',
        'Result: FAIL',
        '',
      ].join('\n'),
    );
    expect(r.stderr.split('\n').filter(Boolean).every((l) => l.startsWith('oss-risk: '))).toBe(true);
  });

  it('AC-P22-15: JSON output: one object, no stderr, contract example shape', async () => {
    const api = new FakeApi();
    api.vulnStatus = 'disabled';
    api.findings = [finding({ finding_type: 'license', risk_level: 'unknown', package_name: 'left-pad', package_version: '1.3.0' })];
    const r = await run([...SCAN, '--format', 'json'], api);
    expect(r.code).toBe(1);
    expect(r.stderr).toBe('');
    const json = parseSingleJson(r.stdout);
    expect(validateCliJson(json)).toEqual([]);
    expect(json).toEqual({
      schemaVersion: 1,
      result: 'fail',
      exitCode: 1,
      project: { id: PROJECT_ID, name: 'demo' },
      scan: { id: SCAN_ID, status: 'completed', totalDependencies: 12 },
      failOn: 'high',
      vulnerabilityDataStatus: 'disabled',
      counts: { security: { low: 0, medium: 0, high: 0, critical: 0 }, license: { low: 0, medium: 0, high: 1, critical: 0 } },
      breaching: [{ type: 'license', package: 'left-pad', version: '1.3.0', level: 'high', id: 'unknown' }],
      breachingTruncated: false,
      warnings: ['vulnerability lookup is disabled on the server; security findings were not checked'],
      error: null,
    });
  });

  it('AC-P22-16: package / project / license names with ESC[2J and newlines are single-line, control-free, capped at 200', async () => {
    const api = new FakeApi();
    api.projects = [{ id: PROJECT_ID, name: 'demo' }];
    api.on('GET', /^\/api\/scans\/[^/]+$/, () => ({
      status: 200,
      body: { data: { id: SCAN_ID, project_id: PROJECT_ID, project_name: 'pro\u001b[2J\nject', status: 'completed', total_dependencies: 1 } },
    }));
    api.on('POST', /^\/api\/scans$/, () => ({ status: 201, body: { data: { id: SCAN_ID, status: 'pending' } } }));
    api.findings = [
      finding({ severity: 'critical', package_name: 'evil\u001b[2J\npkg', package_version: '1\u009b0\n', cve_id: `CVE-${'9'.repeat(400)}` }),
      finding({ finding_type: 'license', risk_level: 'unknown', package_name: 'x\u0007y', normalized_license: 'GPL\u001b]0;t\u0007' }),
    ];
    const text = await run(['scan', '--project', PROJECT_ID], api);
    expect(text.code).toBe(1);
    for (const out of [text.stdout, text.stderr]) {
      expect(out).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/); // eslint-disable-line no-control-regex
    }
    const line = text.stdout.split('\n').find((l) => l.includes('evil'))!;
    expect(line).toContain('pkg@');
    const id = line.trim().split('  ').at(-1)!;
    expect([...id].length).toBe(200);
    const api2 = new FakeApi();
    api2.findings = api.findings;
    const json = await run([...SCAN, '--format', 'json'], api2);
    expect(json.stdout.slice(0, -1)).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/); // eslint-disable-line no-control-regex
    const parsed = JSON.parse(json.stdout);
    expect(validateCliJson(parsed)).toEqual([]);
    expect(parsed.breaching[0].package).not.toContain('\n');
  });
});

describe('AC-P22-17: bootstrap (contract 3.3)', () => {
  const KEY_FILE = path.resolve('qa-bootstrap.key');
  const B = ['bootstrap', '--new-database', '--key-file', 'qa-bootstrap.key'];

  it('AC-P22-17: success -> request order, headers, file = key without newline, stdout two lines', async () => {
    const r = await run([...B, '--project-name', 'self', '--project-path', 'target-dir'], new FakeApi(), { env: { OSS_RISK_API_KEY: 'ignored', OSS_RISK_API_KEY_FILE: '/x' } });
    expect(r.code).toBe(0);
    expect(r.api.paths()).toEqual(['POST /api/auth/setup', 'POST /api/auth/api-keys', 'POST /api/projects', 'POST /api/auth/logout']);
    const [setup, keys, project, logout] = r.api.requests;
    expect(setup.headers).toMatchObject({ Host: '127.0.0.1:3001', Origin: 'http://127.0.0.1:3001', 'Content-Type': 'application/json' });
    expect(setup.headers.Authorization).toBeUndefined();
    expect(JSON.parse(setup.body!)).toEqual({ password: PASSWORD });
    expect(PASSWORD).toHaveLength(43);
    expect(keys.headers).toMatchObject({ Origin: 'http://127.0.0.1:3001', Cookie: `ossrisk_session=${r.api.sessionCookieValue}` });
    expect(JSON.parse(keys.body!)).toEqual({ name: 'bootstrap' });
    expect(project.headers.Authorization).toBe(`Bearer ${r.api.createdKey}`);
    expect(project.headers.Origin).toBeUndefined();
    expect(project.headers.Cookie).toBeUndefined();
    expect(JSON.parse(project.body!)).toEqual({ name: 'self', repoUrl: path.resolve('target-dir'), ecosystems: [] });
    expect(logout.headers).toMatchObject({ Origin: 'http://127.0.0.1:3001', Cookie: `ossrisk_session=${r.api.sessionCookieValue}` });
    expect(r.deps.fs.files.get(KEY_FILE)).toBe(r.api.createdKey);
    expect(r.stdout).toBe(`API key written to ${KEY_FILE}\nProject ID: ${NEW_PROJECT_ID}\n`);
    expect(r.stderr).toBe('oss-risk: initialising server http://127.0.0.1:3001\n');
  });

  it('AC-P22-17: without --new-database -> 2, no file, zero requests', async () => {
    const r = await run(['bootstrap', '--key-file', 'qa-bootstrap.key']);
    expect(r.code).toBe(2);
    expect(r.api.requests).toHaveLength(0);
    expect(r.deps.fs.opened).toHaveLength(0);
    expect(r.stderr).toContain('bootstrap requires --new-database');
  });

  it('AC-P22-17: non-loopback address -> 2, zero requests, no file', async () => {
    for (const url of ['https://oss-risk.example.test', 'http://example.com']) {
      const r = await run([...B, '--url', url]);
      expect(r.code).toBe(2);
      expect(r.api.requests).toHaveLength(0);
      expect(r.deps.fs.opened).toHaveLength(0);
    }
  });

  it('AC-P22-17: existing key file -> 2, zero requests, file untouched', async () => {
    const api = new FakeApi();
    const deps = makeDeps(B, api);
    deps.fs.files.set(KEY_FILE, 'previous');
    expect(await main(deps)).toBe(2);
    expect(api.requests).toHaveLength(0);
    expect(deps.fs.files.get(KEY_FILE)).toBe('previous');
    expect(deps.err.text()).toContain('key file already exists');
  });

  it('AC-P22-17: setup 409 setup_already_done -> 4 with the fixed text; key file removed', async () => {
    const api = new FakeApi().on('POST', /^\/api\/auth\/setup$/, () => ({ status: 409, body: { code: 'setup_already_done', message: 'x', error: 'Conflict' } }));
    const r = await run(B, api);
    expect(r.code).toBe(4);
    expect(r.stderr).toContain('oss-risk: error: database already initialised; bootstrap only works on an empty database\n');
    expect(r.deps.fs.files.has(KEY_FILE)).toBe(false);
    expect(api.paths()).toEqual(['POST /api/auth/setup']);
  });

  it('AC-P22-17: setup 403 host_rejected -> 2; api-keys 500 -> 3 with the unusable-password note, file removed', async () => {
    const host = new FakeApi().on('POST', /^\/api\/auth\/setup$/, () => ({ status: 403, body: { code: 'host_rejected', message: 'x', error: 'x' } }));
    expect((await run(B, host)).code).toBe(2);
    const keys = new FakeApi().on('POST', /^\/api\/auth\/api-keys$/, () => ({ status: 500 }));
    const r = await run(B, keys);
    expect(r.code).toBe(3);
    expect(r.stderr).toContain('database is now initialised without a usable password; recreate the temporary database');
    expect(r.deps.fs.files.has(KEY_FILE)).toBe(false);
    expect(keys.paths().at(-1)).toBe('POST /api/auth/logout');
  });

  it('AC-P22-17: project 400 path_not_allowed -> 2, key file kept, logout still tried; logout failure -> warning only', async () => {
    const api = new FakeApi().on('POST', /^\/api\/projects$/, () => ({ status: 400, body: { code: 'path_not_allowed', message: 'Path is not allowed', error: 'Bad Request' } }));
    const r = await run([...B, '--project-name', 'p', '--project-path', 'd'], api);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('project rejected by the server: Path is not allowed');
    expect(r.deps.fs.files.get(KEY_FILE)).toBe(api.createdKey);
    expect(api.paths().at(-1)).toBe('POST /api/auth/logout');
    const lo = new FakeApi().on('POST', /^\/api\/auth\/logout$/, () => ({ status: 500 }));
    const rl = await run(B, lo);
    expect(rl.code).toBe(0);
    expect(rl.stderr).toContain('oss-risk: warning: logout failed; the session expires on its own\n');
  });

  it('AC-P22-17: POSIX key file mode not 0600 -> 2, file removed, zero requests (Windows: mode ignored)', async () => {
    const api = new FakeApi();
    const deps = makeDeps(B, api, { platform: 'linux' });
    deps.fs.mode = 0o100644;
    expect(await main(deps)).toBe(2);
    expect(api.requests).toHaveLength(0);
    expect(deps.fs.files.has(KEY_FILE)).toBe(false);
    const ok = makeDeps(B, new FakeApi(), { platform: 'linux' });
    expect(await main(ok)).toBe(0);
    const win = makeDeps(B, new FakeApi(), { platform: 'win32' });
    win.fs.mode = 0o100666;
    expect(await main(win)).toBe(0);
  });
});
