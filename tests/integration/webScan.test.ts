/**
 * REQ-008 end to end against a real (embedded) PostgreSQL and loopback HTTP
 * servers: P-25 (web URL, allowlist, PATCH, kind=web), P-26 (worker pipeline,
 * TOCTOU, unreachable target, secrets never stored), P-27 (web-findings API,
 * PDF/CSV, dependency outputs 404 for web scans), P-28 (fake ZAP daemon),
 * plus the recheck/status scope (web scans never become the "latest" scan).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Express } from 'express';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanWorker } from '../../src/scanner/worker';
import { parseAllowedHosts } from '../../src/webscan/allowlist';
import { createWebScanner } from '../../src/webscan/engine';
import { createZapConnector } from '../../src/webscan/zap';
import { useTestDatabase } from '../helpers/db';
import { expectErrorBody, makeApp, req, setupPassword } from '../helpers/http';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file', setDatabaseUrlEnv: true });
const ALLOW = parseAllowedHosts('127.0.0.1');
const COOKIE_SECRET = 'cookie-value-must-not-be-stored';
const CONFIG_SECRET = 'config-password-must-not-be-stored';
const silent = { log: () => undefined, warn: () => undefined, error: () => undefined };

let app: Express;
let cookie = '';
let site: http.Server;
let siteUrl = '';
let zap: http.Server;
let zapOrigin = '';
const zapCalls: Array<{ path: string; key: string | undefined; params: Record<string, string> }> = [];

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

beforeAll(async () => {
  site = http.createServer((rq, rs) => {
    const u = rq.url ?? '/';
    if (u === '/') {
      rs.setHeader('Server', 'Microsoft-IIS/10.0');
      rs.setHeader('Set-Cookie', [`ASP.NET_SessionId=${COOKIE_SECRET}; path=/`]);
      rs.setHeader('Content-Type', 'text/html; charset=utf-8');
      rs.end('<html><head><script src="/js/jquery-1.12.4.min.js"></script><script src="/js/site.js"></script></head><body>ok</body></html>');
      return;
    }
    if (u === '/js/site.js') {
      rs.setHeader('Content-Type', 'application/javascript');
      rs.end('//! moment.js\n//! version : 2.19.1\n');
      return;
    }
    if (u === '/.git/HEAD') return void rs.end('ref: refs/heads/main\n');
    if (u === '/appsettings.json') {
      rs.setHeader('Content-Type', 'application/json');
      rs.end(JSON.stringify({ ConnectionStrings: { Db: `Password=${CONFIG_SECRET}` } }));
      return;
    }
    rs.statusCode = 404;
    rs.end('not found');
  });
  siteUrl = `http://127.0.0.1:${await listen(site)}/`;

  zap = http.createServer((rq, rs) => {
    const url = new URL(rq.url ?? '/', 'http://x');
    zapCalls.push({ path: url.pathname, key: rq.headers['x-zap-api-key'] as string | undefined, params: Object.fromEntries(url.searchParams) });
    rs.setHeader('Content-Type', 'application/json');
    const p = url.pathname;
    if (p === '/JSON/core/view/version/') return void rs.end('{"version":"2.16.0"}');
    if (p === '/JSON/context/action/newContext/') return void rs.end('{"contextId":"7"}');
    if (p.endsWith('/action/scan/')) return void rs.end('{"scan":"1"}');
    if (p.endsWith('/view/status/')) return void rs.end('{"status":"100"}');
    if (p === '/JSON/pscan/view/recordsToScan/') return void rs.end('{"recordsToScan":"0"}');
    if (p === '/JSON/alert/view/alerts/') {
      const start = Number(url.searchParams.get('start'));
      const target = url.searchParams.get('baseurl') ?? '';
      const alerts = start > 0 ? [] : [
        { pluginId: '40012', alert: 'Cross Site Scripting (Reflected)', riskcode: '3', confidence: '2', url: `${target}/search?q=1`, description: 'XSS', solution: 'Encode', cweid: '79', tags: { OWASP_2021_A03: 'x' } },
        { pluginId: '10202', alert: 'Absence of Anti-CSRF Tokens', riskcode: '2', confidence: '0', url: `${target}/form` },
        { pluginId: '90022', alert: 'Application Error Disclosure', riskcode: '2', confidence: '2', url: 'https://outside.example/x' },
      ];
      return void rs.end(JSON.stringify({ alerts }));
    }
    rs.end('{"Result":"OK"}');
  });
  zapOrigin = `http://127.0.0.1:${await listen(zap)}`;

  app = await makeApp(db.pool, { webAllowlist: ALLOW });
  cookie = await setupPassword(app);
});

afterAll(async () => {
  await new Promise((r) => site.close(r));
  await new Promise((r) => zap.close(r));
});

beforeEach(async () => {
  // Only the scan created by the current test may be claimed.
  await db.query(`UPDATE scans SET status = 'cancelled' WHERE status IN ('pending','queued','running')`);
  zapCalls.length = 0;
});

function worker(options: { allowlist?: ReturnType<typeof parseAllowedHosts>; zap?: boolean; noScanner?: boolean } = {}): ScanWorker {
  const allowlist = options.allowlist ?? ALLOW;
  return new ScanWorker({
    db: db.pool,
    scanRoots: [],
    logger: silent,
    webScanner: options.noScanner
      ? null
      : createWebScanner({
          allowlist,
          env: {},
          legacyTlsProbe: async () => null,
          zap: options.zap ? createZapConnector({ config: { origin: zapOrigin, apiKey: 'zap-test-key' }, env: {}, budgets: { pollMs: 10 } }) : null,
        }),
  });
}

async function newProject(name: string, webUrl?: string): Promise<string> {
  const res = await req(app, 'post', '/api/projects', { cookie }).send(webUrl ? { name, webUrl } : { name });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data.id as string;
}

async function queueWeb(projectId: string): Promise<string> {
  const res = await req(app, 'post', '/api/scans', { cookie }).send({ projectId, kind: 'web' });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data.id as string;
}

describe('P-25: web URL on projects', () => {
  it('AC-P25-4: POST /api/projects stores the normalized webUrl; list returns web_url and web_scan_mode', async () => {
    await newProject('web-only', 'http://127.0.0.1:9/app');
    const list = await req(app, 'get', '/api/projects', { cookie });
    const p = list.body.data.find((x: { name: string }) => x.name === 'web-only');
    expect(p).toMatchObject({ web_url: 'http://127.0.0.1:9/app', web_scan_mode: 'passive', repo_url: null });
  });

  it('AC-P25-2/3: invalid URL -> web_url_invalid; host outside the allowlist -> web_url_not_allowed; nothing stored', async () => {
    const before = (await db.query('SELECT id FROM projects')).length;
    expectErrorBody(await req(app, 'post', '/api/projects', { cookie }).send({ name: 'x', webUrl: 'ftp://127.0.0.1/' }), 400, 'web_url_invalid');
    const res = await req(app, 'post', '/api/projects', { cookie }).send({ name: 'x', webUrl: 'https://evil.example/' });
    expectErrorBody(res, 400, 'web_url_not_allowed');
    expect(JSON.stringify(res.body)).not.toContain('evil.example');
    expect((await db.query('SELECT id FROM projects')).length).toBe(before);
  });

  it('AC-P25-5: PATCH sets/clears webUrl and webScanMode, audits project_updated; bad body 400; unknown project 404', async () => {
    const id = await newProject('patch-me');
    const res = await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({ webUrl: siteUrl, webScanMode: 'active' });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ id, web_url: siteUrl, web_scan_mode: 'active' });
    const audit = await db.query<{ old_data: unknown; new_data: unknown }>(`SELECT old_data, new_data FROM audit_logs WHERE action = 'project_updated' AND entity_id = $1`, [id]);
    expect(audit).toEqual([{ old_data: { web_url: null, web_scan_mode: 'passive' }, new_data: { web_url: siteUrl, web_scan_mode: 'active' } }]);

    const cleared = await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({ webUrl: null });
    expect(cleared.body.data.web_url).toBeNull();
    expectErrorBody(await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({ name: 'x' }), 400, 'invalid_request');
    expectErrorBody(await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({}), 400, 'invalid_request');
    expectErrorBody(await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({ webScanMode: 'aggressive' }), 400, 'invalid_request');
    expectErrorBody(await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({ webUrl: 'https://evil.example/' }), 400, 'web_url_not_allowed');
    expectErrorBody(await req(app, 'patch', '/api/projects/7f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f', { cookie }).send({ webUrl: null }), 404, 'not_found');
    expectErrorBody(await req(app, 'patch', '/api/projects/not-a-uuid', { cookie }).send({ webUrl: null }), 400, 'invalid_request');
  });

  it('AC-P25-6: kind validation, missing web URL, scan row shape', async () => {
    const plain = await newProject('no-web');
    expectErrorBody(await req(app, 'post', '/api/scans', { cookie }).send({ projectId: plain, kind: 'web' }), 400, 'project_web_url_missing');
    expectErrorBody(await req(app, 'post', '/api/scans', { cookie }).send({ projectId: plain, kind: 'dast' }), 400, 'invalid_request');
    const id = await newProject('kind-web', siteUrl);
    const res = await req(app, 'post', '/api/scans', { cookie }).send({ projectId: id, kind: 'web', ref: 'ignored' });
    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ scan_kind: 'web', target_url: siteUrl, ref: null, ref_type: null, status: 'pending', web_summary: null });
    expect(res.body.data).not.toHaveProperty('next_attempt_at');
  });
});

describe('P-26 / P-27: worker pipeline and outputs', () => {
  let scanId = '';
  let projectId = '';

  it('AC-P26-1…9: a web scan completes with findings, components, counters and summary; no secret is stored', async () => {
    projectId = await newProject('portal', siteUrl);
    scanId = await queueWeb(projectId);
    expect(await worker().runOnce()).toBe(scanId);

    const [row] = await db.query<{ status: string; total_dependencies: number; total_vulnerabilities: number; high_vulns: number; license_violations: number; web_summary: Record<string, unknown>; error_message: string | null }>(
      'SELECT status, total_dependencies, total_vulnerabilities, high_vulns, license_violations, web_summary, error_message FROM scans WHERE id = $1',
      [scanId],
    );
    expect(row.status).toBe('completed');
    expect(row.total_dependencies).toBe(0);
    expect(row.license_violations).toBe(0);
    expect(row.web_summary).toMatchObject({ version: 1, final_url: siteUrl, engines: { builtin: 'complete', zap: 'not_configured', zap_mode: null }, components: 2 });
    // No vulnerability lookup engine injected -> library lookup reported as off.
    expect(row.web_summary.vulnerability_lookup).toBe('disabled');
    expect(row.error_message).toMatch(/\[web\] JavaScript kütüphanesi açık sorgusu kapalı/);

    const rules = (await db.query<{ rule_id: string }>('SELECT rule_id FROM web_findings WHERE scan_id = $1 ORDER BY rule_id', [scanId])).map((r) => r.rule_id);
    expect(rules).toEqual(expect.arrayContaining(['WEB-TLS-001', 'WEB-EXP-001', 'WEB-EXP-003', 'WEB-INF-001', 'WEB-CKE-002', 'WEB-HDR-003']));
    expect(row.high_vulns).toBe((await db.query(`SELECT 1 FROM web_findings WHERE scan_id = $1 AND severity = 'high'`, [scanId])).length);
    expect(row.total_vulnerabilities).toBe((await db.query(`SELECT 1 FROM web_findings WHERE scan_id = $1 AND severity <> 'info'`, [scanId])).length);

    const components = await db.query('SELECT name, npm_name, version, detection FROM web_scan_components WHERE scan_id = $1 ORDER BY lower(name)', [scanId]);
    expect(components).toEqual([
      { name: 'jQuery', npm_name: 'jquery', version: '1.12.4', detection: 'url' },
      { name: 'Moment', npm_name: 'moment', version: '2.19.1', detection: 'banner' },
    ]);

    const dump = JSON.stringify(await db.query('SELECT * FROM web_findings')) + JSON.stringify(await db.query('SELECT web_summary, error_message FROM scans'));
    expect(dump).not.toContain(COOKIE_SECRET);
    expect(dump).not.toContain(CONFIG_SECRET);
    const audit = await db.query(`SELECT action FROM audit_logs WHERE entity_id = $1 ORDER BY id`, [scanId]);
    expect(audit.map((a) => a.action)).toEqual(['scan_started', 'scan_started', 'scan_completed']);
  });

  it('AC-P27-1/2: GET /api/scans/{id}/web-findings returns sorted findings, components, score and grade', async () => {
    const res = await req(app, 'get', `/api/scans/${scanId}/web-findings`, { cookie });
    expect(res.status).toBe(200);
    const data = res.body.data;
    expect(data.scan).toMatchObject({ id: scanId, project_id: projectId, project_name: 'portal', target_url: siteUrl });
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const ranks = data.findings.map((f: { severity: string }) => order.indexOf(f.severity));
    expect(ranks).toEqual([...ranks].sort((a: number, b: number) => a - b));
    const c = data.counts;
    expect(data.score).toBe(Math.max(0, 100 - 40 * c.critical - 20 * c.high - 8 * c.medium - 2 * c.low));
    expect(data.grade).toBe(data.summary.grade);
    expect(data.components).toHaveLength(2);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('AC-P27-3: web PDF and CSV; dependency outputs and web-findings answer 404 for the wrong scan kind', async () => {
    const pdf = await req(app, 'get', `/api/scans/${scanId}/exports/web-report.pdf`, { cookie }).buffer(true).parse((res, cb) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => cb(null, Buffer.concat(chunks)));
    });
    expect(pdf.status).toBe(200);
    expect(pdf.headers['content-type']).toBe('application/pdf');
    expect(pdf.headers['content-disposition']).toBe(`attachment; filename="web-report-${scanId}.pdf"`);
    expect((pdf.body as Buffer).subarray(0, 5).toString()).toBe('%PDF-');

    const csv = await req(app, 'get', `/api/scans/${scanId}/exports/web-findings.csv`, { cookie });
    expect(csv.status).toBe(200);
    const text = csv.text.replace(/^\uFEFF/, '');
    expect(text.split('\r\n')[0]).toBe('Severity,Rule,Category,Title,Location,Evidence,CWE,OWASP,Component,Version,Fixed Version,CVSS,Advisory,Source,Status,Recommendation');
    expect(text).not.toContain(COOKIE_SECRET);

    for (const path of ['exports/project-report.pdf', 'exports/license-inventory.csv', 'notice']) {
      expect((await req(app, 'get', `/api/scans/${scanId}/${path}`, { cookie })).status, path).toBe(404);
    }
    const [dep] = await db.query<{ id: string }>(
      `INSERT INTO scans (project_id, trigger, status, completed_at) VALUES ($1, 'manual', 'completed', NOW()) RETURNING id`,
      [projectId],
    );
    expectErrorBody(await req(app, 'get', `/api/scans/${dep.id}/web-findings`, { cookie }), 404, 'not_found');
    expect((await req(app, 'get', `/api/scans/${dep.id}/exports/web-report.pdf`, { cookie })).status).toBe(404);
    expectErrorBody(await req(app, 'get', '/api/scans/not-a-uuid/web-findings', { cookie }), 400, 'invalid_request');
  });

  it('recheck/status scope: the latest *dependency* scan stays the project\'s scan when a web scan is newer', async () => {
    const res = await req(app, 'get', '/api/vulnerability-data/status', { cookie });
    expect(res.status).toBe(200);
    const project = res.body.data.projects.find((p: { project_id: string }) => p.project_id === projectId);
    const [dep] = await db.query<{ id: string }>(`SELECT id FROM scans WHERE project_id = $1 AND scan_kind = 'dependency' AND status = 'completed'`, [projectId]);
    expect(project?.latest_scan_id).toBe(dep.id);
  });
});

describe('P-26 failure handling', () => {
  it('AC-P25-7: allowlist changed after queueing -> failed at once, not retried', async () => {
    const id = await newProject('toctou', siteUrl);
    const scan = await queueWeb(id);
    await worker({ allowlist: parseAllowedHosts('other.local') }).runOnce();
    const [row] = await db.query<{ status: string; retry_count: number; error_message: string }>('SELECT status, retry_count, error_message FROM scans WHERE id = $1', [scan]);
    expect(row).toMatchObject({ status: 'failed', retry_count: 0 });
    expect(row.error_message).toBe('Web adresi WEB_SCAN_ALLOWED_HOSTS izin listesinde değil.');
  });

  it('no web scanner wired -> permanent failure', async () => {
    const id = await newProject('no-scanner', siteUrl);
    const scan = await queueWeb(id);
    await worker({ noScanner: true }).runOnce();
    const [row] = await db.query<{ status: string }>('SELECT status FROM scans WHERE id = $1', [scan]);
    expect(row.status).toBe('failed');
  });

  it('AC-P26-3: unreachable target -> transient (queued for retry with a fixed message)', async () => {
    const closed = http.createServer();
    const port = await listen(closed);
    await new Promise((r) => closed.close(r));
    const id = await newProject('down', `http://127.0.0.1:${port}/`);
    const scan = await queueWeb(id);
    await worker().runOnce();
    const [row] = await db.query<{ status: string; retry_count: number; error_message: string }>('SELECT status, retry_count, error_message FROM scans WHERE id = $1', [scan]);
    expect(row).toMatchObject({ status: 'queued', retry_count: 1, error_message: 'Hedef adrese ulaşılamadı (ECONNREFUSED).' });
  });
});

describe('P-28: OWASP ZAP connector against a fake daemon', () => {
  it('AC-P28-2/4/5: passive flow, API key header only, alerts grouped; false positives and foreign URLs dropped', async () => {
    const id = await newProject('zap-passive', siteUrl);
    const scan = await queueWeb(id);
    await worker({ zap: true }).runOnce();
    const paths = zapCalls.map((c) => c.path);
    expect(paths).toEqual(expect.arrayContaining(['/JSON/core/view/version/', '/JSON/core/action/newSession/', '/JSON/spider/action/scan/', '/JSON/pscan/view/recordsToScan/', '/JSON/alert/view/alerts/']));
    expect(paths).not.toContain('/JSON/ascan/action/scan/');
    expect(zapCalls.every((c) => c.key === 'zap-test-key')).toBe(true);
    // Security review M-2/M-3: scoped context, no redirect following, no form submission.
    const call = (path: string) => zapCalls.find((c) => c.path === path)?.params;
    expect(call('/JSON/context/action/includeInContext/')?.regex).toBe('^https?://127\\.0\\.0\\.1(:\\d+)?(/.*)?$');
    expect(call('/JSON/context/action/setContextInScope/')?.booleanInScope).toBe('true');
    expect(call('/JSON/spider/action/setOptionProcessForm/')?.Boolean).toBe('false');
    expect(call('/JSON/spider/action/setOptionPostForm/')?.Boolean).toBe('false');
    expect(call('/JSON/core/action/accessUrl/')?.followRedirects).toBe('false');
    expect(call('/JSON/spider/action/scan/')?.contextName).toBe(call('/JSON/context/action/newContext/')?.contextName);
    expect(JSON.stringify(zapCalls.map((c) => c.params))).not.toContain('zap-test-key');
    const zapRows = await db.query('SELECT rule_id, severity, source, category, cwe_id, owasp FROM web_findings WHERE scan_id = $1 AND source = $2', [scan, 'zap']);
    expect(zapRows).toEqual([{ rule_id: 'ZAP-40012', severity: 'high', source: 'zap', category: 'zap', cwe_id: 79, owasp: 'A03:2021' }]);
    const [row] = await db.query<{ web_summary: { engines: unknown } }>('SELECT web_summary FROM scans WHERE id = $1', [scan]);
    expect(row.web_summary.engines).toEqual({ builtin: 'complete', zap: 'complete', zap_mode: 'passive' });
  });

  it('AC-P28-7: active mode runs the active scan', async () => {
    const id = await newProject('zap-active', siteUrl);
    await req(app, 'patch', `/api/projects/${id}`, { cookie }).send({ webScanMode: 'active' });
    await queueWeb(id);
    await worker({ zap: true }).runOnce();
    expect(zapCalls.find((c) => c.path === '/JSON/ascan/action/scan/')?.params).toMatchObject({ inScopeOnly: 'true', contextId: '7' });
  });

  it('AC-P28-3: unreachable ZAP -> built-in results only, zap = unavailable, [zap] line', async () => {
    const id = await newProject('zap-down', siteUrl);
    const scan = await queueWeb(id);
    const closed = http.createServer();
    const port = await listen(closed);
    await new Promise((r) => closed.close(r));
    const w = new ScanWorker({
      db: db.pool,
      scanRoots: [],
      logger: silent,
      webScanner: createWebScanner({ allowlist: ALLOW, env: {}, legacyTlsProbe: async () => null, zap: createZapConnector({ config: { origin: `http://127.0.0.1:${port}`, apiKey: null }, env: {} }) }),
    });
    await w.runOnce();
    const [row] = await db.query<{ status: string; web_summary: { engines: { zap: string } }; error_message: string }>('SELECT status, web_summary, error_message FROM scans WHERE id = $1', [scan]);
    expect(row.status).toBe('completed');
    expect(row.web_summary.engines.zap).toBe('unavailable');
    expect(row.error_message).toMatch(/\[zap\] ZAP API'ye ulaşılamadı \([A-Z_]+\); yalnız yerleşik kontroller çalıştı\./);
  });
});
