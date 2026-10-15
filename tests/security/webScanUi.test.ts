/**
 * REQ-008 UI (AC-P27-5, AC-P27-6, AC-P28-7): public/index.html + public/app.js
 * in jsdom with an in-memory fake API (harness of tests/security/f6Ui.test.ts).
 * Every API string reaches the DOM as text only.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as jsdomModule from 'jsdom';
import { JSDOM } from 'jsdom';
import { repoPath } from '../helpers/paths';

vi.setConfig({ testTimeout: 20_000 });

const BASE = 'http://127.0.0.1:3001';
const PUBLIC_DIR = repoPath('public');
const NOW = new Date().toISOString();
const XSS = '<img src=x onerror="window.__pwned=1">';
const WEB_ID = '77777777-8888-4999-8aaa-bbbbbbbbbbb1';
const DEP_ID = '77777777-8888-4999-8aaa-bbbbbbbbbbb2';
const PROJECT = { id: '11111111-2222-4333-8444-555555555555', name: `Portal ${XSS}`, criticality: 'medium', repo_url: null, web_url: 'https://portal.sirket.local/app/', web_scan_mode: 'passive', ecosystems: [], created_at: NOW };

const baseScan = { project_id: PROJECT.id, project_name: 'Portal', trigger: 'manual', queued_at: NOW, started_at: NOW, completed_at: NOW, error_message: null, total_dependencies: 0, total_vulnerabilities: 3, critical_vulns: 0, high_vulns: 1, license_violations: 0 };
const WEB_SCAN = { ...baseScan, id: WEB_ID, status: 'completed', ref: null, scan_kind: 'web', target_url: 'https://portal.sirket.local/app/', web_summary: { grade: 'C', score: 64 } };
const DEP_SCAN = { ...baseScan, id: DEP_ID, status: 'completed', ref: 'main', scan_kind: 'dependency', target_url: null, web_summary: null, total_dependencies: 12 };

const WEB_FINDINGS = {
  scan: { id: WEB_ID, project_id: PROJECT.id, project_name: 'Portal', target_url: 'https://portal.sirket.local/app/', completed_at: NOW },
  score: 64, grade: 'C', counts: { critical: 0, high: 1, medium: 2, low: 0, info: 1 },
  summary: { engines: { builtin: 'complete', zap: 'not_configured', zap_mode: null }, vulnerability_lookup: 'complete', requests: 40 },
  findings: [{
    id: 'f1', rule_id: 'WEB-EXP-002', source: 'builtin', category: 'exposure', severity: 'high', confidence: 'high',
    title: `.env ${XSS}`, description: 'desc', recommendation: `fix ${XSS}`, location: 'https://portal.sirket.local/.env',
    evidence: `1 anahtar; ör. ${XSS}`, cwe_id: 538, owasp: 'A05:2021', component_name: null, component_version: null,
    fixed_version: null, cvss_score: null, advisory_id: null, status: 'open',
  }],
  components: [{ name: 'jQuery', npm_name: 'jquery', version: '1.12.4', detection: 'url', location: 'x' }],
};

interface Reply { status: number; body?: unknown }
type Handler = (body: unknown) => Reply;
interface Call { key: string; body: unknown }

type LoaderResult = (Promise<Buffer> & { abort(): void }) | null;
type ResourceLoaderCtor = new () => { fetch(url: string, options: unknown): LoaderResult };
const ResourceLoaderBase = (jsdomModule as unknown as { ResourceLoader: ResourceLoaderCtor }).ResourceLoader;
class PublicDirLoader extends ResourceLoaderBase {
  override fetch(url: string): LoaderResult {
    const target = new URL(url);
    if (target.origin !== BASE || target.pathname.startsWith('/vendor/')) return null;
    const file = path.resolve(PUBLIC_DIR, `.${decodeURIComponent(target.pathname)}`);
    if (!file.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return null;
    return Object.assign(Promise.resolve(fs.readFileSync(file)), { abort: () => undefined });
  }
}

let open: JSDOM[] = [];
afterEach(() => {
  for (const d of open) d.window.close();
  open = [];
});

function loadPage(over: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const routes: Record<string, Handler> = {
    'GET /health': () => ({ status: 200, body: { status: 'healthy', database: 'connected' } }),
    'GET /api/auth/me': () => ({ status: 200, body: { data: { id: 'u', email: 'qa@example.test', displayName: 'QA', roles: ['admin'] } } }),
    'GET /api/projects': () => ({ status: 200, body: { data: [PROJECT] } }),
    'GET /api/scans': () => ({ status: 200, body: { data: [WEB_SCAN, DEP_SCAN] } }),
    [`GET /api/scans/${WEB_ID}/web-findings`]: () => ({ status: 200, body: { data: WEB_FINDINGS } }),
    ...over,
  };
  const dom = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8'), {
    url: `${BASE}/`, runScripts: 'dangerously', resources: new PublicDirLoader() as never, pretendToBeVisual: true,
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>;
      w.alert = () => undefined;
      w.lucide = { createIcons: () => undefined };
      const con = window.console as unknown as Record<string, unknown>;
      for (const m of ['log', 'info', 'warn', 'error', 'debug']) con[m] = () => undefined;
      w.fetch = async (input: unknown, init?: { method?: string; body?: string }) => {
        const url = new URL(String(input), BASE);
        const key = `${(init?.method ?? 'GET').toUpperCase()} ${url.pathname}`;
        const body = init?.body ? JSON.parse(init.body) : undefined;
        calls.push({ key, body });
        const handler = routes[key];
        const reply = handler ? handler(body) : { status: 200, body: { data: [] } };
        return new Response(reply.status === 204 ? null : JSON.stringify(reply.body ?? {}), { status: reply.status, headers: { 'Content-Type': 'application/json' } });
      };
    },
  });
  open.push(dom);
  return { dom, doc: dom.window.document, calls };
}

async function waitFor(cond: () => boolean, what: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > 5000) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

describe('AC-P27-5: scan rows', () => {
  it('a web scan row shows the Web badge, the target host, the grade and only the web PDF/CSV links', async () => {
    const { doc } = loadPage();
    await waitFor(() => !!doc.getElementById(`scan-row-${WEB_ID}`), 'rows');
    const row = doc.getElementById(`scan-row-${WEB_ID}`)!;
    expect(row.querySelector('.kind-web')?.textContent).toBe('Web');
    expect(row.textContent).toContain('portal.sirket.local');
    expect(row.textContent).toContain('Grade C');
    const links = Array.from(row.querySelectorAll('a')).map((a) => [a.getAttribute('href'), a.textContent?.trim()]);
    expect(links).toEqual([
      [`/api/scans/${WEB_ID}/exports/web-report.pdf`, 'PDF'],
      [`/api/scans/${WEB_ID}/exports/web-findings.csv`, 'CSV'],
    ]);
    // The dependency row keeps its five outputs.
    expect(doc.getElementById(`scan-row-${DEP_ID}`)!.querySelectorAll('a')).toHaveLength(5);
  });
});

describe('AC-P27-5: Vulnerabilities view for a web scan', () => {
  it('loads /web-findings, renders the grade card and findings as text (no injected element)', async () => {
    const { dom, doc, calls } = loadPage();
    await waitFor(() => calls.some((c) => c.key === 'GET /api/scans'), 'dashboard');
    (doc.querySelector('#sidebar-nav [data-view="findings"]') as HTMLButtonElement).click();
    await waitFor(() => !!doc.querySelector('.web-summary'), 'web summary');
    expect(calls.some((c) => c.key === `GET /api/scans/${WEB_ID}/web-findings`)).toBe(true);
    const container = doc.getElementById('findings-container')!;
    expect(container.querySelector('.web-grade')?.textContent).toBe('C');
    expect(container.textContent).toContain('Security grade C · 64/100');
    expect(container.textContent).toContain(XSS);
    expect(container.querySelector('img')).toBeNull();
    expect((dom.window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    expect(container.textContent).toContain('jQuery 1.12.4');
  });

  it('the SBOM Center dropdown lists dependency scans only', async () => {
    const { doc, calls } = loadPage();
    await waitFor(() => calls.some((c) => c.key === 'GET /api/scans'), 'dashboard');
    (doc.querySelector('#sidebar-nav [data-view="sbom"]') as HTMLButtonElement).click();
    await waitFor(() => (doc.getElementById('sbom-scan-select') as HTMLSelectElement).options.length > 0 && (doc.getElementById('sbom-scan-select') as HTMLSelectElement).options[0].value !== '', 'sbom options');
    const values = Array.from((doc.getElementById('sbom-scan-select') as HTMLSelectElement).options).map((o) => o.value);
    expect(values).toEqual([DEP_ID]);
  });
});

describe('AC-P27-6 / AC-P28-7: projects view', () => {
  it('shows the web URL as text, Web Scan posts kind=web, the modal PATCHes webUrl/webScanMode and warns for active', async () => {
    const { doc, calls } = loadPage({
      'POST /api/scans': () => ({ status: 201, body: { data: { id: 'new' } } }),
      [`PATCH /api/projects/${PROJECT.id}`]: () => ({ status: 200, body: { data: PROJECT } }),
    });
    await waitFor(() => calls.some((c) => c.key === 'GET /api/scans'), 'dashboard');
    (doc.querySelector('#sidebar-nav [data-view="projects"]') as HTMLButtonElement).click();
    await waitFor(() => !!doc.querySelector('button[data-action="web-scan-project"]'), 'project row');
    const tbody = doc.getElementById('projects-list-tbody')!;
    expect(tbody.textContent).toContain('https://portal.sirket.local/app/');
    expect(tbody.querySelector('img')).toBeNull();
    // No repository -> no dependency "Scan Now" button.
    expect(tbody.querySelector('button[data-action="scan-project"]')).toBeNull();

    (tbody.querySelector('button[data-action="web-scan-project"]') as HTMLButtonElement).click();
    await waitFor(() => calls.some((c) => c.key === 'POST /api/scans'), 'web scan posted');
    expect(calls.find((c) => c.key === 'POST /api/scans')?.body).toEqual({ projectId: PROJECT.id, trigger: 'manual', kind: 'web' });

    (doc.querySelector('#sidebar-nav [data-view="projects"]') as HTMLButtonElement).click();
    await waitFor(() => !!doc.querySelector('button[data-action="edit-web-url"]'), 'project row again');
    (doc.querySelector('button[data-action="edit-web-url"]') as HTMLButtonElement).click();
    expect(doc.getElementById('webUrlModal')!.classList.contains('open')).toBe(true);
    expect((doc.getElementById('webUrlInput') as HTMLInputElement).value).toBe(PROJECT.web_url);
    const mode = doc.getElementById('webScanMode') as HTMLSelectElement;
    mode.value = 'active';
    mode.dispatchEvent(new doc.defaultView!.Event('change'));
    expect(doc.getElementById('webScanModeWarning')!.classList.contains('show')).toBe(true);
    (doc.getElementById('webUrlInput') as HTMLInputElement).value = '  ';
    (doc.getElementById('web-modal-save-btn') as HTMLButtonElement).click();
    await waitFor(() => calls.some((c) => c.key === `PATCH /api/projects/${PROJECT.id}`), 'patch');
    expect(calls.find((c) => c.key === `PATCH /api/projects/${PROJECT.id}`)?.body).toEqual({ webUrl: null, webScanMode: 'active' });
  });

  it('New Project Scan with only a web URL creates the project with webUrl and queues only a web scan', async () => {
    const { doc, calls } = loadPage({
      'POST /api/projects': () => ({ status: 201, body: { data: { id: 'p-new' } } }),
      'POST /api/scans': () => ({ status: 201, body: { data: { id: 's-new' } } }),
    });
    await waitFor(() => calls.some((c) => c.key === 'GET /api/scans'), 'dashboard');
    (doc.getElementById('new-scan-btn') as HTMLButtonElement).click();
    (doc.getElementById('projectName') as HTMLInputElement).value = 'Web only';
    (doc.getElementById('webUrl') as HTMLInputElement).value = 'https://portal.sirket.local/';
    (doc.getElementById('launch-btn') as HTMLButtonElement).click();
    await waitFor(() => calls.some((c) => c.key === 'POST /api/scans'), 'scan queued');
    expect(calls.find((c) => c.key === 'POST /api/projects')?.body).toEqual({ name: 'Web only', ecosystems: ['nodejs'], webUrl: 'https://portal.sirket.local/' });
    expect(calls.filter((c) => c.key === 'POST /api/scans').map((c) => c.body)).toEqual([{ projectId: 'p-new', trigger: 'manual', kind: 'web' }]);
  });
});
