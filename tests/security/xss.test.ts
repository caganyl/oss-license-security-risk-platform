/**
 * REQ-002 · P-02 (AC-P02-1…7) — public/index.html in jsdom.
 * fetch is replaced by an in-memory fake API. Sub-resources are served by
 * PublicDirLoader: same-origin `<script src="/…">` files are read from
 * public/ (so the page script may live in `public/app.js`, AC-P02-6), while
 * public/vendor/* (lucide, stubbed as `window.lucide`) and every external URL
 * are never loaded. Every dynamic field returned by the API carries an
 * HTML/JS payload; the UI must render it as text: no element is created from
 * it, no handler runs. The static part checks the D-17 page structure.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as jsdomModule from 'jsdom';
import { JSDOM } from 'jsdom';
import { repoPath } from '../helpers/paths';

vi.setConfig({ testTimeout: 20_000 });

const XSS = '<img src=x onerror=alert(1)>';
const QUOTE_BREAK = "x');alert(2);//";
const BASE = 'http://127.0.0.1:3001';
const IDS = {
  project: '11111111-2222-4333-8444-555555555555',
  scan: '66666666-7777-4888-8999-aaaaaaaaaaaa',
  user: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
};
const NOW = new Date().toISOString();

type Route = (method: string, body: unknown) => { status: number; body: unknown } | undefined;

function defaultApi(overrides: Record<string, Route> = {}): Route {
  const routes: Record<string, Route> = {
    'GET /health': () => ({ status: 200, body: { status: 'healthy', database: 'connected' } }),
    'GET /api/auth/me': () => ({ status: 200, body: { data: { id: IDS.user, email: XSS, displayName: XSS, roles: ['admin'] } } }),
    'GET /api/projects': () => ({
      status: 200,
      body: { data: [{ id: IDS.project, name: XSS, description: XSS, criticality: 'high', repo_url: XSS, ecosystems: ['nodejs'], tags: [], created_at: NOW }] },
    }),
    'GET /api/scans': () => ({
      status: 200,
      body: {
        data: [{
          id: IDS.scan, project_id: IDS.project, project_name: XSS, status: 'completed', ref: XSS, trigger: 'manual',
          total_dependencies: 2, total_vulnerabilities: 1, critical_vulns: 1, high_vulns: 0, license_violations: 1,
          queued_at: NOW, started_at: NOW, completed_at: NOW, error_message: XSS,
        }],
      },
    }),
    [`GET /api/scans/${IDS.scan}`]: () => ({ status: 200, body: { data: { id: IDS.scan, project_name: XSS, status: 'completed', ref: XSS } } }),
    [`GET /api/scans/${IDS.scan}/findings`]: () => ({
      status: 200,
      body: {
        data: [
          {
            id: 'f1', finding_type: 'security', status: 'open', severity: 'critical', cvss_score: 9.8, fix_version: XSS, fix_available: true,
            vuln_title: XSS, vuln_description: XSS, cve_id: XSS, ghsa_id: null, package_name: XSS, package_version: XSS, purl: 'pkg:npm/x@1',
          },
          {
            id: 'f2', finding_type: 'license', status: 'open', detected_license: XSS, normalized_license: XSS, risk_level: 'high',
            applied_policy: XSS, package_name: XSS, package_version: XSS, purl: 'pkg:npm/y@1',
          },
        ],
      },
    }),
    [`GET /api/scans/${IDS.scan}/sbom`]: () => ({ status: 200, body: { data: [] } }),
    'GET /api/users': () => ({
      status: 200,
      body: { data: [{ id: IDS.user, display_name: XSS, email: XSS, roles: ['admin'], status: 'active', created_at: NOW }] },
    }),
    'POST /api/scans': () => ({ status: 201, body: { data: { id: IDS.scan } } }),
    ...overrides,
  };
  return (key, body) => routes[key]?.(key, body);
}

interface Page {
  dom: JSDOM;
  alert: ReturnType<typeof vi.fn>;
  calls: string[];
}

let open: JSDOM[] = [];
afterEach(() => {
  for (const dom of open) dom.window.close();
  open = [];
});

const PUBLIC_DIR = repoPath('public');

/**
 * jsdom 26 (runtime) exports ResourceLoader, but the installed @types/jsdom
 * no longer declares it; the minimal shape used here is typed locally.
 */
type LoaderResult = (Promise<Buffer> & { abort(): void }) | null;
type ResourceLoaderCtor = new () => { fetch(url: string, options: unknown): LoaderResult };
const ResourceLoaderBase = (jsdomModule as unknown as { ResourceLoader: ResourceLoaderCtor }).ResourceLoader;

/** Serves same-origin files from public/ (except vendor/); everything else is not loaded. */
class PublicDirLoader extends ResourceLoaderBase {
  override fetch(url: string, options: unknown): LoaderResult {
    const target = new URL(url);
    if (target.origin !== BASE || target.pathname.startsWith('/vendor/')) return null;
    const file = path.resolve(PUBLIC_DIR, `.${decodeURIComponent(target.pathname)}`);
    if (!file.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      return null; // missing local files are reported by the static AC-P02-6 test
    }
    void options;
    return Object.assign(Promise.resolve(fs.readFileSync(file)), { abort: () => undefined });
  }
}

function loadPage(overrides: Record<string, Route> = {}): Page {
  const html = fs.readFileSync(repoPath('public', 'index.html'), 'utf8');
  const api = defaultApi(overrides);
  const alert = vi.fn();
  const calls: string[] = [];
  const dom = new JSDOM(html, {
    url: `${BASE}/`,
    runScripts: 'dangerously',
    resources: new PublicDirLoader() as never, // see ResourceLoaderBase
    pretendToBeVisual: true,
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>;
      w.alert = alert;
      w.confirm = () => true;
      w.prompt = () => null;
      w.lucide = { createIcons: () => undefined };
      w.fetch = async (input: unknown, init?: { method?: string; body?: unknown }) => {
        const url = new URL(String(input), BASE);
        const method = (init?.method ?? 'GET').toUpperCase();
        const key = `${method} ${url.pathname}`;
        calls.push(key);
        const hit = api(key, init?.body);
        const status = hit?.status ?? 404;
        const body = hit?.body ?? { error: 'Not Found', message: 'Resource not found', code: 'not_found' };
        return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
      };
    },
  });
  open.push(dom);
  return { dom, alert, calls };
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out waiting for: ${what} (if the payload is missing as text, it was parsed as HTML — AC-P02)`);
    }
    await new Promise((r) => setTimeout(r, 20));
  }
}

function payloadCount(page: Page): number {
  const text = page.dom.window.document.body.textContent ?? '';
  return text.split(XSS).length - 1;
}

/** Nothing executable was created from API data. */
function expectNoInjection(page: Page): void {
  const doc = page.dom.window.document;
  expect(doc.querySelectorAll('img').length, 'an <img> element was created from API data').toBe(0);
  expect(doc.querySelectorAll('[onerror], [onload]').length, 'an onerror/onload attribute was created from API data').toBe(0);
  const scripts = Array.from(doc.querySelectorAll('script')).filter((s) => !s.src && (s.textContent ?? '').includes('alert('));
  expect(scripts.length, 'a <script> element was created from API data').toBe(0);
  expect(page.alert).not.toHaveBeenCalled();
}

function navigate(page: Page, view: string): void {
  const btn = page.dom.window.document.querySelector<HTMLElement>(`[data-view="${view}"]`);
  if (!btn) throw new Error(`navigation entry for view "${view}" not found`);
  btn.click();
}

describe('P-02 XSS — API data is rendered as text (AC-P02-1…3)', () => {
  it('AC-P02-1: project name in the dashboard scan list is plain text; no img, no handler', async () => {
    const page = loadPage();
    await waitFor(() => page.calls.includes('GET /api/scans') && payloadCount(page) > 0, 'scan list rendered with the payload as text');
    expectNoInjection(page);
  });

  it('AC-P02-1: project name and repo URL in the projects view are plain text', async () => {
    const page = loadPage();
    await waitFor(() => page.calls.includes('GET /api/scans'), 'initial load');
    navigate(page, 'projects');
    await waitFor(() => page.calls.includes('GET /api/projects') && payloadCount(page) >= 2, 'projects rendered');
    expectNoInjection(page);
  });

  it('AC-P02-1: a quote-breaking project name cannot inject code into inline handlers', async () => {
    const page = loadPage({
      'GET /api/projects': () => ({
        status: 200,
        body: { data: [{ id: IDS.project, name: QUOTE_BREAK, criticality: 'low', repo_url: null, ecosystems: [], tags: [], created_at: NOW }] },
      }),
    });
    await waitFor(() => page.calls.includes('GET /api/scans'), 'initial load');
    navigate(page, 'projects');
    const doc = page.dom.window.document;
    await waitFor(() => (doc.body.textContent ?? '').includes(QUOTE_BREAK), 'quote-break name rendered');
    const row = Array.from(doc.querySelectorAll('tr, li, .card, div')).find(
      (el) => (el.textContent ?? '').includes(QUOTE_BREAK) && el.querySelector('button'),
    );
    for (const button of Array.from(row?.querySelectorAll('button') ?? [])) (button as HTMLElement).click();
    await new Promise((r) => setTimeout(r, 100));
    expect(page.alert).not.toHaveBeenCalled();
  });

  it('AC-P02-3: package name, license, CVE id/title/description in the findings view are plain text', async () => {
    const page = loadPage();
    await waitFor(() => page.calls.includes('GET /api/scans'), 'initial load');
    navigate(page, 'findings');
    await waitFor(() => page.calls.includes(`GET /api/scans/${IDS.scan}/findings`) && payloadCount(page) >= 6, 'findings rendered');
    expectNoInjection(page);
  });

  it('AC-P02-3: user display name and e-mail in the users view are plain text', async () => {
    const page = loadPage();
    await waitFor(() => page.calls.includes('GET /api/scans'), 'initial load');
    navigate(page, 'users');
    await waitFor(() => page.calls.includes('GET /api/users') && payloadCount(page) >= 2, 'users rendered');
    expectNoInjection(page);
  });

  it('AC-P02-3: a server error message is shown as text', async () => {
    const page = loadPage({
      'POST /api/scans': () => ({ status: 400, body: { error: 'Bad Request', message: XSS, code: 'invalid_request' } }),
      'POST /api/projects': () => ({ status: 400, body: { error: 'Bad Request', message: XSS, code: 'invalid_request' } }),
    });
    await waitFor(() => page.calls.includes('GET /api/scans'), 'initial load');
    navigate(page, 'projects');
    const doc = page.dom.window.document;
    const findScanButton = () =>
      Array.from(doc.querySelectorAll('button')).find((b) => /scan/i.test(b.textContent ?? '') && b.closest('tr, li, .card'));
    await waitFor(() => findScanButton() !== undefined, 'per-project scan button rendered');
    const before = payloadCount(page);
    const scanButton = findScanButton()!;
    (scanButton as HTMLElement).click();
    await waitFor(() => page.calls.includes('POST /api/scans') && payloadCount(page) > before, 'error message rendered');
    expectNoInjection(page);
  });
});

describe('P-02 page structure: no external or inline script (AC-P02-5…7, D-17, contract K13)', () => {
  const EXTERNAL_RE = /^\s*(?:[a-z][a-z0-9+.-]*:|\/\/)/i; // any scheme (http:, https:, data:, javascript:) or protocol-relative
  const html = fs.readFileSync(repoPath('public', 'index.html'), 'utf8');
  const doc = new JSDOM(html).window.document; // parsed only; no script runs
  const scripts = Array.from(doc.querySelectorAll('script'));
  const localFile = (src: string) => path.join(PUBLIC_DIR, ...src.replace(/^\//, '').split('/'));

  it('AC-P02-5: no <script src> points to an external origin (http, https, //, data:, javascript:)', () => {
    const external = scripts.map((s) => s.getAttribute('src')).filter((src): src is string => src !== null && EXTERNAL_RE.test(src));
    expect(external).toEqual([]);
  });

  it('AC-P02-5: lucide 1.48.0 is loaded from the local /vendor/ path and the file exists', () => {
    const lucide = scripts.map((s) => s.getAttribute('src') ?? '').filter((src) => /lucide/i.test(src));
    expect(lucide).toEqual(['/vendor/lucide-1.48.0.min.js']);
    expect(fs.existsSync(localFile(lucide[0]))).toBe(true);
  });

  it('AC-P02-6: no inline <script> (every script has a src and an empty body)', () => {
    const inline = scripts.filter((s) => !s.hasAttribute('src') || (s.textContent ?? '').trim() !== '');
    expect(inline.map((s) => (s.textContent ?? '').trim().slice(0, 60))).toEqual([]);
  });

  it('AC-P02-6: the page script is public/app.js, loaded as /app.js; every local script file exists', () => {
    const srcs = scripts.map((s) => s.getAttribute('src')).filter((src): src is string => src !== null);
    expect(srcs).toContain('/app.js');
    for (const src of srcs.filter((s) => !EXTERNAL_RE.test(s))) {
      expect(fs.existsSync(localFile(src)), `${src} under public/`).toBe(true);
    }
  });

  it('AC-P02-6: no inline event handler attributes (on*=) and no javascript: URLs', () => {
    const offenders: string[] = [];
    for (const el of Array.from(doc.querySelectorAll('*'))) {
      for (const attr of Array.from(el.attributes)) {
        if (/^on/i.test(attr.name)) offenders.push(`<${el.tagName.toLowerCase()} ${attr.name}>`);
        if (/^(href|src|action|formaction)$/i.test(attr.name) && /^\s*javascript:/i.test(attr.value)) {
          offenders.push(`<${el.tagName.toLowerCase()} ${attr.name}="javascript:…">`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('AC-P02-7 (a): no external stylesheet, font or preconnect link; no external @import/url() in inline styles', () => {
    const links = Array.from(doc.querySelectorAll('link[href]'))
      .map((l) => `${l.getAttribute('rel') ?? ''} ${l.getAttribute('href') ?? ''}`)
      .filter((entry) => EXTERNAL_RE.test(entry.split(' ').pop() ?? ''));
    expect(links).toEqual([]);
    const styles = Array.from(doc.querySelectorAll('style')).map((s) => s.textContent ?? '').join('\n');
    expect(styles).not.toMatch(/@import\s+(?:url\()?\s*['"]?\s*(?:https?:)?\/\//i);
    expect(styles).not.toMatch(/url\(\s*['"]?\s*(?:https?:)?\/\//i);
    expect(html).not.toMatch(/fonts\.(googleapis|gstatic)\.com/i);
  });
});

describe('P-02 UI works with the P-01 session (AC-P02-4)', () => {
  const hasPasswordInput = (page: Page) => page.dom.window.document.querySelector('input[type="password"]') !== null;

  it('AC-P02-4: GET /api/auth/me 401 setup_required -> a password (setup) form is shown, no data requests succeed', async () => {
    const unauth = () => ({ status: 401, body: { error: 'Unauthorized', message: 'Initial password setup required', code: 'setup_required' } });
    const page = loadPage({ 'GET /api/auth/me': unauth, 'GET /api/scans': unauth, 'GET /api/projects': unauth });
    await waitFor(() => hasPasswordInput(page), 'setup form with a password field');
  });

  it('AC-P02-4: 401 unauthenticated from a data endpoint -> login form; server message rendered as text', async () => {
    const unauth = () => ({ status: 401, body: { error: 'Unauthorized', message: 'Authentication required', code: 'unauthenticated' } });
    const page = loadPage({
      'GET /api/auth/me': unauth,
      'GET /api/scans': unauth,
      'GET /api/projects': unauth,
      'POST /api/auth/login': () => ({ status: 401, body: { error: 'Unauthorized', message: XSS, code: 'invalid_credentials' } }),
    });
    await waitFor(() => hasPasswordInput(page), 'login form with a password field');
    const doc = page.dom.window.document;
    const input = doc.querySelector<HTMLInputElement>('input[type="password"]')!;
    input.value = 'wrong-password-123';
    const form = input.closest('form');
    if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
    else (input.closest('div, section, form')?.querySelector('button') as HTMLElement | null)?.click();
    await waitFor(() => page.calls.includes('POST /api/auth/login') && payloadCount(page) > 0, 'login error message rendered');
    expectNoInjection(page);
  });
});
