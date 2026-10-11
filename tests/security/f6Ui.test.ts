/**
 * REQ-007 UI (contract `docs/contracts/REQ-007-cli-and-exports.md` sections 8
 * and 9): public/index.html + public/app.js in jsdom with an in-memory fake
 * API (approach of tests/security/noticeLink.test.ts).
 *   AC-P24-8 / AC-P24-9  one-click links PDF, Excel, CSV, NOTICE, SBOM
 *   AC-AK-1…4            API Keys view: list/empty/error, create with one-time
 *                        reveal, removal on Done / view switch / pagehide /
 *                        logout, Copy (both paths), revoke; the key never
 *                        reaches storage, console, URL or serialised markup.
 * The key below is assembled at run time and is not a real credential.
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
const SECRET = 'S'.repeat(20) + 'qa_TEST-only' + 'x'.repeat(11); // 43 chars
const PREFIX = ['ossr', '0123456789abcdef'].join('_');
const NEW_KEY = `${PREFIX}_${SECRET}`;
const ID = {
  done1: '66666666-7777-4888-8999-aaaaaaaaaaa1',
  done2: '66666666-7777-4888-8999-aaaaaaaaaaa2',
  running: '66666666-7777-4888-8999-aaaaaaaaaaa3',
  failed: '66666666-7777-4888-8999-aaaaaaaaaaa4',
  pending: '66666666-7777-4888-8999-aaaaaaaaaaa5',
};
const scan = (id: string, status: string) => ({
  id, project_id: '11111111-2222-4333-8444-555555555555', project_name: `p-${status}`, status, ref: 'main', trigger: 'manual',
  total_dependencies: 1, total_vulnerabilities: 0, critical_vulns: 0, high_vulns: 0, license_violations: 0,
  queued_at: NOW, started_at: NOW, completed_at: status === 'completed' ? NOW : null, error_message: null,
});

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

interface Page {
  dom: JSDOM;
  doc: Document;
  calls: Call[];
  routes: Record<string, Handler>;
  confirms: string[];
  confirmAnswer: { value: boolean };
  sinks: string[];
  clipboard: { writes: string[]; mode: 'ok' | 'missing' | 'reject' };
}

const KEY_ROWS = [
  { id: 'k-active', name: '<img src=x onerror=alert(1)>', keyPrefix: PREFIX, createdAt: NOW, lastUsedAt: null, revokedAt: null },
  { id: 'k-old', name: null, keyPrefix: 'ossr_fedcba9876543210', createdAt: NOW, lastUsedAt: NOW, revokedAt: NOW },
];

function loadPage(over: Record<string, Handler> = {}): Page {
  const calls: Call[] = [];
  const confirms: string[] = [];
  const confirmAnswer = { value: true };
  const sinks: string[] = [];
  const clipboard = { writes: [] as string[], mode: 'ok' as 'ok' | 'missing' | 'reject' };
  const routes: Record<string, Handler> = {
    'GET /health': () => ({ status: 200, body: { status: 'healthy', database: 'connected' } }),
    'GET /api/auth/me': () => ({ status: 200, body: { data: { id: 'u', email: 'qa@example.test', displayName: 'QA', roles: ['admin'] } } }),
    'GET /api/projects': () => ({ status: 200, body: { data: [] } }),
    'GET /api/scans': () => ({ status: 200, body: { data: [scan(ID.done1, 'completed'), scan(ID.running, 'running'), scan(ID.failed, 'failed'), scan(ID.pending, 'pending'), scan(ID.done2, 'completed')] } }),
    'GET /api/auth/api-keys': () => ({ status: 200, body: { data: KEY_ROWS } }),
    'POST /api/auth/api-keys': () => ({ status: 201, body: { data: { id: 'k-new', name: 'ci', keyPrefix: PREFIX, key: NEW_KEY, createdAt: NOW } } }),
    'DELETE /api/auth/api-keys/k-active': () => ({ status: 204 }),
    'POST /api/auth/logout': () => ({ status: 204 }),
    ...over,
  };
  const dom = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8'), {
    url: `${BASE}/`, runScripts: 'dangerously', resources: new PublicDirLoader() as never, pretendToBeVisual: true,
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>;
      w.alert = () => undefined;
      w.confirm = (msg: string) => { confirms.push(String(msg)); return confirmAnswer.value; };
      w.lucide = { createIcons: () => undefined };
      const record = (...a: unknown[]) => { sinks.push(a.map((x) => String(x)).join(' ')); };
      const con = window.console as unknown as Record<string, unknown>;
      for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace', 'table', 'dir']) con[m] = record;
      for (const store of [window.localStorage, window.sessionStorage]) {
        const s = store as unknown as Record<string, unknown>;
        s.setItem = (k: string, v: string) => { sinks.push(`${k}=${v}`); };
      }
      Object.defineProperty(window.navigator, 'clipboard', {
        configurable: true,
        get: () => (clipboard.mode === 'missing' ? undefined : {
          writeText: async (t: string) => {
            if (clipboard.mode === 'reject') throw new Error('denied');
            clipboard.writes.push(t);
          },
        }),
      });
      w.fetch = async (input: unknown, init?: { method?: string; body?: string }) => {
        const url = new URL(String(input), BASE);
        sinks.push(`url:${url.href}`);
        const key = `${(init?.method ?? 'GET').toUpperCase()} ${url.pathname}`;
        const body = init?.body ? JSON.parse(init.body) : undefined;
        calls.push({ key, body });
        const handler = routes[key];
        const reply = handler ? handler(body) : { status: 200, body: { data: [] } };
        return new Response(reply.status === 204 ? null : JSON.stringify(reply.body ?? {}), {
          status: reply.status, headers: { 'Content-Type': 'application/json' },
        });
      };
    },
  });
  open.push(dom);
  return { dom, doc: dom.window.document, calls, routes, confirms, confirmAnswer, sinks, clipboard };
}

async function waitFor(cond: () => boolean, what: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > 5000) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}
const tick = () => new Promise((r) => setTimeout(r, 50));
/** Drops whole-line `//` and `/** … *\/` comments (they describe the rules in prose). */
const stripLineComments = (code: string) => code.replace(/\/\*\*[\s\S]*?\*\//g, '').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');

async function openApiKeys(p: Page): Promise<void> {
  await waitFor(() => p.calls.some((c) => c.key === 'GET /api/scans'), 'dashboard loaded');
  (p.doc.querySelector('#sidebar-nav [data-view="api-keys"]') as HTMLButtonElement).click();
  await waitFor(() => (p.doc.getElementById('api-keys-body') as HTMLElement).dataset.state !== 'loading', 'api keys list settled');
}

async function createKey(p: Page, name = ''): Promise<void> {
  (p.doc.getElementById('api-key-name') as HTMLInputElement).value = name;
  (p.doc.getElementById('api-key-create-form') as HTMLFormElement).dispatchEvent(new p.dom.window.Event('submit', { cancelable: true, bubbles: true }));
  await tick();
}

function expectNoKeyLeak(p: Page): void {
  for (const s of p.sinks) {
    expect(s, 'key in storage / console / URL').not.toContain(SECRET);
  }
  expect(p.dom.window.location.href).not.toContain(SECRET);
  expect(p.doc.documentElement.outerHTML).not.toContain(SECRET);
  expect(p.doc.getElementById('toast-msg')?.textContent ?? '').not.toContain(SECRET);
}

// ---------------------------------------------------------------------------
describe('AC-P24-8 / AC-P24-9: one-click download links (contract section 8)', () => {
  it('completed rows: PDF, Excel, CSV, NOTICE, SBOM in this order; the four exports are <a download> with aria-labels and no target/rel; SBOM unchanged', async () => {
    const { doc } = loadPage();
    await waitFor(() => doc.querySelectorAll('a[href$="/notice"]').length >= 2, 'links rendered');
    for (const id of [ID.done1, ID.done2]) {
      const expected: Array<[string, string, string]> = [
        [`/api/scans/${id}/exports/project-report.pdf`, 'Download project PDF report', 'PDF'],
        [`/api/scans/${id}/exports/license-inventory.xlsx`, 'Download license inventory (Excel)', 'Excel'],
        [`/api/scans/${id}/exports/license-inventory.csv`, 'Download license inventory (CSV)', 'CSV'],
        [`/api/scans/${id}/notice`, 'Download NOTICE file', 'NOTICE'],
      ];
      const sbom = doc.querySelector<HTMLAnchorElement>(`a[href="/api/scans/${id}/sbom/download"]`)!;
      expect(sbom).not.toBeNull();
      for (const [href, label, text] of expected) {
        const matches = doc.querySelectorAll<HTMLAnchorElement>(`a[href="${href}"][download]`);
        expect(matches, href).toHaveLength(1);
        const a = matches[0];
        expect(a.getAttribute('download')).toBe('');
        expect(a.getAttribute('aria-label')).toBe(label);
        expect(a.textContent?.trim()).toBe(text);
        expect(a.className).toBe('btn btn-sm');
        expect(a.hasAttribute('target')).toBe(false);
        expect(a.hasAttribute('rel')).toBe(false);
        expect(a.getAttribute('style')).toBe(sbom.getAttribute('style'));
        expect(a.parentElement).toBe(sbom.parentElement);
      }
      expect(Array.from(sbom.parentElement!.querySelectorAll('a')).map((a) => a.textContent?.trim())).toEqual(['PDF', 'Excel', 'CSV', 'NOTICE', 'SBOM']);
      expect(sbom.getAttribute('target')).toBe('_blank');
      expect(sbom.getAttribute('rel')).toBe('noopener');
      expect(sbom.hasAttribute('download')).toBe(false);
    }
    for (const id of [ID.running, ID.failed, ID.pending]) expect(doc.querySelector(`a[href*="${id}"]`), id).toBeNull();
  });

  it('scanActions builds every href with apiPath and uses no fetch/Blob/innerHTML for downloads', () => {
    const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8').replace(/\r\n/g, '\n');
    const start = src.indexOf('function scanActions(');
    const body = stripLineComments(src.slice(start, src.indexOf('\n}\n', start)));
    expect(start).toBeGreaterThan(-1);
    for (const p of ["apiPath('scans', row.id, 'exports', 'project-report.pdf')", "apiPath('scans', row.id, 'exports', 'license-inventory.xlsx')",
      "apiPath('scans', row.id, 'exports', 'license-inventory.csv')", "apiPath('scans', row.id, 'notice')", "apiPath('scans', row.id, 'sbom', 'download')"]) {
      expect(body).toContain(p);
    }
    expect(body).not.toMatch(/fetch\(|Blob|createObjectURL|innerHTML|outerHTML|insertAdjacentHTML/);
  });
});

describe('AC-AK-1: API Keys view and list (contract 9.1, 9.2)', () => {
  it('static markup: nav entry after Users & Roles, CLI hint, form novalidate, name input limits', () => {
    const { doc } = loadPage();
    const nav = Array.from(doc.querySelectorAll<HTMLButtonElement>('#sidebar-nav .nav-item')).map((b) => b.dataset.view);
    expect(nav.indexOf('api-keys')).toBe(nav.indexOf('users') + 1);
    expect(doc.getElementById('view-api-keys')).not.toBeNull();
    expect(doc.getElementById('api-keys-cli-hint')!.textContent).toBe(
      'Use the key with the CLI: set OSS_RISK_API_KEY (or OSS_RISK_API_KEY_FILE) and run oss-risk scan --project <name>. Only one key is active at a time.',
    );
    expect(doc.getElementById('api-key-create-form')!.hasAttribute('novalidate')).toBe(true);
    const input = doc.getElementById('api-key-name') as HTMLInputElement;
    expect(input.getAttribute('maxlength')).toBe('100');
    expect(input.getAttribute('autocomplete')).toBe('off');
    expect(doc.getElementById('api-keys-error')!.getAttribute('role')).toBe('alert');
  });

  it('list: name (textContent, no markup), prefix, Never, Active / Revoked; Revoke only on the active row', async () => {
    const p = loadPage();
    await openApiKeys(p);
    const { doc } = p;
    expect(doc.getElementById('page-title')!.textContent).toBe('API Keys');
    expect((doc.getElementById('api-keys-body') as HTMLElement).dataset.state).toBe('ready');
    expect((doc.getElementById('api-keys-table') as HTMLElement).hidden).toBe(false);
    expect((doc.getElementById('api-keys-empty') as HTMLElement).hidden).toBe(true);
    const rows = Array.from(doc.querySelectorAll('#api-keys-tbody tr'));
    expect(rows).toHaveLength(2);
    const cells = (r: Element) => Array.from(r.children).map((c) => c.textContent?.trim());
    const [active, revoked] = rows;
    expect(cells(active)[0]).toBe('<img src=x onerror=alert(1)>');
    expect(doc.querySelector('#api-keys-tbody img')).toBeNull();
    expect(cells(active)[1]).toBe(PREFIX);
    expect(cells(active)[3]).toBe('Never');
    expect(cells(active)[4]).toBe('Active');
    const revokeBtn = active.querySelector('button')!;
    expect(revokeBtn.textContent?.trim()).toBe('Revoke');
    expect(revokeBtn.getAttribute('aria-label')).toBe(`Revoke API key ${PREFIX}`);
    expect(cells(revoked)[0]).toBe('—');
    expect(cells(revoked)[4]).toMatch(/^Revoked /);
    expect(revoked.querySelector('button')).toBeNull();
  });

  it('empty list -> "No API keys yet."; list error -> data-state error and alert', async () => {
    const empty = loadPage({ 'GET /api/auth/api-keys': () => ({ status: 200, body: { data: [] } }) });
    await openApiKeys(empty);
    expect((empty.doc.getElementById('api-keys-body') as HTMLElement).dataset.state).toBe('empty');
    expect((empty.doc.getElementById('api-keys-empty') as HTMLElement).hidden).toBe(false);
    expect((empty.doc.getElementById('api-keys-table') as HTMLElement).hidden).toBe(true);

    const broken = loadPage({ 'GET /api/auth/api-keys': () => ({ status: 500, body: { error: 'x', message: 'Internal server error', code: 'internal_error' } }) });
    await openApiKeys(broken);
    expect((broken.doc.getElementById('api-keys-body') as HTMLElement).dataset.state).toBe('error');
    expect((broken.doc.getElementById('api-keys-error') as HTMLElement).hidden).toBe(false);
    expect(broken.doc.getElementById('api-keys-error')!.textContent).toBe('Could not load API keys.');
  });
});

describe('AC-AK-2: create with one-time reveal (contract 9.3)', () => {
  it('active key -> confirm text; cancel -> no POST', async () => {
    const p = loadPage();
    await openApiKeys(p);
    p.confirmAnswer.value = false;
    await createKey(p, 'ci');
    expect(p.confirms).toEqual(['Creating a new key revokes the current active key. Continue?']);
    expect(p.calls.some((c) => c.key === 'POST /api/auth/api-keys')).toBe(false);
    expect(p.doc.getElementById('api-key-reveal')).toBeNull();
  });

  it('no active key -> no confirm; empty name -> body {}', async () => {
    const p = loadPage({ 'GET /api/auth/api-keys': () => ({ status: 200, body: { data: [KEY_ROWS[1]] } }) });
    await openApiKeys(p);
    await createKey(p, '   ');
    await waitFor(() => p.doc.getElementById('api-key-reveal') !== null, 'reveal panel');
    expect(p.confirms).toEqual([]);
    expect(p.calls.find((c) => c.key === 'POST /api/auth/api-keys')!.body).toEqual({});
  });

  it('confirm -> POST {name: trimmed}; panel shows the key once (readonly field value, not in markup); name cleared; list reloaded; nothing leaks', async () => {
    const p = loadPage();
    await openApiKeys(p);
    const listCalls = () => p.calls.filter((c) => c.key === 'GET /api/auth/api-keys').length;
    const before = listCalls();
    await createKey(p, '  ci-key  ');
    await waitFor(() => p.doc.getElementById('api-key-reveal') !== null, 'reveal panel');
    expect(p.calls.find((c) => c.key === 'POST /api/auth/api-keys')!.body).toEqual({ name: 'ci-key' });
    const field = p.doc.getElementById('api-key-value') as HTMLInputElement;
    expect(field.value).toBe(NEW_KEY);
    expect(field.readOnly).toBe(true);
    expect(field.getAttribute('autocomplete')).toBe('off');
    expect(field.getAttribute('aria-label')).toBe('New API key');
    expect(p.doc.getElementById('api-key-reveal')!.textContent).toContain('Copy this key now. It will not be shown again.');
    expect(p.doc.getElementById('api-key-copy-btn')).not.toBeNull();
    expect(p.doc.getElementById('api-key-dismiss-btn')!.textContent?.trim()).toBe('Done');
    expect((p.doc.getElementById('api-key-name') as HTMLInputElement).value).toBe('');
    await waitFor(() => listCalls() > before, 'list reloaded');
    expect((p.doc.getElementById('api-key-create-btn') as HTMLButtonElement).disabled).toBe(false);
    expectNoKeyLeak(p);
    // refreshAll keeps the panel (contract 9.3 step 6)
    (p.doc.getElementById('refresh-btn') as HTMLButtonElement).click();
    await tick();
    expect(p.doc.getElementById('api-key-reveal')).not.toBeNull();
  });

  it.each([
    ['Done', async (p: Page) => { (p.doc.getElementById('api-key-dismiss-btn') as HTMLButtonElement).click(); }],
    ['view switch', async (p: Page) => { (p.doc.querySelector('#sidebar-nav [data-view="dashboard"]') as HTMLButtonElement).click(); }],
    ['pagehide', async (p: Page) => { p.dom.window.dispatchEvent(new p.dom.window.Event('pagehide')); }],
    ['logout', async (p: Page) => { (p.doc.getElementById('logout-btn') as HTMLButtonElement).click(); }],
    ['401 redirect', async (p: Page) => {
      p.routes['GET /api/auth/api-keys'] = () => ({ status: 401, body: { error: 'x', message: 'Authentication required', code: 'unauthenticated' } });
      (p.doc.getElementById('refresh-btn') as HTMLButtonElement).click();
    }],
  ])('reveal panel is removed from the DOM on %s', async (_label, act) => {
    const p = loadPage();
    await openApiKeys(p);
    await createKey(p, 'ci');
    await waitFor(() => p.doc.getElementById('api-key-reveal') !== null, 'reveal panel');
    const field = p.doc.getElementById('api-key-value') as HTMLInputElement;
    await act(p);
    await waitFor(() => p.doc.getElementById('api-key-reveal') === null, 'panel removed');
    expect(field.value).toBe('');
    expect(p.doc.getElementById('api-key-value')).toBeNull();
    expectNoKeyLeak(p);
  });

  it('Copy: clipboard available -> writeText(key) and "Copied to clipboard"; missing or rejected -> field selected and "Press Ctrl+C to copy"', async () => {
    for (const mode of ['ok', 'missing', 'reject'] as const) {
      const p = loadPage();
      await openApiKeys(p);
      await createKey(p, 'ci');
      await waitFor(() => p.doc.getElementById('api-key-reveal') !== null, 'reveal panel');
      p.clipboard.mode = mode;
      (p.doc.getElementById('api-key-copy-btn') as HTMLButtonElement).click();
      const status = p.doc.getElementById('api-key-copy-status')!;
      await waitFor(() => (status.textContent ?? '') !== '', `copy status (${mode})`);
      if (mode === 'ok') {
        expect(status.textContent).toBe('Copied to clipboard');
        expect(p.clipboard.writes).toEqual([NEW_KEY]);
      } else {
        expect(status.textContent).toBe('Press Ctrl+C to copy');
        expect(p.clipboard.writes).toEqual([]);
      }
      expect(status.getAttribute('aria-live')).toBe('polite');
      expectNoKeyLeak(p);
    }
  });

  it('create error -> no panel, error toast without the key, button enabled again', async () => {
    const p = loadPage({ 'POST /api/auth/api-keys': () => ({ status: 400, body: { error: 'x', message: 'name must be at most 100 characters', code: 'invalid_request' } }) });
    await openApiKeys(p);
    await createKey(p, 'ci');
    await waitFor(() => (p.doc.getElementById('toast-msg')?.textContent ?? '') !== '', 'toast');
    expect(p.doc.getElementById('api-key-reveal')).toBeNull();
    expect(p.doc.getElementById('toast-msg')!.textContent).toBe('name must be at most 100 characters');
    expect((p.doc.getElementById('api-key-create-btn') as HTMLButtonElement).disabled).toBe(false);
  });
});

describe('AC-AK-3: revoke (contract 9.4)', () => {
  it('confirm text, DELETE /api/auth/api-keys/{id}, list reloaded; cancel -> no request', async () => {
    const p = loadPage();
    await openApiKeys(p);
    const btn = () => p.doc.querySelector<HTMLButtonElement>('#api-keys-tbody button')!;
    p.confirmAnswer.value = false;
    btn().click();
    await tick();
    expect(p.confirms).toEqual([`Revoke API key ${PREFIX}? Clients using it will stop working.`]);
    expect(p.calls.some((c) => c.key.startsWith('DELETE '))).toBe(false);

    p.confirmAnswer.value = true;
    const before = p.calls.filter((c) => c.key === 'GET /api/auth/api-keys').length;
    p.routes['GET /api/auth/api-keys'] = () => ({ status: 200, body: { data: [{ ...KEY_ROWS[0], revokedAt: NOW }, KEY_ROWS[1]] } });
    btn().click();
    await waitFor(() => p.calls.filter((c) => c.key === 'GET /api/auth/api-keys').length > before, 'list reloaded');
    expect(p.calls.filter((c) => c.key === 'DELETE /api/auth/api-keys/k-active')).toHaveLength(1);
    await waitFor(() => p.doc.querySelector('#api-keys-tbody button') === null, 'no active row');
  });

  it('revoking the key shown in the open panel also removes the panel', async () => {
    const p = loadPage({
      'POST /api/auth/api-keys': () => ({ status: 201, body: { data: { id: 'k-active', name: 'ci', keyPrefix: PREFIX, key: NEW_KEY, createdAt: NOW } } }),
    });
    await openApiKeys(p);
    await createKey(p, 'ci');
    await waitFor(() => p.doc.getElementById('api-key-reveal') !== null, 'reveal panel');
    await waitFor(() => p.doc.querySelector('#api-keys-tbody button') !== null, 'list ready');
    p.doc.querySelector<HTMLButtonElement>('#api-keys-tbody button')!.click();
    await waitFor(() => p.doc.getElementById('api-key-reveal') === null, 'panel removed on revoke');
  });

  it('revoke error -> error toast, row and button kept', async () => {
    const p = loadPage({ 'DELETE /api/auth/api-keys/k-active': () => ({ status: 500, body: { error: 'x', message: 'Internal server error', code: 'internal_error' } }) });
    await openApiKeys(p);
    p.doc.querySelector<HTMLButtonElement>('#api-keys-tbody button')!.click();
    await waitFor(() => (p.doc.getElementById('toast-msg')?.textContent ?? '') !== '', 'toast');
    expect(p.doc.getElementById('toast-msg')!.textContent).toBe('Internal server error');
    const btn = p.doc.querySelector<HTMLButtonElement>('#api-keys-tbody button')!;
    expect(btn).not.toBeNull();
    expect(btn.disabled).toBe(false);
  });
});

describe('AC-AK-4: static guarantees of the API Keys code', () => {
  it('no innerHTML, storage, console or inline handler in the API Keys block; the key is never assigned to a module-level variable', () => {
    const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8').replace(/\r\n/g, '\n');
    const start = src.indexOf('// API Keys view (REQ-007');
    const end = src.indexOf('// ── Modal Handlers', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const block = stripLineComments(src.slice(start, end));
    expect(block).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|console\.|history\.|location\.|setAttribute\('value'/);
    const moduleLets = Array.from(block.matchAll(/^let\s+(\w+)/gm)).map((m) => m[1]);
    expect(moduleLets.sort()).toEqual(['apiKeysHasActive', 'apiKeysLoadSeq']);
  });
});
