/**
 * REQ-010 UI (docs/product/REQ-010.md; contract docs/contracts/REQ-010-system-features.md):
 * public/index.html + public/app.js in jsdom with an in-memory fake API
 * (harness of tests/security/f6Ui.test.ts).
 *   AC-P33-1…5  Turkish UI, no English UI phrases, tr-TR / relative time,
 *               API error code -> Turkish text, clone error headlines
 *   AC-P34-1…4  view purposes, glossary tooltips, Help view (no server call)
 *   AC-P35-2/3  Sistem Durumu view and feature-aware modal hints
 *   AC-P36-1…3  dashboard counters, no preselected ecosystem, "Paket bulunamadı"
 *   AC-P38-1/2  "Raporlar" menu: items, keyboard, focus, aria-expanded
 *   AC-G-1      server data only as text
 */
import fs from 'node:fs';
import path from 'node:path';
import * as ts from 'typescript';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as jsdomModule from 'jsdom';
import { JSDOM } from 'jsdom';
import { repoPath } from '../helpers/paths';

vi.setConfig({ testTimeout: 20_000 });

const BASE = 'http://127.0.0.1:3001';
const PUBLIC_DIR = repoPath('public');
const XSS = '<img src=x onerror="window.__pwned=1">';
const P1 = '11111111-2222-4333-8444-555555555551';
const P2 = '11111111-2222-4333-8444-555555555552';
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

let seq = 0;
function scan(over: Record<string, unknown> = {}): Record<string, unknown> {
  seq += 1;
  return {
    id: `99999999-8888-4777-8666-${String(seq).padStart(12, '0')}`, project_id: P1, project_name: `proje-${seq}`, status: 'completed',
    ref: 'main', trigger: 'manual', scan_kind: 'dependency', target_url: null, web_summary: null,
    total_dependencies: 3, total_vulnerabilities: 0, critical_vulns: 0, high_vulns: 0, license_violations: 0,
    queued_at: ago(2 * MIN), started_at: ago(2 * MIN), completed_at: ago(MIN), error_message: null,
    ...over,
  };
}

interface Reply { status: number; body?: unknown; headers?: Record<string, string> }
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

const FEATURES_ALL_ON = {
  local_scan: { enabled: true, roots: 1 },
  web_scan: { enabled: true, allowed_hosts: 2 },
  zap: { enabled: false },
  registry_enrichment: { enabled: true },
  vulnerability_lookup: { enabled: true },
  vulnerability_recheck: { enabled: true },
  nvd: { enabled: true, api_key: false },
  repo_tokens: { enabled: true },
  windows_git_auth: { enabled: false, hosts: 0 },
};

function loadPage(over: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const routes: Record<string, Handler> = {
    'GET /health': () => ({ status: 200, body: { status: 'healthy', database: 'connected' } }),
    'GET /api/auth/me': () => ({ status: 200, body: { data: { id: 'u', email: 'qa@example.test', displayName: 'QA', roles: ['admin'] } } }),
    'GET /api/projects': () => ({ status: 200, body: { data: [] } }),
    'GET /api/scans': () => ({ status: 200, body: { data: [] } }),
    'GET /api/system/features': () => ({ status: 200, body: { data: FEATURES_ALL_ON } }),
    ...over,
  };
  const dom = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8'), {
    url: `${BASE}/`, runScripts: 'dangerously', resources: new PublicDirLoader() as never, pretendToBeVisual: true,
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>;
      w.alert = () => undefined;
      w.confirm = () => true;
      w.lucide = { createIcons: () => undefined };
      const con = window.console as unknown as Record<string, unknown>;
      for (const m of ['log', 'info', 'warn', 'error', 'debug']) con[m] = () => undefined;
      w.fetch = async (input: unknown, init?: { method?: string; body?: string }) => {
        const url = new URL(String(input), BASE);
        const key = `${(init?.method ?? 'GET').toUpperCase()} ${url.pathname}`;
        const body = init?.body ? JSON.parse(init.body) : undefined;
        calls.push({ key, body });
        const handler = routes[key];
        const reply = handler ? handler(body) : { status: 404, body: { error: 'Not Found', message: 'Resource not found', code: 'not_found' } };
        return new Response(reply.status === 204 ? null : JSON.stringify(reply.body ?? {}), {
          status: reply.status, headers: { 'Content-Type': 'application/json', ...(reply.headers ?? {}) },
        });
      };
    },
  });
  open.push(dom);
  return { dom, doc: dom.window.document, calls, routes };
}

async function waitFor(cond: () => boolean, what: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > 5000) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}
const tick = () => new Promise((r) => setTimeout(r, 50));
const toast = (doc: Document) => doc.getElementById('toast-msg')?.textContent ?? '';
const dashboardReady = (p: ReturnType<typeof loadPage>) => waitFor(() => p.calls.some((c) => c.key === 'GET /api/scans'), 'dashboard loaded');
const nav = (doc: Document, view: string) => (doc.querySelector(`#sidebar-nav [data-view="${view}"]`) as HTMLButtonElement).click();

// ---------------------------------------------------------------------------
// Static extraction of user-visible strings (AC-P33-2)
// ---------------------------------------------------------------------------

/** String literals and template-literal text of app.js (comments excluded by the parser). */
function appStringLiterals(): string[] {
  const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8');
  const sf = ts.createSourceFile('app.js', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const parent = node.parent;
      const isKey = (ts.isPropertyAssignment(parent) && parent.name === node) || (ts.isElementAccessExpression(parent) && parent.argumentExpression === node);
      if (!isKey) out.push(node.text);
    } else if (ts.isTemplateExpression(node)) {
      out.push(node.head.text, ...node.templateSpans.map((s) => s.literal.text));
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  // Code tokens (selectors, API paths, data-action values, CSS) have no upper-case letter and no space.
  return out.filter((s) => !(/^[^A-Z\s]*$/.test(s)) && !s.startsWith('/api/'));
}

/** Text nodes (outside <style>/<script>) and user-facing attributes of index.html. */
function htmlVisibleStrings(): string[] {
  const doc = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8')).window.document;
  const out: string[] = [doc.title, doc.querySelector('meta[name="description"]')?.getAttribute('content') ?? ''];
  const walker = doc.createTreeWalker(doc.body, 4 /* NodeFilter.SHOW_TEXT */);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const parent = (n as Text).parentElement;
    if (parent && !['SCRIPT', 'STYLE'].includes(parent.tagName) && (n.textContent ?? '').trim() !== '') out.push((n.textContent ?? '').trim());
  }
  for (const el of Array.from(doc.querySelectorAll('[title], [aria-label], [placeholder], [alt]'))) {
    for (const a of ['title', 'aria-label', 'placeholder', 'alt']) {
      const v = el.getAttribute(a);
      if (v) out.push(v);
    }
  }
  return out;
}

const ENGLISH_UI = [
  'Dashboard', 'Scan History', 'Launch Scanner', 'No scans', 'Failed to', 'Scan Now', 'Projects', 'Vulnerabilities',
  'Loading', 'Download', 'Sign in', 'Logout', 'Cancel', 'Completed', 'Pending', 'Scanning', 'Unexpected error',
  'Request failed', 'Could not', 'Generate', 'Revoke', 'Never', 'Settings', 'Users & Roles', 'API Keys',
  'Compliance Hub', 'License Alert', 'Security grade', 'Recommendation', 'Grade',
];

describe('AC-P33-1 / AC-P33-2: Turkish UI', () => {
  it('AC-P33-1: lang="tr"; product name "OSS Risk Platformu" in the page title and the sidebar', () => {
    const doc = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8')).window.document;
    expect(doc.documentElement.getAttribute('lang')).toBe('tr');
    expect(doc.title).toBe('OSS Risk Platformu');
    expect(doc.querySelector('aside .logo-text')?.textContent?.trim()).toBe('OSS Risk Platformu');
  });

  it('AC-P33-2: no English UI phrase in user-visible string literals of app.js or visible text/attributes of index.html', () => {
    const appStrings = appStringLiterals();
    const htmlStrings = htmlVisibleStrings();
    // The extractors really see the UI texts.
    expect(appStrings).toContain('Taramayı başlat');
    expect(appStrings).toContain('Genel Bakış');
    expect(htmlStrings).toContain('Tarama Geçmişi');
    const offenders: string[] = [];
    for (const [where, list] of [['app.js', appStrings], ['index.html', htmlStrings]] as const) {
      for (const s of list) {
        for (const phrase of ENGLISH_UI) {
          if (new RegExp(`\\b${phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(s)) offenders.push(`${where}: "${phrase}" in "${s.slice(0, 80)}"`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('AC-P33-2: sidebar menu, login screen and status labels are Turkish', async () => {
    const doc = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8')).window.document;
    expect(Array.from(doc.querySelectorAll('#sidebar-nav .nav-item')).map((b) => b.textContent?.trim())).toEqual([
      'Genel Bakış', 'Tarama Geçmişi', 'Bulgular', 'Projeler', 'SBOM Merkezi', 'Kullanıcılar ve Roller', 'API Anahtarları', 'Sistem Durumu', 'Yardım',
    ]);

    const unauth = () => ({ status: 401, body: { error: 'Unauthorized', message: 'Initial password setup required', code: 'setup_required' } });
    const setup = loadPage({ 'GET /api/auth/me': unauth });
    await waitFor(() => !!setup.doc.getElementById('auth-form'), 'setup form');
    expect(setup.doc.getElementById('auth-title')?.textContent).toBe('Yönetici parolasını belirleyin');
    expect(setup.doc.querySelector('label[for="auth-password"]')?.textContent).toBe('Yeni parola');
    expect(setup.doc.getElementById('auth-submit')?.textContent?.trim()).toBe('Parolayı kaydet ve devam et');

    const statuses = ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'];
    const rows = statuses.map((status) => scan({ status, completed_at: status === 'completed' ? ago(MIN) : null }));
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: rows } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody tr').length === statuses.length, 'rows');
    const badges = rows.map((r) => p.doc.getElementById(`scan-row-${r.id}`)!.querySelector('.status-badge')?.textContent?.trim());
    expect(badges).toEqual(['Bekliyor', 'Sırada', 'Taranıyor', 'Tamamlandı', 'Başarısız', 'İptal']);
  });

  it('AC-P33-3: Turkish relative time and tr-TR numbers', async () => {
    const rows = [
      scan({ completed_at: ago(10_000) }),
      scan({ completed_at: ago(5 * MIN + 5000) }),
      scan({ completed_at: ago(2 * HOUR + MIN) }),
      scan({ completed_at: ago(3 * DAY + HOUR), total_dependencies: 1234 }),
    ];
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: rows } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody tr').length === rows.length, 'rows');
    const timeCell = (r: Record<string, unknown>) => p.doc.getElementById(`scan-row-${r.id}`)!.children[5].textContent;
    expect(rows.map(timeCell)).toEqual(['az önce', '5 dk önce', '2 saat önce', '3 gün önce']);
    expect(p.doc.getElementById(`scan-row-${rows[3].id}`)!.children[2].textContent).toBe('1.234');
  });
});

describe('AC-P33-4: API error code -> Turkish actionable text', () => {
  it('path_not_allowed on project creation is shown as its Turkish text (not the server message)', async () => {
    const p = loadPage({
      'POST /api/projects': () => ({ status: 400, body: { error: 'Bad Request', message: 'Local path is not under an allowed scan root', code: 'path_not_allowed' } }),
    });
    await dashboardReady(p);
    (p.doc.getElementById('new-scan-btn') as HTMLButtonElement).click();
    (p.doc.getElementById('projectName') as HTMLInputElement).value = 'Yerel';
    (p.doc.getElementById('repoPath') as HTMLInputElement).value = 'D:\\Kod\\proje';
    (p.doc.getElementById('launch-btn') as HTMLButtonElement).click();
    await waitFor(() => toast(p.doc) !== '', 'toast');
    expect(toast(p.doc)).toMatch(/^Bu yerel klasör taranamaz: .*SCAN_ROOTS/);
    expect(toast(p.doc)).not.toContain('allowed scan root');
  });

  it('invalid_token when saving a repo token is shown as its Turkish text', async () => {
    const project = { id: P1, name: 'Özel repo', criticality: 'high', repo_url: 'https://tfs.sirket.local/c/p/_git/r', web_url: null, ecosystems: [], created_at: ago(DAY), has_repo_credential: false };
    const p = loadPage({
      'GET /api/projects': () => ({ status: 200, body: { data: [project] } }),
      [`PUT /api/projects/${P1}/repo-credential`]: () => ({ status: 400, body: { error: 'Bad Request', message: 'Body must be { "token": string }', code: 'invalid_token' } }),
    });
    await dashboardReady(p);
    nav(p.doc, 'projects');
    await waitFor(() => !!p.doc.querySelector('button[data-action="edit-repo-token"]'), 'token button');
    (p.doc.querySelector('button[data-action="edit-repo-token"]') as HTMLButtonElement).click();
    (p.doc.getElementById('repoTokenInput') as HTMLInputElement).value = 'abc def';
    (p.doc.getElementById('token-modal-save-btn') as HTMLButtonElement).click();
    await waitFor(() => toast(p.doc) !== '', 'toast');
    expect(toast(p.doc)).toBe('Token geçersiz: boşluk içermemeli ve en fazla 1024 karakter olmalı. Token’ı yeniden kopyalayıp yapıştırın.');
  });

  it('invalid_credentials on the login form, too_many_attempts with Retry-After, unknown code -> server message as text', async () => {
    const unauth = () => ({ status: 401, body: { error: 'Unauthorized', message: 'Authentication required', code: 'unauthenticated' } });
    let attempt = 0;
    const p = loadPage({
      'GET /api/auth/me': unauth,
      'POST /api/auth/login': () => {
        attempt += 1;
        if (attempt === 1) return { status: 401, body: { error: 'Unauthorized', message: 'Invalid credentials', code: 'invalid_credentials' } };
        if (attempt === 2) return { status: 429, body: { error: 'Too Many Requests', message: 'Too many attempts', code: 'too_many_attempts' }, headers: { 'Retry-After': '30' } };
        return { status: 400, body: { error: 'Bad Request', message: XSS, code: 'some_future_code' } };
      },
    });
    await waitFor(() => !!p.doc.getElementById('auth-form'), 'login form');
    const submit = async () => {
      (p.doc.getElementById('auth-password') as HTMLInputElement).value = 'wrong-password-123';
      const before = attempt;
      (p.doc.getElementById('auth-form') as HTMLFormElement).requestSubmit();
      await waitFor(() => attempt > before && (p.doc.getElementById('auth-submit') as HTMLButtonElement).disabled === false, 'login answered');
      await tick();
      return p.doc.getElementById('auth-error')?.textContent ?? '';
    };
    expect(await submit()).toBe('Parola hatalı. Kontrol edip tekrar deneyin.');
    expect(await submit()).toBe('Çok fazla deneme yapıldı. Biraz bekleyip tekrar deneyin. 30 saniye sonra tekrar deneyin.');
    expect(await submit()).toBe(XSS);
    expect(p.doc.querySelector('#auth-screen img')).toBeNull();
    expect((p.dom.window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe('AC-P33-5: clone error headline in Turkish, git detail unchanged', () => {
  it('a classified clone error gets the Turkish headline; the git detail follows as text; other errors keep their first sentence', async () => {
    const detail = `fatal: Authentication failed for 'https://tfs.sirket.local/c/p/_git/r/' ${XSS}`;
    const auth = scan({ status: 'failed', completed_at: null, error_message: `Repository requires authentication: add a repo access token to the project, or list the host in GIT_WINDOWS_AUTH_HOSTS. ${detail}` });
    const network = scan({ status: 'failed', completed_at: null, error_message: 'Git server could not be reached. fatal: unable to access: Could not resolve host' });
    const other = scan({ status: 'failed', completed_at: null, error_message: 'git clone failed (exit code 128). fatal: something else' });
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: [auth, network, other] } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody .scan-error').length === 3, 'error rows');
    const parts = (r: Record<string, unknown>) => {
      const box = p.doc.getElementById(`scan-row-${r.id}`)!.querySelector('.scan-error')!;
      return [box.querySelector('strong')?.textContent, box.querySelector('span')?.textContent];
    };
    expect(parts(auth)).toEqual(['Repo giriş istiyor: projeye bir repo erişim anahtarı (PAT) ekleyin veya yöneticinizden sunucuyu GIT_WINDOWS_AUTH_HOSTS listesine eklemesini isteyin.', detail]);
    expect(parts(network)).toEqual(['Git sunucusuna ulaşılamadı. Ağ/VPN bağlantısını kontrol edip taramayı yeniden başlatın.', 'fatal: unable to access: Could not resolve host']);
    expect(parts(other)).toEqual(['git clone failed (exit code 128).', 'fatal: something else']);
    expect(p.doc.querySelector('#scans-tbody img')).toBeNull();
  });
});

describe('AC-P36: counters, ecosystem default, zero-package warning', () => {
  it('AC-P36-1: counters sum only the latest completed dependency scan per project (web, failed and older scans ignored)', async () => {
    const rows = [
      scan({ project_id: P1, scan_kind: 'web', total_dependencies: 0, critical_vulns: 7, license_violations: 0, completed_at: ago(10 * MIN) }),
      scan({ project_id: P2, status: 'failed', total_dependencies: 999, critical_vulns: 99, completed_at: null }),
      scan({ project_id: P1, total_dependencies: 10, license_violations: 1, critical_vulns: 2, completed_at: ago(HOUR) }),
      scan({ project_id: P2, total_dependencies: 1225, license_violations: 0, critical_vulns: 1, completed_at: ago(2 * HOUR) }),
      scan({ project_id: P1, total_dependencies: 100, license_violations: 50, critical_vulns: 50, completed_at: ago(2 * DAY) }),
    ];
    const p = loadPage({
      'GET /api/projects': () => ({ status: 200, body: { data: [{ id: P1, name: 'a' }, { id: P2, name: 'b' }] } }),
      'GET /api/scans': () => ({ status: 200, body: { data: rows } }),
    });
    const text = (id: string) => p.doc.getElementById(id)?.textContent;
    await waitFor(() => text('stat-packages') === '1.235' && text('stat-critical-cves') === '3' && text('stat-license-alerts') === '1' && text('stat-projects') === '2', 'counters');
    for (const card of Array.from(p.doc.querySelectorAll('.stat-card'))) {
      expect(card.querySelector('.stat-note')?.textContent?.length ?? 0, 'one-sentence explanation').toBeGreaterThan(10);
    }
  });

  it('AC-P36-2: no technology is preselected ("Otomatik algıla" is) and the hint explains auto-detection', () => {
    const doc = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8')).window.document;
    const inputs = Array.from(doc.querySelectorAll<HTMLInputElement>('#ecosystems input[name="eco"]'));
    expect(inputs.map((i) => i.value)).toEqual(['auto', 'nodejs', 'python', 'dotnet']);
    expect(inputs.filter((i) => i.hasAttribute('checked')).map((i) => i.value)).toEqual(['auto']);
    expect(doc.getElementById('ecosystems-hint')?.textContent).toMatch(/^Boş bırakılırsa tüm desteklenen ekosistemler otomatik algılanır \(önerilen\)\./);
  });

  it('ecosystem cards: a technology turns auto off, auto clears the technologies, clearing all returns to auto; the POST body follows', async () => {
    const p = loadPage({ 'POST /api/projects': () => ({ status: 201, body: { data: { id: P1, name: 'x' } } }), 'POST /api/scans': () => ({ status: 201, body: { data: scan() } }) });
    await dashboardReady(p);
    const box = (v: string) => p.doc.querySelector<HTMLInputElement>(`#ecosystems input[value="${v}"]`)!;
    const toggle = (v: string) => box(v).click();
    toggle('dotnet');
    expect(box('auto').checked).toBe(false);
    expect(box('dotnet').checked).toBe(true);
    toggle('python');
    toggle('auto');
    expect(['nodejs', 'python', 'dotnet'].map((v) => box(v).checked)).toEqual([false, false, false]);
    toggle('nodejs');
    toggle('nodejs');
    expect(box('auto').checked).toBe(true);
    toggle('dotnet');
    (p.doc.getElementById('projectName') as HTMLInputElement).value = 'Eco';
    (p.doc.getElementById('repoPath') as HTMLInputElement).value = 'C:\\work\\eco';
    (p.doc.getElementById('launch-btn') as HTMLButtonElement).click();
    await waitFor(() => p.calls.some((c) => c.key === 'POST /api/projects'), 'project POST');
    expect((p.calls.find((c) => c.key === 'POST /api/projects')!.body as { ecosystems: string[] }).ecosystems).toEqual(['dotnet']);
  });

  it('AC-P36-3: a completed dependency scan with 0 packages shows "Paket bulunamadı" and likely causes; web scans and non-zero scans do not', async () => {
    const empty = scan({ total_dependencies: 0 });
    const full = scan({ total_dependencies: 4 });
    const web = scan({ scan_kind: 'web', total_dependencies: 0, target_url: 'https://portal.sirket.local/' });
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: [empty, full, web] } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody tr').length === 3, 'rows');
    const note = (r: Record<string, unknown>) => p.doc.getElementById(`scan-row-${r.id}`)!.querySelector('.scan-nopkg');
    expect(note(empty)?.querySelector('strong')?.textContent).toBe('Paket bulunamadı');
    expect(note(empty)?.textContent).toMatch(/yanlış klasör/);
    expect(note(empty)?.textContent).toMatch(/ekosistem/);
    expect(note(empty)?.textContent).toMatch(/kilit/);
    expect(note(full)).toBeNull();
    expect(note(web)).toBeNull();
  });
});

describe('REQ-010 r2: zero findings is "clean" only when the vulnerability lookup ran', () => {
  it('unavailable/disabled -> "Kontrol edilemedi", partial -> "Kısmen kontrol edildi", complete -> "✓ Temiz"', async () => {
    const unavailable = scan({ vulnerability_data_status: 'unavailable' });
    const disabled = scan({ vulnerability_data_status: 'disabled' });
    const partial = scan({ vulnerability_data_status: 'partial' });
    const complete = scan({ vulnerability_data_status: 'complete' });
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: [unavailable, disabled, partial, complete] } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody tr').length === 4, 'rows');
    const text = (r: Record<string, unknown>) => p.doc.getElementById(`scan-row-${r.id}`)!.textContent ?? '';
    expect(text(unavailable)).toContain('Kontrol edilemedi');
    expect(text(unavailable)).not.toContain('Temiz');
    expect(text(disabled)).toContain('Kontrol edilemedi');
    expect(text(partial)).toContain('Kısmen kontrol edildi');
    expect(text(complete)).toContain('✓ Temiz');
  });
});

describe('AC-P38-1 / AC-P38-2: "Raporlar" menu', () => {
  it('one menu button per completed dependency row with the five described options; keyboard, focus and aria-expanded', async () => {
    const a = scan();
    const b = scan();
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: [a, b] } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody .reports-btn').length === 2, 'menu buttons');
    const { doc, dom } = p;
    const win = dom.window;
    const rowA = doc.getElementById(`scan-row-${a.id}`)!;
    expect(rowA.querySelectorAll('.reports-btn')).toHaveLength(1);
    const button = rowA.querySelector('.reports-btn') as HTMLButtonElement;
    expect(button.textContent?.trim()).toBe('Raporlar');
    expect(button.getAttribute('aria-haspopup')).toBe('menu');
    expect(button.getAttribute('aria-expanded')).toBe('false');
    const menu = doc.getElementById(button.getAttribute('aria-controls')!)!;
    expect(menu.getAttribute('role')).toBe('menu');
    expect(menu.hidden).toBe(true);
    const items = Array.from(menu.querySelectorAll<HTMLAnchorElement>('[role="menuitem"]'));
    expect(items.map((i) => i.querySelector('.reports-item-title')?.textContent)).toEqual(
      ['Yönetici raporu (PDF)', 'Ayrıntılı tablo (Excel)', 'Paket listesi (CSV)', 'Lisans bildirimi (NOTICE)', 'SBOM']);
    expect(items.map((i) => i.getAttribute('href'))).toEqual([
      `/api/scans/${a.id}/exports/project-report.pdf`, `/api/scans/${a.id}/exports/license-inventory.xlsx`,
      `/api/scans/${a.id}/exports/license-inventory.csv`, `/api/scans/${a.id}/notice`, `/api/scans/${a.id}/sbom/download`,
    ]);
    for (const i of items) expect(i.querySelector('.reports-item-desc')?.textContent?.length ?? 0).toBeGreaterThan(10);
    expect(items[3].querySelector('.reports-item-desc')?.textContent).toMatch(/ürünle birlikte dağıtmak/);
    expect(items[4].querySelector('.reports-item-desc')?.textContent).toMatch(/makine okunur/);

    const key = (target: Element, k: string) => target.dispatchEvent(new win.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }));
    // Mouse click opens without moving focus.
    button.dispatchEvent(new win.MouseEvent('click', { bubbles: true, detail: 1 }));
    expect(button.getAttribute('aria-expanded')).toBe('true');
    expect(menu.hidden).toBe(false);
    // Escape closes and returns focus to the button.
    key(button, 'Escape');
    expect(button.getAttribute('aria-expanded')).toBe('false');
    expect(menu.hidden).toBe(true);
    expect(doc.activeElement).toBe(button);
    // Keyboard activation (Enter/Space -> click with detail 0) moves focus to the first item; arrows move.
    button.click();
    expect(menu.hidden).toBe(false);
    expect(doc.activeElement).toBe(items[0]);
    key(items[0], 'ArrowDown');
    expect(doc.activeElement).toBe(items[1]);
    key(items[1], 'ArrowUp');
    key(items[0], 'ArrowUp');
    expect(doc.activeElement).toBe(items[4]);
    key(items[4], 'Escape');
    expect(menu.hidden).toBe(true);
    expect(doc.activeElement).toBe(button);
    // Opening another menu closes the first; a click outside closes it.
    button.dispatchEvent(new win.MouseEvent('click', { bubbles: true, detail: 1 }));
    const buttonB = doc.getElementById(`scan-row-${b.id}`)!.querySelector('.reports-btn') as HTMLButtonElement;
    buttonB.dispatchEvent(new win.MouseEvent('click', { bubbles: true, detail: 1 }));
    expect(menu.hidden).toBe(true);
    expect(button.getAttribute('aria-expanded')).toBe('false');
    expect(buttonB.getAttribute('aria-expanded')).toBe('true');
    doc.getElementById('page-title')!.dispatchEvent(new win.MouseEvent('click', { bubbles: true, detail: 1 }));
    expect(buttonB.getAttribute('aria-expanded')).toBe('false');
    expect(doc.getElementById(buttonB.getAttribute('aria-controls')!)!.hidden).toBe(true);
  });

  it('web scan rows offer only the web PDF and the findings CSV; active and failed rows have no menu', async () => {
    const web = scan({ scan_kind: 'web', target_url: 'https://portal.sirket.local/', web_summary: { grade: 'B', score: 81 } });
    const running = scan({ status: 'running', completed_at: null });
    const failed = scan({ status: 'failed', completed_at: null });
    const p = loadPage({ 'GET /api/scans': () => ({ status: 200, body: { data: [web, running, failed] } }) });
    await waitFor(() => p.doc.querySelectorAll('#scans-tbody tr').length === 3, 'rows');
    const items = Array.from(p.doc.getElementById(`scan-row-${web.id}`)!.querySelectorAll('[role="menuitem"]'));
    expect(items.map((i) => i.querySelector('.reports-item-title')?.textContent)).toEqual(['Web güvenlik raporu (PDF)', 'Bulgu listesi (CSV)']);
    expect(items.map((i) => i.getAttribute('href'))).toEqual([`/api/scans/${web.id}/exports/web-report.pdf`, `/api/scans/${web.id}/exports/web-findings.csv`]);
    expect(p.doc.getElementById(`scan-row-${running.id}`)!.querySelector('.reports-btn')).toBeNull();
    expect(p.doc.getElementById(`scan-row-${failed.id}`)!.querySelector('.reports-btn')).toBeNull();
  });
});

describe('AC-P35-2 / AC-P35-3: system status', () => {
  const OFF = {
    ...FEATURES_ALL_ON,
    local_scan: { enabled: false, roots: 0 },
    web_scan: { enabled: false, allowed_hosts: 0 },
    repo_tokens: { enabled: false },
  };

  it('Sistem Durumu lists every feature with Açık/Kapalı, a description and, when off, the .env setting and restart', async () => {
    const p = loadPage({ 'GET /api/system/features': () => ({ status: 200, body: { data: OFF } }) });
    await dashboardReady(p);
    nav(p.doc, 'system');
    await waitFor(() => p.doc.getElementById('system-status-body')?.dataset.state === 'ready', 'system status');
    expect(p.doc.getElementById('page-title')?.textContent).toBe('Sistem Durumu');
    expect(p.doc.getElementById('page-subtitle')?.textContent?.length ?? 0).toBeGreaterThan(20);
    const items = Array.from(p.doc.querySelectorAll<HTMLElement>('#system-status-body .feature-item'));
    expect(items.map((i) => i.dataset.feature)).toEqual(Object.keys(FEATURES_ALL_ON));
    const item = (k: string) => p.doc.querySelector<HTMLElement>(`#system-status-body [data-feature="${k}"]`)!;
    const local = item('local_scan');
    expect(local.querySelector('.status-badge')?.textContent?.trim()).toBe('Kapalı');
    expect(local.querySelector('.feature-desc')?.textContent?.length ?? 0).toBeGreaterThan(10);
    expect(local.querySelector('.feature-enable')?.textContent).toMatch(/SCAN_ROOTS/);
    expect(local.querySelector('.feature-enable')?.textContent).toMatch(/yeniden başlatın/);
    expect(item('repo_tokens').querySelector('.feature-enable')?.textContent).toMatch(/ENCRYPTION_KEY/);
    const registry = item('registry_enrichment');
    expect(registry.querySelector('.status-badge')?.textContent?.trim()).toBe('Açık');
    expect(registry.querySelector('.feature-enable')).toBeNull();
    expect(item('nvd').textContent).toContain('NVD API anahtarı: tanımlı değil');
    expect(item('web_scan').textContent).toContain('İzinli sunucu girdisi: 0');
  });

  it.each([
    ['404 (endpoint missing)', { status: 404, body: { error: 'Not Found', message: 'Resource not found', code: 'not_found' } }],
    ['403 (no settings:read)', { status: 403, body: { error: 'Forbidden', message: 'Forbidden', code: 'forbidden' } }],
    ['malformed body', { status: 200, body: { data: [] } }],
  ])('%s -> "Sistem durumu alınamadı"', async (_label, reply) => {
    const p = loadPage({ 'GET /api/system/features': () => reply as Reply });
    await dashboardReady(p);
    nav(p.doc, 'system');
    await waitFor(() => p.doc.getElementById('system-status-body')?.dataset.state === 'error', 'error state');
    expect(p.doc.getElementById('system-status-body')?.textContent).toContain('Sistem durumu alınamadı');
    expect(p.doc.querySelector('#system-status-body .feature-item')).toBeNull();
  });

  it('AC-P35-3: the new-project modal explains disabled local folder scan, web scan and token storage; nothing is shown when they are on', async () => {
    const p = loadPage({ 'GET /api/system/features': () => ({ status: 200, body: { data: OFF } }) });
    await dashboardReady(p);
    (p.doc.getElementById('new-scan-btn') as HTMLButtonElement).click();
    const warning = (id: string) => p.doc.getElementById(id)!;
    await waitFor(() => warning('repoPath-feature-warning').classList.contains('show'), 'local scan warning');
    expect(warning('repoPath-feature-warning').textContent).toMatch(/SCAN_ROOTS/);
    expect(warning('webUrl-feature-warning').classList.contains('show')).toBe(true);
    expect(warning('webUrl-feature-warning').textContent).toMatch(/WEB_SCAN_ALLOWED_HOSTS/);
    const repo = p.doc.getElementById('repoPath') as HTMLInputElement;
    repo.value = 'https://tfs.sirket.local/c/p/_git/r';
    repo.dispatchEvent(new p.dom.window.Event('input'));
    expect((p.doc.getElementById('repoTokenGroup') as HTMLElement).hidden).toBe(false);
    expect(warning('repoToken-feature-warning').classList.contains('show')).toBe(true);
    expect(warning('repoToken-feature-warning').textContent).toMatch(/ENCRYPTION_KEY/);

    const on = loadPage();
    await dashboardReady(on);
    (on.doc.getElementById('new-scan-btn') as HTMLButtonElement).click();
    await waitFor(() => on.calls.some((c) => c.key === 'GET /api/system/features'), 'features requested');
    await tick();
    for (const id of ['repoPath-feature-warning', 'webUrl-feature-warning', 'repoToken-feature-warning']) {
      expect(on.doc.getElementById(id)!.classList.contains('show'), id).toBe(false);
    }
  });
});

describe('AC-P34: purposes, glossary tooltips, Help view', () => {
  const GLOSSARY = ['sbom', 'cyclonedx', 'spdx', 'cve', 'cvss', 'purl', 'license', 'dependency', 'notice', 'owasp', 'cwe', 'grade', 'webscan', 'pat'];

  it('AC-P34-1: every view sets a title and a one-sentence purpose', async () => {
    const p = loadPage();
    await dashboardReady(p);
    const views = Array.from(p.doc.querySelectorAll<HTMLElement>('#sidebar-nav .nav-item')).map((b) => b.dataset.view!);
    const seen = new Set<string>();
    for (const view of views) {
      nav(p.doc, view);
      await tick();
      const subtitle = p.doc.getElementById('page-subtitle')?.textContent ?? '';
      expect(subtitle.length, view).toBeGreaterThan(30);
      expect(subtitle.trim().endsWith('.'), view).toBe(true);
      seen.add(subtitle);
    }
    expect(seen.size).toBe(views.length);
  });

  it('AC-P34-3: every glossary term has a tooltip source (data-term in index.html or termTitle in app.js) and a Help entry', async () => {
    const html = fs.readFileSync(repoPath('public', 'index.html'), 'utf8');
    const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8');
    const used = new Set([
      ...Array.from(html.matchAll(/data-term="(\w+)"/g)).map((m) => m[1]),
      ...Array.from(src.matchAll(/termTitle\('(\w+)'\)/g)).map((m) => m[1]),
    ]);
    for (const key of GLOSSARY) expect(used.has(key), key).toBe(true);

    const p = loadPage();
    await dashboardReady(p);
    // Static data-term elements get their title from the dictionary at start-up.
    expect(p.doc.querySelector('#view-sbom [data-term="sbom"]')?.getAttribute('title')).toMatch(/^SBOM: Yazılım malzeme listesi/);
    expect(p.doc.querySelector('#repoTokenGroup [data-term="pat"]')?.getAttribute('title')).toMatch(/^PAT: /);
  });

  it('AC-P34-4: the Help view opens from the menu with "İlk adımlar" and "Sözlük" and makes no server call', async () => {
    const p = loadPage();
    await dashboardReady(p);
    await tick();
    const before = p.calls.length;
    nav(p.doc, 'help');
    await waitFor(() => p.doc.querySelectorAll('#help-body .help-steps > li').length > 0, 'help rendered');
    expect(p.calls.length).toBe(before);
    expect(p.doc.getElementById('page-title')?.textContent).toBe('Yardım');
    const headings = Array.from(p.doc.querySelectorAll('#help-body h3')).map((h) => h.textContent);
    expect(headings).toContain('İlk adımlar');
    expect(headings).toContain('Sözlük');
    const steps = Array.from(p.doc.querySelectorAll('#help-body .help-steps > li strong')).map((s) => s.textContent);
    expect(steps).toEqual(['Proje ekleyin', 'Taramayı başlatın', 'Sonuçları inceleyin', 'Rapor indirin']);
    const terms = Array.from(p.doc.querySelectorAll<HTMLElement>('#help-glossary .glossary-entry')).map((e) => e.dataset.term);
    expect(terms).toEqual(GLOSSARY);
    for (const dd of Array.from(p.doc.querySelectorAll('#help-glossary dd'))) expect(dd.textContent?.length ?? 0).toBeGreaterThan(30);
  });

  it('AC-P34-2: empty states say what to do', async () => {
    const p = loadPage();
    await waitFor(() => (p.doc.getElementById('table-empty') as HTMLElement).style.display === 'block', 'dashboard empty');
    expect(p.doc.getElementById('table-empty')?.textContent).toMatch(/ilk taramayı başlatın/);
    expect(p.doc.getElementById('empty-new-scan-btn')).not.toBeNull();
    nav(p.doc, 'projects');
    await waitFor(() => (p.doc.getElementById('projects-list-tbody')?.textContent ?? '') !== '', 'projects empty');
    expect(p.doc.getElementById('projects-list-tbody')?.textContent).toMatch(/“Proje ekle” düğmesiyle/);
    nav(p.doc, 'scans');
    await waitFor(() => (p.doc.getElementById('scans-list-tbody')?.textContent ?? '') !== '', 'history empty');
    expect(p.doc.getElementById('scans-list-tbody')?.textContent).toMatch(/tarama başlatın/);
  });
});

describe('AC-G-1: server data only as text', () => {
  it('app.js never builds markup from strings (no innerHTML / outerHTML / insertAdjacentHTML / document.write)', () => {
    const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8');
    const sf = ts.createSourceFile('app.js', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    const names: string[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isPropertyAccessExpression(node)) names.push(node.name.text);
      ts.forEachChild(node, visit);
    };
    visit(sf);
    for (const forbidden of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'write', 'writeln']) expect(names, forbidden).not.toContain(forbidden);
  });
});
