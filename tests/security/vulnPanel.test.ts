/**
 * REQ-005 · AC-P18-11 / AC-P19-7: Dashboard "Vulnerability data" panel
 * (contract REQ-005 section 6). public/index.html + public/app.js in jsdom
 * with an in-memory fake API (same approach as noticeLink.test.ts).
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
const GEN = '2026-10-10T09:00:00.000Z';
const EVIL = '<img src=x onerror="window.__xss=1">';

function statusBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    generated_at: GEN,
    settings: { lookup_enabled: true, recheck_enabled: true, interval_hours: 24, nvd_enabled: true },
    scheduler: { paused: false, next_check_earliest_at: '2026-10-11T03:00:12.000Z', current_run: null },
    last_run: {
      id: '7d0c7a52-4c1e-4a43-9a51-3c1f0e2b9a10', status: 'partial', started_at: '2026-10-10T03:00:12.000Z', finished_at: '2026-10-10T03:02:40.512Z',
      projects_checked: 3, packages_checked: 410, packages_unchecked: 12, findings_opened: 1, acceptances_reopened: 0, error_summary: 'osv:unreachable',
    },
    projects: [
      { project_id: 'a', project_name: 'demo-app', latest_scan_id: 's1', latest_scan_completed_at: GEN, vulnerability_data_status: 'partial', vulnerability_checked_at: GEN },
      { project_id: 'b', project_name: 'ok-app', latest_scan_id: 's2', latest_scan_completed_at: GEN, vulnerability_data_status: 'complete', vulnerability_checked_at: GEN },
      { project_id: 'c', project_name: EVIL, latest_scan_id: 's3', latest_scan_completed_at: GEN, vulnerability_data_status: null, vulnerability_checked_at: null },
      { project_id: 'd', project_name: 'off-app', latest_scan_id: 's4', latest_scan_completed_at: GEN, vulnerability_data_status: 'disabled', vulnerability_checked_at: GEN },
      { project_id: 'e', project_name: 'down-app', latest_scan_id: 's5', latest_scan_completed_at: GEN, vulnerability_data_status: 'unavailable', vulnerability_checked_at: GEN },
    ],
    projects_truncated: false,
    project_status_counts: { complete: 1, partial: 1, unavailable: 1, disabled: 1, not_checked: 1 },
    risk_acceptance_expiry: { reopened_last_7_days: 2, last_evaluated_at: '2026-10-10T08:41:00.000Z' },
    ...over,
  };
}

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

type StatusReply = { status: number; body: unknown } | 'pending';
function loadPage(reply: StatusReply): { dom: JSDOM; calls: string[] } {
  const calls: string[] = [];
  const routes: Record<string, unknown> = {
    'GET /health': { status: 'healthy', database: 'connected' },
    'GET /api/auth/me': { data: { id: 'u', email: 'qa@example.test', displayName: 'QA', roles: ['admin'] } },
  };
  const dom = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8'), {
    url: `${BASE}/`, runScripts: 'dangerously', resources: new PublicDirLoader() as never, pretendToBeVisual: true,
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>;
      w.alert = () => undefined;
      w.lucide = { createIcons: () => undefined };
      w.fetch = async (input: unknown, init?: { method?: string }) => {
        const key = `${(init?.method ?? 'GET').toUpperCase()} ${new URL(String(input), BASE).pathname}`;
        calls.push(key);
        if (key === 'GET /api/vulnerability-data/status') {
          if (reply === 'pending') return new Promise(() => undefined);
          return new Response(JSON.stringify(reply.body), { status: reply.status, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify(routes[key] ?? { data: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      };
    },
  });
  open.push(dom);
  return { dom, calls };
}

async function waitFor(cond: () => boolean, what: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > 5000) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}
const rowsOf = (doc: Document) =>
  Array.from(doc.querySelectorAll('#vuln-data-body tr')).map((tr) => [tr.querySelector('th')?.textContent ?? '', tr.querySelector('td')?.textContent ?? '']);
async function ready(reply: StatusReply) {
  const page = loadPage(reply);
  const doc = page.dom.window.document;
  await waitFor(() => doc.getElementById('vuln-data-body')?.getAttribute('data-state') === 'ready', 'panel ready');
  return { ...page, doc };
}

describe('AC-P18-11: Dashboard vulnerability data panel (contract 6)', () => {
  it('AC-P18-11: #vuln-data-card sits in #view-dashboard after .stats-grid and before the recent scans card; skeleton per contract 6.1', () => {
    const doc = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8')).window.document;
    const card = doc.getElementById('vuln-data-card')!;
    expect(card).not.toBeNull();
    expect(card.className).toBe('content-card');
    expect(card.closest('#view-dashboard')).not.toBeNull();
    expect(card.querySelector('.card-header h2.card-title')?.textContent?.trim()).toBe('Vulnerability data');
    expect(doc.getElementById('vuln-data-body')?.getAttribute('data-state')).toBe('loading');
    const siblings = Array.from(card.parentElement!.children);
    const stats = siblings.findIndex((e) => e.classList.contains('stats-grid'));
    const recent = siblings.findIndex((e) => /Recent Compliance Scans/.test(e.textContent ?? ''));
    const mine = siblings.indexOf(card);
    expect(stats).toBeGreaterThanOrEqual(0);
    expect(mine).toBe(stats + 1);
    expect(recent).toBeGreaterThan(mine);
  });

  it('AC-P18-11: loading state text while the request is pending; only GET status is called for the panel', async () => {
    const { dom, calls } = loadPage('pending');
    const doc = dom.window.document;
    await waitFor(() => calls.includes('GET /api/vulnerability-data/status'), 'status requested');
    const body = doc.getElementById('vuln-data-body')!;
    expect(body.getAttribute('data-state')).toBe('loading');
    expect(body.textContent?.trim()).toBe('Loading vulnerability data status...');
    expect(calls.filter((c) => c.includes('vulnerability-data') && !c.startsWith('GET '))).toEqual([]);
  });

  it('AC-P18-11 / AC-P19-7: ready — 7 rows with fixed labels, partial warning, counts, malicious project name as text only', async () => {
    const { doc, dom } = await ready({ status: 200, body: { data: statusBody() } });
    const rows = rowsOf(doc);
    expect(rows.map((r) => r[0])).toEqual([
      'Daily recheck', 'Last recheck', 'New findings (last recheck)', 'Packages not checked (last recheck)', 'Next check',
      'Risk acceptances reopened (last 7 days)', 'Last expiry check',
    ]);
    expect(rows[0][1]).toBe('Every 24 h');
    expect(rows[1][1]).toBe(`Partial · ${new Date('2026-10-10T03:02:40.512Z').toLocaleString()}`);
    expect(rows[2][1]).toBe('1');
    expect(rows[3][1]).toBe('12');
    expect(rows[4][1]).toBe(new Date('2026-10-11T03:00:12.000Z').toLocaleString());
    expect(rows[5][1]).toBe('2');
    expect(rows[6][1]).toBe(new Date('2026-10-10T08:41:00.000Z').toLocaleString());
    const items = Array.from(doc.querySelectorAll('ul#vuln-data-warnings > li')).map((li) => li.textContent);
    expect(items).toEqual(['demo-app: vulnerability data partial', `${EVIL}: not checked yet`, 'off-app: vulnerability lookup disabled', 'down-app: vulnerability data unavailable']);
    expect(doc.getElementById('vuln-data-body')!.textContent).toContain('Projects with incomplete vulnerability data (4)');
    expect(doc.querySelector('#vuln-data-body img')).toBeNull();
    expect((dom.window as unknown as { __xss?: number }).__xss).toBeUndefined();
    expect(doc.getElementById('vuln-data-body')!.textContent).not.toContain('Showing the first 500 projects.');
  });

  it('AC-P18-11: value rules — disabled settings, running, never run, paused, due now, not yet evaluated, all complete, truncation note', async () => {
    const a = await ready({ status: 200, body: { data: statusBody({
      settings: { lookup_enabled: true, recheck_enabled: false, interval_hours: 24, nvd_enabled: true },
      scheduler: { paused: true, next_check_earliest_at: null, current_run: { id: 'r', started_at: '2026-10-10T08:59:00.000Z' } },
      projects: [], project_status_counts: { complete: 0, partial: 0, unavailable: 0, disabled: 0, not_checked: 0 },
      risk_acceptance_expiry: { reopened_last_7_days: 0, last_evaluated_at: null }, projects_truncated: true,
    }) } });
    const r = Object.fromEntries(rowsOf(a.doc));
    expect(r['Daily recheck']).toBe('Disabled (VULNERABILITY_RECHECK=off)');
    expect(r['Last recheck']).toBe(`Running since ${new Date('2026-10-10T08:59:00.000Z').toLocaleString()}`);
    expect(r['Next check']).toBe('Paused');
    expect(r['Last expiry check']).toBe('Not yet evaluated');
    expect(a.doc.getElementById('vuln-data-body')!.textContent).toContain('All projects have complete vulnerability data.');
    expect(a.doc.getElementById('vuln-data-warnings')).toBeNull();
    expect(a.doc.getElementById('vuln-data-body')!.textContent).toContain('Showing the first 500 projects.');

    const b = await ready({ status: 200, body: { data: statusBody({
      settings: { lookup_enabled: false, recheck_enabled: true, interval_hours: 24, nvd_enabled: true },
      scheduler: { paused: false, next_check_earliest_at: '2026-10-10T08:00:00.000Z', current_run: null },
      last_run: null,
    }) } });
    const rb = Object.fromEntries(rowsOf(b.doc));
    expect(rb['Daily recheck']).toBe('Disabled (VULNERABILITY_LOOKUP=off)');
    expect(rb['Last recheck']).toBe('Never run');
    expect(rb['New findings (last recheck)']).toBe('—');
    expect(rb['Packages not checked (last recheck)']).toBeUndefined();
    expect(rb['Next check']).toBe('Due now');
    expect(rowsOf(b.doc)).toHaveLength(6);

    const c = await ready({ status: 200, body: { data: statusBody({ last_run: { ...(statusBody().last_run as object), status: 'disabled', packages_unchecked: 0 } }) } });
    expect(Object.fromEntries(rowsOf(c.doc))['Last recheck']).toMatch(/^Skipped \(lookup disabled\) · /);
  });

  it('AC-P18-11: API error (500 with a server message, malformed body) -> error state with the fixed text only', async () => {
    for (const reply of [
      { status: 500, body: { error: 'Internal Server Error', message: 'SECRET server detail', code: 'internal_error' } },
      { status: 200, body: { nodata: true } },
    ]) {
      const { dom } = loadPage(reply);
      const doc = dom.window.document;
      await waitFor(() => doc.getElementById('vuln-data-body')?.getAttribute('data-state') === 'error', 'panel error');
      const body = doc.getElementById('vuln-data-body')!;
      expect(body.textContent?.trim()).toBe('Vulnerability data status could not be loaded.');
      expect(body.textContent).not.toContain('SECRET');
      expect(body.querySelector('table')).toBeNull();
    }
  });

  it('AC-P18-11: panel code renders with el()/textContent only — no innerHTML / insertAdjacentHTML', () => {
    const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8');
    for (const fn of ['function loadVulnerabilityDataStatus(', 'function vulnDataRows(', 'function vulnDataWarnings(']) {
      const start = src.indexOf(fn);
      expect(start, fn).toBeGreaterThan(-1);
      const body = src.slice(start, src.indexOf('\n}\n', start));
      expect(body, fn).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML/);
    }
  });
});
