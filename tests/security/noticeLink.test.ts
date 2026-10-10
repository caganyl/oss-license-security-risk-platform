/**
 * REQ-004 · AC-P15-15: "NOTICE" link next to "SBOM" in completed scan rows
 * (contract section 7). public/index.html + public/app.js in jsdom with an
 * in-memory fake API (same approach as tests/security/xss.test.ts).
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
const ROUTES: Record<string, unknown> = {
  'GET /health': { status: 'healthy', database: 'connected' },
  'GET /api/auth/me': { data: { id: 'u', email: 'qa@example.test', displayName: 'QA', roles: ['admin'] } },
  'GET /api/projects': { data: [] },
  'GET /api/scans': { data: [scan(ID.done1, 'completed'), scan(ID.running, 'running'), scan(ID.failed, 'failed'), scan(ID.pending, 'pending'), scan(ID.done2, 'completed')] },
};

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

function loadPage(): { dom: JSDOM; calls: string[] } {
  const calls: string[] = [];
  const dom = new JSDOM(fs.readFileSync(repoPath('public', 'index.html'), 'utf8'), {
    url: `${BASE}/`, runScripts: 'dangerously', resources: new PublicDirLoader() as never, pretendToBeVisual: true,
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>;
      w.alert = () => undefined;
      w.lucide = { createIcons: () => undefined };
      w.fetch = async (input: unknown, init?: { method?: string }) => {
        const key = `${(init?.method ?? 'GET').toUpperCase()} ${new URL(String(input), BASE).pathname}`;
        calls.push(key);
        const body = ROUTES[key];
        return new Response(JSON.stringify(body ?? { data: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
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

describe('AC-P15-15: NOTICE link in the scan list (contract section 7)', () => {
  it('AC-P15-15: completed rows show SBOM then NOTICE (same style); href /api/scans/<id>/notice; none for running / failed / pending', async () => {
    const { dom } = loadPage();
    const doc = dom.window.document;
    await waitFor(() => doc.querySelectorAll('a[href$="/notice"]').length >= 2, 'NOTICE links rendered');
    const links = Array.from(doc.querySelectorAll<HTMLAnchorElement>('a[href$="/notice"]'));
    const hrefs = new Set(links.map((a) => a.getAttribute('href')));
    expect(hrefs).toEqual(new Set([`/api/scans/${ID.done1}/notice`, `/api/scans/${ID.done2}/notice`]));
    for (const a of links) {
      expect(a.textContent?.trim()).toBe('NOTICE');
      expect(a.className).toBe('btn btn-sm');
      expect(a.getAttribute('target')).toBe('_blank');
      expect(a.getAttribute('rel')).toBe('noopener');
      const sbom = a.previousElementSibling as HTMLAnchorElement;
      const id = a.getAttribute('href')!.split('/')[3];
      expect(sbom.tagName).toBe('A');
      expect(sbom.getAttribute('href')).toBe(`/api/scans/${id}/sbom/download`);
      expect(sbom.textContent?.trim()).toBe('SBOM');
      expect(a.getAttribute('style')).toBe(sbom.getAttribute('style'));
      expect(a.parentElement!.children).toHaveLength(2);
    }
    for (const id of [ID.running, ID.failed, ID.pending]) {
      expect(doc.querySelector(`a[href*="${id}"]`), id).toBeNull();
    }
  });

  it('AC-P15-15: scanActions builds the links with el() — no innerHTML / insertAdjacentHTML', () => {
    const src = fs.readFileSync(repoPath('public', 'app.js'), 'utf8');
    const start = src.indexOf('function scanActions(');
    const body = src.slice(start, src.indexOf('\n}\n', start));
    expect(start).toBeGreaterThan(-1);
    expect(body).toContain("apiPath('scans', row.id, 'notice')");
    expect(body).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML/);
  });
});
