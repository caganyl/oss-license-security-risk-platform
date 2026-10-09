/**
 * REQ-002 · contract K13 (security review L-3, M-1), AC-P02-6, AC-P02-7 (a), D-17.
 * Every response — JSON, HTML, static file, /health, 204 and every error,
 * including the Host rejection — carries X-Content-Type-Options,
 * X-Frame-Options and Referrer-Policy. HTML responses also carry a CSP whose
 * mandatory directives are fixed by docs/contracts/REQ-002-auth-api.md
 * ("Güvenlik başlıkları") and which names no external origin anywhere.
 * Tests run in file order: unauthenticated cases first, then setup.
 */
import request from 'supertest';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { Express } from 'express';
import { useTestDatabase } from '../helpers/db';
import { HOST_HEADER, ORIGIN, makeApp, req, setupPassword } from '../helpers/http';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file', setDatabaseUrlEnv: true });
let app: Express;
let cookie = '';

beforeAll(async () => {
  app = await makeApp(db.pool);
});

type Res = { status: number; headers: Record<string, unknown> };

const BASE_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

function expectBaseHeaders(res: Res, label: string): void {
  for (const [name, value] of Object.entries(BASE_HEADERS)) {
    expect(String(res.headers[name] ?? '<missing>'), `${label} (HTTP ${res.status}): ${name}`).toBe(value);
  }
}

/** `default-src 'self'; script-src 'self'` -> { 'default-src': ["'self'"], ... } (directive names lower-cased). */
function parseCsp(header: unknown): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of String(header ?? '').split(';')) {
    const [name, ...values] = part.trim().split(/\s+/).filter(Boolean);
    if (name) directives[name.toLowerCase()] = values;
  }
  return directives;
}

const MANDATORY_CSP: Record<string, string[]> = {
  'default-src': ["'self'"],
  'script-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'none'"],
  'frame-ancestors': ["'none'"],
  'form-action': ["'self'"],
};
/** Source tokens that name no external origin; 'unsafe-inline' is tolerated only in style-src (contract K13). */
const LOCAL_TOKENS = new Set(["'self'", "'none'", 'data:']);

function expectHtmlCsp(res: Res, label: string): void {
  const raw = res.headers['content-security-policy'];
  expect(raw, `${label}: Content-Security-Policy header`).toBeDefined();
  const csp = parseCsp(raw);
  for (const [directive, values] of Object.entries(MANDATORY_CSP)) {
    expect(csp[directive], `${label}: CSP ${directive}`).toEqual(values);
  }
  for (const [directive, values] of Object.entries(csp)) {
    for (const token of values) {
      const allowed = LOCAL_TOKENS.has(token) || (directive === 'style-src' && token === "'unsafe-inline'");
      expect(allowed, `${label}: CSP ${directive} contains "${token}" (external origin or disallowed keyword)`).toBe(true);
    }
  }
}

describe('K13 security headers on every response', () => {
  it('GET / (HTML) -> base headers and the mandatory CSP without external origins (AC-P02-6, AC-P02-7 a)', async () => {
    const res = await req(app, 'get', '/');
    expect(res.status).toBe(200);
    expect(String(res.headers['content-type'])).toContain('text/html');
    expectBaseHeaders(res, 'GET /');
    expectHtmlCsp(res, 'GET /');
  });

  it('GET /index.html -> same CSP as GET /', async () => {
    const res = await req(app, 'get', '/index.html');
    expect(res.status).toBe(200);
    expectBaseHeaders(res, 'GET /index.html');
    expectHtmlCsp(res, 'GET /index.html');
  });

  it('static .js file (public/vendor/lucide-1.48.0.min.js) -> base headers', async () => {
    const res = await req(app, 'get', '/vendor/lucide-1.48.0.min.js');
    expect(res.status).toBe(200);
    expectBaseHeaders(res, 'GET /vendor/lucide-1.48.0.min.js');
  });

  it('GET /health -> base headers', async () => {
    expectBaseHeaders(await req(app, 'get', '/health'), 'GET /health');
  });

  it('Host rejection (foreign Host) -> 403 with base headers', async () => {
    const res = await request(app).get('/health').set('Host', 'evil.example:3001');
    expect(res.status).toBe(403);
    expectBaseHeaders(res, 'foreign Host');
  });

  it('GET /api/auth/me before setup -> 401 with base headers', async () => {
    const res = await req(app, 'get', '/api/auth/me');
    expect(res.status).toBe(401);
    expectBaseHeaders(res, 'GET /api/auth/me (401)');
  });

  it('malformed JSON body -> 400 with base headers', async () => {
    const res = await request(app)
      .post('/api/auth/setup')
      .set('Host', HOST_HEADER)
      .set('Origin', ORIGIN)
      .set('Content-Type', 'application/json')
      .send('{"password":');
    expect(res.status).toBe(400);
    expectBaseHeaders(res, 'malformed JSON');
  });

  it('GET /api/auth/me with a session -> 200 with base headers; unknown /api route -> 404 with base headers', async () => {
    cookie = await setupPassword(app);
    const me = await req(app, 'get', '/api/auth/me', { cookie });
    expect(me.status).toBe(200);
    expectBaseHeaders(me, 'GET /api/auth/me (200)');
    const missing = await req(app, 'get', '/api/does-not-exist', { cookie });
    expect(missing.status).toBe(404);
    expectBaseHeaders(missing, 'GET /api/does-not-exist');
  });

  it('POST /api/auth/logout -> 204 with base headers', async () => {
    const res = await req(app, 'post', '/api/auth/logout', { cookie });
    expect(res.status).toBe(204);
    expectBaseHeaders(res, 'POST /api/auth/logout (204)');
  });
});
