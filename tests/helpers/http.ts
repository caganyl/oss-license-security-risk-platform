import request from 'supertest';
import type { Express } from 'express';
import type { Pool } from 'pg';
import { loadSrcGuarded } from './loadSrc';
import type { AppDeps, AppModule } from './contracts';

export const TEST_PORT = 3001;
export const HOST_HEADER = `127.0.0.1:${TEST_PORT}`;
export const ORIGIN = `http://127.0.0.1:${TEST_PORT}`;
/** Test-only password (not a secret). */
export const TEST_PASSWORD = 'correct-horse-battery-42';
export const API_KEY_RE = /^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/;
export const KEY_PREFIX_RE = /^ossr_[0-9a-f]{16}$/;

export const loadApp = () => loadSrcGuarded<AppModule>('src/app.ts', ['createApp', 'startServer']);

export async function makeApp(db: Pool, extra: Partial<AppDeps> = {}): Promise<Express> {
  const { createApp } = await loadApp();
  return createApp({ db, port: TEST_PORT, host: '127.0.0.1', ...extra });
}

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

/** Request with an allowed Host header (and same-origin Origin for writes). */
export function req(app: Express, method: Method, url: string, opts: { cookie?: string; bearer?: string; origin?: string | null } = {}) {
  let r = request(app)[method](url).set('Host', HOST_HEADER);
  const origin = opts.origin === undefined ? (method === 'get' ? null : ORIGIN) : opts.origin;
  if (origin !== null) r = r.set('Origin', origin);
  if (opts.cookie) r = r.set('Cookie', opts.cookie);
  if (opts.bearer) r = r.set('Authorization', `Bearer ${opts.bearer}`);
  return r;
}

export function setCookieLines(res: { headers: Record<string, unknown> }): string[] {
  const raw = res.headers['set-cookie'];
  if (!raw) return [];
  return Array.isArray(raw) ? (raw as string[]) : [String(raw)];
}

/** `ossrisk_session=<value>` from Set-Cookie, or undefined. */
export function sessionCookie(res: { headers: Record<string, unknown> }): string | undefined {
  const line = setCookieLines(res).find((l) => l.startsWith('ossrisk_session='));
  if (!line) return undefined;
  const pair = line.split(';')[0];
  return pair === 'ossrisk_session=' ? undefined : pair;
}

export async function setupPassword(app: Express, password = TEST_PASSWORD): Promise<string> {
  const res = await req(app, 'post', '/api/auth/setup').send({ password });
  if (res.status !== 201) throw new Error(`setup failed: ${res.status} ${JSON.stringify(res.body)}`);
  const cookie = sessionCookie(res);
  if (!cookie) throw new Error('setup did not set the session cookie');
  return cookie;
}

export async function login(app: Express, password = TEST_PASSWORD): Promise<string> {
  const res = await req(app, 'post', '/api/auth/login').send({ password });
  if (res.status !== 204) throw new Error(`login failed: ${res.status} ${JSON.stringify(res.body)}`);
  const cookie = sessionCookie(res);
  if (!cookie) throw new Error('login did not set the session cookie');
  return cookie;
}

export async function createApiKey(app: Express, cookie: string): Promise<{ id: string; key: string; keyPrefix: string }> {
  const res = await req(app, 'post', '/api/auth/api-keys', { cookie }).send({ name: 'ci' });
  if (res.status !== 201) throw new Error(`api key creation failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body.data;
}

/** Asserts the contract error body {error, message, code} with JSON content type. */
export function expectErrorBody(res: { status: number; headers: Record<string, unknown>; body: unknown }, status: number, code: string): void {
  if (res.status !== status) {
    throw new Error(`expected HTTP ${status} (${code}), got ${res.status}: ${JSON.stringify(res.body)}`);
  }
  const ct = String(res.headers['content-type'] ?? '');
  if (!ct.includes('application/json')) throw new Error(`expected JSON error body, got content-type "${ct}"`);
  const body = res.body as Record<string, unknown>;
  for (const field of ['error', 'message', 'code']) {
    if (typeof body[field] !== 'string') throw new Error(`error body lacks "${field}": ${JSON.stringify(body)}`);
  }
  if (body.code !== code) throw new Error(`expected code "${code}", got "${String(body.code)}"`);
}
