/**
 * REQ-002 · P-01 (AC-P01-1…17), AC-G-8, AC-G-9
 * Contract: docs/contracts/REQ-002-auth-api.md (0.2.2-draft), ADR-001.
 * Every test gets a fresh migrated database (no users) and a fresh app from
 * `createApp({ db, port: 3001, host: '127.0.0.1' })` (src/app.ts).
 * Session expiry is tested by moving sessions.last_seen_at / expires_at in
 * the DB, which works for both a DB clock and an app clock implementation.
 */
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Express } from 'express';
import type { Pool } from 'pg';
import { useTestDatabase } from '../helpers/db';
import {
  API_KEY_RE,
  HOST_HEADER,
  KEY_PREFIX_RE,
  ORIGIN,
  TEST_PASSWORD,
  createApiKey,
  expectErrorBody,
  loadApp,
  login,
  makeApp,
  req,
  sessionCookie,
  setCookieLines,
  setupPassword,
} from '../helpers/http';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test', setDatabaseUrlEnv: true });
const sha256 = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const RANDOM_UUID = '7d1f3f5e-1c2b-4a3d-9e8f-0123456789ab';

/** Captures console output so tests can assert that secrets are never logged. */
let logged: string[] = [];
beforeEach(() => {
  logged = [];
  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      logged.push(args.map((a) => (a instanceof Error ? `${a.message} ${a.stack}` : typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
    });
  }
});
afterEach(() => {
  vi.restoreAllMocks();
});

async function app(): Promise<Express> {
  return makeApp(db.pool);
}

async function insertUser(email: string, opts: { status?: string; admin?: boolean; deleted?: boolean } = {}): Promise<string> {
  const [row] = await db.query<{ id: string }>(
    `INSERT INTO users (email, display_name, status, deleted_at) VALUES ($1, $1, $2::user_status, $3) RETURNING id`,
    [email, opts.status ?? 'active', opts.deleted ? new Date() : null],
  );
  if (opts.admin !== false) {
    await db.query(`INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'admin'`, [row.id]);
  }
  return row.id;
}

/** Documented recovery SQL step (db/README.md, ADR-001 karar 12). */
async function runRecoverySql(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE users SET password_hash = NULL, password_changed_at = NULL, updated_at = NOW() WHERE password_hash IS NOT NULL`,
    );
    await client.query('DELETE FROM sessions');
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** Protected /api routes that exist today (src/routes/*.ts) — none may answer without credentials. */
const PROTECTED_ROUTES: Array<['get' | 'post' | 'put' | 'patch' | 'delete', string]> = [
  ['get', '/api/auth/me'],
  ['post', '/api/auth/logout'],
  ['get', '/api/auth/api-keys'],
  ['post', '/api/auth/api-keys'],
  ['delete', `/api/auth/api-keys/${RANDOM_UUID}`],
  ['get', '/api/projects'],
  ['post', '/api/projects'],
  ['get', '/api/scans'],
  ['post', '/api/scans'],
  ['get', `/api/scans/${RANDOM_UUID}`],
  ['get', `/api/scans/${RANDOM_UUID}/findings`],
  ['get', '/api/users'],
  ['post', '/api/users'],
  ['get', `/api/users/${RANDOM_UUID}`],
  ['patch', `/api/users/${RANDOM_UUID}`],
  ['put', `/api/users/${RANDOM_UUID}/roles`],
  ['delete', `/api/users/${RANDOM_UUID}`],
  ['get', `/api/findings/${RANDOM_UUID}/workflow`],
  ['post', `/api/findings/${RANDOM_UUID}/assign`],
  ['post', `/api/findings/${RANDOM_UUID}/unassign`],
  ['post', `/api/findings/${RANDOM_UUID}/resolve`],
  ['post', `/api/findings/${RANDOM_UUID}/accept-risk`],
  ['post', `/api/findings/${RANDOM_UUID}/false-positive`],
  ['post', `/api/findings/${RANDOM_UUID}/wont-fix`],
  ['post', `/api/findings/${RANDOM_UUID}/reopen`],
  ['post', `/api/findings/${RANDOM_UUID}/comments`],
  ['post', `/api/scans/${RANDOM_UUID}/sbom`],
  ['get', `/api/scans/${RANDOM_UUID}/sbom`],
  ['get', `/api/sbom/${RANDOM_UUID}/download`],
  ['get', `/api/scans/${RANDOM_UUID}/sbom/download`],
  ['post', `/api/scans/${RANDOM_UUID}/reports`],
  ['get', `/api/scans/${RANDOM_UUID}/reports`],
  ['get', `/api/reports/${RANDOM_UUID}/download`],
  ['get', '/api/does-not-exist'],
];

// ---------------------------------------------------------------------------
describe('P-01 unauthenticated access (AC-P01-1, AC-P01-7, AC-P01-10)', () => {
  it('AC-P01-1: before setup every protected /api route answers 401 code=setup_required', async () => {
    const a = await app();
    for (const [method, url] of PROTECTED_ROUTES) {
      const res = await req(a, method, url).send(method === 'get' ? undefined : {});
      expectErrorBody(res, 401, 'setup_required');
    }
  });

  it('AC-P01-1 / AC-P01-10: after setup every protected /api route answers 401 code=unauthenticated without credentials', async () => {
    const a = await app();
    await setupPassword(a);
    for (const [method, url] of PROTECTED_ROUTES) {
      const res = await req(a, method, url).send(method === 'get' ? undefined : {});
      expectErrorBody(res, 401, 'unauthenticated');
    }
  });

  it('AC-P01-7: no mock user — GET /api/projects without credentials never returns 200', async () => {
    const a = await app();
    const res = await req(a, 'get', '/api/projects');
    expect(res.status).toBe(401);
  });

  it('AC-P01-1: exempt endpoints are reachable without credentials (/health, /, login, setup)', async () => {
    const a = await app();
    expect((await req(a, 'get', '/health')).status).toBe(200);
    expect((await req(a, 'get', '/')).status).toBe(200);
    const loginRes = await req(a, 'post', '/api/auth/login').send({ password: TEST_PASSWORD });
    expectErrorBody(loginRes, 401, 'setup_required');
    expect((await req(a, 'post', '/api/auth/setup').send({ password: TEST_PASSWORD })).status).toBe(201);
  });
});

// ---------------------------------------------------------------------------
describe('P-01 setup (AC-P01-4, AC-P01-5, AC-P01-11, AC-P01-14, AC-P01-16, ADR-001 karar 2)', () => {
  it('AC-P01-11: setup on an empty DB -> 201 + session cookie (auto login), one active admin user', async () => {
    const a = await app();
    const res = await req(a, 'post', '/api/auth/setup').send({ password: TEST_PASSWORD });
    expect(res.status).toBe(201);
    const line = setCookieLines(res).find((l) => l.startsWith('ossrisk_session='))!;
    expect(line).toBeDefined();
    expect(line).toMatch(/HttpOnly/i);
    expect(line).toMatch(/SameSite=Strict/i);
    expect(line).toMatch(/Path=\//i);
    expect(line).toMatch(/Max-Age=604800/i);
    expect(line).not.toMatch(/Secure/i);
    const cookie = sessionCookie(res)!;
    const me = await req(a, 'get', '/api/auth/me', { cookie });
    expect(me.status).toBe(200);
    expect(me.body.data).toMatchObject({ roles: ['admin'] });
    expect(me.body.data).not.toHaveProperty('sessionId');
    const users = await db.query<{ status: string; roles: string[] }>(
      `SELECT u.status::text, array_agg(r.name::text) AS roles FROM users u
       JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id GROUP BY u.id`,
    );
    expect(users).toEqual([{ status: 'active', roles: ['admin'] }]);
  });

  it('AC-P01-5: only a salted scrypt hash is stored; session cookie stored as SHA-256 only; password never logged', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const [user] = await db.query<{ password_hash: string }>('SELECT password_hash FROM users');
    expect(user.password_hash).toMatch(/^scrypt\$/);
    expect(user.password_hash).not.toContain(TEST_PASSWORD);
    const token = cookie.split('=')[1];
    const sessions = await db.query<{ token_hash: string }>('SELECT token_hash FROM sessions');
    expect(sessions).toEqual([{ token_hash: sha256(token) }]);
    expect(logged.join('\n')).not.toContain(TEST_PASSWORD);
    expect(logged.join('\n')).not.toContain(token);
  });

  it.each([
    ['11 characters', 'a'.repeat(11), 'Password must be at least 12 characters'],
    ['1025 characters', 'a'.repeat(1025), 'Password must be at most 1024 characters'],
    ['missing', undefined, 'Password is required'],
    ['not a string', 123456789012, 'Password is required'],
  ])('AC-P01-14: password %s -> 400 invalid_password, nothing stored, no cookie', async (_l, password, message) => {
    const a = await app();
    const res = await req(a, 'post', '/api/auth/setup').send(password === undefined ? {} : { password });
    expectErrorBody(res, 400, 'invalid_password');
    expect(res.body.message).toBe(message);
    expect(sessionCookie(res)).toBeUndefined();
    expect(await db.query('SELECT 1 FROM users WHERE password_hash IS NOT NULL')).toEqual([]);
  });

  it('AC-P01-14: exactly 12 characters is accepted', async () => {
    const a = await app();
    expect((await req(a, 'post', '/api/auth/setup').send({ password: 'x'.repeat(12) })).status).toBe(201);
  });

  it('AC-P01-4: second setup -> 409 setup_already_done (even with a session), password unchanged', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const [before] = await db.query<{ password_hash: string }>('SELECT password_hash FROM users');
    for (const opts of [{}, { cookie }]) {
      const res = await req(a, 'post', '/api/auth/setup', opts).send({ password: 'another-password-123' });
      expectErrorBody(res, 409, 'setup_already_done');
      expect(sessionCookie(res)).toBeUndefined();
    }
    const [after] = await db.query<{ password_hash: string }>('SELECT password_hash FROM users');
    expect(after.password_hash).toBe(before.password_hash);
    await expect(login(a, 'another-password-123')).rejects.toThrow();
  });

  it('AC-P01-16 / ADR-001 karar 2: after the recovery SQL step setup reuses the same user; API key keeps working; old cookie 401', async () => {
    const a = await app();
    const oldCookie = await setupPassword(a);
    const { key } = await createApiKey(a, oldCookie);
    const [before] = await db.query<{ id: string }>('SELECT id FROM users');
    await runRecoverySql(db.pool);

    expectErrorBody(await req(a, 'get', '/api/projects', { cookie: oldCookie }), 401, 'setup_required');
    const res = await req(a, 'post', '/api/auth/setup').send({ password: 'recovered-password-1' });
    expect(res.status).toBe(201);
    expect(sessionCookie(res)).toBeDefined();
    const users = await db.query<{ id: string }>('SELECT id FROM users');
    expect(users).toEqual([{ id: before.id }]);
    expect((await req(a, 'get', '/api/projects', { bearer: key })).status).toBe(200);
    expect((await req(a, 'get', '/api/projects', { cookie: oldCookie })).status).toBe(401);
    expect((await req(a, 'get', '/api/auth/me', { cookie: sessionCookie(res) })).body.data.id).toBe(before.id);
  });

  const FIXED_STATE_MSG = 'Setup cannot proceed: user state requires manual repair (see db/README.md)';

  async function expectStateInvalid(a: Express, ids: string[]): Promise<void> {
    const countBefore = (await db.query('SELECT id FROM users')).length;
    const res = await req(a, 'post', '/api/auth/setup').send({ password: TEST_PASSWORD });
    expectErrorBody(res, 500, 'setup_state_invalid');
    expect(res.body.message).toBe(FIXED_STATE_MSG);
    expect(sessionCookie(res)).toBeUndefined();
    for (const id of ids) expect(JSON.stringify(res.body)).not.toContain(id);
    expect(await db.query('SELECT 1 FROM users WHERE password_hash IS NOT NULL')).toEqual([]);
    expect((await db.query('SELECT id FROM users')).length).toBe(countBefore);
  }

  it('ADR-001 karar 2: two password-less active admins -> 500 setup_state_invalid', async () => {
    const ids = [await insertUser('a@example.invalid'), await insertUser('b@example.invalid')];
    await expectStateInvalid(await app(), ids);
  });

  it('ADR-001 karar 2: only an inactive admin -> 500 setup_state_invalid, no new user', async () => {
    await expectStateInvalid(await app(), [await insertUser('i@example.invalid', { status: 'inactive' })]);
  });

  it('ADR-001 karar 2: only a soft-deleted admin -> 500 setup_state_invalid', async () => {
    await expectStateInvalid(await app(), [await insertUser('d@example.invalid', { deleted: true })]);
  });

  it('ADR-001 karar 2: only an active user without the admin role -> 500 setup_state_invalid', async () => {
    await expectStateInvalid(await app(), [await insertUser('n@example.invalid', { admin: false })]);
  });

  it('ADR-001 karar 2: admin role row missing -> 500 setup_state_invalid', async () => {
    await db.query(`DELETE FROM roles WHERE name = 'admin'`);
    await expectStateInvalid(await app(), []);
  });

  it('ADR-001 karar 2: two concurrent setups on an empty DB -> one 201, one 409', async () => {
    const a = await app();
    const [r1, r2] = await Promise.all([
      req(a, 'post', '/api/auth/setup').send({ password: 'concurrent-pass-1' }),
      req(a, 'post', '/api/auth/setup').send({ password: 'concurrent-pass-2' }),
    ]);
    expect([r1.status, r2.status].sort()).toEqual([201, 409]);
    expect((await db.query('SELECT id FROM users')).length).toBe(1);
  });

  it('ADR-001 karar 2: two concurrent setups after recovery -> one 201, one 409, same single user', async () => {
    const a = await app();
    await setupPassword(a);
    await runRecoverySql(db.pool);
    const [r1, r2] = await Promise.all([
      req(a, 'post', '/api/auth/setup').send({ password: 'concurrent-pass-1' }),
      req(a, 'post', '/api/auth/setup').send({ password: 'concurrent-pass-2' }),
    ]);
    expect([r1.status, r2.status].sort()).toEqual([201, 409]);
    expect((await db.query('SELECT id FROM users')).length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
describe('P-01 login, logout and sessions (AC-P01-2, -6, -12, -13)', () => {
  it('AC-P01-2 / AC-P01-10: valid session cookie -> protected request 200', async () => {
    const a = await app();
    await setupPassword(a);
    const cookie = await login(a);
    expect((await req(a, 'get', '/api/projects', { cookie })).status).toBe(200);
  });

  it('AC-P01-6: wrong password -> 401 invalid_credentials and no Set-Cookie', async () => {
    const a = await app();
    await setupPassword(a);
    const res = await req(a, 'post', '/api/auth/login').send({ password: 'wrong-password-123' });
    expectErrorBody(res, 401, 'invalid_credentials');
    expect(sessionCookie(res)).toBeUndefined();
    expect(logged.join('\n')).not.toContain('wrong-password-123');
  });

  it('ADR-001 karar 11: 5 failed logins then 429 + Retry-After, even for the correct password', async () => {
    const a = await app();
    await setupPassword(a);
    for (let i = 0; i < 5; i += 1) {
      expect((await req(a, 'post', '/api/auth/login').send({ password: `wrong-password-${i}x` })).status).toBe(401);
    }
    const blocked = await req(a, 'post', '/api/auth/login').send({ password: TEST_PASSWORD });
    expectErrorBody(blocked, 429, 'too_many_attempts');
    const retryAfter = Number(blocked.headers['retry-after']);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(30);
    expect(sessionCookie(blocked)).toBeUndefined();
  });

  it('AC-P01-12: logout closes only the current session; other session and API key stay valid', async () => {
    const a = await app();
    const setupCookie = await setupPassword(a);
    const { key } = await createApiKey(a, setupCookie);
    const c1 = await login(a);
    const c2 = await login(a);
    const out = await req(a, 'post', '/api/auth/logout', { cookie: c1 });
    expect(out.status).toBe(204);
    expect(setCookieLines(out).find((l) => l.startsWith('ossrisk_session='))).toMatch(/Max-Age=0/i);
    expectErrorBody(await req(a, 'get', '/api/projects', { cookie: c1 }), 401, 'unauthenticated');
    expect((await req(a, 'get', '/api/projects', { cookie: c2 })).status).toBe(200);
    expect((await req(a, 'get', '/api/projects', { cookie: setupCookie })).status).toBe(200);
    expect((await req(a, 'get', '/api/projects', { bearer: key })).status).toBe(200);
  });

  it('AC-P01-12: logout with Bearer -> 403 forbidden; without credentials -> 401', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const { key } = await createApiKey(a, cookie);
    expectErrorBody(await req(a, 'post', '/api/auth/logout', { bearer: key, origin: null }), 403, 'forbidden');
    expectErrorBody(await req(a, 'post', '/api/auth/logout'), 401, 'unauthenticated');
  });

  async function sessionAfterSetup(a: Express): Promise<{ cookie: string; id: string }> {
    const cookie = await setupPassword(a);
    const [s] = await db.query<{ id: string }>('SELECT id FROM sessions WHERE token_hash = $1', [sha256(cookie.split('=')[1])]);
    return { cookie, id: s.id };
  }

  it('AC-P01-13: idle for more than 12 hours -> 401', async () => {
    const a = await app();
    const { cookie, id } = await sessionAfterSetup(a);
    await db.query(`UPDATE sessions SET last_seen_at = now() - interval '12 hours 1 minute' WHERE id = $1`, [id]);
    expectErrorBody(await req(a, 'get', '/api/projects', { cookie }), 401, 'unauthenticated');
  });

  it('AC-P01-13: used within 12 hours -> 200 and last_seen_at refreshed; expires_at not extended', async () => {
    const a = await app();
    const { cookie, id } = await sessionAfterSetup(a);
    await db.query(`UPDATE sessions SET last_seen_at = now() - interval '11 hours 59 minutes' WHERE id = $1`, [id]);
    const [before] = await db.query<{ expires_at: Date }>('SELECT expires_at FROM sessions WHERE id = $1', [id]);
    expect((await req(a, 'get', '/api/projects', { cookie })).status).toBe(200);
    const [after] = await db.query<{ fresh: boolean; expires_at: Date }>(
      `SELECT last_seen_at > now() - interval '5 minutes' AS fresh, expires_at FROM sessions WHERE id = $1`,
      [id],
    );
    expect(after.fresh).toBe(true);
    expect(after.expires_at.getTime()).toBe(before.expires_at.getTime());
  });

  it('AC-P01-13: absolute limit 7 days — expires_at = created_at + 7 days; past expires_at -> 401 even if recently used', async () => {
    const a = await app();
    const { cookie, id } = await sessionAfterSetup(a);
    const [s] = await db.query<{ diff: number }>(
      `SELECT extract(epoch FROM (expires_at - created_at))::int AS diff FROM sessions WHERE id = $1`,
      [id],
    );
    expect(Math.abs(s.diff - 7 * 24 * 3600)).toBeLessThanOrEqual(5);
    await db.query(
      `UPDATE sessions SET created_at = now() - interval '7 days 1 minute', expires_at = now() - interval '1 minute', last_seen_at = now() WHERE id = $1`,
      [id],
    );
    expectErrorBody(await req(a, 'get', '/api/projects', { cookie }), 401, 'unauthenticated');
  });
});

// ---------------------------------------------------------------------------
describe('P-01 API keys (AC-P01-3, AC-P01-5, AC-P01-15, D-16)', () => {
  it('AC-P01-3 / AC-P01-15: key format, one-time display, Bearer 200, hash-only storage', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const res = await req(a, 'post', '/api/auth/api-keys', { cookie }).send({ name: 'ci' });
    expect(res.status).toBe(201);
    expect(String(res.headers['cache-control'])).toContain('no-store');
    const { id, key, keyPrefix } = res.body.data;
    expect(key).toMatch(API_KEY_RE);
    expect(key).toHaveLength(65);
    expect(keyPrefix).toMatch(KEY_PREFIX_RE);
    expect(keyPrefix).toBe(key.slice(0, 21));
    expect(keyPrefix).not.toContain(key.slice(22));
    expect((await req(a, 'get', '/api/projects', { bearer: key })).status).toBe(200);

    const rows = await db.query<{ key_hash: string; key_prefix: string }>('SELECT key_hash, key_prefix FROM api_keys WHERE id = $1', [id]);
    expect(rows).toEqual([{ key_hash: sha256(key), key_prefix: keyPrefix }]);
    const list = await req(a, 'get', '/api/auth/api-keys', { cookie });
    expect(list.status).toBe(200);
    expect(JSON.stringify(list.body)).not.toContain(key);
    expect(JSON.stringify(list.body)).not.toContain(sha256(key));
    expect(logged.join('\n')).not.toContain(key);
  });

  it('AC-P01-3: invalid, malformed, wrong-secret and query-string keys -> 401', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const { key } = await createApiKey(a, cookie);
    const wrongSecret = `${key.slice(0, 22)}${'A'.repeat(43)}`;
    for (const bearer of [wrongSecret, 'ossr_short', 'not-a-key', `${key}x`]) {
      expectErrorBody(await req(a, 'get', '/api/projects', { bearer }), 401, 'unauthenticated');
    }
    expectErrorBody(await req(a, 'get', `/api/projects?api_key=${key}`), 401, 'unauthenticated');
    const basic = await req(a, 'get', '/api/projects').set('Authorization', `Basic ${Buffer.from(`x:${key}`).toString('base64')}`);
    expectErrorBody(basic, 401, 'unauthenticated');
  });

  it('AC-P01-15 (1) / D-16: new key while A is active -> 201 (no 409); A 401, B 200, single active key', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const keyA = await createApiKey(a, cookie);
    const resB = await req(a, 'post', '/api/auth/api-keys', { cookie }).send({});
    expect(resB.status).toBe(201);
    const keyB = resB.body.data;
    expectErrorBody(await req(a, 'get', '/api/projects', { bearer: keyA.key }), 401, 'unauthenticated');
    expect((await req(a, 'get', '/api/projects', { bearer: keyB.key })).status).toBe(200);
    expect(await db.query('SELECT id FROM api_keys WHERE revoked_at IS NULL')).toEqual([{ id: keyB.id }]);
    const list = await req(a, 'get', '/api/auth/api-keys', { cookie });
    expect(list.body.data.filter((k: { revokedAt: unknown }) => k.revokedAt === null)).toHaveLength(1);
  });

  it('AC-P01-15 (2): DELETE revokes (row kept), key 401, repeated DELETE 204, unknown/invalid id 404', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const { id, key } = await createApiKey(a, cookie);
    expect((await req(a, 'delete', `/api/auth/api-keys/${id}`, { cookie })).status).toBe(204);
    expectErrorBody(await req(a, 'get', '/api/projects', { bearer: key }), 401, 'unauthenticated');
    const rows = await db.query<{ revoked: boolean }>('SELECT revoked_at IS NOT NULL AS revoked FROM api_keys WHERE id = $1', [id]);
    expect(rows).toEqual([{ revoked: true }]);
    expect((await req(a, 'delete', `/api/auth/api-keys/${id}`, { cookie })).status).toBe(204);
    expectErrorBody(await req(a, 'delete', `/api/auth/api-keys/${RANDOM_UUID}`, { cookie }), 404, 'not_found');
    expectErrorBody(await req(a, 'delete', '/api/auth/api-keys/not-a-uuid', { cookie }), 404, 'not_found');
  });

  it('AC-P01-15: key management with Bearer -> 403 forbidden (a leaked CI key cannot mint or revoke keys)', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const { id, key } = await createApiKey(a, cookie);
    expectErrorBody(await req(a, 'post', '/api/auth/api-keys', { bearer: key, origin: null }).send({}), 403, 'forbidden');
    expectErrorBody(await req(a, 'get', '/api/auth/api-keys', { bearer: key }), 403, 'forbidden');
    expectErrorBody(await req(a, 'delete', `/api/auth/api-keys/${id}`, { bearer: key, origin: null }), 403, 'forbidden');
  });

  it('AC-P01-15: two concurrent key creations leave exactly one active key', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const results = await Promise.all([
      req(a, 'post', '/api/auth/api-keys', { cookie }).send({}),
      req(a, 'post', '/api/auth/api-keys', { cookie }).send({}),
    ]);
    expect(results.map((r) => r.status)).toEqual([201, 201]);
    expect(await db.query('SELECT id FROM api_keys WHERE revoked_at IS NULL')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
describe('P-01 Origin / Host checks (ADR-001 karar 5)', () => {
  it('cookie-authenticated POST with a foreign Origin -> 403 origin_rejected; Origin null and missing Origin+Referer -> 403', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const body = { name: 'origin-test' };
    for (const origin of ['http://evil.example', 'null']) {
      expectErrorBody(await req(a, 'post', '/api/projects', { cookie, origin }).send(body), 403, 'origin_rejected');
    }
    expectErrorBody(await req(a, 'post', '/api/projects', { cookie, origin: null }).send(body), 403, 'origin_rejected');
    expect(await db.query('SELECT id FROM projects')).toEqual([]);
  });

  it('same-origin Referer without Origin is accepted', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const res = await req(a, 'post', '/api/projects', { cookie, origin: null }).set('Referer', `${ORIGIN}/`).send({ name: 'via-referer' });
    expect(res.status).toBe(201);
  });

  it('Bearer POST without Origin is accepted (Origin check applies to cookies only)', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const { key } = await createApiKey(a, cookie);
    expect((await req(a, 'post', '/api/projects', { bearer: key, origin: null }).send({ name: 'ci-project' })).status).toBe(201);
  });

  it('login and setup with a foreign Origin -> 403 origin_rejected (setup does not store the password)', async () => {
    const a = await app();
    expectErrorBody(await req(a, 'post', '/api/auth/setup', { origin: 'http://evil.example' }).send({ password: TEST_PASSWORD }), 403, 'origin_rejected');
    expect(await db.query('SELECT id FROM users')).toEqual([]);
    await setupPassword(a);
    expectErrorBody(await req(a, 'post', '/api/auth/login', { origin: 'http://evil.example' }).send({ password: TEST_PASSWORD }), 403, 'origin_rejected');
  });

  it('foreign Host -> 403 host_rejected JSON on /health, static /, and /api/auth/setup', async () => {
    const a = await app();
    for (const [method, url] of [['get', '/health'], ['get', '/'], ['post', '/api/auth/setup']] as const) {
      const res = await req(a, method, url).set('Host', `evil.example:3001`).send(method === 'post' ? { password: TEST_PASSWORD } : undefined);
      expectErrorBody(res, 403, 'host_rejected');
    }
    expect(await db.query('SELECT id FROM users')).toEqual([]);
  });

  it('allowed Host variants: localhost:<PORT> and [::1]:<PORT>', async () => {
    const a = await app();
    for (const host of [`localhost:3001`, `[::1]:3001`, HOST_HEADER]) {
      expect((await req(a, 'get', '/health').set('Host', host)).status).toBe(200);
    }
  });
});

// ---------------------------------------------------------------------------
describe('P-01 identity on written records (AC-P01-8, AC-P01-17)', () => {
  it('AC-P01-17: project owner and scan initiator are the authenticated user, never the 0000… fallback', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const [user] = await db.query<{ id: string }>('SELECT id FROM users');
    const proj = await req(a, 'post', '/api/projects', { cookie }).send({ name: 'owner-test' });
    expect(proj.status).toBe(201);
    const scan = await req(a, 'post', '/api/scans', { cookie }).send({ projectId: proj.body.data.id });
    expect(scan.status).toBe(201);
    const [p] = await db.query<{ owner_id: string }>('SELECT owner_id FROM projects WHERE id = $1', [proj.body.data.id]);
    const [s] = await db.query<{ initiated_by: string }>('SELECT initiated_by FROM scans WHERE id = $1', [scan.body.data.id]);
    expect(p.owner_id).toBe(user.id);
    expect(s.initiated_by).toBe(user.id);
  });

  it('AC-P01-8: the authenticated user works with the single role admin', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    expect((await req(a, 'get', '/api/auth/me', { cookie })).body.data.roles).toEqual(['admin']);
    expect((await req(a, 'get', '/api/users', { cookie })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
describe('JSON errors and /health (AC-G-8, AC-G-9)', () => {
  it('AC-G-8: undefined /api route -> 404 JSON not_found', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    expectErrorBody(await req(a, 'get', '/api/does-not-exist', { cookie }), 404, 'not_found');
  });

  it('AC-G-8: malformed JSON -> 400 JSON invalid_request', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const res = await req(a, 'post', '/api/projects', { cookie }).set('Content-Type', 'application/json').send('{"name": ');
    expectErrorBody(res, 400, 'invalid_request');
  });

  it('AC-G-8: existing validation 400 keeps its message and gets code invalid_request', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const res = await req(a, 'post', '/api/projects', { cookie }).send({});
    expectErrorBody(res, 400, 'invalid_request');
    expect(res.body.message).toBe('Project name is required');
  });

  it('AC-G-8: unexpected error -> 500 internal_error with a fixed message, no stack or raw DB text', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const res = await req(a, 'get', '/api/scans/not-a-uuid', { cookie }); // pg: invalid input syntax for type uuid
    expectErrorBody(res, 500, 'internal_error');
    expect(res.body.message).toBe('Internal server error');
    const text = JSON.stringify(res.body);
    expect(text).not.toMatch(/invalid input syntax|uuid|\bat\s+\S+\s+\(|\.ts:\d+/i);
  });

  it('AC-G-8: body over the parser limit -> 413 payload_too_large JSON', async () => {
    const a = await app();
    const cookie = await setupPassword(a);
    const res = await req(a, 'post', '/api/projects', { cookie }).send({ name: 'x', description: 'y'.repeat(2_000_000) });
    expectErrorBody(res, 413, 'payload_too_large');
  });

  it('AC-G-9: /health with a failing database -> 500 fixed body, raw DB message never returned', async () => {
    const secretish = 'connect ECONNREFUSED 10.9.8.7:5432 password authentication failed for user "dbuser-x"';
    const failingDb = {
      query: async () => {
        throw new Error(secretish);
      },
      connect: async () => {
        throw new Error(secretish);
      },
    } as unknown as Pool;
    const a = await makeApp(failingDb);
    const res = await req(a, 'get', '/health');
    expect(res.status).toBe(500);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.body).toEqual({
      status: 'unhealthy',
      database: 'disconnected',
      error: 'Internal Server Error',
      message: 'Database unavailable',
      code: 'internal_error',
    });
    expect(JSON.stringify(res.body)).not.toMatch(/ECONNREFUSED|dbuser-x|10\.9\.8\.7/);
  });

  it('AC-G-9: /health healthy -> 200 {status:healthy, database:connected}', async () => {
    const a = await app();
    const res = await req(a, 'get', '/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'healthy', database: 'connected' });
  });
});

// ---------------------------------------------------------------------------
describe('P-01 bind address (AC-P01-9)', () => {
  it('AC-P01-9: without HOST the server listens on 127.0.0.1 only', async () => {
    const { startServer } = await loadApp();
    const saved = process.env.HOST;
    delete process.env.HOST;
    try {
      const server = await startServer({ db: db.pool, port: 0 });
      try {
        expect((server.address() as AddressInfo).address).toBe('127.0.0.1');
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    } finally {
      if (saved !== undefined) process.env.HOST = saved;
    }
  });
});
