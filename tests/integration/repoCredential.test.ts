/**
 * REQ-009 end to end against a real (embedded) PostgreSQL: P-29 repo access
 * token (PUT /api/projects/{id}/repo-credential, no DELETE, never echoed,
 * encrypted at rest, audit without secrets), AC-P29-8/10 scan linking,
 * AC-P31-1 no ref -> NULL -> clone without --branch (fake clone captures the
 * call), and the integrations:write guard.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Express } from 'express';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ROLE_PERMISSIONS } from '../../src/config/permissions';
import { ScanWorker, decryptToken } from '../../src/scanner/worker';
import { useTestDatabase } from '../helpers/db';
import { expectErrorBody, makeApp, req, setupPassword } from '../helpers/http';
import { REPO_ROOT } from '../helpers/paths';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file', setDatabaseUrlEnv: true });
const KEY = 'repo-credential-test-key-not-secret';
const TOKEN_A = 'pat-A-test-value-not-real-0123456789';
const TOKEN_B = 'pat-B-test-value-not-real-9876543210';
const TFS_URL = 'https://tfs.example.local/Collection/Project/_git/Repo';
const silent = { log: () => undefined, warn: () => undefined, error: () => undefined };

let app: Express;
let cookie = '';
let savedKey: string | undefined;

async function createProject(name: string, repoUrl: string): Promise<string> {
  const res = await req(app, 'post', '/api/projects', { cookie }).send({ name, repoUrl, ecosystems: [] });
  expect(res.status).toBe(201);
  expect(res.body.data.has_repo_credential).toBe(false);
  return res.body.data.id as string;
}

const putToken = (id: string, body: unknown) => req(app, 'put', `/api/projects/${id}/repo-credential`, { cookie }).send(body as object);

beforeAll(async () => {
  savedKey = process.env.ENCRYPTION_KEY;
  process.env.ENCRYPTION_KEY = KEY;
  app = await makeApp(db.pool);
  cookie = await setupPassword(app);
});

afterAll(() => {
  if (savedKey === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = savedKey;
});

beforeEach(async () => {
  await db.pool.query(`UPDATE scans SET status = 'cancelled' WHERE status IN ('pending','queued','running')`);
});

describe('AC-P29-1…7: PUT /api/projects/{id}/repo-credential', () => {
  it('AC-P29-2: invalid bodies -> 400 invalid_token, nothing stored', async () => {
    const id = await createProject('cred-invalid', TFS_URL);
    for (const body of [{}, { token: '' }, { token: 'has space' }, { token: 'tab\there' }, { token: 'x'.repeat(1025) }, { token: 42 }, { token: TOKEN_A, extra: 1 }, [TOKEN_A]]) {
      expectErrorBody(await putToken(id, body), 400, 'invalid_token');
    }
    const rows = await db.pool.query('SELECT 1 FROM integrations WHERE project_id = $1', [id]);
    expect(rows.rowCount).toBe(0);
  });

  it('AC-P29-3: unknown project -> 404; non-https repo -> 400 repo_credential_not_applicable', async () => {
    expectErrorBody(await putToken('00000000-0000-4000-8000-000000000000', { token: TOKEN_A }), 404, 'not_found');
    expectErrorBody(await putToken('not-a-uuid', { token: TOKEN_A }), 400, 'invalid_request');
    const owner = await db.pool.query<{ id: string }>('SELECT id FROM users LIMIT 1');
    const local = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (name, repo_url, owner_id) VALUES ('cred-local', 'C:\\work\\repo', $1) RETURNING id`,
      [owner.rows[0].id],
    );
    expectErrorBody(await putToken(local.rows[0].id, { token: TOKEN_A }), 400, 'repo_credential_not_applicable');
  });

  it('AC-P29-4…7: stored encrypted, never echoed, replaced by a new PUT, audited without secrets; no DELETE route', async () => {
    const id = await createProject('cred-tfs', TFS_URL);
    const first = await putToken(id, { token: TOKEN_A });
    expect(first.status).toBe(200);
    expect(first.body).toEqual({ data: { has_repo_credential: true, provider: 'azure_devops' } });

    const stored = await db.pool.query<{ provider: string; repo_url: string; access_token_enc: Buffer; is_active: boolean }>(
      'SELECT provider::text AS provider, repo_url, access_token_enc, is_active FROM integrations WHERE project_id = $1',
      [id],
    );
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]).toMatchObject({ provider: 'azure_devops', repo_url: TFS_URL, is_active: true });
    expect(stored.rows[0].access_token_enc.toString('utf8')).not.toContain(TOKEN_A);
    expect(decryptToken(stored.rows[0].access_token_enc, KEY)).toBe(TOKEN_A);

    const list = await req(app, 'get', '/api/projects', { cookie });
    expect(list.status).toBe(200);
    const item = (list.body.data as Array<Record<string, unknown>>).find((p) => p.id === id)!;
    expect(item.has_repo_credential).toBe(true);
    expect(JSON.stringify(list.body)).not.toContain(TOKEN_A);
    expect(Object.keys(item)).not.toContain('access_token_enc');

    const second = await putToken(id, { token: TOKEN_B });
    expect(second.status).toBe(200);
    const after = await db.pool.query<{ access_token_enc: Buffer }>(
      'SELECT access_token_enc FROM integrations WHERE project_id = $1 AND is_active',
      [id],
    );
    expect(after.rows).toHaveLength(1);
    expect(decryptToken(after.rows[0].access_token_enc, KEY)).toBe(TOKEN_B);

    const audit = await db.pool.query<{ action: string; old_data: unknown; new_data: unknown }>(
      `SELECT action::text AS action, old_data, new_data FROM audit_logs WHERE entity_type = 'integration' ORDER BY occurred_at`,
    );
    expect(audit.rows.map((r) => r.action)).toEqual(['integration_created', 'integration_updated']);
    const auditText = JSON.stringify(audit.rows);
    for (const secret of [TOKEN_A, TOKEN_B]) expect(auditText).not.toContain(secret);

    const del = await req(app, 'delete', `/api/projects/${id}/repo-credential`, { cookie });
    expect(del.status).toBe(404);
    expect((await db.pool.query('SELECT 1 FROM integrations WHERE project_id = $1 AND is_active', [id])).rowCount).toBe(1);
  });

  it('AC-P29-4: provider follows the host', async () => {
    const gh = await createProject('cred-gh', 'https://github.com/org/private-repo.git');
    expect((await putToken(gh, { token: TOKEN_A })).body.data.provider).toBe('github');
    const gl = await createProject('cred-gl', 'https://gitlab.example.com/g/r.git');
    expect((await putToken(gl, { token: TOKEN_A })).body.data.provider).toBe('gitlab');
  });

  it('AC-P29-1: the route is guarded by integrations:write, which only admin holds', () => {
    const routes = fs.readFileSync(path.join(REPO_ROOT, 'src', 'routes', 'projectRoutes.ts'), 'utf8');
    expect(routes).toMatch(/router\.put\('\/projects\/:id\/repo-credential', guard\('integrations:write'\)/);
    expect(routes).not.toMatch(/router\.delete\(/);
    const holders = Object.entries(ROLE_PERMISSIONS).filter(([, perms]) => perms.has('integrations:write')).map(([role]) => role);
    expect(holders).toEqual(['admin']);
  });
});

describe('AC-P29-8/10, AC-P31-1: scans link the integration and clone the remote default branch', () => {
  it('no ref -> scans.ref NULL + integration_id; the worker clones with the decrypted token and ref null', async () => {
    const id = await createProject('cred-scan', TFS_URL);
    expect((await putToken(id, { token: TOKEN_A })).status).toBe(200);
    const created = await req(app, 'post', '/api/scans', { cookie }).send({ projectId: id });
    expect(created.status).toBe(201);
    expect(created.body.data.ref).toBeNull();
    const row = await db.pool.query<{ integration_id: string | null; ref: string | null }>('SELECT integration_id, ref FROM scans WHERE id = $1', [created.body.data.id]);
    expect(row.rows[0].ref).toBeNull();
    expect(row.rows[0].integration_id).not.toBeNull();

    const calls: Array<{ url: string; ref: string | null; token: string | null }> = [];
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-test-repocred-'));
    try {
      const worker = new ScanWorker({
        db: db.pool,
        tmpRoot,
        logger: silent,
        scanRoots: [],
        cloneRepo: async (url, ref, dest, token) => {
          calls.push({ url, ref, token });
          fs.mkdirSync(dest, { recursive: true });
        },
        runParser: async (_dir, _eco, scanId) => ({ scan_id: scanId, status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] }),
      });
      expect(await worker.runOnce()).toBe(created.body.data.id);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
    expect(calls).toEqual([{ url: TFS_URL, ref: null, token: TOKEN_A }]);
    const done = await db.pool.query<{ status: string; error_message: string | null }>('SELECT status, error_message FROM scans WHERE id = $1', [created.body.data.id]);
    expect(done.rows[0].status).toBe('completed');
    expect(String(done.rows[0].error_message ?? '')).not.toContain(TOKEN_A);
  });

  it('an explicit ref is kept', async () => {
    const id = await createProject('cred-ref', TFS_URL);
    const created = await req(app, 'post', '/api/scans', { cookie }).send({ projectId: id, ref: 'develop' });
    expect(created.status).toBe(201);
    expect(created.body.data.ref).toBe('develop');
  });

  it('AC-P29-10: an integration for another repo URL is not linked (the token never goes to another host)', async () => {
    const id = await createProject('cred-moved', TFS_URL);
    expect((await putToken(id, { token: TOKEN_A })).status).toBe(200);
    await db.pool.query(`UPDATE projects SET repo_url = 'https://other.example.local/C/P/_git/R' WHERE id = $1`, [id]);
    const created = await req(app, 'post', '/api/scans', { cookie }).send({ projectId: id });
    expect(created.status).toBe(201);
    const row = await db.pool.query<{ integration_id: string | null }>('SELECT integration_id FROM scans WHERE id = $1', [created.body.data.id]);
    expect(row.rows[0].integration_id).toBeNull();
    const list = await req(app, 'get', '/api/projects', { cookie });
    expect((list.body.data as Array<Record<string, unknown>>).find((p) => p.id === id)!.has_repo_credential).toBe(false);
  });
});
