/**
 * REQ-002 · P-04 (AC-P04-2…6) and P-03 (AC-P03-7, AC-P03-11) at the HTTP boundary.
 * POST /api/projects (repoUrl) and POST /api/scans (effective repo_url) are
 * classified BEFORE anything is stored/queued; on rejection nothing is
 * written. Contract: REQ-002-auth-api.md "P-04 — 400 davranışı".
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Express } from 'express';
import { useTestDatabase } from '../helpers/db';
import { expectErrorBody, makeApp, req, setupPassword } from '../helpers/http';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file', setDatabaseUrlEnv: true });
const dirs = { base: '', root: '', proj: '', outside: '', link: '' };
let app: Express;
let cookie = '';

beforeAll(async () => {
  dirs.base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-http-roots-')));
  dirs.root = path.join(dirs.base, 'root');
  dirs.proj = path.join(dirs.root, 'proj');
  dirs.outside = path.join(dirs.base, 'outside');
  dirs.link = path.join(dirs.root, 'link');
  fs.mkdirSync(dirs.proj, { recursive: true });
  fs.mkdirSync(dirs.outside, { recursive: true });
  fs.symlinkSync(dirs.outside, dirs.link, 'junction');
  app = await makeApp(db.pool, { scanRoots: [dirs.root] });
  cookie = await setupPassword(app);
});

afterAll(() => {
  if (dirs.base) fs.rmSync(dirs.base, { recursive: true, force: true });
});

const count = async (table: 'projects' | 'scans') => (await db.query(`SELECT id FROM ${table}`)).length;

describe('P-04 POST /api/projects repoUrl classification', () => {
  it('AC-P04-2: local directory under SCAN_ROOTS -> 201', async () => {
    const res = await req(app, 'post', '/api/projects', { cookie }).send({ name: 'local-ok', repoUrl: dirs.proj });
    expect(res.status).toBe(201);
  });

  it('AC-P03-7: https repository -> 201', async () => {
    const res = await req(app, 'post', '/api/projects', { cookie }).send({ name: 'remote-ok', repoUrl: 'https://github.com/org/repo.git' });
    expect(res.status).toBe(201);
  });

  const pathCases: Array<[string, () => string]> = [
    ['AC-P04-3: directory outside SCAN_ROOTS', () => dirs.outside],
    ['AC-P04-4: ".." traversal', () => `${dirs.proj}${path.sep}..${path.sep}..${path.sep}outside`],
    ['AC-P04-4: junction pointing outside', () => dirs.link],
    ['AC-P04-3: non-existent directory', () => path.join(dirs.root, 'missing')],
  ];
  it.each(pathCases)('%s -> 400 path_not_allowed, project not stored', async (_label, value) => {
    const before = await count('projects');
    const res = await req(app, 'post', '/api/projects', { cookie }).send({ name: 'rejected', repoUrl: value() });
    expectErrorBody(res, 400, 'path_not_allowed');
    expect(res.body.message).toBe('Local path is not under an allowed scan root');
    expect(JSON.stringify(res.body)).not.toContain(dirs.base);
    expect(await count('projects')).toBe(before);
  });

  const urlCases = [
    'http://github.com/org/repo.git',
    'ssh://git@github.com/org/repo.git',
    'git@github.com:org/repo.git',
    'ext::sh -c touch% /tmp/pwned',
    'file:///C:/repos/app',
    'https://user:not-a-real-token@github.com/org/repo.git',
    '\\\\server\\share\\repo',
    'relative/path',
    '.',
  ];
  it.each(urlCases)('AC-P03-7 / AC-P04-5: %j -> 400 repo_url_not_allowed, project not stored', async (value) => {
    const before = await count('projects');
    const res = await req(app, 'post', '/api/projects', { cookie }).send({ name: 'rejected', repoUrl: value });
    expectErrorBody(res, 400, 'repo_url_not_allowed');
    expect(res.body.message).toBe('Repository URL is not allowed; only https URLs are accepted');
    expect(await count('projects')).toBe(before);
  });
});

describe('P-04 POST /api/scans re-checks the effective repo_url (AC-P04-5)', () => {
  async function projectWithRepo(repoUrl: string): Promise<string> {
    const [row] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ('direct-insert', $1) RETURNING id`, [repoUrl]);
    return row.id;
  }

  it('AC-P04-5: stored local path outside SCAN_ROOTS -> 400 path_not_allowed, no scan queued', async () => {
    const projectId = await projectWithRepo(dirs.outside);
    const before = await count('scans');
    expectErrorBody(await req(app, 'post', '/api/scans', { cookie }).send({ projectId }), 400, 'path_not_allowed');
    expect(await count('scans')).toBe(before);
  });

  it('AC-P04-5: stored ssh URL -> 400 repo_url_not_allowed, no scan queued', async () => {
    const projectId = await projectWithRepo('git@github.com:org/repo.git');
    const before = await count('scans');
    expectErrorBody(await req(app, 'post', '/api/scans', { cookie }).send({ projectId }), 400, 'repo_url_not_allowed');
    expect(await count('scans')).toBe(before);
  });

  it('AC-P04-2: stored path under SCAN_ROOTS -> 201', async () => {
    const projectId = await projectWithRepo(dirs.proj);
    expect((await req(app, 'post', '/api/scans', { cookie }).send({ projectId })).status).toBe(201);
  });
});

describe('P-03 project without a source (AC-P03-11, D-20, contract K12)', () => {
  const SOURCE_MISSING_MESSAGE = 'Project has no repository URL or local path';

  it.each([
    ['NULL', null],
    ["''", ''],
  ])('AC-P03-11: repo_url %s -> 400 project_source_missing, no scan row', async (_label, repoUrl) => {
    const [row] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ('no-source', $1) RETURNING id`, [repoUrl]);
    const before = await count('scans');
    const res = await req(app, 'post', '/api/scans', { cookie }).send({ projectId: row.id });
    expectErrorBody(res, 400, 'project_source_missing');
    expect(res.body.message).toBe(SOURCE_MISSING_MESSAGE);
    expect(await count('scans')).toBe(before);
  });

  it('K12 (regression): unknown projectId -> 404 not_found, not 400', async () => {
    const res = await req(app, 'post', '/api/scans', { cookie }).send({ projectId: '7d1f3f5e-1c2b-4a3d-9e8f-0123456789ab' });
    expectErrorBody(res, 404, 'not_found');
  });

  it('K12 (regression): POST /api/projects without repoUrl is still 201', async () => {
    const res = await req(app, 'post', '/api/projects', { cookie }).send({ name: 'no-source-allowed' });
    expect(res.status).toBe(201);
  });
});

describe('P-04 SCAN_ROOTS undefined (AC-P04-6)', () => {
  it('AC-P04-6: app built without scanRoots and without SCAN_ROOTS env rejects every local path', async () => {
    const saved = process.env.SCAN_ROOTS;
    delete process.env.SCAN_ROOTS;
    try {
      const closed = await makeApp(db.pool);
      const before = await count('projects');
      const res = await req(closed, 'post', '/api/projects', { cookie }).send({ name: 'closed', repoUrl: dirs.proj });
      expectErrorBody(res, 400, 'path_not_allowed');
      expect(await count('projects')).toBe(before);
    } finally {
      if (saved !== undefined) process.env.SCAN_ROOTS = saved;
    }
  });
});
