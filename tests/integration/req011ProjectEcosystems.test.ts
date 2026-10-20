/**
 * REQ-011 AC-P42-3 / D-313: `POST /api/projects` accepts only supported
 * ecosystem values (the ten of `SCAN_ECOSYSTEMS`, including the new rust,
 * dart and swift enum values of migration 010); anything else is a 400
 * `invalid_request` before any row is written (it used to be a 500 from the
 * `::tech_ecosystem` cast).
 */
import type { Express } from 'express';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { SCAN_ECOSYSTEMS } from '../../src/types/scan';
import { useTestDatabase } from '../helpers/db';
import { expectErrorBody, makeApp, req, setupPassword } from '../helpers/http';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });
let app: Express;
let cookie = '';

beforeAll(async () => {
  app = await makeApp(db.pool);
  cookie = await setupPassword(app);
});

const create = (body: Record<string, unknown>) => req(app, 'post', '/api/projects', { cookie }).send(body);

describe('AC-P42-3: project ecosystem allowlist', () => {
  it('every supported ecosystem is stored (duplicates once, order kept) and listed', async () => {
    const res = await create({ name: 'req011-all', ecosystems: [...SCAN_ECOSYSTEMS, 'rust'] });
    expect(res.status).toBe(201);
    expect(res.body.data.ecosystems).toEqual([...SCAN_ECOSYSTEMS]);
    const rows = await db.query<{ ecosystem: string }>(
      `SELECT ecosystem::text AS ecosystem FROM project_tech_stacks WHERE project_id = $1 ORDER BY 1`,
      [res.body.data.id],
    );
    expect(rows.map((r) => r.ecosystem)).toEqual([...SCAN_ECOSYSTEMS].sort());
  });

  it('absent, null and [] mean "every supported ecosystem" (no stack row)', async () => {
    for (const [name, body] of [
      ['req011-absent', {}],
      ['req011-null', { ecosystems: null }],
      ['req011-empty', { ecosystems: [] }],
    ] as const) {
      const res = await create({ name, ...body });
      expect(res.status, name).toBe(201);
      expect(res.body.data.ecosystems).toEqual([]);
    }
  });

  it.each([
    ['unknown value', ['cobol']],
    ['enum value without a parser', ['container']],
    ['wrong case', ['Java']],
    ['empty string', ['']],
    ['number', [1]],
    ['nested array', [['nodejs']]],
    ['not an array', 'nodejs'],
    ['object', { 0: 'nodejs' }],
    ['too many entries', Array.from({ length: 41 }, () => 'nodejs')],
  ])('%s -> 400 invalid_request with the allowed list, no project row', async (label, ecosystems) => {
    const name = `req011-bad-${label}`;
    const res = await create({ name, ecosystems });
    expectErrorBody(res, 400, 'invalid_request');
    expect(res.body.message).toBe(`ecosystems must be an array of: ${SCAN_ECOSYSTEMS.join(', ')}`);
    expect(await db.query(`SELECT 1 FROM projects WHERE name = $1`, [name])).toEqual([]);
  });
});
