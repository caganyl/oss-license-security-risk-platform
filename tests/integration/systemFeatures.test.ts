/**
 * REQ-010 AC-P35-1 end to end: GET /api/system/features needs a session,
 * answers the contract shape, and never echoes a setting value.
 */
import type { Express } from 'express';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { parseAllowedHosts } from '../../src/webscan/allowlist';
import { useTestDatabase } from '../helpers/db';
import { makeApp, req, setupPassword } from '../helpers/http';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file', setDatabaseUrlEnv: true });
let app: Express;
let cookie = '';

beforeAll(async () => {
  app = await makeApp(db.pool, { scanRoots: [], webAllowlist: parseAllowedHosts('portal.example.local') });
  cookie = await setupPassword(app);
});

describe('AC-P35-1: GET /api/system/features', () => {
  it('401 without a session', async () => {
    const res = await req(app, 'get', '/api/system/features');
    expect(res.status).toBe(401);
  });

  it('200 with the contract keys, booleans and counts only', async () => {
    const res = await req(app, 'get', '/api/system/features', { cookie });
    expect(res.status).toBe(200);
    const data = res.body.data as Record<string, Record<string, unknown>>;
    expect(Object.keys(data).sort()).toEqual([
      'local_scan', 'nvd', 'registry_enrichment', 'repo_tokens', 'vulnerability_lookup', 'vulnerability_recheck', 'web_scan', 'windows_git_auth', 'zap',
    ]);
    for (const feature of Object.values(data)) {
      for (const value of Object.values(feature)) expect(['boolean', 'number']).toContain(typeof value);
    }
    expect(data.local_scan).toEqual({ enabled: false, roots: 0 });
    expect(data.web_scan.enabled).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain('portal.example.local');
  });
});
