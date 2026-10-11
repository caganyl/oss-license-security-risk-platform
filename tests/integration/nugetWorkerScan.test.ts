/**
 * REQ-006 · P-20 end to end through the scan worker (AC-P20-11, AC-P20-17, AC-G-8).
 *
 * The sample solution (tests/fixtures/dotnet/sample-solution) is copied to a
 * temp scan root and scanned by `ScanWorker.runOnce` with the default
 * lock-aware parser thread. Enrichment and vulnerability lookup are off
 * (`enricher: null`, `vulnerabilityLookup: null`): no request may leave the
 * process (fetch spy; the network guard blocks non-loopback anyway). Real
 * embedded PostgreSQL, fresh migrated DB per test.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanWorker } from '../../src/scanner/worker';
import { useTestDatabase } from '../helpers/db';
import { SAMPLE_SOLUTION, parseDotnet } from '../helpers/nugetGolden';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'test' });

let tmpRoot = '';
let root = '';
const logs: string[] = [];
const push = (...a: unknown[]) => void logs.push(a.map(String).join(' '));
const logger = { log: push, warn: push, error: push };

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-nuget-e2e-'));
  root = path.join(tmpRoot, 'repo');
  fs.cpSync(SAMPLE_SOLUTION, root, { recursive: true });
  logs.length = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

async function insertProject(stack: string[]): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id`, [`nuget-${stack.join('-') || 'empty'}`, root]);
  for (const e of stack) await db.query(`INSERT INTO project_tech_stacks (project_id, ecosystem) VALUES ($1, $2)`, [p.id, e]);
  return p.id;
}

async function scan(projectId: string): Promise<string> {
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, queued_at) VALUES ($1, 'manual', 'pending', 'main', NOW()) RETURNING id`,
    [projectId],
  );
  const w = new ScanWorker({ db: db.pool, tmpRoot, logger, scanRoots: [root], runId: 'run-nuget', enricher: null, vulnerabilityLookup: null });
  expect(await w.runOnce()).toBe(s.id);
  return s.id;
}

type Row = [string, string, string | null, string, string, string, string, string | null];

async function rows(scanId: string): Promise<Row[]> {
  const r = await db.query<{ ecosystem: string; name: string; version: string | null; purl: string; scope: string; manifest_file: string; manifest_path: string; declared_range: string | null }>(
    `SELECT p.ecosystem::text, p.name, p.version, p.purl, sd.scope::text, sd.manifest_file, sd.manifest_path, sd.declared_range
       FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1`,
    [scanId],
  );
  return r.map((x) => [x.ecosystem, x.name, x.version, x.purl, x.scope, x.manifest_file, x.manifest_path, x.declared_range] as Row).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

describe('AC-P20-11 (end to end): dotnet stack scan of the sample solution', () => {
  it('AC-P20-11: scan_dependencies hold every dotnet package with purl, scope, version and declared_range; no network request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const projectId = await insertProject(['dotnet']);
    const scanId = await scan(projectId);

    const [s] = await db.query<{ status: string; error_message: string | null }>(`SELECT status::text, error_message FROM scans WHERE id = $1`, [scanId]);
    expect(s.status, logs.join('\n')).toBe('completed');

    const expected = parseDotnet(root, 'x')
      .dependencies.map((d) => [d.ecosystem, d.name, d.version, d.purl, d.scope, d.manifest_file, d.manifest_path, d.declared_range] as Row)
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const actual = await rows(scanId);
    expect(actual).toHaveLength(18);
    expect(actual).toEqual(expected);
    expect(actual.filter((r) => r[4] === 'transitive').map((r) => `${r[6]}|${r[3]}`)).toEqual(
      expect.arrayContaining(['src/App|pkg:nuget/Serilog@3.1.1', 'src/App|pkg:nuget/Microsoft.Extensions.Logging.Abstractions@8.0.0', 'src/Lib|pkg:nuget/Serilog@3.1.1']),
    );
    expect(actual.find((r) => r[1] === 'Humanizer')).toEqual(['dotnet', 'Humanizer', null, 'pkg:nuget/Humanizer', 'direct', 'Tools.csproj', 'src/Tools', '$(LibVersion)']);

    const files = await db.query<{ file_path: string; ecosystem: string }>(`SELECT file_path, ecosystem::text FROM scan_files WHERE scan_id = $1 ORDER BY file_path`, [scanId]);
    expect(files.map((f) => f.file_path)).toEqual([
      'Directory.Packages.props',
      'legacy/LegacyApp/packages.config',
      'src/App/packages.lock.json',
      'src/Lib/obj/project.assets.json',
      'src/Tools/Tools.csproj',
    ]);
    expect(new Set(files.map((f) => f.ecosystem))).toEqual(new Set(['dotnet']));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('AC-P20-17: a project whose stack is only nodejs does not scan .NET files', async () => {
    const scanId = await scan(await insertProject(['nodejs']));
    expect(await rows(scanId)).toEqual([]);
  });
});
