/**
 * REQ-003 follow-up items, static checks:
 * - AC-T-5 (D-24 / D-49): `package.json` `overrides.uuid = "11.1.1"`, exceljs
 *   stays 4.4.0, every `uuid` in package-lock.json is 11.1.1 and exceljs
 *   resolves that copy at run time. `npm audit --omit=dev` needs the network
 *   (AC-G-4) and is not run here; its result belongs in the handoff.
 * - AC-T-6 (L-2 / D-50, document only): `db/README.md` password recovery
 *   section — stop the application first, complete setup right after, and
 *   the optional API key revocation line present only as a SQL comment.
 */
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../helpers/paths';

const readJson = <T>(rel: string): T => JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8')) as T;

interface PackageJson {
  dependencies?: Record<string, string>;
  overrides?: Record<string, unknown>;
}
interface LockEntry {
  version?: string;
  dependencies?: Record<string, string>;
  dev?: boolean;
}
interface PackageLock {
  lockfileVersion: number;
  packages: Record<string, LockEntry>;
}

describe('AC-T-5 / D-49: uuid override for exceljs', () => {
  const pkg = readJson<PackageJson>('package.json');
  const lock = readJson<PackageLock>('package-lock.json');

  it('AC-T-5: package.json overrides.uuid === "11.1.1"; exceljs stays a direct dependency', () => {
    expect(pkg.overrides?.uuid).toBe('11.1.1');
    expect(pkg.dependencies?.exceljs).toMatch(/^\^?4\.4\.0$/);
    expect(pkg.dependencies?.uuid, 'uuid is not added as a new direct dependency').toBeUndefined();
  });

  it('AC-T-5: lock — exceljs 4.4.0 requires uuid; every uuid entry (hoisted or nested under exceljs) is 11.1.1', () => {
    expect(lock.lockfileVersion).toBeGreaterThanOrEqual(2);
    const exceljs = lock.packages['node_modules/exceljs'];
    expect(exceljs?.version).toBe('4.4.0');
    expect(exceljs?.dependencies?.uuid).toBeDefined();
    const uuidEntries = Object.entries(lock.packages).filter(([key]) => /(^|\/)node_modules\/uuid$/.test(key));
    expect(uuidEntries.length).toBeGreaterThan(0);
    for (const [key, entry] of uuidEntries) expect(entry.version, key).toBe('11.1.1');
    expect(lock.packages['node_modules/exceljs/node_modules/uuid']?.version ?? '11.1.1').toBe('11.1.1');
  });

  it('AC-T-5: at run time exceljs resolves uuid 11.1.1 and its v4 still works', () => {
    const fromExceljs = createRequire(path.join(REPO_ROOT, 'node_modules', 'exceljs', 'package.json'));
    expect((fromExceljs('uuid/package.json') as { version: string }).version).toBe('11.1.1');
    const { v4 } = fromExceljs('uuid') as { v4: () => string };
    expect(v4()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe('AC-T-6 / L-2 / D-50: db/README.md password recovery section', () => {
  const readme = fs.readFileSync(path.join(REPO_ROOT, 'db', 'README.md'), 'utf8');
  const start = readme.search(/^## Parola kurtarma/m);
  const rest = start === -1 ? '' : readme.slice(start);
  const next = rest.slice(3).search(/^## /m);
  const section = next === -1 ? rest : rest.slice(0, next + 3);

  it('AC-T-6: the section exists and is listed in the table of contents', () => {
    expect(start, 'heading "## Parola kurtarma"').toBeGreaterThan(-1);
    expect(readme).toMatch(/\]\(#parola-kurtarma[^)]*\)/);
  });

  it('AC-T-6: recovery is done while the application is stopped, before the SQL', () => {
    const stop = section.search(/uygulamayı durdurun/i);
    const sql = section.indexOf('```sql');
    expect(stop).toBeGreaterThan(-1);
    expect(sql).toBeGreaterThan(stop);
  });

  it('AC-T-6: setup is completed as soon as the application starts again (the first visitor could set the password)', () => {
    expect(section).toMatch(/açılır açılmaz[^]*setup[^]*hemen|setup[^]*hemen/i);
  });

  it('AC-T-6: the API key revocation line is present only as a SQL comment', () => {
    const sqlBlock = /```sql\r?\n([^]*?)```/.exec(section)?.[1] ?? '';
    expect(sqlBlock).not.toBe('');
    const lines = sqlBlock.split(/\r?\n/);
    const revoke = 'UPDATE api_keys SET revoked_at = NOW() WHERE revoked_at IS NULL;';
    expect(lines.some((l) => /^\s*--\s*/.test(l) && l.replace(/^\s*--\s*/, '').trim() === revoke), 'commented revoke line').toBe(true);
    const active = lines.filter((l) => !/^\s*--/.test(l)).join('\n');
    expect(active).not.toMatch(/api_keys/i);
    expect(active).toMatch(/BEGIN;[^]*COMMIT;/);
  });
});
