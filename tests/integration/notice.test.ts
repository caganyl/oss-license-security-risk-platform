/**
 * REQ-004 · P-15 NOTICE: `GET /api/scans/{scanId}/notice` contract tests and
 * the NOTICE.txt format (AC-P15-11…14; contract
 * `docs/contracts/REQ-004-notice-and-outputs.md` sections 2, 3, 4.3, 9, 10).
 *
 * Real embedded PostgreSQL (one migrated database for the file); rows are
 * seeded with SQL (helpers/f3Seed) so every status of contract 4.3 can be set.
 * The golden file `tests/fixtures/notice/golden-f3.txt` is hand-written from
 * the contract (not captured from the implementation) and compared byte for
 * byte; `tests/fixtures/.gitattributes` keeps it `-text`.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import type { Express } from 'express';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ARCHIVE_EXTRACTOR_VERSION } from '../../src/enrichment/cache';
import { NOTICE_SIZE_LIMIT_LINE, NoticeService, PRE_F3_NOTE } from '../../src/notice/noticeService';
import { useTestDatabase } from '../helpers/db';
import { f3Dep, insertArchive, seedScan } from '../helpers/f3Seed';
import { createApiKey, expectErrorBody, makeApp, req, setupPassword } from '../helpers/http';
import { repoPath } from '../helpers/paths';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 240_000 });

const db = useTestDatabase({ scope: 'file' });

const E = '='.repeat(80);
// Format characters built from code points (never literal in the source).
const RLO = String.fromCharCode(0x202e);
const ZWSP = String.fromCharCode(0x200b);
const F = '-'.repeat(80);
const GOLDEN_ID = '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f';
const GOLDEN_PATH = repoPath('tests', 'fixtures', 'notice', 'golden-f3.txt');

let app: Express;
let cookie = '';
let apiKey = '';

async function seedGolden(): Promise<void> {
  await seedScan(db, {
    projectName: 'golden-app',
    scanId: GOLDEN_ID,
    deps: [
      f3Dep({ ecosystem: 'java', name: 'org.foo:bar', version: '1.0.0', purl: 'pkg:maven/org.foo/bar@1.0.0', licenseSource: 'none', enrichmentStatus: 'disabled' }),
      f3Dep({ ecosystem: 'nodejs', name: 'Alpha', version: '1.0.0', purl: 'pkg:npm/Alpha@1.0.0', licenseSource: 'none', enrichmentStatus: 'no_license', licenseLockHint: 'MIT', noticeStatus: 'no_candidate' }),
      f3Dep({
        ecosystem: 'nodejs', name: 'alpha', version: '1.0.0', purl: 'pkg:npm/alpha@1.0.0', licenseExpression: 'MIT', noticeStatus: 'collected',
        archive: {
          ecosystem: 'npm', name: 'alpha', version: '1.0.0', outcome: 'collected',
          licenseFiles: [
            { path: 'package/LICENSE', text: `Alpha License\r\n${E}\r\nPackage: forged\n${F} trailing\n  indented line\nbell\u0007here\n\n\n` },
            { path: 'package/LICENSE.big', omitted: 'file_too_large' },
          ],
          copyrightLines: ['Copyright (c) 2024 Alpha Authors', 'Copyright (c) 2025 Second Author'],
        },
      }),
      f3Dep({ ecosystem: 'nodejs', name: 'cleared', version: '1.0.0', purl: 'pkg:npm/cleared@1.0.0', licenseExpression: 'ISC', noticeStatus: 'collected' }),
      f3Dep({
        ecosystem: 'nodejs', name: 'ms', version: '2.1.3', purl: 'pkg:npm/ms@2.1.3', licenseExpression: 'MIT', noticeStatus: 'collected', extraScopes: ['transitive', 'dev'],
        archive: {
          ecosystem: 'npm', name: 'ms', version: '2.1.3', outcome: 'collected',
          licenseFiles: [{ path: 'package/license.md', text: 'The MIT License (MIT)\n\nCopyright (c) 2020 Vercel, Inc.\n' }],
          copyrightLines: ['Copyright (c) 2020 Vercel, Inc.'],
        },
      }),
      f3Dep({ ecosystem: 'nodejs', name: 'nover', version: null, purl: 'pkg:npm/nover', licenseSource: 'none', enrichmentStatus: 'version_unknown', licenseLockHint: 'MIT' }),
      f3Dep({ ecosystem: 'nodejs', name: 'nover', version: '1.0.0', purl: 'pkg:npm/nover@1.0.0', licenseExpression: 'BSD-3-Clause', licenseSource: 'lockfile (unverified)', enrichmentStatus: 'disabled' }),
      f3Dep({ ecosystem: 'nodejs', name: 'offline', version: '3.0.0', purl: 'pkg:npm/offline@3.0.0', licenseSource: 'none', enrichmentStatus: 'unreachable' }),
      f3Dep({
        ecosystem: 'nodejs', name: 'omitall', version: '1.0.0', purl: 'pkg:npm/omitall@1.0.0', licenseExpression: 'MIT', noticeStatus: 'collected',
        archive: {
          ecosystem: 'npm', name: 'omitall', version: '1.0.0', outcome: 'collected',
          licenseFiles: [{ path: 'package/COPYING', omitted: 'mystery' }, { path: 'package/LICENSE', omitted: 'package_text_limit' }],
        },
      }),
      f3Dep({ ecosystem: 'nodejs', name: 'Zeta', version: '1.0.0', purl: 'pkg:npm/Zeta@1.0.0', scope: 'transitive', extraScopes: ['dev'], licenseExpression: 'MIT OR Apache-2.0', licenseSource: 'lockfile (unverified)', enrichmentStatus: 'not_found' }),
      f3Dep({ ecosystem: 'nodejs', name: 'devonly', version: '1.0.0', purl: 'pkg:npm/devonly@1.0.0', scope: 'dev', licenseExpression: 'MIT', noticeStatus: 'not_runtime' }),
      f3Dep({
        ecosystem: 'python', name: 'bigpkg', version: '2.0', purl: 'pkg:pypi/bigpkg@2.0', licenseExpression: 'GPL-3.0-only', licenseSource: 'registry:pypi', noticeStatus: 'limit_exceeded',
        archive: { ecosystem: 'pypi', name: 'bigpkg', version: '2.0', outcome: 'limit_exceeded' },
      }),
      f3Dep({
        ecosystem: 'python', name: 'six', version: '1.16.0', purl: 'pkg:pypi/six@1.16.0', licenseExpression: 'MIT', licenseSource: 'registry:pypi', noticeStatus: 'no_license_file',
        archive: { ecosystem: 'pypi', name: 'six', version: '1.16.0', outcome: 'no_license_file' },
      }),
    ],
  });
  await db.query(
    `INSERT INTO registry_package_cache (ecosystem, name, version, outcome, declared_license, license_text, extractor_version)
     VALUES ('pypi', 'six', '1.16.0', 'found', 'MIT', $1, 1)`,
    [`MIT License\n${E}\nPermission is hereby granted.\n`],
  );
}

beforeAll(async () => {
  await seedGolden();
  app = await makeApp(db.pool);
  cookie = await setupPassword(app);
  apiKey = (await createApiKey(app, cookie)).key;
}, 240_000);

const notice = (id: string, opts: Parameters<typeof req>[3] = { cookie: '' }) => req(app, 'get', `/api/scans/${id}/notice`, opts).buffer(true).parse((res, cb) => {
  const chunks: Buffer[] = [];
  res.on('data', (c: Buffer) => chunks.push(Buffer.from(c)));
  res.on('end', () => cb(null, Buffer.concat(chunks)));
});

const golden = () => fs.readFileSync(GOLDEN_PATH);
/** Golden with every text block replaced by the size-limit line (blocks: alpha file, ms file, six metadata). */
function goldenText(): string {
  return golden().toString('utf8');
}

// ---------------------------------------------------------------------------
describe('AC-P15-11: GET /api/scans/{scanId}/notice — contract test (section 2)', () => {
  it('AC-P15-11: 200 with session cookie; headers exactly as contract 2.3; X-Checksum-SHA256 = body digest', async () => {
    const res = await notice(GOLDEN_ID, { cookie });
    expect(res.status).toBe(200);
    const body = res.body as Buffer;
    expect(res.headers['content-type']).toBe('text/plain; charset=utf-8');
    expect(res.headers['content-disposition']).toBe(`attachment; filename="NOTICE-${GOLDEN_ID}.txt"`);
    expect(res.headers['content-length']).toBe(String(body.length));
    expect(res.headers['x-checksum-sha256']).toBe(crypto.createHash('sha256').update(body).digest('hex'));
    expect(res.headers['x-checksum-sha256']).toMatch(/^[0-9a-f]{64}$/);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('AC-P15-11: API key (Bearer) works; upper-case scanId still gives the lower-case canonical filename and Scan ID', async () => {
    const res = await notice(GOLDEN_ID.toUpperCase(), { bearer: apiKey });
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toBe(`attachment; filename="NOTICE-${GOLDEN_ID}.txt"`);
    expect((res.body as Buffer).toString('utf8')).toContain(`\nScan ID: ${GOLDEN_ID}\n`);
  });

  it('AC-P15-11: 400 invalid_request for a malformed UUID; error bodies never carry Content-Disposition', async () => {
    for (const bad of ['not-a-uuid', '3f2b8c1e-5d4a-0b6f-9c2d-1a2b3c4d5e6f', `${GOLDEN_ID}x`]) {
      const res = await req(app, 'get', `/api/scans/${bad}/notice`, { cookie });
      expectErrorBody(res, 400, 'invalid_request');
      expect(res.body.message).toBe('scanId must be a valid UUID');
      expect(res.headers['content-disposition']).toBeUndefined();
    }
  });

  it('AC-P15-11: 401 unauthenticated without credentials (also for an invalid scanId: guard runs first)', async () => {
    for (const id of [GOLDEN_ID, 'bad']) {
      const res = await req(app, 'get', `/api/scans/${id}/notice`);
      expectErrorBody(res, 401, 'unauthenticated');
      expect(res.headers['content-disposition']).toBeUndefined();
    }
    expectErrorBody(await req(app, 'get', `/api/scans/${GOLDEN_ID}/notice`, { bearer: 'ossr_0000000000000000_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }), 401, 'unauthenticated');
  });

  it('AC-P15-11: 404 not_found for a missing scan and for running / failed / pending scans (same body)', async () => {
    const missing = await req(app, 'get', '/api/scans/00000000-0000-4000-8000-000000000000/notice', { cookie });
    expectErrorBody(missing, 404, 'not_found');
    expect(missing.body.message).toBe('Scan not found or not yet completed');
    for (const status of ['running', 'failed', 'pending']) {
      const { scanId } = await seedScan(db, { projectName: `st-${status}`, status, deps: [] });
      const res = await req(app, 'get', `/api/scans/${scanId}/notice`, { cookie });
      expectErrorBody(res, 404, 'not_found');
      expect(res.body).toEqual(missing.body);
      expect(res.headers['content-disposition']).toBeUndefined();
    }
  });

  it('AC-P15-11: read only — no network request, no sbom_documents / reports / audit_logs row', async () => {
    const count = async () => (await db.query<{ n: string }>(
      `SELECT (SELECT count(*) FROM sbom_documents) + (SELECT count(*) FROM reports) + (SELECT count(*) FROM audit_logs) AS n`,
    ))[0].n;
    const before = await count();
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    try {
      expect((await notice(GOLDEN_ID, { cookie })).status).toBe(200);
    } finally {
      vi.unstubAllGlobals();
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(await count()).toBe(before);
  });

  it('AC-P15-11: 403 forbidden without reports:read (user without roles); RBAC body', async () => {
    const roles = await db.query<{ user_id: string; role_id: string }>('SELECT user_id, role_id FROM user_roles');
    await db.query('DELETE FROM user_roles');
    try {
      const res = await req(app, 'get', `/api/scans/${GOLDEN_ID}/notice`, { cookie });
      expectErrorBody(res, 403, 'forbidden');
      expect(res.body.message).toBe('Permission "reports:read" is required');
      expect(res.headers['content-disposition']).toBeUndefined();
    } finally {
      for (const r of roles) await db.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [r.user_id, r.role_id]);
    }
  });
});

// ---------------------------------------------------------------------------
describe('AC-P15-12…14: NOTICE.txt format (contract section 3)', () => {
  it('AC-P15-14: golden NOTICE (tests/fixtures/notice/golden-f3.txt) byte for byte; two requests give the same bytes and checksum', async () => {
    const a = await notice(GOLDEN_ID, { cookie });
    const b = await notice(GOLDEN_ID, { bearer: apiKey });
    const body = a.body as Buffer;
    expect(body.toString('utf8')).toBe(goldenText()); // readable diff first
    expect(body.equals(golden())).toBe(true);
    expect((b.body as Buffer).equals(body)).toBe(true);
    expect(b.headers['x-checksum-sha256']).toBe(a.headers['x-checksum-sha256']);
  });

  it('AC-P15-14: UTF-8 without BOM, LF only (no CR), trailing LF; the golden file itself is LF-only', async () => {
    const body = (await notice(GOLDEN_ID, { cookie })).body as Buffer;
    expect(body.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(false);
    expect(body.includes(0x0d)).toBe(false);
    expect(body[body.length - 1]).toBe(0x0a);
    expect(golden().includes(0x0d)).toBe(false);
    const attrs = fs.readFileSync(repoPath('tests', 'fixtures', '.gitattributes'), 'utf8');
    expect(attrs).toMatch(/^\* -text$/m);
  });

  it('AC-P15-12: one entry per unique runtime key; dev+runtime once, dev-only absent, versionless runtime listed', async () => {
    const text = (await notice(GOLDEN_ID, { cookie })).body.toString('utf8') as string;
    const lines = text.split('\n');
    const entries = lines.filter((l) => l === E).length;
    const [{ n }] = await db.query<{ n: string }>(
      `SELECT count(DISTINCT (p.ecosystem, p.name, COALESCE(p.version, ''))) AS n
         FROM scan_dependencies sd JOIN packages p ON p.id = sd.package_id WHERE sd.scan_id = $1 AND sd.scope <> 'dev'`,
      [GOLDEN_ID],
    );
    expect(entries).toBe(Number(n));
    expect(entries).toBe(12);
    expect(lines.filter((l) => l === 'Package: ms')).toHaveLength(1);
    expect(lines.filter((l) => l === 'Package: Zeta')).toHaveLength(1);
    expect(text).not.toContain('Package: devonly');
    expect(text).toContain('Package: nover\nVersion: (unknown)\n');
  });

  it('AC-P15-14: ordering (label, lower-case name, name, version) by UTF-8 bytes, not localeCompare', async () => {
    const { scanId } = await seedScan(db, {
      projectName: 'order-app',
      deps: [
        f3Dep({ ecosystem: 'nodejs', name: 'zed', version: '1.0.0', purl: 'pkg:npm/zed@1.0.0' }),
        f3Dep({ ecosystem: 'nodejs', name: 'émile', version: '1.0.0', purl: 'pkg:npm/%C3%A9mile@1.0.0' }),
        f3Dep({ ecosystem: 'nodejs', name: 'Beta', version: '2.0.0', purl: 'pkg:npm/Beta@2.0.0' }),
        f3Dep({ ecosystem: 'nodejs', name: 'beta', version: '10.0.0', purl: 'pkg:npm/beta@10.0.0' }),
        f3Dep({ ecosystem: 'nodejs', name: 'beta', version: '9.0.0', purl: 'pkg:npm/beta@9.0.0' }),
        f3Dep({ ecosystem: 'python', name: 'aaa', version: '1', purl: 'pkg:pypi/aaa@1', licenseSource: 'registry:pypi' }),
      ],
    });
    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    const order = text.split('\n').filter((l) => l.startsWith('Package: ') || l.startsWith('Version: '));
    expect(order).toEqual([
      'Package: Beta', 'Version: 2.0.0',
      'Package: beta', 'Version: 10.0.0',
      'Package: beta', 'Version: 9.0.0',
      'Package: zed', 'Version: 1.0.0',
      'Package: émile', 'Version: 1.0.0',
      'Package: aaa', 'Version: 1',
    ]);
  });

  it('AC-P15-13 / contract 3.7: size limit (injected maxBytes = 0) replaces every text block, keeps all structure lines and header counts', async () => {
    const body = (await new NoticeService(db.pool, { maxBytes: 0 }).generate(GOLDEN_ID)).body.toString('utf8');
    const expected = goldenText()
      .replace(/(File: package\/LICENSE\n-{80}\n)[\s\S]*?\nbellhere\n/, `$1${NOTICE_SIZE_LIMIT_LINE}\n`)
      .replace(/(File: package\/license\.md\n-{80}\n)[\s\S]*?Vercel, Inc\.\n/, `$1${NOTICE_SIZE_LIMIT_LINE}\n`)
      .replace(/(License text from package metadata\n-{80}\n)[\s\S]*$/, `$1${NOTICE_SIZE_LIMIT_LINE}\n`);
    expect(body).toBe(expected);
    expect(body.split('\n').filter((l) => l === NOTICE_SIZE_LIMIT_LINE)).toHaveLength(3);
    expect(body).toContain('Packages with license files: 2\n');
  });

  it('AC-P15-13 / C-7: after the first overflow every later block is omitted, even a smaller one that would fit', async () => {
    const g = goldenText();
    const afterAlpha = Buffer.byteLength(g.slice(0, g.indexOf('bellhere\n') + 'bellhere\n'.length), 'utf8');
    // Limit one byte below the end of the alpha block: alpha does not fit; ms and six would, but stay omitted.
    const cut = (await new NoticeService(db.pool, { maxBytes: afterAlpha - 1 }).generate(GOLDEN_ID)).body.toString('utf8');
    expect(cut.split('\n').filter((l) => l === NOTICE_SIZE_LIMIT_LINE)).toHaveLength(3);
    expect(cut).not.toContain('The MIT License (MIT)');
    // Exactly at the limit the alpha block is still written (written + block <= limit).
    const exact = (await new NoticeService(db.pool, { maxBytes: afterAlpha }).generate(GOLDEN_ID)).body.toString('utf8');
    expect(exact).toContain('\nbellhere\n');
    expect(exact.split('\n').filter((l) => l === NOTICE_SIZE_LIMIT_LINE)).toHaveLength(2);
  });

  it('AC-P15-14 / contract 2.5: pre-F3 scan — note line, NOASSERTION / not recorded, archive cache lookup or the rescan reason', async () => {
    await insertArchive(db, {
      ecosystem: 'npm', name: 'cached-old', version: '1.2.3', outcome: 'collected', extractorVersion: ARCHIVE_EXTRACTOR_VERSION,
      licenseFiles: [{ path: 'package/LICENSE', text: 'Old cached license\n' }], copyrightLines: ['Copyright 2001 Old'],
    });
    const { scanId } = await seedScan(db, {
      projectName: 'pre-f3-app',
      deps: [
        { ecosystem: 'nodejs', name: 'cached-old', version: '1.2.3', purl: 'pkg:npm/cached-old@1.2.3' },
        { ecosystem: 'nodejs', name: 'uncached-old', version: '4.5.6', purl: 'pkg:npm/uncached-old@4.5.6' },
      ],
    });
    const text = (await notice(scanId, { cookie })).body.toString('utf8') as string;
    expect(text).toContain(`Generated automatically; not legal advice. Review before distribution.\n${PRE_F3_NOTE}\n\n${E}\n`);
    expect(PRE_F3_NOTE).toBe('Note: This scan predates license enrichment. License data is incomplete; rescan the project for a complete NOTICE.');
    expect(text).toContain([
      'Package: cached-old', 'Version: 1.2.3', 'Ecosystem: npm', 'PURL: pkg:npm/cached-old@1.2.3', 'License: NOASSERTION',
      'License source: not recorded', 'Copyright: Copyright 2001 Old', 'License files: 1', F, 'File: package/LICENSE', F, 'Old cached license', '',
    ].join('\n'));
    expect(text).toContain('Package: uncached-old\nVersion: 4.5.6\nEcosystem: npm\nPURL: pkg:npm/uncached-old@4.5.6\nLicense: NOASSERTION\nLicense source: not recorded\nCopyright: (none found)\nLicense files: 0\nReason: scan predates license enrichment; rescan required\n');
    expect(text).toContain('Packages with license files: 1\nPackages without license files: 1\n');
  });

  it('AC-P15-14 / contract 2.5: completed scan without dependencies -> header only, Packages: 0, no pre-F3 note', async () => {
    const { scanId } = await seedScan(db, { projectName: 'empty-app', completedAt: null, deps: [] });
    const text = (await new NoticeService(db.pool).generate(scanId)).body.toString('utf8');
    expect(text).toBe([
      'THIRD-PARTY SOFTWARE NOTICES', 'NOTICE format: 1', 'Project: empty-app', `Scan ID: ${scanId}`, 'Scan completed at: n/a',
      'Packages: 0', 'Packages with license files: 0', 'Packages without license files: 0',
      'Generated automatically; not legal advice. Review before distribution.', '',
    ].join('\n'));
  });

  it('contract 9 / 3.6: untrusted control/format characters are stripped; single-line fields cannot forge entries or headers', async () => {
    const { scanId } = await seedScan(db, {
      projectName: `evil${RLO}app\u001b[2J\u0007\nScan ID: forged`,
      deps: [
        f3Dep({
          ecosystem: 'nodejs', name: `x\n${E}\nPackage: forged`, version: `1.0.0${ZWSP}`, purl: 'pkg:npm/x-forge@1.0.0', licenseExpression: 'MIT\u0001', noticeStatus: 'collected',
          archive: {
            ecosystem: 'npm', name: 'x-forge', version: '1.0.0', outcome: 'collected',
            licenseFiles: [{ path: `package/LICENSE\n${F}`, text: `ok${RLO}\u001b]0;title\u0007 line\n${F}\n${E}x\n` }],
            copyrightLines: ['Copyright\u0085 (c) \u001b[31mEvil\u001b[0m\nPackage: forged2'],
          },
        }),
      ],
    });
    const body = (await new NoticeService(db.pool).generate(scanId)).body;
    const text = body.toString('utf8');
    for (const ch of [RLO, '\u001b', '\u0007', '\u0001', ZWSP, String.fromCharCode(0x85)]) expect(text.includes(ch), JSON.stringify(ch)).toBe(false);
    const lines = text.split('\n');
    expect(lines.filter((l) => l === E)).toHaveLength(1);
    expect(lines.filter((l) => l.startsWith('Scan ID: '))).toHaveLength(1);
    expect(lines.filter((l) => l.startsWith('Package: '))).toEqual([`Package: x ${E} Package: forged`]);
    expect(lines.filter((l) => l.startsWith('Copyright: '))).toHaveLength(1);
    // Exactly-FILE_SEP lines: block boundaries only (file header pair), the text lines are shielded.
    expect(lines.filter((l) => l === F)).toHaveLength(2);
    expect(text).toContain(`\n ${F}\n ${E}x\n`);
  });
});
