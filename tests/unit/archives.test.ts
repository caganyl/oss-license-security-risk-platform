/**
 * REQ-004 · Archive readers and the archive thread (AC-P15-4…10; ADR-006
 * Karar 7, D-67). All archives are generated in-test (helpers/archiveBuilder);
 * gzip bombs are built at run time and never committed.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ARCHIVE_THREAD_RESOURCE_LIMITS, runArchiveInThread, type ArchiveThreadOptions } from '../../src/enrichment/archive/archiveThread';
import { detectFormat, extractArchive } from '../../src/enrichment/archive/extract';
import { type ArchiveLimits, normalizeArchivePath } from '../../src/enrichment/archive/licenseFiles';
import { collectArchive, type ArchiveStageContext, type RunArchiveThreadFn } from '../../src/enrichment/archiveStage';
import { DownloadQuota } from '../../src/enrichment/budget';
import type { RegistrySession } from '../../src/enrichment/registryClient';
import { buildTar, buildZip, gnuLongName, paxEntry, sha512b64, tgz, type TarEntry } from '../helpers/archiveBuilder';

vi.setConfig({ testTimeout: 60_000 });

const LIMITS: ArchiveLimits = {
  maxDecompressedBytes: 1024 * 1024,
  maxEntries: 20,
  maxFileBytes: 4096,
  maxPackageTextBytes: 8192,
  maxFiles: 3,
  maxLongNameBytes: 1024,
};
const npm = (bytes: Buffer, limits = LIMITS) => extractArchive({ kind: 'npm', filename: null, bytes, limits });
const pypi = (filename: string, bytes: Buffer, limits = LIMITS) => extractArchive({ kind: 'pypi', filename, bytes, limits });
const paths = (r: { licenseFiles: Array<{ path: string }> }) => r.licenseFiles.map((f) => f.path);
const LIC = 'MIT License\nCopyright (c) 2021 Acme\n';

describe('AC-P15-5: tar reader', () => {
  it('AC-P15-5: ustar file with prefix field, PAX path and GNU long name are all resolved', async () => {
    const r = await npm(tgz([
      { name: 'package/package.json', data: '{}' },
      { name: 'LICENSE', prefix: 'package', data: LIC },
      paxEntry({ path: 'package/NOTICE' }),
      { name: 'ignored-short-name', data: 'notice text' },
      gnuLongName('package/COPYING'),
      { name: 'trunc', data: 'copying text' },
    ]));
    expect(r.outcome).toBe('collected');
    expect(paths(r)).toEqual(['package/COPYING', 'package/LICENSE', 'package/NOTICE']);
    expect(r.copyrightLines).toEqual(['Copyright (c) 2021 Acme']);
  });

  it('AC-P15-5: PAX size overrides the header size', async () => {
    const r = await npm(tgz([
      { name: 'package/a.js', data: 'x' },
      paxEntry({ size: '3' }),
      { name: 'package/LICENSE', data: 'abc', sizeField: 999 },
    ]));
    expect(r.licenseFiles).toEqual([{ path: 'package/LICENSE', text: 'abc' }]);
  });

  it('AC-P15-5: a bad header checksum -> unsupported_format (header)', async () => {
    const r = await npm(tgz([{ name: 'package/LICENSE', data: LIC, badChecksum: true }]));
    expect(r).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'header', licenseFiles: [] });
  });

  it('AC-P15-5: truncated inside an entry -> unsupported_format (truncated)', async () => {
    const tar = buildTar([{ name: 'package/LICENSE', data: 'x'.repeat(2000) }], { end: false });
    const r = await npm(zlib.gzipSync(tar.subarray(0, 1024)));
    expect(r).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'truncated' });
  });

  it('AC-P15-5: more entries than the limit (meta headers included) -> limit_exceeded (entries)', async () => {
    const entries: TarEntry[] = Array.from({ length: LIMITS.maxEntries + 1 }, (_, i) => ({ name: `package/f${i}.js`, data: '1' }));
    expect(await npm(tgz(entries))).toMatchObject({ outcome: 'limit_exceeded', outcomeDetail: 'entries' });
  });

  it('AC-P15-5: GNU base-256 size, malformed PAX and an oversized long name are refused', async () => {
    const raw = Buffer.alloc(12, 0);
    raw[0] = 0x80;
    expect(await npm(tgz([{ name: 'package/LICENSE', data: '', rawSize: raw }]))).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'base256' });
    expect(await npm(tgz([{ name: 'PaxHeader', type: 'x', data: '99 path=x\n' }, { name: 'package/LICENSE', data: 'a' }]))).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'pax' });
    expect(await npm(tgz([gnuLongName(`package/${'L'.repeat(2000)}`), { name: 'x', data: 'a' }]))).toMatchObject({ outcome: 'limit_exceeded', outcomeDetail: 'long_name' });
  });

  it('AC-P15-5: gzip bomb (generated at test time) -> limit_exceeded (decompressed), without inflating it all', async () => {
    const header = buildTar([{ name: 'package/blob.bin', data: '' }], { end: false }).subarray(0, 512);
    const bomb = Buffer.concat([buildTar([{ name: 'package/LICENSE', data: LIC }], { end: false }), header, Buffer.alloc(16 * 1024 * 1024, 0x41)]);
    // Patch the size of the blob header to 16 MiB (checksum recomputed by rebuilding the header).
    const real = buildTar([{ name: 'package/blob.bin', data: '', sizeField: 16 * 1024 * 1024 }], { end: false }).subarray(0, 512);
    real.copy(bomb, bomb.length - 16 * 1024 * 1024 - 512);
    const gz = zlib.gzipSync(bomb, { level: 9 });
    expect(gz.length).toBeLessThan(100 * 1024);
    const t = performance.now();
    expect(await npm(gz)).toMatchObject({ outcome: 'limit_exceeded', outcomeDetail: 'decompressed' });
    expect(performance.now() - t).toBeLessThan(5000);
  });

  it('AC-P15-5: corrupt gzip -> unsupported_format (gzip)', async () => {
    const gz = tgz([{ name: 'package/LICENSE', data: LIC }]);
    gz[gz.length - 5] ^= 0xff;
    gz[20] ^= 0xff;
    expect((await npm(gz)).outcome).toBe('unsupported_format');
  });
});

describe('AC-P15-6 / D-67: license file selection', () => {
  it('AC-P15-6: npm/sdist — only <top folder>/<name>, case-insensitive prefixes; deeper, other top folders, symlinks, traversal ignored', async () => {
    const r = await npm(tgz([
      { name: 'package/package.json', data: '{}' },
      { name: 'package/licence.md', data: 'licence' },
      { name: 'package/sub/LICENSE', data: 'deep' },
      { name: 'other/LICENSE', data: 'other top' },
      { name: 'package/LICENSE-link', type: '2', data: '' },
      { name: '../LICENSE', data: 'traversal' },
      { name: '/abs/LICENSE', data: 'abs' },
      { name: 'package/README.md', data: 'readme' },
    ]), { ...LIMITS, maxFiles: 10 });
    expect(paths(r)).toEqual(['package/licence.md']);
  });

  it('AC-P15-6: at most maxFiles in code point order (uppercase before lowercase), streamed', async () => {
    const r = await npm(tgz([
      { name: 'package/x.js', data: '' },
      { name: 'package/notice', data: 'n' },
      { name: 'package/LICENSE', data: 'l' },
      { name: 'package/COPYRIGHT', data: 'c' },
      { name: 'package/NOTICE', data: 'N' },
      { name: 'package/COPYING', data: 'C' },
    ]));
    expect(paths(r)).toEqual(['package/COPYING', 'package/COPYRIGHT', 'package/LICENSE']);
  });

  it('AC-P15-7: a file over 1 MiB-equivalent is omitted file_too_large; past the package text cap package_text_limit', async () => {
    const r = await npm(tgz([
      { name: 'package/a', data: '' },
      { name: 'package/COPYING', data: 'x'.repeat(LIMITS.maxFileBytes + 1) },
      { name: 'package/LICENSE', data: 'y'.repeat(4000) },
      { name: 'package/NOTICE', data: 'z'.repeat(4000) },
    ]), { ...LIMITS, maxPackageTextBytes: 6000 });
    expect(r.licenseFiles).toEqual([
      { path: 'package/COPYING', omitted: 'file_too_large' },
      { path: 'package/LICENSE', text: 'y'.repeat(4000) },
      { path: 'package/NOTICE', omitted: 'package_text_limit' },
    ]);
  });

  it('AC-P15-6: wheel — <x>.dist-info/<name> and <x>.dist-info/licenses/**; not top-level or package folders', async () => {
    const r = await pypi('p-1.0-py3-none-any.whl', buildZip([
      { name: 'p/__init__.py', data: '' },
      { name: 'p/LICENSE', data: 'pkg' },
      { name: 'LICENSE', data: 'top' },
      { name: 'p-1.0.dist-info/LICENSE.txt', data: LIC },
      { name: 'p-1.0.dist-info/licenses/vendor/NOTICE', data: 'vendored' },
      { name: 'p-1.0.dist-info/sub/COPYING', data: 'no' },
      { name: '.dist-info/LICENSE', data: 'no' },
    ]), { ...LIMITS, maxFiles: 10 });
    expect(paths(r)).toEqual(['p-1.0.dist-info/LICENSE.txt', 'p-1.0.dist-info/licenses/vendor/NOTICE']);
    expect(r.copyrightLines).toEqual(['Copyright (c) 2021 Acme']);
  });

  it('AC-P15-8: invalid UTF-8 in a license file becomes U+FFFD; a NUL (binary) file is dropped', async () => {
    const r = await npm(tgz([
      { name: 'package/LICENSE', data: Buffer.from([0x41, 0xff, 0x42]) },
      { name: 'package/NOTICE', data: Buffer.from([0x41, 0x00, 0x42]) },
    ]));
    expect(r.licenseFiles).toEqual([{ path: 'package/LICENSE', text: 'A\uFFFDB' }]);
  });

  it('AC-P15-6: no matching file -> no_license_file', async () => {
    expect(await npm(tgz([{ name: 'package/index.js', data: '' }]))).toMatchObject({ outcome: 'no_license_file', licenseFiles: [] });
  });

  it('AC-P15-6: path normalization rejects absolute, drive, .., empty components and NUL', () => {
    expect(normalizeArchivePath('./package\\LICENSE')).toBe('package/LICENSE');
    for (const bad of ['/etc/LICENSE', 'C:/LICENSE', 'a/../LICENSE', 'a//LICENSE', 'a/\u0000', '']) expect(normalizeArchivePath(bad), bad).toBeNull();
  });
});

describe('AC-P15-5: zip reader and format detection', () => {
  const wheel = (entries: Parameters<typeof buildZip>[0], options?: Parameters<typeof buildZip>[1]) => pypi('p-1-py3-none-any.whl', buildZip(entries, options));

  it('AC-P15-5: stored and deflate entries are read; CRC mismatch skips the entry', async () => {
    const r = await wheel([
      { name: 'p.dist-info/LICENSE', data: 'stored', method: 0 },
      { name: 'p.dist-info/NOTICE', data: 'deflated '.repeat(50), method: 8 },
      { name: 'p.dist-info/COPYING', data: 'bad crc', badCrc: true },
    ]);
    expect(r.licenseFiles).toEqual([
      { path: 'p.dist-info/LICENSE', text: 'stored' },
      { path: 'p.dist-info/NOTICE', text: 'deflated '.repeat(50) },
    ]);
  });

  it('AC-P15-5: encrypted entries and unsupported methods are rejected (unsupported_format when nothing else is left)', async () => {
    expect(await wheel([{ name: 'p.dist-info/LICENSE', data: 'secret', method: 0, flags: 0x0001 }])).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'encrypted' });
    expect(await wheel([{ name: 'p.dist-info/LICENSE', data: 'bz', method: 12 }])).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'method' });
    const mixed = await wheel([{ name: 'p.dist-info/LICENSE', data: 'ok', method: 0 }, { name: 'p.dist-info/NOTICE', data: 's', method: 0, flags: 0x0040 }]);
    expect(mixed).toMatchObject({ outcome: 'collected', licenseFiles: [{ path: 'p.dist-info/LICENSE', text: 'ok' }] });
  });

  it('AC-P15-5: ZIP64 (EOCD marker, locator or 0x0001 extra field) -> unsupported_format (zip64)', async () => {
    const e = [{ name: 'p.dist-info/LICENSE', data: 'x', method: 0 }];
    expect(await wheel(e, { zip64Eocd: true })).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'zip64' });
    expect(await wheel(e, { zip64Locator: true })).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'zip64' });
    const extra = Buffer.alloc(12);
    extra.writeUInt16LE(0x0001, 0);
    extra.writeUInt16LE(8, 2);
    expect(await wheel([{ ...e[0], extra }])).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'zip64' });
  });

  it('AC-P15-5: more central directory entries than the limit -> limit_exceeded (entries)', async () => {
    const entries = Array.from({ length: LIMITS.maxEntries + 1 }, (_, i) => ({ name: `p/f${i}.py`, data: '', method: 0 }));
    expect(await wheel(entries)).toMatchObject({ outcome: 'limit_exceeded', outcomeDetail: 'entries' });
  });

  it('AC-P15-5: file extension and magic bytes must agree', async () => {
    const zip = buildZip([{ name: 'p-1/LICENSE', data: LIC }]);
    const gz = tgz([{ name: 'p-1/LICENSE', data: LIC }]);
    expect((await pypi('p-1.zip', zip)).outcome).toBe('collected');
    expect((await pypi('p-1.tar.gz', gz)).outcome).toBe('collected');
    for (const [name, bytes] of [['p.whl', gz], ['p.zip', gz], ['p.tar.gz', zip], ['p.egg', zip], ['p.tar.bz2', gz]] as const) {
      expect(await pypi(name, bytes), name).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'format' });
    }
    expect(await npm(zip)).toMatchObject({ outcome: 'unsupported_format', outcomeDetail: 'format' });
    expect(detectFormat('pypi', 'P-1.WHL', zip)).toEqual({ format: 'zip', wheel: true });
  });
});

describe('AC-P15-4 / AC-P15-10: real archive thread', () => {
  let dir = '';
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-arch-'));
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
  const script = (name: string, body: string) => {
    const file = path.join(dir, `${name}.js`);
    fs.writeFileSync(file, body);
    return file;
  };
  const opts = (extra: Partial<ArchiveThreadOptions> = {}): ArchiveThreadOptions => ({ limits: LIMITS, threadTimeoutMs: 30_000, maxThreads: 2, resourceLimits: ARCHIVE_THREAD_RESOURCE_LIMITS, ...extra });
  const input = () => ({ kind: 'npm' as const, filename: null, bytes: tgz([{ name: 'package/LICENSE', data: LIC }]) });

  it('AC-P15-4: the default (source-mode) thread extracts license files and copyright lines', async () => {
    const r = await runArchiveInThread(input(), new AbortController().signal, opts());
    expect(r).toEqual({ kind: 'ok', result: { outcome: 'collected', outcomeDetail: null, licenseFiles: [{ path: 'package/LICENSE', text: LIC }], copyrightLines: ['Copyright (c) 2021 Acme'] } });
  });

  it('AC-P15-10: timeout, crash, exit, OOM and a bad reply are failed (processing_failed) classes', async () => {
    const hang = script('hang', `require('node:worker_threads').parentPort.on('message', () => {}); setInterval(() => {}, 1000);`);
    expect(await runArchiveInThread(input(), new AbortController().signal, opts({ threadScript: hang, threadTimeoutMs: 300 }))).toEqual({ kind: 'failed', code: 'TIMEOUT' });
    const crash = script('crash', `require('node:worker_threads').parentPort.on('message', () => { throw new Error('boom'); });`);
    expect(await runArchiveInThread(input(), new AbortController().signal, opts({ threadScript: crash }))).toEqual({ kind: 'failed', code: 'CRASH' });
    const exit = script('exit', `require('node:worker_threads').parentPort.on('message', () => process.exit(3));`);
    expect(await runArchiveInThread(input(), new AbortController().signal, opts({ threadScript: exit }))).toEqual({ kind: 'failed', code: 'EXIT' });
    const oom = script('oom', `require('node:worker_threads').parentPort.on('message', () => { const a = []; for (;;) a.push(new Array(1e5).fill({ x: Math.random() })); });`);
    expect(await runArchiveInThread(input(), new AbortController().signal, opts({ threadScript: oom, resourceLimits: { maxOldGenerationSizeMb: 16, maxYoungGenerationSizeMb: 4, stackSizeMb: 4 } }))).toEqual({ kind: 'failed', code: 'OOM' });
    const bad = script('bad', `const p = require('node:worker_threads').parentPort; p.on('message', () => p.postMessage({ ok: true, result: { outcome: 'collected', outcomeDetail: 'Free text!', licenseFiles: [], copyrightLines: [] } }));`);
    expect(await runArchiveInThread(input(), new AbortController().signal, opts({ threadScript: bad }))).toEqual({ kind: 'failed', code: 'BAD_RESULT' });
  });

  it('AC-P15-4: an abort terminates the thread and reports aborted', async () => {
    const hang = script('hang2', `require('node:worker_threads').parentPort.on('message', () => {}); setInterval(() => {}, 1000);`);
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const t = performance.now();
    expect(await runArchiveInThread(input(), ac.signal, opts({ threadScript: hang }))).toEqual({ kind: 'aborted' });
    expect(performance.now() - t).toBeLessThan(10_000);
  });

  it('AC-P15-10: a thread failure is processing_failed and is NOT written to the archive cache; success is written once', async () => {
    const bytes = tgz([{ name: 'package/LICENSE', data: LIC }]);
    const session = {
      endpoints: { npm: 'http://127.0.0.1:1', pypi: 'http://127.0.0.1:1', files: 'http://127.0.0.1:1' },
      isHostClosed: () => false,
      getJson: async () => ({ kind: 'not_found' }),
      getArchive: async () => ({ kind: 'ok', body: bytes, digest: sha512b64(bytes), size: bytes.length }),
    } as unknown as RegistrySession;
    const task = { ecosystem: 'npm' as const, requestName: 'a', version: '1.0.0', candidates: [{ url: 'http://127.0.0.1:1/a/-/a-1.0.0.tgz', algorithm: 'sha512' as const, digests: [sha512b64(bytes)], size: null, filename: 'a-1.0.0.tgz' }] };
    const run = async (runThread: RunArchiveThreadFn) => {
      const query = vi.fn(async () => ({ rows: [{ id: '00000000-0000-0000-0000-000000000001' }], rowCount: 1 }));
      const ctx: ArchiveStageContext = { session, db: { query } as unknown as ArchiveStageContext['db'], signal: new AbortController().signal, cached: new Map(), quota: new DownloadQuota(1e9), threadOptions: opts(), runThread, warn: () => undefined };
      return { result: await collectArchive(task, ctx), writes: query.mock.calls.length };
    };
    for (const code of ['OOM', 'CRASH', 'TIMEOUT', 'EXIT', 'BAD_RESULT']) {
      expect(await run(async () => ({ kind: 'failed', code }))).toEqual({ result: { noticeStatus: 'processing_failed', archiveId: null }, writes: 0 });
    }
    const ok = await run(runArchiveInThread);
    expect(ok.result.noticeStatus).toBe('collected');
    expect(ok.writes).toBe(1);
  });

  it('AC-P15-2: integrity mismatch -> integrity_failed, the thread is never started, nothing cached', async () => {
    const bytes = tgz([{ name: 'package/LICENSE', data: LIC }]);
    const session = { endpoints: {}, isHostClosed: () => false, getArchive: async () => ({ kind: 'ok', body: bytes, digest: sha512b64(bytes), size: bytes.length }) } as unknown as RegistrySession;
    const runThread = vi.fn<RunArchiveThreadFn>();
    const query = vi.fn();
    const r = await collectArchive(
      { ecosystem: 'npm', requestName: 'a', version: '1.0.0', candidates: [{ url: 'http://127.0.0.1:1/a.tgz', algorithm: 'sha512', digests: [sha512b64(Buffer.from('other'))], size: null, filename: null }] },
      { session, db: { query } as unknown as ArchiveStageContext['db'], signal: new AbortController().signal, cached: new Map(), quota: new DownloadQuota(1e9), threadOptions: opts(), runThread, warn: () => undefined },
    );
    expect(r).toEqual({ noticeStatus: 'integrity_failed', archiveId: null });
    expect(runThread).not.toHaveBeenCalled();
    expect(query).not.toHaveBeenCalled();
  });
});
