/**
 * REQ-005 contract 1.1.0 post-review fixes in the lookup engine and the safe
 * HTTP client, against the loopback fake OSV/NVD server (no real network):
 *   P-1  vector-only OSV record -> local score, no NVD request (section 3.5.3)
 *   M-1  per-package / total id limits and the detail request limit (section 3.5.1)
 *   L-1  invalid querybatch `modified` -> details refetched (section 3.5.2)
 *   L-4  circuit breaker counts every attempt, 429/5xx responses included
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AppClock } from '../../src/lib/clock';
import { createVulnerabilityClient, type VulnerabilityClient } from '../../src/vulnerability/client';
import { createVulnerabilityLookup, normalizeResolved, type LookupDependency } from '../../src/vulnerability/lookup';
import { NORMALIZED_RECORD_VERSION, type CachedNvd, type CachedOsvRecord, type VulnCache } from '../../src/vulnerability/vulnCache';
import type { OsvVulnerability } from '../../src/vulnerability/normalize';
import { VULNERABILITY_LIMITS, type VulnerabilityConfig } from '../../src/scanner/sandbox/runner.config';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';

let osv: FakeOsv;
const clients: VulnerabilityClient[] = [];
let sleeps: number[] = [];
const clock: AppClock = {
  now: () => Date.parse('2026-10-10T08:00:00Z'),
  sleep: async (ms) => {
    sleeps.push(ms);
  },
};
let warnings: string[] = [];

beforeEach(async () => {
  osv = await startFakeOsv();
  sleeps = [];
  warnings = [];
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  await osv.close();
});

const CONFIG: VulnerabilityConfig = { lookupEnabled: true, recheckEnabled: true, intervalHours: 24, timeoutMs: 3_000, concurrency: 16, nvdEnabled: true };

function vulnClient(): VulnerabilityClient {
  const c = createVulnerabilityClient({ config: CONFIG, endpoints: { osv: osv.origin, nvd: osv.origin }, env: {}, clock, warn: (m) => warnings.push(m) });
  clients.push(c);
  return c;
}

function memoryCache() {
  const osvRows = new Map<string, CachedOsvRecord>();
  const cache: VulnCache = {
    async readOsv(ids) {
      return new Map(ids.filter((id) => osvRows.has(id)).map((id) => [id, osvRows.get(id) as CachedOsvRecord]));
    },
    async writeOsv(record) {
      osvRows.set(record.id, { record, modifiedMs: record.modified ? Date.parse(record.modified) : null, withdrawn: false, recordVersion: NORMALIZED_RECORD_VERSION });
    },
    async readNvd() {
      return new Map<string, CachedNvd>();
    },
    async writeNvd() {},
  };
  const seed = (id: string, modified: string | null = '2026-01-01T00:00:00.000Z') => {
    const record: OsvVulnerability = { id, summary: `${id} cached`, ...(modified ? { modified } : {}) };
    osvRows.set(id, { record, modifiedMs: modified ? Date.parse(modified) : null, withdrawn: false, recordVersion: NORMALIZED_RECORD_VERSION });
  };
  return { cache, osvRows, seed };
}

function engine(cache: VulnCache = memoryCache().cache) {
  return createVulnerabilityLookup({ client: vulnClient(), db: { query: async () => ({ rows: [] }) }, clock, logger: { warn: (m: string) => warnings.push(m) }, cache });
}

const npm = (name: string): LookupDependency => ({ ecosystem: 'nodejs', name, version: '1.0.0' });
const keyOf = (name: string) => `npm\u0000${name}\u0000${'1.0.0'}`;
const signal = () => new AbortController().signal;
const ids = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => `${prefix}-${String(i).padStart(5, '0')}`);

describe('P-1: vector-only OSV record', () => {
  it('P-1 / AC-P17-9: a CVE alias with a CVSS_V3 vector and no numeric score -> local score, no NVD request, advisory_data.cvss.source = osv_vector', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-p1p1-p1p1-p1p1' }]);
    osv.addRecord('GHSA-p1p1-p1p1-p1p1', { aliases: ['CVE-2026-11111'], severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N' }] });
    const result = await engine().lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(0);
    const resolved = result.byKey.get(keyOf('a')) ?? [];
    expect(resolved).toHaveLength(1);
    const v = normalizeResolved(resolved[0], { ecosystem: 'nodejs', name: 'a' });
    expect(v).toMatchObject({ cveId: 'CVE-2026-11111', cvssScore: 5.4, cvssVersion: '3.1', severity: 'medium' });
    expect((v.advisoryData as { cvss?: { source?: string } }).cvss?.source).toBe('osv_vector');
    expect(result.counts.nvdUnavailable).toBe(0);
  });

  it('P-1 control: an invalid vector and no score -> NVD is asked (source nvd)', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-p1p1-p1p1-p1p2' }]);
    osv.addRecord('GHSA-p1p1-p1p1-p1p2', { aliases: ['CVE-2026-11112'], severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L' }] });
    await engine().lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(1);
  });
});

describe('M-1 / contract 1.1.0 section 3.5.1: OSV id and detail limits', () => {
  it('M-1: 201 distinct ids for one package -> package unchecked, osv:id_limit, none of its ids requested; 200 -> checked', async () => {
    expect(VULNERABILITY_LIMITS.osvMaxIdsPerPackage).toBe(200);
    const { cache, seed } = memoryCache();
    const over = ids('OSV-2026-A', 201);
    const at = ids('OSV-2026-B', 200);
    for (const id of at) seed(id);
    osv.vulns.set(osvKey('npm', 'over', '1.0.0'), over.map((id) => ({ id })));
    osv.vulns.set(osvKey('npm', 'at', '1.0.0'), at.map((id) => ({ id })));
    const result = await engine(cache).lookup([npm('over'), npm('at')], { signal: signal() });
    expect(result.keyStates.get(keyOf('over'))).toBe('unchecked');
    expect(result.keyStates.get(keyOf('at'))).toBe('checked');
    expect(result.failures.has('id_limit')).toBe(true);
    expect(result.byKey.get(keyOf('over')) ?? []).toHaveLength(0);
    expect(result.byKey.get(keyOf('at'))).toHaveLength(200);
    expect(osv.detailCount()).toBe(0); // 200 cached ids, the 201 dropped ones never requested
    expect(result.counts.unchecked).toBe(1);
  });

  it('M-1: the per-package limit counts distinct ids over all pages (101 + 100 -> unchecked)', async () => {
    const all = ids('OSV-2026-P', 201);
    osv.pages.set(osvKey('npm', 'paged', '1.0.0'), [all.slice(0, 101).map((id) => ({ id })), all.slice(101).map((id) => ({ id }))]);
    const result = await engine().lookup([npm('paged')], { signal: signal() });
    expect(osv.count('/v1/querybatch')).toBe(2);
    expect(result.keyStates.get(keyOf('paged'))).toBe('unchecked');
    expect(result.failures.has('id_limit')).toBe(true);
    expect(osv.detailCount()).toBe(0);
  });

  it('M-1: 5001 distinct ids in one lookup -> the package that crosses the limit is unchecked with osv:total_id_limit', async () => {
    expect(VULNERABILITY_LIMITS.osvMaxDistinctIds).toBe(5_000);
    const { cache, seed } = memoryCache();
    const deps: LookupDependency[] = [];
    // 25 packages x 200 ids = 5000 distinct ids, the 26th adds one more.
    for (let p = 0; p < 26; p++) {
      const name = `pkg-${String(p).padStart(2, '0')}`;
      const list = p < 25 ? ids(`OSV-2026-T${String(p).padStart(2, '0')}`, 200) : ['OSV-2026-EXTRA-1'];
      for (const id of list) seed(id);
      osv.vulns.set(osvKey('npm', name, '1.0.0'), list.map((id) => ({ id })));
      deps.push(npm(name));
    }
    // A package sharing only known ids stays checked after the limit was reached.
    osv.vulns.set(osvKey('npm', 'pkg-shared', '1.0.0'), [{ id: 'OSV-2026-T00-00000' }]);
    deps.push(npm('pkg-shared'));
    const result = await engine(cache).lookup(deps, { signal: signal() });
    expect(result.failures.has('total_id_limit')).toBe(true);
    expect(result.keyStates.get(keyOf('pkg-25'))).toBe('unchecked');
    expect(result.keyStates.get(keyOf('pkg-24'))).toBe('checked');
    expect(result.keyStates.get(keyOf('pkg-shared'))).toBe('checked');
    expect(result.counts.unchecked).toBe(1);
    expect(osv.detailCount()).toBe(0);
  });

  it('M-1: 2001 network detail requests needed -> 2000 sent, osv:detail_limit, the rest counted as detail missing (D)', async () => {
    expect(VULNERABILITY_LIMITS.osvMaxDetailRequests).toBe(2_000);
    // 11 packages x 182 ids = 2002 ids, none cached.
    const all: string[] = [];
    const deps: LookupDependency[] = [];
    for (let p = 0; p < 11; p++) {
      const name = `d-${String(p).padStart(2, '0')}`;
      const list = ids(`OSV-2026-D${String(p).padStart(2, '0')}`, 182);
      for (const id of list) osv.records.set(id, { id, summary: id, modified: '2026-01-01T00:00:00Z' });
      osv.vulns.set(osvKey('npm', name, '1.0.0'), list.map((id) => ({ id })));
      all.push(...list);
      deps.push(npm(name));
    }
    expect(all).toHaveLength(2002);
    const result = await engine().lookup(deps, { signal: signal() });
    expect(osv.detailCount()).toBe(2000);
    expect(result.failures.has('detail_limit')).toBe(true);
    expect(result.counts.detailMissing).toBe(2);
    expect(result.detailMissingIds.size).toBe(2);
    expect(result.counts.unchecked).toBe(0);
  }, 120_000);
});

describe('L-1: invalid querybatch modified', () => {
  it('L-1: an invalid querybatch modified -> cached record refetched, package stays checked; a valid older modified uses the cache', async () => {
    const { cache, seed } = memoryCache();
    seed('GHSA-l1l1-l1l1-l1l1', '2026-05-01T00:00:00.000Z');
    seed('GHSA-l1l1-l1l1-l1l2', '2026-05-01T00:00:00.000Z');
    osv.addRecord('GHSA-l1l1-l1l1-l1l1');
    osv.addRecord('GHSA-l1l1-l1l1-l1l2');
    osv.vulns.set(osvKey('npm', 'bad', '1.0.0'), [{ id: 'GHSA-l1l1-l1l1-l1l1', modified: '2026-02-30T00:00:00Z' }]);
    osv.vulns.set(osvKey('npm', 'good', '1.0.0'), [{ id: 'GHSA-l1l1-l1l1-l1l2', modified: '2026-04-01T00:00:00Z' }]);
    const result = await engine(cache).lookup([npm('bad'), npm('good')], { signal: signal() });
    expect(osv.count('/v1/vulns/GHSA-l1l1-l1l1-l1l1')).toBe(1);
    expect(osv.count('/v1/vulns/GHSA-l1l1-l1l1-l1l2')).toBe(0);
    expect(result.keyStates.get(keyOf('bad'))).toBe('checked');
    expect(result.keyStates.get(keyOf('good'))).toBe('checked');
    expect(result.status).toBe('complete');
  });
});

describe('L-4: circuit breaker counts every attempt', () => {
  const url = () => `${osv.origin}/v1/vulns/GHSA-l4l4-l4l4-l4l4`;

  it('L-4: persistent 503 -> 5 attempts open the circuit (request 2 stops retrying, request 3 refused without a connection)', async () => {
    osv.override('/v1/vulns/GHSA-l4l4-l4l4-l4l4', { status: 503, body: {} });
    const session = vulnClient().session()!;
    const results = [];
    for (let i = 0; i < 3; i++) results.push(await session.request('osv-vuln', url(), { signal: signal() }));
    expect(osv.count('/v1/vulns/GHSA-l4l4-l4l4-l4l4')).toBe(5);
    expect(results[0]).toMatchObject({ kind: 'error', code: 'HTTP_503' });
    expect(results[1]).toMatchObject({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
    expect(results[2]).toMatchObject({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
    expect(session.isHostClosed(new URL(osv.origin).host)).toBe(true);
  });

  it('L-4: 429 with a long Retry-After counts one failed attempt per request (5 requests close the host)', async () => {
    osv.override('/v1/vulns/GHSA-l4l4-l4l4-l4l4', { status: 429, headers: { 'retry-after': '120' }, body: {} });
    const session = vulnClient().session()!;
    for (let i = 0; i < 6; i++) await session.request('osv-vuln', url(), { signal: signal() });
    expect(osv.count('/v1/vulns/GHSA-l4l4-l4l4-l4l4')).toBe(5);
    expect(session.isHostClosed(new URL(osv.origin).host)).toBe(true);
  });

  it('L-4 / F3 behaviour: any other HTTP response (404) resets the counter; 404s alone never close the host', async () => {
    osv.override('/v1/vulns/GHSA-l4l4-l4l4-l4l4', [{ status: 503, body: {} }, { status: 503, body: {} }, { status: 503, body: {} }, { status: 404, body: {} }, { status: 503, body: {} }, { status: 503, body: {} }, { status: 503, body: {} }, { status: 404, body: {} }]);
    const session = vulnClient().session()!;
    for (let i = 0; i < 4; i++) await session.request('osv-vuln', url(), { signal: signal() });
    expect(osv.count('/v1/vulns/GHSA-l4l4-l4l4-l4l4')).toBe(8);
    expect(session.isHostClosed(new URL(osv.origin).host)).toBe(false);
    osv.override('/v1/vulns/GHSA-l4l4-l4l4-l4l4', { status: 404, body: {} });
    for (let i = 0; i < 8; i++) await session.request('osv-vuln', url(), { signal: signal() });
    expect(session.isHostClosed(new URL(osv.origin).host)).toBe(false);
    expect(sleeps).toEqual([1000, 2000, 1000, 2000]);
  });
});
