/**
 * REQ-005 P-17 · Vulnerability lookup engine and its safe HTTP client against
 * the loopback fake OSV/NVD server (AC-P17-1…14; ADR-007 Karar 1–6, 11;
 * contract REQ-005 §3.3). The OSV/NVD caches are an in-memory `VulnCache`
 * (the pg cache is covered by the scan integration tests); no real network.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AppClock } from '../../src/lib/clock';
import { shouldUseProxy } from '../../src/lib/http/proxy';
import { createVulnerabilityClient, type VulnerabilityClient, type VulnerabilityClientOptions } from '../../src/vulnerability/client';
import {
  PRODUCTION_VULNERABILITY_ENDPOINTS,
  assertInjectableVulnerabilityEndpoint,
  nvdCveUrl,
  osvVulnUrl,
  warnRemovedVulnerabilitySettings,
} from '../../src/vulnerability/endpoints';
import {
  computeVulnerabilityBudgetMs,
  createVulnerabilityLookup,
  normalizeResolved,
  type LookupDependency,
  type VulnerabilityLookup,
} from '../../src/vulnerability/lookup';
import { createSlidingWindowLimiter } from '../../src/vulnerability/rateLimiter';
import { vulnerabilityDataStatusOf, vulnerabilitySummaryLines } from '../../src/vulnerability/summaryLines';
import { NORMALIZED_RECORD_VERSION, type CachedNvd, type CachedOsvRecord, type VulnCache } from '../../src/vulnerability/vulnCache';
import type { OsvVulnerability } from '../../src/vulnerability/normalize';
import type { VulnerabilityConfig } from '../../src/scanner/sandbox/runner.config';
import { type FakeOsv, PASSTHROUGH, nvdBody, osvKey, startFakeOsv } from '../helpers/fakeOsv';

let osv: FakeOsv;
const clients: VulnerabilityClient[] = [];
let sleeps: number[] = [];
let nowMs = Date.parse('2026-10-10T08:00:00Z');
const clock: AppClock = {
  now: () => nowMs,
  sleep: async (ms) => {
    sleeps.push(ms);
  },
};
let warnings: string[] = [];

beforeEach(async () => {
  osv = await startFakeOsv();
  sleeps = [];
  warnings = [];
  nowMs = Date.parse('2026-10-10T08:00:00Z');
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  await osv.close();
});

const CONFIG: VulnerabilityConfig = { lookupEnabled: true, recheckEnabled: true, intervalHours: 24, timeoutMs: 3_000, concurrency: 4, nvdEnabled: true };

function vulnClient(opts: Partial<VulnerabilityClientOptions> = {}, config: Partial<VulnerabilityConfig> = {}): VulnerabilityClient {
  const c = createVulnerabilityClient({
    config: { ...CONFIG, ...config },
    endpoints: { osv: osv.origin, nvd: osv.origin },
    env: {},
    clock,
    warn: (m) => warnings.push(m),
    ...opts,
  });
  clients.push(c);
  return c;
}

/** In-memory cache with call logs (TTL semantics of `vulnCache.ts`). */
function memoryCache() {
  const osvRows = new Map<string, CachedOsvRecord>();
  const nvdRows = new Map<string, { value: CachedNvd; expiresAt: number }>();
  const nvdWrites: Array<{ cve: string; outcome: string; ttlMs: number }> = [];
  const cache: VulnCache = {
    async readOsv(ids) {
      return new Map(ids.filter((id) => osvRows.has(id)).map((id) => [id, osvRows.get(id) as CachedOsvRecord]));
    },
    async writeOsv(record) {
      const ms = record.modified ? Date.parse(record.modified) : null;
      osvRows.set(record.id, { record, modifiedMs: ms, withdrawn: Boolean(record.withdrawn), recordVersion: NORMALIZED_RECORD_VERSION });
    },
    async readNvd(cves, now) {
      const out = new Map<string, CachedNvd>();
      for (const cve of cves) {
        const row = nvdRows.get(cve);
        if (row && row.expiresAt > now) out.set(cve, row.value);
      }
      return out;
    },
    async writeNvd(cve, value, now, ttlMs) {
      nvdWrites.push({ cve, outcome: value.outcome, ttlMs });
      nvdRows.set(cve, { value, expiresAt: now + ttlMs });
    },
  };
  return { cache, osvRows, nvdRows, nvdWrites };
}

function lookupEngine(c: VulnerabilityClient, cache: VulnCache = memoryCache().cache): VulnerabilityLookup {
  return createVulnerabilityLookup({ client: c, db: { query: async () => ({ rows: [] }) }, clock, logger: { warn: (m: string) => warnings.push(m) }, cache });
}

const npm = (name: string, version: string | null = '1.0.0'): LookupDependency => ({ ecosystem: 'nodejs', name, version });
const py = (name: string, version = '1.0.0'): LookupDependency => ({ ecosystem: 'python', name, version });
const many = (n: number) => Array.from({ length: n }, (_, i) => npm(`pkg-${String(i).padStart(4, '0')}`));
const signal = () => new AbortController().signal;
const keyOf = (name: string, version = '1.0.0') => `npm\u0000${name}\u0000${version}`;

describe('AC-P17-1 / AC-P17-2: querybatch submission', () => {
  it('AC-P17-2 (1): 200 packages -> exactly one POST /v1/querybatch with 200 queries, zero /v1/query', async () => {
    const result = await lookupEngine(vulnClient()).lookup(many(200), { signal: signal() });
    expect(osv.count('/v1/querybatch', 'POST')).toBe(1);
    expect(osv.batches()[0]).toHaveLength(200);
    expect(osv.count('/v1/query')).toBe(0);
    expect(result.status).toBe('complete');
    expect(result.summaryLines).toEqual([]);
    expect(result.counts).toMatchObject({ candidates: 200, unchecked: 0 });
  });

  it('AC-P17-2 (2): 1000 packages -> 1 batch; 1001 -> 2 batches (1000 + 1), sent sequentially', async () => {
    await lookupEngine(vulnClient()).lookup(many(1000), { signal: signal() });
    expect(osv.batches().map((b) => b.length)).toEqual([1000]);
    osv.resetCounts();
    await lookupEngine(vulnClient()).lookup(many(1001), { signal: signal() });
    expect(osv.batches().map((b) => b.length)).toEqual([1000, 1]);
  });

  it('AC-P17-2 (3): the same package and version in two manifests is one query; inexact versions and invalid names are no candidates', async () => {
    const deps = [npm('a'), npm('a'), npm('b', '^1.0.0'), npm('c', null), npm('d', '*'), npm('Bad Name!'), { ecosystem: 'go', name: 'x', version: '1.0.0' } as unknown as LookupDependency];
    const result = await lookupEngine(vulnClient()).lookup(deps, { signal: signal() });
    expect(osv.batches()).toEqual([[{ package: { ecosystem: 'npm', name: 'a' }, version: '1.0.0' }]]);
    expect(result.counts.candidates).toBe(1);
  });

  it('AC-P17-1 / D-109: scoped npm name is raw @scope/name in the body (no %2F); PyPI is PEP 503; order is (ecosystem, name, version)', async () => {
    await lookupEngine(vulnClient()).lookup([py('Zope_Interface.Ext', '5.0'), npm('zeta'), npm('@scope/pkg', '2.0.0'), npm('alpha')], { signal: signal() });
    const raw = JSON.stringify(osv.requests[0].body);
    expect(raw).not.toContain('%2F');
    expect(osv.batches()[0]).toEqual([
      { package: { ecosystem: 'PyPI', name: 'zope-interface-ext' }, version: '5.0' },
      { package: { ecosystem: 'npm', name: '@scope/pkg' }, version: '2.0.0' },
      { package: { ecosystem: 'npm', name: 'alpha' }, version: '1.0.0' },
      { package: { ecosystem: 'npm', name: 'zeta' }, version: '1.0.0' },
    ]);
    expect(osv.requests[0].headers['content-type']).toBe('application/json');
  });

  it('AC-P17-1: the same input produces the same request body', async () => {
    const deps = [npm('b'), npm('a'), py('x')];
    await lookupEngine(vulnClient()).lookup(deps, { signal: signal() });
    await lookupEngine(vulnClient()).lookup([...deps].reverse(), { signal: signal() });
    expect(JSON.stringify(osv.requests[0].body)).toBe(JSON.stringify(osv.requests[1].body));
  });
});

describe('AC-P17-3: pagination', () => {
  it('AC-P17-3: a two-page result resends only that query with page_token; ids of both pages are kept', async () => {
    osv.pages.set(osvKey('npm', 'paged', '1.0.0'), [[{ id: 'GHSA-aaaa-aaaa-aaaa', modified: '2026-01-01T00:00:00Z' }], [{ id: 'GHSA-bbbb-bbbb-bbbb', modified: '2026-01-01T00:00:00Z' }]]);
    osv.addRecord('GHSA-aaaa-aaaa-aaaa');
    osv.addRecord('GHSA-bbbb-bbbb-bbbb');
    const result = await lookupEngine(vulnClient()).lookup([npm('other'), npm('paged')], { signal: signal() });
    const batches = osv.batches();
    expect(batches).toHaveLength(2);
    expect(batches[0]).toHaveLength(2);
    expect(batches[1]).toEqual([{ package: { ecosystem: 'npm', name: 'paged' }, version: '1.0.0', page_token: 'p1' }]);
    expect(result.byKey.get(keyOf('paged'))?.map((v) => v.id).sort()).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb']);
    expect(result.status).toBe('complete');
  });

  it('AC-P17-3: more than 10 pages -> package unchecked (page_limit), at most 10 batch requests carry it', async () => {
    osv.pages.set(osvKey('npm', 'endless', '1.0.0'), Array.from({ length: 12 }, (_, i) => [{ id: `OSV-2026-${i}` }]));
    const result = await lookupEngine(vulnClient()).lookup([npm('endless'), npm('fine')], { signal: signal() });
    expect(osv.count('/v1/querybatch')).toBe(10);
    expect(result.keyStates.get(keyOf('endless'))).toBe('unchecked');
    expect(result.keyStates.get(keyOf('fine'))).toBe('checked');
    expect(result.failures.has('page_limit')).toBe(true);
    expect(result.status).toBe('partial');
  });
});

describe('AC-P17-4: response validation', () => {
  it.each([
    ['missing results', { foo: 1 }],
    ['too few results', { results: [{}] }],
    ['too many results', { results: [{}, {}, {}] }],
    ['results not objects', { results: [1, 2] }],
  ])('AC-P17-4: %s -> every package of the batch unchecked, status unavailable', async (_l, body) => {
    osv.override('/v1/querybatch', { body });
    const result = await lookupEngine(vulnClient()).lookup([npm('a'), npm('b')], { signal: signal() });
    expect([...result.keyStates.values()]).toEqual(['unchecked', 'unchecked']);
    expect(result.status).toBe('unavailable');
    expect(result.failures.has('invalid_response')).toBe(true);
    expect(result.summaryLines).toEqual(['[osv] Vulnerability data unavailable: 2 of 2 package(s) could not be checked; 0 vulnerability record(s) missing details.']);
  });

  it('AC-P17-4: non-JSON body is an error for that request', async () => {
    osv.override('/v1/querybatch', { body: 'not json', headers: { 'content-type': 'text/plain' } });
    const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(result.status).toBe('unavailable');
  });

  it("AC-P17-4: '../x' id and a numeric `vulns` -> package unchecked, no detail request", async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: '../x' }]);
    osv.override('/v1/querybatch', (req) => {
      void req;
      return { body: { results: [{ vulns: [{ id: '../x' }] }, { vulns: 7 }] } };
    });
    const result = await lookupEngine(vulnClient()).lookup([npm('a'), npm('b')], { signal: signal() });
    expect(osv.detailCount()).toBe(0);
    expect(result.keyStates.get(keyOf('a'))).toBe('unchecked');
    expect(result.keyStates.get(keyOf('b'))).toBe('unchecked');
    expect(result.byKey.size).toBe(0);
  });

  it('AC-P17-4 r2: one invalid and one valid id in the same package -> the valid id still yields a vulnerability, package unchecked (partial)', async () => {
    osv.vulns.set(osvKey('npm', 'mixed', '1.0.0'), [{ id: 'bad/id' }, { id: 'GHSA-cccc-cccc-cccc', modified: '2026-01-01T00:00:00Z' }]);
    osv.addRecord('GHSA-cccc-cccc-cccc');
    const result = await lookupEngine(vulnClient()).lookup([npm('mixed'), npm('clean')], { signal: signal() });
    expect(result.keyStates.get(keyOf('mixed'))).toBe('unchecked');
    expect(result.byKey.get(keyOf('mixed'))?.map((v) => v.id)).toEqual(['GHSA-cccc-cccc-cccc']);
    expect(osv.detailCount()).toBe(1);
    expect(result.status).toBe('partial');
    expect(result.summaryLines[0]).toBe('[osv] Vulnerability data partial: 1 of 2 package(s) could not be checked; 0 vulnerability record(s) missing details.');
  });
});

describe('AC-P17-5 / AC-P17-6: details and cache', () => {
  it('AC-P17-5: one detail request per distinct id (shared by two packages); warm second lookup -> 1 batch and 0 details; advanced modified -> only that id', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-1111-1111-1111', modified: '2026-01-01T00:00:00Z' }, { id: 'OSV-2026-9', modified: '2026-01-01T00:00:00Z' }]);
    osv.vulns.set(osvKey('npm', 'b', '1.0.0'), [{ id: 'GHSA-1111-1111-1111', modified: '2026-01-01T00:00:00Z' }]);
    osv.addRecord('GHSA-1111-1111-1111');
    osv.addRecord('OSV-2026-9');
    const { cache } = memoryCache();
    const engine = lookupEngine(vulnClient(), cache);
    await engine.lookup([npm('a'), npm('b')], { signal: signal() });
    expect(osv.detailCount()).toBe(2);
    expect(osv.count('/v1/vulns/GHSA-1111-1111-1111')).toBe(1);

    osv.resetCounts();
    const second = await engine.lookup([npm('a'), npm('b')], { signal: signal() });
    expect(osv.count('/v1/querybatch')).toBe(1);
    expect(osv.detailCount()).toBe(0);
    expect(second.status).toBe('complete');

    osv.resetCounts();
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-1111-1111-1111', modified: '2026-01-01T00:00:00Z' }, { id: 'OSV-2026-9', modified: '2026-03-01T00:00:00Z' }]);
    osv.addRecord('OSV-2026-9', { modified: '2026-03-01T00:00:00Z' });
    await engine.lookup([npm('a'), npm('b')], { signal: signal() });
    expect(osv.requests.filter((r) => r.path.startsWith('/v1/vulns/')).map((r) => r.path)).toEqual(['/v1/vulns/OSV-2026-9']);
  });

  it('AC-P17-5: the id is one encoded path component', () => {
    expect(osvVulnUrl({ osv: 'https://api.osv.dev', nvd: 'x' }, 'PYSEC-2021:1')).toBe('https://api.osv.dev/v1/vulns/PYSEC-2021%3A1');
  });

  it('AC-P17-6: a withdrawn record yields no vulnerability', async () => {
    osv.vulns.set(osvKey('npm', 'w', '1.0.0'), [{ id: 'GHSA-wwww-wwww-wwww' }]);
    osv.addRecord('GHSA-wwww-wwww-wwww', { withdrawn: '2026-02-01T00:00:00Z' });
    const result = await lookupEngine(vulnClient()).lookup([npm('w')], { signal: signal() });
    expect(result.byKey.size).toBe(0);
    expect(result.keyStates.get(keyOf('w'))).toBe('checked');
  });
});

describe('AC-P17-11: failure visibility', () => {
  it('AC-P17-11: detail 500 -> minimal record (title = id, medium, source link), detail missing, status partial, exact [osv] line', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-dddd-dddd-dddd', modified: '2026-01-01T00:00:00Z' }]);
    osv.override('/v1/vulns/GHSA-dddd-dddd-dddd', { status: 500, body: {} });
    const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    const [resolved] = result.byKey.get(keyOf('a')) ?? [];
    expect(resolved.record).toBeNull();
    const normalized = normalizeResolved(resolved, { ecosystem: 'nodejs', name: 'a' });
    expect(normalized).toMatchObject({ title: 'GHSA-dddd-dddd-dddd', severity: 'medium', ghsaId: 'GHSA-dddd-dddd-dddd', minimal: true, sourceUrl: 'https://osv.dev/vulnerability/GHSA-dddd-dddd-dddd' });
    expect(result.status).toBe('partial');
    expect(result.counts.detailMissing).toBe(1);
    expect(result.summaryLines).toEqual(['[osv] Vulnerability data partial: 0 of 1 package(s) could not be checked; 1 vulnerability record(s) missing details.']);
    expect(sleeps).toEqual([1000, 2000]);
  });

  it('AC-P17-11: OSV down -> every candidate unchecked (never clean), unavailable, one [osv] line without names', async () => {
    osv.override('/v1/querybatch', { status: 503, body: {} });
    const result = await lookupEngine(vulnClient()).lookup([npm('secret-name'), npm('b')], { signal: signal() });
    expect([...result.keyStates.values()].every((s) => s === 'unchecked')).toBe(true);
    expect(result.byKey.size).toBe(0);
    expect(result.status).toBe('unavailable');
    expect(result.summaryLines).toHaveLength(1);
    expect(result.summaryLines[0]).not.toContain('secret-name');
  });

  it('AC-P17-11: status rules (disabled first; no candidate complete; none checked unavailable; partial; complete)', () => {
    expect(vulnerabilityDataStatusOf({ enabled: false, candidates: 0, checked: 0, detailMissing: 0 })).toBe('disabled');
    expect(vulnerabilityDataStatusOf({ enabled: true, candidates: 0, checked: 0, detailMissing: 0 })).toBe('complete');
    expect(vulnerabilityDataStatusOf({ enabled: true, candidates: 3, checked: 0, detailMissing: 0 })).toBe('unavailable');
    expect(vulnerabilityDataStatusOf({ enabled: true, candidates: 3, checked: 2, detailMissing: 0 })).toBe('partial');
    expect(vulnerabilityDataStatusOf({ enabled: true, candidates: 3, checked: 3, detailMissing: 1 })).toBe('partial');
    expect(vulnerabilityDataStatusOf({ enabled: true, candidates: 3, checked: 3, detailMissing: 0 })).toBe('complete');
  });

  it('AC-P17-11 / AC-P17-13: [osv] then [nvd] exact templates (contract §3.3)', () => {
    expect(vulnerabilitySummaryLines('disabled', { candidates: 4, unchecked: 4, detailMissing: 0, nvdUnavailable: 2 })).toEqual([
      '[osv] Vulnerability data disabled: vulnerability lookup disabled; 4 package(s) not checked.',
    ]);
    expect(vulnerabilitySummaryLines('partial', { candidates: 5, unchecked: 2, detailMissing: 3, nvdUnavailable: 1 })).toEqual([
      '[osv] Vulnerability data partial: 2 of 5 package(s) could not be checked; 3 vulnerability record(s) missing details.',
      '[nvd] CVSS unavailable for 1 vulnerability record(s); severity taken from OSV data or the default.',
    ]);
    expect(vulnerabilitySummaryLines('complete', { candidates: 5, unchecked: 0, detailMissing: 0, nvdUnavailable: 2 })).toEqual([
      '[nvd] CVSS unavailable for 2 vulnerability record(s); severity taken from OSV data or the default.',
    ]);
    expect(vulnerabilitySummaryLines('complete', { candidates: 5, unchecked: 0, detailMissing: 0, nvdUnavailable: 0 })).toEqual([]);
  });
});

describe('AC-P17-12: on/off', () => {
  it('AC-P17-12: VULNERABILITY_LOOKUP=off -> no request, no session, status disabled with the disabled line', async () => {
    const c = vulnClient({}, { lookupEnabled: false });
    expect(c.session()).toBeNull();
    const result = await lookupEngine(c).lookup([npm('a'), npm('b')], { signal: signal() });
    expect(osv.requests).toHaveLength(0);
    expect(result.status).toBe('disabled');
    expect(result.summaryLines).toEqual(['[osv] Vulnerability data disabled: vulnerability lookup disabled; 2 package(s) not checked.']);
  });

  it('AC-P17-12: NVD_ENABLED=false -> OSV continues, no NVD request', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-eeee-eeee-eeee' }]);
    osv.addRecord('GHSA-eeee-eeee-eeee', { aliases: ['CVE-2024-11111'], severity: [] });
    const result = await lookupEngine(vulnClient({}, { nvdEnabled: false })).lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(0);
    expect(result.status).toBe('complete');
    expect(result.summaryLines).toEqual([]);
  });
});

describe('AC-P17-13: NVD rate limit and cache', () => {
  function seedNvdCase(): void {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-ffff-ffff-ffff' }, { id: 'GHSA-gggg-gggg-gggg' }]);
    osv.addRecord('GHSA-ffff-ffff-ffff', { aliases: ['CVE-2024-22222'], severity: [] });
    // Numeric OSV score -> no NVD request (a vector-only severity has no score under the legacy rule).
    osv.addRecord('GHSA-gggg-gggg-gggg', { aliases: ['CVE-2024-33333'], severity: [{ type: 'CVSS_V3', score: '7.5' }] });
    osv.nvd.set('CVE-2024-22222', nvdBody('CVE-2024-22222', 9.8, 'CRITICAL'));
  }

  it('AC-P17-13: NVD only for a CVE without OSV CVSS; found cached 7 d (second lookup: 0 NVD requests); CVSS applied', async () => {
    seedNvdCase();
    const mem = memoryCache();
    const engine = lookupEngine(vulnClient(), mem.cache);
    const first = await engine.lookup([npm('a')], { signal: signal() });
    expect(osv.requests.filter((r) => r.path === '/rest/json/cves/2.0').map((r) => r.query)).toEqual(['?cveId=CVE-2024-22222']);
    expect(mem.nvdWrites).toEqual([{ cve: 'CVE-2024-22222', outcome: 'found', ttlMs: 7 * 24 * 3_600_000 }]);
    const resolved = first.byKey.get(keyOf('a'))?.find((v) => v.id === 'GHSA-ffff-ffff-ffff');
    expect(normalizeResolved(resolved!, { ecosystem: 'nodejs', name: 'a' })).toMatchObject({ cvssScore: 9.8, severity: 'critical' });
    osv.resetCounts();
    nowMs += 6 * 24 * 3_600_000;
    await engine.lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(0);
    nowMs += 2 * 24 * 3_600_000;
    await engine.lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(1);
  });

  it('AC-P17-13: "no CVSS" cached 24 h; transient errors are not cached and give one [nvd] line without changing the status', async () => {
    seedNvdCase();
    osv.nvd.delete('CVE-2024-22222');
    const mem = memoryCache();
    const engine = lookupEngine(vulnClient(), mem.cache);
    await engine.lookup([npm('a')], { signal: signal() });
    expect(mem.nvdWrites).toEqual([{ cve: 'CVE-2024-22222', outcome: 'no_cvss', ttlMs: 24 * 3_600_000 }]);
    osv.resetCounts();
    nowMs += 23 * 3_600_000;
    await engine.lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(0);

    nowMs += 2 * 3_600_000;
    osv.resetCounts();
    osv.override('/rest/json/cves/2.0', { status: 503, body: {} });
    const failed = await engine.lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(3);
    expect(mem.nvdWrites).toHaveLength(1);
    expect(failed.status).toBe('complete');
    expect(failed.summaryLines).toEqual(['[nvd] CVSS unavailable for 1 vulnerability record(s); severity taken from OSV data or the default.']);
  });

  it('AC-P17-13: 429 with Retry-After: 5 is honoured (wait 5 s), then succeeds', async () => {
    seedNvdCase();
    osv.override('/rest/json/cves/2.0', [{ status: 429, headers: { 'retry-after': '5' }, body: {} }, PASSTHROUGH]);
    const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(sleeps).toContain(5000);
    expect(osv.nvdCount()).toBe(2);
    expect(result.counts.nvdUnavailable).toBe(0);
  });

  it('AC-P17-13: sliding window without key: 5 immediate attempts, the 6th waits 30 s (injected clock); with key 50', async () => {
    let t = 0;
    const waits: number[] = [];
    const fake: AppClock = {
      now: () => t,
      sleep: async (ms) => {
        waits.push(ms);
        t += ms;
      },
    };
    const limiter = createSlidingWindowLimiter({ windowMs: 30_000, max: 5, clock: fake });
    for (let i = 0; i < 5; i++) expect(await limiter.acquire(signal())).toBe(true);
    expect(waits).toEqual([]);
    expect(await limiter.acquire(signal())).toBe(true);
    expect(waits).toEqual([30_000]);
    const keyed = createSlidingWindowLimiter({ windowMs: 30_000, max: 50, clock: fake });
    waits.length = 0;
    for (let i = 0; i < 50; i++) await keyed.acquire(signal());
    expect(waits).toEqual([]);
    const aborted = new AbortController();
    aborted.abort();
    expect(await keyed.acquire(aborted.signal)).toBe(false);
  });

  it('AC-P17-7: a CVE id outside ^CVE-\\d{4}-\\d{4,}$ is never requested', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-hhhh-hhhh-hhhh' }]);
    osv.addRecord('GHSA-hhhh-hhhh-hhhh', { aliases: ['CVE-24-1'], severity: [] });
    await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(osv.nvdCount()).toBe(0);
  });
});

describe('AC-P17-14: time budget and abort', () => {
  it('AC-P17-14: budget = min(T/4, remaining - T/8)', () => {
    expect(computeVulnerabilityBudgetMs(80_000, 80_000)).toBe(20_000);
    expect(computeVulnerabilityBudgetMs(80_000, 25_000)).toBe(15_000);
    expect(computeVulnerabilityBudgetMs(80_000, 5_000)).toBe(-5_000);
  });

  it('AC-P17-14: budget <= 0 -> no request, every candidate unchecked (time_limit)', async () => {
    const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal(), budgetMs: 0 });
    expect(osv.requests).toHaveLength(0);
    expect(result.status).toBe('unavailable');
    expect(result.failures.has('time_limit')).toBe(true);
  });

  it('AC-P17-14: a slow server and a small budget -> unchecked, the lookup returns', async () => {
    osv.override('/v1/querybatch', { hang: true });
    const started = Date.now();
    const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal(), budgetMs: 200 });
    expect(Date.now() - started).toBeLessThan(2_500);
    expect(result.keyStates.get(keyOf('a'))).toBe('unchecked');
    expect(result.status).toBe('unavailable');
  });

  it('AC-P17-14: a job abort during the request is rethrown with the job reason', async () => {
    osv.override('/v1/querybatch', { hang: true });
    const job = new AbortController();
    const reason = new Error('shutdown');
    setTimeout(() => job.abort(reason), 100);
    await expect(lookupEngine(vulnClient()).lookup([npm('a')], { signal: job.signal })).rejects.toBe(reason);
  });
});

describe('AC-P17-7 / AC-P17-8 / AC-P17-9 / AC-P17-10: safe client', () => {
  it('AC-P17-7: OSV requests carry no apiKey/cookie/authorization; NVD gets apiKey; fixed User-Agent; the key is never logged', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-iiii-iiii-iiii' }]);
    osv.addRecord('GHSA-iiii-iiii-iiii', { aliases: ['CVE-2024-44444'], severity: [] });
    const key = 'nvd-test-key-0123456789';
    await lookupEngine(vulnClient({ env: { NVD_API_KEY: key } })).lookup([npm('a')], { signal: signal() });
    for (const r of osv.requests) {
      expect(r.headers.cookie).toBeUndefined();
      expect(r.headers.authorization).toBeUndefined();
      expect(r.headers['user-agent']).toMatch(/^oss-risk-platform\/[0-9A-Za-z.+-]+ \(vulnerability-lookup\)$/);
      if (r.path.startsWith('/v1/')) expect(r.headers.apikey).toBeUndefined();
      else expect(r.headers.apikey).toBe(key);
    }
    expect(osv.nvdCount()).toBe(1);
    expect(warnings.join('\n')).not.toContain(key);
  });

  it('AC-P17-7: fixed hosts and paths; https only; injection accepts production origins or loopback http only', () => {
    expect(PRODUCTION_VULNERABILITY_ENDPOINTS).toEqual({ osv: 'https://api.osv.dev', nvd: 'https://services.nvd.nist.gov' });
    expect(assertInjectableVulnerabilityEndpoint('https://api.osv.dev')).toBe('https://api.osv.dev');
    expect(assertInjectableVulnerabilityEndpoint('http://127.0.0.1:9')).toBe('http://127.0.0.1:9');
    for (const bad of ['http://api.osv.dev', 'https://evil.example', 'http://localhost:9', 'https://api.osv.dev/v1', 'https://u:p@api.osv.dev', 'http://10.0.0.1:80']) {
      expect(() => assertInjectableVulnerabilityEndpoint(bad), bad).toThrow();
    }
    expect(nvdCveUrl(PRODUCTION_VULNERABILITY_ENDPOINTS, 'CVE-2024-1234')).toBe('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234');
  });

  it('AC-P17-7: a purpose refuses other paths/queries (URL_NOT_ALLOWED, no request)', async () => {
    const session = vulnClient().session()!;
    const r1 = await session.request('osv-vuln', `${osv.origin}/v1/vulns/a/b`, { signal: signal() });
    const r2 = await session.request('nvd-cve', `${osv.origin}/rest/json/cves/2.0?cveId=CVE-2024-1234&x=1`, { signal: signal() });
    const r3 = await session.request('osv-querybatch', `${osv.origin}/v1/query`, { signal: signal(), body: Buffer.from('{}') });
    for (const r of [r1, r2, r3]) expect(r).toMatchObject({ code: 'URL_NOT_ALLOWED' });
    expect(osv.requests).toHaveLength(0);
  });

  it('AC-P17-7: a redirect is not followed (3xx -> error), the batch packages are unchecked', async () => {
    osv.override('/v1/querybatch', { status: 302, headers: { location: `${osv.origin}/v1/querybatch2` } });
    const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(osv.count('/v1/querybatch2')).toBe(0);
    expect(osv.count('/v1/querybatch')).toBe(1);
    expect(result.status).toBe('unavailable');
  });

  it('AC-P17-8: OSV_API_URL / NVD_API_URL are ignored; one warning naming each variable, never the value', () => {
    const env = { OSV_API_URL: 'http://127.0.0.1:1/mirror-secret', NVD_API_URL: 'https://nvd-mirror.internal/token=abc' };
    const out: string[] = [];
    warnRemovedVulnerabilitySettings(env, (m) => out.push(m));
    expect(out).toHaveLength(2);
    expect(out[0]).toContain('OSV_API_URL');
    expect(out[1]).toContain('NVD_API_URL');
    expect(out.join('\n')).not.toMatch(/mirror|token|127\.0\.0\.1/);
    const out2: string[] = [];
    warnRemovedVulnerabilitySettings({}, (m) => out2.push(m));
    expect(out2).toEqual([]);
    const c = createVulnerabilityClient({ config: CONFIG, env, clock, warn: () => undefined });
    clients.push(c);
    expect(c.endpoints).toEqual(PRODUCTION_VULNERABILITY_ENDPOINTS);
  });

  it('AC-P17-9: the F3 proxy decision is used for the OSV/NVD hosts; an invalid proxy or old Node opens no connection and never logs the value', async () => {
    expect(shouldUseProxy('https://api.osv.dev/v1/querybatch', '')).toBe(true);
    expect(shouldUseProxy('https://api.osv.dev/v1/querybatch', '.osv.dev')).toBe(false);
    expect(shouldUseProxy('https://services.nvd.nist.gov/rest/json/cves/2.0', 'services.nvd.nist.gov')).toBe(false);
    const invalid = createVulnerabilityClient({ config: CONFIG, env: { HTTPS_PROXY: 'ftp://user:pw-secret@proxy' }, clock, warn: (m) => warnings.push(m) });
    const old = createVulnerabilityClient({ config: CONFIG, env: { https_proxy: 'http://user:pw-secret@proxy:8080' }, nodeVersion: '22.0.0', clock, warn: (m) => warnings.push(m) });
    clients.push(invalid, old);
    for (const c of [invalid, old]) {
      const r = await c.session()!.request('osv-querybatch', 'https://api.osv.dev/v1/querybatch', { signal: signal(), body: Buffer.from('{"queries":[]}') });
      expect(r).toMatchObject({ kind: 'unreachable', code: 'PROXY_UNAVAILABLE' });
    }
    expect(warnings.length).toBeGreaterThanOrEqual(2);
    expect(warnings.join('\n')).not.toContain('pw-secret');
  });

  it('AC-P17-10: 17 MiB querybatch (Content-Length and chunked) -> too large, packages unchecked', async () => {
    const big = Buffer.alloc(17 * 1024 * 1024, 0x20);
    for (const chunked of [false, true]) {
      osv.override('/v1/querybatch', { body: big, chunked, headers: { 'content-type': 'application/json' } });
      const result = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
      expect(result.status, String(chunked)).toBe('unavailable');
    }
  });

  it('AC-P17-10: Retry-After 120 gives up after one request; 5xx retried twice (1 s, 2 s); other 4xx not retried', async () => {
    osv.override('/v1/querybatch', { status: 429, headers: { 'retry-after': '120' }, body: {} });
    await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(osv.count('/v1/querybatch')).toBe(1);
    expect(sleeps).toEqual([]);
    osv.resetCounts();
    osv.override('/v1/querybatch', [{ status: 502, body: {} }, { status: 503, body: {} }, PASSTHROUGH]);
    const ok = await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(osv.count('/v1/querybatch')).toBe(3);
    expect(sleeps).toEqual([1000, 2000]);
    expect(ok.status).toBe('complete');
    osv.resetCounts();
    sleeps = [];
    osv.override('/v1/querybatch', { status: 400, body: {} });
    await lookupEngine(vulnClient()).lookup([npm('a')], { signal: signal() });
    expect(osv.count('/v1/querybatch')).toBe(1);
    expect(sleeps).toEqual([]);
  });

  it('AC-P17-10: circuit breaker: 5 consecutive network failures close the host for the session', async () => {
    osv.override('/v1/vulns/GHSA-jjjj-jjjj-jjjj', { reset: true });
    const session = vulnClient().session()!;
    const url = `${osv.origin}/v1/vulns/GHSA-jjjj-jjjj-jjjj`;
    const results = [];
    for (let i = 0; i < 3; i++) results.push(await session.request('osv-vuln', url, { signal: signal() }));
    // Security review L-4: the breaker counts every attempt (3 per request), so the 5th attempt
    // (2nd attempt of request 2) opens the circuit, request 2 stops retrying and request 3 is
    // refused without a connection.
    expect(osv.count('/v1/vulns/GHSA-jjjj-jjjj-jjjj')).toBe(5);
    expect(results[0]).toMatchObject({ kind: 'unreachable' });
    expect(results[2]).toMatchObject({ kind: 'unreachable', code: 'CIRCUIT_OPEN' });
    expect(session.isHostClosed(new URL(osv.origin).host)).toBe(true);
    const fresh = vulnClient().session()!;
    await fresh.request('osv-vuln', url, { signal: signal() });
    expect(osv.count('/v1/vulns/GHSA-jjjj-jjjj-jjjj')).toBeGreaterThan(6);
  });

  it('AC-P17-10: OSV_CONCURRENCY bounds simultaneous detail requests', async () => {
    const ids = Array.from({ length: 8 }, (_, i) => `OSV-2026-10${i}`);
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), ids.map((id) => ({ id })));
    let active = 0;
    let max = 0;
    for (const id of ids) {
      osv.addRecord(id);
      osv.override(`/v1/vulns/${id}`, () => {
        active++;
        max = Math.max(max, active);
        setTimeout(() => active--, 80);
        return { body: osv.records.get(id)!, delayMs: 80 };
      });
    }
    await lookupEngine(vulnClient({}, { concurrency: 2 })).lookup([npm('a')], { signal: signal() });
    expect(osv.detailCount()).toBe(8);
    expect(max).toBeLessThanOrEqual(2);
  });
});

describe('AC-P17-5 cache record version', () => {
  it('AC-P17-5: a cached record of an older record_version is a miss (detail refetched)', async () => {
    osv.vulns.set(osvKey('npm', 'a', '1.0.0'), [{ id: 'GHSA-kkkk-kkkk-kkkk', modified: '2026-01-01T00:00:00Z' }]);
    osv.addRecord('GHSA-kkkk-kkkk-kkkk');
    const mem = memoryCache();
    mem.osvRows.set('GHSA-kkkk-kkkk-kkkk', {
      record: { id: 'GHSA-kkkk-kkkk-kkkk', modified: '2026-01-01T00:00:00Z' } as OsvVulnerability,
      modifiedMs: Date.parse('2026-01-01T00:00:00Z'),
      withdrawn: false,
      recordVersion: NORMALIZED_RECORD_VERSION - 1,
    });
    await lookupEngine(vulnClient(), mem.cache).lookup([npm('a')], { signal: signal() });
    expect(osv.detailCount()).toBe(1);
  });
});
