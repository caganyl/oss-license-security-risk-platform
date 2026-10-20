/**
 * REQ-011 P-41 (AC-P41-1…4; D-301, ADR-012 Karar 2): OSV coordinates of
 * every supported ecosystem, independent of registry enrichment; the npm /
 * PyPI / NuGet keys and request bodies stay as they were (AC-P41-2); the
 * recheck scope SQL mirrors the same table (AC-P41-3).
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AppClock } from '../../src/lib/clock';
import { coordinateKey } from '../../src/enrichment/coordinates';
import { createVulnerabilityClient, type VulnerabilityClient } from '../../src/vulnerability/client';
import { candidateQueries, createVulnerabilityLookup, vulnerabilityKeyOf, type LookupDependency } from '../../src/vulnerability/lookup';
import { normalizeOsvVulnerability, type OsvVulnerability } from '../../src/vulnerability/normalize';
import { OSV_ECOSYSTEM_OF_PROJECT, OSV_KEY_PREFIX_OF_PROJECT, osvCoordinateOf } from '../../src/vulnerability/osvCoordinates';
import { NORMALIZED_RECORD_VERSION, type CachedOsvRecord, type VulnCache } from '../../src/vulnerability/vulnCache';
import { SCAN_ECOSYSTEMS } from '../../src/types/scan';
import { type FakeOsv, osvKey, startFakeOsv } from '../helpers/fakeOsv';
import { REPO_ROOT } from '../helpers/paths';

const dep = (ecosystem: string, name: string, version: string | null): LookupDependency => ({ ecosystem, name, version }) as LookupDependency;

describe('D-301: osvCoordinateOf covers all ten ecosystems', () => {
  it('maps every supported ecosystem to its OSV name and nothing else', () => {
    expect(Object.keys(OSV_ECOSYSTEM_OF_PROJECT).sort()).toEqual([...SCAN_ECOSYSTEMS].sort());
    expect(Object.keys(OSV_KEY_PREFIX_OF_PROJECT).sort()).toEqual([...SCAN_ECOSYSTEMS].sort());
    expect(OSV_ECOSYSTEM_OF_PROJECT).toEqual({
      nodejs: 'npm',
      python: 'PyPI',
      dotnet: 'NuGet',
      java: 'Maven',
      go: 'Go',
      php: 'Packagist',
      rust: 'crates.io',
      ruby: 'RubyGems',
      dart: 'Pub',
      swift: 'SwiftURL',
    });
    for (const eco of ['container', 'other', '__proto__', 'constructor']) expect(osvCoordinateOf(eco, 'x', '1.0.0'), eco).toEqual({ kind: 'unsupported' });
  });

  it.each([
    ['java', 'org.apache.logging.log4j:log4j-core', '2.14.1', 'Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'],
    ['go', 'github.com/gin-gonic/gin', 'v1.9.1', 'Go', 'github.com/gin-gonic/gin', '1.9.1'],
    ['go', 'golang.org/x/net', 'v0.0.0-20230101000000-abcdef123456', 'Go', 'golang.org/x/net', '0.0.0-20230101000000-abcdef123456'],
    ['go', 'github.com/Azure/go-autorest', 'v11.1.2+incompatible', 'Go', 'github.com/Azure/go-autorest', '11.1.2+incompatible'],
    ['php', 'Symfony/Http-Kernel', 'v6.4.1', 'Packagist', 'symfony/http-kernel', '6.4.1'],
    ['php', 'monolog/monolog', '3.5.0', 'Packagist', 'monolog/monolog', '3.5.0'],
    ['rust', 'serde_json', '1.0.108', 'crates.io', 'serde_json', '1.0.108'],
    ['ruby', 'nokogiri', '1.15.4', 'RubyGems', 'nokogiri', '1.15.4'],
    ['dart', 'http', '1.2.0', 'Pub', 'http', '1.2.0'],
    ['swift', 'github.com/apple/swift-nio', '2.62.0', 'SwiftURL', 'github.com/apple/swift-nio', '2.62.0'],
  ])('%s %s@%s -> %s', (ecosystem, name, version, osv, requestName, requestVersion) => {
    const coordinate = osvCoordinateOf(ecosystem, name, version);
    expect(coordinate).toEqual({ kind: 'ok', key: `${osv}\u0000${requestName}\u0000${version}`, ecosystem: osv, name: requestName, version: requestVersion });
  });

  it('AC-P41-2: npm / PyPI / NuGet keep the F4/F5 keys and request values', () => {
    expect(osvCoordinateOf('nodejs', '@scope/pkg', '1.0.0')).toEqual({ kind: 'ok', key: coordinateKey('npm', '@scope/pkg', '1.0.0'), ecosystem: 'npm', name: '@scope/pkg', version: '1.0.0' });
    expect(osvCoordinateOf('python', 'Zope_Interface', '5.0')).toEqual({ kind: 'ok', key: coordinateKey('pypi', 'zope-interface', '5.0'), ecosystem: 'PyPI', name: 'zope-interface', version: '5.0' });
    expect(osvCoordinateOf('dotnet', 'Newtonsoft.Json', '13.0.1')).toEqual({ kind: 'ok', key: coordinateKey('nuget', 'newtonsoft.json', '13.0.1'), ecosystem: 'NuGet', name: 'Newtonsoft.Json', version: '13.0.1' });
  });

  it('AC-P40-6 / AC-P41-4: no exact version is version_unknown (never a candidate), for every ecosystem', () => {
    for (const eco of SCAN_ECOSYSTEMS) {
      // A Gradle dynamic version such as `1.+` looks exact here (`+` is semver build metadata): the parser stores it as declaredRange.
      for (const version of [null, undefined, '', '^1.0.0', '>=1,<2', '*', '~> 1.2', 'unknown']) {
        expect(osvCoordinateOf(eco, eco === 'java' ? 'g:a' : 'name', version as string | null).kind, `${eco} ${String(version)}`).toBe('version_unknown');
      }
    }
  });

  it.each([
    ['java', 'no-colon'],
    ['java', 'g:a:b'],
    ['go', 'x'],
    ['go', 'example/local'],
    ['go', 'github.com/a/../b'],
    ['php', 'single'],
    ['php', 'a/b/c'],
    ['rust', 'a/b'],
    ['rust', 'x'.repeat(65)],
    ['ruby', 'bad name'],
    ['dart', 'Http'],
    ['swift', 'https://github.com/apple/swift-nio.git'],
    ['swift', 'github.com/apple'],
  ])('invalid %s name %s -> invalid_coordinates', (ecosystem, name) => {
    expect(osvCoordinateOf(ecosystem, name, '1.0.0')).toEqual({ kind: 'invalid_coordinates' });
  });

  it('invalid versions are rejected with the F3 version rule', () => {
    for (const version of ['1.0/../x', 'a?b', '1#2', 'x'.repeat(129)]) expect(osvCoordinateOf('rust', 'serde', version).kind, version).toBe('invalid_coordinates');
  });

  it('vulnerabilityKeyOf and candidateQueries use the same coordinate; keys of different ecosystems never collide', () => {
    const deps = [dep('rust', 'serde', '1.0.0'), dep('ruby', 'serde', '1.0.0'), dep('nodejs', 'serde', '1.0.0'), dep('rust', 'serde', '1.0.0'), dep('go', 'x', '1.0.0')];
    const queries = candidateQueries(deps);
    expect(queries.map((q) => [q.ecosystem, q.name, q.version])).toEqual([
      ['crates.io', 'serde', '1.0.0'],
      ['RubyGems', 'serde', '1.0.0'],
      ['npm', 'serde', '1.0.0'],
    ]);
    expect(new Set(queries.map((q) => q.key)).size).toBe(3);
    expect(queries.map((q) => q.key)).toEqual(deps.slice(0, 3).map((d) => vulnerabilityKeyOf(d)));
    expect(vulnerabilityKeyOf(dep('go', 'x', '1.0.0'))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
let osv: FakeOsv;
const clients: VulnerabilityClient[] = [];
const clock: AppClock = { now: () => Date.parse('2026-10-20T08:00:00Z'), sleep: async () => {} };
beforeEach(async () => {
  osv = await startFakeOsv();
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  await osv.close();
});

function engine() {
  const client = createVulnerabilityClient({
    config: { lookupEnabled: true, recheckEnabled: true, intervalHours: 24, timeoutMs: 3_000, concurrency: 4, nvdEnabled: false },
    endpoints: { osv: osv.origin, nvd: osv.origin },
    env: {},
    clock,
    warn: () => {},
  });
  clients.push(client);
  const rows = new Map<string, CachedOsvRecord>();
  const cache: VulnCache = {
    async readOsv(ids) {
      return new Map(ids.filter((id) => rows.has(id)).map((id) => [id, rows.get(id) as CachedOsvRecord]));
    },
    async writeOsv(record) {
      rows.set(record.id, { record, modifiedMs: null, withdrawn: false, recordVersion: NORMALIZED_RECORD_VERSION });
    },
    async readNvd() {
      return new Map();
    },
    async writeNvd() {},
  };
  return createVulnerabilityLookup({ client, db: { query: async () => ({ rows: [] }) }, clock, logger: { warn: () => {} }, cache });
}
const signal = () => new AbortController().signal;

describe('AC-P41-1: new ecosystems are queried through the existing OSV client', () => {
  it('one querybatch with the OSV ecosystem names and name formats; results map back by key', async () => {
    osv.vulns.set(osvKey('Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'), [{ id: 'GHSA-jfh8-c2jp-5v3q', modified: '2026-01-01T00:00:00Z' }]);
    osv.addRecord('GHSA-jfh8-c2jp-5v3q');
    const deps = [
      dep('java', 'org.apache.logging.log4j:log4j-core', '2.14.1'),
      dep('go', 'github.com/gin-gonic/gin', 'v1.9.1'),
      dep('php', 'Monolog/Monolog', 'v3.5.0'),
      dep('rust', 'serde', '1.0.0'),
      dep('ruby', 'rack', '2.2.8'),
      dep('dart', 'http', '1.2.0'),
      dep('swift', 'github.com/apple/swift-nio', '2.62.0'),
    ];
    const result = await engine().lookup(deps, { signal: signal() });
    expect(osv.count('/v1/querybatch', 'POST')).toBe(1);
    expect(osv.batches()[0]).toEqual([
      { package: { ecosystem: 'Go', name: 'github.com/gin-gonic/gin' }, version: '1.9.1' },
      { package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' }, version: '2.14.1' },
      { package: { ecosystem: 'Packagist', name: 'monolog/monolog' }, version: '3.5.0' },
      { package: { ecosystem: 'Pub', name: 'http' }, version: '1.2.0' },
      { package: { ecosystem: 'RubyGems', name: 'rack' }, version: '2.2.8' },
      { package: { ecosystem: 'SwiftURL', name: 'github.com/apple/swift-nio' }, version: '2.62.0' },
      { package: { ecosystem: 'crates.io', name: 'serde' }, version: '1.0.0' },
    ]);
    expect(result.status).toBe('complete');
    expect(result.counts).toMatchObject({ candidates: 7, unchecked: 0 });
    const key = vulnerabilityKeyOf(deps[0]) as string;
    expect(result.keyStates.get(key)).toBe('checked');
    expect(result.byKey.get(key)?.map((v) => v.id)).toEqual(['GHSA-jfh8-c2jp-5v3q']);
  });

  it('AC-P41-4: packages without an exact version are no candidates: status complete, nothing unchecked, no request', async () => {
    const deps = [dep('java', 'g:a', null), dep('php', 'a/b', null), dep('rust', 'serde', null), dep('go', 'github.com/a/b', '')];
    const result = await engine().lookup(deps, { signal: signal() });
    expect(osv.count('/v1/querybatch', 'POST')).toBe(0);
    expect(result.status).toBe('complete');
    expect(result.counts).toMatchObject({ candidates: 0, unchecked: 0 });
  });

  it('AC-P41-2: an npm/PyPI/NuGet-only input sends exactly the same body as before (no new ecosystem leaks in)', async () => {
    await engine().lookup([dep('python', 'Foo_Bar', '1.0'), dep('nodejs', 'a', '1.0.0'), dep('dotnet', 'Newtonsoft.Json', '13.0.1')], { signal: signal() });
    expect(osv.batches()).toEqual([
      [
        { package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json' }, version: '13.0.1' },
        { package: { ecosystem: 'PyPI', name: 'foo-bar' }, version: '1.0' },
        { package: { ecosystem: 'npm', name: 'a' }, version: '1.0.0' },
      ],
    ]);
  });
});

describe('affected entry of the new OSV ecosystems', () => {
  it('bestAffected picks the entry of the dependency OSV ecosystem (crates.io, Pub, SwiftURL)', () => {
    for (const [ecosystem, osvName] of [
      ['rust', 'crates.io'],
      ['dart', 'Pub'],
      ['swift', 'SwiftURL'],
    ] as const) {
      const record = {
        id: 'OSV-2026-1',
        modified: '2026-01-01T00:00:00Z',
        affected: [
          { package: { ecosystem: 'npm', name: 'zzz' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
          { package: { ecosystem: osvName, name: 'other-name' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }] },
        ],
      } as unknown as OsvVulnerability;
      const normalized = normalizeOsvVulnerability(record, { ecosystem, name: 'pkg' });
      expect(normalized.fixedVersion, ecosystem).toBe('1.2.3');
      expect(normalized.affectedEcosystem).toBe(ecosystem);
    }
  });
});

describe('AC-P41-3: the recheck scope SQL mirrors OSV_KEY_PREFIX_OF_PROJECT', () => {
  it('CASE arms, IN list and the lower-cased request names (PyPI, NuGet, Packagist)', () => {
    const source = fs.readFileSync(path.join(REPO_ROOT, 'src', 'vulnerability', 'recheck.ts'), 'utf8');
    const sql = /const SCOPE_PAGE_SQL = `([\s\S]*?)`;/.exec(source)?.[1] ?? '';
    const ecoCase = /SELECT CASE p\.ecosystem::text ([\s\S]*?) END AS eco/.exec(sql)?.[1] ?? '';
    const arms = [...ecoCase.matchAll(/WHEN '([^']+)' THEN '([^']+)'/g)].map((m) => [m[1], m[2]]);
    expect(Object.fromEntries(arms)).toEqual(OSV_KEY_PREFIX_OF_PROJECT);
    expect(arms).toHaveLength(Object.keys(OSV_KEY_PREFIX_OF_PROJECT).length);
    const inList = /WHERE p\.ecosystem::text IN \(([^)]*)\)/.exec(sql)?.[1] ?? '';
    expect([...inList.matchAll(/'([^']+)'/g)].map((m) => m[1]).sort()).toEqual(Object.keys(OSV_KEY_PREFIX_OF_PROJECT).sort());
    expect(sql).toContain(`WHEN 'php' THEN lower(p.name COLLATE "C")`);
    // The JS key of a stored row starts with the SQL key prefix (row filter `key.startsWith(eco + NUL)`).
    for (const [ecosystem, prefix] of Object.entries(OSV_KEY_PREFIX_OF_PROJECT)) {
      const sample: Record<string, [string, string]> = {
        nodejs: ['a', '1.0.0'],
        python: ['a', '1.0.0'],
        dotnet: ['A', '1.0.0'],
        java: ['g:a', '1.0.0'],
        go: ['github.com/a/b', 'v1.0.0'],
        php: ['A/B', '1.0.0'],
        rust: ['a', '1.0.0'],
        ruby: ['a', '1.0.0'],
        dart: ['a', '1.0.0'],
        swift: ['github.com/a/b', '1.0.0'],
      };
      const [name, version] = sample[ecosystem];
      expect(vulnerabilityKeyOf(dep(ecosystem, name, version))?.startsWith(`${prefix}\u0000`), ecosystem).toBe(true);
    }
  });
});
