/**
 * REQ-011 P-43 · deps.dev and pub.dev license clients (AC-P43-1…3, AC-G-3;
 * ADR-012 Karar 3, D-317…D-321) against the loopback fake registry. No real
 * network: the injected endpoints are `http://127.0.0.1:<port>` and the
 * network guard fails any other connection.
 */
import { URL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDependencyEnricher, enrichmentKeyOf, type DependencyEnricher, type EnrichmentDependency } from '../../src/enrichment';
import { hasArchiveStage } from '../../src/enrichment/archiveStage';
import { METADATA_EXTRACTOR_VERSIONS } from '../../src/enrichment/cache';
import {
  checkCoordinates,
  noRegistryEcosystem,
  registryEcosystemOf,
  registryRequestName,
  splitDepsDevRequestName,
} from '../../src/enrichment/coordinates';
import { depsDevDeclaredLicense, depsDevVersionUrl, extractDepsDevMetadata, fetchDepsDevMetadata } from '../../src/enrichment/depsDevRegistry';
import { resolveEffectiveLicense } from '../../src/enrichment/effectiveLicense';
import { extractPubDevMetadata, fetchPubDevMetadata, pubDevDeclaredLicense, pubDevScoreUrl } from '../../src/enrichment/pubDevRegistry';
import {
  LICENSE_API_MAX_BYTES,
  PRODUCTION_ENDPOINTS,
  RegistryUrlError,
  assertAllowedUrl,
  assertInjectableEndpoint,
  createRegistryClient,
  isDepsDevVersionPath,
  isPubDevScorePath,
  type RegistryClient,
  type RegistryClientOptions,
  type RegistryClock,
} from '../../src/enrichment/registryClient';
import { type FakeRegistry, startFakeRegistry } from '../helpers/fakeRegistry';

vi.setConfig({ testTimeout: 20_000 });

let reg: FakeRegistry;
const clients: RegistryClient[] = [];
const enrichers: DependencyEnricher[] = [];
const fastClock: RegistryClock = { now: () => Date.now(), sleep: async () => undefined };
const signal = () => new AbortController().signal;

beforeEach(async () => {
  reg = await startFakeRegistry();
});
afterEach(async () => {
  for (const c of clients.splice(0)) c.close();
  for (const e of enrichers.splice(0)) e.close();
  await reg.close();
});

function client(opts: Partial<RegistryClientOptions> = {}): RegistryClient {
  const c = createRegistryClient({
    timeoutMs: 2_000,
    concurrency: 4,
    endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin, nuget: reg.origin, depsdev: reg.origin, pubdev: reg.origin },
    clock: fastClock,
    env: {},
    warn: () => undefined,
    ...opts,
  });
  clients.push(c);
  return c;
}

const DD = (system: string, encodedName: string, encodedVersion: string) => `/v3/systems/${system}/packages/${encodedName}/versions/${encodedVersion}`;
const PUB = (name: string) => `/api/packages/${name}/score`;

// ---------------------------------------------------------------------------
describe('coordinates: project ecosystem -> registry (AC-P43-1/2, D-319, D-320)', () => {
  it('java/go/rust/ruby -> depsdev, dart -> pubdev; php and swift have no registry (noRegistryEcosystem)', () => {
    expect(['java', 'go', 'rust', 'ruby', 'dart', 'php', 'swift'].map(registryEcosystemOf)).toEqual(['depsdev', 'depsdev', 'depsdev', 'depsdev', 'pubdev', null, null]);
    expect(['nodejs', 'python', 'dotnet'].map(registryEcosystemOf)).toEqual(['npm', 'pypi', 'nuget']);
    expect(['php', 'swift'].map(noRegistryEcosystem)).toEqual([true, true]);
    expect(['java', 'dart', 'nodejs', 'container'].map(noRegistryEcosystem)).toEqual([false, false, false, false]);
  });

  it('deps.dev request names carry their system (cache row name); pub.dev names as they are', () => {
    expect(checkCoordinates('java', 'org.slf4j:slf4j-api', '2.0.9')).toEqual({ kind: 'ok', ecosystem: 'depsdev', requestName: 'MAVEN:org.slf4j:slf4j-api', version: '2.0.9' });
    expect(checkCoordinates('go', 'github.com/stretchr/testify', 'v1.8.4')).toEqual({ kind: 'ok', ecosystem: 'depsdev', requestName: 'GO:github.com/stretchr/testify', version: 'v1.8.4' });
    expect(checkCoordinates('rust', 'serde', '1.0.193')).toEqual({ kind: 'ok', ecosystem: 'depsdev', requestName: 'CARGO:serde', version: '1.0.193' });
    expect(checkCoordinates('ruby', 'rails', '7.1.2')).toEqual({ kind: 'ok', ecosystem: 'depsdev', requestName: 'RUBYGEMS:rails', version: '7.1.2' });
    expect(checkCoordinates('dart', 'http', '1.1.0')).toEqual({ kind: 'ok', ecosystem: 'pubdev', requestName: 'http', version: '1.1.0' });
    expect(checkCoordinates('php', 'monolog/monolog', '3.5.0')).toEqual({ kind: 'unsupported' });
    expect(checkCoordinates('swift', 'github.com/apple/swift-nio', '2.0.0')).toEqual({ kind: 'unsupported' });
    expect(splitDepsDevRequestName('MAVEN:g:a')).toEqual(['MAVEN', 'g:a']);
    expect(splitDepsDevRequestName('NPM:x')).toBeNull();
    expect(registryRequestName('rust', 'rand')).not.toBe(registryRequestName('ruby', 'rand'));
  });

  it('invalid names/versions and unknown versions make no request (invalid_coordinates / version_unknown)', () => {
    for (const [eco, name] of [
      ['java', 'no-colon'],
      ['java', 'g:a:extra'],
      ['go', 'nodot/x'],
      ['go', 'github.com/../x'],
      ['rust', 'bad crate'],
      ['ruby', 'a/b'],
      ['dart', 'Http'],
      ['dart', 'a-b'],
    ]) {
      expect(checkCoordinates(eco, name, '1.0.0'), `${eco} ${name}`).toEqual({ kind: 'invalid_coordinates' });
    }
    expect(checkCoordinates('java', 'g:a', '1.0/../x')).toEqual({ kind: 'invalid_coordinates' });
    expect(checkCoordinates('go', 'github.com/a/b', null)).toEqual({ kind: 'version_unknown' });
    // Versionless keys of two deps.dev systems stay apart.
    expect(enrichmentKeyOf({ ecosystem: 'rust', name: 'rand', version: null })).not.toBe(enrichmentKeyOf({ ecosystem: 'ruby', name: 'rand', version: null }));
    expect(enrichmentKeyOf({ ecosystem: 'php', name: 'a/b', version: '1.0.0' })).toBeNull();
  });

  it('own extractor counters; no archive stage for depsdev/pubdev (D-321)', () => {
    expect(METADATA_EXTRACTOR_VERSIONS.depsdev).toBe(1);
    expect(METADATA_EXTRACTOR_VERSIONS.pubdev).toBe(1);
    expect(['npm', 'pypi', 'nuget', 'depsdev', 'pubdev'].map((e) => hasArchiveStage(e as never))).toEqual([true, true, true, false, false]);
  });
});

// ---------------------------------------------------------------------------
describe('AC-G-3: fixed origins and purpose path rules', () => {
  it('production origins are https://api.deps.dev and https://pub.dev; injectable only as those or loopback', () => {
    expect(PRODUCTION_ENDPOINTS.depsdev).toBe('https://api.deps.dev');
    expect(PRODUCTION_ENDPOINTS.pubdev).toBe('https://pub.dev');
    expect(assertInjectableEndpoint('https://api.deps.dev')).toBe('https://api.deps.dev');
    expect(assertInjectableEndpoint('https://pub.dev/')).toBe('https://pub.dev');
    for (const bad of ['http://api.deps.dev', 'https://deps.dev', 'https://pub.dev/api', 'https://api.pub.dev']) {
      expect(() => assertInjectableEndpoint(bad), bad).toThrow(RegistryUrlError);
    }
  });

  it('a purpose accepts only its own origin over https', () => {
    const ep = { ...PRODUCTION_ENDPOINTS };
    expect(assertAllowedUrl('https://api.deps.dev/v3/systems/GO/packages/x/versions/v1', 'metadata-depsdev', ep).host).toBe('api.deps.dev');
    expect(assertAllowedUrl('https://pub.dev/api/packages/http/score', 'metadata-pubdev', ep).host).toBe('pub.dev');
    for (const [url, purpose] of [
      ['https://pub.dev/api/packages/http/score', 'metadata-depsdev'],
      ['https://api.deps.dev/v3/x', 'metadata-pubdev'],
      ['http://api.deps.dev/v3/x', 'metadata-depsdev'],
      ['https://u:p@pub.dev/api/packages/http/score', 'metadata-pubdev'],
    ] as const) {
      expect(() => assertAllowedUrl(url, purpose, ep), url).toThrow(RegistryUrlError);
    }
  });

  it('exact path shapes: one encoded segment per name/version, known system, no query/fragment', () => {
    const u = (s: string) => new URL(`https://api.deps.dev${s}`);
    expect(isDepsDevVersionPath(u(DD('MAVEN', 'org.slf4j%3Aslf4j-api', '2.0.9')))).toBe(true);
    expect(isDepsDevVersionPath(u(DD('GO', 'github.com%2Fa%2Fb', 'v1.0.0')))).toBe(true);
    for (const bad of [
      DD('NPM', 'x', '1'),
      DD('GO', 'github.com/a/b', 'v1'),
      `${DD('CARGO', 'serde', '1.0.0')}?x=1`,
      '/v3/systems/CARGO/packages/serde',
      '/v3alpha/systems/CARGO/packages/serde/versions/1',
      DD('CARGO', '..', '1'),
    ]) {
      expect(isDepsDevVersionPath(u(bad)), bad).toBe(false);
    }
    const p = (s: string) => new URL(`https://pub.dev${s}`);
    expect(isPubDevScorePath(p(PUB('http')))).toBe(true);
    for (const bad of ['/api/packages/http', '/api/packages/http/score?x', '/api/packages/a/b/score', '/packages/http/score']) {
      expect(isPubDevScorePath(p(bad)), bad).toBe(false);
    }
  });

  it('a URL outside the path rule makes no request (URL_NOT_ALLOWED)', async () => {
    const s = client().session();
    expect(await s.getJson(`${reg.origin}/v3/systems/NPM/packages/x/versions/1`, 'metadata-depsdev', { signal: signal() })).toEqual({ kind: 'error', code: 'URL_NOT_ALLOWED' });
    expect(await s.getJson(`${reg.origin}/api/packages/http/score?x=1`, 'metadata-pubdev', { signal: signal() })).toEqual({ kind: 'error', code: 'URL_NOT_ALLOWED' });
    expect(reg.total()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P43-1: deps.dev client', () => {
  it('URL encoding: Maven colon, Go slashes and "+" stay inside one segment', () => {
    expect(depsDevVersionUrl('https://api.deps.dev', 'MAVEN', 'org.slf4j:slf4j-api', '2.0.9')).toBe(
      'https://api.deps.dev/v3/systems/MAVEN/packages/org.slf4j%3Aslf4j-api/versions/2.0.9',
    );
    expect(depsDevVersionUrl('https://api.deps.dev', 'GO', 'github.com/foo/bar', 'v2.0.0+incompatible')).toBe(
      'https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v2.0.0%2Bincompatible',
    );
  });

  it('licenses -> one SPDX expression (AND, compound items parenthesized, non-standard dropped)', () => {
    expect(depsDevDeclaredLicense({ licenses: ['MIT'] })).toBe('MIT');
    expect(depsDevDeclaredLicense({ licenses: ['MIT OR Apache-2.0', 'BSD-3-Clause', 'MIT OR Apache-2.0'] })).toBe('(MIT OR Apache-2.0) AND BSD-3-Clause');
    expect(depsDevDeclaredLicense({ licenses: ['non-standard', 'Apache-2.0'] })).toBe('Apache-2.0');
    expect(depsDevDeclaredLicense({ licenses: ['non-standard'] })).toBeNull();
    expect(depsDevDeclaredLicense({ licenses: [] })).toBeNull();
    expect(depsDevDeclaredLicense({})).toBeNull();
    expect(depsDevDeclaredLicense({ licenses: [42, null, ' ISC '] })).toBe('ISC');
    expect(extractDepsDevMetadata({ licenses: 'MIT' })).toEqual({ kind: 'error', code: 'FIELD_TYPE' });
  });

  it('happy path: GET on the exact path with fixed headers; found + declared license, no archive candidate', async () => {
    const path = DD('MAVEN', 'org.slf4j%3Aslf4j-api', '2.0.9');
    reg.route(path, { body: { versionKey: { system: 'MAVEN', name: 'org.slf4j:slf4j-api', version: '2.0.9' }, licenses: ['MIT'] } });
    const r = await fetchDepsDevMetadata(client().session(), 'MAVEN:org.slf4j:slf4j-api', '2.0.9', signal());
    expect(r).toEqual({ kind: 'found', metadata: { declaredLicense: 'MIT', licenseText: null, archiveCandidates: [] } });
    expect(reg.requests.map((q) => [q.method, q.path])).toEqual([['GET', path]]);
    const h = reg.requests[0].headers;
    expect(h.accept).toBe('application/json');
    expect(h.cookie).toBeUndefined();
    expect(h.authorization).toBeUndefined();
    expect(String(h['user-agent'])).toContain('license-enrichment');
  });

  it('404 -> not_found; 500 (after retries) -> error; reset -> unreachable; hang -> unreachable TIMEOUT', async () => {
    const s = client({ timeoutMs: 300 }).session();
    expect(await fetchDepsDevMetadata(s, 'CARGO:ghost', '1.0.0', signal())).toEqual({ kind: 'not_found' });
    reg.route(DD('CARGO', 'boom', '1.0.0'), { status: 500 });
    expect(await fetchDepsDevMetadata(s, 'CARGO:boom', '1.0.0', signal())).toEqual({ kind: 'error', code: 'HTTP_500' });
    expect(reg.count(DD('CARGO', 'boom', '1.0.0'))).toBe(3);
    reg.route(DD('CARGO', 'reset', '1.0.0'), { reset: true });
    expect((await fetchDepsDevMetadata(s, 'CARGO:reset', '1.0.0', signal())).kind).toBe('unreachable');
    reg.route(DD('CARGO', 'hang', '1.0.0'), { hang: true });
    expect(await fetchDepsDevMetadata(client({ timeoutMs: 200 }).session(), 'CARGO:hang', '1.0.0', signal())).toEqual({ kind: 'unreachable', code: 'TIMEOUT' });
  });

  it('oversized body -> TOO_LARGE; invalid JSON -> BAD_JSON; not JSON -> BAD_CONTENT_TYPE; redirect is not followed', async () => {
    expect(LICENSE_API_MAX_BYTES).toBe(1024 * 1024);
    reg.route(DD('RUBYGEMS', 'big', '1.0.0'), { body: { licenses: ['MIT'], pad: 'x'.repeat(4096) } });
    expect(await fetchDepsDevMetadata(client({ limits: { licenseApiMaxBytes: 1024 } }).session(), 'RUBYGEMS:big', '1.0.0', signal())).toEqual({ kind: 'error', code: 'TOO_LARGE' });
    reg.route(DD('RUBYGEMS', 'bad', '1.0.0'), { body: '{"licenses": [', headers: { 'content-type': 'application/json' } });
    expect(await fetchDepsDevMetadata(client().session(), 'RUBYGEMS:bad', '1.0.0', signal())).toEqual({ kind: 'error', code: 'BAD_JSON' });
    reg.route(DD('RUBYGEMS', 'html', '1.0.0'), { body: '<html></html>', headers: { 'content-type': 'text/html' } });
    expect(await fetchDepsDevMetadata(client().session(), 'RUBYGEMS:html', '1.0.0', signal())).toEqual({ kind: 'error', code: 'BAD_CONTENT_TYPE' });
    reg.route(DD('RUBYGEMS', 'moved', '1.0.0'), { status: 302, headers: { location: DD('RUBYGEMS', 'rails', '1.0.0') } });
    expect(await fetchDepsDevMetadata(client().session(), 'RUBYGEMS:moved', '1.0.0', signal())).toEqual({ kind: 'error', code: 'REDIRECT' });
    expect(reg.count(DD('RUBYGEMS', 'rails', '1.0.0'))).toBe(0);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P43-2: pub.dev client', () => {
  it('license:<spdx> tags -> expression; classification tags ignored', () => {
    expect(pubDevDeclaredLicense({ tags: ['sdk:dart', 'license:bsd-3-clause', 'license:fsf-libre', 'license:osi-approved', 'is:null-safe'] })).toBe('bsd-3-clause');
    expect(pubDevDeclaredLicense({ tags: ['license:mit', 'license:apache-2.0', 'license:MIT'] })).toBe('mit AND apache-2.0');
    expect(pubDevDeclaredLicense({ tags: ['license:unknown', 'license:osi-approved'] })).toBeNull();
    expect(pubDevDeclaredLicense({ tags: ['license:mit; rm -rf', 'license:', 'license: gpl-3.0 '] })).toBe('gpl-3.0');
    expect(pubDevDeclaredLicense({ tags: [] })).toBeNull();
    expect(pubDevDeclaredLicense({})).toBeNull();
    expect(extractPubDevMetadata({ tags: 'license:mit' })).toEqual({ kind: 'error', code: 'FIELD_TYPE' });
  });

  it('happy path: GET /api/packages/<name>/score; one request serves every version of the name in flight', async () => {
    expect(pubDevScoreUrl('https://pub.dev', 'http')).toBe('https://pub.dev/api/packages/http/score');
    reg.route(PUB('http'), { delayMs: 50, body: { grantedPoints: 140, tags: ['license:bsd-3-clause', 'license:osi-approved'] } });
    const s = client().session();
    const [a, b] = await Promise.all([fetchPubDevMetadata(s, 'http', '1.1.0', signal()), fetchPubDevMetadata(s, 'http', '1.2.0', signal())]);
    expect(a).toEqual({ kind: 'found', metadata: { declaredLicense: 'bsd-3-clause', licenseText: null, archiveCandidates: [] } });
    expect(b).toEqual(a);
    expect(reg.count(PUB('http'))).toBe(1);
  });

  it('404 -> not_found; reset -> unreachable', async () => {
    expect(await fetchPubDevMetadata(client().session(), 'ghost', '1.0.0', signal())).toEqual({ kind: 'not_found' });
    reg.route(PUB('flaky'), { reset: true });
    expect((await fetchPubDevMetadata(client().session(), 'flaky', '1.0.0', signal())).kind).toBe('unreachable');
  });
});

// ---------------------------------------------------------------------------
describe('enricher: new ecosystems end to end without a database (cache stub)', () => {
  const deps: EnrichmentDependency[] = [
    { ecosystem: 'go', name: 'github.com/stretchr/testify', version: 'v1.8.4', scope: 'direct' },
    { ecosystem: 'java', name: 'org.slf4j:slf4j-api', version: '2.0.9', scope: 'direct' },
    { ecosystem: 'rust', name: 'serde', version: '1.0.193', scope: 'dev' },
    { ecosystem: 'ruby', name: 'rails', version: '7.1.2', scope: 'direct' },
    { ecosystem: 'dart', name: 'http', version: '1.1.0', scope: 'direct' },
    { ecosystem: 'php', name: 'monolog/monolog', version: '3.5.0', scope: 'direct', licenses: ['MIT'] },
    { ecosystem: 'swift', name: 'github.com/apple/swift-nio', version: '2.62.0', scope: 'direct' },
  ];
  const seed = () => {
    reg.route(DD('GO', 'github.com%2Fstretchr%2Ftestify', 'v1.8.4'), { body: { licenses: ['MIT'] } });
    reg.route(DD('MAVEN', 'org.slf4j%3Aslf4j-api', '2.0.9'), { body: { licenses: ['MIT'] } });
    reg.route(DD('CARGO', 'serde', '1.0.193'), { body: { licenses: ['MIT OR Apache-2.0'] } });
    reg.route(DD('RUBYGEMS', 'rails', '7.1.2'), { body: { licenses: ['MIT'] } });
    reg.route(PUB('http'), { body: { tags: ['license:bsd-3-clause'] } });
  };
  const writes: unknown[][] = [];
  const db = {
    query: async (sql: string, params?: unknown[]) => {
      if (/INSERT INTO registry_package_cache/.test(sql)) writes.push(params ?? []);
      return { rows: [] };
    },
  };
  function enricher(enabled = true): DependencyEnricher {
    const e = createDependencyEnricher({
      config: { enabled, timeoutMs: 2_000, concurrency: 4 },
      db: db as never,
      logger: { warn: () => undefined },
      endpoints: { npm: reg.origin, pypi: reg.origin, files: reg.origin, nuget: reg.origin, depsdev: reg.origin, pubdev: reg.origin },
      clock: fastClock,
      env: {},
    });
    enrichers.push(e);
    return e;
  }

  it('go/maven/cargo/rubygems/dart -> ok + registry:depsdev / registry:pubdev; no archive (not_attempted / not_runtime); php and swift have no key', async () => {
    seed();
    writes.length = 0;
    const result = await enricher().enrich(deps, { signal: signal(), budgetMs: 10_000 });
    const out = (i: number) => result.outcomes.get(enrichmentKeyOf(deps[i]) as string);
    const expected: [number, string, string, string][] = [
      [0, 'depsdev', 'MIT', 'not_attempted'],
      [1, 'depsdev', 'MIT', 'not_attempted'],
      [2, 'depsdev', 'MIT OR Apache-2.0', 'not_runtime'],
      [3, 'depsdev', 'MIT', 'not_attempted'],
      [4, 'pubdev', 'bsd-3-clause', 'not_attempted'],
    ];
    for (const [i, registry, license, notice] of expected) {
      expect(out(i), deps[i].name).toMatchObject({ status: 'ok', registry, declaredLicense: license, noticeStatus: notice, noticeArchiveId: null, lockIntegrity: null });
      const eff = resolveEffectiveLicense({
        status: 'ok',
        ecosystem: registry as 'depsdev',
        declaredLicense: license,
        lockLicenses: [],
        normalize: (s) => s,
        sanitize: (s) => s,
      });
      expect(eff.licenseSource).toBe(`registry:${registry}`);
    }
    expect(result.outcomes.size).toBe(5);
    expect(result.summaryLine).toBeNull();
    expect(reg.total()).toBe(5);
    // Cache rows: ecosystem depsdev/pubdev, deps.dev names with their system.
    expect(writes.map((p) => [p[0], p[1], p[2], p[3]]).sort()).toEqual(
      [
        ['depsdev', 'CARGO:serde', '1.0.193', 'found'],
        ['depsdev', 'GO:github.com/stretchr/testify', 'v1.8.4', 'found'],
        ['depsdev', 'MAVEN:org.slf4j:slf4j-api', '2.0.9', 'found'],
        ['depsdev', 'RUBYGEMS:rails', '7.1.2', 'found'],
        ['pubdev', 'http', '1.1.0', 'found'],
      ].sort(),
    );
  });

  it('AC-P43-3: unreachable host -> status unreachable, enrich returns normally with the [registry] line', async () => {
    reg.route(DD('GO', 'github.com%2Fstretchr%2Ftestify', 'v1.8.4'), { reset: true });
    reg.route(PUB('http'), { status: 404 });
    const result = await enricher().enrich([deps[0], deps[4]], { signal: signal(), budgetMs: 10_000 });
    expect(result.outcomes.get(enrichmentKeyOf(deps[0]) as string)?.status).toBe('unreachable');
    expect(result.outcomes.get(enrichmentKeyOf(deps[4]) as string)?.status).toBe('not_found');
    expect(result.summaryLine).toContain('unreachable: 1');
  });

  it('AC-G-3: REGISTRY_ENRICHMENT=off -> no request at all, every new-ecosystem key disabled', async () => {
    seed();
    const result = await enricher(false).enrich(deps, { signal: signal(), budgetMs: 10_000 });
    expect(reg.total()).toBe(0);
    expect([...result.outcomes.values()].map((o) => o.status)).toEqual(['disabled', 'disabled', 'disabled', 'disabled', 'disabled']);
  });

  it('budget 0 -> budget_exceeded, no request', async () => {
    seed();
    const result = await enricher().enrich(deps.slice(0, 5), { signal: signal(), budgetMs: 0 });
    expect(reg.total()).toBe(0);
    expect(new Set([...result.outcomes.values()].map((o) => o.status))).toEqual(new Set(['budget_exceeded']));
  });
});
