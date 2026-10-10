/**
 * Registry license enrichment of one scan — the single entry point called by
 * the scan worker (REQ-004 P-14, P-15, L-6; ADR-006 Karar 2, 11, 14).
 *
 * Per unique key `(registry, request name, version)`:
 *   1. classification without requests: enrichment off -> `disabled`;
 *      version NULL -> `version_unknown`; invalid name/version ->
 *      `invalid_coordinates` (AC-P14-4);
 *   2. one bulk metadata cache read;
 *   3. metadata requests for misses (the registry client's process-wide
 *      limiter); found/not-found results are cached at once;
 *   4. archive stage for runtime (union over manifests), exact-version keys
 *      whose metadata was found: bulk archive cache read, then download +
 *      integrity + thread (`archiveStage.ts`);
 *   5. the single `[registry]` summary line (contract section 8).
 *
 * Signals: everything runs on `AbortSignal.any([job, budget])`. A job abort
 * (time limit / shutdown) is rethrown as is; a budget abort turns the
 * remaining and in-flight keys into `budget_exceeded` and `enrich` returns
 * normally. No other error escapes a key: it becomes `error` (metadata) or
 * `processing_failed` (archive). Enrichment never fails or retries a scan.
 */
import { ENRICHMENT_LIMITS, type EnrichmentConfig } from '../scanner/sandbox/runner.config';
import { type DependencyScope, isRuntimeScope as isRuntimeDependencyScope } from '../types/scan';
import { ARCHIVE_THREAD_RESOURCE_LIMITS, type ArchiveThreadOptions, runArchiveInThread } from './archive/archiveThread';
import { type ArchiveTask, type RunArchiveThreadFn, archiveCacheKey, collectArchive, errorCodeOf, triedCandidates } from './archiveStage';
import { DownloadQuota, createBudgetSignal } from './budget';
import { type CacheDb, type CachedArchive, type CachedMetadata, readArchiveCache, readMetadataCache, writeMetadataCache } from './cache';
import { type RegistryEcosystem, checkCoordinates, coordinateKey, registryEcosystemOf, requestName } from './coordinates';
import { HINT_FALLBACK_STATUSES, lockHintOf, registrySummaryLine } from './effectiveLicense';
import { digestKey } from './integrity';
import { fetchNpmMetadata } from './npmRegistry';
import { fetchPypiMetadata } from './pypiRegistry';
import { type RegistryClient, type RegistryClientLimits, type RegistryClock, type RegistryEndpoints, createRegistryClient } from './registryClient';
import { sanitizeText } from './text';
import type { EnrichmentStatus, MetadataOutcome, NoticeStatus, RegistryMetadata } from './types';

/** The parts of a parsed dependency the enricher reads. */
export interface EnrichmentDependency {
  ecosystem: string;
  name: string;
  version?: string | null;
  scope?: string;
  licenses?: string[];
}

/** Enrichment outcome of one key (shared by every manifest row of the key). */
export interface DependencyEnrichment {
  status: EnrichmentStatus;
  registry: RegistryEcosystem;
  /** Registry declaration (status `ok`), else null. */
  declaredLicense: string | null;
  noticeStatus: NoticeStatus;
  noticeArchiveId: string | null;
}

export interface EnrichmentResult {
  /** Key: `enrichmentKeyOf(dep)`. Dependencies of unsupported ecosystems have no entry. */
  outcomes: Map<string, DependencyEnrichment>;
  /** The `[registry]` line, or null. */
  summaryLine: string | null;
}

export interface EnrichOptions {
  /** Job signal (time limit / shutdown). */
  signal: AbortSignal;
  /** `computeBudgetMs(...)`; `<= 0` means no request at all. */
  budgetMs: number;
}

export interface DependencyEnricher {
  readonly enabled: boolean;
  enrich(dependencies: readonly EnrichmentDependency[], options: EnrichOptions): Promise<EnrichmentResult>;
  /** Result used when `enrich` threw something other than a job abort: requestable keys are `error`. */
  failed(dependencies: readonly EnrichmentDependency[]): EnrichmentResult;
  /** Destroys pooled sockets (shutdown, tests). */
  close(): void;
}

export interface DependencyEnricherOptions {
  config: EnrichmentConfig;
  db: CacheDb;
  logger?: Pick<Console, 'warn'>;
  /** Code-level test injection only (validated by the client); `runtime.ts` never passes it. */
  endpoints?: Partial<RegistryEndpoints>;
  clock?: RegistryClock;
  clientLimits?: Partial<RegistryClientLimits>;
  /** Proxy environment (default `process.env`). */
  env?: Readonly<Record<string, string | undefined>>;
  /** Test hooks of the archive stage. */
  archive?: Partial<ArchiveThreadOptions> & { runThread?: RunArchiveThreadFn; scanDownloadQuotaBytes?: number };
}

/** Same scope rule as the policy loop of the worker (`dep.scope || 'direct'`, ADR-003 b). */
function isRuntimeScope(scope: string | undefined): boolean {
  return isRuntimeDependencyScope((scope || 'direct') as DependencyScope);
}

function versionOf(dep: EnrichmentDependency): string | null {
  return dep.version === null || dep.version === undefined || dep.version === '' ? null : dep.version;
}

/** Key of a dependency in `EnrichmentResult.outcomes`, or null for an unsupported ecosystem. */
export function enrichmentKeyOf(dep: EnrichmentDependency): string | null {
  const registry = registryEcosystemOf(dep.ecosystem);
  if (registry === null) return null;
  const version = versionOf(dep);
  return version === null ? `${registry}\u0000${requestName(registry, dep.name)}\u0000\u0001` : coordinateKey(registry, requestName(registry, dep.name), version);
}

interface KeyInfo {
  key: string;
  registry: RegistryEcosystem;
  check: ReturnType<typeof checkCoordinates>;
  runtime: boolean;
  hasHint: boolean;
}

function groupKeys(dependencies: readonly EnrichmentDependency[]): Map<string, KeyInfo> {
  const keys = new Map<string, KeyInfo>();
  for (const dep of dependencies) {
    const key = enrichmentKeyOf(dep);
    if (key === null) continue;
    const runtime = isRuntimeScope(dep.scope);
    const hasHint = lockHintOf(dep.licenses ?? [], sanitizeText) !== null;
    const existing = keys.get(key);
    if (existing) {
      existing.runtime ||= runtime;
      existing.hasHint ||= hasHint;
      continue;
    }
    keys.set(key, {
      key,
      registry: registryEcosystemOf(dep.ecosystem) as RegistryEcosystem,
      check: checkCoordinates(dep.ecosystem, dep.name, versionOf(dep)),
      runtime,
      hasHint,
    });
  }
  return keys;
}

function buildResult(infos: Iterable<KeyInfo>, outcomes: Map<string, DependencyEnrichment>, summary: 'enabled' | 'disabled' | 'none'): EnrichmentResult {
  const entries: Array<{ status: EnrichmentStatus; usedHint: boolean }> = [];
  for (const info of infos) {
    const outcome = outcomes.get(info.key);
    if (outcome) entries.push({ status: outcome.status, usedHint: HINT_FALLBACK_STATUSES.has(outcome.status) && info.hasHint });
  }
  return { outcomes, summaryLine: summary === 'none' ? null : registrySummaryLine(entries, summary === 'enabled') };
}

function noRequestOutcome(info: KeyInfo, status: EnrichmentStatus): DependencyEnrichment {
  return { status, registry: info.registry, declaredLicense: null, noticeStatus: info.runtime ? 'not_attempted' : 'not_runtime', noticeArchiveId: null };
}

/**
 * Result without any request: every key `disabled` (enrichment off, or no
 * enricher injected — then `withLine` is false and no `[registry]` line is
 * written, ADR-006 netleştirme 10).
 */
export function disabledEnrichment(dependencies: readonly EnrichmentDependency[], withLine: boolean): EnrichmentResult {
  const infos = groupKeys(dependencies);
  const outcomes = new Map<string, DependencyEnrichment>();
  for (const info of infos.values()) outcomes.set(info.key, noRequestOutcome(info, 'disabled'));
  return buildResult(infos.values(), outcomes, withLine ? 'disabled' : 'none');
}

function classified(info: KeyInfo): EnrichmentStatus | null {
  if (info.check.kind === 'version_unknown') return 'version_unknown';
  if (info.check.kind !== 'ok') return 'invalid_coordinates';
  return null;
}

/** Runs `fn` over `items` with `limit` workers; stops picking after the first throw, waits for all, rethrows it. */
async function runPool<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let failure: { err: unknown } | null = null;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (failure === null && next < items.length) {
      const item = items[next++];
      try {
        await fn(item);
      } catch (err) {
        failure ??= { err };
      }
    }
  });
  await Promise.allSettled(workers);
  if (failure !== null) throw (failure as { err: unknown }).err;
}

function abortReasonOf(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const err = new Error('Tarama iptal edildi.');
  err.name = 'AbortError';
  return err;
}

function metadataStatus(metadata: RegistryMetadata): EnrichmentStatus {
  return metadata.declaredLicense !== null && metadata.declaredLicense.trim() !== '' ? 'ok' : 'no_license';
}

export function createDependencyEnricher(options: DependencyEnricherOptions): DependencyEnricher {
  const { config, db } = options;
  const logger = options.logger ?? console;
  const warn = (message: string) => logger.warn(message);
  // Enrichment off: no network client, no cache access (AC-P14-16).
  const client: RegistryClient | null = config.enabled
    ? createRegistryClient({
        timeoutMs: config.timeoutMs,
        concurrency: config.concurrency,
        endpoints: options.endpoints,
        env: options.env,
        clock: options.clock,
        limits: options.clientLimits,
        warn,
      })
    : null;
  const threadOptions: ArchiveThreadOptions = {
    limits: options.archive?.limits ?? {
      maxDecompressedBytes: ENRICHMENT_LIMITS.archive.maxDecompressedBytes,
      maxEntries: ENRICHMENT_LIMITS.archive.maxEntries,
      maxFileBytes: ENRICHMENT_LIMITS.archive.maxFileBytes,
      maxPackageTextBytes: ENRICHMENT_LIMITS.archive.maxPackageTextBytes,
      maxFiles: ENRICHMENT_LIMITS.archive.maxFiles,
      maxLongNameBytes: ENRICHMENT_LIMITS.archive.maxLongNameBytes,
    },
    threadTimeoutMs: options.archive?.threadTimeoutMs ?? ENRICHMENT_LIMITS.archive.threadTimeoutMs,
    maxThreads: options.archive?.maxThreads ?? ENRICHMENT_LIMITS.archive.maxThreads,
    resourceLimits: options.archive?.resourceLimits ?? ARCHIVE_THREAD_RESOURCE_LIMITS,
    threadScript: options.archive?.threadScript,
  };
  const runThread: RunArchiveThreadFn = options.archive?.runThread ?? runArchiveInThread;
  const quotaBytes = options.archive?.scanDownloadQuotaBytes ?? ENRICHMENT_LIMITS.archive.scanDownloadQuotaBytes;

  async function enrich(dependencies: readonly EnrichmentDependency[], enrichOptions: EnrichOptions): Promise<EnrichmentResult> {
    if (client === null) return disabledEnrichment(dependencies, true);
    const jobSignal = enrichOptions.signal;
    jobSignal.throwIfAborted();
    const budgetSignal = createBudgetSignal(enrichOptions.budgetMs);
    const signal = AbortSignal.any([jobSignal, budgetSignal]);
    const session = client.session();
    const infos = groupKeys(dependencies);
    const outcomes = new Map<string, DependencyEnrichment>();
    const found = new Map<string, RegistryMetadata>();

    /** Classifies a caught error: job abort rethrown, budget -> `budget`, anything else -> `other`. */
    const classify = (err: unknown): 'budget' | 'other' => {
      if (jobSignal.aborted) throw abortReasonOf(jobSignal);
      if (budgetSignal.aborted) return 'budget';
      warn(`Kayıt defteri zenginleştirmesinde beklenmeyen hata (${errorCodeOf(err)}).`);
      return 'other';
    };

    // 1. Classification without requests.
    const requestable: KeyInfo[] = [];
    for (const info of infos.values()) {
      const status = classified(info);
      if (status !== null) outcomes.set(info.key, noRequestOutcome(info, status));
      else requestable.push(info);
    }

    // 2. Bulk metadata cache read (a failed read means "all misses").
    let cachedMetadata = new Map<string, CachedMetadata>();
    if (requestable.length > 0 && !signal.aborted) {
      try {
        cachedMetadata = await readMetadataCache(
          db,
          requestable.map((info) => {
            const c = info.check as Extract<KeyInfo['check'], { kind: 'ok' }>;
            return { ecosystem: c.ecosystem, name: c.requestName, version: c.version };
          }),
        );
      } catch (err) {
        classify(err);
      }
    }

    const setMetadataOutcome = (info: KeyInfo, outcome: MetadataOutcome | { kind: 'budget_exceeded' }) => {
      if (outcome.kind === 'found') {
        found.set(info.key, outcome.metadata);
        const status = metadataStatus(outcome.metadata);
        outcomes.set(info.key, {
          status,
          registry: info.registry,
          declaredLicense: status === 'ok' ? outcome.metadata.declaredLicense : null,
          noticeStatus: info.runtime ? 'not_attempted' : 'not_runtime',
          noticeArchiveId: null,
        });
        return;
      }
      outcomes.set(info.key, noRequestOutcome(info, outcome.kind));
    };

    // 3. Metadata (cache hit, else request; stale row only on a transient failure).
    await runPool(requestable, config.concurrency, async (info) => {
      const c = info.check as Extract<KeyInfo['check'], { kind: 'ok' }>;
      const cached = cachedMetadata.get(info.key);
      if (cached?.kind === 'hit') {
        setMetadataOutcome(info, cached.outcome);
        return;
      }
      if (signal.aborted) {
        if (jobSignal.aborted) throw abortReasonOf(jobSignal);
        setMetadataOutcome(info, { kind: 'budget_exceeded' });
        return;
      }
      let outcome: MetadataOutcome;
      try {
        outcome =
          c.ecosystem === 'npm'
            ? await fetchNpmMetadata(session, c.requestName, c.version, signal)
            : await fetchPypiMetadata(session, c.requestName, c.version, signal);
      } catch (err) {
        setMetadataOutcome(info, classify(err) === 'budget' ? { kind: 'budget_exceeded' } : { kind: 'error', code: 'UNEXPECTED' });
        return;
      }
      if (outcome.kind === 'found' || outcome.kind === 'not_found') {
        try {
          await writeMetadataCache(db, { ecosystem: c.ecosystem, name: c.requestName, version: c.version }, outcome);
        } catch (err) {
          // Only this record is lost; the in-memory result is used (ADR-006 Karar 2).
          warn(`Kayıt defteri önbelleği yazılamadı (${errorCodeOf(err)}).`);
        }
      } else if (cached?.kind === 'stale') {
        outcome = { kind: 'found', metadata: cached.metadata };
      }
      setMetadataOutcome(info, outcome);
    });

    // 4. Archive stage: runtime keys whose metadata was found.
    const archiveInfos = requestable.filter((info) => info.runtime && found.has(info.key));
    let cachedArchives = new Map<string, CachedArchive>();
    if (archiveInfos.length > 0 && !signal.aborted) {
      const keys = archiveInfos.flatMap((info) => {
        const c = info.check as Extract<KeyInfo['check'], { kind: 'ok' }>;
        return triedCandidates(c.ecosystem, (found.get(info.key) as RegistryMetadata).archiveCandidates).flatMap((candidate) =>
          candidate.digests.map((value) => ({ ecosystem: c.ecosystem, name: c.requestName, version: c.version, digest: digestKey(candidate.algorithm, value) })),
        );
      });
      try {
        cachedArchives = await readArchiveCache(db, keys);
      } catch (err) {
        classify(err);
      }
    }
    const quota = new DownloadQuota(quotaBytes);
    await runPool(archiveInfos, config.concurrency, async (info) => {
      const c = info.check as Extract<KeyInfo['check'], { kind: 'ok' }>;
      const current = outcomes.get(info.key) as DependencyEnrichment;
      const task: ArchiveTask = {
        ecosystem: c.ecosystem,
        requestName: c.requestName,
        version: c.version,
        candidates: (found.get(info.key) as RegistryMetadata).archiveCandidates,
      };
      try {
        if (signal.aborted && triedCandidates(task.ecosystem, task.candidates).length > 0) {
          // Cached results are still used after the budget ran out (no request needed).
          const hit = triedCandidates(task.ecosystem, task.candidates)
            .flatMap((cand) => cand.digests.map((v) => cachedArchives.get(archiveCacheKey(c.ecosystem, c.requestName, c.version, digestKey(cand.algorithm, v)))))
            .find((h) => h !== undefined);
          if (hit) {
            outcomes.set(info.key, { ...current, noticeStatus: hit.outcome, noticeArchiveId: hit.id });
            return;
          }
          signal.throwIfAborted();
        }
        const result = await collectArchive(task, { session, db, signal, cached: cachedArchives, quota, threadOptions, runThread, warn });
        outcomes.set(info.key, { ...current, noticeStatus: result.noticeStatus, noticeArchiveId: result.archiveId });
      } catch (err) {
        const kind = classify(err);
        outcomes.set(info.key, { ...current, noticeStatus: kind === 'budget' ? 'budget_exceeded' : 'processing_failed', noticeArchiveId: null });
      }
    });

    return buildResult(infos.values(), outcomes, 'enabled');
  }

  return {
    enabled: client !== null,
    enrich,
    failed(dependencies) {
      if (client === null) return disabledEnrichment(dependencies, true);
      const infos = groupKeys(dependencies);
      const outcomes = new Map<string, DependencyEnrichment>();
      for (const info of infos.values()) outcomes.set(info.key, noRequestOutcome(info, classified(info) ?? 'error'));
      return buildResult(infos.values(), outcomes, 'enabled');
    },
    close() {
      client?.close();
    },
  };
}
