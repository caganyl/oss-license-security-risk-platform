/**
 * Archive stage of one package (REQ-004 AC-P15-1…5, AC-P15-10; ADR-006
 * Karar 6, 7, 10): archive cache -> download (main thread, via the registry
 * session, 64 MiB cap, streamed hash) -> integrity BEFORE parsing -> archive
 * thread -> archive cache write.
 *
 * - npm: the single `dist.tarball` candidate (sha512 from `integrity`, else
 *   sha1 `shasum`, D-83).
 * - PyPI: candidates already ordered by AC-P15-3 (D-65); at most 3 are tried
 *   and only `download_failed` / `integrity_failed` / `limit_exceeded` (size
 *   or quota) moves to the next one.
 * - Cached: the reader's own outcomes (`collected`, `no_license_file`,
 *   `unsupported_format`, `limit_exceeded`). Not cached: download, integrity,
 *   quota, thread failure/OOM/timeout, aborts.
 * - An abort (budget or job) is rethrown; the enricher classifies it.
 */
import { ENRICHMENT_LIMITS } from '../scanner/sandbox/runner.config';
import type { ArchiveThreadInput, ArchiveThreadOptions, ArchiveThreadOutcome } from './archive/archiveThread';
import { type DownloadQuota, type InFlightByteBudget, processInFlightBudget } from './budget';
import { type CacheDb, type CachedArchive, writeArchiveCache } from './cache';
import { type RegistryEcosystem, coordinateKey } from './coordinates';
import { digestKey, verifyDigest } from './integrity';
import type { LockIntegrity } from './lockIntegrity';
import type { RegistrySession } from './registryClient';
import type { ArchiveCandidate, NoticeStatus } from './types';

export interface ArchiveTask {
  ecosystem: RegistryEcosystem;
  requestName: string;
  version: string;
  candidates: readonly ArchiveCandidate[];
  /** NuGet: `.nuspec` `<license type="file">` path (ADR-008 Karar 11). */
  declaredLicensePath?: string | null;
}

export interface ArchiveStageResult {
  noticeStatus: NoticeStatus;
  archiveId: string | null;
  /**
   * NuGet only (ADR-008 Karar 10): `match` (cached row for the lock hash, raw
   * SHA-512 or signed-package content hash equal) or `mismatch` (fail-safe:
   * nothing opened, nothing cached). Absent -> the caller's default.
   */
  lockIntegrity?: LockIntegrity;
}

export type RunArchiveThreadFn = (
  input: ArchiveThreadInput,
  signal: AbortSignal,
  options: ArchiveThreadOptions,
) => Promise<ArchiveThreadOutcome>;

export interface ArchiveStageContext {
  session: RegistrySession;
  db: CacheDb;
  /** Enrichment signal (job + budget). */
  signal: AbortSignal;
  /** Archive cache rows read in bulk (`archiveCacheKey`). */
  cached: ReadonlyMap<string, CachedArchive>;
  quota: DownloadQuota;
  threadOptions: ArchiveThreadOptions;
  runThread: RunArchiveThreadFn;
  warn: (message: string) => void;
  /** In-flight archive byte budget (L-4); default: the process-wide budget. */
  inFlight?: InFlightByteBudget;
}

/** Map key of `readArchiveCache` results. */
export function archiveCacheKey(ecosystem: RegistryEcosystem, requestName: string, version: string, digest: string): string {
  return `${coordinateKey(ecosystem, requestName, version)}\u0000${digest}`;
}

/** Candidates tried for a package (npm: 1, PyPI: up to 3). */
export function triedCandidates(ecosystem: RegistryEcosystem, candidates: readonly ArchiveCandidate[]): ArchiveCandidate[] {
  switch (ecosystem) {
    case 'npm':
    case 'nuget':
      return candidates.slice(0, 1);
    case 'pypi':
      return candidates.slice(0, ENRICHMENT_LIMITS.archive.maxCandidatesTried);
    case 'depsdev':
    case 'pubdev':
      // REQ-011 D-321: no archive stage (the enricher never schedules one).
      return [];
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported registry ecosystem: ${String(unreachable)}`);
    }
  }
}

/**
 * True when the registry has an archive (NOTICE text) stage: npm, PyPI,
 * NuGet. deps.dev / pub.dev keys keep `notice_status = 'not_attempted'` /
 * `'not_runtime'` (REQ-011 D-321: NOTICE shows the SPDX id only).
 */
export function hasArchiveStage(ecosystem: RegistryEcosystem): boolean {
  switch (ecosystem) {
    case 'npm':
    case 'pypi':
    case 'nuget':
      return true;
    case 'depsdev':
    case 'pubdev':
      return false;
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported registry ecosystem: ${String(unreachable)}`);
    }
  }
}

/** Archive request purpose of a registry (exhaustive, ADR-008 Karar 1). */
function archivePurposeOf(ecosystem: RegistryEcosystem): 'archive-npm' | 'archive-pypi' | 'archive-nuget' {
  switch (ecosystem) {
    case 'npm':
      return 'archive-npm';
    case 'pypi':
      return 'archive-pypi';
    case 'nuget':
      return 'archive-nuget';
    case 'depsdev':
    case 'pubdev':
      throw new Error(`registry ecosystem has no archive stage: ${ecosystem}`);
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported registry ecosystem: ${String(unreachable)}`);
    }
  }
}

/** Archive reader kind of a registry with an archive stage (deps.dev / pub.dev have none, D-321). */
function archiveKindOf(ecosystem: RegistryEcosystem): ArchiveThreadInput['kind'] {
  switch (ecosystem) {
    case 'npm':
    case 'pypi':
    case 'nuget':
      return ecosystem;
    case 'depsdev':
    case 'pubdev':
      throw new Error(`registry ecosystem has no archive stage: ${ecosystem}`);
    default: {
      const unreachable: never = ecosystem;
      throw new Error(`unsupported registry ecosystem: ${String(unreachable)}`);
    }
  }
}

function abortError(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const err = new Error('Arşiv toplama iptal edildi.');
  err.name = 'AbortError';
  return err;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

export async function collectArchive(task: ArchiveTask, ctx: ArchiveStageContext): Promise<ArchiveStageResult> {
  const candidates = triedCandidates(task.ecosystem, task.candidates);
  if (candidates.length === 0) return { noticeStatus: 'no_candidate', archiveId: null };
  const purpose = archivePurposeOf(task.ecosystem);
  const nuget = task.ecosystem === 'nuget';
  let last: NoticeStatus = 'download_failed';

  for (const candidate of candidates) {
    for (const value of candidate.digests) {
      const hit = ctx.cached.get(archiveCacheKey(task.ecosystem, task.requestName, task.version, digestKey(candidate.algorithm, value)));
      // NuGet: a row keyed by the lock hash was written only from bytes verified against it (ADR-008 Karar 10.1).
      if (hit) return nuget ? { noticeStatus: hit.outcome, archiveId: hit.id, lockIntegrity: 'match' } : { noticeStatus: hit.outcome, archiveId: hit.id };
    }
    ctx.signal.throwIfAborted();
    const host = hostOf(candidate.url);
    if (host !== null && ctx.session.isHostClosed(host)) return { noticeStatus: 'download_failed', archiveId: null };

    const reserved = candidate.size ?? ENRICHMENT_LIMITS.client.archiveMaxBytes;
    // L-4: hold the expected body size in the process-wide in-flight budget
    // from before the download until the archive thread has finished with the
    // body (waits, never fails; an abort of `ctx.signal` is rethrown like any
    // other abort of this stage). A body larger than declared (the client caps
    // it at `archiveMaxBytes`) is accounted on top without waiting.
    const inFlight = ctx.inFlight ?? processInFlightBudget(ENRICHMENT_LIMITS.archive.processInFlightBytes);
    const held = Math.min(reserved, ENRICHMENT_LIMITS.client.archiveMaxBytes);
    const releases: Array<() => void> = [await inFlight.acquire(held, ctx.signal)];
    let outcome: ArchiveThreadOutcome;
    let download;
    try {
      if (!ctx.quota.reserve(reserved)) return { noticeStatus: 'limit_exceeded', archiveId: null };
      let downloaded = 0;
      try {
        download = await ctx.session.getArchive(candidate.url, purpose, {
          signal: ctx.signal,
          algorithm: candidate.algorithm,
          dedupeKey: `${coordinateKey(task.ecosystem, task.requestName, task.version)}\u0000${candidate.digests[0] ?? ''}`,
        });
        if (download.kind === 'ok') downloaded = download.size;
      } finally {
        // The reservation becomes the real byte count (failed downloads count 0: the client hides partial sizes).
        ctx.quota.settle(reserved, downloaded);
      }
      if (download.kind === 'download_failed') {
        last = 'download_failed';
        continue;
      }
      if (download.kind === 'limit_exceeded') {
        last = 'limit_exceeded';
        continue;
      }
      if (download.size > held) releases.push(inFlight.grow(download.size - held));
      const rawMatch = verifyDigest({ algorithm: candidate.algorithm, values: candidate.digests }, download.digest);
      if (!rawMatch && !nuget) {
        // Integrity before parsing: the buffer is dropped, nothing is cached.
        last = 'integrity_failed';
        continue;
      }

      // NuGet without a raw match: the thread verifies the signed-package content
      // hash first and opens no entry when it differs (ADR-008 Karar 10.2).
      const input: ArchiveThreadInput = { kind: archiveKindOf(task.ecosystem), filename: candidate.filename, bytes: download.body };
      if (nuget) {
        if (task.declaredLicensePath) input.declaredLicensePath = task.declaredLicensePath;
        if (!rawMatch) input.verify = { nugetContentHash: candidate.digests.map((value) => digestKey('sha512', value)) };
      }
      outcome = await ctx.runThread(input, ctx.signal, ctx.threadOptions);
    } finally {
      for (const release of releases) release();
    }
    if (outcome.kind === 'aborted') throw abortError(ctx.signal);
    if (outcome.kind === 'integrity_mismatch') {
      // L-5 fail-safe: the buffer is dropped, nothing is cached, NOTICE is not attempted.
      return { noticeStatus: 'not_attempted', archiveId: null, lockIntegrity: 'mismatch' };
    }
    if (outcome.kind === 'failed') {
      ctx.warn(`Arşiv işlenemedi (${outcome.code}); önbelleğe yazılmadı.`);
      return { noticeStatus: 'processing_failed', archiveId: null };
    }
    const { result } = outcome;
    let archiveId: string | null = null;
    try {
      archiveId =
        (await writeArchiveCache(
          ctx.db,
          {
            ecosystem: task.ecosystem,
            name: task.requestName,
            version: task.version,
            // NuGet rows are keyed by the verified lock hash (raw or content hash), not the raw archive digest.
            digest: nuget ? digestKey('sha512', candidate.digests[0]) : digestKey(candidate.algorithm, download.digest),
          },
          {
            outcome: result.outcome,
            outcomeDetail: result.outcomeDetail,
            licenseFiles: result.licenseFiles,
            copyrightLines: result.copyrightLines,
            archiveUrl: candidate.url,
            archiveSize: download.size,
          },
        )) || null;
    } catch (err) {
      // A failed cache write only loses this record (ADR-006 Karar 2).
      ctx.warn(`Arşiv önbelleği yazılamadı (${errorCodeOf(err)}).`);
    }
    return nuget ? { noticeStatus: result.outcome, archiveId, lockIntegrity: 'match' } : { noticeStatus: result.outcome, archiveId };
  }
  return { noticeStatus: last, archiveId: null };
}

/** Class/code of an error for logs, never its message (ADR-004 Karar 6). */
export function errorCodeOf(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(code)) return code;
  return err instanceof Error && /^[A-Za-z0-9_]{1,64}$/.test(err.name) ? err.name : 'Error';
}
