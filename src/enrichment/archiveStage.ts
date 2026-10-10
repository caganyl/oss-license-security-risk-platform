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
import type { ArchiveThreadOptions, ArchiveThreadOutcome } from './archive/archiveThread';
import type { ArchiveKind } from './archive/extract';
import type { DownloadQuota } from './budget';
import { type CacheDb, type CachedArchive, writeArchiveCache } from './cache';
import { type RegistryEcosystem, coordinateKey } from './coordinates';
import { digestKey, verifyDigest } from './integrity';
import type { RegistrySession } from './registryClient';
import type { ArchiveCandidate, NoticeStatus } from './types';

export interface ArchiveTask {
  ecosystem: RegistryEcosystem;
  requestName: string;
  version: string;
  candidates: readonly ArchiveCandidate[];
}

export interface ArchiveStageResult {
  noticeStatus: NoticeStatus;
  archiveId: string | null;
}

export type RunArchiveThreadFn = (
  input: { kind: ArchiveKind; filename: string | null; bytes: Uint8Array },
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
}

/** Map key of `readArchiveCache` results. */
export function archiveCacheKey(ecosystem: RegistryEcosystem, requestName: string, version: string, digest: string): string {
  return `${coordinateKey(ecosystem, requestName, version)}\u0000${digest}`;
}

/** Candidates tried for a package (npm: 1, PyPI: up to 3). */
export function triedCandidates(ecosystem: RegistryEcosystem, candidates: readonly ArchiveCandidate[]): ArchiveCandidate[] {
  return candidates.slice(0, ecosystem === 'npm' ? 1 : ENRICHMENT_LIMITS.archive.maxCandidatesTried);
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
  const purpose = task.ecosystem === 'npm' ? 'archive-npm' : 'archive-pypi';
  let last: NoticeStatus = 'download_failed';

  for (const candidate of candidates) {
    for (const value of candidate.digests) {
      const hit = ctx.cached.get(archiveCacheKey(task.ecosystem, task.requestName, task.version, digestKey(candidate.algorithm, value)));
      if (hit) return { noticeStatus: hit.outcome, archiveId: hit.id };
    }
    ctx.signal.throwIfAborted();
    const host = hostOf(candidate.url);
    if (host !== null && ctx.session.isHostClosed(host)) return { noticeStatus: 'download_failed', archiveId: null };

    const reserved = candidate.size ?? ENRICHMENT_LIMITS.client.archiveMaxBytes;
    if (!ctx.quota.reserve(reserved)) return { noticeStatus: 'limit_exceeded', archiveId: null };
    let downloaded = 0;
    let download;
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
    if (!verifyDigest({ algorithm: candidate.algorithm, values: candidate.digests }, download.digest)) {
      // Integrity before parsing: the buffer is dropped, nothing is cached.
      last = 'integrity_failed';
      continue;
    }

    const outcome = await ctx.runThread(
      { kind: task.ecosystem, filename: candidate.filename, bytes: download.body },
      ctx.signal,
      ctx.threadOptions,
    );
    if (outcome.kind === 'aborted') throw abortError(ctx.signal);
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
          { ecosystem: task.ecosystem, name: task.requestName, version: task.version, digest: digestKey(candidate.algorithm, download.digest) },
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
    return { noticeStatus: result.outcome, archiveId };
  }
  return { noticeStatus: last, archiveId: null };
}

/** Class/code of an error for logs, never its message (ADR-004 Karar 6). */
export function errorCodeOf(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(code)) return code;
  return err instanceof Error && /^[A-Za-z0-9_]{1,64}$/.test(err.name) ? err.name : 'Error';
}
