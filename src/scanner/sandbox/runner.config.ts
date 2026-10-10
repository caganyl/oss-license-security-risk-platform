/**
 * Scan runner configuration.
 *
 * All tunables live here so the worker (src/scanner/worker.ts) and tests
 * import from one authoritative source rather than scattering magic numbers
 * through the codebase.
 *
 * Values that are also stored in the `system_settings` DB table are marked
 * with the key they mirror so the worker can override them at runtime.
 */

import { boundedNumber } from '../../lib/bounds';
import type { TechEcosystem } from '../../types/scan';

// Upper bounds of the queue settings (security review I-3). Each one keeps
// every derived timer below the `setTimeout` limit (2^31-1 ms, ~24.8 days).
/** `scan.max_retries` / SCAN_MAX_RETRIES: total attempts including the first. */
export const MAX_SCAN_ATTEMPTS = 10;
/** `scan.timeout_minutes`: 24 hours. */
export const MAX_TIMEOUT_MINUTES = 24 * 60;
/** Job/clone/report time limits in ms: 24 hours. */
export const MAX_JOB_TIMEOUT_MS = MAX_TIMEOUT_MINUTES * 60_000;
/** Poll intervals: 1 hour. */
export const MAX_POLL_INTERVAL_MS = 60 * 60_000;
/** Concurrent scans/reports. */
export const MAX_WORKER_CONCURRENCY = 32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// The container section and its run-flag builder were removed with the
// container sandbox (REQ-002 P-03, ADR-002 karar 1): scans run directly on
// this machine in a temporary workspace (src/scanner/workspace.ts).

export interface ScanConfig {
  /**
   * Hard timeout for the dependency parser of one scan in milliseconds.
   * Mirrors system_settings key: scan.timeout_minutes
   */
  timeoutMs: number;
  /**
   * Shallow clone depth passed as --depth to git clone.
   * 1 = tip only (fastest); increase if you need blame/history in parsers.
   */
  shallowDepth: number;
  /**
   * Abort the clone if the remote advertises a pack larger than this (MiB).
   * Passed to git as --filter=blob:limit=<N>m.
   */
  maxRepoSizeMb: number;
  /**
   * Ecosystems enabled in the MVP.  Extend when Java/.NET parsers are ready.
   */
  supportedEcosystems: TechEcosystem[];
}

export interface RetryPolicy {
  /**
   * Maximum number of scan attempts (initial + retries).
   * Mirrors system_settings key: scan.max_retries
   */
  maxAttempts: number;
  /**
   * Wait before the first retry in milliseconds; doubles per retry
   * (`backoffSeconds` in retryPolicy.ts, REQ-003 D-40). No env override.
   */
  initialBackoffMs: number;
  /** Cap on the retry wait in milliseconds (REQ-003 D-40). */
  maxBackoffMs: number;
}

export interface CleanupPolicy {
  /**
   * Always remove the temporary scan workspace (ossrisk-scan-*) after the
   * scan — even on failure (withTempWorkspace).
   */
  alwaysCleanWorkspace: boolean;
  /**
   * Env var names that carry credentials; they are never passed to the git
   * child process. (The parser thread gets no environment at all.)
   */
  credentialEnvVars: readonly string[];
}

/**
 * Dependency parser thread (REQ-003 AC-P10-14, ADR-005 Karar 5). Fixed
 * values, no env override: with WORKER_MAX_CONCURRENT=4 the worst case is
 * ~2 GiB of parser heap. The 32 MiB per-file limit lives in the parsers
 * (src/scanner/parsers/common.ts) because the thread cannot import this file.
 */
export interface ParserConfig {
  resourceLimits: {
    maxOldGenerationSizeMb: number;
    maxYoungGenerationSizeMb: number;
    stackSizeMb: number;
  };
}

export interface WorkerConfig {
  /**
   * Maximum number of scans that this worker process may run concurrently.
   */
  maxConcurrentScans: number;
  /**
   * How often (ms) the worker polls the DB queue for new scan jobs.
   * Lower = lower latency; higher = fewer idle DB round-trips.
   */
  pollIntervalMs: number;
  // scans.worker_id is the per-process run id (src/lib/runId.ts, REQ-003
  // AC-P12-3); there is no worker-id environment variable any more.
}

/**
 * Registry license enrichment (REQ-004 P-14/P-15, ADR-006 Karar 14, D-61).
 * Only the three `REGISTRY_*` settings come from the environment; every
 * limit is a fixed constant (`ENRICHMENT_LIMITS`).
 */
export interface EnrichmentConfig {
  /** `REGISTRY_ENRICHMENT`: `on` (default) / `off`. */
  enabled: boolean;
  /** `REGISTRY_TIMEOUT_MS`: total time of one request attempt (1 ms – 24 h, default 15 000). */
  timeoutMs: number;
  /** `REGISTRY_CONCURRENCY`: process-wide request slots (1–32, default 4). */
  concurrency: number;
}

export interface SandboxRunnerConfig {
  scan: ScanConfig;
  retry: RetryPolicy;
  cleanup: CleanupPolicy;
  worker: WorkerConfig;
  parser: ParserConfig;
  enrichment: EnrichmentConfig;
}

/** Upper bound of `REGISTRY_CONCURRENCY`. */
export const MAX_REGISTRY_CONCURRENCY = 32;

const MiB = 1024 * 1024;

/** Fixed enrichment limits (ADR-006 Karar 4, 6, 7, 14); no environment override. */
export const ENRICHMENT_LIMITS = Object.freeze({
  client: Object.freeze({
    /** Metadata response (network and decompressed bytes). */
    metadataMaxBytes: 8 * MiB,
    /** One package archive. */
    archiveMaxBytes: 64 * MiB,
    /** Archive download time floor: `max(REGISTRY_TIMEOUT_MS, 60 s)`. */
    archiveMinTimeoutMs: 60_000,
    /** Retries after the first attempt, with these waits. */
    maxRetries: 2,
    retryBackoffMs: Object.freeze([1_000, 2_000]) as readonly number[],
    /** A longer `Retry-After` gives up the package (`error`). */
    maxRetryAfterMs: 30_000,
    /** Same-origin metadata redirects. */
    maxRedirects: 3,
    /** Consecutive failed network attempts per host and scan before the host closes. */
    failureThreshold: 5,
  }),
  archive: Object.freeze({
    maxDecompressedBytes: 512 * MiB,
    maxEntries: 100_000,
    maxFileBytes: 1 * MiB,
    maxPackageTextBytes: 4 * MiB,
    maxFiles: 10,
    maxLongNameBytes: 64 * 1024,
    scanDownloadQuotaBytes: 2 * 1024 * MiB,
    threadTimeoutMs: 60_000,
    maxThreads: 2,
    maxCandidatesTried: 3,
    maxCandidatesStored: 32,
  }),
  notice: Object.freeze({
    maxBytes: 64 * MiB,
  }),
});

/** `REGISTRY_ENRICHMENT`: `on`/`off` (case-insensitive); anything else -> default `on` and one warning naming the setting. */
export function parseEnrichmentSwitch(raw: unknown, warn: (message: string) => void = console.warn): boolean {
  if (raw === undefined || raw === null || (typeof raw === 'string' && raw.trim() === '')) return true;
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (value === 'on') return true;
  if (value === 'off') return false;
  warn('REGISTRY_ENRICHMENT geçersiz (on/off); varsayılan on kullanılıyor.');
  return true;
}

/** Enrichment settings from an environment (range-checked like the queue settings, REQ-003 I-3). */
export function enrichmentConfigFrom(source: Readonly<Record<string, string | undefined>>): EnrichmentConfig {
  return {
    enabled: parseEnrichmentSwitch(source.REGISTRY_ENRICHMENT),
    timeoutMs: boundedNumber(source.REGISTRY_TIMEOUT_MS, 15_000, {
      name: 'REGISTRY_TIMEOUT_MS',
      min: 1,
      max: MAX_JOB_TIMEOUT_MS,
      integer: true,
    }),
    concurrency: boundedNumber(source.REGISTRY_CONCURRENCY, 4, {
      name: 'REGISTRY_CONCURRENCY',
      min: 1,
      max: MAX_REGISTRY_CONCURRENCY,
      integer: true,
    }),
  };
}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

// Environment overrides are range-checked (security review I-3): out of range -> default + warning.
const env = process.env;

export const sandboxRunnerConfig: SandboxRunnerConfig = {
  scan: {
    // 60 minutes — mirrors system_settings scan.timeout_minutes = 60
    timeoutMs: boundedNumber(env.SCAN_TIMEOUT_MS, 60 * 60 * 1000, {
      name: 'SCAN_TIMEOUT_MS',
      min: 1,
      max: MAX_JOB_TIMEOUT_MS,
      integer: true,
    }),
    shallowDepth: 1,
    maxRepoSizeMb: 512,
    // MVP: Node.js and Python only
    supportedEcosystems: ['nodejs', 'python'],
  },

  retry: {
    // Mirrors system_settings scan.max_retries = 3
    maxAttempts: boundedNumber(env.SCAN_MAX_RETRIES, 3, {
      name: 'SCAN_MAX_RETRIES',
      min: 1,
      max: MAX_SCAN_ATTEMPTS,
      integer: true,
    }),
    // 30 s, 60 s, 120 s, ... capped at 10 min (REQ-003 D-40, ADR-004 Karar 8).
    initialBackoffMs: 30_000,
    maxBackoffMs: 600_000,
  },

  cleanup: {
    alwaysCleanWorkspace: true,
    credentialEnvVars: ['ACCESS_TOKEN', 'AUTHED_URL'],
  },

  worker: {
    maxConcurrentScans: boundedNumber(env.WORKER_MAX_CONCURRENT, 4, {
      name: 'WORKER_MAX_CONCURRENT',
      min: 1,
      max: MAX_WORKER_CONCURRENCY,
      integer: true,
    }),
    pollIntervalMs: boundedNumber(env.WORKER_POLL_INTERVAL_MS, 5_000, {
      name: 'WORKER_POLL_INTERVAL_MS',
      min: 1,
      max: MAX_POLL_INTERVAL_MS,
      integer: true,
    }),
  },

  parser: {
    resourceLimits: {
      maxOldGenerationSizeMb: 512,
      maxYoungGenerationSizeMb: 64,
      stackSizeMb: 4,
    },
  },

  enrichment: enrichmentConfigFrom(env),
} as const;
