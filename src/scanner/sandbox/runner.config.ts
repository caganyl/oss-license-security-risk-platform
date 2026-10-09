/**
 * Sandbox runner configuration.
 *
 * All tunables live here so the worker (src/scanner/worker.ts, yet to be
 * written) and tests import from one authoritative source rather than
 * scattering magic numbers through the codebase.
 *
 * Values that are also stored in the `system_settings` DB table are marked
 * with the key they mirror so the worker can override them at runtime.
 */

import type { TechEcosystem } from '../../types/scan';

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
  /** Base delay between retries in milliseconds (exponential back-off base). */
  initialBackoffMs: number;
  /** Cap on retry delay in milliseconds. */
  maxBackoffMs: number;
}

export interface CleanupPolicy {
  /**
   * Always remove the temporary scan workspace (ossrisk-scan-*) after the
   * scan — even on failure (withTempWorkspace).
   */
  alwaysCleanWorkspace: boolean;
  /**
   * Env var names that carry credentials; they are never passed to the git or
   * parser child processes.
   */
  credentialEnvVars: readonly string[];
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
  /**
   * Unique identifier for this worker instance, written to scans.worker_id.
   * Defaults to hostname + PID if not set via env.
   */
  workerId: string;
}

export interface SandboxRunnerConfig {
  scan: ScanConfig;
  retry: RetryPolicy;
  cleanup: CleanupPolicy;
  worker: WorkerConfig;
}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

export const sandboxRunnerConfig: SandboxRunnerConfig = {
  scan: {
    // 60 minutes — mirrors system_settings scan.timeout_minutes = 60
    timeoutMs: Number(process.env.SCAN_TIMEOUT_MS) || 60 * 60 * 1000,
    shallowDepth: 1,
    maxRepoSizeMb: 512,
    // MVP: Node.js and Python only
    supportedEcosystems: ['nodejs', 'python'],
  },

  retry: {
    // Mirrors system_settings scan.max_retries = 3
    maxAttempts: Number(process.env.SCAN_MAX_RETRIES) || 3,
    initialBackoffMs: 5_000,
    maxBackoffMs: 120_000,
  },

  cleanup: {
    alwaysCleanWorkspace: true,
    credentialEnvVars: ['ACCESS_TOKEN', 'AUTHED_URL'],
  },

  worker: {
    maxConcurrentScans: Number(process.env.WORKER_MAX_CONCURRENT) || 4,
    pollIntervalMs: Number(process.env.WORKER_POLL_INTERVAL_MS) || 5_000,
    workerId: process.env.WORKER_ID
      ?? `${process.env.HOSTNAME ?? 'worker'}-${process.pid}`,
  },
} as const;
