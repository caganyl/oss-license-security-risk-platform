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

import type { TechEcosystem } from '../types/scan';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ContainerConfig {
  /** Docker image name (without tag). */
  image: string;
  /** Image tag / digest. Pin to a digest in production for supply-chain safety. */
  tag: string;
  /**
   * Memory limit in MiB.
   * Large monorepos with thousands of transitive deps can spike npm/pip usage.
   */
  memoryLimitMb: number;
  /**
   * CPU period + quota expressed as a fraction of one core (0 < value ≤ 1.0).
   * Prevents a single scan from starving other workers on the same host.
   */
  cpuQuota: number;
  /**
   * Docker network mode.
   * - 'none'  : no network after clone; preferred for archive/upload scans.
   * - 'bridge': default Docker bridge; required for HTTPS clone.
   * The worker switches to 'none' after the clone step when running in two-
   * phase mode (future enhancement).
   */
  networkMode: 'none' | 'bridge';
  /** Mount the container's root filesystem read-only except for /workspace. */
  readonlyRootfs: boolean;
  /** Equivalent to --security-opt=no-new-privileges in docker run. */
  noNewPrivileges: boolean;
  /**
   * Linux capabilities to drop.
   * Drop ALL and add back only what git + pip/npm strictly need.
   */
  capDrop: string[];
  capAdd: string[];
  /** Additional --security-opt flags (e.g. seccomp profile path). */
  securityOpts: string[];
}

export interface ScanConfig {
  /**
   * Hard timeout for the entire scan container in milliseconds.
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
   * Always wipe /workspace/<scan_id> on container exit — even on failure.
   * The entrypoint.sh trap handles this; the worker double-checks via
   * `docker volume rm` after the container exits.
   */
  alwaysCleanWorkspace: boolean;
  /**
   * Env var names that carry credentials.  The worker scrubs these from any
   * captured container log lines before persisting them.
   */
  credentialEnvVars: readonly string[];
  /**
   * Remove the stopped container (not just exit) automatically.
   * Maps to `--rm` in docker run.
   */
  autoRemoveContainer: boolean;
}

export interface WorkerConfig {
  /**
   * Maximum number of scan containers that this worker process may run
   * concurrently on the same host.
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
  container: ContainerConfig;
  scan: ScanConfig;
  retry: RetryPolicy;
  cleanup: CleanupPolicy;
  worker: WorkerConfig;
}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

export const sandboxRunnerConfig: SandboxRunnerConfig = {
  container: {
    image: 'oss-risk-platform/sandbox-scanner',
    tag: process.env.SANDBOX_IMAGE_TAG ?? 'latest',
    memoryLimitMb: 1024,
    cpuQuota: 0.5,
    networkMode: 'bridge',
    readonlyRootfs: false,
    noNewPrivileges: true,
    // Drop every capability; the scanner needs none.
    capDrop: ['ALL'],
    capAdd: [],
    securityOpts: [
      'no-new-privileges:true',
      // Uncomment and set path when a custom seccomp profile is available:
      // 'seccomp=/etc/docker/seccomp/scanner.json',
    ],
  },

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
    autoRemoveContainer: true,
  },

  worker: {
    maxConcurrentScans: Number(process.env.WORKER_MAX_CONCURRENT) || 4,
    pollIntervalMs: Number(process.env.WORKER_POLL_INTERVAL_MS) || 5_000,
    workerId: process.env.WORKER_ID
      ?? `${process.env.HOSTNAME ?? 'worker'}-${process.pid}`,
  },
} as const;

// ---------------------------------------------------------------------------
// Docker run flags builder (consumed by the worker when spawning containers)
// ---------------------------------------------------------------------------

export function buildDockerRunFlags(
  scanId: string,
  config: SandboxRunnerConfig = sandboxRunnerConfig,
): string[] {
  const { container, scan, cleanup } = config;

  const flags: string[] = [
    '--name',        `scanner-${scanId}`,
    '--memory',      `${container.memoryLimitMb}m`,
    '--cpus',        String(container.cpuQuota),
    '--network',     container.networkMode,
    '--user',        '10001:10001',
    '--workdir',     '/workspace',
    // Write output to a named tmp volume so the worker can read it on exit
    '--volume',      `scan-${scanId}-workspace:/workspace`,
  ];

  if (container.readonlyRootfs) flags.push('--read-only');
  if (container.noNewPrivileges) flags.push('--security-opt', 'no-new-privileges:true');
  if (cleanup.autoRemoveContainer) flags.push('--rm');

  for (const cap of container.capDrop) {
    flags.push('--cap-drop', cap);
  }
  for (const cap of container.capAdd) {
    flags.push('--cap-add', cap);
  }
  for (const opt of container.securityOpts) {
    flags.push('--security-opt', opt);
  }

  // Env vars injected by the worker at runtime (not stored in config)
  flags.push(
    '--env', `SCAN_ID=${scanId}`,
    '--env', `ECOSYSTEMS=${scan.supportedEcosystems.join(',')}`,
    '--env', `SHALLOW_DEPTH=${scan.shallowDepth}`,
    '--env', `MAX_REPO_MB=${scan.maxRepoSizeMb}`,
  );

  return flags;
}
