import crypto from 'crypto';
import os from 'os';
import path from 'path';
import type { Pool, PoolClient } from 'pg';
import { errorCode } from '../db/advisoryLock';
import { createRunId } from '../lib/runId';
import { ScanSourceError, canonicalizeScanRoots, parseScanRoots, resolveScanSource } from '../lib/scanSource';
import { sandboxRunnerConfig } from './sandbox/runner.config';
import { ParserFailedError, createThreadParser } from './parsers/threadParser';
import { scanErrorMessage, scanErrorText, shortErrorForLog } from './errorMessage';
import {
  NonRetryableScanError,
  ORPHAN_RECOVERY_MESSAGE,
  ScanAbortError,
  type ScanAbortReason,
  type ScanQueueSettings,
  abortReasonOf,
  classifyScanFailure,
  decideRetry,
  parseScanQueueSettings,
  timeoutMessage,
} from './retryPolicy';
import {
  type CloneRepoFn,
  cloneRepo as defaultCloneRepo,
  isValidRef,
  sweepStaleWorkspaces,
  withTempWorkspace,
} from './workspace';
import { isRuntimeScope, type RunParserFn, type SandboxScanResult } from '../types/scan';
import { computeFindingFingerprint } from '../analysis/findingFingerprint';
import { normalizeLicense } from '../analysis/licenseNormalizer';
import {
  normalizeLegacyVulnerability,
  vulnerabilityLookupService,
  type NormalizedVulnerability,
  type VulnerabilitySeverity,
} from '../analysis/vulnerabilityLookup';

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const STALE_WORKSPACE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Fixed-message error of `decryptToken`. The message never contains the
 * token, the buffer in any encoding or the raw crypto exception (D-14).
 */
export class TokenDecryptionError extends Error {
  constructor(reason: 'key_missing' | 'invalid_data' | 'auth_failed') {
    const detail =
      reason === 'key_missing'
        ? 'ENCRYPTION_KEY is not set'
        : reason === 'invalid_data'
          ? 'invalid encrypted data'
          : 'authentication failed';
    super(`Integration token could not be decrypted: ${detail}`);
    this.name = 'TokenDecryptionError';
  }
}

/**
 * Decrypts `integrations.access_token_enc` (AES-256-GCM, key =
 * SHA-256(ENCRYPTION_KEY), layout `IV(12) | tag(16) | ciphertext`).
 * No token (null/undefined/empty) -> `null`. Otherwise it returns the
 * decrypted token or throws; it never falls back to reading the buffer as
 * plain text (REQ-002 AC-P09-5 / D-14, ADR-002 karar 6).
 */
export function decryptToken(encrypted: Buffer | null | undefined, keyString?: string): string | null {
  if (!encrypted || encrypted.length === 0) return null;
  const keyMaterial = keyString || process.env.ENCRYPTION_KEY;
  if (!keyMaterial) throw new TokenDecryptionError('key_missing');
  if (encrypted.length < IV_LENGTH + TAG_LENGTH) throw new TokenDecryptionError('invalid_data');

  const key = crypto.createHash('sha256').update(keyMaterial).digest();
  const iv = encrypted.subarray(0, IV_LENGTH);
  const tag = encrypted.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = encrypted.subarray(IV_LENGTH + TAG_LENGTH);

  let decrypted: Buffer;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // The crypto exception is dropped on purpose: no detail about the data leaves here.
    throw new TokenDecryptionError('auth_failed');
  }
  return decrypted.toString('utf8');
}

export type { RunParserFn };
export type WorkerLogger = Pick<Console, 'log' | 'warn' | 'error'>;

export interface ScanWorkerDeps {
  db: Pool;
  cloneRepo: CloneRepoFn;
  runParser: RunParserFn;
  scanRoots: string[];
  tmpRoot: string;
  logger: WorkerLogger;
  /**
   * Run id written to `scans.worker_id` and used as the write fence (ADR-004
   * Karar 4). Default: a fresh `createRunId()`; the runtime passes its own.
   */
  runId: string;
}

export { NonRetryableScanError };

/** Options of the (internal) result write. */
interface PersistOptions {
  /** Fence: only a `running` row owned by this run id is written (ADR-004 Karar 4). */
  runId?: string;
  /** Job abort signal: checked before every dependency; abort rolls back. */
  signal?: AbortSignal;
}

/** normalized_license of a runtime package whose license could not be found (AC-P06-1). */
const NO_ASSERTION = 'NOASSERTION';

interface NewFinding {
  scanId: string;
  projectId: string;
  scanDependencyId: string;
  findingType: 'license' | 'security';
  fingerprint: string;
}

interface CarriedDecision {
  findingId: string;
  status: 'false_positive' | 'accepted';
  reviewId: string;
}

interface StoredVulnerability {
  id: string;
  severity: VulnerabilitySeverity;
  cvssScore: number | null;
  osvId: string | null;
  ghsaId: string | null;
  cveId: string | null;
}

/**
 * A claimed scan job. It is in the worker's active set from the claim commit
 * (same tick) until its last write succeeded or was given up (ADR-004 Karar 9).
 */
interface ClaimedJob {
  scanRow: ScanJobRow;
  settings: ScanQueueSettings;
  controller: AbortController;
  timer: NodeJS.Timeout | null;
  /** Resolves when the job has finished (never rejects). */
  done: Promise<void>;
  resolveDone: () => void;
}

interface ScanJobRow {
  id: string;
  project_id: string;
  ref: string | null;
  retry_count: number;
  project_repo_url: string | null;
  integration_repo_url: string | null;
  default_branch: string | null;
  access_token_enc: Buffer | null;
}

export class ScanWorker {
  private polling = false;
  private paused = false;
  private pollTimeout: NodeJS.Timeout | null = null;
  private readonly deps: ScanWorkerDeps;
  /** Active job set (ADR-004 Karar 9): scan id -> job. */
  private readonly activeJobs = new Map<string, ClaimedJob>();

  constructor(deps: Partial<ScanWorkerDeps> = {}) {
    if (!deps.db) {
      // There is no global pool any more (ADR-004 Karar 1): the runtime injects the single pool.
      throw new Error('ScanWorker requires deps.db');
    }
    this.deps = {
      db: deps.db,
      cloneRepo: deps.cloneRepo ?? defaultCloneRepo,
      // TypeScript parsers in a worker_threads thread (REQ-003 P-10, ADR-005 Karar 5).
      runParser: deps.runParser ?? createThreadParser({ resourceLimits: sandboxRunnerConfig.parser.resourceLimits }),
      scanRoots: deps.scanRoots ?? parseScanRoots(process.env.SCAN_ROOTS),
      tmpRoot: deps.tmpRoot ?? os.tmpdir(),
      logger: deps.logger ?? console,
      runId: deps.runId ?? createRunId(),
    };
  }

  private get db(): Pool {
    return this.deps.db;
  }

  private get logger(): WorkerLogger {
    return this.deps.logger;
  }

  /** Run id written to `scans.worker_id` (write fence). */
  public get runId(): string {
    return this.deps.runId;
  }

  /** Ids of the jobs currently in the active set. */
  public get activeScanIds(): string[] {
    return [...this.activeJobs.keys()];
  }

  /**
   * Stand-alone start (tests): canonicalize SCAN_ROOTS, sweep stale
   * workspaces, recover orphaned scans, poll. The runtime runs these steps
   * itself in the ADR-004 Karar 2 order.
   */
  public async start(): Promise<void> {
    // An invalid SCAN_ROOTS entry is an explicit startup error (ADR-002 karar 4).
    this.deps.scanRoots = await canonicalizeScanRoots(this.deps.scanRoots);
    await this.recoverOrphanedScans();
    await this.sweepWorkspaces();
    this.startPolling();
  }

  /** Removes stale `ossrisk-scan-*` folders (best effort). */
  public async sweepWorkspaces(): Promise<void> {
    await sweepStaleWorkspaces(this.deps.tmpRoot, STALE_WORKSPACE_MAX_AGE_MS, this.logger);
  }

  public startPolling(): void {
    if (this.polling) return;
    this.polling = true;
    this.logger.log(`Tarama worker'ı başladı (çalışma kimliği ${this.runId}).`);
    this.schedulePoll(0);
  }

  /** Stops polling (running jobs continue). */
  public stop(): void {
    const wasPolling = this.polling;
    this.polling = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
      this.pollTimeout = null;
    }
    if (wasPolling) this.logger.log("Tarama worker'ı yoklamayı bıraktı.");
  }

  /** Degraded mode (ADR-004 Karar 3): no claims and no orphan sweep; running jobs continue. */
  public pause(): void {
    this.paused = true;
  }

  public resume(): void {
    if (!this.paused) return;
    this.paused = false;
    this.schedulePoll(0);
  }

  /**
   * Aborts every active job with `reason` and resolves once all of them have
   * finished (their own return/failure write included). Never rejects.
   */
  public async abortActiveJobs(reason: ScanAbortReason): Promise<void> {
    const jobs = [...this.activeJobs.values()];
    for (const job of jobs) {
      if (!job.controller.signal.aborted) job.controller.abort(new ScanAbortError(reason));
    }
    await Promise.all(jobs.map((job) => job.done));
  }

  /**
   * One poll iteration processed to the end without the poll loop: orphan
   * sweep, claim of the next pending/queued scan, processing (DB updated).
   * Returns the scan id, or `null` when nothing was claimable.
   */
  public async runOnce(): Promise<string | null> {
    await this.recoverOrphanedScans();
    const job = await this.claimNextJob();
    if (!job) return null;
    await this.processJob(job);
    return job.scanRow.id;
  }

  /**
   * Orphan recovery (AC-P12-11, ADR-004 Karar 9): every `running` scan that
   * is not in this process's active set is handled as a transient failure
   * (retry with backoff, or `failed` + `scan_failed` when no attempt is left),
   * independent of its `worker_id`. Safe only under the single-instance lock.
   * At start-up the active set is empty, so all `running` rows are recovered.
   * Errors are logged (class/code only), never thrown.
   */
  public async recoverOrphanedScans(): Promise<number> {
    let client: PoolClient | null = null;
    try {
      client = await this.db.connect();
      await client.query('BEGIN');
      const settings = await this.readSettings(client);
      const orphans = await client.query<{ id: string; retry_count: number }>(
        `SELECT id, retry_count FROM scans
         WHERE status = 'running' AND NOT (id = ANY($1::uuid[]))
         ORDER BY created_at
         FOR UPDATE SKIP LOCKED`,
        [this.activeScanIds],
      );
      const logs: string[] = [];
      for (const row of orphans.rows) {
        const decision = decideRetry('transient', row.retry_count, settings.maxAttempts);
        const message = scanErrorText(ORPHAN_RECOVERY_MESSAGE);
        if (decision.action === 'retry') {
          const res = await client.query<{ next_attempt_at: Date }>(
            `UPDATE scans
             SET status = 'queued', retry_count = $2,
                 next_attempt_at = NOW() + make_interval(secs => $3),
                 error_message = $4, worker_id = NULL, updated_at = NOW()
             WHERE id = $1 AND status = 'running'
             RETURNING next_attempt_at`,
            [row.id, decision.attempt, decision.delaySeconds, message],
          );
          logs.push(retryLogLine(row.id, decision.attempt, decision.maxAttempts, res.rows[0]?.next_attempt_at, message));
        } else {
          await client.query(
            `UPDATE scans
             SET status = 'failed', completed_at = NOW(), next_attempt_at = NULL,
                 error_message = $2, updated_at = NOW()
             WHERE id = $1 AND status = 'running'`,
            [row.id, message],
          );
          await client.query(
            `INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
             VALUES ('scan_failed', 'scan', $1, NOW())`,
            [row.id],
          );
          logs.push(`Tarama ${row.id} sahipsiz kaldı ve deneme hakkı bitti (${decision.attempt}/${decision.maxAttempts}); failed.`);
        }
      }
      await client.query('COMMIT');
      for (const line of logs) this.logger.warn(line);
      return orphans.rows.length;
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => undefined);
      this.logger.error(`Sahipsiz tarama kurtarma başarısız (${errorCode(err)}).`);
      return 0;
    } finally {
      client?.release();
    }
  }

  private schedulePoll(delayMs: number): void {
    if (!this.polling || this.paused) return;
    if (this.pollTimeout) clearTimeout(this.pollTimeout);
    this.pollTimeout = setTimeout(() => {
      this.pollTimeout = null;
      this.poll().catch((err) => {
        this.logger.error(`Tarama yoklaması başarısız (${errorCode(err)}).`);
        this.schedulePoll(sandboxRunnerConfig.worker.pollIntervalMs);
      });
    }, delayMs);
  }

  private async poll(): Promise<void> {
    if (!this.polling || this.paused) return;

    const maxConcurrent = sandboxRunnerConfig.worker.maxConcurrentScans;
    if (this.activeJobs.size >= maxConcurrent) {
      this.schedulePoll(sandboxRunnerConfig.worker.pollIntervalMs);
      return;
    }

    try {
      // Orphan sweep before every claim (ADR-004 Karar 9); logs its own errors.
      await this.recoverOrphanedScans();
      if (!this.polling || this.paused) return;
      const job = await this.claimNextJob();
      if (job) {
        // Run asynchronously; poll again when it ends (processJob never rejects).
        this.processJob(job).finally(() => this.schedulePoll(0));
        if (this.activeJobs.size < maxConcurrent) {
          this.schedulePoll(0);
          return;
        }
      }
    } catch (err) {
      // Database outage (AC-P12-8): log the class only and retry on the next poll.
      this.logger.error(`Tarama işi sahiplenilemedi (${errorCode(err)}).`);
    }

    this.schedulePoll(sandboxRunnerConfig.worker.pollIntervalMs);
  }

  private async readSettings(client: PoolClient): Promise<ScanQueueSettings> {
    const res = await client.query<{ key: string; value: unknown }>(
      `SELECT key, value FROM system_settings WHERE key IN ('scan.max_retries', 'scan.timeout_minutes')`,
    );
    return parseScanQueueSettings(res.rows);
  }

  private async claimNextJob(): Promise<ClaimedJob | null> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      const settings = await this.readSettings(client);

      // Claim query of ADR-004 Karar 8: a retry waiting for its backoff is
      // skipped, so it never blocks a newer scan (AC-P13-7).
      const scanResult = await client.query(
        `
        SELECT s.id, s.project_id, s.integration_id, s.ref, s.ref_type, s.retry_count,
               p.repo_url as project_repo_url,
               i.repo_url as integration_repo_url, i.default_branch, i.access_token_enc
        FROM scans s
        JOIN projects p ON p.id = s.project_id
        LEFT JOIN integrations i ON i.id = s.integration_id
        WHERE s.status IN ('pending', 'queued')
          AND s.retry_count < $1
          AND (s.next_attempt_at IS NULL OR s.next_attempt_at <= NOW())
        ORDER BY s.created_at ASC
        LIMIT 1
        FOR UPDATE OF s SKIP LOCKED
        `,
        [settings.maxAttempts]
      );

      if (scanResult.rows.length === 0) {
        await client.query('COMMIT');
        return null;
      }

      const scanRow = scanResult.rows[0];

      // timeout_at is informational (AC-P13-6); the local timer decides.
      // A fractional scan.timeout_minutes is allowed, hence the interval product.
      await client.query(
        `
        UPDATE scans
        SET status = 'running',
            worker_id = $1,
            started_at = NOW(),
            timeout_at = NOW() + ($3::double precision * INTERVAL '1 minute'),
            next_attempt_at = NULL,
            updated_at = NOW()
        WHERE id = $2
        `,
        [this.runId, scanRow.id, settings.timeoutMinutes]
      );

      // Log the start action
      await client.query(
        `
        INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
        VALUES ('scan_started', 'scan', $1, NOW())
        `,
        [scanRow.id]
      );

      await client.query('COMMIT');
      // No await between the commit and the active-set insert (ADR-004
      // implementer warning 4): the orphan sweep must never see this row
      // as `running` without its job.
      return this.registerJob(scanRow, settings);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  private registerJob(scanRow: ScanJobRow, settings: ScanQueueSettings): ClaimedJob {
    let resolveDone: () => void = () => undefined;
    const done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });
    const controller = new AbortController();
    const job: ClaimedJob = { scanRow, settings, controller, timer: null, done, resolveDone };
    // Job time limit (D-42, AC-P13-6): covers clone, parse, OSV and the result write.
    job.timer = setTimeout(() => {
      if (!controller.signal.aborted) controller.abort(new ScanAbortError('timeout'));
    }, settings.timeoutMinutes * 60_000);
    this.activeJobs.set(scanRow.id, job);
    return job;
  }

  /**
   * Single execution path (ADR-002 karar 1): decrypt token -> classify the
   * source (TOCTOU re-check) -> local directory in place, or shallow clone
   * into a temp workspace -> parser (worker thread) -> results. There is no other folder to
   * fall back to: an unresolvable source fails the scan.
   */
  private async processJob(job: ClaimedJob): Promise<void> {
    const { scanRow } = job;
    const scanId = scanRow.id;
    const signal = job.controller.signal;
    this.logger.log(`Starting execution of scan ${scanId} (project ${scanRow.project_id})...`);
    try {
      signal.throwIfAborted();
      // Before any clone: a token that cannot be decrypted fails the scan (D-14).
      let token: string | null;
      try {
        token = decryptToken(scanRow.access_token_enc);
      } catch (err) {
        throw new NonRetryableScanError((err as Error).message);
      }

      const repoUrl = scanRow.integration_repo_url || scanRow.project_repo_url;
      if (!repoUrl) {
        throw new NonRetryableScanError('Project has no repository URL or local path to scan');
      }
      let source;
      try {
        source = await resolveScanSource(repoUrl, this.deps.scanRoots);
      } catch (err) {
        if (err instanceof ScanSourceError) throw new NonRetryableScanError(err.message);
        throw err;
      }

      const ecosystems = await this.loadEcosystems(scanRow.project_id);
      let result: SandboxScanResult;
      signal.throwIfAborted();
      if (source.kind === 'local') {
        result = await this.deps.runParser(source.path, ecosystems, scanId, signal);
      } else {
        const ref = scanRow.ref || scanRow.default_branch || null;
        if (ref !== null && !isValidRef(ref)) {
          throw new NonRetryableScanError('Invalid git ref for the scan');
        }
        const remoteUrl = source.url;
        result = await withTempWorkspace(
          async (workspace) => {
            const repoDir = path.join(workspace, 'repo');
            // The clone and the parser thread are awaited (killed/terminated on
            // abort) before withTempWorkspace removes the folder.
            await this.deps.cloneRepo(remoteUrl, ref, repoDir, token, signal);
            signal.throwIfAborted();
            return this.deps.runParser(repoDir, ecosystems, scanId, signal);
          },
          { tmpRoot: this.deps.tmpRoot, logger: this.logger },
        );
      }

      if (result.status === 'failed') {
        // Permanent (D-41): the same input fails the same way.
        throw new ParserFailedError('Dependency parser reported a parsing failure.');
      }
      this.logger.log(`Scan ${scanId} parsed. Writing ${result.total_deps} dependencies to the database...`);
      const stored = await this.persistResults(scanId, scanRow.project_id, result, { runId: this.runId, signal });
      if (stored) this.logger.log(`Scan ${scanId} results stored.`);
    } catch (err) {
      await this.handleScanFailure(job, err);
    } finally {
      if (job.timer) clearTimeout(job.timer);
      job.timer = null;
      // Removed only after the last write succeeded or was given up (ADR-004 Karar 9).
      this.activeJobs.delete(scanId);
      job.resolveDone();
    }
  }

  private async loadEcosystems(projectId: string): Promise<string[]> {
    let ecosystems: string[] = [];
    try {
      const stackResult = await this.db.query<{ ecosystem: string }>(
        'SELECT ecosystem FROM project_tech_stacks WHERE project_id = $1',
        [projectId]
      );
      ecosystems = stackResult.rows
        .map((r) => r.ecosystem)
        .filter((e) => e === 'nodejs' || e === 'python');
    } catch (err) {
      this.logger.warn(`Warning: failed to fetch tech stack for project ${projectId}:`, err);
    }
    // Fallback to all supported MVP ecosystems
    return ecosystems.length > 0 ? ecosystems : ['nodejs', 'python'];
  }

  /**
   * Writes a parse result for `scanId` (tests call it directly). Without the
   * run-id fence: the internal job path uses the fenced `persistResults`.
   */
  public async saveScanResults(
    scanId: string,
    projectId: string,
    result: SandboxScanResult
  ): Promise<void> {
    await this.persistResults(scanId, projectId, result, {});
  }

  /**
   * Result write transaction. With `options.runId` it first locks the row
   * with the fence (`status = 'running' AND worker_id = $runId`); if the row
   * is no longer ours the result is dropped (returns false, ADR-004 Karar 4).
   * `options.signal` is checked before every dependency; an abort rolls back.
   */
  private async persistResults(
    scanId: string,
    projectId: string,
    result: SandboxScanResult,
    options: PersistOptions,
  ): Promise<boolean> {
    const { runId, signal } = options;
    const vulnerabilityLookup = await vulnerabilityLookupService.lookupDependencies(result.dependencies, signal);
    signal?.throwIfAborted();
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      if (runId !== undefined) {
        const owned = await client.query(
          `SELECT id FROM scans WHERE id = $1 AND status = 'running' AND worker_id = $2 FOR UPDATE`,
          [scanId, runId],
        );
        if (owned.rows.length === 0) {
          await client.query('ROLLBACK');
          this.logger.warn(`Tarama ${scanId} başka bir örnek tarafından devralındı; sonuç atıldı.`);
          return false;
        }
      }

      let totalVulns = 0;
      let criticalVulns = 0;
      let highVulns = 0;
      let mediumVulns = 0;
      let lowVulns = 0;
      let licenseViolations = 0;

      // Fetch SLA settings
      const slaResult = await client.query(
        `SELECT key, value FROM system_settings WHERE key LIKE 'sla.%'`
      );
      const slaDays: Record<string, number> = {
        critical: 7,
        high: 30,
        medium: 90,
        low: 180,
      };
      for (const row of slaResult.rows) {
        const severity = row.key.split('.')[1];
        slaDays[severity] = Number(row.value);
      }

      // One finding per fingerprint per scan (ADR-003 c, AC-P08-2): the same
      // package in several manifests stays in the inventory but is reported once.
      const seenFingerprints = new Set<string>();
      const openFinding = (spec: Omit<NewFinding, 'scanId' | 'projectId' | 'scanDependencyId'>, scanDependencyId: string) =>
        this.insertFinding(client, seenFingerprints, { ...spec, scanId, projectId, scanDependencyId });

      // Process dependencies
      for (const dep of result.dependencies) {
        // Abort (time limit/shutdown) rolls the whole write back (ADR-004 Karar 7).
        signal?.throwIfAborted();
        const scope = dep.scope || 'direct';
        // packages.version holds only an exact version; unknown -> NULL (ADR-003 a).
        const version = dep.version === null || dep.version === undefined || dep.version === '' ? null : dep.version;

        // Insert package (deduplicated). purl is a deterministic function of
        // (ecosystem, normalised name, version), so it is the conflict target;
        // this also covers the versionless partial unique index.
        const pkgResult = await client.query<{ id: string; purl: string; version: string | null }>(
          `
          INSERT INTO packages (ecosystem, name, version, purl)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (purl) DO UPDATE SET purl = EXCLUDED.purl
          RETURNING id, purl, version
          `,
          [dep.ecosystem, dep.name, version, dep.purl]
        );
        const pkg = pkgResult.rows[0];
        const packageId = pkg.id;

        // Insert scan dependency; the declared range is a per-manifest fact.
        const depResult = await client.query(
          `
          INSERT INTO scan_dependencies (scan_id, package_id, scope, manifest_file, manifest_path, depth, declared_range)
          VALUES ($1, $2, $3, $4, $5, 0, $6)
          ON CONFLICT (scan_id, package_id, manifest_path, scope) DO NOTHING
          RETURNING id
          `,
          [scanId, packageId, scope, dep.manifest_file, dep.manifest_path, dep.declared_range ?? null]
        );

        let scanDepId: string;
        if (depResult.rows.length > 0) {
          scanDepId = depResult.rows[0].id;
        } else {
          const getDepId = await client.query(
            `
            SELECT id FROM scan_dependencies
            WHERE scan_id = $1 AND package_id = $2 AND manifest_path = $3 AND scope = $4
            `,
            [scanId, packageId, dep.manifest_path, scope]
          );
          scanDepId = getDepId.rows[0].id;
        }

        // License policy applies to runtime scope only (ADR-003 b, AC-P07-1…3):
        // a dev package stays in the inventory but is never a violation.
        const runtime = isRuntimeScope(scope);

        if (runtime && (!dep.licenses || dep.licenses.length === 0)) {
          // No license found for a runtime package -> "unknown" finding (AC-P06-1).
          const opened = await openFinding({
            findingType: 'license',
            fingerprint: computeFindingFingerprint({
              projectId, purl: pkg.purl, version: pkg.version, findingType: 'license', normalizedLicense: NO_ASSERTION,
            }),
          }, scanDepId);
          if (opened) {
            licenseViolations++;
            await client.query(
              `
              INSERT INTO license_findings (finding_id, license_id, detected_license, normalized_license, risk_level, applied_policy)
              VALUES ($1, NULL, NULL, $2, 'unknown', NULL)
              `,
              [opened, NO_ASSERTION]
            );
          }
        }

        // Process licenses and evaluate policy risk
        if (runtime && dep.licenses && dep.licenses.length > 0) {
          for (const rawLicense of dep.licenses) {
            const norm = normalizeLicense(rawLicense);

            // Look up by canonical SPDX ID first; fall back to raw string for unlisted licenses
            const lookupKey = norm.spdxId || rawLicense;
            const licResult = await client.query(
              `SELECT id, risk_level, spdx_id FROM licenses WHERE spdx_id = $1`,
              [lookupKey]
            );

            let licenseId: string | null = null;
            // DB is authoritative when the license is catalogued; engine risk is the fallback
            let riskLevel: string = norm.riskLevel;
            let normalizedLicense: string = norm.normalized;

            if (licResult.rows.length > 0) {
              licenseId = licResult.rows[0].id;
              riskLevel = licResult.rows[0].risk_level;
              normalizedLicense = licResult.rows[0].spdx_id || norm.normalized;
            }

            // Look up license policies
            let policy: string | null = null;
            if (licenseId) {
              const polResult = await client.query(
                `
                SELECT policy FROM license_policies
                WHERE license_id = $1 AND (project_id IS NULL OR project_id = $2)
                ORDER BY project_id DESC
                LIMIT 1
                `,
                [licenseId, projectId]
              );
              if (polResult.rows.length > 0) {
                policy = polResult.rows[0].policy;
              }
            }

            const isViolation =
              policy === 'prohibited' ||
              policy === 'restricted' ||
              policy === 'review_required' ||
              (!policy && (riskLevel === 'high' || riskLevel === 'critical' || riskLevel === 'unknown'));

            if (isViolation) {
              const findingId = await openFinding({
                findingType: 'license',
                fingerprint: computeFindingFingerprint({
                  projectId, purl: pkg.purl, version: pkg.version, findingType: 'license', normalizedLicense,
                }),
              }, scanDepId);
              if (!findingId) continue;
              licenseViolations++;

              await client.query(
                `
                INSERT INTO license_findings (finding_id, license_id, detected_license, normalized_license, risk_level, applied_policy)
                VALUES ($1, $2, $3, $4, $5, $6)
                `,
                [findingId, licenseId, rawLicense, normalizedLicense, riskLevel, policy]
              );
            }
          }
        }

        const lookupKey = vulnerabilityLookupService.dependencyKey(dep);
        const lookedUpVulnerabilities = vulnerabilityLookup.get(lookupKey) || [];
        const legacyVulnerabilities = (dep.vulnerabilities || [])
          .map((vuln) => normalizeLegacyVulnerability(vuln, dep));
        // No vulnerability matching without an exact version (ADR-003 a): a range
        // would flood the results with false positives.
        const vulnerabilities = version === null ? [] : mergeVulnerabilities([
          ...lookedUpVulnerabilities,
          ...legacyVulnerabilities,
        ]);

        // Process vulnerabilities and generate security findings
        if (vulnerabilities.length > 0) {
          for (const vuln of vulnerabilities) {
            const storedVuln = await this.upsertVulnerability(client, vuln);
            const vulnId = storedVuln.id;
            const severity = storedVuln.severity;
            const cvssScore = storedVuln.cvssScore;

            const findingId = await openFinding({
              findingType: 'security',
              fingerprint: computeFindingFingerprint({
                projectId,
                purl: pkg.purl,
                version: pkg.version,
                findingType: 'security',
                vulnerability: { id: vulnId, osvId: storedVuln.osvId, ghsaId: storedVuln.ghsaId, cveId: storedVuln.cveId },
              }),
            }, scanDepId);
            if (!findingId) continue;

            totalVulns++;
            if (severity === 'critical') criticalVulns++;
            else if (severity === 'high') highVulns++;
            else if (severity === 'medium') mediumVulns++;
            else if (severity === 'low') lowVulns++;

            const days = slaDays[severity] ?? 90;
            const slaDeadline = new Date();
            slaDeadline.setDate(slaDeadline.getDate() + days);

            const fixVersion = vuln.fixedVersion;
            const fixAvailable = Boolean(vuln.fixedVersion);

            await client.query(
              `
              INSERT INTO security_findings (finding_id, vulnerability_id, severity, cvss_score, fix_version, sla_deadline, fix_available)
              VALUES ($1, $2, $3, $4, $5, $6, $7)
              `,
              [findingId, vulnId, severity, cvssScore, fixVersion, slaDeadline, fixAvailable]
            );
          }
        }
      }

      // Save scanned files
      for (const file of result.scan_files) {
        await client.query(
          `
          INSERT INTO scan_files (scan_id, filename, file_path, ecosystem, file_hash, size_bytes)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT DO NOTHING
          `,
          [scanId, file.filename, file.file_path, file.ecosystem, file.file_hash, file.size_bytes]
        );
      }

      // Handle warnings from parse errors if any
      let warningMsg: string | null = null;
      if (result.parse_errors && result.parse_errors.length > 0) {
        warningMsg = scanErrorText(result.parse_errors
          .map(pe => `[${pe.ecosystem}] File ${pe.file}: ${pe.error}`)
          .join('\n'));
      }

      signal?.throwIfAborted();
      // Update scan row (fenced when called for a claimed job).
      const updated = await client.query(
        `
        UPDATE scans
        SET status = 'completed',
            completed_at = NOW(),
            total_dependencies = $1,
            total_vulnerabilities = $2,
            critical_vulns = $3,
            high_vulns = $4,
            medium_vulns = $5,
            low_vulns = $6,
            license_violations = $7,
            error_message = COALESCE(error_message, $8),
            next_attempt_at = NULL,
            updated_at = NOW()
        WHERE id = $9
          AND ($10::text IS NULL OR (status = 'running' AND worker_id = $10::text))
        `,
        [
          result.total_deps,
          totalVulns,
          criticalVulns,
          highVulns,
          mediumVulns,
          lowVulns,
          licenseViolations,
          warningMsg,
          scanId,
          runId ?? null,
        ]
      );
      if (runId !== undefined && updated.rowCount !== 1) {
        await client.query('ROLLBACK');
        this.logger.warn(`Tarama ${scanId} başka bir örnek tarafından devralındı; sonuç atıldı.`);
        return false;
      }

      // Audit log scan completed
      await client.query(
        `
        INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
        VALUES ('scan_completed', 'scan', $1, NOW())
        `,
        [scanId]
      );

      await client.query('COMMIT');
      return true;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  private async upsertVulnerability(
    client: PoolClient,
    vuln: NormalizedVulnerability
  ): Promise<StoredVulnerability> {
    const identifiers = Array.from(new Set([
      vuln.cveId,
      vuln.ghsaId,
      vuln.osvId,
      vuln.sourceId,
      ...vuln.aliases,
    ].filter(Boolean))) as string[];

    const existing = await client.query(
      `
      SELECT v.id
      FROM vulnerabilities v
      LEFT JOIN vulnerability_aliases va ON va.vulnerability_id = v.id
      WHERE v.cve_id = ANY($1::text[])
         OR v.ghsa_id = ANY($1::text[])
         OR v.osv_id = ANY($1::text[])
         OR va.alias_id = ANY($1::text[])
      LIMIT 1
      `,
      [identifiers]
    );

    let vulnerabilityId: string;
    // The identifiers as stored (COALESCE keeps older values): the fingerprint
    // must use the same columns as the SQL backfill.
    let storedIds: { osv_id: string | null; ghsa_id: string | null; cve_id: string | null };

    if (existing.rows.length > 0) {
      vulnerabilityId = existing.rows[0].id;
      const updated = await client.query(
        `
        UPDATE vulnerabilities
        SET cve_id = COALESCE(vulnerabilities.cve_id, $2),
            ghsa_id = COALESCE(vulnerabilities.ghsa_id, $3),
            osv_id = COALESCE(vulnerabilities.osv_id, $4),
            title = $5,
            description = COALESCE($6, vulnerabilities.description),
            severity = $7,
            cvss_score = $8,
            cvss_vector = $9,
            cvss_version = $10,
            affected_ecosystem = $11,
            affected_package = $12,
            affected_versions = $13,
            fixed_version = $14,
            published_at = COALESCE($15, vulnerabilities.published_at),
            last_modified_at = COALESCE($16, vulnerabilities.last_modified_at),
            advisory_data = $17::jsonb,
            source = 'osv',
            source_url = $18,
            updated_at = NOW()
        WHERE id = $1
        RETURNING osv_id, ghsa_id, cve_id
        `,
        [
          vulnerabilityId,
          vuln.cveId,
          vuln.ghsaId,
          vuln.osvId,
          vuln.title,
          vuln.description,
          vuln.severity,
          vuln.cvssScore,
          vuln.cvssVector,
          vuln.cvssVersion,
          vuln.affectedEcosystem,
          vuln.affectedPackage,
          vuln.affectedVersions,
          vuln.fixedVersion,
          vuln.publishedAt,
          vuln.lastModifiedAt,
          JSON.stringify(vuln.advisoryData),
          vuln.sourceUrl,
        ]
      );
      storedIds = updated.rows[0];
    } else {
      const inserted = await client.query(
        `
        INSERT INTO vulnerabilities (
          cve_id, ghsa_id, osv_id, title, description, severity, cvss_score,
          cvss_vector, cvss_version, affected_ecosystem, affected_package,
          affected_versions, fixed_version, published_at, last_modified_at,
          advisory_data, source, source_url
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, 'osv', $17)
        RETURNING id, osv_id, ghsa_id, cve_id
        `,
        [
          vuln.cveId,
          vuln.ghsaId,
          vuln.osvId,
          vuln.title,
          vuln.description,
          vuln.severity,
          vuln.cvssScore,
          vuln.cvssVector,
          vuln.cvssVersion,
          vuln.affectedEcosystem,
          vuln.affectedPackage,
          vuln.affectedVersions,
          vuln.fixedVersion,
          vuln.publishedAt,
          vuln.lastModifiedAt,
          JSON.stringify(vuln.advisoryData),
          vuln.sourceUrl,
        ]
      );
      vulnerabilityId = inserted.rows[0].id;
      storedIds = inserted.rows[0];
    }

    for (const alias of identifiers) {
      const aliasType = alias.startsWith('CVE-')
        ? 'cve'
        : alias.startsWith('GHSA-')
          ? 'ghsa'
          : alias.startsWith('SNYK-')
            ? 'snyk'
            : 'osv';

      await client.query(
        `
        INSERT INTO vulnerability_aliases (vulnerability_id, alias_id, alias_type)
        VALUES ($1, $2, $3)
        ON CONFLICT (vulnerability_id, alias_id) DO NOTHING
        `,
        [vulnerabilityId, alias, aliasType]
      );
    }

    return {
      id: vulnerabilityId,
      severity: vuln.severity,
      cvssScore: vuln.cvssScore,
      osvId: storedIds.osv_id,
      ghsaId: storedIds.ghsa_id,
      cveId: storedIds.cve_id,
    };
  }

  /**
   * Inserts a finding with its fingerprint unless one with the same
   * fingerprint was already opened in this scan (returns null then).
   * Decision carry-over (ADR-003 c): the latest finding of the same project
   * with the same fingerprint from another scan decides the initial status —
   * false_positive and an unexpired risk acceptance (accepted_until >=
   * CURRENT_DATE) are carried with a copy of their review; an expired or
   * open-ended acceptance, wont_fix and every other status open a new `open`
   * finding and leave the old one untouched.
   */
  private async insertFinding(client: PoolClient, seen: Set<string>, finding: NewFinding): Promise<string | null> {
    if (seen.has(finding.fingerprint)) return null;
    seen.add(finding.fingerprint);

    const carry = await this.findCarriedDecision(client, finding);
    const inserted = await client.query<{ id: string }>(
      `
      INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status, fingerprint, carried_from_finding_id)
      VALUES ($1, $2, $3::finding_type, $4::finding_status, $5, $6)
      RETURNING id
      `,
      [
        finding.scanId,
        finding.scanDependencyId,
        finding.findingType,
        carry ? carry.status : 'open',
        finding.fingerprint,
        carry ? carry.findingId : null,
      ]
    );
    const findingId = inserted.rows[0].id;

    if (carry) {
      await client.query(
        `
        INSERT INTO finding_reviews (finding_id, decision, reviewer_id, accepted_until, target_version, notes)
        SELECT $1, decision, reviewer_id, accepted_until, target_version, $3
        FROM finding_reviews
        WHERE id = $2
        `,
        [findingId, carry.reviewId, `${carry.findingId} bulgusundan taşındı`]
      );
    }
    return findingId;
  }

  private async findCarriedDecision(client: PoolClient, finding: NewFinding): Promise<CarriedDecision | null> {
    // project_id is part of the fingerprint; the scans join is a defensive filter.
    const previous = await client.query<{ id: string; status: string }>(
      `
      SELECT f.id, f.status::text AS status
      FROM findings f
      JOIN scans s ON s.id = f.scan_id
      WHERE f.fingerprint = $1 AND s.project_id = $2 AND f.scan_id <> $3
      ORDER BY f.created_at DESC, s.created_at DESC
      LIMIT 1
      `,
      [finding.fingerprint, finding.projectId, finding.scanId]
    );
    const last = previous.rows[0];
    if (!last || (last.status !== 'false_positive' && last.status !== 'accepted')) return null;

    const decision = last.status === 'false_positive' ? 'false_positive' : 'accept_risk';
    const review = await client.query<{ id: string; still_valid: boolean }>(
      `
      SELECT id, (accepted_until IS NOT NULL AND accepted_until >= CURRENT_DATE) AS still_valid
      FROM finding_reviews
      WHERE finding_id = $1 AND decision = $2::review_decision
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [last.id, decision]
    );
    const source = review.rows[0];
    // A closed status without its review has no auditable reason: do not carry.
    if (!source) return null;
    if (decision === 'accept_risk' && !source.still_valid) return null;
    return { findingId: last.id, status: last.status as 'false_positive' | 'accepted', reviewId: source.id };
  }

  /**
   * Failure/abort write of a claimed job (ADR-004 Karar 5, 8). Every UPDATE
   * is fenced with `status = 'running' AND worker_id = $runId`. Never throws:
   * if the write itself fails the row stays `running` and the next orphan
   * sweep recovers it (ADR-004 Karar 6, 9).
   */
  private async handleScanFailure(job: ClaimedJob, err: unknown): Promise<void> {
    const scanId = job.scanRow.id;
    const signal = job.controller.signal;
    const failureClass = classifyScanFailure(err, signal);
    let client: PoolClient | null = null;
    try {
      client = await this.db.connect();

      if (failureClass === 'return-to-queue') {
        // Shutdown return: retry_count, error_message unchanged (AC-P12-10).
        const res = await client.query(
          `UPDATE scans
           SET status = 'queued', next_attempt_at = NULL, worker_id = NULL, updated_at = NOW()
           WHERE id = $1 AND status = 'running' AND worker_id = $2`,
          [scanId, this.runId],
        );
        this.logger.log(
          res.rowCount === 1
            ? `Tarama ${scanId} kapanış nedeniyle durduruldu ve kuyruğa geri bırakıldı.`
            : `Tarama ${scanId} başka bir örnek tarafından devralındı; iade yazılmadı.`,
        );
        return;
      }

      const message = scanErrorText(
        abortReasonOf(signal) === 'timeout' ? timeoutMessage(job.settings.timeoutMinutes) : scanErrorMessage(err),
      );
      const decision = decideRetry(failureClass, job.scanRow.retry_count, job.settings.maxAttempts);

      await client.query('BEGIN');
      if (decision.action === 'retry') {
        const res = await client.query<{ next_attempt_at: Date }>(
          `UPDATE scans
           SET status = 'queued', retry_count = $3,
               next_attempt_at = NOW() + make_interval(secs => $4),
               error_message = $5, worker_id = NULL, updated_at = NOW()
           WHERE id = $1 AND status = 'running' AND worker_id = $2
           RETURNING next_attempt_at`,
          [scanId, this.runId, decision.attempt, decision.delaySeconds, message],
        );
        if (res.rowCount !== 1) {
          await client.query('ROLLBACK');
          this.logger.warn(`Tarama ${scanId} başka bir örnek tarafından devralındı; hata yazılmadı.`);
          return;
        }
        await client.query('COMMIT');
        this.logger.warn(retryLogLine(scanId, decision.attempt, decision.maxAttempts, res.rows[0]?.next_attempt_at, message));
        return;
      }

      const res = await client.query(
        `UPDATE scans
         SET status = 'failed', completed_at = NOW(), next_attempt_at = NULL,
             error_message = $3, updated_at = NOW()
         WHERE id = $1 AND status = 'running' AND worker_id = $2`,
        [scanId, this.runId, message],
      );
      if (res.rowCount !== 1) {
        await client.query('ROLLBACK');
        this.logger.warn(`Tarama ${scanId} başka bir örnek tarafından devralındı; hata yazılmadı.`);
        return;
      }
      await client.query(
        `INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
         VALUES ('scan_failed', 'scan', $1, NOW())`,
        [scanId],
      );
      await client.query('COMMIT');
      this.logger.error(
        failureClass === 'transient'
          ? `Tarama ${scanId} deneme ${decision.attempt}/${decision.maxAttempts} başarısız; deneme hakkı bitti: ${shortErrorForLog(message)}`
          : `Tarama ${scanId} yeniden denenmeyecek bir hatayla başarısız: ${shortErrorForLog(message)}`,
      );
    } catch (writeErr) {
      if (client) await client.query('ROLLBACK').catch(() => undefined);
      this.logger.error(`Tarama ${scanId} için hata durumu yazılamadı (${errorCode(writeErr)}); sonraki yoklamada kurtarılacak.`);
    } finally {
      client?.release();
    }
  }
}

/** Retry log line (AC-P13-8): attempt n/max, next attempt time, shortened error. */
function retryLogLine(scanId: string, attempt: number, maxAttempts: number, nextAttemptAt: Date | undefined, message: string): string {
  const when = nextAttemptAt instanceof Date ? nextAttemptAt.toISOString() : String(nextAttemptAt ?? '?');
  return `Tarama ${scanId} deneme ${attempt}/${maxAttempts} başarısız; sonraki deneme ${when}: ${shortErrorForLog(message)}`;
}

function mergeVulnerabilities(vulnerabilities: NormalizedVulnerability[]): NormalizedVulnerability[] {
  const merged = new Map<string, NormalizedVulnerability>();

  for (const vuln of vulnerabilities) {
    const key = vuln.cveId || vuln.ghsaId || vuln.osvId || vuln.sourceId;
    if (!merged.has(key)) {
      merged.set(key, vuln);
      continue;
    }

    const existing = merged.get(key)!;
    merged.set(key, {
      ...existing,
      ...vuln,
      aliases: Array.from(new Set([...existing.aliases, ...vuln.aliases])),
      fixedVersion: vuln.fixedVersion || existing.fixedVersion,
      cvssScore: vuln.cvssScore ?? existing.cvssScore,
      cvssVector: vuln.cvssVector || existing.cvssVector,
      cvssVersion: vuln.cvssVersion || existing.cvssVersion,
      description: vuln.description || existing.description,
      affectedVersions: vuln.affectedVersions || existing.affectedVersions,
      publishedAt: vuln.publishedAt || existing.publishedAt,
      lastModifiedAt: vuln.lastModifiedAt || existing.lastModifiedAt,
    });
  }

  return Array.from(merged.values());
}
