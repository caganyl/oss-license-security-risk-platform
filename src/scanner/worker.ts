import crypto from 'crypto';
import os from 'os';
import path from 'path';
import type { Pool, PoolClient } from 'pg';
import { errorCode } from '../db/advisoryLock';
import { createRunId } from '../lib/runId';
import { ScanSourceError, canonicalizeScanRoots, parseScanRoots, resolveScanSource } from '../lib/scanSource';
import { sandboxRunnerConfig } from './sandbox/runner.config';
import { ParserFailedError, createLockAwareThreadParser } from './parsers/threadParser';
import { type ErrorTextContext, scanErrorMessage, scanErrorText, shortErrorForLog } from './errorMessage';
import { type GitVersionProvider, assertGitForRemoteScan, getGitVersion } from './gitVersion';
import {
  NonRetryableScanError,
  ORPHAN_RECOVERY_MESSAGE,
  ATTEMPTS_EXHAUSTED_MESSAGE,
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
  gitTokenSecretForms,
  isValidRef,
  sweepStaleWorkspaces,
  withTempWorkspace,
} from './workspace';
import { isRuntimeScope, toParserRunOutput, type ParserRunOutput, type RunParserFn, type SandboxScanResult } from '../types/scan';
import { computeFindingFingerprint } from '../analysis/findingFingerprint';
import { normalizeLicense } from '../analysis/licenseNormalizer';
import { type DependencyEnricher, type EnrichmentResult, disabledEnrichment, enrichmentKeyOf } from '../enrichment';
import { computeBudgetMs } from '../enrichment/budget';
import { resolveEffectiveLicense } from '../enrichment/effectiveLicense';
import { sanitizeText } from '../enrichment/text';
import { localDateString, systemClock, type AppClock } from '../lib/clock';
import { normalizeLegacyVulnerability } from '../vulnerability/normalize';
import {
  computeVulnerabilityBudgetMs,
  normalizeResolved,
  vulnerabilityKeyOf,
  type VulnerabilityLookup,
  type VulnerabilityLookupResult,
} from '../vulnerability/lookup';
import {
  insertFinding,
  insertSecurityFinding,
  loadSlaDays,
  mergeVulnerabilities,
  upsertVulnerability,
  type NewFinding,
} from '../vulnerability/findingWriter';
import { WebUrlError } from '../webscan/allowlist';
import type { WebScanner } from '../webscan/engine';
import { type LibraryVulnerability, writeWebResults } from '../webscan/persist';
import type { DetectedComponent, LookupState, WebScanMode } from '../webscan/types';

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
  /**
   * Git version gate of remote scans (REQ-003 AC-T-3, ADR-002 Ek E2): git
   * missing or older than 2.32 fails the scan permanently before a temp
   * folder is created. Default: the cached `git --version`
   * (`getGitVersion`) with the real `cloneRepo`; `null` (the default when a
   * `cloneRepo` is injected, since it does not run git) skips the gate.
   */
  gitVersion: GitVersionProvider | null;
  /**
   * Registry license enrichment (REQ-004, ADR-006 Karar 2). The runtime
   * always passes one (`REGISTRY_ENRICHMENT=off` -> disabled mode). `null`
   * (tests, `saveScanResults`): no enrichment step, every key `disabled`, no
   * `[registry]` line — the result equals F2.
   */
  enricher: DependencyEnricher | null;
  /**
   * Vulnerability lookup engine (REQ-005 P-17, ADR-007 Karar 5). The runtime
   * always passes one (`VULNERABILITY_LOOKUP=off` -> disabled mode). `null`
   * (tests, `saveScanResults`): no lookup, `vulnerability_data_status` stays
   * NULL, no `[osv]`/`[nvd]` line — the result equals F3 (AC-G-8).
   */
  vulnerabilityLookup: VulnerabilityLookup | null;
  /** Application clock (default `systemClock`). */
  clock: AppClock;
  /**
   * Web (URL) scanner (REQ-008, ADR-010 Karar 1). The runtime always passes
   * one; `null` (tests, older wiring) fails web scans permanently.
   */
  webScanner: WebScanner | null;
}

export { NonRetryableScanError };

/** Options of the (internal) result write. */
interface PersistOptions {
  /** Fence: only a `running` row owned by this run id is written (ADR-004 Karar 4). */
  runId?: string;
  /** Job abort signal: checked before every dependency; abort rolls back. */
  signal?: AbortSignal;
  /** Sanitizer context of the parse warning text (L-5). */
  errorContext?: ErrorTextContext;
  /** Enrichment result (effective license, NOTICE fields, `[registry]` line); absent -> all `disabled`, no line. */
  enrichment?: EnrichmentResult;
  /** Vulnerability lookup result (status, `[osv]`/`[nvd]` lines); absent -> no lookup (F3). */
  vulnerability?: VulnerabilityLookupResult;
}

/** normalized_license of a runtime package whose license could not be found (AC-P06-1). */
const NO_ASSERTION = 'NOASSERTION';

/**
 * A claimed scan job. It is in the worker's active set from the claim commit
 * (same tick) until its last write succeeded or was given up (ADR-004 Karar 9).
 */
interface ClaimedJob {
  scanRow: ScanJobRow;
  settings: ScanQueueSettings;
  controller: AbortController;
  timer: NodeJS.Timeout | null;
  /** Monotonic (`performance.now()`) end of the job time limit (enrichment budget, ADR-006 Karar 2). */
  deadlineMs: number;
  /** Resolves when the job has finished (never rejects). */
  done: Promise<void>;
  resolveDone: () => void;
  /** Token forms of this job (raw + Basic base64), masked in `error_message` (L-5). */
  secrets: string[];
  /** Temp workspace(s) of this job, replaced by `<workspace>` (L-5). */
  workspaceDirs: string[];
}

interface ScanJobRow {
  id: string;
  project_id: string;
  ref: string | null;
  retry_count: number;
  /** REQ-008: `dependency` | `web`. */
  scan_kind: string;
  target_url: string | null;
  web_scan_mode: string | null;
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
  /** Out-of-range `system_settings` warnings already logged (I-3). */
  private readonly settingsWarnings = new Set<string>();

  constructor(deps: Partial<ScanWorkerDeps> = {}) {
    if (!deps.db) {
      // There is no global pool any more (ADR-004 Karar 1): the runtime injects the single pool.
      throw new Error('ScanWorker requires deps.db');
    }
    this.deps = {
      db: deps.db,
      cloneRepo: deps.cloneRepo ?? defaultCloneRepo,
      // TypeScript parsers in a worker_threads thread (REQ-003 P-10, ADR-005 Karar 5).
      runParser: deps.runParser ?? createLockAwareThreadParser({ resourceLimits: sandboxRunnerConfig.parser.resourceLimits }),
      scanRoots: deps.scanRoots ?? parseScanRoots(process.env.SCAN_ROOTS),
      tmpRoot: deps.tmpRoot ?? os.tmpdir(),
      logger: deps.logger ?? console,
      runId: deps.runId ?? createRunId(),
      gitVersion: deps.gitVersion !== undefined ? deps.gitVersion : deps.cloneRepo ? null : getGitVersion,
      enricher: deps.enricher ?? null,
      vulnerabilityLookup: deps.vulnerabilityLookup ?? null,
      clock: deps.clock ?? systemClock,
      webScanner: deps.webScanner ?? null,
    };
  }

  /** L-5 sanitizer context (ADR-002 Ek E3): job secrets/workspace, SCAN_ROOTS, temp roots. */
  private errorContext(job?: ClaimedJob): ErrorTextContext {
    return {
      secrets: job?.secrets ?? [],
      workspaceDirs: job?.workspaceDirs ?? [],
      scanRoots: this.deps.scanRoots,
      tempDirs: [this.deps.tmpRoot, os.tmpdir()],
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
        const message = scanErrorText(ORPHAN_RECOVERY_MESSAGE, this.errorContext());
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
    return parseScanQueueSettings(res.rows, (message) => {
      // Read on every poll: each rejected value is logged once per process.
      if (this.settingsWarnings.has(message)) return;
      this.settingsWarnings.add(message);
      this.logger.warn(message);
    });
  }

  /**
   * Waiting scans whose attempts are already used up can no longer be
   * claimed (`retry_count < scan.max_retries`); this happens when
   * `scan.max_retries` is lowered while they wait (I-3). As in ADR-004 Karar
   * 8 a scan without an attempt left fails: `failed` + `scan_failed`, the last
   * failure text is kept. Runs inside the claim transaction.
   */
  private async failExhaustedScans(client: PoolClient, maxAttempts: number): Promise<void> {
    const res = await client.query<{ id: string }>(
      `WITH exhausted AS (
         SELECT id FROM scans
         WHERE status IN ('pending', 'queued') AND retry_count >= $1
         FOR UPDATE SKIP LOCKED
       ), failed AS (
         UPDATE scans s
         SET status = 'failed', completed_at = NOW(), next_attempt_at = NULL, worker_id = NULL,
             error_message = COALESCE(s.error_message, $2), updated_at = NOW()
         FROM exhausted e
         WHERE s.id = e.id
         RETURNING s.id
       )
       INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
       SELECT 'scan_failed'::audit_action, 'scan', id, NOW() FROM failed
       RETURNING entity_id AS id`,
      [maxAttempts, scanErrorText(ATTEMPTS_EXHAUSTED_MESSAGE, this.errorContext())],
    );
    for (const row of res.rows) {
      this.logger.warn(`Tarama ${row.id} için deneme hakkı kalmadı (scan.max_retries=${maxAttempts}); failed.`);
    }
  }

  private async claimNextJob(): Promise<ClaimedJob | null> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      const settings = await this.readSettings(client);
      await this.failExhaustedScans(client, settings.maxAttempts);

      // Claim query of ADR-004 Karar 8: a retry waiting for its backoff is
      // skipped, so it never blocks a newer scan (AC-P13-7).
      const scanResult = await client.query(
        `
        SELECT s.id, s.project_id, s.integration_id, s.ref, s.ref_type, s.retry_count,
               s.scan_kind, s.target_url, p.web_scan_mode,
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
    const job: ClaimedJob = {
      scanRow,
      settings,
      controller,
      timer: null,
      deadlineMs: performance.now() + settings.timeoutMinutes * 60_000,
      done,
      resolveDone,
      secrets: [],
      workspaceDirs: [],
    };
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
      // REQ-008 ADR-010 Karar 1: same queue, timer, retry and fence; own pipeline.
      if (scanRow.scan_kind === 'web') {
        await this.processWebJob(job);
        return;
      }
      // Before any clone: a token that cannot be decrypted fails the scan (D-14).
      let token: string | null;
      try {
        token = decryptToken(scanRow.access_token_enc);
      } catch (err) {
        throw new NonRetryableScanError((err as Error).message);
      }
      if (token) job.secrets.push(token);

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
      let parsed: ParserRunOutput;
      signal.throwIfAborted();
      if (source.kind === 'local') {
        parsed = toParserRunOutput(await this.deps.runParser(source.path, ecosystems, scanId, signal));
      } else {
        const ref = scanRow.ref || scanRow.default_branch || null;
        if (ref !== null && !isValidRef(ref)) {
          throw new NonRetryableScanError('Invalid git ref for the scan');
        }
        const remoteUrl = source.url;
        job.secrets.push(...gitTokenSecretForms(token ? { url: remoteUrl, token } : null));
        // Git missing/older than 2.32: permanent, before any temp folder (AC-T-3).
        if (this.deps.gitVersion) await assertGitForRemoteScan(this.deps.gitVersion);
        signal.throwIfAborted();
        parsed = await withTempWorkspace(
          async (workspace) => {
            job.workspaceDirs.push(workspace);
            const repoDir = path.join(workspace, 'repo');
            // The clone and the parser thread are awaited (killed/terminated on
            // abort) before withTempWorkspace removes the folder.
            await this.deps.cloneRepo(remoteUrl, ref, repoDir, token, signal);
            signal.throwIfAborted();
            return toParserRunOutput(await this.deps.runParser(repoDir, ecosystems, scanId, signal));
          },
          { tmpRoot: this.deps.tmpRoot, logger: this.logger },
        );
      }
      const result: SandboxScanResult = parsed.result;

      if (result.status === 'failed') {
        // Permanent (D-41): the same input fails the same way.
        throw new ParserFailedError('Dependency parser reported a parsing failure.');
      }
      // Registry enrichment: after parsing, before OSV and the result transaction (ADR-006 Karar 2).
      const enrichment = await this.enrichDependencies(job, result, parsed.lockIntegrity, parsed.nugetIntegrity);
      // Vulnerability lookup: after enrichment, outside the result transaction (ADR-007 Karar 5).
      const vulnerability = await this.lookupVulnerabilities(job, result, canonicalNamesOf(enrichment));
      this.logger.log(`Scan ${scanId} parsed. Writing ${result.total_deps} dependencies to the database...`);
      const stored = await this.persistResults(scanId, scanRow.project_id, result, {
        runId: this.runId,
        signal,
        errorContext: this.errorContext(job),
        enrichment,
        vulnerability,
      });
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

  /**
   * Runs the injected enricher within the budget
   * `min(T/2, remaining - T/4)` (AC-P14-14). A job abort is rethrown as is
   * (ADR-004 Karar 8 classification); every other error is logged by class
   * and the scan continues with `error` outcomes — enrichment never reaches
   * `handleScanFailure` and never causes a retry (AC-P14-13).
   */
  private async enrichDependencies(
    job: ClaimedJob,
    result: SandboxScanResult,
    lockIntegrity: ParserRunOutput['lockIntegrity'],
    nugetIntegrity?: ParserRunOutput['nugetIntegrity'],
  ): Promise<EnrichmentResult | undefined> {
    const enricher = this.deps.enricher;
    if (!enricher) return undefined;
    const signal = job.controller.signal;
    const timeoutMs = job.settings.timeoutMinutes * 60_000;
    const budgetMs = computeBudgetMs(timeoutMs, job.deadlineMs - performance.now());
    try {
      // NuGet side channel (ADR-008 Karar 6, 10.1): the only source of a NuGet archive candidate.
      const options = nugetIntegrity && nugetIntegrity.length > 0 ? { signal, budgetMs, lockIntegrity, nugetIntegrity } : { signal, budgetMs, lockIntegrity };
      return await enricher.enrich(result.dependencies, options);
    } catch (err) {
      if (signal.aborted) throw signal.reason ?? err;
      this.logger.warn(`Scan ${job.scanRow.id}: registry enrichment failed (${errorCode(err)}); continuing without it.`);
      return enricher.failed(result.dependencies);
    }
  }

  /**
   * Runs the injected vulnerability lookup within the budget
   * `min(T/4, remaining - T/8)` (AC-P17-14). A job abort is rethrown as is
   * (ADR-004 Karar 8); every other error is logged by class/code and every
   * candidate becomes unchecked — the lookup never reaches
   * `handleScanFailure` and never causes a retry (ADR-007 Karar 5).
   */
  private async lookupVulnerabilities(
    job: ClaimedJob,
    result: SandboxScanResult,
    canonicalNames?: ReadonlyMap<string, string>,
  ): Promise<VulnerabilityLookupResult | undefined> {
    const engine = this.deps.vulnerabilityLookup;
    if (!engine) return undefined;
    const signal = job.controller.signal;
    const timeoutMs = job.settings.timeoutMinutes * 60_000;
    const budgetMs = computeVulnerabilityBudgetMs(timeoutMs, job.deadlineMs - performance.now());
    const startedAt = new Date(this.deps.clock.now());
    try {
      // NuGet OSV body name (ADR-008 Karar 13.2): the `.nuspec` `<id>` of this scan's enrichment.
      const options = canonicalNames && canonicalNames.size > 0 ? { signal, budgetMs, canonicalNames } : { signal, budgetMs };
      return await engine.lookup(result.dependencies, options);
    } catch (err) {
      if (signal.aborted) throw signal.reason ?? err;
      this.logger.warn(`Scan ${job.scanRow.id}: vulnerability lookup failed (${errorCode(err)}); continuing without it.`);
      return engine.failed(result.dependencies, startedAt);
    }
  }

  private async loadEcosystems(projectId: string): Promise<string[]> {
    let ecosystems: string[] = [];
    try {
      const stackResult = await this.db.query<{ ecosystem: string }>(
        'SELECT ecosystem FROM project_tech_stacks WHERE project_id = $1',
        [projectId]
      );
      const supported: readonly string[] = sandboxRunnerConfig.scan.supportedEcosystems;
      ecosystems = stackResult.rows.map((r) => r.ecosystem).filter((e) => supported.includes(e));
    } catch (err) {
      // Class/code only, never the raw error object (ADR-004 Karar 6; security review I-6).
      this.logger.warn(`Warning: failed to fetch tech stack for project ${projectId} (${errorCode(err)}).`);
    }
    // Empty stack: every supported ecosystem, in order (`nodejs`, `python`, `dotnet`; REQ-006 AC-P20-17).
    return ecosystems.length > 0 ? ecosystems : [...sandboxRunnerConfig.scan.supportedEcosystems];
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
    const { runId, signal, errorContext = this.errorContext() } = options;
    // No enricher (tests, saveScanResults): every key `disabled`, no `[registry]` line (D-82).
    const enrichment = options.enrichment ?? disabledEnrichment(result.dependencies, false);
    const vulnerability = options.vulnerability;
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
      const slaDays = await loadSlaDays(client);

      // One finding per fingerprint per scan (ADR-003 c, AC-P08-2): the same
      // package in several manifests stays in the inventory but is reported once.
      const seenFingerprints = new Set<string>();
      // "Today" of the carry-over check from the injected clock, not CURRENT_DATE (ADR-007 Karar 9).
      const today = localDateString(this.deps.clock.now());
      const openFinding = (spec: Omit<NewFinding, 'scanId' | 'projectId' | 'scanDependencyId'>, scanDependencyId: string) =>
        insertFinding(client, seenFingerprints, { ...spec, scanId, projectId, scanDependencyId }, { today });

      // Process dependencies
      for (const dep of result.dependencies) {
        // Abort (time limit/shutdown) rolls the whole write back (ADR-004 Karar 7).
        signal?.throwIfAborted();
        const scope = dep.scope || 'direct';
        // packages.version holds only an exact version; unknown -> NULL (ADR-003 a).
        const version = dep.version === null || dep.version === undefined || dep.version === '' ? null : dep.version;

        // L-6 effective license (ADR-006 Karar 11). The policy loop below is
        // unchanged and runs on `policyInput` (fingerprint formula unchanged,
        // D-73); a `disabled` key with a lock hint gives exactly `dep.licenses` (F2).
        const enrichKey = enrichmentKeyOf(dep);
        const enriched = enrichKey === null ? undefined : enrichment.outcomes.get(enrichKey);
        const resolved = enriched
          ? resolveEffectiveLicense({
              status: enriched.status,
              ecosystem: enriched.registry,
              declaredLicense: enriched.declaredLicense,
              lockLicenses: dep.licenses ?? [],
              normalize: (raw) => normalizeLicense(raw).normalized,
              sanitize: sanitizeText,
            })
          : null;
        // L-5 fail-safe (ADR-007 Karar 12): on a lock integrity mismatch neither
        // the registry license nor the lock hint enters the policy; the hint is
        // kept stored but never shown. A runtime package then gets the
        // NOASSERTION ("unknown") finding below.
        const effective =
          resolved && enriched?.lockIntegrity === 'mismatch'
            ? { ...resolved, licenseExpression: null, licenseSource: 'none' as const, hintDiffers: false, policyInput: [] as string[] }
            : resolved;
        const policyInput: string[] = effective ? effective.policyInput : [...(dep.licenses ?? [])];

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
          INSERT INTO scan_dependencies (scan_id, package_id, scope, manifest_file, manifest_path, depth, declared_range,
                                         license_expression, license_source, license_lock_hint, license_hint_differs,
                                         license_enrichment_status, notice_status, notice_archive_id, lock_integrity,
                                         license_unclassified)
          VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
          ON CONFLICT (scan_id, package_id, manifest_path, scope) DO NOTHING
          RETURNING id
          `,
          [
            scanId,
            packageId,
            scope,
            dep.manifest_file,
            dep.manifest_path,
            dep.declared_range ?? null,
            effective?.licenseExpression ?? null,
            effective?.licenseSource ?? null,
            effective?.lockHint ?? null,
            effective?.hintDiffers ?? null,
            enriched?.status ?? null,
            enriched?.noticeStatus ?? null,
            enriched?.noticeArchiveId ?? null,
            enriched?.lockIntegrity ?? null,
            // ADR-008 Karar 12: only a NuGet `no_license` key without an L-5 mismatch keeps the reason.
            enriched && enriched.registry === 'nuget' && enriched.status === 'no_license' && enriched.lockIntegrity !== 'mismatch'
              ? (enriched.licenseUnclassified ?? null)
              : null,
          ]
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

        if (runtime && policyInput.length === 0) {
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
        if (runtime && policyInput.length > 0) {
          for (const rawLicense of policyInput) {
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

        const vulnKey = vulnerability ? vulnerabilityKeyOf(dep) : null;
        const lookedUpVulnerabilities =
          vulnKey === null ? [] : (vulnerability?.byKey.get(vulnKey) ?? []).map((resolved) => normalizeResolved(resolved, dep));
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
            const storedVuln = await upsertVulnerability(client, vuln);
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

            await insertSecurityFinding(client, {
              findingId,
              vulnerabilityId: vulnId,
              severity,
              cvssScore,
              fixVersion: vuln.fixedVersion,
              slaDays,
            });
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
      // The single `[registry]` line goes after the parse warnings (contract section 8).
      let warningMsg: string | null = null;
      const warningLines = (result.parse_errors ?? []).map((pe) => `[${pe.ecosystem}] File ${pe.file}: ${pe.error}`);
      if (enrichment.summaryLine !== null) warningLines.push(enrichment.summaryLine);
      // `[osv]` then `[nvd]` after `[registry]` (contract REQ-005 section 3.4).
      if (vulnerability) warningLines.push(...vulnerability.summaryLines);
      if (warningLines.length > 0) {
        warningMsg = scanErrorText(warningLines.join('\n'), errorContext);
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
            vulnerability_data_status = $11::text,
            vulnerability_checked_at = $12::timestamptz,
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
          vulnerability?.status ?? null,
          vulnerability?.checkedAt ?? null,
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

  /**
   * Web scan pipeline (REQ-008, ADR-010 Karar 1, 7): engine -> JavaScript
   * library lookup -> fenced result write. A rejected target (allowlist
   * changed, AC-P25-7) is permanent; an unreachable main page is transient
   * (AC-P26-3); a job abort is rethrown.
   */
  private async processWebJob(job: ClaimedJob): Promise<void> {
    const { scanRow } = job;
    const signal = job.controller.signal;
    const scanner = this.deps.webScanner;
    if (!scanner) throw new NonRetryableScanError('Web taraması bu süreçte kullanılamıyor.');
    if (!scanRow.target_url) throw new NonRetryableScanError('Web taramasının hedef adresi yok.');
    const mode: WebScanMode = scanRow.web_scan_mode === 'active' ? 'active' : 'passive';
    let outcome;
    try {
      outcome = await scanner.scan(
        { scanId: scanRow.id, projectId: scanRow.project_id, url: scanRow.target_url, mode },
        { signal, deadlineMs: job.deadlineMs },
      );
    } catch (err) {
      if (err instanceof WebUrlError) {
        throw new NonRetryableScanError(
          err.code === 'web_url_not_allowed'
            ? 'Web adresi WEB_SCAN_ALLOWED_HOSTS izin listesinde değil.'
            : 'Web adresi geçersiz.',
        );
      }
      throw err;
    }
    const lookup = await this.lookupWebComponents(job, outcome.components);
    this.logger.log(`Web scan ${scanRow.id} finished: ${outcome.findings.length} built-in/ZAP findings, ${outcome.components.length} components.`);
    const stored = await this.persistWebResults(job, outcome, lookup);
    if (stored) this.logger.log(`Web scan ${scanRow.id} results stored.`);
  }

  /**
   * OSV lookup of the detected JavaScript libraries with the scan budget
   * (AC-P26-7, D-234). Same isolation as `lookupVulnerabilities`: only a job
   * abort escapes.
   */
  private async lookupWebComponents(
    job: ClaimedJob,
    components: readonly DetectedComponent[],
  ): Promise<{ state: LookupState; vulnerabilities: LibraryVulnerability[]; summaryLines: string[] }> {
    const candidates = components.filter((c) => c.npmName !== null);
    const deps = candidates.map((c) => ({ ecosystem: 'nodejs' as const, name: c.npmName as string, version: c.version }));
    if (deps.length === 0) return { state: 'not_needed', vulnerabilities: [], summaryLines: [] };
    const engine = this.deps.vulnerabilityLookup;
    if (!engine) {
      return { state: 'disabled', vulnerabilities: [], summaryLines: ['[web] JavaScript kütüphanesi açık sorgusu kapalı (VULNERABILITY_LOOKUP=off).'] };
    }
    const signal = job.controller.signal;
    const timeoutMs = job.settings.timeoutMinutes * 60_000;
    const budgetMs = computeVulnerabilityBudgetMs(timeoutMs, job.deadlineMs - performance.now());
    const startedAt = new Date(this.deps.clock.now());
    let result: VulnerabilityLookupResult;
    try {
      result = await engine.lookup(deps, { signal, budgetMs });
    } catch (err) {
      if (signal.aborted) throw signal.reason ?? err;
      this.logger.warn(`Web scan ${job.scanRow.id}: library vulnerability lookup failed (${errorCode(err)}); continuing without it.`);
      result = engine.failed(deps, startedAt);
    }
    const vulnerabilities: LibraryVulnerability[] = [];
    candidates.forEach((component, i) => {
      const key = vulnerabilityKeyOf(deps[i]);
      if (key === null) return;
      for (const resolved of result.byKey.get(key) ?? []) {
        vulnerabilities.push({ component, vulnerability: normalizeResolved(resolved, deps[i]) });
      }
    });
    const lines = result.status === 'disabled'
      ? ['[web] JavaScript kütüphanesi açık sorgusu kapalı (VULNERABILITY_LOOKUP=off).']
      : result.summaryLines;
    return { state: result.status, vulnerabilities, summaryLines: lines };
  }

  /** Fenced web result write (ADR-010 Karar 1); false when the row is no longer ours. */
  private async persistWebResults(
    job: ClaimedJob,
    outcome: Awaited<ReturnType<WebScanner['scan']>>,
    lookup: { state: LookupState; vulnerabilities: LibraryVulnerability[]; summaryLines: string[] },
  ): Promise<boolean> {
    const scanId = job.scanRow.id;
    const signal = job.controller.signal;
    signal.throwIfAborted();
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      const owned = await client.query(
        `SELECT id FROM scans WHERE id = $1 AND status = 'running' AND worker_id = $2 FOR UPDATE`,
        [scanId, this.runId],
      );
      if (owned.rows.length === 0) {
        await client.query('ROLLBACK');
        this.logger.warn(`Tarama ${scanId} başka bir örnek tarafından devralındı; sonuç atıldı.`);
        return false;
      }
      const { summary, counts } = await writeWebResults(
        client,
        { scanId, projectId: job.scanRow.project_id, outcome, libraryVulnerabilities: lookup.vulnerabilities, lookupState: lookup.state },
        signal,
      );
      const lines = [...outcome.warnings, ...lookup.summaryLines];
      const warningMsg = lines.length > 0 ? scanErrorText(lines.join('\n'), this.errorContext(job)) : null;
      signal.throwIfAborted();
      const total = counts.critical + counts.high + counts.medium + counts.low;
      const updated = await client.query(
        `UPDATE scans
         SET status = 'completed', completed_at = NOW(),
             total_dependencies = 0, total_vulnerabilities = $1, critical_vulns = $2, high_vulns = $3,
             medium_vulns = $4, low_vulns = $5, license_violations = 0,
             error_message = COALESCE(error_message, $6), next_attempt_at = NULL,
             web_summary = $7::jsonb, updated_at = NOW()
         WHERE id = $8 AND status = 'running' AND worker_id = $9`,
        [total, counts.critical, counts.high, counts.medium, counts.low, warningMsg, JSON.stringify(summary), scanId, this.runId],
      );
      if (updated.rowCount !== 1) {
        await client.query('ROLLBACK');
        this.logger.warn(`Tarama ${scanId} başka bir örnek tarafından devralındı; sonuç atıldı.`);
        return false;
      }
      await client.query(
        `INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
         VALUES ('scan_completed', 'scan', $1, NOW())`,
        [scanId],
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
        this.errorContext(job),
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
/** `.nuspec` `<id>` per NuGet enrichment key (= vulnerability key), for the OSV body name (ADR-008 Karar 13.2). */
function canonicalNamesOf(enrichment: EnrichmentResult | undefined): Map<string, string> {
  const names = new Map<string, string>();
  for (const [key, outcome] of enrichment?.outcomes ?? []) {
    if (outcome.registry === 'nuget' && typeof outcome.canonicalName === 'string' && outcome.canonicalName !== '') names.set(key, outcome.canonicalName);
  }
  return names;
}

function retryLogLine(scanId: string, attempt: number, maxAttempts: number, nextAttemptAt: Date | undefined, message: string): string {
  const when = nextAttemptAt instanceof Date ? nextAttemptAt.toISOString() : String(nextAttemptAt ?? '?');
  return `Tarama ${scanId} deneme ${attempt}/${maxAttempts} başarısız; sonraki deneme ${when}: ${shortErrorForLog(message)}`;
}

