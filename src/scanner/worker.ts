import crypto from 'crypto';
import os from 'os';
import path from 'path';
import type { Pool, PoolClient } from 'pg';
import { pool as defaultPool } from '../lib/db';
import { ScanSourceError, canonicalizeScanRoots, parseScanRoots, resolveScanSource } from '../lib/scanSource';
import { sandboxRunnerConfig } from './sandbox/runner.config';
import { createThreadParser } from './parsers/threadParser';
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

const WORKER_ID = sandboxRunnerConfig.worker.workerId;

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

/** Deterministic failure (invalid source, ref or token): the scan fails without retry. */
class NonRetryableScanError extends Error {}

interface ClaimedJob {
  scanRow: ScanJobRow;
  timeoutMs: number;
  maxAttempts: number;
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
  private activeScans = 0;
  private isRunning = false;
  private pollTimeout: NodeJS.Timeout | null = null;
  private readonly deps: ScanWorkerDeps;

  constructor(deps: Partial<ScanWorkerDeps> = {}) {
    this.deps = {
      db: deps.db ?? defaultPool,
      cloneRepo: deps.cloneRepo ?? defaultCloneRepo,
      // TypeScript parsers in a worker_threads thread (REQ-003 P-10, ADR-005 Karar 5).
      runParser: deps.runParser ?? createThreadParser({ resourceLimits: sandboxRunnerConfig.parser.resourceLimits }),
      scanRoots: deps.scanRoots ?? parseScanRoots(process.env.SCAN_ROOTS),
      tmpRoot: deps.tmpRoot ?? os.tmpdir(),
      logger: deps.logger ?? console,
    };
    this.deps.logger.log(`Scan Worker initialized with Worker ID: ${WORKER_ID}`);
  }

  private get db(): Pool {
    return this.deps.db;
  }

  private get logger(): WorkerLogger {
    return this.deps.logger;
  }

  public async start(): Promise<void> {
    this.logger.log('Scan Worker starting...');
    // An invalid SCAN_ROOTS entry is an explicit startup error (ADR-002 karar 4).
    this.deps.scanRoots = await canonicalizeScanRoots(this.deps.scanRoots);
    await sweepStaleWorkspaces(this.deps.tmpRoot, STALE_WORKSPACE_MAX_AGE_MS, this.logger);
    this.isRunning = true;
    await this.cleanupOrphanedScans();
    this.schedulePoll(0);
  }

  public stop(): void {
    this.isRunning = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
    }
    this.logger.log('Scan Worker stopped.');
  }

  /**
   * Claims the next pending/queued scan and processes it to the end (DB
   * updated) without starting the poll loop. Returns the scan id, or `null`
   * when the queue is empty.
   */
  public async runOnce(): Promise<string | null> {
    const job = await this.claimNextJob();
    if (!job) return null;
    await this.processJob(job);
    return job.scanRow.id;
  }

  private async cleanupOrphanedScans(): Promise<void> {
    try {
      this.logger.log('Cleaning up orphaned running scans for this worker...');
      const result = await this.db.query(
        `
        UPDATE scans
        SET status = 'failed',
            error_message = 'Worker restarted while scan was running',
            completed_at = NOW(),
            updated_at = NOW()
        WHERE worker_id = $1 AND status = 'running'
        RETURNING id
        `,
        [WORKER_ID]
      );
      if (result.rowCount && result.rowCount > 0) {
        this.logger.log(`Recovered and failed ${result.rowCount} orphaned running scans.`);
      }
    } catch (error) {
      this.logger.error('Failed to cleanup orphaned scans:', error);
    }
  }

  private schedulePoll(delayMs: number): void {
    if (!this.isRunning) return;
    if (this.pollTimeout) clearTimeout(this.pollTimeout);
    this.pollTimeout = setTimeout(() => this.poll(), delayMs);
  }

  private async poll(): Promise<void> {
    if (!this.isRunning) return;

    // Check if worker is at maximum capacity
    const maxConcurrent = sandboxRunnerConfig.worker.maxConcurrentScans;
    if (this.activeScans >= maxConcurrent) {
      // Postpone poll and check again later
      this.schedulePoll(sandboxRunnerConfig.worker.pollIntervalMs);
      return;
    }

    try {
      const job = await this.claimNextJob();
      if (job) {
        this.activeScans++;
        // Run job asynchronously; free the slot and poll again when it ends.
        this.processJob(job)
          .catch((err) => {
            this.logger.error(`Unhandled error running scan ${job.scanRow.id}:`, err);
          })
          .finally(() => {
            this.activeScans--;
            this.schedulePoll(0);
          });

        // If we still have capacity, immediately try to poll for another job
        if (this.activeScans < maxConcurrent) {
          this.schedulePoll(0);
          return;
        }
      }
    } catch (err) {
      this.logger.error('Error claiming scan job from database:', err);
    }

    // Schedule next regular poll
    this.schedulePoll(sandboxRunnerConfig.worker.pollIntervalMs);
  }

  private async claimNextJob(): Promise<ClaimedJob | null> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Fetch dynamic settings from system_settings
      const settingsResult = await client.query(
        `SELECT key, value FROM system_settings WHERE key IN ('scan.max_retries', 'scan.timeout_minutes')`
      );
      let maxAttempts = sandboxRunnerConfig.retry.maxAttempts;
      let timeoutMinutes = 60;
      for (const row of settingsResult.rows) {
        if (row.key === 'scan.max_retries') maxAttempts = Number(row.value);
        if (row.key === 'scan.timeout_minutes') timeoutMinutes = Number(row.value);
      }
      const timeoutMs = timeoutMinutes * 60 * 1000;

      // Select next pending or queued scan using FOR UPDATE SKIP LOCKED
      const scanResult = await client.query(
        `
        SELECT s.id, s.project_id, s.integration_id, s.ref, s.ref_type, s.retry_count,
               p.repo_url as project_repo_url,
               i.repo_url as integration_repo_url, i.default_branch, i.access_token_enc
        FROM scans s
        JOIN projects p ON p.id = s.project_id
        LEFT JOIN integrations i ON i.id = s.integration_id
        WHERE s.status IN ('pending', 'queued') AND s.retry_count < $1
        ORDER BY s.created_at ASC
        LIMIT 1
        FOR UPDATE OF s SKIP LOCKED
        `,
        [maxAttempts]
      );

      if (scanResult.rows.length === 0) {
        await client.query('COMMIT');
        return null;
      }

      const scanRow = scanResult.rows[0];

      // Update scan record as running
      await client.query(
        `
        UPDATE scans
        SET status = 'running',
            worker_id = $1,
            started_at = NOW(),
            updated_at = NOW()
        WHERE id = $2
        `,
        [WORKER_ID, scanRow.id]
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
      return { scanRow, timeoutMs, maxAttempts };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Single execution path (ADR-002 karar 1): decrypt token -> classify the
   * source (TOCTOU re-check) -> local directory in place, or shallow clone
   * into a temp workspace -> parser (worker thread) -> results. There is no other folder to
   * fall back to: an unresolvable source fails the scan.
   */
  private async processJob(job: ClaimedJob): Promise<void> {
    const { scanRow, timeoutMs, maxAttempts } = job;
    const scanId = scanRow.id;
    this.logger.log(`Starting execution of scan ${scanId} (project ${scanRow.project_id})...`);
    // Interim parser time limit (system_settings scan.timeout_minutes); the
    // job-level AbortSignal of ADR-004 Karar 7 replaces it in the runtime work.
    const parserAbort = new AbortController();
    let parserTimer: NodeJS.Timeout | null = null;
    const parserSignal = (): AbortSignal => {
      if (!parserTimer) {
        parserTimer = setTimeout(() => {
          parserAbort.abort(new Error(`Dependency parser timed out after ${Math.round(timeoutMs / 60000)} minutes.`));
        }, timeoutMs);
      }
      return parserAbort.signal;
    };
    try {
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
      if (source.kind === 'local') {
        result = await this.deps.runParser(source.path, ecosystems, scanId, parserSignal());
      } else {
        const ref = scanRow.ref || scanRow.default_branch || null;
        if (ref !== null && !isValidRef(ref)) {
          throw new NonRetryableScanError('Invalid git ref for the scan');
        }
        const remoteUrl = source.url;
        result = await withTempWorkspace(
          async (workspace) => {
            const repoDir = path.join(workspace, 'repo');
            await this.deps.cloneRepo(remoteUrl, ref, repoDir, token);
            return this.deps.runParser(repoDir, ecosystems, scanId, parserSignal());
          },
          { tmpRoot: this.deps.tmpRoot, logger: this.logger },
        );
      }

      if (result.status === 'failed') {
        throw new Error('Dependency parser reported a parsing failure.');
      }
      this.logger.log(`Scan ${scanId} parsed. Writing ${result.total_deps} dependencies to the database...`);
      await this.saveScanResults(scanId, scanRow.project_id, result);
      this.logger.log(`Scan ${scanId} results stored.`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Scan ${scanId} failed: ${errMsg}`);
      await this.handleScanFailure(scanId, scanRow.retry_count, maxAttempts, errMsg, !(err instanceof NonRetryableScanError));
    } finally {
      if (parserTimer) clearTimeout(parserTimer);
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

  public async saveScanResults(
    scanId: string,
    projectId: string,
    result: SandboxScanResult
  ): Promise<void> {
    const vulnerabilityLookup = await vulnerabilityLookupService.lookupDependencies(result.dependencies);
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

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
        warningMsg = result.parse_errors
          .map(pe => `[${pe.ecosystem}] File ${pe.file}: ${pe.error}`)
          .join('\n');
      }

      // Update scan row
      await client.query(
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
            updated_at = NOW()
        WHERE id = $9
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
        ]
      );

      // Audit log scan completed
      await client.query(
        `
        INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
        VALUES ('scan_completed', 'scan', $1, NOW())
        `,
        [scanId]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
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

  private async handleScanFailure(
    scanId: string,
    retryCount: number,
    maxAttempts: number,
    errorMessage: string,
    retryable: boolean
  ): Promise<void> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      const nextRetry = retryCount + 1;
      // Validation/token errors are deterministic and never retried (ADR-002 karar 3, 6).
      const canRetry = retryable && nextRetry < maxAttempts;

      if (canRetry) {
        await client.query(
          `
          UPDATE scans
          SET status = 'queued',
              retry_count = $1,
              error_message = $2,
              updated_at = NOW()
          WHERE id = $3
          `,
          [nextRetry, errorMessage, scanId]
        );
        this.logger.log(`Scan ${scanId} failed (attempt ${nextRetry}/${maxAttempts}). Rescheduling. Error: ${errorMessage}`);
      } else {
        await client.query(
          `
          UPDATE scans
          SET status = 'failed',
              completed_at = NOW(),
              error_message = $1,
              updated_at = NOW()
          WHERE id = $2
          `,
          [errorMessage, scanId]
        );

        // Audit log scan failure
        await client.query(
          `
          INSERT INTO audit_logs (action, entity_type, entity_id, occurred_at)
          VALUES ('scan_failed', 'scan', $1, NOW())
          `,
          [scanId]
        );
        this.logger.error(
          retryable
            ? `Scan ${scanId} failed all ${maxAttempts} attempts. Error: ${errorMessage}`
            : `Scan ${scanId} failed (not retried). Error: ${errorMessage}`,
        );
      }

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      this.logger.error(`Failed to update database for failed scan ${scanId}:`, err);
    } finally {
      client.release();
    }
  }
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

// Start worker process directly if called as main module
if (require.main === module) {
  const worker = new ScanWorker();
  
  // Clean shutdown handlers
  const shutdown = () => {
    console.log('Shutdown signal received.');
    worker.stop();
    defaultPool.end().then(() => {
      console.log('Database connections closed. Exiting.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  worker.start().catch((err) => {
    console.error('Fatal worker startup error:', err);
    process.exit(1);
  });
}
