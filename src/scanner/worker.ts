import { spawn, exec } from 'child_process';
import crypto from 'crypto';
import { pool } from '../lib/db';
import { sandboxRunnerConfig, buildDockerRunFlags } from './sandbox/runner.config';
import type { SandboxScanResult } from '../types/scan';
import { normalizeLicense } from '../analysis/licenseNormalizer';
import {
  normalizeLegacyVulnerability,
  vulnerabilityLookupService,
  type NormalizedVulnerability,
  type VulnerabilitySeverity,
} from '../analysis/vulnerabilityLookup';

const WORKER_ID = sandboxRunnerConfig.worker.workerId;

// Cryptography: decrypt AES-256-GCM token from DB
function decryptToken(encryptedBuffer: Buffer | null, keyString?: string): string | null {
  if (!encryptedBuffer) return null;
  const keyEnv = keyString || process.env.ENCRYPTION_KEY;
  if (!keyEnv) {
    // Fallback to plain text if no key is configured
    return encryptedBuffer.toString('utf8');
  }

  try {
    const key = crypto.createHash('sha256').update(keyEnv).digest();
    if (encryptedBuffer.length < 28) {
      return encryptedBuffer.toString('utf8');
    }

    const iv = encryptedBuffer.subarray(0, 12);
    const tag = encryptedBuffer.subarray(12, 28);
    const ciphertext = encryptedBuffer.subarray(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  } catch (err) {
    // Fallback if the token was stored unencrypted
    return encryptedBuffer.toString('utf8');
  }
}

// Helper to scrub credentials from output
function scrubLogs(logs: string, credentials: readonly string[]): string {
  let scrubbed = logs;
  for (const cred of credentials) {
    if (cred && cred.length > 0) {
      scrubbed = scrubbed.split(cred).join('[REDACTED]');
    }
  }
  return scrubbed;
}

export class ScanWorker {
  private activeScans = 0;
  private isRunning = false;
  private pollTimeout: NodeJS.Timeout | null = null;

  constructor() {
    console.log(`Scan Worker initialized with Worker ID: ${WORKER_ID}`);
  }

  public async start(): Promise<void> {
    this.isRunning = true;
    console.log('Scan Worker starting...');
    await this.cleanupOrphanedScans();
    this.schedulePoll(0);
  }

  public stop(): void {
    this.isRunning = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
    }
    console.log('Scan Worker stopped.');
  }

  private async cleanupOrphanedScans(): Promise<void> {
    try {
      console.log('Cleaning up orphaned running scans for this worker...');
      const result = await pool.query(
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
        console.log(`Recovered and failed ${result.rowCount} orphaned running scans.`);
        for (const row of result.rows) {
          // Attempt to remove their docker volumes
          exec(`docker volume rm scan-${row.id}-workspace`, () => {});
        }
      }
    } catch (error) {
      console.error('Failed to cleanup orphaned scans:', error);
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
        // Run job asynchronously
        this.runScanJob(job.scanRow, job.timeoutMs, job.maxAttempts).catch((err) => {
          console.error(`Unhandled error running scan ${job.scanRow.id}:`, err);
        });

        // If we still have capacity, immediately try to poll for another job
        if (this.activeScans < maxConcurrent) {
          this.schedulePoll(0);
          return;
        }
      }
    } catch (err) {
      console.error('Error claiming scan job from database:', err);
    }

    // Schedule next regular poll
    this.schedulePoll(sandboxRunnerConfig.worker.pollIntervalMs);
  }

  private async claimNextJob() {
    const client = await pool.connect();
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
        FOR UPDATE SKIP LOCKED
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

  private async runScanJob(scanRow: any, timeoutMs: number, maxAttempts: number): Promise<void> {
    const scanId = scanRow.id;
    console.log(`Starting execution of scan ${scanId} (project ${scanRow.project_id})...`);

    // Determine ecosystems to parse
    let ecosystems: string[] = [];
    try {
      const stackResult = await pool.query(
        'SELECT ecosystem FROM project_tech_stacks WHERE project_id = $1',
        [scanRow.project_id]
      );
      ecosystems = stackResult.rows
        .map(r => r.ecosystem)
        .filter(e => e === 'nodejs' || e === 'python');
    } catch (err) {
      console.warn(`Warning: failed to fetch tech stack for project ${scanRow.project_id}:`, err);
    }
    if (ecosystems.length === 0) {
      ecosystems = ['nodejs', 'python']; // Fallback to all supported MVP ecosystems
    }

    const repoUrl = scanRow.integration_repo_url || scanRow.project_repo_url;
    const ref = scanRow.ref || scanRow.default_branch || 'main';
    const accessToken = decryptToken(scanRow.access_token_enc);

    // Build Docker arguments
    const dockerArgs = ['run', ...buildDockerRunFlags(scanId, sandboxRunnerConfig)];
    dockerArgs.push('--env', `REPO_URL=${repoUrl}`);
    dockerArgs.push('--env', `REPO_REF=${ref}`);
    dockerArgs.push('--env', `ECOSYSTEMS=${ecosystems.join(',')}`);
    if (accessToken) {
      dockerArgs.push('--env', `ACCESS_TOKEN=${accessToken}`);
    }
    dockerArgs.push(`${sandboxRunnerConfig.container.image}:${sandboxRunnerConfig.container.tag}`);

    console.log(`Running: docker ${dockerArgs.filter(arg => !accessToken || arg !== `ACCESS_TOKEN=${accessToken}`).join(' ')}`);

    const child = spawn('docker', dockerArgs);
    let stdoutData = '';
    let stderrData = '';

    child.stdout.on('data', (chunk) => {
      stdoutData += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderrData += chunk.toString();
    });

    const timeoutId = setTimeout(() => {
      console.error(`Scan ${scanId} timed out after ${timeoutMs}ms. Terminating container.`);
      child.kill('SIGKILL');
      exec(`docker kill scanner-${scanId}`, () => {});
    }, timeoutMs);

    child.on('close', async (code) => {
      clearTimeout(timeoutId);
      this.activeScans--;

      // Cleanup Docker volume in background
      exec(`docker volume rm scan-${scanId}-workspace`, (err) => {
        if (err) console.warn(`Note: Docker volume cleanup failed or already removed for scan ${scanId}`);
      });

      const scrubbedStderr = scrubLogs(stderrData, accessToken ? [accessToken] : []);

      try {
        if (child.killed) {
          throw new Error(`Scan execution exceeded timeout limit of ${timeoutMs / 60000} minutes.`);
        }
        if (code !== 0) {
          throw new Error(`Scan container exited with non-zero code ${code}.\nLogs: ${scrubbedStderr}`);
        }

        const lines = stdoutData.trim().split('\n');
        const lastLine = lines[lines.length - 1];
        if (!lastLine) {
          throw new Error('Scanner container produced no output on stdout.');
        }

        let scanResult: SandboxScanResult;
        try {
          scanResult = JSON.parse(lastLine);
        } catch (parseErr) {
          const parseErrMsg = parseErr instanceof Error ? parseErr.message : String(parseErr);
          throw new Error(`Failed to parse scanner JSON result: ${parseErrMsg}. Raw output: ${lastLine}`);
        }

        if (scanResult.status === 'failed') {
          throw new Error('Sandbox scanner reporting inner parsing failure.');
        }

        console.log(`Scan ${scanId} completed parsing. Writing results to database...`);
        await this.saveScanResults(scanId, scanRow.project_id, scanResult);
        console.log(`Scan ${scanId} results successfully stored.`);

      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        console.error(`Scan ${scanId} failed processing:`, errMsg);
        await this.handleScanFailure(scanId, scanRow.retry_count, maxAttempts, errMsg, scrubbedStderr);
      }

      // Trigger next poll immediately to process pending scans
      this.schedulePoll(0);
    });
  }

  private async saveScanResults(
    scanId: string,
    projectId: string,
    result: SandboxScanResult
  ): Promise<void> {
    const vulnerabilityLookup = await vulnerabilityLookupService.lookupDependencies(result.dependencies);
    const client = await pool.connect();
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

      // Process dependencies
      for (const dep of result.dependencies) {
        // Insert package (deduplicated)
        const pkgResult = await client.query(
          `
          INSERT INTO packages (ecosystem, name, version, purl)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (ecosystem, name, version) DO UPDATE SET purl = EXCLUDED.purl
          RETURNING id
          `,
          [dep.ecosystem, dep.name, dep.version, dep.purl]
        );
        const packageId = pkgResult.rows[0].id;

        // Insert scan dependency
        const depResult = await client.query(
          `
          INSERT INTO scan_dependencies (scan_id, package_id, scope, manifest_file, manifest_path, depth)
          VALUES ($1, $2, $3, $4, $5, 0)
          ON CONFLICT (scan_id, package_id, manifest_path, scope) DO NOTHING
          RETURNING id
          `,
          [scanId, packageId, dep.scope || 'direct', dep.manifest_file, dep.manifest_path]
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
            [scanId, packageId, dep.manifest_path, dep.scope || 'direct']
          );
          scanDepId = getDepId.rows[0].id;
        }

        // Process licenses and evaluate policy risk
        if (dep.licenses && dep.licenses.length > 0) {
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
              licenseViolations++;

              const findResult = await client.query(
                `
                INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status)
                VALUES ($1, $2, 'license', 'open')
                RETURNING id
                `,
                [scanId, scanDepId]
              );
              const findingId = findResult.rows[0].id;

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
        const vulnerabilities = mergeVulnerabilities([
          ...lookedUpVulnerabilities,
          ...legacyVulnerabilities,
        ]);

        // Process vulnerabilities and generate security findings
        if (vulnerabilities.length > 0) {
          for (const vuln of vulnerabilities) {
            totalVulns++;

            const storedVuln = await this.upsertVulnerability(client, vuln);
            const vulnId = storedVuln.id;
            const severity = storedVuln.severity;
            const cvssScore = storedVuln.cvssScore;

            if (severity === 'critical') criticalVulns++;
            else if (severity === 'high') highVulns++;
            else if (severity === 'medium') mediumVulns++;
            else if (severity === 'low') lowVulns++;

            const days = slaDays[severity] ?? 90;
            const slaDeadline = new Date();
            slaDeadline.setDate(slaDeadline.getDate() + days);

            const findResult = await client.query(
              `
              INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status)
              VALUES ($1, $2, 'security', 'open')
              RETURNING id
              `,
              [scanId, scanDepId]
            );
            const findingId = findResult.rows[0].id;

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
    client: any,
    vuln: NormalizedVulnerability
  ): Promise<{ id: string; severity: VulnerabilitySeverity; cvssScore: number | null }> {
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

    if (existing.rows.length > 0) {
      vulnerabilityId = existing.rows[0].id;
      await client.query(
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
        RETURNING id
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
    };
  }

  private async handleScanFailure(
    scanId: string,
    retryCount: number,
    maxAttempts: number,
    errorMessage: string,
    logs: string
  ): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const nextRetry = retryCount + 1;
      const canRetry = nextRetry < maxAttempts;

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
        console.log(`Scan ${scanId} failed (attempt ${nextRetry}/${maxAttempts}). Rescheduling. Error: ${errorMessage}`);
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
        console.error(`Scan ${scanId} failed all ${maxAttempts} attempts. Error: ${errorMessage}`);
      }

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      console.error(`Failed to update database for failed scan ${scanId}:`, err);
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
    pool.end().then(() => {
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
