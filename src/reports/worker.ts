import type { Pool } from 'pg';
import { errorCode } from '../db/advisoryLock';
import { sanitizeErrorText } from '../lib/errorText';
import { shortErrorForLog } from '../scanner/errorMessage';
import { ReportService } from './reportService';
import { exportWorkerConfig, type ExportWorkerConfig } from './worker.config';

export type ExportWorkerLogger = Pick<Console, 'log' | 'warn' | 'error'>;

/** Dependencies of the report worker (REQ-003 P-12, ADR-004 Karar 1). */
export interface ExportWorkerDeps {
  /** Required: the runtime's single pool. */
  db: Pool;
  logger: ExportWorkerLogger;
  /** Default: `new ReportService(db)`. */
  reportService: ReportService;
  /** Default: `exportWorkerConfig`. */
  config: ExportWorkerConfig;
}

/**
 * Report queue worker: `pending -> generating -> ready | failed`. Runs in the
 * runtime process next to the API and the scan worker. Report generation
 * (pdfkit/exceljs) cannot be cancelled; on shutdown the runtime waits for it
 * a bounded time and returns the rest to `pending` (ADR-004 Karar 5).
 */
export class ExportWorker {
  private polling = false;
  private paused = false;
  private shuttingDown = false;
  private pollTimeout: NodeJS.Timeout | null = null;
  private readonly active = new Set<Promise<void>>();
  private readonly deps: ExportWorkerDeps;

  constructor(deps: Partial<ExportWorkerDeps> = {}) {
    if (!deps.db) throw new Error('ExportWorker requires deps.db');
    this.deps = {
      db: deps.db,
      logger: deps.logger ?? console,
      reportService: deps.reportService ?? new ReportService(deps.db),
      config: deps.config ?? exportWorkerConfig,
    };
  }

  private get db(): Pool {
    return this.deps.db;
  }

  private get logger(): ExportWorkerLogger {
    return this.deps.logger;
  }

  public get activeCount(): number {
    return this.active.size;
  }

  /** Stand-alone start: start-up recovery, then polling. */
  public async start(): Promise<void> {
    await this.recoverOrphanedReports();
    this.startPolling();
  }

  public startPolling(): void {
    if (this.polling) return;
    this.polling = true;
    this.logger.log("Rapor worker'ı başladı.");
    this.schedulePoll(0);
  }

  public stop(): void {
    const wasPolling = this.polling;
    this.polling = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
      this.pollTimeout = null;
    }
    if (wasPolling) this.logger.log("Rapor worker'ı yoklamayı bıraktı.");
  }

  /** Degraded mode (ADR-004 Karar 3): no new claims; running reports continue. */
  public pause(): void {
    this.paused = true;
  }

  public resume(): void {
    if (!this.paused) return;
    this.paused = false;
    this.schedulePoll(0);
  }

  /**
   * Shutdown mode (ADR-004 Karar 5): polling stops and the worker's error
   * path no longer writes `failed` (the runtime returns `generating` reports
   * to `pending`).
   */
  public enterShutdown(): void {
    this.shuttingDown = true;
    this.stop();
  }

  /** Resolves true when every running report finished within `timeoutMs`. */
  public async waitForIdle(timeoutMs: number): Promise<boolean> {
    if (this.active.size === 0) return true;
    let timer: NodeJS.Timeout | null = null;
    const timedOut = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), Math.max(0, timeoutMs));
    });
    try {
      return await Promise.race([Promise.all([...this.active]).then(() => true as const), timedOut]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Start-up recovery: `generating -> failed` (unchanged behaviour, AC-P12-11). */
  public async recoverOrphanedReports(): Promise<number> {
    try {
      const result = await this.db.query(
        `
        UPDATE reports
        SET status = 'failed',
            error_message = 'Server/Worker restarted while report was generating',
            completed_at = NOW()
        WHERE status = 'generating'
        RETURNING id
        `
      );
      const count = result.rowCount ?? 0;
      if (count > 0) this.logger.warn(`${count} yarım kalmış rapor failed yapıldı.`);
      return count;
    } catch (error) {
      this.logger.error(`Yarım kalmış rapor kurtarma başarısız (${errorCode(error)}).`);
      return 0;
    }
  }

  private schedulePoll(delayMs: number): void {
    if (!this.polling || this.paused) return;
    if (this.pollTimeout) clearTimeout(this.pollTimeout);
    this.pollTimeout = setTimeout(() => {
      this.pollTimeout = null;
      this.poll().catch((err) => {
        this.logger.error(`Rapor yoklaması başarısız (${errorCode(err)}).`);
        this.schedulePoll(this.deps.config.pollIntervalMs);
      });
    }, delayMs);
  }

  private async poll(): Promise<void> {
    if (!this.polling || this.paused) return;

    const maxConcurrent = this.deps.config.maxConcurrentExports;
    if (this.active.size >= maxConcurrent) {
      this.schedulePoll(this.deps.config.pollIntervalMs);
      return;
    }

    try {
      const reportId = await this.claimNextJob();
      if (reportId) {
        const job = this.runExportJob(reportId);
        this.active.add(job);
        job.finally(() => {
          this.active.delete(job);
          this.schedulePoll(0);
        });

        if (this.active.size < maxConcurrent) {
          this.schedulePoll(0);
          return;
        }
      }
    } catch (err) {
      // Database outage (AC-P12-8): class only, retried on the next poll.
      this.logger.error(`Rapor işi sahiplenilemedi (${errorCode(err)}).`);
    }

    this.schedulePoll(this.deps.config.pollIntervalMs);
  }

  private async claimNextJob(): Promise<string | null> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      const result = await client.query(
        `
        SELECT id
        FROM reports
        WHERE status = 'pending'
        ORDER BY requested_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
        `
      );

      if (result.rows.length === 0) {
        await client.query('COMMIT');
        return null;
      }

      const reportId = result.rows[0].id;
      await client.query(`UPDATE reports SET status = 'generating' WHERE id = $1`, [reportId]);
      await client.query('COMMIT');
      return reportId;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /** Never rejects (ADR-004 Karar 6). */
  private async runExportJob(reportId: string): Promise<void> {
    this.logger.log(`Starting generation of report ${reportId}...`);
    const timeoutMs = this.deps.config.timeoutMs;

    let timeoutId: NodeJS.Timeout | null = null;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(`Report generation timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    try {
      await Promise.race([this.deps.reportService.processReport(reportId), timeoutPromise]);
      this.logger.log(`Report ${reportId} successfully generated.`);
    } catch (err) {
      // L-5 (ADR-002 Ek E3): the same sanitized text for the log and error_message.
      const errMsg = sanitizeErrorText(err instanceof Error ? err.message : String(err));
      this.logger.error(`Failed to generate report ${reportId}: ${shortErrorForLog(errMsg)}`);
      if (this.shuttingDown) return;
      try {
        await this.db.query(
          `
          UPDATE reports
          SET status = 'failed',
              error_message = $2,
              completed_at = NOW()
          WHERE id = $1 AND status != 'ready'
          `,
          [reportId, errMsg]
        );
      } catch (dbErr) {
        this.logger.error(`Report ${reportId} could not be marked failed (${errorCode(dbErr)}).`);
      }
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  }
}
