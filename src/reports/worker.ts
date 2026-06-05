import { pool } from '../lib/db';
import { ReportService } from './reportService';
import { exportWorkerConfig } from './worker.config';

const WORKER_ID = exportWorkerConfig.workerId;

export class ExportWorker {
  private activeExports = 0;
  private isRunning = false;
  private pollTimeout: NodeJS.Timeout | null = null;
  private readonly reportService: ReportService;

  constructor() {
    this.reportService = new ReportService(pool);
    console.log(`Export Worker initialized with Worker ID: ${WORKER_ID}`);
  }

  public async start(): Promise<void> {
    this.isRunning = true;
    console.log('Export Worker starting...');
    await this.cleanupOrphanedExports();
    this.schedulePoll(0);
  }

  public stop(): void {
    this.isRunning = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
    }
    console.log('Export Worker stopped.');
  }

  private async cleanupOrphanedExports(): Promise<void> {
    try {
      console.log('Cleaning up orphaned generating reports...');
      const result = await pool.query(
        `
        UPDATE reports
        SET status = 'failed',
            error_message = 'Server/Worker restarted while report was generating',
            completed_at = NOW()
        WHERE status = 'generating'
        RETURNING id
        `
      );
      if (result.rowCount && result.rowCount > 0) {
        console.log(`Recovered and failed ${result.rowCount} orphaned generating reports.`);
      }
    } catch (error) {
      console.error('Failed to cleanup orphaned reports:', error);
    }
  }

  private schedulePoll(delayMs: number): void {
    if (!this.isRunning) return;
    if (this.pollTimeout) clearTimeout(this.pollTimeout);
    this.pollTimeout = setTimeout(() => this.poll(), delayMs);
  }

  private async poll(): Promise<void> {
    if (!this.isRunning) return;

    const maxConcurrent = exportWorkerConfig.maxConcurrentExports;
    if (this.activeExports >= maxConcurrent) {
      this.schedulePoll(exportWorkerConfig.pollIntervalMs);
      return;
    }

    try {
      const reportId = await this.claimNextJob();
      if (reportId) {
        this.activeExports++;
        this.runExportJob(reportId).catch((err) => {
          console.error(`Unhandled error in runExportJob for report ${reportId}:`, err);
        });

        // If we still have capacity, check for another job immediately
        if (this.activeExports < maxConcurrent) {
          this.schedulePoll(0);
          return;
        }
      }
    } catch (err) {
      console.error('Error claiming report job from database:', err);
    }

    this.schedulePoll(exportWorkerConfig.pollIntervalMs);
  }

  private async claimNextJob(): Promise<string | null> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Select next pending report using FOR UPDATE SKIP LOCKED
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

      // Update report record as generating
      await client.query(
        `
        UPDATE reports
        SET status = 'generating'
        WHERE id = $1
        `,
        [reportId]
      );

      await client.query('COMMIT');
      return reportId;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async runExportJob(reportId: string): Promise<void> {
    console.log(`Starting generation of report ${reportId}...`);

    let timeoutId: NodeJS.Timeout | null = null;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(`Report generation timed out after ${exportWorkerConfig.timeoutMs}ms`));
      }, exportWorkerConfig.timeoutMs);
    });

    try {
      await Promise.race([
        this.reportService.processReport(reportId),
        timeoutPromise,
      ]);
      console.log(`Report ${reportId} successfully generated.`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`Failed to generate report ${reportId}:`, errMsg);

      // Transition report status to failed
      try {
        await pool.query(
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
        console.error(`Failed to update report ${reportId} status to failed:`, dbErr);
      }
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      this.activeExports--;
      this.schedulePoll(0);
    }
  }
}

// Start worker process directly if called as main module
if (require.main === module) {
  const worker = new ExportWorker();

  const shutdown = () => {
    console.log('Received shutdown signal. Stopping Export Worker...');
    worker.stop();
    // Allow process to exit naturally
    setTimeout(() => process.exit(0), 1000).unref();
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  worker.start().catch((err) => {
    console.error('Fatal export worker startup error:', err);
    process.exit(1);
  });
}
