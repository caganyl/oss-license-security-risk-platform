/**
 * Single-process runtime (REQ-003 P-12/P-13; ADR-004 Karar 1–9).
 *
 * One process runs the API, the scan worker and the report worker on one
 * `pg.Pool`, guarded by the single-instance advisory lock held on its own
 * connection. This module never calls `process.exit` itself except through
 * the injected `exit` (forced-exit timer, lock taken over by another
 * instance); `src/main.ts` wires it to the real process.
 */
import type http from 'node:http';
import type { AddressInfo } from 'node:net';
import { Client, type Pool } from 'pg';
import { listenApp } from './app';
import { assertRequiredEnv, MissingConfigError, isLoopbackHost, resolveHost } from './config/env';
import {
  RUNTIME_LOCK_APPLICATION_NAME,
  acquireInstanceLock,
  errorCode,
  findInstanceLockHolders,
  type InstanceLock,
  type LockClient,
  type LockClientFactory,
  type LockLostEvent,
} from './db/advisoryLock';
import { checkMigrationsForStartup } from './db/migrator';
import { createPool } from './lib/db';
import { formatFatalError } from './lib/redact';
import { createRunId } from './lib/runId';
import { canonicalizeScanRoots, parseScanRoots } from './lib/scanSource';
import { ExportWorker, type ExportWorkerDeps } from './reports/worker';
import { describeGitVersion, getGitVersion, type GitVersionProvider } from './scanner/gitVersion';
import { ScanWorker, type ScanWorkerDeps } from './scanner/worker';

export type RuntimeLogger = Pick<Console, 'log' | 'warn' | 'error'>;
export type ExitFn = (code: number) => void;

/**
 * - `signal`: SIGINT/SIGTERM/SIGBREAK/SIGHUP -> exit 0
 * - `fatal`: unhandledRejection/uncaughtException -> exit 1
 * - `lock-lost`: the lock is held by another instance -> exit 1
 * - `manual`: programmatic call (tests) -> exit 0
 */
export type ShutdownReason = 'signal' | 'fatal' | 'lock-lost' | 'manual';

export type RuntimeState = 'created' | 'starting' | 'running' | 'degraded' | 'stopping' | 'stopped' | 'failed';

/** One-line start-up refusal (ADR-004 Karar 2); the process exits with `exitCode`. */
export class RuntimeStartupError extends Error {
  readonly exitCode = 1;
  constructor(message: string) {
    super(message);
    this.name = 'RuntimeStartupError';
  }
}

export const LOCK_HELD_MESSAGE = 'Bu veritabanına bağlı başka bir örnek çalışıyor veya bir göç sürüyor.';
const STARTUP_CANCELLED_MESSAGE = 'Başlangıç kapanış isteğiyle iptal edildi.';

export const DEFAULT_SHUTDOWN_TIMEOUT_MS = 15_000;
export const DEFAULT_REPORT_DRAIN_MS = 10_000;
export const DEFAULT_RELOCK_INTERVAL_MS = 5_000;

export interface RuntimeOptions {
  /** Environment (default `process.env`): DATABASE_URL, SCAN_ROOTS, PORT, HOST. */
  env?: NodeJS.ProcessEnv;
  logger?: RuntimeLogger;
  /** Called by the forced-exit timer and after a `lock-lost` shutdown. Default `process.exit`. */
  exit?: ExitFn;
  port?: number;
  host?: string;
  /** Default: the runtime's `db/migrations` folder. */
  migrationsDir?: string;
  /** Default: `parseScanRoots(env.SCAN_ROOTS)`; canonicalized at step 4. */
  scanRoots?: string[];
  /** Base folder of `ossrisk-scan-*` workspaces (default `os.tmpdir()`). */
  tmpRoot?: string;
  /** Default: `createPool({ connectionString })` (pool `error` listener attached). */
  createPool?: (connectionString: string, logger: RuntimeLogger) => Pool;
  /** Lock connection factory (tests), passed to `acquireInstanceLock`. */
  lockClientFactory?: LockClientFactory<LockClient>;
  /** Lock heartbeat (default 10 s). */
  heartbeatIntervalMs?: number;
  /** Re-acquire interval in degraded mode (default 5 s). */
  relockIntervalMs?: number;
  /** Forced exit after this long (default 15 s). */
  shutdownTimeoutMs?: number;
  /** Max wait for running reports (default 10 s). */
  reportDrainMs?: number;
  /** Run id (default `createRunId()`). */
  runId?: string;
  /** Injection points of the scan worker (cloneRepo, runParser, ...). `db`, `scanRoots`, `runId` are set by the runtime. */
  scanWorker?: Partial<Omit<ScanWorkerDeps, 'db' | 'scanRoots' | 'runId'>>;
  /** Injection points of the report worker (`reportService`, `config`, `logger`). */
  exportWorker?: Partial<Omit<ExportWorkerDeps, 'db'>>;
  /** Step 5 (never stops the start-up). Default: `defaultCheckGit` with `gitVersion`. */
  checkGit?: (logger: RuntimeLogger) => Promise<void>;
  /**
   * Git version provider (default: the cached `git --version`, ADR-002 Ek E2)
   * used by step 5 and by the scan worker's remote-scan gate, unless
   * `scanWorker.gitVersion` is given.
   */
  gitVersion?: GitVersionProvider;
}

/** What `installProcessHandlers` needs from a runtime. */
export interface ShutdownTarget {
  shutdown(reason: ShutdownReason): Promise<number>;
  readonly shuttingDown: boolean;
}

export interface RuntimeHandle extends ShutdownTarget {
  readonly state: RuntimeState;
  readonly runId: string;
  /** Available once the corresponding start-up step succeeded. */
  readonly server: http.Server | null;
  readonly pool: Pool | null;
  readonly scanWorker: ScanWorker | null;
  readonly exportWorker: ExportWorker | null;
  readonly lock: InstanceLock<LockClient> | null;
  /** Listening address (after step 6). */
  readonly address: AddressInfo | null;
  /** Runs the start-up sequence; rejects with `RuntimeStartupError` (resources closed). */
  start(): Promise<void>;
  /** Idempotent; resolves with the exit code (0, or 1 for `fatal`/`lock-lost`). */
  shutdown(reason?: ShutdownReason): Promise<number>;
}

class Runtime implements RuntimeHandle {
  state: RuntimeState = 'created';
  readonly runId: string;
  server: http.Server | null = null;
  pool: Pool | null = null;
  scanWorker: ScanWorker | null = null;
  exportWorker: ExportWorker | null = null;
  lock: InstanceLock<LockClient> | null = null;

  private readonly env: NodeJS.ProcessEnv;
  private readonly logger: RuntimeLogger;
  private readonly exit: ExitFn;
  private startPromise: Promise<void> | null = null;
  private shutdownPromise: Promise<number> | null = null;
  private shutdownRequested = false;
  private relockTimer: NodeJS.Timeout | null = null;
  private lockLostDuringStart: LockLostEvent | null = null;

  constructor(private readonly options: RuntimeOptions) {
    this.env = options.env ?? process.env;
    this.logger = options.logger ?? console;
    this.exit = options.exit ?? ((code: number) => process.exit(code));
    this.runId = options.runId ?? createRunId();
  }

  get shuttingDown(): boolean {
    return this.shutdownRequested;
  }

  get address(): AddressInfo | null {
    const addr = this.server?.address();
    return addr && typeof addr === 'object' ? addr : null;
  }

  start(): Promise<void> {
    if (!this.startPromise) this.startPromise = this.runStart();
    return this.startPromise;
  }

  private checkCancelled(): void {
    if (this.shutdownRequested) throw new RuntimeStartupError(STARTUP_CANCELLED_MESSAGE);
    if (this.lockLostDuringStart) {
      throw new RuntimeStartupError(`Tek örnek kilidinin bağlantısı başlangıçta koptu (${describeLockLoss(this.lockLostDuringStart)}).`);
    }
  }

  private async runStart(): Promise<void> {
    if (this.state !== 'created') throw new RuntimeStartupError('Çalışma zamanı zaten başlatıldı.');
    this.state = 'starting';
    try {
      // 1. Environment (REQ-002 AC-P09-3, D-52).
      try {
        assertRequiredEnv(this.env);
      } catch (err) {
        throw new RuntimeStartupError(err instanceof MissingConfigError ? err.message : 'Ortam yapılandırması geçersiz.');
      }
      const connectionString = this.env.DATABASE_URL as string;

      // 2. Database and the single-instance lock (D-34, AC-P12-4).
      let acquired;
      try {
        acquired = await acquireInstanceLock({
          connection: connectionString,
          applicationName: RUNTIME_LOCK_APPLICATION_NAME,
          clientFactory: this.options.lockClientFactory,
          heartbeatIntervalMs: this.options.heartbeatIntervalMs,
        });
      } catch (err) {
        // Class/code only: never the connection string (ADR-004 Karar 2).
        throw new RuntimeStartupError(`Veritabanına bağlanılamadı (${errorCode(err)}).`);
      }
      if (!acquired.acquired) throw new RuntimeStartupError(LOCK_HELD_MESSAGE);
      this.adoptLock(acquired.lock);
      this.checkCancelled();

      // 3. Migration check on the lock connection; never applies (D-35, AC-P12-5).
      let check;
      try {
        check = await checkMigrationsForStartup(acquired.lock.client, this.options.migrationsDir);
      } catch (err) {
        throw new RuntimeStartupError(`Göç durumu okunamadı (${errorCode(err)}).`);
      }
      if (!check.ok) throw new RuntimeStartupError(check.message);
      this.checkCancelled();

      // 4. SCAN_ROOTS (ADR-002 karar 4).
      let scanRoots: string[];
      try {
        scanRoots = await canonicalizeScanRoots(this.options.scanRoots ?? parseScanRoots(this.env.SCAN_ROOTS));
      } catch (err) {
        throw new RuntimeStartupError(`SCAN_ROOTS geçersiz: ${err instanceof Error ? err.message : errorCode(err)}`);
      }
      this.checkCancelled();

      // 5. Git version: informational, never stops the start-up (AC-T-3).
      try {
        if (this.options.checkGit) await this.options.checkGit(this.logger);
        else await defaultCheckGit(this.logger, this.options.gitVersion ?? getGitVersion);
      } catch (err) {
        this.logger.warn(`git sürüm kontrolü yapılamadı (${errorCode(err)}).`);
      }
      this.checkCancelled();

      // 6. HTTP listen (default 127.0.0.1, AC-P12-2). Nothing in the database
      // has changed so far: a busy port leaves queued scans untouched.
      const pool = (this.options.createPool ?? defaultCreatePool)(connectionString, this.logger);
      this.pool = pool;
      const host = resolveHost(this.options.host, this.env);
      try {
        this.server = await listenApp({ db: pool, port: this.options.port, host, scanRoots }, this.env);
      } catch (err) {
        throw new RuntimeStartupError(`HTTP sunucusu ${host} üzerinde dinleyemedi (${errorCode(err)}).`);
      }
      const addr = this.address;
      this.logger.log(`API dinliyor: http://${addr && !isLoopbackHost(addr.address) ? addr.address : host}:${addr?.port ?? '?'}`);
      this.checkCancelled();

      // 7. Workers: (a) orphaned scans, (b) orphaned reports, (c) stale
      // workspaces, (d) polling. Recovery errors are logged; workers start anyway.
      this.scanWorker = new ScanWorker({
        ...this.options.scanWorker,
        logger: this.options.scanWorker?.logger ?? this.logger,
        tmpRoot: this.options.scanWorker?.tmpRoot ?? this.options.tmpRoot,
        ...(this.options.gitVersion && this.options.scanWorker?.gitVersion === undefined
          ? { gitVersion: this.options.gitVersion }
          : {}),
        db: pool,
        scanRoots,
        runId: this.runId,
      });
      this.exportWorker = new ExportWorker({
        ...this.options.exportWorker,
        logger: this.options.exportWorker?.logger ?? this.logger,
        db: pool,
      });
      await this.scanWorker.recoverOrphanedScans();
      await this.exportWorker.recoverOrphanedReports();
      await this.scanWorker.sweepWorkspaces();
      this.checkCancelled();
      this.scanWorker.startPolling();
      this.exportWorker.startPolling();
      this.state = 'running';
      this.logger.log(`Uygulama hazır (çalışma kimliği ${this.runId}).`);
    } catch (err) {
      await this.closeAfterFailedStart();
      this.state = 'failed';
      if (err instanceof RuntimeStartupError) throw err;
      throw new RuntimeStartupError(`Başlangıç başarısız (${errorCode(err)}).`);
    }
  }

  private async closeAfterFailedStart(): Promise<void> {
    this.scanWorker?.stop();
    this.exportWorker?.stop();
    if (this.server) {
      const server = this.server;
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    }
    if (this.pool) await this.pool.end().catch(() => undefined);
    // The lock goes last (ADR-004 implementer warning 3).
    if (this.lock) await this.lock.release();
  }

  // -------------------------------------------------------------------------
  // Lock loss / degraded mode (ADR-004 Karar 3, AC-P12-15)
  // -------------------------------------------------------------------------

  private adoptLock(lock: InstanceLock<LockClient>): void {
    this.lock = lock;
    lock.onLost((event) => this.onLockLost(event));
    lock.startHeartbeat();
  }

  private onLockLost(event: LockLostEvent): void {
    if (this.state === 'starting') {
      this.lockLostDuringStart = event;
      return;
    }
    if (this.state !== 'running') return;
    this.state = 'degraded';
    this.logger.warn(
      `Tek örnek kilidinin bağlantısı koptu (${describeLockLoss(event)}); bozulmuş kip: worker'lar yeni iş almıyor, kilit yeniden deneniyor.`,
    );
    this.scanWorker?.pause();
    this.exportWorker?.pause();
    this.scheduleRelock();
  }

  private scheduleRelock(): void {
    if (this.state !== 'degraded') return;
    if (this.relockTimer) clearTimeout(this.relockTimer);
    this.relockTimer = setTimeout(() => {
      this.relockTimer = null;
      this.tryRelock().catch((err) => {
        this.logger.error(`Kilit yeniden alma denemesi başarısız (${errorCode(err)}).`);
        this.scheduleRelock();
      });
    }, this.options.relockIntervalMs ?? DEFAULT_RELOCK_INTERVAL_MS);
  }

  private async tryRelock(): Promise<void> {
    if (this.state !== 'degraded') return;
    const previousPid = this.lock?.backendPid ?? null;
    let result;
    try {
      result = await acquireInstanceLock({
        connection: this.env.DATABASE_URL as string,
        applicationName: RUNTIME_LOCK_APPLICATION_NAME,
        clientFactory: this.options.lockClientFactory,
        heartbeatIntervalMs: this.options.heartbeatIntervalMs,
      });
    } catch (err) {
      // Database still unreachable: keep trying.
      this.logger.warn(`Kilit yeniden alınamadı (${errorCode(err)}); tekrar denenecek.`);
      this.scheduleRelock();
      return;
    }
    if (this.state !== 'degraded') {
      if (result.acquired) await result.lock.release();
      return;
    }
    if (result.acquired) {
      this.adoptLock(result.lock);
      this.state = 'running';
      this.logger.log('Tek örnek kilidi yeniden alındı; worker\'lar devam ediyor.');
      // No orphan recovery here: the running scans are this process's (Karar 3).
      this.scanWorker?.resume();
      this.exportWorker?.resume();
      return;
    }
    // Held by someone: our own half-open old session, or another instance.
    if (previousPid !== null && (await this.onlyHolderIs(previousPid))) {
      this.logger.warn('Kilit hâlâ önceki (kopmuş) oturumda görünüyor; tekrar denenecek.');
      this.scheduleRelock();
      return;
    }
    this.logger.error('Tek örnek kilidi başka bir örneğe geçti; kapanılıyor.');
    const code = await this.shutdown('lock-lost');
    this.exit(code);
  }

  private async onlyHolderIs(pid: number): Promise<boolean> {
    const factory = this.options.lockClientFactory;
    const config = { connectionString: this.env.DATABASE_URL as string, application_name: RUNTIME_LOCK_APPLICATION_NAME };
    const client: LockClient = factory ? factory(config) : new Client(config);
    client.on('error', () => undefined);
    try {
      await client.connect();
      const holders = await findInstanceLockHolders(client);
      return holders.length > 0 && holders.every((h) => h === pid);
    } catch {
      return false;
    } finally {
      await client.end().catch(() => undefined);
    }
  }

  // -------------------------------------------------------------------------
  // Shutdown (ADR-004 Karar 5, AC-P12-10)
  // -------------------------------------------------------------------------

  shutdown(reason: ShutdownReason = 'manual'): Promise<number> {
    if (!this.shutdownPromise) {
      this.shutdownRequested = true;
      this.shutdownPromise = this.runShutdown(reason);
    }
    return this.shutdownPromise;
  }

  private async runShutdown(reason: ShutdownReason): Promise<number> {
    const exitCode = reason === 'fatal' || reason === 'lock-lost' ? 1 : 0;
    const budgetMs = this.options.shutdownTimeoutMs ?? DEFAULT_SHUTDOWN_TIMEOUT_MS;
    const startedAt = Date.now();
    // 1. Forced exit timer: deliberately not unref'd (implementer warning 6).
    const forceTimer = setTimeout(() => {
      this.logger.error(`Kapanış ${Math.round(budgetMs / 1000)} sn'de tamamlanamadı; zorla çıkılıyor.`);
      this.exit(1);
    }, budgetMs);
    this.logger.log(`Kapanış başladı (${reason}).`);

    try {
      // A start-up in progress is cancelled; its failure path closes what it opened.
      if (this.startPromise && this.state === 'starting') {
        await this.startPromise.catch(() => undefined);
      }
      const wasStarted = this.state === 'running' || this.state === 'degraded';
      this.state = 'stopping';
      if (this.relockTimer) {
        clearTimeout(this.relockTimer);
        this.relockTimer = null;
      }
      if (!wasStarted) {
        // Nothing (left) open: start never ran, or failed and cleaned up.
        return exitCode;
      }

      // 2. No new connections.
      const server = this.server;
      const serverClosed = server
        ? new Promise<void>((resolve) => server.close(() => resolve()))
        : Promise.resolve();
      server?.closeIdleConnections();

      // 3. Workers stop polling; lock heartbeat stops.
      this.scanWorker?.stop();
      this.exportWorker?.enterShutdown();
      this.lock?.stopHeartbeat();

      // 4. Running scans: abort with reason 'shutdown'; each returns its row to `queued`.
      await this.scanWorker?.abortActiveJobs('shutdown');

      // 5. Running reports cannot be cancelled: wait within the remaining budget.
      const remaining = budgetMs - (Date.now() - startedAt) - 2_000;
      const drainMs = Math.max(0, Math.min(this.options.reportDrainMs ?? DEFAULT_REPORT_DRAIN_MS, remaining));
      const drained = (await this.exportWorker?.waitForIdle(drainMs)) ?? true;
      if (!drained) this.logger.warn('Süren raporlar beklenen sürede bitmedi; pending yapılacak.');

      // 6. Sweep: this run's `running` scans -> queued, every `generating` report -> pending.
      if (this.pool) {
        try {
          const res = await this.pool.query<{ scans: number; reports: number }>(
            `WITH s AS (
               UPDATE scans
               SET status = 'queued', next_attempt_at = NULL, worker_id = NULL, updated_at = NOW()
               WHERE status = 'running' AND worker_id = $1
               RETURNING id
             ), r AS (
               UPDATE reports SET status = 'pending' WHERE status = 'generating' RETURNING id
             )
             SELECT (SELECT count(*) FROM s)::int AS scans, (SELECT count(*) FROM r)::int AS reports`,
            [this.runId],
          );
          const row = res.rows[0];
          if (row && (row.scans > 0 || row.reports > 0)) {
            this.logger.log(`Kapanış süpürmesi: ${row.scans} tarama queued, ${row.reports} rapor pending yapıldı.`);
          }
        } catch (err) {
          this.logger.error(`Kapanış süpürmesi yazılamadı (${errorCode(err)}); sonraki başlangıçta kurtarılacak.`);
        }
      }

      // 7. Remaining connections, pool.
      server?.closeAllConnections();
      await serverClosed;
      if (this.pool) await this.pool.end().catch((err) => this.logger.error(`Havuz kapatılamadı (${errorCode(err)}).`));

      // 8. The lock goes last: no second instance while this one may still write.
      if (this.lock) await this.lock.release();
      this.logger.log('Kapanış tamamlandı.');
      return exitCode;
    } catch (err) {
      this.logger.error(`Kapanış sırasında hata (${errorCode(err)}).`);
      if (this.lock) await this.lock.release();
      return 1;
    } finally {
      // 9.
      clearTimeout(forceTimer);
      this.state = 'stopped';
    }
  }
}

function describeLockLoss(event: LockLostEvent): string {
  return event.code ? `${event.reason}, ${event.code}` : event.reason;
}

function defaultCreatePool(connectionString: string, logger: RuntimeLogger): Pool {
  return createPool({ connectionString, logger });
}

/**
 * Step 5 of ADR-004 Karar 2 / ADR-002 Ek E2: reads the (cached) git version
 * through `provider` and logs it; a warning when git is missing or older than
 * 2.32. Never throws a startup error: remote scans fail on their own
 * (`GitUnavailableError`, AC-T-3), local scans are unaffected.
 */
export async function defaultCheckGit(logger: RuntimeLogger, provider: GitVersionProvider = getGitVersion): Promise<void> {
  const { level, message } = describeGitVersion(await provider());
  if (level === 'warn') logger.warn(message);
  else logger.log(message);
}

/** Creates a runtime without any I/O; call `start()` (after `installProcessHandlers`). */
export function createRuntime(options: RuntimeOptions = {}): RuntimeHandle {
  return new Runtime(options);
}

/**
 * `createRuntime(options).start()`: resolves with the running handle, or
 * rejects with `RuntimeStartupError` after closing everything it opened.
 */
export async function startRuntime(options: RuntimeOptions = {}): Promise<RuntimeHandle> {
  const runtime = createRuntime(options);
  await runtime.start();
  return runtime;
}

// ---------------------------------------------------------------------------
// Process handlers (ADR-004 Karar 5, 6; AC-P12-9, AC-P12-10)
// ---------------------------------------------------------------------------

export const SHUTDOWN_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGBREAK', 'SIGHUP'] as const;

/** The part of `process` the handlers use; tests pass an `EventEmitter`. */
export interface ProcessLike {
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  removeListener(event: string, listener: (...args: unknown[]) => void): unknown;
  env?: NodeJS.ProcessEnv;
}

/**
 * Wires signals and process-level errors to `runtime.shutdown`:
 * - SIGINT/SIGTERM/SIGBREAK/SIGHUP -> `shutdown('signal')`, then `exit(code)`;
 * - unhandledRejection/uncaughtException -> one redacted log entry,
 *   `shutdown('fatal')`, `exit(1)`;
 * - any second signal or fatal error while shutting down -> `exit(1)` at once.
 * Returns a function that removes the listeners.
 */
export function installProcessHandlers(
  runtime: ShutdownTarget,
  proc: ProcessLike = process as unknown as ProcessLike,
  exit: ExitFn = (code: number) => process.exit(code),
  logger: RuntimeLogger = console,
): () => void {
  const env = proc.env ?? process.env;
  let begun = false;

  const begin = (reason: ShutdownReason) => {
    if (begun || runtime.shuttingDown) {
      logger.error('Kapanış sürerken ikinci sinyal/hata alındı; beklemeden çıkılıyor.');
      exit(1);
      return;
    }
    begun = true;
    runtime.shutdown(reason).then(
      (code) => exit(code),
      () => exit(1),
    );
  };

  const listeners: Array<[string, (...args: unknown[]) => void]> = [];
  for (const signal of SHUTDOWN_SIGNALS) {
    const listener = () => {
      logger.log(`${signal} alındı.`);
      begin('signal');
    };
    listeners.push([signal, listener]);
  }
  listeners.push([
    'unhandledRejection',
    (reason: unknown) => {
      logger.error(formatFatalError('unhandledRejection', reason, env));
      begin('fatal');
    },
  ]);
  listeners.push([
    'uncaughtException',
    (error: unknown) => {
      logger.error(formatFatalError('uncaughtException', error, env));
      begin('fatal');
    },
  ]);

  for (const [event, listener] of listeners) proc.on(event, listener);
  return () => {
    for (const [event, listener] of listeners) proc.removeListener(event, listener);
  };
}
