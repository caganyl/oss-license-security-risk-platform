/**
 * Single-instance lock shared by the runtime (`npm start`) and the migration
 * tool (`npm run db:migrate`). REQ-003 D-34, AC-P11-11, AC-P12-4, AC-P12-15;
 * ADR-004 Karar 3 and Karar 10.
 *
 * - PostgreSQL session-level advisory lock, two-int4-key form, non-blocking:
 *   `pg_try_advisory_lock(1330860882, 1)`. 1330860882 = 0x4F535352 ("OSSR"),
 *   1 = single-instance lock. The key is FROZEN: changing it would let an old
 *   and a new build run against the same database at the same time.
 * - The lock lives on its own `pg.Client`, never on a pool connection (pool
 *   connections are closed/reused, which would silently drop the lock).
 * - This module only owns the lock itself: acquire, release, heartbeat and the
 *   "lock connection lost" event. What to do when the lock is lost (degraded
 *   mode, re-acquire every 5 s, shutdown) is the runtime's decision.
 * - Nothing here logs. Errors surfaced to callers carry only an error class /
 *   code, never the connection string or password.
 */
import { Client, type ClientConfig } from 'pg';

/** First int4 key: ASCII "OSSR" (0x4F535352), the "OSS Risk" namespace. Frozen. */
export const INSTANCE_LOCK_NAMESPACE = 1330860882;
/** Second int4 key: the single-instance lock. Frozen. */
export const INSTANCE_LOCK_ID = 1;

/** application_name of the runtime's lock connection (ADR-004 Karar 3). */
export const RUNTIME_LOCK_APPLICATION_NAME = 'oss-risk:instance';
/** application_name of the migration tool's connection (ADR-004 Karar 10). */
export const MIGRATE_LOCK_APPLICATION_NAME = 'oss-risk:migrate';

export const DEFAULT_HEARTBEAT_INTERVAL_MS = 10_000;
export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 5_000;
export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

// The keys are compile-time constants, so they are inlined as literals (no
// parameters): exactly the statement ADR-004 documents.
const TRY_LOCK_SQL =
  `SELECT pg_try_advisory_lock(${INSTANCE_LOCK_NAMESPACE}, ${INSTANCE_LOCK_ID}) AS acquired, ` +
  'pg_backend_pid() AS pid';
const UNLOCK_SQL = `SELECT pg_advisory_unlock(${INSTANCE_LOCK_NAMESPACE}, ${INSTANCE_LOCK_ID}) AS released`;
const HEARTBEAT_SQL = 'SELECT 1';
// Two-int4 advisory keys are stored as classid = key1, objid = key2, objsubid = 2.
const HOLDERS_SQL =
  'SELECT pid FROM pg_locks ' +
  "WHERE locktype = 'advisory' AND granted " +
  'AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) ' +
  `AND classid = ${INSTANCE_LOCK_NAMESPACE} AND objid = ${INSTANCE_LOCK_ID} AND objsubid = 2 ` +
  'ORDER BY pid';

/** Anything with a text-only `query` (a `pg.Client`, a test double, ...). */
export interface LockQueryable {
  query(text: string): Promise<{ rows: unknown[] }>;
}

/**
 * Minimal client surface the lock needs. `pg.Client` satisfies it; tests can
 * pass a fake through `clientFactory`.
 */
export interface LockClient extends LockQueryable {
  connect(): Promise<unknown>;
  end(): Promise<unknown>;
  on(event: 'error', listener: (err: Error) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
}

export type LockClientFactory<C extends LockClient> = (config: ClientConfig) => C;

/** Why the lock connection is considered lost. No message text on purpose. */
export interface LockLostEvent {
  reason: 'connection-error' | 'connection-ended' | 'heartbeat-failed' | 'heartbeat-timeout';
  /** Error class or code only (`ECONNRESET`, `57P01`, `Error`, ...). */
  code?: string;
}

export type LockLostListener = (event: LockLostEvent) => void;

export interface InstanceLockOptions<C extends LockClient = Client> {
  /** `DATABASE_URL` or a `pg` client config. Never logged by this module. */
  connection: string | ClientConfig;
  /** `oss-risk:instance` (runtime) or `oss-risk:migrate` (migration tool). */
  applicationName: string;
  /** Defaults to `new pg.Client(config)`. */
  clientFactory?: LockClientFactory<C>;
  /** Default 10 s. Applied only if `connection` does not set its own. */
  connectTimeoutMs?: number;
  /** Default 10 s (ADR-004 Karar 3). */
  heartbeatIntervalMs?: number;
  /** Default 5 s (ADR-004 Karar 3). */
  heartbeatTimeoutMs?: number;
}

export interface InstanceLock<C extends LockClient = Client> {
  /**
   * The dedicated lock connection. The runtime may use it only for the
   * start-up migration check; the migration tool runs its whole command on
   * it. It must never be handed to a pool.
   */
  readonly client: C;
  /** Server process id of the session holding the lock (`pg_backend_pid()`). */
  readonly backendPid: number | null;
  /** True once the connection was considered lost (see `onLost`); stays true after `release()`. */
  readonly lost: boolean;
  /** True once `release()` was called. */
  readonly released: boolean;
  /**
   * Fires at most once, when the lock connection errors, ends unexpectedly or
   * a heartbeat fails/times out. The lock must then be treated as gone on the
   * server side. Listeners added after the loss are called immediately.
   * Returns an unsubscribe function.
   */
  onLost(listener: LockLostListener): () => void;
  /** Starts the `SELECT 1` heartbeat (runtime only). Idempotent. */
  startHeartbeat(): void;
  /** Stops the heartbeat. Idempotent. */
  stopHeartbeat(): void;
  /**
   * Unlocks and closes the connection. Never throws (shutdown path); returns
   * true only if PostgreSQL confirmed the unlock. Idempotent.
   */
  release(): Promise<boolean>;
}

export type AcquireInstanceLockResult<C extends LockClient = Client> =
  | { acquired: true; lock: InstanceLock<C> }
  /** Lock held by another session (another instance or a migration). */
  | { acquired: false };

/** Error class/code of an arbitrary error, safe to log (no message text). */
export function errorCode(err: unknown): string {
  if (err && typeof err === 'object') {
    const code = (err as { code?: unknown }).code;
    if (typeof code === 'string' && code !== '') return code;
    const name = (err as { name?: unknown }).name;
    if (typeof name === 'string' && name !== '') return name;
  }
  return typeof err;
}

/**
 * Low-level primitive: `pg_try_advisory_lock` on an already connected client.
 * Returns true if this session now holds the lock.
 */
export async function tryAcquireInstanceLock(client: LockQueryable): Promise<boolean> {
  const res = await client.query(TRY_LOCK_SQL);
  const row = res.rows[0] as { acquired?: unknown } | undefined;
  return row?.acquired === true;
}

/** Low-level primitive: `pg_advisory_unlock`. True if this session held the lock. */
export async function releaseInstanceLock(client: LockQueryable): Promise<boolean> {
  const res = await client.query(UNLOCK_SQL);
  const row = res.rows[0] as { released?: unknown } | undefined;
  return row?.released === true;
}

/**
 * Server pids currently holding the instance lock in the current database
 * (normally zero or one). Diagnostic helper for the runtime (e.g. to tell a
 * lingering half-open session of its own apart from another instance) and for
 * tests.
 */
export async function findInstanceLockHolders(client: LockQueryable): Promise<number[]> {
  const res = await client.query(HOLDERS_SQL);
  return res.rows.map((r) => Number((r as { pid: unknown }).pid));
}

function buildClientConfig(options: InstanceLockOptions<LockClient>): ClientConfig {
  const base: ClientConfig =
    typeof options.connection === 'string' ? { connectionString: options.connection } : { ...options.connection };
  return {
    ...base,
    application_name: options.applicationName,
    keepAlive: true,
    connectionTimeoutMillis: base.connectionTimeoutMillis ?? options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
  };
}

/**
 * Opens a dedicated connection and tries to take the instance lock.
 *
 * - `{ acquired: true, lock }`: the caller owns the lock until
 *   `lock.release()` (or until the process/connection dies, when PostgreSQL
 *   drops it).
 * - `{ acquired: false }`: another session holds it; the connection has
 *   already been closed.
 * - Throws on connection/query errors (the connection is closed first). The
 *   error is the original `pg`/Node error; log it with `errorCode(err)` only.
 */
export async function acquireInstanceLock<C extends LockClient = Client>(
  options: InstanceLockOptions<C>,
): Promise<AcquireInstanceLockResult<C>> {
  const factory = (options.clientFactory ?? ((config: ClientConfig) => new Client(config))) as LockClientFactory<C>;
  const client = factory(buildClientConfig(options as InstanceLockOptions<LockClient>));

  const heartbeatIntervalMs = options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
  const heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;

  let state: 'connecting' | 'held' | 'released' | 'lost' = 'connecting';
  let lostEvent: LockLostEvent | null = null;
  const listeners = new Set<LockLostListener>();
  let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  let heartbeatInFlight = false;
  let backendPid: number | null = null;

  const stopHeartbeat = (): void => {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
  };

  const markLost = (event: LockLostEvent): void => {
    if (state !== 'held') return;
    state = 'lost';
    lostEvent = event;
    stopHeartbeat();
    // Best effort: a half-open socket must not linger. Not awaited.
    Promise.resolve()
      .then(() => client.end())
      .catch(() => undefined);
    for (const listener of [...listeners]) {
      try {
        listener(event);
      } catch {
        // A faulty listener must not break the others or crash the process.
      }
    }
  };

  // Required before connect (ADR-004 implementer warning 7): an 'error' event
  // without a listener would crash the process. Stays attached for the
  // lifetime of the client, including after release.
  client.on('error', (err: Error) => markLost({ reason: 'connection-error', code: errorCode(err) }));
  client.on('end', () => markLost({ reason: 'connection-ended' }));

  const closeQuietly = async (): Promise<void> => {
    try {
      await client.end();
    } catch {
      // already closed / never opened
    }
  };

  let acquired: boolean;
  try {
    await client.connect();
    const res = await client.query(TRY_LOCK_SQL);
    const row = res.rows[0] as { acquired?: unknown; pid?: unknown } | undefined;
    acquired = row?.acquired === true;
    backendPid = row?.pid === undefined || row?.pid === null ? null : Number(row.pid);
  } catch (err) {
    state = 'released';
    await closeQuietly();
    throw err;
  }

  if (!acquired) {
    state = 'released';
    await closeQuietly();
    return { acquired: false };
  }
  state = 'held';

  const heartbeat = async (): Promise<void> => {
    if (heartbeatInFlight || state !== 'held') return;
    heartbeatInFlight = true;
    let timeout: ReturnType<typeof setTimeout> | null = null;
    try {
      const outcome = await Promise.race([
        client.query(HEARTBEAT_SQL).then(
          () => ({ ok: true as const }),
          (err: unknown) => ({ ok: false as const, event: { reason: 'heartbeat-failed', code: errorCode(err) } as LockLostEvent }),
        ),
        new Promise<{ ok: false; event: LockLostEvent }>((resolve) => {
          timeout = setTimeout(() => resolve({ ok: false, event: { reason: 'heartbeat-timeout' } }), heartbeatTimeoutMs);
          timeout.unref?.();
        }),
      ]);
      if (!outcome.ok) markLost(outcome.event);
    } finally {
      if (timeout) clearTimeout(timeout);
      heartbeatInFlight = false;
    }
  };

  const lock: InstanceLock<C> = {
    client,
    get backendPid() {
      return backendPid;
    },
    get lost() {
      return lostEvent !== null;
    },
    get released() {
      return state === 'released';
    },
    onLost(listener: LockLostListener) {
      if (state === 'lost' && lostEvent) {
        try {
          listener(lostEvent);
        } catch {
          // see markLost
        }
        return () => undefined;
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    startHeartbeat() {
      if (heartbeatTimer || state !== 'held') return;
      heartbeatTimer = setInterval(() => {
        heartbeat().catch(() => undefined);
      }, heartbeatIntervalMs);
      heartbeatTimer.unref?.();
    },
    stopHeartbeat,
    async release() {
      if (state === 'released') return false;
      const wasHeld = state === 'held';
      // Set first so the 'end' event caused by client.end() is not a "loss".
      state = 'released';
      stopHeartbeat();
      listeners.clear();
      let unlocked = false;
      if (wasHeld) {
        try {
          unlocked = await releaseInstanceLock(client);
        } catch {
          // Connection already broken: the server drops the lock with the session.
        }
      }
      await closeQuietly();
      return unlocked;
    },
  };

  return { acquired: true, lock };
}
