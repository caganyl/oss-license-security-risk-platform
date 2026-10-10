import { Pool } from 'pg';
import { errorCode } from '../db/advisoryLock';

/**
 * The single `pg.Pool` of the process (REQ-003 P-12, ADR-004 Karar 1).
 *
 * There is no module-level pool any more: the runtime (`src/runtime.ts`)
 * creates exactly one and injects it into the API and both workers. Importing
 * this module never opens a connection.
 */
export interface CreatePoolOptions {
  /** `DATABASE_URL`. Never logged. */
  connectionString: string;
  /** Receives one line per idle-client error (error class/code only). */
  logger?: Pick<Console, 'error'>;
  env?: NodeJS.ProcessEnv;
}

/** `application_name` of the pool connections (the lock uses `oss-risk:instance`). */
export const POOL_APPLICATION_NAME = 'oss-risk:app';

export function createPool(options: CreatePoolOptions): Pool {
  const env = options.env ?? process.env;
  const logger = options.logger ?? console;
  const pool = new Pool({
    connectionString: options.connectionString,
    application_name: POOL_APPLICATION_NAME,
    max: Number(env.DB_POOL_MAX) || 20,
    idleTimeoutMillis: Number(env.DB_POOL_IDLE_TIMEOUT_MS) || 30000,
    connectionTimeoutMillis: Number(env.DB_POOL_CONN_TIMEOUT_MS) || 2000,
  });
  // Required (ADR-004 implementer warning 7): an idle client losing its
  // connection emits 'error' on the pool; without a listener that would crash
  // the process (AC-P12-8). The pg error object can carry host/user names, so
  // only its class/code is logged.
  pool.on('error', (err: Error) => {
    logger.error(`Veritabanı havuzu: boştaki bağlantı hatası (${errorCode(err)}).`);
  });
  return pool;
}
