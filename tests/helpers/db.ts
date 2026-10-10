/**
 * Per-file / per-test PostgreSQL databases for Vitest (AC-G-5).
 *
 * Cluster acquisition:
 *   1. If tests/helpers/pgGlobalSetup.ts is registered as Vitest globalSetup,
 *      the single shared cluster it provides is used.
 *   2. Otherwise (current vitest.config.ts has no globalSetup) each test file
 *      lazily starts its own embedded cluster and stops it in afterAll.
 * Either way every database is created from the migrated template and
 * dropped afterwards; the developer's database (DATABASE_URL from .env) is
 * never used.
 */
import { afterAll, afterEach, beforeAll, beforeEach, inject } from 'vitest';
import { Pool, type QueryResultRow } from 'pg';
import {
  TEMPLATE_DB,
  createDatabase,
  databaseUrl,
  dropDatabase,
  startCluster,
  uniqueDbName,
  type ClusterInfo,
  type RunningCluster,
} from './pgCluster';

declare module 'vitest' {
  export interface ProvidedContext {
    ossrTestPgCluster: ClusterInfo;
  }
}

let localCluster: Promise<RunningCluster> | undefined;
let users = 0;

async function acquireCluster(): Promise<ClusterInfo> {
  users += 1;
  const provided = inject('ossrTestPgCluster') as ClusterInfo | undefined;
  if (provided) return provided;
  localCluster ??= startCluster();
  return (await localCluster).info;
}

async function releaseCluster(): Promise<void> {
  users -= 1;
  if (users <= 0 && localCluster) {
    const running = await localCluster.catch(() => undefined);
    localCluster = undefined;
    await running?.stop();
  }
}

export interface TestDatabase {
  readonly pool: Pool;
  readonly url: string;
  readonly name: string;
  readonly cluster: ClusterInfo;
  query<R extends QueryResultRow = QueryResultRow>(text: string, values?: unknown[]): Promise<R[]>;
}

export interface UseTestDatabaseOptions {
  /** 'file': one database for the whole file; 'test': a fresh database per test. */
  scope?: 'file' | 'test';
  /** true (default): clone the migrated template; false: empty database. */
  migrated?: boolean;
  /** Also point process.env.DATABASE_URL at the test database (restored afterwards). */
  setDatabaseUrlEnv?: boolean;
}

/**
 * Registers the hooks and returns a handle whose properties become valid
 * inside tests/hooks. Call once at the top level of a test file.
 */
export function useTestDatabase(options: UseTestDatabaseOptions = {}): TestDatabase {
  const scope = options.scope ?? 'file';
  const template = options.migrated === false ? 'template0' : TEMPLATE_DB;
  const state: { cluster?: ClusterInfo; pool?: Pool; name?: string; url?: string } = {};
  const previousDatabaseUrl = process.env.DATABASE_URL;

  async function open(): Promise<void> {
    const cluster = state.cluster!;
    const name = uniqueDbName();
    await createDatabase(cluster, name, template);
    state.name = name;
    state.url = databaseUrl(cluster, name);
    state.pool = new Pool({ connectionString: state.url, max: 10 });
    if (options.setDatabaseUrlEnv) process.env.DATABASE_URL = state.url;
  }

  async function close(): Promise<void> {
    const pool = state.pool;
    const name = state.name;
    state.pool = undefined;
    state.name = undefined;
    await pool?.end().catch(() => undefined);
    if (name) await dropDatabase(state.cluster!, name).catch(() => undefined);
  }

  beforeAll(async () => {
    state.cluster = await acquireCluster();
    if (scope === 'file') await open();
  }, 240_000);

  if (scope === 'test') {
    beforeEach(open, 60_000);
    afterEach(close, 60_000);
  }

  afterAll(async () => {
    if (scope === 'file') await close();
    if (options.setDatabaseUrlEnv) {
      if (previousDatabaseUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = previousDatabaseUrl;
    }
    await releaseCluster();
  }, 120_000);

  function need<T>(value: T | undefined, what: string): T {
    if (value === undefined) throw new Error(`test database ${what} used outside a test/hook`);
    return value;
  }

  return {
    get pool() {
      return need(state.pool, 'pool');
    },
    get url() {
      return need(state.url, 'url');
    },
    get name() {
      return need(state.name, 'name');
    },
    get cluster() {
      return need(state.cluster, 'cluster');
    },
    async query<R extends QueryResultRow = QueryResultRow>(text: string, values?: unknown[]): Promise<R[]> {
      const res = await need(state.pool, 'pool').query<R>(text, values);
      return res.rows;
    },
  };
}

export interface ScratchDatabase {
  readonly name: string;
  /** postgres://user:password@127.0.0.1:port/name (test cluster, random per-run password). */
  readonly url: string;
  readonly cluster: ClusterInfo;
  /** Small pool (max 3) for assertions; closed together with the database. */
  readonly pool: Pool;
  query<R extends QueryResultRow = QueryResultRow>(text: string, values?: unknown[]): Promise<R[]>;
}

/**
 * Extra throw-away databases on the cluster of `base`. REQ-003 P-11/P-12
 * tests need several per test (empty, F1 state, migrated, a second database
 * for the per-database instance lock). Every database created through the
 * returned function is dropped (WITH FORCE) after the test.
 */
export function useScratchDatabases(base: TestDatabase): (options?: { migrated?: boolean }) => Promise<ScratchDatabase> {
  const created: Array<{ name: string; pool: Pool; cluster: ClusterInfo }> = [];

  afterEach(async () => {
    for (const db of created.splice(0)) {
      await db.pool.end().catch(() => undefined);
      await dropDatabase(db.cluster, db.name).catch(() => undefined);
    }
  }, 60_000);

  return async (options = {}) => {
    const cluster = base.cluster;
    const name = uniqueDbName('s');
    await createDatabase(cluster, name, options.migrated === false ? 'template0' : TEMPLATE_DB);
    const url = databaseUrl(cluster, name);
    const pool = new Pool({ connectionString: url, max: 3 });
    pool.on('error', () => undefined);
    created.push({ name, pool, cluster });
    return {
      name,
      url,
      cluster,
      pool,
      async query<R extends QueryResultRow = QueryResultRow>(text: string, values?: unknown[]): Promise<R[]> {
        return (await pool.query<R>(text, values)).rows;
      },
    };
  };
}
