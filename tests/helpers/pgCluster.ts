/**
 * Throw-away PostgreSQL cluster for tests (embedded-postgres, AC-G-5).
 *
 * - Data directory under os.tmpdir(), persistent:false (deleted on stop).
 * - Random free port and a random per-run password (never a fixed secret).
 * - initdb with --locale=C --encoding=UTF8: initdb fails under the Turkish
 *   Windows locale otherwise.
 * - A template database with all db/migrations applied; tests clone it with
 *   CREATE DATABASE ... TEMPLATE, which is much faster than re-migrating.
 *
 * This file must not import from 'vitest' (it is also used by the optional
 * globalSetup in tests/helpers/pgGlobalSetup.ts, which runs in the main
 * process).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Client } from 'pg';
import { applyMigrations } from './migrations';

export interface ClusterInfo {
  host: string;
  port: number;
  user: string;
  password: string;
  /** Database with db/migrations/*.up.sql applied; used as CREATE DATABASE template. */
  templateDb: string;
}

export interface RunningCluster {
  info: ClusterInfo;
  stop(): Promise<void>;
}

interface EmbeddedPostgresInstance {
  initialise(): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
}
type EmbeddedPostgresCtor = new (options: Record<string, unknown>) => EmbeddedPostgresInstance;

export const TEMPLATE_DB = 'ossr_template';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

export function adminClient(info: ClusterInfo, database = 'postgres'): Client {
  return new Client({
    host: info.host,
    port: info.port,
    user: info.user,
    password: info.password,
    database,
  });
}

export function databaseUrl(info: ClusterInfo, database: string): string {
  return `postgres://${encodeURIComponent(info.user)}:${encodeURIComponent(info.password)}@${info.host}:${info.port}/${encodeURIComponent(database)}`;
}

export async function startCluster(): Promise<RunningCluster> {
  // embedded-postgres is ESM-only and has no "main"/"types" for the
  // CommonJS/node10 resolution used by tsconfig; a computed specifier keeps
  // tsc from resolving it while Vitest loads it natively.
  const specifier = 'embedded-postgres';
  const mod = (await import(/* @vite-ignore */ specifier)) as { default: EmbeddedPostgresCtor };

  const info: ClusterInfo = {
    host: '127.0.0.1',
    port: await freePort(),
    user: 'postgres',
    password: crypto.randomBytes(24).toString('base64url'),
    templateDb: TEMPLATE_DB,
  };
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-test-pg-'));
  const logs: string[] = [];
  const pg = new mod.default({
    databaseDir: dataDir,
    port: info.port,
    user: info.user,
    password: info.password,
    persistent: false,
    initdbFlags: ['--locale=C', '--encoding=UTF8'],
    onLog: (message: string) => {
      logs.push(message);
      if (logs.length > 200) logs.shift();
    },
    onError: (err: unknown) => {
      logs.push(String(err));
    },
  });

  try {
    await pg.initialise();
    await pg.start();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`embedded PostgreSQL failed to start: ${msg}\n${logs.slice(-20).join('')}`);
  }

  const admin = adminClient(info);
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${TEMPLATE_DB}`);
  } finally {
    await admin.end();
  }
  const tmpl = adminClient(info, TEMPLATE_DB);
  await tmpl.connect();
  try {
    await applyMigrations(tmpl);
  } finally {
    await tmpl.end();
  }

  return {
    info,
    async stop() {
      try {
        await pg.stop();
      } catch {
        // best effort; data dir lives under os.tmpdir()
      }
    },
  };
}

let counter = 0;
export function uniqueDbName(prefix = 't'): string {
  counter += 1;
  return `${prefix}_${process.pid}_${Date.now().toString(36)}_${counter}_${crypto.randomBytes(3).toString('hex')}`;
}

/** Creates a database. template: TEMPLATE_DB (migrated) or 'template0' (empty). */
export async function createDatabase(info: ClusterInfo, name: string, template: string): Promise<void> {
  const admin = adminClient(info);
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${name}" TEMPLATE "${template}"`);
  } finally {
    await admin.end();
  }
}

export async function dropDatabase(info: ClusterInfo, name: string): Promise<void> {
  const admin = adminClient(info);
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}
