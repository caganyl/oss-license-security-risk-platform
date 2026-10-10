/**
 * Migration library (REQ-003 P-11, AC-P11-1…13, 16…18; ADR-004 Karar 10).
 *
 * Pure core shared by the CLI (`src/db/migrate.ts`) and the runtime start-up
 * check (`checkMigrationsForStartup`). It never opens connections, never takes
 * the instance lock and never logs on its own: callers pass an already
 * connected client (the lock connection) and an optional `log` callback.
 *
 * Compatibility with the F1 `db/migrate.sh` (AC-P11-3): same
 * `schema_migrations(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL
 * DEFAULT NOW())` table, same version names (file name minus `.up.sql` /
 * `.down.sql`), one transaction per file together with its bookkeeping row.
 *
 * Migration SQL is sent with a single-argument `client.query(sql)` (simple
 * query protocol): multi-statement files and `$$` blocks work. Passing a
 * values array would switch `pg` to the extended protocol and break them
 * (ADR-004 implementer warning 1).
 */
import fs from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { errorCode } from './advisoryLock';

/**
 * `db/migrations` resolved from this file: `src/db` (tests) and `dist/db`
 * (compiled) sit at the same depth below the repository root (ADR-004 Karar 10).
 */
export const DEFAULT_MIGRATIONS_DIR = path.resolve(__dirname, '..', '..', 'db', 'migrations');

/** File name rule (AC-P11-10). Version = `NNN_name`. */
export const MIGRATION_FILE_PATTERN = /^(\d{3})_([a-z0-9_]+)\.(up|down)\.sql$/;

/** Identical to the DDL of the removed `db/migrate.sh` (AC-P11-3). */
export const SCHEMA_MIGRATIONS_DDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`;

/**
 * A file must not manage its own transaction and must not contain psql
 * meta-commands (AC-P11-10). Checked line by line; `DO $$ BEGIN … END $$`
 * blocks are not affected because their `BEGIN` has no semicolon. `END;` is
 * deliberately not matched (it closes PL/pgSQL blocks).
 */
const FORBIDDEN_LINE_PATTERNS: ReadonlyArray<{ pattern: RegExp; what: string }> = [
  { pattern: /^\s*(?:BEGIN|COMMIT|ROLLBACK|ABORT)(?:\s+(?:WORK|TRANSACTION))?\s*;/i, what: 'transaction kontrolü' },
  { pattern: /^\s*START\s+TRANSACTION\b/i, what: 'transaction kontrolü' },
  { pattern: /^\s*BEGIN\s+(?:ISOLATION|READ|DEFERRABLE|NOT\s+DEFERRABLE)\b/i, what: 'transaction kontrolü' },
  { pattern: /^\s*(?:COMMIT|ROLLBACK)\s+(?:AND\s+(?:NO\s+)?CHAIN|PREPARED)\b/i, what: 'transaction kontrolü' },
  { pattern: /^\s*PREPARE\s+TRANSACTION\b/i, what: 'transaction kontrolü' },
  { pattern: /^\s*\\/, what: 'psql meta komutu' },
];

export interface Migration {
  /** `NNN_name`, e.g. `005_scan_next_attempt` (the `schema_migrations.version` value). */
  version: string;
  /** Three-digit number, e.g. `005`. */
  number: string;
  /** Name part, e.g. `scan_next_attempt`. */
  name: string;
  upFile: string;
  downFile: string;
  /** Normalized content: BOM removed, CRLF -> LF. */
  upSql: string;
  downSql: string;
}

/** Minimal client surface (`pg.Client` satisfies it; tests may pass a fake). */
export interface MigrationClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

export interface AppliedVersion {
  version: string;
  appliedAt: Date | null;
}

export interface MigrationState {
  /** False when `schema_migrations` does not exist (fresh database). */
  tableExists: boolean;
  /** Applied versions that have a file, in version order. */
  applied: AppliedVersion[];
  /** Versions with a file that are not applied, in version order. */
  pending: Migration[];
  /** Applied versions without a file (database newer than the code). */
  unknown: AppliedVersion[];
  /** Pending versions numbered below the highest applied number (subset of `pending`). */
  outOfOrder: Migration[];
}

export type MigrationRejectionCode =
  | 'invalid_directory'
  | 'unknown_versions'
  | 'out_of_order'
  | 'invalid_target'
  | 'target_not_applied';

/** State/validation rejection: nothing was changed (CLI exit code 3). */
export class MigrationRejectedError extends Error {
  constructor(
    readonly code: MigrationRejectionCode,
    message: string,
    /** Individual problems (directory validation) or affected versions. */
    readonly details: string[] = [],
  ) {
    super(details.length > 0 ? `${message}\n  - ${details.join('\n  - ')}` : message);
    this.name = 'MigrationRejectedError';
  }
}

/**
 * A migration file (or its bookkeeping) failed and its transaction was rolled
 * back (CLI exit code 1). Earlier versions stay applied/reverted.
 */
export class MigrationSqlError extends Error {
  constructor(
    readonly version: string,
    readonly direction: 'up' | 'down',
    /** SQLSTATE for database errors, otherwise the Node/pg error code or class. */
    readonly code: string,
    /** True when the failure was not a PostgreSQL error (connection lost, ...). */
    readonly connectionError: boolean,
    message: string,
  ) {
    super(message);
    this.name = 'MigrationSqlError';
  }
}

export interface RunOptions {
  /** Progress lines (`uygulandı …`, `atlandı …`, …). */
  log?: (line: string) => void;
  /** Millisecond clock for durations; defaults to `Date.now`. */
  now?: () => number;
}

export interface UpResult {
  applied: string[];
  skipped: string[];
}

export interface DownResult {
  target: string;
  reverted: string[];
}

// ---------------------------------------------------------------------------
// Directory reading and validation
// ---------------------------------------------------------------------------

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Bytes -> SQL text (AC-P11-13): leading UTF-8 BOM removed, strict UTF-8
 * decoding (throws on invalid bytes), CRLF -> LF.
 */
export function decodeMigrationSql(bytes: Uint8Array): string {
  const start = bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  return utf8.decode(bytes.subarray(start)).replace(/\r\n/g, '\n');
}

/** Lines violating the content rule, as `satır N (<what>): <line>`. */
export function findForbiddenStatements(sql: string): string[] {
  const out: string[] = [];
  sql.split('\n').forEach((line, i) => {
    const hit = FORBIDDEN_LINE_PATTERNS.find((p) => p.pattern.test(line));
    if (hit) out.push(`satır ${i + 1} (${hit.what}): ${line.trim().slice(0, 80)}`);
  });
  return out;
}

/**
 * Reads and validates a migration directory before anything is changed
 * (AC-P11-10). All problems are collected and reported together. Non-`.sql`
 * files are ignored.
 *
 * @throws MigrationRejectedError `invalid_directory`
 */
export async function loadMigrations(dir: string = DEFAULT_MIGRATIONS_DIR): Promise<Migration[]> {
  let entries: fs.Dirent[];
  try {
    entries = await fs.promises.readdir(dir, { withFileTypes: true });
  } catch (err) {
    throw new MigrationRejectedError('invalid_directory', `Göç klasörü okunamadı: ${dir} (${errorCode(err)}).`);
  }

  const problems: string[] = [];
  // number -> name -> { up?, down? }
  const byNumber = new Map<string, Map<string, { up?: string; down?: string }>>();

  for (const entry of entries) {
    if (!entry.name.toLowerCase().endsWith('.sql')) continue;
    if (!entry.isFile()) {
      problems.push(`${entry.name}: normal bir dosya değil.`);
      continue;
    }
    const m = MIGRATION_FILE_PATTERN.exec(entry.name);
    if (!m) {
      problems.push(
        `${entry.name}: dosya adı kurala uymuyor (NNN_ad.up.sql / NNN_ad.down.sql; ad yalnız küçük harf, rakam ve _).`,
      );
      continue;
    }
    const [, number, name, direction] = m;
    let names = byNumber.get(number);
    if (!names) byNumber.set(number, (names = new Map()));
    const pair = names.get(name) ?? {};
    pair[direction as 'up' | 'down'] = path.join(dir, entry.name);
    names.set(name, pair);
  }

  const migrations: Migration[] = [];
  for (const number of [...byNumber.keys()].sort()) {
    const names = byNumber.get(number)!;
    if (names.size > 1) {
      problems.push(
        `numara ${number} birden çok sürümde kullanılıyor: ${[...names.keys()].map((n) => `${number}_${n}`).sort().join(', ')}.`,
      );
    }
    for (const [name, pair] of [...names.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      const version = `${number}_${name}`;
      if (!pair.up) problems.push(`${version}: .up.sql eşi yok.`);
      if (!pair.down) problems.push(`${version}: .down.sql eşi yok.`);
      if (!pair.up || !pair.down) continue;

      const upSql = await readSql(pair.up, problems);
      const downSql = await readSql(pair.down, problems);
      if (upSql === null || downSql === null) continue;
      migrations.push({ version, number, name, upFile: pair.up, downFile: pair.down, upSql, downSql });
    }
  }

  if (problems.length > 0) {
    throw new MigrationRejectedError(
      'invalid_directory',
      `Göç klasörü geçersiz (${problems.length} sorun); hiçbir değişiklik yapılmadı:`,
      problems,
    );
  }
  return migrations;
}

async function readSql(file: string, problems: string[]): Promise<string | null> {
  const base = path.basename(file);
  let sql: string;
  try {
    sql = decodeMigrationSql(await fs.promises.readFile(file));
  } catch (err) {
    problems.push(
      err instanceof TypeError ? `${base}: geçerli UTF-8 değil.` : `${base}: okunamadı (${errorCode(err)}).`,
    );
    return null;
  }
  const forbidden = findForbiddenStatements(sql);
  for (const f of forbidden) {
    problems.push(`${base} ${f} — göç dosyası kendi transaction'ını açamaz ve psql meta komutu içeremez.`);
  }
  return forbidden.length > 0 ? null : sql;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

function toDate(v: unknown): Date | null {
  if (v instanceof Date) return v;
  if (typeof v === 'string' || typeof v === 'number') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

function numberOf(version: string): string | null {
  const m = /^(\d{3})_/.exec(version);
  return m ? m[1] : null;
}

/**
 * Compares `schema_migrations` with the migration files. Read-only: when the
 * table does not exist it is NOT created and every version is pending
 * (AC-P11-5). Used by `status`, `up`, `down` and the runtime start-up check.
 */
export async function readMigrationState(client: MigrationClient, migrations: Migration[]): Promise<MigrationState> {
  const existsRes = await client.query("SELECT to_regclass('schema_migrations') IS NOT NULL AS present");
  const tableExists = (existsRes.rows[0] as { present?: unknown } | undefined)?.present === true;

  const rows: AppliedVersion[] = [];
  if (tableExists) {
    const res = await client.query('SELECT version, applied_at FROM schema_migrations ORDER BY version');
    for (const r of res.rows as Array<{ version: unknown; applied_at: unknown }>) {
      rows.push({ version: String(r.version), appliedAt: toDate(r.applied_at) });
    }
  }

  const known = new Set(migrations.map((m) => m.version));
  const appliedSet = new Set(rows.map((r) => r.version));
  const applied = rows.filter((r) => known.has(r.version));
  const unknown = rows.filter((r) => !known.has(r.version));
  const pending = migrations.filter((m) => !appliedSet.has(m.version));

  const appliedNumbers = applied.map((r) => numberOf(r.version)).filter((n): n is string => n !== null);
  const maxApplied = appliedNumbers.length > 0 ? appliedNumbers.sort()[appliedNumbers.length - 1] : null;
  const outOfOrder = maxApplied === null ? [] : pending.filter((m) => m.number < maxApplied);

  return { tableExists, applied, pending, unknown, outOfOrder };
}

function unknownVersionsError(state: MigrationState): MigrationRejectedError {
  const versions = state.unknown.map((u) => u.version);
  return new MigrationRejectedError(
    'unknown_versions',
    `Veritabanı bu koddan yeni (bilinmeyen sürüm: ${versions.join(', ')}). ` +
      'Bu sürümlerin göç dosyası klasörde yok; kodu güncelleyin. Hiçbir değişiklik yapılmadı.',
  );
}

function outOfOrderError(state: MigrationState): MigrationRejectedError {
  const maxApplied = state.applied
    .map((r) => numberOf(r.version))
    .filter((n): n is string => n !== null)
    .sort()
    .pop();
  return new MigrationRejectedError(
    'out_of_order',
    `Sıra dışı bekleyen sürüm: ${state.outOfOrder.map((m) => m.version).join(', ')} ` +
      `(uygulanmış en büyük numara ${maxApplied}). Yeni göç, uygulanmış en büyük numaradan sonra ` +
      'eklenmelidir. Hiçbir değişiklik yapılmadı.',
  );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/** `status`: read-only (AC-P11-5). */
export async function migrationStatus(client: MigrationClient, migrations: Migration[]): Promise<MigrationState> {
  return readMigrationState(client, migrations);
}

/** Human-readable `status` lines. */
export function formatStatus(state: MigrationState): string[] {
  const lines: string[] = [];
  if (!state.tableExists) lines.push('schema_migrations tablosu yok; tüm sürümler bekleyen.');
  const outOfOrder = new Set(state.outOfOrder.map((m) => m.version));
  const rows: Array<{ version: string; text: string }> = [
    ...state.applied.map((a) => ({
      version: a.version,
      text: `uygulanmış  ${a.version}  ${a.appliedAt ? a.appliedAt.toISOString() : '-'}`,
    })),
    ...state.pending.map((p) => ({
      version: p.version,
      text: `bekleyen    ${p.version}${outOfOrder.has(p.version) ? '  (sıra dışı: up reddeder)' : ''}`,
    })),
    ...state.unknown.map((u) => ({
      version: u.version,
      text: `bilinmeyen  ${u.version}  ${u.appliedAt ? u.appliedAt.toISOString() : '-'}  (dosyası yok)`,
    })),
  ].sort((a, b) => (a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
  lines.push(...rows.map((r) => r.text));
  lines.push(
    `özet: ${state.applied.length} uygulanmış, ${state.pending.length} bekleyen, ${state.unknown.length} bilinmeyen`,
  );
  return lines;
}

/**
 * `up` (AC-P11-1…4, 9, 17): applies pending versions in file order, each in
 * its own transaction together with its `schema_migrations` row. Stops at the
 * first failure (that version rolled back, earlier ones stay applied, later
 * ones are not tried).
 *
 * @throws MigrationRejectedError `unknown_versions` | `out_of_order` (nothing changed)
 * @throws MigrationSqlError on the first failing version
 */
export async function migrateUp(
  client: MigrationClient,
  migrations: Migration[],
  options: RunOptions = {},
): Promise<UpResult> {
  const log = options.log ?? (() => undefined);
  const now = options.now ?? Date.now;
  const state = await readMigrationState(client, migrations);
  if (state.unknown.length > 0) throw unknownVersionsError(state);
  if (state.outOfOrder.length > 0) throw outOfOrderError(state);

  if (!state.tableExists) await client.query(SCHEMA_MIGRATIONS_DDL);

  const pending = new Set(state.pending.map((m) => m.version));
  const result: UpResult = { applied: [], skipped: [] };
  for (const m of migrations) {
    if (!pending.has(m.version)) {
      log(`atlandı ${m.version}`);
      result.skipped.push(m.version);
      continue;
    }
    const started = now();
    await runInTransaction(client, m.version, 'up', m.upSql, {
      text: 'INSERT INTO schema_migrations (version) VALUES ($1)',
      values: [m.version],
    });
    log(`uygulandı ${m.version} (${Math.max(0, Math.round(now() - started))} ms)`);
    result.applied.push(m.version);
  }
  return result;
}

/**
 * Resolves `--to` (AC-P11-8): full version (`003_declared_range`) or the
 * three-digit number (`003`).
 *
 * @throws MigrationRejectedError `invalid_target`
 */
export function resolveDownTarget(target: string, migrations: Migration[]): Migration {
  const found = /^\d{3}$/.test(target)
    ? migrations.find((m) => m.number === target)
    : migrations.find((m) => m.version === target);
  if (!found) {
    throw new MigrationRejectedError(
      'invalid_target',
      `Hedef sürüm bulunamadı: ${target} (tam sürüm adı, ör. 003_declared_range, veya üç haneli numara, ör. 003). ` +
        'Hiçbir değişiklik yapılmadı.',
    );
  }
  return found;
}

/**
 * `down --to <target>` (AC-P11-7, 8, 9): reverts every applied version above
 * the target, newest first, each in its own transaction together with the
 * `DELETE FROM schema_migrations` row. The target stays applied, so `001` can
 * never be reverted by the tool. The list is logged before anything changes.
 *
 * @throws MigrationRejectedError `invalid_target` | `target_not_applied` | `unknown_versions`
 * @throws MigrationSqlError on the first failing version (earlier reverts stay)
 */
export async function migrateDown(
  client: MigrationClient,
  migrations: Migration[],
  target: string,
  options: RunOptions = {},
): Promise<DownResult> {
  const log = options.log ?? (() => undefined);
  const now = options.now ?? Date.now;
  const targetMigration = resolveDownTarget(target, migrations);
  const state = await readMigrationState(client, migrations);
  if (state.unknown.length > 0) throw unknownVersionsError(state);
  if (!state.applied.some((a) => a.version === targetMigration.version)) {
    throw new MigrationRejectedError(
      'target_not_applied',
      `Hedef sürüm uygulanmamış: ${targetMigration.version}. Hiçbir değişiklik yapılmadı.`,
    );
  }

  const byVersion = new Map(migrations.map((m) => [m.version, m]));
  const toRevert = state.applied
    .map((a) => byVersion.get(a.version)!)
    .filter((m) => m.number > targetMigration.number)
    .sort((a, b) => (a.number < b.number ? 1 : a.number > b.number ? -1 : 0));

  if (toRevert.length === 0) {
    log(`geri alınacak sürüm yok (hedef ${targetMigration.version} en son uygulanmış sürüm).`);
    return { target: targetMigration.version, reverted: [] };
  }
  log(`geri alınacak (sırayla): ${toRevert.map((m) => m.version).join(', ')}`);

  const result: DownResult = { target: targetMigration.version, reverted: [] };
  for (const m of toRevert) {
    const started = now();
    await runInTransaction(client, m.version, 'down', m.downSql, {
      text: 'DELETE FROM schema_migrations WHERE version = $1',
      values: [m.version],
    });
    log(`geri alındı ${m.version} (${Math.max(0, Math.round(now() - started))} ms)`);
    result.reverted.push(m.version);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Runtime start-up check (REQ-003 D-35, AC-P12-5; ADR-004 Karar 2 adım 3)
// ---------------------------------------------------------------------------

export type StartupMigrationCheck =
  | { ok: true; applied: string[] }
  | { ok: false; reason: 'pending' | 'unknown_versions'; versions: string[]; message: string }
  | { ok: false; reason: 'invalid_directory'; versions: []; problems: string[]; message: string };

/**
 * Called by the runtime on the lock connection before anything starts. Never
 * applies migrations (D-35) and never writes. Connection/query errors are
 * thrown unchanged (the caller logs only `errorCode(err)`).
 */
export async function checkMigrationsForStartup(
  client: MigrationClient,
  dir: string = DEFAULT_MIGRATIONS_DIR,
): Promise<StartupMigrationCheck> {
  let migrations: Migration[];
  try {
    migrations = await loadMigrations(dir);
  } catch (err) {
    if (err instanceof MigrationRejectedError) {
      return {
        ok: false,
        reason: 'invalid_directory',
        versions: [],
        problems: err.details,
        message: err.message,
      };
    }
    throw err;
  }
  const state = await readMigrationState(client, migrations);
  if (state.unknown.length > 0) {
    const versions = state.unknown.map((u) => u.version);
    return {
      ok: false,
      reason: 'unknown_versions',
      versions,
      message: `Veritabanı bu koddan yeni (bilinmeyen sürüm: ${versions.join(', ')}).`,
    };
  }
  if (state.pending.length > 0) {
    const versions = state.pending.map((m) => m.version);
    return {
      ok: false,
      reason: 'pending',
      versions,
      message: `Bekleyen göç var: ${versions.join(', ')}. Önce \`npm run db:migrate\` çalıştırın.`,
    };
  }
  return { ok: true, applied: state.applied.map((a) => a.version) };
}

// ---------------------------------------------------------------------------
// Transaction + error formatting
// ---------------------------------------------------------------------------

interface PgErrorFields {
  code?: unknown;
  severity?: unknown;
  message?: unknown;
  detail?: unknown;
  hint?: unknown;
  position?: unknown;
  where?: unknown;
}

function isDatabaseError(err: unknown): err is PgErrorFields {
  return (
    !!err &&
    typeof err === 'object' &&
    typeof (err as PgErrorFields).severity === 'string' &&
    typeof (err as PgErrorFields).code === 'string'
  );
}

/** 1-based line of a 1-based character `position` in `sql`. */
export function lineOfPosition(sql: string, position: number): number | null {
  if (!Number.isInteger(position) || position < 1) return null;
  const upTo = Array.from(sql).slice(0, position - 1).join('');
  return upTo.split('\n').length;
}

function toMigrationSqlError(err: unknown, version: string, direction: 'up' | 'down', sql: string): MigrationSqlError {
  if (!isDatabaseError(err)) {
    // Not a PostgreSQL error (connection lost, ...): class/code only.
    const code = errorCode(err);
    return new MigrationSqlError(
      version,
      direction,
      code,
      true,
      `Göç ${version} (${direction}) başarısız: bağlantı hatası (${code}). Bu sürümün değişiklikleri geri alındı.`,
    );
  }
  const code = String(err.code);
  const parts = [`Göç ${version} (${direction}) başarısız: [${code}] ${String(err.message ?? '')}`];
  const line = err.position !== undefined ? lineOfPosition(sql, Number(err.position)) : null;
  if (line !== null) parts.push(`  satır: ${line}`);
  if (typeof err.detail === 'string' && err.detail) parts.push(`  detay: ${err.detail}`);
  if (typeof err.hint === 'string' && err.hint) parts.push(`  ipucu: ${err.hint}`);
  if (typeof err.where === 'string' && err.where) parts.push(`  konum: ${err.where.split('\n')[0]}`);
  parts.push('  Bu sürümün değişiklikleri ve kaydı geri alındı; sonraki sürümler denenmedi.');
  return new MigrationSqlError(version, direction, code, false, parts.join('\n'));
}

async function runInTransaction(
  client: MigrationClient,
  version: string,
  direction: 'up' | 'down',
  sql: string,
  bookkeeping: { text: string; values: unknown[] },
): Promise<void> {
  let open = false;
  try {
    await client.query('BEGIN');
    open = true;
    // Single argument on purpose: simple query protocol (see file header).
    await client.query(sql);
    await client.query(bookkeeping.text, bookkeeping.values);
    open = false; // a failed COMMIT already ends the transaction server-side
    await client.query('COMMIT');
  } catch (err) {
    if (open) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // connection gone: the server rolls back with the session
      }
    }
    throw toMigrationSqlError(err, version, direction, sql);
  }
}
