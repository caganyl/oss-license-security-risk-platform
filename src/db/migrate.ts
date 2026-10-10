/**
 * Migration CLI (REQ-003 P-11; ADR-004 Karar 10).
 *
 *   npm run build
 *   npm run db:migrate                         # up
 *   npm run db:migrate -- status
 *   npm run db:migrate -- down --to 003        # or --to 003_declared_range
 *
 * `npm run db:migrate` = `node dist/db/migrate.js` (compiled output; the
 * command never builds by itself). Every command, `status` included, holds the
 * shared instance lock on one dedicated connection for its whole run
 * (AC-P11-11).
 *
 * Exit codes (AC-P11-18): 0 success, 1 SQL/connection error, 2 usage or
 * configuration error, 3 state rejection, 4 lock held by another process.
 *
 * Output never contains the connection string, the password, the host or the
 * database name (AC-P11-12): connection errors are reported by class/code.
 */
import dotenv from 'dotenv';
import { Client, type ClientConfig } from 'pg';
import {
  acquireInstanceLock,
  errorCode,
  MIGRATE_LOCK_APPLICATION_NAME,
  type AcquireInstanceLockResult,
} from './advisoryLock';
import {
  DEFAULT_MIGRATIONS_DIR,
  type Migration,
  formatStatus,
  loadMigrations,
  migrateDown,
  migrateUp,
  migrationStatus,
  MigrationRejectedError,
  MigrationSqlError,
  resolveDownTarget,
} from './migrator';

export const MIGRATE_EXIT = Object.freeze({
  ok: 0,
  failure: 1,
  usage: 2,
  rejected: 3,
  locked: 4,
});

export type MigrateCommand =
  | { kind: 'up' }
  | { kind: 'status' }
  | { kind: 'down'; to: string }
  | { kind: 'help' };

export type ParsedMigrateArgs = MigrateCommand | { kind: 'usage-error'; message: string };

export const MIGRATE_USAGE = [
  'Kullanım: npm run db:migrate [-- <komut>]   (önce: npm run build)',
  '  (komut yok) | up        Bekleyen göçleri dosya sırasıyla uygular.',
  '  status                  Uygulanmış, bekleyen ve bilinmeyen sürümleri listeler; değişiklik yapmaz.',
  '  down --to <hedef>       Hedeften sonraki uygulanmış sürümleri ters sırayla geri alır; hedef uygulanmış',
  '                          kalır. <hedef>: tam ad (003_declared_range) veya numara (003). 001 geri alınamaz.',
  'Doğrudan: node dist/db/migrate.js [up | status | down --to <hedef>]',
  "Bağlantı: DATABASE_URL (ortam değişkeni veya .env). Parola URL'de veya PGPASSWORD ile.",
  'Çıkış kodları: 0 başarı, 1 SQL/bağlantı hatası, 2 kullanım/yapılandırma hatası, 3 durum reddi,',
  '               4 kilit başka süreçte (uygulama veya başka bir göç çalışıyor).',
].join('\n');

export const LOCK_HELD_MESSAGE =
  'Kilit alınamadı: uygulama çalışıyor veya başka bir göç sürüyor; önce durdurun. Hiçbir değişiklik yapılmadı.';

/** Parses CLI arguments (after `node dist/db/migrate.js`). Pure. */
export function parseMigrateArgs(argv: readonly string[]): ParsedMigrateArgs {
  if (argv.length === 0) return { kind: 'up' };
  const [cmd, ...rest] = argv;
  if ((cmd === 'help' || cmd === '--help' || cmd === '-h') && rest.length === 0) return { kind: 'help' };
  if (cmd === 'up' && rest.length === 0) return { kind: 'up' };
  if (cmd === 'status' && rest.length === 0) return { kind: 'status' };
  if (cmd === 'down') {
    if (rest.length === 2 && rest[0] === '--to' && rest[1].trim() !== '' && !rest[1].startsWith('-')) {
      return { kind: 'down', to: rest[1].trim() };
    }
    if (rest.length === 1 && rest[0].startsWith('--to=') && rest[0].slice(5).trim() !== '') {
      return { kind: 'down', to: rest[0].slice(5).trim() };
    }
    return {
      kind: 'usage-error',
      message: rest.length === 0 ? 'down hedefsiz çalıştırılamaz: --to <hedef> gerekli.' : `Geçersiz down argümanı: ${rest.join(' ')}`,
    };
  }
  return { kind: 'usage-error', message: `Bilinmeyen komut veya argüman: ${argv.join(' ')}` };
}

/**
 * Turns a connection-time error into a one-line explanation without any
 * connection detail. The original message is only inspected, never printed.
 */
export function describeConnectionError(err: unknown): string {
  const code = errorCode(err);
  const message = err instanceof Error ? err.message : '';
  const known: Record<string, string> = {
    ECONNREFUSED: 'sunucu bağlantıyı reddetti (PostgreSQL çalışıyor mu, host/port doğru mu?)',
    ENOTFOUND: 'sunucu adı çözülemedi',
    EAI_AGAIN: 'sunucu adı çözülemedi',
    ETIMEDOUT: 'bağlantı zaman aşımına uğradı',
    ECONNRESET: 'bağlantı sunucu tarafından kapatıldı',
    '28P01': 'parola doğrulaması başarısız',
    '28000': 'kimlik doğrulama reddedildi (pg_hba.conf)',
    '3D000': 'veritabanı yok',
    '57P03': 'sunucu bağlantı kabul etmiyor (başlıyor/kapanıyor)',
    '53300': 'sunucuda bağlantı sınırı dolu',
  };
  let why = known[code];
  if (!why && /connection timeout/i.test(message)) why = 'bağlantı zaman aşımına uğradı';
  if (!why && /client password must be a string/i.test(message)) {
    why = "parola verilmedi (DATABASE_URL içinde veya PGPASSWORD ile verin)";
  }
  return `Veritabanına bağlanılamadı (${code})${why ? `: ${why}` : ''}.`;
}

function isDatabaseError(err: unknown): err is { code: string; message: string } {
  return (
    !!err &&
    typeof err === 'object' &&
    typeof (err as { severity?: unknown }).severity === 'string' &&
    typeof (err as { code?: unknown }).code === 'string'
  );
}

export interface MigrateCliDeps {
  /** Defaults to `process.env` (the entry point loads `.env` first). */
  env?: NodeJS.ProcessEnv;
  /** stdout line writer. */
  out?: (line: string) => void;
  /** stderr line writer. */
  err?: (line: string) => void;
  /** Defaults to `db/migrations` (AC-P11-4 tests pass their own folder). */
  migrationsDir?: string;
  /** Defaults to `new pg.Client(config)`. */
  clientFactory?: (config: ClientConfig) => Client;
}

/**
 * Runs one CLI invocation and returns the exit code. Never throws and never
 * calls `process.exit`.
 */
export async function runMigrateCli(argv: readonly string[], deps: MigrateCliDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const out = deps.out ?? ((line: string) => process.stdout.write(`${line}\n`));
  const errOut = deps.err ?? ((line: string) => process.stderr.write(`${line}\n`));
  const dir = deps.migrationsDir ?? DEFAULT_MIGRATIONS_DIR;

  // 1. Arguments (exit 2).
  const parsed = parseMigrateArgs(argv);
  if (parsed.kind === 'help') {
    out(MIGRATE_USAGE);
    return MIGRATE_EXIT.ok;
  }
  if (parsed.kind === 'usage-error') {
    errOut(parsed.message);
    errOut(MIGRATE_USAGE);
    return MIGRATE_EXIT.usage;
  }

  // 2. Configuration (exit 2). The value is never printed.
  const connectionString = env.DATABASE_URL?.trim();
  if (!connectionString) {
    errOut(
      'DATABASE_URL tanımlı değil. .env.example dosyasını .env olarak kopyalayıp doldurun ' +
        'veya DATABASE_URL ortam değişkenini verin.',
    );
    return MIGRATE_EXIT.usage;
  }

  // 3. Folder validation before touching the database (exit 3, AC-P11-10).
  let migrations: Migration[];
  try {
    migrations = await loadMigrations(dir);
    if (parsed.kind === 'down') resolveDownTarget(parsed.to, migrations);
  } catch (e) {
    if (e instanceof MigrationRejectedError) {
      errOut(e.message);
      return MIGRATE_EXIT.rejected;
    }
    errOut(`Beklenmeyen hata (${errorCode(e)}).`);
    return MIGRATE_EXIT.failure;
  }

  // 4. Connection + instance lock (exit 1 / 4).
  let acquired: AcquireInstanceLockResult<Client>;
  try {
    acquired = await acquireInstanceLock<Client>({
      connection: connectionString,
      applicationName: MIGRATE_LOCK_APPLICATION_NAME,
      clientFactory: deps.clientFactory,
    });
  } catch (e) {
    errOut(describeConnectionError(e));
    return MIGRATE_EXIT.failure;
  }
  if (!acquired.acquired) {
    errOut(LOCK_HELD_MESSAGE);
    return MIGRATE_EXIT.locked;
  }

  const { lock } = acquired;
  const client = lock.client;
  // RAISE NOTICE output of migrations goes to stdout (ADR-004 Karar 10).
  client.on('notice', (notice: { message?: string }) => out(`NOTICE: ${notice.message ?? ''}`));

  // 5. Command.
  try {
    switch (parsed.kind) {
      case 'status': {
        const state = await migrationStatus(client, migrations);
        for (const line of formatStatus(state)) out(line);
        break;
      }
      case 'up': {
        const result = await migrateUp(client, migrations, { log: out });
        out(
          result.applied.length === 0
            ? 'Bekleyen göç yok.'
            : `Tamam: ${result.applied.length} göç uygulandı, ${result.skipped.length} atlandı.`,
        );
        break;
      }
      case 'down': {
        const result = await migrateDown(client, migrations, parsed.to, { log: out });
        out(`Tamam: ${result.reverted.length} göç geri alındı; son uygulanmış sürüm ${result.target}.`);
        break;
      }
    }
    return MIGRATE_EXIT.ok;
  } catch (e) {
    if (e instanceof MigrationRejectedError) {
      errOut(e.message);
      return MIGRATE_EXIT.rejected;
    }
    if (e instanceof MigrationSqlError) {
      errOut(e.message);
      return MIGRATE_EXIT.failure;
    }
    if (isDatabaseError(e)) {
      errOut(`Veritabanı hatası: [${e.code}] ${e.message}`);
      return MIGRATE_EXIT.failure;
    }
    errOut(`Bağlantı veya beklenmeyen hata (${errorCode(e)}).`);
    return MIGRATE_EXIT.failure;
  } finally {
    await lock.release();
  }
}

/* c8 ignore start */
if (require.main === module) {
  // Loaded here, not at import time, so tests importing runMigrateCli are not
  // affected by a developer's .env.
  dotenv.config();
  runMigrateCli(process.argv.slice(2))
    .catch(() => MIGRATE_EXIT.failure)
    .then((code) => {
      process.exitCode = code;
      // Safety net: never hang on a half-open socket after the work is done.
      setTimeout(() => process.exit(code), 2_000).unref();
    });
}
/* c8 ignore stop */
