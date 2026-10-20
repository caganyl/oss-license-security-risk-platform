/**
 * The only process entry point: `npm start` = `node dist/main.js`
 * (REQ-003 P-12, AC-P12-1, AC-P12-3; ADR-004 Karar 1).
 *
 * Loads `.env`, installs the signal/fatal-error handlers first (a Ctrl+C
 * during start-up cancels it through the same shutdown path) and starts the
 * runtime: API + scan worker + report worker in this one process.
 */
import 'dotenv/config';
import { errorCode } from './db/advisoryLock';
import { trustSystemCertificates } from './lib/systemCa';
import { RuntimeStartupError, createRuntime, installProcessHandlers } from './runtime';

export async function main(exit: (code: number) => void = (code) => process.exit(code)): Promise<void> {
  // Before any HTTPS client exists: corporate proxy root CAs come from the OS store (REQ-010 r2).
  try {
    const { added } = trustSystemCertificates();
    if (added > 0) console.log(`Sistem sertifika deposundan ${added} kök sertifika eklendi (kurumsal proxy desteği).`);
  } catch (err) {
    console.warn(`Sistem sertifika deposu okunamadı (${errorCode(err)}); Node'un kendi listesi kullanılıyor.`);
  }
  const runtime = createRuntime({ exit });
  installProcessHandlers(runtime, undefined, exit);
  try {
    await runtime.start();
  } catch (err) {
    // A shutdown request cancelled the start-up: the handler exits.
    if (runtime.shuttingDown) return;
    console.error(err instanceof RuntimeStartupError ? err.message : `Başlangıç başarısız (${errorCode(err)}).`);
    exit(err instanceof RuntimeStartupError ? err.exitCode : 1);
  }
}

if (require.main === module) {
  void main();
}
