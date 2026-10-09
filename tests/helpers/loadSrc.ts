import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { REPO_ROOT } from './paths';

/**
 * Thrown when a module/export required by the REQ-002 tests does not exist
 * yet. Tests are expected to fail with this error until backend-engineer
 * implements the interface documented in tests/README.md.
 */
export class MissingImplementationError extends Error {
  constructor(message: string) {
    super(`[not implemented — see tests/README.md] ${message}`);
    this.name = 'MissingImplementationError';
  }
}

function absolute(relPath: string): string {
  return path.join(REPO_ROOT, relPath);
}

function exportedTextually(source: string, name: string): boolean {
  const decl = new RegExp(
    `export\\s+(?:default\\s+)?(?:async\\s+)?(?:function\\*?|const|let|var|class|abstract\\s+class)\\s+${name}\\b`,
  );
  const list = new RegExp(`export\\s*\\{[^}]*\\b${name}\\b[^}]*\\}`);
  return decl.test(source) || list.test(source);
}

/**
 * Dynamically imports a module under src/ by repository-relative path.
 *
 * Why dynamic: several modules/exports the tests need do not exist yet
 * (REQ-002 is test-first). A static import would break `npm run typecheck`;
 * a computed specifier keeps tsc from resolving it while Vitest still loads
 * the real TypeScript source at run time. The caller types the result with
 * the interfaces in tests/helpers/contracts.ts.
 */
export async function loadSrc<T>(relPath: string, requiredExports: readonly string[] = []): Promise<T> {
  const abs = absolute(relPath);
  if (!fs.existsSync(abs)) {
    throw new MissingImplementationError(`${relPath} does not exist`);
  }
  const specifier = pathToFileURL(abs).href;
  const mod = (await import(/* @vite-ignore */ specifier)) as Record<string, unknown>;
  const missing = requiredExports.filter((name) => mod[name] === undefined);
  if (missing.length > 0) {
    throw new MissingImplementationError(`${relPath} does not export: ${missing.join(', ')}`);
  }
  return mod as T;
}

/**
 * Like loadSrc, but refuses to import the module unless every required
 * export is visible in the source text first. Used for modules with import
 * side effects in their current form (src/app.ts calls app.listen() at import
 * time today): importing it from a test would open a real port.
 */
export async function loadSrcGuarded<T>(relPath: string, requiredExports: readonly string[]): Promise<T> {
  const abs = absolute(relPath);
  if (!fs.existsSync(abs)) {
    throw new MissingImplementationError(`${relPath} does not exist`);
  }
  const source = fs.readFileSync(abs, 'utf8');
  const missing = requiredExports.filter((name) => !exportedTextually(source, name));
  if (missing.length > 0) {
    throw new MissingImplementationError(
      `${relPath} does not export: ${missing.join(', ')} (module not imported to avoid side effects)`,
    );
  }
  return loadSrc<T>(relPath, requiredExports);
}

export function readRepoFile(relPath: string): string {
  return fs.readFileSync(absolute(relPath), 'utf8');
}
