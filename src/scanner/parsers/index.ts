/**
 * Dependency manifest parsers (REQ-003 P-10, ADR-005).
 *
 * `parseManifests` is the TypeScript counterpart of the legacy
 * Python `scan.py` (frozen as golden output, REQ-003 D-26): pure and synchronous (it only reads
 * the file system), so the golden tests call it directly, and the scan
 * worker runs it inside a `worker_threads` thread (`thread.ts`,
 * `threadParser.ts`).
 */
import type { SandboxScanResult } from '../../types/scan';
import { emptyResult, extendResult, pyStrip, walkTree, type ParseResult, type TreeWalk } from './common';
import { parse as parseNodejs } from './nodejs';
import { parse as parsePython } from './python';

const PARSERS: Readonly<Record<string, (walk: TreeWalk) => ParseResult>> = {
  nodejs: parseNodejs,
  python: parsePython,
};

/** Python `scan._ecosystems`: comma-separated names, stripped, empties dropped, order kept. */
function normalizeEcosystems(ecosystems: readonly string[]): string[] {
  return ecosystems
    .join(',')
    .split(',')
    .map((ecosystem) => pyStrip(ecosystem))
    .filter((ecosystem) => ecosystem !== '');
}

/**
 * Parses every supported manifest under `rootDir` for the given ecosystems
 * (processed in the given order). An unsupported ecosystem yields a
 * `{ ecosystem, file: '', error }` record. The tree is walked once and
 * shared by the ecosystems; links are never followed (ADR-005 Karar 6).
 * `status` is always `completed`; `total_deps = dependencies.length`.
 */
export function parseManifests(rootDir: string, ecosystems: readonly string[], scanId: string): SandboxScanResult {
  const result = emptyResult();
  let walk: TreeWalk | null = null;

  for (const ecosystem of normalizeEcosystems(ecosystems)) {
    const parser = Object.prototype.hasOwnProperty.call(PARSERS, ecosystem) ? PARSERS[ecosystem] : undefined;
    if (!parser) {
      result.parse_errors.push({ ecosystem, file: '', error: `unsupported ecosystem '${ecosystem}'` });
      continue;
    }
    if (!walk) {
      walk = walkTree(rootDir);
      result.parse_errors.push(...walk.errors);
    }
    extendResult(result, parser(walk));
  }

  return {
    scan_id: scanId,
    status: 'completed',
    total_deps: result.dependencies.length,
    dependencies: result.dependencies,
    scan_files: result.scan_files,
    parse_errors: result.parse_errors,
  };
}

export { MAX_MANIFEST_BYTES, SKIP_DIRS } from './common';
