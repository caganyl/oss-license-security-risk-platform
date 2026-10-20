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
import {
  LINK_NOT_FOLLOWED_MESSAGE,
  compareCodePoints,
  emptyResult,
  extendResult,
  isSpecEcosystem,
  pyStrip,
  walkTree,
  type ParseErrorRecord,
  type TreeWalk,
  type WalkOptions,
} from './common';
import { KitScanBudget } from './kit';
import type { IntegrityCollector } from './lockIntegrityValue';
import { parserFor } from './registry';

/**
 * "Link not followed" records of the spec files of `ecosystem` (REQ-011
 * D-304), sorted by path. Written by `parseManifests` for every spec
 * ecosystem, so the parsers never have to.
 */
function specLinkErrors(walk: TreeWalk, ecosystem: string): ParseErrorRecord[] {
  if (!isSpecEcosystem(ecosystem)) return [];
  return [...(walk.specLinks?.get(ecosystem) ?? [])]
    .sort((a, b) => compareCodePoints(a.relPath, b.relPath))
    .map((link) => ({ ecosystem, file: link.relPath, error: LINK_NOT_FOLLOWED_MESSAGE }));
}

export interface ParseManifestsOptions {
  /** L-5 side channel of the npm lock parsers (REQ-005, ADR-007 Karar 12); not part of the result. */
  integrityCollector?: IntegrityCollector;
}

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
export function parseManifests(
  rootDir: string,
  ecosystems: readonly string[],
  scanId: string,
  options: ParseManifestsOptions = {},
): SandboxScanResult {
  const result = emptyResult();
  let walk: TreeWalk | null = null;
  const list = normalizeEcosystems(ecosystems);
  // .NET names are recognised only when `dotnet` is requested, the spec files
  // of the other ecosystems only when those are requested; `byDir` is always
  // the unchanged F4 walk (golden guarantee, ADR-008 Karar 2, REQ-011 D-304).
  const walkOptions: WalkOptions = list.includes('dotnet') ? { dotnet: true, ecosystems: list } : { ecosystems: list };
  const run = { integrityCollector: options.integrityCollector, budget: new KitScanBudget() };

  for (const ecosystem of list) {
    const parser = parserFor(ecosystem);
    if (!parser) {
      result.parse_errors.push({ ecosystem, file: '', error: `unsupported ecosystem '${ecosystem}'` });
      continue;
    }
    if (!walk) {
      walk = walkTree(rootDir, walkOptions);
      result.parse_errors.push(...walk.errors);
    }
    const parsed = parser(walk, run);
    const links = specLinkErrors(walk, ecosystem);
    if (ecosystem === 'nodejs' || ecosystem === 'python') {
      // Extra-format links come after the F4 records (whose order the goldens freeze).
      extendResult(result, parsed);
      result.parse_errors.push(...links);
    } else {
      // Like .NET: the ecosystem's link records first.
      result.parse_errors.push(...links);
      extendResult(result, parsed);
    }
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
