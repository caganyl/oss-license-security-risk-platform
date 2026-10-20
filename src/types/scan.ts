/**
 * Scan-domain types — mirrors the DB enums in the schema.
 */

/** Mirrors the tech_ecosystem DB enum (`rust`, `dart`, `swift` added by migration 010, REQ-011 D-300). */
export type TechEcosystem =
  | 'nodejs'
  | 'python'
  | 'java'
  | 'dotnet'
  | 'go'
  | 'php'
  | 'rust'
  | 'ruby'
  | 'dart'
  | 'swift'
  | 'container'
  | 'other';

/**
 * Ecosystems the dependency parsers understand, in the default stack order
 * (REQ-011 D-307): an empty project stack scans all of them in this order.
 * `container` and `other` are enum values without a parser.
 */
export const SCAN_ECOSYSTEMS = ['nodejs', 'python', 'dotnet', 'java', 'go', 'php', 'rust', 'ruby', 'dart', 'swift'] as const;

/** One of `SCAN_ECOSYSTEMS`. */
export type ScanEcosystem = (typeof SCAN_ECOSYSTEMS)[number];

/** Type guard of `SCAN_ECOSYSTEMS` (exact, case-sensitive value). */
export function isScanEcosystem(value: unknown): value is ScanEcosystem {
  return typeof value === 'string' && (SCAN_ECOSYSTEMS as readonly string[]).includes(value);
}

/** Mirrors the scan_status DB enum. */
export type ScanStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timeout';

/** Mirrors the scan_trigger DB enum. */
export type ScanTrigger =
  | 'manual'
  | 'scheduled'
  | 'pre_release'
  | 'pull_request'
  | 'file_upload';

/** Mirrors the dependency_scope DB enum. */
export type DependencyScope =
  | 'direct'
  | 'transitive'
  | 'dev'
  | 'peer'
  | 'optional';

/**
 * Runtime scope (ADR-003 b): everything except `dev`. `peer` and `optional`
 * are installed and run in production, so they count as runtime.
 */
export function isRuntimeScope(scope: DependencyScope | null | undefined): boolean {
  return scope !== 'dev';
}

/** Raw dependency record produced by the dependency parsers. */
export interface ScannedDependency {
  ecosystem: TechEcosystem;
  name: string;
  /** Exact resolved version, or null when only a range is known (no lock file). */
  version: string | null;
  /** Range declared in the manifest (`^4.17.0`, `>=2,<3`), if any. */
  declared_range?: string | null;
  /** Carries a version only when `version` is exact (ADR-003 a). */
  purl: string;
  scope?: DependencyScope;
  licenses?: string[];
  vulnerabilities?: Array<{ id: string; fix_versions: string[] }>;
  manifest_file: string;
  manifest_path: string;
}

/** Scan file record produced by the dependency parsers. */
export interface ScannedFile {
  ecosystem: TechEcosystem;
  filename: string;
  file_path: string;
  file_hash: string;
  size_bytes: number;
}

/**
 * Result of one dependency parse: returned by `parseManifests`
 * (src/scanner/parsers, run in a worker thread; REQ-003 P-10, ADR-005).
 */
export interface SandboxScanResult {
  scan_id: string;
  status: 'completed' | 'failed';
  total_deps: number;
  dependencies: ScannedDependency[];
  scan_files: ScannedFile[];
  parse_errors: Array<{ ecosystem: string; file: string; error: string }>;
}

/** One npm lockfile `integrity` record of the parser side channel (REQ-005 L-5, ADR-007 Karar 12). */
export interface ParserLockIntegrityRecord {
  manifestPath: string;
  name: string;
  version: string;
  integrity: string;
}

/**
 * Parse result plus the L-5 side channel (`runParserInThreadWithSideChannel`).
 * `result` is the unchanged golden shape; `lockIntegrity` never enters it.
 */
export interface ParserRunOutput {
  result: SandboxScanResult;
  lockIntegrity: ParserLockIntegrityRecord[];
  /**
   * NuGet lock/assets SHA-512 records (`sha512-<base64>`; REQ-006 AC-P20-16,
   * ADR-008 Karar 6). Present only when the thread sent at least one valid record.
   */
  nugetIntegrity?: ParserLockIntegrityRecord[];
}

/**
 * Parser injection point of the scan worker. `signal` (optional, ADR-004
 * Karar 7) aborts the parse; three-argument implementations stay valid.
 * An implementation returns either the bare result (no L-5 side channel:
 * every key `not_comparable`) or a `ParserRunOutput`.
 */
export type RunParserFn = (
  workDir: string,
  ecosystems: string[],
  scanId: string,
  signal?: AbortSignal,
) => Promise<SandboxScanResult | ParserRunOutput>;

/** Normalizes a `RunParserFn` return value to `ParserRunOutput`. */
export function toParserRunOutput(value: SandboxScanResult | ParserRunOutput): ParserRunOutput {
  if ('result' in value && 'lockIntegrity' in value) return value;
  return { result: value as SandboxScanResult, lockIntegrity: [] };
}
