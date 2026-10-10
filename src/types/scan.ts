/**
 * Scan-domain types — mirrors the DB enums in the schema.
 */

/** Mirrors the tech_ecosystem DB enum. */
export type TechEcosystem =
  | 'nodejs'
  | 'python'
  | 'java'
  | 'dotnet'
  | 'go'
  | 'php'
  | 'ruby'
  | 'container'
  | 'other';

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

/**
 * Parser injection point of the scan worker. `signal` (optional, ADR-004
 * Karar 7) aborts the parse; three-argument implementations stay valid.
 */
export type RunParserFn = (
  workDir: string,
  ecosystems: string[],
  scanId: string,
  signal?: AbortSignal,
) => Promise<SandboxScanResult>;
