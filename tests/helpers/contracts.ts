/**
 * Interfaces the REQ-002 tests expect from src/ (test-first). The prose
 * version, with rationale, is in tests/README.md ("Beklenen arayüzler").
 * Modules are loaded with loadSrc()/loadSrcGuarded() and cast to these types.
 */
import type { Server } from 'node:http';
import type { Express } from 'express';
import type { Pool } from 'pg';

// ---------------------------------------------------------------------------
// src/app.ts
// ---------------------------------------------------------------------------
export interface AppDeps {
  /** Database pool. Required; the app must not fall back to the global pool. */
  db: Pool;
  /** Port used for the Host/Origin allow-list (default: PORT env or 3001). */
  port?: number;
  /** Bind/allow-list host (default: HOST env or 127.0.0.1). */
  host?: string;
  /** Allowed local scan roots (default: parseScanRoots(process.env.SCAN_ROOTS)). */
  scanRoots?: string[];
}

export interface AppModule {
  createApp(deps: AppDeps): Express;
  startServer(options: AppDeps): Promise<Server>;
}

// ---------------------------------------------------------------------------
// src/lib/scanSource.ts
// ---------------------------------------------------------------------------
export type ScanSource = { kind: 'remote'; url: string } | { kind: 'local'; path: string };

export type ScanSourceErrorCode = 'path_not_allowed' | 'repo_url_not_allowed';

export interface ScanSourceModule {
  parseScanRoots(value: string | undefined): string[];
  resolveScanSource(value: string, scanRoots: readonly string[]): Promise<ScanSource>;
  ScanSourceError: new (code: ScanSourceErrorCode, message?: string) => Error & {
    code: ScanSourceErrorCode;
    statusCode: number;
  };
}

// ---------------------------------------------------------------------------
// src/scanner/workspace.ts
// ---------------------------------------------------------------------------
export type CloneRepoFn = (url: string, ref: string | null, dest: string, token: string | null) => Promise<void>;

export interface WorkspaceModule {
  buildGitCloneArgs(url: string, ref: string | null, dest: string): string[];
  withTempWorkspace<T>(fn: (dir: string) => Promise<T>, options?: { tmpRoot?: string }): Promise<T>;
  cloneRepo: CloneRepoFn;
}

// ---------------------------------------------------------------------------
// Parser output (src/types/scan.ts after P-05)
// ---------------------------------------------------------------------------
export interface ScannedDependencyFixture {
  ecosystem: string;
  name: string;
  /** Exact resolved version, or null when unknown (P-05). */
  version: string | null;
  /** Range as declared in the manifest, if any (P-05). */
  declared_range?: string | null;
  purl: string;
  scope?: 'direct' | 'transitive' | 'dev' | 'peer' | 'optional';
  licenses?: string[];
  vulnerabilities?: Array<{ id: string; fix_versions: string[] }>;
  manifest_file: string;
  manifest_path: string;
}

export interface ScanResultFixture {
  scan_id: string;
  status: 'completed' | 'failed';
  total_deps: number;
  dependencies: ScannedDependencyFixture[];
  scan_files: Array<{ ecosystem: string; filename: string; file_path: string; file_hash: string; size_bytes: number }>;
  parse_errors: Array<{ ecosystem: string; file: string; error: string }>;
}

// ---------------------------------------------------------------------------
// src/scanner/worker.ts
// ---------------------------------------------------------------------------
export type RunParserFn = (workDir: string, ecosystems: string[], scanId: string) => Promise<ScanResultFixture>;

export interface ScanWorkerDeps {
  db: Pool;
  cloneRepo: CloneRepoFn;
  runParser: RunParserFn;
  scanRoots: string[];
  /** Base directory for ossrisk-scan-* workspaces (default os.tmpdir()). */
  tmpRoot: string;
  logger: Pick<Console, 'log' | 'warn' | 'error'>;
}

export interface ScanWorkerInstance {
  /** Claims the next pending/queued scan, processes it completely, returns its id (null if none). */
  runOnce(): Promise<string | null>;
  saveScanResults(scanId: string, projectId: string, result: ScanResultFixture): Promise<void>;
}

export interface WorkerModule {
  ScanWorker: new (deps?: Partial<ScanWorkerDeps>) => ScanWorkerInstance;
  decryptToken(encrypted: Buffer | null | undefined, keyString?: string): string | null;
}

// ---------------------------------------------------------------------------
// src/analysis/findingFingerprint.ts
// ---------------------------------------------------------------------------
export interface FingerprintInput {
  projectId: string;
  /** packages.purl as stored. */
  purl: string;
  /** packages.version as stored (may be null / untrimmed). */
  version: string | null;
  findingType: 'license' | 'security';
  /** license_findings.normalized_license (license findings). */
  normalizedLicense?: string | null;
  /** Advisory identifiers + vulnerabilities.id (security findings). */
  vulnerability?: { id: string; osvId?: string | null; ghsaId?: string | null; cveId?: string | null };
}

export interface FingerprintModule {
  computeFindingFingerprint(input: FingerprintInput): string;
}

// ---------------------------------------------------------------------------
// Existing modules used as-is
// ---------------------------------------------------------------------------
export interface ScanControllerModule {
  ScanController: new (db: Pool) => {
    getScanFindings(req: unknown, res: unknown, next: (err?: unknown) => void): Promise<void>;
  };
}
