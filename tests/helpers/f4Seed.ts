/**
 * REQ-005 (F4) direct database seeding for the recheck / expiry / status
 * tests. Packages are upserted (UNIQUE (ecosystem, name, version)) so several
 * projects can share one package, which `f3Seed.seedScan` does not allow.
 * Test data only (no secrets).
 */
import type { AppClock } from '../../src/lib/clock';
import { createVulnerabilityClient, type VulnerabilityClient } from '../../src/vulnerability/client';
import { createVulnerabilityLookup, type VulnerabilityLookup } from '../../src/vulnerability/lookup';
import type { VulnerabilityConfig } from '../../src/scanner/sandbox/runner.config';
import type { TestDatabase } from './db';

export const F4_CONFIG: VulnerabilityConfig = {
  lookupEnabled: true,
  recheckEnabled: true,
  intervalHours: 24,
  timeoutMs: 3_000,
  concurrency: 4,
  nvdEnabled: false,
};

export interface ScanSeed {
  projectId?: string;
  projectName?: string;
  /** npm packages `[name, version]`. */
  deps: Array<[string, string]>;
  status?: string;
  completedAt?: string | null;
  vulnerabilityDataStatus?: string | null;
  vulnerabilityCheckedAt?: string | null;
  repoUrl?: string;
}

export interface SeededScan {
  projectId: string;
  scanId: string;
  /** scan_dependencies id by package name. */
  sd: Record<string, string>;
}

export async function insertProject(db: TestDatabase, name: string, repoUrl = 'https://example.test/repo.git'): Promise<string> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, $2) RETURNING id::text AS id`, [name, repoUrl]);
  return p.id;
}

export async function upsertNpmPackage(db: TestDatabase, name: string, version: string): Promise<string> {
  const [pkg] = await db.query<{ id: string }>(
    `INSERT INTO packages (ecosystem, name, version, purl) VALUES ('nodejs', $1, $2, $3)
     ON CONFLICT (ecosystem, name, version) DO UPDATE SET name = EXCLUDED.name RETURNING id::text AS id`,
    [name, version, `pkg:npm/${name}@${version}`],
  );
  return pkg.id;
}

/** Project (unless given), scan and scan_dependencies (scope direct, package-lock.json). */
export async function seedF4Scan(db: TestDatabase, o: ScanSeed): Promise<SeededScan> {
  const projectId = o.projectId ?? (await insertProject(db, o.projectName ?? `p-${Math.random().toString(36).slice(2)}`, o.repoUrl));
  const status = o.status ?? 'completed';
  const completedAt = o.completedAt === undefined ? (status === 'completed' ? '2026-10-09T08:00:00.000Z' : null) : o.completedAt;
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (project_id, trigger, status, ref, completed_at, total_dependencies, vulnerability_data_status, vulnerability_checked_at)
     VALUES ($1, 'manual', $2::scan_status, 'main', $3::timestamptz, $4, $5, $6::timestamptz) RETURNING id::text AS id`,
    [projectId, status, completedAt, o.deps.length, o.vulnerabilityDataStatus ?? null, o.vulnerabilityCheckedAt ?? null],
  );
  const sd: Record<string, string> = {};
  for (const [name, version] of o.deps) {
    const pkgId = await upsertNpmPackage(db, name, version);
    const [row] = await db.query<{ id: string }>(
      `INSERT INTO scan_dependencies (scan_id, package_id, scope, manifest_file, manifest_path, depth)
       VALUES ($1, $2, 'direct', 'package-lock.json', '.', 0) RETURNING id::text AS id`,
      [s.id, pkgId],
    );
    sd[name] = row.id;
  }
  return { projectId, scanId: s.id, sd };
}

export async function insertUser(db: TestDatabase, email = `qa-${Math.random().toString(36).slice(2)}@example.test`): Promise<string> {
  const [u] = await db.query<{ id: string }>(`INSERT INTO users (email, display_name) VALUES ($1, 'QA') RETURNING id::text AS id`, [email]);
  return u.id;
}

/** A finding row with a deterministic 64-hex fingerprint. */
export async function insertFindingRow(
  db: TestDatabase,
  o: { scanId: string; sdId: string; status: string; fingerprint?: string; type?: string; assigneeId?: string | null },
): Promise<string> {
  const [f] = await db.query<{ id: string }>(
    `INSERT INTO findings (scan_id, scan_dependency_id, finding_type, status, fingerprint, assignee_id)
     VALUES ($1, $2, $3::finding_type, $4::finding_status, COALESCE($5, md5(random()::text) || md5(random()::text)), $6)
     RETURNING id::text AS id`,
    [o.scanId, o.sdId, o.type ?? 'security', o.status, o.fingerprint ?? null, o.assigneeId ?? null],
  );
  return f.id;
}

export async function insertReview(
  db: TestDatabase,
  o: { findingId: string; reviewerId: string; decision: string; acceptedUntil?: string | null; createdAt?: string },
): Promise<string> {
  const [r] = await db.query<{ id: string }>(
    `INSERT INTO finding_reviews (finding_id, decision, reviewer_id, accepted_until, created_at)
     VALUES ($1, $2::review_decision, $3, $4::date, COALESCE($5::timestamptz, NOW())) RETURNING id::text AS id`,
    [o.findingId, o.decision, o.reviewerId, o.acceptedUntil ?? null, o.createdAt ?? null],
  );
  return r.id;
}

/** Real lookup engine (pg cache) against the loopback fake OSV/NVD server. */
export function makeF4Lookup(
  db: TestDatabase,
  origin: string,
  clock: AppClock,
  logs: string[],
  clients: VulnerabilityClient[],
  config: Partial<VulnerabilityConfig> = {},
): VulnerabilityLookup {
  const client = createVulnerabilityClient({
    config: { ...F4_CONFIG, ...config },
    endpoints: { osv: origin, nvd: origin },
    env: {},
    clock,
    warn: (m: string) => logs.push(m),
  });
  clients.push(client);
  return createVulnerabilityLookup({ client, db: db.pool, clock, logger: { warn: (m: string) => logs.push(m) } });
}
