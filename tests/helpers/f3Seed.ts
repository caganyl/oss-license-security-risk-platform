/**
 * REQ-004 (F3) direct database seeding for output tests (NOTICE, SBOM,
 * reports). Rows are written with plain SQL so every effective-license /
 * NOTICE column value of contract section 4 can be set exactly, without the
 * scan worker or a registry. Test data only (no secrets).
 */
import type { TestDatabase } from './db';

export interface SeedArchive {
  ecosystem: 'npm' | 'pypi';
  name: string;
  version: string;
  outcome: 'collected' | 'no_license_file' | 'unsupported_format' | 'limit_exceeded';
  licenseFiles?: Array<{ path: string; text: string } | { path: string; omitted: string }>;
  copyrightLines?: string[];
  extractorVersion?: number;
}

export interface SeedDep {
  ecosystem: string;
  name: string;
  version: string | null;
  purl: string;
  scope?: string;
  manifestPath?: string;
  depth?: number;
  licenseExpression?: string | null;
  licenseSource?: string | null;
  licenseLockHint?: string | null;
  licenseHintDiffers?: boolean | null;
  enrichmentStatus?: string | null;
  noticeStatus?: string | null;
  /** Archive row written and linked through `notice_archive_id`. */
  archive?: SeedArchive;
  /** Extra scan_dependencies rows for the same package (other manifests / scopes). */
  extraScopes?: string[];
}

export interface SeedScanOptions {
  projectName: string;
  scanId?: string;
  status?: string;
  completedAt?: string | null;
  deps: SeedDep[];
}

export async function insertArchive(db: TestDatabase, a: SeedArchive): Promise<string> {
  const [row] = await db.query<{ id: string }>(
    `INSERT INTO registry_archive_cache
       (ecosystem, name, version, archive_digest, archive_url, archive_size, outcome, license_files, copyright_lines, extractor_version)
     VALUES ($1, $2, $3, $4, $5, 1, $6, $7::jsonb, $8::text[], $9) RETURNING id::text AS id`,
    [
      a.ecosystem, a.name, a.version, `sha512-${a.name}-${a.version}`, `https://registry.npmjs.org/${a.name}/-/${a.name}-${a.version}.tgz`,
      a.outcome, JSON.stringify(a.licenseFiles ?? []), a.copyrightLines ?? [], a.extractorVersion ?? 1,
    ],
  );
  return row.id;
}

/** Creates project, scan and packages/scan_dependencies; returns the scan id (lower case). */
export async function seedScan(db: TestDatabase, o: SeedScanOptions): Promise<{ scanId: string; projectId: string }> {
  const [p] = await db.query<{ id: string }>(`INSERT INTO projects (name, repo_url) VALUES ($1, 'https://example.test/repo.git') RETURNING id`, [o.projectName]);
  const status = o.status ?? 'completed';
  const completedAt = o.completedAt === undefined ? (status === 'completed' ? '2026-10-10T08:15:30.123Z' : null) : o.completedAt;
  const [s] = await db.query<{ id: string }>(
    `INSERT INTO scans (id, project_id, trigger, status, ref, completed_at, total_dependencies)
     VALUES (COALESCE($1::uuid, gen_random_uuid()), $2, 'manual', $3::scan_status, 'main', $4::timestamptz, $5) RETURNING id::text AS id`,
    [o.scanId ?? null, p.id, status, completedAt, o.deps.length],
  );
  for (const d of o.deps) {
    const [pkg] = await db.query<{ id: string }>(
      `INSERT INTO packages (ecosystem, name, version, purl) VALUES ($1::tech_ecosystem, $2, $3, $4) RETURNING id`,
      [d.ecosystem, d.name, d.version, d.purl],
    );
    const archiveId = d.archive ? await insertArchive(db, d.archive) : null;
    for (const scope of [d.scope ?? 'direct', ...(d.extraScopes ?? [])]) {
      await db.query(
        `INSERT INTO scan_dependencies
           (scan_id, package_id, scope, manifest_file, manifest_path, depth, license_expression, license_source, license_lock_hint,
            license_hint_differs, license_enrichment_status, notice_status, notice_archive_id)
         VALUES ($1, $2, $3::dependency_scope, 'package-lock.json', $4, $5, $6, $7, $8, $9, $10, $11, $12::uuid)`,
        [
          s.id, pkg.id, scope, d.manifestPath ?? '.', d.depth ?? 0, d.licenseExpression ?? null, d.licenseSource ?? null,
          d.licenseLockHint ?? null, d.licenseHintDiffers ?? null, d.enrichmentStatus ?? null, d.noticeStatus ?? null, archiveId,
        ],
      );
    }
  }
  return { scanId: s.id, projectId: p.id };
}

/** F3 dependency defaults: registry hit with a license. */
export function f3Dep(d: SeedDep): SeedDep {
  return { licenseSource: 'registry:npm', enrichmentStatus: 'ok', noticeStatus: 'not_attempted', ...d };
}
