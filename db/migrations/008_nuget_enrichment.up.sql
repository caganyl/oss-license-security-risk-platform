-- =============================================================================
-- 008_nuget_enrichment — NuGet in the registry caches, the 'registry:nuget'
-- license source and the "unclassified license" marker
-- REQ-006 / P-20, P-21 (AC-G-7, AC-P21-5, AC-P21-6, AC-P21-7, AC-NV-3) ·
-- ADR-008 Karar 9, 12, 13.4, 14 · D-139, D-157, D-158
-- PostgreSQL 15+
--
-- 1. registry_package_cache: ecosystem CHECK += 'nuget' (key: 'nuget',
--    ASCII-lowercased id, lowercased normalized version). Three new nullable
--    columns, filled only by NuGet 'found' rows (registry_package_cache_nuget_fields):
--    - license_unclassified ('file' | 'url'): .nuspec <license type="file">
--      or a <licenseUrl> that maps to no SPDX expression (ADR-008 Karar 9);
--    - license_file_path (<= 256): the license file path declared in the
--      .nuspec (normalized archive path; NOTICE collects it from the .nupkg);
--    - canonical_name (<= 100): the .nuspec <id> in its original case, sent to
--      OSV and used by the recheck scope (ADR-008 Karar 13.2, 13.4).
-- 2. registry_archive_cache: ecosystem CHECK += 'nuget'.
-- 3. scan_dependencies: license_source CHECK += 'registry:nuget' (always
--    carries a non-empty license_expression); new license_unclassified
--    ('file' | 'url' | NULL). The marker is NOT a status value: such rows are
--    license_enrichment_status 'no_license', license_source 'none',
--    license_expression NULL. It is written only for NuGet keys with status
--    'no_license' and lock_integrity <> 'mismatch'; NULL otherwise (npm/PyPI,
--    pre-F5 rows). The column is never returned by the API (AC-G-4).
--
-- Value sets are identical to docs/contracts/REQ-004-notice-and-outputs.md
-- 1.4.0 sections 4.1 and 4.5. license_enrichment_status, notice_status and
-- lock_integrity sets are unchanged; lock_integrity only gains a NuGet
-- meaning (contract 4.4), so its column comment is updated. No enum change
-- (tech_ecosystem already has 'dotnet'). 001…007 are unchanged.
--
-- The inline CHECKs replaced here carry PostgreSQL's default names
-- (<table>_<column>_check, created by 006). DROP CONSTRAINT is written
-- WITHOUT "IF EXISTS" on purpose: if a name were wrong the migration must
-- fail instead of silently leaving the old CHECK next to the new one.
--
-- Data: no data migration. Existing rows get NULL in every new column (no
-- defaults, no table rewrite); existing values all satisfy the widened CHECKs.
--
-- Runs inside a single transaction (npm run db:migrate: one transaction per
-- file together with its schema_migrations row); no BEGIN/COMMIT here and no
-- CONCURRENTLY / non-transactional statement.
-- Lock / downtime: each ALTER TABLE takes ACCESS EXCLUSIVE on its table. The
-- added columns are nullable without defaults (catalog-only), but every
-- added CHECK is validated with one scan of the table (subcommands of one
-- ALTER TABLE share that scan): the two cache tables and scan_dependencies.
-- No index is created (the registry_package_cache primary key
-- (ecosystem, name, version) serves the recheck scope LEFT JOIN). Seconds
-- even for large local databases. Stop the application before migrating
-- (the tool refuses while it runs).
--
-- DEPLOYMENT ORDER: apply before starting the REQ-006 runtime; the REQ-006
-- worker, NOTICE, report, SBOM and OSV recheck code read and write these
-- columns/values and `npm start` refuses to start while this migration is
-- pending. Code older than REQ-006 ignores the new columns and never writes
-- the new values.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Registry metadata cache (ADR-008 Karar 9, 13.2, 14)
--    One ALTER TABLE: registry_package_cache is scanned once.
-- ---------------------------------------------------------------------------
ALTER TABLE registry_package_cache
    DROP CONSTRAINT registry_package_cache_ecosystem_check,
    ADD  CONSTRAINT registry_package_cache_ecosystem_check
         CHECK (ecosystem IN ('npm', 'pypi', 'nuget')),
    ADD COLUMN license_unclassified TEXT NULL
         CHECK (license_unclassified IN ('file', 'url')),
    ADD COLUMN license_file_path    TEXT NULL
         CHECK (license_file_path IS NULL OR char_length(license_file_path) <= 256),
    ADD COLUMN canonical_name       TEXT NULL
         CHECK (canonical_name IS NULL OR char_length(canonical_name) <= 100),
    -- the three NuGet fields exist only on NuGet 'found' rows
    ADD CONSTRAINT registry_package_cache_nuget_fields
         CHECK ((ecosystem = 'nuget' AND outcome = 'found')
                OR (license_unclassified IS NULL AND license_file_path IS NULL
                    AND canonical_name IS NULL));

COMMENT ON COLUMN registry_package_cache.license_unclassified IS
  'NuGet only (REQ-006, ADR-008 Karar 9): file = .nuspec <license type="file">, url = <licenseUrl> not mapped to an SPDX expression. The URL itself is never stored.';
COMMENT ON COLUMN registry_package_cache.license_file_path IS
  'NuGet only: license file path declared in the .nuspec (normalized archive path, <= 256); NULL when absent or invalid.';
COMMENT ON COLUMN registry_package_cache.canonical_name IS
  'NuGet only: .nuspec <id> in its original case (<= 100), used as the OSV package name (ADR-008 Karar 13.2, 13.4).';

-- ---------------------------------------------------------------------------
-- 2. Package archive (NOTICE) cache (ADR-008 Karar 11, 14)
-- ---------------------------------------------------------------------------
ALTER TABLE registry_archive_cache
    DROP CONSTRAINT registry_archive_cache_ecosystem_check,
    ADD  CONSTRAINT registry_archive_cache_ecosystem_check
         CHECK (ecosystem IN ('npm', 'pypi', 'nuget'));

-- ---------------------------------------------------------------------------
-- 3. Effective license source and the unclassified marker per scan
--    dependency (ADR-008 Karar 12, 14; contract 4.1, 4.5)
--    One ALTER TABLE: scan_dependencies is scanned once.
-- ---------------------------------------------------------------------------
ALTER TABLE scan_dependencies
    DROP CONSTRAINT scan_dependencies_license_source_check,
    ADD  CONSTRAINT scan_dependencies_license_source_check
         CHECK (license_source IN ('registry:npm', 'registry:pypi', 'registry:nuget',
                                   'lockfile (unverified)', 'none')),
    ADD COLUMN license_unclassified TEXT NULL
         CHECK (license_unclassified IN ('file', 'url'));

COMMENT ON COLUMN scan_dependencies.license_unclassified IS
  'NuGet license not classified (REQ-006 AC-P21-5/6, ADR-008 Karar 12): file | url; only with status no_license, source none and lock_integrity <> mismatch. NULL otherwise. Never returned by the API.';
COMMENT ON COLUMN scan_dependencies.lock_integrity IS
  'Lockfile hash vs registry archive (REQ-005 L-5, ADR-007 Karar 12; NuGet: .nupkg vs lock/assets hash, ADR-008 Karar 10). NULL = not compared (enrichment off, PyPI, scan before F4 / NuGet before F5).';
