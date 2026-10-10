-- =============================================================================
-- 008_nuget_enrichment — rollback
-- PostgreSQL 15+
--
-- DATA LOSS:
--   * NuGet license metadata cache rows (registry_package_cache, ecosystem
--     'nuget') are deleted, together with their license_unclassified,
--     license_file_path and canonical_name values. Re-downloadable from
--     api.nuget.org.
--   * NuGet archive (NOTICE) cache rows (registry_archive_cache, ecosystem
--     'nuget') are deleted. Re-downloadable; scan_dependencies.notice_archive_id
--     of NuGet rows becomes NULL via ON DELETE SET NULL (notice_status stays),
--     so a NOTICE of those scans needs a rescan.
--   * scan_dependencies.license_source 'registry:nuget' is rewritten to 'none'
--     (bulk UPDATE). license_expression is KEPT, so those rows show an
--     expression with source 'none' until rescanned.
--   * scan_dependencies.license_unclassified is dropped: the 'license file in
--     package' / 'unclassified license URL' markers are lost permanently
--     (re-running 008 up does NOT restore them; those rows then look like a
--     plain no_license / none row until rescanned).
--   No scan, scan_dependencies, package, finding or license_findings row is
--   deleted. dotnet packages, their findings and lock_integrity values stay.
--
-- Bulk data update: run only with explicit human approval (REQ-006 Notes,
-- D-158). Roll back together with reverting the REQ-006 runtime: the REQ-006
-- worker writes 'nuget' / 'registry:nuget' values the restored CHECKs reject.
-- Lock / downtime: DELETE / UPDATE take row locks; each ALTER TABLE takes a
-- brief ACCESS EXCLUSIVE lock, DROP COLUMN is catalog-only, and every re-added
-- CHECK is validated with one scan of its table. Stop the application first.
-- Order: data first (the narrowed CHECKs must hold), then the columns and
-- constraints. DROP CONSTRAINT without IF EXISTS, as in the up file.
-- =============================================================================

DELETE FROM registry_archive_cache WHERE ecosystem = 'nuget';
DELETE FROM registry_package_cache WHERE ecosystem = 'nuget';
UPDATE scan_dependencies SET license_source = 'none' WHERE license_source = 'registry:nuget';

ALTER TABLE scan_dependencies
    DROP COLUMN license_unclassified,
    DROP CONSTRAINT scan_dependencies_license_source_check,
    ADD  CONSTRAINT scan_dependencies_license_source_check
         CHECK (license_source IN ('registry:npm', 'registry:pypi',
                                   'lockfile (unverified)', 'none'));

COMMENT ON COLUMN scan_dependencies.lock_integrity IS
  'npm lockfile sha512 vs registry dist.integrity (REQ-005 L-5, ADR-007 Karar 12). NULL = not compared (enrichment off, non-npm, scan before F4).';

ALTER TABLE registry_archive_cache
    DROP CONSTRAINT registry_archive_cache_ecosystem_check,
    ADD  CONSTRAINT registry_archive_cache_ecosystem_check CHECK (ecosystem IN ('npm', 'pypi'));

ALTER TABLE registry_package_cache
    DROP CONSTRAINT registry_package_cache_nuget_fields,
    DROP COLUMN canonical_name,
    DROP COLUMN license_file_path,
    DROP COLUMN license_unclassified,
    DROP CONSTRAINT registry_package_cache_ecosystem_check,
    ADD  CONSTRAINT registry_package_cache_ecosystem_check CHECK (ecosystem IN ('npm', 'pypi'));
