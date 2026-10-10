-- =============================================================================
-- 006_registry_enrichment — rollback
-- PostgreSQL 15+
--
-- DATA LOSS:
--   * registry_package_cache and registry_archive_cache are dropped with all
--     rows: the registry license metadata cache and the extracted license files
--     / copyright lines. Both are re-downloadable from the public registries;
--     re-applying 006 starts with an empty cache and the next scans fetch again.
--   * scan_dependencies.license_expression, license_source, license_lock_hint,
--     license_hint_differs, license_enrichment_status, notice_status and
--     notice_archive_id are dropped: the effective license / NOTICE fields of
--     every scan completed after F3 are lost permanently (re-running 006 up
--     does NOT restore them; those scans then look like pre-F3 scans). Reports
--     and SBOMs of those scans fall back to license_findings; a NOTICE needs a
--     rescan.
--   No other column or row is touched: scan_dependencies rows, packages
--   (including the unused copyright_text / notice_text / metadata /
--   enriched_at columns, D-79), findings and license_findings stay intact.
--
-- Roll back together with reverting the REQ-004 runtime: the REQ-004 worker,
-- SBOM, report and NOTICE code read and write these tables/columns.
-- Lock / downtime: DROP COLUMN is catalog-only but takes a brief ACCESS
-- EXCLUSIVE lock on scan_dependencies. Stop the application first.
-- Order: the foreign key column goes before the referenced table.
-- =============================================================================

DROP INDEX IF EXISTS idx_scan_dependencies_notice_archive;

ALTER TABLE scan_dependencies
    DROP CONSTRAINT IF EXISTS scan_dependencies_license_f3_together,
    DROP COLUMN IF EXISTS notice_archive_id,
    DROP COLUMN IF EXISTS notice_status,
    DROP COLUMN IF EXISTS license_enrichment_status,
    DROP COLUMN IF EXISTS license_hint_differs,
    DROP COLUMN IF EXISTS license_lock_hint,
    DROP COLUMN IF EXISTS license_source,
    DROP COLUMN IF EXISTS license_expression;

DROP TABLE IF EXISTS registry_archive_cache;
DROP TABLE IF EXISTS registry_package_cache;
