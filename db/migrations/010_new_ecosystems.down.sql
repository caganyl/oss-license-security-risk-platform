-- =============================================================================
-- 010_new_ecosystems — rollback
-- PostgreSQL 15+
--
-- DATA LOSS:
--   * Every package of the ecosystems 'rust', 'dart' and 'swift' is deleted
--     together with its scan_dependencies rows; findings of those rows (and
--     their license/security finding details, comments and history) go with
--     them via ON DELETE CASCADE. Scan summary counters (scans.total_*) are
--     NOT recomputed; rescan the affected projects.
--   * scan_files and project_tech_stacks rows of those ecosystems are
--     deleted (the projects then scan with their remaining stack, or with
--     every supported ecosystem when the stack becomes empty).
--   * vulnerabilities.affected_ecosystem 'rust' | 'dart' | 'swift' becomes
--     NULL (the catalog rows themselves stay).
--   * deps.dev / pub.dev license metadata cache rows (registry_package_cache,
--     ecosystem 'depsdev' | 'pubdev') are deleted. Re-downloadable.
--   * scan_dependencies.license_source 'registry:depsdev' | 'registry:pubdev'
--     is rewritten to 'none' (bulk UPDATE). license_expression is KEPT.
--   Java, Go, PHP and Ruby rows stay (those enum values predate 010).
--
-- Bulk data update: run only with explicit human approval (REQ-011 Notes).
-- Roll back together with reverting the REQ-011 runtime: the REQ-011 worker
-- writes values the restored type and CHECKs reject.
-- Enum values cannot be dropped in PostgreSQL: the type is recreated with the
-- 001 value list and the four columns are converted (ALTER COLUMN TYPE
-- rewrites packages, scan_files, project_tech_stacks and vulnerabilities and
-- rebuilds their indexes under ACCESS EXCLUSIVE). Stop the application first.
-- Order: data first (the narrowed type and CHECKs must hold), then the
-- constraints, then the type. DROP CONSTRAINT without IF EXISTS, as in the up
-- file.
-- =============================================================================

DELETE FROM scan_dependencies
 WHERE package_id IN (SELECT id FROM packages WHERE ecosystem::text IN ('rust', 'dart', 'swift'));
DELETE FROM packages WHERE ecosystem::text IN ('rust', 'dart', 'swift');
DELETE FROM scan_files WHERE ecosystem::text IN ('rust', 'dart', 'swift');
DELETE FROM project_tech_stacks WHERE ecosystem::text IN ('rust', 'dart', 'swift');
UPDATE vulnerabilities SET affected_ecosystem = NULL WHERE affected_ecosystem::text IN ('rust', 'dart', 'swift');
DELETE FROM registry_package_cache WHERE ecosystem IN ('depsdev', 'pubdev');
UPDATE scan_dependencies SET license_source = 'none' WHERE license_source IN ('registry:depsdev', 'registry:pubdev');

ALTER TABLE scan_dependencies
    DROP CONSTRAINT scan_dependencies_license_source_check,
    ADD  CONSTRAINT scan_dependencies_license_source_check
         CHECK (license_source IN ('registry:npm', 'registry:pypi', 'registry:nuget',
                                   'lockfile (unverified)', 'none'));

ALTER TABLE registry_package_cache
    DROP CONSTRAINT registry_package_cache_ecosystem_check,
    ADD  CONSTRAINT registry_package_cache_ecosystem_check
         CHECK (ecosystem IN ('npm', 'pypi', 'nuget'));

ALTER TYPE tech_ecosystem RENAME TO tech_ecosystem_010;
CREATE TYPE tech_ecosystem AS ENUM (
    'nodejs', 'python', 'java', 'dotnet', 'go', 'php', 'ruby', 'container', 'other'
);
ALTER TABLE project_tech_stacks
    ALTER COLUMN ecosystem TYPE tech_ecosystem USING ecosystem::text::tech_ecosystem;
ALTER TABLE scan_files
    ALTER COLUMN ecosystem TYPE tech_ecosystem USING ecosystem::text::tech_ecosystem;
ALTER TABLE packages
    ALTER COLUMN ecosystem TYPE tech_ecosystem USING ecosystem::text::tech_ecosystem;
ALTER TABLE vulnerabilities
    ALTER COLUMN affected_ecosystem TYPE tech_ecosystem USING affected_ecosystem::text::tech_ecosystem;
DROP TYPE tech_ecosystem_010;
