-- =============================================================================
-- 010_new_ecosystems — Rust, Dart and Swift project ecosystems; deps.dev and
-- pub.dev as registry license sources
-- REQ-011 / P-40, P-43 (AC-P40-1, AC-P43-1, AC-P43-2) · ADR-012 Karar 4 ·
-- D-300, D-318
-- PostgreSQL 15+
--
-- 1. tech_ecosystem += 'rust', 'dart', 'swift' (java, go, php and ruby
--    already exist since 001). The values are placed next to their
--    neighbours (rust after php, dart and swift after ruby), so the enum
--    order stays "parser ecosystems first, container/other last". The new
--    values are NOT used anywhere in this migration: PostgreSQL forbids using
--    a value added by ALTER TYPE ... ADD VALUE in the same transaction.
-- 2. registry_package_cache: ecosystem CHECK += 'depsdev' (Go, Maven, Cargo,
--    RubyGems license metadata from api.deps.dev) and 'pubdev' (Dart license
--    metadata from pub.dev). registry_archive_cache is unchanged: no package
--    archive is downloaded for the new ecosystems (D-321).
-- 3. scan_dependencies: license_source CHECK += 'registry:depsdev',
--    'registry:pubdev'.
--
-- The inline CHECKs replaced here carry PostgreSQL's default names
-- (<table>_<column>_check, created by 006 and replaced by 008 with the same
-- names). DROP CONSTRAINT is written WITHOUT "IF EXISTS" on purpose: if a
-- name were wrong the migration must fail instead of silently leaving the old
-- CHECK next to the new one.
--
-- Data: no data migration; existing values all satisfy the widened CHECKs.
--
-- Runs inside a single transaction (npm run db:migrate: one transaction per
-- file together with its schema_migrations row); no BEGIN/COMMIT here and no
-- CONCURRENTLY / non-transactional statement (ALTER TYPE ... ADD VALUE is
-- allowed inside a transaction block since PostgreSQL 12).
-- Lock / downtime: ALTER TYPE takes a brief lock on the type; each ALTER TABLE
-- takes ACCESS EXCLUSIVE on its table and validates the re-added CHECK with
-- one scan (registry_package_cache, scan_dependencies). No index is created.
-- Seconds even for large local databases. Stop the application before
-- migrating (the tool refuses while it runs).
--
-- DEPLOYMENT ORDER: apply before starting the REQ-011 runtime; the REQ-011
-- worker writes the new ecosystem values and `npm start` refuses to start
-- while this migration is pending. Older code never writes the new values.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Project ecosystems (D-300)
-- ---------------------------------------------------------------------------
ALTER TYPE tech_ecosystem ADD VALUE 'rust' AFTER 'php';
ALTER TYPE tech_ecosystem ADD VALUE 'dart' AFTER 'ruby';
ALTER TYPE tech_ecosystem ADD VALUE 'swift' AFTER 'dart';

-- ---------------------------------------------------------------------------
-- 2. Registry metadata cache (D-318, ADR-012 Karar 3)
-- ---------------------------------------------------------------------------
ALTER TABLE registry_package_cache
    DROP CONSTRAINT registry_package_cache_ecosystem_check,
    ADD  CONSTRAINT registry_package_cache_ecosystem_check
         CHECK (ecosystem IN ('npm', 'pypi', 'nuget', 'depsdev', 'pubdev'));

-- ---------------------------------------------------------------------------
-- 3. Effective license source per scan dependency (D-318)
-- ---------------------------------------------------------------------------
ALTER TABLE scan_dependencies
    DROP CONSTRAINT scan_dependencies_license_source_check,
    ADD  CONSTRAINT scan_dependencies_license_source_check
         CHECK (license_source IN ('registry:npm', 'registry:pypi', 'registry:nuget',
                                   'registry:depsdev', 'registry:pubdev',
                                   'lockfile (unverified)', 'none'));
