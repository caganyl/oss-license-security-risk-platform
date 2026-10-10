-- =============================================================================
-- 006_registry_enrichment — registry license enrichment cache, archive (NOTICE)
-- cache and the per-scan-dependency effective license / NOTICE fields
-- REQ-004 / P-14, P-15, P-16, L-6 (AC-P14-6, AC-P14-8, AC-P14-17, AC-P15-10,
-- AC-G-7) · ADR-006 Karar 9, 10, 11 · D-57, D-62, D-79
-- PostgreSQL 15+ (gen_random_uuid(): pgcrypto from 001, built in since 13)
--
-- 1. registry_package_cache: metadata cache keyed by registry identity
--    (ecosystem 'npm' | 'pypi', request name, exact version). 'found' rows
--    never expire (refreshed only when the code's METADATA_EXTRACTOR_VERSION
--    grows); 'not_found' (404/410) rows expire after 24 h. Transient errors are
--    never stored. Written in its own autocommit transaction, independent of
--    the scan result transaction (AC-P14-8).
-- 2. registry_archive_cache: license files and copyright lines extracted from
--    one package archive, keyed by (ecosystem, name, version, archive_digest).
--    Only outcomes produced by the reader itself are stored; the row is
--    updated in place (same id) when ARCHIVE_EXTRACTOR_VERSION grows.
-- 3. scan_dependencies: effective license, its source, the lockfile hint, the
--    enrichment status and the NOTICE outcome, written inside the scan result
--    transaction. All new columns are NULL for scans completed before F3
--    (NULL = "predates license enrichment").
--
-- The status/source value sets are identical to
-- docs/contracts/REQ-004-notice-and-outputs.md section 4; adding a value
-- requires a contract revision and a new migration.
-- The ecosystem column is TEXT + CHECK, not tech_ecosystem: it is the registry
-- identity, not the project ecosystem.
-- packages.copyright_text / notice_text / metadata / enriched_at stay unused
-- and are NOT dropped (D-79); dropping them is a separate cleanup decision.
--
-- Data: no data migration. Existing scan_dependencies rows get NULL in every
-- new column; the two cache tables start empty.
--
-- Runs inside a single transaction (npm run db:migrate: one transaction per
-- file together with its schema_migrations row); no BEGIN/COMMIT here and no
-- CONCURRENTLY / non-transactional statement.
-- Lock / downtime: the new tables are created empty. ALTER TABLE
-- scan_dependencies adds nullable columns without defaults (catalog-only, no
-- table rewrite) but holds ACCESS EXCLUSIVE on scan_dependencies while the
-- CHECK constraints and the foreign key are validated (one scan of the table;
-- all subcommands are in a single ALTER TABLE so the table is scanned once),
-- then CREATE INDEX scans it again under a SHARE lock. Seconds even for large
-- local databases. Stop the application before migrating (the tool refuses
-- while it runs).
--
-- DEPLOYMENT ORDER: apply before starting the REQ-004 runtime; the REQ-004
-- worker, SBOM, report and NOTICE code read and write these tables/columns and
-- `npm start` refuses to start while this migration is pending. Code older
-- than REQ-004 ignores the new tables and columns.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Registry metadata cache (ADR-006 Karar 9, 10; D-57)
-- ---------------------------------------------------------------------------
CREATE TABLE registry_package_cache (
    ecosystem          TEXT        NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name               TEXT        NOT NULL,  -- request name: npm as-is, PyPI PEP 503
    version            TEXT        NOT NULL,
    outcome            TEXT        NOT NULL CHECK (outcome IN ('found', 'not_found')),
    declared_license   TEXT        NULL,      -- derived per AC-P14-1/2/3; NULL = registry has no license
    license_text       TEXT        NULL,      -- long PyPI license text (NOTICE fallback), <= 1 MiB
    archive_candidates JSONB       NOT NULL DEFAULT '[]'::jsonb,
    extractor_version  INTEGER     NOT NULL CHECK (extractor_version > 0),
    fetched_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NULL,      -- NULL = found (never expires); not_found = fetched_at + 24 h
    PRIMARY KEY (ecosystem, name, version),
    CONSTRAINT registry_package_cache_expiry
        CHECK ((outcome = 'not_found') = (expires_at IS NOT NULL)),
    CONSTRAINT registry_package_cache_not_found_empty
        CHECK (outcome = 'found' OR (declared_license IS NULL AND license_text IS NULL
                                     AND archive_candidates = '[]'::jsonb))
);

COMMENT ON TABLE registry_package_cache IS
  'Registry license metadata cache (REQ-004 P-14, ADR-006 Karar 10). Re-downloadable; safe to clear (db/README.md).';
COMMENT ON COLUMN registry_package_cache.expires_at IS
  'NULL for found rows (never expire); NOW() + 24 h for not_found rows. Evaluated with the database clock.';
COMMENT ON COLUMN registry_package_cache.extractor_version IS
  'METADATA_EXTRACTOR_VERSION of the code that wrote the row; a row with an older version is a cache miss.';

-- ---------------------------------------------------------------------------
-- 2. Package archive (NOTICE) cache (ADR-006 Karar 7, 9, 10; D-57)
-- ---------------------------------------------------------------------------
CREATE TABLE registry_archive_cache (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem         TEXT        NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name              TEXT        NOT NULL,
    version           TEXT        NOT NULL,
    archive_digest    TEXT        NOT NULL,   -- 'sha512-<b64>' | 'sha1-<hex>' | 'sha256-<hex>'
    archive_url       TEXT        NOT NULL,
    archive_size      BIGINT      NOT NULL CHECK (archive_size >= 0),
    outcome           TEXT        NOT NULL CHECK (outcome IN
                          ('collected', 'no_license_file', 'unsupported_format', 'limit_exceeded')),
    outcome_detail    TEXT        NULL,       -- fixed code, e.g. 'entries', 'decompressed', 'zip64'
    license_files     JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- [{path,text} | {path,omitted}]
    copyright_lines   TEXT[]      NOT NULL DEFAULT '{}',
    extractor_version INTEGER     NOT NULL CHECK (extractor_version > 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Upsert target (ON CONFLICT ON CONSTRAINT registry_archive_cache_key); its
    -- (ecosystem, name, version) prefix also serves the pre-F3 NOTICE lookup.
    CONSTRAINT registry_archive_cache_key UNIQUE (ecosystem, name, version, archive_digest)
);

COMMENT ON TABLE registry_archive_cache IS
  'License files and copyright lines extracted from package archives (REQ-004 P-15, ADR-006 Karar 7, 10). Re-downloadable; safe to clear (db/README.md).';
COMMENT ON COLUMN registry_archive_cache.extractor_version IS
  'ARCHIVE_EXTRACTOR_VERSION of the code that wrote the row; updated in place (same id) when it grows.';

-- ---------------------------------------------------------------------------
-- 3. Effective license and NOTICE fields per scan dependency
--    (ADR-006 Karar 9, 11; D-62; contract section 4)
--    One ALTER TABLE: scan_dependencies is scanned once to validate the CHECK
--    constraints and the foreign key (all values are NULL).
-- ---------------------------------------------------------------------------
ALTER TABLE scan_dependencies
    ADD COLUMN license_expression        TEXT    NULL,
    ADD COLUMN license_source            TEXT    NULL CHECK (license_source IN
        ('registry:npm', 'registry:pypi', 'lockfile (unverified)', 'none')),
    ADD COLUMN license_lock_hint         TEXT    NULL,
    ADD COLUMN license_hint_differs      BOOLEAN NULL,
    ADD COLUMN license_enrichment_status TEXT    NULL CHECK (license_enrichment_status IN
        ('ok', 'no_license', 'not_found', 'unreachable', 'error', 'disabled',
         'version_unknown', 'invalid_coordinates', 'budget_exceeded')),
    ADD COLUMN notice_status             TEXT    NULL CHECK (notice_status IN
        ('collected', 'no_license_file', 'unsupported_format', 'limit_exceeded',
         'no_candidate', 'integrity_failed', 'download_failed', 'processing_failed',
         'budget_exceeded', 'not_attempted', 'not_runtime')),
    ADD COLUMN notice_archive_id         UUID    NULL
        REFERENCES registry_archive_cache(id) ON DELETE SET NULL,
    -- source and status are written together; both NULL = scan predates F3
    ADD CONSTRAINT scan_dependencies_license_f3_together
        CHECK ((license_source IS NULL) = (license_enrichment_status IS NULL));

COMMENT ON COLUMN scan_dependencies.license_source IS
  'Effective license source (REQ-004 L-6, ADR-006 Karar 11). NULL = scan completed before license enrichment (F3).';
COMMENT ON COLUMN scan_dependencies.notice_archive_id IS
  'registry_archive_cache row used for NOTICE/copyright; set to NULL when the cache is cleared (rescan required).';

-- Supports ON DELETE SET NULL when archive cache rows are deleted and the
-- NOTICE join; most rows are NULL (pre-F3, non-runtime, transient outcomes).
CREATE INDEX idx_scan_dependencies_notice_archive
    ON scan_dependencies (notice_archive_id) WHERE notice_archive_id IS NOT NULL;
