-- =============================================================================
-- 003_declared_range — exact version vs. declared range
-- REQ-002 / P-05 (AC-P05-2, AC-P05-3, AC-P05-4, AC-P05-5) · ADR-003 (a)
-- PostgreSQL 15+
--
-- packages.version now holds ONLY an exactly resolved version, or NULL when it
-- is unknown (then the purl carries no version). The manifest-declared range
-- (^1.2.0, >=2,<3, ...) moves to scan_dependencies.declared_range.
--
-- Runs inside a single transaction (db/migrate.sh --single-transaction).
-- Lock / downtime: ACCESS EXCLUSIVE on packages and scan_dependencies for the
-- duration (UPDATEs + CHECK validation + index build). Stop the API and worker
-- before migrating.
--
-- "purl has a version" is decided on the purl itself: qualifiers (?...) and
-- subpath (#...) are cut off, then an '@' AFTER the last '/' marks the version.
-- This keeps scoped npm names (pkg:npm/@scope/name) versionless.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Schema: nullable version, declared range column
-- ---------------------------------------------------------------------------
ALTER TABLE scan_dependencies
    ADD COLUMN declared_range TEXT;

ALTER TABLE packages
    ALTER COLUMN version DROP NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. Precondition: at most one versionless row per (ecosystem, name).
--    purl is UNIQUE and derived from the name, so this holds for data written
--    by the current parsers. If it does not hold, merging catalog rows is a
--    data-repair decision for a human; abort instead of guessing.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    dup_groups INTEGER;
BEGIN
    SELECT count(*) INTO dup_groups
    FROM (
        SELECT ecosystem, name
        FROM packages
        WHERE split_part(split_part(purl, '#', 1), '?', 1) !~ '@[^/]*$'
        GROUP BY ecosystem, name
        HAVING count(*) > 1
    ) d;

    IF dup_groups > 0 THEN
        RAISE EXCEPTION '003_declared_range: % (ecosystem, name) group(s) have more than one versionless purl row; merge them manually before migrating', dup_groups;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Data fix (existing rows)
--    a) Copy the old pseudo-version of versionless packages into every linked
--       scan_dependencies row as declared_range. The Python parser's sentinel
--       'unknown' (no specifier at all) and blank values are not ranges and
--       become NULL.
--    b) Clear packages.version for those packages.
--    Order matters: (a) must read the old value before (b) clears it.
-- ---------------------------------------------------------------------------
UPDATE scan_dependencies sd
SET    declared_range = NULLIF(NULLIF(btrim(p.version), ''), 'unknown')
FROM   packages p
WHERE  sd.package_id = p.id
  AND  split_part(split_part(p.purl, '#', 1), '?', 1) !~ '@[^/]*$';

UPDATE packages
SET    version = NULL
WHERE  split_part(split_part(purl, '#', 1), '?', 1) !~ '@[^/]*$';

-- ---------------------------------------------------------------------------
-- 4. Integrity
-- ---------------------------------------------------------------------------
-- PostgreSQL treats NULLs as distinct in UNIQUE (ecosystem, name, version);
-- this partial index allows only one versionless row per package name.
CREATE UNIQUE INDEX idx_packages_unversioned_unique
    ON packages(ecosystem, name)
    WHERE version IS NULL;

-- AC-P05-3: a package with unknown version must not carry a version (or a
-- range masquerading as one) in its purl.
ALTER TABLE packages
    ADD CONSTRAINT packages_unversioned_purl_chk
    CHECK (version IS NOT NULL
           OR split_part(split_part(purl, '#', 1), '?', 1) !~ '@[^/]*$');
