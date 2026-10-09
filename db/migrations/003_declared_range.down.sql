-- =============================================================================
-- 003_declared_range — rollback
-- PostgreSQL 15+
--
-- Restores the pre-003 shape: packages.version NOT NULL, no declared_range.
-- Rows with version NULL get back a pseudo-version (pre-003 behaviour):
--   the most recent non-NULL scan_dependencies.declared_range of that package,
--   otherwise the Python parser sentinel 'unknown'.
--
-- DATA LOSS:
--   * scan_dependencies.declared_range is dropped. When a package was declared
--     with different ranges in different manifests/scans, only the most recent
--     range survives (in packages.version); per-manifest ranges (AC-P05-4) are
--     lost. Re-running 003 up copies that single value back to every linked
--     scan_dependencies row, so the original per-manifest ranges are NOT
--     recovered.
--   * The pre-003 limitation returns: two different ranges of one package can
--     no longer coexist (UNIQUE purl), scans hitting that case roll back.
-- Must run after 004 down (db/migrate.sh down goes in reverse order).
-- =============================================================================

-- Plain temp table (not ON COMMIT DROP) so the file also works when replayed
-- inside a larger transaction (db/tests); it is dropped explicitly at the end.
CREATE TEMP TABLE _003_restore AS
SELECT p.id,
       p.ecosystem,
       p.name,
       COALESCE(
           (SELECT sd.declared_range
            FROM   scan_dependencies sd
            WHERE  sd.package_id = p.id
              AND  sd.declared_range IS NOT NULL
            ORDER  BY sd.created_at DESC, sd.id DESC
            LIMIT  1),
           'unknown') AS restored_version
FROM   packages p
WHERE  p.version IS NULL;

-- The restored pseudo-version must not collide with UNIQUE (ecosystem, name,
-- version) of an existing exact-version row.
DO $$
DECLARE
    collisions INTEGER;
BEGIN
    SELECT count(*) INTO collisions
    FROM   _003_restore r
    JOIN   packages q
      ON   q.ecosystem = r.ecosystem
     AND   q.name      = r.name
     AND   q.version   = r.restored_version;

    IF collisions > 0 THEN
        RAISE EXCEPTION '003_declared_range down: % versionless package(s) would collide with an existing (ecosystem, name, version) row; resolve manually', collisions;
    END IF;
END $$;

ALTER TABLE packages
    DROP CONSTRAINT IF EXISTS packages_unversioned_purl_chk;

DROP INDEX IF EXISTS idx_packages_unversioned_unique;

UPDATE packages p
SET    version = r.restored_version
FROM   _003_restore r
WHERE  p.id = r.id;

ALTER TABLE packages
    ALTER COLUMN version SET NOT NULL;

ALTER TABLE scan_dependencies
    DROP COLUMN IF EXISTS declared_range;

DROP TABLE _003_restore;
