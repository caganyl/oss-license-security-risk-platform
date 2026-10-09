-- =============================================================================
-- 004_finding_fingerprint — deterministic finding fingerprint + decision carry
-- REQ-002 / P-08 (AC-P08-1, AC-P08-2, AC-P08-5) · ADR-003 (c) · D-1
-- PostgreSQL 15+ (sha256(bytea) is built in since 11; no extension needed)
--
-- Must run after 003_declared_range: packages.version is already cleaned of
-- range values, so legacy "range-versioned" security findings get a
-- versionless purl scope and will not match new (versioned) fingerprints —
-- their decisions are not carried (accepted, safe direction; ADR-003).
--
-- Runs inside a single transaction (db/migrate.sh --single-transaction).
-- Lock / downtime: ACCESS EXCLUSIVE on findings for the whole migration; the
-- backfill rewrites every findings row, SET NOT NULL and the CHECK scan the
-- table once more. Stop the API and worker before migrating.
--
-- DEPLOYMENT ORDER: after this migration findings.fingerprint is NOT NULL.
-- A worker that inserts findings without a fingerprint (pre-REQ-002 code)
-- fails every scan with a NOT NULL violation. Apply together with the
-- REQ-002 worker change, never ahead of it.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Columns (nullable first, so existing rows can be backfilled)
-- ---------------------------------------------------------------------------
ALTER TABLE findings
    ADD COLUMN fingerprint             CHAR(64),
    ADD COLUMN carried_from_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- 2. Backfill — ADR-003 (c) formula, v1
--
--   fingerprint = lower_hex(sha256(UTF-8(
--       'v1|' || project_id || '|' || purl_scope || '|' || finding_type || '|' || key)))
--
--   project_id  scans.project_id as lowercase UUID text
--   purl_base   packages.purl without qualifiers (?...) and subpath (#...),
--               without the trailing '@version' (only an '@' after the last
--               '/', so scoped npm names survive), lowercased; for pkg:pypi the
--               name is PEP 503-normalised ([-_.]+ -> '-').
--   version     packages.version with leading/trailing ASCII whitespace
--               (space, \t, \n, \v, \f, \r) removed, case preserved; '' = NULL.
--   purl_scope  license : purl_base                               (versionless)
--               security: purl_base || '@' || version             (versioned)
--                         purl_base when version is NULL          (legacy only)
--               then every '|' is encoded as '%7C'.
--   key         license : lower(COALESCE(normalized_license, 'NOASSERTION'))
--               security: upper(COALESCE(osv_id, ghsa_id, cve_id, vulnerabilities.id::text))
--   copyright   not produced in F1 -> no fingerprint -> migration aborts.
--
-- The worker (TypeScript) must implement byte-identical rules; an equality
-- test over shared fixtures is required (see db/tests/f1_migrations_test.sql
-- for SQL-side reference values).
-- The backfill never changes findings.status.
-- ---------------------------------------------------------------------------
WITH src AS (
    SELECT f.id,
           f.finding_type,
           lower(s.project_id::text) AS project_id,
           lower(regexp_replace(
                     split_part(split_part(p.purl, '#', 1), '?', 1),
                     '@[^/]*$', '')) AS base_raw,
           NULLIF(btrim(p.version, ' ' || chr(9) || chr(10) || chr(11) || chr(12) || chr(13)), '')
                                     AS version,
           lf.normalized_license,
           upper(COALESCE(v.osv_id, v.ghsa_id, v.cve_id, v.id::text)) AS vuln_key
    FROM   findings f
    JOIN   scans s                    ON s.id  = f.scan_id
    JOIN   scan_dependencies sd       ON sd.id = f.scan_dependency_id
    JOIN   packages p                 ON p.id  = sd.package_id
    LEFT   JOIN license_findings  lf  ON lf.finding_id = f.id
    LEFT   JOIN security_findings sf  ON sf.finding_id = f.id
    LEFT   JOIN vulnerabilities   v   ON v.id = sf.vulnerability_id
), norm AS (
    SELECT id,
           finding_type,
           project_id,
           version,
           normalized_license,
           vuln_key,
           CASE WHEN base_raw LIKE 'pkg:pypi/%'
                THEN 'pkg:pypi/' || regexp_replace(substr(base_raw, 10), '[-_.]+', '-', 'g')
                ELSE base_raw
           END AS purl_base
    FROM   src
)
UPDATE findings f
SET    fingerprint = encode(sha256(convert_to(
           'v1|' || n.project_id || '|' ||
           replace(CASE WHEN n.finding_type = 'security' AND n.version IS NOT NULL
                        THEN n.purl_base || '@' || n.version   -- security: versioned
                        ELSE n.purl_base                       -- license (and legacy NULL version)
                   END,
                   '|', '%7C') || '|' ||
           n.finding_type::text || '|' ||
           CASE n.finding_type
               WHEN 'license'  THEN lower(COALESCE(n.normalized_license, 'NOASSERTION'))
               WHEN 'security' THEN n.vuln_key
           END,                                                -- copyright -> NULL
           'UTF8')), 'hex')
FROM   norm n
WHERE  f.id = n.id;

-- ---------------------------------------------------------------------------
-- 3. Fail loudly if any row could not be fingerprinted (copyright findings,
--    security findings without a security_findings detail row, ...). Never
--    leave NULLs behind silently.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    missing INTEGER;
    detail  TEXT;
BEGIN
    SELECT count(*),
           string_agg(DISTINCT finding_type::text, ', ')
      INTO missing, detail
    FROM   findings
    WHERE  fingerprint IS NULL;

    IF missing > 0 THEN
        RAISE EXCEPTION '004_finding_fingerprint: backfill incomplete, % finding(s) without fingerprint (finding_type: %)', missing, detail;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Constraints and indexes
-- ---------------------------------------------------------------------------
ALTER TABLE findings
    ALTER COLUMN fingerprint SET NOT NULL;

ALTER TABLE findings
    ADD CONSTRAINT findings_fingerprint_format_chk
        CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT findings_carried_from_not_self_chk
        CHECK (carried_from_finding_id IS NULL OR carried_from_finding_id <> id);

-- Carry-over lookup: latest finding with the same fingerprint (the query also
-- joins scans and filters on project_id defensively; the project is already
-- part of the hash, so this index is selective on its own).
-- No UNIQUE (scan_id, fingerprint) in F1: legacy data contains duplicates.
CREATE INDEX idx_findings_fingerprint_created
    ON findings(fingerprint, created_at DESC);

-- Supports ON DELETE SET NULL when findings are removed (scan cascade).
CREATE INDEX idx_findings_carried_from
    ON findings(carried_from_finding_id)
    WHERE carried_from_finding_id IS NOT NULL;
