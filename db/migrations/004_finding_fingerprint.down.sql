-- =============================================================================
-- 004_finding_fingerprint — rollback
-- PostgreSQL 15+
--
-- DATA LOSS:
--   * findings.fingerprint is dropped. It is derived data: re-running 004 up
--     recomputes the same values for rows whose package/scan/vulnerability
--     data did not change.
--   * findings.carried_from_finding_id is dropped: the link "this decision was
--     carried from finding X" is lost permanently (re-running 004 up does not
--     restore it). The carried finding_reviews rows and the carried
--     findings.status values themselves are NOT touched and remain; only the
--     provenance link disappears (the review notes still mention the source
--     finding id).
-- Rollback must be deployed together with reverting the REQ-002 worker
-- change; the worker would otherwise write to a missing column.
-- =============================================================================

DROP INDEX IF EXISTS idx_findings_carried_from;
DROP INDEX IF EXISTS idx_findings_fingerprint_created;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_carried_from_not_self_chk,
    DROP CONSTRAINT IF EXISTS findings_fingerprint_format_chk,
    DROP COLUMN IF EXISTS carried_from_finding_id,
    DROP COLUMN IF EXISTS fingerprint;
