-- =============================================================================
-- 005_scan_next_attempt — rollback
-- PostgreSQL 15+
--
-- DATA LOSS:
--   * Only the retry scheduling of queued scans (scans.next_attempt_at) is
--     lost. Queued scans that were waiting for a retry become claimable
--     immediately after this rollback. No other column or row is touched.
--
-- Roll back together with reverting the REQ-003 runtime: the REQ-003 worker
-- reads and writes this column and would fail on every claim without it.
-- Lock / downtime: DROP COLUMN is a catalog-only change but takes a brief
-- ACCESS EXCLUSIVE lock on scans. Stop the application first.
-- =============================================================================

ALTER TABLE scans DROP COLUMN next_attempt_at;
