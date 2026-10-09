-- =============================================================================
-- 005_scan_next_attempt — retry backoff time for queued scans
-- REQ-003 / P-13 (AC-P11-16, AC-P13-2, AC-P13-7) · ADR-004 Karar 8, 11 · D-40
-- PostgreSQL 15+
--
-- Adds scans.next_attempt_at: the earliest time (database clock, NOW()) a
-- queued scan may be claimed again after a transient failure. NULL means
-- "claimable immediately" (new scans, shutdown hand-backs, failed/completed
-- scans).
--
-- Data: no data migration. Existing rows get NULL, i.e. stay claimable
-- immediately, which is today's behaviour.
-- No index (the partial index idx_scans_status_active already narrows the
-- claim query; next_attempt_at is a row filter) and no CHECK constraint
-- (ADR-004 Karar 11).
--
-- Runs inside a single transaction (npm run db:migrate: one transaction per
-- file together with its schema_migrations row); no BEGIN/COMMIT here.
-- Lock / downtime: ALTER TABLE ... ADD COLUMN with no default is a catalog-only
-- change (no table rewrite) but takes a brief ACCESS EXCLUSIVE lock on scans.
-- Stop the application before migrating (the tool refuses while it runs).
--
-- DEPLOYMENT ORDER: apply before starting the REQ-003 runtime; the REQ-003
-- worker reads and writes this column and `npm start` refuses to start while
-- this migration is pending. Code older than REQ-003 ignores the column.
-- =============================================================================

ALTER TABLE scans ADD COLUMN next_attempt_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN scans.next_attempt_at IS
  'Earliest time a queued scan may be claimed again (retry backoff, REQ-003 P-13). NULL = immediately.';
