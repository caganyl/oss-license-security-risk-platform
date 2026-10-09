-- =============================================================================
-- 002_local_auth — rollback
-- PostgreSQL 15+
--
-- DATA LOSS (irreversible, re-running the up migration does NOT restore it):
--   * users.password_hash / password_changed_at are dropped: the local password
--     is lost; after re-applying 002 the first-run setup flow opens again.
--   * All rows of sessions are dropped: every browser session is logged out.
--   * All rows of api_keys are dropped (active and revoked, including the
--     revocation audit trail): every CLI/CI key stops working and must be
--     re-issued after re-applying 002.
-- No other table is touched; users, user_roles and every reference to users
-- (findings, reviews, projects ...) stay intact.
-- =============================================================================

DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS sessions;

DROP INDEX IF EXISTS idx_users_single_password;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_password_hash_format_chk,
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS password_hash;
