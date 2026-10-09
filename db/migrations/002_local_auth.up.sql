-- =============================================================================
-- 002_local_auth — local password, DB-backed sessions, API keys
-- REQ-002 / P-01 · ADR-001 (decisions 1, 2, 3, 6, 7) · D-6, D-16
-- PostgreSQL 15+
--
-- Runs inside a single transaction (db/migrate.sh uses --single-transaction);
-- this file therefore contains no BEGIN/COMMIT.
--
-- Lock / downtime: ADD COLUMN without default is metadata-only, but takes a
-- short ACCESS EXCLUSIVE lock on users. New tables are empty. Stop the API and
-- worker before migrating (see db/README.md).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Precondition: the 'admin' role seeded by 001 must exist. Setup (ADR-001
-- decision 2) grants it to the local user; fail loudly instead of re-seeding.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM roles WHERE name = 'admin') THEN
        RAISE EXCEPTION '002_local_auth: roles row ''admin'' is missing (expected from 001 seed)';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- users: local password (scrypt, ADR-001 decision 1)
-- Stored format: scrypt$<N>$<r>$<p>$<salt_b64>$<hash_b64>. NULL = no password
-- set yet (setup open) or reset by the recovery SQL step (db/README.md).
-- ---------------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN password_hash       TEXT,
    ADD COLUMN password_changed_at TIMESTAMPTZ;

-- Guard against accidentally persisting a plaintext password (AC-P01-5): only
-- the self-describing scrypt format is accepted.
ALTER TABLE users
    ADD CONSTRAINT users_password_hash_format_chk
    CHECK (password_hash IS NULL OR password_hash ~ '^scrypt\$');

-- At most one user may hold a password (single local user). Also serialises
-- two concurrent setup requests at the DB level: the second one fails with a
-- unique violation and the API answers 409 (ADR-001 decision 2).
CREATE UNIQUE INDEX idx_users_single_password
    ON users ((TRUE))
    WHERE password_hash IS NOT NULL;

-- ---------------------------------------------------------------------------
-- sessions: server-side browser sessions (ADR-001 decision 3)
-- The cookie carries 32 random bytes; only their SHA-256 hex digest is stored,
-- so reading this table is not enough to hijack a session.
-- Validity is evaluated by the API (DB clock = now()):
--   expires_at   > now()                       -- absolute limit, created_at + 7 days
--   last_seen_at > now() - interval '12 hours' -- idle limit
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    TEXT        NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    CONSTRAINT sessions_token_hash_format_chk CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

-- Expired-session cleanup on login (DELETE ... WHERE expires_at <= now()).
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
-- FK cascade and per-user cleanup.
CREATE INDEX idx_sessions_user    ON sessions(user_id);

-- ---------------------------------------------------------------------------
-- api_keys: CLI/CI bearer keys (ADR-001 decisions 6 and 7)
-- Key format: ossr_<16 lowercase hex>_<43 base64url>. Never stored in plain
-- text: key_hash = SHA-256 hex of the full key text; key_prefix = 'ossr_<P>'
-- (21 chars), display/log correlation only, never used for lookup.
-- Revocation sets revoked_at; rows are not deleted (audit trail).
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT,
    key_hash      TEXT        NOT NULL UNIQUE,
    key_prefix    TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    CONSTRAINT api_keys_key_hash_format_chk   CHECK (key_hash   ~ '^[0-9a-f]{64}$'),
    CONSTRAINT api_keys_key_prefix_format_chk CHECK (key_prefix ~ '^ossr_[0-9a-f]{16}$')
);

-- Single active key per user (D-16 / AC-P01-15). Issuing a new key revokes the
-- previous one in the same transaction; this index is the DB-level backstop.
CREATE UNIQUE INDEX idx_api_keys_one_active_per_user
    ON api_keys(user_id)
    WHERE revoked_at IS NULL;

-- Key listing (active + revoked) and FK cascade.
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
