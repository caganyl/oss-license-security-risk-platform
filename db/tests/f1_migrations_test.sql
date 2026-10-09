-- =============================================================================
-- F1 migration test — 002_local_auth, 003_declared_range, 004_finding_fingerprint
-- REQ-002 · AC-P05-5, AC-P08-5, AC-G-10 (migration side)
--
-- psql is NOT required (REQ-003 AC-P11-15, AC-G-2): `npm test` runs this file
-- through node-postgres against embedded PostgreSQL in
-- tests/integration/migrations.test.ts (tests/helpers/psqlScript.ts inlines
-- the \ir lines and drops \set/\echo). tests/unit/findingFingerprint.test.ts
-- reads the _expected_fp reference table below. The psql dialect is kept only
-- so the file stays readable as one script; keep the \ir / \set / \echo lines
-- limited to what psqlScript.ts supports.
--
-- Run ONLY against an EMPTY, throw-away test database (AC-G-5), never against
-- a real/production database. Optional manual run, if psql is available:
--
--   psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f db/tests/f1_migrations_test.sql
--
-- What it does, in ONE transaction that is ROLLED BACK at the end (the test
-- database is left empty):
--   1. 001 up, 002 up, seed legacy (pre-003) data incl. range "versions"
--   2. 003 up  -> assert version/declared_range fix and new constraints
--   3. 004 up  -> assert backfilled fingerprints against independently
--                 computed reference values (Node crypto, ADR-003 formula v1)
--   4. assert 002 constraints (single password, single active API key, ...)
--   5. 004 down, 003 down, 002 down -> assert pre-002 shape restored
--   6. 002 up, 003 up, 004 up again  -> assert the same fingerprints
-- Any failed assertion raises an exception and psql stops (ON_ERROR_STOP).
--
-- The reference fingerprint table below doubles as the SQL side of the
-- TS <-> SQL fingerprint equality test required by ADR-003 (c).
-- schema_migrations is not touched: files are replayed directly. 005 and the
-- migration tool itself are covered by the REQ-003 Vitest migration tests.
-- =============================================================================

\set ON_ERROR_STOP on

BEGIN;

-- ---------------------------------------------------------------------------
-- Test helpers (pg_temp: session-local, rolled back with the transaction)
-- ---------------------------------------------------------------------------
CREATE FUNCTION pg_temp.assert_true(cond BOOLEAN, msg TEXT) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF cond IS NOT TRUE THEN
        RAISE EXCEPTION 'ASSERT FAILED: %', msg;
    END IF;
END $$;

CREATE FUNCTION pg_temp.expect_error(stmt TEXT, expected_state TEXT) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE stmt;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = expected_state THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'ASSERT FAILED: expected SQLSTATE %, got % (%) for: %',
            expected_state, SQLSTATE, SQLERRM, stmt;
    END;
    RAISE EXCEPTION 'ASSERT FAILED: expected SQLSTATE %, statement succeeded: %',
        expected_state, stmt;
END $$;

CREATE FUNCTION pg_temp.column_exists(tbl TEXT, col TEXT) RETURNS BOOLEAN
LANGUAGE sql AS $$
    SELECT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = tbl AND column_name = col)
$$;

-- Reference fingerprints: sha256('v1|' || project || '|' || purl_scope || '|' || type || '|' || key)
-- computed outside PostgreSQL (Node crypto) from the ADR-003 (c) rules.
CREATE TEMP TABLE _expected_fp (label TEXT, finding_id UUID, fp TEXT, input TEXT);
INSERT INTO _expected_fp VALUES
 ('f1',  'd0000000-0000-4000-8000-000000000001', '42f0b22324a5a3bbed4c155b231cc35879e85bb0ee7d2afce4d602e7771bbf87', 'P1 | pkg:npm/lodash | license | mit'),
 ('f2',  'd0000000-0000-4000-8000-000000000002', '70c6c5ea9bbb1712c0d83a8bf4e17c6726fc8645f51a2fd9dba1bdd8e21bfb65', 'P1 | pkg:npm/lodash@4.17.21 | security | GHSA-ABCD-EFGH-IJKL (ghsa wins over cve)'),
 ('f3',  'd0000000-0000-4000-8000-000000000003', '064f7a075f16eea76664623b6d59ad3f4e191d6af226bc063393822312b23035', 'P1 | pkg:npm/@scope/pkg | license | noassertion (scoped npm, NULL license)'),
 ('f4',  'd0000000-0000-4000-8000-000000000004', '6556573739453144074cfe21668e1645d58791ed7733260a6479ead0bc30f536', 'P1 | pkg:npm/@scope/pkg | security | CVE-2021-0001 (legacy range -> NULL version -> versionless)'),
 ('f5',  'd0000000-0000-4000-8000-000000000005', '5e6520c3cada091b64f0910c1be7f920338550320781d87e4ba45f34e14994df', 'P1 | pkg:pypi/django-rest-framework | license | bsd-3-clause (PEP 503)'),
 ('f6',  'd0000000-0000-4000-8000-000000000006', 'cc8820ca8a71cd754c4aa948ae6bd1fbd4e8714e5606288b0b6bfd9a91f7bad6', 'P1 | pkg:pypi/requests@2.31.0 | security | <vuln uuid upper> (qualifier+subpath, no advisory id)'),
 ('f7',  'd0000000-0000-4000-8000-000000000007', '22440d55343aabcdf5f2ef0451433ea34bc6f0a73ecf3056e7b8a7349b155f08', 'P1 | pkg:npm/weird@1.0.0%7Cbeta | security | OSV-2024-0001 (pipe encoded, osv wins)'),
 ('f8',  'd0000000-0000-4000-8000-000000000008', '4fe3032f80067f438cee2b801861ea8a5bb48725fa43b09e8de79330021350eb', 'P1 | pkg:maven/org.group/art@1.0 | security | OSV-X-1 (version trimmed, base lowercased)'),
 ('f9',  'd0000000-0000-4000-8000-000000000009', '6aa94827fe5927864ba5510860e4affd976811839969cf1ec855fc9d49087df8', 'P2 | pkg:npm/lodash | license | mit (other project)'),
 ('f10', 'd0000000-0000-4000-8000-000000000010', '42f0b22324a5a3bbed4c155b231cc35879e85bb0ee7d2afce4d602e7771bbf87', 'same as f1 (P1, second scan)'),
 ('f11', 'd0000000-0000-4000-8000-000000000011', '46c891c1e48b05660ac6f58323db39fcc39e03e21eb7ec8bb08225ccb6f84dfc', 'P1 | pkg:pypi/foo-bar | license | gpl-3.0-only'),
 ('f12', 'd0000000-0000-4000-8000-000000000012', '064f7a075f16eea76664623b6d59ad3f4e191d6af226bc063393822312b23035', 'same as f3 (second manifest, legacy duplicate allowed)');

CREATE FUNCTION pg_temp.assert_fingerprints() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(e.label || ' got ' || COALESCE(f.fingerprint::text, '<NULL>'), '; ' ORDER BY e.label)
      INTO bad
    FROM   _expected_fp e
    LEFT   JOIN findings f ON f.id = e.finding_id
    WHERE  f.fingerprint::text IS DISTINCT FROM e.fp;

    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'ASSERT FAILED: fingerprint mismatch: %', bad;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. 001 + 002 up, legacy data
-- ---------------------------------------------------------------------------
\ir ../migrations/001_initial_core_schema.up.sql
\ir ../migrations/002_local_auth.up.sql

INSERT INTO users (id, email, display_name, status) VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', 'owner@example.invalid',  'Owner',  'active'),
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', 'second@example.invalid', 'Second', 'active');

INSERT INTO projects (id, name) VALUES
 ('11111111-1111-1111-1111-111111111111', 'P1'),
 ('22222222-2222-2222-2222-222222222222', 'P2');

INSERT INTO scans (id, project_id, trigger, status) VALUES
 ('51111111-1111-1111-1111-111111111111', '11111111-1111-1111-1111-111111111111', 'manual', 'completed'),
 ('51111111-1111-1111-1111-111111111112', '11111111-1111-1111-1111-111111111111', 'manual', 'completed'),
 ('52222222-2222-2222-2222-222222222222', '22222222-2222-2222-2222-222222222222', 'manual', 'completed');

-- Legacy shape: ranges / 'unknown' stored in version with a versionless purl.
INSERT INTO packages (id, ecosystem, name, version, purl) VALUES
 ('a0000000-0000-4000-8000-000000000001', 'nodejs', 'lodash',                '4.17.21',    'pkg:npm/lodash@4.17.21'),
 ('a0000000-0000-4000-8000-000000000002', 'nodejs', '@Scope/Pkg',            '^1.2.0',     'pkg:npm/@Scope/Pkg'),
 ('a0000000-0000-4000-8000-000000000003', 'python', 'Foo_Bar',               'unknown',    'pkg:pypi/foo-bar'),
 ('a0000000-0000-4000-8000-000000000004', 'python', 'Django.Rest_framework', '>=2,<3',     'pkg:pypi/django.rest-framework'),
 ('a0000000-0000-4000-8000-000000000005', 'python', 'requests',              '2.31.0',     'pkg:pypi/requests@2.31.0?repository_url=https://pypi.example/simple#src/sub'),
 ('a0000000-0000-4000-8000-000000000006', 'nodejs', 'weird',                 '1.0.0|beta', 'pkg:npm/weird@1.0.0%7Cbeta'),
 ('a0000000-0000-4000-8000-000000000007', 'java',   'Org.Group:Art',         ' 1.0 ',      'pkg:maven/Org.Group/Art@1.0');

INSERT INTO scan_dependencies (id, scan_id, package_id, scope, manifest_file, manifest_path) VALUES
 ('b0000000-0000-4000-8000-000000000001', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000001', 'direct', 'package.json',     'package.json'),
 ('b0000000-0000-4000-8000-000000000002', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000002', 'direct', 'package.json',     'a/package.json'),
 ('b0000000-0000-4000-8000-000000000012', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000002', 'direct', 'package.json',     'b/package.json'),
 ('b0000000-0000-4000-8000-000000000003', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000003', 'direct', 'requirements.txt', 'requirements.txt'),
 ('b0000000-0000-4000-8000-000000000004', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000004', 'direct', 'requirements.txt', 'requirements.txt'),
 ('b0000000-0000-4000-8000-000000000005', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000005', 'direct', 'requirements.txt', 'requirements.txt'),
 ('b0000000-0000-4000-8000-000000000006', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000006', 'direct', 'package.json',     'package.json'),
 ('b0000000-0000-4000-8000-000000000007', '51111111-1111-1111-1111-111111111111', 'a0000000-0000-4000-8000-000000000007', 'direct', 'pom.xml',          'pom.xml'),
 ('b0000000-0000-4000-8000-000000000008', '52222222-2222-2222-2222-222222222222', 'a0000000-0000-4000-8000-000000000001', 'direct', 'package.json',     'package.json'),
 ('b0000000-0000-4000-8000-000000000009', '51111111-1111-1111-1111-111111111112', 'a0000000-0000-4000-8000-000000000001', 'direct', 'package.json',     'package.json');

INSERT INTO vulnerabilities (id, osv_id, ghsa_id, cve_id, title) VALUES
 ('c0000000-0000-4000-8000-000000000001', NULL,            'ghsa-abcd-efgh-ijkl', 'CVE-2020-0001', 'v1'),
 ('c0000000-0000-4000-8000-000000000002', NULL,            NULL,                  'cve-2021-0001', 'v2'),
 ('abcdef00-0000-4000-8000-000000000003', NULL,            NULL,                  NULL,            'v3'),
 ('c0000000-0000-4000-8000-000000000004', 'OSV-2024-0001', 'GHSA-zzzz-zzzz-zzzz', NULL,            'v4'),
 ('c0000000-0000-4000-8000-000000000005', 'osv-x-1',       NULL,                  NULL,            'v5');

INSERT INTO findings (id, scan_id, scan_dependency_id, finding_type, status) VALUES
 ('d0000000-0000-4000-8000-000000000001', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000001', 'license',  'false_positive'),
 ('d0000000-0000-4000-8000-000000000002', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000001', 'security', 'accepted'),
 ('d0000000-0000-4000-8000-000000000003', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000002', 'license',  'open'),
 ('d0000000-0000-4000-8000-000000000004', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000002', 'security', 'open'),
 ('d0000000-0000-4000-8000-000000000005', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000004', 'license',  'open'),
 ('d0000000-0000-4000-8000-000000000006', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000005', 'security', 'wont_fix'),
 ('d0000000-0000-4000-8000-000000000007', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000006', 'security', 'open'),
 ('d0000000-0000-4000-8000-000000000008', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000007', 'security', 'open'),
 ('d0000000-0000-4000-8000-000000000009', '52222222-2222-2222-2222-222222222222', 'b0000000-0000-4000-8000-000000000008', 'license',  'open'),
 ('d0000000-0000-4000-8000-000000000010', '51111111-1111-1111-1111-111111111112', 'b0000000-0000-4000-8000-000000000009', 'license',  'open'),
 ('d0000000-0000-4000-8000-000000000011', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000003', 'license',  'open'),
 ('d0000000-0000-4000-8000-000000000012', '51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000012', 'license',  'open');

INSERT INTO license_findings (finding_id, normalized_license) VALUES
 ('d0000000-0000-4000-8000-000000000001', 'MIT'),
 ('d0000000-0000-4000-8000-000000000003', NULL),
 ('d0000000-0000-4000-8000-000000000005', 'BSD-3-Clause'),
 ('d0000000-0000-4000-8000-000000000009', 'MIT'),
 ('d0000000-0000-4000-8000-000000000010', 'MIT'),
 ('d0000000-0000-4000-8000-000000000011', 'GPL-3.0-only'),
 ('d0000000-0000-4000-8000-000000000012', NULL);

INSERT INTO security_findings (finding_id, vulnerability_id, severity) VALUES
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000001', 'high'),
 ('d0000000-0000-4000-8000-000000000004', 'c0000000-0000-4000-8000-000000000002', 'high'),
 ('d0000000-0000-4000-8000-000000000006', 'abcdef00-0000-4000-8000-000000000003', 'high'),
 ('d0000000-0000-4000-8000-000000000007', 'c0000000-0000-4000-8000-000000000004', 'high'),
 ('d0000000-0000-4000-8000-000000000008', 'c0000000-0000-4000-8000-000000000005', 'high');

CREATE TEMP TABLE _status_before AS SELECT id, status FROM findings;

-- ---------------------------------------------------------------------------
-- 2. 003 up
-- ---------------------------------------------------------------------------
\ir ../migrations/003_declared_range.up.sql

SELECT pg_temp.assert_true((SELECT version = '4.17.21'    FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000001'), '003: exact npm version kept');
SELECT pg_temp.assert_true((SELECT version IS NULL        FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000002'), '003: scoped npm range -> NULL');
SELECT pg_temp.assert_true((SELECT version IS NULL        FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000003'), '003: python unknown -> NULL');
SELECT pg_temp.assert_true((SELECT version IS NULL        FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000004'), '003: python range -> NULL');
SELECT pg_temp.assert_true((SELECT version = '2.31.0'     FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000005'), '003: qualifier purl keeps version');
SELECT pg_temp.assert_true((SELECT version = '1.0.0|beta' FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000006'), '003: encoded version kept');
SELECT pg_temp.assert_true((SELECT version = ' 1.0 '      FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000007'), '003: version text untouched');

SELECT pg_temp.assert_true((SELECT declared_range = '^1.2.0' FROM scan_dependencies WHERE id = 'b0000000-0000-4000-8000-000000000002'), '003: range copied (manifest a)');
SELECT pg_temp.assert_true((SELECT declared_range = '^1.2.0' FROM scan_dependencies WHERE id = 'b0000000-0000-4000-8000-000000000012'), '003: range copied (manifest b)');
SELECT pg_temp.assert_true((SELECT declared_range = '>=2,<3' FROM scan_dependencies WHERE id = 'b0000000-0000-4000-8000-000000000004'), '003: python range copied');
SELECT pg_temp.assert_true((SELECT declared_range IS NULL    FROM scan_dependencies WHERE id = 'b0000000-0000-4000-8000-000000000003'), '003: unknown is not a range');
SELECT pg_temp.assert_true((SELECT declared_range IS NULL    FROM scan_dependencies WHERE id = 'b0000000-0000-4000-8000-000000000001'), '003: exact version has no range');

-- second versionless row for the same (ecosystem, name)
SELECT pg_temp.expect_error($q$INSERT INTO packages (ecosystem, name, version, purl) VALUES ('nodejs', '@Scope/Pkg', NULL, 'pkg:npm/@scope/pkg-dup')$q$, '23505');
-- unknown version with a versioned purl (AC-P05-3)
SELECT pg_temp.expect_error($q$INSERT INTO packages (ecosystem, name, version, purl) VALUES ('nodejs', 'new-pkg', NULL, 'pkg:npm/new-pkg@1.0.0')$q$, '23514');

-- ---------------------------------------------------------------------------
-- 3. 004 up
-- ---------------------------------------------------------------------------
\ir ../migrations/004_finding_fingerprint.up.sql

SELECT pg_temp.assert_fingerprints();
SELECT pg_temp.assert_true(
    (SELECT is_nullable = 'NO' FROM information_schema.columns
     WHERE table_name = 'findings' AND column_name = 'fingerprint'), '004: fingerprint NOT NULL');
SELECT pg_temp.assert_true(
    NOT EXISTS (SELECT 1 FROM findings f JOIN _status_before b USING (id) WHERE f.status <> b.status),
    '004: backfill does not change status');
SELECT pg_temp.assert_true(
    to_regclass('public.idx_findings_fingerprint_created') IS NOT NULL, '004: fingerprint index exists');

SELECT pg_temp.expect_error($q$INSERT INTO findings (scan_id, scan_dependency_id, finding_type) VALUES ('51111111-1111-1111-1111-111111111111', 'b0000000-0000-4000-8000-000000000001', 'license')$q$, '23502');
SELECT pg_temp.expect_error($q$UPDATE findings SET carried_from_finding_id = id WHERE id = 'd0000000-0000-4000-8000-000000000001'$q$, '23514');
SELECT pg_temp.expect_error($q$UPDATE findings SET fingerprint = upper(fingerprint) WHERE id = 'd0000000-0000-4000-8000-000000000001'$q$, '23514');

-- carry link + ON DELETE SET NULL
UPDATE findings SET carried_from_finding_id = 'd0000000-0000-4000-8000-000000000001'
WHERE id = 'd0000000-0000-4000-8000-000000000010';
SELECT pg_temp.assert_true(
    (SELECT carried_from_finding_id = 'd0000000-0000-4000-8000-000000000001' FROM findings WHERE id = 'd0000000-0000-4000-8000-000000000010'),
    '004: carried_from_finding_id stored');

-- ---------------------------------------------------------------------------
-- 4. 002 constraints
-- ---------------------------------------------------------------------------
UPDATE users SET password_hash = 'scrypt$131072$8$1$c2FsdHNhbHRzYWx0c2FsdA==$aGFzaA==', password_changed_at = NOW()
WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
SELECT pg_temp.expect_error($q$UPDATE users SET password_hash = 'scrypt$131072$8$1$b3RoZXI=$b3RoZXI=' WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'$q$, '23505');
SELECT pg_temp.expect_error($q$UPDATE users SET password_hash = 'not-a-scrypt-hash' WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'$q$, '23514');

INSERT INTO sessions (user_id, token_hash, expires_at)
VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', repeat('b', 64), NOW() + INTERVAL '7 days');
SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', repeat('b', 64), NOW())$q$, '23505');
SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', 'plain-token', NOW())$q$, '23514');

INSERT INTO api_keys (id, user_id, key_hash, key_prefix)
VALUES ('e0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', repeat('a', 64), 'ossr_0123456789abcdef');
SELECT pg_temp.expect_error($q$INSERT INTO api_keys (user_id, key_hash, key_prefix) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', repeat('c', 64), 'ossr_fedcba9876543210')$q$, '23505');
SELECT pg_temp.expect_error($q$INSERT INTO api_keys (user_id, key_hash, key_prefix) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', repeat('d', 64), 'ossr_0123')$q$, '23514');
SELECT pg_temp.expect_error($q$INSERT INTO api_keys (user_id, key_hash, key_prefix) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', repeat('D', 64), 'ossr_0123456789abcdef')$q$, '23514');
-- rotation: revoke the active key, then a new active key is accepted (D-16)
UPDATE api_keys SET revoked_at = NOW() WHERE id = 'e0000000-0000-4000-8000-000000000001';
INSERT INTO api_keys (user_id, key_hash, key_prefix)
VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', repeat('c', 64), 'ossr_fedcba9876543210');
SELECT pg_temp.assert_true(
    (SELECT count(*) = 1 FROM api_keys WHERE user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1' AND revoked_at IS NULL),
    '002: exactly one active key after rotation');

-- documented password recovery step (db/README.md) behaves as specified
UPDATE users SET password_hash = NULL, password_changed_at = NULL, updated_at = NOW()
WHERE password_hash IS NOT NULL;
DELETE FROM sessions;
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM users WHERE password_hash IS NOT NULL), 'recovery: no password left');
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM sessions), 'recovery: no session left');
SELECT pg_temp.assert_true((SELECT count(*) = 2 FROM api_keys), 'recovery: api keys untouched');

-- ---------------------------------------------------------------------------
-- 5. Rollback chain: 004 down, 003 down, 002 down
-- ---------------------------------------------------------------------------
\ir ../migrations/004_finding_fingerprint.down.sql
\ir ../migrations/003_declared_range.down.sql
\ir ../migrations/002_local_auth.down.sql

SELECT pg_temp.assert_true(NOT pg_temp.column_exists('findings', 'fingerprint'),             'down: findings.fingerprint dropped');
SELECT pg_temp.assert_true(NOT pg_temp.column_exists('findings', 'carried_from_finding_id'), 'down: findings.carried_from_finding_id dropped');
SELECT pg_temp.assert_true(NOT pg_temp.column_exists('scan_dependencies', 'declared_range'), 'down: declared_range dropped');
SELECT pg_temp.assert_true(NOT pg_temp.column_exists('users', 'password_hash'),              'down: users.password_hash dropped');
SELECT pg_temp.assert_true(to_regclass('public.sessions') IS NULL, 'down: sessions dropped');
SELECT pg_temp.assert_true(to_regclass('public.api_keys') IS NULL, 'down: api_keys dropped');
SELECT pg_temp.assert_true(
    (SELECT is_nullable = 'NO' FROM information_schema.columns
     WHERE table_name = 'packages' AND column_name = 'version'), 'down: packages.version NOT NULL again');
SELECT pg_temp.assert_true((SELECT version = '^1.2.0'  FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000002'), 'down: range restored from declared_range');
SELECT pg_temp.assert_true((SELECT version = 'unknown' FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000003'), 'down: unknown sentinel restored');
SELECT pg_temp.assert_true((SELECT version = '>=2,<3'  FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000004'), 'down: python range restored');
SELECT pg_temp.assert_true((SELECT count(*) = 12 FROM findings), 'down: findings rows kept');

-- ---------------------------------------------------------------------------
-- 6. Re-apply: 002 up, 003 up, 004 up -> same result
-- ---------------------------------------------------------------------------
\ir ../migrations/002_local_auth.up.sql
\ir ../migrations/003_declared_range.up.sql
\ir ../migrations/004_finding_fingerprint.up.sql

SELECT pg_temp.assert_fingerprints();
SELECT pg_temp.assert_true((SELECT declared_range = '^1.2.0' FROM scan_dependencies WHERE id = 'b0000000-0000-4000-8000-000000000002'), 're-up: range copied again');
SELECT pg_temp.assert_true((SELECT version IS NULL FROM packages WHERE id = 'a0000000-0000-4000-8000-000000000002'), 're-up: version NULL again');

\echo 'F1 migration test: ALL ASSERTIONS PASSED (rolling back)'

ROLLBACK;
