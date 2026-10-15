-- =============================================================================
-- 009_web_scan — web (URL) security scans
-- REQ-008 / P-25, P-26, P-27, P-28 · ADR-010 Karar 1, 2 · D-210, D-211, D-232
-- PostgreSQL 15+
--
-- 1. projects: web_url (optional address of the running application) and
--    web_scan_mode ('passive' | 'active'; 'active' lets the optional OWASP
--    ZAP step run an active scan, ADR-010 Karar 8).
-- 2. scans: scan_kind ('dependency' | 'web'), target_url (snapshot of the
--    project web_url when the web scan was queued) and web_summary (JSONB,
--    contract REQ-008 section 2.5). Every existing row becomes 'dependency'
--    with target_url NULL, which satisfies scans_web_target_chk.
-- 3. web_findings: findings of web scans. They are not tied to a scanned
--    dependency, so they do not go into findings (scan_dependency_id is NOT
--    NULL there, ADR-010 Karar 2). A JavaScript library vulnerability links
--    to the shared vulnerabilities catalogue.
-- 4. web_scan_components: JavaScript libraries detected on the page.
--
-- Value sets are identical to docs/contracts/REQ-008-web-scan.md 1.0.0
-- section 2. No enum is changed (finding_status is reused). 001…008 are
-- unchanged.
--
-- Data: no data migration. scans.scan_kind gets the constant default
-- 'dependency' (catalog-only on PostgreSQL 11+, no table rewrite).
--
-- Runs inside a single transaction (npm run db:migrate: one transaction per
-- file together with its schema_migrations row); no BEGIN/COMMIT here and no
-- CONCURRENTLY / non-transactional statement.
-- Lock / downtime: each ALTER TABLE takes ACCESS EXCLUSIVE on its table; the
-- added CHECKs are validated with one scan of projects and one of scans. The
-- two new tables are empty. Seconds even for large local databases. Stop the
-- application before migrating (the tool refuses while it runs).
--
-- DEPLOYMENT ORDER: apply before starting the REQ-008 runtime; `npm start`
-- refuses to start while this migration is pending. Code older than REQ-008
-- ignores the new columns and tables; it would however claim a queued web
-- scan as a dependency scan (target_url is not read) and fail it, so roll
-- back the runtime and this migration together.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Web address of a project (REQ-008 P-25)
-- ---------------------------------------------------------------------------
ALTER TABLE projects
    ADD COLUMN web_url       TEXT NULL,
    ADD COLUMN web_scan_mode TEXT NOT NULL DEFAULT 'passive',
    ADD CONSTRAINT projects_web_url_len_chk
        CHECK (web_url IS NULL OR char_length(web_url) BETWEEN 1 AND 2048),
    ADD CONSTRAINT projects_web_scan_mode_chk
        CHECK (web_scan_mode IN ('passive', 'active'));

COMMENT ON COLUMN projects.web_url IS
  'Address of the running application scanned by web scans (REQ-008 P-25). http/https, no user info, no fragment; its host must be in WEB_SCAN_ALLOWED_HOSTS. NULL = no web target.';
COMMENT ON COLUMN projects.web_scan_mode IS
  'passive (default) | active: active lets the optional OWASP ZAP step run an active scan (REQ-008 AC-P28-7, ADR-010 Karar 8). The built-in web checks are always passive.';

-- ---------------------------------------------------------------------------
-- 2. Scan kind and web target (ADR-010 Karar 1)
-- ---------------------------------------------------------------------------
ALTER TABLE scans
    ADD COLUMN scan_kind   TEXT  NOT NULL DEFAULT 'dependency',
    ADD COLUMN target_url  TEXT  NULL,
    ADD COLUMN web_summary JSONB NULL,
    ADD CONSTRAINT scans_scan_kind_chk
        CHECK (scan_kind IN ('dependency', 'web')),
    ADD CONSTRAINT scans_web_target_chk
        CHECK ((scan_kind = 'web') = (target_url IS NOT NULL)
               AND (target_url IS NULL OR char_length(target_url) BETWEEN 1 AND 2048));

COMMENT ON COLUMN scans.scan_kind IS
  'dependency (default: dependency files of repo_url) | web (running application at target_url), REQ-008 D-210.';
COMMENT ON COLUMN scans.target_url IS
  'Web scans only: projects.web_url at the time the scan was queued. NULL for dependency scans.';
COMMENT ON COLUMN scans.web_summary IS
  'Web scans only, set on completion: request count, engine states, TLS facts, counts, score and grade (contract REQ-008 section 2.5).';

-- ---------------------------------------------------------------------------
-- 3. Web findings (ADR-010 Karar 2; contract 2.3)
-- ---------------------------------------------------------------------------
CREATE TABLE web_findings (
    id                UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID           NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id        UUID           NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_id           TEXT           NOT NULL,
    source            TEXT           NOT NULL,
    category          TEXT           NOT NULL,
    severity          TEXT           NOT NULL,
    confidence        TEXT           NOT NULL DEFAULT 'high',
    title             TEXT           NOT NULL,
    description       TEXT           NOT NULL,
    recommendation    TEXT           NOT NULL,
    location          TEXT           NULL,
    evidence          TEXT           NULL,
    cwe_id            INTEGER        NULL,
    owasp             TEXT           NULL,
    vulnerability_id  UUID           NULL REFERENCES vulnerabilities(id),
    component_name    TEXT           NULL,
    component_version TEXT           NULL,
    fixed_version     TEXT           NULL,
    cvss_score        NUMERIC(4, 1)  NULL,
    fingerprint       CHAR(64)       NOT NULL,
    status            finding_status NOT NULL DEFAULT 'open',
    created_at        TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    CONSTRAINT web_findings_rule_id_chk
        CHECK (rule_id ~ '^(WEB-[A-Z]{3,4}-[0-9]{3}|ZAP-[0-9]{1,9})$'),
    CONSTRAINT web_findings_source_chk
        CHECK (source IN ('builtin', 'zap')),
    CONSTRAINT web_findings_category_chk
        CHECK (category IN ('transport', 'headers', 'disclosure', 'cookies', 'cors',
                            'exposure', 'content', 'components', 'zap')),
    CONSTRAINT web_findings_severity_chk
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT web_findings_confidence_chk
        CHECK (confidence IN ('low', 'medium', 'high')),
    CONSTRAINT web_findings_text_len_chk
        CHECK (char_length(title) BETWEEN 1 AND 300
               AND char_length(description) <= 4000
               AND char_length(recommendation) <= 4000
               AND (location IS NULL OR char_length(location) <= 2048)
               AND (evidence IS NULL OR char_length(evidence) <= 2000)),
    CONSTRAINT web_findings_component_len_chk
        CHECK ((component_name IS NULL OR char_length(component_name) <= 214)
               AND (component_version IS NULL OR char_length(component_version) <= 214)
               AND (fixed_version IS NULL OR char_length(fixed_version) <= 214)),
    CONSTRAINT web_findings_cwe_chk
        CHECK (cwe_id IS NULL OR cwe_id > 0),
    CONSTRAINT web_findings_owasp_chk
        CHECK (owasp IS NULL OR owasp ~ '^A(0[1-9]|10):2021$'),
    CONSTRAINT web_findings_cvss_chk
        CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    CONSTRAINT web_findings_fingerprint_format_chk
        CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT web_findings_scan_fingerprint_key UNIQUE (scan_id, fingerprint)
);

CREATE INDEX web_findings_project_fingerprint_idx ON web_findings (project_id, fingerprint);

COMMENT ON TABLE web_findings IS
  'Findings of web scans (REQ-008, ADR-010 Karar 2). fingerprint = sha256(''w1|project_id|rule_id|key''); status is always open until web finding decisions exist (D-232).';

-- ---------------------------------------------------------------------------
-- 4. JavaScript libraries detected by a web scan (contract 2.4)
-- ---------------------------------------------------------------------------
CREATE TABLE web_scan_components (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    npm_name    TEXT        NULL,
    version     TEXT        NOT NULL,
    detection   TEXT        NOT NULL,
    location    TEXT        NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT web_scan_components_detection_chk
        CHECK (detection IN ('url', 'banner', 'html')),
    CONSTRAINT web_scan_components_len_chk
        CHECK (char_length(name) BETWEEN 1 AND 100
               AND (npm_name IS NULL OR char_length(npm_name) BETWEEN 1 AND 214)
               AND char_length(version) BETWEEN 1 AND 64
               AND (location IS NULL OR char_length(location) <= 2048)),
    CONSTRAINT web_scan_components_scan_name_version_key UNIQUE (scan_id, name, version)
);
