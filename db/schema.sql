-- =============================================================================
-- OSS License & Security Risk Platform — Database Schema
-- PostgreSQL 15+
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- trigram indexes for full-text search

-- ---------------------------------------------------------------------------
-- ENUMS
-- ---------------------------------------------------------------------------

CREATE TYPE user_status AS ENUM ('active', 'inactive', 'pending');

CREATE TYPE role_name AS ENUM (
    'admin',
    'security_analyst',
    'legal_reviewer',
    'developer',
    'manager'
);

CREATE TYPE project_criticality AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TYPE tech_ecosystem AS ENUM (
    'nodejs', 'python', 'java', 'dotnet', 'go', 'php', 'ruby', 'container', 'other'
);

CREATE TYPE integration_provider AS ENUM (
    'github', 'gitlab', 'azure_devops', 'bitbucket', 'local'
);

CREATE TYPE scan_trigger AS ENUM (
    'manual', 'scheduled', 'pre_release', 'pull_request', 'file_upload'
);

CREATE TYPE scan_status AS ENUM (
    'pending', 'queued', 'running', 'completed', 'failed', 'cancelled', 'timeout'
);

CREATE TYPE dependency_scope AS ENUM (
    'direct', 'transitive', 'dev', 'peer', 'optional'
);

CREATE TYPE license_risk_level AS ENUM (
    'safe', 'low', 'medium', 'high', 'critical', 'unknown'
);

CREATE TYPE license_policy AS ENUM (
    'approved', 'restricted', 'prohibited', 'review_required'
);

CREATE TYPE vuln_severity AS ENUM ('none', 'low', 'medium', 'high', 'critical');

CREATE TYPE finding_type AS ENUM ('security', 'license', 'copyright');

CREATE TYPE finding_status AS ENUM (
    'open', 'in_review', 'resolved', 'accepted', 'false_positive', 'wont_fix'
);

CREATE TYPE review_decision AS ENUM (
    'remediate', 'upgrade_version', 'accept_risk', 'false_positive', 'wont_fix'
);

CREATE TYPE sbom_format AS ENUM (
    'spdx_json', 'spdx_tag_value', 'cyclonedx_json', 'cyclonedx_xml'
);

CREATE TYPE report_type AS ENUM (
    'executive_summary', 'project_report', 'license_inventory',
    'audit_evidence', 'vulnerability_report'
);

CREATE TYPE report_format AS ENUM ('pdf', 'excel', 'csv', 'json');

CREATE TYPE report_status AS ENUM ('pending', 'generating', 'ready', 'failed');

CREATE TYPE audit_action AS ENUM (
    'user_login', 'user_logout', 'user_created', 'user_updated', 'user_deleted',
    'project_created', 'project_updated', 'project_deleted',
    'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
    'finding_opened', 'finding_updated', 'finding_resolved',
    'review_submitted', 'comment_added',
    'policy_created', 'policy_updated', 'policy_deleted',
    'sbom_generated', 'report_generated',
    'integration_created', 'integration_updated', 'integration_deleted',
    'settings_updated'
);

-- =============================================================================
-- USERS & RBAC
-- =============================================================================

CREATE TABLE users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT        NOT NULL UNIQUE,
    display_name    TEXT        NOT NULL,
    avatar_url      TEXT,
    status          user_status NOT NULL DEFAULT 'pending',
    -- SSO / OAuth identity
    sso_provider    TEXT,                       -- 'saml', 'oidc', 'github', etc.
    sso_subject     TEXT,                       -- external identity subject claim
    mfa_enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,                -- soft delete
    UNIQUE (sso_provider, sso_subject)
);

CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        role_name   NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_roles (
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- =============================================================================
-- PROJECTS
-- =============================================================================

CREATE TABLE projects (
    id              UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT                 NOT NULL,
    description     TEXT,
    criticality     project_criticality  NOT NULL DEFAULT 'medium',
    owner_id        UUID                 REFERENCES users(id) ON DELETE SET NULL,
    tech_lead_id    UUID                 REFERENCES users(id) ON DELETE SET NULL,
    repo_url        TEXT,
    -- cron expression for scheduled scans; NULL = no schedule
    scan_schedule   TEXT,
    tags            TEXT[]               NOT NULL DEFAULT '{}',
    metadata        JSONB                NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE TABLE project_tech_stacks (
    project_id  UUID           NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ecosystem   tech_ecosystem NOT NULL,
    PRIMARY KEY (project_id, ecosystem)
);

-- =============================================================================
-- SOURCE INTEGRATIONS (SCM connections)
-- =============================================================================

CREATE TABLE integrations (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID                 NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider            integration_provider NOT NULL,
    name                TEXT                 NOT NULL,
    repo_url            TEXT,
    default_branch      TEXT                 NOT NULL DEFAULT 'main',
    -- Credentials are AES-256-GCM encrypted at the application layer and masked in the UI
    access_token_enc    BYTEA,
    webhook_secret_enc  BYTEA,
    is_active           BOOLEAN              NOT NULL DEFAULT TRUE,
    last_synced_at      TIMESTAMPTZ,
    created_by          UUID                 REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ          NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- SCANS
-- =============================================================================

CREATE TABLE scans (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id              UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    integration_id          UUID         REFERENCES integrations(id) ON DELETE SET NULL,
    trigger                 scan_trigger NOT NULL,
    status                  scan_status  NOT NULL DEFAULT 'pending',
    -- Source reference
    ref                     TEXT,        -- branch name, tag, or commit SHA
    ref_type                TEXT,        -- 'branch', 'tag', 'commit'
    pr_number               INTEGER,     -- populated when trigger = 'pull_request'
    -- Timing
    queued_at               TIMESTAMPTZ,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    timeout_at              TIMESTAMPTZ,
    -- Outcome summary — denormalized for fast dashboard queries
    total_dependencies      INTEGER      NOT NULL DEFAULT 0,
    total_vulnerabilities   INTEGER      NOT NULL DEFAULT 0,
    critical_vulns          INTEGER      NOT NULL DEFAULT 0,
    high_vulns              INTEGER      NOT NULL DEFAULT 0,
    medium_vulns            INTEGER      NOT NULL DEFAULT 0,
    low_vulns               INTEGER      NOT NULL DEFAULT 0,
    license_violations      INTEGER      NOT NULL DEFAULT 0,
    -- Error and retry state
    error_message           TEXT,
    retry_count             INTEGER      NOT NULL DEFAULT 0,
    -- Worker identity for queue-based processing
    worker_id               TEXT,
    initiated_by            UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_files (
    id          UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID           NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    filename    TEXT           NOT NULL,
    file_path   TEXT           NOT NULL,  -- relative path within repo or upload
    ecosystem   tech_ecosystem NOT NULL,
    file_hash   TEXT           NOT NULL,  -- SHA-256 of file contents
    size_bytes  INTEGER,
    created_at  TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PACKAGE CATALOG (canonical, deduplicated across all scans)
-- =============================================================================

CREATE TABLE packages (
    id              UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem       tech_ecosystem NOT NULL,
    name            TEXT           NOT NULL,
    version         TEXT           NOT NULL,
    -- Package URL per https://github.com/package-url/purl-spec
    -- e.g. pkg:npm/lodash@4.17.21 or pkg:pypi/requests@2.31.0
    purl            TEXT           NOT NULL UNIQUE,
    -- Enrichment from public registries
    description     TEXT,
    homepage_url    TEXT,
    repository_url  TEXT,
    author          TEXT,
    -- Copyright / notice text extracted from package metadata
    copyright_text  TEXT,
    notice_text     TEXT,
    -- Raw registry metadata cache
    metadata        JSONB          NOT NULL DEFAULT '{}',
    enriched_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    UNIQUE (ecosystem, name, version)
);

-- =============================================================================
-- SCAN DEPENDENCIES (a package instance detected within one scan)
-- =============================================================================

CREATE TABLE scan_dependencies (
    id              UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID               NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    package_id      UUID               NOT NULL REFERENCES packages(id),
    scope           dependency_scope   NOT NULL DEFAULT 'direct',
    manifest_file   TEXT               NOT NULL,  -- e.g. 'package.json', 'requirements.txt'
    manifest_path   TEXT               NOT NULL,  -- relative path to manifest within repo
    -- Position in dependency tree; NULL parent = root-level direct dependency
    parent_dep_id   UUID               REFERENCES scan_dependencies(id) ON DELETE SET NULL,
    depth           INTEGER            NOT NULL DEFAULT 0,  -- 0 = direct dependency
    created_at      TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    UNIQUE (scan_id, package_id, manifest_path, scope)
);

-- =============================================================================
-- LICENSES
-- =============================================================================

CREATE TABLE licenses (
    id              UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SPDX identifier per https://spdx.org/licenses/
    spdx_id         TEXT               UNIQUE,
    name            TEXT               NOT NULL,
    risk_level      license_risk_level NOT NULL DEFAULT 'unknown',
    -- e.g. 'permissive', 'weak_copyleft', 'strong_copyleft', 'proprietary'
    category        TEXT,
    is_osi_approved BOOLEAN            NOT NULL DEFAULT FALSE,
    is_fsf_libre    BOOLEAN            NOT NULL DEFAULT FALSE,
    -- Human-readable summary of obligations (attribution, notice, source disclosure, etc.)
    obligations     TEXT,
    reference_url   TEXT,
    created_at      TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ        NOT NULL DEFAULT NOW()
);

CREATE TABLE license_policies (
    id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id  UUID            NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    policy      license_policy  NOT NULL,
    -- NULL project_id = global organization policy; non-NULL = project-scoped override
    project_id  UUID            REFERENCES projects(id) ON DELETE CASCADE,
    reason      TEXT,
    created_by  UUID            REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    -- One effective policy per license per scope
    UNIQUE (license_id, project_id)
);

-- =============================================================================
-- VULNERABILITIES (CVE / GHSA / OSV catalog)
-- =============================================================================

CREATE TABLE vulnerabilities (
    id                  UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Advisory identifiers (at most one per type)
    cve_id              TEXT           UNIQUE,  -- e.g. CVE-2021-44228
    ghsa_id             TEXT           UNIQUE,  -- e.g. GHSA-jfh8-c2jp-hdp8
    osv_id              TEXT           UNIQUE,  -- Open Source Vulnerabilities id
    title               TEXT           NOT NULL,
    description         TEXT,
    severity            vuln_severity  NOT NULL DEFAULT 'medium',
    cvss_score          NUMERIC(4, 1),          -- 0.0 – 10.0
    cvss_vector         TEXT,                   -- CVSS vector string
    cvss_version        TEXT,                   -- '2.0', '3.0', '3.1', '4.0'
    -- Affected package info (denormalized from advisory for query performance)
    affected_ecosystem  tech_ecosystem,
    affected_package    TEXT,
    affected_versions   TEXT,                   -- semver range, e.g. '<4.17.21'
    fixed_version       TEXT,                   -- first non-vulnerable version
    -- Timeline
    published_at        TIMESTAMPTZ,
    last_modified_at    TIMESTAMPTZ,
    -- Raw advisory payload from upstream source
    advisory_data       JSONB          NOT NULL DEFAULT '{}',
    -- Data origin: 'nvd', 'osv', 'github', 'snyk'
    source              TEXT           NOT NULL DEFAULT 'nvd',
    source_url          TEXT,
    created_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- Aliases link alternate advisory IDs to a canonical vulnerability row
CREATE TABLE vulnerability_aliases (
    vulnerability_id    UUID    NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    alias_id            TEXT    NOT NULL,  -- e.g. alternate CVE-* or GHSA-* ids
    alias_type          TEXT    NOT NULL,  -- 'cve', 'ghsa', 'osv', 'snyk'
    PRIMARY KEY (vulnerability_id, alias_id)
);

-- =============================================================================
-- FINDINGS (unified base for security, license, and copyright findings)
-- =============================================================================

CREATE TABLE findings (
    id                  UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             UUID           NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scan_dependency_id  UUID           NOT NULL REFERENCES scan_dependencies(id) ON DELETE CASCADE,
    finding_type        finding_type   NOT NULL,
    status              finding_status NOT NULL DEFAULT 'open',
    assignee_id         UUID           REFERENCES users(id) ON DELETE SET NULL,
    deadline            DATE,
    -- Manual risk override applied by a reviewer
    risk_override       TEXT,
    -- Suppression (temporary or permanent muting of this finding)
    suppressed          BOOLEAN        NOT NULL DEFAULT FALSE,
    suppressed_by       UUID           REFERENCES users(id) ON DELETE SET NULL,
    suppressed_at       TIMESTAMPTZ,
    suppression_reason  TEXT,
    created_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- Security-specific finding detail (one row per security finding)
CREATE TABLE security_findings (
    finding_id      UUID          PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    vulnerability_id UUID         NOT NULL REFERENCES vulnerabilities(id),
    severity        vuln_severity NOT NULL,
    cvss_score      NUMERIC(4, 1),
    fix_version     TEXT,
    -- SLA deadline computed from severity + org policy at scan time
    sla_deadline    DATE,
    fix_available   BOOLEAN       NOT NULL DEFAULT FALSE,
    -- Reachability analysis result (NULL = not yet analyzed)
    is_reachable    BOOLEAN
);

-- License-specific finding detail (one row per license finding)
CREATE TABLE license_findings (
    finding_id          UUID               PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    license_id          UUID               REFERENCES licenses(id) ON DELETE SET NULL,
    -- Raw license expression as detected before normalization
    detected_license    TEXT,
    -- Normalized SPDX expression
    normalized_license  TEXT,
    risk_level          license_risk_level NOT NULL DEFAULT 'unknown',
    -- Policy in effect at the moment of detection
    applied_policy      license_policy,
    -- Copyright notices extracted from the package
    copyright_notices   TEXT[]
);

-- =============================================================================
-- REVIEW WORKFLOW
-- =============================================================================

-- Reviews are append-only history; rows are never updated or deleted
CREATE TABLE finding_reviews (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID            NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    decision        review_decision NOT NULL,
    reviewer_id     UUID            NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    -- For 'accept_risk': when the acceptance expires and finding re-opens
    accepted_until  DATE,
    -- For 'upgrade_version': the target version recommended
    target_version  TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE TABLE finding_comments (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID        NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author_id   UUID        NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    content     TEXT        NOT NULL,
    edited_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- SBOM DOCUMENTS
-- =============================================================================

CREATE TABLE sbom_documents (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format          sbom_format NOT NULL,
    -- Spec version: '2.3' for SPDX, '1.4'/'1.5' for CycloneDX
    spec_version    TEXT        NOT NULL,
    -- Object storage reference (S3 key, filesystem path, etc.)
    storage_key     TEXT        NOT NULL,
    file_size_bytes BIGINT,
    checksum_sha256 TEXT        NOT NULL,
    -- Document namespace or serial number per format spec
    document_id     TEXT,
    generated_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- REPORTS
-- =============================================================================

CREATE TABLE reports (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID          REFERENCES projects(id) ON DELETE SET NULL,
    report_type     report_type   NOT NULL,
    format          report_format NOT NULL,
    status          report_status NOT NULL DEFAULT 'pending',
    -- Filters and parameters used to generate the report (date range, severity, etc.)
    parameters      JSONB         NOT NULL DEFAULT '{}',
    -- Object storage reference populated once the report is ready
    storage_key     TEXT,
    file_size_bytes BIGINT,
    checksum_sha256 TEXT,
    error_message   TEXT,
    requested_by    UUID          NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    requested_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

-- =============================================================================
-- AUDIT LOG (append-only, immutable — no UPDATE or DELETE ever issued on this table)
-- =============================================================================

CREATE TABLE audit_logs (
    id          BIGSERIAL   PRIMARY KEY,
    action      audit_action NOT NULL,
    actor_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
    -- Denormalized email so the audit record survives user deletion
    actor_email TEXT,
    -- Polymorphic reference to the affected entity
    entity_type TEXT,       -- e.g. 'project', 'scan', 'finding', 'policy'
    entity_id   UUID,
    -- State snapshot before and after the action
    old_data    JSONB,
    new_data    JSONB,
    -- Request context
    ip_address  INET,
    user_agent  TEXT,
    request_id  TEXT,       -- distributed tracing / correlation ID
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- SYSTEM SETTINGS
-- =============================================================================

CREATE TABLE system_settings (
    key         TEXT        PRIMARY KEY,
    value       JSONB       NOT NULL,
    description TEXT,
    -- Marks secrets that must be masked in UI output and logs
    is_secret   BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- users
CREATE INDEX idx_users_email       ON users(email)  WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status      ON users(status) WHERE deleted_at IS NULL;

-- projects
CREATE INDEX idx_projects_owner       ON projects(owner_id)    WHERE deleted_at IS NULL;
CREATE INDEX idx_projects_criticality ON projects(criticality) WHERE deleted_at IS NULL;
CREATE INDEX idx_projects_name_trgm   ON projects USING gin(name gin_trgm_ops);

-- integrations
CREATE INDEX idx_integrations_project ON integrations(project_id);

-- scans
CREATE INDEX idx_scans_project_status  ON scans(project_id, status);
CREATE INDEX idx_scans_project_created ON scans(project_id, created_at DESC);
CREATE INDEX idx_scans_status_active   ON scans(status) WHERE status IN ('pending', 'queued', 'running');
CREATE INDEX idx_scans_worker          ON scans(worker_id) WHERE worker_id IS NOT NULL;

-- scan_files
CREATE INDEX idx_scan_files_scan ON scan_files(scan_id);

-- packages
CREATE INDEX idx_packages_purl           ON packages(purl);
CREATE INDEX idx_packages_ecosystem_name ON packages(ecosystem, name);
CREATE INDEX idx_packages_name_trgm      ON packages USING gin(name gin_trgm_ops);

-- scan_dependencies
CREATE INDEX idx_scan_deps_scan    ON scan_dependencies(scan_id);
CREATE INDEX idx_scan_deps_package ON scan_dependencies(package_id);
CREATE INDEX idx_scan_deps_parent  ON scan_dependencies(parent_dep_id) WHERE parent_dep_id IS NOT NULL;

-- vulnerabilities
CREATE INDEX idx_vulns_cve       ON vulnerabilities(cve_id)                        WHERE cve_id IS NOT NULL;
CREATE INDEX idx_vulns_severity  ON vulnerabilities(severity);
CREATE INDEX idx_vulns_package   ON vulnerabilities(affected_ecosystem, affected_package);
CREATE INDEX idx_vulns_published ON vulnerabilities(published_at DESC);

-- findings
CREATE INDEX idx_findings_scan        ON findings(scan_id);
CREATE INDEX idx_findings_dep         ON findings(scan_dependency_id);
CREATE INDEX idx_findings_type_status ON findings(finding_type, status);
CREATE INDEX idx_findings_assignee    ON findings(assignee_id)    WHERE assignee_id IS NOT NULL;
CREATE INDEX idx_findings_deadline    ON findings(deadline)       WHERE deadline IS NOT NULL AND status = 'open';

-- security_findings
CREATE INDEX idx_sec_findings_vuln    ON security_findings(vulnerability_id);
CREATE INDEX idx_sec_findings_sev     ON security_findings(severity);
CREATE INDEX idx_sec_findings_sla     ON security_findings(sla_deadline) WHERE sla_deadline IS NOT NULL;

-- license_findings
CREATE INDEX idx_lic_findings_license ON license_findings(license_id) WHERE license_id IS NOT NULL;
CREATE INDEX idx_lic_findings_risk    ON license_findings(risk_level);

-- license_policies
CREATE UNIQUE INDEX idx_license_policies_global_unique
    ON license_policies(license_id)
    WHERE project_id IS NULL;

-- finding_reviews
CREATE INDEX idx_reviews_finding  ON finding_reviews(finding_id);
CREATE INDEX idx_reviews_reviewer ON finding_reviews(reviewer_id);
CREATE INDEX idx_reviews_created  ON finding_reviews(created_at DESC);

-- finding_comments
CREATE INDEX idx_comments_finding ON finding_comments(finding_id);

-- sbom_documents
CREATE INDEX idx_sbom_scan ON sbom_documents(scan_id);

-- reports
CREATE INDEX idx_reports_project   ON reports(project_id)   WHERE project_id IS NOT NULL;
CREATE INDEX idx_reports_requester ON reports(requested_by);
CREATE INDEX idx_reports_status    ON reports(status)        WHERE status IN ('pending', 'generating');

-- audit_logs
CREATE INDEX idx_audit_actor    ON audit_logs(actor_id);
CREATE INDEX idx_audit_entity   ON audit_logs(entity_type, entity_id);
CREATE INDEX idx_audit_action   ON audit_logs(action);
CREATE INDEX idx_audit_occurred ON audit_logs(occurred_at DESC);

-- =============================================================================
-- SEED DATA: Built-in roles
-- =============================================================================

INSERT INTO roles (name, description) VALUES
    ('admin',            'Full platform administration and configuration access'),
    ('security_analyst', 'Manage and triage security vulnerability findings'),
    ('legal_reviewer',   'Review and approve license compliance findings'),
    ('developer',        'View scan results and findings for assigned projects'),
    ('manager',          'Access risk dashboards and generate reports');

-- =============================================================================
-- SEED DATA: SPDX license catalog with risk classification
-- =============================================================================

INSERT INTO licenses (spdx_id, name, risk_level, category, is_osi_approved, is_fsf_libre, obligations) VALUES
    -- Permissive (safe)
    ('MIT',              'MIT License',                                  'safe',     'permissive',       TRUE,  TRUE,  'Attribution required in copyright notices'),
    ('Apache-2.0',       'Apache License 2.0',                          'safe',     'permissive',       TRUE,  TRUE,  'Attribution, state changes, include NOTICE file if present'),
    ('BSD-2-Clause',     'BSD 2-Clause "Simplified" License',           'safe',     'permissive',       TRUE,  TRUE,  'Attribution required in source and binary distributions'),
    ('BSD-3-Clause',     'BSD 3-Clause "New" or "Revised" License',     'safe',     'permissive',       TRUE,  TRUE,  'Attribution required; no endorsement using project name'),
    ('ISC',              'ISC License',                                  'safe',     'permissive',       TRUE,  TRUE,  'Attribution required'),
    ('0BSD',             'BSD Zero Clause License',                      'safe',     'permissive',       TRUE,  FALSE, 'No obligations'),
    ('Unlicense',        'The Unlicense',                                'safe',     'public_domain',    FALSE, TRUE,  'No obligations; dedicated to public domain'),
    ('CC0-1.0',          'Creative Commons Zero v1.0 Universal',         'safe',     'public_domain',    FALSE, TRUE,  'No obligations; waives all copyright'),
    -- Weak copyleft (medium)
    ('LGPL-2.0-only',    'GNU Lesser General Public License v2.0',       'medium',   'weak_copyleft',    TRUE,  TRUE,  'Modifications to LGPL code must be shared; dynamic linking permitted'),
    ('LGPL-2.1-only',    'GNU Lesser General Public License v2.1',       'medium',   'weak_copyleft',    TRUE,  TRUE,  'Modifications to LGPL code must be shared; dynamic linking permitted'),
    ('LGPL-3.0-only',    'GNU Lesser General Public License v3.0',       'medium',   'weak_copyleft',    TRUE,  TRUE,  'Modifications to LGPL code must be shared; dynamic linking permitted'),
    ('MPL-2.0',          'Mozilla Public License 2.0',                   'medium',   'weak_copyleft',    TRUE,  TRUE,  'File-level copyleft; modifications to MPL-covered files must be disclosed'),
    ('EPL-2.0',          'Eclipse Public License 2.0',                   'medium',   'weak_copyleft',    TRUE,  TRUE,  'Module-level copyleft; source disclosure required for modifications'),
    ('CDDL-1.0',         'Common Development and Distribution License 1.0','medium', 'weak_copyleft',    TRUE,  FALSE, 'File-level copyleft; incompatible with GPL'),
    -- Strong copyleft (high)
    ('GPL-2.0-only',     'GNU General Public License v2.0',              'high',     'strong_copyleft',  TRUE,  TRUE,  'Derivative works must be licensed under GPL-2.0; source must be provided'),
    ('GPL-2.0-or-later', 'GNU General Public License v2.0 or later',     'high',     'strong_copyleft',  TRUE,  TRUE,  'Derivative works must be licensed under GPL-2.0+; source must be provided'),
    ('GPL-3.0-only',     'GNU General Public License v3.0',              'high',     'strong_copyleft',  TRUE,  TRUE,  'Derivative works must be licensed under GPL-3.0; source must be provided'),
    ('GPL-3.0-or-later', 'GNU General Public License v3.0 or later',     'high',     'strong_copyleft',  TRUE,  TRUE,  'Derivative works must be licensed under GPL-3.0+; source must be provided'),
    -- Network copyleft (critical)
    ('AGPL-3.0-only',    'GNU Affero General Public License v3.0',       'critical', 'network_copyleft', TRUE,  TRUE,  'Network use (SaaS) triggers copyleft; entire application source must be disclosed'),
    ('AGPL-3.0-or-later','GNU Affero General Public License v3.0 or later','critical','network_copyleft',TRUE, TRUE,  'Network use (SaaS) triggers copyleft; entire application source must be disclosed'),
    ('SSPL-1.0',         'Server Side Public License v1',                'critical', 'network_copyleft', FALSE, FALSE, 'Entire service stack (including infrastructure) must be open sourced'),
    -- Source-available / proprietary (high)
    ('BSL-1.1',          'Business Source License 1.1',                  'high',     'source_available', FALSE, FALSE, 'Not open source; production use restricted; converts to open source after specified date'),
    ('CC-BY-NC-4.0',     'Creative Commons Attribution Non-Commercial 4.0','high',   'non_commercial',   FALSE, FALSE, 'Non-commercial use only; commercial use prohibited')
ON CONFLICT (spdx_id) DO NOTHING;

-- =============================================================================
-- SEED DATA: Default system settings
-- =============================================================================

INSERT INTO system_settings (key, value, description) VALUES
    ('sla.critical_days',           '7',                '"Target remediation days for CRITICAL severity vulnerabilities"'),
    ('sla.high_days',               '30',               '"Target remediation days for HIGH severity vulnerabilities"'),
    ('sla.medium_days',             '90',               '"Target remediation days for MEDIUM severity vulnerabilities"'),
    ('sla.low_days',                '180',              '"Target remediation days for LOW severity vulnerabilities"'),
    ('scan.max_retries',            '3',                '"Maximum retry attempts for a failed scan job"'),
    ('scan.timeout_minutes',        '60',               '"Per-scan worker timeout in minutes"'),
    ('scan.sandbox_enabled',        'true',             '"Clone repositories inside an isolated sandbox; delete workspace after scan"'),
    ('sbom.default_format',         '"cyclonedx_json"', '"Default SBOM output format"'),
    ('report.async_threshold_rows', '10000',            '"Row count above which report generation runs asynchronously"')
ON CONFLICT (key) DO NOTHING;

-- =============================================================================
-- SEED DATA: Mock Admin User
-- =============================================================================

INSERT INTO users (id, email, display_name, status)
VALUES ('00000000-0000-0000-0000-000000000000', 'admin@company.com', 'Admin User', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT '00000000-0000-0000-0000-000000000000', id FROM roles WHERE name = 'admin'
ON CONFLICT DO NOTHING;
