-- =============================================================================
-- OSS License & Security Risk Platform — Initial Core Schema Rollback
-- PostgreSQL 15+
-- =============================================================================

DROP TABLE IF EXISTS system_settings CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS sbom_documents CASCADE;
DROP TABLE IF EXISTS finding_comments CASCADE;
DROP TABLE IF EXISTS finding_reviews CASCADE;
DROP TABLE IF EXISTS license_findings CASCADE;
DROP TABLE IF EXISTS security_findings CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS vulnerability_aliases CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS license_policies CASCADE;
DROP TABLE IF EXISTS licenses CASCADE;
DROP TABLE IF EXISTS scan_dependencies CASCADE;
DROP TABLE IF EXISTS packages CASCADE;
DROP TABLE IF EXISTS scan_files CASCADE;
DROP TABLE IF EXISTS scans CASCADE;
DROP TABLE IF EXISTS integrations CASCADE;
DROP TABLE IF EXISTS project_tech_stacks CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

DROP TYPE IF EXISTS audit_action CASCADE;
DROP TYPE IF EXISTS report_status CASCADE;
DROP TYPE IF EXISTS report_format CASCADE;
DROP TYPE IF EXISTS report_type CASCADE;
DROP TYPE IF EXISTS sbom_format CASCADE;
DROP TYPE IF EXISTS review_decision CASCADE;
DROP TYPE IF EXISTS finding_status CASCADE;
DROP TYPE IF EXISTS finding_type CASCADE;
DROP TYPE IF EXISTS vuln_severity CASCADE;
DROP TYPE IF EXISTS license_policy CASCADE;
DROP TYPE IF EXISTS license_risk_level CASCADE;
DROP TYPE IF EXISTS dependency_scope CASCADE;
DROP TYPE IF EXISTS scan_status CASCADE;
DROP TYPE IF EXISTS scan_trigger CASCADE;
DROP TYPE IF EXISTS integration_provider CASCADE;
DROP TYPE IF EXISTS tech_ecosystem CASCADE;
DROP TYPE IF EXISTS project_criticality CASCADE;
DROP TYPE IF EXISTS role_name CASCADE;
DROP TYPE IF EXISTS user_status CASCADE;

DROP EXTENSION IF EXISTS "pg_trgm";
DROP EXTENSION IF EXISTS "pgcrypto";
