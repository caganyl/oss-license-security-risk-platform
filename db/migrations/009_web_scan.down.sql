-- =============================================================================
-- 009_web_scan — rollback
-- PostgreSQL 15+
--
-- DATA LOSS:
--   * Every web scan (scans.scan_kind = 'web') is deleted (rows of tables
--     that reference scans with ON DELETE CASCADE go with it; a web scan has
--     none besides the two web tables). Its audit_logs rows are kept: they
--     carry the scan id as plain data, not as a foreign key.
--   * web_findings and web_scan_components are dropped.
--   * projects.web_url and projects.web_scan_mode are dropped: the web
--     addresses of the projects are lost permanently (re-running 009 up does
--     NOT restore them).
--   * scans.scan_kind, scans.target_url and scans.web_summary are dropped.
--   No dependency scan, scan_dependencies, package, finding or
--   vulnerabilities row is deleted.
--
-- Bulk data update: run only with explicit human approval. Roll back
-- together with reverting the REQ-008 runtime: the REQ-008 worker, API and
-- reports read and write these columns and tables.
-- Lock / downtime: DELETE takes row locks on scans; each ALTER TABLE takes a
-- brief ACCESS EXCLUSIVE lock (DROP COLUMN / DROP CONSTRAINT are
-- catalog-only). Stop the application first.
-- Order: dependent tables, web scan rows, then the columns.
-- =============================================================================

DROP TABLE web_scan_components;
DROP TABLE web_findings;

DELETE FROM scans WHERE scan_kind = 'web';

ALTER TABLE scans
    DROP CONSTRAINT scans_web_target_chk,
    DROP CONSTRAINT scans_scan_kind_chk,
    DROP COLUMN web_summary,
    DROP COLUMN target_url,
    DROP COLUMN scan_kind;

ALTER TABLE projects
    DROP CONSTRAINT projects_web_scan_mode_chk,
    DROP CONSTRAINT projects_web_url_len_chk,
    DROP COLUMN web_scan_mode,
    DROP COLUMN web_url;
