import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { HttpError } from '../lib/httpError';
import { resolveScanSource } from '../lib/scanSource';
import { type HostAllowlist, normalizeWebUrl, parseAllowedHosts } from '../webscan/allowlist';

/**
 * `scans` columns returned by POST /api/scans and GET /api/scans/{id}: the F1
 * row (`*` at the time) minus the queue-internal `timeout_at` and
 * `next_attempt_at` (REQ-003 D-43, AC-G-8). An explicit list so a new column
 * never leaks into the API by accident.
 */
const SCAN_RESPONSE_COLUMNS = [
  'id', 'project_id', 'integration_id', 'trigger', 'status', 'ref', 'ref_type', 'pr_number',
  'queued_at', 'started_at', 'completed_at',
  'total_dependencies', 'total_vulnerabilities', 'critical_vulns', 'high_vulns', 'medium_vulns', 'low_vulns',
  'license_violations', 'error_message', 'retry_count', 'worker_id', 'initiated_by', 'created_at', 'updated_at',
  // REQ-008 contract 3.5 (additive).
  'scan_kind', 'target_url', 'web_summary',
] as const;
const SCAN_RETURNING = SCAN_RESPONSE_COLUMNS.join(', ');
const SCAN_SELECT = SCAN_RESPONSE_COLUMNS.map((c) => `s.${c}`).join(', ');

export class ScanController {
  /**
   * @param scanRoots Allowed local scan roots (SCAN_ROOTS, P-04); empty = no local paths.
   * @param webAllowlist Web scan hosts (REQ-008 P-25); empty = web scans refused.
   */
  constructor(
    private readonly db: Pool,
    private readonly scanRoots: readonly string[] = [],
    private readonly webAllowlist: HostAllowlist = parseAllowedHosts(''),
  ) {}

  listScans = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const projectId = req.query.projectId;
      let query = `
        SELECT s.id, s.project_id, s.trigger, s.status, s.ref, s.ref_type, s.queued_at, s.started_at,
               s.completed_at, s.total_dependencies, s.total_vulnerabilities, s.critical_vulns,
               s.high_vulns, s.medium_vulns, s.low_vulns, s.license_violations, s.error_message, s.retry_count,
               s.scan_kind, s.target_url, s.web_summary,
               p.name AS project_name
        FROM scans s
        JOIN projects p ON p.id = s.project_id
      `;
      const values: unknown[] = [];
      if (projectId && typeof projectId === 'string') {
        query += ` WHERE s.project_id = $1`;
        values.push(projectId);
      }
      query += ` ORDER BY s.created_at DESC LIMIT 50`;

      const result = await this.db.query(query, values);
      res.json({ data: result.rows });
    } catch (err) {
      next(err);
    }
  };

  createScan = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Initiator is always the authenticated user; there is no fallback identity (AC-P01-17).
      const user = req.user;
      if (!user) {
        throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
      }
      const { projectId, ref, refType, trigger, kind } = req.body;
      if (!projectId || typeof projectId !== 'string') {
        throw Object.assign(new Error('projectId is required'), { statusCode: 400 });
      }
      // REQ-008 AC-P25-6: absent = dependency (unchanged behaviour).
      if (kind !== undefined && kind !== 'dependency' && kind !== 'web') {
        throw new HttpError(400, 'kind must be dependency or web');
      }
      if (kind === 'web') {
        await this.createWebScan(req, res, projectId, trigger);
        return;
      }

      // Verify project exists; its active integration for exactly this repo URL
      // carries the repo access token (REQ-009 AC-P29-8, AC-P29-10).
      const projCheck = await this.db.query<{ id: string; repo_url: string | null; integration_id: string | null }>(
        `SELECT p.id, p.repo_url,
                (SELECT i.id FROM integrations i
                  WHERE i.project_id = p.id AND i.is_active AND i.access_token_enc IS NOT NULL AND i.repo_url = p.repo_url
                  ORDER BY i.created_at ASC LIMIT 1) AS integration_id
         FROM projects p WHERE p.id = $1`,
        [projectId],
      );
      if (projCheck.rows.length === 0) {
        throw Object.assign(new Error('Project not found'), { statusCode: 404 });
      }

      // P-03 (AC-P03-11, K12) and P-04 (AC-P04-5): re-check the effective
      // source before queueing; a rejection is a 400 and no scans row is
      // created. A linked integration has the same repo_url, so the project's
      // repo_url is the effective one. A missing source would otherwise only
      // fail later in the worker, so it is rejected up front.
      const repoUrl = projCheck.rows[0].repo_url;
      if (repoUrl === null || repoUrl === '') {
        throw new HttpError(400, 'Project has no repository URL or local path', 'project_source_missing');
      }
      await resolveScanSource(repoUrl, this.scanRoots);

      // REQ-009 D-255: no ref = NULL, the worker clones the remote's default
      // branch instead of assuming 'main'.
      const result = await this.db.query(`
        INSERT INTO scans (project_id, trigger, status, ref, ref_type, queued_at, initiated_by, integration_id)
        VALUES ($1, COALESCE($2, 'manual')::scan_trigger, 'pending', $3, COALESCE($4, 'branch'), NOW(), $5, $6)
        RETURNING ${SCAN_RETURNING}
      `, [
        projectId,
        trigger || 'manual',
        typeof ref === 'string' && ref !== '' ? ref : null,
        refType || 'branch',
        user.id,
        projCheck.rows[0].integration_id,
      ]);

      // Write audit
      await this.db.query(
        `INSERT INTO audit_logs (action, actor_id, actor_email, entity_type, entity_id, new_data, occurred_at)
         VALUES ('scan_started', $1, $2, 'scan', $3, $4, NOW())`,
        [user.id, user.email, result.rows[0].id, JSON.stringify(result.rows[0])]
      ).catch(err => console.error('Failed to write audit log:', err));

      res.status(201).json({ data: result.rows[0] });
    } catch (err) {
      next(err);
    }
  };

  /** `POST /api/scans` with `kind: "web"` (REQ-008 AC-P25-6, contract 3.4). */
  private async createWebScan(req: Request, res: Response, projectId: string, trigger: unknown): Promise<void> {
    const user = req.user!;
    const project = await this.db.query<{ id: string; web_url: string | null }>(
      'SELECT id, web_url FROM projects WHERE id = $1 AND deleted_at IS NULL',
      [projectId],
    );
    if (project.rows.length === 0) throw new HttpError(404, 'Project not found');
    const webUrl = project.rows[0].web_url;
    if (webUrl === null || webUrl === '') throw new HttpError(400, 'Project has no web URL', 'project_web_url_missing');
    // The allowlist may have changed since the URL was stored.
    const target = normalizeWebUrl(webUrl, this.webAllowlist);
    const result = await this.db.query(
      `INSERT INTO scans (project_id, trigger, status, ref, ref_type, queued_at, initiated_by, scan_kind, target_url)
       VALUES ($1, COALESCE($2, 'manual')::scan_trigger, 'pending', NULL, NULL, NOW(), $3, 'web', $4)
       RETURNING ${SCAN_RETURNING}`,
      [projectId, typeof trigger === 'string' && trigger !== '' ? trigger : 'manual', user.id, target],
    );
    await this.db.query(
      `INSERT INTO audit_logs (action, actor_id, actor_email, entity_type, entity_id, new_data, occurred_at)
       VALUES ('scan_started', $1, $2, 'scan', $3, $4, NOW())`,
      [user.id, user.email, result.rows[0].id, JSON.stringify(result.rows[0])],
    ).catch((err) => console.error('Failed to write audit log:', err));
    res.status(201).json({ data: result.rows[0] });
  }

  getScan = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;
      const result = await this.db.query(`
        SELECT ${SCAN_SELECT}, p.name AS project_name
        FROM scans s
        JOIN projects p ON p.id = s.project_id
        WHERE s.id = $1
      `, [id]);
      if (result.rows.length === 0) {
        throw Object.assign(new Error('Scan not found'), { statusCode: 404 });
      }
      res.json({ data: result.rows[0] });
    } catch (err) {
      next(err);
    }
  };

  getScanFindings = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;
      const findingsResult = await this.db.query(`
        SELECT f.id, f.finding_type, f.status, f.deadline,
               -- Security info
               sf.severity, sf.cvss_score, sf.fix_version, sf.fix_available,
               v.title AS vuln_title, v.description AS vuln_description, v.cve_id, v.ghsa_id,
               -- License info
               lf.detected_license, lf.normalized_license, lf.risk_level, lf.applied_policy,
               -- Package info
               pkg.name AS package_name, pkg.version AS package_version, pkg.purl
        FROM findings f
        JOIN scan_dependencies sd ON sd.id = f.scan_dependency_id
        JOIN packages pkg ON pkg.id = sd.package_id
        LEFT JOIN security_findings sf ON sf.finding_id = f.id
        LEFT JOIN vulnerabilities v ON v.id = sf.vulnerability_id
        LEFT JOIN license_findings lf ON lf.finding_id = f.id
        WHERE f.scan_id = $1
        ORDER BY sf.cvss_score DESC NULLS LAST, lf.risk_level DESC NULLS LAST
      `, [id]);
      res.json({ data: findingsResult.rows });
    } catch (err) {
      next(err);
    }
  };
}
