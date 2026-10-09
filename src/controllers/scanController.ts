import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { resolveScanSource } from '../lib/scanSource';

export class ScanController {
  /** @param scanRoots Allowed local scan roots (SCAN_ROOTS, P-04); empty = no local paths. */
  constructor(
    private readonly db: Pool,
    private readonly scanRoots: readonly string[] = [],
  ) {}

  listScans = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const projectId = req.query.projectId;
      let query = `
        SELECT s.id, s.project_id, s.trigger, s.status, s.ref, s.ref_type, s.queued_at, s.started_at,
               s.completed_at, s.total_dependencies, s.total_vulnerabilities, s.critical_vulns,
               s.high_vulns, s.medium_vulns, s.low_vulns, s.license_violations, s.error_message, s.retry_count,
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
      const { projectId, ref, refType, trigger } = req.body;
      if (!projectId || typeof projectId !== 'string') {
        throw Object.assign(new Error('projectId is required'), { statusCode: 400 });
      }

      // Verify project exists
      const projCheck = await this.db.query<{ id: string; repo_url: string | null }>(
        'SELECT id, repo_url FROM projects WHERE id = $1',
        [projectId],
      );
      if (projCheck.rows.length === 0) {
        throw Object.assign(new Error('Project not found'), { statusCode: 404 });
      }

      // P-04 (AC-P04-5): re-check the effective source before queueing; a
      // rejection is a 400 and no scans row is created. Scans created here
      // carry no integration, so the project's repo_url is the effective one.
      const repoUrl = projCheck.rows[0].repo_url;
      if (repoUrl) {
        await resolveScanSource(repoUrl, this.scanRoots);
      }

      const result = await this.db.query(`
        INSERT INTO scans (project_id, trigger, status, ref, ref_type, queued_at, initiated_by)
        VALUES ($1, COALESCE($2, 'manual')::scan_trigger, 'pending', $3, COALESCE($4, 'branch'), NOW(), $5)
        RETURNING *
      `, [
        projectId,
        trigger || 'manual',
        ref || 'main',
        refType || 'branch',
        user.id
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

  getScan = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;
      const result = await this.db.query(`
        SELECT s.*, p.name AS project_name
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
