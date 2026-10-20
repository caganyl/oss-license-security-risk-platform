import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { HttpError } from '../lib/httpError';
import { ScanSourceError, resolveScanSource } from '../lib/scanSource';
import { encryptToken } from '../lib/tokenCrypto';
import { isAzureDevOpsUrl } from '../scanner/workspace';
import { type HostAllowlist, normalizeWebUrl, parseAllowedHosts } from '../webscan/allowlist';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PATCH_KEYS = new Set(['webUrl', 'webScanMode']);

/**
 * `has_repo_credential` of a project row (REQ-009 contract §3): an active
 * integration with a token for exactly the project's repo URL. Never the token.
 */
function hasRepoCredentialSql(table: string): string {
  return `EXISTS (SELECT 1 FROM integrations i WHERE i.project_id = ${table}.id AND i.is_active
            AND i.access_token_enc IS NOT NULL AND i.repo_url = ${table}.repo_url) AS has_repo_credential`;
}

/** Columns of a project item (list, create, PATCH; REQ-008 contract 3.1, REQ-009 §3). */
const PROJECT_COLUMNS = `id, name, description, criticality, repo_url, scan_schedule, tags, created_at, updated_at, web_url, web_scan_mode,
  ${hasRepoCredentialSql('projects')}`;

const MAX_TOKEN_LENGTH = 1024;

/** No whitespace and no control character (U+0000-U+001F, U+007F) (REQ-009 AC-P29-2). */
function isPrintableToken(token: string): boolean {
  if (/\s/.test(token)) return false;
  for (let i = 0; i < token.length; i++) {
    const code = token.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

/** Integration provider of a repo URL (REQ-009 AC-P29-4). */
function providerFor(repoUrl: string): 'azure_devops' | 'github' | 'gitlab' | 'bitbucket' {
  if (isAzureDevOpsUrl(repoUrl)) return 'azure_devops';
  const host = new URL(repoUrl).hostname.toLowerCase();
  if (host.includes('gitlab')) return 'gitlab';
  if (host === 'bitbucket.org') return 'bitbucket';
  return 'github';
}

export class ProjectController {
  /**
   * @param scanRoots Allowed local scan roots (SCAN_ROOTS, P-04); empty = no local paths.
   * @param webAllowlist Web scan hosts (WEB_SCAN_ALLOWED_HOSTS, REQ-008 P-25); empty = no web URL.
   */
  constructor(
    private readonly db: Pool,
    private readonly scanRoots: readonly string[] = [],
    private readonly webAllowlist: HostAllowlist = parseAllowedHosts(''),
  ) {}

  listProjects = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.db.query(`
        SELECT p.id, p.name, p.description, p.criticality, p.repo_url, p.scan_schedule, p.tags, p.created_at, p.updated_at,
               p.web_url, p.web_scan_mode, ${hasRepoCredentialSql('p')},
               COALESCE(array_agg(pts.ecosystem::text) FILTER (WHERE pts.ecosystem IS NOT NULL), '{}') AS ecosystems
        FROM projects p
        LEFT JOIN project_tech_stacks pts ON pts.project_id = p.id
        WHERE p.deleted_at IS NULL
        GROUP BY p.id
        ORDER BY p.name ASC
      `);
      res.json({ data: result.rows });
    } catch (err) {
      next(err);
    }
  };

  createProject = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // P-04 / AC-P03-7: classify repoUrl before anything is stored; rejection -> 400, no row.
    let storedRepoUrl: string | null = null;
    let storedWebUrl: string | null = null;
    try {
      const repoUrl: unknown = req.body?.repoUrl;
      if (repoUrl !== undefined && repoUrl !== null && repoUrl !== '') {
        if (typeof repoUrl !== 'string') throw new ScanSourceError('repo_url_not_allowed');
        const source = await resolveScanSource(repoUrl, this.scanRoots);
        storedRepoUrl = source.kind === 'local' ? source.path : source.url;
      }
      // REQ-008 AC-P25-3/4: after repoUrl, before anything is stored.
      const webUrl: unknown = req.body?.webUrl;
      if (webUrl !== undefined && webUrl !== null && webUrl !== '') {
        storedWebUrl = normalizeWebUrl(webUrl, this.webAllowlist);
      }
    } catch (err) {
      next(err);
      return;
    }

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      // Owner is always the authenticated user; there is no fallback identity (AC-P01-17).
      const user = req.user;
      if (!user) {
        throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
      }
      const { name, description, criticality, scanSchedule, tags, ecosystems } = req.body;
      if (!name || typeof name !== 'string' || name.trim() === '') {
        throw Object.assign(new Error('Project name is required'), { statusCode: 400 });
      }

      const insertProj = await client.query(`
        INSERT INTO projects (name, description, criticality, repo_url, scan_schedule, tags, owner_id, web_url)
        VALUES ($1, $2, COALESCE($3, 'medium')::project_criticality, $4, $5, $6, $7, $8)
        RETURNING ${PROJECT_COLUMNS}
      `, [
        name.trim(),
        description || null,
        criticality || 'medium',
        storedRepoUrl,
        scanSchedule || null,
        tags || [],
        user.id,
        storedWebUrl,
      ]);
      const project = insertProj.rows[0];

      const insertedEcosystems: string[] = [];
      if (Array.isArray(ecosystems) && ecosystems.length > 0) {
        for (const eco of ecosystems) {
          if (eco && typeof eco === 'string') {
            await client.query(`
              INSERT INTO project_tech_stacks (project_id, ecosystem)
              VALUES ($1, $2::tech_ecosystem)
              ON CONFLICT DO NOTHING
            `, [project.id, eco]);
            insertedEcosystems.push(eco);
          }
        }
      }

      await client.query('COMMIT');
      project.ecosystems = insertedEcosystems;

      // Log audit
      await this.db.query(
        `INSERT INTO audit_logs (action, actor_id, actor_email, entity_type, entity_id, new_data, occurred_at)
         VALUES ('project_created', $1, $2, 'project', $3, $4, NOW())`,
        [user.id, user.email, project.id, JSON.stringify(project)]
      ).catch(err => console.error('Failed to write audit log:', err));

      res.status(201).json({ data: project });
    } catch (err) {
      await client.query('ROLLBACK');
      next(err);
    } finally {
      client.release();
    }
  };

  /**
   * `PATCH /api/projects/{id}` (REQ-008 AC-P25-5, contract 3.3): `webUrl`
   * (string | null) and `webScanMode` only. Audit `project_updated` with the
   * old and new web fields.
   */
  updateProject = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = req.user;
      if (!user) throw new HttpError(401, 'Authentication required');
      const { id } = req.params;
      if (typeof id !== 'string' || !UUID_RE.test(id)) throw new HttpError(400, 'id must be a valid UUID');
      const body: unknown = req.body;
      if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new HttpError(400, 'Request body must be a JSON object');
      const keys = Object.keys(body);
      if (keys.length === 0 || keys.some((k) => !PATCH_KEYS.has(k))) {
        throw new HttpError(400, 'Only webUrl and webScanMode can be changed');
      }
      const input = body as { webUrl?: unknown; webScanMode?: unknown };
      const sets: string[] = [];
      const values: unknown[] = [];
      if ('webUrl' in input) {
        const webUrl = input.webUrl === null || input.webUrl === '' ? null : normalizeWebUrl(input.webUrl, this.webAllowlist);
        values.push(webUrl);
        sets.push(`web_url = $${values.length}`);
      }
      if ('webScanMode' in input) {
        if (input.webScanMode !== 'passive' && input.webScanMode !== 'active') {
          throw new HttpError(400, 'webScanMode must be passive or active');
        }
        values.push(input.webScanMode);
        sets.push(`web_scan_mode = $${values.length}`);
      }

      const client = await this.db.connect();
      try {
        await client.query('BEGIN');
        const before = await client.query<{ web_url: string | null; web_scan_mode: string }>(
          'SELECT web_url, web_scan_mode FROM projects WHERE id = $1 AND deleted_at IS NULL FOR UPDATE',
          [id],
        );
        if (before.rows.length === 0) throw new HttpError(404, 'Project not found');
        values.push(id);
        const updated = await client.query(
          `UPDATE projects SET ${sets.join(', ')}, updated_at = NOW() WHERE id = $${values.length} RETURNING ${PROJECT_COLUMNS}`,
          values,
        );
        const project = updated.rows[0];
        const stack = await client.query<{ ecosystem: string }>('SELECT ecosystem::text AS ecosystem FROM project_tech_stacks WHERE project_id = $1 ORDER BY 1', [id]);
        project.ecosystems = stack.rows.map((r) => r.ecosystem);
        await client.query(
          `INSERT INTO audit_logs (action, actor_id, actor_email, entity_type, entity_id, old_data, new_data, occurred_at)
           VALUES ('project_updated', $1, $2, 'project', $3, $4, $5, NOW())`,
          [
            user.id,
            user.email,
            id,
            JSON.stringify(before.rows[0]),
            JSON.stringify({ web_url: project.web_url, web_scan_mode: project.web_scan_mode }),
          ],
        );
        await client.query('COMMIT');
        res.json({ data: project });
      } catch (err) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw err;
      } finally {
        client.release();
      }
    } catch (err) {
      next(err);
    }
  };

  /**
   * `PUT /api/projects/{id}/repo-credential` (REQ-009 P-29, contract §1):
   * stores the repo access token encrypted on the project's single active
   * integration. There is no delete endpoint (D-262); a new PUT replaces the
   * token. The token never appears in a response, the audit log or an error.
   */
  setRepoCredential = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = req.user;
      if (!user) throw new HttpError(401, 'Authentication required');
      const { id } = req.params;
      if (typeof id !== 'string' || !UUID_RE.test(id)) throw new HttpError(400, 'id must be a valid UUID');
      const body: unknown = req.body;
      const token = typeof body === 'object' && body !== null && !Array.isArray(body) && Object.keys(body).length === 1
        ? (body as { token?: unknown }).token
        : undefined;
      if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH || !isPrintableToken(token)) {
        throw new HttpError(400, 'Body must be { "token": string } with 1-1024 characters and no whitespace', 'invalid_token');
      }

      const client = await this.db.connect();
      try {
        await client.query('BEGIN');
        const projectRow = await client.query<{ repo_url: string | null }>(
          'SELECT repo_url FROM projects WHERE id = $1 AND deleted_at IS NULL FOR UPDATE',
          [id],
        );
        if (projectRow.rows.length === 0) throw new HttpError(404, 'Project not found');
        const repoUrl = projectRow.rows[0].repo_url;
        if (repoUrl === null || !/^https:\/\//i.test(repoUrl)) {
          throw new HttpError(400, 'A repo access token applies only to an https repository URL', 'repo_credential_not_applicable');
        }
        const provider = providerFor(repoUrl);
        const encrypted = encryptToken(token);
        const existing = await client.query<{ id: string }>(
          'SELECT id FROM integrations WHERE project_id = $1 AND is_active ORDER BY created_at ASC',
          [id],
        );
        let integrationId: string;
        if (existing.rows.length === 0) {
          const inserted = await client.query<{ id: string }>(
            `INSERT INTO integrations (project_id, provider, name, repo_url, access_token_enc, is_active, created_by)
             VALUES ($1, $2::integration_provider, 'repo-credential', $3, $4, TRUE, $5)
             RETURNING id`,
            [id, provider, repoUrl, encrypted, user.id],
          );
          integrationId = inserted.rows[0].id;
        } else {
          integrationId = existing.rows[0].id;
          await client.query(
            `UPDATE integrations SET provider = $2::integration_provider, repo_url = $3, access_token_enc = $4, updated_at = NOW()
             WHERE id = $1`,
            [integrationId, provider, repoUrl, encrypted],
          );
          // One active integration per project (D-250): any extra active row is retired.
          await client.query(
            'UPDATE integrations SET is_active = FALSE, access_token_enc = NULL, updated_at = NOW() WHERE project_id = $1 AND is_active AND id <> $2',
            [id, integrationId],
          );
        }
        await client.query(
          `INSERT INTO audit_logs (action, actor_id, actor_email, entity_type, entity_id, old_data, new_data, occurred_at)
           VALUES ($1::audit_action, $2, $3, 'integration', $4, $5, $6, NOW())`,
          [
            existing.rows.length === 0 ? 'integration_created' : 'integration_updated',
            user.id,
            user.email,
            integrationId,
            JSON.stringify({ project_id: id, has_repo_credential: existing.rows.length > 0 }),
            JSON.stringify({ project_id: id, provider, has_repo_credential: true }),
          ],
        );
        await client.query('COMMIT');
        res.json({ data: { has_repo_credential: true, provider } });
      } catch (err) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw err;
      } finally {
        client.release();
      }
    } catch (err) {
      next(err);
    }
  };
}
