import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';

export class ProjectController {
  constructor(private readonly db: Pool) {}

  listProjects = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.db.query(`
        SELECT p.id, p.name, p.description, p.criticality, p.repo_url, p.scan_schedule, p.tags, p.created_at, p.updated_at,
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
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      const { name, description, criticality, repoUrl, scanSchedule, tags, ecosystems } = req.body;
      if (!name || typeof name !== 'string' || name.trim() === '') {
        throw Object.assign(new Error('Project name is required'), { statusCode: 400 });
      }

      const insertProj = await client.query(`
        INSERT INTO projects (name, description, criticality, repo_url, scan_schedule, tags, owner_id)
        VALUES ($1, $2, COALESCE($3, 'medium')::project_criticality, $4, $5, $6, $7)
        RETURNING id, name, description, criticality, repo_url, scan_schedule, tags, created_at, updated_at
      `, [
        name.trim(),
        description || null,
        criticality || 'medium',
        repoUrl || null,
        scanSchedule || null,
        tags || [],
        req.user?.id || '00000000-0000-0000-0000-000000000000'
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
        [req.user?.id || null, req.user?.email || null, project.id, JSON.stringify(project)]
      ).catch(err => console.error('Failed to write audit log:', err));

      res.status(201).json({ data: project });
    } catch (err) {
      await client.query('ROLLBACK');
      next(err);
    } finally {
      client.release();
    }
  };
}
