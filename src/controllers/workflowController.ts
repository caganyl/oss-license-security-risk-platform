import type { NextFunction, Request, Response } from 'express';
import type { Pool, PoolClient } from 'pg';
import { sendError } from '../lib/httpError';
import {
  effectiveReviewDecision,
  resolveTransition,
  validateTransitionRequest,
} from '../lib/findingStateMachine';
import type {
  FindingAction,
  FindingStatus,
  FindingTransitionInput,
  FindingType,
  TransitionDef,
} from '../types/findings';

type AuditAction = 'finding_updated' | 'finding_resolved' | 'review_submitted' | 'comment_added';

interface FindingRow {
  id: string;
  scan_id: string;
  scan_dependency_id: string;
  finding_type: FindingType;
  status: FindingStatus;
  assignee_id: string | null;
  deadline: string | null;
  risk_override: string | null;
  suppressed: boolean;
  suppressed_by: string | null;
  suppressed_at: string | null;
  suppression_reason: string | null;
  created_at: string;
  updated_at: string;
}

interface ReviewRow {
  id: string;
  finding_id: string;
  decision: string;
  reviewer_id: string;
  reviewer_email: string | null;
  accepted_until: string | null;
  target_version: string | null;
  notes: string | null;
  created_at: string;
}

interface CommentRow {
  id: string;
  finding_id: string;
  author_id: string;
  author_email: string | null;
  content: string;
  edited_at: string | null;
  created_at: string;
}

interface AuditInput {
  action: AuditAction;
  actorId?: string;
  actorEmail?: string;
  entityId: string;
  oldData?: unknown;
  newData?: unknown;
  req: Request;
}

interface WorkflowResponse {
  finding: ReturnType<typeof toFindingResponse>;
  reviews: ReturnType<typeof toReviewResponse>[];
  comments: ReturnType<typeof toCommentResponse>[];
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value: string | undefined): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

function toFindingResponse(row: FindingRow) {
  return {
    id: row.id,
    scanId: row.scan_id,
    scanDependencyId: row.scan_dependency_id,
    findingType: row.finding_type,
    status: row.status,
    assigneeId: row.assignee_id,
    deadline: row.deadline,
    riskOverride: row.risk_override,
    suppressed: row.suppressed,
    suppressedBy: row.suppressed_by,
    suppressedAt: row.suppressed_at,
    suppressionReason: row.suppression_reason,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toReviewResponse(row: ReviewRow) {
  return {
    id: row.id,
    findingId: row.finding_id,
    decision: row.decision,
    reviewerId: row.reviewer_id,
    reviewerEmail: row.reviewer_email,
    acceptedUntil: row.accepted_until,
    targetVersion: row.target_version,
    notes: row.notes,
    createdAt: row.created_at,
  };
}

function toCommentResponse(row: CommentRow) {
  return {
    id: row.id,
    findingId: row.finding_id,
    authorId: row.author_id,
    authorEmail: row.author_email,
    content: row.content,
    editedAt: row.edited_at,
    createdAt: row.created_at,
  };
}

function parseString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') {
    throw Object.assign(new Error(`${field} must be a string`), { statusCode: 400 });
  }
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function parseTransitionInput(req: Request): Omit<FindingTransitionInput, 'actorRoles'> {
  return {
    notes: parseString(req.body.notes, 'notes'),
    assigneeId: parseString(req.body.assigneeId, 'assigneeId'),
    acceptedUntil: parseString(req.body.acceptedUntil, 'acceptedUntil'),
    targetVersion: parseString(req.body.targetVersion, 'targetVersion'),
  };
}

function handleControllerError(err: unknown, res: Response, next: NextFunction): void {
  const error = err as Error & { statusCode?: number; code?: string; detail?: string };

  if (error.code === '23503') {
    // Fixed text: the driver's `detail` would echo raw DB internals (AC-G-8).
    sendError(res, 400, 'Referenced record does not exist', 'invalid_request');
    return;
  }

  if (error.statusCode) {
    sendError(res, error.statusCode, error.message);
    return;
  }

  next(err);
}

export class WorkflowController {
  constructor(private readonly db: Pool) {}

  getWorkflow = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      this.validateFindingId(req.params.id);
      const finding = await this.fetchFinding(req.params.id);
      if (!finding) {
        throw Object.assign(new Error('Finding not found'), { statusCode: 404 });
      }

      this.ensureFindingScope(finding, req);
      res.json({ data: await this.buildWorkflowResponse(finding) });
    } catch (err) {
      handleControllerError(err, res, next);
    }
  };

  assignFinding = this.transitionHandler('assign');
  unassignFinding = this.transitionHandler('unassign');
  resolveFinding = this.transitionHandler('resolve');
  acceptRisk = this.transitionHandler('accept_risk');
  markFalsePositive = this.transitionHandler('mark_false_positive');
  wontFix = this.transitionHandler('wont_fix');
  reopenFinding = this.transitionHandler('reopen');

  addComment = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      this.validateFindingId(req.params.id);
      const content = parseString(req.body.content, 'content');
      if (!content) {
        throw Object.assign(new Error('content is required'), { statusCode: 400 });
      }

      const finding = await this.fetchFindingForUpdate(client, req.params.id);
      if (!finding) {
        throw Object.assign(new Error('Finding not found'), { statusCode: 404 });
      }
      this.ensureFindingScope(finding, req);

      const comment = await this.insertComment(client, finding.id, req.user?.id, content);
      const workflow = await this.buildWorkflowResponse(finding, client);
      await this.insertAudit(client, {
        action: 'comment_added',
        actorId: req.user?.id,
        actorEmail: req.user?.email,
        entityId: finding.id,
        newData: { comment: toCommentResponse(comment) },
        req,
      });

      await client.query('COMMIT');
      res.status(201).json({ data: workflow });
    } catch (err) {
      await client.query('ROLLBACK');
      handleControllerError(err, res, next);
    } finally {
      client.release();
    }
  };

  private transitionHandler(action: FindingAction) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const client = await this.db.connect();

      try {
        await client.query('BEGIN');
        this.validateFindingId(req.params.id);

        const existing = await this.fetchFindingForUpdate(client, req.params.id);
        if (!existing) {
          throw Object.assign(new Error('Finding not found'), { statusCode: 404 });
        }
        this.ensureFindingScope(existing, req);

        const def = resolveTransition(action, existing.status);
        if (!def) {
          throw Object.assign(
            new Error(`Cannot ${action} a finding with status "${existing.status}"`),
            { statusCode: 409 },
          );
        }

        const input: FindingTransitionInput = {
          ...parseTransitionInput(req),
          actorRoles: req.user?.roles ?? [],
        };
        const validationErrors = validateTransitionRequest(def, input);
        if (validationErrors.length > 0) {
          throw Object.assign(new Error(validationErrors.join('; ')), { statusCode: 400 });
        }

        if (input.assigneeId && !isUuid(input.assigneeId)) {
          throw Object.assign(new Error('assigneeId must be a valid UUID'), { statusCode: 400 });
        }

        if (action === 'assign') {
          await this.assertUserExists(client, input.assigneeId);
        }

        const updated = await this.updateFindingForTransition(client, existing.id, action, def.to, input);
        const review = def.createsReview
          ? await this.insertReview(client, existing.id, req.user?.id, def, input)
          : null;
        const workflow = await this.buildWorkflowResponse(updated, client);

        await this.insertAudit(client, {
          action: def.auditAction,
          actorId: req.user?.id,
          actorEmail: req.user?.email,
          entityId: existing.id,
          oldData: toFindingResponse(existing),
          newData: {
            finding: toFindingResponse(updated),
            review: review ? toReviewResponse(review) : undefined,
          },
          req,
        });

        await client.query('COMMIT');
        res.json({ data: workflow });
      } catch (err) {
        await client.query('ROLLBACK');
        handleControllerError(err, res, next);
      } finally {
        client.release();
      }
    };
  }

  private validateFindingId(id: string | undefined): void {
    if (!isUuid(id)) {
      throw Object.assign(new Error('finding id must be a valid UUID'), { statusCode: 400 });
    }
  }

  private ensureFindingScope(finding: FindingRow, req: Request): void {
    const roles = req.user?.roles ?? [];
    const onlyLegalReviewer =
      roles.includes('legal_reviewer') &&
      !roles.includes('admin') &&
      !roles.includes('security_analyst');

    if (onlyLegalReviewer && finding.finding_type !== 'license') {
      throw Object.assign(new Error('Legal reviewers may only act on license findings'), {
        statusCode: 403,
      });
    }
  }

  private async fetchFinding(id: string, client: Pool | PoolClient = this.db): Promise<FindingRow | null> {
    const result = await client.query<FindingRow>(
      `
        SELECT *
        FROM findings
        WHERE id = $1
      `,
      [id],
    );

    return result.rows[0] ?? null;
  }

  private async fetchFindingForUpdate(client: PoolClient, id: string): Promise<FindingRow | null> {
    const result = await client.query<FindingRow>(
      `
        SELECT *
        FROM findings
        WHERE id = $1
        FOR UPDATE
      `,
      [id],
    );

    return result.rows[0] ?? null;
  }

  private async updateFindingForTransition(
    client: PoolClient,
    findingId: string,
    action: FindingAction,
    status: FindingStatus,
    input: FindingTransitionInput,
  ): Promise<FindingRow> {
    const assigneeId =
      action === 'assign' ? input.assigneeId
      : action === 'unassign' || action === 'reopen' ? null
      : undefined;

    const result = await client.query<FindingRow>(
      `
        UPDATE findings
        SET
          status = $2,
          assignee_id = CASE WHEN $3::boolean THEN $4::uuid ELSE assignee_id END,
          updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `,
      [findingId, status, assigneeId !== undefined, assigneeId ?? null],
    );

    return result.rows[0];
  }

  private async insertReview(
    client: PoolClient,
    findingId: string,
    reviewerId: string | undefined,
    def: TransitionDef,
    input: FindingTransitionInput,
  ): Promise<ReviewRow> {
    if (!reviewerId) {
      throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
    }

    const decision = effectiveReviewDecision(def, input);
    if (!decision) {
      throw Object.assign(new Error('Review decision could not be resolved'), { statusCode: 400 });
    }

    const result = await client.query<ReviewRow>(
      `
        INSERT INTO finding_reviews (
          finding_id,
          decision,
          reviewer_id,
          accepted_until,
          target_version,
          notes
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
          id,
          finding_id,
          decision,
          reviewer_id,
          NULL::text AS reviewer_email,
          accepted_until,
          target_version,
          notes,
          created_at
      `,
      [
        findingId,
        decision,
        reviewerId,
        input.acceptedUntil ?? null,
        input.targetVersion ?? null,
        input.notes ?? null,
      ],
    );

    return result.rows[0];
  }

  private async insertComment(
    client: PoolClient,
    findingId: string,
    authorId: string | undefined,
    content: string,
  ): Promise<CommentRow> {
    if (!authorId) {
      throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
    }

    const result = await client.query<CommentRow>(
      `
        INSERT INTO finding_comments (finding_id, author_id, content)
        VALUES ($1, $2, $3)
        RETURNING
          id,
          finding_id,
          author_id,
          NULL::text AS author_email,
          content,
          edited_at,
          created_at
      `,
      [findingId, authorId, content],
    );

    return result.rows[0];
  }

  private async assertUserExists(client: PoolClient, userId: string | undefined): Promise<void> {
    if (!userId) return;

    const result = await client.query<{ exists: boolean }>(
      `
        SELECT EXISTS (
          SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL
        )
      `,
      [userId],
    );

    if (!result.rows[0]?.exists) {
      throw Object.assign(new Error('assigneeId must reference an active user'), {
        statusCode: 400,
      });
    }
  }

  private async buildWorkflowResponse(
    finding: FindingRow,
    client: Pool | PoolClient = this.db,
  ): Promise<WorkflowResponse> {
    const reviews = await this.fetchReviews(finding.id, client);
    const comments = await this.fetchComments(finding.id, client);

    return {
      finding: toFindingResponse(finding),
      reviews: reviews.map(toReviewResponse),
      comments: comments.map(toCommentResponse),
    };
  }

  private async fetchReviews(findingId: string, client: Pool | PoolClient): Promise<ReviewRow[]> {
    const result = await client.query<ReviewRow>(
      `
        SELECT
          fr.id,
          fr.finding_id,
          fr.decision,
          fr.reviewer_id,
          u.email AS reviewer_email,
          fr.accepted_until,
          fr.target_version,
          fr.notes,
          fr.created_at
        FROM finding_reviews fr
        LEFT JOIN users u ON u.id = fr.reviewer_id
        WHERE fr.finding_id = $1
        ORDER BY fr.created_at DESC
      `,
      [findingId],
    );

    return result.rows;
  }

  private async fetchComments(findingId: string, client: Pool | PoolClient): Promise<CommentRow[]> {
    const result = await client.query<CommentRow>(
      `
        SELECT
          fc.id,
          fc.finding_id,
          fc.author_id,
          u.email AS author_email,
          fc.content,
          fc.edited_at,
          fc.created_at
        FROM finding_comments fc
        LEFT JOIN users u ON u.id = fc.author_id
        WHERE fc.finding_id = $1
        ORDER BY fc.created_at DESC
      `,
      [findingId],
    );

    return result.rows;
  }

  private async insertAudit(client: PoolClient, input: AuditInput): Promise<void> {
    await client.query(
      `
        INSERT INTO audit_logs (
          action,
          actor_id,
          actor_email,
          entity_type,
          entity_id,
          old_data,
          new_data,
          ip_address,
          user_agent,
          request_id
        )
        VALUES ($1, $2, $3, 'finding', $4, $5, $6, $7, $8, $9)
      `,
      [
        input.action,
        input.actorId ?? null,
        input.actorEmail ?? null,
        input.entityId,
        input.oldData ? JSON.stringify(input.oldData) : null,
        input.newData ? JSON.stringify(input.newData) : null,
        input.req.ip,
        input.req.get('user-agent') ?? null,
        input.req.get('x-request-id') ?? null,
      ],
    );
  }
}
