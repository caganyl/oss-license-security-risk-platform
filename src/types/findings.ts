/**
 * Finding domain types — mirrors finding_status, review_decision, and finding_type
 * DB enums, plus the state machine's input/definition interfaces.
 */

import type { RoleName } from './auth';

/** Mirrors the finding_status DB enum. */
export type FindingStatus =
  | 'open'
  | 'in_review'
  | 'resolved'
  | 'accepted'
  | 'false_positive'
  | 'wont_fix';

/** Mirrors the review_decision DB enum. */
export type ReviewDecision =
  | 'remediate'
  | 'upgrade_version'
  | 'accept_risk'
  | 'false_positive'
  | 'wont_fix';

/** Mirrors the finding_type DB enum. */
export type FindingType = 'security' | 'license' | 'copyright';

/**
 * User-initiated actions that drive finding state transitions.
 *
 * Each action maps to exactly one TransitionDef in FINDING_TRANSITIONS.
 */
export type FindingAction =
  | 'assign'            // open | in_review → in_review (sets assignee)
  | 'unassign'          // in_review → open (clears assignee)
  | 'resolve'           // open | in_review → resolved
  | 'accept_risk'       // open | in_review → accepted (requires expiry date)
  | 'mark_false_positive' // open | in_review → false_positive
  | 'wont_fix'          // open | in_review → wont_fix
  | 'reopen';           // resolved | accepted | false_positive | wont_fix → open

/** Input payload provided by the caller for any transition request. */
export interface FindingTransitionInput {
  actorRoles: RoleName[];
  notes?: string;
  assigneeId?: string;   // required for 'assign'
  acceptedUntil?: string; // ISO-8601 date; required for 'accept_risk'
  targetVersion?: string; // optional for 'resolve'; records upgrade_version decision
}

/** Declarative definition of one finding state transition. */
export interface TransitionDef {
  /** Valid source states — transition is rejected if current status is not in this list. */
  from: readonly FindingStatus[];
  /** Target state applied to findings.status on success. */
  to: FindingStatus;
  /** Roles that may trigger this action. */
  allowedRoles: readonly RoleName[];
  /** When true the executor must insert a finding_reviews row. */
  createsReview: boolean;
  /**
   * Default review_decision recorded in finding_reviews.
   * For 'resolve', the executor substitutes 'upgrade_version' when targetVersion is provided.
   */
  reviewDecision?: ReviewDecision;
  /** Subset of FindingTransitionInput keys (excluding actorRoles) that must be non-empty. */
  requiredInputFields: ReadonlyArray<keyof Omit<FindingTransitionInput, 'actorRoles'>>;
  /** Audit action written to audit_logs on success. */
  auditAction: 'finding_updated' | 'finding_resolved' | 'review_submitted';
}
