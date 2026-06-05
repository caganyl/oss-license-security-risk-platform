import type { RoleName } from '../types/auth';
import type {
  FindingAction,
  FindingStatus,
  FindingTransitionInput,
  ReviewDecision,
  TransitionDef,
} from '../types/findings';

// ─── Role groups ─────────────────────────────────────────────────────────────

const ANALYSTS: readonly RoleName[] = ['admin', 'security_analyst', 'legal_reviewer'];
// Reopen and wont_fix are stronger decisions — legal reviewers may not override them
const SENIOR_ANALYSTS: readonly RoleName[] = ['admin', 'security_analyst'];

// ─── State machine configuration ─────────────────────────────────────────────

/**
 * Complete set of valid finding state transitions.
 *
 * Each key is a FindingAction (a user-initiated verb). The TransitionDef
 * declares the source states, target state, who may act, whether a
 * finding_reviews row is required, and which fields must be supplied.
 *
 * Auto-reopen on accepted_until expiry is not listed here — it is triggered
 * by a scheduled job, not by user action.
 */
export const FINDING_TRANSITIONS: Readonly<Record<FindingAction, TransitionDef>> = {
  /**
   * Claim a finding for active triage. Can be used to re-assign an already
   * in-review finding (from → ['open', 'in_review']).
   */
  assign: {
    from: ['open', 'in_review'],
    to: 'in_review',
    allowedRoles: ANALYSTS,
    createsReview: false,
    requiredInputFields: ['assigneeId'],
    auditAction: 'finding_updated',
  },

  /** Release a finding back to the queue without a resolution decision. */
  unassign: {
    from: ['in_review'],
    to: 'open',
    allowedRoles: ANALYSTS,
    createsReview: false,
    requiredInputFields: [],
    auditAction: 'finding_updated',
  },

  /**
   * Mark a finding as remediated (dependency patched / license replaced).
   * Default reviewDecision is 'remediate'; executor substitutes 'upgrade_version'
   * when targetVersion is present in the input.
   */
  resolve: {
    from: ['open', 'in_review'],
    to: 'resolved',
    allowedRoles: ANALYSTS,
    createsReview: true,
    reviewDecision: 'remediate',
    requiredInputFields: [],
    auditAction: 'finding_resolved',
  },

  /**
   * Accept the risk for a bounded period. acceptedUntil is mandatory so the
   * acceptance is time-bounded; a background job re-opens the finding after
   * the deadline passes.
   */
  accept_risk: {
    from: ['open', 'in_review'],
    to: 'accepted',
    allowedRoles: ANALYSTS,
    createsReview: true,
    reviewDecision: 'accept_risk',
    requiredInputFields: ['acceptedUntil', 'notes'],
    auditAction: 'review_submitted',
  },

  /**
   * Flag as a false positive — the finding does not represent a real risk
   * in this context. Requires justification notes.
   */
  mark_false_positive: {
    from: ['open', 'in_review'],
    to: 'false_positive',
    allowedRoles: ANALYSTS,
    createsReview: true,
    reviewDecision: 'false_positive',
    requiredInputFields: ['notes'],
    auditAction: 'review_submitted',
  },

  /**
   * Acknowledge but permanently decline to remediate. Restricted to
   * admin/security_analyst because it is the strongest possible decision —
   * it removes the finding from active dashboards and SLA tracking.
   */
  wont_fix: {
    from: ['open', 'in_review'],
    to: 'wont_fix',
    allowedRoles: SENIOR_ANALYSTS,
    createsReview: true,
    reviewDecision: 'wont_fix',
    requiredInputFields: ['notes'],
    auditAction: 'review_submitted',
  },

  /**
   * Overturn a previous terminal decision and return the finding to the
   * open queue for re-triage. Only senior analysts can reverse a decision.
   */
  reopen: {
    from: ['resolved', 'accepted', 'false_positive', 'wont_fix'],
    to: 'open',
    allowedRoles: SENIOR_ANALYSTS,
    createsReview: false,
    requiredInputFields: [],
    auditAction: 'finding_updated',
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Look up the TransitionDef for an action from the given status.
 * Returns null when the transition is not valid from currentStatus.
 */
export function resolveTransition(
  action: FindingAction,
  currentStatus: FindingStatus,
): TransitionDef | null {
  const def = FINDING_TRANSITIONS[action];
  return (def.from as FindingStatus[]).includes(currentStatus) ? def : null;
}

/**
 * Validate actor roles and required input fields against a TransitionDef.
 * Returns an array of human-readable error messages; empty = valid.
 */
export function validateTransitionRequest(
  def: TransitionDef,
  input: FindingTransitionInput,
): string[] {
  const errors: string[] = [];

  if (!input.actorRoles.some((r) => (def.allowedRoles as RoleName[]).includes(r))) {
    errors.push(`Not authorized; requires one of: ${def.allowedRoles.join(', ')}`);
  }

  for (const field of def.requiredInputFields) {
    const val = input[field as keyof FindingTransitionInput];
    if (val == null || (typeof val === 'string' && val.trim() === '')) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  if (input.acceptedUntil !== undefined) {
    const until = new Date(input.acceptedUntil);
    if (isNaN(until.getTime())) {
      errors.push('acceptedUntil must be a valid ISO date string');
    } else if (until <= new Date()) {
      errors.push('acceptedUntil must be a future date');
    }
  }

  return errors;
}

/**
 * Resolve the review_decision to write into finding_reviews.
 * Handles the 'resolve' action's remediate/upgrade_version fork.
 */
export function effectiveReviewDecision(
  def: TransitionDef,
  input: FindingTransitionInput,
): ReviewDecision | undefined {
  if (!def.reviewDecision) return undefined;
  if (def.reviewDecision === 'remediate' && input.targetVersion) {
    return 'upgrade_version';
  }
  return def.reviewDecision;
}
