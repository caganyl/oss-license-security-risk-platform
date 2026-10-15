/**
 * Web scan score, grade and fingerprint (REQ-008 D-223, D-232; contract
 * section 6; ADR-010 Karar 2). Pure.
 */
import crypto from 'node:crypto';
import type { WebGrade, WebSeverity } from './types';

export const SCORE_WEIGHTS: Readonly<Record<WebSeverity, number>> = { critical: 40, high: 20, medium: 8, low: 2, info: 0 };

export function emptyCounts(): Record<WebSeverity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function countBySeverity(severities: Iterable<WebSeverity>): Record<WebSeverity, number> {
  const counts = emptyCounts();
  for (const s of severities) counts[s] += 1;
  return counts;
}

/** `max(0, 100 − 40·critical − 20·high − 8·medium − 2·low)`. */
export function webScore(counts: Readonly<Record<WebSeverity, number>>): number {
  let penalty = 0;
  for (const severity of Object.keys(SCORE_WEIGHTS) as WebSeverity[]) penalty += SCORE_WEIGHTS[severity] * (counts[severity] ?? 0);
  return Math.max(0, 100 - penalty);
}

export function webGrade(score: number): WebGrade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/** `sha256('w1|' + projectId + '|' + ruleId + '|' + key)`, lower-case hex. */
export function webFingerprint(projectId: string, ruleId: string, key: string): string {
  return crypto.createHash('sha256').update(`w1|${projectId.toLowerCase()}|${ruleId}|${key}`, 'utf8').digest('hex');
}
