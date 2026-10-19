/**
 * Shared types of the web (URL) scanner (REQ-008, ADR-010; contract
 * `docs/contracts/REQ-008-web-scan.md`). Type-only module.
 */

export type WebSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type WebConfidence = 'low' | 'medium' | 'high';
export type WebCategory =
  | 'transport'
  | 'headers'
  | 'disclosure'
  | 'cookies'
  | 'cors'
  | 'exposure'
  | 'content'
  | 'components'
  | 'zap';
export type WebFindingSource = 'builtin' | 'zap';
export type WebScanMode = 'passive' | 'active';

/** Severity order, most severe first (contract section 3.6 ordering). */
export const WEB_SEVERITY_ORDER: readonly WebSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * One finding before it is written (`web_findings` row without ids). Every
 * text is already sanitized and capped by `rules.ts` / `zap.ts`.
 */
export interface WebFindingDraft {
  ruleId: string;
  source: WebFindingSource;
  category: WebCategory;
  severity: WebSeverity;
  confidence: WebConfidence;
  title: string;
  description: string;
  recommendation: string;
  /** URL without query and fragment, or null. */
  location: string | null;
  evidence: string | null;
  cweId: number | null;
  owasp: string | null;
  /** Fingerprint key part (contract / ADR-010 Karar 2). */
  key: string;
  componentName?: string | null;
  componentVersion?: string | null;
  fixedVersion?: string | null;
  cvssScore?: number | null;
}

/** A JavaScript library detected on the page (contract section 5). */
export interface DetectedComponent {
  name: string;
  /** npm package name sent to OSV, or null when unknown (cdnjs library without a mapping). */
  npmName: string | null;
  version: string;
  detection: 'url' | 'banner' | 'html';
  /** URL without query and fragment, or null (HTML attribute). */
  location: string | null;
}

/** Response of one probe request (probeClient.ts). */
export interface ProbeResponse {
  url: string;
  status: number;
  /** Lower-case header names; `set-cookie` is always an array. */
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  truncated: boolean;
  /** TLS facts of the connection (https only, when readable). */
  tls: ProbeTlsInfo | null;
}

export interface ProbeTlsInfo {
  protocol: string | null;
  /** ISO date or null. */
  validTo: string | null;
  issuer: string | null;
}

/** A failed probe: network-level code only, never a message. */
export interface ProbeFailure {
  url: string;
  code: string;
  /** TLS certificate validation failure (WEB-TLS-003). */
  tlsCertificate: boolean;
}

export type ProbeOutcome = { ok: true; response: ProbeResponse } | { ok: false; failure: ProbeFailure };

export type EngineState = 'complete' | 'partial';
export type ZapState = 'not_configured' | 'complete' | 'partial' | 'unavailable' | 'failed';
export type LookupState = 'complete' | 'partial' | 'unavailable' | 'disabled' | 'not_needed';

/** `scans.web_summary` (contract section 2.5, version 1). */
export interface WebScanSummary {
  version: 1;
  requests: number;
  request_limit_reached: boolean;
  final_url: string | null;
  tls: { protocol: string | null; valid_to: string | null; issuer: string | null } | null;
  engines: { builtin: EngineState; zap: ZapState; zap_mode: WebScanMode | null };
  vulnerability_lookup: LookupState;
  components: number;
  counts: Record<WebSeverity, number>;
  score: number;
  grade: WebGrade;
}

export type WebGrade = 'A' | 'B' | 'C' | 'D' | 'F';
