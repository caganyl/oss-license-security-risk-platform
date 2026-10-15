/**
 * Result write of a web scan inside the worker's fenced transaction
 * (REQ-008 AC-P26-7, AC-P26-9; ADR-010 Karar 1, 2, 7).
 *
 * Writes `web_scan_components`, upserts JavaScript library vulnerabilities
 * into the shared `vulnerabilities` catalogue, writes `web_findings` (one per
 * fingerprint, D-236) and returns the `web_summary` and the counters the
 * worker puts on the `scans` row.
 */
import type { PoolClient } from 'pg';
import type { NormalizedVulnerability } from '../vulnerability/normalize';
import { upsertVulnerability } from '../vulnerability/findingWriter';
import { finding } from './rules';
import { countBySeverity, webFingerprint, webGrade, webScore } from './score';
import type { WebScanOutcome } from './engine';
import type { DetectedComponent, LookupState, WebFindingDraft, WebScanSummary, WebSeverity } from './types';

export interface LibraryVulnerability {
  component: DetectedComponent;
  vulnerability: NormalizedVulnerability;
}

export interface WebPersistInput {
  scanId: string;
  projectId: string;
  outcome: WebScanOutcome;
  libraryVulnerabilities: readonly LibraryVulnerability[];
  lookupState: LookupState;
}

export interface WebPersistResult {
  summary: WebScanSummary;
  counts: Record<WebSeverity, number>;
}

function librarySeverity(severity: string): WebSeverity {
  return severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low' ? severity : 'low';
}

const cut = (value: string | null | undefined, max: number) => (value === null || value === undefined ? null : value.slice(0, max));

export async function writeWebResults(client: PoolClient, input: WebPersistInput, signal?: AbortSignal): Promise<WebPersistResult> {
  const { scanId, projectId, outcome } = input;

  for (const c of outcome.components) {
    signal?.throwIfAborted();
    await client.query(
      `INSERT INTO web_scan_components (scan_id, name, npm_name, version, detection, location)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (scan_id, name, version) DO NOTHING`,
      [scanId, cut(c.name, 100), cut(c.npmName, 214), cut(c.version, 64), c.detection, cut(c.location, 2048)],
    );
  }

  const drafts: Array<WebFindingDraft & { vulnerabilityId?: string }> = [...outcome.findings];
  for (const { component, vulnerability } of input.libraryVulnerabilities) {
    signal?.throwIfAborted();
    const stored = await upsertVulnerability(client, vulnerability);
    const advisory = stored.cveId ?? stored.ghsaId ?? stored.osvId ?? vulnerability.sourceId;
    drafts.push({
      ...finding('WEB-LIB-001', {
        location: component.location,
        evidence: `${component.name}@${component.version} — ${advisory}`,
        key: `${component.npmName ?? component.name}@${component.version}|${advisory}`,
        severity: librarySeverity(stored.severity),
        componentName: component.name,
        componentVersion: component.version,
        fixedVersion: vulnerability.fixedVersion,
        cvssScore: stored.cvssScore,
      }),
      vulnerabilityId: stored.id,
    });
  }

  const written: WebSeverity[] = [];
  const seen = new Set<string>();
  for (const d of drafts) {
    signal?.throwIfAborted();
    const fingerprint = webFingerprint(projectId, d.ruleId, d.key);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    await client.query(
      `INSERT INTO web_findings (scan_id, project_id, rule_id, source, category, severity, confidence, title, description,
                                 recommendation, location, evidence, cwe_id, owasp, vulnerability_id, component_name,
                                 component_version, fixed_version, cvss_score, fingerprint)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
      [
        scanId,
        projectId,
        d.ruleId,
        d.source,
        d.category,
        d.severity,
        d.confidence,
        cut(d.title, 300),
        cut(d.description, 4000),
        cut(d.recommendation, 4000),
        cut(d.location, 2048),
        cut(d.evidence, 2000),
        d.cweId,
        d.owasp,
        d.vulnerabilityId ?? null,
        cut(d.componentName, 214),
        cut(d.componentVersion, 214),
        cut(d.fixedVersion, 214),
        d.cvssScore ?? null,
        fingerprint,
      ],
    );
    written.push(d.severity);
  }

  const counts = countBySeverity(written);
  const score = webScore(counts);
  const summary: WebScanSummary = {
    version: 1,
    requests: outcome.requests,
    request_limit_reached: outcome.requestLimitReached,
    final_url: outcome.finalUrl,
    tls: outcome.tls ? { protocol: outcome.tls.protocol, valid_to: outcome.tls.validTo, issuer: outcome.tls.issuer } : null,
    engines: { builtin: outcome.builtin, zap: outcome.zap, zap_mode: outcome.zapMode },
    vulnerability_lookup: input.lookupState,
    components: outcome.components.length,
    counts,
    score,
    grade: webGrade(score),
  };
  return { summary, counts };
}
