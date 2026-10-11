/**
 * Output formatting and terminal safety (REQ-007 contract sections 5.3–5.6,
 * ADR-009 Karar 5).
 *
 * - Every remote/repository text goes through `cleanText`: `singleLine`,
 *   C0/C1 removal, code point limit (ANSI sequences are neutralised).
 * - `Output` is the only writer: it replaces registered secrets (API key,
 *   its secret part, bootstrap password, session cookie value) with
 *   `[redacted]` before writing. That path is defence in depth and must never
 *   be hit; `redactionHits` lets tests prove it.
 * - JSON output is built by one constructor with the fixed field order.
 */
import { singleLine } from '../lib/outputText';
import type { BreachItem, Counts, DataStatus } from './evaluate';
import type { FailOn } from './args';

/** Contract 5.5: singleLine → C0/C1 (U+0000–U+001F, U+007F–U+009F) removal → at most `max` code points. */
export function cleanText(text: unknown, max = 200): string {
  if (text === null || text === undefined) return '';
  const folded = singleLine(typeof text === 'string' ? text : String(text));
  const kept: string[] = [];
  for (const ch of folded) {
    const c = ch.codePointAt(0) ?? 0;
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) continue;
    if (kept.length >= max) break;
    kept.push(ch);
  }
  return kept.join('');
}

export interface Writer {
  write(chunk: string): unknown;
}

export class Output {
  private readonly secrets: string[] = [];
  redactionHits = 0;

  constructor(
    private readonly stdout: Writer,
    private readonly stderr: Writer,
  ) {}

  addSecret(secret: string | null | undefined): void {
    if (secret && secret.length >= 8 && !this.secrets.includes(secret)) {
      this.secrets.push(secret);
      // Longest first so that a full key is replaced before its secret part.
      this.secrets.sort((a, b) => b.length - a.length);
    }
  }

  private redact(text: string): string {
    let out = text;
    for (const secret of this.secrets) {
      if (out.includes(secret)) {
        this.redactionHits++;
        out = out.split(secret).join('[redacted]');
      }
    }
    return out;
  }

  out(line: string): void {
    this.stdout.write(this.redact(`${line}\n`));
  }

  err(line: string): void {
    this.stderr.write(this.redact(`${line}\n`));
  }
}

export type ScanResult = 'pass' | 'fail' | 'incomplete' | 'error';

export interface ScanReport {
  result: ScanResult;
  exitCode: number;
  project: { id: string; name: string } | null;
  scan: { id: string; status: string; totalDependencies: number | null } | null;
  failOn: FailOn | null;
  vulnerabilityDataStatus: DataStatus | null;
  counts: Counts | null;
  /** Full sorted list of breaching findings (truncated by the formatters). */
  breaching: BreachItem[];
  warnings: string[];
  error: { code: string; message: string } | null;
}

export const JSON_BREACHING_LIMIT = 500;
export const TEXT_BREACHING_LIMIT = 20;

/** Contract 5.6: one object, fixed field order, every key present. */
export function formatJson(report: ScanReport): string {
  const levelCounts = (c: Counts['security']) => ({ low: c.low, medium: c.medium, high: c.high, critical: c.critical });
  const ordered = {
    schemaVersion: 1,
    result: report.result,
    exitCode: report.exitCode,
    project: report.project ? { id: report.project.id, name: report.project.name } : null,
    scan: report.scan
      ? { id: report.scan.id, status: report.scan.status, totalDependencies: report.scan.totalDependencies }
      : null,
    failOn: report.failOn,
    vulnerabilityDataStatus: report.vulnerabilityDataStatus,
    counts: report.counts
      ? { security: levelCounts(report.counts.security), license: levelCounts(report.counts.license) }
      : null,
    breaching: report.breaching
      .slice(0, JSON_BREACHING_LIMIT)
      .map((b) => ({ type: b.type, package: b.package, version: b.version, level: b.level, id: b.id })),
    breachingTruncated: report.breaching.length > JSON_BREACHING_LIMIT,
    warnings: [...report.warnings],
    error: report.error ? { code: report.error.code, message: report.error.message } : null,
  };
  return JSON.stringify(ordered);
}

const RESULT_LABEL: Readonly<Record<ScanResult, string>> = {
  pass: 'PASS',
  fail: 'FAIL',
  incomplete: 'INCOMPLETE',
  error: 'ERROR',
};

/** Contract 5.3 stdout summary (only for a completed scan: exit 0, 1, 5). */
export function formatTextSummary(report: ScanReport): string[] {
  const project = report.project ?? { id: '-', name: '-' };
  const scan = report.scan ?? { id: '-', status: '-', totalDependencies: null };
  const counts = report.counts;
  const line = (c: Counts['security'] | undefined) =>
    c ? `critical=${c.critical} high=${c.high} medium=${c.medium} low=${c.low}` : 'critical=0 high=0 medium=0 low=0';
  const lines = [
    `Project: ${project.name} (${project.id})`,
    `Scan: ${scan.id}`,
    `Status: ${scan.status}`,
    `Dependencies: ${scan.totalDependencies ?? '-'}`,
    `Security findings: ${line(counts?.security)}`,
    `License findings: ${line(counts?.license)}`,
    `Vulnerability data: ${report.vulnerabilityDataStatus ?? 'unknown'}`,
    `Fail on: ${report.failOn ?? '-'}`,
  ];
  if (report.failOn !== null && report.failOn !== 'none') {
    lines.push(`Findings at or above ${report.failOn}: ${report.breaching.length}`);
    for (const b of report.breaching.slice(0, TEXT_BREACHING_LIMIT)) {
      lines.push(`  ${b.package}@${b.version ?? '-'}  ${b.type}  ${b.level}  ${b.id}`);
    }
    if (report.breaching.length > TEXT_BREACHING_LIMIT) {
      lines.push(`  ... and ${report.breaching.length - TEXT_BREACHING_LIMIT} more`);
    }
  }
  lines.push(`Result: ${RESULT_LABEL[report.result]}`);
  return lines;
}

/** Usage error line (contract 2.2). */
export function usageErrorLine(message: string, command: string | null): string {
  const hint = command ? `oss-risk ${command} --help` : 'oss-risk --help';
  return `oss-risk: error: ${message} (see: ${hint})`;
}
