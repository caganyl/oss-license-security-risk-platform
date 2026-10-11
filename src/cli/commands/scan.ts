/**
 * `oss-risk scan` (REQ-007 contract section 4, ADR-009 Karar 3–5).
 *
 * Flow: address + key checks (no network) → project resolution → one
 * `POST /api/scans` (never retried) → polling every 2 s within `--timeout`
 * → findings → vulnerability data status (never an exit code by itself) →
 * `--fail-on` decision. 2/3/4 stop the flow immediately.
 */
import type { ScanArgs } from '../args';
import { ApiClient, isOk, mapHttpError, parseJson, serverMessage } from '../client';
import { apiKeySecretPart, resolveApiKey, resolveTarget } from '../config';
import { dataStatusFrom, decide, evaluateFindings } from '../evaluate';
import { CliError, EXIT_RUNTIME, EXIT_USAGE } from '../exitCodes';
import type { CliDeps } from '../main';
import { cleanText, formatJson, formatTextSummary, type Output, type ScanReport } from '../output';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TERMINAL: ReadonlySet<string> = new Set(['completed', 'failed', 'cancelled', 'timeout']);
export const POLL_INTERVAL_MS = 2_000;

type Row = Record<string, unknown>;

function dataObject(body: unknown, method: string, path: string): Row {
  const data = body && typeof body === 'object' ? (body as Row).data : undefined;
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new CliError('unexpected_response', EXIT_RUNTIME, `${method} ${path} returned an unexpected body`);
  }
  return data as Row;
}

function dataArray(body: unknown, method: string, path: string): unknown[] {
  const data = body && typeof body === 'object' ? (body as Row).data : undefined;
  if (!Array.isArray(data)) {
    throw new CliError('unexpected_response', EXIT_RUNTIME, `${method} ${path} returned an unexpected body`);
  }
  return data;
}

function totalDependencies(value: unknown): number | null {
  const n = typeof value === 'string' && /^[0-9]+$/.test(value) ? Number(value) : value;
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 ? n : null;
}

export async function runScan(args: ScanArgs, deps: CliDeps, out: Output): Promise<number> {
  const json = args.format === 'json';
  const report: ScanReport = {
    result: 'error',
    exitCode: EXIT_RUNTIME,
    project: null,
    scan: null,
    failOn: args.failOn,
    vulnerabilityDataStatus: null,
    counts: null,
    breaching: [],
    warnings: [],
    error: null,
  };
  const progress = (line: string): void => {
    if (!json) out.err(`oss-risk: ${line}`);
  };
  const warn = (text: string): void => {
    report.warnings.push(text);
    if (!json) out.err(`oss-risk: warning: ${text}`);
  };

  try {
    // 1. Configuration (exit 2, no network).
    const target = resolveTarget(args.url, deps.env, 'scan');
    const key = await resolveApiKey(deps.env, deps.readKeyFile);
    out.addSecret(key);
    out.addSecret(apiKeySecretPart(key));
    const api = new ApiClient(target, deps.request, deps.version, deps.sleep);
    const auth = { bearer: key };

    // 2. Project.
    const wanted = args.project.trim();
    let projectId: string;
    let projectName: string | null = null;
    if (UUID_RE.test(wanted)) {
      projectId = wanted;
    } else {
      const projects = dataArray(await api.getJson('/api/projects', auth), 'GET', '/api/projects');
      const matches = projects.filter(
        (p): p is Row => p !== null && typeof p === 'object' && (p as Row).name === wanted && typeof (p as Row).id === 'string',
      );
      if (matches.length === 0) throw new CliError('project_not_found', EXIT_USAGE, 'project not found');
      if (matches.length > 1) {
        throw new CliError('project_ambiguous', EXIT_USAGE, 'project name is ambiguous; use the project id');
      }
      projectId = matches[0].id as string;
      projectName = cleanText(matches[0].name);
    }
    report.project = { id: cleanText(projectId), name: projectName ?? '' };

    // 3. Start the scan: one attempt only.
    const created = await api.post('/api/scans', { ...auth, body: { projectId } });
    if (created.status === 400) {
      const msg = serverMessage(created);
      throw new CliError('project_rejected', EXIT_USAGE, `project rejected by the server${msg ? `: ${msg}` : ''}`);
    }
    if (created.status === 404) throw new CliError('project_not_found', EXIT_USAGE, 'project not found');
    if (!isOk(created)) throw mapHttpError('POST', '/api/scans', created);
    const scanData = dataObject(parseJson('POST', '/api/scans', created), 'POST', '/api/scans');
    if (typeof scanData.id !== 'string' || !UUID_RE.test(scanData.id)) {
      throw new CliError('unexpected_response', EXIT_RUNTIME, 'POST /api/scans returned an unexpected body');
    }
    const scanId = scanData.id.toLowerCase();
    const started = deps.now();
    if (projectName === null && typeof scanData.project_name === 'string') projectName = cleanText(scanData.project_name);
    report.scan = {
      id: scanId,
      status: cleanText(scanData.status ?? 'pending'),
      totalDependencies: totalDependencies(scanData.total_dependencies),
    };
    let queuedPrinted = false;
    const printQueued = (): void => {
      if (queuedPrinted || projectName === null) return;
      queuedPrinted = true;
      report.project = { id: report.project!.id, name: projectName };
      progress(`scan ${scanId} queued for project ${projectName}`);
    };
    printQueued();

    // 4. Poll until a terminal status or the --timeout budget is spent.
    const scanPath = `/api/scans/${scanId}`;
    let lastStatus: string | null = null;
    let scanRow: Row;
    for (;;) {
      scanRow = dataObject(await api.getJson(scanPath, auth), 'GET', scanPath);
      if (projectName === null) projectName = cleanText(typeof scanRow.project_name === 'string' ? scanRow.project_name : '-');
      if (typeof scanRow.project_id === 'string' && UUID_RE.test(scanRow.project_id)) {
        report.project = { id: scanRow.project_id.toLowerCase(), name: projectName };
      }
      printQueued();
      const status = typeof scanRow.status === 'string' ? scanRow.status : 'unknown';
      report.scan = { id: scanId, status: cleanText(status), totalDependencies: totalDependencies(scanRow.total_dependencies) };
      if (status !== lastStatus) {
        progress(`scan ${scanId} status ${cleanText(status)}`);
        lastStatus = status;
      }
      if (TERMINAL.has(status)) break;
      if (deps.now() - started >= args.timeoutSeconds * 1000) {
        throw new CliError('wait_timeout', EXIT_RUNTIME, `timed out waiting for scan ${scanId}; the scan continues on the server`);
      }
      await deps.sleep(POLL_INTERVAL_MS);
    }
    if (lastStatus !== 'completed') {
      const detail = typeof scanRow.error_message === 'string' ? cleanText(scanRow.error_message, 500) : null;
      throw new CliError(
        'scan_failed',
        EXIT_RUNTIME,
        `scan ${scanId} ended with status ${cleanText(lastStatus)}${detail !== null ? `: ${detail}` : ''}`,
      );
    }

    // 5. Findings (single response, no paging).
    const findingsPath = `/api/scans/${scanId}/findings`;
    const findings = dataArray(
      await api.getJson(findingsPath, { ...auth, tooLargeMessage: 'findings response exceeds 32 MiB' }),
      'GET',
      findingsPath,
    );
    const evaluation = evaluateFindings(findings, args.failOn);
    report.counts = evaluation.counts;
    report.breaching = evaluation.breaching;

    // 6. Vulnerability data status: every failure means `unknown`, never an exit code.
    let statusBody: unknown = null;
    try {
      statusBody = await api.getJson('/api/vulnerability-data/status', auth);
    } catch (err) {
      if (!(err instanceof CliError)) throw err;
    }
    const dataStatus = dataStatusFrom(statusBody, scanId);
    report.vulnerabilityDataStatus = dataStatus;

    const decision = decide(args.failOn, evaluation.breaching.length, dataStatus, args.allowIncomplete, scanId);
    for (const w of decision.warnings) warn(w);
    report.result = decision.result;
    report.exitCode = decision.exitCode;
    if (json) out.out(formatJson(report));
    else for (const line of formatTextSummary(report)) out.out(line);
    return decision.exitCode;
  } catch (err) {
    if (!(err instanceof CliError)) throw err;
    report.result = 'error';
    report.exitCode = err.exitCode;
    report.error = { code: err.code, message: cleanText(err.message, 600) };
    if (json) out.out(formatJson(report));
    else out.err(`oss-risk: error: ${err.message}`);
    return err.exitCode;
  }
}
