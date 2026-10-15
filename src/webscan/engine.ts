/**
 * Web scan orchestrator (REQ-008 P-26, P-28; ADR-010 Karar 6, 7, 8).
 *
 * Order: main page (same-host redirects) -> page rules -> soft-404 probe ->
 * (in parallel, bounded by the probe client) http variant, CORS x2, error
 * probes x2, sensitive file probes, directory listing candidates, script
 * downloads -> legacy TLS handshake -> optional ZAP step. The engine never
 * touches the database: the worker writes the outcome (ADR-010 Karar 1).
 *
 * A job abort (time limit / shutdown) is rethrown with the job signal's
 * reason. An unreachable main page is a transient failure
 * (`WebTargetUnreachableError`, AC-P26-3); a certificate failure is a finding
 * (AC-P26-4).
 */
import crypto from 'node:crypto';
import { systemClock, type AppClock } from '../lib/clock';
import { type HostAllowlist, locationOf, normalizeWebUrl } from './allowlist';
import { checkPageContent, detectDirectoryListing, detectErrorPage, directoryListingFinding, errorPageFinding } from './checks/content';
import { EXPOSURE_PROBES, evaluateProbe, probeBases } from './checks/exposure';
import { checkCookies, checkCors, checkDisclosureHeaders, checkSecurityHeaders, CORS_PROBE_ORIGIN, isHtml } from './checks/headers';
import { certificateFinding, checkCertificateExpiry, checkHttpRedirect, checkLegacyProtocol, checkPlainHttp } from './checks/transport';
import { documentBase, extractTags } from './html';
import { dedupeComponents, detectFromHtml, detectFromScriptBody, detectFromScriptUrl, scriptUrls } from './libraries';
import { MAX_REQUESTS_PER_SCAN, type ProbeClient, createProbeClient, fetchMainPage } from './probeClient';
import { probeLegacyTls } from './tlsProbe';
import type { DetectedComponent, EngineState, ProbeResponse, ProbeTlsInfo, WebFindingDraft, WebScanMode, ZapState } from './types';
import type { ZapConnector } from './zap';

export const PAGE_MAX_BYTES = 2 * 1024 * 1024;
export const SCRIPT_MAX_BYTES = 4 * 1024 * 1024;
export const PROBE_MAX_BYTES = 256 * 1024;
export const MAX_SCRIPT_DOWNLOADS = 20;
export const MAX_DIRECTORY_CANDIDATES = 3;

/** The main page could not be reached at all: transient (retried, AC-P26-3). */
export class WebTargetUnreachableError extends Error {
  constructor(readonly code: string) {
    super(`Hedef adrese ulaşılamadı (${code}).`);
    this.name = 'WebTargetUnreachableError';
  }
}

export interface WebScanTarget {
  scanId: string;
  projectId: string;
  url: string;
  mode: WebScanMode;
}

export interface WebScanRunOptions {
  signal: AbortSignal;
  /** Monotonic (`performance.now()`) end of the job time limit. */
  deadlineMs: number;
}

export interface WebScanOutcome {
  findings: WebFindingDraft[];
  components: DetectedComponent[];
  /** `[web]` / `[zap]` lines (contract section 8). */
  warnings: string[];
  requests: number;
  requestLimitReached: boolean;
  finalUrl: string | null;
  tls: ProbeTlsInfo | null;
  builtin: EngineState;
  zap: ZapState;
  zapMode: WebScanMode | null;
}

export interface WebScanner {
  readonly allowlist: HostAllowlist;
  /** True when the ZAP step is configured. */
  readonly zapConfigured: boolean;
  scan(target: WebScanTarget, options: WebScanRunOptions): Promise<WebScanOutcome>;
  close(): void;
}

export interface WebScannerOptions {
  allowlist: HostAllowlist;
  timeoutMs?: number;
  maxRequests?: number;
  zap?: ZapConnector | null;
  clock?: AppClock;
  env?: Readonly<Record<string, string | undefined>>;
  /** Injection point of the legacy TLS probe (tests). */
  legacyTlsProbe?: typeof probeLegacyTls;
}

const sha256 = (body: Buffer) => crypto.createHash('sha256').update(body).digest('hex');
const decoder = new TextDecoder('utf-8', { fatal: false });
const textOf = (response: ProbeResponse) => decoder.decode(response.body);

/** One finding per (rule, key) (D-236): the first wins. */
function dedupeFindings(findings: readonly WebFindingDraft[]): WebFindingDraft[] {
  const seen = new Set<string>();
  const out: WebFindingDraft[] = [];
  for (const f of findings) {
    const id = `${f.ruleId}|${f.key}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(f);
  }
  return out;
}

/** Folder of each same-host script (not the origin root), at most `MAX_DIRECTORY_CANDIDATES`. */
function directoryCandidates(scripts: readonly URL[], pageHost: string, root: string): string[] {
  const dirs: string[] = [];
  for (const s of scripts) {
    if (s.host.toLowerCase() !== pageHost) continue;
    const dir = new URL('.', `${s.origin}${s.pathname}`).href;
    if (dir === root || dirs.includes(dir)) continue;
    dirs.push(dir);
    if (dirs.length >= MAX_DIRECTORY_CANDIDATES) break;
  }
  return dirs;
}

export function createWebScanner(options: WebScannerOptions): WebScanner {
  const clock = options.clock ?? systemClock;
  const zap = options.zap ?? null;
  const legacy = options.legacyTlsProbe ?? probeLegacyTls;

  async function scan(target: WebScanTarget, run: WebScanRunOptions): Promise<WebScanOutcome> {
    const { signal } = run;
    // TOCTOU (AC-P25-7): the caller maps WebUrlError to a permanent failure.
    const url = normalizeWebUrl(target.url, options.allowlist);
    const client: ProbeClient = createProbeClient({
      allowlist: options.allowlist,
      timeoutMs: options.timeoutMs,
      maxRequests: options.maxRequests ?? MAX_REQUESTS_PER_SCAN,
      env: options.env,
    });
    try {
      return await scanWith(client, target, url, run);
    } finally {
      client.close();
      signal.throwIfAborted();
    }
  }

  async function scanWith(client: ProbeClient, target: WebScanTarget, url: string, run: WebScanRunOptions): Promise<WebScanOutcome> {
    const { signal } = run;
    const findings: WebFindingDraft[] = [];
    const components: DetectedComponent[] = [];
    const warnings: string[] = [];
    let builtin: EngineState = 'complete';

    const get = (u: string, maxBytes: number, origin?: string) => client.request(u, { signal, maxBytes, ...(origin !== undefined ? { origin } : {}) });
    const ok = async (u: string, maxBytes: number, origin?: string): Promise<ProbeResponse | null> => {
      const outcome = await get(u, maxBytes, origin);
      return outcome.ok ? outcome.response : null;
    };

    const main = await fetchMainPage(client, url, signal, PAGE_MAX_BYTES);
    const page = main.final;
    const targetUrl = new URL(url);

    if (!page) {
      const failure = main.failure?.failure;
      if (!failure || !failure.tlsCertificate) throw new WebTargetUnreachableError(failure?.code ?? 'NETWORK_ERROR');
      // AC-P26-4: certificate failure is a finding, the scan completes.
      findings.push(certificateFinding(url, failure.code));
      warnings.push(`[web] TLS sertifikası doğrulanamadığı için içerik kontrolleri yapılamadı (${failure.code}).`);
      builtin = 'partial';
      if (targetUrl.protocol === 'https:') {
        const [variant, accepted] = await Promise.all([
          targetUrl.port === '' ? ok(httpVariant(targetUrl), PROBE_MAX_BYTES) : Promise.resolve(null),
          client.usesProxy(url) ? Promise.resolve(null) : legacy(url, options.allowlist, signal),
        ]);
        findings.push(...checkHttpRedirect(variant), ...checkLegacyProtocol(url, accepted));
      }
      // The main page failure is already reported by the TLS line above.
      return finish(client, target, run, { findings, components, warnings, builtin, finalUrl: locationOf(url), tls: null, knownFailures: 1 });
    }

    if (main.crossHostRedirect) warnings.push('[web] Ana sayfa başka bir hosta yönlendiriyor; o host taranmadı.');
    const pageUrl = page.url;
    const page2 = new URL(pageUrl);
    const pageHost = page2.host.toLowerCase();
    const https = page2.protocol === 'https:';

    // Page-level rules.
    findings.push(...checkPlainHttp(page));
    if (https) findings.push(...checkCertificateExpiry(pageUrl, page.tls, clock.now()));
    findings.push(...checkSecurityHeaders(page), ...checkDisclosureHeaders(page), ...checkCookies(main.chain));
    const html = isHtml(page) ? textOf(page) : '';
    const tags = html ? extractTags(html) : [];
    const base = documentBase(tags, pageUrl);
    if (html) findings.push(...checkPageContent(tags, pageUrl));
    const pageError = detectErrorPage(textOf(page));
    if (pageError) findings.push(errorPageFinding(pageUrl, pageError));
    const pageDir = detectDirectoryListing(textOf(page));
    if (pageDir) findings.push(directoryListingFinding(pageUrl, pageDir));
    components.push(...detectFromHtml(html, locationOf(pageUrl)));

    // Soft-404 reference (D-219) before the file probes are evaluated.
    const random = crypto.randomBytes(8).toString('hex');
    const root = `${page2.origin}/`;
    const soft = await ok(`${root}oss-risk-${random}`, PROBE_MAX_BYTES);
    const softHash = soft && soft.status === 200 ? sha256(soft.body) : null;

    const scripts = scriptUrls(tags, base);
    const toDownload: URL[] = [];
    for (const s of scripts) {
      const detected = detectFromScriptUrl(s);
      if (detected) components.push(detected);
      else if (s.host.toLowerCase() === pageHost && toDownload.length < MAX_SCRIPT_DOWNLOADS) toDownload.push(s);
    }

    const bases = probeBases(url);
    const dirBase = bases[bases.length - 1];
    const tasks: Array<Promise<void>> = [];
    const task = (fn: () => Promise<void>) => tasks.push(fn());

    if (https && page2.port === '') {
      task(async () => {
        findings.push(...checkHttpRedirect(await ok(httpVariant(page2), PROBE_MAX_BYTES)));
      });
    }
    task(async () => {
      const [foreign, nullOrigin] = await Promise.all([ok(pageUrl, PROBE_MAX_BYTES, CORS_PROBE_ORIGIN), ok(pageUrl, PROBE_MAX_BYTES, 'null')]);
      findings.push(...checkCors(foreign, nullOrigin));
    });
    for (const path of [`oss-risk-${random}.aspx`, '%3C%3E']) {
      task(async () => {
        const r = await ok(`${dirBase}${path}`, PROBE_MAX_BYTES);
        const label = r ? detectErrorPage(textOf(r)) : null;
        if (r && label) findings.push(errorPageFinding(r.url, label));
      });
    }
    for (const b of bases) {
      for (const probe of EXPOSURE_PROBES) {
        task(async () => {
          const r = await ok(new URL(probe.path, b).href, PROBE_MAX_BYTES);
          if (!r) return;
          const f = evaluateProbe(probe, r, sha256(r.body), softHash);
          if (f) findings.push(f);
        });
      }
    }
    for (const dir of directoryCandidates(scripts, pageHost, root)) {
      task(async () => {
        const r = await ok(dir, PROBE_MAX_BYTES);
        const label = r && r.status === 200 ? detectDirectoryListing(textOf(r)) : null;
        if (r && label) findings.push(directoryListingFinding(r.url, label));
      });
    }
    for (const s of toDownload) {
      task(async () => {
        const r = await ok(s.href, SCRIPT_MAX_BYTES);
        if (r && r.status === 200) components.push(...detectFromScriptBody(textOf(r), locationOf(s)));
      });
    }
    let accepted: string | null = null;
    if (https && !client.usesProxy(pageUrl)) {
      task(async () => {
        accepted = await legacy(pageUrl, options.allowlist, signal);
      });
    }
    // Every task settles; a job abort rejects and is rethrown below.
    const settled = await Promise.allSettled(tasks);
    signal.throwIfAborted();
    const rejected = settled.find((s) => s.status === 'rejected');
    if (rejected) throw (rejected as PromiseRejectedResult).reason;
    findings.push(...checkLegacyProtocol(pageUrl, accepted));

    return finish(client, target, run, { findings, components, warnings, builtin, finalUrl: locationOf(pageUrl), tls: https ? page.tls : null });
  }

  async function finish(
    client: ProbeClient,
    target: WebScanTarget,
    run: WebScanRunOptions,
    partial: { findings: WebFindingDraft[]; components: DetectedComponent[]; warnings: string[]; builtin: EngineState; finalUrl: string | null; tls: ProbeTlsInfo | null; knownFailures?: number },
  ): Promise<WebScanOutcome> {
    const { warnings } = partial;
    let builtin = partial.builtin;
    if (client.stats.budgetExhausted) {
      builtin = 'partial';
      warnings.push(`[web] İstek sınırına (${options.maxRequests ?? MAX_REQUESTS_PER_SCAN}) ulaşıldı; bazı kontroller atlandı.`);
    }
    const failures = client.stats.failures - (partial.knownFailures ?? 0);
    if (failures > 0) warnings.push(`[web] ${failures} istek başarısız oldu.`);

    let zapState: ZapState = 'not_configured';
    let zapMode: WebScanMode | null = null;
    const findings = [...partial.findings];
    if (zap) {
      zapMode = target.mode;
      const result = await zap.run({ targetUrl: partial.finalUrl ?? target.url, mode: target.mode, scanId: target.scanId, signal: run.signal, deadlineMs: run.deadlineMs, allowlist: options.allowlist });
      zapState = result.state;
      findings.push(...result.findings);
      warnings.push(...result.warnings);
    }
    return {
      findings: dedupeFindings(findings),
      components: dedupeComponents(partial.components),
      warnings,
      requests: client.stats.requests,
      requestLimitReached: client.stats.budgetExhausted,
      finalUrl: partial.finalUrl,
      tls: partial.tls,
      builtin,
      zap: zapState,
      zapMode,
    };
  }

  return {
    allowlist: options.allowlist,
    zapConfigured: zap !== null,
    scan,
    close() {
      zap?.close();
    },
  };
}

/** `http://` variant of an https URL on the default port (WEB-TLS-002). */
function httpVariant(url: URL): string {
  const u = new URL(url.href);
  u.protocol = 'http:';
  u.port = '';
  return u.href;
}

