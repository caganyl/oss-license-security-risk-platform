/**
 * Optional OWASP ZAP connector (REQ-008 P-28; ADR-010 Karar 8; contract
 * section 7).
 *
 * Talks to an already running ZAP daemon through its JSON API with an
 * instance of the shared safe HTTP client: one origin (`ZAP_API_URL`, https
 * or loopback http), the API key only as the `X-ZAP-API-Key` purpose header
 * of that origin, no redirects, 8 MiB response cap, 30 s timeout.
 *
 * ZAP failures never fail the web scan: they become the engine state and a
 * `[zap]` warning line. One web scan uses ZAP at a time (in-process mutex,
 * AC-P28-6).
 */
import { systemClock, type AppClock } from '../lib/clock';
import { createSafeHttpClient, parseJsonBody, type SafeHttpClient, type SafeHttpSession } from '../lib/http/safeHttpClient';
import { type HostAllowlist, isAllowedRequestUrl, locationOf } from './allowlist';
import { cleanBlock, cleanText } from './rules';
import type { WebConfidence, WebFindingDraft, WebScanMode, WebSeverity, ZapState } from './types';

export const ZAP_TIMEOUT_MS = 30_000;
export const ZAP_MAX_BYTES = 8 * 1024 * 1024;
export interface ZapBudgets {
  spiderMs: number;
  passiveMs: number;
  activeMs: number;
  pollMs: number;
}
/** D-229: spider 5 min, passive queue 2 min, active scan 30 min; status poll every 2 s. */
export const ZAP_BUDGETS: Readonly<ZapBudgets> = Object.freeze({ spiderMs: 5 * 60_000, passiveMs: 2 * 60_000, activeMs: 30 * 60_000, pollMs: 2_000 });
/** Time kept free at the end of the job for the result write. */
export const ZAP_DEADLINE_MARGIN_MS = 60_000;
export const ZAP_ALERT_PAGE = 500;
export const ZAP_ALERT_PAGES = 10;
const MAX_EXAMPLE_URLS = 10;

export const ZAP_URL_INVALID_WARNING = 'ZAP_API_URL geçersiz; ZAP kullanılmayacak.';

export interface ZapConfig {
  origin: string;
  apiKey: string | null;
}

/**
 * `ZAP_API_URL` / `ZAP_API_KEY` (contract section 1). Blank URL -> null
 * silently; invalid -> null with one warning naming the variable.
 * `localhost` is mapped to `127.0.0.1` (the safe client's loopback rule).
 */
export function parseZapConfig(env: Readonly<Record<string, string | undefined>>, warn: (message: string) => void = console.warn): ZapConfig | null {
  const raw = (env.ZAP_API_URL ?? '').trim();
  if (raw === '') return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    warn(ZAP_URL_INVALID_WARNING);
    return null;
  }
  if (url.username || url.password) {
    warn(ZAP_URL_INVALID_WARNING);
    return null;
  }
  if (url.protocol === 'http:') {
    if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
    if (url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') {
      warn(ZAP_URL_INVALID_WARNING);
      return null;
    }
  } else if (url.protocol !== 'https:') {
    warn(ZAP_URL_INVALID_WARNING);
    return null;
  }
  const key = (env.ZAP_API_KEY ?? '').trim();
  return { origin: url.origin, apiKey: key === '' ? null : key };
}

export interface ZapRunInput {
  targetUrl: string;
  mode: WebScanMode;
  scanId: string;
  signal: AbortSignal;
  /** Monotonic end of the job time limit. */
  deadlineMs: number;
  allowlist: HostAllowlist;
}

export interface ZapRunResult {
  state: ZapState;
  findings: WebFindingDraft[];
  warnings: string[];
}

export interface ZapConnector {
  run(input: ZapRunInput): Promise<ZapRunResult>;
  close(): void;
}

export interface ZapConnectorOptions {
  config: ZapConfig;
  clock?: AppClock;
  /** Monotonic clock (default `performance.now`), injectable for tests. */
  monotonic?: () => number;
  budgets?: Partial<ZapBudgets>;
  env?: Readonly<Record<string, string | undefined>>;
}

/** ZAP call failed: carries a fixed code only. */
class ZapCallError extends Error {
  constructor(readonly code: string) {
    super(`ZAP call failed (${code})`);
    this.name = 'ZapCallError';
  }
}

interface ZapAlert {
  pluginId?: unknown;
  alert?: unknown;
  name?: unknown;
  risk?: unknown;
  riskcode?: unknown;
  confidence?: unknown;
  url?: unknown;
  description?: unknown;
  solution?: unknown;
  cweid?: unknown;
  tags?: unknown;
}

const RISK: Readonly<Record<string, WebSeverity>> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' };
const RISK_NAMES: Readonly<Record<string, WebSeverity>> = { high: 'high', medium: 'medium', low: 'low', informational: 'info' };
const CONFIDENCE: Readonly<Record<string, WebConfidence | 'false_positive'>> = {
  '0': 'false_positive',
  'false positive': 'false_positive',
  '1': 'low',
  low: 'low',
  '2': 'medium',
  medium: 'medium',
  '3': 'high',
  high: 'high',
  '4': 'high',
  confirmed: 'high',
};

const SEVERITY_RANK: Readonly<Record<WebSeverity, number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Maps ZAP alerts to findings (contract section 7, AC-P28-5): grouped by
 * plugin id, false positives dropped, URLs outside the allowlist dropped,
 * at most 10 example URLs. Pure.
 */
export function mapZapAlerts(alerts: readonly ZapAlert[], allowlist: HostAllowlist): WebFindingDraft[] {
  const groups = new Map<string, { alert: ZapAlert; severity: WebSeverity; confidence: WebConfidence; urls: string[] }>();
  for (const a of alerts) {
    const pluginId = String(a.pluginId ?? '').trim();
    if (!/^\d{1,9}$/.test(pluginId)) continue;
    const rawConfidence = String(a.confidence ?? '').trim().toLowerCase();
    const confidence = CONFIDENCE[rawConfidence] ?? 'medium';
    if (confidence === 'false_positive') continue;
    const severity = RISK[String(a.riskcode ?? '').trim()] ?? RISK_NAMES[String(a.risk ?? '').trim().toLowerCase()] ?? 'info';
    const url = typeof a.url === 'string' ? a.url : '';
    if (!isAllowedRequestUrl(url, allowlist)) continue;
    const location = locationOf(url);
    const group = groups.get(pluginId);
    if (!group) {
      groups.set(pluginId, { alert: a, severity, confidence, urls: [location] });
      continue;
    }
    if (!group.urls.includes(location)) group.urls.push(location);
    // The most severe instance decides the group's severity.
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[group.severity]) group.severity = severity;
  }
  const findings: WebFindingDraft[] = [];
  for (const [pluginId, g] of groups) {
    const title = cleanText(typeof g.alert.alert === 'string' ? g.alert.alert : typeof g.alert.name === 'string' ? g.alert.name : `ZAP ${pluginId}`, 300) ?? `ZAP ${pluginId}`;
    const cwe = Number(g.alert.cweid);
    const owasp = owaspFromTags(g.alert.tags);
    const shown = g.urls.slice(0, MAX_EXAMPLE_URLS);
    findings.push({
      ruleId: `ZAP-${pluginId}`,
      source: 'zap',
      category: 'zap',
      severity: g.severity,
      confidence: g.confidence,
      title,
      description: cleanBlock(typeof g.alert.description === 'string' ? g.alert.description : '') || title,
      recommendation: cleanBlock(typeof g.alert.solution === 'string' ? g.alert.solution : '') || 'ZAP açıklamasına bakın.',
      location: g.urls[0] ?? null,
      evidence: cleanText(`${g.urls.length} adres: ${shown.join(', ')}${g.urls.length > shown.length ? ', …' : ''}`, 2000),
      cweId: Number.isInteger(cwe) && cwe > 0 ? cwe : null,
      owasp,
      key: `zap:${pluginId}`,
    });
  }
  return findings;
}

/** `OWASP_2021_A05` tag -> `A05:2021`; first match. */
export function owaspFromTags(tags: unknown): string | null {
  if (!tags || typeof tags !== 'object') return null;
  for (const key of Object.keys(tags as Record<string, unknown>)) {
    const m = /^OWASP_2021_A(0[1-9]|10)$/.exec(key);
    if (m) return `A${m[1]}:2021`;
  }
  return null;
}

/** Resolves with `p`, or rejects with the signal's reason when it aborts first. */
function untilAborted(p: Promise<unknown>, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      () => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      },
      () => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      },
    );
  });
}

/** ZAP context include regex: the target host on any port, http or https (contract section 7). */
export function scopeRegex(targetUrl: string): string {
  const host = new URL(targetUrl).hostname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return `^https?://${host}(:\\d+)?(/.*)?$`;
}

export function createZapConnector(options: ZapConnectorOptions): ZapConnector {
  const clock = options.clock ?? systemClock;
  const monotonic = options.monotonic ?? (() => performance.now());
  const budgets = { ...ZAP_BUDGETS, ...options.budgets };
  const apiKey = options.config.apiKey;
  const core: SafeHttpClient = createSafeHttpClient({
    origins: { zap: options.config.origin },
    purposes: {
      zap: {
        originKey: 'zap',
        method: 'GET',
        redirect: 'none',
        maxBytes: ZAP_MAX_BYTES,
        accept: 'application/json',
        acceptEncoding: 'identity',
        pathRule: (url) => url.pathname.startsWith('/JSON/'),
        ...(apiKey !== null ? { extraHeaders: () => ({ 'X-ZAP-API-Key': apiKey }) } : {}),
        kind: 'json',
      },
    },
    timeoutMs: ZAP_TIMEOUT_MS,
    concurrency: 1,
    limits: { maxRetries: 1, retryBackoffMs: [1000], maxRetryAfterMs: 5000, failureThreshold: 5 },
    userAgentSuffix: 'zap-connector',
    proxyWarningSubject: 'ZAP bağlayıcısı',
    env: options.env,
    clock,
  });

  // AC-P28-6: one web scan uses ZAP at a time.
  let queue: Promise<unknown> = Promise.resolve();

  async function call(session: SafeHttpSession, path: string, params: Record<string, string>, signal: AbortSignal): Promise<Record<string, unknown>> {
    const url = new URL(`/JSON/${path}/`, options.config.origin);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const result = await session.request('zap', url.href, { signal });
    if (result.kind === 'ok') {
      const parsed = parseJsonBody(result);
      if (!parsed.ok) throw new ZapCallError(parsed.code);
      return parsed.json;
    }
    if (result.kind === 'not_found') throw new ZapCallError(`HTTP_${result.status}`);
    if (result.kind === 'too_large') throw new ZapCallError('TOO_LARGE');
    throw new ZapCallError(result.code);
  }

  async function runExclusive(input: ZapRunInput): Promise<ZapRunResult> {
    const { signal } = input;
    const session = core.session();
    const warnings: string[] = [];
    let partial = false;
    const remaining = (budget: number) => Math.min(budget, input.deadlineMs - ZAP_DEADLINE_MARGIN_MS - monotonic());

    /** Polls `statusPath` until 100 or the budget ends (then `stopPath`). Returns false on timeout. */
    const pollUntilDone = async (statusPath: string, stopPath: string, scanId: string, budget: number): Promise<boolean> => {
      const end = monotonic() + remaining(budget);
      for (;;) {
        signal.throwIfAborted();
        const status = await call(session, statusPath, { scanId }, signal);
        if (Number(status.status) >= 100) return true;
        if (monotonic() >= end) {
          await call(session, stopPath, { scanId }, signal).catch(() => undefined);
          return false;
        }
        await clock.sleep(budgets.pollMs, signal);
      }
    };

    try {
      await call(session, 'core/view/version', {}, signal);
    } catch (err) {
      if (signal.aborted) throw signal.reason;
      const code = err instanceof ZapCallError ? err.code : 'NETWORK_ERROR';
      return { state: 'unavailable', findings: [], warnings: [`[zap] ZAP API'ye ulaşılamadı (${code}); yalnız yerleşik kontroller çalıştı.`] };
    }

    try {
      await call(session, 'core/action/newSession', { name: `oss-risk-${input.scanId}`, overwrite: 'true' }, signal);
      // Security review M-2: ZAP is held to the target host through a context
      // (spider and active scan run in scope only) and never follows a
      // redirect when seeding. The ZAP host itself should still be isolated.
      const contextName = `oss-risk-${input.scanId}`;
      const context = await call(session, 'context/action/newContext', { contextName }, signal);
      const contextId = String(context.contextId ?? '');
      if (!/^\d+$/.test(contextId)) throw new ZapCallError('BAD_CONTEXT_ID');
      await call(session, 'context/action/includeInContext', { contextName, regex: scopeRegex(input.targetUrl) }, signal);
      await call(session, 'context/action/setContextInScope', { contextName, booleanInScope: 'true' }, signal);
      // Security review M-3: the spider never submits forms (passive must stay read-only).
      await call(session, 'spider/action/setOptionProcessForm', { Boolean: 'false' }, signal);
      await call(session, 'spider/action/setOptionPostForm', { Boolean: 'false' }, signal);
      await call(session, 'core/action/accessUrl', { url: input.targetUrl, followRedirects: 'false' }, signal);

      if (remaining(budgets.spiderMs) > 0) {
        const spider = await call(session, 'spider/action/scan', { url: input.targetUrl, recurse: 'true', subtreeOnly: 'true', contextName }, signal);
        const spiderId = String(spider.scan ?? '');
        if (!/^\d+$/.test(spiderId)) throw new ZapCallError('BAD_SCAN_ID');
        if (!(await pollUntilDone('spider/view/status', 'spider/action/stop', spiderId, budgets.spiderMs))) partial = true;
      } else {
        partial = true;
      }

      // Passive queue drains (AC-P28-4).
      const passiveEnd = monotonic() + Math.max(0, remaining(budgets.passiveMs));
      for (;;) {
        signal.throwIfAborted();
        const records = await call(session, 'pscan/view/recordsToScan', {}, signal);
        if (Number(records.recordsToScan) <= 0) break;
        if (monotonic() >= passiveEnd) {
          partial = true;
          break;
        }
        await clock.sleep(budgets.pollMs, signal);
      }

      if (input.mode === 'active') {
        if (remaining(budgets.activeMs) > 0) {
          const ascan = await call(session, 'ascan/action/scan', { url: input.targetUrl, recurse: 'true', inScopeOnly: 'true', contextId }, signal);
          const ascanId = String(ascan.scan ?? '');
          if (!/^\d+$/.test(ascanId)) throw new ZapCallError('BAD_SCAN_ID');
          if (!(await pollUntilDone('ascan/view/status', 'ascan/action/stop', ascanId, budgets.activeMs))) partial = true;
        } else {
          partial = true;
        }
      }

      const alerts: ZapAlert[] = [];
      const baseurl = new URL(input.targetUrl).origin;
      for (let page = 0; page < ZAP_ALERT_PAGES; page++) {
        const res = await call(session, 'alert/view/alerts', { baseurl, start: String(page * ZAP_ALERT_PAGE), count: String(ZAP_ALERT_PAGE) }, signal);
        const batch = Array.isArray(res.alerts) ? (res.alerts as ZapAlert[]) : [];
        alerts.push(...batch);
        if (batch.length < ZAP_ALERT_PAGE) break;
      }
      if (partial) warnings.push('[zap] ZAP taraması süre sınırında durduruldu; sonuçlar kısmi.');
      return { state: partial ? 'partial' : 'complete', findings: mapZapAlerts(alerts, input.allowlist), warnings };
    } catch (err) {
      if (signal.aborted) throw signal.reason;
      const code = err instanceof ZapCallError ? err.code : 'NETWORK_ERROR';
      return { state: 'failed', findings: [], warnings: [`[zap] ZAP adımı başarısız oldu (${code}).`] };
    }
  }

  return {
    run(input) {
      // Security review M-4: waiting for the lock honours the job signal, so a
      // queued scan stops at its time limit / shutdown instead of after every
      // ZAP run ahead of it. The chain never rejects.
      const previous = queue;
      let release: () => void = () => undefined;
      const mine = new Promise<void>((resolve) => {
        release = resolve;
      });
      queue = previous.then(() => mine);
      return (async () => {
        try {
          await untilAborted(previous, input.signal);
          return await runExclusive(input);
        } finally {
          release();
        }
      })();
    },
    close() {
      core.close();
    },
  };
}
