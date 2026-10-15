/**
 * Sensitive file probes and their content validators (REQ-008 AC-P26-6,
 * D-219, D-220, D-235; contract section 4.3). Pure functions: the engine
 * fetches `path` under each base and passes the response here.
 *
 * Validators read the body in memory only; nothing of the content is kept
 * except the evidence text, which carries key names, never values
 * (AC-P26-8).
 */
import { locationOf } from '../allowlist';
import { finding } from '../rules';
import type { ProbeResponse, WebFindingDraft } from '../types';

export interface ExposureProbe {
  ruleId: string;
  path: string;
  /** Evidence text when the body passes, or null. */
  validate(body: Buffer, response: ProbeResponse): string | null;
}

const decoder = new TextDecoder('utf-8', { fatal: false });
const text = (body: Buffer) => decoder.decode(body.subarray(0, 256 * 1024));
const looksLikeHtml = (t: string) => /^\s*(<!doctype html|<html|<head|<body)/i.test(t);

function parseJsonObject(body: Buffer): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text(body).replace(/^\uFEFF/, ''));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** `.env`: ≥ 50 % of the non-blank, non-comment lines are `KEY=…`; evidence = first 5 key names. */
export function validateDotEnv(body: Buffer): string | null {
  const t = text(body);
  if (looksLikeHtml(t)) return null;
  const lines = t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'));
  if (lines.length === 0) return null;
  const keys: string[] = [];
  for (const line of lines) {
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]{0,100})\s*=/.exec(line);
    if (m) keys.push(m[1]);
  }
  if (keys.length === 0 || keys.length * 2 < lines.length) return null;
  return `${keys.length} anahtar; ör. ${keys.slice(0, 5).join(', ')}`;
}

const APPSETTINGS_KEYS = ['ConnectionStrings', 'Logging', 'AllowedHosts', 'Jwt', 'Kestrel'];

export function validateAppSettings(body: Buffer): string | null {
  const json = parseJsonObject(body);
  if (!json) return null;
  const present = APPSETTINGS_KEYS.filter((k) => Object.prototype.hasOwnProperty.call(json, k));
  return present.length > 0 ? `Üst düzey anahtarlar: ${present.join(', ')}` : null;
}

function openApiVersion(body: Buffer): string | null {
  const json = parseJsonObject(body);
  if (!json) return null;
  const v = json.openapi ?? json.swagger;
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  return `OpenAPI ${String(v).slice(0, 20)}`;
}

const includes = (needle: string, evidence: string) => (body: Buffer) => (text(body).includes(needle) ? evidence : null);

/** Contract section 4.3, in probe order. */
export const EXPOSURE_PROBES: readonly ExposureProbe[] = [
  { ruleId: 'WEB-EXP-001', path: '.git/HEAD', validate: (b) => (/^(ref: refs\/|[0-9a-f]{40}\s*$)/.test(text(b)) ? 'HEAD dosyası okunabiliyor' : null) },
  { ruleId: 'WEB-EXP-002', path: '.env', validate: validateDotEnv },
  { ruleId: 'WEB-EXP-003', path: 'appsettings.json', validate: validateAppSettings },
  { ruleId: 'WEB-EXP-003', path: 'appsettings.Development.json', validate: validateAppSettings },
  { ruleId: 'WEB-EXP-003', path: 'appsettings.Production.json', validate: validateAppSettings },
  { ruleId: 'WEB-EXP-003', path: 'web.config', validate: includes('<configuration', 'web.config içeriği okunabiliyor') },
  { ruleId: 'WEB-EXP-004', path: 'elmah.axd', validate: includes('Error Log for', 'ELMAH hata günlüğü açık') },
  {
    ruleId: 'WEB-EXP-004',
    path: 'trace.axd',
    validate: (b) => (/Application Trace|Trace Information/.test(text(b)) ? 'ASP.NET izleme sayfası açık' : null),
  },
  { ruleId: 'WEB-EXP-005', path: '.svn/entries', validate: (b) => (/^(\d{1,3}|dir)\s*(\n|$)/.test(text(b)) && !looksLikeHtml(text(b)) ? '.svn/entries' : null) },
  { ruleId: 'WEB-EXP-005', path: '.hg/requires', validate: (b) => (/^(revlogv1|store)\b/m.test(text(b)) && !looksLikeHtml(text(b)) ? '.hg/requires' : null) },
  {
    ruleId: 'WEB-EXP-005',
    path: '.DS_Store',
    validate: (b) => (b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31])) ? '.DS_Store' : null),
  },
  { ruleId: 'WEB-EXP-006', path: 'server-status', validate: includes('Apache Server Status', 'server-status') },
  { ruleId: 'WEB-EXP-006', path: 'server-info', validate: includes('Apache Server Information', 'server-info') },
  { ruleId: 'WEB-EXP-006', path: 'phpinfo.php', validate: (b) => (text(b).includes('phpinfo()') && text(b).includes('PHP Version') ? 'phpinfo.php' : null) },
  { ruleId: 'WEB-EXP-007', path: 'swagger/index.html', validate: includes('swagger-ui', 'swagger/index.html') },
  { ruleId: 'WEB-EXP-007', path: 'swagger-ui.html', validate: includes('swagger-ui', 'swagger-ui.html') },
  { ruleId: 'WEB-EXP-007', path: 'swagger/v1/swagger.json', validate: openApiVersion },
  { ruleId: 'WEB-EXP-007', path: 'v3/api-docs', validate: openApiVersion },
  { ruleId: 'WEB-EXP-007', path: 'openapi.json', validate: openApiVersion },
];

/**
 * Bases the probes run under (D-220): the origin root and, when different,
 * the directory of the target URL (`https://host/Portal/`).
 */
export function probeBases(targetUrl: string): string[] {
  const target = new URL(targetUrl);
  const root = `${target.origin}/`;
  // A last segment without a dot is taken as a folder (`/Portal` -> `/Portal/`).
  const last = target.pathname.split('/').pop() ?? '';
  const pathname = last !== '' && !last.includes('.') ? `${target.pathname}/` : target.pathname;
  const dir = new URL('.', `${target.origin}${pathname}`).href;
  return dir === root ? [root] : [root, dir];
}

/**
 * Finding for one probe response, or null. `softNotFoundHash` is the SHA-256
 * of the body of the random-path response when it answered `200` (D-219);
 * `bodyHash` is the hash of this response's body.
 */
export function evaluateProbe(
  probe: ExposureProbe,
  response: ProbeResponse,
  bodyHash: string,
  softNotFoundHash: string | null,
): WebFindingDraft | null {
  if (response.status !== 200) return null;
  if (softNotFoundHash !== null && bodyHash === softNotFoundHash) return null;
  const evidence = probe.validate(response.body, response);
  if (evidence === null) return null;
  const location = locationOf(response.url);
  return finding(probe.ruleId, { location, evidence, key: new URL(location).pathname });
}
