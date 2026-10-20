/**
 * REQ-010 backend units: system features (AC-P35-1, booleans and counts
 * only), dependency PDF overall status (D-278) and action list
 * (AC-P37-3, D-279), Turkish PDF texts (AC-P37-2, contract 1.6.0 §5.3).
 */
import { describe, expect, it } from 'vitest';
import {
  actionItems,
  overallStatus,
  pdfVulnerabilityDataText,
} from '../../src/reports/dependencyPdf';
import type { ReportData, ReportDependency } from '../../src/reports/reportService';
import { systemFeatures } from '../../src/routes/systemRoutes';
import { parseAllowedHosts } from '../../src/webscan/allowlist';

const SECRET_VALUES = {
  ENCRYPTION_KEY: 'enc-key-value-must-not-leak',
  NVD_API_KEY: 'nvd-key-value-must-not-leak',
  WEB_SCAN_ALLOWED_HOSTS: 'portal.sirket.local, *.sirket.com.tr',
  ZAP_API_URL: 'http://127.0.0.1:8090',
  ZAP_API_KEY: 'zap-key-value-must-not-leak',
  GIT_WINDOWS_AUTH_HOSTS: 'tfs.sirket.local',
};

describe('AC-P35-1: system features are booleans and counts only', () => {
  it('everything on: counts right, no value, host, path or key in the output', () => {
    const roots = ['C:\\secret\\root'];
    const out = systemFeatures(SECRET_VALUES, roots, parseAllowedHosts(SECRET_VALUES.WEB_SCAN_ALLOWED_HOSTS));
    expect(out).toEqual({
      local_scan: { enabled: true, roots: 1 },
      web_scan: { enabled: true, allowed_hosts: 2 },
      zap: { enabled: true },
      registry_enrichment: { enabled: true },
      vulnerability_lookup: { enabled: true },
      vulnerability_recheck: { enabled: true },
      nvd: { enabled: true, api_key: true },
      repo_tokens: { enabled: true },
      windows_git_auth: { enabled: true, hosts: 1 },
    });
    const text = JSON.stringify(out);
    for (const value of [...Object.values(SECRET_VALUES), 'secret', 'sirket', 'tfs', '127.0.0.1']) expect(text).not.toContain(value);
  });

  it('defaults: local/web/zap/tokens/windows off; switches turned off are reported off', () => {
    const out = systemFeatures(
      { REGISTRY_ENRICHMENT: 'off', VULNERABILITY_LOOKUP: 'off', VULNERABILITY_RECHECK: 'off' },
      [],
      parseAllowedHosts(''),
    );
    expect(out.local_scan).toEqual({ enabled: false, roots: 0 });
    expect(out.web_scan).toEqual({ enabled: false, allowed_hosts: 0 });
    expect(out.zap.enabled).toBe(false);
    expect(out.registry_enrichment.enabled).toBe(false);
    expect(out.vulnerability_lookup.enabled).toBe(false);
    expect(out.vulnerability_recheck.enabled).toBe(false);
    expect(out.nvd).toEqual({ enabled: false, api_key: false });
    expect(out.repo_tokens.enabled).toBe(false);
    expect(out.windows_git_auth).toEqual({ enabled: false, hosts: 0 });
  });
});

function dep(name: string, opts: { sev?: string; fix?: string | null; status?: string; risk?: string; license?: string; suppressed?: boolean } = {}): ReportDependency {
  return {
    id: name, ecosystem: 'npm', name, version: '1.0.0', purl: '', scope: 'direct', manifestFile: 'package-lock.json', manifestPath: '.', depth: 1,
    licenseExpression: opts.license ?? 'MIT', licenseSource: null, licenseLockHint: null, licenseHintDiffers: null, licenseEnrichmentStatus: null, lockIntegrity: null,
    licenses: [{ detectedLicense: opts.license ?? 'MIT', normalizedLicense: opts.license ?? 'MIT', riskLevel: opts.risk ?? 'safe', appliedPolicy: null, status: 'open', suppressed: false }],
    vulnerabilities: opts.sev
      ? [{ advisoryId: `CVE-${name}`, title: 't', severity: opts.sev, cvssScore: null, fixVersion: opts.fix ?? null, fixAvailable: !!opts.fix, status: opts.status ?? 'open', suppressed: opts.suppressed ?? false, publishedAt: null }]
      : [],
  };
}

function report(deps: ReportDependency[], counts: Partial<ReportData['scan']> = {}): ReportData {
  return {
    generatedAt: new Date(),
    scan: {
      id: 's', ref: null, trigger: 'manual', completedAt: new Date(), createdAt: new Date(), totalDependencies: deps.length, totalVulnerabilities: 0,
      criticalVulns: 0, highVulns: 0, mediumVulns: 0, lowVulns: 0, licenseViolations: 0, vulnerabilityDataStatus: 'complete', ...counts,
    },
    project: { id: 'p', name: 'p', description: null, criticality: 'medium', repoUrl: null },
    dependencies: deps,
  };
}

describe('D-278: overall status sentence', () => {
  it.each([
    [report([dep('a')], { criticalVulns: 1 }), 'critical'],
    [report([dep('a')], { highVulns: 1 }), 'attention'],
    [report([dep('gpl', { risk: 'high', license: 'GPL-3.0-only' })]), 'attention'],
    [report([dep('a')], { lowVulns: 2 }), 'improve'],
    [report([dep('x', { risk: 'unknown', license: 'Custom' })]), 'improve'],
    [report([dep('a')]), 'clean'],
  ])('-> %#', (data, level) => {
    expect(overallStatus(data).level).toBe(level);
  });
});

describe('AC-P37-3: "Ne yapılmalı?" actions', () => {
  it('critical before high, a fix version first, closed/suppressed findings skipped, licenses after vulnerabilities', () => {
    const items = actionItems(report([
      dep('high-nofix', { sev: 'high' }),
      dep('crit-fix', { sev: 'critical', fix: '2.0.0' }),
      dep('high-fix', { sev: 'high', fix: '1.2.0' }),
      dep('fixed-one', { sev: 'critical', fix: '9.9.9', status: 'fixed' }),
      dep('muted', { sev: 'critical', suppressed: true }),
      dep('medium-only', { sev: 'medium', fix: '1.0.1' }),
      dep('agpl', { risk: 'critical', license: 'AGPL-3.0-only' }),
    ]));
    expect(items).toEqual([
      'crit-fix paketini 1.0.0 sürümünden 2.0.0 sürümüne yükseltin (kritik açık: CVE-crit-fix).',
      'high-fix paketini 1.0.0 sürümünden 1.2.0 sürümüne yükseltin (yüksek açık: CVE-high-fix).',
      'high-nofix 1.0.0: düzeltilmiş sürüm henüz yok (yüksek açık: CVE-high-nofix). Paketin gerekliliğini ve alternatiflerini değerlendirin.',
      'agpl (AGPL-3.0-only): ağ copyleft lisansı; sunucuda/SaaS olarak kullanımda kaynak kodun paylaşılması gerekebilir. Hukuk birimiyle değerlendirin.',
    ]);
  });

  it('nothing to do -> empty list; more than 10 -> 9 items + a "more" line', () => {
    expect(actionItems(report([dep('a'), dep('b')]))).toEqual([]);
    const many = actionItems(report(Array.from({ length: 14 }, (_, i) => dep(`p${String(i).padStart(2, '0')}`, { sev: 'critical', fix: '2.0.0' }))));
    expect(many).toHaveLength(10);
    expect(many[9]).toBe('…ve 5 madde daha; ayrıntılar aşağıdaki tablolarda.');
  });

  it('unknown licenses are one aggregated item', () => {
    const items = actionItems(report([dep('x', { risk: 'unknown', license: 'Custom' }), dep('y', { risk: 'unknown', license: 'Custom' })]));
    expect(items).toEqual(['2 paketin lisansı belirlenemedi; Excel çıktısındaki lisans sütunundan kontrol edin.']);
  });
});

describe('contract 1.6.0 §5.3: Turkish vulnerability-data texts', () => {
  it.each([
    ['complete', 'tam'],
    ['partial', 'kısmi (bazı paketler kontrol edilemedi)'],
    ['unavailable', 'alınamadı (güvenlik açığı kaynağına ulaşılamadı)'],
    ['disabled', 'kapalı (sorgu devre dışı)'],
    [null, 'kontrol edilmedi'],
    ['toString', 'kontrol edilmedi'],
  ])('%j -> %s', (status, text) => {
    expect(pdfVulnerabilityDataText(status)).toBe(text);
  });
});
