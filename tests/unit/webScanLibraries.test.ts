/**
 * REQ-008 AC-P26-7 / D-222 (contract section 5): JavaScript library detection;
 * D-223 (contract section 6): score and grade; ADR-010 Karar 2 fingerprint;
 * AC-P26-5: the rule catalogue equals the contract table.
 */
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { extractTags } from '../../src/webscan/html';
import { dedupeComponents, detectFromHtml, detectFromScriptBody, detectFromScriptUrl, scriptUrls } from '../../src/webscan/libraries';
import { WEB_RULES } from '../../src/webscan/rules';
import { countBySeverity, webFingerprint, webGrade, webScore } from '../../src/webscan/score';
import { repoPath } from '../helpers/paths';

const url = (u: string) => detectFromScriptUrl(new URL(u));

describe('script URL signatures', () => {
  it.each([
    ['https://app.local/js/jquery-3.4.1.min.js', 'jQuery', 'jquery', '3.4.1'],
    ['https://app.local/js/jquery.1.12.4.slim.min.js', 'jQuery', 'jquery', '1.12.4'],
    ['https://app.local/js/jquery-3.4.1-min.js', 'jQuery', 'jquery', '3.4.1'],
    ['https://app.local/js/jquery-ui-1.12.1.min.js', 'jQuery UI', 'jquery-ui', '1.12.1'],
    ['https://app.local/lib/bootstrap-4.3.1.bundle.min.js', 'Bootstrap', 'bootstrap', '4.3.1'],
    ['https://app.local/lib/react-dom-16.8.0.production.min.js', 'React DOM', 'react-dom', '16.8.0'],
    ['https://app.local/lib/purify-2.0.8.min.js', 'DOMPurify', 'dompurify', '2.0.8'],
    ['https://cdn.jsdelivr.net/npm/vue@2.6.10/dist/vue.min.js', 'Vue', 'vue', '2.6.10'],
    ['https://cdn.jsdelivr.net/npm/@angular/core@12.0.0/bundles/core.umd.js', '@angular/core', '@angular/core', '12.0.0'],
    ['https://unpkg.com/lodash@4.17.15/lodash.min.js', 'Lodash', 'lodash', '4.17.15'],
    ['https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js', 'Bootstrap', 'bootstrap', '3.3.7'],
    ['https://cdnjs.cloudflare.com/ajax/libs/unknown-lib/1.0.0/x.js', 'unknown-lib', null, '1.0.0'],
    ['https://code.jquery.com/jquery/3.3.1/jquery.min.js', 'jQuery', 'jquery', '3.3.1'],
    ['https://app.local/js/app.bundle.js', null, null, null],
    ['https://cdn.jsdelivr.net/npm/vue@latest/dist/vue.js', null, null, null],
  ])('%s', (u, name, npm, version) => {
    const c = url(u);
    if (name === null) {
      expect(c).toBeNull();
      return;
    }
    expect(c).toMatchObject({ name, npmName: npm, version, detection: 'url' });
  });

  it('the location never carries the query string', () => {
    expect(url('https://app.local/js/jquery-3.4.1.min.js?v=abc')?.location).toBe('https://app.local/js/jquery-3.4.1.min.js');
  });

  it('jquery-3.4.1-min.js keeps the plain version (no fake pre-release); a real pre-release is kept', () => {
    expect(url('https://app.local/js/jquery-3.4.1-min.js')?.version).toBe('3.4.1');
    expect(url('https://app.local/js/jquery-4.0.0-beta.2.min.js')?.version).toBe('4.0.0-beta.2');
  });
});

describe('banner and HTML signatures', () => {
  it.each([
    ['/*! jQuery v3.4.1 | (c) JS Foundation */', 'jQuery', '3.4.1'],
    ['/*! jQuery JavaScript Library v1.12.4 */', 'jQuery', '1.12.4'],
    ['/*! jQuery UI - v1.12.1 - 2016-09-14 */', 'jQuery UI', '1.12.1'],
    ['/*! Bootstrap v4.3.1 (https://getbootstrap.com/) */', 'Bootstrap', '4.3.1'],
    ['/** @license AngularJS v1.7.8 */', 'AngularJS', '1.7.8'],
    ['/*! Vue.js v2.6.10 (c) */', 'Vue', '2.6.10'],
    ['//! moment.js\n//! version : 2.24.0\n', 'Moment', '2.24.0'],
    ['/*! handlebars v4.0.11 */', 'Handlebars', '4.0.11'],
    ['/*! @license DOMPurify 2.0.8 */', 'DOMPurify', '2.0.8'],
    ['/*! Chart.js v2.9.4 */', 'Chart.js', '2.9.4'],
  ])('%j', (body, name, version) => {
    expect(detectFromScriptBody(body, 'https://app.local/x.js')).toEqual([
      expect.objectContaining({ name, version, detection: 'banner', location: 'https://app.local/x.js' }),
    ]);
  });

  it('a bundle with two libraries yields both; plain code yields none', () => {
    expect(detectFromScriptBody('/*! jQuery v3.4.1 */\n/*! Bootstrap v4.3.1 (https://getbootstrap.com/) */', null).map((c) => c.name).sort()).toEqual(['Bootstrap', 'jQuery']);
    expect(detectFromScriptBody('function x(){return 1}', null)).toEqual([]);
  });

  it('Angular ng-version attribute', () => {
    expect(detectFromHtml('<app-root ng-version="15.2.9"></app-root>', 'https://app.local/')).toEqual([
      { name: 'Angular', npmName: '@angular/core', version: '15.2.9', detection: 'html', location: 'https://app.local/' },
    ]);
    expect(detectFromHtml('<app-root></app-root>', null)).toEqual([]);
  });

  it('script URL list is resolved, unique and http(s) only; dedupe keeps the first detection', () => {
    const tags = extractTags('<script src="/a.js"></script><script src="/a.js"></script><script src="data:text/javascript,1"></script><script>inline()</script>');
    expect(scriptUrls(tags, 'https://app.local/p/').map((u) => u.href)).toEqual(['https://app.local/a.js']);
    const a = { name: 'jQuery', npmName: 'jquery', version: '3.4.1', detection: 'url' as const, location: 'x' };
    expect(dedupeComponents([a, { ...a, detection: 'banner', location: 'y' }])).toEqual([a]);
  });
});

describe('D-223 score and grade', () => {
  it('weights and floor', () => {
    expect(webScore(countBySeverity([]))).toBe(100);
    expect(webScore(countBySeverity(['info', 'info']))).toBe(100);
    expect(webScore(countBySeverity(['low', 'medium']))).toBe(90);
    expect(webScore(countBySeverity(['high']))).toBe(80);
    expect(webScore(countBySeverity(['critical', 'critical', 'critical']))).toBe(0);
  });
  it.each([[100, 'A'], [90, 'A'], [89, 'B'], [75, 'B'], [74, 'C'], [60, 'C'], [59, 'D'], [40, 'D'], [39, 'F'], [0, 'F']])('%i -> %s', (score, grade) => {
    expect(webGrade(score)).toBe(grade);
  });
  it('fingerprint is 64 lower-case hex, stable and case-insensitive in the project id', () => {
    const a = webFingerprint('AAAAAAAA-0000-4000-8000-000000000001', 'WEB-HDR-001', 'https://app.local/');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(webFingerprint('aaaaaaaa-0000-4000-8000-000000000001', 'WEB-HDR-001', 'https://app.local/')).toBe(a);
    expect(webFingerprint('aaaaaaaa-0000-4000-8000-000000000001', 'WEB-HDR-002', 'https://app.local/')).not.toBe(a);
  });
});

describe('AC-P26-5: rule catalogue equals the contract table (docs/contracts/REQ-008-web-scan.md §4)', () => {
  const contract = fs.readFileSync(repoPath('docs', 'contracts', 'REQ-008-web-scan.md'), 'utf8');
  const rows = [...contract.matchAll(/^\| (WEB-[A-Z]{3,4}-\d{3}) \| (\w+) \| ([^|]+) \| ([^|]+) \| (\d+) \| (A\d\d:2021) \|$/gm)];

  it('every contract row has a rule with the same category, severity, title, CWE and OWASP; no extra rule', () => {
    expect(rows.length).toBe(Object.keys(WEB_RULES).length);
    for (const [, id, category, severity, title, cwe, owasp] of rows) {
      const rule = WEB_RULES[id];
      expect(rule, id).toBeDefined();
      expect(rule.category, id).toBe(category);
      const sev = severity.trim();
      // WEB-CKE-002: "medium (oturum çerezi) / low" -> catalogue default low; WEB-LIB-001: from CVSS.
      if (/^(info|low|medium|high|critical)$/.test(sev)) expect(rule.severity, id).toBe(sev);
      expect(rule.title, id).toBe(title.trim());
      expect(rule.cwe, id).toBe(Number(cwe));
      expect(rule.owasp, id).toBe(owasp);
    }
  });

  it('every rule has a description and a recommendation', () => {
    for (const rule of Object.values(WEB_RULES)) {
      expect(rule.description.length, rule.id).toBeGreaterThan(20);
      expect(rule.recommendation.length, rule.id).toBeGreaterThan(20);
    }
  });
});
