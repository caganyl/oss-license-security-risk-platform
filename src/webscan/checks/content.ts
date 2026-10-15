/**
 * Page content rules: mixed content, missing SRI, insecure form targets,
 * detailed error pages and directory listings (REQ-008 P-26; contract
 * sections 4.1 and 4.2). Pure functions.
 */
import { locationOf } from '../allowlist';
import { type HtmlTag, documentBase, resolveUrl } from '../html';
import { finding } from '../rules';
import type { WebFindingDraft } from '../types';

const MAX_LISTED_URLS = 10;

function listUrls(urls: readonly string[]): string {
  const shown = urls.slice(0, MAX_LISTED_URLS).join(', ');
  return urls.length > MAX_LISTED_URLS ? `${urls.length} adres: ${shown}, …` : `${urls.length} adres: ${shown}`;
}

function isStylesheet(tag: HtmlTag): boolean {
  return (tag.attrs.rel ?? '').toLowerCase().split(/\s+/).includes('stylesheet');
}

/** WEB-CNT-001 / 002 / 003 on the final main page (`pageUrl` = its URL). */
export function checkPageContent(tags: readonly HtmlTag[], pageUrl: string): WebFindingDraft[] {
  const out: WebFindingDraft[] = [];
  const page = new URL(pageUrl);
  const https = page.protocol === 'https:';
  const base = documentBase(tags, pageUrl);
  const location = locationOf(pageUrl);

  const mixed: string[] = [];
  const noSri: string[] = [];
  const insecureForms: string[] = [];
  for (const tag of tags) {
    if (tag.name === 'script' && tag.attrs.src !== undefined) {
      const src = resolveUrl(tag.attrs.src, base);
      if (!src) continue;
      if (https && src.protocol === 'http:') mixed.push(locationOf(src));
      if (src.host.toLowerCase() !== page.host.toLowerCase() && !(tag.attrs.integrity ?? '').trim()) noSri.push(locationOf(src));
    } else if (tag.name === 'link' && isStylesheet(tag)) {
      const href = resolveUrl(tag.attrs.href, base);
      if (href && https && href.protocol === 'http:') mixed.push(locationOf(href));
    } else if (tag.name === 'iframe') {
      const src = resolveUrl(tag.attrs.src, base);
      if (src && https && src.protocol === 'http:') mixed.push(locationOf(src));
    } else if (tag.name === 'form' && tag.attrs.action !== undefined) {
      const action = resolveUrl(tag.attrs.action, base);
      if (action && https && action.protocol === 'http:') insecureForms.push(locationOf(action));
    }
  }
  const unique = (list: string[]) => [...new Set(list)];
  if (mixed.length > 0) out.push(finding('WEB-CNT-001', { location, evidence: listUrls(unique(mixed)), key: 'mixed-content' }));
  if (noSri.length > 0) out.push(finding('WEB-CNT-002', { location, evidence: listUrls(unique(noSri)), key: 'sri' }));
  if (insecureForms.length > 0) out.push(finding('WEB-CNT-003', { location, evidence: listUrls(unique(insecureForms)), key: 'insecure-form' }));
  return out;
}

/** Contract 4.2 error page patterns, in evaluation order; first match wins. */
const ERROR_PATTERNS: ReadonlyArray<{ label: string; test: (text: string) => boolean }> = [
  { label: 'aspnet-ysod', test: (t) => /Server Error in '[^'\n]{0,200}' Application/.test(t) },
  { label: 'aspnetcore-developer-page', test: (t) => t.includes('An unhandled exception occurred while processing the request') },
  { label: 'stack-trace-dotnet', test: (t) => /Stack Trace:/i.test(t) && /\bat System\./.test(t) },
  { label: 'aspnet-version-info', test: (t) => t.includes('Version Information:') && t.includes('ASP.NET Version') },
  { label: 'python-traceback', test: (t) => t.includes('Traceback (most recent call last)') },
  { label: 'werkzeug-debugger', test: (t) => t.includes('Werkzeug Debugger') },
  { label: 'laravel-whoops', test: (t) => t.includes('Whoops! There was an error') },
  { label: 'java-exception', test: (t) => /java\.lang\.[A-Za-z]{1,60}Exception/.test(t) && /(^|\n)\s*at [a-z][\w$.]{0,200}\(/.test(t) },
  {
    label: 'sql-error',
    test: (t) => t.includes('SQLSTATE[') || /\bORA-0\d{4}\b/.test(t) || t.includes('Microsoft OLE DB Provider') || t.includes('Unclosed quotation mark'),
  },
];

/** Label of the first matching detailed-error pattern, or null. */
export function detectErrorPage(text: string): string | null {
  for (const pattern of ERROR_PATTERNS) if (pattern.test(text)) return pattern.label;
  return null;
}

const DIR_PATTERNS: ReadonlyArray<{ label: string; re: RegExp }> = [
  { label: 'dir-apache-nginx', re: /<title>\s*Index of \//i },
  { label: 'dir-iis', re: /\[To Parent Directory\]/ },
  { label: 'dir-python', re: /<title>\s*Directory listing for /i },
];

/** Label of the first matching directory listing pattern, or null. */
export function detectDirectoryListing(text: string): string | null {
  for (const p of DIR_PATTERNS) if (p.re.test(text)) return p.label;
  return null;
}

export function errorPageFinding(url: string, label: string): WebFindingDraft {
  // One finding per scan for this rule: the root cause is one server setting.
  return finding('WEB-INF-004', { location: locationOf(url), evidence: `Desen: ${label}`, key: 'error-page' });
}

export function directoryListingFinding(url: string, label: string): WebFindingDraft {
  return finding('WEB-INF-005', { location: locationOf(url), evidence: `Desen: ${label}` });
}
