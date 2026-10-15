/**
 * JavaScript library detection (REQ-008 AC-P26-7, D-222; contract section 5).
 *
 * Three sources: script URLs (file name and CDN path patterns; third-party
 * scripts are never downloaded), banner comments of downloaded same-host
 * scripts, and HTML attributes (`ng-version`). Pure functions.
 */
import { locationOf } from './allowlist';
import type { HtmlTag } from './html';
import type { DetectedComponent } from './types';

// Pre-release only with a conventional tag, so `jquery-3.4.1-min.js` keeps `3.4.1`.
const VERSION = String.raw`(\d{1,4}\.\d{1,4}\.\d{1,4}(?:-(?:alpha|beta|rc|pre)[0-9A-Za-z.]{0,30})?)`;
const VERSION_RE = new RegExp(`^${VERSION}$`);

interface KnownLibrary {
  name: string;
  npm: string;
  /** File name stem(s) before `-X.Y.Z` / `.X.Y.Z`. */
  stems: string[];
  /** Banner patterns with the version in group 1. */
  banners: RegExp[];
}

const KNOWN: readonly KnownLibrary[] = [
  { name: 'jQuery UI', npm: 'jquery-ui', stems: ['jquery-ui'], banners: [new RegExp(String.raw`jQuery UI - v${VERSION}`)] },
  { name: 'jQuery', npm: 'jquery', stems: ['jquery'], banners: [new RegExp(String.raw`jQuery (?:JavaScript Library )?v${VERSION}`)] },
  { name: 'Bootstrap', npm: 'bootstrap', stems: ['bootstrap'], banners: [new RegExp(String.raw`Bootstrap v${VERSION} \(https?:\/\/getbootstrap\.com`)] },
  { name: 'AngularJS', npm: 'angular', stems: ['angular'], banners: [new RegExp(String.raw`@license AngularJS v${VERSION}`)] },
  { name: 'Vue', npm: 'vue', stems: ['vue'], banners: [new RegExp(String.raw`Vue\.js v${VERSION}`)] },
  { name: 'Lodash', npm: 'lodash', stems: ['lodash'], banners: [] },
  { name: 'Moment', npm: 'moment', stems: ['moment'], banners: [new RegExp(String.raw`//! moment\.js\s*\n//! version : ${VERSION}`)] },
  { name: 'Handlebars', npm: 'handlebars', stems: ['handlebars'], banners: [new RegExp(String.raw`handlebars v${VERSION}`, 'i')] },
  { name: 'Knockout', npm: 'knockout', stems: ['knockout'], banners: [new RegExp(String.raw`Knockout JavaScript library v${VERSION}`)] },
  { name: 'DOMPurify', npm: 'dompurify', stems: ['purify', 'dompurify'], banners: [new RegExp(String.raw`@license DOMPurify ${VERSION}`)] },
  { name: 'Chart.js', npm: 'chart.js', stems: ['chart'], banners: [new RegExp(String.raw`Chart\.js v${VERSION}`)] },
  { name: 'Select2', npm: 'select2', stems: ['select2'], banners: [new RegExp(String.raw`Select2 ${VERSION}`)] },
  { name: 'React DOM', npm: 'react-dom', stems: ['react-dom'], banners: [] },
  { name: 'React', npm: 'react', stems: ['react'], banners: [] },
  { name: 'Axios', npm: 'axios', stems: ['axios'], banners: [] },
];

const BY_NPM = new Map(KNOWN.map((k) => [k.npm, k]));

/** cdnjs library name -> npm name (contract section 5). */
const CDNJS: Readonly<Record<string, string>> = {
  jquery: 'jquery',
  jqueryui: 'jquery-ui',
  'twitter-bootstrap': 'bootstrap',
  'angular.js': 'angular',
  vue: 'vue',
  'lodash.js': 'lodash',
  'moment.js': 'moment',
  'handlebars.js': 'handlebars',
  knockout: 'knockout',
  dompurify: 'dompurify',
  'chart.js': 'chart.js',
  select2: 'select2',
  react: 'react',
  'react-dom': 'react-dom',
  axios: 'axios',
};

const NPM_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]{0,100}\/)?[a-z0-9][a-z0-9._-]{0,100}$/;

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const FILE_RES = KNOWN.map((lib) => ({
  lib,
  re: new RegExp(`^(?:${lib.stems.map(escapeRe).join('|')})[.-]${VERSION}(?:[.-](?:min|slim|bundle|umd|production|development|full|js))*\\.js$`, 'i'),
}));

function component(name: string, npmName: string | null, version: string, detection: DetectedComponent['detection'], location: string | null): DetectedComponent | null {
  if (!VERSION_RE.test(version)) return null;
  if (npmName !== null && !NPM_NAME_RE.test(npmName)) return null;
  return { name: name.slice(0, 100), npmName, version, detection, location };
}

/** Library of one script URL (file name, jsDelivr, unpkg or cdnjs pattern), or null. */
export function detectFromScriptUrl(url: URL): DetectedComponent | null {
  const location = locationOf(url);
  const path = decodeURIComponentSafe(url.pathname);
  const host = url.hostname.toLowerCase();

  // jsDelivr `/npm/<pkg>@<ver>/…` and unpkg `/<pkg>@<ver>/…`: the package name is the npm name.
  const npmCdn = host === 'cdn.jsdelivr.net' ? /^\/npm\/((?:@[^/@]+\/)?[^/@]+)@([^/]+)\//.exec(path) : host === 'unpkg.com' ? /^\/((?:@[^/@]+\/)?[^/@]+)@([^/]+)\//.exec(path) : null;
  if (npmCdn) {
    const npm = npmCdn[1].toLowerCase();
    const known = BY_NPM.get(npm);
    return component(known?.name ?? npm, npm, npmCdn[2], 'url', location);
  }
  // cdnjs `/ajax/libs/<lib>/<ver>/…`
  const cdnjs = host === 'cdnjs.cloudflare.com' ? /^\/ajax\/libs\/([^/]+)\/([^/]+)\//.exec(path) : null;
  if (cdnjs) {
    const npm = CDNJS[cdnjs[1].toLowerCase()] ?? null;
    const known = npm ? BY_NPM.get(npm) : undefined;
    return component(known?.name ?? cdnjs[1], npm, cdnjs[2], 'url', location);
  }
  const file = path.split('/').pop() ?? '';
  for (const { lib, re } of FILE_RES) {
    const m = re.exec(file);
    if (m) return component(lib.name, lib.npm, m[1], 'url', location);
  }
  // `/jquery/3.4.1/jquery.min.js`-style folders (code.jquery.com, ajax.googleapis.com, local copies).
  const folder = /\/(jquery|jqueryui|jquery-ui|bootstrap|angularjs|vue|lodash|moment)\/(\d{1,4}\.\d{1,4}\.\d{1,4})\//i.exec(path);
  if (folder) {
    const npm = { jquery: 'jquery', jqueryui: 'jquery-ui', 'jquery-ui': 'jquery-ui', bootstrap: 'bootstrap', angularjs: 'angular', vue: 'vue', lodash: 'lodash', moment: 'moment' }[folder[1].toLowerCase()] ?? null;
    const known = npm ? BY_NPM.get(npm) : undefined;
    if (known) return component(known.name, known.npm, folder[2], 'url', location);
  }
  return null;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Libraries announced by banner comments in a downloaded script body. */
export function detectFromScriptBody(body: string, location: string | null): DetectedComponent[] {
  const found: DetectedComponent[] = [];
  for (const lib of KNOWN) {
    for (const re of lib.banners) {
      const m = re.exec(body);
      if (m) {
        const c = component(lib.name, lib.npm, m[1], 'banner', location);
        if (c) found.push(c);
        break;
      }
    }
  }
  return found;
}

/** Angular 2+ `ng-version="X.Y.Z"` on any element of the page. */
export function detectFromHtml(html: string, pageLocation: string | null): DetectedComponent[] {
  const m = new RegExp(String.raw`\sng-version="${VERSION}"`).exec(html);
  if (!m) return [];
  const c = component('Angular', '@angular/core', m[1], 'html', pageLocation);
  return c ? [c] : [];
}

/** Script URLs of the page (resolved, http(s) only), in document order, unique. */
export function scriptUrls(tags: readonly HtmlTag[], base: string): URL[] {
  const seen = new Set<string>();
  const urls: URL[] = [];
  for (const tag of tags) {
    if (tag.name !== 'script' || tag.attrs.src === undefined) continue;
    let url: URL;
    try {
      url = new URL(tag.attrs.src.trim(), base);
    } catch {
      continue;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
    if (seen.has(url.href)) continue;
    seen.add(url.href);
    urls.push(url);
  }
  return urls;
}

/** One entry per (name, version); the first detection wins (D-222). */
export function dedupeComponents(components: readonly DetectedComponent[]): DetectedComponent[] {
  const map = new Map<string, DetectedComponent>();
  for (const c of components) {
    const key = `${c.name.toLowerCase()}@${c.version}`;
    if (!map.has(key)) map.set(key, c);
  }
  return [...map.values()];
}
