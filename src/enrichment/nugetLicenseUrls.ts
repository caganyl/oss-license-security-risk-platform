/**
 * NuGet `licenseUrl` classification (REQ-006 AC-P21-6, D-134; ADR-008
 * Karar 9). Pure: the URL is only parsed with `new URL`, never requested,
 * logged or stored.
 *
 * - `licenses.nuget.org/<expression>` -> the SPDX expression (decoded once,
 *   validated against the known SPDX id list);
 * - `aka.ms/deprecateLicenseUrl` -> ignored (as if no `licenseUrl`);
 * - a small fixed table of well-known license pages -> its SPDX id;
 * - anything else -> unclassified.
 *
 * A change of the table or the rules bumps the NuGet metadata extractor
 * version (`METADATA_EXTRACTOR_VERSIONS.nuget`, `cache.ts`).
 */
import { KNOWN_SPDX_IDS } from '../analysis/licenseNormalizer';
import { buildIdIndex, canonicalizeSpdxExpression } from '../lib/spdxExpression';

export type LicenseUrlClass = { kind: 'expression'; value: string } | { kind: 'ignore' } | { kind: 'unclassified' };

const MAX_URL_CHARS = 2000;

/** Canonical URL form (host without `www.`, lower-case path, no trailing `/` or one page extension) -> SPDX id. */
const LICENSE_URL_TABLE: ReadonlyMap<string, string> = new Map([
  ['opensource.org/licenses/mit', 'MIT'],
  ['opensource.org/licenses/mit-license', 'MIT'],
  ['opensource.org/licenses/apache-2.0', 'Apache-2.0'],
  ['apache.org/licenses/license-2.0', 'Apache-2.0'],
  ['opensource.org/licenses/bsd-2-clause', 'BSD-2-Clause'],
  ['opensource.org/licenses/bsd-3-clause', 'BSD-3-Clause'],
  ['opensource.org/licenses/isc', 'ISC'],
  ['opensource.org/licenses/isc-license', 'ISC'],
  ['opensource.org/licenses/mpl-2.0', 'MPL-2.0'],
  ['mozilla.org/mpl/2.0', 'MPL-2.0'],
]);

let idIndex: Map<string, string> | null = null;
function spdxIndex(): Map<string, string> {
  idIndex ??= buildIdIndex(KNOWN_SPDX_IDS);
  return idIndex;
}

function asciiLowerText(value: string): string {
  return value.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/** Canonical form used for the table lookup, or null when the URL has a query or fragment. */
function canonicalForm(url: URL): string | null {
  if (url.search !== '' || url.hash !== '') return null;
  let host = asciiLowerText(url.hostname);
  if (host.startsWith('www.')) host = host.slice(4);
  let path = asciiLowerText(url.pathname);
  while (path.endsWith('/')) path = path.slice(0, -1);
  path = path.replace(/\.(html|htm|txt|php)$/, '');
  return `${host}${path}`;
}

export function classifyLicenseUrl(raw: string): LicenseUrlClass {
  const value = raw.trim();
  if (value.length === 0 || value.length > MAX_URL_CHARS) return { kind: 'unclassified' };
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { kind: 'unclassified' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { kind: 'unclassified' };
  const host = asciiLowerText(url.hostname);

  if (host === 'licenses.nuget.org') {
    let expression: string;
    try {
      expression = decodeURIComponent(url.pathname.replace(/^\//, ''));
    } catch {
      return { kind: 'unclassified' };
    }
    const canonical = expression.trim() === '' ? null : canonicalizeSpdxExpression(expression, spdxIndex());
    return canonical === null ? { kind: 'unclassified' } : { kind: 'expression', value: canonical };
  }

  if (host === 'aka.ms' && asciiLowerText(url.pathname) === '/deprecatelicenseurl') return { kind: 'ignore' };

  const canonical = canonicalForm(url);
  if (canonical === null) return { kind: 'unclassified' };
  const fromTable = LICENSE_URL_TABLE.get(canonical);
  if (fromTable !== undefined) return { kind: 'expression', value: fromTable };
  const spdxPrefix = 'spdx.org/licenses/';
  if (canonical.startsWith(spdxPrefix)) {
    const id = canonical.slice(spdxPrefix.length);
    const known = id.length > 0 && !id.includes('/') ? spdxIndex().get(id) : undefined;
    if (known !== undefined) return { kind: 'expression', value: known };
  }
  return { kind: 'unclassified' };
}
