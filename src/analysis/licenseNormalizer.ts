/**
 * License Normalization Engine
 *
 * Maps raw license strings (as reported by package managers) to canonical SPDX identifiers
 * and evaluates their risk level based on copyleft category and enterprise compliance impact.
 *
 * Risk tiers:
 *   safe     — permissive; attribution only, no copyleft obligation
 *   medium   — weak copyleft; modifications to covered files must be shared
 *   high     — strong copyleft; derivative works must be relicensed
 *   critical — network copyleft (AGPL/SSPL); SaaS use triggers full source disclosure
 *   unknown  — unrecognized or proprietary; requires legal review
 */

export type LicenseRiskLevel = 'safe' | 'medium' | 'high' | 'critical' | 'unknown';

export interface NormalizationResult {
  /** Canonical SPDX identifier, null when the license is unrecognized or proprietary. */
  spdxId: string | null;
  /** Best normalized form: spdxId when mapped, else the cleaned raw input. */
  normalized: string;
  riskLevel: LicenseRiskLevel;
  /** True when the input contained SPDX AND/OR/WITH operators. */
  isSpdxExpression: boolean;
  originalRaw: string;
}

// ---------------------------------------------------------------------------
// Risk ordering helpers
// ---------------------------------------------------------------------------

const RISK_ORDER: LicenseRiskLevel[] = ['safe', 'medium', 'high', 'critical', 'unknown'];

/** Returns whichever risk level is more severe. 'unknown' beats everything. */
function riskMax(a: LicenseRiskLevel, b: LicenseRiskLevel): LicenseRiskLevel {
  if (a === 'unknown' || b === 'unknown') return 'unknown';
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

/** Returns whichever risk level is less severe. 'unknown' is treated as worst-case. */
function riskMin(a: LicenseRiskLevel, b: LicenseRiskLevel): LicenseRiskLevel {
  if (a === 'unknown') return b;
  if (b === 'unknown') return a;
  return RISK_ORDER.indexOf(a) <= RISK_ORDER.indexOf(b) ? a : b;
}

// ---------------------------------------------------------------------------
// SPDX risk map — mirrors the licenses seed data in schema.sql plus extras
// ---------------------------------------------------------------------------

export const SPDX_RISK_MAP: Readonly<Record<string, LicenseRiskLevel>> = {
  // Permissive — safe
  'MIT': 'safe',
  'MIT-0': 'safe',
  'Apache-2.0': 'safe',
  'Apache-1.1': 'safe',
  'BSD-2-Clause': 'safe',
  'BSD-3-Clause': 'safe',
  'BSD-4-Clause': 'safe',
  'ISC': 'safe',
  '0BSD': 'safe',
  'Unlicense': 'safe',
  'CC0-1.0': 'safe',
  'Zlib': 'safe',
  'Python-2.0': 'safe',
  'PSF-2.0': 'safe',
  'BlueOak-1.0.0': 'safe',
  'Artistic-2.0': 'safe',
  'Artistic-1.0': 'safe',
  'Ruby': 'safe',
  'WTFPL': 'safe',
  'Boost-1.0': 'safe',
  'X11': 'safe',
  'FTL': 'safe',
  'IJG': 'safe',
  'Libpng': 'safe',
  'libtiff': 'safe',
  'NTP': 'safe',
  'OFL-1.1': 'safe',
  'OpenSSL': 'safe',
  'Unicode-DFS-2016': 'safe',
  'W3C': 'safe',
  'Beerware': 'safe',
  'HPND': 'safe',
  'curl': 'safe',
  'Xfig': 'safe',
  'Vim': 'safe',
  // Weak copyleft — medium
  'LGPL-2.0-only': 'medium',
  'LGPL-2.0-or-later': 'medium',
  'LGPL-2.1-only': 'medium',
  'LGPL-2.1-or-later': 'medium',
  'LGPL-3.0-only': 'medium',
  'LGPL-3.0-or-later': 'medium',
  'MPL-2.0': 'medium',
  'MPL-1.1': 'medium',
  'EPL-2.0': 'medium',
  'EPL-1.0': 'medium',
  'CDDL-1.0': 'medium',
  'EUPL-1.1': 'medium',
  'EUPL-1.2': 'medium',
  'APSL-2.0': 'medium',
  'CPAL-1.0': 'medium',
  'OSL-3.0': 'medium',
  'CPL-1.0': 'medium',
  'CC-BY-4.0': 'medium',
  'CC-BY-SA-4.0': 'medium',
  // Strong copyleft — high
  'GPL-2.0-only': 'high',
  'GPL-2.0-or-later': 'high',
  'GPL-3.0-only': 'high',
  'GPL-3.0-or-later': 'high',
  'BSL-1.1': 'high',
  'CC-BY-NC-4.0': 'high',
  'CC-BY-NC-SA-4.0': 'high',
  'CC-BY-ND-4.0': 'high',
  // Network copyleft — critical
  'AGPL-3.0-only': 'critical',
  'AGPL-3.0-or-later': 'critical',
  'SSPL-1.0': 'critical',
};

// ---------------------------------------------------------------------------
// Alias map: lowercased raw string → canonical SPDX ID
// Covers the most common variants reported by npm, pip, and package registries.
// ---------------------------------------------------------------------------

export const ALIAS_MAP: Readonly<Record<string, string>> = {
  // MIT
  'mit': 'MIT',
  'mit license': 'MIT',
  'the mit license': 'MIT',
  'mit/x11': 'MIT',
  'x11': 'X11',
  'mit-0': 'MIT-0',
  'mit0': 'MIT-0',
  // Apache
  'apache-2.0': 'Apache-2.0',
  'apache 2.0': 'Apache-2.0',
  'apache 2': 'Apache-2.0',
  'apache2': 'Apache-2.0',
  'apache license 2.0': 'Apache-2.0',
  'apache license, version 2.0': 'Apache-2.0',
  'apache software license 2.0': 'Apache-2.0',
  'apache software license, version 2.0': 'Apache-2.0',
  'the apache software license, version 2.0': 'Apache-2.0',
  'asl 2.0': 'Apache-2.0',
  'asf 2.0': 'Apache-2.0',
  'apache-1.1': 'Apache-1.1',
  'apache 1.1': 'Apache-1.1',
  // BSD
  'bsd': 'BSD-2-Clause',
  'bsd license': 'BSD-2-Clause',
  'bsd-2-clause': 'BSD-2-Clause',
  'bsd 2-clause': 'BSD-2-Clause',
  'bsd 2-clause license': 'BSD-2-Clause',
  'bsd 2 clause': 'BSD-2-Clause',
  'simplified bsd': 'BSD-2-Clause',
  'freebsd': 'BSD-2-Clause',
  '2-clause bsd': 'BSD-2-Clause',
  'bsd-3-clause': 'BSD-3-Clause',
  'bsd 3-clause': 'BSD-3-Clause',
  'bsd 3-clause license': 'BSD-3-Clause',
  'bsd 3 clause': 'BSD-3-Clause',
  'new bsd': 'BSD-3-Clause',
  'revised bsd': 'BSD-3-Clause',
  'modified bsd': 'BSD-3-Clause',
  '3-clause bsd': 'BSD-3-Clause',
  'bsd-4-clause': 'BSD-4-Clause',
  '0bsd': '0BSD',
  'bsd zero clause license': '0BSD',
  'bsd-0': '0BSD',
  // ISC
  'isc': 'ISC',
  'isc license': 'ISC',
  'iscl': 'ISC',
  // Unlicense / Public domain
  'unlicense': 'Unlicense',
  'the unlicense': 'Unlicense',
  'public domain': 'CC0-1.0',
  'cc0-1.0': 'CC0-1.0',
  'cc0': 'CC0-1.0',
  'cc0 1.0': 'CC0-1.0',
  'creative commons zero': 'CC0-1.0',
  'creative commons zero v1.0': 'CC0-1.0',
  'creative commons zero v1.0 universal': 'CC0-1.0',
  // GPL-2
  'gpl-2.0': 'GPL-2.0-only',
  'gpl-2.0-only': 'GPL-2.0-only',
  'gpl-2': 'GPL-2.0-only',
  'gpl2': 'GPL-2.0-only',
  'gplv2': 'GPL-2.0-only',
  'gpl v2': 'GPL-2.0-only',
  'gnu gpl v2': 'GPL-2.0-only',
  'gnu general public license v2': 'GPL-2.0-only',
  'gnu general public license v2.0': 'GPL-2.0-only',
  'gnu general public license version 2': 'GPL-2.0-only',
  'gpl-2.0+': 'GPL-2.0-or-later',
  'gpl-2.0-or-later': 'GPL-2.0-or-later',
  'gpl v2+': 'GPL-2.0-or-later',
  'gplv2+': 'GPL-2.0-or-later',
  // GPL-3
  'gpl-3.0': 'GPL-3.0-only',
  'gpl-3.0-only': 'GPL-3.0-only',
  'gpl-3': 'GPL-3.0-only',
  'gpl3': 'GPL-3.0-only',
  'gplv3': 'GPL-3.0-only',
  'gpl v3': 'GPL-3.0-only',
  'gnu gpl v3': 'GPL-3.0-only',
  'gnu gpl': 'GPL-3.0-only',
  'gnu general public license v3': 'GPL-3.0-only',
  'gnu general public license v3.0': 'GPL-3.0-only',
  'gnu general public license version 3': 'GPL-3.0-only',
  'gnu general public license': 'GPL-3.0-only',
  'gpl-3.0+': 'GPL-3.0-or-later',
  'gpl-3.0-or-later': 'GPL-3.0-or-later',
  'gpl v3+': 'GPL-3.0-or-later',
  'gplv3+': 'GPL-3.0-or-later',
  // LGPL-2
  'lgpl-2.0': 'LGPL-2.0-only',
  'lgpl-2.0-only': 'LGPL-2.0-only',
  'lgpl 2.0': 'LGPL-2.0-only',
  'lgpl-2.1': 'LGPL-2.1-only',
  'lgpl-2.1-only': 'LGPL-2.1-only',
  'lgpl 2.1': 'LGPL-2.1-only',
  'lgplv2': 'LGPL-2.1-only',
  'lgpl v2': 'LGPL-2.1-only',
  'lgpl v2.1': 'LGPL-2.1-only',
  'gnu lesser general public license v2': 'LGPL-2.0-only',
  'gnu lesser general public license v2.1': 'LGPL-2.1-only',
  'lgpl-2.0+': 'LGPL-2.0-or-later',
  'lgpl-2.0-or-later': 'LGPL-2.0-or-later',
  'lgpl-2.1+': 'LGPL-2.1-or-later',
  'lgpl-2.1-or-later': 'LGPL-2.1-or-later',
  // LGPL-3
  'lgpl-3.0': 'LGPL-3.0-only',
  'lgpl-3.0-only': 'LGPL-3.0-only',
  'lgpl 3.0': 'LGPL-3.0-only',
  'lgplv3': 'LGPL-3.0-only',
  'lgpl v3': 'LGPL-3.0-only',
  'gnu lesser general public license v3': 'LGPL-3.0-only',
  'lgpl-3.0+': 'LGPL-3.0-or-later',
  'lgpl-3.0-or-later': 'LGPL-3.0-or-later',
  // AGPL
  'agpl-3.0': 'AGPL-3.0-only',
  'agpl-3.0-only': 'AGPL-3.0-only',
  'agplv3': 'AGPL-3.0-only',
  'agpl v3': 'AGPL-3.0-only',
  'gnu agpl v3': 'AGPL-3.0-only',
  'gnu affero general public license v3': 'AGPL-3.0-only',
  'gnu affero general public license v3.0': 'AGPL-3.0-only',
  'agpl-3.0+': 'AGPL-3.0-or-later',
  'agpl-3.0-or-later': 'AGPL-3.0-or-later',
  // MPL
  'mpl-2.0': 'MPL-2.0',
  'mpl 2.0': 'MPL-2.0',
  'mpl2': 'MPL-2.0',
  'mozilla public license 2.0': 'MPL-2.0',
  'mozilla public license, version 2.0': 'MPL-2.0',
  'mpl-1.1': 'MPL-1.1',
  'mpl 1.1': 'MPL-1.1',
  'mozilla public license 1.1': 'MPL-1.1',
  // EPL
  'epl-2.0': 'EPL-2.0',
  'epl 2.0': 'EPL-2.0',
  'eclipse public license 2.0': 'EPL-2.0',
  'eclipse public license - v 2.0': 'EPL-2.0',
  'epl-1.0': 'EPL-1.0',
  'epl 1.0': 'EPL-1.0',
  'eclipse public license 1.0': 'EPL-1.0',
  'eclipse public license - v 1.0': 'EPL-1.0',
  // CDDL
  'cddl-1.0': 'CDDL-1.0',
  'cddl 1.0': 'CDDL-1.0',
  'common development and distribution license 1.0': 'CDDL-1.0',
  // Python / PSF
  'python-2.0': 'Python-2.0',
  'psf': 'PSF-2.0',
  'psf-2.0': 'PSF-2.0',
  'psfl': 'PSF-2.0',
  'python software foundation license': 'PSF-2.0',
  'python software foundation license v2': 'PSF-2.0',
  // Creative Commons
  'cc-by-4.0': 'CC-BY-4.0',
  'cc by 4.0': 'CC-BY-4.0',
  'creative commons attribution 4.0': 'CC-BY-4.0',
  'creative commons attribution 4.0 international': 'CC-BY-4.0',
  'cc-by-sa-4.0': 'CC-BY-SA-4.0',
  'cc-by-nc-4.0': 'CC-BY-NC-4.0',
  'cc-by-nc-sa-4.0': 'CC-BY-NC-SA-4.0',
  'cc-by-nd-4.0': 'CC-BY-ND-4.0',
  // Other
  'zlib': 'Zlib',
  'zlib/libpng': 'Zlib',
  'zlib license': 'Zlib',
  'boost-1.0': 'Boost-1.0',
  'bsl-1.0': 'Boost-1.0',
  'boost software license 1.0': 'Boost-1.0',
  'boost software license': 'Boost-1.0',
  'bsl-1.1': 'BSL-1.1',
  'busl-1.1': 'BSL-1.1',
  'business source license 1.1': 'BSL-1.1',
  'sspl-1.0': 'SSPL-1.0',
  'server side public license': 'SSPL-1.0',
  'server side public license v1': 'SSPL-1.0',
  'artistic-2.0': 'Artistic-2.0',
  'artistic license 2.0': 'Artistic-2.0',
  'perl': 'Artistic-2.0',
  'artistic-1.0': 'Artistic-1.0',
  'ruby': 'Ruby',
  'eupl-1.2': 'EUPL-1.2',
  'eupl 1.2': 'EUPL-1.2',
  'eupl-1.1': 'EUPL-1.1',
  'wtfpl': 'WTFPL',
  'do what the fuck you want to public license': 'WTFPL',
  'ofl-1.1': 'OFL-1.1',
  'sil open font license 1.1': 'OFL-1.1',
  'sil open font license': 'OFL-1.1',
  'openssl': 'OpenSSL',
  'openssl license': 'OpenSSL',
  'unicode-dfs-2016': 'Unicode-DFS-2016',
  'hpnd': 'HPND',
  'historical permission notice and disclaimer': 'HPND',
  'vim': 'Vim',
};

/**
 * Strings that indicate a package is proprietary or otherwise unlicensed.
 * These are not SPDX identifiers but are common in npm package.json files.
 */
const PROPRIETARY_MARKERS = new Set([
  'unlicensed',
  'proprietary',
  'commercial',
  'all rights reserved',
  'see license in license',
  'see license in license.md',
  'see license in license.txt',
  'see license in readme',
  'see license in readme.md',
  'copyright',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Normalizes a raw license string to a canonical SPDX identifier and evaluates risk.
 *
 * Handles:
 *   - Case-insensitive alias matching (e.g. "Apache 2.0" → "Apache-2.0")
 *   - Trailing parentheticals (e.g. "MIT License (MIT)" → "MIT")
 *   - SPDX expression operators (OR/AND/WITH)
 *   - Proprietary/unlicensed markers
 */
export function normalizeLicense(raw: string): NormalizationResult {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();

  if (PROPRIETARY_MARKERS.has(lower)) {
    return { spdxId: null, normalized: trimmed, riskLevel: 'unknown', isSpdxExpression: false, originalRaw: raw };
  }

  // Detect SPDX expression operators — handle before alias lookup
  if (/\b(AND|OR|WITH)\b/i.test(trimmed)) {
    return _normalizeSpdxExpression(trimmed, raw);
  }

  // Strip trailing parentheticals added by some tools (e.g. "MIT License (MIT)")
  const cleaned = trimmed.replace(/\s*\([^)]*\)\s*$/, '').trim();

  // Direct match on canonical SPDX ID (exact case)
  if (SPDX_RISK_MAP[cleaned] !== undefined) {
    return { spdxId: cleaned, normalized: cleaned, riskLevel: SPDX_RISK_MAP[cleaned], isSpdxExpression: false, originalRaw: raw };
  }

  // Alias map lookup (case-insensitive)
  const aliasKey = cleaned.toLowerCase();
  const spdxId = ALIAS_MAP[aliasKey];
  if (spdxId) {
    const riskLevel = SPDX_RISK_MAP[spdxId] ?? 'unknown';
    return { spdxId, normalized: spdxId, riskLevel, isSpdxExpression: false, originalRaw: raw };
  }

  // Unrecognized
  return { spdxId: null, normalized: trimmed, riskLevel: 'unknown', isSpdxExpression: false, originalRaw: raw };
}

/**
 * Returns the risk level for a canonical SPDX ID.
 * Returns 'unknown' if the ID is not in the built-in risk map.
 */
export function evaluateLicenseRisk(spdxId: string): LicenseRiskLevel {
  return SPDX_RISK_MAP[spdxId] ?? 'unknown';
}

// ---------------------------------------------------------------------------
// SPDX expression handling
// ---------------------------------------------------------------------------

/**
 * Evaluates a compound SPDX expression:
 *   OR  — consumer chooses the better license → minimum risk wins
 *   AND — all licenses apply simultaneously → maximum risk governs
 *   WITH — exception modifier; base license risk is preserved
 *
 * Nested parentheses are not parsed (covers >95% of real-world expressions).
 */
function _normalizeSpdxExpression(expression: string, raw: string): NormalizationResult {
  const stripped = expression.replace(/^\(|\)$/g, '').trim();

  const orTokens = stripped.split(/\s+OR\s+/i);
  if (orTokens.length > 1) {
    let best: NormalizationResult | null = null;
    for (const token of orTokens) {
      const part = normalizeLicense(token.trim());
      if (!best || riskMin(best.riskLevel, part.riskLevel) !== best.riskLevel) {
        best = part;
      }
    }
    return { ...best!, normalized: expression, isSpdxExpression: true, originalRaw: raw };
  }

  const andTokens = stripped.split(/\s+AND\s+/i);
  if (andTokens.length > 1) {
    let worst: NormalizationResult | null = null;
    for (const token of andTokens) {
      const part = normalizeLicense(token.trim());
      if (!worst || riskMax(worst.riskLevel, part.riskLevel) !== worst.riskLevel) {
        worst = part;
      }
    }
    return { ...worst!, normalized: expression, isSpdxExpression: true, originalRaw: raw };
  }

  // WITH exception: keep base license risk
  const withTokens = stripped.split(/\s+WITH\s+/i);
  if (withTokens.length > 1) {
    const base = normalizeLicense(withTokens[0].trim());
    return { ...base, normalized: expression, isSpdxExpression: true, originalRaw: raw };
  }

  return normalizeLicense(expression);
}
