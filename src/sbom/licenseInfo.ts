/**
 * Effective license and copyright of one SBOM package (REQ-004 contract
 * `docs/contracts/REQ-004-notice-and-outputs.md` section 6, ADR-006 Karar 13,
 * AC-P16-1…7). Shared by the SPDX and CycloneDX writers so every format makes
 * the same choice for the same scan.
 */
import { canonicalizeSpdxExpression } from '../lib/spdxExpression';
import type { SbomDependency } from './sbomService';

export interface SbomLicenseInfo {
  /** Effective license input `L` (cleaned single-line), or null when there is none. */
  declared: string | null;
  /** Canonical SPDX expression `C`, or null when `L` is missing or invalid. */
  canonical: string | null;
  /** True when `L` exists but is not a valid SPDX expression. */
  invalid: boolean;
  /** `license_source = 'lockfile (unverified)'` (C-11). */
  lockfileSource: boolean;
  /** Extracted copyright lines (archive cache); empty for pre-F3 scans and dev packages. */
  copyrightLines: string[];
}

/**
 * - F3 scan (`license_source` set): `L` = `license_expression`.
 * - Pre-F3 scan (`license_source IS NULL`): `L` = the package's
 *   `license_findings` values (`normalizedLicense`, else `detectedLicense`),
 *   unique in first-seen order, joined with ` AND ` (AC-P16-2).
 * Validity: `canonicalizeSpdxExpression(L, knownIds)` (AC-P16-3).
 */
export function sbomLicenseInfo(dep: SbomDependency, knownIds: ReadonlyMap<string, string>): SbomLicenseInfo {
  let declared: string | null;
  if (dep.licenseSource !== null) {
    declared = nonEmpty(dep.licenseExpression);
  } else {
    const ids: string[] = [];
    for (const l of dep.licenses) {
      const value = nonEmpty(l.normalizedLicense) ?? nonEmpty(l.detectedLicense);
      if (value !== null && !ids.includes(value)) ids.push(value);
    }
    declared = ids.length > 0 ? ids.join(' AND ') : null;
  }
  const canonical = declared === null ? null : canonicalizeSpdxExpression(declared, knownIds);
  return {
    declared,
    canonical,
    invalid: declared !== null && canonical === null,
    lockfileSource: dep.licenseSource === 'lockfile (unverified)',
    copyrightLines: dep.licenseSource === null ? [] : dep.copyrightLines.filter((line) => line.trim() !== ''),
  };
}

/** True when the canonical expression is compound (`AND`/`OR`/`WITH`), i.e. not a single id. */
export function isCompoundExpression(canonical: string): boolean {
  return /\s(AND|OR|WITH)\s/.test(canonical) || canonical.includes('(');
}

function nonEmpty(value: string | null | undefined): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value : null;
}
