/**
 * L-6 precedence: effective license, its source, the lockfile hint and the
 * policy input of one scanned package (REQ-004 AC-L6-1…4, D-54, D-81;
 * ADR-006 Karar 11), plus the `[registry]` summary line (contract section 8).
 *
 * | status                                          | effective license        | source                    | policy input        |
 * | ----------------------------------------------- | ------------------------ | ------------------------- | ------------------- |
 * | ok                                              | normalize(declared)      | registry:npm / pypi       | [declared]          |
 * | no_license                                      | none                     | none                      | [] (NOASSERTION)    |
 * | not_found, unreachable, error, budget, disabled | hint, else none          | lockfile (unverified)/none| dep.licenses, else []|
 * | version_unknown, invalid_coordinates            | none                     | none                      | [] (NOASSERTION)    |
 *
 * The enricher classifies `disabled` first (D-81: with enrichment off a
 * version-less package is `disabled` and keeps its hint, AC-G-8).
 *
 * Pure module: only type imports; the normalizer and the text cleanup are
 * injected (ADR-006 Karar 1).
 */
import type { RegistryEcosystem } from './coordinates';
import type { EnrichmentStatus, LicenseSource } from './types';

/** Maximum lock hint length in code points (ADR-006 Karar 11, AC-L6-4). */
export const MAX_LOCK_HINT_CHARS = 200;

/** Statuses whose lock hint becomes the effective license (AC-L6-3). */
export const HINT_FALLBACK_STATUSES: ReadonlySet<EnrichmentStatus> = new Set<EnrichmentStatus>([
  'not_found',
  'unreachable',
  'error',
  'budget_exceeded',
  'disabled',
]);

export interface EffectiveLicenseInput {
  status: EnrichmentStatus;
  ecosystem: RegistryEcosystem;
  /** Registry declaration (status `ok`). */
  declaredLicense: string | null;
  /** Parser's `dep.licenses` (already unique and sorted). */
  lockLicenses: readonly string[];
  /** `normalizeLicense(raw).normalized`. */
  normalize: (raw: string) => string;
  /** ADR-006 Karar 8 cleanup (`sanitizeText`). */
  sanitize: (text: string) => string;
}

export interface EffectiveLicense {
  /** `scan_dependencies.license_expression`; null = no effective license. */
  licenseExpression: string | null;
  licenseSource: LicenseSource;
  /** `scan_dependencies.license_lock_hint`; null when the lockfile declares nothing. */
  lockHint: string | null;
  /** `scan_dependencies.license_hint_differs`: set only for `ok` with a hint. */
  hintDiffers: boolean | null;
  /** Licenses evaluated by the policy loop (unchanged F2 loop, D-73). */
  policyInput: string[];
}

function cutCodePoints(text: string, max: number): string {
  const chars = Array.from(text);
  return chars.length <= max ? text : chars.slice(0, max).join('');
}

/** Lock hint text: cleaned items joined with ` AND `, cut to 200 code points; null when empty. */
export function lockHintOf(lockLicenses: readonly string[], sanitize: (text: string) => string): string | null {
  const items = lockLicenses
    .filter((l): l is string => typeof l === 'string')
    .map((l) => sanitize(l).replace(/\n/g, ' ').trim())
    .filter((l) => l.length > 0);
  if (items.length === 0) return null;
  return cutCodePoints(items.join(' AND '), MAX_LOCK_HINT_CHARS);
}

/** Comparison form of a license list (AC-L6-4): normalized items, upper case, sorted, ` AND `-joined. */
function comparisonForm(items: readonly string[], normalize: (raw: string) => string): string {
  return items
    .map((item) => normalize(item).toUpperCase())
    .sort()
    .join(' AND ');
}

export function resolveEffectiveLicense(input: EffectiveLicenseInput): EffectiveLicense {
  const lockItems = input.lockLicenses.filter((l): l is string => typeof l === 'string' && l.trim().length > 0);
  const lockHint = lockHintOf(lockItems, input.sanitize);

  if (input.status === 'ok' && input.declaredLicense !== null && input.declaredLicense.trim() !== '') {
    const declared = input.declaredLicense;
    const hintDiffers = lockHint === null ? null : comparisonForm([declared], input.normalize) !== comparisonForm(lockItems, input.normalize);
    return {
      licenseExpression: input.normalize(declared),
      licenseSource: input.ecosystem === 'npm' ? 'registry:npm' : 'registry:pypi',
      lockHint,
      hintDiffers,
      policyInput: [declared],
    };
  }

  if (HINT_FALLBACK_STATUSES.has(input.status) && lockHint !== null) {
    return {
      licenseExpression: lockHint,
      licenseSource: 'lockfile (unverified)',
      lockHint,
      hintDiffers: null,
      policyInput: [...input.lockLicenses],
    };
  }

  // no_license (AC-L6-2), version_unknown / invalid_coordinates (D-81), or no hint.
  return { licenseExpression: null, licenseSource: 'none', lockHint, hintDiffers: null, policyInput: [] };
}

// ---------------------------------------------------------------------------
// `[registry]` summary line (contract section 8)
// ---------------------------------------------------------------------------

export interface SummaryEntry {
  status: EnrichmentStatus;
  /** The package fell back to its lock hint (effective source `lockfile (unverified)`). */
  usedHint: boolean;
}

/**
 * The single `[registry]` line for unique registry keys, or null when none
 * is due (enrichment on and no `unreachable`/`error`/`budget_exceeded` key).
 * The caller passes it through `sanitizeErrorText` with the parse errors.
 */
export function registrySummaryLine(entries: Iterable<SummaryEntry>, enabled: boolean): string | null {
  let total = 0;
  let hinted = 0;
  let unreachable = 0;
  let error = 0;
  let budget = 0;
  let affectedHinted = 0;
  for (const entry of entries) {
    total++;
    if (entry.usedHint) hinted++;
    if (entry.status === 'unreachable') unreachable++;
    else if (entry.status === 'error') error++;
    else if (entry.status === 'budget_exceeded') budget++;
    else continue;
    if (entry.usedHint) affectedHinted++;
  }
  if (!enabled) {
    return `[registry] License enrichment disabled: ${hinted} package(s) use the lockfile license (unverified), ${total - hinted} have no license.`;
  }
  const affected = unreachable + error + budget;
  if (affected === 0) return null;
  return (
    `[registry] Registry lookup incomplete for ${affected} package(s) (unreachable: ${unreachable}, error: ${error}, ` +
    `time budget exceeded: ${budget}); license from lockfile (unverified): ${affectedHinted}, no license: ${affected - affectedHinted}.`
  );
}
