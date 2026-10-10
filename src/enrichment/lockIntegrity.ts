/**
 * L-5 lockfile integrity comparison (REQ-005 AC-L5-*; ADR-007 Karar 12).
 *
 * Pure: compares the npm lockfile `integrity` values collected by the parser
 * thread's side channel with the registry's `dist.integrity` (sha512 archive
 * candidates). Key `(npm, request name, version)` (`coordinateKey`).
 *
 * - No sha512 on one side (lock value absent/broken/sha1, no candidate) ->
 *   `not_comparable` (F3 behaviour).
 * - Every comparable lock record shares at least one digest with the registry
 *   set -> `match`.
 * - At least one comparable lock record shares none -> `mismatch`
 *   (conservative: the same name@version pointing at different archives in two
 *   manifests makes the key mismatch).
 *
 * PyPI is never compared. Wiring (side channel, fail-safe, display) is
 * pending (see the REQ-005 batch 2 report).
 */
import type { ArchiveCandidate } from './types';
import { parseSriSha512 } from './integrity';

export type LockIntegrity = 'match' | 'mismatch' | 'not_comparable';

/** One side-channel record from the parser thread (values bounded there). */
export interface LockIntegrityRecord {
  manifestPath: string;
  name: string;
  version: string;
  integrity: string;
}

/** Maximum length and character set of a side-channel value (checked in the thread). */
export const MAX_LOCK_INTEGRITY_CHARS = 1024;
export const LOCK_INTEGRITY_CHARS_RE = /^[A-Za-z0-9+/=?\-. ]*$/;

/** True when a lockfile `integrity` value may enter the side channel. */
export function isAcceptableLockIntegrity(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_LOCK_INTEGRITY_CHARS && LOCK_INTEGRITY_CHARS_RE.test(value);
}

/** Compares the lock records of one key with the registry archive candidates of that key. */
export function compareLockIntegrity(lockRecords: readonly Pick<LockIntegrityRecord, 'integrity'>[], candidates: readonly ArchiveCandidate[] | null): LockIntegrity {
  const registry = new Set<string>();
  for (const candidate of candidates ?? []) {
    if (candidate.algorithm !== 'sha512') continue;
    for (const digest of candidate.digests) registry.add(digest);
  }
  const comparable = lockRecords.map((record) => parseSriSha512(record.integrity)).filter((values) => values.length > 0);
  if (registry.size === 0 || comparable.length === 0) return 'not_comparable';
  return comparable.every((values) => values.some((value) => registry.has(value))) ? 'match' : 'mismatch';
}
