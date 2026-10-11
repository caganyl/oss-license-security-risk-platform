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
 * PyPI is never compared. The side-channel bounds live next to the parsers
 * (`src/scanner/parsers/lockIntegrityValue.ts`, the thread may only load that
 * folder) and are re-exported here.
 */
import type { LockIntegrityRecord } from '../scanner/parsers/lockIntegrityValue';
import { parseSriSha512 } from './integrity';
import type { ArchiveCandidate } from './types';

export { IntegrityCollector, LOCK_INTEGRITY_CHARS_RE, MAX_LOCK_INTEGRITY_CHARS, isAcceptableLockIntegrity, type LockIntegrityRecord } from '../scanner/parsers/lockIntegrityValue';

export type LockIntegrity = 'match' | 'mismatch' | 'not_comparable';

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
