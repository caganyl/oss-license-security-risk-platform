/**
 * L-5 side channel of the npm lock parsers (REQ-005 AC-L5-*; ADR-007 Karar 12).
 *
 * Lives next to the parsers because the parser thread may only load modules
 * of this folder (the compiled thread layout has nothing else); the
 * comparison itself is `src/enrichment/lockIntegrity.ts`, which re-exports
 * these names. Dependency objects never get an `integrity` field: records go
 * to an optional collector instead, so the golden output stays unchanged.
 */

/** One side-channel record (values bounded by `isAcceptableLockIntegrity`). */
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

/**
 * Optional collector passed to the npm parser. Records are deduplicated; the
 * parser adds at most one record per emitted dependency entry, and the thread
 * caps the list at the dependency count.
 */
export class IntegrityCollector {
  private readonly seen = new Set<string>();
  readonly records: LockIntegrityRecord[] = [];

  /** Adds a record when the value passes the side-channel bounds; anything else is dropped. */
  add(manifestPath: string, name: string, version: string, integrity: unknown): void {
    if (!isAcceptableLockIntegrity(integrity)) return;
    const key = `${manifestPath}\u0000${name}\u0000${version}\u0000${integrity}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.records.push({ manifestPath, name, version, integrity });
  }
}
