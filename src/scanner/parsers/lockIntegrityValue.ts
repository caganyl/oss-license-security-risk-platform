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

  private readonly nugetSeen = new Set<string>();
  /** NuGet records (REQ-006 AC-P20-16, ADR-008 Karar 6); kept apart from the npm `records`. */
  readonly nugetRecords: LockIntegrityRecord[] = [];

  /**
   * Adds a NuGet `contentHash` / `sha512` value (base64 SHA-512) as
   * `sha512-<base64>` when it is exactly 86 base64 characters plus `==`;
   * anything else is dropped. `name` keeps the source casing, `version` is
   * the normalized form.
   */
  addNuget(manifestPath: string, name: string, version: string, base64Sha512: unknown): void {
    if (!isNugetSha512Base64(base64Sha512)) return;
    const integrity = `sha512-${base64Sha512}`;
    if (!isAcceptableLockIntegrity(integrity)) return;
    const key = `${manifestPath}\u0000${name}\u0000${version}\u0000${integrity}`;
    if (this.nugetSeen.has(key)) return;
    this.nugetSeen.add(key);
    this.nugetRecords.push({ manifestPath, name, version, integrity });
  }
}

/** Base64 form of a 64-byte SHA-512: `^[A-Za-z0-9+/]{86}==$` (hand-written check). */
export function isNugetSha512Base64(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 88) return false;
  if (value.charCodeAt(86) !== 0x3d || value.charCodeAt(87) !== 0x3d) return false;
  for (let i = 0; i < 86; i++) {
    const c = value.charCodeAt(i);
    const ok = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2f;
    if (!ok) return false;
  }
  return true;
}

/** Side-channel form of a NuGet value: `sha512-` + the base64 check above. */
export function isNugetLockIntegrity(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith('sha512-') && isNugetSha512Base64(value.slice(7));
}
