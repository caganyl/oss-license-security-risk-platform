/**
 * `packages.lock.json` v1/v2 reader (REQ-006 AC-P20-3; ADR-008 Karar 5.2).
 *
 * Pure function of the file bytes: no file system access (the orchestrator
 * `nuget.ts` reads the file). File-level problems throw `NugetFileError`
 * with a fixed text; entry-level problems skip the entry and are reported
 * once per file and kind. `err.message` of `JSON.parse` is never used: newer
 * V8 versions quote source text in it.
 *
 * Imports only `./` modules (ADR-008 Karar 1).
 */
import {
  NUGET_MAX_DEPENDENCIES_PER_FOLDER,
  NUGET_MESSAGES,
  NugetFileError,
  compareCodePoints,
  isPyDict,
  sanitizeDeclaredRange,
  type NugetEntry,
  type NugetHashRecord,
  type NugetIssue,
  type NugetSourceResult,
} from './common';
import { classifyNugetVersion, isValidNugetId, nugetKey } from './nugetIdentity';

const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** JSON root of a .NET JSON file; invalid UTF-8 or JSON is the fixed `JSON ayrıştırılamadı.` error. */
export function parseNugetJson(data: Uint8Array): unknown {
  let text: string;
  try {
    text = STRICT_UTF8.decode(data);
  } catch {
    throw new NugetFileError(NUGET_MESSAGES.json);
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new NugetFileError(NUGET_MESSAGES.json);
  }
}

/** Ordered set of entry issues (first occurrence order). */
export class IssueSet {
  private readonly kinds: NugetIssue[] = [];
  add(kind: NugetIssue): void {
    if (!this.kinds.includes(kind)) this.kinds.push(kind);
  }
  list(): NugetIssue[] {
    return [...this.kinds];
  }
}

export const LOCK_FILE_NAME = 'packages.lock.json';

export function parseNugetLock(data: Uint8Array): NugetSourceResult {
  const root = parseNugetJson(data);
  if (!isPyDict(root)) throw new NugetFileError(NUGET_MESSAGES.structure);
  const version = root.version;
  if (typeof version !== 'number' || (version !== 1 && version !== 2)) throw new NugetFileError(NUGET_MESSAGES.lockVersion);
  const dependencies = root.dependencies;
  if (!isPyDict(dependencies)) throw new NugetFileError(NUGET_MESSAGES.structure);

  const issues = new IssueSet();
  const byKey = new Map<string, NugetEntry>();
  const hashes: NugetHashRecord[] = [];
  const targets = Object.keys(dependencies).sort(compareCodePoints);
  for (const target of targets) {
    const entries = dependencies[target];
    if (!isPyDict(entries)) throw new NugetFileError(NUGET_MESSAGES.structure);
    for (const [id, value] of Object.entries(entries)) {
      if (!isPyDict(value)) {
        issues.add('invalidEntry');
        continue;
      }
      const type = value.type;
      let scope: 'direct' | 'transitive';
      if (type === 'Project') continue;
      if (type === 'Direct') scope = 'direct';
      else if (type === 'Transitive' || type === 'CentralTransitive') scope = 'transitive';
      else {
        issues.add('unknownType');
        continue;
      }
      if (!isValidNugetId(id)) {
        issues.add('invalidId');
        continue;
      }
      const resolved = classifyNugetVersion(value.resolved);
      if (resolved.kind !== 'exact') {
        issues.add('invalidEntry');
        continue;
      }
      const declared = scope === 'direct' && typeof value.requested === 'string' ? sanitizeDeclaredRange(value.requested) : null;
      const key = nugetKey(id, resolved.version);
      const existing = byKey.get(key);
      if (existing) {
        if (scope === 'direct' && existing.scope !== 'direct') {
          existing.scope = 'direct';
          existing.declaredRange = declared;
        }
      } else {
        if (byKey.size >= NUGET_MAX_DEPENDENCIES_PER_FOLDER) throw new NugetFileError(NUGET_MESSAGES.limit);
        byKey.set(key, { name: id, version: resolved.version, scope, declaredRange: declared, manifestFile: LOCK_FILE_NAME });
      }
      if (value.contentHash !== undefined) hashes.push({ name: id, version: resolved.version, hash: value.contentHash });
    }
  }
  return { entries: [...byKey.values()], issues: issues.list(), hashes };
}
