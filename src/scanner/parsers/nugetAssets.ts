/**
 * `obj/project.assets.json` v3/v4 reader (REQ-006 AC-P20-4; ADR-008 Karar 5.3; REQ-009 P-32).
 *
 * Reads only `version`, `libraries.*.type`, `libraries.*.sha512` and
 * `project.frameworks.*.dependencies.*.version`. Nothing else (restore
 * settings, package folders, logs, targets, library paths/files) is read,
 * kept or written to an error text: those fields carry absolute paths of the
 * build machine.
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
  type NugetSourceResult,
} from './common';
import { asciiLower, classifyNugetVersion, isValidNugetId, nugetKey } from './nugetIdentity';
import { IssueSet, parseNugetJson } from './nugetLock';

export const ASSETS_FILE_NAME = 'project.assets.json';

/**
 * Accepted `version` values (REQ-009 D-259). The .NET 10 SDK writes 4; every
 * field read here has the same shape in 3 and 4.
 */
const ASSETS_VERSIONS: ReadonlySet<unknown> = new Set([3, 4]);

/** Direct dependency ids (`asciiLower`) -> declared range of the first framework (code point order). */
function directDependencies(project: unknown): Map<string, string | null> {
  const direct = new Map<string, string | null>();
  if (!isPyDict(project) || !isPyDict(project.frameworks)) return direct;
  const frameworks = project.frameworks;
  for (const framework of Object.keys(frameworks).sort(compareCodePoints)) {
    const entry = frameworks[framework];
    if (!isPyDict(entry) || !isPyDict(entry.dependencies)) continue;
    for (const [id, value] of Object.entries(entry.dependencies)) {
      const key = asciiLower(id);
      if (direct.has(key)) continue;
      const range = isPyDict(value) && typeof value.version === 'string' ? sanitizeDeclaredRange(value.version) : null;
      direct.set(key, range);
    }
  }
  return direct;
}

export function parseNugetAssets(data: Uint8Array): NugetSourceResult {
  const root = parseNugetJson(data);
  if (!isPyDict(root)) throw new NugetFileError(NUGET_MESSAGES.structure);
  if (!ASSETS_VERSIONS.has(root.version)) throw new NugetFileError(NUGET_MESSAGES.assetsVersion);
  const libraries = root.libraries;
  if (!isPyDict(libraries)) throw new NugetFileError(NUGET_MESSAGES.structure);

  const direct = directDependencies(root.project);
  const issues = new IssueSet();
  const byKey = new Map<string, NugetEntry>();
  const hashes: NugetHashRecord[] = [];
  for (const [libraryKey, value] of Object.entries(libraries)) {
    const slash = libraryKey.indexOf('/');
    if (slash === -1 || libraryKey.indexOf('/', slash + 1) !== -1 || !isPyDict(value)) {
      issues.add('invalidEntry');
      continue;
    }
    const type = value.type;
    if (type === 'project') continue;
    if (type !== 'package') {
      issues.add('unknownType');
      continue;
    }
    const id = libraryKey.slice(0, slash);
    if (!isValidNugetId(id)) {
      issues.add('invalidId');
      continue;
    }
    const version = classifyNugetVersion(libraryKey.slice(slash + 1));
    if (version.kind !== 'exact') {
      issues.add('invalidEntry');
      continue;
    }
    const key = nugetKey(id, version.version);
    if (!byKey.has(key)) {
      if (byKey.size >= NUGET_MAX_DEPENDENCIES_PER_FOLDER) throw new NugetFileError(NUGET_MESSAGES.limit);
      const lowerId = asciiLower(id);
      const isDirect = direct.has(lowerId);
      byKey.set(key, {
        name: id,
        version: version.version,
        scope: isDirect ? 'direct' : 'transitive',
        declaredRange: isDirect ? (direct.get(lowerId) ?? null) : null,
        manifestFile: ASSETS_FILE_NAME,
      });
    }
    if (value.sha512 !== undefined) hashes.push({ name: id, version: version.version, hash: value.sha512 });
  }
  return { entries: [...byKey.values()], issues: issues.list(), hashes };
}
