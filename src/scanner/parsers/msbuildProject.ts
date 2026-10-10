/**
 * MSBuild project file `PackageReference`, central package management
 * (`Directory.Packages.props`) and `packages.config` readers (REQ-006
 * AC-P20-5…7; ADR-008 Karar 5.4–5.6).
 *
 * Nothing is evaluated: no `Import`, `Sdk`, `PropertyGroup`, `Condition` or
 * `$(…)` property (a property version is simply unknown). `ItemGroup`s
 * directly under `Project` and inside `Choose`/`When`/`Otherwise` are read
 * (conditions ignored, all merged); `ItemGroup`s inside `Target` are build
 * steps and are never read. MSBuild element and attribute names are
 * compared ASCII case-insensitively.
 *
 * Pure functions of the file bytes; imports only `./` modules (ADR-008 Karar 1).
 */
import {
  NUGET_MESSAGES,
  NugetFileError,
  sanitizeDeclaredRange,
  type NugetEntry,
  type NugetIssue,
} from './common';
import { asciiLower, classifyNugetVersion, isValidNugetId } from './nugetIdentity';
import { IssueSet } from './nugetLock';
import { XmlError, parseXml, type XmlElement } from './xmlReader';

export const CPM_FILE_NAME = 'Directory.Packages.props';
export const PACKAGES_CONFIG_FILE_NAME = 'packages.config';

/** XML of a repository file; reader errors become the fixed file error texts. */
function readXml(data: Uint8Array): XmlElement {
  try {
    return parseXml(data);
  } catch (err) {
    if (err instanceof XmlError) {
      switch (err.code) {
        case 'doctype':
          throw new NugetFileError(NUGET_MESSAGES.xmlDoctype);
        case 'limit':
          throw new NugetFileError(NUGET_MESSAGES.xmlLimit);
        case 'encoding':
          throw new NugetFileError(NUGET_MESSAGES.xmlEncoding);
        default:
          throw new NugetFileError(NUGET_MESSAGES.xmlMalformed);
      }
    }
    throw new NugetFileError(NUGET_MESSAGES.xmlMalformed);
  }
}

function isNamed(element: XmlElement, lowerName: string): boolean {
  return asciiLower(element.localName) === lowerName;
}

/** First attribute with this name (ASCII case-insensitive), or null. */
function attribute(element: XmlElement, lowerName: string): string | null {
  for (const [name, value] of element.attributes) {
    if (asciiLower(name) === lowerName) return value;
  }
  return null;
}

/** First child element with this local name (ASCII case-insensitive), or null. */
function child(element: XmlElement, lowerName: string): XmlElement | null {
  for (const c of element.children) if (isNamed(c, lowerName)) return c;
  return null;
}

function isBlank(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return false;
  }
  return true;
}

/** Value of an attribute, then of a child element; blank values count as absent. */
function attributeOrChild(element: XmlElement, lowerName: string): string | null {
  const attr = attribute(element, lowerName);
  if (attr !== null && !isBlank(attr)) return attr;
  const node = child(element, lowerName);
  if (node !== null && !isBlank(node.text)) return node.text;
  return null;
}

/** `ItemGroup` elements under `Project`, including `Choose`/`When`/`Otherwise`, never under `Target`. */
function itemGroups(project: XmlElement): XmlElement[] {
  const groups: XmlElement[] = [];
  const visit = (parent: XmlElement): void => {
    for (const c of parent.children) {
      if (isNamed(c, 'itemgroup')) groups.push(c);
      else if (isNamed(c, 'choose') || isNamed(c, 'when') || isNamed(c, 'otherwise')) visit(c);
    }
  };
  visit(project);
  return groups;
}

function projectRoot(data: Uint8Array): XmlElement {
  const root = readXml(data);
  if (!isNamed(root, 'project')) throw new NugetFileError(NUGET_MESSAGES.structure);
  return root;
}

/** One `PackageReference` before the CPM lookup: `explicitVersion` is `VersionOverride ?? Version` (raw text). */
export interface ProjectReference {
  id: string;
  explicitVersion: string | null;
}

export interface ProjectFileResult {
  references: ProjectReference[];
  issues: NugetIssue[];
}

export function parseProjectFile(data: Uint8Array): ProjectFileResult {
  const root = projectRoot(data);
  const issues = new IssueSet();
  const references: ProjectReference[] = [];
  for (const group of itemGroups(root)) {
    for (const item of group.children) {
      if (!isNamed(item, 'packagereference')) continue;
      const include = attribute(item, 'include');
      if (include === null) {
        // `Update`/`Remove` items modify references of imported files: skipped.
        if (attribute(item, 'update') === null && attribute(item, 'remove') === null) issues.add('invalidId');
        continue;
      }
      if (!isValidNugetId(include)) {
        issues.add('invalidId');
        continue;
      }
      references.push({ id: include, explicitVersion: attributeOrChild(item, 'versionoverride') ?? attributeOrChild(item, 'version') });
    }
  }
  return { references, issues: issues.list() };
}

export interface CentralPackages {
  /** `asciiLower(id)` -> raw version text (first in document order wins). */
  versions: Map<string, string>;
  /** `GlobalPackageReference` items in document order (raw version text). */
  globals: ProjectReference[];
  issues: NugetIssue[];
}

export function parseCentralPackages(data: Uint8Array): CentralPackages {
  const root = projectRoot(data);
  const issues = new IssueSet();
  const versions = new Map<string, string>();
  const globals: ProjectReference[] = [];
  for (const group of itemGroups(root)) {
    for (const item of group.children) {
      const isVersion = isNamed(item, 'packageversion');
      const isGlobal = isNamed(item, 'globalpackagereference');
      if (!isVersion && !isGlobal) continue;
      const include = attribute(item, 'include');
      if (include === null) continue; // `Update` items are ignored
      if (isVersion && attribute(item, 'update') !== null) continue;
      if (!isValidNugetId(include)) {
        issues.add('invalidId');
        continue;
      }
      const version = attributeOrChild(item, 'version');
      if (isVersion) {
        const key = asciiLower(include);
        if (version !== null && !versions.has(key)) versions.set(key, version);
      } else {
        globals.push({ id: include, explicitVersion: version });
      }
    }
  }
  return { versions, globals, issues: issues.list() };
}

/** Record of a direct reference whose raw version text is `raw` (null: no version anywhere). */
export function directEntry(id: string, raw: string | null, manifestFile: string, keepExactRange = true): NugetEntry {
  if (raw === null) return { name: id, version: null, scope: 'direct', declaredRange: null, manifestFile };
  const version = classifyNugetVersion(raw);
  const exact = version.kind === 'exact' ? version.version : null;
  const declaredRange = exact !== null && !keepExactRange ? null : sanitizeDeclaredRange(raw);
  return { name: id, version: exact, scope: 'direct', declaredRange, manifestFile };
}

export interface PackagesConfigResult {
  entries: NugetEntry[];
  issues: NugetIssue[];
}

/** `packages.config`: `package` children of `packages` (`developmentDependency` etc. ignored). */
export function parsePackagesConfig(data: Uint8Array): PackagesConfigResult {
  const root = readXml(data);
  if (root.localName !== 'packages') throw new NugetFileError(NUGET_MESSAGES.structure);
  const issues = new IssueSet();
  const entries: NugetEntry[] = [];
  for (const item of root.children) {
    if (item.localName !== 'package') continue;
    let id: string | null = null;
    let version: string | null = null;
    for (const [name, value] of item.attributes) {
      if (name === 'id' && id === null) id = value;
      else if (name === 'version' && version === null) version = value;
    }
    if (!isValidNugetId(id)) {
      issues.add('invalidId');
      continue;
    }
    entries.push(directEntry(id, version !== null && !isBlank(version) ? version : null, PACKAGES_CONFIG_FILE_NAME, false));
  }
  return { entries, issues: issues.list() };
}
