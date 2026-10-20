/**
 * Java / Kotlin (Maven coordinates) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.java), per folder in this priority (AC-P40-2):
 *   1. `gradle.lockfile` — exact versions (`group:artifact:version=configurations`);
 *      configurations containing only test classpaths -> `dev`, others
 *      runtime (`direct`/`transitive` cannot be told apart: use `transitive`
 *      unless the same folder's build file declares it);
 *   2. `pom.xml` — direct `<dependencies>` (scope `test` -> `dev`,
 *      `provided`/`compile`/`runtime` -> `direct`); `${...}` resolved from
 *      `<properties>`, versions from `<dependencyManagement>`; anything
 *      unresolved (parent POM, BOM import, R-2) -> `version: null` +
 *      `declaredRange`. XML only through `parseXml` of `./xmlReader`
 *      (DOCTYPE/entities rejected, AC-P40-4);
 *   3. `build.gradle` / `build.gradle.kts` — common declaration forms
 *      (`implementation 'g:a:v'`, `implementation("g:a:v")`,
 *      `testImplementation` -> `dev`), best effort (R-1); dynamic versions
 *      (`1.+`, `latest.release`, ranges) -> `version: null` + `declaredRange`.
 * Package name `group:artifact` (D-308); purl `pkg:maven/group/artifact@v`.
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/java/` and its own tests
 * `tests/unit/parser-java*.test.ts`; shared modules are frozen):
 * - signature stays `parseJava(walk: TreeWalk, ctx: ParserContext): ParseResult`
 *   and the function ends with `return ctx.finish();`;
 * - iterate `ctx.folders()` (code point order, `files` by exact name), pick
 *   the source per folder by the priority above, read with
 *   `ctx.read(file, (input) => ...)` (`input.text()` = strict UTF-8 without
 *   BOM, `input.data` = bytes), and add the folder with
 *   `ctx.commit(folder, read.record, entries)` (pass every used source's
 *   record; unused files never enter `scan_files`);
 * - a broken file: throw `new ParserFileError(PARSER_MESSAGES.x)` inside the
 *   read callback (or let the JSON/TOML/YAML/XML reader throw) -> one fixed
 *   Turkish record, the next source/folder continues (AC-P40-3);
 * - `DependencyEntry.name` follows the table in `purl.ts`; the kit builds
 *   the purl, dedupes, applies the 20 000 / 100 000 limits (AC-P40-5) and
 *   sorts the result;
 * - no exact version -> `version: null` + `declaredRange` (AC-P40-6; such a
 *   package never reaches OSV);
 * - never run a build tool, never read outside the walk, never put file
 *   content into an error text.
 *
 * Phase 2 details (decisions inside the contract above):
 * - `gradle.lockfile`: `#` comments, blank lines and the `empty=` line are
 *   skipped. A configuration whose name contains `test` (any case:
 *   `testCompileClasspath`, `androidTestRuntimeClasspath`,
 *   `debugUnitTestRuntimeClasspath`) is a test classpath; an entry listed
 *   only in such configurations is `dev`. Otherwise it is `direct` when the
 *   same folder's `build.gradle(.kts)` or `pom.xml` declares the
 *   `group:artifact` with a non-test configuration/scope (its version as
 *   written becomes `declaredRange`), else `transitive`. Those declaration
 *   files are read and enter `scan_files` with the lock. A malformed line is
 *   skipped with one "invalid entries skipped" record; a lock without a
 *   single valid line but with malformed ones is a structure error and the
 *   folder falls back to `pom.xml` / the build files.
 * - `pom.xml`: root element `project` (else structure error). Only
 *   `project/dependencies/dependency` is read (`<build>`/`<plugins>`,
 *   `<profiles>` and `<reporting>` are not). `${name}` is resolved from
 *   `<properties>` and `project.version`/`version`/`pom.version`,
 *   `project.groupId`, `project.artifactId`, `project.parent.version`,
 *   `project.parent.groupId` (the project's own value, else the parent's);
 *   nesting is followed to depth 16, cycles and results over 1 024 code
 *   units are unresolved. A missing `<version>`/`<scope>` is taken from the
 *   same POM's `<dependencyManagement>`; BOM imports (`scope` `import`) and
 *   the parent POM are never fetched (R-2). Scope `test` -> `dev`;
 *   `<optional>true</optional>` -> `optional`; any other scope -> `direct`.
 *   `declaredRange` is the version as written (own or managed); a version
 *   that is unresolved, a range (`[1.0,2.0)`), dynamic (`LATEST`,
 *   `RELEASE`, `1.+`) or otherwise not a plain version gives
 *   `version: null`. A dependency without a version anywhere gets
 *   `version: null` and no `declaredRange`. A dependency whose `groupId` or
 *   `artifactId` is missing or unresolved is skipped with the "invalid
 *   entries skipped" record.
 * - `build.gradle(.kts)`: a small linear lexer (identifiers, strings,
 *   punctuation; comments dropped; Kotlin `${...}` templates with nested
 *   quotes skipped, nested at most 16 deep) finds dependency configurations (`implementation`,
 *   `api`, `compileOnly`, `runtimeOnly`, `compile`, `runtime`,
 *   `annotationProcessor`, `kapt`, `ksp`, any `<prefix>Implementation` /
 *   `Api` / `CompileOnly` / `RuntimeOnly` / `AnnotationProcessor` and
 *   `kapt<X>` / `ksp<X>`), not preceded by `.`. Arguments: a coordinate
 *   string `g:a[:v[:classifier]][@ext]` (Groovy comma lists too) or the map
 *   / named-argument notation `group: 'g', name: 'a', version: 'v'`
 *   (`group = "g"` in Kotlin). A configuration name containing `test` ->
 *   `dev`. Versions with `$` (variables, `${libs.versions.x.get()}`),
 *   dynamic (`1.+`, `+`, `latest.release`) or ranges -> `version: null` +
 *   `declaredRange` as written; `1.0!!` (strict shorthand) -> `1.0`.
 *   `platform(...)`/`enforcedPlatform(...)`, `project(...)`, `files(...)`,
 *   `kotlin(...)` and version catalog aliases (`libs.x`: the coordinate
 *   lives in `gradle/libs.versions.toml`, outside the walk spec) give no
 *   entry; `constraints { ... }` blocks are skipped. An unterminated string
 *   or block comment is a structure error. A coordinate without a usable
 *   group/artifact is skipped with the "invalid entries skipped" record.
 *   When both `build.gradle` and `build.gradle.kts` exist, both are read.
 * - Entries are committed non-test first, so a package declared both ways
 *   keeps its runtime scope when the kit dedupes `(name, version)`.
 */
import type { DependencyScope, ScannedFile } from '../../types/scan';
import type { ParseResult, TreeWalk, WalkedFile } from './common';
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ManifestFolder, type ParserContext } from './kit';
import { parseXml, type XmlElement } from './xmlReader';

const LOCK_FILE = 'gradle.lockfile';
const POM_FILE = 'pom.xml';
const GRADLE_FILES = ['build.gradle', 'build.gradle.kts'] as const;

/** Longest interpolated `${...}` value of a POM (UTF-16 code units). */
const MAX_INTERPOLATED = 1024;
/** Deepest nesting of `${...}` references followed. */
const MAX_INTERPOLATION_DEPTH = 16;

/** One declared package of a manifest (POM or build script). */
interface Declaration {
  name: string;
  version: string | null;
  /** Version as written, or null when none was written. */
  declared: string | null;
  scope: DependencyScope;
}

interface ManifestData {
  declarations: Declaration[];
  invalid: boolean;
}

interface LockLine {
  name: string;
  version: string;
  testOnly: boolean;
}

interface LockData {
  lines: LockLine[];
  invalid: boolean;
}

interface Loaded<T> {
  file: WalkedFile;
  value: T;
  record: ScannedFile;
}

// ---------------------------------------------------------------- shared rules

/** Maven group id / artifact id usable in `group:artifact` and the purl. */
function validCoordinatePart(value: string): boolean {
  return value !== '' && value.length <= 256 && !/[\s:/\\$@{}]/.test(value);
}

const DYNAMIC_KEYWORDS: ReadonlySet<string> = new Set(['latest', 'release', 'latest.release', 'latest.integration']);

/** A plain Maven/Gradle version (no range, no dynamic selector, no variable). */
export function isExactMavenVersion(version: string): boolean {
  if (!/^[0-9A-Za-z][0-9A-Za-z._~-]*$/.test(version) || version.length > 256) return false;
  return !DYNAMIC_KEYWORDS.has(version.toLowerCase());
}

/** `{version, declared}` of a version text as written (null = none written). */
function versionOf(written: string | null): { version: string | null; declared: string | null } {
  if (written === null || written === '') return { version: null, declared: null };
  if (written.includes('$')) return { version: null, declared: written };
  // Gradle strict shorthand `1.0!!` pins exactly that version.
  const plain = written.endsWith('!!') ? written.slice(0, -2) : written;
  return { version: isExactMavenVersion(plain) ? plain : null, declared: written };
}

function isTestName(name: string): boolean {
  return name.toLowerCase().includes('test');
}

/** Non-test entries first (stable), so the kit's dedupe keeps the runtime scope. */
function runtimeFirst<T extends { scope: DependencyScope }>(list: readonly T[]): T[] {
  return [...list.filter((d) => d.scope !== 'dev'), ...list.filter((d) => d.scope === 'dev')];
}

// ---------------------------------------------------------------- gradle.lockfile

export function parseGradleLockfile(text: string): LockData {
  const lines: LockLine[] = [];
  let invalid = false;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    const coordinate = eq === -1 ? line : line.slice(0, eq);
    if (eq !== -1 && coordinate === 'empty') continue;
    const parts = coordinate.split(':');
    if (eq === -1 || parts.length !== 3 || !validCoordinatePart(parts[0]) || !validCoordinatePart(parts[1]) || parts[2] === '' || /\s/.test(parts[2])) {
      invalid = true;
      continue;
    }
    const configurations = line
      .slice(eq + 1)
      .split(',')
      .map((c) => c.trim())
      .filter((c) => c !== '');
    lines.push({ name: `${parts[0]}:${parts[1]}`, version: parts[2], testOnly: configurations.length > 0 && configurations.every(isTestName) });
  }
  if (lines.length === 0 && invalid) throw new ParserFileError(PARSER_MESSAGES.structure);
  return { lines, invalid };
}

// ---------------------------------------------------------------- pom.xml

function childOf(element: XmlElement, localName: string): XmlElement | null {
  for (const child of element.children) if (child.localName === localName) return child;
  return null;
}

function childrenOf(element: XmlElement | null, localName: string): XmlElement[] {
  return element === null ? [] : element.children.filter((c) => c.localName === localName);
}

function textOf(element: XmlElement, localName: string): string | null {
  const child = childOf(element, localName);
  if (child === null) return null;
  const text = child.text.trim();
  return text === '' ? null : text;
}

/** `${name}` resolver of one POM (properties + project built-ins). */
class PomProperties {
  private readonly values = new Map<string, string>();
  private readonly cache = new Map<string, string | null>();

  constructor(project: XmlElement) {
    const properties = childOf(project, 'properties');
    for (const property of properties?.children ?? []) {
      if (!this.values.has(property.localName)) this.values.set(property.localName, property.text.trim());
    }
    const parent = childOf(project, 'parent');
    const parentVersion = parent ? textOf(parent, 'version') : null;
    const parentGroup = parent ? textOf(parent, 'groupId') : null;
    const version = textOf(project, 'version') ?? parentVersion;
    const group = textOf(project, 'groupId') ?? parentGroup;
    const artifact = textOf(project, 'artifactId');
    const builtIns: Array<[string[], string | null]> = [
      [['project.version', 'pom.version', 'version'], version],
      [['project.groupId', 'pom.groupId', 'groupId'], group],
      [['project.artifactId', 'pom.artifactId', 'artifactId'], artifact],
      [['project.parent.version', 'parent.version'], parentVersion],
      [['project.parent.groupId', 'parent.groupId'], parentGroup],
    ];
    for (const [keys, value] of builtIns) {
      for (const key of keys) {
        if (value !== null) this.values.set(key, value);
        else this.values.delete(key);
      }
    }
  }

  /** The text with every `${name}` replaced, or null when one cannot be resolved. */
  resolve(text: string): string | null {
    return this.interpolate(text, 0, new Set());
  }

  private interpolate(text: string, depth: number, active: Set<string>): string | null {
    let out = '';
    let i = 0;
    while (i < text.length) {
      const start = text.indexOf('${', i);
      if (start === -1) {
        out += text.slice(i);
        break;
      }
      const end = text.indexOf('}', start + 2);
      if (end === -1) return null;
      out += text.slice(i, start);
      const value = this.lookup(text.slice(start + 2, end), depth, active);
      if (value === null) return null;
      out += value;
      if (out.length > MAX_INTERPOLATED) return null;
      i = end + 1;
    }
    return out.length > MAX_INTERPOLATED ? null : out;
  }

  private lookup(name: string, depth: number, active: Set<string>): string | null {
    const cached = this.cache.get(name);
    if (cached !== undefined) return cached;
    const raw = this.values.get(name);
    if (raw === undefined || depth >= MAX_INTERPOLATION_DEPTH || active.has(name)) return null;
    active.add(name);
    const value = this.interpolate(raw, depth + 1, active);
    active.delete(name);
    this.cache.set(name, value);
    return value;
  }
}

interface ManagedDependency {
  version: string | null;
  scope: string | null;
}

export function parsePom(data: Uint8Array): ManifestData {
  const project = parseXml(data);
  if (project.localName !== 'project') throw new ParserFileError(PARSER_MESSAGES.structure);
  const props = new PomProperties(project);
  const coordinateOf = (dependency: XmlElement): string | null => {
    const group = textOf(dependency, 'groupId');
    const artifact = textOf(dependency, 'artifactId');
    if (group === null || artifact === null) return null;
    const g = props.resolve(group);
    const a = props.resolve(artifact);
    if (g === null || a === null || !validCoordinatePart(g) || !validCoordinatePart(a)) return null;
    return `${g}:${a}`;
  };

  const managed = new Map<string, ManagedDependency>();
  const management = childOf(project, 'dependencyManagement');
  for (const dependency of childrenOf(management ? childOf(management, 'dependencies') : null, 'dependency')) {
    const name = coordinateOf(dependency);
    const scope = textOf(dependency, 'scope');
    // A BOM import (`<scope>import</scope>`) would need the imported POM (R-2): not resolved.
    if (name === null || scope === 'import' || managed.has(name)) continue;
    managed.set(name, { version: textOf(dependency, 'version'), scope });
  }

  const declarations: Declaration[] = [];
  let invalid = false;
  for (const dependency of childrenOf(childOf(project, 'dependencies'), 'dependency')) {
    const name = coordinateOf(dependency);
    if (name === null) {
      invalid = true;
      continue;
    }
    const managedEntry = managed.get(name);
    const written = textOf(dependency, 'version') ?? managedEntry?.version ?? null;
    let version: string | null = null;
    if (written !== null) {
      const resolved = props.resolve(written);
      version = resolved !== null && isExactMavenVersion(resolved) ? resolved : null;
    }
    const scope = textOf(dependency, 'scope') ?? managedEntry?.scope ?? null;
    const optional = textOf(dependency, 'optional') === 'true';
    declarations.push({ name, version, declared: written, scope: scope === 'test' ? 'dev' : optional ? 'optional' : 'direct' });
  }
  return { declarations, invalid };
}

// ---------------------------------------------------------------- build.gradle(.kts)

type Token = { kind: 'id' | 'str' | 'punct'; value: string };

function structureError(): ParserFileError {
  return new ParserFileError(PARSER_MESSAGES.structure);
}

function isIdStart(c: number): boolean {
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
}

function isIdPart(c: number): boolean {
  return isIdStart(c) || (c >= 0x30 && c <= 0x39);
}

/**
 * Tokens of a Groovy/Kotlin build script. Single forward pass: every
 * terminator is found with `indexOf` or a forward scan from the cursor.
 */
export function lexGradle(text: string): Token[] {
  const tokens: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text.charCodeAt(i);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
      i++;
    } else if (text.startsWith('//', i)) {
      const end = text.indexOf('\n', i);
      i = end === -1 ? n : end + 1;
    } else if (text.startsWith('/*', i)) {
      const end = text.indexOf('*/', i + 2);
      if (end === -1) throw structureError();
      i = end + 2;
    } else if (text.startsWith("'''", i) || text.startsWith('"""', i)) {
      const quote = text.slice(i, i + 3);
      const end = text.indexOf(quote, i + 3);
      if (end === -1) throw structureError();
      tokens.push({ kind: 'str', value: text.slice(i + 3, end) });
      i = end + 3;
    } else if (c === 0x27 || c === 0x22) {
      const end = stringEnd(text, i);
      tokens.push({ kind: 'str', value: text.slice(i + 1, end) });
      i = end + 1;
    } else if (isIdStart(c)) {
      let j = i + 1;
      while (j < n && isIdPart(text.charCodeAt(j))) j++;
      tokens.push({ kind: 'id', value: text.slice(i, j) });
      i = j;
    } else if (c >= 0x30 && c <= 0x39) {
      let j = i + 1;
      while (j < n && isIdPart(text.charCodeAt(j))) j++;
      tokens.push({ kind: 'punct', value: text.slice(i, j) });
      i = j;
    } else {
      tokens.push({ kind: 'punct', value: text[i] });
      i++;
    }
  }
  return tokens;
}

/** Deepest `"${ "${ … }" }"` template nesting accepted (bounded recursion). */
const MAX_TEMPLATE_DEPTH = 16;

/** Index of the closing quote of the single-line string starting at `start`. */
function stringEnd(text: string, start: number, depth = 0): number {
  if (depth > MAX_TEMPLATE_DEPTH) throw structureError();
  const quote = text[start];
  let i = start + 1;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\\') {
      i += 2;
    } else if (ch === quote) {
      return i;
    } else if (ch === '\n') {
      throw structureError();
    } else if (quote === '"' && ch === '$' && text[i + 1] === '{') {
      i = templateEnd(text, i + 2, depth);
    } else {
      i++;
    }
  }
  throw structureError();
}

/** Index after the `}` closing a `${` template whose body starts at `start` (nested braces and strings allowed). */
function templateEnd(text: string, start: number, nesting: number): number {
  let braces = 1;
  let i = start;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\n') throw structureError();
    if (ch === '"' || ch === "'") {
      i = stringEnd(text, i, nesting + 1) + 1;
      continue;
    }
    if (ch === '{') braces++;
    if (ch === '}' && --braces === 0) return i + 1;
    i++;
  }
  throw structureError();
}

const BASE_CONFIGURATIONS: ReadonlySet<string> = new Set([
  'implementation',
  'api',
  'compileOnly',
  'compileOnlyApi',
  'runtimeOnly',
  'compile',
  'runtime',
  'annotationProcessor',
  'kapt',
  'ksp',
  'developmentOnly',
  'testCompile',
  'testRuntime',
]);

/** Gradle dependency configuration name (see the module comment). */
export function isGradleConfiguration(name: string): boolean {
  if (BASE_CONFIGURATIONS.has(name)) return true;
  if (/^[a-z][A-Za-z0-9]*(Implementation|Api|CompileOnly|CompileOnlyApi|RuntimeOnly|AnnotationProcessor)$/.test(name)) return true;
  return /^(kapt|ksp)[A-Z][A-Za-z0-9]*$/.test(name);
}

/** Function-like arguments that never name a registry package of their own. */
const NON_PACKAGE_CALLS: ReadonlySet<string> = new Set(['platform', 'enforcedPlatform', 'project', 'files', 'fileTree', 'kotlin', 'gradleApi', 'localGroovy', 'testFixtures', 'variantOf']);

export function parseGradleScript(text: string): ManifestData {
  const tokens = lexGradle(text);
  const declarations: Declaration[] = [];
  let invalid = false;
  const at = (i: number): Token | undefined => tokens[i];
  const isPunct = (i: number, value: string): boolean => at(i)?.kind === 'punct' && at(i)?.value === value;

  const addCoordinate = (coordinate: string, scope: DependencyScope): void => {
    let body = coordinate.trim();
    const lastColon = body.lastIndexOf(':');
    const atSign = body.indexOf('@', lastColon + 1);
    if (atSign !== -1) body = body.slice(0, atSign);
    const parts = body.split(':');
    if (parts.length < 2 || parts.length > 4 || !validCoordinatePart(parts[0]) || !validCoordinatePart(parts[1])) {
      invalid = true;
      return;
    }
    const { version, declared } = versionOf(parts.length >= 3 ? parts[2] : null);
    declarations.push({ name: `${parts[0]}:${parts[1]}`, version, declared, scope });
  };

  /** Value of a map/named argument: a string, or a dotted identifier chain as written (a variable). */
  const valueAt = (i: number): { text: string; variable: boolean; next: number } | null => {
    const token = at(i);
    if (token?.kind === 'str') return { text: token.value, variable: false, next: i + 1 };
    if (token?.kind !== 'id') return null;
    let textValue = token.value;
    let j = i + 1;
    while (isPunct(j, '.') && at(j + 1)?.kind === 'id') {
      textValue += `.${at(j + 1)!.value}`;
      j += 2;
    }
    return { text: textValue, variable: true, next: j };
  };

  const parseMap = (start: number, scope: DependencyScope): number => {
    const fields = new Map<string, { text: string; variable: boolean }>();
    let i = start;
    for (;;) {
      const key = at(i);
      if (key?.kind !== 'id' || !(isPunct(i + 1, ':') || isPunct(i + 1, '='))) break;
      const value = valueAt(i + 2);
      if (value === null) break;
      fields.set(key.value, { text: value.text, variable: value.variable });
      i = value.next;
      if (!isPunct(i, ',')) break;
      i++;
    }
    const group = fields.get('group');
    const name = fields.get('name');
    if (!group || !name || group.variable || name.variable || !validCoordinatePart(group.text) || !validCoordinatePart(name.text)) {
      invalid = true;
      return i;
    }
    const versionField = fields.get('version');
    const { version, declared } = versionField?.variable ? { version: null, declared: versionField.text } : versionOf(versionField?.text ?? null);
    declarations.push({ name: `${group.text}:${name.text}`, version, declared, scope });
    return i;
  };

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (token.kind === 'id' && token.value === 'constraints' && isPunct(i + 1, '{')) {
      // Constraints pin versions of other declarations; they are not dependencies.
      let depth = 0;
      let j = i + 1;
      for (; j < tokens.length; j++) {
        if (isPunct(j, '{')) depth++;
        else if (isPunct(j, '}') && --depth === 0) break;
      }
      i = j + 1;
      continue;
    }
    if (token.kind !== 'id' || !isGradleConfiguration(token.value) || isPunct(i - 1, '.')) {
      i++;
      continue;
    }
    const scope: DependencyScope = isTestName(token.value) ? 'dev' : 'direct';
    let j = i + 1;
    if (isPunct(j, '(')) j++;
    const arg = at(j);
    if (arg?.kind === 'str') {
      addCoordinate(arg.value, scope);
      j++;
      while (isPunct(j, ',') && at(j + 1)?.kind === 'str') {
        addCoordinate(at(j + 1)!.value, scope);
        j += 2;
      }
    } else if (arg?.kind === 'id' && (isPunct(j + 1, ':') || isPunct(j + 1, '='))) {
      j = parseMap(j, scope);
    } else if (arg?.kind === 'id' && NON_PACKAGE_CALLS.has(arg.value)) {
      j++;
    }
    // Anything else (catalog alias `libs.x`, a variable, a closure) gives no entry.
    i = Math.max(j, i + 1);
  }
  return { declarations, invalid };
}

// ---------------------------------------------------------------- folders

function toEntries(declarations: readonly Declaration[], manifestFile: string): DependencyEntry[] {
  return declarations.map((d) => ({ name: d.name, version: d.version, scope: d.scope, manifestFile, declaredRange: d.declared }));
}

function lockEntries(lock: LockData, manifests: readonly Loaded<ManifestData>[]): DependencyEntry[] {
  // Runtime declarations of the folder's build files: `group:artifact` -> version as written.
  const runtime = new Map<string, string | null>();
  for (const manifest of manifests) {
    for (const d of manifest.value.declarations) {
      if (d.scope === 'dev') continue;
      const known = runtime.get(d.name);
      if (known === undefined || (known === null && d.declared !== null)) runtime.set(d.name, d.declared);
    }
  }
  const entries = lock.lines.map((line): DependencyEntry => {
    if (line.testOnly) return { name: line.name, version: line.version, scope: 'dev', manifestFile: LOCK_FILE, declaredRange: null };
    if (runtime.has(line.name)) return { name: line.name, version: line.version, scope: 'direct', manifestFile: LOCK_FILE, declaredRange: runtime.get(line.name) ?? null };
    return { name: line.name, version: line.version, scope: 'transitive', manifestFile: LOCK_FILE, declaredRange: null };
  });
  return runtimeFirst(entries);
}

export function parseJava(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  for (const folder of ctx.folders()) {
    if (ctx.capped) break;
    parseFolder(folder, ctx);
  }
  return ctx.finish();
}

function loadOptional(file: WalkedFile | undefined, load: (file: WalkedFile) => Loaded<ManifestData> | null): Loaded<ManifestData> | null {
  return file ? load(file) : null;
}

function parseFolder(folder: ManifestFolder, ctx: ParserContext): void {
  const loadPom = (file: WalkedFile): Loaded<ManifestData> | null => {
    const read = ctx.read(file, (input) => parsePom(input.data));
    return read ? { file, value: read.value, record: read.record } : null;
  };
  const loadGradle = (file: WalkedFile): Loaded<ManifestData> | null => {
    const read = ctx.read(file, (input) => parseGradleScript(input.text()));
    return read ? { file, value: read.value, record: read.record } : null;
  };
  const loadGradleFiles = (): Loaded<ManifestData>[] =>
    GRADLE_FILES.map((name) => loadOptional(folder.files.get(name), loadGradle)).filter((m): m is Loaded<ManifestData> => m !== null);
  const flagInvalid = (manifests: readonly Loaded<ManifestData>[]): void => {
    for (const m of manifests) if (m.value.invalid) ctx.issue(m.file, PARSER_MESSAGES.invalidEntry);
  };

  const lockFile = folder.files.get(LOCK_FILE);
  if (lockFile) {
    const read = ctx.read(lockFile, (input) => parseGradleLockfile(input.text()));
    if (read) {
      const pom = loadOptional(folder.files.get(POM_FILE), loadPom);
      const manifests = [...loadGradleFiles(), ...(pom ? [pom] : [])];
      if (read.value.invalid) ctx.issue(lockFile, PARSER_MESSAGES.invalidEntry);
      flagInvalid(manifests);
      ctx.commit(folder, [read.record, ...manifests.map((m) => m.record)], lockEntries(read.value, manifests), lockFile);
      return;
    }
  }

  const pom = loadOptional(folder.files.get(POM_FILE), loadPom);
  if (pom) {
    flagInvalid([pom]);
    ctx.commit(folder, pom.record, runtimeFirst(toEntries(pom.value.declarations, POM_FILE)), pom.file);
    return;
  }

  const scripts = loadGradleFiles();
  if (scripts.length === 0) return;
  flagInvalid(scripts);
  const entries = runtimeFirst(scripts.flatMap((s) => toEntries(s.value.declarations, s.file.name)));
  ctx.commit(folder, scripts.map((s) => s.record), entries, scripts[0].file);
}
