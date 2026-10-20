/**
 * Swift (SwiftPM) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.swift): `Package.resolved` only (D-310: no
 * CocoaPods).
 *   - v1: `object.pins[]` with `package`, `repositoryURL`, `state.version`;
 *     v2/v3: `pins[]` with `identity`, `kind`, `location`, `state.version`;
 *     other `version` values -> `ParserFileError(PARSER_MESSAGES.unsupportedVersion)`;
 *   - only remote source control pins (`kind: remoteSourceControl`, or any
 *     v1 pin with a URL); local/registry pins skipped (D-311);
 *   - name = `swiftPackageIdentity(location)` from `./purl` (`host/owner/repo`,
 *     also the OSV `SwiftURL` name); null identity -> skipped;
 *   - `state.version` missing (branch/revision pin) -> `version: null`,
 *     `declaredRange` = the branch name when present;
 *   - the file does not tell direct from transitive: use `direct`.
 * Purl `pkg:swift/<host>/<owner>/<repo>@v`. No license source (D-320).
 *
 * Details of the phase-2 implementation:
 * - The top-level `version` must be the JSON number 1, 2 or 3 (missing or
 *   anything else -> "unsupported lock version"); v3 only adds
 *   `originHash`, which is ignored.
 * - v1 pins: a `repositoryURL` that is a local path (or `file://`) has no
 *   identity and is skipped. v2/v3 pins: `localSourceControl`, `fileSystem`
 *   and `registry` kinds are skipped (not a source control URL package).
 * - Branch / revision pins: `state.version` null or absent -> `version:
 *   null` and `declaredRange` = `state.branch`, or `state.revision` when no
 *   branch is written (a revision-only pin), so the report shows what was
 *   pinned; such a package never reaches OSV (AC-P40-6).
 * - Broken file -> one fixed record: invalid JSON, a root that is not an
 *   object, or `pins` (v1 `object.pins`) that is not an array ("unexpected
 *   structure"). A pin that is not an object, lacks the string URL / kind,
 *   has no `state` object or a non-string `version` / `branch` /
 *   `revision` is dropped with one "invalid entries skipped" record.
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/swift/` and its own tests
 * `tests/unit/parser-swift*.test.ts`; shared modules are frozen):
 * - signature stays `parseSwift(walk: TreeWalk, ctx: ParserContext): ParseResult`
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
 */
import { isPyDict, type ParseResult, type TreeWalk } from './common';
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ParserContext } from './kit';
import { swiftPackageIdentity } from './purl';

const PACKAGE_RESOLVED = 'Package.resolved';

type JsonObject = Record<string, unknown>;

interface ResolvedFile {
  entries: DependencyEntry[];
  invalid: boolean;
}

function own(table: JsonObject, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

function optionalString(value: unknown): string | null | undefined {
  if (value === undefined || value === null) return null;
  return typeof value === 'string' ? value : undefined;
}

/** Entry of one pin's `state` at `location`; null = skipped, undefined = malformed pin. */
function pinEntry(location: string, state: unknown): DependencyEntry | null | undefined {
  if (!isPyDict(state)) return undefined;
  const version = optionalString(own(state, 'version'));
  const branch = optionalString(own(state, 'branch'));
  const revision = optionalString(own(state, 'revision'));
  if (version === undefined || branch === undefined || revision === undefined) return undefined;
  const name = swiftPackageIdentity(location);
  if (name === null) return null; // local path, unusable URL (D-311)
  if (version !== null && version !== '') return { name, version, scope: 'direct', manifestFile: PACKAGE_RESOLVED, declaredRange: null };
  const pinned = branch !== null && branch !== '' ? branch : revision;
  return { name, version: null, scope: 'direct', manifestFile: PACKAGE_RESOLVED, declaredRange: pinned === '' ? null : pinned };
}

function parsePackageResolved(text: string): ResolvedFile {
  const root: unknown = JSON.parse(text);
  if (!isPyDict(root)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const version = own(root, 'version');
  let pins: unknown;
  if (version === 1) {
    const object = own(root, 'object');
    if (!isPyDict(object)) throw new ParserFileError(PARSER_MESSAGES.structure);
    pins = own(object, 'pins');
  } else if (version === 2 || version === 3) {
    pins = own(root, 'pins');
  } else {
    throw new ParserFileError(PARSER_MESSAGES.unsupportedVersion);
  }
  if (!Array.isArray(pins)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const file: ResolvedFile = { entries: [], invalid: false };
  for (const pin of pins as unknown[]) {
    let entry: DependencyEntry | null | undefined;
    if (!isPyDict(pin)) {
      entry = undefined;
    } else if (version === 1) {
      const url = own(pin, 'repositoryURL');
      entry = typeof url === 'string' ? pinEntry(url, own(pin, 'state')) : undefined;
    } else {
      const kind = own(pin, 'kind');
      const location = own(pin, 'location');
      if (typeof kind !== 'string' || typeof location !== 'string') entry = undefined;
      else if (kind !== 'remoteSourceControl') entry = null; // localSourceControl, fileSystem, registry (D-311)
      else entry = pinEntry(location, own(pin, 'state'));
    }
    if (entry === undefined) file.invalid = true;
    else if (entry !== null) file.entries.push(entry);
  }
  return file;
}

export function parseSwift(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  for (const folder of ctx.folders()) {
    if (ctx.capped) break;
    const file = folder.files.get(PACKAGE_RESOLVED);
    if (!file) continue;
    const read = ctx.read(file, (input) => parsePackageResolved(input.text()));
    if (!read) continue;
    if (read.value.invalid) ctx.issue(file, PARSER_MESSAGES.invalidEntry);
    ctx.commit(folder, read.record, read.value.entries);
  }
  return ctx.finish();
}
