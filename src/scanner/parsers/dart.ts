/**
 * Dart / Flutter (pub) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.dart): `pubspec.lock` only.
 *   - read with `parseYamlSubset` of `./yamlSubset` (anchors, aliases,
 *     tags and multi-document streams are rejected, AC-P40-4);
 *   - `packages.<name>`: only `source: hosted` (git/path/sdk skipped,
 *     D-311); `dependency: "direct main"` / `"direct overridden"` ->
 *     `direct`, `"direct dev"` -> `dev`, `transitive` -> `transitive`;
 *     `version` exact.
 * Package name = pub package name; purl `pkg:pub/<name>@v` (lower case).
 *
 * Details of the phase-2 implementation:
 * - The package name is the `packages` key (pub writes the same name in
 *   `description.name`). Every hosted package is taken, whatever
 *   `description.url` says (`https://pub.dev`, the legacy
 *   `https://pub.dartlang.org`, or a private pub server / mirror). A
 *   package whose URL is not one of the two public ones (or has no URL) is
 *   marked `privateSource` (security review M-5): it stays in the
 *   inventory and is still looked up on OSV, but never on pub.dev.
 * - `sdk` (`flutter`, `flutter_test`, ...), `git` and `path` packages are
 *   never entries (D-311). The lock has no constraints: `declaredRange` is
 *   always null.
 * - Broken file -> one fixed record: YAML outside the subset or invalid
 *   (YAML texts of the kit), a root that is not a mapping or a `packages`
 *   value that is not a mapping ("unexpected structure"). `packages`
 *   missing or empty -> no entries. A package entry that is not a mapping,
 *   has no string `source`, or (hosted) has an unknown `dependency` value or
 *   no string `version` is dropped with one "invalid entries skipped"
 *   record for the file.
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/dart/` and its own tests
 * `tests/unit/parser-dart*.test.ts`; shared modules are frozen):
 * - signature stays `parseDart(walk: TreeWalk, ctx: ParserContext): ParseResult`
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
import type { DependencyScope } from '../../types/scan';
import { isPyDict, type ParseResult, type TreeWalk } from './common';
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ParserContext } from './kit';
import { parseYamlSubset } from './yamlSubset';

const PUBSPEC_LOCK = 'pubspec.lock';

const SCOPES: ReadonlyMap<string, DependencyScope> = new Map([
  ['direct main', 'direct'],
  ['direct overridden', 'direct'],
  ['direct dev', 'dev'],
  ['transitive', 'transitive'],
]);

interface PubLock {
  entries: DependencyEntry[];
  invalid: boolean;
}

function own(table: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

function parsePubspecLock(text: string): PubLock {
  const root = parseYamlSubset(text);
  if (!isPyDict(root)) throw new ParserFileError(PARSER_MESSAGES.structure);
  const packages = own(root, 'packages');
  const lock: PubLock = { entries: [], invalid: false };
  if (packages === undefined || packages === null) return lock;
  if (!isPyDict(packages)) throw new ParserFileError(PARSER_MESSAGES.structure);
  for (const [name, value] of Object.entries(packages)) {
    if (!isPyDict(value)) {
      lock.invalid = true;
      continue;
    }
    const source = own(value, 'source');
    if (typeof source !== 'string') {
      lock.invalid = true;
      continue;
    }
    if (source !== 'hosted') continue; // sdk, git, path (D-311)
    const dependency = own(value, 'dependency');
    const scope = typeof dependency === 'string' ? SCOPES.get(dependency) : undefined;
    const version = own(value, 'version');
    if (scope === undefined || typeof version !== 'string' || version === '') {
      lock.invalid = true;
      continue;
    }
    const entry: DependencyEntry = { name, version, scope, manifestFile: PUBSPEC_LOCK, declaredRange: null };
    if (!isPublicPubServer(own(value, 'description'))) entry.privateSource = true;
    lock.entries.push(entry);
  }
  return lock;
}

/** pub.dev and its legacy name; any other hosted URL is a private server or a mirror. */
const PUBLIC_PUB_URLS: ReadonlySet<string> = new Set(['https://pub.dev', 'https://pub.dartlang.org']);

/**
 * True when a hosted package's `description.url` is pub.dev (security
 * review M-5). A missing or non-string URL counts as private, so an
 * unknown source is never sent to the pub.dev license lookup.
 */
function isPublicPubServer(description: unknown): boolean {
  if (!isPyDict(description)) return false;
  const url = own(description, 'url');
  if (typeof url !== 'string') return false;
  const normalized = url.toLowerCase().replace(/\/$/, '');
  return PUBLIC_PUB_URLS.has(normalized);
}

export function parseDart(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  for (const folder of ctx.folders()) {
    if (ctx.capped) break;
    const file = folder.files.get(PUBSPEC_LOCK);
    if (!file) continue;
    const read = ctx.read(file, (input) => parsePubspecLock(input.text()));
    if (!read) continue;
    if (read.value.invalid) ctx.issue(file, PARSER_MESSAGES.invalidEntry);
    ctx.commit(folder, read.record, read.value.entries);
  }
  return ctx.finish();
}
