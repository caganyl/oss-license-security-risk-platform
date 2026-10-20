/**
 * PHP (Composer) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.php), per folder in this priority (AC-P40-2):
 *   1. `composer.lock` — `packages` (runtime) and `packages-dev` (`dev`);
 *      a package required by the folder's `composer.json` `require` is
 *      `direct`, the others `transitive` (all `direct` when there is no
 *      `composer.json`); `license` array -> `licenses: [arr.join(' OR ')]`
 *      (AC-P40-7, source `lockfile (unverified)`); versions as written
 *      (`v1.2.3` allowed: `osvCoordinateOf` drops the `v` for OSV);
 *   2. `composer.json` — `require` (`direct`) and `require-dev` (`dev`),
 *      `version: null` + `declaredRange`; platform packages (`php`,
 *      `ext-*`, `lib-*`, `composer-plugin-api`, `composer-runtime-api`) are
 *      skipped.
 * Package name `vendor/name`; purl `pkg:composer/vendor/name@v` (lower case).
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/php/` and its own tests
 * `tests/unit/parser-php*.test.ts`; shared modules are frozen):
 * - signature stays `parsePhp(walk: TreeWalk, ctx: ParserContext): ParseResult`
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
 * - Names are ASCII lower-cased (Packagist names are case-insensitive);
 *   `direct` membership compares lower-cased `require` keys.
 * - Composer branch versions in the lock (`dev-main`, `2.x-dev`) are not
 *   exact: `version: null`, `declaredRange` = the lock's version text.
 * - Licenses: a `license` array (or a single string) of non-empty texts
 *   becomes ONE expression joined with ` OR ` (Composer: several licenses =
 *   disjunctive choice); with more than one item, an item that already holds
 *   whitespace (a compound expression) is put in parentheses so the ` OR `
 *   does not change its meaning. The enrichment layer treats it as the lock
 *   hint (`licenses` of the dependency -> `lockfile (unverified)`, D-319).
 *   Another type is ignored (no license), not an error.
 * - A broken `composer.lock` gets its record and the folder falls back to
 *   `composer.json` (AC-P40-3: the next source continues). A broken
 *   `composer.json` next to a valid lock gets its record and is treated as
 *   missing (all lock `packages` `direct`); its record is not used.
 * - `null`/absent `packages`, `packages-dev`, `require`, `require-dev` and
 *   an empty JSON array for them (PHP's `[]` for an empty map) are empty;
 *   any other non-matching type is a structure error for the file. A lock
 *   package without a string `name`/`version`, or a `composer.json`
 *   constraint that is not a string, is skipped with the kit's "invalid
 *   entries skipped" record (once per file).
 */
import type { DependencyScope } from '../../types/scan';
import type { ParseResult, TreeWalk } from './common';
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ParserContext } from './kit';
import { asciiLower } from './nugetIdentity';

const LOCK_FILE = 'composer.lock';
const MANIFEST_FILE = 'composer.json';

/** Composer platform packages (php, its variants, hhvm, extensions, system libraries, plugin/runtime APIs). */
const PLATFORM_RE = /^(?:php(?:-64bit|-ipv6|-zts|-debug)?|hhvm|composer|composer-plugin-api|composer-runtime-api|ext-.+|lib-.+)$/;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPlatform(lowerName: string): boolean {
  return PLATFORM_RE.test(lowerName);
}

/** A Composer branch version (`dev-main`, `1.0.x-dev`): no exact version. */
function isBranchVersion(version: string): boolean {
  const lower = asciiLower(version);
  return lower.startsWith('dev-') || lower.endsWith('-dev');
}

/** Root object of a Composer JSON file, or a structure error. */
function rootOf(text: string): JsonObject {
  const root: unknown = JSON.parse(text);
  if (!isObject(root)) throw new ParserFileError(PARSER_MESSAGES.structure);
  return root;
}

/** A list section (`packages`, `packages-dev`): absent/null/array, else a structure error. */
function listSection(root: JsonObject, key: string): readonly unknown[] {
  const value = root[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new ParserFileError(PARSER_MESSAGES.structure);
  return value;
}

/** A map section (`require`, `require-dev`): absent/null/object/empty array, else a structure error. */
function mapSection(root: JsonObject, key: string): Array<[string, unknown]> {
  const value = root[key];
  if (value === undefined || value === null) return [];
  if (Array.isArray(value) && value.length === 0) return [];
  if (!isObject(value)) throw new ParserFileError(PARSER_MESSAGES.structure);
  return Object.entries(value);
}

/** AC-P40-7: the `license` field as one SPDX expression list (`[]` or one item). */
export function composerLicenses(value: unknown): string[] {
  const raw = typeof value === 'string' ? [value] : Array.isArray(value) ? value : [];
  const items = raw.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter((item) => item !== '');
  if (items.length === 0) return [];
  if (items.length === 1) return [items[0]];
  return [items.map((item) => (/\s/.test(item) && !(item.startsWith('(') && item.endsWith(')')) ? `(${item})` : item)).join(' OR ')];
}

interface ManifestData {
  /** Lower-cased `require` names (platform packages included; they never match a lock package). */
  required: Set<string>;
  /** Fallback entries (`version: null` + `declaredRange`). */
  entries: DependencyEntry[];
  /** Entries skipped as invalid (non-string constraint). */
  invalid: boolean;
}

function readManifestData(root: JsonObject): ManifestData {
  const data: ManifestData = { required: new Set(), entries: [], invalid: false };
  const sections: Array<[string, DependencyScope]> = [
    ['require', 'direct'],
    ['require-dev', 'dev'],
  ];
  for (const [key, scope] of sections) {
    for (const [rawName, constraint] of mapSection(root, key)) {
      const name = asciiLower(rawName);
      if (scope === 'direct') data.required.add(name);
      if (isPlatform(name)) continue;
      if (typeof constraint !== 'string') {
        data.invalid = true;
        continue;
      }
      data.entries.push({ name, version: null, scope, manifestFile: MANIFEST_FILE, declaredRange: constraint });
    }
  }
  return data;
}

interface LockPackage {
  name: string;
  version: string;
  dev: boolean;
  licenses: string[];
}

interface LockData {
  packages: LockPackage[];
  invalid: boolean;
}

function readLockData(root: JsonObject): LockData {
  const data: LockData = { packages: [], invalid: false };
  const sections: Array<[string, boolean]> = [
    ['packages', false],
    ['packages-dev', true],
  ];
  for (const [key, dev] of sections) {
    for (const pkg of listSection(root, key)) {
      if (!isObject(pkg) || typeof pkg.name !== 'string' || typeof pkg.version !== 'string') {
        data.invalid = true;
        continue;
      }
      const name = asciiLower(pkg.name);
      if (isPlatform(name)) continue;
      data.packages.push({ name, version: pkg.version, dev, licenses: composerLicenses(pkg.license) });
    }
  }
  return data;
}

function lockEntries(lock: LockData, required: ReadonlySet<string> | null): DependencyEntry[] {
  return lock.packages.map((pkg) => {
    const scope: DependencyScope = pkg.dev ? 'dev' : required === null || required.has(pkg.name) ? 'direct' : 'transitive';
    const branch = isBranchVersion(pkg.version);
    return {
      name: pkg.name,
      version: branch ? null : pkg.version,
      scope,
      manifestFile: LOCK_FILE,
      declaredRange: branch ? pkg.version : null,
      licenses: pkg.licenses,
    };
  });
}

export function parsePhp(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  for (const folder of ctx.folders()) {
    if (ctx.capped) break;
    const lockFile = folder.files.get(LOCK_FILE);
    const manifestFile = folder.files.get(MANIFEST_FILE);

    const lock = lockFile ? ctx.read(lockFile, (input) => readLockData(rootOf(input.text()))) : null;
    const manifest = manifestFile ? ctx.read(manifestFile, (input) => readManifestData(rootOf(input.text()))) : null;

    if (lockFile && lock) {
      if (lock.value.invalid) ctx.issue(lockFile, PARSER_MESSAGES.invalidEntry);
      const entries = lockEntries(lock.value, manifest ? manifest.value.required : null);
      ctx.commit(folder, manifest ? [lock.record, manifest.record] : [lock.record], entries, lockFile);
      continue;
    }
    if (manifestFile && manifest) {
      if (manifest.value.invalid) ctx.issue(manifestFile, PARSER_MESSAGES.invalidEntry);
      ctx.commit(folder, manifest.record, manifest.value.entries, manifestFile);
    }
  }
  return ctx.finish();
}
