/**
 * PHP (Composer) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * STUB (phase 1): returns no dependencies yet.
 * TODO(REQ-011 phase 2): implement the rules below.
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
 */
import type { ParseResult, TreeWalk } from './common';
import type { ParserContext } from './kit';

export function parsePhp(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  return ctx.finish();
}
