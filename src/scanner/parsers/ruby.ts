/**
 * Ruby (Bundler) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * STUB (phase 1): returns no dependencies yet.
 * TODO(REQ-011 phase 2): implement the rules below.
 *
 * Files (MANIFEST_SPECS.ruby): `Gemfile.lock` only.
 *   - `GEM` section `specs:` entries (4-space `name (version)` lines; the
 *     6-space lines are their dependencies); `GIT`/`PATH` sections skipped
 *     (D-311); a platform suffix (`1.15.0-x86_64-linux`) is kept in the
 *     version only if OSV needs it — decide with a fixture and document;
 *   - gems listed under `DEPENDENCIES` are `direct`, the rest `transitive`
 *     (Bundler groups are not in the lock file: no `dev`).
 * Package name = gem name; purl `pkg:gem/<name>@v`.
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/ruby/` and its own tests
 * `tests/unit/parser-ruby*.test.ts`; shared modules are frozen):
 * - signature stays `parseRuby(walk: TreeWalk, ctx: ParserContext): ParseResult`
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

export function parseRuby(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  return ctx.finish();
}
