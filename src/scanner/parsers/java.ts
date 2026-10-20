/**
 * Java / Kotlin (Maven coordinates) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * STUB (phase 1): returns no dependencies yet.
 * TODO(REQ-011 phase 2): implement the rules below.
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
 */
import type { ParseResult, TreeWalk } from './common';
import type { ParserContext } from './kit';

export function parseJava(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  return ctx.finish();
}
