/**
 * Go modules dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.go): `go.mod` only (D-309: Go 1.17+ lists every
 * required module; `go.sum` is not read).
 *   - `require` lines and blocks; `// indirect` -> `transitive`, others
 *     `direct`;
 *   - `replace` with a local path (`./`, `../`, absolute) -> the module is
 *     skipped (D-311); a module-to-module replace uses the replacement path
 *     and version; `exclude` lines are ignored; `retract` is ignored;
 *   - versions are exact (`v1.2.3`, pseudo-versions, `+incompatible`); keep
 *     them as written (with `v`): `osvCoordinateOf` drops the `v` for OSV.
 * Package name = module path (case kept); purl `pkg:golang/<module>@v`.
 *
 * Syntax follows `golang.org/x/mod/modfile` (the parts a dependency list
 * needs): one statement per line, `verb (` ... `)` blocks, `//` comments
 * (the `indirect` marker is the line's trailing comment, `indirect` or
 * `indirect; ...`), module paths and versions bare or quoted (`"..."` with
 * the simple escapes, or `` `...` ``). A version that is not canonical
 * semver (only an unmaintained, hand-written go.mod has one) is kept as
 * `declaredRange` with `version: null` (AC-P40-6). Unknown verbs (`go`,
 * `toolchain`, `godebug`, `tool`, `ignore`, future ones) are ignored. A
 * structural error (unterminated block or quote, a `require`/`replace` with
 * the wrong arguments, a nested block) makes the whole file one
 * "unexpected structure" record (AC-P40-3).
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/golang/` and its own tests
 * `tests/unit/parser-golang*.test.ts`; shared modules are frozen):
 * - signature stays `parseGo(walk: TreeWalk, ctx: ParserContext): ParseResult`
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
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ParserContext } from './kit';

const GO_MOD = 'go.mod';

/** Canonical module version: semver with `v` (pseudo-versions and `+incompatible` included). */
const GO_VERSION = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** One logical go.mod line: its tokens (`(`/`)` kept as tokens) and its trailing comment. */
interface GoLine {
  tokens: string[];
  comment: string | null;
}

interface GoRequire {
  path: string;
  version: string;
  indirect: boolean;
}

interface GoReplace {
  oldPath: string;
  oldVersion: string | null;
  newPath: string;
  newVersion: string | null;
}

function structureError(): ParserFileError {
  return new ParserFileError(PARSER_MESSAGES.structure);
}

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = { '\\': '\\', '"': '"', "'": "'", n: '\n', t: '\t', r: '\r' };

/** Splits one physical line into tokens; `"..."` and `` `...` `` are unquoted. Linear in the line length. */
function lexLine(line: string): GoLine {
  const tokens: string[] = [];
  let comment: string | null = null;
  let i = 0;
  const n = line.length;
  while (i < n) {
    const c = line[i];
    if (c === ' ' || c === '\t' || c === '\f' || c === '\v') {
      i++;
    } else if (c === '/' && line[i + 1] === '/') {
      comment = line.slice(i + 2);
      break;
    } else if (c === '(' || c === ')') {
      tokens.push(c);
      i++;
    } else if (c === '`') {
      const end = line.indexOf('`', i + 1);
      if (end === -1) throw structureError();
      tokens.push(line.slice(i + 1, end));
      i = end + 1;
    } else if (c === '"') {
      let value = '';
      let j = i + 1;
      for (;;) {
        if (j >= n) throw structureError();
        const d = line[j];
        if (d === '"') break;
        if (d === '\\') {
          const mapped = SIMPLE_ESCAPES[line[j + 1] ?? ''];
          if (mapped === undefined) throw structureError();
          value += mapped;
          j += 2;
        } else {
          value += d;
          j++;
        }
      }
      tokens.push(value);
      i = j + 1;
    } else {
      let j = i;
      while (j < n) {
        const d = line[j];
        if (d === ' ' || d === '\t' || d === '\f' || d === '\v' || d === '(' || d === ')' || d === '"' || d === '`') break;
        if (d === '/' && line[j + 1] === '/') break;
        j++;
      }
      tokens.push(line.slice(i, j));
      i = j;
    }
  }
  return { tokens, comment };
}

/** modfile `isIndirect`: the trailing comment is `indirect` or starts with `indirect;`. */
function isIndirect(comment: string | null): boolean {
  if (comment === null) return false;
  const text = comment.trim();
  return text === 'indirect' || text.startsWith('indirect;');
}

/** modfile `IsDirectoryPath`: a replacement that points to a local directory (D-311). */
function isDirectoryPath(path: string): boolean {
  return (
    path === '.' ||
    path === '..' ||
    path.startsWith('./') ||
    path.startsWith('.\\') ||
    path.startsWith('../') ||
    path.startsWith('..\\') ||
    path.startsWith('/') ||
    path.startsWith('\\') ||
    (path.length >= 2 && /^[A-Za-z]$/.test(path[0]) && path[1] === ':')
  );
}

function parseRequire(line: GoLine): GoRequire {
  if (line.tokens.length !== 2 || line.tokens.some((t) => t === '' || t === '(' || t === ')')) throw structureError();
  return { path: line.tokens[0], version: line.tokens[1], indirect: isIndirect(line.comment) };
}

/** `old [v] => new [v]`; a non-directory replacement needs a version (modfile rule). */
function parseReplace(line: GoLine): GoReplace {
  const t = line.tokens;
  if (t.some((token) => token === '' || token === '(' || token === ')')) throw structureError();
  const arrow = t.indexOf('=>');
  if (arrow !== 1 && arrow !== 2) throw structureError();
  const right = t.slice(arrow + 1);
  if (right.length < 1 || right.length > 2 || right.includes('=>')) throw structureError();
  const newPath = right[0];
  const newVersion = right[1] ?? null;
  if (newVersion === null && !isDirectoryPath(newPath)) throw structureError();
  return { oldPath: t[0], oldVersion: arrow === 2 ? t[1] : null, newPath, newVersion };
}

/** Requirements and replacements of a go.mod text (CRLF/CR accepted). */
function parseGoMod(text: string): { requires: GoRequire[]; replaces: GoReplace[] } {
  const requires: GoRequire[] = [];
  const replaces: GoReplace[] = [];
  let block: string | null = null;
  const handle = (verb: string, line: GoLine): void => {
    if (verb === 'require') requires.push(parseRequire(line));
    else if (verb === 'replace') replaces.push(parseReplace(line));
    // module, go, toolchain, godebug, exclude, retract, tool, ignore and unknown verbs: not a dependency.
  };
  for (const physical of text.split(/\r\n|\r|\n/)) {
    const line = lexLine(physical);
    const tokens = line.tokens;
    if (tokens.length === 0) continue;
    if (block !== null) {
      if (tokens.length === 1 && tokens[0] === ')') {
        block = null;
        continue;
      }
      if (tokens.includes('(') || tokens.includes(')')) throw structureError();
      handle(block, { tokens, comment: line.comment });
      continue;
    }
    const verb = tokens[0];
    if (verb === '(' || verb === ')') throw structureError();
    if (tokens.length >= 2 && tokens[1] === '(') {
      if (tokens.length === 2) {
        block = verb;
        continue;
      }
      if (tokens.length === 3 && tokens[2] === ')') continue; // `require ()`
      throw structureError();
    }
    if (tokens.includes('(') || tokens.includes(')')) throw structureError();
    handle(verb, { tokens: tokens.slice(1), comment: line.comment });
  }
  if (block !== null) throw structureError();
  return { requires, replaces };
}

/** Requirement after `replace` (version-specific replace first, then path-wide); null = local directory, skipped. */
function applyReplace(req: GoRequire, replaces: readonly GoReplace[]): { path: string; version: string } | null {
  let match: GoReplace | undefined;
  for (const r of replaces) {
    if (r.oldPath !== req.path) continue;
    if (r.oldVersion === req.version) match = r; // the last matching line wins, as in modfile
    else if (r.oldVersion === null && (match === undefined || match.oldVersion === null)) match = r;
  }
  if (!match) return { path: req.path, version: req.version };
  if (match.newVersion === null) return null;
  return { path: match.newPath, version: match.newVersion };
}

function goEntries(text: string): DependencyEntry[] {
  const { requires, replaces } = parseGoMod(text);
  const entries: DependencyEntry[] = [];
  for (const req of requires) {
    const target = applyReplace(req, replaces);
    if (target === null) continue;
    const exact = GO_VERSION.test(target.version);
    entries.push({
      name: target.path,
      version: exact ? target.version : null,
      scope: req.indirect ? 'transitive' : 'direct',
      manifestFile: GO_MOD,
      declaredRange: exact ? null : target.version,
    });
  }
  return entries;
}

export function parseGo(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  for (const folder of ctx.folders()) {
    if (ctx.capped) break;
    const file = folder.files.get(GO_MOD);
    if (!file) continue;
    const read = ctx.read(file, (input) => goEntries(input.text()));
    if (read === null) continue;
    ctx.commit(folder, read.record, read.value);
  }
  return ctx.finish();
}
