/**
 * Ruby (Bundler) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.ruby): `Gemfile.lock` only.
 *   - `GEM` section `specs:` entries (4-space `name (version)` lines; the
 *     6-space lines are their dependencies); `GIT`/`PATH` sections skipped
 *     (D-311); a platform suffix (`1.15.0-x86_64-linux`) is dropped from
 *     the version (OSV does not use it; see below and the
 *     `platform-suffix` fixture);
 *   - gems listed under `DEPENDENCIES` are `direct`, the rest `transitive`
 *     (Bundler groups are not in the lock file: no `dev`).
 * Package name = gem name; purl `pkg:gem/<name>@v`.
 *
 * Details of the phase-2 implementation:
 * - Line format: an unindented line opens a section (`GEM`, `GIT`, `PATH`,
 *   `PLUGIN SOURCE`, `PLATFORMS`, `DEPENDENCIES`, `CHECKSUMS`,
 *   `RUBY VERSION`, `BUNDLED WITH`; unknown upper-case sections are
 *   ignored). CRLF/CR line ends are accepted.
 * - Every `GEM` section is read (one per gem server `remote:`; a private
 *   server or a mirror such as Artifactory is still a RubyGems source). Gems
 *   of a section whose remotes are not all rubygems.org are marked
 *   `privateSource` (security review M-5): kept in the inventory and still
 *   looked up on OSV, but never sent to the deps.dev license lookup;
 *   `GIT`, `PATH` and `PLUGIN SOURCE` gems are never entries (D-311).
 * - Platform suffix: Bundler writes `version-platform` for platform gems
 *   (`1.15.4-x86_64-linux`, `9.4.3.0-java`). A canonical RubyGems version
 *   never contains `-` (`Gem::Version` rewrites it to `.pre.`), so the text
 *   before the first `-` is the version, which is what OSV `RubyGems` and
 *   `pkg:gem` expect; the platform variants of one release collapse into one
 *   entry (kit dedupe).
 * - Scope: a gem named under `DEPENDENCIES` (a trailing `!` = git/path
 *   source is dropped) is `direct` with its requirement (`~> 1.15`) as
 *   `declaredRange`; every other `GEM` spec is `transitive`.
 * - Broken file -> one "unexpected structure" record: text before the first
 *   section, an unindented line that is not an upper-case section name
 *   (a merge conflict marker, another format), or no known section at all.
 *   A malformed spec / dependency line drops only that line with one
 *   "invalid entries skipped" record for the file.
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
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ParserContext } from './kit';

const GEMFILE_LOCK = 'Gemfile.lock';

const KNOWN_SECTIONS: ReadonlySet<string> = new Set([
  'GEM',
  'GIT',
  'PATH',
  'PLUGIN SOURCE',
  'PLATFORMS',
  'DEPENDENCIES',
  'CHECKSUMS',
  'RUBY VERSION',
  'BUNDLED WITH',
]);

/** Unindented section header. */
const SECTION_LINE = /^[A-Z][A-Z0-9 ]*$/;
/** `    name (version[-platform])` under `specs:`. */
const SPEC_LINE = /^ {4}([^\s()]+) \(([^\s()]+)\)$/;
/** `  name`, `  name!`, `  name (req)`, `  name (req)!` under `DEPENDENCIES`. */
const DEPENDENCY_LINE = /^ {2}([^\s()!]+)(?: \(([^()]*)\))?!?$/;

interface GemSpec {
  name: string;
  version: string;
  /** The `GEM` section it was listed in (its remotes decide `privateSource`). */
  source: GemSource;
}

/** `remote:` values of one `GEM` section. */
interface GemSource {
  remotes: string[];
}

/** rubygems.org written with or without `www.`, `http`/`https` and a trailing `/`. */
const PUBLIC_GEM_REMOTES: ReadonlySet<string> = new Set(['https://rubygems.org', 'http://rubygems.org', 'https://www.rubygems.org', 'http://www.rubygems.org']);

/**
 * True when every remote of a `GEM` section is rubygems.org (security
 * review M-5). A section without a remote, or with any other server (a
 * private gem server, a mirror), counts as private: its gems are never sent
 * to the deps.dev license lookup.
 */
function isPublicGemSource(source: GemSource): boolean {
  return source.remotes.length > 0 && source.remotes.every((remote) => PUBLIC_GEM_REMOTES.has(remote.toLowerCase().replace(/\/$/, '')));
}

/** `  remote: <url>` key line of a `GEM` section. */
const REMOTE_LINE = /^ {2}remote: (\S+)$/;

interface GemLock {
  specs: GemSpec[];
  /** `DEPENDENCIES` gem -> requirement (null when none is written). */
  direct: Map<string, string | null>;
  invalid: boolean;
}

function structureError(): ParserFileError {
  return new ParserFileError(PARSER_MESSAGES.structure);
}

/** Version without the Bundler platform suffix (`1.15.4-x86_64-linux` -> `1.15.4`); null when nothing is left. */
function baseVersion(version: string): string | null {
  const dash = version.indexOf('-');
  const base = dash === -1 ? version : version.slice(0, dash);
  return base === '' ? null : base;
}

function isBlank(line: string): boolean {
  for (let i = 0; i < line.length; i++) if (line[i] !== ' ' && line[i] !== '\t') return false;
  return true;
}

/** Specs of the `GEM` sections and the `DEPENDENCIES` list of a Gemfile.lock text. Linear in the text length. */
function parseGemfileLock(text: string): GemLock {
  const lock: GemLock = { specs: [], direct: new Map(), invalid: false };
  let section: string | null = null;
  let gemSource: GemSource = { remotes: [] };
  let inSpecs = false;
  let known = false;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (isBlank(line)) continue;
    if (line[0] !== ' ') {
      if (!SECTION_LINE.test(line)) throw structureError();
      section = line;
      inSpecs = false;
      if (line === 'GEM') gemSource = { remotes: [] };
      if (KNOWN_SECTIONS.has(line)) known = true;
      continue;
    }
    if (section === null) throw structureError();
    if (section === 'GEM') {
      if (line === '  specs:') {
        inSpecs = true;
      } else if (/^ {2}\S/.test(line)) {
        inSpecs = false; // `remote:` and other section keys
        const remote = REMOTE_LINE.exec(line);
        if (remote) gemSource.remotes.push(remote[1]);
      } else if (inSpecs && /^ {4}\S/.test(line)) {
        const match = SPEC_LINE.exec(line);
        const version = match ? baseVersion(match[2]) : null;
        if (match && version !== null) lock.specs.push({ name: match[1], version, source: gemSource });
        else lock.invalid = true;
      }
      // 6-space lines: dependencies of the spec above (resolved specs of their own).
    } else if (section === 'DEPENDENCIES') {
      if (/^ {2}\S/.test(line)) {
        const match = DEPENDENCY_LINE.exec(line);
        if (match) {
          const requirement = match[2]?.trim() ?? '';
          if (!lock.direct.has(match[1])) lock.direct.set(match[1], requirement === '' ? null : requirement);
        } else {
          lock.invalid = true;
        }
      }
    }
    // GIT, PATH, PLUGIN SOURCE (D-311), PLATFORMS, CHECKSUMS, RUBY VERSION, BUNDLED WITH: not entries.
  }
  if (!known) throw structureError();
  return lock;
}

function gemEntries(lock: GemLock): DependencyEntry[] {
  return lock.specs.map((spec): DependencyEntry => {
    const direct = lock.direct.has(spec.name);
    const entry: DependencyEntry = {
      name: spec.name,
      version: spec.version,
      scope: direct ? 'direct' : 'transitive',
      manifestFile: GEMFILE_LOCK,
      declaredRange: direct ? (lock.direct.get(spec.name) ?? null) : null,
    };
    if (!isPublicGemSource(spec.source)) entry.privateSource = true;
    return entry;
  });
}

export function parseRuby(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  for (const folder of ctx.folders()) {
    if (ctx.capped) break;
    const file = folder.files.get(GEMFILE_LOCK);
    if (!file) continue;
    const read = ctx.read(file, (input) => parseGemfileLock(input.text()));
    if (!read) continue;
    if (read.value.invalid) ctx.issue(file, PARSER_MESSAGES.invalidEntry);
    ctx.commit(folder, read.record, gemEntries(read.value));
  }
  return ctx.finish();
}
