/**
 * Rust (Cargo) dependency parser — REQ-011 P-40 (AC-P40-1…7; ADR-012 Karar 1).
 *
 * Files (MANIFEST_SPECS.rust), per folder in this priority (AC-P40-2):
 *   1. `Cargo.lock` — `[[package]]` entries whose `source` starts with
 *      `registry+` only (path/git/workspace members skipped, D-311); exact
 *      versions; a crate listed in the folder's `Cargo.toml` dependency
 *      tables is `direct` (`dev-dependencies` -> `dev`), the rest
 *      `transitive`;
 *   2. `Cargo.toml` — `[dependencies]`, `[build-dependencies]` (`direct`),
 *      `[dev-dependencies]` (`dev`), target-specific tables too; `path`/`git`
 *      dependencies skipped; `version: null` + `declaredRange`.
 * TOML only through `parseTomlText` of `./toml` (smol-toml, D-303).
 * Package name = crate name; purl `pkg:cargo/<name>@v`.
 *
 * Details of the phase-2 implementation:
 * - `Cargo.lock` v1–v4 (`version` absent, or 1…4; anything else ->
 *   "unsupported lock version"). Only crates.io packages are taken:
 *   `source` = `registry+https://github.com/rust-lang/crates.io-index` or the
 *   sparse `sparse+https://index.crates.io/`. Packages without `source`
 *   (workspace members, path crates) and `git+` sources are skipped (D-311);
 *   alternative registries are skipped too (the purl/OSV coordinate
 *   `pkg:cargo/<name>` means crates.io).
 * - Lock scope: a registry package referenced (`name`, `name version` or
 *   `name version (source)`) from the `dependencies` of a package without
 *   `source` (or the v1 `[root]` table) is a first-level dependency of the
 *   project: `dev` when the crate is declared only in `dev-dependencies` of
 *   the folder's `Cargo.toml` (or of a workspace member covered by this
 *   lock, see below), otherwise `direct`; its declared requirement becomes
 *   `declaredRange` (as with `package.json` next to a Node lock). Every
 *   other registry package is `transitive`.
 * - Workspace members: Cargo writes one `Cargo.lock` at the workspace root.
 *   A folder without a usable `Cargo.lock` whose `Cargo.toml` `[package]`
 *   name is a source-less package of the nearest ancestor folder's lock is
 *   covered by that lock: its `Cargo.toml` only refines the ancestor's
 *   scopes (and enters `scan_files` with it) instead of adding versionless
 *   duplicates.
 * - `Cargo.toml` fallback: string or table (`version = "…"`) declarations;
 *   `package = "…"` renames are resolved to the crate name; `path`, `git`,
 *   `registry`/`registry-index` declarations are skipped; `workspace = true`
 *   takes the requirement from `[workspace.dependencies]` of the nearest
 *   folder (this one or an ancestor) whose `Cargo.toml` has a `[workspace]`
 *   table (null when it has none). `[workspace.dependencies]` alone adds no
 *   entry (members declare what they use). The legacy `dev_dependencies` /
 *   `build_dependencies` spellings are read too.
 * - A broken `Cargo.lock` is one record and the folder falls back to its
 *   `Cargo.toml` ("the next source continues"); a broken `Cargo.toml` is one
 *   record as well. Malformed single entries are dropped with one
 *   "invalid entries skipped" record per used file.
 *
 * Contract for this file (phase 2 owner edits ONLY this file, its own
 * fixtures under `tests/fixtures/rust/` and its own tests
 * `tests/unit/parser-rust*.test.ts`; shared modules are frozen):
 * - signature stays `parseRust(walk: TreeWalk, ctx: ParserContext): ParseResult`
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
import type { ScannedFile } from '../../types/scan';
import { isPyDict, type ParseResult, type TreeWalk, type WalkedFile } from './common';
import { PARSER_MESSAGES, ParserFileError, type DependencyEntry, type ManifestFolder, type ParserContext } from './kit';
import { parseTomlText } from './toml';

const CARGO_LOCK = 'Cargo.lock';
const CARGO_TOML = 'Cargo.toml';

/** crates.io index URLs as Cargo writes them into `source` (git index and sparse index). */
const CRATES_IO_SOURCES: ReadonlySet<string> = new Set(['registry+https://github.com/rust-lang/crates.io-index', 'sparse+https://index.crates.io/']);

const NORMAL_TABLES = ['dependencies', 'build-dependencies', 'build_dependencies'] as const;
const DEV_TABLES = ['dev-dependencies', 'dev_dependencies'] as const;

type Table = Record<string, unknown>;

/** One declaration of a `Cargo.toml` dependency table. */
interface CargoDecl {
  /** Crate name (`package = "…"` resolved). */
  name: string;
  /** Declared requirement (`"1.0"`, `version = "1.0"`), or null. */
  range: string | null;
  /** `workspace = true`: the requirement comes from `[workspace.dependencies]`. */
  workspace: boolean;
  /** Not a registry crate (path, git, other registry): never an entry (D-311). */
  local: boolean;
}

interface CargoManifest {
  packageName: string | null;
  /** `[dependencies]`, `[build-dependencies]`, target-specific ones, in file order. */
  normal: CargoDecl[];
  /** `[dev-dependencies]` and target-specific ones. */
  dev: CargoDecl[];
  /** True when the file has a `[workspace]` table (a workspace root). */
  isWorkspaceRoot: boolean;
  /** `[workspace.dependencies]` by key. */
  workspaceDeps: Map<string, CargoDecl>;
  invalid: boolean;
}

interface LockPackage {
  name: string;
  version: string;
  source: string | null;
  dependencies: string[];
}

interface CargoLock {
  /** crates.io packages (entries). */
  registry: LockPackage[];
  /** Packages without `source` (workspace members, path crates) and the v1 `[root]`. */
  local: LockPackage[];
  invalid: boolean;
}

interface Loaded<T> {
  file: WalkedFile;
  value: T;
  record: ScannedFile;
}

interface FolderState {
  folder: ManifestFolder;
  lock: Loaded<CargoLock> | null;
  manifest: Loaded<CargoManifest> | null;
  /** Workspace members whose resolution lives in this folder's lock. */
  members: Loaded<CargoManifest>[];
  /** Covered by an ancestor's lock: no entries of its own. */
  covered: boolean;
}

function structureError(): ParserFileError {
  return new ParserFileError(PARSER_MESSAGES.structure);
}

function own(table: Table, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

/** Optional sub-table: absent -> null, not a table -> structure error (Cargo rejects such a file too). */
function optionalTable(table: Table, key: string): Table | null {
  const value = own(table, key);
  if (value === undefined) return null;
  if (!isPyDict(value)) throw structureError();
  return value;
}

// ---------------------------------------------------------------- Cargo.toml

/** One declaration (`key = "1.0"` or `key = { … }`), or null when the value is malformed. */
function declarationOf(key: string, value: unknown): CargoDecl | null {
  if (typeof value === 'string') return { name: key, range: value, workspace: false, local: false };
  if (!isPyDict(value)) return null;
  const renamed = own(value, 'package');
  const version = own(value, 'version');
  if ((renamed !== undefined && typeof renamed !== 'string') || (version !== undefined && typeof version !== 'string')) return null;
  return {
    name: typeof renamed === 'string' ? renamed : key,
    range: typeof version === 'string' ? version : null,
    workspace: own(value, 'workspace') === true,
    local: ['path', 'git', 'registry', 'registry-index'].some((k) => own(value, k) !== undefined),
  };
}

/** Declarations of one dependency table; malformed values set `state.invalid`. */
function declarationsOf(table: Table | null, state: { invalid: boolean }): CargoDecl[] {
  if (table === null) return [];
  const out: CargoDecl[] = [];
  for (const [key, value] of Object.entries(table)) {
    const decl = declarationOf(key, value);
    if (decl === null) state.invalid = true;
    else out.push(decl);
  }
  return out;
}

function parseCargoToml(text: string): CargoManifest {
  const root = parseTomlText(text);
  const state = { invalid: false };
  const normal: CargoDecl[] = [];
  const dev: CargoDecl[] = [];
  const collect = (scope: Table): void => {
    for (const key of NORMAL_TABLES) normal.push(...declarationsOf(optionalTable(scope, key), state));
    for (const key of DEV_TABLES) dev.push(...declarationsOf(optionalTable(scope, key), state));
  };
  collect(root);
  const target = optionalTable(root, 'target');
  if (target !== null) {
    for (const value of Object.values(target)) {
      if (!isPyDict(value)) throw structureError();
      collect(value);
    }
  }
  const pkg = optionalTable(root, 'package');
  const name = pkg === null ? undefined : own(pkg, 'name');
  const workspace = optionalTable(root, 'workspace');
  const workspaceDeps = new Map<string, CargoDecl>();
  if (workspace !== null) {
    const table = optionalTable(workspace, 'dependencies');
    for (const [key, value] of Object.entries(table ?? {})) {
      const decl = declarationOf(key, value);
      if (decl === null) state.invalid = true;
      else workspaceDeps.set(key, decl);
    }
  }
  return { packageName: typeof name === 'string' ? name : null, normal, dev, isWorkspaceRoot: workspace !== null, workspaceDeps, invalid: state.invalid };
}

// ---------------------------------------------------------------- Cargo.lock

function lockPackageOf(value: unknown): LockPackage | null {
  if (!isPyDict(value)) return null;
  const name = own(value, 'name');
  const version = own(value, 'version');
  const source = own(value, 'source');
  const deps = own(value, 'dependencies');
  if (typeof name !== 'string' || typeof version !== 'string') return null;
  if (source !== undefined && typeof source !== 'string') return null;
  if (deps !== undefined && !(Array.isArray(deps) && deps.every((d) => typeof d === 'string'))) return null;
  return { name, version, source: typeof source === 'string' ? source : null, dependencies: (deps as string[] | undefined) ?? [] };
}

function parseCargoLock(text: string): CargoLock {
  const root = parseTomlText(text);
  const version = own(root, 'version');
  if (version !== undefined) {
    const n = typeof version === 'number' || typeof version === 'bigint' ? Number(version) : NaN;
    if (!Number.isInteger(n) || n < 1 || n > 4) throw new ParserFileError(PARSER_MESSAGES.unsupportedVersion);
  }
  const packages = own(root, 'package');
  if (packages !== undefined && !Array.isArray(packages)) throw structureError();
  const lock: CargoLock = { registry: [], local: [], invalid: false };
  for (const value of (packages as unknown[] | undefined) ?? []) {
    const pkg = lockPackageOf(value);
    if (pkg === null) {
      lock.invalid = true;
    } else if (pkg.source === null) {
      lock.local.push(pkg);
    } else if (CRATES_IO_SOURCES.has(pkg.source)) {
      lock.registry.push(pkg);
    }
    // git+ and other registries: not a crates.io package (D-311).
  }
  const legacyRoot = own(root, 'root');
  if (legacyRoot !== undefined) {
    const pkg = lockPackageOf(legacyRoot);
    if (pkg === null) lock.invalid = true;
    else lock.local.push(pkg);
  }
  return lock;
}

/** `name\0version` keys of the registry packages referenced by the lock's source-less packages. */
function firstLevelKeys(lock: CargoLock): Set<string> {
  const byName = new Map<string, LockPackage[]>();
  for (const pkg of lock.registry) {
    const list = byName.get(pkg.name);
    if (list) list.push(pkg);
    else byName.set(pkg.name, [pkg]);
  }
  const keys = new Set<string>();
  for (const local of lock.local) {
    for (const ref of local.dependencies) {
      const [name, version] = ref.trim().split(/\s+/, 2);
      const candidates = byName.get(name ?? '') ?? [];
      const hits = version === undefined ? candidates : candidates.filter((p) => p.version === version);
      // `name` alone is written only when the name is unique in the lock.
      if (version === undefined && hits.length !== 1) continue;
      for (const hit of hits) keys.add(`${hit.name}\u0000${hit.version}`);
    }
  }
  return keys;
}

// ---------------------------------------------------------------- folders

function parentDir(relDir: string): string | null {
  if (relDir === '') return null;
  const slash = relDir.lastIndexOf('/');
  return slash === -1 ? '' : relDir.slice(0, slash);
}

/** Crate name and requirement of a declaration; `workspace = true` is looked up in the nearest workspace root (null = skip, not a registry crate). */
function resolveDecl(decl: CargoDecl, workspaceRoot: CargoManifest | null): { name: string; range: string | null } | null {
  if (decl.local) return null;
  if (!decl.workspace) return { name: decl.name, range: decl.range };
  // A member writes `key = { workspace = true }` under the same key as `[workspace.dependencies]`.
  const inherited = workspaceRoot?.workspaceDeps.get(decl.name);
  if (inherited === undefined) return { name: decl.name, range: null };
  if (inherited.local) return null;
  return { name: inherited.name, range: inherited.range };
}

export function parseRust(walk: TreeWalk, ctx: ParserContext): ParseResult {
  void walk;
  const states = new Map<string, FolderState>();
  // Pass 1: every Cargo file is read once (lock before manifest, folders in code point order).
  for (const folder of ctx.folders()) {
    const state: FolderState = { folder, lock: null, manifest: null, members: [], covered: false };
    const lockFile = folder.files.get(CARGO_LOCK);
    if (lockFile) {
      const read = ctx.read(lockFile, (input) => parseCargoLock(input.text()));
      if (read) state.lock = { file: lockFile, value: read.value, record: read.record };
    }
    const tomlFile = folder.files.get(CARGO_TOML);
    if (tomlFile) {
      const read = ctx.read(tomlFile, (input) => parseCargoToml(input.text()));
      if (read) state.manifest = { file: tomlFile, value: read.value, record: read.record };
    }
    states.set(folder.relDir, state);
  }

  const ancestorStates = function* (relDir: string, includeSelf: boolean): Generator<FolderState> {
    let dir: string | null = includeSelf ? relDir : parentDir(relDir);
    while (dir !== null) {
      const state = states.get(dir);
      if (state) yield state;
      dir = parentDir(dir);
    }
  };
  const workspaceRootOf = (relDir: string): CargoManifest | null => {
    for (const state of ancestorStates(relDir, true)) if (state.manifest?.value.isWorkspaceRoot) return state.manifest.value;
    return null;
  };

  // Workspace members covered by the nearest ancestor lock that lists them as source-less packages.
  for (const state of states.values()) {
    const name = state.manifest?.value.packageName;
    if (state.lock !== null || !state.manifest || name === null || name === undefined) continue;
    for (const ancestor of ancestorStates(state.folder.relDir, false)) {
      if (ancestor.lock?.value.local.some((p) => p.name === name)) {
        ancestor.members.push(state.manifest);
        state.covered = true;
        break;
      }
    }
  }

  // Pass 2: entries per folder.
  for (const state of states.values()) {
    if (ctx.capped) break;
    if (state.covered) continue;
    const { folder } = state;
    if (state.lock) {
      const manifests = [state.manifest, ...state.members].filter((m): m is Loaded<CargoManifest> => m !== null);
      const entries = lockEntries(state.lock.value, manifests, (m) => workspaceRootOf(m.file.relDir));
      if (state.lock.value.invalid) ctx.issue(state.lock.file, PARSER_MESSAGES.invalidEntry);
      for (const m of manifests) if (m.value.invalid) ctx.issue(m.file, PARSER_MESSAGES.invalidEntry);
      ctx.commit(folder, [state.lock.record, ...manifests.map((m) => m.record)], entries);
    } else if (state.manifest) {
      const manifest = state.manifest;
      const entries = manifestEntries(manifest.value, workspaceRootOf(folder.relDir));
      if (manifest.value.invalid) ctx.issue(manifest.file, PARSER_MESSAGES.invalidEntry);
      ctx.commit(folder, manifest.record, entries);
    }
  }
  return ctx.finish();
}

function lockEntries(lock: CargoLock, manifests: readonly Loaded<CargoManifest>[], workspaceRootOf: (m: Loaded<CargoManifest>) => CargoManifest | null): DependencyEntry[] {
  // Declared crates of the folder (and covered members): normal wins over dev.
  const normal = new Map<string, string | null>();
  const dev = new Map<string, string | null>();
  for (const m of manifests) {
    const root = workspaceRootOf(m);
    for (const [decls, target] of [
      [m.value.normal, normal],
      [m.value.dev, dev],
    ] as const) {
      for (const decl of decls) {
        const resolved = resolveDecl(decl, root);
        if (resolved === null) continue;
        const known = target.get(resolved.name);
        if (known === undefined || (known === null && resolved.range !== null)) target.set(resolved.name, resolved.range);
      }
    }
  }
  const firstLevel = firstLevelKeys(lock);
  return lock.registry.map((pkg): DependencyEntry => {
    if (!firstLevel.has(`${pkg.name}\u0000${pkg.version}`)) {
      return { name: pkg.name, version: pkg.version, scope: 'transitive', manifestFile: CARGO_LOCK, declaredRange: null };
    }
    if (normal.has(pkg.name) || !dev.has(pkg.name)) {
      return { name: pkg.name, version: pkg.version, scope: 'direct', manifestFile: CARGO_LOCK, declaredRange: normal.get(pkg.name) ?? null };
    }
    return { name: pkg.name, version: pkg.version, scope: 'dev', manifestFile: CARGO_LOCK, declaredRange: dev.get(pkg.name) ?? null };
  });
}

function manifestEntries(manifest: CargoManifest, workspaceRoot: CargoManifest | null): DependencyEntry[] {
  const entries: DependencyEntry[] = [];
  // Normal declarations first: the kit keeps the first of (name, null), so a crate in both tables stays `direct`.
  for (const [decls, scope] of [
    [manifest.normal, 'direct'],
    [manifest.dev, 'dev'],
  ] as const) {
    for (const decl of decls) {
      const resolved = resolveDecl(decl, workspaceRoot);
      if (resolved === null) continue;
      entries.push({ name: resolved.name, version: null, scope, manifestFile: CARGO_TOML, declaredRange: resolved.range });
    }
  }
  return entries;
}
