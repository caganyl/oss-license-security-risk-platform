/**
 * .NET (NuGet) dependency parser (REQ-006 P-20; ADR-008 Karar 5, 7).
 *
 * Project folders: every folder with a project file (`*.csproj`, `*.fsproj`,
 * `*.vbproj`), a `packages.lock.json` or a `packages.config`, and the parent
 * of every `obj/project.assets.json`. Folders are processed in code point
 * order of their relative path (`.` for the root). Per folder:
 *   1. `packages.lock.json` — when it reads cleanly, it is the only source;
 *   2. otherwise `obj/project.assets.json`;
 *   3. otherwise all project files (name order) and `packages.config`
 *      together, with the nearest regular `Directory.Packages.props` up to the
 *      scan root (CPM); one failing file does not stop the others.
 * A file error yields one `parse_errors` record with a fixed text and the
 * next source is tried; entry problems yield one record per file and kind.
 * Only sources that were actually used (and used CPM files) enter
 * `scan_files`. NuGet has no dev scope (all records are runtime).
 *
 * Scan limit (security review L-1): a folder whose records would take the
 * scan total over `NUGET_MAX_DEPENDENCIES_PER_SCAN` is not added (no records,
 * `scan_files` or hashes; its file-level records stay), the remaining folders
 * are skipped, and one
 * `parse_errors` record with a fixed text and an empty `file` is written.
 *
 * The lock `contentHash` / assets `sha512` values go to the optional
 * `IntegrityCollector` (`addNuget`), never into the result (ADR-008 Karar 6).
 *
 * Imports only `./` modules (ADR-008 Karar 1).
 */
import type { ScannedDependency, ScannedFile } from '../../types/scan';
import {
  LINK_NOT_FOLLOWED_MESSAGE,
  ManifestReadError,
  NUGET_MAX_DEPENDENCIES_PER_FOLDER,
  NUGET_MAX_DEPENDENCIES_PER_SCAN,
  NUGET_MESSAGES,
  NugetFileError,
  compareCodePoints,
  emptyResult,
  isDotnetProjectFileName,
  readManifest,
  type NugetEntry,
  type NugetIssue,
  type ParseErrorRecord,
  type ParseResult,
  type TreeWalk,
  type WalkedFile,
} from './common';
import type { IntegrityCollector } from './lockIntegrityValue';
import {
  CPM_FILE_NAME,
  PACKAGES_CONFIG_FILE_NAME,
  directEntry,
  parseCentralPackages,
  parsePackagesConfig,
  parseProjectFile,
  type CentralPackages,
} from './msbuildProject';
import { parseNugetAssets } from './nugetAssets';
import { asciiLower, nugetKey, nugetPurl } from './nugetIdentity';
import { LOCK_FILE_NAME, parseNugetLock } from './nugetLock';

const ECOSYSTEM = 'dotnet';
const ASSETS_NAME = 'project.assets.json';

const ISSUE_MESSAGES: Readonly<Record<NugetIssue, string>> = {
  invalidId: NUGET_MESSAGES.invalidId,
  unknownType: NUGET_MESSAGES.unknownType,
  invalidEntry: NUGET_MESSAGES.invalidEntry,
};

interface ProjectFolder {
  relDir: string;
  manifestPath: string;
  lock?: WalkedFile;
  assets?: WalkedFile;
  projectFiles: WalkedFile[];
  config?: WalkedFile;
}

type CpmState = { ok: true; file: WalkedFile; record: ScannedFile; table: CentralPackages } | { ok: false };

class NugetRun {
  readonly errors: ParseErrorRecord[] = [];
  readonly dependencies: ScannedDependency[] = [];
  private readonly scanFiles = new Map<string, ScannedFile>();
  private readonly cpmCache = new Map<string, CpmState>();
  /** True once a folder was dropped by the scan limit; no folder is processed afterwards. */
  capped = false;

  constructor(
    private readonly dotnetByDir: Map<string, Map<string, WalkedFile>>,
    private readonly collector: IntegrityCollector | undefined,
  ) {}

  fileError(file: WalkedFile, message: string): void {
    this.errors.push({ ecosystem: ECOSYSTEM, file: file.relPath, error: message });
  }

  issueErrors(file: WalkedFile, issues: readonly NugetIssue[]): void {
    for (const issue of issues) this.fileError(file, ISSUE_MESSAGES[issue]);
  }

  addScanFile(record: ScannedFile): void {
    if (!this.scanFiles.has(record.file_path)) this.scanFiles.set(record.file_path, record);
  }

  sortedScanFiles(): ScannedFile[] {
    return [...this.scanFiles.values()].sort((a, b) => compareCodePoints(a.file_path, b.file_path));
  }

  /**
   * Reads and parses one file; a file error is recorded with its fixed text
   * and null is returned. Messages of unexpected errors are never used.
   */
  read<T>(file: WalkedFile, parse: (data: Buffer) => T): { value: T; record: ScannedFile } | null {
    try {
      const { data, record } = readManifest(file, ECOSYSTEM);
      return { value: parse(data), record };
    } catch (err) {
      let message: string = NUGET_MESSAGES.structure;
      if (err instanceof NugetFileError) {
        message = err.message;
      } else if (err instanceof ManifestReadError) {
        const prefix = `${file.relPath}: `;
        message = err.message.startsWith(prefix) ? err.message.slice(prefix.length) : NUGET_MESSAGES.structure;
      }
      this.fileError(file, message);
      return null;
    }
  }

  /** Nearest regular `Directory.Packages.props` from `relDir` up to the scan root (parsed once per scan). */
  centralPackages(relDir: string): CpmState | null {
    let dir: string | null = relDir;
    while (dir !== null) {
      const file = this.dotnetByDir.get(dir)?.get(CPM_FILE_NAME);
      if (file) {
        let state = this.cpmCache.get(file.relPath);
        if (!state) {
          const read = this.read(file, parseCentralPackages);
          if (read) {
            this.issueErrors(file, read.value.issues);
            state = { ok: true, file, record: read.record, table: read.value };
          } else {
            state = { ok: false };
          }
          this.cpmCache.set(file.relPath, state);
        }
        return state;
      }
      if (dir === '') break;
      const slash = dir.lastIndexOf('/');
      dir = slash === -1 ? '' : dir.slice(0, slash);
    }
    return null;
  }

  /**
   * Scan limit check for one folder's `count` records: false (and the one
   * fixed-text, path-free record) when the scan total would exceed the limit.
   */
  fitsScanLimit(count: number): boolean {
    if (this.capped) return false;
    if (this.dependencies.length + count <= NUGET_MAX_DEPENDENCIES_PER_SCAN) return true;
    this.capped = true;
    this.errors.push({ ecosystem: ECOSYSTEM, file: '', error: NUGET_MESSAGES.scanLimit });
    return false;
  }

  emit(folder: ProjectFolder, entries: Iterable<NugetEntry>): void {
    for (const entry of entries) {
      this.dependencies.push({
        ecosystem: ECOSYSTEM,
        name: entry.name,
        version: entry.version,
        purl: nugetPurl(entry.name, entry.version),
        scope: entry.scope,
        licenses: [],
        manifest_file: entry.manifestFile,
        manifest_path: folder.manifestPath,
        declared_range: entry.declaredRange,
      });
    }
  }

  /** Lock or assets source; true when it was used. */
  jsonSource(folder: ProjectFolder, file: WalkedFile, parse: typeof parseNugetLock): boolean {
    const read = this.read(file, parse);
    if (!read) return false;
    this.issueErrors(file, read.value.issues);
    // A folder over the scan limit still counts as "used": the next source of the same folder is not tried.
    if (!this.fitsScanLimit(read.value.entries.length)) return true;
    this.addScanFile(read.record);
    this.emit(folder, read.value.entries);
    if (this.collector) {
      for (const h of read.value.hashes) this.collector.addNuget(folder.manifestPath, h.name, h.version, h.hash);
    }
    return true;
  }

  /** Step 3: project files, `packages.config` and CPM `GlobalPackageReference`s merged (first source wins). */
  projectSources(folder: ProjectFolder): void {
    const merged = new Map<string, NugetEntry>();
    // scan_files of the used files wait for the scan limit check of the whole folder (issues keep their order).
    const used: ScannedFile[] = [];
    let cpm: CpmState | null | undefined;
    let projectUsed = false;

    /** Merges one file's entries; over the folder limit the file is a file error (false). */
    const mergeFile = (file: WalkedFile, entries: NugetEntry[], issues: readonly NugetIssue[], record: ScannedFile): boolean => {
      const fresh = new Map<string, NugetEntry>();
      for (const entry of entries) {
        const key = nugetKey(entry.name, entry.version);
        if (!merged.has(key) && !fresh.has(key)) fresh.set(key, entry);
      }
      if (merged.size + fresh.size > NUGET_MAX_DEPENDENCIES_PER_FOLDER) {
        this.fileError(file, NUGET_MESSAGES.limit);
        return false;
      }
      this.issueErrors(file, issues);
      used.push(record);
      for (const [key, entry] of fresh) merged.set(key, entry);
      return true;
    };

    for (const file of [...folder.projectFiles].sort((a, b) => compareCodePoints(a.name, b.name))) {
      const read = this.read(file, parseProjectFile);
      if (!read) continue;
      if (cpm === undefined) cpm = this.centralPackages(folder.relDir);
      const table = cpm && cpm.ok ? cpm.table.versions : null;
      const entries = read.value.references.map((ref) =>
        directEntry(ref.id, ref.explicitVersion ?? table?.get(asciiLower(ref.id)) ?? null, file.name),
      );
      if (mergeFile(file, entries, read.value.issues, read.record)) projectUsed = true;
    }

    if (folder.config) {
      const read = this.read(folder.config, parsePackagesConfig);
      if (read) mergeFile(folder.config, read.value.entries, read.value.issues, read.record);
    }

    if (projectUsed && cpm && cpm.ok && cpm.table.globals.length > 0) {
      const globals = cpm.table.globals.map((g) => directEntry(g.id, g.explicitVersion, CPM_FILE_NAME));
      mergeFile(cpm.file, globals, [], cpm.record);
    }

    if (!this.fitsScanLimit(merged.size)) return;
    for (const record of used) this.addScanFile(record);
    if (projectUsed && cpm && cpm.ok) this.addScanFile(cpm.record);

    this.emit(folder, merged.values());
  }

  run(folder: ProjectFolder): void {
    if (folder.lock && this.jsonSource(folder, folder.lock, parseNugetLock)) return;
    if (folder.assets && this.jsonSource(folder, folder.assets, parseNugetAssets)) return;
    this.projectSources(folder);
  }
}

function projectFolders(dotnetByDir: Map<string, Map<string, WalkedFile>>): ProjectFolder[] {
  const folders = new Map<string, ProjectFolder>();
  const folderOf = (relDir: string): ProjectFolder => {
    let folder = folders.get(relDir);
    if (!folder) {
      folder = { relDir, manifestPath: relDir === '' ? '.' : relDir, projectFiles: [] };
      folders.set(relDir, folder);
    }
    return folder;
  };
  for (const [relDir, files] of dotnetByDir) {
    for (const file of files.values()) {
      if (file.name === ASSETS_NAME) {
        // The walk only collects it when the direct parent folder is `obj`.
        folderOf(relDir === 'obj' ? '' : relDir.slice(0, -'/obj'.length)).assets = file;
      } else if (file.name === LOCK_FILE_NAME) {
        folderOf(relDir).lock = file;
      } else if (file.name === PACKAGES_CONFIG_FILE_NAME) {
        folderOf(relDir).config = file;
      } else if (isDotnetProjectFileName(file.name)) {
        folderOf(relDir).projectFiles.push(file);
      }
    }
  }
  return [...folders.values()].sort((a, b) => compareCodePoints(a.manifestPath, b.manifestPath));
}

function compareDependencies(a: ScannedDependency, b: ScannedDependency): number {
  return (
    compareCodePoints(a.manifest_path, b.manifest_path) ||
    compareCodePoints(asciiLower(a.name), asciiLower(b.name)) ||
    (a.version === null ? (b.version === null ? 0 : 1) : b.version === null ? -1 : compareCodePoints(asciiLower(a.version), asciiLower(b.version))) ||
    compareCodePoints(a.manifest_file, b.manifest_file)
  );
}

export function parse(walk: TreeWalk, collector?: IntegrityCollector): ParseResult {
  const result = emptyResult();
  const dotnetByDir = walk.dotnetByDir;
  if (!dotnetByDir) return result;

  const links = [...(walk.dotnetLinks ?? [])].sort((a, b) => compareCodePoints(a.relPath, b.relPath));
  for (const link of links) result.parse_errors.push({ ecosystem: ECOSYSTEM, file: link.relPath, error: LINK_NOT_FOLLOWED_MESSAGE });

  const run = new NugetRun(dotnetByDir, collector);
  for (const folder of projectFolders(dotnetByDir)) {
    if (run.capped) break;
    run.run(folder);
  }

  result.dependencies.push(...run.dependencies.sort(compareDependencies));
  result.scan_files.push(...run.sortedScanFiles());
  result.parse_errors.push(...run.errors);
  return result;
}
