/**
 * Parser kit of the REQ-011 ecosystems (D-304, D-315; AC-P40-1…7).
 *
 * Every new ecosystem parser (`java.ts`, `golang.ts`, `php.ts`, `rust.ts`,
 * `ruby.ts`, `dart.ts`, `swift.ts`) has the signature
 *
 *     export function parseJava(walk: TreeWalk, ctx: ParserContext): ParseResult
 *
 * and does only the format work: pick the source of each folder
 * (`ctx.folders()`, lock file before manifest, AC-P40-2), read it with
 * `ctx.read(...)` and hand the entries to `ctx.commit(...)`; it returns
 * `ctx.finish()`. The kit owns everything shared:
 *
 * - **Files**: `ctx.folders()` lists the folders holding at least one file of
 *   the ecosystem's `ManifestSpec` (collected by the walk only when the
 *   ecosystem is requested), in code point order of `manifestPath`
 *   (`.` = scan root). Links and files resolving outside the root never
 *   appear; `parseManifests` writes their "link not followed" records.
 * - **Reading** (`ctx.read`): 32 MiB limit, one read per file (hash and text
 *   from the same buffer), strict UTF-8 (`text()` drops a leading BOM).
 *   Any failure becomes ONE `parse_errors` record for that file with a fixed
 *   Turkish text from `PARSER_MESSAGES` (never a library message, never a
 *   path) and `null` is returned, so the parser moves on (AC-P40-3). JSON
 *   (`SyntaxError`), TOML, YAML subset and XML reader errors are mapped to
 *   their texts automatically; throw `ParserFileError(PARSER_MESSAGES.x)`
 *   for a format-level problem (unsupported lock version, wrong structure).
 * - **Entries** (`ctx.commit(folder, sources, entries)`): adds the
 *   `scan_files` records of the used sources and the entries of one folder
 *   at once. The kit sets `ecosystem`, `manifest_path` and the purl
 *   (`purlFor`), cleans `declared_range` (control characters, at most 200
 *   code points), keeps at most 16 source license strings of at most 256
 *   code units each, dedupes by `(lower(name), version)` per folder, skips
 *   invalid entries with one "invalid entries skipped" record per source
 *   file, and applies the limits of AC-P40-5: 20 000 records per folder
 *   (over it: the folder's entries are dropped, one record on the source
 *   file) and 100 000 per scan across all kit ecosystems (over it: one
 *   record with an empty `file`, every later commit is refused).
 * - **Result** (`ctx.finish()`): dependencies sorted by
 *   `(manifest_path, lower(name), version (null last), manifest_file)`,
 *   `scan_files` by path, `parse_errors` in the order they were recorded.
 *
 * Imports only `./` modules and types (ADR-005 Karar 1 boundary).
 */
import type { DependencyScope, ScannedDependency, ScannedFile } from '../../types/scan';
import {
  ManifestReadError,
  NUGET_MESSAGES,
  compareCodePoints,
  decodeStrict,
  emptyResult,
  readManifest,
  sanitizeDeclaredRange,
  type ParseErrorRecord,
  type ParseResult,
  type SpecEcosystem,
  type TreeWalk,
  type WalkedFile,
} from './common';
import { asciiLower } from './nugetIdentity';
import { PurlError, purlFor } from './purl';
import { TomlSyntaxError } from './toml';
import { XmlError } from './xmlReader';
import { YamlSubsetError } from './yamlSubset';

/** Ecosystems parsed through the kit (REQ-011 P-40). */
export type KitEcosystem = Exclude<SpecEcosystem, 'nodejs' | 'python'>;

export const KIT_ECOSYSTEMS: readonly KitEcosystem[] = ['java', 'go', 'php', 'rust', 'ruby', 'dart', 'swift'];

/**
 * Fixed `parse_errors` texts (AC-P40-3: Turkish, path-free). Parsers pass
 * one of these to `ParserFileError` / `ctx.fileError`; free text is never
 * written. Texts shared with the .NET parser are the same strings.
 */
export const PARSER_MESSAGES = Object.freeze({
  json: NUGET_MESSAGES.json,
  toml: 'TOML ayrıştırılamadı.',
  yaml: 'YAML ayrıştırılamadı.',
  yamlUnsupported: 'Desteklenmeyen YAML özelliği (çapa, takma ad, etiket veya çok belgeli akış).',
  xmlMalformed: NUGET_MESSAGES.xmlMalformed,
  xmlDoctype: NUGET_MESSAGES.xmlDoctype,
  xmlLimit: NUGET_MESSAGES.xmlLimit,
  xmlEncoding: NUGET_MESSAGES.xmlEncoding,
  structure: NUGET_MESSAGES.structure,
  unsupportedVersion: 'Desteklenmeyen kilit dosyası sürümü.',
  unsupportedFormat: 'Desteklenmeyen dosya biçimi.',
  invalidEntry: NUGET_MESSAGES.invalidEntry,
  limit: NUGET_MESSAGES.limit,
  scanLimit: 'Tarama bağımlılık sınırını aşıyor (100 000); kalan proje klasörleri atlandı.',
});

export type ParserMessage = (typeof PARSER_MESSAGES)[keyof typeof PARSER_MESSAGES];

/** Records per project folder (AC-P40-5; same value as .NET). */
export const KIT_MAX_DEPENDENCIES_PER_FOLDER = 20_000;
/** Records per scan across all kit ecosystems (AC-P40-5). */
export const KIT_MAX_DEPENDENCIES_PER_SCAN = 100_000;
/** Longest accepted package name / version (UTF-16 code units); longer entries are invalid. */
export const KIT_MAX_NAME_LENGTH = 512;
export const KIT_MAX_VERSION_LENGTH = 256;

/** A file-level problem with one of the fixed texts; the file is skipped. */
export class ParserFileError extends Error {
  constructor(message: ParserMessage) {
    super(message);
    this.name = 'ParserFileError';
  }
}

/** One project folder of an ecosystem. */
export interface ManifestFolder {
  /** Root-relative directory with `/` (`''` = scan root). */
  relDir: string;
  /** `manifest_path` of its records (`.` = scan root). */
  manifestPath: string;
  /** Spec files of this folder by exact name. */
  files: ReadonlyMap<string, WalkedFile>;
}

/** Bytes of one manifest; `text()` decodes strict UTF-8 once (BOM dropped) or throws a file error. */
export interface ManifestInput {
  data: Buffer;
  text(): string;
}

/** One package of a source, before the kit turns it into a `ScannedDependency`. */
export interface DependencyEntry {
  /** Ecosystem package name (see the table in `purl.ts`: Maven `group:artifact`, Swift `host/owner/repo` ...). */
  name: string;
  /** Exact resolved version, or null (then `declaredRange` carries the declaration, AC-P40-6). */
  version: string | null;
  scope: DependencyScope;
  /** File name the entry came from (`manifest_file`), e.g. `Cargo.lock`. */
  manifestFile: string;
  declaredRange?: string | null;
  /** License expressions found in the source itself (only `composer.lock`, AC-P40-7). */
  licenses?: string[];
  /**
   * True when the package comes from a non-public package server (a private
   * pub server, a gem server other than rubygems.org): its name is never
   * sent to a license registry (security review M-5). Becomes
   * `ScannedDependency.private_source`.
   */
  privateSource?: boolean;
}

/** Most license strings kept per entry, and the longest one (UTF-16 code units; security review L-3). */
export const KIT_MAX_LICENSES = 16;
export const KIT_MAX_LICENSE_LENGTH = 256;

/** Source licenses (`composer.lock`) capped to `KIT_MAX_LICENSES` strings of at most `KIT_MAX_LICENSE_LENGTH` code units. */
function boundedLicenses(licenses: readonly string[] | undefined): string[] {
  const out: string[] = [];
  for (const license of licenses ?? []) {
    if (out.length >= KIT_MAX_LICENSES) break;
    if (typeof license !== 'string') continue;
    let text = license.length > KIT_MAX_LICENSE_LENGTH ? license.slice(0, KIT_MAX_LICENSE_LENGTH) : license;
    // Never end on half of a surrogate pair.
    const last = text.charCodeAt(text.length - 1);
    if (text.length < license.length && last >= 0xd800 && last <= 0xdbff) text = text.slice(0, -1);
    out.push(text);
  }
  return out;
}

/** Scan-wide budget shared by all kit contexts of one `parseManifests` call. */
export class KitScanBudget {
  total = 0;
  capped = false;
}

/** C0/C1 control character or DEL; with `spaces`, also any whitespace. */
function hasControl(value: string, spaces: boolean): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return true;
    if (spaces && /\s/.test(value[i])) return true;
  }
  return false;
}

function validEntry(entry: DependencyEntry): boolean {
  const { name, version } = entry;
  if (typeof name !== 'string' || name === '' || name.length > KIT_MAX_NAME_LENGTH || hasControl(name, false)) return false;
  if (version === null) return true;
  return typeof version === 'string' && version !== '' && version.length <= KIT_MAX_VERSION_LENGTH && !hasControl(version, true);
}

function compareDependencies(a: ScannedDependency, b: ScannedDependency): number {
  return (
    compareCodePoints(a.manifest_path, b.manifest_path) ||
    compareCodePoints(asciiLower(a.name), asciiLower(b.name)) ||
    (a.version === null ? (b.version === null ? 0 : 1) : b.version === null ? -1 : compareCodePoints(a.version, b.version)) ||
    compareCodePoints(a.manifest_file, b.manifest_file)
  );
}

/** Per-ecosystem helper handed to a kit parser (see the module comment). */
export class ParserContext {
  private readonly errors: ParseErrorRecord[] = [];
  private readonly dependencies: ScannedDependency[] = [];
  private readonly scanFiles = new Map<string, ScannedFile>();
  private readonly folderKeys = new Map<string, Set<string>>();
  private readonly issued = new Set<string>();
  private scanLimitReported = false;

  constructor(
    private readonly walk: TreeWalk,
    readonly ecosystem: KitEcosystem,
    private readonly budget: KitScanBudget = new KitScanBudget(),
  ) {}

  /** Folders with at least one spec file, in code point order of `manifestPath`. */
  folders(): ManifestFolder[] {
    const byDir = this.walk.specByDir?.get(this.ecosystem);
    if (!byDir) return [];
    return [...byDir]
      .map(([relDir, files]) => ({ relDir, manifestPath: relDir === '' ? '.' : relDir, files }))
      .sort((a, b) => compareCodePoints(a.manifestPath, b.manifestPath));
  }

  /**
   * Reads `file` and runs `parse` on it. Returns the parsed value and the
   * `scan_files` record (not yet added: pass it to `commit` when the source
   * is used), or null after writing one fixed-text record for the file.
   */
  read<T>(file: WalkedFile, parse: (input: ManifestInput) => T): { value: T; record: ScannedFile } | null {
    try {
      const { data, record } = readManifest(file, this.ecosystem);
      let decoded: string | null = null;
      const input: ManifestInput = {
        data,
        text: () => {
          if (decoded === null) {
            const text = decodeStrict(data, file.relPath);
            decoded = text.startsWith('﻿') ? text.slice(1) : text;
          }
          return decoded;
        },
      };
      return { value: parse(input), record };
    } catch (err) {
      this.fileError(file, this.messageOf(err, file));
      return null;
    }
  }

  private messageOf(err: unknown, file: WalkedFile): string {
    if (err instanceof ParserFileError) return err.message;
    if (err instanceof ManifestReadError) {
      const prefix = `${file.relPath}: `;
      return err.message.startsWith(prefix) ? err.message.slice(prefix.length) : PARSER_MESSAGES.structure;
    }
    if (err instanceof YamlSubsetError) return err.code === 'unsupported' ? PARSER_MESSAGES.yamlUnsupported : PARSER_MESSAGES.yaml;
    if (err instanceof TomlSyntaxError) return PARSER_MESSAGES.toml;
    if (err instanceof XmlError) {
      switch (err.code) {
        case 'doctype':
          return PARSER_MESSAGES.xmlDoctype;
        case 'limit':
          return PARSER_MESSAGES.xmlLimit;
        case 'encoding':
          return PARSER_MESSAGES.xmlEncoding;
        default:
          return PARSER_MESSAGES.xmlMalformed;
      }
    }
    if (err instanceof SyntaxError) return PARSER_MESSAGES.json;
    return PARSER_MESSAGES.structure;
  }

  /** One `parse_errors` record for `file` (a `WalkedFile` or a root-relative path); `message` is a fixed text. */
  fileError(file: WalkedFile | string, message: ParserMessage | string): void {
    this.errors.push({ ecosystem: this.ecosystem, file: typeof file === 'string' ? file : file.relPath, error: message });
  }

  /** Like `fileError`, but at most once per file and message (entry-level problems). */
  issue(file: WalkedFile | string, message: ParserMessage): void {
    const relPath = typeof file === 'string' ? file : file.relPath;
    const key = `${relPath}\u0000${message}`;
    if (this.issued.has(key)) return;
    this.issued.add(key);
    this.fileError(relPath, message);
  }

  /**
   * Adds the entries of `folder` together with the `scan_files` records of
   * the sources they came from. Returns false (nothing added) when a limit
   * refuses the folder. `limitFile` receives the folder-limit record
   * (default: the first source).
   */
  commit(folder: ManifestFolder, sources: ScannedFile | readonly ScannedFile[], entries: readonly DependencyEntry[], limitFile?: WalkedFile | string): boolean {
    const records = Array.isArray(sources) ? (sources as readonly ScannedFile[]) : [sources as ScannedFile];
    if (this.budget.capped) {
      this.reportScanLimit();
      return false;
    }
    const keys = this.folderKeys.get(folder.manifestPath) ?? new Set<string>();
    const fresh: ScannedDependency[] = [];
    const freshKeys = new Set<string>();
    for (const entry of entries) {
      let purl: string;
      try {
        if (!validEntry(entry)) throw new PurlError();
        purl = purlFor(this.ecosystem, entry.name, entry.version);
      } catch {
        this.issue(sourcePathOf(folder, entry.manifestFile, records), PARSER_MESSAGES.invalidEntry);
        continue;
      }
      const key = JSON.stringify([asciiLower(entry.name), entry.version]);
      if (keys.has(key) || freshKeys.has(key)) continue;
      freshKeys.add(key);
      const declared = entry.declaredRange === null || entry.declaredRange === undefined ? null : sanitizeDeclaredRange(entry.declaredRange);
      const dependency: ScannedDependency = {
        ecosystem: this.ecosystem,
        name: entry.name,
        version: entry.version,
        purl,
        scope: entry.scope,
        licenses: boundedLicenses(entry.licenses),
        manifest_file: entry.manifestFile,
        manifest_path: folder.manifestPath,
        declared_range: declared === '' ? null : declared,
      };
      // Only when true, so records of public packages keep their exact shape.
      if (entry.privateSource === true) dependency.private_source = true;
      fresh.push(dependency);
    }
    if (keys.size + fresh.length > KIT_MAX_DEPENDENCIES_PER_FOLDER) {
      this.fileError(limitFile ?? records[0]?.file_path ?? folder.manifestPath, PARSER_MESSAGES.limit);
      return false;
    }
    if (this.budget.total + fresh.length > KIT_MAX_DEPENDENCIES_PER_SCAN) {
      this.budget.capped = true;
      this.reportScanLimit();
      return false;
    }
    this.budget.total += fresh.length;
    for (const key of freshKeys) keys.add(key);
    this.folderKeys.set(folder.manifestPath, keys);
    for (const record of records) if (!this.scanFiles.has(record.file_path)) this.scanFiles.set(record.file_path, record);
    this.dependencies.push(...fresh);
    return true;
  }

  /** True once the scan-wide limit refused a folder; a parser may stop early. */
  get capped(): boolean {
    return this.budget.capped;
  }

  private reportScanLimit(): void {
    if (this.scanLimitReported) return;
    this.scanLimitReported = true;
    this.errors.push({ ecosystem: this.ecosystem, file: '', error: PARSER_MESSAGES.scanLimit });
  }

  /** The ecosystem's `ParseResult` (sorted; see the module comment). */
  finish(): ParseResult {
    const result = emptyResult();
    result.dependencies.push(...[...this.dependencies].sort(compareDependencies));
    result.scan_files.push(...[...this.scanFiles.values()].sort((a, b) => compareCodePoints(a.file_path, b.file_path)));
    result.parse_errors.push(...this.errors);
    return result;
  }
}

/** Source path for an entry-level record: the record whose file name matches the entry, else the first one. */
function sourcePathOf(folder: ManifestFolder, manifestFile: string, records: readonly ScannedFile[]): string {
  const match = records.find((r) => r.filename === manifestFile);
  if (match) return match.file_path;
  return records[0]?.file_path ?? folder.manifestPath;
}

/** Signature of every kit parser (`parseJava`, `parseGo`, ...). */
export type KitParser = (walk: TreeWalk, ctx: ParserContext) => ParseResult;
