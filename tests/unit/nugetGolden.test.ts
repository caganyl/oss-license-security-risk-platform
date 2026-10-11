/**
 * REQ-006 · P-20 NuGet parser goldens and behaviour on fixture trees
 * (AC-P20-1…7, AC-P20-10…12, AC-P20-14, AC-P20-15, AC-G-6; ADR-008 golden strategy).
 *
 * Goldens are byte-compared JSON (`tests/helpers/nugetGolden.ts`). They are
 * frozen with F5; `UPDATE_NUGET_GOLDENS=1` rewrites them (only for an
 * intentional, reviewed change). npm/PyPI goldens are untouched and still
 * verified by `parsersGolden.test.ts` (AC-G-6).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import {
  LINK_NOT_FOLLOWED_MESSAGE,
  NUGET_MAX_DEPENDENCIES_PER_FOLDER,
  NUGET_MAX_DEPENDENCIES_PER_SCAN,
  NUGET_MESSAGES,
  walkTree,
} from '../../src/scanner/parsers/common';
import { IntegrityCollector } from '../../src/scanner/parsers/lockIntegrityValue';
import type { SandboxScanResult } from '../../src/types/scan';
import {
  DOTNET_CASES_DIR,
  DOTNET_EXPECTED_DIR,
  DOTNET_FIXTURES,
  NUGET_GOLDEN_CASES,
  SAMPLE_SOLUTION,
  folderSummary,
  goldenText,
  nugetScanId,
  parseDotnet,
  sampleGoldenValue,
} from '../helpers/nugetGolden';
import { FORMATS_DIR } from '../helpers/parserGolden';

const UPDATE = process.env.UPDATE_NUGET_GOLDENS === '1';
const caseDir = (name: string) => path.join(DOTNET_CASES_DIR, name);
const cache = new Map<string, SandboxScanResult>();
const runCase = (name: string): SandboxScanResult => {
  let r = cache.get(name);
  if (!r) {
    r = parseDotnet(caseDir(name), nugetScanId(name));
    cache.set(name, r);
  }
  return r;
};

function expectGolden(name: string, actual: string): void {
  const file = path.join(DOTNET_EXPECTED_DIR, `${name}.json`);
  if (UPDATE) {
    fs.mkdirSync(DOTNET_EXPECTED_DIR, { recursive: true });
    fs.writeFileSync(file, actual);
  }
  expect(fs.existsSync(file), `${name}: golden file is missing`).toBe(true);
  expect(fs.readFileSync(file, 'utf8')).toBe(actual);
  expect(fs.readFileSync(file).equals(Buffer.from(actual, 'utf8')), `${name}: golden bytes`).toBe(true);
}

let tmpBase = '';
beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-nuget-'));
});
afterAll(() => {
  if (tmpBase) fs.rmSync(tmpBase, { recursive: true, force: true });
});
function tmpTree(name: string, files: Record<string, string | Buffer>): string {
  const root = path.join(tmpBase, name);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  fs.mkdirSync(root, { recursive: true });
  return root;
}

// ---------------------------------------------------------------------------
describe('AC-P20-12: NuGet goldens (one per source kind, byte compared)', () => {
  it.each(NUGET_GOLDEN_CASES.map((n) => [n]))('AC-P20-12: %s equals its golden', (name) => {
    expectGolden(name, goldenText(runCase(name)));
  });

  it('AC-P20-12: the golden set is exactly the case folders plus the sample solution', () => {
    const cases = fs.readdirSync(DOTNET_CASES_DIR).sort();
    expect(cases).toEqual([...NUGET_GOLDEN_CASES].sort());
    const goldens = fs.readdirSync(DOTNET_EXPECTED_DIR).sort();
    expect(goldens).toEqual([...NUGET_GOLDEN_CASES, 'sample-solution'].map((n) => `${n}.json`).sort());
  });

  it('AC-P20-12 / AC-P20-10: the golden set is not vacuous and every record has the dotnet shape', () => {
    let deps = 0;
    let errors = 0;
    for (const name of NUGET_GOLDEN_CASES) {
      const r = runCase(name);
      deps += r.dependencies.length;
      errors += r.parse_errors.length;
      expect(r.total_deps).toBe(r.dependencies.length);
      for (const d of r.dependencies) {
        expect(Object.keys(d)).toEqual(['ecosystem', 'name', 'version', 'purl', 'scope', 'licenses', 'manifest_file', 'manifest_path', 'declared_range']);
        expect(d.ecosystem).toBe('dotnet');
        expect(d.licenses).toEqual([]);
        expect(['direct', 'transitive']).toContain(d.scope);
        expect(d.manifest_path).not.toContain('\\');
        expect(d.purl.startsWith(`pkg:nuget/${d.name}`)).toBe(true);
      }
      for (const f of r.scan_files) {
        expect(f.ecosystem).toBe('dotnet');
        expect(f.file_hash).toMatch(/^[0-9a-f]{64}$/);
        expect(f.size_bytes).toBeGreaterThan(0);
      }
    }
    expect(deps).toBeGreaterThan(20);
    expect(errors).toBeGreaterThan(10);
  });
});

describe('AC-P20-11: "Örnek .NET projesinde doğrudan ve dolaylı paketler listeleniyor"', () => {
  it('AC-P20-11: the sample solution equals its golden (summary + full result)', () => {
    expectGolden('sample-solution', goldenText(sampleGoldenValue()));
  });

  it('AC-P20-11: per project folder direct/transitive counts and known transitive packages', () => {
    const summary = folderSummary(parseDotnet(SAMPLE_SOLUTION, 'x'));
    expect(Object.fromEntries(Object.entries(summary).map(([k, v]) => [k, [v.direct, v.transitive]]))).toEqual({
      'legacy/LegacyApp': [3, 0],
      'src/App': [3, 3],
      'src/Lib': [1, 1],
      'src/Tools': [7, 0],
    });
    expect(summary['src/App'].transitivePurls).toContain('pkg:nuget/Serilog@3.1.1'); // CentralTransitive
    expect(summary['src/App'].transitivePurls).toContain('pkg:nuget/Microsoft.Extensions.Logging.Abstractions@8.0.0');
    expect(summary['src/Lib'].transitivePurls).toEqual(['pkg:nuget/Serilog@3.1.1']);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P20-2: project folder and source precedence', () => {
  it('AC-P20-2: lock + csproj -> only the lock is used and only it enters scan_files', () => {
    const r = runCase('lock-v2');
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['packages.lock.json']);
    expect(r.dependencies.some((d) => d.name.startsWith('Never.Read'))).toBe(false);
  });

  it('AC-P20-2: assets + csproj -> only obj/project.assets.json is used; its project folder is the parent of obj', () => {
    const r = runCase('assets-v3');
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['obj/project.assets.json']);
    expect(new Set(r.dependencies.map((d) => d.manifest_path))).toEqual(new Set(['.']));
    expect(r.dependencies.some((d) => d.name.startsWith('Never.Read'))).toBe(false);
  });

  it('AC-P20-2: lock + assets + csproj in one folder -> only the lock; broken lock -> assets and one parse_errors record', () => {
    const lockOk = fs.readFileSync(path.join(caseDir('lock-v1'), 'packages.lock.json'));
    const assets = fs.readFileSync(path.join(caseDir('broken'), 'a', 'obj', 'project.assets.json')); // issue-free assets file
    const csproj = fs.readFileSync(path.join(caseDir('lock-v2'), 'App.csproj'));
    const all = tmpTree('prec-all', { 'p/packages.lock.json': lockOk, 'p/obj/project.assets.json': assets, 'p/App.csproj': csproj });
    const r1 = parseDotnet(all, 's');
    expect(r1.scan_files.map((f) => f.file_path)).toEqual(['p/packages.lock.json']);
    expect(r1.parse_errors).toEqual([]);
    const broken = tmpTree('prec-broken', { 'p/packages.lock.json': '{', 'p/obj/project.assets.json': assets, 'p/App.csproj': csproj });
    const r2 = parseDotnet(broken, 's');
    expect(r2.scan_files.map((f) => f.file_path)).toEqual(['p/obj/project.assets.json']);
    expect(r2.parse_errors).toEqual([{ ecosystem: 'dotnet', file: 'p/packages.lock.json', error: NUGET_MESSAGES.json }]);
    expect(r2.dependencies.every((d) => d.manifest_file === 'project.assets.json' && d.manifest_path === 'p')).toBe(true);
  });

  it('AC-P20-2 / AC-P20-15: broken sources fall through with fixed texts (lock -> assets -> project files)', () => {
    const r = runCase('broken');
    expect(r.dependencies.map((d) => [d.manifest_path, d.manifest_file, d.name])).toEqual([
      ['a', 'project.assets.json', 'Fallback.Package'],
      ['b', 'b.csproj', 'Project.File.Fallback'],
    ]);
    const messages = new Set<string>(Object.values(NUGET_MESSAGES));
    for (const e of r.parse_errors) {
      expect(e.ecosystem).toBe('dotnet');
      expect(messages.has(e.error), e.error).toBe(true);
    }
    expect(r.parse_errors.map((e) => e.error)).toEqual([
      NUGET_MESSAGES.json,
      NUGET_MESSAGES.lockVersion,
      NUGET_MESSAGES.assetsVersion,
      NUGET_MESSAGES.xmlDoctype,
      NUGET_MESSAGES.xmlMalformed,
      NUGET_MESSAGES.structure,
      NUGET_MESSAGES.structure,
      NUGET_MESSAGES.xmlMalformed,
    ]);
  });
});

describe('AC-P20-1: discovery', () => {
  it('AC-P20-1: project.assets.json counts only directly inside a folder named exactly "obj" (case-sensitive)', () => {
    const assets = fs.readFileSync(path.join(caseDir('assets-v3'), 'obj', 'project.assets.json'));
    const root = tmpTree('disc-obj', { 'x/Obj/project.assets.json': assets, 'y/project.assets.json': assets, 'z/obj/deep/project.assets.json': assets });
    const r = parseDotnet(root, 's');
    expect(r).toMatchObject({ dependencies: [], scan_files: [], parse_errors: [] });
  });

  it('AC-P20-1: project extensions are case-insensitive, fixed names case-sensitive; obj and bin are walked', () => {
    const proj = '<Project><ItemGroup><PackageReference Include="P" Version="1.0.0" /></ItemGroup></Project>';
    const cfg = '<packages><package id="C" version="1.0.0" /></packages>';
    const root = tmpTree('disc-names', {
      'a/A.CSPROJ': proj,
      'b/B.FsProj': proj,
      'c/Packages.config': cfg,
      'd/bin/packages.config': cfg,
      'e/csproj': proj,
    });
    const r = parseDotnet(root, 's');
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['a/A.CSPROJ', 'b/B.FsProj', 'd/bin/packages.config']);
  });

  it('AC-P20-1 / AC-G-6: without dotnet requested, .NET files are invisible; walkTree output has no dotnet keys', () => {
    const r = parseManifests(SAMPLE_SOLUTION, ['nodejs', 'python'], 's');
    expect(r).toEqual({ scan_id: 's', status: 'completed', total_deps: 0, dependencies: [], scan_files: [], parse_errors: [] });
    const walk = walkTree(SAMPLE_SOLUTION);
    expect(Object.keys(walk).sort()).toEqual(['byDir', 'errors', 'fileLinks', 'rootDir']);
    expect(JSON.stringify(walkTree(SAMPLE_SOLUTION, {}), (_k, v: unknown) => (v instanceof Map ? [...v] : v))).toBe(
      JSON.stringify(walk, (_k, v: unknown) => (v instanceof Map ? [...v] : v)),
    );
    expect(walkTree(SAMPLE_SOLUTION, { dotnet: true }).dotnetByDir?.size).toBeGreaterThan(0);
  });
});

describe('AC-G-6: npm/PyPI output unchanged on a tree with .NET files and .NET-named links', () => {
  const copyTree = (src: string, dst: string) => fs.cpSync(src, dst, { recursive: true });

  it('AC-G-6: nodejs/python parse of an npm fixture copy plus .NET files is byte-identical to the plain copy', () => {
    const plain = path.join(tmpBase, 'g6-plain');
    const withNet = path.join(tmpBase, 'g6-net');
    copyTree(path.join(FORMATS_DIR, 'npm-lock-v2'), plain);
    copyTree(path.join(FORMATS_DIR, 'npm-lock-v2'), withNet);
    copyTree(SAMPLE_SOLUTION, path.join(withNet, 'dotnet-sample'));
    copyTree(caseDir('broken'), path.join(withNet, 'dotnet-broken'));
    const a = parseManifests(plain, ['nodejs', 'python'], 'g6');
    const b = parseManifests(withNet, ['nodejs', 'python'], 'g6');
    expect(a.dependencies.length).toBeGreaterThan(0);
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
  });

  it('AC-G-6 / AC-P20-1: a .NET-named link gives the F4 filesystem record without dotnet and a dotnet record with it', (ctx) => {
    const root = tmpTree('g6-links', { 'real.csproj': '<Project />' });
    try {
      fs.symlinkSync(path.join(root, 'real.csproj'), path.join(root, 'linked.csproj'), 'file');
      fs.symlinkSync(path.join(root, 'real.csproj'), path.join(root, 'packages.lock.json'), 'file');
    } catch {
      ctx.skip(); // file symlinks need Developer Mode / admin on Windows
      return;
    }
    const f4 = parseManifests(root, ['nodejs', 'python'], 's');
    expect([...f4.parse_errors].sort((x, y) => x.file.localeCompare(y.file))).toEqual([
      { ecosystem: 'filesystem', file: 'linked.csproj', error: LINK_NOT_FOLLOWED_MESSAGE },
      { ecosystem: 'filesystem', file: 'packages.lock.json', error: LINK_NOT_FOLLOWED_MESSAGE },
    ]);
    const net = parseManifests(root, ['dotnet'], 's');
    expect(net.parse_errors.filter((e) => e.error === LINK_NOT_FOLLOWED_MESSAGE).map((e) => [e.ecosystem, e.file]).sort()).toEqual([
      ['dotnet', 'linked.csproj'],
      ['dotnet', 'packages.lock.json'],
    ]);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P20-3 / AC-P20-4: lock and assets entries', () => {
  it('AC-P20-3: multi-TFM merge, Direct wins over Transitive, case-insensitive (id, version) dedupe keeps first casing', () => {
    const r = runCase('lock-v2');
    const core = r.dependencies.filter((d) => d.name.toLowerCase() === 'contoso.core');
    expect(core).toHaveLength(1);
    expect(core[0]).toMatchObject({ name: 'Contoso.Core', version: '1.0.0-Beta', scope: 'direct', declared_range: '[1.0.0-Beta, )' });
    expect(r.dependencies.filter((d) => d.name === 'Contoso.Utils').map((d) => d.version)).toEqual(['1.2.3', '4.0.10.1']);
    const memory = parseDotnet(SAMPLE_SOLUTION, 's').dependencies.find((d) => d.name === 'System.Memory');
    expect(memory).toMatchObject({ scope: 'direct', declared_range: '[4.5.5, )' }); // Transitive in net6.0, Direct in net8.0
  });

  it('AC-P20-3 / D-154: one parse_errors record per issue kind and file, at most three', () => {
    const errs = runCase('lock-v2').parse_errors;
    expect(errs).toHaveLength(3);
    expect(new Set(errs.map((e) => e.error))).toEqual(new Set([NUGET_MESSAGES.invalidId, NUGET_MESSAGES.unknownType, NUGET_MESSAGES.invalidEntry]));
    expect(runCase('assets-v3').parse_errors).toHaveLength(3);
  });

  it('AC-P20-3: Project entries are skipped; requested is declared_range only for Direct', () => {
    const r = runCase('lock-v2');
    expect(r.dependencies.some((d) => d.name === 'Sibling')).toBe(false);
    for (const d of r.dependencies) if (d.scope === 'transitive') expect(d.declared_range).toBeNull();
  });

  it('AC-P20-4 / AC-P20-15: absolute user paths from restore/packageFolders/logs never appear in the output', () => {
    for (const r of [runCase('assets-v3'), parseDotnet(SAMPLE_SOLUTION, 's')]) {
      const text = JSON.stringify(r);
      expect(text).not.toContain('fixtureuser');
      expect(text).not.toContain('C:\\\\');
      expect(text).not.toContain('.nuget');
    }
  });
});

describe('AC-P20-5 / AC-P20-6 / AC-P20-7: project files, CPM, packages.config', () => {
  it('AC-P20-5 / D-155: Choose/When/Otherwise ItemGroups are read, Target ItemGroups are not; Update/Remove ignored', () => {
    const deps = runCase('project-cpm').dependencies.filter((d) => d.manifest_path === 'src/A');
    const names = deps.map((d) => d.name);
    expect(names).toEqual(expect.arrayContaining(['When.Pkg', 'Otherwise.Pkg', 'Lower.Case.Item']));
    expect(names).not.toContain('Target.Pkg');
    expect(deps.find((d) => d.name === 'Foo')).toMatchObject({ version: '1.0.0', manifest_file: 'A.csproj' }); // not Update's 5.5.5
    expect(deps.find((d) => d.name === 'Bar')).toMatchObject({ version: '2.5.0', declared_range: '2.5.0' }); // VersionOverride child
    expect(deps.find((d) => d.name === 'Otherwise.Pkg')).toMatchObject({ version: '2.0.0', declared_range: '2.0.0.0' });
    expect(deps.every((d) => d.scope === 'direct')).toBe(true);
  });

  it('AC-P20-6: nearest Directory.Packages.props wins; GlobalPackageReference added for project-file folders only', () => {
    const r = runCase('project-cpm');
    expect(r.dependencies.find((d) => d.manifest_path === 'src/B')).toMatchObject({ name: 'Foo', version: '9.0.0' });
    expect(r.dependencies.filter((d) => d.name === 'Global.Analyzers').map((d) => d.manifest_path)).toEqual(['src/A']);
    const sample = parseDotnet(SAMPLE_SOLUTION, 's');
    expect(sample.dependencies.filter((d) => d.name === 'Nerdbank.GitVersioning').map((d) => d.manifest_path)).toEqual(['src/Tools']);
    expect(sample.dependencies.find((d) => d.manifest_path === 'src/Tools' && d.name === 'Serilog')?.version).toBe('3.0.1'); // VersionOverride > table
  });

  it('AC-P20-6: the CPM walk stops at the scan root (a props file above the root is never used)', () => {
    const r = parseDotnet(path.join(DOTNET_FIXTURES, 'cpm-boundary', 'repo'), 's');
    expect(r.dependencies).toEqual([
      expect.objectContaining({ name: 'Outside.Root', version: null, declared_range: null, manifest_path: 'app' }),
    ]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['app/app.csproj']);
  });

  it('AC-P20-8 / D-126: $(…) is never evaluated (property defined in the same file stays unknown)', () => {
    const humanizer = parseDotnet(SAMPLE_SOLUTION, 's').dependencies.find((d) => d.name === 'Humanizer');
    expect(humanizer).toMatchObject({ version: null, declared_range: '$(LibVersion)', purl: 'pkg:nuget/Humanizer' });
  });

  it('AC-P20-7 / D-127: no dev scope anywhere (developmentDependency, packages.config, test-like names)', () => {
    for (const r of [...NUGET_GOLDEN_CASES.map(runCase), parseDotnet(SAMPLE_SOLUTION, 's')]) {
      for (const d of r.dependencies) expect(d.scope).not.toBe('dev');
    }
    expect(runCase('packages-config').dependencies.find((d) => d.name === 'Dev.Tool')).toMatchObject({ scope: 'direct', version: '1.0.0' });
  });
});

describe('AC-P20-14: dependency limit per project folder', () => {
  const lockWith = (n: number) => {
    const entries: Record<string, unknown> = {};
    for (let i = 0; i < n; i++) entries[`P${i}`] = { type: 'Transitive', resolved: '1.0.0' };
    return JSON.stringify({ version: 2, dependencies: { 'net8.0': entries } });
  };
  const proj = '<Project><ItemGroup><PackageReference Include="Fallback" Version="1.0.0" /></ItemGroup></Project>';

  it('AC-P20-14: 20 000 entries are accepted; 20 001 make the lock a file error and the next source is used', () => {
    const ok = parseDotnet(tmpTree('limit-ok', { 'packages.lock.json': lockWith(20_000) }), 's');
    expect(ok.dependencies).toHaveLength(20_000);
    expect(ok.parse_errors).toEqual([]);
    const over = parseDotnet(tmpTree('limit-over', { 'packages.lock.json': lockWith(20_001), 'a.csproj': proj }), 's');
    expect(over.parse_errors).toEqual([{ ecosystem: 'dotnet', file: 'packages.lock.json', error: NUGET_MESSAGES.limit }]);
    expect(over.dependencies.map((d) => d.name)).toEqual(['Fallback']);
  });
});

describe('REQ-006 security review L-1: total .NET dependency limit per scan (100 000)', () => {
  const HASH = `${'ABCDEFGHIJ'.repeat(8)}KLMNOP==`;
  // One 20 000-entry lock body shared by every folder (same ids per folder are fine: dedupe is per folder).
  let lock20k = '';
  const lock = () => {
    if (!lock20k) {
      const entries: Record<string, unknown> = {};
      for (let i = 0; i < NUGET_MAX_DEPENDENCIES_PER_FOLDER; i++) entries[`P${i}`] = { type: 'Transitive', resolved: '1.0.0', contentHash: HASH };
      lock20k = JSON.stringify({ version: 2, dependencies: { 'net8.0': entries } });
    }
    return lock20k;
  };

  it('L-1: limit constants (20 000 per folder, 100 000 per scan) and a fixed, path-free message', () => {
    expect(NUGET_MAX_DEPENDENCIES_PER_FOLDER).toBe(20_000);
    expect(NUGET_MAX_DEPENDENCIES_PER_SCAN).toBe(100_000);
    expect(NUGET_MESSAGES.scanLimit).toBe('Tarama .NET bağımlılık sınırını aşıyor (100 000); kalan proje klasörleri atlandı.');
  });

  it('L-1: 6 folders x 20 000 lock entries -> exactly 100 000 records, one file:"" record, the 6th folder has no scan_files or hashes', () => {
    const files: Record<string, string> = {};
    for (let i = 1; i <= 6; i++) files[`d${i}/packages.lock.json`] = lock();
    const root = tmpTree('scan-limit-locks', files);
    const collector = new IntegrityCollector();
    const r = parseManifests(root, ['dotnet'], 's', { integrityCollector: collector });

    expect(r.dependencies).toHaveLength(NUGET_MAX_DEPENDENCIES_PER_SCAN);
    expect(r.total_deps).toBe(NUGET_MAX_DEPENDENCIES_PER_SCAN);
    expect(r.parse_errors).toEqual([{ ecosystem: 'dotnet', file: '', error: NUGET_MESSAGES.scanLimit }]);
    const perFolder = new Map<string, number>();
    for (const d of r.dependencies) perFolder.set(d.manifest_path, (perFolder.get(d.manifest_path) ?? 0) + 1);
    expect([...perFolder]).toEqual([['d1', 20_000], ['d2', 20_000], ['d3', 20_000], ['d4', 20_000], ['d5', 20_000]]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['d1/packages.lock.json', 'd2/packages.lock.json', 'd3/packages.lock.json', 'd4/packages.lock.json', 'd5/packages.lock.json']);
    expect(collector.nugetRecords).toHaveLength(NUGET_MAX_DEPENDENCIES_PER_SCAN);
    expect(collector.nugetRecords.some((x) => x.manifestPath === 'd6')).toBe(false);
  });

  it('L-1: exactly 100 000 is accepted; a project-file folder over the limit keeps its file-level records but adds no scan_files, and later folders are skipped', () => {
    const files: Record<string, string> = {};
    for (let i = 1; i <= 5; i++) files[`d${i}/packages.lock.json`] = lock();
    // e: one valid reference and one invalid id (file-level issue record stays); f: never read (after the cap).
    files['e/e.csproj'] = '<Project><ItemGroup><PackageReference Include="Over.Cap" Version="1.0.0" /><PackageReference Include="Bad Id" Version="1.0.0" /></ItemGroup></Project>';
    files['f/packages.lock.json'] = '{';
    const r = parseDotnet(tmpTree('scan-limit-project', files), 's');

    expect(r.dependencies).toHaveLength(NUGET_MAX_DEPENDENCIES_PER_SCAN);
    expect(r.dependencies.some((d) => d.name === 'Over.Cap' || d.manifest_path === 'e' || d.manifest_path === 'f')).toBe(false);
    expect(r.scan_files.map((f) => f.file_path)).not.toContain('e/e.csproj');
    expect(r.scan_files).toHaveLength(5);
    expect(r.parse_errors).toEqual([
      { ecosystem: 'dotnet', file: 'e/e.csproj', error: NUGET_MESSAGES.invalidId },
      { ecosystem: 'dotnet', file: '', error: NUGET_MESSAGES.scanLimit },
    ]);
  });

  it('L-1: 100 000 records in five folders -> no scan limit record (boundary is inclusive)', () => {
    const files: Record<string, string> = {};
    for (let i = 1; i <= 5; i++) files[`d${i}/packages.lock.json`] = lock();
    const r = parseDotnet(tmpTree('scan-limit-boundary', files), 's');
    expect(r.dependencies).toHaveLength(NUGET_MAX_DEPENDENCIES_PER_SCAN);
    expect(r.parse_errors).toEqual([]);
  });
});

describe('REQ-006 security review I-8: "__proto__" / "constructor" keys in .NET lock and assets files', () => {
  const HASH = `${'ABCDEFGHIJ'.repeat(8)}KLMNOP==`;
  // Raw JSON text: JSON.parse makes "__proto__" an own data property (never the prototype setter).
  const lockText =
    '{"version":2,"dependencies":{' +
    '"__proto__":{"Tfm.Proto.Pkg":{"type":"Direct","requested":"[1.0.0, )","resolved":"1.0.0"}},' +
    '"net8.0":{' +
    `"__proto__":{"type":"Direct","requested":"[1.0.0, )","resolved":"1.0.0","contentHash":"${HASH}","polluted":"yes"},` +
    '"constructor":{"type":"Transitive","resolved":"2.0.0"},' +
    '"hasOwnProperty":{"type":"Transitive","resolved":"3.0.0"},' +
    '"Good.Pkg":{"type":"Direct","requested":"[4.0.0, )","resolved":"4.0.0"}}}}';
  const assetsText =
    '{"version":3,"libraries":{' +
    `"__proto__/1.0.0":{"type":"package","sha512":"${HASH}"},` +
    '"constructor/2.0.0":{"type":"package"},' +
    '"__proto__":{"type":"package"},' +
    '"Good.Pkg/4.0.0":{"type":"package"}},' +
    '"project":{"frameworks":{"__proto__":{"dependencies":{"__proto__":{"version":"[1.0.0, )"}}},' +
    '"net8.0":{"dependencies":{"Good.Pkg":{"version":"[4.0.0, )"},"constructor":{"version":"[2.0.0, )"}}}}}}';

  const clean = () => {
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(false);
    expect(typeof ({} as { hasOwnProperty: unknown }).hasOwnProperty).toBe('function');
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
  };

  it('I-8: lock — "__proto__"/"constructor"/"hasOwnProperty" ids and a "__proto__" TFM key are ordinary keys; no prototype is touched', () => {
    const collector = new IntegrityCollector();
    const r = parseManifests(tmpTree('proto-lock', { 'packages.lock.json': lockText }), ['dotnet'], 's', { integrityCollector: collector });
    clean();
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies.map((d) => [d.name, d.version, d.scope, d.declared_range])).toEqual([
      ['__proto__', '1.0.0', 'direct', '[1.0.0, )'],
      ['constructor', '2.0.0', 'transitive', null],
      ['Good.Pkg', '4.0.0', 'direct', '[4.0.0, )'],
      ['hasOwnProperty', '3.0.0', 'transitive', null],
      ['Tfm.Proto.Pkg', '1.0.0', 'direct', '[1.0.0, )'],
    ]);
    for (const d of r.dependencies) {
      expect(Object.getPrototypeOf(d)).toBe(Object.prototype);
      expect(Object.keys(d)).toEqual(['ecosystem', 'name', 'version', 'purl', 'scope', 'licenses', 'manifest_file', 'manifest_path', 'declared_range']);
    }
    expect(r.dependencies.find((d) => d.name === '__proto__')?.purl).toBe('pkg:nuget/__proto__@1.0.0');
    expect(JSON.stringify(r)).not.toContain('polluted');
    expect(collector.nugetRecords).toEqual([{ manifestPath: '.', name: '__proto__', version: '1.0.0', integrity: `sha512-${HASH}` }]);
  });

  it('I-8: assets — "__proto__/1.0.0" and "constructor/2.0.0" libraries and "__proto__" framework/dependency keys are ordinary keys', () => {
    const collector = new IntegrityCollector();
    const r = parseManifests(tmpTree('proto-assets', { 'obj/project.assets.json': assetsText }), ['dotnet'], 's', { integrityCollector: collector });
    clean();
    expect(r.dependencies.map((d) => [d.name, d.version, d.scope, d.declared_range, d.manifest_file])).toEqual([
      ['__proto__', '1.0.0', 'direct', '[1.0.0, )', 'project.assets.json'],
      ['constructor', '2.0.0', 'direct', '[2.0.0, )', 'project.assets.json'],
      ['Good.Pkg', '4.0.0', 'direct', '[4.0.0, )', 'project.assets.json'],
    ]);
    // "__proto__" without a "/version" part is an invalid entry (one fixed-text record).
    expect(r.parse_errors).toEqual([{ ecosystem: 'dotnet', file: 'obj/project.assets.json', error: NUGET_MESSAGES.invalidEntry }]);
    expect(collector.nugetRecords).toEqual([{ manifestPath: '.', name: '__proto__', version: '1.0.0', integrity: `sha512-${HASH}` }]);
  });
});

describe('AC-P20-15: error texts', () => {
  it('AC-P20-15: every dotnet error is a fixed text without paths, document content or package names', () => {
    const fixed = new Set<string>([...Object.values(NUGET_MESSAGES), LINK_NOT_FOLLOWED_MESSAGE]);
    for (const name of NUGET_GOLDEN_CASES) {
      for (const e of runCase(name).parse_errors) {
        expect(fixed.has(e.error), `${name}: ${e.error}`).toBe(true);
        expect(path.isAbsolute(e.file)).toBe(false);
        for (const leak of ['Secret', 'Xxe', 'Unclosed', 'Wrong.Root', 'Entity.User', 'fixtureuser', 'Bad Id', 'Weird.Kind']) {
          expect(e.error).not.toContain(leak);
        }
      }
    }
  });
});

describe('AC-P20-16: integrity side channel from the parsers', () => {
  it('AC-P20-16: lock contentHash and assets sha512 go to the collector as sha512-<base64>; never into the result', () => {
    const collector = new IntegrityCollector();
    const r = parseManifests(SAMPLE_SOLUTION, ['dotnet'], 's', { integrityCollector: collector });
    expect(collector.records).toEqual([]);
    const byKey = new Map(collector.nugetRecords.map((x) => [`${x.manifestPath}|${x.name}|${x.version}`, x.integrity]));
    expect(byKey.get('src/App|Newtonsoft.Json|13.0.3')).toBe(`sha512-ABCDEFGHIJ${'ABCDEFGHIJ'.repeat(7)}KLMNOP==`);
    expect(byKey.get('src/Lib|Serilog.Sinks.Console|5.0.1')?.startsWith('sha512-HBCDEFGHIJ')).toBe(true);
    expect(collector.nugetRecords.length).toBe(new Set(byKey.keys()).size); // multi-TFM duplicates collapsed
    expect(JSON.stringify(r)).not.toContain('BCDEFGHIJ');
    expect(JSON.stringify(r)).not.toContain('sha512');
    expect(JSON.stringify(r)).toBe(JSON.stringify(parseManifests(SAMPLE_SOLUTION, ['dotnet'], 's')));
  });

  it('AC-P20-16: an invalid contentHash is dropped (lock-v2 has one valid and one invalid value)', () => {
    const collector = new IntegrityCollector();
    parseManifests(caseDir('lock-v2'), ['dotnet'], 's', { integrityCollector: collector });
    expect(collector.nugetRecords.map((x) => x.name)).toEqual(['Contoso.Core']);
  });
});
