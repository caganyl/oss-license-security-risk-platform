/**
 * REQ-011 phase 1 core: walker manifest specs (D-304), parser kit
 * (AC-P40-3, AC-P40-5, AC-P40-6), parser registry and stubs (D-315), purl
 * builders (AC-P42-1).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import {
  FILE_TOO_LARGE_MESSAGE,
  LINK_NOT_FOLLOWED_MESSAGE,
  MANIFEST_SPECS,
  MAX_MANIFEST_BYTES,
  NEW_ECOSYSTEM_IGNORED_DIRS,
  SKIP_DIRS,
  walkTree,
  type TreeWalk,
} from '../../src/scanner/parsers/common';
import {
  KIT_ECOSYSTEMS,
  KIT_MAX_DEPENDENCIES_PER_FOLDER,
  KIT_MAX_DEPENDENCIES_PER_SCAN,
  KitScanBudget,
  PARSER_MESSAGES,
  ParserContext,
  ParserFileError,
  type DependencyEntry,
  type KitEcosystem,
} from '../../src/scanner/parsers/kit';
import {
  cargoPurl,
  composerPurl,
  gemPurl,
  golangPurl,
  mavenPurl,
  pubPurl,
  purlFor,
  swiftPackageIdentity,
  swiftPurl,
} from '../../src/scanner/parsers/purl';
import { KIT_PARSERS, PARSER_REGISTRY, parserFor } from '../../src/scanner/parsers/registry';
import { parseTomlText } from '../../src/scanner/parsers/toml';
import { parseXml } from '../../src/scanner/parsers/xmlReader';
import { parseYamlSubset } from '../../src/scanner/parsers/yamlSubset';
import { SCAN_ECOSYSTEMS } from '../../src/types/scan';
import { sandboxRunnerConfig } from '../../src/scanner/sandbox/runner.config';
import { FORMATS_DIR } from '../helpers/parserGolden';

let tmpBase = '';
beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-req011-'));
});
afterAll(() => {
  if (tmpBase) fs.rmSync(tmpBase, { recursive: true, force: true });
});
let counter = 0;
function tree(files: Record<string, string | Buffer>): string {
  const root = path.join(tmpBase, `t${++counter}`);
  fs.mkdirSync(root, { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

function specFiles(walk: TreeWalk, ecosystem: Parameters<NonNullable<TreeWalk['specByDir']>['get']>[0]): string[] {
  const byDir = walk.specByDir?.get(ecosystem);
  if (!byDir) return [];
  return [...byDir.values()].flatMap((files) => [...files.values()].map((f) => f.relPath)).sort();
}

// ---------------------------------------------------------------------------
describe('D-307: supported ecosystems and registry', () => {
  it('SCAN_ECOSYSTEMS order is nodejs, python, dotnet, java, go, php, rust, ruby, dart, swift and is the default stack', () => {
    expect([...SCAN_ECOSYSTEMS]).toEqual(['nodejs', 'python', 'dotnet', 'java', 'go', 'php', 'rust', 'ruby', 'dart', 'swift']);
    expect(sandboxRunnerConfig.scan.supportedEcosystems).toEqual([...SCAN_ECOSYSTEMS]);
  });

  it('every supported ecosystem has a parser; unknown values (container, other, __proto__) have none', () => {
    expect(Object.keys(PARSER_REGISTRY).sort()).toEqual([...SCAN_ECOSYSTEMS].sort());
    for (const eco of SCAN_ECOSYSTEMS) expect(parserFor(eco), eco).toBeTypeOf('function');
    for (const eco of ['container', 'other', '__proto__', 'constructor', 'JAVA']) expect(parserFor(eco), eco).toBeUndefined();
    expect(Object.keys(KIT_PARSERS).sort()).toEqual([...KIT_ECOSYSTEMS].sort());
  });

  // Phase 2 filled the parsers, so "stubs return nothing" became an invariant every parser must keep:
  // degenerate files never crash, never yield a package, and only produce fixed error texts.
  it('degenerate manifests of every new ecosystem: no crash, no dependency, only fixed parse_errors texts', () => {
    const root = tree({
      'gradle.lockfile': 'x',
      'pom.xml': '<project/>',
      'go.mod': 'module x',
      'composer.lock': '{}',
      'Cargo.lock': '',
      'Gemfile.lock': '',
      'pubspec.lock': '',
      'Package.resolved': '{}',
    });
    const r = parseManifests(root, ['java', 'go', 'php', 'rust', 'ruby', 'dart', 'swift'], 'stub');
    expect(r.status).toBe('completed');
    expect(r.dependencies).toEqual([]);
    const fixed = new Set<string>(Object.values(PARSER_MESSAGES));
    for (const e of r.parse_errors) expect(fixed.has(e.error), e.error).toBe(true);
  });

  it('AC-G-1: the npm/PyPI/.NET result of a fixture is identical whether or not the new ecosystems are requested', () => {
    for (const fixture of ['npm-lock-v2', 'py-poetry-project-and-lock']) {
      const root = path.join(FORMATS_DIR, fixture);
      const before = parseManifests(root, ['nodejs', 'python', 'dotnet'], 'same');
      const after = parseManifests(root, [...SCAN_ECOSYSTEMS], 'same');
      expect(after, fixture).toEqual(before);
    }
  });
});

// ---------------------------------------------------------------------------
describe('D-304: walker manifest specs', () => {
  const files = {
    'package.json': '{}',
    'requirements.txt': 'a==1\n',
    'requirements-prod.txt': 'b==1\n',
    'requirements_ci.txt': 'c==1\n',
    'Pipfile.lock': '{}',
    'pnpm-lock.yaml': 'lockfileVersion: 9.0\n',
    'svc/go.mod': 'module x\n',
    'svc/vendor/github.com/a/b/go.mod': 'module y\n',
    'app/pom.xml': '<project/>',
    'app/target/classes/pom.xml': '<project/>',
    'app/.gradle/x/gradle.lockfile': '',
    'web/composer.json': '{}',
    'web/vendor/acme/lib/composer.json': '{}',
    'mobile/pubspec.lock': '',
    'mobile/.dart_tool/pubspec.lock': '',
    'ios/Package.resolved': '{}',
    'ios/.build/checkouts/x/Package.resolved': '{}',
    'ios/Pods/Package.resolved': '{}',
    'node_modules/x/go.mod': 'module z\n',
    'GO.MOD': 'module upper\n',
  };

  it('without requested spec ecosystems the walk has no spec maps and byDir is unchanged', () => {
    const root = tree(files);
    const plain = walkTree(root);
    const withSpecs = walkTree(root, { ecosystems: [...SCAN_ECOSYSTEMS] });
    expect(plain.specByDir).toBeUndefined();
    expect(plain.specLinks).toBeUndefined();
    expect(withSpecs.byDir).toEqual(plain.byDir);
    expect(withSpecs.fileLinks).toEqual(plain.fileLinks);
    expect(withSpecs.errors).toEqual(plain.errors);
    expect(walkTree(root, { ecosystems: ['dotnet', 'container'] }).specByDir).toBeUndefined();
  });

  it('collects exact names per requested ecosystem only, ignores vendor/build folders of the new ecosystems and never takes byDir names', () => {
    const root = tree(files);
    const walk = walkTree(root, { ecosystems: ['nodejs', 'python', 'java', 'go', 'php', 'dart', 'swift'] });
    expect(specFiles(walk, 'go')).toEqual(['svc/go.mod']);
    expect(specFiles(walk, 'java')).toEqual(['app/pom.xml']);
    expect(specFiles(walk, 'php')).toEqual(['web/composer.json']);
    expect(specFiles(walk, 'dart')).toEqual(['mobile/pubspec.lock']);
    expect(specFiles(walk, 'swift')).toEqual(['ios/Package.resolved']);
    expect(specFiles(walk, 'nodejs')).toEqual(['pnpm-lock.yaml']);
    // requirements.txt stays in byDir (F4 golden); the pattern adds the other requirements*.txt files.
    expect(specFiles(walk, 'python')).toEqual(['Pipfile.lock', 'requirements-prod.txt', 'requirements_ci.txt']);
    expect(walk.byDir.get('')?.has('requirements.txt')).toBe(true);
    expect(walk.specByDir?.has('rust')).toBe(false);
    expect(walk.specByDir?.has('ruby')).toBe(false);
  });

  it('spec sets: every new ecosystem ignores the same build folders; SKIP_DIRS is unchanged', () => {
    expect([...NEW_ECOSYSTEM_IGNORED_DIRS].sort()).toEqual(['.build', '.dart_tool', '.gradle', 'Pods', 'target', 'vendor']);
    for (const eco of KIT_ECOSYSTEMS) expect(MANIFEST_SPECS[eco].ignoredDirs, eco).toBe(NEW_ECOSYSTEM_IGNORED_DIRS);
    expect(MANIFEST_SPECS.nodejs.ignoredDirs.size).toBe(0);
    expect(SKIP_DIRS.has('vendor')).toBe(false);
    expect(MANIFEST_SPECS.java.names).toEqual(['gradle.lockfile', 'pom.xml', 'build.gradle', 'build.gradle.kts']);
    expect(MANIFEST_SPECS.go.names).toEqual(['go.mod']);
    expect(MANIFEST_SPECS.php.names).toEqual(['composer.lock', 'composer.json']);
    expect(MANIFEST_SPECS.rust.names).toEqual(['Cargo.lock', 'Cargo.toml']);
    expect(MANIFEST_SPECS.ruby.names).toEqual(['Gemfile.lock']);
    expect(MANIFEST_SPECS.dart.names).toEqual(['pubspec.lock']);
    expect(MANIFEST_SPECS.swift.names).toEqual(['Package.resolved']);
  });

  it('links with a spec name become "link not followed" records of that ecosystem (not filesystem records)', () => {
    const root = tree({ 'real/go.mod': 'module x\n', 'real/Cargo.lock': '' });
    let linked = true;
    try {
      fs.symlinkSync(path.join(root, 'real', 'go.mod'), path.join(root, 'go.mod'), 'file');
      fs.symlinkSync(path.join(root, 'real', 'Cargo.lock'), path.join(root, 'Cargo.lock'), 'file');
    } catch {
      linked = false; // Windows without symlink privilege
    }
    if (!linked) return;
    const r = parseManifests(root, ['go'], 'links');
    // A link with the requested ecosystem's name is that ecosystem's record; a link named after a
    // non-requested ecosystem (Cargo.lock) stays a generic filesystem record, as for any other name.
    expect(r.parse_errors.map((e) => [e.ecosystem, e.file, e.error]).sort()).toEqual([
      ['filesystem', 'Cargo.lock', LINK_NOT_FOLLOWED_MESSAGE],
      ['go', 'go.mod', LINK_NOT_FOLLOWED_MESSAGE],
    ]);
    const none = parseManifests(root, ['nodejs'], 'links');
    expect(none.parse_errors.map((e) => [e.ecosystem, e.file]).sort()).toEqual([
      ['filesystem', 'Cargo.lock'],
      ['filesystem', 'go.mod'],
    ]);
  });
});

// ---------------------------------------------------------------------------
describe('Parser kit (AC-P40-3, AC-P40-5, AC-P40-6)', () => {
  function context(files: Record<string, string | Buffer>, ecosystem: KitEcosystem = 'go', budget?: KitScanBudget): ParserContext {
    const root = tree(files);
    return new ParserContext(walkTree(root, { ecosystems: [ecosystem] }), ecosystem, budget);
  }
  const entry = (name: string, version: string | null, extra: Partial<DependencyEntry> = {}): DependencyEntry => ({
    name,
    version,
    scope: 'direct',
    manifestFile: 'go.mod',
    ...extra,
  });

  it('folders are sorted by manifest path; commit adds records with ecosystem, manifest path, purl and sorted output', () => {
    const ctx = context({ 'b/go.mod': 'module b\n', 'go.mod': 'module root\n', 'a/go.mod': 'module a\n' });
    const folders = ctx.folders();
    expect(folders.map((f) => f.manifestPath)).toEqual(['.', 'a', 'b']);
    for (const folder of [...folders].reverse()) {
      const read = ctx.read(folder.files.get('go.mod')!, (input) => input.text());
      expect(read).not.toBeNull();
      expect(
        ctx.commit(folder, read!.record, [
          entry('github.com/Z/z', 'v1.0.0'),
          entry('github.com/a/a', null, { declaredRange: 'latest\u0007', scope: 'transitive' }),
          entry('github.com/a/a', null), // duplicate (same lower name and version) dropped
        ]),
      ).toBe(true);
    }
    const r = ctx.finish();
    expect(r.parse_errors).toEqual([]);
    expect(r.scan_files.map((f) => [f.file_path, f.ecosystem, f.filename])).toEqual([
      ['a/go.mod', 'go', 'go.mod'],
      ['b/go.mod', 'go', 'go.mod'],
      ['go.mod', 'go', 'go.mod'],
    ]);
    expect(r.dependencies.slice(0, 2)).toEqual([
      {
        ecosystem: 'go',
        name: 'github.com/a/a',
        version: null,
        purl: 'pkg:golang/github.com/a/a',
        scope: 'transitive',
        licenses: [],
        manifest_file: 'go.mod',
        manifest_path: '.',
        declared_range: 'latest',
      },
      {
        ecosystem: 'go',
        name: 'github.com/Z/z',
        version: 'v1.0.0',
        purl: 'pkg:golang/github.com/Z/z@v1.0.0',
        scope: 'direct',
        licenses: [],
        manifest_file: 'go.mod',
        manifest_path: '.',
        declared_range: null,
      },
    ]);
    expect(r.dependencies.map((d) => d.manifest_path)).toEqual(['.', '.', 'a', 'a', 'b', 'b']);
  });

  it('invalid entries are skipped with one fixed record per source file; a read that is not committed adds no scan file', () => {
    const ctx = context({ 'pom.xml': '<project/>', 'build.gradle': '' }, 'java');
    const [folder] = ctx.folders();
    const pom = ctx.read(folder.files.get('pom.xml')!, () => 1)!;
    ctx.read(folder.files.get('build.gradle')!, () => 1);
    const bad = (name: string, version: string | null) => entry(name, version, { manifestFile: 'pom.xml' });
    expect(ctx.commit(folder, pom.record, [bad('no-colon', '1'), bad('', '1'), bad('g:a', 'a b'), bad('g:a\u0000', '1'), bad('g:a', '1.0')])).toBe(true);
    const r = ctx.finish();
    expect(r.parse_errors).toEqual([{ ecosystem: 'java', file: 'pom.xml', error: PARSER_MESSAGES.invalidEntry }]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['pom.xml']);
    expect(r.dependencies.map((d) => d.purl)).toEqual(['pkg:maven/g/a@1.0']);
  });

  it('read errors become one fixed, path-free record per file and parsing continues (JSON, TOML, YAML, XML, UTF-8, size, ParserFileError, unexpected)', () => {
    const cases: Array<{ dir: string; bytes: string | Buffer; parse: (text: () => string) => unknown; error: string | null }> = [
      { dir: 'a', bytes: '{"packages": [', parse: (text) => JSON.parse(text()), error: PARSER_MESSAGES.json },
      { dir: 'b', bytes: '{}', parse: () => parseTomlText('a = '), error: PARSER_MESSAGES.toml },
      { dir: 'c', bytes: Buffer.from([0x7b, 0xff, 0x7d]), parse: (text) => text(), error: 'Dosya geçerli UTF-8 değil.' },
      { dir: 'd', bytes: '{}', parse: () => parseYamlSubset('a: &x 1\n'), error: PARSER_MESSAGES.yamlUnsupported },
      { dir: 'e', bytes: '{}', parse: () => parseXml(Buffer.from('<!DOCTYPE x><x/>')), error: PARSER_MESSAGES.xmlDoctype },
      { dir: 'f', bytes: '{}', parse: () => parseYamlSubset('a: [\n'), error: PARSER_MESSAGES.yaml },
      {
        dir: 'g',
        bytes: '{}',
        parse: () => {
          throw new ParserFileError(PARSER_MESSAGES.unsupportedVersion);
        },
        error: PARSER_MESSAGES.unsupportedVersion,
      },
      {
        dir: 'h',
        bytes: '{}',
        parse: () => {
          throw new Error(`boom ${tmpBase}`);
        },
        error: PARSER_MESSAGES.structure,
      },
      { dir: 'i', bytes: '{}', parse: () => 'size checked first', error: FILE_TOO_LARGE_MESSAGE },
      { dir: 'j', bytes: '{}', parse: (text) => text(), error: null },
    ];
    const ctx = context(Object.fromEntries(cases.map((c) => [`${c.dir}/composer.lock`, c.bytes])), 'php');
    const folders = ctx.folders();
    expect(folders.map((f) => f.manifestPath)).toEqual(cases.map((c) => c.dir));
    folders.forEach((folder, i) => {
      const file = folder.files.get('composer.lock')!;
      if (cases[i].dir === 'i') Object.assign(file, { size: MAX_MANIFEST_BYTES + 1 });
      const read = ctx.read(file, (input) => cases[i].parse(() => input.text()));
      expect(read === null, cases[i].dir).toBe(cases[i].error !== null);
    });
    const errors = ctx.finish().parse_errors;
    expect(errors).toEqual(cases.filter((c) => c.error !== null).map((c) => ({ ecosystem: 'php', file: `${c.dir}/composer.lock`, error: c.error })));
    for (const rec of errors) expect(rec.error).not.toContain(tmpBase);
  });
  it('folder limit: over 20 000 records the folder is refused with one record on the source', () => {
    const ctx = context({ 'go.mod': 'module x\n' });
    const [folder] = ctx.folders();
    const read = ctx.read(folder.files.get('go.mod')!, () => null)!;
    const many = Array.from({ length: KIT_MAX_DEPENDENCIES_PER_FOLDER + 1 }, (_, i) => entry(`example.com/m${i}`, 'v1.0.0'));
    expect(ctx.commit(folder, read.record, many)).toBe(false);
    expect(ctx.commit(folder, read.record, many.slice(0, KIT_MAX_DEPENDENCIES_PER_FOLDER))).toBe(true);
    const r = ctx.finish();
    expect(r.parse_errors).toEqual([{ ecosystem: 'go', file: 'go.mod', error: PARSER_MESSAGES.limit }]);
    expect(r.dependencies).toHaveLength(KIT_MAX_DEPENDENCIES_PER_FOLDER);
  });

  it('scan limit: shared by every kit ecosystem of one parse; one record with an empty file per ecosystem, later commits refused', () => {
    const budget = new KitScanBudget();
    budget.total = KIT_MAX_DEPENDENCIES_PER_SCAN - 1;
    const go = context({ 'go.mod': 'module x\n' }, 'go', budget);
    const [folder] = go.folders();
    const read = go.read(folder.files.get('go.mod')!, () => null)!;
    expect(go.commit(folder, read.record, [entry('example.com/a', 'v1.0.0')])).toBe(true);
    expect(go.commit(folder, read.record, [entry('example.com/b', 'v1.0.0')])).toBe(false);
    expect(go.capped).toBe(true);
    expect(go.commit(folder, read.record, [entry('example.com/c', 'v1.0.0')])).toBe(false);
    const rust = context({ 'Cargo.lock': '' }, 'rust', budget);
    const [rf] = rust.folders();
    const rr = rust.read(rf.files.get('Cargo.lock')!, () => null)!;
    expect(rust.commit(rf, rr.record, [entry('serde', '1.0.0', { manifestFile: 'Cargo.lock' })])).toBe(false);
    expect(go.finish().parse_errors).toEqual([{ ecosystem: 'go', file: '', error: PARSER_MESSAGES.scanLimit }]);
    expect(rust.finish()).toEqual({ dependencies: [], scan_files: [], parse_errors: [{ ecosystem: 'rust', file: '', error: PARSER_MESSAGES.scanLimit }] });
  });

  it('licenses are copied (AC-P40-7 shape) and a BOM is dropped by text()', () => {
    const ctx = context({ 'composer.lock': '﻿{"x":1}' }, 'php');
    const [folder] = ctx.folders();
    const read = ctx.read(folder.files.get('composer.lock')!, (input) => JSON.parse(input.text()))!;
    expect(read.value).toEqual({ x: 1 });
    const licenses = ['MIT OR Apache-2.0'];
    ctx.commit(folder, read.record, [{ name: 'Acme/Lib', version: '1.0.0', scope: 'direct', manifestFile: 'composer.lock', licenses }]);
    const [dep] = ctx.finish().dependencies;
    expect(dep.licenses).toEqual(['MIT OR Apache-2.0']);
    expect(dep.licenses).not.toBe(licenses);
    expect(dep.purl).toBe('pkg:composer/acme/lib@1.0.0');
  });
});

// ---------------------------------------------------------------------------
describe('AC-P42-1: purl builders (purl-spec types)', () => {
  it('maven, golang, composer, cargo, gem, pub, swift', () => {
    expect(mavenPurl('org.apache.commons:commons-lang3', '3.12.0')).toBe('pkg:maven/org.apache.commons/commons-lang3@3.12.0');
    expect(mavenPurl('com.Example:Lib', null)).toBe('pkg:maven/com.Example/Lib');
    expect(golangPurl('github.com/Azure/go-autorest', 'v0.11.29+incompatible')).toBe('pkg:golang/github.com/Azure/go-autorest@v0.11.29%2Bincompatible');
    expect(golangPurl('golang.org/x/net', 'v0.0.0-20230101000000-abcdef123456')).toBe('pkg:golang/golang.org/x/net@v0.0.0-20230101000000-abcdef123456');
    expect(composerPurl('Symfony/Console', 'v6.4.1')).toBe('pkg:composer/symfony/console@v6.4.1');
    expect(cargoPurl('serde_json', '1.0.108')).toBe('pkg:cargo/serde_json@1.0.108');
    expect(gemPurl('rails', '7.1.2')).toBe('pkg:gem/rails@7.1.2');
    expect(pubPurl('Flutter_Bloc', '8.1.3')).toBe('pkg:pub/flutter_bloc@8.1.3');
    expect(swiftPurl('github.com/apple/swift-nio', '2.62.0')).toBe('pkg:swift/github.com/apple/swift-nio@2.62.0');
    expect(swiftPurl('gitlab.com/group/sub/repo', null)).toBe('pkg:swift/gitlab.com/group/sub/repo');
  });

  it('encodes special characters per segment and rejects names of the wrong shape', () => {
    expect(mavenPurl('g:a b', '1')).toBe('pkg:maven/g/a%20b@1');
    expect(cargoPurl('a@b', '1')).toBe('pkg:cargo/a%40b@1');
    for (const bad of [() => mavenPurl('noversion', '1'), () => mavenPurl('a:b:c', '1'), () => mavenPurl(':a', '1')]) expect(bad).toThrow();
    expect(() => composerPurl('single', '1')).toThrow();
    expect(() => composerPurl('a/b/c', '1')).toThrow();
    expect(() => golangPurl('a//b', '1')).toThrow();
    expect(() => swiftPurl('github.com/apple', '1')).toThrow();
    expect(() => cargoPurl('a/b', '1')).toThrow();
  });

  it('purlFor dispatches every supported ecosystem (npm/PyPI/NuGet unchanged)', () => {
    expect(purlFor('nodejs', '@scope/x', '1.0.0')).toBe('pkg:npm/@scope/x@1.0.0');
    expect(purlFor('python', 'Foo_Bar', '1.0')).toBe('pkg:pypi/foo-bar@1.0');
    expect(purlFor('dotnet', 'Newtonsoft.Json', '13.0.1')).toBe('pkg:nuget/Newtonsoft.Json@13.0.1');
    expect(purlFor('java', 'g:a', '1')).toBe('pkg:maven/g/a@1');
    expect(purlFor('go', 'example.com/m', 'v1.0.0')).toBe('pkg:golang/example.com/m@v1.0.0');
    expect(purlFor('php', 'a/b', '1')).toBe('pkg:composer/a/b@1');
    expect(purlFor('rust', 'serde', '1')).toBe('pkg:cargo/serde@1');
    expect(purlFor('ruby', 'rack', '1')).toBe('pkg:gem/rack@1');
    expect(purlFor('dart', 'http', '1')).toBe('pkg:pub/http@1');
    expect(purlFor('swift', 'github.com/a/b', '1')).toBe('pkg:swift/github.com/a/b@1');
  });

  it('swiftPackageIdentity normalizes repository locations', () => {
    expect(swiftPackageIdentity('https://github.com/apple/swift-nio.git')).toBe('github.com/apple/swift-nio');
    expect(swiftPackageIdentity('https://GitHub.com/Apple/swift-nio/')).toBe('github.com/Apple/swift-nio');
    expect(swiftPackageIdentity('git@github.com:apple/swift-log.git')).toBe('github.com/apple/swift-log');
    expect(swiftPackageIdentity('ssh://git@gitlab.example.com:2222/team/sub/pkg.git')).toBe('gitlab.example.com/team/sub/pkg');
    expect(swiftPackageIdentity('https://user:token@github.com/a/b.git')).toBe('github.com/a/b');
    for (const bad of ['', '../local/pkg', '/abs/path', 'file:///x/y', 'https://github.com/only', 'https://github.com/a/../b', 'https://h/a/b?x=1', 'https://h o/a/b']) {
      expect(swiftPackageIdentity(bad), bad).toBeNull();
    }
  });
});
