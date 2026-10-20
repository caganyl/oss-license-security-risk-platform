/**
 * REQ-011 security review fixes — regression tests.
 *
 * - M-1 `go.mod`: `replace` lines are indexed by old module path, so many
 *   `require` x many `replace` lines are linear (was O(require x replace)).
 * - M-2 `Cargo.lock`: workspace membership uses one name set per lock (was
 *   a linear scan of the lock's source-less packages per member folder).
 * - M-4 YAML subset reader: a line limit checked before splitting, and no
 *   per-line object for blank/comment lines.
 * - M-3 `pom.xml`: interpolation input capped at 1 024 characters, memoized,
 *   and independent of the declaration order at the depth limit.
 * - M-5 private pub / gem sources: `private_source` on the record (the
 *   enricher side is in tests/integration/req011Licenses.test.ts).
 * - L-2 gem names of dots only; L-3 source license strings capped.
 *
 * Time limit: like `parserLinear.test.ts`, the assertions allow
 * `PERF_LIMIT_MS` = 2 s (the inputs take tens of milliseconds with the
 * fixes; the former quadratic code needs several seconds to minutes). The
 * measured time is printed in the failure message.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkCoordinates, isValidDepsDevName } from '../../src/enrichment/coordinates';
import { parseManifests } from '../../src/scanner/parsers';
import type { TreeWalk } from '../../src/scanner/parsers/common';
import { KIT_MAX_LICENSES, KIT_MAX_LICENSE_LENGTH, PARSER_MESSAGES, ParserContext } from '../../src/scanner/parsers/kit';
import { DEFAULT_YAML_LIMITS, YamlSubsetError, parseYamlSubset } from '../../src/scanner/parsers/yamlSubset';
import { osvCoordinateOf } from '../../src/vulnerability/osvCoordinates';

const PERF_LIMIT_MS = 2_000;
/** Generous per-test timeout: building the fixture trees is not measured. */
const TEST_TIMEOUT_MS = 120_000;
const MIB = 1024 * 1024;

function timed<T>(fn: () => T): { value: T; ms: number } {
  const start = performance.now();
  const value = fn();
  return { value, ms: performance.now() - start };
}

let tmpBase = '';
beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-req011-sec-'));
});
afterAll(() => {
  if (tmpBase) fs.rmSync(tmpBase, { recursive: true, force: true });
});

function root(name: string, files: Record<string, string>): string {
  const dir = path.join(tmpBase, name);
  for (const [rel, content] of Object.entries(files)) {
    const file = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content, 'utf8');
  }
  return dir;
}

// ---------------------------------------------------------------------------
describe('M-1: go.mod replace lines are indexed by old module path', () => {
  it('version-specific replace beats path-wide whatever the line order; the last matching line wins', () => {
    const dir = root('go-semantics', {
      'go.mod': [
        'module example.com/app',
        'require (',
        '\texample.com/a v1.0.0',
        '\texample.com/b v1.0.0',
        '\texample.com/c v1.0.0',
        '\texample.com/d v2.0.0',
        ')',
        // a: version-specific line after a path-wide one
        'replace example.com/a => example.com/a-wide v9.0.0',
        'replace example.com/a v1.0.0 => example.com/a-exact v1.1.0',
        // b: path-wide line after a version-specific one: the version-specific line still wins
        'replace example.com/b v1.0.0 => example.com/b-exact v1.1.0',
        'replace example.com/b => example.com/b-wide v9.0.0',
        // c: two path-wide lines, the last wins
        'replace example.com/c => example.com/c-first v1.0.1',
        'replace example.com/c => example.com/c-last v1.0.2',
        // d: a version-specific line for another version does not apply; path-wide local dir skips it
        'replace example.com/d v1.0.0 => example.com/d-other v1.0.0',
        'replace example.com/d => ../d',
        '',
      ].join('\n'),
    });
    const r = parseManifests(dir, ['go'], 'm1-semantics');
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies.map((d) => `${d.name}@${d.version}`)).toEqual(['example.com/a-exact@v1.1.0', 'example.com/b-exact@v1.1.0', 'example.com/c-last@v1.0.2']);
  });

  it(
    `50 000 require + 50 000 replace lines parse in well under ${PERF_LIMIT_MS} ms`,
    () => {
      const n = 50_000;
      const lines = ['module example.com/big', 'require ('];
      for (let i = 0; i < n; i++) lines.push(`\texample.com/mod${i} v1.0.${i}`);
      lines.push(')', 'replace (');
      // Half of the replace lines match a requirement (path-wide), half never match.
      for (let i = 0; i < n; i++) lines.push(i % 2 === 0 ? `\texample.com/mod${i} => example.com/fork${i} v2.0.0` : `\texample.com/other${i} v1.0.0 => example.com/x${i} v1.0.0`);
      lines.push(')', '');
      const dir = root('go-big', { 'go.mod': lines.join('\n') });
      const { value: r, ms } = timed(() => parseManifests(dir, ['go'], 'm1-big'));
      expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
      // 50 000 entries exceed the 20 000 per-folder limit: one fixed record, no entries.
      expect(r.parse_errors).toEqual([{ ecosystem: 'go', file: 'go.mod', error: PARSER_MESSAGES.limit }]);
      expect(r.dependencies).toEqual([]);
    },
    TEST_TIMEOUT_MS,
  );
});

// ---------------------------------------------------------------------------
describe('M-2: Cargo workspace membership uses one name set per lock', () => {
  it(
    `1 000 member folders under a Cargo.lock with 300 000 source-less packages: membership adds well under ${PERF_LIMIT_MS} ms`,
    () => {
      const packages = 300_000;
      const members = 1_000;
      const lock: string[] = ['version = 3', ''];
      for (let i = 0; i < packages; i++) lock.push('[[package]]', `name = "local${i}"`, 'version = "0.1.0"', '');
      lock.push('[[package]]', 'name = "serde"', 'version = "1.0.200"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', '');
      const memberFiles: Record<string, string> = {};
      // Members not listed in the lock: the former code scanned all 300 000 packages for each of them (3 * 10^8 checks).
      for (let i = 0; i < members; i++) memberFiles[`crates/m${i}/Cargo.toml`] = `[package]\nname = "member${i}"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1"\n`;
      // One member listed in the lock (last position): covered by the root lock.
      memberFiles['crates/covered/Cargo.toml'] = `[package]\nname = "local${packages - 1}"\nversion = "0.1.0"\n`;
      const dir = root('rust-big', { 'Cargo.lock': lock.join('\n'), ...memberFiles });
      // Baselines: reading the lock alone (TOML of 300 000 tables) and walking/reading the member
      // folders alone (file system cost on Windows) are not what the fix changes.
      const lockOnly = root('rust-big-lock-only', { 'Cargo.lock': lock.join('\n') });
      const membersOnly = root('rust-big-members-only', memberFiles);
      parseManifests(membersOnly, ['rust'], 'm2-warmup');
      const { ms: lockMs } = timed(() => parseManifests(lockOnly, ['rust'], 'm2-lock'));
      const { ms: membersMs } = timed(() => parseManifests(membersOnly, ['rust'], 'm2-members'));
      const { value: r, ms } = timed(() => parseManifests(dir, ['rust'], 'm2-big'));
      const extra = ms - lockMs - membersMs;
      expect(extra, `took ${ms.toFixed(0)} ms (lock alone ${lockMs.toFixed(0)} ms, members alone ${membersMs.toFixed(0)} ms)`).toBeLessThan(PERF_LIMIT_MS);
      expect(r.parse_errors).toEqual([]);
      const serde = r.dependencies.filter((d) => d.name === 'serde');
      // root lock (1) + every uncovered member manifest (3 000); the covered member adds nothing of its own.
      expect(serde).toHaveLength(members + 1);
      expect(r.dependencies.some((d) => d.manifest_path === 'crates/covered')).toBe(false);
    },
    TEST_TIMEOUT_MS,
  );
});

// ---------------------------------------------------------------------------
describe('M-3: pom.xml ${...} interpolation is bounded and order-independent', () => {
  function pom(properties: string, management: string, dependencies: string): string {
    return [
      '<project xmlns="http://maven.apache.org/POM/4.0.0">',
      '  <modelVersion>4.0.0</modelVersion>',
      '  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>',
      `  <properties>${properties}</properties>`,
      `  <dependencyManagement><dependencies>${management}</dependencies></dependencyManagement>`,
      `  <dependencies>${dependencies}</dependencies>`,
      '</project>',
      '',
    ].join('\n');
  }

  it(
    `64 KiB of \${e} in a managed version shared by 5 000 dependencies stays fast (< ${PERF_LIMIT_MS} ms) and is unresolved`,
    () => {
      const huge = '${e}'.repeat(16 * 1024);
      const deps = Array.from({ length: 5_000 }, (_, i) => `<dependency><groupId>org.x</groupId><artifactId>a${i % 50}</artifactId></dependency>`).join('');
      const managed = Array.from({ length: 50 }, (_, i) => `<dependency><groupId>org.x</groupId><artifactId>a${i}</artifactId><version>${huge}</version></dependency>`).join('');
      const dir = root('java-huge-interp', { 'pom.xml': pom('<e></e>', managed, deps) });
      const { value: r, ms } = timed(() => parseManifests(dir, ['java'], 'm3-huge'));
      expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
      expect(r.parse_errors).toEqual([]);
      expect(r.dependencies).toHaveLength(50);
      for (const d of r.dependencies) {
        expect(d.version).toBeNull();
        expect(d.declared_range).toBe('${e}'.repeat(50)); // the kit keeps at most 200 code points of the declaration
      }
    },
    TEST_TIMEOUT_MS,
  );

  it('a text longer than 1 024 characters is unresolved even when it would shrink; shorter texts still resolve', () => {
    const long = `\${e}${'${e}'.repeat(300)}1.0.0`; // 1 209 characters -> "1.0.0" if expanded
    const dir = root('java-long-text', {
      'pom.xml': pom(
        '<e></e><v>2.0.0</v>',
        '',
        `<dependency><groupId>org.x</groupId><artifactId>long</artifactId><version>${long}</version></dependency>` +
          '<dependency><groupId>org.x</groupId><artifactId>short</artifactId><version>${e}${v}</version></dependency>',
      ),
    });
    const r = parseManifests(dir, ['java'], 'm3-long');
    expect(r.dependencies.map((d) => `${d.name}@${d.version ?? '-'}`)).toEqual(['org.x:long@-', 'org.x:short@2.0.0']);
  });

  it('the depth limit gives the same result whatever the order of the declarations', () => {
    // p1 -> p2 -> ... -> p17 = "1.0.0": ${p2} needs 16 nested lookups (resolved), ${p1} needs 17 (unresolved).
    const chain = Array.from({ length: 16 }, (_, i) => `<p${i + 1}>\${p${i + 2}}</p${i + 1}>`).join('') + '<p17>1.0.0</p17>';
    const shallow = '<dependency><groupId>org.x</groupId><artifactId>shallow</artifactId><version>${p2}</version></dependency>';
    const deep = '<dependency><groupId>org.x</groupId><artifactId>deep</artifactId><version>${p1}</version></dependency>';
    const results = [
      ['deep-first', deep + shallow],
      ['shallow-first', shallow + deep],
    ].map(([name, deps]) => {
      const r = parseManifests(root(`java-depth-${name}`, { 'pom.xml': pom(chain, '', deps) }), ['java'], `m3-${name}`);
      return r.dependencies.map((d) => `${d.name}@${d.version ?? '-'}`);
    });
    expect(results[0]).toEqual(['org.x:deep@-', 'org.x:shallow@1.0.0']);
    expect(results[1]).toEqual(results[0]);
  });
});

// ---------------------------------------------------------------------------
describe('M-4: YAML subset reader line limit and blank lines', () => {
  it('the default line limit is 2 000 000', () => {
    expect(DEFAULT_YAML_LIMITS.maxLines).toBe(2_000_000);
  });

  it.each([
    ['32 MiB of "\\n"', () => '\n'.repeat(32 * MIB)],
    ['32 MiB of "#\\n"', () => '#\n'.repeat(16 * MIB)],
    ['32 MiB of "\\r\\n"', () => '\r\n'.repeat(16 * MIB)],
  ])(
    '%s is a limit error, quickly',
    (_label, make) => {
      const text = make();
      const { value: err, ms } = timed(() => {
        try {
          parseYamlSubset(text);
          return null;
        } catch (e) {
          return e;
        }
      });
      expect(err).toBeInstanceOf(YamlSubsetError);
      expect((err as YamlSubsetError).code).toBe('limit');
      expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
    },
    TEST_TIMEOUT_MS,
  );

  it('exactly maxLines lines are still read; one more is a limit error', () => {
    const limits = { maxLines: 10 };
    expect(parseYamlSubset(`a: b${'\n'.repeat(9)}`, limits)).toEqual({ a: 'b' });
    expect(() => parseYamlSubset(`a: b${'\n'.repeat(10)}`, limits)).toThrow(YamlSubsetError);
  });

  it(
    `1 900 000 blank and comment lines around content parse in well under ${PERF_LIMIT_MS} ms, with block scalars keeping "#" lines`,
    () => {
      const filler = '\n#\n'.repeat(475_000);
      const text = `${filler}a: b\nc: |\n  x\n  # kept\n\n  y\n${filler}`;
      const { value, ms } = timed(() => parseYamlSubset(text));
      expect(value).toEqual({ a: 'b', c: 'x\n# kept\n\ny\n' });
      expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'a 32 MiB pubspec.lock of newlines becomes one fixed YAML record',
    () => {
      const dir = root('dart-newlines', { 'pubspec.lock': '\n'.repeat(32 * MIB) });
      const { value: r, ms } = timed(() => parseManifests(dir, ['dart'], 'm4-dart'));
      expect(r.parse_errors).toEqual([{ ecosystem: 'dart', file: 'pubspec.lock', error: PARSER_MESSAGES.yaml }]);
      expect(r.dependencies).toEqual([]);
      expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS * 2);
    },
    TEST_TIMEOUT_MS,
  );
});

// ---------------------------------------------------------------------------
describe('M-5: private pub / gem sources are marked private_source (inventory kept, no license lookup)', () => {
  function hosted(name: string, url: string | null): string {
    const description = url === null ? `      name: ${name}\n` : `      name: ${name}\n      url: "${url}"\n`;
    return `  ${name}:\n    dependency: "direct main"\n    description:\n${description}    source: hosted\n    version: "1.0.0"`;
  }

  it('pubspec.lock: only https://pub.dev and https://pub.dartlang.org (any case, optional trailing "/") are public', () => {
    const dir = root('dart-private', {
      'pubspec.lock': [
        'packages:',
        hosted('a_pubdev', 'https://pub.dev'),
        hosted('b_slash', 'https://pub.dev/'),
        hosted('c_upper', 'HTTPS://PUB.DEV'),
        hosted('d_legacy', 'https://pub.dartlang.org'),
        hosted('e_private', 'https://pub.example.internal'),
        hosted('f_http', 'http://pub.dev'),
        hosted('g_lookalike', 'https://pub.dev.example.com'),
        hosted('h_no_url', null),
        '',
      ].join('\n'),
    });
    const r = parseManifests(dir, ['dart'], 'm5-dart');
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies.map((d) => `${d.name}:${d.private_source === true ? 'private' : 'public'}`)).toEqual([
      'a_pubdev:public',
      'b_slash:public',
      'c_upper:public',
      'd_legacy:public',
      'e_private:private',
      'f_http:private',
      'g_lookalike:private',
      'h_no_url:private',
    ]);
    // Public records keep their exact shape (no `private_source: false`).
    expect(Object.keys(r.dependencies[0])).not.toContain('private_source');
  });

  it('Gemfile.lock: a GEM section is public only when every remote is rubygems.org', () => {
    const gem = (remotes: string[], name: string) => ['GEM', ...remotes.map((r) => `  remote: ${r}`), '  specs:', `    ${name} (1.0.0)`, ''].join('\n');
    const dir = root('ruby-private', {
      'Gemfile.lock': [
        gem(['https://rubygems.org/'], 'a-public'),
        gem(['https://RubyGems.org'], 'b-case'),
        gem(['http://www.rubygems.org/'], 'c-www'),
        gem(['https://gems.example.internal/'], 'd-private'),
        gem(['https://rubygems.org/', 'https://gems.example.internal/'], 'e-mixed'),
        gem([], 'f-no-remote'),
        gem(['https://rubygems.org.example.com/'], 'g-lookalike'),
        'DEPENDENCIES',
        '  a-public',
        '',
      ].join('\n'),
    });
    const r = parseManifests(dir, ['ruby'], 'm5-ruby');
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies.map((d) => `${d.name}:${d.private_source === true ? 'private' : 'public'}`)).toEqual([
      'a-public:public',
      'b-case:public',
      'c-www:public',
      'd-private:private',
      'e-mixed:private',
      'f-no-remote:private',
      'g-lookalike:private',
    ]);
  });
});

// ---------------------------------------------------------------------------
describe('L-2: a gem name of dots only is not a coordinate', () => {
  it.each(['.', '..', '...'])('%j is rejected by the OSV and the deps.dev coordinate', (name) => {
    expect(osvCoordinateOf('ruby', name, '1.0.0')).toEqual({ kind: 'invalid_coordinates' });
    expect(isValidDepsDevName('RUBYGEMS', name)).toBe(false);
    expect(checkCoordinates('ruby', name, '1.0.0')).toEqual({ kind: 'invalid_coordinates' });
  });

  it.each(['rails', 'a.b', '.hidden', 'x..y'])('%j is still accepted', (name) => {
    expect(osvCoordinateOf('ruby', name, '1.0.0').kind).toBe('ok');
    expect(isValidDepsDevName('RUBYGEMS', name)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe('L-3: source license strings are capped (16 entries x 256 code units)', () => {
  const folder = { relDir: '', manifestPath: '.', files: new Map() };
  const record = { ecosystem: 'php' as const, filename: 'composer.lock', file_path: 'composer.lock', file_hash: 'x', size_bytes: 1 };

  it('40 strings of 300 characters become 16 strings of 256', () => {
    const ctx = new ParserContext({} as TreeWalk, 'php');
    ctx.commit(folder, record, [{ name: 'a/b', version: '1.0.0', scope: 'direct', manifestFile: 'composer.lock', licenses: Array.from({ length: 40 }, (_, i) => `${i}`.padEnd(300, 'y')) }]);
    const [d] = ctx.finish().dependencies;
    expect(d.licenses).toHaveLength(KIT_MAX_LICENSES);
    expect(d.licenses?.every((l) => l.length === KIT_MAX_LICENSE_LENGTH)).toBe(true);
    expect(d.licenses?.[15].startsWith('15')).toBe(true);
  });

  it('a cut never leaves half of a surrogate pair; short strings are unchanged', () => {
    const ctx = new ParserContext({} as TreeWalk, 'php');
    ctx.commit(folder, record, [{ name: 'a/b', version: '1.0.0', scope: 'direct', manifestFile: 'composer.lock', licenses: [`${'x'.repeat(255)}😀tail`, 'MIT'] }]);
    const [d] = ctx.finish().dependencies;
    expect(d.licenses).toEqual(['x'.repeat(255), 'MIT']);
  });

  it('composer.lock: a long license array joined by the parser is capped to 256 code units', () => {
    const licenses = Array.from({ length: 100 }, (_, i) => `LicenseRef-${i}`);
    const dir = root('php-long-license', {
      'composer.lock': JSON.stringify({ packages: [{ name: 'acme/lib', version: '1.0.0', license: licenses }], 'packages-dev': [] }),
    });
    const r = parseManifests(dir, ['php'], 'l3-php');
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies[0].licenses?.[0]).toHaveLength(KIT_MAX_LICENSE_LENGTH);
  });
});
