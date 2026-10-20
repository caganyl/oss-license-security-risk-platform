/**
 * REQ-011 AC-P40-4 / D-303: safe YAML subset reader (pnpm-lock.yaml v6/v9,
 * pubspec.lock). Anchors, aliases, tags and multi-document streams are
 * rejected; the work is linear in the input size.
 */
import { describe, expect, it } from 'vitest';
import { YamlSubsetError, parseYamlSubset } from '../../src/scanner/parsers/yamlSubset';

// Lock files are deeply nested test data; their shape is asserted with toEqual.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Loose = Record<string, any>;

function code(text: string): string {
  try {
    parseYamlSubset(text);
  } catch (err) {
    if (err instanceof YamlSubsetError) return err.code;
    throw err;
  }
  return 'ok';
}

describe('accepted subset', () => {
  it('block mappings, sequences, scalars, comments and the leading document marker', () => {
    const text = [
      '---',
      '# comment',
      'name: demo # trailing comment',
      'empty:',
      'tilde: ~',
      'yes: true',
      'no: False',
      'num: 5.4',
      "single: 'it''s'",
      'double: "a\\tb\\u00e7\\x41"',
      'url: https://example.com/a#frag',
      'list:',
      '  - one',
      '  - "two"',
      '  -',
      '    nested: x',
      'same-indent-list:',
      '- a',
      '- b',
      'map:',
      '  inner:',
      '    deep: 1',
      '',
    ].join('\n');
    expect(parseYamlSubset(text)).toEqual({
      name: 'demo',
      empty: null,
      tilde: null,
      yes: true,
      no: false,
      num: '5.4',
      single: "it's",
      double: 'a\tbçA',
      url: 'https://example.com/a#frag',
      list: ['one', 'two', { nested: 'x' }],
      'same-indent-list': ['a', 'b'],
      map: { inner: { deep: '1' } },
    });
  });

  it('sequence items holding mappings and nested sequences', () => {
    expect(parseYamlSubset('- a: 1\n  b: 2\n- - x\n  - y\n- plain\n')).toEqual([{ a: '1', b: '2' }, ['x', 'y'], 'plain']);
  });

  it('one-line flow collections of scalars', () => {
    expect(parseYamlSubset("resolution: {integrity: sha512-abc==, tarball: 'https://r/x.tgz'}\ncpu: [x64, arm64]\nempty: {}\nnone: []\ntrailing: [a, b,]\n")).toEqual({
      resolution: { integrity: 'sha512-abc==', tarball: 'https://r/x.tgz' },
      cpu: ['x64', 'arm64'],
      empty: {},
      none: [],
      trailing: ['a', 'b'],
    });
  });

  it('literal and folded block scalars with chomping', () => {
    expect(parseYamlSubset('a: |\n  line1\n  line2\nb: >-\n  folded\n  text\n\n  para\nc: |+\n  keep\n\nd: x\n')).toEqual({
      a: 'line1\nline2\n',
      b: 'folded text\npara',
      c: 'keep\n\n',
      d: 'x',
    });
  });

  it('a __proto__ key is an own property, not the prototype', () => {
    const value = parseYamlSubset('__proto__:\n  polluted: yes\n') as Record<string, unknown>;
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(value, '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('BOM, CRLF and an empty document', () => {
    expect(parseYamlSubset('\uFEFFa: 1\r\nb: 2\r\n')).toEqual({ a: '1', b: '2' });
    expect(parseYamlSubset('')).toBeNull();
    expect(parseYamlSubset('# only a comment\n')).toBeNull();
  });

  it('pnpm-lock.yaml v9 shape', () => {
    const text = [
      "lockfileVersion: '9.0'",
      '',
      'settings:',
      '  autoInstallPeers: true',
      '',
      'importers:',
      '',
      '  .:',
      '    dependencies:',
      '      lodash:',
      '        specifier: ^4.17.21',
      '        version: 4.17.21',
      '    devDependencies:',
      "      '@types/node':",
      '        specifier: ^20.0.0',
      '        version: 20.11.0',
      '',
      'packages:',
      '',
      "  '@types/node@20.11.0':",
      "    resolution: {integrity: sha512-o9bjXmDNcF7GbM4CNQpmi+TutCgap/K3w1JyKgxAjqx41zp9qlIAVFi0IhCNsJcXolEqLWhbFbEeL0PvYm4pcQ==}",
      '',
      '  lodash@4.17.21:',
      '    resolution: {integrity: sha512-v2kDE==}',
      '',
      'snapshots:',
      '',
      "  '@types/node@20.11.0':",
      '    dependencies:',
      '      undici-types: 5.26.5',
      '',
      '  lodash@4.17.21: {}',
      '',
    ].join('\n');
    const lock = parseYamlSubset(text) as Loose;
    expect(lock.lockfileVersion).toBe('9.0');
    expect(lock.importers['.'].dependencies.lodash).toEqual({ specifier: '^4.17.21', version: '4.17.21' });
    expect(lock.importers['.'].devDependencies['@types/node'].version).toBe('20.11.0');
    expect(Object.keys(lock.packages)).toEqual(['@types/node@20.11.0', 'lodash@4.17.21']);
    expect(lock.snapshots['lodash@4.17.21']).toEqual({});
    expect(lock.snapshots['@types/node@20.11.0']).toEqual({ dependencies: { 'undici-types': '5.26.5' } });
  });

  it('pnpm-lock.yaml v6 shape (unquoted lockfileVersion, /name@version keys)', () => {
    const text = [
      "lockfileVersion: '6.0'",
      'dependencies:',
      '  express:',
      '    specifier: ^4.18.2',
      '    version: 4.18.2',
      'packages:',
      '  /express@4.18.2:',
      '    resolution: {integrity: sha512-x==}',
      "    engines: {node: '>= 0.10.0'}",
      '    dependencies:',
      '      accepts: 1.3.8',
      '    dev: false',
    ].join('\n');
    const lock = parseYamlSubset(text) as Loose;
    expect(lock.packages['/express@4.18.2']).toEqual({
      resolution: { integrity: 'sha512-x==' },
      engines: { node: '>= 0.10.0' },
      dependencies: { accepts: '1.3.8' },
      dev: false,
    });
    expect(parseYamlSubset('lockfileVersion: 5.4\n')).toEqual({ lockfileVersion: '5.4' });
  });

  it('pubspec.lock shape', () => {
    const text = [
      '# Generated by pub',
      '# See https://dart.dev/tools/pub/glossary#lockfile',
      'packages:',
      '  http:',
      '    dependency: "direct main"',
      '    description:',
      '      name: http',
      '      sha256: "5895291c13fa8a3bd82e76d5627f69e0d85ca6a30dcac95c4ea19a5d555879c2"',
      '      url: "https://pub.dev"',
      '    source: hosted',
      '    version: "1.2.0"',
      '  my_local:',
      '    dependency: "direct main"',
      '    description:',
      '      path: "../my_local"',
      '      relative: true',
      '    source: path',
      '    version: "0.0.1"',
      'sdks:',
      '  dart: ">=3.0.0 <4.0.0"',
      '  flutter: ">=3.10.0"',
    ].join('\n');
    const lock = parseYamlSubset(text) as Loose;
    expect(lock.packages.http).toEqual({
      dependency: 'direct main',
      description: { name: 'http', sha256: '5895291c13fa8a3bd82e76d5627f69e0d85ca6a30dcac95c4ea19a5d555879c2', url: 'https://pub.dev' },
      source: 'hosted',
      version: '1.2.0',
    });
    expect(lock.packages.my_local.description.relative).toBe(true);
    expect(lock.sdks).toEqual({ dart: '>=3.0.0 <4.0.0', flutter: '>=3.10.0' });
  });
});

describe('rejected (AC-P40-4)', () => {
  it.each([
    ['anchor value', 'a: &x 1\n'],
    ['alias value', 'a: *x\n'],
    ['merge key with alias', '<<: *base\n'],
    ['tag value', 'a: !!str 1\n'],
    ['custom tag', 'a: !thing x\n'],
    ['anchor key', '&k a: 1\n'],
    ['alias in flow', 'a: [*x]\n'],
    ['directive', '%YAML 1.2\n---\na: 1\n'],
    ['second document', 'a: 1\n---\nb: 2\n'],
    ['document end marker', 'a: 1\n...\n'],
    ['complex key', '? a\n: b\n'],
    ['tagged document marker', '--- !tag\na: 1\n'],
  ])('%s -> unsupported', (_name, text) => {
    expect(code(text)).toBe('unsupported');
  });

  it.each([
    ['nested flow', 'a: {b: [1, 2]}\n'],
    ['nested flow sequence', 'a: [[1]]\n'],
    ['unclosed flow', 'a: [1, 2\n'],
    ['unclosed quote', 'a: "x\n'],
    ['multi-line plain scalar', 'a: one\n  two\n'],
    ['multi-line quoted scalar', 'a: "one\n  two"\n'],
    ['tab indentation', 'a:\n\tb: 1\n'],
    ['bad indentation', 'a: 1\n  b: 2\n'],
    ['mapping value where scalar expected', 'a: b: c\n'],
    ['reserved indicator', 'a: @x\n'],
    ['bad escape', 'a: "\\q"\n'],
    ['lone surrogate escape', 'a: "\\ud800"\n'],
    ['text after quoted scalar', "a: 'x' y\n"],
    ['scalar then mapping at top level', 'x\na: 1\n'],
  ])('%s -> syntax', (_name, text) => {
    expect(code(text)).toBe('syntax');
  });

  it('duplicate keys (block and flow)', () => {
    expect(code('a: 1\na: 2\n')).toBe('duplicate_key');
    expect(code('a: {b: 1, b: 2}\n')).toBe('duplicate_key');
  });

  it('limits: size, depth and node count', () => {
    expect(() => parseYamlSubset('a: 1\n', { maxChars: 3 })).toThrow(YamlSubsetError);
    const deep = Array.from({ length: 70 }, (_, i) => `${' '.repeat(i * 2)}k${i}:`).join('\n') + '\n';
    expect(code(deep)).toBe('limit');
    expect(() => parseYamlSubset('- a\n- b\n- c\n', { maxNodes: 2 })).toThrow(YamlSubsetError);
  });

  it('error messages are fixed texts without document content', () => {
    try {
      parseYamlSubset('secret-token-value: &anchor x\n');
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(YamlSubsetError);
      expect((err as Error).message).not.toContain('secret');
      expect((err as YamlSubsetError).line).toBe(1);
    }
  });
});

describe('linear time', () => {
  it('large mapping, long plain line, many quotes and many flow items stay fast', () => {
    const n = 100_000;
    const big = Array.from({ length: n }, (_, i) => `  pkg${i}:\n    version: "1.0.${i}"`).join('\n');
    const longLine = `a: ${'x'.repeat(2_000_000)}\n`;
    const quotes = `a: '${"''".repeat(500_000)}'\n`;
    const flow = `a: [${Array.from({ length: 200_000 }, (_, i) => `v${i}`).join(', ')}]\n`;
    const colons = `a: ${'b:'.repeat(500_000)}c\n`;
    const started = performance.now();
    expect(Object.keys((parseYamlSubset(`packages:\n${big}\n`) as Record<string, Record<string, unknown>>).packages)).toHaveLength(n);
    expect((parseYamlSubset(longLine) as Record<string, string>).a).toHaveLength(2_000_000);
    expect((parseYamlSubset(quotes) as Record<string, string>).a).toHaveLength(500_000);
    expect((parseYamlSubset(flow) as Record<string, unknown[]>).a).toHaveLength(200_000);
    expect(code(colons)).toBe('ok');
    expect(performance.now() - started).toBeLessThan(15_000);
  });
});
