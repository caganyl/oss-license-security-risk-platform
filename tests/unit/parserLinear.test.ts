/**
 * REQ-003 security review M-1: the parser string helpers are linear on
 * hostile manifest lines.
 *
 * - `pyStrip` / `pyRstrip` / `isPyWhitespace` (src/scanner/parsers/common.ts)
 *   match Python's `str.strip()` whitespace set exactly (table over the whole
 *   BMP, independent of the `PY_WS` constant) and give the same result as the
 *   former regex implementation.
 * - `matchRequirementLine` gives the same `(name, rest)` as the former
 *   `REQUIREMENT_RE` of src/scanner/parsers/python.ts (redefined below as it
 *   was before commit f32b00c) on deterministic pseudo-random inputs.
 * - 1–2 MB whitespace runs in `requirements.txt`, `yarn.lock`,
 *   `package.json` and `pyproject.toml` requirement texts with an embedded
 *   "\n" are parsed in well under a second.
 *
 * Time limit: the requirement is "< 1 s"; the assertions allow
 * `PERF_LIMIT_MS` = 2 s so a loaded CI runner does not make the test flaky.
 * The former quadratic/cubic code needs ~10^11+ backtracking steps on these
 * inputs (minutes to hours), so 2 s still separates linear from quadratic by
 * orders of magnitude. The measured time is printed in the failure message.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import { PY_WS, isPyWhitespace, matchRequirementLine, pyRstrip, pyStrip } from '../../src/scanner/parsers/common';

const PERF_LIMIT_MS = 2_000;
const MB = 1024 * 1024;

/** Python 3 `str.isspace()` / `str.strip()` set (bidi WS, B, S or category Zs), written out independently of PY_WS. */
const PYTHON_WHITESPACE: ReadonlySet<number> = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

// The implementations replaced in commit f32b00c (security review M-1), kept here as the reference.
const OLD_STRIP_RE = new RegExp(`^[${PY_WS}]+|[${PY_WS}]+$`, 'gu');
const OLD_RSTRIP_RE = new RegExp(`[${PY_WS}]+$`, 'u');
const OLD_REQUIREMENT_RE = new RegExp(
  `^[${PY_WS}]*([A-Za-z0-9_.-]+)[${PY_WS}]*(\\[[^\\n]*?\\])?[${PY_WS}]*([^\\n]*)(?=\\n?$)`,
  'u',
);
const oldStrip = (v: string) => v.replace(OLD_STRIP_RE, '');
const oldRstrip = (v: string) => v.replace(OLD_RSTRIP_RE, '');
function oldMatch(v: string): [string, string] | null {
  const m = OLD_REQUIREMENT_RE.exec(v);
  return m ? [m[1], m[3]] : null;
}

/** mulberry32: small deterministic PRNG (fixed seed -> the same inputs on every run). */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomStrings(seed: number, count: number, alphabet: readonly string[], maxLen: number): string[] {
  const rnd = prng(seed);
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const len = Math.floor(rnd() * (maxLen + 1));
    let s = '';
    for (let j = 0; j < len; j++) s += alphabet[Math.floor(rnd() * alphabet.length)];
    out.push(s);
  }
  return out;
}

function timed<T>(fn: () => T): { value: T; ms: number } {
  const start = performance.now();
  const value = fn();
  return { value, ms: performance.now() - start };
}

let tmpBase = '';
beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-m1-'));
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
describe('M-1: pyStrip / pyRstrip use exactly the Python str.strip() whitespace set', () => {
  it('M-1: isPyWhitespace and the PY_WS character class agree with the Python table on every BMP code unit', () => {
    const cls = new RegExp(`^[${PY_WS}]$`, 'u');
    const mismatches: string[] = [];
    for (let c = 0; c <= 0xffff; c++) {
      const expected = PYTHON_WHITESPACE.has(c);
      if (isPyWhitespace(c) !== expected) mismatches.push(`isPyWhitespace U+${c.toString(16).padStart(4, '0')}`);
      if (cls.test(String.fromCharCode(c)) !== expected) mismatches.push(`PY_WS U+${c.toString(16).padStart(4, '0')}`);
    }
    expect(mismatches).toEqual([]);
  });

  it.each([...PYTHON_WHITESPACE].map((c) => [`U+${c.toString(16).padStart(4, '0')}`, String.fromCharCode(c)]))(
    'M-1: %s is stripped on both ends (pyStrip) and on the right (pyRstrip)',
    (_label, ch) => {
      expect(pyStrip(`${ch}${ch}x y${ch}`)).toBe('x y');
      expect(pyRstrip(`${ch}x${ch}${ch}`)).toBe(`${ch}x`);
    },
  );

  it.each([
    ['U+200B zero width space', '​'],
    ['U+FEFF BOM', '﻿'],
    ['U+180E Mongolian vowel separator (not Zs since Unicode 6.3)', '᠎'],
    ['U+2060 word joiner', '⁠'],
    ['NUL', '\x00'],
    ['U+001B ESC', '\x1b'],
    ['U+0084', '\x84'],
  ])('M-1: %s is not Python whitespace and is kept', (_label, ch) => {
    expect(pyStrip(`${ch}x${ch}`)).toBe(`${ch}x${ch}`);
    expect(pyRstrip(`x${ch}`)).toBe(`x${ch}`);
  });

  it('M-1: same result as the former regex implementation on 20 000 pseudo-random strings (seed 0x5eed)', () => {
    const alphabet = ['a', 'Z', '0', '=', ' ', '\t', '\n', '\r', '\x0b', '\x1c', '\x85', '\xa0', ' ', '　', '​', '﻿', '😀', 'é'];
    const diffs = randomStrings(0x5eed, 20_000, alphabet, 12).filter((v) => pyStrip(v) !== oldStrip(v) || pyRstrip(v) !== oldRstrip(v));
    expect(diffs.map((d) => JSON.stringify(d))).toEqual([]);
  });

  it('M-1: unchanged input is returned as is; all-whitespace input becomes empty', () => {
    expect(pyStrip('abc')).toBe('abc');
    expect(pyRstrip('abc')).toBe('abc');
    expect(pyStrip(' \t　\n')).toBe('');
    expect(pyRstrip(' \t　\n')).toBe('');
    expect(pyStrip('')).toBe('');
  });
});

// ---------------------------------------------------------------------------
describe('M-1: matchRequirementLine is equivalent to the former REQUIREMENT_RE', () => {
  it.each([
    [''],
    ['\n'],
    ['a'],
    ['a\n'],
    ['a\n\n'],
    ['flask==3.0.0'],
    ['  flask >= 2 '],
    ['requests[security,socks]>=2.31'],
    ['requests [security] >=2.31\n'],
    ['a[x]]y'],
    ['a[]]'],
    ['a[x\n]y'],
    ['a[x]\ny'],
    ['a[x] y\n'],
    ['a [x]　[y]\n'],
    ['[a]'],
    ['  name.with-dots_1 ~= 1.0'],
    ['a​b'],
    ['foo bar\nbaz'],
    ['x\n'],
    ['foo   x\ny'],
    ['aaa\nb\nc'],
    ['a   [x   ]\ny\nz'],
    ['a[]]]\nx\n'],
    ['a[]]]\nx\ny'],
  ])('M-1: %j', (input) => {
    expect(matchRequirementLine(input)).toEqual(oldMatch(input));
  });

  it('M-1: same (name, rest) or null on 30 000 pseudo-random requirement-like texts (seed 0xc0ffee)', () => {
    const alphabet = ['a', 'B', '7', '_', '.', '-', ' ', '\t', '\n', '\r', '[', ']', '[', ']', '=', '>', ',', ';', '　', '\x85', '\x0b', '​', 'é', '#'];
    const diffs: string[] = [];
    for (const input of randomStrings(0xc0ffee, 30_000, alphabet, 14)) {
      const actual = matchRequirementLine(input);
      const expected = oldMatch(input);
      if (JSON.stringify(actual) !== JSON.stringify(expected)) diffs.push(`${JSON.stringify(input)}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
    }
    expect(diffs.slice(0, 20)).toEqual([]);
  });

  it('M-1: structured texts (name, optional bracket, whitespace, rest, optional newline) on 10 000 pseudo-random cases (seed 42)', () => {
    const rnd = prng(42);
    const pick = <T>(xs: readonly T[]) => xs[Math.floor(rnd() * xs.length)];
    const ws = ['', ' ', '\t', '  ', '　', '\n', ' \n'];
    const names = ['a', 'flask', 'zope.interface', 'my_pkg-2', ''];
    const brackets = ['', '[x]', '[a,b]', '[]', '[x]]', '[x', ']', '[x\n]', '[[y]]'];
    const rests = ['', '==1.0', '>=2,<3', 'x\ny', '; python_version<"3.8"', '\n', 'a b'];
    const ends = ['', '\n', '\n\n', '\r\n'];
    const diffs: string[] = [];
    for (let i = 0; i < 10_000; i++) {
      const input = `${pick(ws)}${pick(names)}${pick(ws)}${pick(brackets)}${pick(ws)}${pick(rests)}${pick(ends)}`;
      const actual = matchRequirementLine(input);
      const expected = oldMatch(input);
      if (JSON.stringify(actual) !== JSON.stringify(expected)) diffs.push(`${JSON.stringify(input)}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
    }
    expect(diffs.slice(0, 20)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
describe(`M-1: long whitespace runs are linear (< 1 s required, asserted < ${PERF_LIMIT_MS} ms)`, () => {
  it.each([
    ['pyStrip, 2 MB inner run', () => pyStrip(`a${' '.repeat(2 * MB)}b`), `a${' '.repeat(2 * MB)}b`],
    ['pyStrip, 2 MB leading run + text', () => pyStrip(`${' '.repeat(2 * MB)}b`), 'b'],
    ['pyRstrip, 2 MB inner run', () => pyRstrip(`a${'　'.repeat(2 * MB)}b`), `a${'　'.repeat(2 * MB)}b`],
  ])('M-1: %s', (_label, fn, expected) => {
    const { value, ms } = timed(fn);
    expect(value === expected, 'unexpected result').toBe(true);
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
  });

  // Expected values follow the old regex semantics (the short forms of the same shapes,
  // e.g. "a[]]\nx\n", are in the equivalence table above); the old regex itself is not
  // run on these sizes (it would not finish).
  it.each([
    ['"foo" + 1M spaces + "x\\ny"', `foo${' '.repeat(MB)}x\ny`, null],
    ['"a" * 1M + "\\nb\\nc"', `${'a'.repeat(MB)}\nb\nc`, null],
    ['"a" + 1M spaces + "[x" + 1M spaces + "]\\ny\\nz"', `a${' '.repeat(MB)}[x${' '.repeat(MB)}]\ny\nz`, null],
    // the whitespace after the bracket may span the "\n" (PY_WS includes it), so the rest is "x"
    ['"a[" + "]" * 200k + "\\nx\\n"', `a[${']'.repeat(200_000)}\nx\n`, ['a', 'x']],
    ['"a[" + "]" * 200k + "\\nx\\ny"', `a[${']'.repeat(200_000)}\nx\ny`, null],
  ] as const)('M-1: matchRequirementLine on %s, linearly', (_label, input, expected) => {
    const { value, ms } = timed(() => matchRequirementLine(input));
    expect(value).toEqual(expected);
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
  });

  it('M-1: requirements.txt with 1–2 MB whitespace runs inside lines is parsed; the following lines still count', () => {
    const dir = root('req', {
      'requirements.txt': [
        `a${' '.repeat(2 * MB)}b`,
        `${' '.repeat(MB)}requests>=2.31${'\t'.repeat(MB)}`,
        `foo==${' '.repeat(MB)}1.0${' '.repeat(MB)}x`,
        'flask==3.0.0',
        '',
      ].join('\n'),
    });
    const { value: r, ms } = timed(() => parseManifests(dir, ['python'], 'm1-req'));
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
    expect(r.parse_errors).toEqual([]);
    const byName = new Map(r.dependencies.map((d) => [d.name, d]));
    expect(byName.get('flask')).toMatchObject({ version: '3.0.0' });
    expect(byName.get('requests')).toMatchObject({ version: null, declared_range: '>=2.31' });
    expect(byName.has('a')).toBe(true);
  });

  it('M-1: yarn.lock and package.json with 1–2 MB whitespace runs are parsed', () => {
    const dir = root('yarn', {
      'package.json': JSON.stringify({ dependencies: { 'left-pad': `^1.3.0${' '.repeat(MB)}x` } }),
      'yarn.lock': [
        '# yarn lockfile v1',
        '',
        'left-pad@^1.3.0:',
        '  version "1.3.0"',
        `  resolved "x${' '.repeat(2 * MB)}y"`,
        `${' '.repeat(2 * MB)}z`,
        '',
      ].join('\n'),
    });
    const { value: r, ms } = timed(() => parseManifests(dir, ['nodejs'], 'm1-yarn'));
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies).toEqual(expect.arrayContaining([expect.objectContaining({ name: 'left-pad', version: '1.3.0', manifest_file: 'yarn.lock' })]));
  });

  it('M-1: pyproject.toml requirement texts with an embedded "\\n" after 1M spaces / 1M name characters give no dependency, linearly', () => {
    const dir = root('pyproject', {
      'pyproject.toml': [
        '[project]',
        'name = "m1"',
        'dependencies = [',
        `  "foo${' '.repeat(MB)}x\\ny",`,
        `  "${'a'.repeat(MB)}\\nb\\nc",`,
        '  "flask==3.0.0",',
        ']',
        '',
      ].join('\n'),
    });
    const { value: r, ms } = timed(() => parseManifests(dir, ['python'], 'm1-pyproject'));
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(PERF_LIMIT_MS);
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies.map((d) => d.name)).toEqual(['flask']);
  });
});
