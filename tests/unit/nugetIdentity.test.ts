/**
 * REQ-006 · AC-P20-8 version rules and AC-P20-9 identity/purl (ADR-008 Karar 4; D-151, D-152):
 * src/scanner/parsers/nugetIdentity.ts and the pure lock/assets/project readers.
 */
import { describe, expect, it } from 'vitest';
import { NUGET_MESSAGES, NugetFileError } from '../../src/scanner/parsers/common';
import { parsePackagesConfig, parseProjectFile } from '../../src/scanner/parsers/msbuildProject';
import { parseNugetAssets } from '../../src/scanner/parsers/nugetAssets';
import { asciiLower, classifyNugetVersion, isValidNugetId, nugetKey, nugetPurl } from '../../src/scanner/parsers/nugetIdentity';
import { parseNugetLock } from '../../src/scanner/parsers/nugetLock';

const exact = (raw: unknown) => {
  const c = classifyNugetVersion(raw);
  return c.kind === 'exact' ? c.version : null;
};

describe('AC-P20-8: version classification and normalization', () => {
  it.each([
    ['01.02.03', '1.2.3'],
    ['1.0', '1.0.0'],
    ['1.0.0.0', '1.0.0'],
    ['4.0.10.1', '4.0.10.1'],
    ['2.0.0-Beta.1+sha.abc', '2.0.0-Beta.1'],
    ['[1.2.3]', '1.2.3'],
    ['13.0.3', '13.0.3'],
    ['00.0.0', '0.0.0'],
    ['1.0.0-RC.1', '1.0.0-RC.1'],
    ['1.0.0-alpha-2.x-y', '1.0.0-alpha-2.x-y'],
    ['2147483647.0.0', '2147483647.0.0'],
    ['  1.2.3\n', '1.2.3'],
    ['1.2.3+build', '1.2.3'],
  ])('AC-P20-8: %j -> %j (exact)', (raw, expected) => {
    expect(classifyNugetVersion(raw)).toEqual({ kind: 'exact', version: expected });
  });

  it.each([
    '[1.0,2.0)', '(1.0,)', '[1.0,]', '(,2.0]', '[1.0, 2.0]', '1.*', '*', '1.0.0-*', '$(LibVersion)', '$(V).0', '', '   ',
    '1', '1.2.3.4.5', '1.0.0-a..b', '1.0.0-', '1.0.0-a.', '1.0.0-.a', '1.0.0-a_b', '1.0.0+', '1.0.0+a..b', '2147483648.0.0',
    'v1.0.0', '1.0.0 beta', '1..0', '1.0.', '-1.0.0', '1.0.0@x', '1.0.0%2e', '[]', '[1.0.0', '1.0.0]', '１.０.０', `1.0.0-${'a'.repeat(123)}`,
  ])('AC-P20-8 / D-152: %j -> unknown (NULL)', (raw) => {
    expect(classifyNugetVersion(raw)).toEqual({ kind: 'unknown' });
  });

  it('AC-P20-8: maximum length is 128 characters; non-strings are unknown', () => {
    const v128 = `1.0.0-${'a'.repeat(122)}`;
    expect(v128).toHaveLength(128);
    expect(exact(v128)).toBe(v128);
    expect(exact(`${v128}a`)).toBeNull();
    for (const raw of [null, undefined, 1, {}, ['1.0.0']]) expect(classifyNugetVersion(raw)).toEqual({ kind: 'unknown' });
  });
});

describe('AC-P20-9: identity, keys and purl', () => {
  it('AC-P20-9: valid ids follow ^[A-Za-z0-9_]+([.-][A-Za-z0-9_]+)*$ with at most 100 characters', () => {
    for (const id of ['Newtonsoft.Json', 'a', 'A_b-c.d', 'log4net', '_x', 'x'.repeat(100), 'Microsoft.Extensions.Logging.Abstractions']) {
      expect(isValidNugetId(id), id).toBe(true);
    }
    for (const id of ['', 'x'.repeat(101), '.a', 'a.', '-a', 'a-', 'a..b', 'a.-b', 'a/b', 'a\\b', 'a b', 'a%2e', 'İ', 'ı', 'a;b', '../x', 'a:b', null, 1]) {
      expect(isValidNugetId(id), String(id)).toBe(false);
    }
  });

  it('AC-P20-9: keys are ASCII lower case (locale independent: Turkish I/İ/ı never fold)', () => {
    expect(asciiLower('NEWTONSOFT.JSON')).toBe('newtonsoft.json');
    expect(asciiLower('ISTANBUL')).toBe('istanbul');
    expect(asciiLower('I')).not.toBe('I'.toLocaleLowerCase('tr-TR'));
    expect(asciiLower('İı')).toBe('İı');
    expect(asciiLower('already-lower')).toBe('already-lower');
  });

  it('AC-P20-9 / D-151: nugetKey is (lower id, lower version); unknown version differs from any version', () => {
    expect(nugetKey('Contoso.Core', '1.0.0-Beta')).toBe(nugetKey('contoso.core', '1.0.0-beta'));
    expect(nugetKey('INTERNAL', '1.0.0')).toBe(nugetKey('internal', '1.0.0'));
    expect(nugetKey('a', '1.0.0')).not.toBe(nugetKey('a', '1.0.1'));
    expect(nugetKey('a', null)).not.toBe(nugetKey('a', ''));
    expect(nugetKey('a.b', '1.0.0')).not.toBe(nugetKey('a', 'b\u00001.0.0'));
  });

  it('AC-P20-9: purl keeps source casing; no version -> no @', () => {
    expect(nugetPurl('Newtonsoft.Json', '13.0.3')).toBe('pkg:nuget/Newtonsoft.Json@13.0.3');
    expect(nugetPurl('Contoso.Core', '1.0.0-Beta')).toBe('pkg:nuget/Contoso.Core@1.0.0-Beta');
    expect(nugetPurl('Newtonsoft.Json', null)).toBe('pkg:nuget/Newtonsoft.Json');
  });
});

describe('AC-P20-3 / AC-P20-4 / AC-P20-15: pure readers, fixed file errors', () => {
  const json = (v: unknown) => Buffer.from(JSON.stringify(v));
  const fileError = (fn: () => unknown): string => {
    try {
      fn();
    } catch (err) {
      expect(err).toBeInstanceOf(NugetFileError);
      return (err as Error).message;
    }
    throw new Error('expected NugetFileError');
  };

  it('AC-P20-3: lock version must be the number 1 or 2; invalid JSON text never leaks', () => {
    expect(fileError(() => parseNugetLock(json({ version: '2', dependencies: {} })))).toBe(NUGET_MESSAGES.lockVersion);
    expect(fileError(() => parseNugetLock(json({ version: 3, dependencies: {} })))).toBe(NUGET_MESSAGES.lockVersion);
    expect(fileError(() => parseNugetLock(json([])))).toBe(NUGET_MESSAGES.structure);
    expect(fileError(() => parseNugetLock(json({ version: 1, dependencies: { t: [] } })))).toBe(NUGET_MESSAGES.structure);
    expect(fileError(() => parseNugetLock(Buffer.from('{"version": 2, "SECRET-x": ')))).toBe(NUGET_MESSAGES.json);
    expect(fileError(() => parseNugetLock(Buffer.from([0x7b, 0xff, 0x7d])))).toBe(NUGET_MESSAGES.json);
    const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), json({ version: 1, dependencies: {} })]);
    expect(parseNugetLock(bom)).toEqual({ entries: [], issues: [], hashes: [] });
  });

  it('AC-P20-3: an invalid resolved version is an invalidEntry issue; a non-object entry too', () => {
    const r = parseNugetLock(json({ version: 2, dependencies: { 'net8.0': { A: { type: 'Direct', resolved: '[1.0,2.0)' }, B: 'x', C: { type: 'Transitive', resolved: '1.0.0' } } } }));
    expect(r.issues).toEqual(['invalidEntry']);
    expect(r.entries.map((e) => e.name)).toEqual(['C']);
  });

  it('AC-P20-4: assets version must be 3; libraries is required', () => {
    expect(fileError(() => parseNugetAssets(json({ version: 2, libraries: {} })))).toBe(NUGET_MESSAGES.assetsVersion);
    expect(fileError(() => parseNugetAssets(json({ version: 3 })))).toBe(NUGET_MESSAGES.structure);
    const r = parseNugetAssets(json({ version: 3, libraries: { 'A/1.0': { type: 'package' } }, project: { frameworks: { x: { dependencies: { a: { version: '[1.0, )' } } } } } }));
    expect(r.entries).toEqual([{ name: 'A', version: '1.0.0', scope: 'direct', declaredRange: '[1.0, )', manifestFile: 'project.assets.json' }]);
  });

  it('AC-P20-5 / AC-P20-13: project files go through the safe reader (DOCTYPE, encoding, limit -> fixed texts)', () => {
    expect(fileError(() => parseProjectFile(Buffer.from('<!DOCTYPE x><Project/>')))).toBe(NUGET_MESSAGES.xmlDoctype);
    expect(fileError(() => parseProjectFile(Buffer.from('<Project>'.repeat(65))))).toBe(NUGET_MESSAGES.xmlLimit);
    expect(fileError(() => parseProjectFile(Buffer.from('<\u0000P\u0000/\u0000>\u0000', 'latin1')))).toBe(NUGET_MESSAGES.xmlEncoding);
    expect(fileError(() => parseProjectFile(Buffer.from('<Project><x>&secret;</x></Project>')))).toBe(NUGET_MESSAGES.xmlMalformed);
    expect(fileError(() => parsePackagesConfig(Buffer.from('<Project/>')))).toBe(NUGET_MESSAGES.structure);
    const declared = parseProjectFile(Buffer.from(`<Project><ItemGroup><PackageReference Include="A" Version="${'1'.repeat(300)}" /></ItemGroup></Project>`));
    expect(declared.references[0].explicitVersion).toHaveLength(300); // raw; cut to 200 code points when emitted
  });
});
