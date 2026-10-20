/**
 * REQ-011 P-40 — Dart/Flutter (`pubspec.lock`) parser: goldens (AC-P40-1),
 * hosted packages only (git/path/sdk skipped, D-311), dependency kinds ->
 * scope, YAML subset rejections and broken files (AC-P40-3, AC-P40-4).
 */
import { describe, expect, it } from 'vitest';
import type { ScannedDependency } from '../../src/types/scan';
import { PARSER_MESSAGES } from '../../src/scanner/parsers/kit';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['lock-flutter', 'broken'] as const;

function brief(list: readonly ScannedDependency[]): string[] {
  return list.map((d) => `${d.manifest_path}|${d.name}@${d.version ?? '-'}|${d.scope}|${d.declared_range ?? '-'}`);
}

describe('REQ-011 AC-P40-1: Dart goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('dart', 'dart', c));
});

describe('REQ-011 P-40: pubspec.lock', () => {
  it('hosted only; direct main / direct overridden -> direct, direct dev -> dev, transitive -> transitive', () => {
    const result = parseEcosystemCase('dart', 'dart', 'lock-flutter');
    expect(brief(result.dependencies)).toEqual([
      '.|async@2.11.0|transitive|-',
      '.|collection@1.18.0|direct|-', // direct overridden
      '.|flutter_lints@3.0.2|dev|-',
      '.|http@1.2.1|direct|-',
      '.|http_parser@4.0.2|transitive|-', // legacy pub.dartlang.org url
      '.|meta@1.12.0|direct|-', // unquoted `dependency: direct main`
      '.|private_sdk@2.0.0+3|direct|-', // hosted on a private pub server
    ]);
    const names = result.dependencies.map((d) => d.name);
    for (const skipped of ['flutter', 'flutter_test', 'sky_engine', 'local_widgets', 'shared_ui']) expect(names).not.toContain(skipped);
    expect(result.parse_errors).toEqual([]);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['pubspec.lock']);
    expect(result.dependencies.find((d) => d.name === 'private_sdk')?.purl).toBe('pkg:pub/private_sdk@2.0.0%2B3');
    expect(result.dependencies.every((d) => d.version !== null && d.manifest_file === 'pubspec.lock' && d.ecosystem === 'dart')).toBe(true);
  });
});

describe('REQ-011 AC-P40-3 / AC-P40-4: broken pubspec.lock files', () => {
  it('anchors/aliases rejected, YAML syntax and wrong structure are one fixed record each; bad entries dropped; other folders continue', () => {
    const result = parseEcosystemCase('dart', 'dart', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'dart', file: 'a-anchor/pubspec.lock', error: PARSER_MESSAGES.yamlUnsupported },
      { ecosystem: 'dart', file: 'b-bad-yaml/pubspec.lock', error: PARSER_MESSAGES.yaml },
      { ecosystem: 'dart', file: 'c-wrong-structure/pubspec.lock', error: PARSER_MESSAGES.structure },
      { ecosystem: 'dart', file: 'd-invalid-entries/pubspec.lock', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'dart', file: 'f-root-scalar/pubspec.lock', error: PARSER_MESSAGES.structure },
    ]);
    expect(brief(result.dependencies)).toEqual(['d-invalid-entries|args@2.4.2|direct|-', 'g-ok|path@1.9.0|direct|-']);
    // `packages: {}` is a valid lock without dependencies.
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['d-invalid-entries/pubspec.lock', 'e-empty-packages/pubspec.lock', 'g-ok/pubspec.lock']);
    for (const e of result.parse_errors) expect(e.error).not.toMatch(/oops|async|shared|[\\/]/);
  });
});
