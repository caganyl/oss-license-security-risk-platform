/**
 * REQ-011 P-40 — Swift (`Package.resolved` v1/v2/v3) parser: goldens
 * (AC-P40-1), remote source control pins only (local/fileSystem/registry
 * skipped, D-311), branch/revision pins without a version (AC-P40-6) and
 * broken files (AC-P40-3).
 */
import { describe, expect, it } from 'vitest';
import type { ScannedDependency } from '../../src/types/scan';
import { PARSER_MESSAGES } from '../../src/scanner/parsers/kit';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['v1', 'v2', 'v3-branch', 'broken'] as const;

function brief(list: readonly ScannedDependency[]): string[] {
  return list.map((d) => `${d.manifest_path}|${d.name}@${d.version ?? '-'}|${d.scope}|${d.declared_range ?? '-'}`);
}

describe('REQ-011 AC-P40-1: Swift goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('swift', 'swift', c));
});

describe('REQ-011 P-40: Package.resolved', () => {
  it('v1: object.pins with repositoryURL (https and scp-like); a local path pin is skipped; branch pin -> version null + branch', () => {
    const result = parseEcosystemCase('swift', 'swift', 'v1');
    expect(brief(result.dependencies)).toEqual([
      '.|github.com/Alamofire/Alamofire@5.8.1|direct|-',
      '.|github.com/apple/swift-log@1.5.3|direct|-',
      '.|github.com/SnapKit/SnapKit@-|direct|develop',
    ]);
    expect(result.dependencies.map((d) => d.purl)).toEqual([
      'pkg:swift/github.com/Alamofire/Alamofire@5.8.1',
      'pkg:swift/github.com/apple/swift-log@1.5.3',
      'pkg:swift/github.com/SnapKit/SnapKit',
    ]);
    expect(result.parse_errors).toEqual([]);
  });

  it('v2: remoteSourceControl pins; localSourceControl skipped', () => {
    expect(brief(parseEcosystemCase('swift', 'swift', 'v2').dependencies)).toEqual([
      '.|github.com/apple/swift-argument-parser@1.3.0|direct|-',
      '.|github.com/apple/swift-nio@2.64.0|direct|-',
    ]);
  });

  it('v3 (originHash): branch pin -> branch, revision-only pin -> revision as declared_range; fileSystem and registry pins skipped; ssh URL with port', () => {
    const result = parseEcosystemCase('swift', 'swift', 'v3-branch');
    expect(brief(result.dependencies)).toEqual([
      '.|github.com/groue/GRDB.swift@-|direct|development',
      '.|github.com/onevcat/Kingfisher@7.11.0|direct|-',
      '.|gitlab.example.com/mobile/core/pinned-commit@-|direct|1111111111111111111111111111111111111111',
    ]);
    expect(result.dependencies.filter((d) => d.version === null).every((d) => !d.purl.includes('@'))).toBe(true);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['Package.resolved']);
  });
});

describe('REQ-011 AC-P40-3: broken Package.resolved files', () => {
  it('one fixed Turkish record per file; unknown versions rejected; malformed pins dropped; other folders continue', () => {
    const result = parseEcosystemCase('swift', 'swift', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'swift', file: 'a-bad-json/Package.resolved', error: PARSER_MESSAGES.json },
      { ecosystem: 'swift', file: 'b-future-version/Package.resolved', error: PARSER_MESSAGES.unsupportedVersion },
      { ecosystem: 'swift', file: 'c-string-version/Package.resolved', error: PARSER_MESSAGES.unsupportedVersion },
      { ecosystem: 'swift', file: 'd-wrong-structure/Package.resolved', error: PARSER_MESSAGES.structure },
      { ecosystem: 'swift', file: 'e-invalid-pins/Package.resolved', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'swift', file: 'f-v1-no-object/Package.resolved', error: PARSER_MESSAGES.structure },
    ]);
    expect(brief(result.dependencies)).toEqual(['e-invalid-pins|github.com/apple/swift-collections@1.1.0|direct|-', 'g-ok|github.com/apple/swift-algorithms@1.2.0|direct|-']);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['e-invalid-pins/Package.resolved', 'g-ok/Package.resolved']);
    for (const e of result.parse_errors) expect(e.error).not.toMatch(/oops|github|[\\/]/);
  });
});
