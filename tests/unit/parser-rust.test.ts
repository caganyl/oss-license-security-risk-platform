/**
 * REQ-011 P-40 — Rust (`Cargo.lock` > `Cargo.toml`) parser: goldens
 * (AC-P40-1), source priority (AC-P40-2), git/path/alternative-registry skip
 * (D-311), broken files (AC-P40-3) and versionless declarations (AC-P40-6).
 */
import { describe, expect, it } from 'vitest';
import type { ScannedDependency } from '../../src/types/scan';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['lock-v3', 'lock-v4-workspace', 'lock-v1-v2', 'toml-fallback', 'broken'] as const;

type Row = ScannedDependency;

function rows(caseName: string): Row[] {
  return parseEcosystemCase('rust', 'rust', caseName).dependencies;
}

function brief(list: readonly Row[]): string[] {
  return list.map((d) => `${d.manifest_path}|${d.name}@${d.version ?? '-'}|${d.scope}|${d.manifest_file}|${d.declared_range ?? '-'}`);
}

describe('REQ-011 AC-P40-1: Rust goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('rust', 'rust', c));
});

describe('REQ-011 P-40: Cargo.lock', () => {
  it('v3: crates.io packages only; git, path, root and alternative-registry packages skipped; scope from the root references + Cargo.toml', () => {
    expect(brief(rows('lock-v3'))).toEqual([
      '.|bitflags@1.3.2|transitive|Cargo.lock|-',
      '.|bitflags@2.5.0|direct|Cargo.lock|2',
      '.|cc@1.0.98|direct|Cargo.lock|1.0.90',
      '.|clap@4.5.4|direct|Cargo.lock|4.5',
      '.|clap_builder@4.5.2|transitive|Cargo.lock|-',
      '.|itoa@1.0.11|transitive|Cargo.lock|-',
      // dependency of the path crate `local-helper` (helper/ is covered by the root lock)
      '.|once_cell@1.19.0|direct|Cargo.lock|1.19',
      // declared in both [dependencies] and [dev-dependencies]: normal wins
      '.|serde@1.0.203|direct|Cargo.lock|1.0',
      // renamed `json = { package = "serde_json" }`
      '.|serde_json@1.0.117|direct|Cargo.lock|1',
      '.|tempfile@3.10.1|dev|Cargo.lock|3',
      '.|winapi@0.3.9|direct|Cargo.lock|0.3',
    ]);
    const result = parseEcosystemCase('rust', 'rust', 'lock-v3');
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['Cargo.lock', 'Cargo.toml', 'helper/Cargo.toml']);
    expect(result.parse_errors).toEqual([]);
    expect(result.dependencies.find((d) => d.name === 'serde')?.purl).toBe('pkg:cargo/serde@1.0.203');
  });

  it('v4 workspace with the sparse index: members are covered by the root lock (no versionless duplicates), workspace = true resolved', () => {
    expect(brief(rows('lock-v4-workspace'))).toEqual([
      '.|anyhow@1.0.86|direct|Cargo.lock|1.0',
      '.|pin-project-lite@0.2.14|transitive|Cargo.lock|-',
      '.|proptest@1.4.0|dev|Cargo.lock|1.4',
      '.|regex@1.10.5|direct|Cargo.lock|1.10',
      '.|regex-syntax@0.8.4|transitive|Cargo.lock|-',
      '.|tokio@1.38.0|direct|Cargo.lock|1.38',
      // not a package of the root lock: its own Cargo.toml fallback; `log` is not in [workspace.dependencies]
      'examples/standalone|log@-|direct|Cargo.toml|-',
      'examples/standalone|serde@-|direct|Cargo.toml|1',
    ]);
    const result = parseEcosystemCase('rust', 'rust', 'lock-v4-workspace');
    expect(result.scan_files.map((f) => f.file_path)).toEqual([
      'Cargo.lock',
      'Cargo.toml',
      'crates/app/Cargo.toml',
      'crates/util/Cargo.toml',
      'examples/standalone/Cargo.toml',
    ]);
  });

  it('v1 ([root] + [metadata]) and v2 (no version key) are read; scope comes from the source-less packages', () => {
    expect(brief(rows('lock-v1-v2'))).toEqual([
      'v1|libc@0.2.20|direct|Cargo.lock|-',
      'v1|unused-transitive@0.1.0|transitive|Cargo.lock|-',
      'v2|aho-corasick@0.7.18|direct|Cargo.lock|-',
      'v2|memchr@2.4.1|transitive|Cargo.lock|-',
    ]);
  });
});

describe('REQ-011 P-40 / AC-P40-6: Cargo.toml fallback', () => {
  it('version null + declared_range; path/git/registry skipped; dev tables -> dev; target tables read; renames resolved', () => {
    expect(brief(rows('toml-fallback'))).toEqual([
      '.|both@-|direct|Cargo.toml|1.2',
      '.|cc@-|direct|Cargo.toml|1',
      '.|criterion@-|dev|Cargo.toml|0.5',
      // `workspace = true` without a workspace root: no requirement known
      '.|inherited@-|direct|Cargo.toml|-',
      '.|libc@-|direct|Cargo.toml|0.2',
      '.|log@-|direct|Cargo.toml|0.4',
      '.|nover@-|direct|Cargo.toml|-',
      '.|rand@-|direct|Cargo.toml|0.8.5',
      '.|real-crate@-|direct|Cargo.toml|=2.1.0',
      '.|windows-sys@-|dev|Cargo.toml|0.52',
      'ws/member|actual@-|direct|Cargo.toml|0.3',
      'ws/member|insta@-|dev|Cargo.toml|1.39',
      'ws/member|serde@-|direct|Cargo.toml|1.0.200',
    ]);
    const result = parseEcosystemCase('rust', 'rust', 'toml-fallback');
    expect(result.dependencies.every((d) => d.version === null && !d.purl.includes('@'))).toBe(true);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['Cargo.toml', 'ws/Cargo.toml', 'ws/member/Cargo.toml']);
  });
});

describe('REQ-011 AC-P40-3: broken Cargo files', () => {
  it('one fixed Turkish record per file; a broken lock falls back to Cargo.toml; other folders continue', () => {
    const result = parseEcosystemCase('rust', 'rust', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'rust', file: 'a-bad-lock/Cargo.lock', error: 'TOML ayrıştırılamadı.' },
      { ecosystem: 'rust', file: 'b-future-lock/Cargo.lock', error: 'Desteklenmeyen kilit dosyası sürümü.' },
      { ecosystem: 'rust', file: 'c-bad-toml/Cargo.toml', error: 'TOML ayrıştırılamadı.' },
      { ecosystem: 'rust', file: 'e-wrong-shape-toml/Cargo.toml', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'rust', file: 'f-wrong-shape-lock/Cargo.lock', error: 'Beklenmeyen dosya yapısı.' },
      { ecosystem: 'rust', file: 'd-invalid-entry/Cargo.lock', error: 'Geçersiz paket girdileri atlandı.' },
      { ecosystem: 'rust', file: 'g-ok/Cargo.toml', error: 'Geçersiz paket girdileri atlandı.' },
    ]);
    expect(brief(result.dependencies)).toEqual([
      'a-bad-lock|serde@-|direct|Cargo.toml|1',
      'd-invalid-entry|log@0.4.21|direct|Cargo.lock|-',
      'g-ok|itoa@-|direct|Cargo.toml|1',
    ]);
    for (const e of result.parse_errors) expect(e.error).not.toMatch(/serde|oops|[\\/:]/);
  });
});
