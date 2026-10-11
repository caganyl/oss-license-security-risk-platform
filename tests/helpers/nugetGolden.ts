/**
 * REQ-006 · P-20 NuGet golden helpers (AC-P20-11, AC-P20-12; ADR-008 golden strategy).
 *
 * A NuGet golden is the exact `parseManifests(root, ['dotnet'], scanId)`
 * result serialised as `JSON.stringify(value, null, 2) + '\n'` and compared
 * byte for byte (order, keys, file hashes and error texts are all frozen
 * with F5). Fixture bytes are protected by `tests/fixtures/.gitattributes`
 * (`-text`), so `file_hash` is stable on every platform.
 */
import path from 'node:path';
import { parseManifests } from '../../src/scanner/parsers';
import type { SandboxScanResult } from '../../src/types/scan';
import { REPO_ROOT } from './paths';

export const DOTNET_FIXTURES = path.join(REPO_ROOT, 'tests', 'fixtures', 'dotnet');
export const DOTNET_CASES_DIR = path.join(DOTNET_FIXTURES, 'cases');
export const DOTNET_EXPECTED_DIR = path.join(DOTNET_FIXTURES, 'expected');
export const SAMPLE_SOLUTION = path.join(DOTNET_FIXTURES, 'sample-solution');

/** One golden per source kind (AC-P20-12). */
export const NUGET_GOLDEN_CASES = ['lock-v1', 'lock-v2', 'assets-v3', 'project-cpm', 'packages-config', 'broken'] as const;

export const nugetScanId = (name: string): string => `nuget-golden-${name}`;

export function goldenText(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function parseDotnet(rootDir: string, scanId: string): SandboxScanResult {
  return parseManifests(rootDir, ['dotnet'], scanId);
}

export interface FolderSummary {
  direct: number;
  transitive: number;
  transitivePurls: string[];
}

/** Per project folder `direct`/`transitive` counts and the transitive purls (AC-P20-11 golden content). */
export function folderSummary(result: SandboxScanResult): Record<string, FolderSummary> {
  const out: Record<string, FolderSummary> = {};
  for (const dep of result.dependencies) {
    const entry = (out[dep.manifest_path] ??= { direct: 0, transitive: 0, transitivePurls: [] });
    if (dep.scope === 'direct') entry.direct++;
    else if (dep.scope === 'transitive') {
      entry.transitive++;
      entry.transitivePurls.push(dep.purl);
    } else throw new Error(`unexpected NuGet scope ${String(dep.scope)}`);
  }
  return out;
}

/** Golden value of the sample solution: summary first, then the full result. */
export function sampleGoldenValue(): { summary: Record<string, FolderSummary>; result: SandboxScanResult } {
  const result = parseDotnet(SAMPLE_SOLUTION, nugetScanId('sample-solution'));
  return { summary: folderSummary(result), result };
}
