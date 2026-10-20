/**
 * REQ-011 AC-P40-1 golden helper for the new ecosystem parsers (one per
 * ecosystem, written by the phase-2 parser owners).
 *
 * Layout per ecosystem (`<eco>` = the parser file name: java, golang, php,
 * rust, ruby, dart, swift):
 *
 *     tests/fixtures/<eco>/cases/<case>/...      fixture tree (bytes kept: `* -text`)
 *     tests/fixtures/<eco>/expected/<case>.json  golden
 *
 * A golden is the exact `parseManifests(<case dir>, [<ecosystem>],
 * 'golden-<eco>-<case>')` result serialised as `JSON.stringify(value, null, 2)
 * + '\n'` and compared byte for byte (dependencies with name, version, scope,
 * purl, manifest_file, manifest_path, declared_range, licenses; scan_files
 * with hashes; parse_errors texts). `UPDATE_ECOSYSTEM_GOLDENS=1` rewrites the
 * files (only for an intentional, reviewed change).
 *
 * Usage in `tests/unit/parser-<eco>.test.ts`:
 *
 *     import { describe, it } from 'vitest';
 *     import { expectEcosystemGolden } from '../helpers/ecosystemGolden';
 *     describe('AC-P40-1: Go goldens', () => {
 *       for (const c of ['go-mod-basic', 'replace-local', 'broken']) it(c, () => expectEcosystemGolden('golang', 'go', c));
 *     });
 */
import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import type { SandboxScanResult } from '../../src/types/scan';
import { FIXTURES_DIR } from './paths';

export const UPDATE_ECOSYSTEM_GOLDENS = process.env.UPDATE_ECOSYSTEM_GOLDENS === '1';

export function ecosystemCaseDir(fixtureDir: string, caseName: string): string {
  return path.join(FIXTURES_DIR, fixtureDir, 'cases', caseName);
}

export function ecosystemGoldenFile(fixtureDir: string, caseName: string): string {
  return path.join(FIXTURES_DIR, fixtureDir, 'expected', `${caseName}.json`);
}

/** Parse result of one fixture case for exactly one ecosystem. */
export function parseEcosystemCase(fixtureDir: string, ecosystem: string, caseName: string): SandboxScanResult {
  return parseManifests(ecosystemCaseDir(fixtureDir, caseName), [ecosystem], `golden-${fixtureDir}-${caseName}`);
}

export function ecosystemGoldenText(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** Byte comparison of a case result with its golden (rewritten first with `UPDATE_ECOSYSTEM_GOLDENS=1`). */
export function expectEcosystemGolden(fixtureDir: string, ecosystem: string, caseName: string): SandboxScanResult {
  const result = parseEcosystemCase(fixtureDir, ecosystem, caseName);
  const actual = ecosystemGoldenText(result);
  const file = ecosystemGoldenFile(fixtureDir, caseName);
  if (UPDATE_ECOSYSTEM_GOLDENS) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, actual);
  }
  expect(fs.existsSync(file), `${fixtureDir}/${caseName}: golden file is missing`).toBe(true);
  expect(fs.readFileSync(file, 'utf8')).toBe(actual);
  return result;
}
