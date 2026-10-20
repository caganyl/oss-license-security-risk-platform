/**
 * REQ-011 P-39 — missing Node.js formats (AC-P39-1, AC-P39-2, AC-P39-3, AC-P40-3, D-306).
 *
 * Goldens: `tests/fixtures/nodejs-extra/cases/<case>` -> `expected/<case>.json`
 * (exact `parseManifests(<case>, ['nodejs'])` output, byte comparison through
 * `helpers/ecosystemGolden.ts`). The semantic checks below pin the rules the
 * goldens encode, so a golden cannot be regenerated into a wrong behaviour.
 * The F4 npm/yarn behaviour is pinned by the P-10 goldens (AC-G-1).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseManifests } from '../../src/scanner/parsers';
import { PARSER_MESSAGES } from '../../src/scanner/parsers/kit';
import { IntegrityCollector } from '../../src/scanner/parsers/lockIntegrityValue';
import type { SandboxScanResult, ScannedDependency } from '../../src/types/scan';
import { ecosystemCaseDir, expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const FIXTURE = 'nodejs-extra';
const CASES = ['pnpm-v6', 'pnpm-v9', 'bun-lock', 'bun-lockb', 'priority', 'broken'];

const run = (caseName: string): SandboxScanResult => parseEcosystemCase(FIXTURE, 'nodejs', caseName);
const pick = (deps: ScannedDependency[]) =>
  deps
    .map((d) => [d.name, d.version, d.scope, d.manifest_file, d.declared_range ?? null] as const)
    .sort((a, b) => (a[0] !== b[0] ? (a[0] < b[0] ? -1 : 1) : String(a[1]) < String(b[1]) ? -1 : 1));

describe('REQ-011 P-39: Node.js format goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden(FIXTURE, 'nodejs', c));
});

describe('AC-P39-1: pnpm-lock.yaml', () => {
  it('v6: exact versions, peer suffix dropped, importer scopes and specifiers, dev/optional flags, path-form keys, git and link packages', () => {
    const r = run('pnpm-v6');
    expect(r.parse_errors).toEqual([]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['package.json', 'pnpm-lock.yaml']);
    expect(pick(r.dependencies)).toEqual([
      ['@acme/path-form', '2.0.0', 'dev', 'pnpm-lock.yaml', null],
      ['@babel/runtime', '7.23.2', 'direct', 'pnpm-lock.yaml', '^7.23.0'],
      ['from-git', null, 'direct', 'pnpm-lock.yaml', 'github:acme/from-git'],
      ['fsevents', '2.3.3', 'optional', 'pnpm-lock.yaml', '^2.3.3'],
      ['js-tokens', '4.0.0', 'transitive', 'pnpm-lock.yaml', null],
      ['loose-envify', '1.4.0', 'transitive', 'pnpm-lock.yaml', null],
      ['old-style', '1.0.0', 'dev', 'pnpm-lock.yaml', null],
      ['react', '18.2.0', 'direct', 'pnpm-lock.yaml', '^18.2.0'],
      ['react-dom', '18.2.0', 'direct', 'pnpm-lock.yaml', '^18.2.0'],
      ['regenerator-runtime', '0.14.0', 'transitive', 'pnpm-lock.yaml', null],
      ['scheduler', '0.23.0', 'transitive', 'pnpm-lock.yaml', null],
      ['typescript', '5.2.2', 'dev', 'pnpm-lock.yaml', '~5.2.2'],
    ]);
    const purls = new Map(r.dependencies.map((d) => [d.name, d.purl]));
    expect(purls.get('@babel/runtime')).toBe('pkg:npm/@babel/runtime@7.23.2');
    expect(purls.get('react-dom')).toBe('pkg:npm/react-dom@18.2.0');
    expect(purls.get('from-git')).toBe('pkg:npm/from-git');
  });

  it('v9: importers + packages + snapshots; direct/dev from the root importer, dev-only packages through the snapshot graph, aliases, workspace links skipped', () => {
    const r = run('pnpm-v9');
    expect(r.parse_errors).toEqual([]);
    expect(pick(r.dependencies)).toEqual([
      ['@types/node', '20.14.2', 'dev', 'pnpm-lock.yaml', '^20.14.2'],
      ['ansi-regex', '5.0.1', 'transitive', 'pnpm-lock.yaml', null],
      ['debug', '2.6.9', 'transitive', 'pnpm-lock.yaml', null],
      ['express', '4.19.2', 'direct', 'pnpm-lock.yaml', '^4.19.2'],
      ['js-tokens', '4.0.0', 'transitive', 'pnpm-lock.yaml', null],
      ['loose-envify', '1.4.0', 'transitive', 'pnpm-lock.yaml', null],
      ['ms', '2.0.0', 'transitive', 'pnpm-lock.yaml', null],
      // react: a production dependency of the packages/ui importer, not of the root.
      ['react', '18.3.1', 'transitive', 'pnpm-lock.yaml', null],
      // shared-util: reached from express (production) and vitest (dev) -> not dev-only.
      ['shared-util', '1.0.0', 'transitive', 'pnpm-lock.yaml', null],
      ['string-width', '4.2.3', 'direct', 'pnpm-lock.yaml', 'npm:string-width@^4.2.0'],
      ['strip-ansi', '6.0.1', 'transitive', 'pnpm-lock.yaml', null],
      ['tinypool', '0.8.4', 'dev', 'pnpm-lock.yaml', null],
      ['undici-types', '5.26.5', 'dev', 'pnpm-lock.yaml', null],
      ['vitest', '1.6.0', 'dev', 'pnpm-lock.yaml', '^1.6.0'],
    ]);
    expect(r.dependencies.find((d) => d.name === '@types/node')?.purl).toBe('pkg:npm/@types/node@20.14.2');
    expect(r.dependencies.some((d) => d.name === '@acme/ui')).toBe(false);
  });
});

describe('AC-P39-2: bun.lock and bun.lockb', () => {
  it('bun.lock (JSONC: comments, trailing commas, // inside strings): root workspace scopes by top-level key, nested keys transitive, workspace packages skipped', () => {
    const r = run('bun-lock');
    expect(r.parse_errors).toEqual([]);
    expect(pick(r.dependencies)).toEqual([
      ['@types/bun', '1.1.4', 'dev', 'bun.lock', '^1.1.4'],
      ['@types/node', '20.12.14', 'transitive', 'bun.lock', null],
      ['bun-types', '1.1.13', 'transitive', 'bun.lock', null],
      ['fsevents', '2.3.3', 'optional', 'bun.lock', '^2.3.3'],
      ['hono', '4.4.6', 'direct', 'bun.lock', '^4.4.0'],
      ['my-fork', null, 'transitive', 'bun.lock', 'github:acme/my-fork#0123abc'],
      ['react', '18.3.1', 'peer', 'bun.lock', '>=18'],
      ['typescript', '5.4.5', 'dev', 'bun.lock', '^5.4.5'],
      ['undici-types', '5.26.5', 'transitive', 'bun.lock', null],
      ['zod', '3.22.4', 'transitive', 'bun.lock', null],
      ['zod', '3.23.8', 'direct', 'bun.lock', '^3.23.8'],
    ]);
  });

  it('bun.lockb is never read: one "unsupported format" record and package.json alone (no scan_files record for it)', () => {
    const r = run('bun-lockb');
    expect(r.parse_errors).toEqual([{ ecosystem: 'nodejs', file: 'bun.lockb', error: PARSER_MESSAGES.unsupportedFormat }]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual(['package.json']);
    expect(pick(r.dependencies)).toEqual([
      ['hono', null, 'direct', 'package.json', '^4.4.0'],
      ['typescript', '5.4.5', 'dev', 'package.json', '5.4.5'],
    ]);
  });

  it('JSONC cleanup is linear: a 4 MiB bun.lock of whitespace runs and comment markers inside strings parses quickly', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'p39-bun-'));
    try {
      fs.writeFileSync(path.join(root, 'package.json'), '{}');
      const filler = `"${'/*//'.repeat(500_000)}"`;
      const text = `{"lockfileVersion": 1, "x": ${filler},${' '.repeat(1_000_000)}${',\n'.repeat(1)} "packages": {"a": ["a@1.0.0"],${' \n'.repeat(500_000)}}}`;
      fs.writeFileSync(path.join(root, 'bun.lock'), text);
      const started = Date.now();
      const r = parseManifests(root, ['nodejs'], 'linear');
      expect(Date.now() - started).toBeLessThan(5_000);
      // `,` followed by spaces and `,` is not a trailing comma: the text stays invalid JSON (fixed record, no crash).
      expect(r.parse_errors).toEqual([{ ecosystem: 'nodejs', file: 'bun.lock', error: PARSER_MESSAGES.json }]);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('L-5 side channel (ADR-007 Karar 12) for the new lock formats', () => {
  it('pnpm `resolution.integrity` and bun entry hashes reach the collector; dependency objects get no integrity field; a broken lock adds nothing', () => {
    const pnpm = new IntegrityCollector();
    const r = parseManifests(ecosystemCaseDir(FIXTURE, 'pnpm-v9'), ['nodejs'], 'l5', { integrityCollector: pnpm });
    expect(pnpm.records.find((x) => x.name === 'express')).toEqual({
      manifestPath: '.',
      name: 'express',
      version: '4.19.2',
      integrity: 'sha512-5T6nhjsT+EOMzuck8JjBHARTHfMht0POzlA60WV2pMD3gyXw2LZnZ+ueGdNxG+0calOJcWKbpFcuzLZ91YWq9Q==',
    });
    expect(pnpm.records).toHaveLength(r.dependencies.length);
    expect(r.dependencies.some((d) => Object.prototype.hasOwnProperty.call(d, 'integrity'))).toBe(false);

    const bun = new IntegrityCollector();
    parseManifests(ecosystemCaseDir(FIXTURE, 'bun-lock'), ['nodejs'], 'l5', { integrityCollector: bun });
    expect(bun.records.find((x) => x.name === 'hono')?.integrity).toBe('sha512-aG9ubw==');
    // my-fork has no exact version; its third element is not an integrity value.
    expect(bun.records.some((x) => x.name === 'my-fork')).toBe(false);

    const broken = new IntegrityCollector();
    parseManifests(ecosystemCaseDir(FIXTURE, 'broken'), ['nodejs'], 'l5', { integrityCollector: broken });
    expect(broken.records.map((x) => x.manifestPath).sort()).toEqual(['pnpm-invalid-entry', 'z-healthy']);
  });
});

describe('AC-P39-3 / D-306: one Node lock file per folder', () => {
  it('package-lock.json > pnpm-lock.yaml > yarn.lock > bun.lock; unused locks stay out of scan_files; lock files without package.json are ignored', () => {
    const r = run('priority');
    expect(r.parse_errors).toEqual([]);
    expect(r.scan_files.map((f) => f.file_path)).toEqual([
      'a-all-four/package.json',
      'a-all-four/package-lock.json',
      // F4 pair kept as frozen (golden npm-lock-and-yarn, AC-G-1): package-lock.json and yarn.lock are both read.
      'a-all-four/yarn.lock',
      'b-pnpm-yarn-bun/package.json',
      'b-pnpm-yarn-bun/pnpm-lock.yaml',
      'c-yarn-bun/package.json',
      'c-yarn-bun/yarn.lock',
      'd-bun-text-and-binary/package.json',
      'd-bun-text-and-binary/bun.lock',
    ]);
    expect(r.dependencies.map((d) => [d.manifest_path, d.manifest_file, d.version])).toEqual([
      ['a-all-four', 'package-lock.json', '1.3.0'],
      ['a-all-four', 'yarn.lock', '1.2.0'],
      ['b-pnpm-yarn-bun', 'pnpm-lock.yaml', '1.1.0'],
      ['c-yarn-bun', 'yarn.lock', '1.2.0'],
      ['d-bun-text-and-binary', 'bun.lock', '1.0.0'],
    ]);
  });
});

describe('AC-P40-3: broken new-format lock files', () => {
  it('one fixed Turkish record per broken file (no path, no library text), package.json fallback, the other folders are still scanned', () => {
    const r = run('broken');
    expect(r.parse_errors).toEqual([
      { ecosystem: 'nodejs', file: 'bun-json/bun.lock', error: PARSER_MESSAGES.json },
      { ecosystem: 'nodejs', file: 'bun-open-comment/bun.lock', error: PARSER_MESSAGES.json },
      { ecosystem: 'nodejs', file: 'bun-structure/bun.lock', error: PARSER_MESSAGES.structure },
      { ecosystem: 'nodejs', file: 'bun-version/bun.lock', error: PARSER_MESSAGES.unsupportedVersion },
      { ecosystem: 'nodejs', file: 'pnpm-anchor/pnpm-lock.yaml', error: PARSER_MESSAGES.yamlUnsupported },
      { ecosystem: 'nodejs', file: 'pnpm-invalid-entry/pnpm-lock.yaml', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'nodejs', file: 'pnpm-not-utf8/pnpm-lock.yaml', error: 'Dosya geçerli UTF-8 değil.' },
      { ecosystem: 'nodejs', file: 'pnpm-syntax/pnpm-lock.yaml', error: PARSER_MESSAGES.yaml },
      { ecosystem: 'nodejs', file: 'pnpm-v5/pnpm-lock.yaml', error: PARSER_MESSAGES.unsupportedVersion },
    ]);
    const byFolder = new Map(r.dependencies.map((d) => [d.manifest_path, [d.manifest_file, d.version]]));
    for (const folder of ['bun-json', 'bun-open-comment', 'bun-structure', 'bun-version', 'pnpm-anchor', 'pnpm-not-utf8', 'pnpm-syntax', 'pnpm-v5']) {
      expect(byFolder.get(folder), folder).toEqual(['package.json', null]);
    }
    expect(byFolder.get('pnpm-invalid-entry')).toEqual(['pnpm-lock.yaml', '1.3.0']);
    expect(byFolder.get('z-healthy')).toEqual(['bun.lock', '1.3.0']);
    // A broken lock is not listed in scan_files; an invalid entry does not discard the file.
    const files = r.scan_files.map((f) => f.file_path);
    expect(files).not.toContain('pnpm-syntax/pnpm-lock.yaml');
    expect(files).toContain('pnpm-invalid-entry/pnpm-lock.yaml');
  });

  it('records are not written when the nodejs ecosystem is not requested (spec files are opt-in, D-304)', () => {
    const r = parseManifests(ecosystemCaseDir(FIXTURE, 'broken'), ['python'], 'x');
    expect(r.parse_errors).toEqual([]);
    expect(r.dependencies).toEqual([]);
  });
});
