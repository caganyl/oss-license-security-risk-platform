/**
 * REQ-002 · P-08 · AC-P08-1, AC-P08-2 (determinism), D-1
 * ADR-003 (c): the TypeScript fingerprint must be byte-identical to the SQL
 * backfill in db/migrations/004_finding_fingerprint.up.sql. The reference
 * values are read from the `_expected_fp` table in
 * db/tests/f1_migrations_test.sql (single source, verified against SQL by
 * tests/integration/migrations.test.ts).
 */
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { loadSrc, readRepoFile } from '../helpers/loadSrc';
import type { FingerprintInput, FingerprintModule } from '../helpers/contracts';

const P1 = '11111111-1111-1111-1111-111111111111';
const P2 = '22222222-2222-2222-2222-222222222222';

function loadExpected(): Map<string, string> {
  const sql = readRepoFile('db/tests/f1_migrations_test.sql');
  const rows = new Map<string, string>();
  const re = /\('(f\d+)',\s*'[0-9a-f-]{36}',\s*'([0-9a-f]{64})'/g;
  for (let m = re.exec(sql); m; m = re.exec(sql)) rows.set(m[1], m[2]);
  return rows;
}

const sha256 = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/** Fixture rows of f1_migrations_test.sql in their post-003 state. */
const INPUTS: Record<string, { input: FingerprintInput; canonical: string }> = {
  f1: {
    input: { projectId: P1, purl: 'pkg:npm/lodash@4.17.21', version: '4.17.21', findingType: 'license', normalizedLicense: 'MIT' },
    canonical: `v1|${P1}|pkg:npm/lodash|license|mit`,
  },
  f2: {
    input: {
      projectId: P1, purl: 'pkg:npm/lodash@4.17.21', version: '4.17.21', findingType: 'security',
      vulnerability: { id: 'c0000000-0000-4000-8000-000000000001', osvId: null, ghsaId: 'ghsa-abcd-efgh-ijkl', cveId: 'CVE-2020-0001' },
    },
    canonical: `v1|${P1}|pkg:npm/lodash@4.17.21|security|GHSA-ABCD-EFGH-IJKL`,
  },
  f3: {
    input: { projectId: P1, purl: 'pkg:npm/@Scope/Pkg', version: null, findingType: 'license', normalizedLicense: null },
    canonical: `v1|${P1}|pkg:npm/@scope/pkg|license|noassertion`,
  },
  f4: {
    input: {
      projectId: P1, purl: 'pkg:npm/@Scope/Pkg', version: null, findingType: 'security',
      vulnerability: { id: 'c0000000-0000-4000-8000-000000000002', osvId: null, ghsaId: null, cveId: 'cve-2021-0001' },
    },
    canonical: `v1|${P1}|pkg:npm/@scope/pkg|security|CVE-2021-0001`,
  },
  f5: {
    input: { projectId: P1, purl: 'pkg:pypi/django.rest-framework', version: null, findingType: 'license', normalizedLicense: 'BSD-3-Clause' },
    canonical: `v1|${P1}|pkg:pypi/django-rest-framework|license|bsd-3-clause`,
  },
  f6: {
    input: {
      projectId: P1, purl: 'pkg:pypi/requests@2.31.0?repository_url=https://pypi.example/simple#src/sub', version: '2.31.0',
      findingType: 'security', vulnerability: { id: 'abcdef00-0000-4000-8000-000000000003', osvId: null, ghsaId: null, cveId: null },
    },
    canonical: `v1|${P1}|pkg:pypi/requests@2.31.0|security|ABCDEF00-0000-4000-8000-000000000003`,
  },
  f7: {
    input: {
      projectId: P1, purl: 'pkg:npm/weird@1.0.0%7Cbeta', version: '1.0.0|beta', findingType: 'security',
      vulnerability: { id: 'c0000000-0000-4000-8000-000000000004', osvId: 'OSV-2024-0001', ghsaId: 'GHSA-zzzz-zzzz-zzzz', cveId: null },
    },
    canonical: `v1|${P1}|pkg:npm/weird@1.0.0%7Cbeta|security|OSV-2024-0001`,
  },
  f8: {
    input: {
      projectId: P1, purl: 'pkg:maven/Org.Group/Art@1.0', version: ' 1.0 ', findingType: 'security',
      vulnerability: { id: 'c0000000-0000-4000-8000-000000000005', osvId: 'osv-x-1', ghsaId: null, cveId: null },
    },
    canonical: `v1|${P1}|pkg:maven/org.group/art@1.0|security|OSV-X-1`,
  },
  f9: {
    input: { projectId: P2, purl: 'pkg:npm/lodash@4.17.21', version: '4.17.21', findingType: 'license', normalizedLicense: 'MIT' },
    canonical: `v1|${P2}|pkg:npm/lodash|license|mit`,
  },
  f10: {
    input: { projectId: P1, purl: 'pkg:npm/lodash@4.17.21', version: '4.17.21', findingType: 'license', normalizedLicense: 'MIT' },
    canonical: `v1|${P1}|pkg:npm/lodash|license|mit`,
  },
  f11: {
    input: { projectId: P1, purl: 'pkg:pypi/foo-bar', version: null, findingType: 'license', normalizedLicense: 'GPL-3.0-only' },
    canonical: `v1|${P1}|pkg:pypi/foo-bar|license|gpl-3.0-only`,
  },
  f12: {
    input: { projectId: P1, purl: 'pkg:npm/@Scope/Pkg', version: null, findingType: 'license', normalizedLicense: null },
    canonical: `v1|${P1}|pkg:npm/@scope/pkg|license|noassertion`,
  },
};

const loadFingerprint = () =>
  loadSrc<FingerprintModule>('src/analysis/findingFingerprint.ts', ['computeFindingFingerprint']);

describe('P-08 finding fingerprint (TS <-> SQL equality, ADR-003 c)', () => {
  const expected = loadExpected();

  it('fixture self-check: the SQL reference table matches the ADR-003 formula applied to the canonical strings', () => {
    expect([...expected.keys()].sort()).toEqual(Object.keys(INPUTS).sort());
    for (const [label, { canonical }] of Object.entries(INPUTS)) {
      expect(sha256(canonical), label).toBe(expected.get(label));
    }
  });

  it.each(Object.keys(INPUTS))('AC-P08-1: computeFindingFingerprint(%s) equals the SQL backfill value', async (label) => {
    const { computeFindingFingerprint } = await loadFingerprint();
    expect(computeFindingFingerprint(INPUTS[label].input)).toBe(expected.get(label));
  });

  it('AC-P08-1: license fingerprint is versionless (same package, new version -> same fingerprint)', async () => {
    const { computeFindingFingerprint } = await loadFingerprint();
    const base = { projectId: P1, findingType: 'license' as const, normalizedLicense: 'GPL-3.0-only' };
    expect(computeFindingFingerprint({ ...base, purl: 'pkg:npm/foo@1.0.0', version: '1.0.0' })).toBe(
      computeFindingFingerprint({ ...base, purl: 'pkg:npm/foo@1.1.0', version: '1.1.0' }),
    );
  });

  it('AC-P08-1: security fingerprint is versioned (same CVE, new version -> different fingerprint)', async () => {
    const { computeFindingFingerprint } = await loadFingerprint();
    const vulnerability = { id: 'c0000000-0000-4000-8000-0000000000aa', cveId: 'CVE-2099-0001' };
    const base = { projectId: P1, findingType: 'security' as const, vulnerability };
    expect(computeFindingFingerprint({ ...base, purl: 'pkg:npm/foo@1.0.0', version: '1.0.0' })).not.toBe(
      computeFindingFingerprint({ ...base, purl: 'pkg:npm/foo@1.1.0', version: '1.1.0' }),
    );
  });

  it('AC-P08-2: deterministic, 64 lowercase hex, project id case-insensitive', async () => {
    const { computeFindingFingerprint } = await loadFingerprint();
    const input = INPUTS.f1.input;
    const a = computeFindingFingerprint(input);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(computeFindingFingerprint({ ...input })).toBe(a);
    expect(computeFindingFingerprint({ ...input, projectId: P1.toUpperCase() })).toBe(a);
  });
});
