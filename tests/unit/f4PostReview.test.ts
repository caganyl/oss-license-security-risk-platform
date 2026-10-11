/**
 * REQ-005 contract 1.1.0 post-review fixes, pure modules (no I/O):
 *   P-1  local CVSS v3.0/v3.1 base score (section 3.5.3, `src/vulnerability/cvss3.ts`)
 *   L-1  strict RFC 3339 dates and 0–10 scores (section 3.5.2, `src/vulnerability/validate.ts`)
 *   L-2  the single fail-closed on/off switch parser (section 7.1, `parseSwitch`)
 * The recorded NVD pairs below are public NVD base scores of well-known CVEs
 * (offline table; no network). Pairs whose NVD score was not certain were left out.
 */
import { describe, expect, it } from 'vitest';
import { cvss3BaseScore, roundUp } from '../../src/vulnerability/cvss3';
import { normalizeRfc3339, validCvssScore } from '../../src/vulnerability/validate';
import { extractCvss, normalizeOsvVulnerability, type OsvVulnerability } from '../../src/vulnerability/normalize';
import { extractNvdCvss } from '../../src/vulnerability/nvdClient';
import { trimOsvRecord } from '../../src/vulnerability/osvClient';
import {
  enrichmentConfigFrom,
  parseEnrichmentSwitch,
  parseSwitch,
  vulnerabilityConfigFrom,
} from '../../src/scanner/sandbox/runner.config';

// ---------------------------------------------------------------------------
// P-1
// ---------------------------------------------------------------------------
describe('P-1 / contract 1.1.0 section 3.5.3: local CVSS v3 base score', () => {
  const KNOWN: Array<[string, number, '3.0' | '3.1']> = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, '3.1'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, '3.1'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, '3.1'],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4, '3.1'],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, '3.1'],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9, '3.1'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3, '3.1'],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5, '3.0'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, '3.1'],
  ];

  it.each(KNOWN)('P-1 known vector %s -> %d', (vector, score, version) => {
    expect(cvss3BaseScore(vector)).toEqual({ score, version });
  });

  /** Recorded NVD base scores (cve, vector, NVD score). */
  const NVD_RECORDED: Array<[string, string, number]> = [
    ['CVE-2021-44228', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVE-2020-1472', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVE-2021-45046', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', 9.0],
    ['CVE-2021-45105', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', 5.9],
    ['CVE-2014-0160', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
    ['CVE-2014-6271', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVE-2014-3566', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N', 3.4],
    ['CVE-2017-0144', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.1],
    ['CVE-2019-0708', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVE-2021-34527', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVE-2016-5195', 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVE-2022-0847', 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVE-2021-3156', 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVE-2022-21449', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 7.5],
    ['CVE-2023-44487', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVE-2021-23337', 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2],
    ['CVE-2021-23358', 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2],
    ['CVE-2020-8203', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', 7.4],
    ['CVE-2019-10744', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', 9.1],
    ['CVE-2020-28500', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', 5.3],
    ['CVE-2021-44906', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVE-2021-3749', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVE-2022-0155', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N', 6.5],
    ['CVE-2018-3721', 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N', 6.5],
    ['CVE-2019-11358', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
  ];

  it(`P-1: ${NVD_RECORDED.length} recorded NVD vector/score pairs match the local score`, () => {
    expect(NVD_RECORDED.length).toBeGreaterThanOrEqual(20);
    const mismatches = NVD_RECORDED.filter(([, v, s]) => cvss3BaseScore(v)?.score !== s).map(([c, v, s]) => `${c} ${v}: NVD ${s}, local ${String(cvss3BaseScore(v)?.score)}`);
    expect(mismatches).toEqual([]);
  });

  it('P-1: metric order does not matter', () => {
    expect(cvss3BaseScore('CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N')).toEqual({ score: 9.8, version: '3.1' });
  });

  it('P-1: temporal and environmental metrics are accepted and ignored for the base score', () => {
    const base = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    for (const suffix of ['/E:P/RL:O/RC:C', '/E:U/RL:W/RC:U', '/CR:H/IR:L/AR:M/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N', '/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X']) {
      expect(cvss3BaseScore(base + suffix), suffix).toEqual({ score: 9.8, version: '3.1' });
    }
  });

  it('P-1: invalid vectors -> null (missing, duplicate, unknown metric, invalid value, prefix, > 256 chars)', () => {
    const invalid = [
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', // missing A
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:H', // duplicate base metric
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/E:P', // duplicate temporal metric
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y', // unknown metric
      'CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // invalid value
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Z', // invalid temporal value
      'CVSS:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h', // lower case
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/', // trailing slash
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A', // no colon
      'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // no prefix
      'CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      'AV:N/AC:L/Au:N/C:P/I:P/A:P', // CVSS v2
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/__proto__:X',
      `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/${'E:X/'.repeat(60)}E:X`, // > 256 chars
      '',
    ];
    for (const v of invalid) expect(cvss3BaseScore(v), v.slice(0, 80)).toBeNull();
    expect(`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/${'E:X/'.repeat(60)}E:X`.length).toBeGreaterThan(256);
    expect(cvss3BaseScore(42 as unknown as string)).toBeNull();
  });

  it('P-1: roundUp follows CVSS v3.1 Appendix A', () => {
    expect(roundUp(4.02)).toBe(4.1);
    expect(roundUp(4.0)).toBe(4.0);
    expect(roundUp(4.000001)).toBe(4.0);
    expect(roundUp(9.76)).toBe(9.8);
  });

  it('P-1 / section 3.5.3 step order: numeric score wins, else first valid CVSS_V3 vector -> source osv_vector, else null', () => {
    expect(extractCvss([{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }])).toMatchObject({ score: 9.8, version: '3.1', source: 'osv_vector' });
    expect(extractCvss([{ type: 'CVSS_V3', score: '7.1' }])).toMatchObject({ score: 7.1, source: 'osv_score' });
    expect(
      extractCvss([
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:H' },
        { type: 'CVSS_V3', score: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' },
      ]),
    ).toMatchObject({ score: 7.5, version: '3.0', source: 'osv_vector' });
    expect(extractCvss([{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }])).toMatchObject({ score: null, source: null });
    expect(extractCvss([{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }])).toMatchObject({ score: null, source: null });
    expect(extractCvss([])).toEqual({ score: null, vector: null, version: null, source: null });
  });

  it('P-1: normalizeOsvVulnerability with a vector-only record records advisory_data.cvss.source = osv_vector', () => {
    const v = normalizeOsvVulnerability(
      { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-0001'], severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }] } as OsvVulnerability,
      { ecosystem: 'nodejs', name: 'a' },
    );
    expect(v).toMatchObject({ cvssScore: 7.8, cvssVersion: '3.1', severity: 'high' });
    expect((v.advisoryData as { cvss?: { source: string } }).cvss?.source).toBe('osv_vector');
  });
});

// ---------------------------------------------------------------------------
// L-1
// ---------------------------------------------------------------------------
describe('L-1 / contract 1.1.0 section 3.5.2: strict RFC 3339 dates and 0–10 scores', () => {
  it('L-1: valid RFC 3339 values normalize to toISOString (UTC, milliseconds)', () => {
    const cases: Array<[string, string]> = [
      ['2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000Z'],
      ['2026-01-01T03:00:00+03:00', '2026-01-01T00:00:00.000Z'],
      ['2025-12-31T22:30:00-01:30', '2026-01-01T00:00:00.000Z'],
      ['2026-05-06T07:08:09.123456789Z', '2026-05-06T07:08:09.123Z'],
      ['2026-05-06T07:08:09.1Z', '2026-05-06T07:08:09.100Z'],
      ['2024-02-29T12:00:00Z', '2024-02-29T12:00:00.000Z'],
      ['2000-02-29T00:00:00Z', '2000-02-29T00:00:00.000Z'],
      ['0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000Z'],
      ['9999-12-31T23:59:59Z', '9999-12-31T23:59:59.000Z'],
      ['2026-01-01T00:00:00+23:59', '2025-12-31T00:01:00.000Z'],
    ];
    for (const [input, expected] of cases) expect(normalizeRfc3339(input), input).toBe(expected);
  });

  it('L-1: calendar, clock, offset, case, form and year bounds -> null', () => {
    const invalid: unknown[] = [
      '2023-02-29T00:00:00Z', // not a leap year
      '1900-02-29T00:00:00Z', // century, not a leap year
      '2026-04-31T00:00:00Z',
      '2026-13-01T00:00:00Z',
      '2026-00-10T00:00:00Z',
      '2026-01-00T00:00:00Z',
      '2026-01-32T00:00:00Z',
      '2026-01-01T24:00:00Z',
      '2026-01-01T23:60:00Z',
      '2026-01-01T23:59:60Z', // leap second not accepted
      '2026-01-01T00:00:00+24:00',
      '2026-01-01T00:00:00+23:60',
      '2026-01-01t00:00:00Z',
      '2026-01-01T00:00:00z',
      '2026-01-01 00:00:00Z',
      '2026-01-01',
      '2026-01-01T00:00:00', // no offset
      '2026-01-01T00:00Z',
      '2026-01-01T00:00:00.Z',
      '2026-01-01T00:00:00.1234567890Z', // 10 fraction digits
      '+002026-01-01T00:00:00Z',
      '0000-01-01T00:00:00Z',
      '0001-01-01T00:00:00+01:00', // normalizes into year 0
      '9999-12-31T23:59:59-01:00', // normalizes into year 10000
      ` 2026-01-01T00:00:00Z`,
      `2026-01-01T00:00:00Z${' '.repeat(60)}`, // > 64 chars
      'Mon, 01 Jan 2026 00:00:00 GMT',
      1767225600000,
      null,
      undefined,
      {},
    ];
    for (const v of invalid) expect(normalizeRfc3339(v), JSON.stringify(v)).toBeNull();
  });

  it('L-1: validCvssScore accepts only finite 0–10 numbers', () => {
    for (const ok of [0, 0.1, 5, 9.8, 10]) expect(validCvssScore(ok)).toBe(ok);
    for (const bad of [-0.1, 10.1, 11, -5, NaN, Infinity, -Infinity, '9.8', null, undefined]) expect(validCvssScore(bad), String(bad)).toBeNull();
  });

  it('L-1: OSV scores outside 0–10 / NaN are ignored (step 2 vector or null follows)', () => {
    for (const bad of ['10.1', '-1', '11', '1e3', 'NaN', 'Infinity']) {
      expect(extractCvss([{ type: 'CVSS_V3', score: bad }]).score, bad).toBeNull();
    }
    expect(extractCvss([{ type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P/BS:12.5' }]).score).toBeNull();
    expect(
      extractCvss([
        { type: 'CVSS_V4', score: '42' },
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
      ]),
    ).toMatchObject({ score: 5.3, source: 'osv_vector' });
  });

  it('L-1: NVD baseScore outside 0–10 / NaN / non-number -> failed (ignored, not stored)', () => {
    const body = (baseScore: unknown) => ({ vulnerabilities: [{ cve: { id: 'CVE-2026-0001', metrics: { cvssMetricV31: [{ cvssData: { version: '3.1', baseScore, baseSeverity: 'HIGH' } }] } } }] });
    for (const bad of [10.5, -1, Number.NaN, Number.POSITIVE_INFINITY, '9.8', null]) {
      expect(extractNvdCvss(body(bad)), String(bad)).toEqual({ kind: 'failed' });
    }
    expect(extractNvdCvss(body(9.8))).toMatchObject({ kind: 'found', cvss: { cvssScore: 9.8 } });
    expect(extractNvdCvss(body(0))).toMatchObject({ kind: 'found', cvss: { cvssScore: 0 } });
  });

  it('L-1: an invalid published/modified date makes the field NULL, the record is kept', () => {
    const v = normalizeOsvVulnerability(
      { id: 'GHSA-dddd-eeee-ffff', published: '2026-02-30T00:00:00Z', modified: 'yesterday', severity: [] } as OsvVulnerability,
      { ecosystem: 'nodejs', name: 'a' },
    );
    expect(v.sourceId).toBe('GHSA-dddd-eeee-ffff');
    expect(v.publishedAt).toBeNull();
    expect(v.lastModifiedAt).toBeNull();
    const ok = normalizeOsvVulnerability({ id: 'GHSA-dddd-eeee-ffff', published: '2026-02-01T03:00:00+03:00', severity: [] } as OsvVulnerability, { ecosystem: 'nodejs', name: 'a' });
    expect(ok.publishedAt).toBe('2026-02-01T00:00:00.000Z');
  });

  it('L-1: trimOsvRecord keeps a record with invalid dates (dates dropped or nulled, not rejected)', () => {
    const rec = trimOsvRecord({ id: 'GHSA-gggg-hhhh-iiii', summary: 's', modified: '2026-99-99T00:00:00Z', published: 'not a date' }, 'GHSA-gggg-hhhh-iiii');
    expect(rec).not.toBeNull();
    expect(rec?.id).toBe('GHSA-gggg-hhhh-iiii');
    expect(rec?.modified).toBeUndefined();
    expect(rec?.published).toBeUndefined();
    const ok = trimOsvRecord({ id: 'GHSA-gggg-hhhh-iiii', modified: '2026-03-01T02:00:00+02:00' }, 'GHSA-gggg-hhhh-iiii');
    expect(ok?.modified).toBe('2026-03-01T00:00:00.000Z');
  });
});

// ---------------------------------------------------------------------------
// L-2
// ---------------------------------------------------------------------------
describe('L-2 / contract 1.1.0 section 7.1: fail-closed switch parser', () => {
  const ON = ['on', 'true', '1', 'yes', 'ON', 'True', 'YES', '  on  ', '\tyes\n'];
  const OFF = ['off', 'false', '0', 'no', 'OFF', 'False', 'NO', ' 0 '];
  const INVALID = ['enabled', 'disable', '2', 'y', 'n', 'onn', 'o n', 'tru', '-1', 'secret-value-123'];

  it('L-2: every accepted spelling (trimmed, case-insensitive); empty/unset -> default on without warning', () => {
    const warns: string[] = [];
    for (const v of ON) expect(parseSwitch('X_SWITCH', v, (m) => warns.push(m)), JSON.stringify(v)).toBe(true);
    for (const v of OFF) expect(parseSwitch('X_SWITCH', v, (m) => warns.push(m)), JSON.stringify(v)).toBe(false);
    for (const v of [undefined, null, '', '   ']) expect(parseSwitch('X_SWITCH', v, (m) => warns.push(m)), JSON.stringify(v)).toBe(true);
    expect(warns).toEqual([]);
  });

  it('L-2: invalid -> off with exactly one warning naming only the variable (value never logged)', () => {
    for (const v of INVALID) {
      const warns: string[] = [];
      expect(parseSwitch('X_SWITCH', v, (m) => warns.push(m)), v).toBe(false);
      expect(warns).toHaveLength(1);
      expect(warns[0]).toContain('X_SWITCH');
      // Short values (`y`, `n`, `tru`) occur inside the fixed spelling list of the message itself.
      if (v.trim().length > 3) expect(warns[0]).not.toContain(v.trim());
    }
  });

  const FOUR: Array<[string, (raw: string | undefined, warn: (m: string) => void) => boolean]> = [
    ['VULNERABILITY_LOOKUP', (raw, warn) => vulnerabilityConfigFrom({ VULNERABILITY_LOOKUP: raw }, warn).lookupEnabled],
    ['VULNERABILITY_RECHECK', (raw, warn) => vulnerabilityConfigFrom({ VULNERABILITY_RECHECK: raw }, warn).recheckEnabled],
    ['NVD_ENABLED', (raw, warn) => vulnerabilityConfigFrom({ NVD_ENABLED: raw }, warn).nvdEnabled],
    ['REGISTRY_ENRICHMENT', (raw, warn) => parseEnrichmentSwitch(raw, warn)],
  ];

  it.each(FOUR)('L-2: %s uses the same parser (spellings, empty -> on, invalid -> off + one warning)', (name, read) => {
    for (const v of ON) expect(read(v, () => undefined), `${name}=${v}`).toBe(true);
    for (const v of OFF) expect(read(v, () => undefined), `${name}=${v}`).toBe(false);
    expect(read(undefined, () => undefined)).toBe(true);
    expect(read('', () => undefined)).toBe(true);
    const warns: string[] = [];
    expect(read('maybe-later', (m) => warns.push(m))).toBe(false);
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain(name);
    expect(warns[0]).not.toContain('maybe-later');
  });

  it('L-2 / REQ-004 contract 1.3.0 C-24: enrichmentConfigFrom treats an invalid REGISTRY_ENRICHMENT as off (was "on" in F3)', () => {
    const original = console.warn;
    const warns: string[] = [];
    console.warn = (m: unknown) => warns.push(String(m));
    try {
      expect(enrichmentConfigFrom({ REGISTRY_ENRICHMENT: 'enable' }).enabled).toBe(false);
      expect(enrichmentConfigFrom({}).enabled).toBe(true);
      expect(enrichmentConfigFrom({ REGISTRY_ENRICHMENT: 'Yes' }).enabled).toBe(true);
    } finally {
      console.warn = original;
    }
    expect(warns.filter((w) => w.includes('REGISTRY_ENRICHMENT'))).toHaveLength(1);
    expect(warns.join('\n')).not.toContain('enable"');
  });
});
