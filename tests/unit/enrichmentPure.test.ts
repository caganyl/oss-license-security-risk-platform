/**
 * REQ-004 · Pure enrichment modules: npm/PyPI field precedence (AC-P14-1…3,
 * D-53, D-78), SPDX expressions (AC-P16-3), copyright lines (AC-P15-9,
 * linear time), text decoding (AC-P15-8), integrity (AC-P15-2/3, D-83b),
 * effective license L-6 (AC-L6-1…4, D-54, D-81), summary line (contract §8),
 * budget (AC-P14-14) and coordinates (AC-P14-4).
 */
import { describe, expect, it } from 'vitest';
import { normalizeLicense } from '../../src/analysis/licenseNormalizer';
import { classifierTerm } from '../../src/enrichment/classifiers';
import { DownloadQuota, computeBudgetMs, createBudgetSignal } from '../../src/enrichment/budget';
import { checkCoordinates } from '../../src/enrichment/coordinates';
import { MAX_COPYRIGHT_LINES, copyrightLineOf, extractCopyrightLines } from '../../src/enrichment/copyright';
import { registrySummaryLine, resolveEffectiveLicense } from '../../src/enrichment/effectiveLicense';
import { createDigestStream, npmExpectedDigest, parseSriSha512, pypiExpectedDigest, verifyDigest } from '../../src/enrichment/integrity';
import { extractNpmMetadata, npmDeclaredLicense } from '../../src/enrichment/npmRegistry';
import { pypiArchiveCandidates, pypiLicenseFields } from '../../src/enrichment/pypiRegistry';
import { TRUNCATED_NOTE, cleanLicenseText, decodeText } from '../../src/enrichment/text';
import { MAX_SPDX_DEPTH, validateSpdxExpression } from '../../src/lib/spdxExpression';
import { sanitizeText } from '../../src/lib/textSanitize';
import { sha1hex, sha256hex, sha512b64 } from '../helpers/archiveBuilder';

const ORIGIN = 'https://registry.npmjs.org';
const FILES = 'https://files.pythonhosted.org';

describe('AC-P14-1: npm license field precedence', () => {
  it('AC-P14-1: license string > license.type > licenses[].type (OR-joined, unique)', () => {
    expect(npmDeclaredLicense({ license: 'MIT', licenses: [{ type: 'GPL-3.0' }] })).toBe('MIT');
    expect(npmDeclaredLicense({ license: { type: 'ISC', url: 'x' } })).toBe('ISC');
    expect(npmDeclaredLicense({ licenses: [{ type: 'MIT' }, { type: 'Apache-2.0' }, { type: 'MIT' }, 'junk'] })).toBe('MIT OR Apache-2.0');
    expect(npmDeclaredLicense({ license: '   ', licenses: [{ type: 'BSD-3-Clause' }] })).toBe('BSD-3-Clause');
    expect(npmDeclaredLicense({})).toBeNull();
  });

  it('AC-P14-11: unexpected field types make the document an error (FIELD_TYPE), never a crash', () => {
    expect(extractNpmMetadata({ license: 42 }, ORIGIN)).toEqual({ kind: 'error', code: 'FIELD_TYPE' });
    expect(extractNpmMetadata({ licenses: 'MIT' }, ORIGIN)).toEqual({ kind: 'error', code: 'FIELD_TYPE' });
    expect(extractNpmMetadata({ license: 'MIT', dist: 'x' }, ORIGIN)).toEqual({ kind: 'error', code: 'FIELD_TYPE' });
    expect(extractNpmMetadata({ license: 'MIT', dist: { tarball: 7 } }, ORIGIN)).toEqual({ kind: 'error', code: 'FIELD_TYPE' });
  });

  it('AC-P15-2 / D-83: tarball outside <npm origin>/ or without a usable digest gives no candidate; shasum fallback', () => {
    const sri = `sha512-${sha512b64(Buffer.from('a'))}`;
    const ok = extractNpmMetadata({ license: 'MIT', dist: { tarball: `${ORIGIN}/a/-/a-1.tgz`, integrity: sri } }, ORIGIN);
    expect(ok).toMatchObject({ kind: 'found', metadata: { archiveCandidates: [{ algorithm: 'sha512', filename: 'a-1.tgz' }] } });
    const evil = extractNpmMetadata({ license: 'MIT', dist: { tarball: 'https://evil.example/a.tgz', integrity: sri } }, ORIGIN);
    expect(evil).toMatchObject({ kind: 'found', metadata: { archiveCandidates: [] } });
    const sha1 = extractNpmMetadata({ license: 'MIT', dist: { tarball: `${ORIGIN}/a/-/a-1.tgz`, shasum: sha1hex(Buffer.from('a')).toUpperCase() } }, ORIGIN);
    expect(sha1).toMatchObject({ kind: 'found', metadata: { archiveCandidates: [{ algorithm: 'sha1', digests: [sha1hex(Buffer.from('a'))] }] } });
  });
});

describe('AC-P14-2 / AC-P14-3 / D-53 / D-78: PyPI license precedence and trove classifiers', () => {
  const MIT = 'License :: OSI Approved :: MIT License';
  const APACHE = 'License :: OSI Approved :: Apache Software License';

  it('AC-P14-2: license_expression wins over everything', () => {
    expect(pypiLicenseFields({ license_expression: 'Apache-2.0 OR MIT', license: 'BSD', classifiers: [MIT] }).declaredLicense).toBe('Apache-2.0 OR MIT');
  });

  it('AC-P14-2: a short recognized license beats classifiers; an unrecognized one loses to them; else raw short text', () => {
    expect(pypiLicenseFields({ license: 'MIT', classifiers: [APACHE] }).declaredLicense).toBe('MIT');
    expect(pypiLicenseFields({ license: 'Custom Corp License', classifiers: [APACHE] }).declaredLicense).toBe('Apache-2.0');
    expect(pypiLicenseFields({ license: 'Custom Corp License', classifiers: [] }).declaredLicense).toBe('Custom Corp License');
    expect(pypiLicenseFields({ license: null, classifiers: null })).toEqual({ declaredLicense: null, licenseText: null });
  });

  it('AC-P14-2: a multi-line or > 200 character license is never an id but kept as NOTICE text', () => {
    const full = 'Permission is hereby granted, free of charge...\nTHE SOFTWARE IS PROVIDED "AS IS"';
    const r = pypiLicenseFields({ license: full, classifiers: [MIT] });
    expect(r.declaredLicense).toBe('MIT');
    expect(r.licenseText).toContain('Permission is hereby granted');
    const long = 'x'.repeat(201);
    expect(pypiLicenseFields({ license: long })).toEqual({ declaredLicense: null, licenseText: long });
  });

  it('AC-P14-3: classifiers map to SPDX ids, several are AND-joined, name-less ones ignored', () => {
    expect(pypiLicenseFields({ classifiers: [MIT, APACHE, 'License :: OSI Approved', 'Programming Language :: Python'] }).declaredLicense).toBe('MIT AND Apache-2.0');
    expect(pypiLicenseFields({ classifiers: ['License :: OSI Approved :: Python Software Foundation License'] }).declaredLicense).toBe('PSF-2.0');
    expect(classifierTerm('License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)')).toEqual({ kind: 'spdx', id: 'GPL-3.0-or-later' });
    expect(classifierTerm('License :: OSI Approved :: BSD License')).toEqual({ kind: 'raw', text: 'BSD License' });
    expect(classifierTerm('License :: Other/Proprietary License')).toBeNull();
    expect(classifierTerm('Topic :: Utilities')).toBeNull();
  });

  it('AC-P14-11: wrong field types are errors', () => {
    expect(() => pypiLicenseFields({ license: 5 })).toThrow();
    expect(() => pypiLicenseFields({ classifiers: 'MIT' })).toThrow();
  });

  it('AC-P15-3 / D-65: candidate order none-any wheel, other wheels by size, sdist tar.gz, sdist zip; foreign host / bad sha256 / > 64 MiB dropped', () => {
    const h = sha256hex(Buffer.from('x'));
    const f = (filename: string, packagetype: string, size: number, extra: Record<string, unknown> = {}) => ({
      url: `${FILES}/packages/${filename}`, filename, packagetype, size, digests: { sha256: h }, ...extra,
    });
    const urls = [
      f('p-1.zip', 'sdist', 10),
      f('p-1.tar.gz', 'sdist', 50),
      f('p-1-cp312-win_amd64.whl', 'bdist_wheel', 30),
      f('p-1-cp311-linux.whl', 'bdist_wheel', 20),
      f('p-1-py3-none-any.whl', 'bdist_wheel', 999),
      f('evil-none-any.whl', 'bdist_wheel', 1, { url: 'https://evil.example/evil-none-any.whl' }),
      f('bad-none-any.whl', 'bdist_wheel', 1, { digests: { sha256: 'zz' } }),
      f('huge-none-any.whl', 'bdist_wheel', 64 * 1024 * 1024 + 1),
      f('p-1.egg', 'bdist_egg', 1),
    ];
    expect(pypiArchiveCandidates(urls, FILES).map((c) => c.filename)).toEqual([
      'p-1-py3-none-any.whl', 'p-1-cp311-linux.whl', 'p-1-cp312-win_amd64.whl', 'p-1.tar.gz', 'p-1.zip',
    ]);
  });
});

describe('AC-P16-3: SPDX expression validation and canonicalization', () => {
  const ids = ['MIT', 'Apache-2.0', 'GPL-2.0-only', 'BSD-3-Clause'];
  const ok = (e: string) => validateSpdxExpression(e, ids);

  it('AC-P16-3: canonical spelling, upper-case operators, single spaces', () => {
    expect(ok('mit  or   apache-2.0')).toEqual({ valid: true, canonical: 'MIT OR Apache-2.0' });
    expect(ok('( MIT and BSD-3-Clause ) or GPL-2.0-only')).toEqual({ valid: true, canonical: '(MIT AND BSD-3-Clause) OR GPL-2.0-only' });
    expect(ok('gpl-2.0-only with classpath-exception-2.0')).toEqual({ valid: true, canonical: 'GPL-2.0-only WITH Classpath-exception-2.0' });
    expect(ok('MIT+')).toEqual({ valid: true, canonical: 'MIT+' });
  });

  it('AC-P16-3: invalid inputs are classified', () => {
    expect(ok('')).toEqual({ valid: false, reason: 'empty' });
    expect(ok('Foo-1.0')).toEqual({ valid: false, reason: 'unknown_id' });
    expect(ok('MIT WITH Foo-exception')).toEqual({ valid: false, reason: 'unknown_exception' });
    expect(ok('(MIT')).toEqual({ valid: false, reason: 'unbalanced' });
    expect(ok('MIT)')).toEqual({ valid: false, reason: 'unbalanced' });
    expect(ok('MIT AND')).toEqual({ valid: false, reason: 'syntax' });
    expect(ok('MIT, Apache-2.0')).toEqual({ valid: false, reason: 'syntax' });
    expect(ok('(MIT) WITH LLVM-exception')).toEqual({ valid: false, reason: 'syntax' });
    expect(ok(`${'('.repeat(MAX_SPDX_DEPTH + 1)}MIT${')'.repeat(MAX_SPDX_DEPTH + 1)}`)).toEqual({ valid: false, reason: 'too_deep' });
    expect(ok(`${'('.repeat(MAX_SPDX_DEPTH)}MIT${')'.repeat(MAX_SPDX_DEPTH)}`).valid).toBe(true);
  });

  it('AC-P16-3: linear on a 1 MB expression (< 2 s)', () => {
    const big = Array.from({ length: 100_000 }, () => 'MIT').join(' OR ');
    const t = performance.now();
    expect(ok(big).valid).toBe(true);
    expect(ok(`${big} AND`).valid).toBe(false);
    expect(performance.now() - t).toBeLessThan(2000);
  });
});

describe('AC-P15-9 / D-68: copyright lines', () => {
  it('AC-P15-9: statements with a year or (c)/©, comment prefixes removed, spaces collapsed, unique, in order', () => {
    const text = [
      'MIT License',
      '',
      'Copyright (c) 2020   Jane Doe',
      ' * Copyright 2019 Acme Inc.',
      '# (c) Foo Bar',
      '© Baz',
      'Copyright (c) 2020 Jane Doe',
      'Copyright notice must be retained',
      'Copyright (c) <year> <copyright holders>',
      'Copyright (C) 2007 Free Software Foundation, Inc.',
      'copyright without year',
      'Permission is hereby granted, Copyright 2020 X',
    ].join('\n');
    expect(extractCopyrightLines([text])).toEqual(['Copyright (c) 2020 Jane Doe', 'Copyright 2019 Acme Inc.', '(c) Foo Bar', '© Baz']);
  });

  it('AC-P15-9: line cut to 300 code points, at most 50 lines', () => {
    expect(Array.from(copyrightLineOf(`Copyright 2020 ${'é'.repeat(1000)}`) ?? '').length).toBe(300);
    const many = Array.from({ length: 80 }, (_, i) => `Copyright 2020 Holder ${i}`).join('\n');
    expect(extractCopyrightLines([many])).toHaveLength(MAX_COPYRIGHT_LINES);
  });

  it('AC-P15-9: linear on adversarial input — 2 MiB single line, digit runs, many short lines (< 2 s each)', () => {
    const inputs = [
      `Copyright ${'1'.repeat(2 * 1024 * 1024)}`,
      `Copyright ${'2020'.repeat(512 * 1024)}`,
      'copyright '.repeat(220_000),
      'Copyright (c\n'.repeat(160_000),
      ' '.repeat(2 * 1024 * 1024) + 'Copyright 2020 x',
    ];
    for (const input of inputs) {
      const t = performance.now();
      extractCopyrightLines([input]);
      expect(performance.now() - t).toBeLessThan(2000);
    }
  });
});

describe('AC-P15-8: text decoding and cleanup', () => {
  it('AC-P15-8: invalid UTF-8 becomes U+FFFD (no Latin-1 fallback); BOMs; UTF-16; NUL = binary', () => {
    expect(decodeText(Buffer.from([0x61, 0xe9, 0x62]))).toBe('a�b');
    expect(decodeText(Buffer.from([0xef, 0xbb, 0xbf, 0x41]))).toBe('A');
    expect(decodeText(Buffer.from([0xff, 0xfe, 0x41, 0x00, 0x42, 0x00]))).toBe('AB');
    expect(decodeText(Buffer.from([0xfe, 0xff, 0x00, 0x41]))).toBe('A');
    expect(decodeText(Buffer.from([0x41, 0x00, 0x42]))).toBeNull();
  });

  it('AC-P15-8: control/bidi characters are removed by the shared sanitizer', () => {
    const cleaned = sanitizeText('a\u0007b‮c\r\nd');
    for (const ch of ['\u0007', '‮', '\r']) expect(cleaned.includes(ch)).toBe(false);
    expect(cleaned).toContain('d');
  });

  it('AC-P14-2: long license text is capped at 1 MiB UTF-8 with a [truncated] note', () => {
    const out = cleanLicenseText('ş'.repeat(700_000)) ?? '';
    expect(Buffer.byteLength(out, 'utf8')).toBeLessThanOrEqual(1024 * 1024);
    expect(out.endsWith(TRUNCATED_NOTE)).toBe(true);
    expect(out).not.toContain('�');
    expect(cleanLicenseText('  \n ')).toBeNull();
  });
});

describe('AC-P15-2 / AC-P15-3 / D-83b: integrity', () => {
  const data = Buffer.from('archive');
  it('D-83b: sha512 SRI items win (several allowed, others ignored); without sha512 the 40-hex shasum; else null', () => {
    const sri = `sha256-abc sha512-${sha512b64(data)} sha512-${sha512b64(Buffer.from('other'))}?opt`;
    expect(parseSriSha512(sri)).toEqual([sha512b64(data), sha512b64(Buffer.from('other'))]);
    expect(npmExpectedDigest(sri, sha1hex(data))).toMatchObject({ algorithm: 'sha512' });
    expect(npmExpectedDigest('sha1-xyz', sha1hex(data))).toEqual({ algorithm: 'sha1', values: [sha1hex(data)] });
    expect(npmExpectedDigest('sha512-short', 'nothex')).toBeNull();
    expect(npmExpectedDigest(undefined, undefined)).toBeNull();
  });

  it('AC-P15-3: PyPI sha256 must be 64 hex (normalized to lower case)', () => {
    expect(pypiExpectedDigest(sha256hex(data).toUpperCase())).toEqual({ algorithm: 'sha256', values: [sha256hex(data)] });
    expect(pypiExpectedDigest('abc')).toBeNull();
    expect(pypiExpectedDigest(5)).toBeNull();
  });

  it('AC-P15-2: streamed digest verifies against the expected values only', () => {
    for (const [alg, expected] of [['sha512', sha512b64(data)], ['sha1', sha1hex(data)], ['sha256', sha256hex(data)]] as const) {
      const s = createDigestStream(alg);
      s.update(data.subarray(0, 3));
      s.update(data.subarray(3));
      const actual = s.digest();
      expect(verifyDigest({ algorithm: alg, values: ['x', expected] }, actual)).toBe(true);
      expect(verifyDigest({ algorithm: alg, values: ['x'] }, actual)).toBe(false);
    }
  });
});

describe('L-6: effective license (AC-L6-1…4, D-54, D-81)', () => {
  const normalize = (raw: string) => normalizeLicense(raw).normalized;
  const base = { ecosystem: 'npm' as const, declaredLicense: null, lockLicenses: [] as string[], normalize, sanitize: sanitizeText };

  it('AC-L6-1: ok -> registry declaration, source registry:<eco>, policy [declared]; hint compared case/normalization-insensitively', () => {
    const r = resolveEffectiveLicense({ ...base, status: 'ok', declaredLicense: 'MIT', lockLicenses: ['mit'] });
    expect(r).toMatchObject({ licenseSource: 'registry:npm', lockHint: 'mit', hintDiffers: false, policyInput: ['MIT'] });
    expect(r.licenseExpression).toBe(normalize('MIT'));
    const d = resolveEffectiveLicense({ ...base, ecosystem: 'pypi', status: 'ok', declaredLicense: 'Apache-2.0', lockLicenses: ['MIT'] });
    expect(d).toMatchObject({ licenseSource: 'registry:pypi', hintDiffers: true, policyInput: ['Apache-2.0'] });
    expect(resolveEffectiveLicense({ ...base, status: 'ok', declaredLicense: 'MIT' }).hintDiffers).toBeNull();
  });

  it('AC-L6-2: no_license -> no effective license, policy [] even with a lock hint', () => {
    expect(resolveEffectiveLicense({ ...base, status: 'no_license', lockLicenses: ['MIT'] })).toEqual({
      licenseExpression: null, licenseSource: 'none', lockHint: 'MIT', hintDiffers: null, policyInput: [],
    });
  });

  it('AC-L6-3: not_found/unreachable/error/budget_exceeded/disabled fall back to the lock hint (unverified)', () => {
    for (const status of ['not_found', 'unreachable', 'error', 'budget_exceeded', 'disabled'] as const) {
      expect(resolveEffectiveLicense({ ...base, status, lockLicenses: ['Apache-2.0', 'MIT'] }), status).toEqual({
        licenseExpression: 'Apache-2.0 AND MIT', licenseSource: 'lockfile (unverified)', lockHint: 'Apache-2.0 AND MIT', hintDiffers: null, policyInput: ['Apache-2.0', 'MIT'],
      });
      expect(resolveEffectiveLicense({ ...base, status }).licenseSource).toBe('none');
    }
  });

  it('D-81: version_unknown / invalid_coordinates (non-exact lock entries) -> none, policy [] even with a hint', () => {
    for (const status of ['version_unknown', 'invalid_coordinates'] as const) {
      expect(resolveEffectiveLicense({ ...base, status, lockLicenses: ['MIT'] })).toMatchObject({ licenseExpression: null, licenseSource: 'none', lockHint: 'MIT', policyInput: [] });
    }
  });

  it('AC-L6-4: lock hint cleaned, newlines flattened, cut to 200 code points', () => {
    const r = resolveEffectiveLicense({ ...base, status: 'disabled', lockLicenses: [`A\nB${'x'.repeat(300)}`] });
    expect(r.lockHint).not.toContain('\n');
    expect(Array.from(r.lockHint ?? '').length).toBe(200);
  });

  it('contract §8 / D-82: [registry] line — disabled always, enabled only with unreachable/error/budget keys', () => {
    expect(registrySummaryLine([{ status: 'disabled', usedHint: true }, { status: 'disabled', usedHint: false }], false)).toBe(
      '[registry] License enrichment disabled: 1 package(s) use the lockfile license (unverified), 1 have no license.',
    );
    expect(registrySummaryLine([{ status: 'ok', usedHint: false }, { status: 'not_found', usedHint: true }], true)).toBeNull();
    expect(registrySummaryLine([{ status: 'unreachable', usedHint: true }, { status: 'error', usedHint: false }, { status: 'budget_exceeded', usedHint: false }, { status: 'ok', usedHint: false }], true)).toBe(
      '[registry] Registry lookup incomplete for 3 package(s) (unreachable: 1, error: 1, time budget exceeded: 1); license from lockfile (unverified): 1, no license: 2.',
    );
  });
});

describe('AC-P14-14: budget and download quota', () => {
  it('AC-P14-14: budget = min(timeout/2, remaining - timeout/4); <= 0 means an already aborted signal', () => {
    expect(computeBudgetMs(3_600_000, 3_600_000)).toBe(1_800_000);
    expect(computeBudgetMs(60_000, 20_000)).toBe(5_000);
    expect(computeBudgetMs(60_000, 10_000)).toBeLessThan(0);
    expect(createBudgetSignal(0).aborted).toBe(true);
    expect(createBudgetSignal(-5).aborted).toBe(true);
    expect(createBudgetSignal(10_000).aborted).toBe(false);
  });

  it('AC-P15-5: the per-scan download quota reserves then settles to the real size', () => {
    const q = new DownloadQuota(100);
    expect(q.reserve(60)).toBe(true);
    expect(q.reserve(50)).toBe(false);
    q.settle(60, 10);
    expect(q.reserve(90)).toBe(true);
    expect(q.reserve(1)).toBe(false);
  });
});

describe('AC-P14-4: coordinate validation (no request for invalid / version-less keys)', () => {
  it('AC-P14-4: version NULL -> version_unknown; bad names/versions -> invalid', () => {
    expect(checkCoordinates('nodejs', 'left-pad', null).kind).toBe('version_unknown');
    expect(checkCoordinates('nodejs', 'left-pad', '1.3.0').kind).toBe('ok');
    expect(checkCoordinates('nodejs', '../etc/passwd', '1.0.0').kind).not.toBe('ok');
    expect(checkCoordinates('nodejs', 'left-pad', '1.0.0/../../x').kind).not.toBe('ok');
    expect(checkCoordinates('python', 'Requests', '2.31.0').kind).toBe('ok');
    expect(checkCoordinates('python', 'bad name!', '1.0').kind).not.toBe('ok');
  });
});
