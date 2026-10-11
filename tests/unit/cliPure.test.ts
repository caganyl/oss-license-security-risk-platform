/**
 * REQ-007 P-22 · Pure parts of the `oss-risk` CLI (contract
 * `docs/contracts/REQ-007-cli-and-exports.md` sections 2–5): argument
 * grammar, address and key rules, level mapping, `--fail-on`, data
 * completeness, terminal safety and the JSON formatter. No network, no files.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { API_KEY_ARGUMENT_MESSAGE, parseArgs, type FailOn } from '../../src/cli/args';
import { CLI_API_KEY_RE, DEFAULT_URL, KeyFileTooLargeError, apiKeySecretPart, resolveApiKey, resolveTarget } from '../../src/cli/config';
import { compareBreach, dataStatusFrom, decide, effectiveLevel, evaluateFindings, isCounted, type BreachItem, type Level } from '../../src/cli/evaluate';
import { CliError, EXIT_AUTH, EXIT_FAIL, EXIT_INCOMPLETE, EXIT_PASS, EXIT_RUNTIME, EXIT_USAGE, UsageError } from '../../src/cli/exitCodes';
import { Output, cleanText, formatJson, formatTextSummary, type ScanReport } from '../../src/cli/output';
import { REPO_ROOT } from '../helpers/paths';
import { finding, makeApiKey } from '../helpers/cliFakes';
import { validateCliJson } from '../helpers/cliJsonSchema';

function usage(argv: string[]): UsageError {
  try {
    parseArgs(argv);
  } catch (err) {
    if (err instanceof UsageError) return err;
    throw err;
  }
  throw new Error(`expected a usage error for ${JSON.stringify(argv)}`);
}

describe('AC-P22-12: exit code constants (contract 5.1)', () => {
  it('AC-P22-12: 0 pass, 1 fail, 2 usage, 3 runtime, 4 auth, 5 incomplete', () => {
    expect([EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_RUNTIME, EXIT_AUTH, EXIT_INCOMPLETE]).toEqual([0, 1, 2, 3, 4, 5]);
    const u = new UsageError('usage_error', 'x', 'scan');
    expect(u).toBeInstanceOf(CliError);
    expect(u.exitCode).toBe(2);
  });
});

describe('AC-P22-2: argument grammar (contract 2.2)', () => {
  const S = ['scan', '--project', 'demo'];
  it.each([
    ['no command', []],
    ['unknown command', ['frob']],
    ['option without command', ['--project', 'x']],
    ['unknown option', [...S, '--bogus']],
    ['unknown short option', [...S, '-x']],
    ['missing value at end', ['scan', '--project']],
    ['value starting with -', ['scan', '--project', '--format', 'json']],
    ['empty inline value', ['scan', '--project=']],
    ['repeated option', [...S, '--project', 'other']],
    ['repeated option (= form)', ['scan', '--project=a', '--project=b']],
    ['positional extra', [...S, 'extra']],
    ['-- separator', [...S, '--']],
    ['flag with value', [...S, '--allow-incomplete=yes']],
    ['option of the other command', [...S, '--key-file', 'k']],
    ['fail-on case sensitive', [...S, '--fail-on', 'HIGH']],
    ['fail-on unknown', [...S, '--fail-on', 'severe']],
    ['format unknown', [...S, '--format', 'xml']],
    ['timeout below 10', [...S, '--timeout', '9']],
    ['timeout above 86400', [...S, '--timeout', '86401']],
    ['timeout not an integer', [...S, '--timeout', '1e3']],
    ['timeout negative', [...S, '--timeout=-5']],
    ['missing --project', ['scan']],
    ['bootstrap missing --key-file', ['bootstrap', '--new-database']],
    ['bootstrap --project-name alone', ['bootstrap', '--new-database', '--key-file', 'k', '--project-name', 'p']],
    ['bootstrap --project-path alone', ['bootstrap', '--new-database', '--key-file', 'k', '--project-path', '.']],
    ['bootstrap flag with value', ['bootstrap', '--new-database=yes', '--key-file', 'k']],
    ['bootstrap option of scan', ['bootstrap', '--new-database', '--key-file', 'k', '--fail-on', 'high']],
  ])('AC-P22-2: %s -> usage error (exit 2)', (_name, argv) => {
    const err = usage(argv);
    expect(err.exitCode).toBe(2);
    expect(err.message).not.toContain('\n');
  });

  it('AC-P22-2: valid scan forms and defaults (--ad değer and --ad=değer)', () => {
    expect(parseArgs(S)).toEqual({ kind: 'scan', project: 'demo', url: null, failOn: 'high', format: 'text', timeoutSeconds: 1800, allowIncomplete: false });
    expect(
      parseArgs(['scan', '--project=demo', '--url=http://127.0.0.1:9', '--fail-on=none', '--format=json', '--timeout=10', '--allow-incomplete']),
    ).toEqual({ kind: 'scan', project: 'demo', url: 'http://127.0.0.1:9', failOn: 'none', format: 'json', timeoutSeconds: 10, allowIncomplete: true });
    expect((parseArgs([...S, '--timeout', '86400']) as { timeoutSeconds: number }).timeoutSeconds).toBe(86400);
    for (const level of ['none', 'low', 'medium', 'high', 'critical'] as FailOn[]) {
      expect((parseArgs([...S, '--fail-on', level]) as { failOn: FailOn }).failOn).toBe(level);
    }
  });

  it('AC-P22-2: valid bootstrap forms', () => {
    expect(parseArgs(['bootstrap', '--new-database', '--key-file', 'k.key'])).toEqual({
      kind: 'bootstrap', keyFile: 'k.key', url: null, projectName: null, projectPath: null,
    });
    expect(parseArgs(['bootstrap', '--key-file=k', '--new-database', '--project-name', 'p', '--project-path', 'dir', '--url', 'http://localhost:3001'])).toEqual({
      kind: 'bootstrap', keyFile: 'k', url: 'http://localhost:3001', projectName: 'p', projectPath: 'dir',
    });
  });

  it('AC-P22-17 / X-1: bootstrap without --new-database -> 2 with the fixed explanation', () => {
    const err = usage(['bootstrap', '--key-file', 'k']);
    expect(err.exitCode).toBe(2);
    expect(err.code).toBe('new_database_required');
    expect(err.message).toBe('bootstrap requires --new-database: it sets an unknown admin password and is meant only for a new, temporary database');
  });

  it.each([
    [['scan', '--project', 'x', '--api-key', 'VALUE-1']],
    [['scan', '--project', 'x', '--api-key=VALUE-1']],
    [['scan', '--key', 'VALUE-1', '--project', 'x']],
    [['scan', '--key=VALUE-1']],
    [['bootstrap', '--token', 'VALUE-1']],
    [['bootstrap', '--token=VALUE-1', '--new-database']],
    [['--api-key=VALUE-1']],
    [['scan', '--help', '--api-key=VALUE-1']],
    [['scan', '--bogus', '--token', 'VALUE-1']],
  ])('AC-P22-3: %j -> 2 with the fixed text before any other check; value never copied', (argv) => {
    const err = usage(argv);
    expect(err.code).toBe('api_key_argument_rejected');
    expect(err.message).toBe(API_KEY_ARGUMENT_MESSAGE);
    expect(err.format).toBe('text');
    expect(JSON.stringify(err)).not.toContain('VALUE-1');
  });

  it('AC-P22-2: --help/-h wins over --version and over other usage problems; --version/-V', () => {
    expect(parseArgs(['--help'])).toEqual({ kind: 'help', command: null });
    expect(parseArgs(['-h'])).toEqual({ kind: 'help', command: null });
    expect(parseArgs(['scan', '--help'])).toEqual({ kind: 'help', command: 'scan' });
    expect(parseArgs(['bootstrap', '-h', '--bogus'])).toEqual({ kind: 'help', command: 'bootstrap' });
    expect(parseArgs(['--version', '--help'])).toEqual({ kind: 'help', command: null });
    expect(parseArgs(['--version'])).toEqual({ kind: 'version' });
    expect(parseArgs(['-V'])).toEqual({ kind: 'version' });
    expect(parseArgs(['scan', '--bogus', '-V'])).toEqual({ kind: 'version' });
  });

  it('AC-P22-15: --format json parsed before the error -> error carries json and the parsed --fail-on; after -> text', () => {
    const late = usage(['scan', '--format', 'json', '--fail-on', 'low', '--bogus']);
    expect(late.format).toBe('json');
    expect(late.failOn).toBe('low');
    const early = usage(['scan', '--bogus', '--format', 'json']);
    expect(early.format).toBe('text');
  });

  it('AC-P22-2: usage messages name options only (sanitized), never option values', () => {
    const err = usage(['scan', '--project', 'x', '--we\u001b[2Jird=secret-value']);
    expect(err.message).not.toContain('\u001b');
    expect(err.message).not.toContain('secret-value');
    expect(usage(['scan', '--project', 'x', 'positional-value']).message).not.toContain('positional-value');
  });
});

describe('AC-P22-4: server address (contract 3.1)', () => {
  const t = (url: string | null, env: Record<string, string | undefined> = {}, mode: 'scan' | 'bootstrap' = 'scan') => resolveTarget(url, env, mode);
  const code = (fn: () => unknown): string => {
    try {
      fn();
    } catch (err) {
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).exitCode).toBe(2);
      return (err as CliError).code;
    }
    throw new Error('expected CliError');
  };

  it('AC-P22-4: source order --url > OSS_RISK_URL (empty = unset) > http://127.0.0.1:3001', () => {
    expect(DEFAULT_URL).toBe('http://127.0.0.1:3001');
    expect(t(null).origin).toBe('http://127.0.0.1:3001');
    expect(t(null, { OSS_RISK_URL: '' }).origin).toBe('http://127.0.0.1:3001');
    expect(t(null, { OSS_RISK_URL: 'http://localhost:4000' }).origin).toBe('http://localhost:4000');
    expect(t('http://127.0.0.1:5000/', { OSS_RISK_URL: 'http://localhost:4000' }).origin).toBe('http://127.0.0.1:5000');
  });

  it.each([
    ['http://example.com', 'insecure_url'],
    ['http://10.0.0.5:3001', 'insecure_url'],
    ['http://u:p@127.0.0.1:3001', 'invalid_url'],
    ['http://u@127.0.0.1:3001', 'invalid_url'],
    ['http://127.0.0.1:3001/?a=1', 'invalid_url'],
    ['http://127.0.0.1:3001/#frag', 'invalid_url'],
    ['http://127.0.0.1:3001/api', 'invalid_url'],
    ['ftp://127.0.0.1', 'invalid_url'],
    ['not a url', 'invalid_url'],
  ])('AC-P22-4: %s -> 2 (%s)', (url, expected) => {
    expect(code(() => t(url))).toBe(expected);
  });

  it('AC-P22-4: loopback http accepted with explicit Host; non-loopback https accepted without explicit Host', () => {
    expect(t('http://127.0.0.1:3001')).toMatchObject({ loopback: true, hostHeader: '127.0.0.1:3001', connectHost: '127.0.0.1', port: 3001 });
    expect(t('http://localhost')).toMatchObject({ loopback: true, hostHeader: 'localhost:80', port: 80, origin: 'http://localhost:80' });
    expect(t('http://[::1]:3001')).toMatchObject({ loopback: true, hostHeader: '[::1]:3001', connectHost: '::1' });
    expect(t('https://oss-risk.example.test')).toMatchObject({ loopback: false, hostHeader: null, port: 443, protocol: 'https:' });
  });

  it('AC-P22-17: bootstrap accepts only loopback (also https non-loopback -> 2 not_loopback)', () => {
    expect(t('http://127.0.0.1:3001', {}, 'bootstrap').loopback).toBe(true);
    expect(code(() => t('https://oss-risk.example.test', {}, 'bootstrap'))).toBe('not_loopback');
    expect(code(() => t('http://example.com', {}, 'bootstrap'))).toBe('not_loopback');
  });
});

describe('AC-P22-3: API key input (contract 3.2)', () => {
  const k = makeApiKey();
  const files = new Map<string, string>();
  const read = async (file: string, max: number): Promise<Buffer> => {
    const v = files.get(file);
    if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    if (Buffer.byteLength(v) > max) throw new KeyFileTooLargeError();
    return Buffer.from(v);
  };
  const fail = async (env: Record<string, string>): Promise<CliError> => {
    try {
      await resolveApiKey(env, read);
    } catch (err) {
      return err as CliError;
    }
    throw new Error('expected an error');
  };

  it('AC-P22-3: CLI pattern source equals src/lib/apiKeys.ts API_KEY_RE (kept separate on purpose)', () => {
    const text = fs.readFileSync(path.join(REPO_ROOT, 'src', 'lib', 'apiKeys.ts'), 'utf8');
    const m = /export const API_KEY_RE = \/(.+)\/([a-z]*);/.exec(text);
    expect(m).not.toBeNull();
    expect(CLI_API_KEY_RE.source).toBe(m![1]);
    expect(CLI_API_KEY_RE.flags).toBe(m![2]);
  });

  it('AC-P22-3: env value or file (trimmed); the value itself is not trimmed', async () => {
    expect(await resolveApiKey({ OSS_RISK_API_KEY: k.key }, read)).toBe(k.key);
    files.set('/keys/a', `  \n${k.key}\r\n `);
    expect(await resolveApiKey({ OSS_RISK_API_KEY_FILE: '/keys/a' }, read)).toBe(k.key);
    expect((await fail({ OSS_RISK_API_KEY: ` ${k.key}` })).message).toBe('API key has an invalid format');
    expect(apiKeySecretPart(k.key)).toBe(k.secret);
  });

  it('AC-P22-3: both, neither (empty = unset), bad format, file > 1 KiB, missing file -> 2 without value or length', async () => {
    files.set('/keys/a', k.key);
    files.set('/keys/big', `${k.key}${' '.repeat(1100)}`);
    files.set('/keys/bad', 'ossr_short_value');
    const cases: Array<[Record<string, string>, string]> = [
      [{ OSS_RISK_API_KEY: k.key, OSS_RISK_API_KEY_FILE: '/keys/a' }, 'set exactly one of OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE'],
      [{}, 'set exactly one of OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE'],
      [{ OSS_RISK_API_KEY: '', OSS_RISK_API_KEY_FILE: '' }, 'set exactly one of OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE'],
      [{ OSS_RISK_API_KEY: 'ossr_short_value' }, 'API key has an invalid format'],
      [{ OSS_RISK_API_KEY: k.key.toUpperCase() }, 'API key has an invalid format'],
      [{ OSS_RISK_API_KEY_FILE: '/keys/bad' }, 'API key has an invalid format'],
      [{ OSS_RISK_API_KEY_FILE: '/keys/big' }, 'API key file is larger than 1 KiB'],
    ];
    for (const [env, message] of cases) {
      const err = await fail(env);
      expect(err.exitCode).toBe(2);
      expect(err.code).toBe('invalid_api_key_config');
      expect(err.message).toBe(message);
      expect(err.message).not.toContain('ossr_short');
      expect(err.message).not.toMatch(/\d+ (bytes|characters)/);
    }
    const missing = await fail({ OSS_RISK_API_KEY_FILE: '/keys/missing\u001b[2J' });
    expect(missing.exitCode).toBe(2);
    expect(missing.message).toMatch(/^cannot read API key file /);
    expect(missing.message).not.toContain('\u001b');
  });
});

describe('AC-P22-8 / AC-P22-9: counted findings and level mapping (contract 4.2, 4.3)', () => {
  it.each<[string, Record<string, unknown>, Level | null]>([
    ['severity=critical', { finding_type: 'security', severity: 'critical' }, 'critical'],
    ['severity=null', { finding_type: 'security', severity: null }, 'high'],
    ['severity=none', { finding_type: 'security', severity: 'none' }, null],
    ['severity unknown text', { finding_type: 'security', severity: 'moderate' }, 'high'],
    ['severity=low', { finding_type: 'security', severity: 'low' }, 'low'],
    ['risk_level=unknown', { finding_type: 'license', risk_level: 'unknown' }, 'high'],
    ['risk_level=null', { finding_type: 'license', risk_level: null }, 'high'],
    ['risk_level=safe, applied_policy=prohibited', { finding_type: 'license', risk_level: 'safe', applied_policy: 'prohibited' }, 'critical'],
    ['risk_level=low, applied_policy=restricted', { finding_type: 'license', risk_level: 'low', applied_policy: 'restricted' }, 'high'],
    ['risk_level=medium, applied_policy=review_required', { finding_type: 'license', risk_level: 'medium', applied_policy: 'review_required' }, 'medium'],
    ['risk_level=critical, applied_policy=review_required', { finding_type: 'license', risk_level: 'critical', applied_policy: 'review_required' }, 'critical'],
    ['risk_level=safe, applied_policy=null', { finding_type: 'license', risk_level: 'safe', applied_policy: null }, null],
    ['risk_level=safe, applied_policy=approved', { finding_type: 'license', risk_level: 'safe', applied_policy: 'approved' }, null],
    ['copyright', { finding_type: 'copyright', severity: 'critical' }, null],
  ])('AC-P22-9: %s', (_n, row, expected) => {
    expect(effectiveLevel(row)).toBe(expected);
  });

  it('AC-P22-8: only open/in_review security and license findings are counted', () => {
    for (const status of ['open', 'in_review']) expect(isCounted({ status, finding_type: 'security' })).toBe(true);
    for (const status of ['resolved', 'accepted', 'false_positive', 'wont_fix']) expect(isCounted({ status, finding_type: 'license' })).toBe(false);
    expect(isCounted({ status: 'open', finding_type: 'copyright' })).toBe(false);
    const rows = [
      finding({ severity: 'critical', status: 'false_positive' }),
      finding({ severity: 'critical', status: 'accepted' }),
      finding({ finding_type: 'copyright', status: 'open' }),
      finding({ severity: 'critical', status: 'in_review' }),
      finding({ finding_type: 'license', risk_level: 'unknown', status: 'open' }),
      null,
      'garbage',
    ];
    const ev = evaluateFindings(rows, 'high');
    expect(ev.counts).toEqual({ security: { low: 0, medium: 0, high: 0, critical: 1 }, license: { low: 0, medium: 0, high: 1, critical: 0 } });
    expect(ev.breaching).toHaveLength(2);
  });
});

describe('AC-P22-10: --fail-on threshold (contract 4.3)', () => {
  const rows = [finding({ severity: 'medium' })];
  it.each<[FailOn, number]>([
    ['none', 0],
    ['low', 1],
    ['medium', 1],
    ['high', 0],
    ['critical', 0],
  ])('AC-P22-10: one medium finding with --fail-on %s -> %i breaching', (failOn, n) => {
    const ev = evaluateFindings(rows, failOn);
    expect(ev.breaching).toHaveLength(n);
    expect(ev.counts.security.medium).toBe(1); // counts are independent of the threshold
  });

  it('AC-P22-10 / contract 5.6: breaching order level desc -> package (code point) -> version (null first) -> id; identity rules', () => {
    const ev = evaluateFindings(
      [
        finding({ severity: 'high', package_name: 'b', package_version: '1.0.0', cve_id: 'CVE-2', ghsa_id: 'GHSA-x' }),
        finding({ severity: 'critical', package_name: 'z', package_version: '1.0.0', cve_id: null, ghsa_id: 'GHSA-1' }),
        finding({ severity: 'high', package_name: 'b', package_version: null, cve_id: null, ghsa_id: null }),
        finding({ severity: 'high', package_name: 'B', package_version: '1.0.0', cve_id: 'CVE-1' }),
        finding({ severity: 'high', package_name: '\u{1F600}', package_version: '1.0.0', cve_id: 'CVE-3' }),
        finding({ severity: 'high', package_name: '￿', package_version: '1.0.0', cve_id: 'CVE-4' }),
        finding({ finding_type: 'license', risk_level: 'unknown', package_name: 'b', package_version: '1.0.0', normalized_license: null, detected_license: 'Custom' }),
        finding({ finding_type: 'license', risk_level: 'high', package_name: 'b', package_version: '1.0.0', normalized_license: null, detected_license: null }),
      ],
      'high',
    );
    expect(ev.breaching.map((b) => `${b.level}|${b.package}|${b.version}|${b.id}|${b.type}`)).toEqual([
      'critical|z|1.0.0|GHSA-1|security',
      'high|B|1.0.0|CVE-1|security',
      'high|b|null|-|security',
      'high|b|1.0.0|CVE-2|security',
      'high|b|1.0.0|Custom|license',
      'high|b|1.0.0|unknown|license',
      'high|￿|1.0.0|CVE-4|security',
      'high|\u{1F600}|1.0.0|CVE-3|security',
    ]);
    const a: BreachItem = { type: 'security', package: 'a', version: '1', level: 'low', id: 'x' };
    expect(compareBreach(a, { ...a })).toBe(0);
  });
});

describe('AC-P22-13: data completeness and decision (contract 4.4, 5.1, 5.4)', () => {
  const SID = '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f';
  const body = (latest: string, status: unknown) => ({ data: { projects: [{ latest_scan_id: latest, vulnerability_data_status: status }] } });

  it('AC-P22-13: status mapping incl. no match, case-insensitive id, endpoint failure (null body), unrecognised value', () => {
    expect(dataStatusFrom(body(SID, 'complete'), SID)).toBe('complete');
    expect(dataStatusFrom(body(SID.toUpperCase(), 'disabled'), SID)).toBe('disabled');
    expect(dataStatusFrom(body(SID, 'partial'), SID)).toBe('partial');
    expect(dataStatusFrom(body(SID, 'unavailable'), SID)).toBe('unavailable');
    expect(dataStatusFrom(body(SID, null), SID)).toBe('not_checked');
    expect(dataStatusFrom(body('00000000-0000-4000-8000-000000000000', 'complete'), SID)).toBe('unknown');
    expect(dataStatusFrom(body(SID, 'weird'), SID)).toBe('unknown');
    expect(dataStatusFrom(null, SID)).toBe('unknown');
    expect(dataStatusFrom({ data: { projects: 'x' } }, SID)).toBe('unknown');
  });

  const W_DISABLED = 'vulnerability lookup is disabled on the server; security findings were not checked';
  const W_INC = (s: string) => `vulnerability data is ${s} for scan ${SID}; security findings may be missing`;
  const W_ALLOWED = '--allow-incomplete is set; incomplete vulnerability data does not change the exit code';

  it.each([
    ['complete', 'high', 0, false, 0, 'pass', []],
    ['disabled', 'high', 0, false, 0, 'pass', [W_DISABLED]],
    ['partial', 'high', 0, false, 5, 'incomplete', [W_INC('partial')]],
    ['unavailable', 'high', 0, false, 5, 'incomplete', [W_INC('unavailable')]],
    ['not_checked', 'high', 0, false, 5, 'incomplete', [W_INC('not_checked')]],
    ['unknown', 'high', 0, false, 5, 'incomplete', [W_INC('unknown')]],
    ['partial', 'high', 0, true, 0, 'pass', [W_INC('partial'), W_ALLOWED]],
    ['unknown', 'high', 2, false, 1, 'fail', [W_INC('unknown')]],
    ['unknown', 'high', 2, true, 1, 'fail', [W_INC('unknown')]],
    ['partial', 'none', 0, false, 0, 'pass', [W_INC('partial')]],
    ['disabled', 'none', 0, false, 0, 'pass', [W_DISABLED]],
    ['complete', 'low', 1, false, 1, 'fail', []],
  ] as const)('AC-P22-13 / AC-P22-12: status %s, --fail-on %s, %i breaching, allow %s -> %i %s', (status, failOn, breach, allow, exit, result, warnings) => {
    expect(decide(failOn, breach, status, allow, SID)).toEqual({ exitCode: exit, result, warnings: [...warnings] });
  });
});

describe('AC-P22-16: terminal safety (contract 5.5)', () => {
  it('AC-P22-16: singleLine fold, C0/C1 removal (ESC, CR, NEL, DEL), 200 code point cap', () => {
    // singleLine already drops the whole ANSI sequence (stricter than C0 removal alone).
    expect(cleanText('evil\u001b[2J\npkg')).toMatch(/^evil(\[2J)? pkg$/);
    expect(cleanText('a\rb\u0085c\u009bd\u007fe\u0000f\tg')).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/); // eslint-disable-line no-control-regex
    expect([...cleanText('\u{1F600}'.repeat(300))]).toHaveLength(200);
    expect([...cleanText('x'.repeat(900), 500)]).toHaveLength(500);
    expect(cleanText(null)).toBe('');
  });

  it('AC-G-8: Output redacts registered secrets (defence in depth) and counts the hits', () => {
    const out: string[] = [];
    const err: string[] = [];
    const o = new Output({ write: (c: string) => out.push(c) }, { write: (c: string) => err.push(c) });
    const k = makeApiKey();
    o.addSecret(k.key);
    o.addSecret(k.secret);
    o.out('nothing secret');
    expect(o.redactionHits).toBe(0);
    o.err(`x ${k.key} y ${k.secret}`);
    expect(err.join('')).toBe('x [redacted] y [redacted]\n');
    expect(o.redactionHits).toBe(2);
  });
});

describe('AC-P22-14 / AC-P22-15: formatters (contract 5.3, 5.6)', () => {
  const item = (i: number): BreachItem => ({ type: 'license', package: `p${String(i).padStart(3, '0')}`, version: '1.0.0', level: 'high', id: 'unknown' });
  const report = (n: number, over: Partial<ScanReport> = {}): ScanReport => ({
    result: 'fail',
    exitCode: 1,
    project: { id: '0b6e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b', name: 'demo' },
    scan: { id: '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f', status: 'completed', totalDependencies: 412 },
    failOn: 'high',
    vulnerabilityDataStatus: 'disabled',
    counts: { security: { low: 0, medium: 0, high: 0, critical: 0 }, license: { low: 3, medium: 1, high: n, critical: 0 } },
    breaching: Array.from({ length: n }, (_, i) => item(i)),
    warnings: ['w'],
    error: null,
    ...over,
  });

  it('AC-P22-14: text summary lines in contract order, 20 listed + "... and N more"', () => {
    const lines = formatTextSummary(report(25));
    expect(lines.slice(0, 9)).toEqual([
      'Project: demo (0b6e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b)',
      'Scan: 3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f',
      'Status: completed',
      'Dependencies: 412',
      'Security findings: critical=0 high=0 medium=0 low=0',
      'License findings: critical=0 high=25 medium=1 low=3',
      'Vulnerability data: disabled',
      'Fail on: high',
      'Findings at or above high: 25',
    ]);
    expect(lines[9]).toBe('  p000@1.0.0  license  high  unknown');
    expect(lines.filter((l) => l.startsWith('  p'))).toHaveLength(20);
    expect(lines[29]).toBe('  ... and 5 more');
    expect(lines[30]).toBe('Result: FAIL');
    expect(lines).toHaveLength(31);
  });

  it('AC-P22-14: --fail-on none prints no "Findings at or above" block; null version as -', () => {
    const lines = formatTextSummary(report(0, { failOn: 'none', result: 'pass', exitCode: 0, scan: { id: '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f', status: 'completed', totalDependencies: null } }));
    expect(lines.some((l) => l.startsWith('Findings at or above'))).toBe(false);
    expect(lines).toContain('Dependencies: -');
    expect(lines.at(-1)).toBe('Result: PASS');
    const withNull = formatTextSummary(report(1, { breaching: [{ ...item(0), version: null }] }));
    expect(withNull).toContain('  p000@-  license  high  unknown');
  });

  it('AC-P22-15: JSON keeps the fixed key order, validates, truncates breaching at 500', () => {
    const json = JSON.parse(formatJson(report(501)));
    expect(validateCliJson(json)).toEqual([]);
    expect(json.breaching).toHaveLength(500);
    expect(json.breachingTruncated).toBe(true);
    const small = JSON.parse(formatJson(report(500)));
    expect(small.breachingTruncated).toBe(false);
    expect(formatJson(report(1))).not.toContain('\n');
  });

  it('AC-P22-16: JSON escaping of control characters that reach the formatter', () => {
    const text = formatJson(report(1, { project: { id: '0b6e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b', name: 'a"b\\c' } }));
    expect(JSON.parse(text).project.name).toBe('a"b\\c');
  });
});
