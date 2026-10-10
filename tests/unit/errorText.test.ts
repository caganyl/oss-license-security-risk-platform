/**
 * REQ-003 · L-5 error text sanitizer (AC-T-4, AC-P13-8; D-48; ADR-002 Ek E3):
 * `sanitizeErrorText` in src/lib/errorText.ts. Pure apart from the
 * `os.homedir()` / `os.tmpdir()` / `process.env` defaults; most tests pass an
 * explicit context (platform, home, temp, workspace, SCAN_ROOTS, env) so the
 * result does not depend on the machine.
 *
 * Credential-shaped samples (`ghp_…`, `github_pat_…`, `glpat-…`, `ossr_…`)
 * are assembled at run time from obviously fake parts (tests/README.md
 * "Kurallar"); none of them is a real credential.
 */
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import { MAX_ERROR_TEXT_CHARS, REDACTED, sanitizeErrorText, scrubSecrets, truncateCodePoints, type ErrorTextContext } from '../../src/lib/errorText';

const FAKE_TOKEN = 'fake-test-token-0123456789';
const BASIC = Buffer.from(`x-access-token:${FAKE_TOKEN}`, 'utf8').toString('base64');
const HOME = 'C:\\Users\\qa-user';
const TEMP = 'C:\\Users\\qa-user\\AppData\\Local\\Temp';
const WORKSPACE = 'C:\\Users\\qa-user\\AppData\\Local\\Temp\\ossrisk-scan-AbC123';
const SCAN_ROOT = 'D:\\Repos\\scan-root';

const WIN: ErrorTextContext = {
  platform: 'win32',
  homeDir: HOME,
  tempDirs: [TEMP],
  workspaceDirs: [WORKSPACE],
  scanRoots: [SCAN_ROOT],
  secrets: [FAKE_TOKEN, BASIC],
  env: {},
};
const s = (text: string, ctx: ErrorTextContext = WIN) => sanitizeErrorText(text, ctx);
const fake = (...parts: string[]) => parts.join('');
const FILLER = 'FAKE0TEST0'.repeat(4);

const CONTROL_EXCEPT_NL_TAB = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/; // eslint-disable-line no-control-regex
const codePoints = (t: string) => Array.from(t).length;
/** A lone surrogate does not survive a UTF-8 round trip. */
const wellFormed = (t: string) => Buffer.from(t, 'utf8').toString('utf8') === t;

describe('AC-T-4: length limit (2000 code points, cut last)', () => {
  it('AC-T-4: MAX_ERROR_TEXT_CHARS is 2000; 3000 characters -> 2000 code points ending with "…"', () => {
    expect(MAX_ERROR_TEXT_CHARS).toBe(2000);
    const out = s('a'.repeat(3000));
    expect(codePoints(out)).toBe(2000);
    expect(out.endsWith('…')).toBe(true);
    expect(out.slice(0, -1)).toBe('a'.repeat(1999));
  });

  it('AC-T-4: exactly 2000 stays untouched; 2001 is cut to 2000', () => {
    expect(s('b'.repeat(2000))).toBe('b'.repeat(2000));
    const out = s('b'.repeat(2001));
    expect(codePoints(out)).toBe(2000);
    expect(out.endsWith('…')).toBe(true);
  });

  it('AC-T-4: surrogate pairs are never split', () => {
    const out = s('😀'.repeat(2500));
    expect(codePoints(out)).toBe(2000);
    expect(wellFormed(out)).toBe(true);
    expect(truncateCodePoints('ab😀😀', 3)).toBe('ab…');
    expect(truncateCodePoints('😀😀😀', 2)).toBe('😀…');
  });

  it('AC-T-4: the cut comes after masking, so a secret or path at the boundary leaves no fragment', () => {
    const atBoundary = s(`${'x'.repeat(1995)}${FAKE_TOKEN}`);
    expect(atBoundary).not.toContain('fake');
    const pathAtBoundary = s(`${'x'.repeat(1990)}${WORKSPACE}\\repo`);
    expect(pathAtBoundary.toLowerCase()).not.toContain('c:\\users');
    expect(codePoints(pathAtBoundary)).toBeLessThanOrEqual(2000);
  });

  it('AC-T-4: maxChars Infinity keeps the full length (caller cuts later), a custom limit is honoured', () => {
    expect(codePoints(s('c'.repeat(5000), { ...WIN, maxChars: Number.POSITIVE_INFINITY }))).toBe(5000);
    expect(s('c'.repeat(50), { ...WIN, maxChars: 10 })).toBe(`${'c'.repeat(9)}…`);
  });
});

describe('AC-T-4: absolute paths -> fixed placeholders (longest first, both separators, case-insensitive on Windows)', () => {
  it('AC-T-4: workspace under %TEMP% under the profile gets <workspace>; other temp files <temp>; other profile files <home>; SCAN_ROOTS <scan-root>', () => {
    expect(s(`${WORKSPACE}\\repo\\package.json`)).toBe('<workspace>\\repo\\package.json');
    expect(s(`${TEMP}\\other.txt`)).toBe('<temp>\\other.txt');
    expect(s(`${HOME}\\Desktop\\x`)).toBe('<home>\\Desktop\\x');
    expect(s(`${SCAN_ROOT}\\pkg\\package.json`)).toBe('<scan-root>\\pkg\\package.json');
  });

  it('AC-T-4: forward slashes, other letter case and the MSYS /c/... form are masked too', () => {
    expect(s('C:/USERS/QA-USER/APPDATA/LOCAL/TEMP/OSSRISK-SCAN-ABC123/repo')).toBe('<workspace>/repo');
    expect(s('c:\\users\\qa-user\\appdata\\local\\temp\\ossrisk-scan-abc123')).toBe('<workspace>');
    expect(s('d:/repos/SCAN-ROOT/a')).toBe('<scan-root>/a');
    expect(s('/c/Users/qa-user/.gitconfig')).toBe('<home>/.gitconfig');
    expect(s(`'${HOME}'`)).toBe("'<home>'");
  });

  it('AC-T-4: boundary rule — a longer sibling name is not masked (C:\\Users\\qa-userr, qa-user.old, qa-user2)', () => {
    for (const sibling of ['C:\\Users\\qa-userr\\file', 'C:\\Users\\qa-user.old\\file', 'C:\\Users\\qa-user2', 'C:\\Users\\qa-user_x']) {
      expect(s(sibling), sibling).toBe(sibling);
    }
    // the same rule with another (fake) profile name: C:\Users\qa-ownerr is not C:\Users\qa-owner
    expect(s('C:\\Users\\qa-ownerr\\x', { ...WIN, homeDir: 'C:\\Users\\qa-owner' })).toBe('C:\\Users\\qa-ownerr\\x');
    expect(s('C:\\Users\\qa-owner\\x', { ...WIN, homeDir: 'C:\\Users\\qa-owner' })).toBe('<home>\\x');
  });

  it('AC-T-4: on linux paths are case-sensitive', () => {
    const ctx: ErrorTextContext = { platform: 'linux', homeDir: '/home/qa', tempDirs: ['/tmp'], workspaceDirs: ['/tmp/ossrisk-scan-x'], scanRoots: ['/srv/repos'], env: {} };
    expect(s('/tmp/ossrisk-scan-x/repo /home/qa/a /srv/repos/b /tmp/c', ctx)).toBe('<workspace>/repo <home>/a <scan-root>/b <temp>/c');
    expect(s('/HOME/QA/a', ctx)).toBe('/HOME/QA/a');
  });

  it('AC-T-4: defaults mask os.homedir() and os.tmpdir() without any context', () => {
    const out = sanitizeErrorText(`see ${os.homedir()}${os.homedir().includes('\\') ? '\\' : '/'}notes.txt and ${os.tmpdir()}`, { env: {} });
    expect(out.toLowerCase()).not.toContain(os.homedir().toLowerCase());
    expect(out.toLowerCase()).not.toContain(os.tmpdir().toLowerCase());
    expect(out).toMatch(/<home>|<temp>/);
  });
});

describe('AC-T-4: secrets -> [REDACTED]', () => {
  it('AC-T-4: given secret forms (raw token, Basic base64)', () => {
    expect(s(`token ${FAKE_TOKEN} basic ${BASIC}`)).toBe(`token ${REDACTED} basic ${REDACTED}`);
    expect(scrubSecrets(`a ${FAKE_TOKEN} b`, [FAKE_TOKEN, ''])).toBe(`a ${REDACTED} b`);
  });

  it('AC-T-4: URL user:password and user-only user info', () => {
    expect(s("fatal: unable to access 'https://qa-user:not-a-real-pass@git.example.test/x.git/'")).toBe(
      `fatal: unable to access 'https://${REDACTED}@git.example.test/x.git/'`,
    );
    expect(s('https://qa-user@git.example.test/x.git')).toBe(`https://${REDACTED}@git.example.test/x.git`);
  });

  it('AC-T-4: full ossr_ API key masked; the non-secret display prefix alone stays', () => {
    const prefix = fake('ossr', '_', '0123456789abcdef');
    expect(s(`key ${prefix}_${'Q'.repeat(43)} used`)).toBe(`key ${REDACTED} used`);
    expect(s(`prefix ${prefix}`)).toBe(`prefix ${prefix}`);
  });

  it.each([
    ['ghp_', fake('gh', 'p_', FILLER)],
    ['gho_', fake('gh', 'o_', FILLER)],
    ['github_pat_', fake('github', '_pat_', FILLER, '_', FILLER)],
    ['glpat-', fake('gl', 'pat-', FILLER)],
  ])('AC-T-4: provider token shape %s', (_label, value) => {
    const out = s(`remote: invalid credentials ${value} end`);
    expect(out).toBe(`remote: invalid credentials ${REDACTED} end`);
  });

  it('AC-T-4: Authorization: Basic / Bearer / token headers and a bare Bearer value', () => {
    expect(s('> Authorization: Basic eC1hY2Nlc3MtdG9rZW46YWJj')).toBe(`> Authorization: ${REDACTED}`);
    expect(s('authorization: bearer abc.def.ghi')).toBe(`authorization: ${REDACTED}`);
    expect(s('Authorization: token qa-not-real-123')).toBe(`Authorization: ${REDACTED}`);
    expect(s('sent Bearer abcdefghijklmnop1234 to host')).toBe(`sent Bearer ${REDACTED} to host`);
  });

  it('AC-T-4: values of secret environment variables (DATABASE_URL password, ENCRYPTION_KEY)', () => {
    const env = { ENCRYPTION_KEY: 'unit-test-key-A-not-secret', DATABASE_URL: 'postgres://app:qa-db-pass-123@localhost:5432/x' };
    const out = s('k=unit-test-key-A-not-secret p=qa-db-pass-123', { ...WIN, env });
    expect(out).toBe(`k=${REDACTED} p=${REDACTED}`);
  });
});

describe('AC-T-4: secrets glued to ANSI colour sequences (git colours its output)', () => {
  // Formerly a product gap (security review L-1): secrets were masked before ANSI removal
  // and `\b` did not match after the CSI final letter (`m`). Fixed in f32b00c (control
  // characters first, `(?<![A-Za-z0-9])` start boundary); kept as a regression guard.
  it.each([
    ['ghp_', fake('gh', 'p_', FILLER)],
    ['github_pat_', fake('github', '_pat_', FILLER, '_', FILLER)],
    ['glpat-', fake('gl', 'pat-', FILLER)],
  ])('AC-T-4: %s directly after \\x1b[31m is still [REDACTED]', (_label, value) => {
    const out = s(`remote: \x1b[31m${value}\x1b[0m denied`);
    expect(out).not.toContain(value);
    expect(out).toBe(`remote: ${REDACTED} denied`);
  });
});

describe('AC-T-4: control characters', () => {
  it('AC-T-4: ANSI CSI removed, CRLF -> LF, C0 (except \\n, \\t), DEL and C1 removed', () => {
    expect(s('\x1b[31mred\x1b[0m \x1b[1;32mgreen\x1b[K')).toBe('red green');
    expect(s('a\r\nb\rc')).toBe('a\nbc');
    expect(s('x\x00y\x07z\x08\x0b\x0c\x1f\x7f\x85\x9b!')).toBe('xyz!');
    expect(s('keep\ttab\nand newline')).toBe('keep\ttab\nand newline');
  });
});

describe('L-1 (security review): control characters are removed before masking; token boundaries, letter case, format characters', () => {
  const GH = fake('gh', 'p_', FILLER);
  const NO_FILLER = 'FAKE0TEST0';

  it('L-1: a provider token split by a lone \\r (short first part) is joined by the control-character step and then masked', () => {
    const split = fake('gh', 'p_', FILLER.slice(0, 10), '\r', FILLER.slice(10));
    expect(s(`remote: ${split} end`)).toBe(`remote: ${REDACTED} end`);
  });

  // Product bug (found by QA after f32b00c, reported to backend): when the part before
  // the control character is itself a complete token shape (>= 20 characters after
  // `ghp_`), the raw pre-pass masks only that part; step 1 then glues the rest of the
  // token to the placeholder ("[REDACTED]FAKE0TEST0…") and step 2 no longer sees a token.
  // Expected: the whole token disappears. Red until fixed.
  it('L-1: a provider token split by a lone \\r after 20 characters leaves no fragment', () => {
    const split = fake('gh', 'p_', FILLER.slice(0, 20), '\r', FILLER.slice(20));
    const out = s(`remote: ${split} end`);
    expect(out).not.toContain(FILLER.slice(20));
    expect(out).toBe(`remote: ${REDACTED} end`);
  });

  it('L-1: the job token from context.secrets split by \\x00 is masked after joining', () => {
    expect(s(`token ${FAKE_TOKEN.slice(0, 8)}\x00${FAKE_TOKEN.slice(8)} end`)).toBe(`token ${REDACTED} end`);
  });

  it('L-1: a token after a percent escape (%3Aghp_…) or after "_" (_ghp_…) is masked', () => {
    expect(s(`fatal: https%3A${GH}%40git.example.test`)).toBe(`fatal: https%3A${REDACTED}%40git.example.test`);
    expect(s(`x=_${GH}`)).toBe(`x=_${REDACTED}`);
    expect(s(`x=_${fake('gl', 'pat-', FILLER)}`)).toBe(`x=_${REDACTED}`);
  });

  it('L-1: Bearer and Basic values in any letter case (bearer, BEARER, BASIC)', () => {
    const otherBasic = Buffer.from('qa-user:not-a-real-pass-123', 'utf8').toString('base64'); // not in context.secrets
    expect(s('sent bearer abcdefghijklmnop1234 to host')).toBe(`sent bearer ${REDACTED} to host`);
    expect(s('sent BEARER abcdefghijklmnop1234 to host')).toBe(`sent BEARER ${REDACTED} to host`);
    expect(s(`auth BASIC ${otherBasic} sent`)).toBe(`auth BASIC ${REDACTED} sent`);
    expect(s(`auth basic ${otherBasic} sent`)).toBe(`auth basic ${REDACTED} sent`);
  });

  it('L-1: a profile path split by \\x00 (C:\\Users\\qa\\x00-user) is masked after joining', () => {
    expect(s('see C:\\Users\\qa\x00-user\\x')).toBe('see <home>\\x');
    expect(s('see C:/Users/qa-\x07user/x')).toBe('see <home>/x');
  });

  it('L-1: a CSI whose final byte is the drive letter (ESC[1C:\\Users\\…) does not expose the profile path', () => {
    for (const input of ['see \x1b[1C:\\Users\\qa-user\\.gitconfig', 'see \x9b1C:\\Users\\qa-user\\.gitconfig', 'see \x1b[1;2C:/Users/qa-user/.gitconfig']) {
      const out = s(input);
      expect(out.toLowerCase(), JSON.stringify(input)).not.toContain('qa-user');
      expect(out.toLowerCase(), JSON.stringify(input)).not.toContain('users');
      expect(out).not.toMatch(CONTROL_EXCEPT_NL_TAB);
    }
  });

  it('L-1: a token glued to unfinished CSI parameters (ESC[31 + token, 8-bit CSI) does not survive', () => {
    for (const input of [`remote: \x1b[31${GH} end`, `remote: \x9b31${GH} end`, `remote: \x1b[${GH} end`, `remote: \x1b[1;31m${GH}\x1b[0m end`]) {
      const out = s(input);
      expect(out, JSON.stringify(input)).not.toContain(NO_FILLER);
      expect(out).not.toMatch(CONTROL_EXCEPT_NL_TAB);
    }
  });

  it('L-1: an OSC 8 hyperlink is removed whole (ST or BEL terminator, 7-bit and 8-bit); the link target with credentials disappears', () => {
    expect(s('see \x1b]8;;https://qa-user:not-a-real-pass@git.example.test/x\x1b\\the docs\x1b]8;;\x1b\\ now')).toBe('see the docs now');
    expect(s('see \x1b]8;;https://git.example.test/x\x07the docs\x1b]8;;\x07 now')).toBe('see the docs now');
    expect(s('see \x9d8;;https://git.example.test/x\x9cthe docs\x9d8;;\x9c now')).toBe('see the docs now');
    expect(s('title \x1b]0;window title\x07done')).toBe('title done');
  });

  it('L-1 / I-8: format characters (U+202E RTL override, U+200B zero width, U+2060, U+FEFF) are removed; a token split by U+200B is masked', () => {
    expect(s('abc\u202Edef\u200Bghi\u2060jkl\uFEFF')).toBe('abcdefghijkl');
    expect(s(`remote: ${fake('gh', 'p_', FILLER.slice(0, 10), '\u200B', FILLER.slice(10))} end`)).toBe(`remote: ${REDACTED} end`);
  });

  // Time limit: required < 1 s; asserted < 2 s for CI headroom (a quadratic rescan of
  // 200 000 unterminated control strings would take minutes).
  it.each([
    ['200 000 x \\x9d (unterminated 8-bit OSC)', '\x9d'.repeat(200_000)],
    ['100 000 x ESC ]', '\x1b]'.repeat(100_000)],
    ['100 000 x ESC [', '\x1b['.repeat(100_000)],
    ['\\x90 + 200 000 characters without terminator', `\x90${'a'.repeat(200_000)}`],
    ['100 000 x "\\x9b1"', '\x9b1'.repeat(100_000)],
  ])('L-1: %s is sanitized in linear time', (_label, input) => {
    const start = performance.now();
    const out = s(input);
    const ms = performance.now() - start;
    expect(out).not.toMatch(CONTROL_EXCEPT_NL_TAB);
    expect(codePoints(out)).toBeLessThanOrEqual(2000);
    expect(ms, `took ${ms.toFixed(0)} ms`).toBeLessThan(2_000);
  });
});

describe('AC-T-4 / ADR-002 Ek E3 test spec: one fake git stderr with every element', () => {
  it('AC-T-4: token (raw + base64), workspace (two separators, other case), SCAN_ROOTS, profile, \\x1b[31m, \\x00, \\x07 and 3000 characters', () => {
    const stderr = [
      `\x1b[31mfatal:\x1b[0m unable to access 'https://x-access-token:${FAKE_TOKEN}@github.com/o/r.git/'\x07`,
      `trace: Authorization: Basic ${BASIC}\x00`,
      `Cloning into 'C:/users/QA-USER/AppData/Local/Temp/ossrisk-scan-abc123/repo'...`,
      `error: ${WORKSPACE}\\repo\\.git\\config locked`,
      `file ${SCAN_ROOT}\\app\\package.json`,
      `see ${HOME}\\.gitconfig`,
      fake('remote: ', 'gh', 'p_', FILLER),
      'x'.repeat(3000),
    ].join('\r\n');
    const out = s(stderr);
    expect(codePoints(out)).toBeLessThanOrEqual(2000);
    expect(out).not.toContain(FAKE_TOKEN);
    expect(out).not.toContain(BASIC);
    expect(out.toLowerCase()).not.toContain('qa-user');
    expect(out.toLowerCase()).not.toContain('d:\\repos');
    expect(out).not.toContain(FILLER);
    expect(out).not.toMatch(CONTROL_EXCEPT_NL_TAB);
    expect(out).not.toContain('\r');
    expect(out).toContain('<workspace>/repo');
    expect(out).toContain('<workspace>\\repo\\.git\\config');
    expect(out).toContain('<scan-root>\\app');
    expect(out).toContain('<home>\\.gitconfig');
    expect(out.split(REDACTED).length - 1).toBeGreaterThanOrEqual(3);
  });

  it('AC-T-4: non-string input is stringified', () => {
    expect(sanitizeErrorText(42 as unknown as string, { env: {} })).toBe('42');
  });
});
