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
    // the same rule for the profile named in the task: C:\Users\caganyy is not C:\Users\cagany
    expect(s('C:\\Users\\caganyy\\x', { ...WIN, homeDir: 'C:\\Users\\cagany' })).toBe('C:\\Users\\caganyy\\x');
    expect(s('C:\\Users\\cagany\\x', { ...WIN, homeDir: 'C:\\Users\\cagany' })).toBe('<home>\\x');
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
  // Product gap (reported to backend): secrets are masked before ANSI removal, and the
  // `\b` of the token-shape patterns does not match after the CSI final letter (`m`),
  // so `\x1b[31mghp_…` survives once the sequence is stripped. Red until fixed.
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
