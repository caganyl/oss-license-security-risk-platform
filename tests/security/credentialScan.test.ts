/**
 * REQ-002 · P-09 (AC-P09-1, AC-P09-2, AC-P09-4)
 * A small gitleaks-like scan over the working tree (tracked + untracked,
 * not ignored). Failures report file:line:rule only — never the matched
 * value, so the test output itself does not re-leak anything.
 * Excluded: tests/** (deliberate non-secret test values), package-lock.json
 * (integrity hashes), binary files.
 * Synthetic samples in the self-check are assembled at run time so this file
 * itself contains no credential-shaped literal.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../helpers/paths';

function workingTreeFiles(): string[] {
  const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: REPO_ROOT });
  return out
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .filter((f) => fs.existsSync(path.join(REPO_ROOT, f)));
}

const EXCLUDED = [/^tests\//, /(^|\/)package-lock\.json$/, /\.(pdf|png|jpe?g|gif|ico|zip|gz|woff2?|ttf)$/i];
const CONFIG_FILE = /(\.ya?ml|\.env(\..*)?|\.ini|\.toml|\.properties|\.cfg|\.conf|\.json|\.sh|\.ps1|Dockerfile[^/]*)$/i;
const CODE_FILE = /\.(ts|tsx|js|mjs|cjs|py|sql)$/i;
const PLACEHOLDER =
  /^(<[^>]*>?|\$\{?[A-Za-z_][^}]*\}?|\$\(.*\)|changeme|change[-_]?me.*|your[-_].*|x{3,}|\*{3,}|\.{3}|…|example.*|placeholder.*|null|none|true|false|\d+|token|password|secret)$/i;

const SECRET_WORDS = ['PASS' + 'WORD', 'PASS' + 'WD', 'SEC' + 'RET', 'TOK' + 'EN', 'API_?KEY', 'ENCRYPTION_KEY', 'PRIVATE_KEY', 'ACCESS_KEY'].join('|');

interface Rule {
  id: string;
  applies: (file: string) => boolean;
  re: RegExp;
  /** capture group holding the value to check against PLACEHOLDER (0 = no check) */
  valueGroup: number;
}

const RULES: Rule[] = [
  { id: 'credential-in-url', applies: () => true, re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"<>{}()[\]]+:([^\s/@'"<>{}()[\]]+)@/gi, valueGroup: 1 },
  {
    id: 'credential-assignment',
    applies: (f) => CONFIG_FILE.test(f),
    re: new RegExp(`^[\\s-]*["']?[A-Za-z0-9_.-]*?(?:${SECRET_WORDS})["']?\\s*[:=]\\s*["']?([^\\s"'#,}]+)`, 'gim'),
    valueGroup: 1,
  },
  {
    id: 'credential-literal-in-code',
    applies: (f) => CODE_FILE.test(f),
    re: new RegExp(`\\b[A-Za-z0-9_]*(?:${SECRET_WORDS}|apikey)\\s*[:=]\\s*['"\`]([^'"\`\\s]{6,})['"\`]`, 'gi'),
    valueGroup: 1,
  },
  {
    id: 'credential-env-default',
    applies: (f) => CODE_FILE.test(f),
    re: new RegExp(`process\\.env\\.[A-Z0-9_]*(?:${SECRET_WORDS}|KEY|DATABASE_URL)\\s*(?:\\|\\||\\?\\?)\\s*['"\`]([^'"\`]+)['"\`]`, 'g'),
    valueGroup: 1,
  },
  { id: 'private-key-block', applies: () => true, re: new RegExp(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIV${'ATE'} KEY`, 'g'), valueGroup: 0 },
  { id: 'github-token', applies: () => true, re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g, valueGroup: 0 },
  { id: 'aws-access-key', applies: () => true, re: /\bAKIA[0-9A-Z]{16}\b/g, valueGroup: 0 },
  { id: 'slack-token', applies: () => true, re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, valueGroup: 0 },
  { id: 'google-api-key', applies: () => true, re: /\bAIza[0-9A-Za-z_-]{35}\b/g, valueGroup: 0 },
  { id: 'npm-token', applies: () => true, re: /\bnpm_[A-Za-z0-9]{36}\b/g, valueGroup: 0 },
  { id: 'ossr-api-key', applies: () => true, re: /\bossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}\b/g, valueGroup: 0 },
];

function matches(rule: Rule, line: string): boolean {
  rule.re.lastIndex = 0;
  for (let m = rule.re.exec(line); m; m = rule.re.exec(line)) {
    const value = rule.valueGroup ? (m[rule.valueGroup] ?? '') : 'x';
    if (rule.valueGroup && (value.length < 4 || PLACEHOLDER.test(value))) continue;
    return true;
  }
  return false;
}

function scanWorkingTree(): string[] {
  const findings: string[] = [];
  for (const file of workingTreeFiles()) {
    if (EXCLUDED.some((re) => re.test(file))) continue;
    const buf = fs.readFileSync(path.join(REPO_ROOT, file));
    if (buf.includes(0)) continue; // binary
    buf
      .toString('utf8')
      .split(/\r?\n/)
      .forEach((line, idx) => {
        for (const rule of RULES) {
          if (rule.applies(file) && matches(rule, line)) findings.push(`${file}:${idx + 1}: ${rule.id}`);
        }
      });
  }
  return [...new Set(findings)];
}

const rule = (id: string) => RULES.find((r) => r.id === id)!;
const sampleValue = ['s3', 'cr3t', 'val', 'ue9'].join('');

describe('P-09 no hard-coded credentials in the working tree', () => {
  it('scanner self-check: rules fire on synthetic samples and ignore placeholders', () => {
    expect(matches(rule('credential-in-url'), `DATABASE_URL=postgres://app:${sampleValue}@db:5432/x`)).toBe(true);
    expect(matches(rule('credential-in-url'), 'postgres://<kullanici>@localhost:5432/<veritabani>')).toBe(false);
    expect(matches(rule('credential-in-url'), 'postgres://${DB_USER}:${DB_PASS}@db:5432/x')).toBe(false);
    expect(matches(rule('credential-assignment'), `      POSTGRES_${'PASS'}WORD: ${sampleValue}`)).toBe(true);
    expect(matches(rule('credential-assignment'), '      - ENCRYPTION_KEY=${ENCRYPTION_KEY}')).toBe(false);
    expect(matches(rule('credential-assignment'), 'ENCRYPTION_KEY=')).toBe(false);
    expect(matches(rule('credential-literal-in-code'), `const apiTok${'en'} = '${sampleValue}';`)).toBe(true);
    expect(matches(rule('credential-env-default'), `process.env.ENCRYPTION_KEY || '${sampleValue}'`)).toBe(true);
  });

  it('AC-P09-1 / AC-P09-4: gitleaks-like scan of tracked and untracked files is clean', () => {
    const findings = scanWorkingTree();
    expect(findings, `hard-coded credentials found (values not shown):\n${findings.join('\n')}`).toEqual([]);
  });
});

describe('P-09 env example file (AC-P09-2)', () => {
  const file = path.join(REPO_ROOT, ['.env', 'example'].join('.'));

  it('AC-P09-2: .env is git-ignored and the example file is not', () => {
    const lines = fs.readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8').split(/\r?\n/).map((l) => l.trim());
    expect(lines).toContain('.env');
    expect(lines).not.toContain(path.basename(file));
  });

  it('AC-P09-2: the example file exists and lists the required variables', () => {
    expect(fs.existsSync(file), `${path.basename(file)} is missing`).toBe(true);
    const keys = fs
      .readFileSync(file, 'utf8')
      .split(/\r?\n/)
      .map((l) => /^\s*([A-Z][A-Z0-9_]*)\s*=/.exec(l)?.[1])
      .filter(Boolean);
    expect(keys).toEqual(
      expect.arrayContaining(['DATABASE_URL', 'ENCRYPTION_KEY', 'HOST', 'PORT', 'SCAN_ROOTS', 'SCAN_CLONE_TIMEOUT_MS', 'PYTHON_BIN']),
    );
  });

  it('AC-P09-2: credential-bearing variables in the example file hold no real value', () => {
    expect(fs.existsSync(file), `${path.basename(file)} is missing`).toBe(true);
    const sensitive = new RegExp(SECRET_WORDS);
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (!m) continue;
      const [, key, raw] = m;
      const value = raw.replace(/^["']|["']$/g, '').trim();
      if (sensitive.test(key)) {
        expect(value === '' || PLACEHOLDER.test(value), `${key} must be empty or a placeholder`).toBe(true);
      }
      if (key === 'DATABASE_URL') {
        expect(/:\/\/[^/@\s]+:[^/@\s<]+@/.test(value), 'DATABASE_URL must not embed a password').toBe(false);
      }
    }
  });
});
