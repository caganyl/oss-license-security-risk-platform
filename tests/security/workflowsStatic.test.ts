/**
 * REQ-007 P-23 · AC-P23-8 static check of the two GitHub Actions workflows
 * (contract section 10, ADR-009 Karar 11, D-202). The files are read as
 * text; no YAML parser dependency is added (AC-P23-8, AC-G-5). The small
 * indentation-based helpers below only extract what the rules need:
 * top-level blocks, `uses:` lines, `run:` scripts (single line or block
 * scalar), jobs with their `runs-on` / `timeout-minutes`.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../helpers/paths';

const WORKFLOW_DIR = path.join(REPO_ROOT, '.github', 'workflows');
const CI = 'ci.yml';
const EXAMPLE = 'oss-risk-example.yml';
const read = (name: string) => fs.readFileSync(path.join(WORKFLOW_DIR, name), 'utf8');
const linesOf = (text: string) => text.split(/\r?\n/);
const indent = (line: string) => line.length - line.trimStart().length;
const isContent = (line: string) => line.trim() !== '' && !line.trimStart().startsWith('#');

/** Lines of the block that starts at a line matching `^<key>:` at indentation `level` (children only). */
function block(lines: string[], key: string, level = 0): string[] | null {
  const start = lines.findIndex((l) => indent(l) === level && new RegExp(`^\\s*(- )?${key}:`).test(l));
  if (start === -1) return null;
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (isContent(lines[i]) && indent(lines[i]) <= level) break;
    out.push(lines[i]);
  }
  return out;
}

/** Every `run:` script: inline value or the block scalar lines below it. */
function runScripts(lines: string[]): string[] {
  const scripts: string[] = [];
  lines.forEach((line, i) => {
    const m = /^(\s*)(?:- )?run:\s*(.*)$/.exec(line);
    if (!m) return;
    const keyIndent = indent(line) + (line.trimStart().startsWith('- ') ? 2 : 0);
    const value = m[2].trim();
    if (value !== '' && !/^[|>][-+]?$/.test(value)) {
      scripts.push(value);
      return;
    }
    const body: string[] = [];
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() !== '' && indent(lines[j]) <= keyIndent) break;
      body.push(lines[j]);
    }
    scripts.push(body.join('\n'));
  });
  return scripts;
}

/** Job name -> job block lines (jobs are the 2-space children of `jobs:`). */
function jobs(lines: string[]): Map<string, string[]> {
  const jobsBlock = block(lines, 'jobs') ?? [];
  const map = new Map<string, string[]>();
  let current: string | null = null;
  for (const line of jobsBlock) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (m) {
      current = m[1];
      map.set(current, []);
    } else if (current) {
      map.get(current)!.push(line);
    }
  }
  return map;
}

const value = (lines: string[], key: string, level: number): string | null => {
  const l = lines.find((x) => indent(x) === level && x.trimStart().startsWith(`${key}:`));
  return l ? l.trim().slice(key.length + 1).trim() : null;
};

describe('AC-P23-8: helper self-check (negative control)', () => {
  it('AC-P23-8: runScripts sees expressions in inline and block run: values; jobs() reads runs-on/timeout', () => {
    const sample = linesOf(
      [
        'jobs:',
        '  bad:',
        '    runs-on: windows-latest',
        '    timeout-minutes: 45',
        '    steps:',
        '      - run: echo "${{ github.event.pull_request.title }}"',
        '      - name: block',
        '        run: |',
        '          echo one',
        '          echo "${{ inputs.online }}"',
        '      - uses: someone/action@v1',
      ].join('\n'),
    );
    const scripts = runScripts(sample);
    expect(scripts).toHaveLength(2);
    expect(scripts.every((s) => s.includes('${{'))).toBe(true);
    const body = jobs(sample).get('bad')!;
    expect(value(body, 'runs-on', 4)).toBe('windows-latest');
    expect(value(body, 'timeout-minutes', 4)).toBe('45');
  });
});

describe.each([CI, EXAMPLE])('AC-P23-8: %s static rules', (name) => {
  const text = read(name);
  const lines = linesOf(text);

  it('AC-P23-8: no tab characters', () => {
    expect(text.includes('\t')).toBe(false);
  });

  it('AC-P23-5: triggers push, pull_request (no branch filter) and workflow_dispatch; no pull_request_target', () => {
    const on = block(lines, 'on');
    expect(on).not.toBeNull();
    const keys = on!.filter((l) => indent(l) === 2 && isContent(l)).map((l) => l.trim().replace(/:.*$/, ''));
    expect(keys).toEqual(['push', 'pull_request', 'workflow_dispatch']);
    for (const trigger of ['push', 'pull_request']) {
      const children = (block(on!, trigger, 2) ?? []).filter(isContent);
      expect(children, `${trigger} has no filters`).toEqual([]);
    }
    expect(text).not.toContain('pull_request_target');
  });

  it('AC-P23-5: workflow-level permissions exactly contents: read; no job-level permissions; no secrets', () => {
    const perms = (block(lines, 'permissions') ?? []).filter(isContent).map((l) => l.trim());
    expect(perms).toEqual(['contents: read']);
    expect(lines.filter((l) => /^\s+permissions:/.test(l))).toEqual([]);
    expect(text).not.toMatch(/\$\{\{\s*secrets\./);
    expect(text).not.toMatch(/write-all|read-all/);
  });

  it('AC-P23-5: concurrency group per workflow and ref, cancel-in-progress', () => {
    const c = (block(lines, 'concurrency') ?? []).filter(isContent).map((l) => l.trim());
    expect(c).toContain('group: ${{ github.workflow }}-${{ github.ref }}');
    expect(c).toContain('cancel-in-progress: true');
  });

  it('AC-P23-5 / AC-P23-8: every uses: is a first-party actions/* pinned to a 40-hex SHA with a version comment', () => {
    const uses = lines.filter((l) => /^\s*(- )?uses:/.test(l));
    expect(uses.length).toBeGreaterThanOrEqual(2);
    for (const l of uses) {
      expect(l.trim(), l).toMatch(/^(- )?uses: actions\/[a-z0-9-]+@[0-9a-f]{40} # v\d+(\.\d+){0,2}$/);
    }
  });

  it('AC-P23-5: actions/checkout never persists credentials', () => {
    const idx = lines.map((l, i) => (/uses: actions\/checkout@/.test(l) ? i : -1)).filter((i) => i >= 0);
    expect(idx.length).toBeGreaterThanOrEqual(1);
    for (const i of idx) {
      const stepIndent = indent(lines[i]);
      const rest: string[] = [];
      for (let j = i + 1; j < lines.length && !(isContent(lines[j]) && indent(lines[j]) <= stepIndent && lines[j].trimStart().startsWith('- ')); j++) {
        rest.push(lines[j].trim());
      }
      expect(rest).toContain('persist-credentials: false');
    }
  });

  it('AC-P23-5 / AC-P23-8: no ${{ … }} expression inside any run: script (inputs only through env)', () => {
    const scripts = runScripts(lines);
    expect(scripts.length).toBeGreaterThan(0);
    for (const s of scripts) {
      expect(s).not.toContain('${{');
      expect(s).not.toContain('github.event');
    }
  });

  it('AC-P23-1 / AC-P23-2 / AC-P23-8: every job has timeout-minutes <= 30 and runs on ubuntu-latest (D-202)', () => {
    const all = jobs(lines);
    expect(all.size).toBeGreaterThanOrEqual(1);
    for (const [job, body] of all) {
      const t = value(body, 'timeout-minutes', 4);
      expect(t, `${job} timeout-minutes`).toMatch(/^\d+$/);
      expect(Number(t)).toBeGreaterThan(0);
      expect(Number(t)).toBeLessThanOrEqual(30);
      expect(value(body, 'runs-on', 4), `${job} runs-on`).toBe('ubuntu-latest');
    }
  });

  it('AC-P23-1 / AC-P23-2: Node 22 with the npm cache, npm ci', () => {
    expect(text).toMatch(/uses: actions\/setup-node@[0-9a-f]{40} # v4/);
    expect(text).toContain("node-version: '22'");
    expect(text).toContain('cache: npm');
    expect(runScripts(lines)).toContain('npm ci');
  });
});

describe('AC-P23-1: ci.yml content', () => {
  const lines = linesOf(read(CI));
  it('AC-P23-1: lint, typecheck, test, build in this order; no PostgreSQL service (embedded-postgres)', () => {
    const scripts = runScripts(lines);
    const order = ['npm ci', 'npm run lint', 'npm run typecheck', 'npm test', 'npm run build'];
    expect(scripts.filter((s) => order.includes(s))).toEqual(order);
    expect(block(lines, 'services', 4)).toBeNull();
    expect(read(CI)).not.toMatch(/image:\s*postgres/);
  });
});

describe('AC-P23-2…4: oss-risk-example.yml content (contract section 10)', () => {
  const text = read(EXAMPLE);
  const lines = linesOf(text);
  const scripts = runScripts(lines);
  const all = scripts.join('\n');

  it('AC-P23-2: postgres service with a fixed (non-latest) tag and a health check', () => {
    const image = lines.find((l) => /^\s+image:/.test(l))!;
    expect(image).toBeDefined();
    expect(image.trim()).toMatch(/^image: postgres:\d+(\.\d+)?(@sha256:[0-9a-f]{64})?$/);
    expect(text).toMatch(/--health-cmd "pg_isready/);
  });

  it('AC-P23-2 (security review L-4): the postgres port is published on 127.0.0.1 only', () => {
    const ports = lines.filter((l) => /^\s+- [\d.:]*5432:5432\s*$/.test(l)).map((l) => l.trim());
    expect(ports).toEqual(['- 127.0.0.1:5432:5432']);
  });

  it('AC-P23-2: steps in order: build, migrate, start (HOST=127.0.0.1, log file), /health wait, bootstrap, scan, log tail', () => {
    const at = (needle: string) => {
      const i = scripts.findIndex((s) => s.includes(needle));
      expect(i, needle).toBeGreaterThanOrEqual(0);
      return i;
    };
    const seq = [
      at('npm run build'),
      at('npm run db:migrate'),
      at('npm start'),
      at('/health'),
      at('dist/cli/index.js bootstrap'),
      at('dist/cli/index.js scan'),
      at('tail -n 200'),
    ];
    expect([...seq].sort((a, b) => a - b)).toEqual(seq);
    expect(text).toMatch(/^\s+HOST: 127\.0\.0\.1$/m);
    expect(all).toMatch(/npm start > "\$RUNNER_TEMP\/server\.log"/);
    expect(all).toMatch(/seq 1 60/);
    const tailStep = lines.findIndex((l) => l.includes('Server log (last 200 lines)'));
    expect(lines.slice(tailStep, tailStep + 3).map((l) => l.trim())).toContain('if: always()');
  });

  it('AC-P23-2 / AC-P22-17 (N-2, N-5): bootstrap passes --new-database and --key-file under RUNNER_TEMP; CLI via node dist/cli/index.js (no npx)', () => {
    const boot = scripts.find((s) => s.includes('dist/cli/index.js bootstrap'))!;
    const oneLine = boot.replace(/\\\n/g, ' ').replace(/\s+/g, ' ').trim();
    expect(oneLine).toMatch(/node dist\/cli\/index\.js bootstrap --new-database --key-file "\$RUNNER_TEMP\/oss-risk\.key"/);
    expect(oneLine).toContain('--project-name oss-risk-self --project-path "$RUNNER_TEMP/oss-risk-target"');
    expect(oneLine).not.toContain('--url');
    expect(all).not.toMatch(/\bnpx\b/);
  });

  it('AC-P23-2 / AC-P23-8 / AC-P22-10: scan uses OSS_RISK_API_KEY_FILE, a valid --fail-on value (critical), no --allow-incomplete, no key argument', () => {
    const scan = scripts.find((s) => s.includes('dist/cli/index.js scan'))!.replace(/\\\n/g, ' ').replace(/\s+/g, ' ').trim();
    expect(scan).toMatch(/^OSS_RISK_API_KEY_FILE="\$RUNNER_TEMP\/oss-risk\.key" node dist\/cli\/index\.js scan --project oss-risk-self --fail-on critical$/);
    const failOn = [...text.matchAll(/--fail-on[ =](\S+)/g)].map((m) => m[1]);
    expect(failOn.length).toBeGreaterThanOrEqual(1);
    for (const v of failOn) expect(['none', 'low', 'medium', 'high', 'critical']).toContain(v);
    expect(all).not.toContain('--allow-incomplete');
    expect(all).not.toMatch(/--api-key|--token|--key[ =]/);
    expect(all).not.toMatch(/OSS_RISK_API_KEY=/);
    expect(all).not.toMatch(/\bcat\b[^\n]*oss-risk\.key/);
  });

  it('AC-P23-3: scan target is a copy of the root package.json + package-lock.json under RUNNER_TEMP; SCAN_ROOTS set to it', () => {
    expect(all).toContain('cp package.json package-lock.json "$RUNNER_TEMP/oss-risk-target/"');
    expect(all).toContain('echo "SCAN_ROOTS=$RUNNER_TEMP/oss-risk-target" >> "$GITHUB_ENV"');
    expect(all).not.toContain('tests/fixtures');
    expect(text).toMatch(/GITHUB_WORKSPACE/); // the adaptation comment
  });

  it('AC-P23-4: workflow_dispatch input online (boolean, default false) reaches the script only through env; offline turns all three switches off', () => {
    const inputs = block(lines, 'inputs', 4) ?? [];
    const online = block(inputs, 'online', 6) ?? [];
    const keys = online.filter(isContent).map((l) => l.trim());
    expect(keys).toContain('type: boolean');
    expect(keys).toContain('default: false');
    expect(text).toMatch(/^\s+ONLINE: \$\{\{ inputs\.online \}\}$/m);
    expect(all).toContain('if [ "$ONLINE" = "true" ]; then');
    const offline = all.slice(all.indexOf('else'));
    for (const v of ['REGISTRY_ENRICHMENT=off', 'VULNERABILITY_LOOKUP=off', 'VULNERABILITY_RECHECK=off']) expect(offline).toContain(v);
  });
});
