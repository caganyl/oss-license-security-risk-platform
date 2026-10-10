/**
 * Source-level guards for REQ-002 (cheap regressions next to the behavioural
 * tests): AC-P01-7, AC-P01-17, AC-P03-1, AC-P03-2; REQ-003 AC-G-6 (static
 * cleanup), ADR-005 Karar 1 (parser import boundary) and AC-P10-15.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../helpers/paths';

function srcFiles(dir = path.join(REPO_ROOT, 'src')): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return srcFiles(full);
    return /\.(ts|py)$/.test(e.name) ? [full] : [];
  });
}

const rel = (f: string) => path.relative(REPO_ROOT, f).split(path.sep).join('/');
const read = (relPath: string) => fs.readFileSync(path.join(REPO_ROOT, relPath), 'utf8');
const filesContaining = (re: RegExp) => srcFiles().filter((f) => re.test(fs.readFileSync(f, 'utf8'))).map(rel);

describe('P-01 static guards', () => {
  it('AC-P01-17: no all-zero UUID fallback identity anywhere in src/', () => {
    expect(filesContaining(/00000000-0000-0000-0000-000000000000/)).toEqual([]);
  });

  it('AC-P01-7: no mock user middleware (mock session id / hard-coded admin identity) in src/', () => {
    expect(filesContaining(/mock-session-id|admin@company\.com/)).toEqual([]);
  });
});

/** Every file below the repository root except node_modules and .git (repo-relative, '/' separators). */
function repoFiles(dir = REPO_ROOT): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.name === 'node_modules' || e.name === '.git') return [];
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) return [];
    if (e.isDirectory()) return repoFiles(full);
    return [rel(full)];
  });
}

describe('REQ-003 AC-G-6 static cleanup (D-31, D-44)', () => {
  // Red until the main session deletes src/scanner/sandbox/parsers/*.py (AC-P10-17: separate commit).
  it('AC-G-6 / AC-P10-16: no .py file in the repository outside node_modules', () => {
    expect(repoFiles().filter((f) => /\.py$/i.test(f))).toEqual([]);
  });

  it('AC-G-6 / AC-P10-16: PYTHON_BIN and runPythonParser do not occur in src/', () => {
    expect(filesContaining(/PYTHON_BIN|runPythonParser/)).toEqual([]);
  });

  it('AC-G-6 / D-44: docker-compose.yml and db/migrate.sh do not exist', () => {
    expect(fs.existsSync(path.join(REPO_ROOT, 'docker-compose.yml'))).toBe(false);
    expect(fs.existsSync(path.join(REPO_ROOT, 'db', 'migrate.sh'))).toBe(false);
  });

  it("AC-G-6: package.json scripts mention no python, 'py ', bash, docker or ts-node", () => {
    const scripts = (JSON.parse(read('package.json')) as { scripts?: Record<string, string> }).scripts ?? {};
    expect(Object.keys(scripts).length).toBeGreaterThan(0);
    for (const [name, command] of Object.entries(scripts)) {
      expect(command, name).not.toMatch(/python|py |bash|docker|ts-node/i);
    }
  });
});

describe('REQ-003 AC-P12-3 single entry point (ADR-004 Karar 1, 4)', () => {
  it('src/ never reads WORKER_ID or EXPORT_WORKER_ID from the environment', () => {
    expect(filesContaining(/process\.env(\.|\[\s*['"])(EXPORT_)?WORKER_ID\b/)).toEqual([]);
    expect(filesContaining(/\b(EXPORT_)?WORKER_ID\b/)).toEqual([]);
  });

  it('package.json: build/start/db:migrate/typecheck/lint/test, no worker scripts, main = dist/main.js, engines.node ^22.21.0 || >=24.5.0 (REQ-004 ADR-006 Karar 5)', () => {
    const pkg = JSON.parse(read('package.json')) as { main?: string; engines?: { node?: string }; scripts?: Record<string, string> };
    const scripts = pkg.scripts ?? {};
    for (const name of ['build', 'start', 'db:migrate', 'typecheck', 'lint', 'test']) expect(scripts[name], name).toBeTruthy();
    for (const name of ['worker', 'worker:prod', 'export-worker', 'export-worker:prod']) expect(scripts[name], name).toBeUndefined();
    expect(scripts.start).toBe('node dist/main.js');
    expect(scripts['db:migrate']).toBe('node dist/db/migrate.js');
    expect(pkg.main).toBe('dist/main.js');
    expect(pkg.engines?.node).toBe('^22.21.0 || >=24.5.0');
  });

  it('only src/main.ts and src/db/migrate.ts are process entry points (no require.main block in app.ts or the workers)', () => {
    expect(filesContaining(/require\.main\s*===\s*module/).sort()).toEqual(['src/db/migrate.ts', 'src/main.ts']);
  });
});

describe('REQ-003 P-10 parser boundary (ADR-005 Karar 1, AC-P10-15)', () => {
  const parsersDir = path.join(REPO_ROOT, 'src', 'scanner', 'parsers');
  const ALLOWED_RUNTIME = new Set(['node:fs', 'node:path', 'node:crypto', 'node:worker_threads']);
  const SPECIFIER = /(import|export)\s+(type\s+)?(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)|import\(\s*['"]([^'"]+)['"]\s*\)/g;

  function importsOf(file: string): Array<{ spec: string; typeOnly: boolean }> {
    const source = fs.readFileSync(file, 'utf8');
    return [...source.matchAll(SPECIFIER)].map((m) => ({ spec: m[3] ?? m[4] ?? m[5], typeOnly: Boolean(m[2]) }));
  }

  it('ADR-005 Karar 1: src/scanner/parsers imports only node:fs/path/crypto/worker_threads, smol-toml (toml.ts), siblings and types; threadParser.ts may also import ../../lib/threadBootstrap (ADR-006 Karar 16)', () => {
    const files = fs.readdirSync(parsersDir).filter((n) => n.endsWith('.ts'));
    expect(files.sort()).toEqual(['common.ts', 'index.ts', 'nodejs.ts', 'python.ts', 'thread.ts', 'threadParser.ts', 'toml.ts']);
    const violations: string[] = [];
    for (const name of files) {
      const imports = importsOf(path.join(parsersDir, name));
      expect(imports.length, name).toBeGreaterThan(0);
      for (const { spec, typeOnly } of imports) {
        if (typeOnly) continue;
        if (ALLOWED_RUNTIME.has(spec)) continue;
        if (/^\.\/[A-Za-z]+$/.test(spec)) continue;
        if (spec === 'smol-toml' && name === 'toml.ts') continue;
        // Main-thread side only; thread.ts and the parser modules keep the full rule.
        if (spec === '../../lib/threadBootstrap' && name === 'threadParser.ts') continue;
        violations.push(`${name}: ${spec}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it('ADR-006 Karar 1: src/lib/threadBootstrap.ts imports only node:path (no runtime module of src/)', () => {
    const imports = importsOf(path.join(REPO_ROOT, 'src', 'lib', 'threadBootstrap.ts')).filter((i) => !i.typeOnly);
    expect(imports.map((i) => i.spec)).toEqual(['node:path']);
  });

  it('REQ-004 ADR-006 Karar 1 / AC-P15-4: archive thread modules import only node:zlib/worker_threads/buffer, each other and the import-free src/lib/textSanitize.ts', () => {
    const enrichmentDir = path.join(REPO_ROOT, 'src', 'enrichment');
    const threadModules = ['archive/thread.ts', 'archive/extract.ts', 'archive/gzip.ts', 'archive/tar.ts', 'archive/zip.ts', 'archive/licenseFiles.ts', 'text.ts', 'copyright.ts'].map(
      (p) => path.join(enrichmentDir, ...p.split('/')),
    );
    const textSanitize = path.join(REPO_ROOT, 'src', 'lib', 'textSanitize.ts');
    const allowedFiles = new Set([...threadModules, textSanitize].map((f) => path.normalize(f)));
    const allowedRuntime = new Set(['node:zlib', 'node:worker_threads', 'node:buffer']);
    const forbidden = /^(node:)?(fs|fs\/promises|net|tls|http|https|http2|dgram|dns|child_process|cluster)$|^(pg|dotenv)$|(^|\/)lib\/db$/;
    const violations: string[] = [];
    for (const file of threadModules) {
      expect(fs.existsSync(file), rel(file)).toBe(true);
      for (const { spec, typeOnly } of importsOf(file)) {
        if (forbidden.test(spec)) {
          violations.push(`${rel(file)}: ${spec} (forbidden${typeOnly ? ', even as type' : ''})`);
          continue;
        }
        if (typeOnly || allowedRuntime.has(spec)) continue;
        if (spec.startsWith('.') && allowedFiles.has(path.normalize(path.resolve(path.dirname(file), `${spec}.ts`)))) continue;
        violations.push(`${rel(file)}: ${spec}`);
      }
    }
    // textSanitize is reachable from the thread: it must not import any runtime module.
    for (const { spec, typeOnly } of importsOf(textSanitize)) if (!typeOnly) violations.push(`src/lib/textSanitize.ts: ${spec}`);
    expect(violations).toEqual([]);
  });

  it('AC-P10-15: smol-toml is imported only by src/scanner/parsers/toml.ts and pinned exactly to 1.9.0', () => {
    expect(filesContaining(/['"]smol-toml['"]/)).toEqual(['src/scanner/parsers/toml.ts']);
    const pkg = JSON.parse(read('package.json')) as { dependencies: Record<string, string> };
    expect(pkg.dependencies['smol-toml']).toBe('1.9.0');
    const lock = JSON.parse(read('package-lock.json')) as { packages: Record<string, { version?: string }> };
    expect(lock.packages['node_modules/smol-toml']?.version).toBe('1.9.0');
  });
});

describe('P-03 static guards', () => {
  it('AC-P03-1: the scan worker has no Docker execution path', () => {
    expect(read('src/scanner/worker.ts')).not.toMatch(/docker/i);
    expect(filesContaining(/buildDockerRunFlags|dockerAvailable/)).toEqual([]);
  });

  it("AC-P03-2: no '.' working-directory fallback in the scan worker", () => {
    expect(read('src/scanner/worker.ts')).not.toMatch(/(workDir|cwd|work_dir)[^\n]*['"]\.['"]/);
  });
});
