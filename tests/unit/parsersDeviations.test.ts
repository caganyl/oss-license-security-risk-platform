/**
 * REQ-003 · P-10 deliberate deviations from the Python parsers (D-28, ADR-005
 * Karar 2, 3, 6, 7) and file-level error isolation:
 *   AC-P10-10 (SKIP_DIRS relative only), AC-P10-11 (links not followed),
 *   AC-P10-12 (per-file errors), AC-P10-13 (no absolute path in errors),
 *   AC-P10-15 (deep TOML), AC-P10-18 (case-sensitive names), AC-P10-19 (32 MiB),
 *   type-invalid manifest values and JSON NaN/Infinity (REQ-003 Riskler).
 * Fixtures: `tests/fixtures/p10-golden/formats/deviation-*`; links and large
 * files are created at run time under `os.tmpdir()` and removed afterwards.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { MAX_MANIFEST_BYTES, SKIP_DIRS, parseManifests } from '../../src/scanner/parsers';
import type { SandboxScanResult } from '../../src/types/scan';
import { FORMATS_DIR, errorTextProblems } from '../helpers/parserGolden';

const ECOSYSTEMS = ['nodejs', 'python'];
const parse = (root: string): SandboxScanResult => parseManifests(root, ECOSYSTEMS, 'deviation');
const filesOf = (r: SandboxScanResult) => r.scan_files.map((f) => f.file_path).sort();
const errorsOf = (r: SandboxScanResult) => r.parse_errors.map((e) => `${e.ecosystem}:${e.file}`).sort();
const namesOf = (r: SandboxScanResult) => r.dependencies.map((d) => d.name).sort();
const fixture = (...segments: string[]) => path.join(FORMATS_DIR, ...segments);

function expectHealthyShape(r: SandboxScanResult, root: string): void {
  expect(r.status).toBe('completed');
  expect(r.total_deps).toBe(r.dependencies.length);
  expect(errorTextProblems(r, root)).toEqual([]);
}

// ---------------------------------------------------------------------------
// temp tree helpers
// ---------------------------------------------------------------------------
let tmpBase = '';
const links: string[] = [];

function newRoot(name: string): string {
  const dir = path.join(tmpBase, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function write(root: string, rel: string, content: string | Buffer): string {
  const file = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
}

/** File of `size` bytes: `head` followed by zero bytes (truncate extends without writing the data). */
function bigFile(root: string, rel: string, size: number, head = ''): string {
  const file = write(root, rel, head);
  fs.truncateSync(file, size);
  return file;
}

function dirLink(target: string, link: string): void {
  fs.symlinkSync(target, link, 'junction'); // junction needs no privilege on Windows; a dir symlink elsewhere
  links.push(link);
}

function fileLink(target: string, link: string): void {
  fs.symlinkSync(target, link, 'file');
  links.push(link);
}

function removeLinks(): void {
  for (const link of links.splice(0).reverse()) {
    try {
      fs.unlinkSync(link);
    } catch {
      try {
        fs.rmdirSync(link);
      } catch {
        // removed with the tree below
      }
    }
  }
}

/** File symlinks need Developer Mode or an elevated shell on Windows (EPERM otherwise). */
function canCreateFileSymlinks(): boolean {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p10-symprobe-'));
  try {
    fs.writeFileSync(path.join(dir, 'target'), 'x');
    fs.symlinkSync(path.join(dir, 'target'), path.join(dir, 'link'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const FILE_SYMLINKS = canCreateFileSymlinks();
const NO_SYMLINK_NOTE = FILE_SYMLINKS ? '' : ' [skipped: file symlinks need Developer Mode/admin on Windows (EPERM)]';

beforeAll(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ossr-p10-dev-'));
});

afterAll(() => {
  removeLinks();
  if (tmpBase) fs.rmSync(tmpBase, { recursive: true, force: true });
});

const sha256 = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

// ---------------------------------------------------------------------------
describe('AC-P10-18 / D-28 d: manifest names match case-sensitively', () => {
  it('AC-P10-18: Package.json, PACKAGE.JSON, Requirements.txt, PyProject.toml, Poetry.lock … are not parsed and not in scan_files', () => {
    const root = fixture('deviation-case-mismatch');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(filesOf(r)).toEqual(['upper-lock/package.json', 'upper-yarn/package.json']);
    expect(r.parse_errors).toEqual([]);
    expect(r.scan_files.every((f) => f.filename === 'package.json')).toBe(true);
  });

  it('AC-P10-18: Package-Lock.json / Yarn.lock next to package.json are ignored, package.json is parsed lock-less', () => {
    const r = parse(fixture('deviation-case-mismatch'));
    expect(r.dependencies).toEqual([
      expect.objectContaining({ name: 'left-pad', version: null, declared_range: '^1.3.0', manifest_file: 'package.json', manifest_path: 'upper-lock' }),
      expect.objectContaining({ name: 'lodash', version: null, declared_range: '^4.17.21', manifest_file: 'package.json', manifest_path: 'upper-yarn' }),
    ]);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-10 / D-28 b: SKIP_DIRS applies only below the scan root', () => {
  it('AC-P10-10: the skip set is exactly the Python set', () => {
    expect([...SKIP_DIRS].sort()).toEqual(
      ['.git', '.hg', '.svn', '.venv', 'venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache', 'node_modules', 'dist', 'build'].sort(),
    );
  });

  it.each([
    ['build', ['package.json', 'requirements.txt']],
    ['dist', ['pyproject.toml']],
    ['env', ['package.json']],
    ['node_modules', ['poetry.lock']],
  ] as const)('AC-P10-10: root below an ancestor folder named %s still finds its manifests', (ancestor, expected) => {
    const root = fixture('deviation-skipdirs-ancestor', ancestor, 'project');
    expect(path.basename(path.dirname(root))).toBe(ancestor);
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(filesOf(r)).toEqual([...expected].sort());
    expect(r.parse_errors).toEqual([]);
    expect(r.total_deps).toBeGreaterThan(0);
  });

  it('AC-P10-10: in a temp root under build/env/node_modules ancestors, .git and node_modules below the root are skipped, Build is not', () => {
    const root = newRoot(path.join('build', 'env', 'node_modules', 'scan-root'));
    write(root, 'package.json', JSON.stringify({ dependencies: { 'root-dep': '1.0.0' } }));
    write(root, '.git/package.json', JSON.stringify({ dependencies: { 'git-dep': '1.0.0' } }));
    write(root, 'a/node_modules/x/package.json', JSON.stringify({ dependencies: { 'nm-dep': '1.0.0' } }));
    write(root, 'x/Build/requirements.txt', 'cased==1.0.0\n');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(filesOf(r)).toEqual(['package.json', 'x/Build/requirements.txt']);
    expect(namesOf(r)).toEqual(['cased', 'root-dep']);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-11 / L-4 / D-28 a: links and junctions are not followed', () => {
  it('AC-P10-11 (1): a junction to a folder outside the root is not followed; outside packages are neither parsed nor hashed', () => {
    const outside = newRoot('outside-1');
    const outsidePkg = write(outside, 'package.json', JSON.stringify({ dependencies: { 'outside-pkg': '1.0.0' } }));
    const outsideReq = write(outside, 'requirements.txt', 'outside-py==1.0.0\n');
    const root = newRoot('junction-out');
    write(root, 'package.json', JSON.stringify({ dependencies: { 'inside-pkg': '1.0.0' } }));
    fs.mkdirSync(path.join(root, 'sub'));
    dirLink(outside, path.join(root, 'linked'));
    dirLink(outside, path.join(root, 'sub', 'deeper'));

    const r = parse(root);
    expectHealthyShape(r, root);
    expect(namesOf(r)).toEqual(['inside-pkg']);
    expect(filesOf(r)).toEqual(['package.json']);
    const hashes = r.scan_files.map((f) => f.file_hash);
    expect(hashes).not.toContain(sha256(outsidePkg));
    expect(hashes).not.toContain(sha256(outsideReq));
    expect(r.parse_errors).toEqual(
      expect.arrayContaining([
        { ecosystem: 'filesystem', file: 'linked', error: expect.stringMatching(/\S/) },
        { ecosystem: 'filesystem', file: 'sub/deeper', error: expect.stringMatching(/\S/) },
      ]),
    );
    expect(errorsOf(r)).toEqual(['filesystem:linked', 'filesystem:sub/deeper']);
  });

  it('AC-P10-11 (2): a junction loop (to the root itself and to its parent) terminates and the scan completes', () => {
    const root = newRoot(path.join('loop-parent', 'loop-root'));
    write(root, 'requirements.txt', 'flask==3.0.0\n');
    dirLink(root, path.join(root, 'self'));
    dirLink(path.dirname(root), path.join(root, 'up'));
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(filesOf(r)).toEqual(['requirements.txt']);
    expect(namesOf(r)).toEqual(['flask']);
    expect(errorsOf(r)).toEqual(['filesystem:self', 'filesystem:up']);
  });

  it("AC-P10-11 (3): a junction to a folder inside the root gets one 'filesystem' record; the real folder is parsed once", () => {
    const root = newRoot('junction-in');
    write(root, 'real/package.json', JSON.stringify({ dependencies: { 'real-dep': '2.0.0' } }));
    dirLink(path.join(root, 'real'), path.join(root, 'alias'));
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(filesOf(r)).toEqual(['real/package.json']);
    expect(r.dependencies.map((d) => d.manifest_path)).toEqual(['real']);
    expect(r.parse_errors).toEqual([{ ecosystem: 'filesystem', file: 'alias', error: expect.stringMatching(/\S/) }]);
  });

  it.skipIf(!FILE_SYMLINKS)(
    `AC-P10-11: a linked package-lock.json is ignored (nodejs record) and package.json is parsed lock-less${NO_SYMLINK_NOTE}`,
    () => {
      const outside = newRoot('outside-lock');
      const lock = write(
        outside,
        'package-lock.json',
        JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/left-pad': { version: '1.3.0' } } }),
      );
      const root = newRoot('linked-lock');
      write(root, 'package.json', JSON.stringify({ dependencies: { 'left-pad': '^1.3.0' } }));
      fileLink(lock, path.join(root, 'package-lock.json'));
      const r = parse(root);
      expectHealthyShape(r, root);
      expect(filesOf(r)).toEqual(['package.json']);
      expect(r.dependencies).toEqual([expect.objectContaining({ name: 'left-pad', version: null, declared_range: '^1.3.0' })]);
      expect(r.parse_errors).toEqual([{ ecosystem: 'nodejs', file: 'package-lock.json', error: expect.stringMatching(/\S/) }]);
    },
  );

  it.skipIf(!FILE_SYMLINKS)(
    `AC-P10-11 (3) / L-2: linked manifests get an ecosystem record, an unrelated file link gets one 'filesystem' record${NO_SYMLINK_NOTE}`,
    () => {
      const outside = newRoot('outside-files');
      const req = write(outside, 'requirements.txt', 'outside-py==1.0.0\n');
      const pkg = write(outside, 'package.json', JSON.stringify({ dependencies: { 'outside-pkg': '1.0.0' } }));
      const readme = write(outside, 'README.md', '# outside\n');
      const root = newRoot('linked-files');
      fs.mkdirSync(path.join(root, 'npm'));
      fileLink(req, path.join(root, 'requirements.txt'));
      fileLink(pkg, path.join(root, 'npm', 'package.json'));
      fileLink(readme, path.join(root, 'README.md'));
      const r = parse(root);
      expectHealthyShape(r, root);
      expect(r.dependencies).toEqual([]);
      expect(r.scan_files).toEqual([]);
      // L-2 (security review): the target is never resolved, so a file link and a folder
      // link with an unrelated name are not told apart: both get a 'filesystem' record
      // (formerly ADR-005 Karar 6 skipped unrelated file links silently; deviation in the handoff).
      expect(errorsOf(r)).toEqual(['filesystem:README.md', 'nodejs:npm/package.json', 'python:requirements.txt']);
    },
  );
});

// ---------------------------------------------------------------------------
describe('L-2 (security review): link targets are never resolved; the record is chosen by name only', () => {
  it("L-2: junction with an unrelated name -> one 'filesystem' record; SKIP_DIRS names -> no record; a manifest name -> that ecosystem's record", () => {
    const outside = newRoot('l2-outside');
    write(outside, 'package.json', JSON.stringify({ dependencies: { 'outside-pkg': '1.0.0' } }));
    const root = newRoot('l2-names');
    write(root, 'requirements.txt', 'flask==3.0.0\n');
    dirLink(outside, path.join(root, 'docs-link'));
    dirLink(outside, path.join(root, 'node_modules'));
    dirLink(outside, path.join(root, 'build'));
    fs.mkdirSync(path.join(root, 'sub'));
    dirLink(outside, path.join(root, 'sub', '.venv'));
    dirLink(outside, path.join(root, 'sub', 'package.json')); // a folder link that carries a manifest name

    const r = parse(root);
    expectHealthyShape(r, root);
    expect(namesOf(r)).toEqual(['flask']);
    expect(filesOf(r)).toEqual(['requirements.txt']);
    expect(errorsOf(r)).toEqual(['filesystem:docs-link', 'nodejs:sub/package.json']);
  });

  it('L-2: walking a tree with junctions never calls fs.statSync / fs.realpathSync(.native) on a link (lstat only)', () => {
    // vi.spyOn works here: src/scanner/parsers/common.ts reads `fs.<fn>` from the shared
    // CommonJS `node:fs` default export at call time (Vitest externalises node built-ins),
    // which is the same object this file imports. The lstat spy is the positive control
    // proving that calls from the parser module are intercepted at all.
    const outside = newRoot('l2-spy-outside');
    write(outside, 'requirements.txt', 'outside==1.0.0\n');
    const root = newRoot('l2-spy');
    write(root, 'package.json', JSON.stringify({ dependencies: { 'inside-pkg': '1.0.0' } }));
    const linkPaths = [path.join(root, 'unrelated'), path.join(root, 'requirements.txt'), path.join(root, 'node_modules')];
    for (const l of linkPaths) dirLink(outside, l);

    const lstatSpy = vi.spyOn(fs, 'lstatSync');
    const statSpy = vi.spyOn(fs, 'statSync');
    const nativeSpy = vi.spyOn(fs.realpathSync, 'native');
    const realpathSpy = vi.spyOn(fs, 'realpathSync');
    // The mock replacing fs.realpathSync has no `.native`; give it the spied one.
    (fs.realpathSync as unknown as { native: unknown }).native = nativeSpy;
    let r: SandboxScanResult;
    try {
      r = parse(root);
    } finally {
      vi.restoreAllMocks();
    }

    const norm = (p: unknown) => path.resolve(String(p)).toLowerCase();
    const isLinkOrBelow = (p: unknown) => linkPaths.some((l) => norm(p) === l.toLowerCase() || norm(p).startsWith(`${l.toLowerCase()}${path.sep}`));
    const lstatArgs = lstatSpy.mock.calls.map((c) => c[0]);
    expect(lstatArgs.filter(isLinkOrBelow).length, 'positive control: lstat seen on the links').toBeGreaterThanOrEqual(3);
    const resolvingCalls = [...statSpy.mock.calls, ...realpathSpy.mock.calls, ...nativeSpy.mock.calls].map((c) => c[0]).filter(isLinkOrBelow);
    expect(resolvingCalls, 'a link target was resolved').toEqual([]);
    expect(errorsOf(r)).toEqual(['filesystem:unrelated', 'python:requirements.txt']);
    expect(namesOf(r)).toEqual(['inside-pkg']);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-19 / D-28 e: 32 MiB per-file limit', () => {
  it('AC-P10-19: the limit is 32 MiB', () => {
    expect(MAX_MANIFEST_BYTES).toBe(32 * 1024 * 1024);
  });

  it('AC-P10-19: an oversized file is not read, gets no scan_files record and only its own error; a lock-file error is recorded on package.json', () => {
    const root = newRoot('oversize');
    const over = MAX_MANIFEST_BYTES + 1024 * 1024; // 33 MiB
    bigFile(root, 'package.json', over, '{"dependencies":{"too-big":"1.0.0"}');
    write(root, 'ok/package.json', JSON.stringify({ dependencies: { 'ok-dep': '1.0.0' } }));
    write(root, 'locked/package.json', JSON.stringify({ dependencies: { 'locked-dep': '^1.0.0' } }));
    bigFile(root, 'locked/package-lock.json', over, '{"lockfileVersion":3,"packages":{}}');
    bigFile(root, 'py/requirements.txt', over, 'too-big-py==1.0.0\n');
    write(root, 'py-ok/requirements.txt', 'flask==3.0.0\n');

    const r = parse(root);
    expectHealthyShape(r, root);
    expect(errorsOf(r)).toEqual(['nodejs:locked/package.json', 'nodejs:package.json', 'python:py/requirements.txt']);
    for (const e of r.parse_errors) expect(e.error).toMatch(/32 MiB/);
    expect(filesOf(r)).toEqual(['locked/package.json', 'ok/package.json', 'py-ok/requirements.txt']);
    expect(namesOf(r)).toEqual(['flask', 'ok-dep']);
  });

  it('AC-P10-19: a file of exactly 32 MiB is still read (only files above the limit are rejected)', () => {
    const root = newRoot('edge-size');
    bigFile(root, 'requirements.txt', MAX_MANIFEST_BYTES, 'flask==3.0.0\n');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(r.parse_errors).toEqual([]);
    expect(r.scan_files).toEqual([expect.objectContaining({ file_path: 'requirements.txt', size_bytes: MAX_MANIFEST_BYTES })]);
    expect(namesOf(r)).toEqual(['flask']);
  });
});

// ---------------------------------------------------------------------------
describe('AC-P10-12 / AC-P10-13 / AC-P10-15: per-file errors without absolute paths', () => {
  it('AC-P10-12 / AC-P10-13: broken JSON, lock, TOML and invalid UTF-8 (content quoting the root path) give one record each; neighbours are parsed; no error text carries an absolute path', () => {
    const root = newRoot('broken-files');
    const native = root;
    const forward = root.replace(/\\/g, '/');
    write(root, 'bad-json/package.json', `{"p": ${native} }`);
    write(root, 'bad-json-fwd/package.json', `{"p": "${forward}" ,, }`);
    write(root, 'bad-lock/package.json', JSON.stringify({ dependencies: { 'lock-dep': '^1.0.0' } }));
    write(root, 'bad-lock/package-lock.json', `{"x": ${native} oops`);
    write(root, 'bad-toml/pyproject.toml', `[project]\nname = ${forward}\n`);
    write(root, 'bad-poetry/poetry.lock', `[[package]]\nname = "x"\n${native} = 1\n`);
    write(root, 'bad-utf8/package.json', Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0xfe, 0x22, 0x7d]));
    write(root, 'healthy/package.json', JSON.stringify({ dependencies: { 'healthy-dep': '1.0.0' } }));
    write(root, 'healthy/requirements.txt', 'requests==2.31.0\n');

    const r = parse(root);
    expectHealthyShape(r, root);
    expect(errorsOf(r)).toEqual([
      'nodejs:bad-json-fwd/package.json',
      'nodejs:bad-json/package.json',
      'nodejs:bad-lock/package.json',
      'nodejs:bad-utf8/package.json',
      'python:bad-poetry/poetry.lock',
      'python:bad-toml/pyproject.toml',
    ]);
    expect(namesOf(r)).toEqual(['healthy-dep', 'requests']);
    expect(filesOf(r)).toContain('bad-lock/package-lock.json'); // lock record stays, error is on package.json (ADR-005 Karar 2)
    for (const e of r.parse_errors) {
      expect(e.error.toLowerCase()).not.toContain(root.toLowerCase());
      expect(e.error.toLowerCase()).not.toContain(forward.toLowerCase());
      expect(e.error.toLowerCase()).not.toContain(os.tmpdir().toLowerCase());
      expect(e.error.toLowerCase()).not.toContain(os.homedir().toLowerCase());
    }
  });

  it('AC-P10-15 / AC-P10-12: excessively nested TOML and JSON become per-file errors, not a crash', () => {
    const root = newRoot('deep');
    write(root, 'deep-toml/pyproject.toml', `a = ${'['.repeat(5000)}${']'.repeat(5000)}\n`);
    write(root, 'deep-lock/poetry.lock', `[[package]]\nname = ${'{ a = '.repeat(5000)}1${' }'.repeat(5000)}\n`);
    write(root, 'deep-json/package.json', `${'['.repeat(100_000)}${']'.repeat(100_000)}`);
    write(root, 'deep-json-obj/package.json', `{"dependencies":${'{"a":'.repeat(100_000)}1${'}'.repeat(100_000)}}`);
    write(root, 'ok/requirements.txt', 'six\n');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(errorsOf(r)).toEqual([
      'nodejs:deep-json-obj/package.json',
      'nodejs:deep-json/package.json',
      'python:deep-lock/poetry.lock',
      'python:deep-toml/pyproject.toml',
    ]);
    expect(namesOf(r)).toEqual(['six']);
  });
});

// ---------------------------------------------------------------------------
describe('Type-invalid values and JSON NaN/Infinity (REQ-003 Riskler, ADR-005 Karar 2, 3)', () => {
  it('npm: null/number/bool/object/array specifiers and number versions/names in the lock give parse_errors, never a crash', () => {
    const root = fixture('deviation-typeinvalid-npm');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(errorsOf(r)).toEqual(['nodejs:lock-number-version/package.json', 'nodejs:package.json']);
    expect(r.dependencies).toEqual([]);
  });

  it('python: non-list dependencies, non-text items, string groups and non-text poetry.lock values give parse_errors, never a crash', () => {
    const root = fixture('deviation-typeinvalid-python');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(errorsOf(r)).toEqual([
      'python:optional-group-string/pyproject.toml',
      'python:poetry-lock-nonstring/poetry.lock',
      'python:project-deps-numbers/pyproject.toml',
      'python:project-deps-string/pyproject.toml',
    ]);
    // a [project.dependencies] table is iterated by key, as in Python: either way no crash and only text values
    for (const d of r.dependencies) {
      expect(typeof d.name).toBe('string');
      expect(d.version === null || typeof d.version === 'string').toBe(true);
      expect(d.manifest_path).toBe('project-deps-table');
    }
  });

  it('ADR-005 Karar 3: NaN / Infinity JSON is a parse error (lock error on the package.json path; lock scan_files record kept)', () => {
    const root = fixture('deviation-json-nan');
    const r = parse(root);
    expectHealthyShape(r, root);
    expect(errorsOf(r)).toEqual(['nodejs:lock-infinity/package.json', 'nodejs:package.json']);
    expect(filesOf(r)).toEqual(['lock-infinity/package-lock.json', 'lock-infinity/package.json', 'package.json']);
    expect(r.dependencies).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
describe('Ecosystem handling (scan.py counterpart)', () => {
  it("an unsupported ecosystem yields { ecosystem, file: '', error } and the others are still parsed", () => {
    const root = fixture('npm-lock-v2');
    const r = parseManifests(root, ['nodejs', 'java'], 'eco');
    expect(r.status).toBe('completed');
    expect(r.parse_errors).toEqual([{ ecosystem: 'java', file: '', error: expect.stringMatching(/\S/) }]);
    expect(r.total_deps).toBeGreaterThan(0);
  });

  it('comma-separated and padded ecosystem names are normalised; order is kept', () => {
    const root = fixture('py-poetry-project-and-lock');
    const a = parseManifests(root, ['nodejs', 'python'], 'eco');
    const b = parseManifests(root, [' nodejs , python ', ''], 'eco');
    expect(b).toEqual(a);
    expect(parseManifests(root, ['nodejs'], 'eco').dependencies.every((d) => d.ecosystem === 'nodejs')).toBe(true);
  });
});
