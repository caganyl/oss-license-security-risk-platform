/**
 * Source-level guards for REQ-002 (cheap regressions next to the behavioural
 * tests): AC-P01-7, AC-P01-17, AC-P03-1, AC-P03-2.
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

describe('P-03 static guards', () => {
  it('AC-P03-1: the scan worker has no Docker execution path', () => {
    expect(read('src/scanner/worker.ts')).not.toMatch(/docker/i);
    expect(filesContaining(/buildDockerRunFlags|dockerAvailable/)).toEqual([]);
  });

  it("AC-P03-2: no '.' working-directory fallback in the scan worker", () => {
    expect(read('src/scanner/worker.ts')).not.toMatch(/(workDir|cwd|work_dir)[^\n]*['"]\.['"]/);
  });
});
