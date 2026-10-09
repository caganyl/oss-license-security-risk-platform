import path from 'node:path';

/** Repository root (tests/helpers -> repo). */
export const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** tests/fixtures directory. */
export const FIXTURES_DIR = path.join(REPO_ROOT, 'tests', 'fixtures');

export function repoPath(...segments: string[]): string {
  return path.join(REPO_ROOT, ...segments);
}
