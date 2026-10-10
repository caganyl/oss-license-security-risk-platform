/**
 * REQ-004 static checks: AC-G-5 (no new runtime dependency, engines), no
 * environment-driven registry URL (ADR-006 Karar 4 host allow list), runtime
 * enricher wiring and close (ADR-006 Karar 14), NOTICE route guard
 * (AC-P15-11). Source text inspection only.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { repoPath } from '../helpers/paths';

const read = (...p: string[]) => fs.readFileSync(repoPath(...p), 'utf8');
function tsFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    return e.isDirectory() ? tsFiles(full) : e.name.endsWith('.ts') ? [full] : [];
  });
}

describe('AC-G-5: dependencies', () => {
  it('AC-G-5 / D-80: runtime dependencies are exactly the F2 set (no proxy package); engines.node ^22.21.0 || >=24.5.0', () => {
    const pkg = JSON.parse(read('package.json')) as { dependencies: Record<string, string>; engines: { node: string } };
    expect(Object.keys(pkg.dependencies).sort()).toEqual(['dotenv', 'exceljs', 'express', 'pdfkit', 'pg', 'smol-toml']);
    expect(pkg.engines.node).toBe('^22.21.0 || >=24.5.0');
  });
});

describe('ADR-006 host allow list: registry endpoints are not configurable from the environment', () => {
  it('AC-P14-9: src/enrichment has no env-driven registry URL; the three hosts are literal', () => {
    const files = tsFiles(repoPath('src', 'enrichment'));
    expect(files.length).toBeGreaterThan(0);
    const all = files.map((f) => fs.readFileSync(f, 'utf8')).join('\n');
    expect(all).not.toMatch(/REGISTRY_URL|NPM_REGISTRY|npm_config_registry|PIP_INDEX_URL|PYPI_URL|REGISTRY_HOST/i);
    for (const host of ['registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org']) expect(all).toContain(host);
  });
});

describe('ADR-006 Karar 14: runtime enricher wiring', () => {
  it('AC-P14-15 / AC-P14-16: runtime creates the enricher from config (unless injected) and closes it on shutdown and failed start', () => {
    const src = read('src', 'runtime.ts');
    expect(src).toMatch(/createDependencyEnricher\(\{\s*config: sandboxRunnerConfig\.enrichment/);
    expect(src).toMatch(/if \(this\.options\.scanWorker\?\.enricher === undefined\)/);
    const closes = src.match(/this\.closeEnricher\(\)/g) ?? [];
    expect(closes.length).toBeGreaterThanOrEqual(2);
    expect(src).toMatch(/this\.enricher\.close\(\)/);
  });

  it('AC-P15-11: NOTICE route is GET /scans/:scanId/notice behind guard(reports:read)', () => {
    const src = read('src', 'routes', 'noticeRoutes.ts');
    expect(src).toMatch(/\.get\(\s*['"]\/scans\/:scanId\/notice['"]\s*,\s*guard\(['"]reports:read['"]\)/);
  });
});
