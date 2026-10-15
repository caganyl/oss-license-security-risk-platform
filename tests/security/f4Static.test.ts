/**
 * REQ-005 static checks: single network module (ADR-007 Karar 1 / D-87), no
 * `fetch(` in src/, no environment-driven OSV/NVD URL (D-88, AC-P17-8), fixed
 * vulnerability hosts, vulnerability client wiring (AC-G-8). Source text only.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../helpers/paths';

function tsFiles(dir = path.join(REPO_ROOT, 'src')): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    return e.isDirectory() ? tsFiles(full) : e.name.endsWith('.ts') ? [full] : [];
  });
}
const rel = (f: string) => path.relative(REPO_ROOT, f).split(path.sep).join('/');
/** Source without line and block comments (string contents kept). */
const code = (f: string) => fs.readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
const filesMatching = (re: RegExp) => tsFiles().filter((f) => re.test(code(f))).map(rel).sort();

describe('ADR-007 Karar 1: one network module', () => {
  it('D-87: no fetch( anywhere in src/ (OSV/NVD go through the safe client)', () => {
    expect(filesMatching(/(^|[^\w.])fetch\s*\(/m)).toEqual([]);
  });

  // REQ-008 ADR-010 Karar 4, 5: the web scanner's probe client (allowlisted
  // targets, every status read) and its legacy TLS handshake probe are the
  // only other network modules. The list stays exact.
  it('D-87 / ADR-010: only the safe client and the two web scan modules issue outgoing requests or sockets', () => {
    expect(filesMatching(/\b(https?|http2)\.(request|get|connect)\b|\bnet\.(connect|createConnection)\s*\(|\btls\.connect\s*\(|['"](node:)?(undici|http2)['"]/)).toEqual([
      'src/lib/http/safeHttpClient.ts',
      'src/webscan/probeClient.ts',
      'src/webscan/tlsProbe.ts',
    ]);
  });

  it('D-87 / ADR-010: https.Agent / http.Agent are created only by the safe client and the web probe client', () => {
    expect(filesMatching(/new\s+https?\.Agent\s*\(/)).toEqual(['src/lib/http/safeHttpClient.ts', 'src/webscan/probeClient.ts']);
  });

  it('ADR-010 Karar 5: rejectUnauthorized: false appears only in the legacy TLS handshake probe', () => {
    expect(filesMatching(/rejectUnauthorized\s*:\s*false/)).toEqual(['src/webscan/tlsProbe.ts']);
  });
});

describe('D-88 / AC-P17-8: no environment-driven OSV/NVD URL', () => {
  it('AC-P17-8: OSV_API_URL / NVD_API_URL are never read (only the removed-settings list in endpoints.ts names them)', () => {
    expect(filesMatching(/(process\.)?env(\.|\[\s*['"])(OSV_API_URL|NVD_API_URL)\b/)).toEqual([]);
    expect(filesMatching(/OSV_API_URL|NVD_API_URL/)).toEqual(['src/vulnerability/endpoints.ts']);
  });

  it('AC-P17-7: OSV/NVD origins are literal in src/vulnerability/endpoints.ts only', () => {
    expect(filesMatching(/api\.osv\.dev/)).toEqual(['src/vulnerability/endpoints.ts']);
    expect(filesMatching(/services\.nvd\.nist\.gov/)).toEqual(['src/vulnerability/endpoints.ts']);
  });

  it('AC-P17-7: NVD_API_KEY is read only by src/vulnerability/client.ts (src/lib/redact.ts only masks it)', () => {
    expect(filesMatching(/env(\.|\[\s*['"])NVD_API_KEY\b/)).toEqual(['src/vulnerability/client.ts']);
    expect(filesMatching(/NVD_API_KEY/)).toEqual(['src/lib/redact.ts', 'src/vulnerability/client.ts']);
  });

  it('AC-P17-8: the runtime warns about the removed settings and never passes endpoints to the vulnerability client', () => {
    const runtime = code(path.join(REPO_ROOT, 'src', 'runtime.ts'));
    expect(runtime).toMatch(/warnRemovedVulnerabilitySettings\(/);
    const call = /createVulnerabilityClient\(\{([\s\S]*?)\}\)/.exec(runtime);
    expect(call).not.toBeNull();
    expect(call?.[1]).not.toMatch(/endpoints/);
  });
});
