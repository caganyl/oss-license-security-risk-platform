/**
 * REQ-004 · P-16 SBOM license and copyright fields (AC-P16-1, -2, -4, -5,
 * -6; contract `docs/contracts/REQ-004-notice-and-outputs.md` section 6) and
 * the common text rules (section 9) through the pure SPDX / CycloneDX
 * writers. Inputs are built in memory (`SbomScanData`); the database path is
 * covered by tests/integration/f3Outputs.test.ts (AC-P16-7).
 */
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { KNOWN_SPDX_IDS } from '../../src/analysis/licenseNormalizer';
import { excelSafeText, singleLine } from '../../src/lib/outputText';
import { buildIdIndex } from '../../src/lib/spdxExpression';
import { generateCycloneDxJson, generateCycloneDxXml } from '../../src/sbom/formats/cyclonedx';
import { generateSpdxJson, generateSpdxTagValue } from '../../src/sbom/formats/spdx';
import type { SbomDependency, SbomScanData } from '../../src/sbom/sbomService';

const KNOWN = buildIdIndex([...KNOWN_SPDX_IDS]);
// Format / non-characters built from code points (never literal in the source).
const RLO = String.fromCharCode(0x202e);
const NONCHAR = String.fromCharCode(0xfffe);
/** C0 except TAB/LF/CR, U+202E, U+FFFE, U+FFFF present? */
const hasForbidden = (s: string): boolean => [...s].some((ch) => {
  const c = ch.codePointAt(0)!;
  return (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x202e || c === 0xfffe || c === 0xffff;
});

function dep(name: string, o: Partial<SbomDependency> = {}): SbomDependency {
  return {
    id: name, packageId: name, ecosystem: 'nodejs', name, version: '1.0.0', scope: 'direct',
    manifestFile: 'package-lock.json', manifestPath: '.', depth: 0, description: null, homepageUrl: null, author: null,
    licenseExpression: null, licenseSource: 'none', copyrightLines: [], licenses: [], vulnerabilities: [], ...o,
    purl: o.purl ?? `pkg:npm/${encodeURIComponent(name)}@1.0.0`,
  };
}

function data(dependencies: SbomDependency[]): SbomScanData {
  return {
    scan: { id: '3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f', ref: 'main', completedAt: new Date(0), createdAt: new Date(0), totalDependencies: dependencies.length },
    project: { id: '11111111-2222-4333-8444-555555555555', name: 'sbom-app', description: null, repoUrl: null },
    dependencies,
    knownLicenseIds: KNOWN,
  };
}

const F3 = data([
  dep('cr-one', { licenseExpression: 'MIT', licenseSource: 'registry:npm', copyrightLines: ['Copyright 2020 A', 'Copyright 2021 B'] }),
  dep('see-lic', { licenseExpression: 'SEE LICENSE IN LICENSE', licenseSource: 'registry:npm', copyrightLines: ['Copyright 2019 Single'] }),
  dep('lock-lic', { licenseExpression: 'mit or apache-2.0', licenseSource: 'lockfile (unverified)' }),
  dep('both', { licenseExpression: 'Foo-1.0', licenseSource: 'lockfile (unverified)' }),
  dep('nolic', { licenseExpression: null, licenseSource: 'none' }),
  dep('devpkg', { scope: 'dev', licenseExpression: 'ISC', licenseSource: 'registry:npm' }),
  dep('withexc', { licenseExpression: 'GPL-2.0-only WITH Classpath-exception-2.0', licenseSource: 'registry:npm' }),
]);

type SpdxPkg = Record<string, unknown> & { name: string };
const spdxPkgs = (d: SbomScanData) => (JSON.parse(generateSpdxJson(d)) as { packages: SpdxPkg[] }).packages;
const byName = <T extends { name: string }>(list: T[], name: string): T => {
  const hit = list.find((p) => p.name === name);
  if (!hit) throw new Error(`package ${name} missing`);
  return hit;
};
type CdxComp = Record<string, unknown> & { name: string; licenses?: Array<Record<string, unknown>> };
const cdxComps = (d: SbomScanData) => (JSON.parse(generateCycloneDxJson(d)) as { components: CdxComp[] }).components;

describe('AC-P16-1 / AC-P16-2: SPDX 2.3 JSON license and copyright fields', () => {
  it('AC-P16-2: licenseConcluded NOASSERTION everywhere (root and dev included); licenseDeclared canonical or NOASSERTION', () => {
    const pkgs = spdxPkgs(F3);
    for (const p of pkgs) expect(p.licenseConcluded, p.name).toBe('NOASSERTION');
    expect(pkgs[0]).toMatchObject({ SPDXID: 'SPDXRef-ROOT', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION' });
    expect(byName(pkgs, 'cr-one').licenseDeclared).toBe('MIT');
    expect(byName(pkgs, 'lock-lic').licenseDeclared).toBe('MIT OR Apache-2.0');
    expect(byName(pkgs, 'devpkg').licenseDeclared).toBe('ISC');
    expect(byName(pkgs, 'withexc').licenseDeclared).toBe('GPL-2.0-only WITH Classpath-exception-2.0');
    expect(byName(pkgs, 'nolic').licenseDeclared).toBe('NOASSERTION');
  });

  it('AC-P16-2: "SEE LICENSE IN LICENSE" -> NOASSERTION + licenseComments; lockfile source line; both lines in order; absent otherwise', () => {
    const pkgs = spdxPkgs(F3);
    expect(byName(pkgs, 'see-lic')).toMatchObject({ licenseDeclared: 'NOASSERTION', licenseComments: 'Declared license is not a valid SPDX expression: SEE LICENSE IN LICENSE' });
    expect(byName(pkgs, 'lock-lic').licenseComments).toBe('License source: lockfile (unverified)');
    expect(byName(pkgs, 'both').licenseComments).toBe('Declared license is not a valid SPDX expression: Foo-1.0\nLicense source: lockfile (unverified)');
    for (const n of ['cr-one', 'nolic', 'devpkg', 'withexc']) expect(Object.keys(byName(pkgs, n)), n).not.toContain('licenseComments');
  });

  it('AC-P16-1: copyrightText = lines joined with \\n when extracted; NOASSERTION otherwise (root unchanged)', () => {
    const pkgs = spdxPkgs(F3);
    expect(byName(pkgs, 'cr-one').copyrightText).toBe('Copyright 2020 A\nCopyright 2021 B');
    expect(byName(pkgs, 'see-lic').copyrightText).toBe('Copyright 2019 Single');
    expect(byName(pkgs, 'nolic').copyrightText).toBe('NOASSERTION');
  });

  it('AC-P16-2 / C-12: pre-F3 dependency -> licenseDeclared from license_findings (first-seen, AND-joined), copyrightText NOASSERTION', () => {
    const pre = data([
      dep('old-a', {
        licenseSource: null, copyrightLines: ['Copyright ignored'],
        licenses: [{ normalizedLicense: 'MIT', detectedLicense: 'MIT', riskLevel: 'safe' }, { normalizedLicense: null, detectedLicense: 'Apache-2.0', riskLevel: 'safe' }, { normalizedLicense: 'MIT', detectedLicense: null, riskLevel: 'safe' }],
      }),
      dep('old-b', { licenseSource: null, licenses: [] }),
      dep('old-c', { licenseSource: null, licenses: [{ normalizedLicense: 'Weird License', detectedLicense: null, riskLevel: 'unknown' }] }),
    ]);
    const pkgs = spdxPkgs(pre);
    expect(byName(pkgs, 'old-a')).toMatchObject({ licenseDeclared: 'MIT AND Apache-2.0', copyrightText: 'NOASSERTION', licenseConcluded: 'NOASSERTION' });
    expect(byName(pkgs, 'old-b')).toMatchObject({ licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION' });
    expect(byName(pkgs, 'old-c')).toMatchObject({ licenseDeclared: 'NOASSERTION', licenseComments: 'Declared license is not a valid SPDX expression: Weird License' });
    const comps = cdxComps(pre);
    expect(byName(comps, 'old-a').licenses).toEqual([{ expression: 'MIT AND Apache-2.0' }]);
    expect(byName(comps, 'old-a').copyright).toBeUndefined();
    expect(byName(comps, 'old-b').licenses).toBeUndefined();
  });
});

describe('AC-P16-2 / AC-P16-4: SPDX tag-value', () => {
  it('AC-P16-2: field order Declared -> Comments -> CopyrightText; <text> blocks for comments and non-NOASSERTION copyright', () => {
    const tv = generateSpdxTagValue(F3);
    expect(tv).toContain('PackageLicenseConcluded: NOASSERTION\nPackageLicenseDeclared: NOASSERTION\nPackageLicenseComments: <text>Declared license is not a valid SPDX expression: Foo-1.0\nLicense source: lockfile (unverified)</text>\nPackageCopyrightText: NOASSERTION\n');
    expect(tv).toContain('PackageLicenseDeclared: MIT\nPackageCopyrightText: <text>Copyright 2020 A\nCopyright 2021 B</text>\n');
    expect(tv).toContain('PackageCopyrightText: <text>Copyright 2019 Single</text>\n');
    expect(tv).toContain('PackageLicenseDeclared: MIT OR Apache-2.0\nPackageLicenseComments: <text>License source: lockfile (unverified)</text>\n');
  });

  it('AC-P16-4: </text>, "\\nPackageName: sahte", \\x00-class and U+202E in name / copyright create no new package or field', () => {
    const evil = `ev</TEXT>il\nPackageName: sahte\u0001${RLO}<text>`;
    const tv = generateSpdxTagValue(data([dep(evil, { licenseExpression: 'MIT', licenseSource: 'registry:npm', copyrightLines: [`(c) ${evil}`, 'Copyright </text>\nSPDXID: SPDXRef-fake'] })]));
    expect(hasForbidden(tv)).toBe(false);
    const lines = tv.split('\n');
    expect(lines.filter((l) => l.startsWith('PackageName: '))).toHaveLength(2); // root + 1
    expect(lines).not.toContain('PackageName: sahte');
    expect(lines.filter((l) => l.startsWith('SPDXID: '))).toHaveLength(3); // document, root, package
    // The only <text> block is the copyright field; its content holds no raw <text> / </text> (any case).
    const blocks = lines.filter((l) => /^[A-Za-z]+: <text>/.test(l));
    expect(blocks.map((l) => l.split(':')[0])).toEqual(['PackageCopyrightText']);
    const inner = /\nPackageCopyrightText: <text>([\s\S]*?)<\/text>\n/.exec(tv)?.[1] ?? '';
    expect(inner).not.toMatch(/<\/?text>/i);
    expect(inner).toContain('&lt;/text&gt;');
    expect(inner).toContain('&lt;text&gt;');
    const nameLine = lines.find((l) => l.startsWith('PackageName: ev'));
    // Contract 1.1.0 L-1 (C-14): single-line values escape <text>/</text> too (any case in, lower case out).
    expect(nameLine).toBe('PackageName: ev&lt;/text&gt;il PackageName: sahte&lt;text&gt;');
  });
});

describe('AC-P16-5: CycloneDX 1.5 JSON', () => {
  it('AC-P16-5: single licenses entry (id / expression / name), none without license, copyright joined; expression never shares the array', () => {
    const comps = cdxComps(F3);
    expect(byName(comps, 'cr-one').licenses).toEqual([{ license: { id: 'MIT' } }]);
    expect(byName(comps, 'cr-one').copyright).toBe('Copyright 2020 A\nCopyright 2021 B');
    expect(byName(comps, 'see-lic').licenses).toEqual([{ license: { name: 'SEE LICENSE IN LICENSE' } }]);
    expect(byName(comps, 'lock-lic').licenses).toEqual([{ expression: 'MIT OR Apache-2.0' }]);
    expect(byName(comps, 'withexc').licenses).toEqual([{ expression: 'GPL-2.0-only WITH Classpath-exception-2.0' }]);
    expect(byName(comps, 'nolic').licenses).toBeUndefined();
    expect(byName(comps, 'nolic').copyright).toBeUndefined();
    for (const c of comps) {
      expect(c.licenses?.length ?? 0, c.name).toBeLessThanOrEqual(1);
      if (c.licenses?.some((l) => 'expression' in l)) expect(c.licenses).toHaveLength(1);
    }
    expect(JSON.parse(generateCycloneDxJson(F3)).specVersion).toBe('1.5');
  });
});

describe('AC-P16-6: CycloneDX 1.5 XML', () => {
  const parse = (xml: string) => {
    const doc = new new JSDOM('').window.DOMParser().parseFromString(xml, 'application/xml');
    expect(doc.getElementsByTagName('parsererror').length, 'XML is not well-formed').toBe(0);
    return doc;
  };

  it('AC-P16-6: component child order author, name, version, description, scope, licenses, copyright, purl; JSON/XML consistent', () => {
    const d = data([dep('full', { author: 'Au', description: 'Desc', licenseExpression: 'MIT AND ISC', licenseSource: 'registry:npm', copyrightLines: ['Copyright 1', 'Copyright 2'] }), ...F3.dependencies]);
    const doc = parse(generateCycloneDxXml(d));
    const comps = Array.from(doc.getElementsByTagName('components')[0].children);
    const full = comps.find((c) => c.getElementsByTagName('name')[0]?.textContent === 'full')!;
    expect(Array.from(full.children).map((c) => c.tagName)).toEqual(['author', 'name', 'version', 'description', 'scope', 'licenses', 'copyright', 'purl']);
    expect(full.getElementsByTagName('licenses')[0].children).toHaveLength(1);
    expect(full.getElementsByTagName('expression')[0].textContent).toBe('MIT AND ISC');
    expect(full.getElementsByTagName('copyright')[0].textContent).toBe('Copyright 1\nCopyright 2');
    const order = ['author', 'name', 'version', 'description', 'scope', 'licenses', 'copyright', 'purl'];
    const json = cdxComps(d);
    for (const c of comps) {
      const tags = Array.from(c.children).map((x) => x.tagName);
      expect(tags, 'children follow the XSD sequence').toEqual(order.filter((t) => tags.includes(t)));
      const name = c.getElementsByTagName('name')[0].textContent!;
      const j = byName(json, name);
      const lic = c.getElementsByTagName('licenses')[0];
      if (!j.licenses) expect(lic).toBeUndefined();
      else {
        expect(lic.children).toHaveLength(1);
        const e = j.licenses[0] as { expression?: string; license?: { id?: string; name?: string } };
        if (e.expression) expect(lic.getElementsByTagName('expression')[0].textContent).toBe(e.expression);
        else if (e.license?.id) expect(lic.getElementsByTagName('id')[0].textContent).toBe(e.license.id);
        else expect(lic.getElementsByTagName('name')[0].textContent).toBe(e.license?.name);
      }
      expect(c.getElementsByTagName('copyright')[0]?.textContent ?? undefined).toBe(j.copyright);
    }
  });

  it('AC-P16-6: XML-invalid characters removed from text and attributes (metadata component too); output stays well-formed', () => {
    const bad = `a\u0001b\u0008c${NONCHAR}\uD800d<&>"'`;
    const d = data([dep(`n${bad}`, { purl: `pkg:npm/x@1?q=${bad}`, licenseExpression: `Lic${bad}`, licenseSource: 'registry:npm', copyrightLines: [`Copyright \u000bX${bad}`] })]);
    d.project.name = `proj${bad}`;
    const xml = generateCycloneDxXml(d);
    expect(hasForbidden(xml)).toBe(false);
    expect(xml).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
    const doc = parse(xml);
    const comp = doc.getElementsByTagName('components')[0].children[0];
    // Contract 9 step 2 runs first: the lone surrogate becomes U+FFFD (valid XML); U+FFFE and C0 are removed.
    expect(comp.getElementsByTagName('copyright')[0].textContent).toBe('Copyright Xabc�d<&>"\'');
    expect(comp.getAttribute('bom-ref')).toBe('pkg:npm/x@1?q=abc�d<&>"\'');
    expect(doc.getElementsByTagName('metadata')[0].getElementsByTagName('name')[1].textContent).toBe('projabc�d<&>"\'');
  });
});

describe('contract section 9 / 5.1: common text rules', () => {
  it('AC-P16-4 / contract 9 step 3 / B-1: single-line rule maps \\n and \\t to one space (\\r normalized first)', () => {
    expect(singleLine('a\r\nb\rc\nd')).toBe('a b c d');
    expect(singleLine('a\tb')).toBe('a b');
  });

  it('AC-P14-18 / contract 5.1: Excel formula guard prefixes = + - @ \\t \\r with an apostrophe and nothing else', () => {
    for (const v of ['=1+1', '+1', '-1', '@SUM(A1)', '\tx', '\rx']) expect(excelSafeText(v)).toBe(`'${v}`);
    for (const v of ['MIT', '', ' =1', "'x"]) expect(excelSafeText(v)).toBe(v);
  });
});
