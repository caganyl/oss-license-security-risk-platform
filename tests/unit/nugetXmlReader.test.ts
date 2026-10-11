/**
 * REQ-006 · AC-P20-13 safe XML reader (ADR-008 Karar 3): src/scanner/parsers/xmlReader.ts.
 */
import fs from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_XML_LIMITS, XmlError, parseXml, type XmlErrorCode } from '../../src/scanner/parsers/xmlReader';

const b = (text: string) => Buffer.from(text, 'utf8');
const SECRET = 'SECRET-MARKER-c0ffee';

function codeOf(input: Buffer | string): XmlErrorCode | 'ok' {
  try {
    parseXml(typeof input === 'string' ? b(input) : input);
    return 'ok';
  } catch (err) {
    expect(err).toBeInstanceOf(XmlError);
    return (err as XmlError).code;
  }
}

function timed(input: Buffer): { code: XmlErrorCode | 'ok'; ms: number } {
  const start = performance.now();
  const code = codeOf(input);
  return { code, ms: performance.now() - start };
}

afterEach(() => vi.restoreAllMocks());

describe('AC-P20-13: DTD and entities', () => {
  it('AC-P20-13: limits are 64 depth, 200 000 elements, 64 KiB values, 256 attributes', () => {
    expect(DEFAULT_XML_LIMITS).toMatchObject({ maxDepth: 64, maxElements: 200_000, maxValueChars: 65_536, maxAttributes: 256 });
  });

  it('AC-P20-13: <!DOCTYPE> (XXE) and <!ENTITY> are rejected without any file or network access', () => {
    const readSpy = vi.spyOn(fs, 'readFileSync');
    const openSpy = vi.spyOn(fs, 'openSync');
    expect(codeOf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>`)).toBe('doctype');
    expect(codeOf(`<?xml version="1.0"?>\n<!DOCTYPE foo SYSTEM "http://127.0.0.1:9/evil.dtd"><foo/>`)).toBe('doctype');
    expect(codeOf(`<foo><!ENTITY x "y"></foo>`)).toBe('doctype');
    expect(readSpy).not.toHaveBeenCalled();
    expect(openSpy).not.toHaveBeenCalled();
  });

  it('AC-P20-13: billion laughs is rejected at the DOCTYPE (nothing is expanded)', () => {
    const lol = [
      '<?xml version="1.0"?>',
      '<!DOCTYPE lolz [',
      ' <!ENTITY lol "lol">',
      ...Array.from({ length: 9 }, (_, i) => ` <!ENTITY lol${i + 1} "${`&lol${i === 0 ? '' : i};`.repeat(10)}">`),
      ']>',
      '<lolz>&lol9;</lolz>',
    ].join('\n');
    const { code, ms } = timed(b(lol));
    expect(code).toBe('doctype');
    expect(ms).toBeLessThan(2000);
  });

  it('AC-P20-13: the five predefined entities and numeric references are decoded in text and attributes', () => {
    const root = parseXml(b(`<a t="&lt;&gt;&amp;&quot;&apos;&#65;&#x42;&#x1F600;">x &amp; y&#10;</a>`));
    expect(root.attributes).toEqual([['t', `<>&"'AB\u{1F600}`]]);
    expect(root.text).toBe('x & y\n');
  });

  it('AC-P20-13: unknown, unterminated or invalid references are entity errors', () => {
    for (const ref of ['&foo;', '&amp', '&#0;', '&#x110000;', '&#xD800;', '&#;', '&#x;', '&#12a;', '&nbsp;', '&ampamp;']) {
      expect(codeOf(`<a>${ref}</a>`), ref).toBe('entity');
      expect(codeOf(`<a v="${ref}"/>`), ref).toBe('entity');
    }
  });

  it('AC-P20-13: processing instructions and comments are skipped, CDATA is text, namespaces are not resolved', () => {
    const root = parseXml(b(`<?xml version="1.0"?><!-- c --><?pi x?><x:a xmlns:x="urn:x"><![CDATA[<b>&foo;]]><!-- &bad; --><c/></x:a>`));
    expect(root.name).toBe('x:a');
    expect(root.localName).toBe('a');
    expect(root.attributes).toEqual([['xmlns:x', 'urn:x']]);
    expect(root.text).toBe('<b>&foo;');
    expect(root.children.map((c) => c.name)).toEqual(['c']);
  });

  it('AC-P20-13: malformed documents are malformed errors', () => {
    for (const doc of ['', '   ', 'text', '<a>', '<a></b>', '<a/><b/>', '<a b=c/>', '<a b="1" b="2"/>', '<a b="<"/>', '<a><!-- x</a>', '<a><![CDATA[x</a>', '<a b="1"c="2"/>', '<?xml version="1.0"']) {
      expect(codeOf(doc), JSON.stringify(doc)).toBe('malformed');
    }
  });
});

describe('AC-P20-13: size limits', () => {
  it('AC-P20-13: depth 64 is accepted, 65 is a limit error', () => {
    expect(codeOf('<a>'.repeat(64) + '</a>'.repeat(64))).toBe('ok');
    expect(codeOf('<a>'.repeat(65) + '</a>'.repeat(65))).toBe('limit');
  });

  it('AC-P20-13: 200 000 elements are accepted, 200 001 are a limit error', () => {
    expect(codeOf(`<r>${'<e/>'.repeat(199_999)}</r>`)).toBe('ok');
    expect(codeOf(`<r>${'<e/>'.repeat(200_000)}</r>`)).toBe('limit');
  });

  it('AC-P20-13: one attribute value or text of 64 KiB is accepted, one character more is a limit error (after entity decoding)', () => {
    const max = 64 * 1024;
    expect(codeOf(`<a v="${'x'.repeat(max)}"/>`)).toBe('ok');
    expect(codeOf(`<a v="${'x'.repeat(max + 1)}"/>`)).toBe('limit');
    expect(codeOf(`<a>${'x'.repeat(max)}</a>`)).toBe('ok');
    expect(codeOf(`<a>${'x'.repeat(max + 1)}</a>`)).toBe('limit');
    expect(codeOf(`<a>${'x'.repeat(max)}<![CDATA[y]]></a>`)).toBe('limit');
    expect(codeOf(`<a v="${'&amp;'.repeat(max + 1)}"/>`)).toBe('limit');
  });

  it('AC-P20-13: 256 attributes are accepted, 257 are a limit error', () => {
    const attrs = (n: number) => Array.from({ length: n }, (_, i) => `a${i}="1"`).join(' ');
    expect(codeOf(`<a ${attrs(256)}/>`)).toBe('ok');
    expect(codeOf(`<a ${attrs(257)}/>`)).toBe('limit');
  });

  it('AC-P20-13: whitespace-only indentation does not count against the text limit', () => {
    expect(codeOf(`<a>${'<b/>\n    '.repeat(20_000)}</a>`)).toBe('ok');
  });
});

describe('AC-P20-13: encodings', () => {
  const doc = '<a v="ç">İstanbul ğ</a>';
  const utf16le = (s: string) => Buffer.from(s, 'utf16le');
  const swap = (buf: Buffer) => {
    const out = Buffer.from(buf);
    out.swap16();
    return out;
  };

  it('AC-P20-13: UTF-8 with and without BOM', () => {
    expect(parseXml(b(doc)).text).toBe('İstanbul ğ');
    expect(parseXml(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), b(doc)])).attributes).toEqual([['v', 'ç']]);
  });

  it('AC-P20-13: UTF-16 LE and BE with BOM', () => {
    expect(parseXml(Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le(doc)])).text).toBe('İstanbul ğ');
    expect(parseXml(Buffer.concat([Buffer.from([0xfe, 0xff]), swap(utf16le(doc))])).text).toBe('İstanbul ğ');
    expect(parseXml(Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le(`<?xml version="1.0" encoding="utf-16"?>${doc}`)])).localName).toBe('a');
  });

  it('AC-P20-13: BOM-less UTF-16, odd UTF-16 length, invalid UTF-8 and a lying declaration are encoding errors', () => {
    expect(codeOf(utf16le(doc))).toBe('encoding');
    expect(codeOf(swap(utf16le(doc)))).toBe('encoding');
    expect(codeOf(Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le(doc), Buffer.from([0x41])]))).toBe('encoding');
    expect(codeOf(Buffer.concat([b('<a>'), Buffer.from([0xc3, 0x28]), b('</a>')]))).toBe('encoding');
    expect(codeOf(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from([0xff]), b('<a/>')]))).toBe('encoding');
    expect(codeOf(`<?xml version="1.0" encoding="windows-1252"?>${doc}`)).toBe('encoding');
    expect(codeOf('<?xml version="1.0" encoding="windows-1252"?><a>ascii</a>')).toBe('ok');
  });
});

describe('AC-P20-13: linear time on adversarial input (1 s target, 2 s CI allowance)', () => {
  it('AC-P20-13: 1 MiB of nested <a> fails fast with a limit error', () => {
    const { code, ms } = timed(b('<a>'.repeat(350_000)));
    expect(code).toBe('limit');
    expect(ms).toBeLessThan(2000);
  });

  it('AC-P20-13: a 32 MiB single attribute fails fast with a limit error', () => {
    const input = Buffer.concat([b('<a v="'), Buffer.alloc(32 * 1024 * 1024, 0x78), b('"/>')]);
    const { code, ms } = timed(input);
    expect(code).toBe('limit');
    expect(ms).toBeLessThan(2000);
  });

  it('AC-P20-13: many unterminated constructs and references stay linear', () => {
    for (const input of [
      `<a>${'<!-'.repeat(1_000_000)}</a>`,
      `<a>${'&'.repeat(4_000_000)}</a>`,
      `<a>${'<![CDATA'.repeat(500_000)}</a>`,
      `<r>${'<e a="1" b=\'2\'/>'.repeat(150_000)}</r>`,
      `<a b="${'&#x41;'.repeat(10_000)}"/>`,
    ]) {
      const { ms } = timed(b(input));
      expect(ms, input.slice(0, 12)).toBeLessThan(2000);
    }
  });
});

describe('AC-P20-13 / AC-P20-15: error messages never carry document content', () => {
  it('AC-P20-13: every error message is the fixed per-code text', () => {
    const docs = [
      `<!DOCTYPE ${SECRET}><a/>`,
      `<a>&${SECRET};</a>`,
      `<a v="${SECRET}${'x'.repeat(70_000)}"/>`,
      `<${SECRET}></b>`,
      `<?xml version="1.0" encoding="${SECRET}"?><a>ğ ${SECRET}</a>`,
    ];
    const codes: string[] = [];
    for (const d of docs) {
      try {
        parseXml(b(d));
        throw new Error('expected an XmlError');
      } catch (err) {
        expect(err).toBeInstanceOf(XmlError);
        const e = err as XmlError;
        codes.push(e.code);
        expect(e.message).toBe(`XML reader error (${e.code}).`);
        expect(String(e.stack)).not.toContain(SECRET);
        expect(JSON.stringify(e)).not.toContain(SECRET);
      }
    }
    expect(codes).toEqual(['doctype', 'entity', 'limit', 'malformed', 'encoding']);
  });
});
