/**
 * Minimal text extraction for the PDFs pdfkit writes with its standard
 * (AFM) fonts, for REQ-007 export tests (AC-P24-3, AC-P24-10, AC-P24-11).
 * No new dependency (AC-G-5): every `stream … endstream` is inflated
 * (FlateDecode) when possible, then each `BT … ET` text object becomes one
 * line made of its `Tj` / `TJ` strings (hex `<…>` or literal `(…)`), decoded
 * as WinAnsi (windows-1252). Kerning numbers inside `TJ` arrays are dropped.
 * pdfkit writes one text object per laid-out line, so the result is the list
 * of visible lines in page order. Test-only; not a general PDF parser.
 */
import zlib from 'node:zlib';

const WIN_ANSI = new TextDecoder('windows-1252');

function decodeHex(hex: string): string {
  const clean = hex.replace(/\s+/g, '');
  const even = clean.length % 2 === 0 ? clean : `${clean}0`;
  return WIN_ANSI.decode(Buffer.from(even, 'hex'));
}

function decodeLiteral(body: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i];
    if (c !== '\\') {
      bytes.push(body.charCodeAt(i) & 0xff);
      continue;
    }
    const n = body[i + 1];
    i += 1;
    const map: Record<string, number> = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 };
    if (n in map) bytes.push(map[n]);
    else if (/[0-7]/.test(n)) {
      let oct = n;
      while (oct.length < 3 && /[0-7]/.test(body[i + 1] ?? '')) oct += body[(i += 1)];
      bytes.push(parseInt(oct, 8) & 0xff);
    }
  }
  return WIN_ANSI.decode(Buffer.from(bytes));
}

/** Strings of one text object, in order. */
function textObjectStrings(block: string): string {
  let out = '';
  const re = /<([0-9A-Fa-f\s]*)>|\(((?:\\.|[^\\)])*)\)/g;
  for (const op of block.matchAll(/(\[[\s\S]*?\])\s*TJ|(<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\)])*\))\s*Tj/g)) {
    const operand = op[1] ?? op[2];
    for (const s of operand.matchAll(re)) out += s[1] !== undefined ? decodeHex(s[1]) : decodeLiteral(s[2]);
  }
  return out;
}

/** Content streams of the document (inflated when compressed). */
function contentStreams(pdf: Buffer): string[] {
  const latin = pdf.toString('latin1');
  const streams: string[] = [];
  for (const m of latin.matchAll(/stream\r?\n([\s\S]*?)\r?\nendstream/g)) {
    const raw = Buffer.from(m[1], 'latin1');
    try {
      streams.push(zlib.inflateSync(raw).toString('latin1'));
    } catch {
      streams.push(m[1]);
    }
  }
  return streams;
}

/**
 * ToUnicode CMaps of embedded (TrueType, Identity-H) fonts by resource name
 * (`F2` -> code -> text). REQ-010: the dependency report embeds a system
 * font for Turkish glyphs, so its strings are 2-byte glyph codes.
 */
function fontCmaps(pdf: Buffer): Map<string, Map<number, string>> {
  const latin = pdf.toString('latin1');
  const objects = new Map<string, string>();
  for (const m of latin.matchAll(/(\d+) 0 obj([\s\S]*?)endobj/g)) objects.set(m[1], m[2]);
  const streamOf = (body: string): string => {
    const m = /stream\r?\n([\s\S]*?)\r?\nendstream/.exec(body);
    if (!m) return '';
    try {
      return zlib.inflateSync(Buffer.from(m[1], 'latin1')).toString('latin1');
    } catch {
      return m[1];
    }
  };
  const utf16 = (hex: string): string => Buffer.from(hex, 'hex').swap16().toString('utf16le');
  const cmapByObject = new Map<string, Map<number, string>>();
  for (const [id, body] of objects) {
    const ref = /\/ToUnicode (\d+) 0 R/.exec(body);
    if (!ref || !/\/Type\s*\/Font/.test(body)) continue;
    const cmap = new Map<number, string>();
    const text = streamOf(objects.get(ref[1]) ?? '');
    for (const block of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
      for (const p of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) cmap.set(parseInt(p[1], 16), utf16(p[2]));
    }
    for (const block of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
      for (const r of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(\[[^\]]*\]|<[0-9A-Fa-f]+>)/g)) {
        const lo = parseInt(r[1], 16);
        const hi = parseInt(r[2], 16);
        if (r[3].startsWith('[')) {
          [...r[3].matchAll(/<([0-9A-Fa-f]+)>/g)].forEach((d, i) => cmap.set(lo + i, utf16(d[1])));
        } else {
          const base = Buffer.from(r[3].slice(1, -1), 'hex');
          for (let c = lo; c <= hi; c += 1) {
            const out = Buffer.from(base);
            out.writeUInt16BE(base.readUInt16BE(base.length - 2) + (c - lo), base.length - 2);
            cmap.set(c, out.swap16().toString('utf16le'));
          }
        }
      }
    }
    cmapByObject.set(id, cmap);
  }
  const byName = new Map<string, Map<number, string>>();
  for (const dict of latin.matchAll(/\/Font\s*<<([\s\S]*?)>>/g)) {
    for (const f of dict[1].matchAll(/\/(\w+)\s+(\d+) 0 R/g)) {
      const cmap = cmapByObject.get(f[2]);
      if (cmap) byName.set(f[1], cmap);
    }
  }
  return byName;
}

/** Strings of one text object; hex strings of an embedded font are decoded through its CMap. */
function decodeTextObject(block: string, cmaps: Map<string, Map<number, string>>): string {
  const font = /\/(\w+)\s+[\d.]+\s+Tf/.exec(block)?.[1];
  const cmap = font ? cmaps.get(font) : undefined;
  if (!cmap) return textObjectStrings(block);
  let out = '';
  for (const hex of block.matchAll(/<([0-9A-Fa-f\s]*)>/g)) {
    const clean = hex[1].replace(/\s+/g, '');
    for (let i = 0; i + 4 <= clean.length; i += 4) out += cmap.get(parseInt(clean.slice(i, i + 4), 16)) ?? '';
  }
  return out;
}

/**
 * Visible text lines of a pdfkit PDF, in page order. Text objects placed on
 * the same baseline one after another (table cells) form one line joined
 * with " | ".
 */
export function pdfLines(pdf: Buffer): string[] {
  const cmaps = fontCmaps(pdf);
  const lines: string[] = [];
  for (const stream of contentStreams(pdf)) {
    let lastY: number | null = null;
    for (const bt of stream.matchAll(/\bBT\b([\s\S]*?)\bET\b/g)) {
      const text = decodeTextObject(bt[1], cmaps);
      if (text === '') continue;
      const tm = /([-\d.]+)\s+([-\d.]+)\s+Tm/.exec(bt[1]);
      const y = tm ? Number(tm[2]) : null;
      if (y !== null && lastY !== null && Math.abs(y - lastY) < 0.5 && lines.length > 0) {
        lines[lines.length - 1] += ` | ${text}`;
      } else {
        lines.push(text);
      }
      lastY = y;
    }
  }
  return lines;
}
