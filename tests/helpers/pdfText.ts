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

/** Visible text lines of a pdfkit PDF, in page order. */
export function pdfLines(pdf: Buffer): string[] {
  const lines: string[] = [];
  for (const stream of contentStreams(pdf)) {
    for (const bt of stream.matchAll(/\bBT\b([\s\S]*?)\bET\b/g)) {
      const text = textObjectStrings(bt[1]);
      if (text !== '') lines.push(text);
    }
  }
  return lines;
}
