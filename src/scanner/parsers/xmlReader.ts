/**
 * Safe, minimal XML reader (REQ-006 AC-P20-13, AC-P21-4; ADR-008 Karar 3).
 *
 * Hand-written, single pass, index based: the cursor only moves forward and
 * every terminator (`?>`, `-->`, `]]>`, closing quote, `;`) is searched with
 * `indexOf` from the current position, so the total work is O(n). Regular
 * expressions are not used at all (no quantified or backtracking pattern).
 *
 * - No DTD is ever processed: any `<!` construct other than a comment or a
 *   CDATA section (in particular `<!DOCTYPE` and `<!ENTITY`) is a `doctype`
 *   error. Only the five predefined entities and numeric character
 *   references are decoded; nothing is expanded, so entity bombs are
 *   structurally impossible.
 * - Namespaces are not resolved (`localName` is the part after the last
 *   `:`); `xmlns` is an ordinary attribute; no schema or external resource is
 *   loaded.
 * - Limits (depth, element count, value/text size, attribute count, name
 *   length) are checked while scanning and fail fast with `limit`.
 * - `XmlError` never carries document content: its message is built from the
 *   fixed error code only.
 *
 * Pure module: no imports (ADR-008 Karar 1). The input size is bounded by the
 * caller (32 MiB walk limit for repository files, 1 MiB for `.nuspec`).
 */

export interface XmlElement {
  name: string;
  localName: string;
  attributes: ReadonlyArray<[string, string]>;
  children: XmlElement[];
  /**
   * Concatenated character data directly inside the element (text and CDATA).
   * Whitespace-only text runs between tags are ignorable whitespace and are
   * not appended, so indentation of element-only content never counts
   * against the text limit.
   */
  text: string;
}

export interface XmlLimits {
  maxDepth: number;
  maxElements: number;
  /** Maximum length of one attribute value or of one element's accumulated text, in UTF-16 code units. */
  maxValueChars: number;
  maxAttributes: number;
  maxNameChars: number;
}

export const DEFAULT_XML_LIMITS: Readonly<XmlLimits> = Object.freeze({
  maxDepth: 64,
  maxElements: 200_000,
  maxValueChars: 64 * 1024,
  maxAttributes: 256,
  maxNameChars: 256,
});

export type XmlErrorCode = 'doctype' | 'encoding' | 'limit' | 'entity' | 'malformed';

/** Reader failure; the message is derived from the code only (never from the document). */
export class XmlError extends Error {
  readonly code: XmlErrorCode;
  constructor(code: XmlErrorCode) {
    super(`XML reader error (${code}).`);
    this.name = 'XmlError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const UTF16LE = new TextDecoder('utf-16le', { fatal: true, ignoreBOM: true });

function decodeUtf16(bytes: Uint8Array, bigEndian: boolean): string {
  if (bytes.length % 2 !== 0) throw new XmlError('encoding');
  let source = bytes;
  if (bigEndian) {
    // Swapped copy: `utf-16be` support depends on the ICU build, `utf-16le` is always present.
    source = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i += 2) {
      source[i] = bytes[i + 1];
      source[i + 1] = bytes[i];
    }
  }
  try {
    return UTF16LE.decode(source);
  } catch {
    throw new XmlError('encoding');
  }
}

function decode(bytes: Uint8Array): string {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    try {
      return UTF8.decode(bytes.subarray(3));
    } catch {
      throw new XmlError('encoding');
    }
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return decodeUtf16(bytes.subarray(2), false);
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) return decodeUtf16(bytes.subarray(2), true);
  // UTF-16 without a BOM (`<` as `3C 00` / `00 3C`) is not supported.
  if (bytes.length >= 2 && ((bytes[0] === 0x3c && bytes[1] === 0x00) || (bytes[0] === 0x00 && bytes[1] === 0x3c))) {
    throw new XmlError('encoding');
  }
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new XmlError('encoding');
  }
}

function isXmlSpace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function asciiLowerLocal(value: string): string {
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 0x20) : value[i];
  }
  return out;
}

function hasNonAscii(text: string): boolean {
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) > 0x7f) return true;
  return false;
}

/**
 * XML declaration `encoding` check: a value other than UTF-8/UTF-16 is
 * accepted only when the decoded text is pure ASCII (a subset of those
 * encodings); otherwise the bytes were not what the declaration says.
 */
function checkDeclaredEncoding(text: string): void {
  if (!text.startsWith('<?xml') || text.length < 6 || !isXmlSpace(text.charCodeAt(5))) return;
  const end = text.indexOf('?>', 5);
  if (end === -1) throw new XmlError('malformed');
  const decl = text.slice(5, end);
  const at = decl.indexOf('encoding');
  if (at === -1) return;
  let i = at + 'encoding'.length;
  while (i < decl.length && isXmlSpace(decl.charCodeAt(i))) i++;
  if (decl[i] !== '=') throw new XmlError('malformed');
  i++;
  while (i < decl.length && isXmlSpace(decl.charCodeAt(i))) i++;
  const quote = decl[i];
  if (quote !== '"' && quote !== "'") throw new XmlError('malformed');
  const close = decl.indexOf(quote, i + 1);
  if (close === -1) throw new XmlError('malformed');
  const value = asciiLowerLocal(decl.slice(i + 1, close));
  if (value === 'utf-8' || value === 'utf-16' || value === 'utf8' || value === 'utf16') return;
  if (hasNonAscii(text)) throw new XmlError('encoding');
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

function isNameStart(c: number): boolean {
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f || c === 0x3a || c >= 0x80;
}

function isNameChar(c: number): boolean {
  return isNameStart(c) || (c >= 0x30 && c <= 0x39) || c === 0x2e || c === 0x2d;
}

function isXmlChar(cp: number): boolean {
  return cp === 0x9 || cp === 0xa || cp === 0xd || (cp >= 0x20 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd) || (cp >= 0x10000 && cp <= 0x10ffff);
}

const PREDEFINED: Readonly<Record<string, string>> = Object.freeze({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" });
const MAX_REFERENCE_CHARS = 10; // `#x` + 8 hex digits

function isDigits(value: string, hex: boolean): boolean {
  if (value.length === 0 || value.length > 8) return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const digit = c >= 0x30 && c <= 0x39;
    const hexLetter = hex && ((c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66));
    if (!digit && !hexLetter) return false;
  }
  return true;
}

/** Decodes the five predefined entities and numeric references; anything else is an `entity` error. */
function decodeEntities(raw: string, maxChars: number): string {
  let amp = raw.indexOf('&');
  if (amp === -1) {
    if (raw.length > maxChars) throw new XmlError('limit');
    return raw;
  }
  const parts: string[] = [];
  let from = 0;
  let length = 0;
  while (amp !== -1) {
    const semi = raw.indexOf(';', amp + 1);
    if (semi === -1 || semi - amp - 1 > MAX_REFERENCE_CHARS) throw new XmlError('entity');
    const ref = raw.slice(amp + 1, semi);
    let replacement: string;
    if (ref.startsWith('#x')) {
      if (!isDigits(ref.slice(2), true)) throw new XmlError('entity');
      const cp = parseInt(ref.slice(2), 16);
      if (!isXmlChar(cp)) throw new XmlError('entity');
      replacement = String.fromCodePoint(cp);
    } else if (ref.startsWith('#')) {
      if (!isDigits(ref.slice(1), false)) throw new XmlError('entity');
      const cp = parseInt(ref.slice(1), 10);
      if (!isXmlChar(cp)) throw new XmlError('entity');
      replacement = String.fromCodePoint(cp);
    } else if (Object.prototype.hasOwnProperty.call(PREDEFINED, ref)) {
      replacement = PREDEFINED[ref];
    } else {
      throw new XmlError('entity');
    }
    parts.push(raw.slice(from, amp), replacement);
    length += amp - from + replacement.length;
    if (length > maxChars) throw new XmlError('limit');
    from = semi + 1;
    amp = raw.indexOf('&', from);
  }
  parts.push(raw.slice(from));
  length += raw.length - from;
  if (length > maxChars) throw new XmlError('limit');
  return parts.join('');
}

function localNameOf(name: string): string {
  const colon = name.lastIndexOf(':');
  return colon === -1 ? name : name.slice(colon + 1);
}

/**
 * Parses one XML document and returns its root element, or throws `XmlError`.
 * See the module comment for the accepted subset.
 */
export function parseXml(bytes: Uint8Array, limits: Partial<XmlLimits> = {}): XmlElement {
  const lim: XmlLimits = { ...DEFAULT_XML_LIMITS, ...limits };
  const text = decode(bytes);
  checkDeclaredEncoding(text);

  const n = text.length;
  const stack: XmlElement[] = [];
  let root: XmlElement | null = null;
  let elements = 0;
  let i = 0;

  const readName = (from: number): number => {
    if (from >= n || !isNameStart(text.charCodeAt(from))) throw new XmlError('malformed');
    let j = from + 1;
    while (j < n && isNameChar(text.charCodeAt(j))) {
      j++;
      if (j - from > lim.maxNameChars) throw new XmlError('limit');
    }
    return j;
  };
  const skipSpace = (from: number): number => {
    let j = from;
    while (j < n && isXmlSpace(text.charCodeAt(j))) j++;
    return j;
  };
  const appendText = (value: string): void => {
    const top = stack[stack.length - 1];
    if (top.text.length + value.length > lim.maxValueChars) throw new XmlError('limit');
    top.text += value;
  };

  while (i < n) {
    const lt = text.indexOf('<', i);
    const end = lt === -1 ? n : lt;
    if (end > i) {
      const raw = text.slice(i, end);
      let blank = true;
      for (let k = 0; k < raw.length && blank; k++) blank = isXmlSpace(raw.charCodeAt(k));
      if (stack.length === 0) {
        if (!blank) throw new XmlError('malformed');
      } else if (!blank) {
        appendText(decodeEntities(raw, lim.maxValueChars));
      }
    }
    if (lt === -1) break;
    i = lt;

    if (text.startsWith('<?', i)) {
      const close = text.indexOf('?>', i + 2);
      if (close === -1) throw new XmlError('malformed');
      i = close + 2;
      continue;
    }
    if (text.startsWith('<!--', i)) {
      const close = text.indexOf('-->', i + 4);
      if (close === -1) throw new XmlError('malformed');
      i = close + 3;
      continue;
    }
    if (text.startsWith('<![CDATA[', i)) {
      if (stack.length === 0) throw new XmlError('malformed');
      const close = text.indexOf(']]>', i + 9);
      if (close === -1) throw new XmlError('malformed');
      appendText(text.slice(i + 9, close));
      i = close + 3;
      continue;
    }
    if (text.startsWith('<!', i)) throw new XmlError('doctype');

    if (text.startsWith('</', i)) {
      const nameEnd = readName(i + 2);
      const name = text.slice(i + 2, nameEnd);
      const gt = skipSpace(nameEnd);
      if (text[gt] !== '>') throw new XmlError('malformed');
      const top = stack.pop();
      if (!top || top.name !== name) throw new XmlError('malformed');
      i = gt + 1;
      continue;
    }

    // Start tag.
    const nameEnd = readName(i + 1);
    const name = text.slice(i + 1, nameEnd);
    if (stack.length === 0 && root !== null) throw new XmlError('malformed'); // second root
    elements++;
    if (elements > lim.maxElements || stack.length + 1 > lim.maxDepth) throw new XmlError('limit');
    const attributes: Array<[string, string]> = [];
    const seen = new Set<string>();
    let j = nameEnd;
    let selfClosing = false;
    for (;;) {
      const afterSpace = skipSpace(j);
      if (afterSpace >= n) throw new XmlError('malformed');
      if (text[afterSpace] === '>') {
        j = afterSpace + 1;
        break;
      }
      if (text.startsWith('/>', afterSpace)) {
        j = afterSpace + 2;
        selfClosing = true;
        break;
      }
      if (afterSpace === j) throw new XmlError('malformed'); // attributes must be separated by whitespace
      const attrEnd = readName(afterSpace);
      const attrName = text.slice(afterSpace, attrEnd);
      let k = skipSpace(attrEnd);
      if (text[k] !== '=') throw new XmlError('malformed');
      k = skipSpace(k + 1);
      const quote = text[k];
      if (quote !== '"' && quote !== "'") throw new XmlError('malformed');
      const close = text.indexOf(quote, k + 1);
      if (close === -1) throw new XmlError('malformed');
      const rawValue = text.slice(k + 1, close);
      if (rawValue.includes('<')) throw new XmlError('malformed');
      if (seen.has(attrName)) throw new XmlError('malformed');
      seen.add(attrName);
      if (attributes.length + 1 > lim.maxAttributes) throw new XmlError('limit');
      attributes.push([attrName, decodeEntities(rawValue, lim.maxValueChars)]);
      j = close + 1;
    }

    const element: XmlElement = { name, localName: localNameOf(name), attributes, children: [], text: '' };
    if (stack.length === 0) root = element;
    else stack[stack.length - 1].children.push(element);
    if (!selfClosing) stack.push(element);
    i = j;
  }

  if (stack.length > 0 || root === null) throw new XmlError('malformed');
  return root;
}
