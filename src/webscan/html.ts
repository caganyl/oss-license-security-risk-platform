/**
 * Minimal, bounded HTML attribute reader for the web rules (ADR-010 Karar 6).
 *
 * Not a DOM parser: it finds opening tags of a fixed set of elements and
 * reads their attributes. Comments are removed first so commented-out markup
 * does not trigger rules. Linear regular expressions only (no nested
 * quantifiers over the same characters), inputs are capped by the probe
 * client (2 MiB) and at most `MAX_TAGS` tags are returned.
 */

export const MAX_TAGS = 500;

export interface HtmlTag {
  name: string;
  /** Lower-case attribute names; values entity-decoded for `&amp;`, `&quot;`, `&#39;`. */
  attrs: Record<string, string>;
}

const TAG_NAMES: ReadonlySet<string> = new Set(['script', 'link', 'iframe', 'form', 'meta', 'html', 'base']);
/** Longest attribute text read from one tag (security review H-1: bounded work per tag). */
export const MAX_TAG_CHARS = 8192;
const ATTR_RE = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

function decodeEntities(value: string): string {
  return value
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&#x0*27;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&');
}

/**
 * Comments removed with an `indexOf` loop (linear; an unterminated comment
 * hides the rest of the document, as in a browser). Security review H-1: the
 * former lazy regex was quadratic on `<!--` floods.
 */
export function stripComments(html: string): string {
  let out = '';
  let pos = 0;
  for (;;) {
    const start = html.indexOf('<!--', pos);
    if (start === -1) return out + html.slice(pos);
    out += html.slice(pos, start) + ' ';
    const end = html.indexOf('-->', start + 4);
    if (end === -1) return out;
    pos = end + 3;
  }
}

function parseAttrs(attrText: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  ATTR_RE.lastIndex = 0;
  let attr: RegExpExecArray | null;
  let count = 0;
  while ((attr = ATTR_RE.exec(attrText)) !== null && count < 64) {
    count++;
    const name = attr[1].toLowerCase();
    if (name in attrs) continue;
    attrs[name] = decodeEntities(attr[2] ?? attr[3] ?? attr[4] ?? '');
  }
  return attrs;
}

/**
 * Opening tags of `script`, `link`, `iframe`, `form`, `meta`, `html`, `base`
 * in document order. A linear `indexOf` scan (security review H-1): every
 * character is visited a bounded number of times; a tag without a closing `>`
 * ends the scan; attribute text is cut at `MAX_TAG_CHARS`.
 */
export function extractTags(html: string): HtmlTag[] {
  const text = stripComments(html);
  const tags: HtmlTag[] = [];
  let pos = 0;
  while (tags.length < MAX_TAGS) {
    const lt = text.indexOf('<', pos);
    if (lt === -1) break;
    let i = lt + 1;
    while (i < text.length && i - lt <= 7 && /[A-Za-z]/.test(text[i])) i++;
    const name = text.slice(lt + 1, i).toLowerCase();
    if (!TAG_NAMES.has(name) || (i < text.length && !/[\s/>]/.test(text[i]))) {
      pos = lt + 1;
      continue;
    }
    const gt = text.indexOf('>', i);
    if (gt === -1) break;
    tags.push({ name, attrs: parseAttrs(text.slice(i, Math.min(gt, i + MAX_TAG_CHARS))) });
    pos = gt + 1;
  }
  return tags;
}

/** Resolves `ref` against `base`; null when it is not an http(s) URL. */
export function resolveUrl(ref: string | undefined, base: string): URL | null {
  if (ref === undefined) return null;
  const trimmed = ref.trim();
  if (trimmed === '' || /^(javascript|data|mailto|tel|about|blob):/i.test(trimmed)) return null;
  try {
    const url = new URL(trimmed, base);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : null;
  } catch {
    return null;
  }
}

/** Effective base URL of the document (`<base href>` resolved against the page URL). */
export function documentBase(tags: readonly HtmlTag[], pageUrl: string): string {
  const base = tags.find((t) => t.name === 'base' && typeof t.attrs.href === 'string');
  const resolved = base ? resolveUrl(base.attrs.href, pageUrl) : null;
  return resolved ? resolved.href : pageUrl;
}

/** `<title>` text (first 200 characters), used for soft-404 comparison hints only. */
export function titleOf(html: string): string | null {
  const m = /<title[^>]*>([^<]{0,200})/i.exec(html);
  return m ? m[1].trim() : null;
}
