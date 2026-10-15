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

const TAG_RE = /<(script|link|iframe|form|meta|html|base)\b([^>]*)>/gi;
const ATTR_RE = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
const COMMENT_RE = /<!--[\s\S]*?-->/g;

function decodeEntities(value: string): string {
  return value
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&#x0*27;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&');
}

/** Opening tags of `script`, `link`, `iframe`, `form`, `meta`, `html`, `base` in document order. */
export function extractTags(html: string): HtmlTag[] {
  const text = html.replace(COMMENT_RE, ' ');
  const tags: HtmlTag[] = [];
  TAG_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = TAG_RE.exec(text)) !== null && tags.length < MAX_TAGS) {
    const attrs: Record<string, string> = {};
    const attrText = match[2] ?? '';
    ATTR_RE.lastIndex = 0;
    let attr: RegExpExecArray | null;
    let count = 0;
    while ((attr = ATTR_RE.exec(attrText)) !== null && count < 64) {
      count++;
      const name = attr[1].toLowerCase();
      if (name in attrs) continue;
      attrs[name] = decodeEntities(attr[2] ?? attr[3] ?? attr[4] ?? '');
    }
    tags.push({ name: match[1].toLowerCase(), attrs });
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
