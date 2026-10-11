/**
 * CSV serialiser of the one-click license inventory export (REQ-007 P-24,
 * ADR-009 Karar 8; contract `docs/contracts/REQ-007-cli-and-exports.md`
 * section 7).
 *
 * Pure and deterministic: no timestamp, meta or total row. The formula guard
 * (`excelSafeText`) is NOT applied here: the shared row builder
 * (`dependencyRowCells`) already applied it once, so the CSV and the Excel
 * `Dependencies` sheet carry the same cell text.
 */

/** UTF-8 byte order mark, so Excel reads Turkish characters correctly (D-184). */
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const SEPARATOR = ',';
const LINE_END = '\r\n';

/** A field needs quotes when it holds `,` `"` CR or LF (RFC 4180). */
const NEEDS_QUOTES_RE = /[,"\r\n]/;
/** …or when its first or last character is U+0020 or U+0009 (contract section 7). */
const EDGE_SPACE_RE = /^[ \t]|[ \t]$/;

export type CsvCell = string | number | null | undefined;

/**
 * One field: `null`/`undefined` -> empty, a number -> `String(n)` (no
 * prefix), a string as is; quoted per RFC 4180 with every inner `"` doubled.
 * Line breaks inside a quoted field are kept as they are (not normalised).
 */
export function csvField(value: CsvCell): string {
  if (value === null || value === undefined) return '';
  const text = typeof value === 'number' ? String(value) : value;
  if (NEEDS_QUOTES_RE.test(text) || EDGE_SPACE_RE.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

/**
 * Rows (the first one is the header) -> BOM + CRLF-terminated lines, the last
 * line included. An empty row list still yields the BOM.
 */
export function toCsv(rows: ReadonlyArray<ReadonlyArray<CsvCell>>): Buffer {
  const text = rows.map((row) => row.map(csvField).join(SEPARATOR) + LINE_END).join('');
  return Buffer.concat([UTF8_BOM, Buffer.from(text, 'utf8')]);
}
