import fs from 'fs';

/**
 * System TrueType fonts with Turkish glyphs, shared by the web report
 * (REQ-008) and the dependency report (REQ-010 D-277). No font is bundled
 * or downloaded; the first installed pair wins.
 */
const FONT_CANDIDATES: ReadonlyArray<{ regular: string; bold: string }> = [
  { regular: 'C:\\Windows\\Fonts\\arial.ttf', bold: 'C:\\Windows\\Fonts\\arialbd.ttf' },
  { regular: 'C:\\Windows\\Fonts\\segoeui.ttf', bold: 'C:\\Windows\\Fonts\\segoeuib.ttf' },
  { regular: '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', bold: '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf' },
  { regular: '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf', bold: '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf' },
  { regular: '/System/Library/Fonts/Supplemental/Arial.ttf', bold: '/System/Library/Fonts/Supplemental/Arial Bold.ttf' },
];

let fontCache: { regular: string; bold: string } | null | undefined;

export function systemFont(): { regular: string; bold: string } | null {
  if (fontCache !== undefined) return fontCache;
  fontCache = FONT_CANDIDATES.find((c) => fs.existsSync(c.regular) && fs.existsSync(c.bold)) ?? null;
  return fontCache;
}

const TURKISH_FOLD: Readonly<Record<string, string>> = { ş: 's', Ş: 'S', ğ: 'g', Ğ: 'G', ı: 'i', İ: 'I' };

/** Without a system font the built-in Helvetica lacks these six letters; they are folded to ASCII. */
export function foldTurkish(value: string): string {
  return value.replace(/[şŞğĞıİ]/g, (c) => TURKISH_FOLD[c] ?? c);
}

export interface PdfFonts {
  regular: string;
  bold: string;
  /** Text as it can be printed with these fonts (folded when no system font). */
  t(value: string): string;
}

/** Registers the system font on `doc` (if any) and returns the font names and the text filter. */
export function applyPdfFonts(doc: PDFKit.PDFDocument): PdfFonts {
  const font = systemFont();
  if (font) {
    doc.registerFont('body', font.regular);
    doc.registerFont('bold', font.bold);
    return { regular: 'body', bold: 'bold', t: (value) => value };
  }
  return { regular: 'Helvetica', bold: 'Helvetica-Bold', t: foldTurkish };
}
