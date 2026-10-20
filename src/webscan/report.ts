/**
 * Web scan results for the API and the one-click outputs (REQ-008 P-27;
 * contract sections 3.6, 3.7, 6, 9).
 *
 * - `loadWebScanResult`: the `GET /api/scans/{id}/web-findings` payload
 *   (completed web scans only, 404 otherwise).
 * - `renderWebReportPdf`: manager-oriented PDF (AC-P27-4): grade, counts,
 *   top findings and actions on the first page, then the full list and the
 *   component inventory.
 * - `renderWebFindingsCsv`: contract section 9.
 *
 * The PDF uses a TrueType font with Turkish glyphs when one is found at a
 * fixed system path (Windows Arial/Segoe UI, DejaVu/Liberation on Linux);
 * otherwise the standard Helvetica font with Turkish letters folded to ASCII.
 */
import PDFDocument from 'pdfkit';
import type { Pool } from 'pg';
import { excelSafeText, singleLine } from '../lib/outputText';
import { toCsv, type CsvCell } from '../reports/csv';
import { foldTurkish, systemFont } from '../reports/pdfFont';
import { locationOf } from './allowlist';
import { countBySeverity, webGrade, webScore } from './score';
import type { WebSeverity } from './types';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const WEB_SCAN_NOT_FOUND_MESSAGE = 'Scan not found or not a completed web scan';

const SEVERITY_RANK: Readonly<Record<string, number>> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface WebFindingRow {
  id: string;
  rule_id: string;
  source: string;
  category: string;
  severity: WebSeverity;
  confidence: string;
  title: string;
  description: string;
  recommendation: string;
  location: string | null;
  evidence: string | null;
  cwe_id: number | null;
  owasp: string | null;
  component_name: string | null;
  component_version: string | null;
  fixed_version: string | null;
  cvss_score: number | null;
  advisory_id: string | null;
  status: string;
}

export interface WebComponentRow {
  name: string;
  npm_name: string | null;
  version: string;
  detection: string;
  location: string | null;
}

export interface WebScanResult {
  scan: { id: string; project_id: string; project_name: string; target_url: string; completed_at: Date | null };
  score: number;
  grade: string;
  counts: Record<WebSeverity, number>;
  summary: Record<string, unknown> | null;
  findings: WebFindingRow[];
  components: WebComponentRow[];
}

function notFound(): Error {
  return Object.assign(new Error(WEB_SCAN_NOT_FOUND_MESSAGE), { statusCode: 404 });
}

export async function loadWebScanResult(db: Pool, scanId: string): Promise<WebScanResult> {
  if (!UUID_RE.test(scanId)) throw Object.assign(new Error('scanId must be a valid UUID'), { statusCode: 400 });
  const scan = await db.query<{ id: string; project_id: string; project_name: string; target_url: string; completed_at: Date | null; web_summary: Record<string, unknown> | null }>(
    `SELECT s.id, s.project_id, p.name AS project_name, s.target_url, s.completed_at, s.web_summary
     FROM scans s JOIN projects p ON p.id = s.project_id
     WHERE s.id = $1 AND s.status = 'completed' AND s.scan_kind = 'web'`,
    [scanId],
  );
  if (scan.rows.length === 0) throw notFound();
  const findings = await db.query<WebFindingRow & { cvss_score: string | number | null }>(
    `SELECT f.id, f.rule_id, f.source, f.category, f.severity, f.confidence, f.title, f.description, f.recommendation,
            f.location, f.evidence, f.cwe_id, f.owasp, f.component_name, f.component_version, f.fixed_version,
            f.cvss_score, COALESCE(v.cve_id, v.ghsa_id, v.osv_id) AS advisory_id, f.status::text AS status
     FROM web_findings f
     LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
     WHERE f.scan_id = $1`,
    [scanId],
  );
  const rows = findings.rows
    .map((r) => ({ ...r, cvss_score: r.cvss_score === null ? null : Number(r.cvss_score) }))
    .sort(
      (a, b) =>
        (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
        a.rule_id.localeCompare(b.rule_id) ||
        (a.location ?? '').localeCompare(b.location ?? ''),
    );
  const components = await db.query<WebComponentRow>(
    `SELECT name, npm_name, version, detection, location FROM web_scan_components WHERE scan_id = $1 ORDER BY lower(name), version`,
    [scanId],
  );
  const counts = countBySeverity(rows.map((r) => r.severity));
  const score = webScore(counts);
  const { web_summary: summary, ...scanFields } = scan.rows[0];
  return { scan: scanFields, score, grade: webGrade(score), counts, summary, findings: rows, components: components.rows };
}

// ---------------------------------------------------------------------------
// CSV (contract section 9)
// ---------------------------------------------------------------------------

export const WEB_CSV_HEADER = [
  'Severity', 'Rule', 'Category', 'Title', 'Location', 'Evidence', 'CWE', 'OWASP', 'Component', 'Version',
  'Fixed Version', 'CVSS', 'Advisory', 'Source', 'Status', 'Recommendation',
] as const;

export function renderWebFindingsCsv(result: WebScanResult): Buffer {
  const cell = (value: string | null | undefined): string => excelSafeText(singleLine(value));
  const rows: CsvCell[][] = [[...WEB_CSV_HEADER]];
  for (const f of result.findings) {
    rows.push([
      f.severity, f.rule_id, f.category, cell(f.title), cell(f.location), cell(f.evidence),
      f.cwe_id === null ? '' : `CWE-${f.cwe_id}`, f.owasp ?? '', cell(f.component_name), cell(f.component_version),
      cell(f.fixed_version), f.cvss_score === null ? '' : f.cvss_score.toFixed(1), cell(f.advisory_id), f.source, f.status,
      cell(f.recommendation),
    ]);
  }
  return toCsv(rows);
}

// ---------------------------------------------------------------------------
// PDF (AC-P27-4)
// ---------------------------------------------------------------------------

const COLORS: Readonly<Record<string, string>> = {
  critical: '#b91c1c', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#6b7280',
  A: '#15803d', B: '#65a30d', C: '#ca8a04', D: '#ea580c', F: '#b91c1c',
};
const SEVERITY_LABEL: Readonly<Record<string, string>> = { critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', info: 'Bilgi' };
const CATEGORY_LABEL: Readonly<Record<string, string>> = {
  transport: 'HTTPS / TLS', headers: 'Güvenlik başlıkları', disclosure: 'Bilgi ifşası', cookies: 'Çerezler', cors: 'CORS',
  exposure: 'Açıkta kalan dosyalar', content: 'Sayfa içeriği', components: 'JavaScript kütüphaneleri', zap: 'OWASP ZAP bulguları',
};
const ENGINE_LABEL: Readonly<Record<string, string>> = {
  complete: 'tamamlandı', partial: 'kısmi', not_configured: 'tanımlı değil', unavailable: 'ulaşılamadı', failed: 'başarısız',
  disabled: 'kapalı', not_needed: 'gerekmedi',
};

function gradeText(grade: string): string {
  switch (grade) {
    case 'A': return 'Çok iyi: belirgin bir yapılandırma açığı bulunmadı.';
    case 'B': return 'İyi: birkaç iyileştirme önerisi var.';
    case 'C': return 'Orta: giderilmesi gereken önemli eksikler var.';
    case 'D': return 'Zayıf: yüksek riskli açıklar var, öncelikli ele alınmalı.';
    default: return 'Kritik: acil müdahale gerektiren açıklar var.';
  }
}

export async function renderWebReportPdf(result: WebScanResult, generatedAt: Date = new Date()): Promise<Buffer> {
  const font = systemFont();
  const doc = new PDFDocument({ margin: 48, size: 'A4', bufferPages: true, info: { Title: 'Web Security Report', Producer: 'oss-risk-platform' } });
  const chunks: Buffer[] = [];
  doc.on('data', (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve) => doc.on('end', () => resolve(Buffer.concat(chunks))));

  if (font) {
    doc.registerFont('body', font.regular);
    doc.registerFont('bold', font.bold);
  }
  const regular = font ? 'body' : 'Helvetica';
  const bold = font ? 'bold' : 'Helvetica-Bold';
  const t = (value: string | null | undefined): string => {
    const clean = singleLine(value);
    return font ? clean : foldTurkish(clean);
  };
  const left = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const ensure = (space: number) => {
    if (doc.y + space > doc.page.height - doc.page.margins.bottom) doc.addPage();
  };
  const heading = (text: string) => {
    ensure(40);
    doc.moveDown(0.8).font(bold).fontSize(14).fillColor('#111827').text(t(text), left, doc.y, { width });
    doc.moveDown(0.3);
  };

  // Title block
  doc.font(bold).fontSize(20).fillColor('#111827').text(t('Web Güvenlik Raporu'), left, 48, { width });
  doc.moveDown(0.3).font(regular).fontSize(10).fillColor('#374151');
  doc.text(t(`Proje: ${result.scan.project_name}`), { width });
  // Security review I-9: the query string of the stored URL is never printed.
  doc.text(t(`Hedef: ${locationOf(result.scan.target_url) || '-'}`), { width });
  doc.text(t(`Tarama: ${result.scan.id}`), { width });
  doc.text(t(`Tamamlanma: ${result.scan.completed_at ? result.scan.completed_at.toISOString() : '-'}   Rapor: ${generatedAt.toISOString()}`), { width });

  // Grade box
  const boxY = doc.y + 14;
  const gradeColor = COLORS[result.grade] ?? '#111827';
  doc.save().roundedRect(left, boxY, 90, 90, 8).fill(gradeColor).restore();
  doc.font(bold).fontSize(48).fillColor('#ffffff').text(result.grade, left, boxY + 14, { width: 90, align: 'center' });
  doc.font(bold).fontSize(16).fillColor('#111827').text(t(`Güvenlik notu: ${result.grade} (${result.score}/100)`), left + 110, boxY + 6, { width: width - 110 });
  doc.font(regular).fontSize(10).fillColor('#374151').text(t(gradeText(result.grade)), left + 110, doc.y + 4, { width: width - 110 });

  // Severity counts
  const order: WebSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  let x = left + 110;
  const chipY = boxY + 62;
  for (const s of order) {
    const label = t(`${SEVERITY_LABEL[s]}: ${result.counts[s]}`);
    doc.font(bold).fontSize(9);
    const w = doc.widthOfString(label) + 14;
    doc.save().roundedRect(x, chipY, w, 18, 4).fill(COLORS[s]).restore();
    doc.fillColor('#ffffff').text(label, x + 7, chipY + 5, { lineBreak: false });
    x += w + 6;
  }
  doc.x = left;
  doc.y = boxY + 104;

  // Engines
  const summary = (result.summary ?? {}) as { engines?: { builtin?: string; zap?: string; zap_mode?: string | null }; vulnerability_lookup?: string; requests?: number };
  const engines = summary.engines ?? {};
  doc.font(regular).fontSize(9).fillColor('#4b5563').text(
    t(`Yerleşik pasif kontroller: ${ENGINE_LABEL[engines.builtin ?? ''] ?? '-'} · OWASP ZAP: ${ENGINE_LABEL[engines.zap ?? ''] ?? '-'}${engines.zap_mode ? ` (${engines.zap_mode === 'active' ? 'aktif' : 'pasif'})` : ''} · Kütüphane açık sorgusu: ${ENGINE_LABEL[summary.vulnerability_lookup ?? ''] ?? '-'} · İstek sayısı: ${summary.requests ?? '-'}`),
    left, doc.y, { width },
  );

  // Top findings
  const actionable = result.findings.filter((f) => f.severity !== 'info');
  heading('Öne çıkan bulgular');
  if (actionable.length === 0) {
    doc.font(regular).fontSize(10).fillColor('#15803d').text(t('Düşük ve üzeri önemde bulgu yok.'), { width });
  } else {
    for (const f of actionable.slice(0, 5)) {
      ensure(30);
      doc.font(bold).fontSize(10).fillColor(COLORS[f.severity] ?? '#111827').text(t(`[${SEVERITY_LABEL[f.severity] ?? f.severity}] `), left, doc.y, { continued: true });
      doc.fillColor('#111827').text(t(f.title), { width });
      if (f.location) doc.font(regular).fontSize(8).fillColor('#6b7280').text(t(f.location), { width });
      doc.moveDown(0.2);
    }
  }

  // Actions (distinct rules, most severe first)
  heading('Ne yapılmalı?');
  const seenRules = new Set<string>();
  let n = 0;
  for (const f of actionable) {
    if (seenRules.has(f.rule_id) || n >= 5) continue;
    seenRules.add(f.rule_id);
    n++;
    ensure(40);
    doc.font(bold).fontSize(10).fillColor('#111827').text(t(`${n}. ${f.title}`), left, doc.y, { width });
    doc.font(regular).fontSize(9).fillColor('#374151').text(t(f.recommendation), { width });
    doc.moveDown(0.3);
  }
  if (n === 0) doc.font(regular).fontSize(10).fillColor('#374151').text(t('Acil bir aksiyon gerekmiyor; düzenli taramaya devam edin.'), { width });

  // Full list by category
  doc.addPage();
  doc.font(bold).fontSize(16).fillColor('#111827').text(t('Tüm bulgular'), left, doc.page.margins.top, { width });
  const categories = [...new Set(result.findings.map((f) => f.category))];
  for (const category of categories) {
    heading(CATEGORY_LABEL[category] ?? category);
    for (const f of result.findings.filter((x2) => x2.category === category)) {
      ensure(70);
      doc.font(bold).fontSize(10).fillColor(COLORS[f.severity] ?? '#111827').text(t(`[${SEVERITY_LABEL[f.severity] ?? f.severity}] `), left, doc.y, { continued: true });
      doc.fillColor('#111827').text(t(`${f.title}  (${f.rule_id})`), { width });
      doc.font(regular).fontSize(8.5).fillColor('#374151');
      const meta = [f.cwe_id ? `CWE-${f.cwe_id}` : null, f.owasp ? `OWASP ${f.owasp}` : null, f.cvss_score !== null ? `CVSS ${f.cvss_score.toFixed(1)}` : null, f.advisory_id, f.fixed_version ? `Düzeltilmiş sürüm: ${f.fixed_version}` : null]
        .filter((v): v is string => !!v)
        .join(' · ');
      if (meta) doc.text(t(meta), { width });
      if (f.location) doc.text(t(`Konum: ${f.location}`), { width });
      if (f.evidence) doc.text(t(`Kanıt: ${f.evidence}`), { width });
      doc.text(t(`Açıklama: ${f.description}`), { width });
      doc.fillColor('#065f46').text(t(`Öneri: ${f.recommendation}`), { width });
      doc.moveDown(0.5);
    }
  }
  if (result.findings.length === 0) doc.moveDown().font(regular).fontSize(10).fillColor('#374151').text(t('Bulgu yok.'), { width });

  heading('Tespit edilen JavaScript kütüphaneleri');
  if (result.components.length === 0) {
    doc.font(regular).fontSize(9).fillColor('#374151').text(t('Tespit edilen kütüphane yok (paketlenmiş uygulamalarda tespit sınırlıdır).'), { width });
  } else {
    for (const c of result.components) {
      ensure(16);
      doc.font(regular).fontSize(9).fillColor('#111827').text(t(`${c.name} ${c.version}  —  ${c.location ?? 'HTML'}`), left, doc.y, { width });
    }
  }

  heading('Not');
  doc.font(regular).fontSize(8.5).fillColor('#4b5563').text(
    t('Bu rapor otomatik bir tarama sonucudur. Yerleşik kontroller yalnız zararsız GET istekleriyle çalışır; kimlik doğrulama arkasındaki sayfalar ve iş mantığı açıkları kapsanmaz. Otomatik tarama, sızma testinin (pentest) yerini tutmaz.'),
    { width },
  );

  // Page numbers
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    // Writing inside the bottom margin would otherwise start a new page.
    const bottom = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;
    doc.font(regular).fontSize(8).fillColor('#9ca3af').text(`${i + 1} / ${range.count}`, left, doc.page.height - 36, { width, align: 'right', lineBreak: false });
    doc.page.margins.bottom = bottom;
  }
  doc.end();
  return done;
}
