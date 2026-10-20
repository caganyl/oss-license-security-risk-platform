import PDFDocument from 'pdfkit';
import { singleLine } from '../lib/outputText';
import { applyPdfFonts } from './pdfFont';
import type { ReportData, ReportDependency, ReportType } from './reportService';

/**
 * Dependency report PDF in Turkish for managers (REQ-010 P-37): overall
 * status, "Ne yapılmalı?" actions, readable tables, terms. Structural rules
 * of REQ-004 contract 1.6.0 stay: the vulnerability-data row is the last
 * item of the summary (§5.3) and every cut table gets one note line (§5.4,
 * caps 40/40/50).
 */

export const PDF_FINDING_ROW_LIMIT = 40;
export const PDF_DEPENDENCY_ROW_LIMIT = 50;
const MAX_ACTIONS = 10;

/** Label of the vulnerability-data row, last summary item (REQ-004 contract 1.6.0 §5.3). */
export const PDF_VULNERABILITY_DATA_LABEL = 'Güvenlik açığı verisi';

const VULNERABILITY_DATA_TEXT_TR: Readonly<Record<string, string>> = {
  complete: 'tam',
  partial: 'kısmi (bazı paketler kontrol edilemedi)',
  unavailable: 'alınamadı (güvenlik açığı kaynağına ulaşılamadı)',
  disabled: 'kapalı (sorgu devre dışı)',
};

export function pdfVulnerabilityDataText(status: string | null | undefined): string {
  return status != null && Object.hasOwn(VULNERABILITY_DATA_TEXT_TR, status) ? VULNERABILITY_DATA_TEXT_TR[status] : 'kontrol edilmedi';
}

/** Note under a cut table (REQ-004 contract 1.6.0 §5.4); plain integers. */
export function pdfTruncationNoteTr(shown: number, total: number): string {
  return `İlk ${String(shown)} / ${String(total)} kayıt gösteriliyor; tam liste için Excel veya CSV çıktısına bakın.`;
}

const TITLES: Readonly<Record<ReportType, string>> = {
  executive_summary: 'Yönetici Özeti',
  project_report: 'Açık Kaynak Risk Raporu',
  license_inventory: 'Lisans Envanteri Raporu',
  audit_evidence: 'Denetim Kanıtı Raporu',
  vulnerability_report: 'Güvenlik Açığı Raporu',
};

const SEVERITY_TR: Readonly<Record<string, string>> = { critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', info: 'Bilgi', unknown: 'Bilinmiyor' };
const LICENSE_RISK_TR: Readonly<Record<string, string>> = {
  critical: 'Çok yüksek', high: 'Yüksek', medium: 'Orta', safe: 'Düşük', unknown: 'Belirsiz',
};
const STATUS_TR: Readonly<Record<string, string>> = {
  open: 'Açık', in_review: 'İnceleniyor', accepted: 'Risk kabul edildi', risk_accepted: 'Risk kabul edildi',
  false_positive: 'Hatalı bulgu', fixed: 'Giderildi', resolved: 'Giderildi', wont_fix: 'Düzeltilmeyecek',
  suppressed: 'Bastırıldı', compliant: 'Uygun', violation: 'İhlal', review_required: 'İnceleme gerekli',
};
const SCOPE_TR: Readonly<Record<string, string>> = { direct: 'Doğrudan', transitive: 'Dolaylı', dev: 'Geliştirme', peer: 'Eş', optional: 'İsteğe bağlı' };
const TRIGGER_TR: Readonly<Record<string, string>> = { manual: 'elle', scheduled: 'zamanlanmış', schedule: 'zamanlanmış', webhook: 'webhook', ci: 'CI', api: 'API' };
const ECOSYSTEM_TR: Readonly<Record<string, string>> = { npm: 'npm', pypi: 'PyPI', nuget: 'NuGet', nodejs: 'npm', python: 'PyPI', dotnet: 'NuGet' };

/** Statuses that need no further action. */
const CLOSED_STATUSES = new Set(['accepted', 'risk_accepted', 'false_positive', 'fixed', 'resolved', 'wont_fix', 'suppressed']);
const SEVERITY_RANK: Readonly<Record<string, number>> = { critical: 4, high: 3, medium: 2, low: 1 };

const COLORS = {
  text: '#111827', muted: '#4b5563', line: '#e5e7eb', headerBg: '#f3f4f6',
  critical: '#b91c1c', attention: '#ea580c', improve: '#ca8a04', clean: '#15803d',
};

const label = (map: Readonly<Record<string, string>>, value: string | null | undefined): string =>
  value != null && Object.hasOwn(map, value) ? map[value] : (value ?? '-');

const DATE_FORMAT = new Intl.DateTimeFormat('tr-TR', { dateStyle: 'long', timeStyle: 'short', timeZone: 'Europe/Istanbul' });
export function formatDateTr(value: Date | null): string {
  return value ? DATE_FORMAT.format(value) : '-';
}

export type OverallLevel = 'critical' | 'attention' | 'improve' | 'clean';

/** Rule-based overall status (REQ-010 D-278). */
export function overallStatus(data: ReportData): { level: OverallLevel; sentence: string } {
  const riskyLicenses = data.dependencies.some((d) => d.licenses.some((l) => !l.suppressed && (l.riskLevel === 'high' || l.riskLevel === 'critical')));
  const unknownLicenses = data.dependencies.some((d) => d.licenses.some((l) => !l.suppressed && l.riskLevel === 'unknown'));
  if (data.scan.criticalVulns > 0) return { level: 'critical', sentence: 'Acil müdahale gereken kritik güvenlik açıkları var.' };
  if (data.scan.highVulns > 0 || riskyLicenses) {
    return { level: 'attention', sentence: 'Öncelikli ele alınması gereken yüksek riskli bulgular var.' };
  }
  if (data.scan.mediumVulns > 0 || data.scan.lowVulns > 0 || data.scan.licenseViolations > 0 || unknownLicenses) {
    return { level: 'improve', sentence: 'Acil bir risk görünmüyor; iyileştirme önerileri var.' };
  }
  return { level: 'clean', sentence: 'Belirgin bir risk bulunmadı.' };
}

/** Prioritized action list (REQ-010 AC-P37-3, D-279). */
export function actionItems(data: ReportData): string[] {
  type PackageRisk = { dep: ReportDependency; severity: string; fix: string | null; ids: string[] };
  const byPackage = new Map<string, PackageRisk>();
  for (const dep of data.dependencies) {
    for (const v of dep.vulnerabilities) {
      if (v.suppressed || CLOSED_STATUSES.has(v.status)) continue;
      if (v.severity !== 'critical' && v.severity !== 'high') continue;
      const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
      const current = byPackage.get(key) ?? { dep, severity: v.severity, fix: null, ids: [] };
      if ((SEVERITY_RANK[v.severity] ?? 0) > (SEVERITY_RANK[current.severity] ?? 0)) current.severity = v.severity;
      if (v.fixVersion && !current.fix) current.fix = v.fixVersion;
      if (!current.ids.includes(v.advisoryId)) current.ids.push(v.advisoryId);
      byPackage.set(key, current);
    }
  }
  const risks = [...byPackage.values()].sort((a, b) =>
    (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
    || Number(b.fix !== null) - Number(a.fix !== null)
    || a.dep.name.localeCompare(b.dep.name));

  const items: string[] = [];
  for (const r of risks) {
    const sev = label(SEVERITY_TR, r.severity).toLocaleLowerCase('tr-TR');
    const ids = r.ids.slice(0, 2).join(', ') + (r.ids.length > 2 ? ` +${r.ids.length - 2}` : '');
    items.push(r.fix
      ? `${r.dep.name} paketini ${r.dep.version} sürümünden ${r.fix} sürümüne yükseltin (${sev} açık: ${ids}).`
      : `${r.dep.name} ${r.dep.version}: düzeltilmiş sürüm henüz yok (${sev} açık: ${ids}). Paketin gerekliliğini ve alternatiflerini değerlendirin.`);
  }

  const licenseSeen = new Set<string>();
  let unknownCount = 0;
  for (const dep of data.dependencies) {
    for (const l of dep.licenses) {
      if (l.suppressed) continue;
      if (l.riskLevel === 'unknown') {
        unknownCount += 1;
        continue;
      }
      if (l.riskLevel !== 'high' && l.riskLevel !== 'critical') continue;
      const key = `${dep.name}@${dep.version}`;
      if (licenseSeen.has(key)) continue;
      licenseSeen.add(key);
      const name = l.normalizedLicense ?? l.detectedLicense ?? 'bilinmeyen lisans';
      items.push(l.riskLevel === 'critical'
        ? `${dep.name} (${name}): ağ copyleft lisansı; sunucuda/SaaS olarak kullanımda kaynak kodun paylaşılması gerekebilir. Hukuk birimiyle değerlendirin.`
        : `${dep.name} (${name}): güçlü copyleft lisansı; ürünle dağıtımda türev çalışmanın aynı lisansla açılması gerekebilir. Hukuk birimiyle değerlendirin.`);
    }
  }
  if (unknownCount > 0) {
    items.push(`${String(unknownCount)} paketin lisansı belirlenemedi; Excel çıktısındaki lisans sütunundan kontrol edin.`);
  }

  if (items.length > MAX_ACTIONS) {
    const rest = items.length - (MAX_ACTIONS - 1);
    return [...items.slice(0, MAX_ACTIONS - 1), `…ve ${String(rest)} madde daha; ayrıntılar aşağıdaki tablolarda.`];
  }
  return items;
}

export async function renderDependencyPdf(data: ReportData, reportType: ReportType): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 48, size: 'A4', bufferPages: true, info: { Title: TITLES[reportType], Producer: 'oss-risk-platform' } });
  const chunks: Buffer[] = [];
  doc.on('data', (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve) => doc.on('end', () => resolve(Buffer.concat(chunks))));

  const fonts = applyPdfFonts(doc);
  const t = (value: string | null | undefined): string => fonts.t(singleLine(value));
  const left = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const bottom = () => doc.page.height - doc.page.margins.bottom;
  const ensure = (space: number) => {
    if (doc.y + space > bottom()) doc.addPage();
  };
  const heading = (text: string) => {
    ensure(48);
    doc.moveDown(0.9).font(fonts.bold).fontSize(14).fillColor(COLORS.text).text(t(text), left, doc.y, { width });
    doc.moveDown(0.3);
  };
  const paragraph = (text: string, color: string = COLORS.text, size = 10) => {
    doc.font(fonts.regular).fontSize(size).fillColor(color).text(t(text), left, doc.y, { width });
  };

  /** Fits `text` into `w` points with "…" (REQ-010 AC-P37-4). */
  const fit = (text: string | null | undefined, w: number): string => {
    // Database values can be NULL; pre-cut keeps the width search cheap for very long values (security review L1).
    const value = t((text ?? '').slice(0, 300));
    if (doc.widthOfString(value) <= w) return value;
    let cut = value;
    while (cut.length > 1 && doc.widthOfString(`${cut}…`) > w) cut = cut.slice(0, -1);
    return `${cut}…`;
  };

  /** Column-aligned table; `widths` are fractions of the text width. Repeats the header after a page break. */
  const table = (headers: string[], widths: number[], rows: Array<Array<string | null | undefined>>, total: number) => {
    const cols = widths.map((f) => f * width);
    const rowHeight = 15;
    const drawHeader = () => {
      ensure(rowHeight * 2);
      const y = doc.y;
      doc.save().rect(left, y - 2, width, rowHeight).fill(COLORS.headerBg).restore();
      doc.font(fonts.bold).fontSize(8.5).fillColor(COLORS.text);
      let x = left;
      headers.forEach((h, i) => {
        doc.text(fit(h, cols[i] - 6), x + 3, y + 2, { width: cols[i] - 6, lineBreak: false });
        x += cols[i];
      });
      doc.x = left;
      doc.y = y + rowHeight;
    };
    if (rows.length === 0) {
      paragraph('Kayıt yok.', COLORS.muted, 9);
      return;
    }
    drawHeader();
    doc.font(fonts.regular).fontSize(8.5);
    for (const row of rows) {
      if (doc.y + rowHeight > bottom()) {
        doc.addPage();
        drawHeader();
        doc.font(fonts.regular).fontSize(8.5);
      }
      const y = doc.y;
      let x = left;
      doc.fillColor(COLORS.text);
      row.forEach((cell, i) => {
        doc.text(fit(cell, cols[i] - 6), x + 3, y + 2, { width: cols[i] - 6, lineBreak: false });
        x += cols[i];
      });
      doc.save().moveTo(left, y + rowHeight - 1).lineTo(left + width, y + rowHeight - 1).lineWidth(0.5).strokeColor(COLORS.line).stroke().restore();
      doc.x = left;
      doc.y = y + rowHeight;
    }
    if (total > rows.length) {
      ensure(rowHeight);
      doc.moveDown(0.3);
      paragraph(pdfTruncationNoteTr(rows.length, total), COLORS.muted, 8.5);
    }
  };

  // Title block
  doc.font(fonts.bold).fontSize(20).fillColor(COLORS.text).text(t(TITLES[reportType]), left, 48, { width });
  doc.moveDown(0.3);
  paragraph(`Proje: ${data.project.name}`, COLORS.muted);
  if (data.project.repoUrl) paragraph(`Kaynak: ${data.project.repoUrl}`, COLORS.muted);
  paragraph(`Tarama tarihi: ${formatDateTr(data.scan.completedAt ?? data.scan.createdAt)}`, COLORS.muted);
  // Kept on its own line: the sync/async comparison (REQ-007 AC-P24-3) skips it.
  paragraph(`Rapor tarihi: ${formatDateTr(data.generatedAt)}`, COLORS.muted);

  // Overall status (AC-P37-2)
  heading('Genel durum');
  const overall = overallStatus(data);
  const boxY = doc.y;
  doc.save().roundedRect(left, boxY, width, 34, 6).fill(COLORS[overall.level]).restore();
  doc.font(fonts.bold).fontSize(12).fillColor('#ffffff').text(t(overall.sentence), left + 12, boxY + 11, { width: width - 24, lineBreak: false });
  doc.x = left;
  doc.y = boxY + 44;
  const s = data.scan;
  const summary: Array<[string, string]> = [
    ['Taranan paket', s.totalDependencies.toLocaleString('tr-TR')],
    ['Güvenlik açığı', `${s.totalVulnerabilities.toLocaleString('tr-TR')} (Kritik ${s.criticalVulns}, Yüksek ${s.highVulns}, Orta ${s.mediumVulns}, Düşük ${s.lowVulns})`],
    ['Lisans uyarısı', s.licenseViolations.toLocaleString('tr-TR')],
    ['Projenin önem derecesi', label(SEVERITY_TR, data.project.criticality)],
    // REQ-004 contract 1.6.0 §5.3: always the last summary item.
    [PDF_VULNERABILITY_DATA_LABEL, pdfVulnerabilityDataText(s.vulnerabilityDataStatus)],
  ];
  // One text call per line (no `continued`): each line stays one text run for text extraction.
  for (const [key, value] of summary) paragraph(`${key}: ${value}`);
  if (s.vulnerabilityDataStatus !== 'complete') {
    doc.moveDown(0.3);
    paragraph('Not: Güvenlik açığı verisi tam değil; bazı açıklar raporda görünmeyebilir.', COLORS.attention, 9);
  }

  // Actions (AC-P37-3)
  heading('Ne yapılmalı?');
  const actions = actionItems(data);
  if (actions.length === 0) {
    paragraph('Şu an için gereken bir aksiyon yok. Düzenli tarama yapmaya devam edin.', COLORS.clean);
  } else {
    actions.forEach((item, i) => {
      ensure(28);
      paragraph(`${String(i + 1)}. ${item}`);
      doc.moveDown(0.2);
    });
  }

  // Tables (AC-P37-4); caps unchanged (§5.4).
  if (reportType !== 'license_inventory') {
    heading('Güvenlik açıkları');
    paragraph('Paketlerde bilinen güvenlik açıkları; önem derecesi CVSS puanına göre belirlenir.', COLORS.muted, 9);
    doc.moveDown(0.3);
    const vulns = data.dependencies
      .flatMap((dep) => dep.vulnerabilities.map((v) => ({ dep, v })))
      .sort((a, b) => (SEVERITY_RANK[b.v.severity] ?? 0) - (SEVERITY_RANK[a.v.severity] ?? 0));
    table(
      ['Paket', 'Sürüm', 'Açık kodu', 'Önem', 'Düzeltilmiş sürüm', 'Durum'],
      [0.26, 0.12, 0.2, 0.1, 0.17, 0.15],
      vulns.slice(0, PDF_FINDING_ROW_LIMIT).map(({ dep, v }) => [
        dep.name, dep.version, v.advisoryId, label(SEVERITY_TR, v.severity), v.fixVersion ?? 'yok', label(STATUS_TR, v.status),
      ]),
      vulns.length,
    );
  }

  if (reportType !== 'vulnerability_report') {
    heading('Lisans bulguları');
    paragraph('Lisans riski, paketin ürünle birlikte kullanımında doğabilecek yükümlülükleri gösterir.', COLORS.muted, 9);
    doc.moveDown(0.3);
    const licenses = data.dependencies.flatMap((dep) => dep.licenses.map((l) => ({ dep, l })));
    table(
      ['Paket', 'Sürüm', 'Lisans', 'Risk', 'Durum'],
      [0.32, 0.13, 0.25, 0.13, 0.17],
      licenses.slice(0, PDF_FINDING_ROW_LIMIT).map(({ dep, l }) => [
        dep.name, dep.version, l.normalizedLicense ?? l.detectedLicense ?? 'bilinmiyor', label(LICENSE_RISK_TR, l.riskLevel), label(STATUS_TR, l.status),
      ]),
      licenses.length,
    );
  }

  if (reportType === 'project_report' || reportType === 'audit_evidence') {
    heading('Paket envanteri');
    paragraph('Projede kullanılan açık kaynak paketler. Doğrudan: projenin kendisinin eklediği; dolaylı: başka bir paketin getirdiği.', COLORS.muted, 9);
    doc.moveDown(0.3);
    table(
      ['Paket', 'Sürüm', 'Ekosistem', 'Kullanım', 'Lisans'],
      [0.34, 0.14, 0.12, 0.14, 0.26],
      data.dependencies.slice(0, PDF_DEPENDENCY_ROW_LIMIT).map((dep) => [
        dep.name, dep.version, label(ECOSYSTEM_TR, dep.ecosystem), label(SCOPE_TR, dep.scope), singleLine(dep.licenseExpression) || 'bilinmiyor',
      ]),
      data.dependencies.length,
    );
  }

  // Terms and notes (AC-P37-5)
  heading('Terimler');
  const terms: Array<[string, string]> = [
    ['CVE / açık kodu', 'Bilinen bir güvenlik açığının herkese açık kimliği (ör. CVE-2024-1234, GHSA-…).'],
    ['CVSS', '0–10 arası önem puanı; 9+ kritik, 7+ yüksek, 4+ orta.'],
    ['Lisans riski', 'Copyleft lisanslar ürünün kaynak kodunun paylaşılmasını gerektirebilir; izin verici (MIT, Apache) lisanslar genellikle yalnız atıf ister.'],
    ['Doğrudan / dolaylı', 'Doğrudan paketi proje ekler; dolaylı paket başka bir paketin bağımlılığıdır.'],
  ];
  for (const [term, text] of terms) {
    ensure(24);
    paragraph(`${term}: ${text}`, COLORS.muted, 9);
  }
  doc.moveDown(0.6);
  paragraph('Bu rapor otomatik üretilmiştir; hukuki görüş değildir.', COLORS.muted, 8.5);
  paragraph(`Teknik bilgi: tarama kimliği ${data.scan.id} · dal ${data.scan.ref ?? 'varsayılan'} · başlatan ${label(TRIGGER_TR, data.scan.trigger)}`, COLORS.muted, 7.5);

  doc.end();
  return done;
}
