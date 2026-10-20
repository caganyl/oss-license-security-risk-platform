# REQ-010 Güvenlik İncelemesi

- **Tarih:** 2026-10-20
- **Kapsam:** `GET /api/system/features`, Türkçe bağımlılık PDF'i
  (`src/reports/dependencyPdf.ts`, `pdfFont.ts`), Türkçe arayüz yeniden
  yazımı (`public/app.js`, `public/index.html`: sözlük, Yardım, Sistem
  Durumu, Raporlar menüsü, hata kodu eşlemesi), değişen arayüz testleri.
- **Yöntem:** Salt okunur, karşıt kod incelemesi (ayrı inceleme agent'ı;
  `devflow-plugin:security-red-team` bu oturumda yüklü değildi). Ağ yok.
- **Sonuç:** **Go.** Critical, High ve Medium bulgu yok.

## Bulgular

| ID | Önem | Bulgu | Durum |
| --- | --- | --- | --- |
| L1 | Low | PDF `fit()` kısaltma döngüsü hücre başına O(n²) `widthOfString` çağırıyor; satır/aksiyon sınırları (40/40/50, 10) nedeniyle pratikte DoS değil. | **Düzeltildi:** girdi 300 karakterle ön kırpılıyor. |
| L2 | Low | `web_scan.allowed_hosts` sayısı ortam değişkeninin yeniden bölünmesiyle hesaplanıyor; ayrıştırıcının saydığından farklı çıkabilir. Yalnız sayı, sızıntı yok. | Kabul (bilgi amaçlı sayı). |
| L3 | Low | `downloadDoc` `window.location.href` kullanıyor; yol `apiPath` + `encodeURIComponent` ile sabit. | Bilgi; sorun yok. |

## Doğrulanan (sorun yok)

- `GET /api/system/features`: `settings:read`, global kimlik doğrulamasından
  sonra bağlı; yanıt yalnız boolean/sayı. `ENCRYPTION_KEY` yalnız
  "tanımlı mı" olarak, NVD anahtarı `nvdApiKeyConfigured` ile (değişken
  yalnız `src/vulnerability/client.ts` içinde okunmaya devam eder,
  AC-P17-7) kullanılıyor.
- PDF: font yolları sabit; kullanıcı girdisi yola karışmıyor; gizli değer
  basılmıyor; font yoksa Helvetica + ASCII katlama.
- Arayüz: `innerHTML`/`insertAdjacentHTML`/`outerHTML`/`document.write`/
  `eval`/satır içi olay işleyicisi yok; tüm DOM `el()` ile, metin
  `textContent`/`createTextNode` ile. `href` süzgeci `javascript:`/`data:`
  reddediyor; Raporlar menüsü bağlantıları önceki URL'lerle aynı
  (`download`, SBOM'da `target=_blank` + `rel=noopener`). Hata kodu eşlemesi
  `hasOwnProperty` kontrollü (prototip anahtarları eşlenmez); bilinmeyen kodda
  sunucu metni düz metin.
- `tests/security/xss.test.ts`: eşlenen kodlarda sunucu mesajı artık
  gösterilmediği için XSS testi eşlenmemiş bir kodla sunucu metni yolunu
  sınamaya devam ediyor; test zayıflamadı.
