# ADR-010: Web (URL) güvenlik taraması — tarama türü, ayrı bulgu tablosu, izinli prob istemcisi ve isteğe bağlı OWASP ZAP

- **Durum:** Kabul edildi (2026-10-15); güvenlik incelemesi düzeltmeleri
  aynı gün işlendi (Ek: Güvenlik incelemesi sonrası)
- **İlgili:** REQ-008 (P-25…P-28), ADR-004 (tek süreç, kuyruk), ADR-006/007
  (güvenli HTTP katmanı, OSV), ADR-009 (tek tık çıktılar)

## Bağlam

REQ-008, çalışan bir web uygulamasını adresi üzerinden denetleyen bir tarama
türü ister. Mevcut mimari:

- Tek süreç; `ScanWorker` `scans` tablosundan iş alır, yazma çiti
  (`worker_id = runId`), süre sınırı, yeniden deneme ve sahipsiz iş kurtarma
  bu sınıftadır (ADR-004).
- Bulgu modeli bağımlılığa bağlıdır (`findings.scan_dependency_id NOT NULL`).
- Ağ erişimi `safeHttpClient`'tadır: sabit origin kümesi, amaç tablosu, yalnız
  `200` gövdesi. Hedefi kullanıcıya göre değişen ve hata gövdelerini de
  inceleyen bir tarayıcı için uygun değildir.
- Docker, Python ve yeni npm bağımlılığı istenmez (önceki ADR'ler, REQ-008
  Fonksiyonel Olmayan Gereksinimler).

## Kararlar

### 1. Tarama türü, ayrı kuyruk değil (D-210)

`scans.scan_kind TEXT NOT NULL DEFAULT 'dependency'` (`dependency` | `web`) ve
`scans.target_url`. `ScanWorker.claimNextJob` sorgusu `scan_kind`,
`target_url` ve projenin `web_scan_mode`'unu da okur. `processJob` en başta
türe göre dallanır: `web` → `processWebJob`. Talep, süre sınırı zamanlayıcısı,
`handleScanFailure` (yeniden deneme/kalıcı hata/kuyruğa iade) ve sahipsiz iş
kurtarma **değişmeden** paylaşılır. Web işinin sonuç yazımı ayrı bir
transaction'dır (`persistWebResults`) ve bağımlılık yazımıyla aynı çiti
kullanır: önce `status = 'running' AND worker_id = runId` satırı kilitlenir,
sonuç yazılır, `UPDATE … SET status = 'completed'` aynı koşulla yapılır.

Web taraması işçide `webScanner` bağımlılığı olmadan (`null`) çalışmaz:
`NonRetryableScanError` (testler ve eski runtime için güvenli varsayılan).

### 2. Ayrı bulgu ve bileşen tabloları (D-211)

`web_findings` (kural, önem, kategori, CWE, OWASP, konum, kanıt, öneri,
isteğe bağlı `vulnerability_id`, parmak izi, durum) ve `web_scan_components`
(tespit edilen JS kütüphaneleri). `findings`'e dokunulmaz; bağımlılık
sorguları, iş akışı (`workflowController`), raporlar ve yeniden kontrol
etkilenmez. Kütüphane açıkları mevcut `vulnerabilities` kataloğuna
`upsertVulnerability` ile yazılır ve `web_findings.vulnerability_id` ile
bağlanır (tek CVE kataloğu).

Parmak izi: `sha256('w1|' + project_id + '|' + rule_id + '|' + key)`; `key`
kurala göre konum (yol, sorgu dizesi olmadan), çerez adı, kütüphane@sürüm +
açık kimliği veya ZAP eklenti kimliğidir. `UNIQUE (scan_id, fingerprint)`.

### 3. İzin listesi: `WEB_SCAN_ALLOWED_HOSTS` (D-212, D-213)

`src/webscan/allowlist.ts` girdileri başlangıçta ayrıştırır (geçersiz → değer
yazmayan başlangıç hatası). Denetim noktaları: proje kaydı/güncellemesi,
tarama kuyruğa alınırken, işçi başlarken ve prob istemcisinin **her**
isteğinde (`assertAllowed(url)`); yönlendirme hedefleri de aynı denetimden
geçer. Liste süreç başlangıcında okunur; değişiklik yeniden başlatma ister.

### 4. Ayrı prob istemcisi (D-216, D-217)

`src/webscan/probeClient.ts`, `node:http`/`node:https` ile tek tek istek atan
küçük bir istemcidir:

- Yalnız `GET`; sabit `User-Agent`; `Accept-Encoding: gzip, deflate`;
  `Cookie`/`Authorization` asla gönderilmez; çağıranın verebileceği tek ek
  başlık `Origin`'dir (CORS yoklaması).
- Yönlendirme izlenmez; yanıt (durum, başlıklar, kesilmiş gövde) olduğu gibi
  döner. Ana sayfa yardımcısı aynı host içinde 5 adıma kadar izler.
- Gövde sınırı istek başına verilir; sınırda okuma durur ve `truncated: true`
  döner (açılmış gzip baytları da sayılır).
- İstek başına zaman aşımı, tarama başına istek bütçesi (120) ve semafor (3).
  Bütçe bitince istek atılmaz (`budget_exhausted`).
- TLS: Node varsayılan CA deposu + `NODE_EXTRA_CA_CERTS`;
  `rejectUnauthorized` her zaman `true`. Sertifika hataları `err.code` ile
  sınıflandırılır; hata mesajı tutulmaz. Başarılı yanıtta eş sertifikasının
  bitiş tarihi, veren CN'si ve müzakere edilen protokol okunur.
- Vekil: `https` hedefi + `HTTPS_PROXY` + `NO_PROXY` dışı → `proxyEnv`'li
  `https.Agent` (mevcut `proxy.ts`); `http` hedefi doğrudan.
- İş sinyali (`AbortSignal`) her isteğe bağlanır; iptal yeniden fırlatılır.

`safeHttpClient` değişmez; OSV/NVD/kayıt defteri trafiği eskisi gibi oradadır.

### 5. Eski TLS protokol yoklaması (D-218)

`https` hedeflerinde, vekil kullanılmıyorsa, `tls.connect({ minVersion:
'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0',
rejectUnauthorized: false })` ile tek el sıkışma yapılır; `secureConnect`
olursa protokol kabul edilmiştir. Hiçbir uygulama verisi yazılmaz/okunmaz,
soket hemen kapatılır. Sertifika doğrulamasının kapalı olduğu tek yer budur ve
yalnız protokol kabulünü ölçer. OpenSSL derlemesi eski protokolü hiç
desteklemiyorsa (`ERR_SSL_*` istemci tarafında) sonuç "ölçülemedi" sayılır ve
bulgu yazılmaz.

### 6. Kural motoru: saf fonksiyonlar (AC-P26-5)

`src/webscan/checks/*.ts` ağ erişimi yapmaz; prob sonuçlarını (`ProbeResponse`)
alıp `WebFindingDraft[]` döner. Kural kataloğu (`rules.ts`) contract §4'ün
kod karşılığıdır (kimlik, kategori, önem, CWE, OWASP, başlık, açıklama,
öneri). Orkestratör (`engine.ts`) istekleri sırayla planlar: ana sayfa →
soft-404 → (paralel) http varyantı, CORS ×2, hata yoklaması ×2, sabit dosya
yoklamaları, dizin listeleme, betik indirme → TLS protokol yoklaması.

HTML ayrıştırma bağımlılıksızdır: sınırlı sayıda (500) etiket için
`<(script|link|iframe|form|input|meta)\b[^>]*>` ve öznitelik regex'i. Tam DOM
gerekmez; kurallar öznitelik düzeyindedir.

### 7. JS kütüphane tespiti ve OSV (D-222, D-234)

`src/webscan/libraries.ts`: adres desenleri (dosya adı, cdnjs, jsDelivr,
unpkg), başlık yorumu imzaları ve HTML (`ng-version`) imzaları. Yalnız
hedefle aynı hosttaki betikler indirilir (en fazla 20). Sonuç
`{ name, npmName, version, detection, location }`. İşçi, sürümü kesin ve
`npmName`'i bilinen bileşenleri mevcut `VulnerabilityLookup.lookup` ile
(`ecosystem: 'nodejs'`) sorgular; bütçe `computeVulnerabilityBudgetMs` ile
aynıdır. `normalizeResolved` → `upsertVulnerability` → `web_findings`.

### 8. OWASP ZAP bağlayıcısı (D-225…D-229)

`src/webscan/zap.ts`, ZAP'ın JSON API'sini (`/JSON/<bileşen>/<view|action>/<ad>/`)
`safeHttpClient`'ın bir örneğiyle çağırır: tek origin (`ZAP_API_URL`),
`https` veya loopback `http`, `X-ZAP-API-Key` amaç başlığı (yalnız bu origin'e),
yönlendirme yok, yanıt sınırı 8 MiB, zaman aşımı 30 sn. Akış:

1. `core/view/version` (erişilebilirlik),
2. `core/action/newSession` (D-226),
3. `core/action/accessUrl` (hedef),
4. `spider/action/scan` (`subtreeOnly=true`) → `spider/view/status` yoklaması
   → süre aşımında `spider/action/stop`,
5. `pscan/view/recordsToScan` 0 olana kadar,
6. (`active`) `ascan/action/scan` (`recurse=true`) → `ascan/view/status` →
   süre aşımında `ascan/action/stop`,
7. `alert/view/alerts` (`baseurl` = hedef origin, sayfalı, en fazla 5000).

Süreç içi bir kilit (`ZapMutex`) aynı anda tek web taramasının ZAP'ı
kullanmasını sağlar. ZAP hataları web taramasını başarısız yapmaz; motor
durumu `web_summary.engines.zap` ve `[zap]` uyarı satırıdır.

### 9. Sonuçların sunumu ve çıktılar (D-223, D-231)

- `GET /api/scans/{id}/web-findings` tek uç noktadır; not ve skor okuma anında
  bulgulardan hesaplanır ve `web_summary`'de de saklanır (liste ekranı için).
- `ReportService.renderExport` iki yeni tür alır: `web-report.pdf`,
  `web-findings.csv`. Üç bağımlılık çıktısı ve NOTICE/SBOM web taraması için
  `404` döner (taramanın türü yüklenirken denetlenir).
- Arayüz mevcut bileşenlerle genişletilir; yeni ekran eklenmez.

### 10. Yol sahipliği

| Agent | Yollar |
| --- | --- |
| backend-engineer | `src/webscan/**`, `src/scanner/worker.ts`, `src/runtime.ts`, `src/app.ts`, `src/controllers/*`, `src/routes/*`, `src/reports/*`, `src/notice/*`, `src/sbom/*`, `db/**`, `README.md`, `.env.example` |
| frontend-engineer | `public/app.js`, `public/index.html` |
| qa-automation | `tests/**` |

## Gerekçe

- Kuyruk ve hata semantiğini yeniden yazmamak, ADR-004'ün sınanmış
  garantilerini (çit, kurtarma) web işine de verir.
- Ayrı tablo, bağımlılık tarafındaki onlarca sorguya ve raporlara dokunmadan
  yeni bir bulgu biçimi taşımanın en küçük riskli yoludur.
- Ayrı prob istemcisi, `safeHttpClient`'ın "sabit origin" garantisini
  gevşetmeden hedefi değişken bir tarayıcı sağlar.
- Yerleşik pasif motor her kurulumda çalışır; ZAP derinlik isteyenler için
  isteğe bağlı bir ek katmandır (Docker'sız kurulum mümkün).

## Değerlendirilen alternatifler

| Alternatif | Neden seçilmedi |
| --- | --- |
| `findings.scan_dependency_id`'yi NULL yapıp web bulgularını oraya yazmak | Tüm `JOIN scan_dependencies` sorguları, iş akışı, raporlar ve parmak izi taşıma mantığı değişirdi |
| Ayrı `web_scans` tablosu ve ayrı işçi | Kuyruk, süre sınırı, kurtarma, çit ikinci kez yazılırdı; tarama geçmişi iki tabloya bölünürdü |
| Yalnız ZAP | Kurulum (Java + ZAP) zorunlu olurdu; pasif temel kontroller için ağır |
| Nuclei / testssl.sh gibi harici ikili dosyalar | Ek ikili ve platform bağımlılığı; Windows'ta kurulum yükü |
| `cheerio`/`jsdom` ile HTML ayrıştırma | Yeni çalışma zamanı bağımlılığı; öznitelik düzeyindeki kurallar için gereksiz |

## Sonuçlar / Uygulama etkisi

- Göç `009_web_scan` (yalnız ekleme; mevcut satırlar `dependency`).
- `scans` yanıtlarına `scan_kind`, `target_url`, `web_summary` eklenir
  (açık sütun listesi güncellenir).
- `projects` yanıtlarına `web_url`, `web_scan_mode` eklenir; `PATCH` eklenir.
- Yeni ortam değişkenleri: `WEB_SCAN_ALLOWED_HOSTS`, `WEB_SCAN_TIMEOUT_MS`,
  `ZAP_API_URL`, `ZAP_API_KEY`.

## Güvenlik etkisi

- **SSRF:** Sunucu artık kullanıcının verdiği adreslere istek atar. Azaltma:
  varsayılan kapalı izin listesi, her istekte host denetimi, yönlendirme
  izlenmez, yalnız `GET`, istek bütçesi. API yalnız yerel ve kimlik
  doğrulamalı kullanıcıya açıktır (ADR-001).
- **Hedefe zarar:** Yerleşik motor yalnız zararsız `GET` atar; aktif saldırı
  simülasyonu yalnız ZAP + açık proje ayarıyla.
- **Gizli veri:** Yoklanan hassas dosyaların içeriği saklanmaz; kanıt
  alanında yalnız eşleşen anahtar adları bulunur. Çerez değerleri yazılmaz.
- **Anahtar:** `ZAP_API_KEY` yalnız ZAP origin'ine giden başlıkta bulunur.
- **TLS istisnası:** Yalnız Karar 5'teki el sıkışma yoklaması.

## Test stratejisi

- Birim: izin listesi, URL kuralları, her kural (pozitif/negatif), HTML
  öznitelik ayrıştırıcı, kütüphane imzaları, not hesabı, ZAP alarm eşlemesi,
  kanıt maskeleme.
- Entegrasyon: loopback HTTP sunucusuna karşı uçtan uca web taraması
  (işçi → veritabanı → `web-findings` → PDF/CSV), izin listesi dışı hedefin
  reddi, sahte ZAP sunucusu, göç up/down/up ve `schema.sql` eşitliği.

## Ek: Güvenlik incelemesi sonrası (2026-10-15)

Bağımsız inceleme (`docs/quality/security-reports/REQ-008-security-review.md`)
sonrası kararlar:

- **H-1:** HTML etiket ve yorum taraması regex yerine doğrusal `indexOf`
  tarayıcısıdır (`html.ts`), etiket başına öznitelik metni 8 KiB ile sınırlıdır;
  Java yığın izi deseni `m` bayrağı ve sınırlı girintiyle yazılır.
- **M-2/M-3:** ZAP her taramada hedef hostla sınırlı bir bağlam (context)
  açar; spider ve aktif tarama yalnız kapsam içinde çalışır; tohum isteği
  yönlendirme izlemez; spider form göndermez.
- **M-4:** ZAP kilidi beklemesi iş sinyaliyle kesilebilir.
- **L-5:** Ana sayfa yönlendirmesi aynı origin veya varsayılan portlarda
  http ↔ https ile sınırlıdır.
- **L-6:** Doğrudan bağlantılar korumalı `lookup` ile çözülür; loopback,
  link-local ve belirsiz adresler açıkça izinli değilse reddedilir.
- **L-7:** `rejectUnauthorized: true` prob istemcisinde açıkça verilir.
- **L-8:** Tamamlanan web taramasının `error_message`'ı yalnız o denemenin
  uyarı satırlarıdır.
- **I-9:** Hedef adresin sorgu dizesi PDF'te ve arayüzde gösterilmez.
- **Ek bulgu (kapsam dışı, düzeltildi):** Node 22.22 `proxyEnv` tünelinde
  vekil `CONNECT`'i reddedince ham soket dinleyicisiz kalıp
  `uncaughtException` ile uygulamayı kapatıyordu; `guardProxyTunnelErrors`
  `safeHttpClient` ve prob istemcisinin vekil ajanlarına uygulanır.
- **Ek bulgu:** Günlük yeniden kontrol, durum paneli ve yeniden kontrol çiti
  yalnız `scan_kind = 'dependency'` taramalarını "son tarama" sayar.

## Onay (Approval)

Kullanıcı talimatı, 2026-10-15 (REQ-008 "Amaç").
