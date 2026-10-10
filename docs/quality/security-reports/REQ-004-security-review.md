# REQ-004 — Güvenlik İncelemesi (F3: kayıt defteri lisans zenginleştirmesi, arşiv okuma, NOTICE, SBOM/rapor çıktıları)

- İnceleyen: Security Red Team (adversarial review, read-only)
- Tarih: 2026-10-10
- Branch: `req-004-f3-lisans-notice` (HEAD: `f680a89`)
- İnceleme aralığı: `git diff origin/main...HEAD` (`839e5bc` sonrası; 77 dosya, +12 093 / −282)
- Kaynaklar: `docs/product/REQ-004.md` (r2), `docs/architecture/adr/ADR-006-kayit-defteri-zenginlestirme-ve-notice.md`, `docs/contracts/REQ-004-notice-and-outputs.md`, `docs/quality/security-reports/REQ-003-security-review.md`.
- Tehdit bağlamı: Kişisel, tek kullanıcılı Windows aracı. Sunucu yalnız `127.0.0.1`'de dinliyor (ADR-001); Express + TS + PostgreSQL, tek süreç. F3 ile araç ilk kez **dışarıdan güvenilmeyen içerik çekiyor**: npm/PyPI meta verisi ve paket arşivleri (tgz, wheel, sdist zip/tgz). Bu içerik DB'ye, NOTICE.txt'ye, SPDX JSON/tag-value'ya, CycloneDX JSON/XML'e, Excel ve PDF'e akıyor.
- Saldırgan modelleri:
  - **(A1)** Kötü niyetli paket yayıncısı. npm `package.json` alanlarını (`license`, `licenses`), PyPI `info.license`/`license_expression`/sınıflandırıcıları ve arşiv içeriğini kontrol eder.
  - **(A2)** Taranan reponun sahibi. Lock dosyasındaki ad, sürüm ve lisans ipucunu kontrol eder.
  - **(A3)** Ağ konumundaki saldırgan. TLS sayesinde yalnız erişilebilirliği etkileyebilir.
  - **(A4)** Kayıt defterinin kendisi. Güven çapası; ele geçirilmesi kapsam dışı.

> **Yöntem kısıtı:** Bash, rol sınırı hook'u nedeniyle yalnız tek ve değiştirmeyen komutlara izin verdi. `git diff --stat`, `git diff -- package.json`, SBOM/rapor/worker/runtime/normalizer/config diff'leri çalıştı. `pwd`/`git rev-parse` ve `git -C …` engellendi. Testler ve dinamik ölçümler (`npx vitest run`, `node -e`) bu oturumda çalıştırılmadı; dinamik doğrulama gerektiren bulgular "doğrulanmadı" olarak işaretlendi. `npm audit --omit=dev` ve `npm audit` rapor yazıldıktan sonra çalıştırıldı.

## Özet

| Ciddiyet | Sayı |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 5 |
| Info | 8 |

**Merge kararı önerisi: Conditional Go.** Critical veya High bulgu yok. SSRF, TLS, bütünlük sırası, arşiv okuyucu sınırları ve iş parçacığı yalıtımı sağlam tasarlanmış.

- **M-1** (NOTICE üretimi, tüm arşiv kayıtlarını toplam sınır olmadan ana iş parçacığı belleğine yüklüyor): Kötü niyetli paketlere referans veren bir repo, NOTICE indirildiğinde tek süreci OOM ile düşürebilir. Merge öncesi kapatılması önerilir. Kapatılmayacaksa insan risk kabulü handoff'a yazılmalı.
- **L-1** (SPDX tag-value tek satırlık alanların `<text>` ile başlayabilmesi): QA'nın işaretlediği risk doğrulandı. Contract revizyonu ve küçük bir kod düzeltmesi gerekiyor; merge öncesi önerilir.

## Doğrulanan kontroller (olumlu bulgular)

**SSRF / izin listesi (ADR-006 Karar 4, 5)**
- Uç noktalar kodda dondurulmuş (`registryClient.ts:60-64`). Ortam, ayar veya kayıt defteri verisinden okunmuyor. Test enjeksiyonu yalnız kodla yapılabiliyor ve yalnız 3 üretim kökenini ya da `http://127.0.0.1|[::1]:<port>` adresini kabul ediyor (`registryClient.ts:95-109`). `runtime.ts` endpoint geçirmiyor.
- `assertAllowedUrl` her istekte **ve her yönlendirme adımında** çalışıyor (`registryClient.ts:126-141, 537`). WHATWG `new URL` ile ayrıştırıyor, `username`/`password` varsa reddediyor, köken eşitliğini birebir arıyor (varsayılan port `URL.origin` ile normalize; IDN/punycode, büyük harf ve sondaki nokta farkları kökeni değiştirdiği için reddediliyor), http yalnız loopback test kökeninde geçerli. Meta veri en fazla 3 aynı köken yönlendirmesi izliyor; arşiv hiç izlemiyor (`:602`).
- `dist.tarball` ve PyPI `url` önce önek denetiminden (`npmRegistry.ts:71`, `pypiRegistry.ts:101`), sonra yeniden `assertAllowedUrl`'den geçiyor. Aynı köken içinde başka bir paketin tarball'ına işaret etmek (A4 dışında) bütünlük denetimine takılıyor.
- Ad ve sürüm istekten önce doğrulanıyor; npm bileşenleri URL-güvenli karakterlerle sınırlı. Sürümde `/ \ ? # %`, boşluk, kontrol karakteri ve `..` yasak; yol segmentleri `encodeURIComponent` ile kuruluyor (`coordinates.ts:26-61, 73-76`). Lock dosyasından gelen kesin sürüm `EXACT_VERSION_RE` ile denetleniyor; `latest` gibi dist-tag değerleri istek olamıyor.
- Sabit başlıklar: Cookie, `Authorization` veya token yok. User-Agent yalnız `oss-risk-platform/<sürüm>` (`registryClient.ts:244-247, 430`).
- TLS: `rejectUnauthorized`/`checkServerIdentity` geçersiz kılınmıyor (`src/` grep: eşleşme yok). DNS rebinding sabit HTTPS hostlarına giden çağrılarda anlamlı değil; sertifika host adını bağlıyor.
- Vekil: yalnız `HTTPS_PROXY`/`NO_PROXY` okunuyor. Vekil değeri geçersizse veya Node sürümü `proxyEnv` desteklemiyorsa **hiç bağlantı açılmıyor** (fail-closed, `registryClient.ts:383-395, 400`). `NO_PROXY` eşleşmesi etiket sınırına göre yapılıyor (`badexample.com` ≠ `example.com`). Loopback adresleri vekile gitmiyor. Hata yalnız `err.code` ile sınıflanıyor; vekil URL'si ve kimlik bilgisi loglanmıyor (`registryClient.ts:249-252`, `proxy.ts:5-11`).

**Bütünlük (ADR-006 Karar 6)**
- Özet akış sırasında hesaplanıyor. Ayrıştırmadan **önce** `verifyDigest` çalışıyor; uyuşmazlıkta tampon atılıyor ve hiçbir şey önbelleğe yazılmıyor (`archiveStage.ts:121-125`). Karşılaştırma sabit zamanlı (`integrity.ts:73-81`). sha512 64 bayt uzunluk denetiminden geçiyor. sha1 yalnız sha512 yokken kullanılıyor (bkz. I-5).
- Arşivler `Accept-Encoding: identity` ile isteniyor; `Content-Encoding` gelirse reddediliyor. Böylece özet sunulan baytları kapsıyor.

**Arşiv okuyucular (ADR-006 Karar 7)**
- **gzip:** Akış hâlinde açılıyor ve açılmış toplam bayt 512 MiB ile sınırlı; içerik bütün olarak tutulmuyor (`gzip.ts:23-53`).
- **tar:** Başlık checksum'ı zorunlu. Base-256 boyut reddediliyor. Boyut yalnız sekizlik tabanda ve `MAX_SAFE_INTEGER/8` taşma korumasıyla okunuyor. PAX `size` `^\d{1,15}$` biçiminde olmalı ve PAX/GNU gövdesi ≤ 64 KiB. Girdi sayısı (meta başlıklar dahil) ≤ 100 000. Yalnız `0`, `\0` ve `7` türleri dosya sayılıyor; symlink ve hardlink (`1`, `2`) atlanıyor. PAX ayrıştırıcısı doğrusal (`tar.ts`).
- **zip:** Merkezi dizin tabanlı. ZIP64 (EOCD, locator, `0x0001` extra) ve çok diskli arşivler reddediliyor. `cdOffset + cdSize ≤ eocd` denetimi var. Şifreli girdiler ve stored/deflate dışı yöntemler atlanıyor. Yerel başlıkta yöntem ve ad merkezi dizinle eşleşmeli. Inflate çıktısı `min(bildirilen, 1 MiB) + 1` ile sınırlı; boyut ve CRC-32 uyuşmazsa girdi atlanıyor (`zip.ts`).
- **Yol:** `\` → `/` çevriliyor. Mutlak yol, sürücü harfi, `..`, boş bileşen ve NUL içeren adlar hiç eşleşmiyor (`licenseFiles.ts:60-73`). Diske yazma olmadığı için path traversal zaten etkisiz.
- **Seçim:** En fazla 10 dosya alınıyor; dosya başına 1 MiB, paket başına 4 MiB sınırı var. Yalnız seçilen dosyaların gövdesi tamponlanıyor.

**İş parçacığı yalıtımı**
- Her arşiv için yeni bir `Worker` açılıyor. `resourceLimits` 512/64/4 MiB; `env: {}`, `argv`/`execArgv` boş. Süreç genelinde en fazla 2 iş parçacığı. Tampon kopyalanmadan transfer ediliyor (`archiveThread.ts:112-119, 165-166`).
- 60 sn zamanlayıcı veya sinyal geldiğinde `terminate()` çağrılıyor ve bekleniyor. OOM, çökme, mesajsız çıkış ve zaman aşımı `processing_failed` oluyor ve önbelleğe yazılmıyor.
- Ana tarafta yanıt yeniden doğrulanıyor: sonuç kümesi, ayrıntı regex'i, dosya sayısı, yol uzunluğu ≤ 4096 ve metin toplamı ≤ 3×4 MiB (`archiveThread.ts:46-77`). İş parçacığı modülü ağ, dosya sistemi veya `pg` import etmiyor (statik test: `tests/security/f3Static.test.ts`).

**Metin, ReDoS, önbellek**
- Depolanan her metin `sanitizeText`'ten geçiyor: CR normalizasyonu, `stripControl` (ESC/C1, `\p{Cf}`) ve eşleşmeyen vekil → U+FFFD. Çıktıda aynı temizlik yeniden uygulanıyor (`textSanitize.ts`, `outputText.ts:17-20`).
- Telif çıkarıcı regex kullanmıyor, satır başına ilk 4096 karaktere bakıyor (`copyright.ts`). SPDX ifade doğrulayıcı tek geçişli, özyinelemesiz ve derinliği 16 ile sınırlı (`spdxExpression.ts`). Kayıt defteri lisans bildirimi ≤ 1000 kod noktasına kesiliyor (`text.ts:64-68`).
- Önbellek anahtarı `(ekosistem, istek adı, sürüm[, özet])`. Bir paket, başka bir paketin satırını yazamıyor. Yalnız `found` ve `not_found` (404/410) sonuçları yazılıyor; `not_found` 24 saat geçerli. Eşzamanlı upsert `ON CONFLICT` ile güvenli. Eski sürüm kod yeni satırı ezemiyor (`cache.ts:107-138, 224-262`). Tüm sorgular parametreli.
- JSON nesne erişimi: scoped yedek yolda `hasOwnProperty` kullanılıyor (`npmRegistry.ts:110`).

**NOTICE uç noktası ve arayüz**
- `guard('reports:read')`, global kimlik doğrulama middleware'inin arkasında (`noticeRoutes.ts:17`, `app.ts`). UUID doğrulanıyor. Tarama yoksa veya tamamlanmamışsa aynı 404 dönüyor (varlık sızıntısı yok; tek kullanıcı modelinde proje bazlı yetki yok, SBOM ile aynı).
- Başlıklar gövde hazır olduktan sonra yazılıyor. `Content-Disposition` dosya adı DB'deki UUID'den kuruluyor (başlık enjeksiyonu yok). `Cache-Control: no-store`. 500 hatasında ham hata metni dönmüyor (`noticeController.ts`).
- Arayüz yalnız `el('a', { href: apiPath(...) })` ile bağlantı ekliyor. Lisans metni arayüzde render edilmiyor; XSS yüzeyi yok (`public/app.js` `scanActions`).
- NOTICE ayraç kalkanı: güvenilmeyen satır `ENTRY_SEP` veya `FILE_SEP` ile başlıyorsa başına bir boşluk ekleniyor (`outputText.ts:37-50`). Tek satırlık alanlar (ad, sürüm, purl, yol, telif) `singleLine` ile `\n` ve `\t` → boşluk dönüşümünden geçiyor (B-1 düzeltmesi `f680a89`).
- CycloneDX XML: Tüm öğe metinleri ve öznitelikler `xmlText` ile işleniyor: XML 1.0 geçersiz karakterleri ve eşleşmeyen vekiller siliniyor, sonra 5 karakter kaçışlanıyor (`outputText.ts:74-107`). JSON yalnız `JSON.stringify` ile üretiliyor.

**Tedarik zinciri**
- `package.json` diff'i yalnız `engines.node` (`^22.21.0 || >=24.5.0`) değişikliği. Yeni runtime veya dev bağımlılığı yok. tar/zip okuyucuları kendi kodumuz (D-76). `npm audit --omit=dev` ve `npm audit` → `found 0 vulnerabilities` (bu oturumda çalıştırıldı).

## Bulgular

### M-1 — NOTICE üretimi tüm `license_files` JSONB değerlerini toplam sınır olmadan ana iş parçacığına yüklüyor: OOM ile tek süreç DoS

- **Severity:** Medium (doğrulanmadı; statik analiz)
- **Evidence:**
  - `src/notice/noticeService.ts:288-301`: F3 taramasında, taramanın tüm `notice_archive_id` değerleri için `SELECT … license_files, copyright_lines FROM registry_archive_cache WHERE id = ANY($1)` tek sorguda çalışıyor. Sonuç `toArchive` ile tamamen belleğe alınıyor. F3 öncesi yol da aynı (`:303-319`).
  - `:333-348`: PyPI meta veri metinleri (her biri ≤ 1 MiB) de topluca yükleniyor.
  - 64 MiB sınırı (`NoticeWriter.textBlock`, `:198-209`) yalnız **çıktıya** uygulanıyor. Kesim başladıktan sonra okunan metinler yazılmıyor ama bellekte duruyor. Ardından `parts.join('')` ve `Buffer.from` ek kopyalar üretiyor.
  - Paket başına sınır 4 MiB ham metin (ana taraf doğrulaması 12 MiB'a kadar izin veriyor, `archiveThread.ts:69`). Toplam sınır yok.
- **Attack path:**
  1. A1, npm'de tek bir paketin yüzlerce sürümünü yayımlar. Her sürümde 10 adet ~400 KiB `LICENSE*` dosyası vardır (sıkıştırılınca tarball küçük kalır).
  2. A2 bu sürümlerin hepsine (veya farklı adlı kopyalarına) referans veren bir `package-lock.json` hazırlar; kullanıcı repoyu tarar. Arşivler ayrı ayrı toplanır ve önbelleğe yazılır (tarama başına 2 GiB indirme kotası küçük tarball'lar için engel değil).
  3. Kullanıcı NOTICE'ı indirir. 300 sürüm × 4 MiB ≈ 1,2 GB UTF-8 metin; JS string olarak ~2,4 GB ve JSONB ayrıştırma ek yükü oluşur. Tek süreçli sunucu V8 heap sınırında `FATAL ERROR: … heap out of memory` ile çöker. Devam eden taramalar ve rapor işleri düşer.
- **Impacted area:** P-15 NOTICE, sunucu kullanılabilirliği (tek süreç, ADR-004)
- **Remediation requirement:**
  - Arşiv kayıtlarını sırayla ve parça parça okuyun (ör. 50'şer id; ya da önce `octet_length(license_files::text)` ile boyut sorgusu). NOTICE bütçesi dolduğunda kalan kayıtların metnini **hiç okumayın**; yapı satırları için yalnız `outcome` ve dosya yollarını çeken hafif bir sorgu yeterli. Golden çıktı değişmez (kesimden sonra metin zaten yazılmıyor).
  - Ek savunma: `writeArchiveCache` öncesinde paket metnini 4 MiB × kod çözme büyümesi yerine gerçek 4 MiB UTF-8 sınırına indirin. Aynı yöntemi SBOM `copyright_lines` için gerekmiyor (≤ 50 × 300).
  - Regresyon testi: 200 × 4 MiB önbellek satırıyla NOTICE üretiminde tepe heap kullanımı < ~300 MB.
- **Merge decision:** Merge öncesi kapatılması önerilir (backend-engineer). Kapatılmayacaksa insan risk kabulü handoff'a yazılmalı ("NOTICE'ı yalnız güvenilir repolarda indir").

### L-1 — SPDX tag-value: tek satırlık alan değeri `<text>` ile başlayabiliyor; aşağı akış ayrıştırıcıları sonraki paket girdilerini yutar

- **Severity:** Low
- **Evidence:** `src/lib/outputText.ts:54-57`: `tagValueSingleLine` yalnız `singleLine` uyguluyor; `<text>`/`</text>` kaçışı yalnız blok içinde yapılıyor (`:64-67`; contract §6.1 de böyle tanımlıyor). `src/sbom/formats/spdx.ts` `generateSpdxTagValue`: `PackageName: ${sl(dep.name)}`, `PackageVersion: ${sl(dep.version)}`, `PackageSupplier`, `PackageHomePage`, `DocumentName`, `Creator`.
- **Attack path:** A2, `package-lock.json`'da `"node_modules/<text>gizli": {...}` gibi bir girdi koyar. npm ad doğrulaması yalnız zenginleştirme isteği için yapılıyor; `packages.name`'e ad olduğu gibi yazılıyor. Çıktıda `PackageName: <text>gizli` satırı oluşur. SPDX tag-value ayrıştırıcıları (spdx-tools Python lexer'ı `:\s*<text>` ile metin moduna geçer; tools-java da değer `<text>` ile başlıyorsa çok satırlı moda girer) bir sonraki `</text>`'e kadar her şeyi tek değer sayar. Bu sonlandırıcı, üreticinin sonraki pakette yazdığı `PackageCopyrightText`/`PackageLicenseComments` bloğudur. Böylece aradaki paketler, örneğin GPL lisanslı veya zafiyetli bir bağımlılık, SBOM tüketicisinin gözünden saklanır ya da belge geçersiz olur. Uygulama içindeki politika ve rapor analizi etkilenmez.
- **Impacted area:** AC-P16-4, SBOM bütünlüğü (aşağı akış uyum araçları)
- **Remediation requirement:** Tek satırlık tag-value alanlarında da `<text>`/`</text>` (büyük/küçük harfe duyarsız) dizilerini `&lt;text&gt;` biçimine çevirin. Bunun yerine en azından değer başındaki `<text>`'i kaçışlayın. Contract §6.1 tek satır kuralına bu adım eklenmeli (contract-broker), ardından kod ve test güncellenmeli (backend-engineer, qa-automation). JSON çıktısı etkilenmez.
- **Merge decision:** Merge öncesi düzeltilmesi önerilir. Düzeltme küçük; QA zaten işaretledi.

### L-2 — Excel: kayıt defteri verisi taşıyan mevcut sütunlarda formül kalkanı yok

- **Severity:** Low
- **Evidence:** `src/reports/reportService.ts:656-681` (`Licenses` sayfası): `detectedLicense`/`normalizedLicense` ham değerleri yazıyor. F3 ile bu değerlerin kaynağı kayıt defteri bildirimi oldu (`policyInput: [declared]`, `effectiveLicense.ts:94`; worker'da `detected_license = rawLicense`, `worker.ts:941-944`). `Dependencies` sayfasının `Name`/`Version`/`PURL`/`Manifest` sütunları da kalkansız (`:619-630`). Contract §5.1 kalkanı bilinçli olarak yalnız 2 yeni sütunla sınırlıyor ve `Licenses` sayfasının değişmemesini istiyor.
- **Attack path:** A1, npm'de `"license": "=HYPERLINK(\"https://saldirgan/…\",\"MIT\")"` bildirir (≤ 1000 karakter). ExcelJS düz string yazdığı için `.xlsx` açılırken formül çalışmaz. Kullanıcı sayfayı CSV olarak dışa aktarıp yeniden açarsa (ADR-006'nın da öngördüğü senaryo) formül değerlendirilir.
- **Remediation requirement:** `excelSafeText`'i tüm string hücrelere uygulayın (sütun sırası ve başlıklar değişmez, yalnız `=+-@\t\r` önekli değerlere `'` eklenir). Contract §5.1 maddesi "yalnız yeni iki sütun" ifadesinden "tüm güvenilmeyen metin hücreleri" ifadesine revize edilmeli (contract-broker).
- **Merge decision:** Merge'ü engellemez; F3 içinde veya hemen sonra düzeltilmesi önerilir.

### L-3 — Lisans normalleştiricisi düz nesnede miras anahtarları buluyor: `constructor`, `toString`, `__proto__` gibi "lisanslar" ihlal üretmiyor

- **Severity:** Low (F3 öncesinden var; F3 kayıt defteri kaynaklı yeni bir erişim yolu ekliyor; doğrulanmadı)
- **Evidence:** `src/analysis/licenseNormalizer.ts:377` `SPDX_RISK_MAP[cleaned] !== undefined` ve `:383` `ALIAS_MAP[aliasKey]`; ikisi de düz nesne literal (`:54`, `:131`). `normalizeLicense('constructor')` → `spdxId: 'constructor'`, `riskLevel: [Function Object]`. `src/scanner/worker.ts:897, 923-927`: `licenses` tablosunda kayıt ve politika olmadığından `riskLevel` `'high'`, `'critical'` veya `'unknown'` olmuyor, yani `isViolation = false`. Bilinmeyen bir lisans normalde `unknown` ihlali açardı. `isRecognizedLicense` (`:461-465`) de bu değerleri "tanınan" sayıyor.
- **Attack path:** A1 (`"license": "constructor"`) veya hint yolunda A2 (lock `license` alanı) runtime bir paketi lisans ihlali/inceleme kapısından geçirir; raporda lisans `constructor` olarak görünür. Not: Kayıt defteri güven çapası olduğu için yalan söyleyen yayıncı zaten `MIT` bildirebilir; bu yüzden ek yetki sınırlı. Ancak bu davranış, "tanınmayan = unknown = ihlal" değişmezini sessizce bozuyor.
- **Remediation requirement:** Tüm tablo aramalarında `Object.hasOwn` kullanın veya tabloları `Map`/`Object.create(null)` ile kurun. Bu, `SPDX_RISK_MAP`, `ALIAS_MAP`, `evaluateLicenseRisk` (`:469`) ve `TROVE_CLASSIFIER_MAP` (`classifiers.ts:76`) için geçerli. Test: `constructor`, `__proto__`, `toString`, `hasOwnProperty` → `spdxId: null`, `riskLevel: 'unknown'`.
- **Merge decision:** Merge'ü engellemez; düzeltme tek satırlık (backend-engineer).

### L-4 — İndirme sırasında ana iş parçacığı belleği için süreç genelinde bir bayt sınırı yok

- **Severity:** Low (doğrulanmadı)
- **Evidence:** `registryClient.ts:445-455`: Yanıt parçaları bir dizide birikiyor (≤ 64 MiB), ardından `Buffer.concat` geçici bir kopya daha üretiyor (`:449`). Doğrulanmış tampon iş parçacığı slotu (2) boşalana kadar tutuluyor (`archiveThread.ts:134`). Semafor yalnız aktif istek sayısını sınırlıyor. Her taramanın arşiv havuzu `config.concurrency` işçi çalıştırıyor (`index.ts:348`). En kötü durum yaklaşık `WORKER_MAX_CONCURRENT × REGISTRY_CONCURRENCY × 64 MiB` tutulan tampon artı aktif indirmelerin kopyalarıdır. Varsayılanlarla (4 × 4) ≈ 1–2 GiB harici bellek; `REGISTRY_CONCURRENCY=32` ile ≈ 8–16 GiB. Tarama başına 2 GiB kota bunu sınırlamıyor (kota tarama başına ve kümülatif).
- **Attack path:** A2, A1'in yayımladığı ~60 MiB'lık çok sayıda arşive referans verir; birden fazla tarama eşzamanlı çalışır ve sistem belleği tükenir.
- **Remediation requirement:** Süreç genelinde "uçuştaki arşiv baytı" semaforu ekleyin (ör. 256 MiB; `candidate.size` veya `Content-Length` ile rezervasyon). Ayrıca `Buffer.concat` yerine bildirilen uzunlukta önceden ayrılmış bir tampon kullanın.
- **Merge decision:** Merge'ü engellemez; F3 sonrası iyileştirme olarak kaydedilebilir.

### L-5 — Lock `integrity` değeri kayıt defteri `dist.integrity` ile karşılaştırılmıyor: NOTICE/lisans, kurulan değil kayıt defterindeki tarball'a atfediliyor (L-6 kalıntısı)

- **Severity:** Low (tasarım kalıntısı; D-55 ad çakışması riski kabul edilmiş)
- **Evidence:** `archiveStage.ts`, `npmRegistry.ts:62-76`: Beklenen özet yalnız kayıt defteri meta verisinden geliyor; ayrıştırıcının lock `integrity`/`resolved` bilgisi kullanılmıyor. REQ-004 Riskler ("Ad çakışması", D-55): `resolved`'a göre atlama, saldırgan kontrollü bir girdi olduğu için reddedilmiş.
- **Attack path:** A2'nin lock girdisi `name@1.0.0` + `resolved: https://baska-kayit/…` (veya bağımlılık karışıklığı: iç paketin public ikizi). Kurulan kod farklı, ama lisans ve NOTICE public `name@1.0.0`'dan geliyor ve kaynak `registry:npm` olarak "doğrulanmış" görünüyor.
- **Remediation requirement:** Uyuşmazlığı **yalnız işaretleyen**, fail-safe bir kontrol: Lock `integrity` değeri varsa ve kayıt defterinin özetleriyle uyuşmuyorsa durumu `registry:*` yerine `lockfile (unverified)` benzeri bir kaynağa düşürün veya Excel'de `integrity differs` notu gösterin. Bu kontrol L-6'yı yeniden açmaz: saldırgan uyuşmazlığı ancak doğrulamayı düşürmek için kullanabilir, yükseltmek için kullanamaz. Gerekirse ADR/contract revizyonu (solution-architect, contract-broker).
- **Merge decision:** Merge'ü engellemez. D-55'in insan risk kabulü handoff'ta açıkça görünmeli.

### I-1 — Önbelleğe yazılmayan hata türleri her taramada yeniden indirme ve 60 sn iş parçacığı maliyeti doğuruyor

- **Evidence:** Ana tarafta yol > 4096 karakter olduğunda tüm sonuç `BAD_RESULT` oluyor (`archiveThread.ts:58`); iş parçacığında yol uzunluğu sınırlanmıyor (PAX `path` ≤ 64 KiB, `tar.ts:224-225`). Zip'te aynı sıkıştırılmış veriye işaret eden ve CRC'si bozuk binlerce örtüşen "LICENSE" girdisi her biri ~1 MiB inflate ediliyor (`zip.ts:168-174`: `corrupt` girdi koleksiyona eklenmediği için aynı yol tekrar denenebiliyor), 100 000 girdiye kadar. Sonuç zaman aşımı ve `processing_failed`; bu sonuç önbelleğe yazılmıyor.
- **Değerlendirme:** Bütçe, 2 iş parçacığı ve 60 sn ile kendiliğinden sınırlı. Kötü niyetli paket yalnız kendi NOTICE'ını bozuyor.
- **Öneri:** İş parçacığında uzun yollu girdiyi atlayın. Zip'te bozuk girdi sayısına üst sınır koyun (ör. 32) veya aynı yolu bir kez deneyin.

### I-2 — Ana taraf doğrulaması telif satırı uzunluğunu sınırlamıyor ve metni yeniden arındırmıyor

- **Evidence:** `archiveThread.ts:52`: yalnız sayı (≤ 50) ve tür kontrol ediliyor. İş parçacığı satırları 300 kod noktasına kesiyor (`copyright.ts:112`); ana tarafta bunun karşılığı yok. Derinlemesine savunma olarak `copyrightLines` uzunluğu ve metinlerin `sanitizeText` ile yeniden işlenmesi önerilir. Çıktılar zaten `outputClean` uyguluyor.

### I-3 — U+2028/U+2029 (ve U+0085 dışı Unicode satır ayırıcıları) tek satır kuralında katlanmıyor

- **Evidence:** `outputText.ts:28-30` yalnız `\n`/`\t`; `stripControl` `\p{Cf}` siliyor ama `Zl`/`Zp` kategorisini silmiyor. `str.splitlines()` kullanan bir tüketici veya bazı metin görüntüleyiciler NOTICE'ta `Copyright: … U+2028 ====…` gibi sahte bir ayraç satırı görebilir. NOTICE biçimini `\n` ile ayrıştıran tüketiciler etkilenmez.
- **Öneri:** Tek satır kuralına `  ` → boşluk ekleyin; ayraç kalkanını bu karakterlerden sonra da uygulayın (contract §9 küçük revizyon).

### I-4 — tar'da yinelenen yolda ilk girdi kazanıyor, tar çıkarma semantiğinde son girdi kazanır

- **Evidence:** `licenseFiles.ts:125-126` (`wants` yinelenen yolu reddediyor). node-tar ve npm çıkarmasında aynı yolun son kopyası diske yazılır. Yayıncı NOTICE'ta, kurulan dosyadan farklı bir metin gösterebilir. Yayıncı iki metni de zaten kontrol ettiği için etkisi düşük; dokümante edin veya son kopyanın kazanmasını sağlayın.

### I-5 — sha1 yedeği (D-83)

- **Evidence:** `integrity.ts:42-46`. Özet ve URL aynı TLS korumalı meta veriden geliyor; sha512'yi silebilen biri URL'yi de değiştirebilir (A4). Pratik bir ikinci ön görüntü saldırısı yok. Kabul edilebilir; yalnız eski paketlerde devreye giriyor.

### I-6 — `TROVE_CLASSIFIER_MAP` miras anahtar araması

- **Evidence:** `classifiers.ts:76`. `License :: constructor` fonksiyon döndürüyor ve terim sessizce düşüyor (`joinLicenseTermsAnd` string olmayanı atlıyor). PyPI sınıflandırıcıları yükleme sırasında doğruladığı için pratikte erişilemez. L-3 düzeltmesiyle birlikte `Object.hasOwn` kullanın.

### I-7 — `found` meta veri satırları hiç süresi dolmadan tutuluyor

- **Evidence:** `cache.ts:107-117`. Kaldırılan, yank edilen veya meta verisi sonradan düzeltilen sürümlerin lisansı, extractor sürümü artana kadar değişmiyor. Tasarım kararı (ADR-006 Karar 10). Temizleme SQL'i `db/README.md`'de belgelenmiş.

### I-8 — Test ağ koruması iş parçacıklarını kapsamıyor

- **Evidence:** `tests/setup/networkGuard.ts:26-29`. Bu durum belgelenmiş ve iş parçacıkları için statik import kontrolüyle telafi ediliyor. `net.Socket.prototype.connect` kancası undici/`fetch`, `tls` ve `pg`'yi kapsıyor; `dns.resolve*` korunmuyor ama bağlantı yine engelleniyor. Yeterli.

## İncelenmedi / sınırlı incelendi

- **`npm audit` / `npm audit --omit=dev`:** Bu oturumda çalıştırıldı; ikisi de `found 0 vulnerabilities`.
- **Testler** (`npx vitest run`): Çalıştırılmadı. Test dosyaları (`tests/unit/archives.test.ts`, `registryClient.test.ts`, `enrichmentPure.test.ts`, `sbomF3.test.ts`, `tests/integration/notice.test.ts`, `f3Outputs.test.ts`, `tests/security/*.test.ts`) ayrıntılı okunmadı; kapsam yalnız dosya adları ve diff istatistiğinden çıkarıldı.
- **Dinamik doğrulama:** M-1 bellek ölçümü, L-1'in gerçek spdx-tools ile denenmesi, L-3 davranışı ve zip örtüşme süresi (I-1) bu oturumda ölçülmedi.
- **Sınırlı okunanlar:** `src/scanner/parsers/threadParser.ts` diff'i (threadBootstrap'a taşıma), `src/lib/errorText.ts` diff'i (`stripControl` taşıması; REQ-003'te incelendi), `db/migrations/006_*.down.sql`, `db/schema.sql`, `README.md`/`.env.example` diff'leri ve OpenAPI dosyası okunmadı. ADR-006 ve REQ-004 tam okunmadı; ilgili kararlar ve riskler grep ve hedefli okumayla karşılaştırıldı.
- **Proxy davranışının Node sürümüne bağlı ayrıntıları:** `https.Agent({ proxyEnv })`'in CONNECT tüneli ve `https:` vekil TLS doğrulaması Node belgelerine göre varsayıldı, çalıştırılarak doğrulanmadı.
- **Managed run sınırı:** `pwd`/`git rev-parse` engellendi. Konum ve branch oturum bağlamındaki git durumuna dayanıyor (`req-004-f3-lisans-notice`). Bu rapor dışında hiçbir dosyaya yazılmadı.

## Merge kararı

**Conditional Go — Critical/High yok.**

Merge öncesi **önerilen** (yapılmazsa insan risk kabulü handoff'a yazılmalı):
1. **M-1:** NOTICE üretiminde arşiv kayıtlarının parça parça okunması ve bütçe dolunca metinlerin hiç okunmaması + bellek regresyon testi. Sahibi: backend-engineer.
2. **L-1:** Tag-value tek satırlık alanlarda `<text>`/`</text>` kaçışı + contract §6.1 revizyonu + test. Sahibi: contract-broker → backend-engineer → qa-automation.

Merge'ü engellemeyen, F3 içinde veya hemen sonra önerilenler: L-2 (tüm string hücrelerde Excel kalkanı + contract §5.1), L-3 (`Object.hasOwn`), L-4 (uçuştaki bayt semaforu), L-5 (lock integrity uyuşmazlığının işaretlenmesi), I-1, I-3.

**İnsan onayı gerektiren riskler:** M-1 kapatılmadan merge edilecekse DoS risk kabulü. D-55 ad çakışması ve bağımlılık karışıklığı kalıntısı (L-5). Özel paket adlarının kamu kayıt defterlerine gitmesi (REQ-004 D-61; varsayılan açık, `REGISTRY_ENRICHMENT=off` ile kapatılabilir). Dış hizmet entegrasyonu onayı (autonomy-gates) handoff'ta kayıtlı olmalı.

Fix'ler ilgili implementer'lar tarafından yapılmalı. Security Red Team, M-1 ve L-1 düzeltmelerini merge öncesi yeniden incelemeli.

## Handoff notu

Bu inceleme non-trivial'dır. `docs/handoffs/REQ-004.md` bu rapora atıfla güncellenmeli; merge kararı, önerilen düzeltmeler ve risk kabulleri (M-1, L-5/D-55, D-61) yazılmalı. Test sonuçları kanıt olarak eklenmeli (bu oturumda çalıştırılmadı). Security Red Team handoff'u kendisi güncellemez; Delivery Lead / Integration-Release'e bildirilmiştir.
