# REQ-004 NOTICE ve Çıktı Contract'ı (F3 — P-14, P-15, P-16, L-6)

- **Status:** Accepted — Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10;
  1.4.0 revizyonu Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-11;
  1.5.0 revizyonu Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-11
- **status:** approved
- **Sürüm:** 1.5.0 (revizyon: bkz. bölüm 13)
- **Tarih:** 2026-10-10 (1.4.0 ve 1.5.0: 2026-10-11)
- **Revizyon dayanağı (1.5.0):** `docs/product/REQ-007.md` r1 (AC-P24-3, AC-P24-4, AC-P24-8,
  AC-P24-10, AC-P24-11, AC-P24-12; D-186, D-187, D-188),
  `docs/architecture/adr/ADR-009-cli-ci-ve-tek-tik-ciktilar.md` (Karar 9, 10; N-7); ilgili F6
  contract'ı `docs/contracts/REQ-007-cli-and-exports.md` 1.0.0. OpenAPI dosyası **değişmez**
  (`info.version` 1.1.0; uç nokta yüzeyi, başlıklar, hata gövdesi aynı).
- **Makine okunur contract:** `docs/contracts/REQ-004-notice-api.openapi.yaml` (OpenAPI 3.0.3;
  `info.version` 1.1.0 — 1.4.0 ile yalnız bilgi amaçlı `LicenseSource` şemasına `registry:nuget`
  **eklendi** (additive) ve bilgi amaçlı `LicenseUnclassified` şeması tanımlandı; uç nokta
  yüzeyi, yanıt başlıkları ve hata gövdesi değişmez)
- **Revizyon dayanağı (1.4.0):** `docs/product/REQ-006.md` (P-21: AC-P21-5…7, AC-P21-9…12,
  AC-P21-14; AC-P20-17, AC-P20-18; D-130, D-133, D-134, D-137, D-139, D-144),
  `docs/architecture/adr/ADR-008-nuget-ayristirici-ve-zenginlestirme.md` (Karar 4, 9, 10,
  11, 12, 14, 15, 16 satır 6; "REQ-006 netleştirmeleri" 3, 12, 13). REQ-006 ile ADR-008'in
  ayrıştığı yerde ADR-008 izlenir.
- **Revizyon dayanağı (1.1.0):** `docs/quality/security-reports/REQ-004-security-review.md`
  bulguları L-1, L-2, I-3 ve M-1
- **Revizyon dayanağı (1.2.0):** `docs/product/REQ-005.md` L-5 (AC-L5-1…4, D-103),
  `docs/architecture/adr/ADR-007-guvenlik-acigi-sorgusu-ve-yeniden-kontrol.md` Karar 12 ve 14
  (`scan_dependencies.lock_integrity`); ilgili F4 contract'ı
  `docs/contracts/REQ-005-vulnerability-data.md`
- **İlgili:** `docs/product/REQ-004.md` (AC-G-4, AC-P14-13, AC-P14-17, AC-P14-18,
  AC-P14-19, AC-L6-2…4, AC-P15-11…15, AC-P16-1…7; kararlar D-62, D-63,
  D-69…D-74), `docs/architecture/adr/ADR-006-kayit-defteri-zenginlestirme-ve-notice.md`
  (Karar 9, 11, 12, 13), `docs/contracts/REQ-002-auth-api.md` (kimlik, hata
  gövdesi, güvenlik başlıkları)

> **Onay kaydı.** Kullanıcının bu yol haritası için verdiği ve REQ-004'te
> kayıtlı daimi talimatı ("gerisi için de bana sorma, tavsiye edilen sistemle
> git") gereği tüm seçimler önerilen seçenekle yapılmıştır. Karar ana oturum
> aracılığıyla iletilmiştir; kullanıcının bu dosyayı gözden geçirip commit
> etmesi kaydı kesinleştirir. Açık soru yoktur.
>
> **Implementation kapıları (bu contract'tan bağımsız, hâlâ geçerli).**
> Backend (`src/`), frontend (`public/app.js`), database (`db/`) ve test
> (`tests/`) çalışması `docs/ownership/REQ-004.json` `status: approved` olmadan
> başlamaz. Contract şu insan onayı kapılarına dokunan unsurlar içerir ve bu
> kapılar contract onayıyla **kapanmış sayılmaz**:
> - **Dış sistem entegrasyonu:** `registry.npmjs.org`, `pypi.org`,
>   `files.pythonhosted.org` (REQ-004 Notlar, `.claude/rules/autonomy-gates.md`).
> - **Veritabanı migration'ı:** göç `006` (ADR-006 Karar 9); yerel veritabanına
>   uygulanması kullanıcı kararıdır.
> - **Kullanıcı verisi / dağıtılan çıktı:** NOTICE ve SBOM üçüncü taraflara
>   gidebilir; hukuki görüş değildir.
>
> Frontend ve backend bu contract'a göre **paralel** çalışabilir (bkz. bölüm 7).
>
> **1.1.0 revizyonu (güvenlik bulguları L-1, L-2, I-3, M-1)** — Onaylandı
> (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10. Değişiklikler
> yalnız backend çıktı kurallarını (bölüm 1, 3.5–3.7, 5.1, 5.1a, 6.1, 9;
> test ve sürüm notları 10–13) etkiler;
> arayüz (bölüm 7) ve API yüzeyi (bölüm 2, OpenAPI) değişmez. Mevcut kod
> 1.1.0'a uyana kadar bu bölümlerde contract'tan sapmaktadır; backend-engineer
> ve qa-automation düzeltmeyi bu sürüme göre yapar (bölüm 13).
>
> **1.2.0 revizyonu (REQ-005 L-5, lock `integrity` uyuşmazlığı)** — Onaylandı
> (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10. Yeni saklanan kolon
> `scan_dependencies.lock_integrity` (`match` / `mismatch` / `not_comparable` /
> `NULL`; göç `007`) çıktı gösterimini belirler (bölüm 4.4). Değişiklikler yalnız
> `mismatch` satırlarının Excel `License Source` metnini (4.1, 5.1), NOTICE
> `Reason:` seçimini (4.3), `[registry]` satırındaki uyuşmazlık sayısını (8) ve
> SBOM'daki `NOASSERTION` davranışını (6) tanımlar. `license_source` ve
> `notice_status` değer kümeleri **değişmez**; API yüzeyi, arayüz (bölüm 7) ve
> `NOTICE format: 1` değişmez. `match`, `not_comparable` ve `NULL` satırlarında
> tüm çıktılar 1.1.0 ile bayt bayt aynıdır (AC-L5-4; NOTICE golden'ı değişmez).
> Bu revizyon REQ-005 implementation'ıyla birlikte uygulanır; kapıları REQ-005
> contract'ındadır (`docs/ownership/REQ-005.json`, göç `007`).
>
> **1.4.0 revizyonu (REQ-006 F5, NuGet)** — Onaylandı (kullanıcı daimi talimatı,
> önerilen seçenek), 2026-10-11 ("bana soru sorma önerilen seçeneklerle devam et").
> NuGet (`dotnet`) paketleri F3 çıktılarına npm/PyPI ile aynı kurallarla girer.
> Değişiklikler: `license_source` değer kümesine `registry:nuget` (4.1); yeni saklanan
> kolon `scan_dependencies.license_unclassified` (`file` / `url` / `NULL`; göç `008`) ve
> gösterimi (4.5; Excel 4.1/5.1, NOTICE 4.3, SBOM 6); NOTICE ekosistem etiketi `nuget`,
> sıralama ve NuGet tekillik anahtarı (3.3); `.nupkg` lisans dosyaları (3.4, 3.5); NuGet
> `no_candidate` nedeni ve satır 14'ün (C-13) NuGet için kalkması (4.3); `lock_integrity`
> NuGet anlamı (4.4); `[registry]` sayımlarına NuGet anahtarlarının katılması, şablonlar
> değişmeden (8); SBOM purl `pkg:nuget/…` (6); proje formunda `.NET (NuGet)` seçeneği
> (7.1). `NOTICE format: 1` kalır (C-30). NuGet içermeyen taramalarda tüm çıktılar 1.3.0
> ile bayt bayt aynıdır (REQ-006 AC-G-9; mevcut NOTICE ve P-10 golden'ları değişmez).
>
> **1.4.0 insan onayı kapıları (contract onayıyla kapanmış sayılmaz):**
> - **Dış sistem entegrasyonu:** yeni host `api.nuget.org` (`.nuspec` ve `.nupkg`);
>   kesin sürümlü NuGet paket adları dışarı gider. `docs/ownership/REQ-006.json`
>   `status: approved` ve manifestin `api.nuget.org` erişimini açıkça kapsaması gerekir.
> - **Veritabanı migration'ı:** göç `008` (ADR-008 Karar 14); down betiği toplu veri
>   güncellemesi içerir (`registry:nuget` → `none`). Yerel veritabanına uygulanması
>   kullanıcı kararıdır; down yalnız açık insan onayıyla çalışır.
> - **Dağıtılan çıktı:** NuGet `.nupkg` lisans dosyaları NOTICE'e girer; hukuki görüş
>   değildir.
>
> **Paralel çalışma uyarısı (1.4.0):** Bu revizyon `Accepted` olsa da backend
> (`src/`), database (`db/`), frontend (`public/index.html`) ve test (`tests/`)
> çalışması `docs/ownership/REQ-006.json` `status: approved` olmadan **başlatılmamalıdır**.
> Manifest onaylandıktan sonra frontend (bölüm 7.1) ve backend birbirini beklemeden
> çalışabilir; database-engineer göç `008`'i backend'den önce teslim eder (ADR-008
> Karar 17, tek yazar kuralı).
>
> **1.5.0 revizyonu (REQ-007 F6, V-12 ve PDF kesinti notu)** — Onaylandı (kullanıcı daimi
> talimatı, önerilen seçenek), 2026-10-11 ("bana soru sorma önerilen seçeneklerle devam et").
> Değişiklikler: Excel `Summary` sayfasının **sonuna** ve PDF `Summary` listesinin **sonuna**
> `Vulnerability Data Status` satırı (5.3; C-34); PDF'te kesilen üç tablonun her birinin altına
> `Showing first <n> of <N>; see the Excel or CSV export for the full list.` notu (5.4; C-35);
> arayüzde NOTICE bağlantısının `download` özniteliği alması ve `target`/`rel` taşımaması (7;
> C-36). Excel'de yeni sütun yok, mevcut satır/sütun sırası ve metni değişmez; NOTICE, SBOM ve
> `NOTICE format: 1` değişmez; göç yok (`scans.vulnerability_data_status` REQ-005 göç `007` ile
> zaten var). Değişiklikler asenkron raporlarda ve REQ-007 eşzamanlı çıktılarında aynıdır (tek
> oluşturucu).
>
> **Paralel çalışma uyarısı (1.5.0):** backend (`src/reports/**`), frontend (`public/app.js`)
> ve test (`tests/**`) çalışması `docs/ownership/REQ-007.json` `status: approved` olmadan
> **başlatılmamalıdır**. Bu revizyon yeni bir insan onayı kapısı açmaz (dış sistem, göç ve
> kullanıcı verisi etkisi yok).

## İçindekiler

1. Kapsam ve geriye uyumluluk
2. `GET /api/scans/{scanId}/notice`
3. NOTICE.txt biçimi
4. Durum ve kaynak değerleri
5. Excel ve PDF raporları
6. SBOM alan anlamları (SPDX 2.3, CycloneDX 1.5)
7. Arayüz: "NOTICE" bağlantısı
8. `[registry]` uyarı satırı
9. Ortak metin kuralları
10. Test yükümlülükleri
11. Sürümleme
12. Karar kaydı ve REQ/ADR ile netleştirmeler
13. Revizyon geçmişi

## 1. Kapsam ve geriye uyumluluk

Bu contract F3'ün dışarıdan görünen yüzeyini sabitler:

- Yeni tek API uç noktası: `GET /api/scans/{scanId}/notice` (D-70, D-74).
- NOTICE.txt metin biçimi (D-69).
- Etkin lisans durum/kaynak değerleri ve çıktılardaki gösterimleri (AC-P14-17).
- Excel `Dependencies` sayfasının yeni sütunları ve PDF bağımlılık tablosunun
  yeni sütunu (D-63).
- SPDX 2.3 ve CycloneDX 1.5 alan anlamları (D-71, D-72).
- Arayüzdeki "NOTICE" bağlantısı (AC-P15-15).
- Taramanın uyarı metnine eklenen `[registry]` satırının şablonu (AC-P14-13,
  ADR-006 Karar 11).
- (1.2.0) L-5 lock `integrity` uyuşmazlığının (`scan_dependencies.lock_integrity`)
  Excel, NOTICE, SBOM ve `[registry]` gösterimi (REQ-005 AC-L5-2, ADR-007 Karar 12).
  Uyuşmazlık olmayan taramalarda çıktılar 1.1.0 ile bayt bayt aynıdır.
- (1.4.0) NuGet (`dotnet`) paketlerinin tüm F3 çıktılarındaki gösterimi:
  `registry:nuget`, `license_unclassified`, NOTICE etiketi/sıralaması/nedenleri,
  `.nupkg` lisans dosyaları, `lock_integrity` NuGet anlamı, purl ve proje formundaki
  `.NET (NuGet)` seçeneği (REQ-006 AC-P20-17, AC-P20-18, AC-P21-5…14; ADR-008 Karar 11,
  12, 15). NuGet içermeyen taramalarda çıktılar 1.3.0 ile bayt bayt aynıdır.

**Geriye uyumluluk (AC-G-4, D-74):**

- Mevcut uç noktaların JSON yanıt **şemaları değişmez**. Yeni alan, yeni
  zorunlu alan veya kaldırılan alan yoktur. `tests/helpers/contracts.ts`
  kullanan mevcut testler değiştirilmeden geçer.
- Tek değer değişikliği: tamamlanmış taramanın mevcut `error_message`
  alanına en fazla bir `[registry]` satırı eklenebilir (bölüm 8). Alanın tipi
  ve anlamı (uyarı metni, satırlar `\n` ile ayrılmış) aynıdır.
- Daha önce üretilmiş ve saklanmış SBOM dokümanları (`sbom_documents`) ve
  raporlar (`reports`) yeniden üretilmez; yeni kurallar yalnızca F3
  sonrasında **üretilen** dokümanlara uygulanır. `GET
  /api/scans/{scanId}/sbom/download` mevcut bir `cyclonedx_json` dokümanı
  varsa onu döndürmeye devam eder (mevcut davranış).
- SBOM `specVersion` değerleri değişmez: SPDX `2.3`, CycloneDX `1.5`.
- Excel'de mevcut sayfaların ve sütunların adı, sırası ve hücre tipleri
  değişmez; yeni sütunlar `Dependencies` sayfasının **sonuna** eklenir.
  Mevcut metin hücrelerinin içeriği de değişmez; **tek istisna** (1.1.0,
  L-2) formül kalkanıdır: `=`, `+`, `-`, `@`, `\t` veya `\r` ile başlayan
  metin değerlerinin başına `'` eklenir (bölüm 5.1). Bu karakterlerle
  başlamayan değerler bayt bayt aynı kalır.

## 2. `GET /api/scans/{scanId}/notice`

Mevcut SBOM indirme uç noktasıyla aynı katmanlarda: route → controller →
`NoticeService` (ADR-006 Karar 12). Okuma işlemidir; denetim kaydı yazılmaz,
hiçbir tabloya ve diske yazılmaz, ağ isteği yapılmaz.

### 2.1 Kimlik ve yetki

| Kural | Değer |
| --- | --- |
| Kimlik | Oturum çerezi (`ossrisk_session`) **veya** `Authorization: Bearer <API anahtarı>`; diğer `/api/*` uç noktalarıyla aynı global middleware (REQ-002 contract). Oturum zorunlu değildir (yalnız çerez kuralı K11 bu uca uygulanmaz). |
| İzin | `reports:read` → route `guard('reports:read')`. `admin` süper roldür (mevcut `requirePermission`). Bugün tüm rollerde `reports:read` vardır (`src/config/permissions.ts`). |
| Tarama erişim kuralı | SBOM uç noktasıyla **aynı**: proje bazında ek yetki denetimi yoktur; tarama var olmalı **ve** `status = 'completed'` olmalıdır (`SbomService.loadScanData` ile aynı koşul). Yeni yetki kuralı eklenmez. |
| Origin | `GET` olduğu için Origin denetimi uygulanmaz (REQ-002: yalnız değiştiren istekler). Host izin listesi (`403 host_rejected`) global olarak geçerlidir. |

### 2.2 Yol parametresi

- `scanId`: SBOM controller'daki düzenli ifadeyle **birebir** aynı doğrulama:
  `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
  (büyük/küçük harfe duyarsız).
- Uymazsa veritabanına gidilmeden `400`.
- Yanıttaki tüm tarama kimliği gösterimleri (dosya adı ve NOTICE üst bilgisi)
  veritabanından okunan **küçük harfli kanonik** UUID'yi kullanır; istekteki
  yazım (büyük harf) çıktıyı değiştirmez.
- Sorgu parametresi tanımlı değildir; gelen sorgu parametreleri yok sayılır.
  `Accept` başlığı yok sayılır (`406` dönülmez).

### 2.3 Başarılı yanıt — `200`

Gövde bölüm 3'teki NOTICE.txt metnidir.

| Başlık | Değer | Not |
| --- | --- | --- |
| `Content-Type` | `text/plain; charset=utf-8` | Tam bu değer. |
| `Content-Disposition` | `attachment; filename="NOTICE-<scanId>.txt"` | `<scanId>` küçük harfli kanonik UUID. Kaçış gerekmez (doğrulanmış UUID). `filename*` yoktur. Proje adı dosya adına girmez (D-70). |
| `Content-Length` | gövdenin bayt sayısı | |
| `X-Checksum-SHA256` | gövdenin SHA-256 özeti, 64 karakter küçük harf hex | Gövde baytlarının tamamı üzerinden. |
| `Cache-Control` | `no-store` | Kimlik doğrulamalı indirme; tarayıcı/vekil önbelleğine yazılmaz. |
| `X-Content-Type-Options` | `nosniff` | Global (REQ-002 K13); `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` ve CSP de global olarak bulunur. |

- `ETag`/`Last-Modified` contract'ın parçası değildir. Express'in varsayılan
  zayıf `ETag`'i kalabilir; istemciler koşullu isteğe ve `304`'e güvenmez,
  testler `If-None-Match` göndermez.
- `HEAD` isteği Express'in `GET` eşlemesiyle aynı başlıkları gövdesiz döner;
  ayrıca test edilmesi zorunlu değildir.
- Başlıklar (özellikle `Content-Disposition`) yalnız gövde **tamamen
  üretildikten sonra** yazılır. Hata yanıtları `Content-Disposition`
  taşımaz.
- Aynı tarama için iki istek bayt bayt aynı gövdeyi ve aynı
  `X-Checksum-SHA256`'yı döndürür (önbellek tabloları iki istek arasında
  değişmedikçe; AC-P15-14).

### 2.4 Hata yanıtları

Tümü mevcut JSON hata gövdesindedir: `{ "error": <HTTP durum adı>, "message":
<metin>, "code": <kod> }` (`src/lib/httpError.ts` `sendError`,
`Content-Type: application/json; charset=utf-8`). Yeni hata kodu eklenmez.

| Durum | `code` | `message` (sabit) | Ne zaman |
| --- | --- | --- | --- |
| `400` | `invalid_request` | `scanId must be a valid UUID` | `scanId` bölüm 2.2 kuralına uymuyor. |
| `401` | `unauthenticated` | `Authentication required` | Geçerli çerez/anahtar yok. |
| `401` | `setup_required` | `Initial password setup required` | Parola hiç belirlenmemiş (REQ-002). |
| `403` | `forbidden` | `Permission "reports:read" is required` | Rol izni yok. Mevcut RBAC ek alanları (`required`, `userRoles`) korunur. |
| `403` | `host_rejected` | `Host not allowed` | Global Host denetimi. |
| `404` | `not_found` | `Scan not found or not yet completed` | Tarama yok **veya** durumu `completed` değil (`pending`, `queued`, `running`, `failed`, `cancelled`, `timeout`). İki durum aynı yanıtı verir. |
| `500` | `internal_error` | `Internal server error` | Beklenmeyen hata (ör. veritabanı). Ham hata metni dönmez. |

- **Değerlendirme sırası:** Host (`403 host_rejected`) → kimlik (`401`) →
  izin (`403 forbidden`) → `scanId` doğrulaması (`400`) → tarama araması
  (`404`) → üretim (`200`/`500`). `guard` route düzeyinde olduğundan
  kimliksiz istekte geçersiz `scanId` de `401` döner (mevcut SBOM uç
  noktalarıyla aynı).
- **`409` kullanılmaz.** Tamamlanmamış tarama `404` döner (REQ-004
  AC-P15-11, ADR-006 Karar 12; SBOM uç noktasıyla aynı).
- **`413` kullanılmaz.** 64 MiB NOTICE sınırı hata üretmez; sınırı aşacak
  metinler gövdeden çıkarılır ve yanıt yine `200`'dür (bölüm 3.7).

### 2.5 F3 öncesi taramalar

- `completed` olan F3 öncesi tarama (etkin lisans kolonları `NULL`) için de
  `200` döner. Tanım: taramanın en az bir `scan_dependencies` satırı vardır ve
  bu satırlarda `license_source IS NULL`'dır.
- Üst bilgiye yeniden tarama notu eklenir (bölüm 3.2).
- Lisans dosyaları arşiv önbelleğinde `(ekosistem, istek adı, sürüm)` ile,
  güncel çıkarım sürümünde aranır (ADR-006 Karar 12); bulunamazsa girdi
  nedeni `scan predates license enrichment; rescan required` olur.
- Bağımlılığı olmayan tarama F3 öncesi sayılmaz; `Packages: 0` ile yalnız üst
  bilgi döner.

## 3. NOTICE.txt biçimi

### 3.1 Genel kurallar

- **Kodlama:** UTF-8, **BOM yok**.
- **Satır sonu:** yalnız LF (`\n`). Gövdede CR (`\r`) bulunmaz. Her satır,
  dosyanın son satırı dahil, LF ile biter.
- **Dil:** başlıklar ve sabit metinler İngilizce ve bu bölümde yazıldığı gibi
  **harfi harfine** sabittir.
- **Üretim zamanı yazılmaz.** Gövdede istek anına bağlı hiçbir değer yoktur.
- **Ayraçlar** (sabit, 80 karakter):
  - `ENTRY_SEP` = `=` karakterinin 80 tekrarı;
  - `FILE_SEP` = `-` karakterinin 80 tekrarı.
- Güvenilmeyen metin bölüm 9 kurallarından geçer.

### 3.2 Üst bilgi

Sırayla, her biri tek satır:

```
THIRD-PARTY SOFTWARE NOTICES
NOTICE format: 1
Project: <proje adı>
Scan ID: <tarama UUID, küçük harf>
Scan completed at: <completed_at>
Packages: <N>
Packages with license files: <A>
Packages without license files: <B>
Generated automatically; not legal advice. Review before distribution.
```

F3 öncesi taramada (bölüm 2.5) bunu izleyen tek satır:

```
Note: This scan predates license enrichment. License data is incomplete; rescan the project for a complete NOTICE.
```

- `<proje adı>`: `projects.name`, tek satırlık alan kuralıyla (bölüm 9).
- `<completed_at>`: UTC, `Date.prototype.toISOString()` biçimi
  (`2026-10-10T08:15:30.123Z`); `NULL` ise `n/a`.
- `N` = girdi sayısı. `A` = en az bir lisans dosyası **metni** bulunan girdi
  sayısı (bölüm 3.5'teki "metinli girdi"). `B = N − A`. Sayılar 64 MiB
  kesiminden **bağımsızdır** (veri üzerinden hesaplanır).
- Ondalık sayılar binlik ayraçsız yazılır.

### 3.3 Girdi kümesi ve sıralama

- Girdiler taramanın **runtime** `scan_dependencies` satırlarından gelir.
  Runtime = `scope` `dev` değil (`isRuntimeScope`; `direct`, `transitive`,
  `peer`, `optional` ve `NULL`). Bir manifestte `dev`, başka birinde runtime
  olan paket runtime'dır. Yalnız `dev` olan paket yer almaz (AC-P15-12).
- Tekillik anahtarı `(ekosistem, ad, sürüm)`; sürümsüz paketlerde
  `(ekosistem, ad)`. Her anahtar **tam bir kez** listelenir. Aynı anahtarın
  birden çok satırı varsa etkin lisans alanları aynıdır (ADR-006 Karar 9);
  `PURL` olarak UTF-8 bayt sırasına göre en küçük purl alınır.
- **NuGet tekillik anahtarı (1.4.0, C-28):** ekosistem `dotnet` iken anahtar
  `(dotnet, asciiLower(ad), asciiLower(sürüm))`'dür (sürümsüzde `(dotnet,
  asciiLower(ad))`; `asciiLower` yalnız `A–Z`'yi dönüştürür, ADR-008 Karar 4). NuGet
  kimlik ve sürümleri harf duyarsızdır; farklı proje klasörlerinden gelen
  `Newtonsoft.Json` ve `newtonsoft.json` **tek** girdi olur. Girdide gösterilen
  `Package:`/`Version:` değerleri, anahtarın satırları arasında `(ad, sürüm)` UTF-8 bayt
  sırasına göre en küçük olan satırınkidir; `PURL` yukarıdaki kuralla (en küçük purl)
  seçilir. Etkin lisans alanları anahtarın tüm satırlarında aynıdır (zenginleştirme
  anahtarı küçük harflidir). npm/PyPI tekillik anahtarı değişmez.
- **Sıralama anahtarı:** `(ekosistem etiketi, küçük harfli ad, ad, sürüm)`.
  - Ekosistem etiketi: `nodejs` → `npm`, `python` → `pypi`, `dotnet` → `nuget`
    (1.4.0), diğerleri enum değeri olduğu gibi. Etiketlerin bayt sırası
    `npm` < `nuget` < `pypi`'dir; NuGet girdileri npm girdilerinden sonra, PyPI
    girdilerinden önce gelir.
  - Küçük harf: `String.prototype.toLowerCase()` (yerel ayardan bağımsız).
  - Sürüm `NULL` ise karşılaştırmada boş metin sayılır (aynı adın sürümlü
    girdilerinden önce gelir).
  - Her bileşen **UTF-8 bayt dizisi** olarak karşılaştırılır (`Buffer.compare`;
    kod noktası sırasına eşdeğerdir). `localeCompare` **kullanılmaz**.

### 3.4 Girdi yerleşimi

Her girdi bir boş satır ve `ENTRY_SEP` ile başlar. Sabit alanlar şu sırayla
ve her zaman yazılır:

```
<boş satır>
<ENTRY_SEP>
Package: <ad>
Version: <sürüm | (unknown)>
Ecosystem: <ekosistem etiketi>
PURL: <purl | (none)>
License: <etkin lisans ifadesi | NOASSERTION>
License source: <kaynak gösterimi>
Copyright: <telif satırı 1>
Copyright: <telif satırı 2>
License files: <k>
Reason: <neden>                         (yalnız metinsiz girdide)
SPDX license: https://spdx.org/licenses/<kimlik>.html   (yalnız metinsiz girdide, 0..n)
<lisans dosyası blokları>
<meta veri lisans metni bloğu>          (yalnız metinsiz PyPI girdisinde, varsa)
```

- **`License:`** `scan_dependencies.license_expression`; boş/`NULL` ise
  `NOASSERTION`. F3 öncesi taramada `NOASSERTION`.
- **`License source:`** bölüm 4.1 "NOTICE gösterimi" sütunu. F3 öncesi
  taramada `not recorded`.
- **`Copyright:`** arşiv kaydındaki `copyright_lines`, kayıttaki sırayla, her
  biri ayrı satır. Hiç yoksa (veya arşiv kaydı yoksa) tek satır
  `Copyright: (none found)`.
- **`License files: <k>`** `k` = arşiv kaydındaki `license_files` öğe sayısı
  (metinli ve atlanmış öğeler dahil; en fazla 10). Arşiv kaydı yoksa `0`.
- **`Reason:`** yalnız metinsiz girdide, tam bir satır; metin bölüm 4.3
  tablosundan.
- **`SPDX license:`** yalnız metinsiz girdide. Etkin lisans ifadesi AC-P16-3'e
  göre geçerliyse, kanonik ifadedeki her lisans kimliği (istisnalar `WITH
  …` hariç) ilk görülme sırasıyla ve tekrarsız birer satır. İfade geçersiz
  veya boşsa satır yoktur. Gömülü lisans metni kütüphanesi kullanılmaz (D-69).

**NuGet girdileri (1.4.0).** Alanlar ve sıraları aynıdır; yeni alan yoktur:

- `Ecosystem: nuget`; `PURL: pkg:nuget/<id>@<sürüm>` (bölüm 6, purl kuralı).
- `License source:` `registry:nuget` (ifade varsa) veya `none`. `license_unclassified`
  NOTICE'ta `License source:` değerini değiştirmez (yine `none`); metinsiz girdide
  `Reason:` önekiyle görünür (bölüm 4.3, 4.5).
- `Copyright:` ve `License files:` doğrulanmış `.nupkg` arşiv kaydından gelir (F3 telif
  kuralı, ADR-006 Karar 8). `.nuspec` `<copyright>` alanı **yazılmaz** (ADR-008
  Değerlendirilen alternatifler).
- Meta veri lisans metni bloğu NuGet'te hiçbir zaman yazılmaz (NuGet meta verisi
  `license_text` taşımaz; ADR-008 Karar 9).

### 3.5 Lisans dosyası blokları

Arşiv kaydındaki `license_files` öğeleri, kayıttaki sırayla (AC-P15-7:
normalleştirilmiş yolun kod noktası sırası):

Metinli öğe (`{ path, text }`):

```
<FILE_SEP>
File: <path>
<FILE_SEP>
<metin satırları>
```

Atlanmış öğe (`{ path, omitted }`):

```
<FILE_SEP>
File: <path>
[omitted: <atlanma nedeni>]
```

| `omitted` | Atlanma nedeni metni |
| --- | --- |
| `file_too_large` | `license file exceeds 1 MiB limit` |
| `package_text_limit` | `package license text limit (4 MiB) reached` |
| bilinmeyen değer | `not available` |

- **Metinli girdi** = en az bir `{ path, text }` öğesi olan girdi (üst bilgi
  `A` sayısı ve `Reason:` satırının yokluğu buna göre).
- **`.nupkg` lisans dosyaları (1.4.0, ADR-008 Karar 11; REQ-006 AC-P21-10, -11):**
  NuGet arşiv kaydının `license_files` öğeleri iki kaynaktan gelir: (a) arşiv kökündeki
  (yolunda `/` olmayan) ve adı D-67 önek kuralıyla `LICENSE`, `LICENCE`, `COPYING`,
  `NOTICE` veya `COPYRIGHT` ile başlayan dosyalar; (b) `.nuspec` `<license
  type="file">` ile bildirilen ve normalleştirilmiş yolu ASCII harf duyarsız eşleşen dosya
  (adı ne olursa olsun, ör. `docs/EULA.md`). Bir dosya her iki kurala da uyarsa **bir
  kez** listelenir. Öğe sırası, `File:` değeri (arşiv içindeki normalleştirilmiş yol,
  `package/` öneki yoktur) ve 10 dosya / 1 MiB / 4 MiB sınırları F3 ile aynıdır.
  `[Content_Types].xml`, `_rels/`, `package/` altı, `.signature.p7s` ve `<id>.nuspec`
  hiçbir zaman öğe olmaz. Bildirilen yol doğrulamadan geçmediyse (256 karakter,
  `normalizeArchivePath`) yalnız (a) kuralı uygulanır.
- **Metin satırları:** metin bölüm 9 arındırmasından geçer; sondaki `\n`
  karakterleri atılır; kalan metin `\n` ile satırlara bölünür; her satıra
  ayraç kalkanı (bölüm 3.6) uygulanır ve LF ile yazılır. Atıldıktan sonra
  metin boşsa tek satır `(empty)` yazılır. Satır içi boşluk ve sekmeler
  korunur, kesim yapılmaz. Kalkan, satır içindeki U+0085/U+2028/U+2029
  sonrasını da kapsar (bölüm 3.6, 1.1.0).

**Meta veri lisans metni bloğu** (AC-P15-13): yalnız metinsiz girdide,
ekosistem `pypi` iken ve `registry_package_cache.license_text` doluysa:

```
<FILE_SEP>
License text from package metadata
<FILE_SEP>
<metin satırları>
```

### 3.6 Ayraç sahteciliği kalkanı

Güvenilmeyen çok satırlı metinde (lisans dosyası metni, meta veri lisans
metni) arındırmadan **sonra** `ENTRY_SEP` veya `FILE_SEP` ile **başlayan** her
satırın başına tek bir boşluk (U+0020) eklenir. Böylece paket metni sahte bir
girdi veya dosya başlığı üretemez (ADR-006 Karar 12). Tek satırlık alanlar
etiketli olduğu ve satır sonu içeremediği için (bölüm 9) satır başına
çıkamaz.

**Unicode satır ayırıcıları (1.1.0, I-3).** Çıktı satırları yalnız `\n` ile
bölünür; ancak kalkan açısından U+0085 (NEL), U+2028 (LINE SEPARATOR) ve
U+2029 (PARAGRAPH SEPARATOR) de satır sonu sayılır. Kural, `\n` ile bölünmüş
her çıktı satırı için:

1. Kalkan noktaları: satırın başı (konum 0) **ve** satırdaki her U+0085,
   U+2028 veya U+2029 karakterinin hemen sonrası.
2. Bir kalkan noktasından başlayan alt dizi `ENTRY_SEP` veya `FILE_SEP` ile
   başlıyorsa, o noktaya tek bir U+0020 eklenir (ayırıcı karakter korunur,
   boşluk ayırıcıdan **sonra** gelir).
3. Ayırıcı karakterler silinmez, `\n`'e çevrilmez; çok satırlı metnin satır
   yapısı ve diğer baytları değişmez.

Örnek: `abc` U+2028 `====…` (80 `=`) → `abc` U+2028 U+0020 `====…`.

U+0085 bir C1 kontrol karakteridir ve bölüm 9 adım 2'de zaten silinir;
burada savunma derinliği için listelenmiştir (adım 2 değişse bile kalkan
geçerli kalır). Böylece `str.splitlines()` gibi Unicode satır ayırıcılarını
tanıyan tüketiciler de sahte ayraç satırı göremez.

Bir ayrıştırıcı NOTICE'ı şu kuralla güvenle bölebilir: tam olarak
`ENTRY_SEP` olan satır yeni girdi, tam olarak `FILE_SEP` olan satır blok
sınırıdır.

### 3.7 64 MiB boyut sınırı

- Gövde bayt sayılarak kurulur. Bir metin bloğunun (lisans dosyası metni veya
  meta veri metni) satırları yazılmadan önce `yazılmış bayt + bloğun bayt
  sayısı > 67 108 864` ise bu blok ve **sonraki tüm metin blokları** yazılmaz;
  her birinin metin satırları yerine tek satır yazılır:

  ```
  [text omitted: NOTICE size limit]
  ```

- Yapı satırları (üst bilgi, girdi alanları, `File:` satırları, nedenler,
  bağlantılar) her durumda yazılır; girdiler her zaman listelenir. Gövde
  64 MiB'yi yalnız bu yapı satırları kadar aşabilir.
- Kesim kuralı deterministiktir: ilk aşımdan sonra daha küçük bir blok
  yeniden denenmez.
- Kesim üst bilgi sayılarını ve `Reason:` satırını değiştirmez.

**Bellek sınırı (1.1.0, M-1) — üretim yöntemi, çıktı biçimi değişmez.**
64 MiB sınırı yalnız çıktıya değil, **okumaya** da uygulanır:

- Üretici arşiv kayıtlarının lisans dosyası metinlerini
  (`registry_archive_cache.license_files` içindeki `text` değerleri) ve PyPI
  meta veri lisans metinlerini (`registry_package_cache.license_text`) tek
  sorguda topluca belleğe **almaz**; girdi sırasıyla (bölüm 3.3) sınırlı
  partiler hâlinde (ör. 50 kayıt) veya kayıt kayıt okur. Bellekte aynı anda
  tutulan metin, yazılmış gövde + tek partinin metniyle sınırlıdır; girdi
  sayısıyla büyümez.
- Kesim başladıktan sonra (ilk aşım) kalan kayıtların metinleri **hiç
  okunmaz**. Yapı satırları için gereken veriler (sonuç, dosya yolları,
  `omitted` değerleri, öğe sayısı `k`, telif satırları ve öğenin metinli olup
  olmadığı bilgisi) metni döndürmeyen hafif bir sorguyla alınır.
- Üst bilgi sayıları `A`/`B` ve `Reason:` seçimi kesimden bağımsız olarak
  verinin tamamı üzerinden hesaplanmaya devam eder (bölüm 3.2); bunun için
  metin içeriği değil yalnız "en az bir `{ path, text }` öğesi var mı"
  bilgisi gerekir.
- İlk aşımı belirleyen blok, bayt sayısının kesin hesaplanabilmesi için
  okunabilir (paket başına üst sınırla sınırlıdır); ondan sonraki hiçbir
  metin okunmaz.
- Yanıt yine gövde tamamen üretildikten sonra yazılır (bölüm 2.3:
  `Content-Length` ve `X-Checksum-SHA256` gövdeden hesaplanır); "akış"
  burada veritabanından parti parti okuma anlamındadır, HTTP yanıt akışı
  değildir. Gövde birleştirilirken gereksiz tam kopyalardan kaçınılır.
- Çıktı baytları bu yöntemden etkilenmez: toplu okuma ile parti parti okuma
  aynı veri için bayt bayt aynı NOTICE'ı üretir (golden dosyalar M-1
  nedeniyle değişmez).

### 3.8 Örnek

Kısaltılmış örnek (`…` gerçek dosyada yoktur; ayraçlar burada da 80
karakterdir):

```
THIRD-PARTY SOFTWARE NOTICES
NOTICE format: 1
Project: demo-app
Scan ID: 3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f
Scan completed at: 2026-10-10T08:15:30.123Z
Packages: 3
Packages with license files: 1
Packages without license files: 2
Generated automatically; not legal advice. Review before distribution.

================================================================================
Package: ms
Version: 2.1.3
Ecosystem: npm
PURL: pkg:npm/ms@2.1.3
License: MIT
License source: registry:npm
Copyright: Copyright (c) 2020 Vercel, Inc.
License files: 1
--------------------------------------------------------------------------------
File: package/license.md
--------------------------------------------------------------------------------
The MIT License (MIT)

Copyright (c) 2020 Vercel, Inc.
…

================================================================================
Package: requests
Version: (unknown)
Ecosystem: pypi
PURL: pkg:pypi/requests
License: NOASSERTION
License source: none
Copyright: (none found)
License files: 0
Reason: version unknown

================================================================================
Package: six
Version: 1.16.0
Ecosystem: pypi
PURL: pkg:pypi/six@1.16.0
License: MIT
License source: registry:pypi
Copyright: (none found)
License files: 0
Reason: no license file in package archive
SPDX license: https://spdx.org/licenses/MIT.html
```

## 4. Durum ve kaynak değerleri

Saklama yeri `scan_dependencies` (ADR-006 Karar 9). Değerler kolonlardaki
`CHECK` kümeleriyle birebirdir; yeni değer eklemek contract revizyonu ve göç
gerektirir.

### 4.1 `license_source`

| Saklanan değer | Anlamı | Excel `License Source` | NOTICE `License source:` |
| --- | --- | --- | --- |
| `registry:npm` | npm kayıt defteri lisansı | `registry:npm`; uyuşmazlıkta `registry:npm (lockfile differs: <ipucu>)` | `registry:npm` |
| `registry:pypi` | PyPI lisansı | `registry:pypi`; uyuşmazlıkta `registry:pypi (lockfile differs: <ipucu>)` | `registry:pypi` |
| `registry:nuget` (1.4.0) | NuGet `.nuspec` lisansı: `<license type="expression">` veya `licenses.nuget.org` / tablo eşlemeli `licenseUrl` (ADR-008 Karar 9); her zaman dolu bir ifade taşır | `registry:nuget` (NuGet'te lock ipucu yoktur, `(lockfile differs: …)` biçimi oluşmaz) | `registry:nuget` |
| `lockfile (unverified)` | Lock ipucu, doğrulanmadı (AC-L6-3) | `lockfile (unverified)` | `lockfile (unverified)` |
| `none` | Etkin lisans yok | Öncelik sırasıyla ilk uyan: (1) `lock_integrity = 'mismatch'` → `none (lockfile integrity mismatch)` (1.2.0); (2) `license_unclassified = 'file'` → `none (license file in package, not classified)` (1.4.0); (3) `license_unclassified = 'url'` → `none (license URL not classified)` (1.4.0); (4) durum `no_license` ve ipucu varsa `none (lockfile hint ignored: <ipucu>)`; (5) `none` | `none` |
| `NULL` | F3 öncesi tarama | boş hücre | `not recorded` |

- **L-5 (1.2.0):** `lock_integrity = 'mismatch'` satırında `license_source` her zaman
  `none`, `license_expression` `NULL`'dır (ADR-007 Karar 12); Excel hücresi tam olarak
  `none (lockfile integrity mismatch)` olur — ipucu ve kayıt defteri lisansı metne
  **yazılmaz** (doğrulanmamış veri). Bu metin `none (lockfile hint ignored: …)` metnine
  göre önceliklidir. NOTICE `License source:` değeri `none` kalır; uyuşmazlık NOTICE'ta
  `Reason:` satırıyla görünür (bölüm 4.3).
- Uyuşmazlık: `license_hint_differs = true` (yalnız durum `ok` iken dolu).
- `<ipucu>` = `license_lock_hint`; tek satırlık alan kuralı (bölüm 9) ve 200
  kod noktası kesimi (saklanırken zaten kesilmiştir; çıktıda yeniden
  uygulanır).
- NOTICE'ta lisans ipucu uyuşmazlığı (`license_hint_differs`) ve yok sayılan
  ipucu gösterilmez (NOTICE dağıtım belgesidir; L-6 görünürlüğü raporun işidir).
  L-5 bütünlük uyuşmazlığı (`lock_integrity = 'mismatch'`) ise NOTICE'ta yalnız
  `Reason:` satırıyla görünür (bölüm 4.3 satır 15; 1.2.0).
- **1.4.0 (NuGet):** (2) ve (3) metinleri sabittir, URL metni veya dosya yolu **hiçbir
  zaman** hücreye yazılmaz (ADR-008 Karar 9). `license_unclassified` yalnız `none`
  satırlarında dolu olabilir (bölüm 4.5); (1) ile birlikte oluşmaz (yazılma kuralı gereği
  `mismatch` satırında `NULL`), öncelik savunma derinliği içindir. NuGet satırlarında lock
  ipucu yoktur (REQ-006 AC-P21-12), bu yüzden (4) NuGet'te oluşmaz.

### 4.2 `license_enrichment_status`

| Değer | Anlamı | Etkin lisans / kaynak (ADR-006 Karar 11) |
| --- | --- | --- |
| `ok` | Bulundu, lisans var | kayıt defteri / `registry:*` |
| `no_license` | Bulundu, lisans yok | boş / `none` (ipucu kullanılmaz, AC-L6-2) |
| `not_found` | 404/410 | ipucu → `lockfile (unverified)`, yoksa `none` |
| `unreachable` | Ağ hatası / ardışık hata eşiği / vekil hatalı kip | ipucu → `lockfile (unverified)`, yoksa `none` |
| `error` | Yeniden denenmeyen hata, bozuk yanıt, beklenmeyen kod hatası | ipucu → `lockfile (unverified)`, yoksa `none` |
| `disabled` | `REGISTRY_ENRICHMENT=off` veya zenginleştirici yok | ipucu → `lockfile (unverified)`, yoksa `none` |
| `version_unknown` | Sürüm `NULL` | boş / `none` |
| `invalid_coordinates` | Ad/sürüm doğrulamadan geçmedi | boş / `none` |
| `budget_exceeded` | Zaman bütçesi doldu | ipucu → `lockfile (unverified)`, yoksa `none` |
| `NULL` | F3 öncesi | — |

Bu değer bugün hiçbir çıktıda **ham olarak** gösterilmez; NOTICE `Reason:`
metnine (bölüm 4.3) ve `[registry]` sayımına (bölüm 8) dönüşür. Excel'e durum
sütunu eklenmez (D-63).

**`REGISTRY_ENRICHMENT` ayrıştırması (1.3.0; C-24).** F4 açma/kapama anahtarlarıyla
aynı ayrıştırıcı kullanılır (REQ-005 contract 1.1.0 bölüm 7.1): büyük/küçük harf duyarsız,
baştaki ve sondaki boşluk kırpılır. `on|true|1|yes` → açık; `off|false|0|no` → kapalı
(`disabled`); boş veya tanımsız → varsayılan (açık); **başka her değer → kapalı**. Kapalıya
düşüldüğünde tek uyarı yazılır ve uyarı yalnız değişken adını içerir (değer loglanmaz).
**F3'ten davranış farkı:** F3'te (1.0.0–1.2.0, ADR-006 Karar 14) geçersiz değer varsayılana,
yani **açık**a düşüyordu; artık gizlilik gereği kapalıya düşer (fail-closed). `off`, boş ve
tanımsız değerlerin anlamı değişmez. Etkin değer kapalıysa çıktılar mevcut `disabled`
satırının kurallarıyla üretilir; çıktı biçimi değişmez.

### 4.3 `notice_status` ve NOTICE `Reason:` metni

`Reason:` yalnız metinsiz girdide yazılır. Seçim sırası: önce satır 14, sonra
satır 15 (1.2.0), sonra satır 1–2, sonra `notice_status` (satır 3–13); ilk eşleşen
satır kazanır.

| # | Koşul | `Reason:` metni |
| --- | --- | --- |
| 1 | F3 öncesi tarama ve arşiv önbelleğinde kayıt yok | `scan predates license enrichment; rescan required` |
| 2 | `notice_archive_id` `NULL` ama `notice_status` önbelleğe yazılan bir sonuç (`collected`, `no_license_file`, `unsupported_format`, `limit_exceeded`) — önbellek temizlenmiş | `license file data no longer cached; rescan required` |
| 3 | `collected`, ama hiç metinli öğe yok (hepsi atlanmış) | `license files exceed size limits` |
| 4 | `no_license_file` | `no license file in package archive` |
| 5 | `unsupported_format` | `package archive format not supported` |
| 6 | `limit_exceeded` | `archive exceeds size limit` |
| 7 | `no_candidate` — ekosistem `nodejs`/`python` | `no verifiable package archive available` |
| 7a | `no_candidate` — ekosistem `dotnet` (1.4.0; lock/assets bütünlük değeri yok, `.nupkg` indirilmedi) | `package archive not downloaded (no lockfile integrity value)` |
| 8 | `integrity_failed` | `package archive integrity check failed` |
| 9 | `download_failed` | `package archive could not be downloaded` |
| 10 | `processing_failed` | `package archive could not be processed` |
| 11 | `budget_exceeded` | `license enrichment time budget exceeded during scan` |
| 12 | `not_attempted` → zenginleştirme durumuna göre: | |
| | `not_found` | `package not found in registry` |
| | `unreachable` | `registry unreachable during scan` |
| | `error` | `registry lookup failed during scan` |
| | `disabled` | `license enrichment disabled` |
| | `version_unknown` | `version unknown` |
| | `invalid_coordinates` | `invalid package name or version` |
| | `budget_exceeded` | `license enrichment time budget exceeded during scan` |
| | diğer | `package archive not collected` |
| 13 | `not_runtime` | NOTICE'ta yer almaz (runtime değil) |
| 14 | Ekosistem `nodejs`/`python`/`dotnet` dışında (1.4.0: `dotnet` bu satırdan çıkarıldı; C-13 NuGet için kalkar) | `license enrichment not supported for this ecosystem` |
| 15 | `lock_integrity = 'mismatch'` (1.2.0; bu durumda `notice_status = 'not_attempted'`, `notice_archive_id = NULL`; 1.4.0: npm ve NuGet) | `lockfile integrity does not match registry; license not verified` |

**`license_unclassified` öneki (1.4.0, C-26).** Metinsiz bir girdide
`license_unclassified` doluysa, yukarıdaki sırayla seçilen metnin **başına** sabit bir
önek ve `; ` (noktalı virgül + boşluk) eklenir; satır yine **tek** `Reason:` satırıdır:

| `license_unclassified` | Önek |
| --- | --- |
| `file` | `license is a file inside the package (not classified)` |
| `url` | `license URL not classified` |

Örnekler:
`Reason: license is a file inside the package (not classified); package archive not downloaded (no lockfile integrity value)`
(lock'suz proje, `type="file"` paket);
`Reason: license URL not classified; package archive could not be downloaded`.

- Önek yalnız metinsiz girdide görünür. `type="file"` paketin bildirdiği dosya `.nupkg`'den
  toplandıysa girdi metinlidir: lisans metni dosya bloğunda yer alır, `Reason:` satırı
  yoktur, `License: NOASSERTION` ve `License source: none` kalır (ADR-008 Karar 12).
- `license_unclassified` satır 1 ve 15 koşullarında `NULL`'dır (F3/F5 öncesi satırlar ve
  yazılma kuralı), bu yüzden önek o satırlarla birleşmez. Satır 2 ile birleşebilir (ör.
  `type="file"` paketin arşiv önbelleği temizlenmiş):
  `Reason: license is a file inside the package (not classified); license file data no longer cached; rescan required`.
- URL metni ve bildirilen dosya yolu NOTICE'e yazılmaz.

**NuGet notları (1.4.0):**

- NuGet `integrity_failed` **üretmez** (ADR-008 Karar 10.2); satır 8 NuGet'te oluşmaz.
  NuGet bütünlük uyuşmazlığı satır 15 ile görünür.
- NuGet `.nupkg` indirme, boyut, kota ve bütçe hataları F3 değerlerini alır (satır 5, 6,
  9, 10, 11); metinler değişmez.
- NuGet meta veri durumları (`not_found`, `unreachable`, `error`, `disabled`,
  `version_unknown`, `invalid_coordinates`, `budget_exceeded`) satır 12 metinlerini
  kullanır.

- Satır 15 aynı anahtarın tüm runtime satırları için geçerlidir (`lock_integrity`
  anahtar düzeyinde hesaplanır, aynı anahtarın satırları aynı değeri taşır; ADR-007
  Karar 12). Uyuşmazlıklı girdide arşiv kaydı kullanılmadığı için girdi her zaman
  metinsizdir: `License: NOASSERTION`, `License source: none`,
  `Copyright: (none found)`, `License files: 0`, `Reason:` satır 15, `SPDX license:`
  satırı yok (ifade boş). Önbellekte aynı anahtarın arşiv kaydı bulunsa bile
  NOTICE onu **okumaz** (AC-L5-2).
- Arşiv kaydının `outcome_detail` değeri NOTICE'a yazılmaz.
- Önbelleğe yazılan sonuçlar: `collected`, `no_license_file`,
  `unsupported_format`, `limit_exceeded`. Diğerleri geçicidir; tarama satırında
  durur, önbellekte yoktur (ADR-006 Karar 7, 10).

### 4.4 `lock_integrity` (1.2.0, REQ-005 L-5)

Saklama yeri `scan_dependencies.lock_integrity` (göç `007`, `TEXT NULL` + CHECK).
Anahtar `(npm, istek adı, sürüm)`; karşılaştırma kuralı ADR-007 Karar 12.

| Değer | Anlamı | Çıktı etkisi |
| --- | --- | --- |
| `match` | Her karşılaştırılabilir lock `sha512` değeri kayıt defteri `dist.integrity` `sha512` kümesiyle en az bir öğe paylaşıyor | Yok — F3 ile aynı (AC-L5-4) |
| `not_comparable` | Bir tarafta `sha512` yok (lock değeri yok/bozuk/yalnız `sha1`/sınır dışı; meta veri `found` değil veya `sha512` arşiv adayı yok) | Yok — F3 ile aynı |
| `mismatch` | En az bir lock kaydı kayıt defteri kümesiyle hiç öğe paylaşmıyor | Fail-safe (aşağıda) |
| `NULL` | Zenginleştirme kapalı/enjekte edilmemiş, npm dışı ekosistem, F4 öncesi tarama | Yok — F3 ile aynı |

**`mismatch` satırının saklanan değerleri (ADR-007 Karar 12):**
`license_expression = NULL`, `license_source = 'none'`, `license_hint_differs = false`,
`notice_status = 'not_attempted'` (runtime) veya `'not_runtime'` (`dev`),
`notice_archive_id = NULL`. `license_enrichment_status` meta verinin sonucunu korur
(`ok` veya `no_license`); `license_lock_hint` saklı kalır ama hiçbir çıktıya yazılmaz.
Runtime paket için `NOASSERTION` (`unknown`) lisans bulgusu açılır (ADR-003 c
parmak izi anahtarı `NOASSERTION`).

**Çıktı özeti:**

| Çıktı | `mismatch` gösterimi | Bölüm |
| --- | --- | --- |
| Excel `Dependencies.License` | boş metin | 5.1 |
| Excel `Dependencies.License Source` | `none (lockfile integrity mismatch)` | 4.1, 5.1 |
| Excel `Licenses` | `NOASSERTION` bulgusu mevcut satır kuralıyla (yapı değişmez) | 5.1a |
| PDF `License` | `n/a` | 5.2 |
| NOTICE | metinsiz girdi, `Reason: lockfile integrity does not match registry; license not verified` | 4.3 |
| SPDX 2.3 | `licenseDeclared` `NOASSERTION`, `copyrightText` `NOASSERTION`, `licenseComments` yok (L-6 lock satırı da yok, kaynak `none`) | 6.1 |
| CycloneDX 1.5 | `licenses` ve `copyright` yazılmaz | 6.2, 6.3 |
| `[registry]` | uyuşmazlık sayısı `X` | 8 |

`lock_integrity` hiçbir JSON yanıtında dönmez (AC-G-4) ve Excel'e ayrı sütun olarak
eklenmez (D-63).

**NuGet anlamı (1.4.0; ADR-008 Karar 10, netleştirme 12).** Değer kümesi değişmez.
Anahtar `(nuget, asciiLower(id), asciiLower(normal sürüm))`. NuGet kayıt defteri özet
yayımlamadığı için karşılaştırma **indirilen `.nupkg` baytları** ile taramanın
`packages.lock.json` `contentHash` / `project.assets.json` `libraries.*.sha512` değeri
(`sha512-<base64>`) arasında yapılır:

| Değer | NuGet'te ne zaman |
| --- | --- |
| `match` | Anahtarın tek bir ayrık lock/assets değeri `d` var **ve** (a) indirilen baytların ham SHA-512'si `d`'ye eşit **veya** (b) NuGet imzalı paket içerik özeti (`.signature.p7s` girdisi yokmuş gibi hesaplanan, ADR-008 Karar 10.3) `d`'ye eşit; **veya** arşiv önbelleğinde `(nuget, id, sürüm, d)` satırı var (yalnız daha önce `d`'ye karşı doğrulanmış baytlardan yazılır). |
| `not_comparable` | **Zenginleştirme açıkken varsayılan.** Lock/assets değeri yok (lock'suz proje; bu durumda `notice_status = 'no_candidate'`, indirme yok); meta veri `found` değil; koordinat geçersiz / sürüm bilinmiyor; indirme hatası, boyut sınırı, kota veya bütçe aşımı (`.nuspec` lisansı kullanılır, F3 davranışı). |
| `mismatch` | Anahtarın **birden çok farklı** lock/assets değeri var (indirme yapılmaz); **veya** indirilen baytlar ne ham özetle ne içerik özetiyle `d`'ye eşit (içerik özeti hesaplanamadıysa da). Fail-safe yukarıdaki `mismatch` satırıyla **aynıdır**; ek olarak `license_unclassified = NULL`. |
| `NULL` | Zenginleştirme kapalı (`REGISTRY_ENRICHMENT=off` veya fail-closed geçersiz değer) / zenginleştirici enjekte edilmemiş; F5 öncesi tarama. |

- Tablonun ilk satırındaki `npm` anahtarı ve `NULL` satırındaki "npm dışı ekosistem"
  ifadesi 1.4.0 ile şöyle okunur: npm ve NuGet karşılaştırılır; PyPI `NULL` kalır.
- NuGet `integrity_failed` üretmez; `mismatch` satırının çıktı özeti (Excel, NOTICE satır
  15, SBOM, `[registry]` `X`) npm ile aynı metinleri kullanır.
- `match`/`not_comparable` NuGet satırlarında çıktılar bu contract'ın NuGet kurallarıyla
  üretilir (ek uyarı yoktur).

### 4.5 `license_unclassified` (1.4.0, REQ-006 AC-P21-5, AC-P21-6)

Saklama yeri `scan_dependencies.license_unclassified` (göç `008`, `TEXT NULL CHECK
(license_unclassified IN ('file', 'url'))`; ADR-008 Karar 12, 14). Durum değeri
**değildir**: satırın `license_enrichment_status` değeri `no_license`, `license_source`
değeri `none`, `license_expression` değeri `NULL`'dır.

| Değer | Anlamı (`.nuspec`, ADR-008 Karar 9) |
| --- | --- |
| `file` | `<license type="file">`: lisans paketin içindeki bir dosyadadır; SPDX ifadesine sınıflandırılmadı. |
| `url` | `<licenseUrl>` var, ama `licenses.nuget.org` ifadesine veya sabit URL tablosuna eşlenemedi (`aka.ms/deprecateLicenseUrl` yer tutucusu yok sayılır, bu değeri üretmez). |
| `NULL` | Diğer her durum: npm/PyPI satırları, F5 öncesi satırlar, `ok` durumu, ne `license` ne `licenseUrl` olan paket (düz `no_license`), meta veri `found` değil, `lock_integrity = 'mismatch'`. |

**Yazılma kuralı:** yalnız ekosistem `dotnet`, durum `no_license` ve `lock_integrity <>
'mismatch'` iken meta verideki değer yazılır; aksi hâlde `NULL`. Aynı anahtarın tüm
satırları aynı değeri taşır.

**Çıktı özeti:**

| Çıktı | `file` | `url` | Bölüm |
| --- | --- | --- | --- |
| Excel `Dependencies.License` | boş metin | boş metin | 5.1 |
| Excel `Dependencies.License Source` | `none (license file in package, not classified)` | `none (license URL not classified)` | 4.1, 5.1 |
| Excel `Licenses` / bulgu API'si | runtime paket için `NOASSERTION` bulgusu (mevcut satır kuralı, yapı değişmez) | aynı | 5.1a |
| PDF `License` | `n/a` | `n/a` | 5.2 |
| NOTICE `License:` / `License source:` | `NOASSERTION` / `none` | `NOASSERTION` / `none` | 3.4 |
| NOTICE lisans dosyası | bildirilen dosya ve kök `LICENSE*` dosyaları `.nupkg` doğrulandıysa bloklarda | kök `LICENSE*` dosyaları doğrulandıysa bloklarda | 3.5 |
| NOTICE `Reason:` (yalnız metinsiz girdi) | önek `license is a file inside the package (not classified); …` | önek `license URL not classified; …` | 4.3 |
| SPDX 2.3 | `licenseDeclared` `NOASSERTION`; yeni `licenseComments` satırı **yok** | aynı | 6.1 (C-27) |
| CycloneDX 1.5 | `licenses` yazılmaz | aynı | 6.2, 6.3 |
| `[registry]` | ayrı sayılmaz; şablon değişmez | aynı | 8 |

Kolon hiçbir JSON yanıtında dönmez (REQ-006 AC-G-4) ve Excel'e ayrı sütun olarak
eklenmez.

## 5. Excel ve PDF raporları

### 5.1 Excel `Dependencies` sayfası

Mevcut 7 sütun aynen kalır (1.1.0: formül kalkanı öneki hariç, bölüm
5.1a); iki yeni sütun **sona** eklenir:

| # | Başlık (birebir) | `key` | Genişlik | Değer |
| --- | --- | --- | --- | --- |
| 1–7 | `Name`, `Version`, `Ecosystem`, `Scope`, `Manifest`, `Depth`, `PURL` | mevcut | mevcut | mevcut |
| 8 | `License` | `license` | 32 | `license_expression`; boş/`NULL` → boş metin |
| 9 | `License Source` | `licenseSource` | 48 | bölüm 4.1 "Excel" sütunu (1.2.0: `lock_integrity = 'mismatch'` → `none (lockfile integrity mismatch)`; 1.4.0: `registry:nuget`, `none (license file in package, not classified)`, `none (license URL not classified)`); F3 öncesi → boş metin |

- **NuGet satırları (1.4.0):** `Ecosystem` sütunu mevcut kuralla enum değerini yazar
  (`dotnet`); `PURL` `pkg:nuget/…` (bölüm 6). `License` sütununun kuralı ekosistemden
  bağımsızdır: ifade yoksa boş metin (C-29). REQ-006 AC-P21-7'deki "lisans hücresi boş
  kalmaz" ölçütü, NuGet satırında `License` (ifade) **veya** `License Source` (kaynak /
  neden metni, hiçbir zaman boş değil) ile birlikte `Licenses` sayfasındaki ve bulgu
  API'sindeki `NOASSERTION` bulgusuyla karşılanır.

- Satır başına bir `scan_dependencies` satırı (mevcut). Başlık satırı kalın,
  donuk ve otomatik filtreli (mevcut döngü; filtre 9 sütunu kapsar).
- Yeni iki sütunun hücre tipi her zaman **düz metin** (string). ExcelJS
  `{ formula }`, sayı, tarih veya zengin metin kullanılmaz.
- Yeni iki sütunun değerleri bölüm 9 tek satırlık alan kuralından (adım
  1–3) geçer, ardından formül kalkanı uygulanır.
- F3 öncesi taramada iki hücre boştur ve rapor hatasız üretilir (AC-P14-18).

### 5.1a Formül kalkanı — tüm sayfalar (1.1.0, L-2)

**Kural:** Bir metin (string) hücre değeri `=`, `+`, `-`, `@`, `\t`
(U+0009) veya `\r` (U+000D) ile başlıyorsa başına tek bir `'` (U+0027)
eklenir (`excelSafeText`). Diğer değerler değişmeden yazılır; boş metin boş
kalır. Kalkan tek geçişlidir (değer başına bir kez; zaten `'` ile başlayan
değere yeniden eklenmez çünkü `'` tetikleyici değildir).

**Kapsam:** Excel raporunun **her sayfasındaki her metin hücresi** — değeri
tarama, lock dosyası, kayıt defteri, OSV/zafiyet kaynağı veya proje
kaydından gelen hücreler başta olmak üzere. 1.0.0'da kalkan yalnız
`Dependencies` sayfasının `License` ve `License Source` sütunlarındaydı;
1.1.0 ile mevcut sayfalara genişletilir:

| Sayfa | Kalkan uygulanan metin sütunları |
| --- | --- |
| `Summary` | `Value` (özellikle `Project`, `Repository`, `Reference`); `Metric` etiketleri sabit metindir, kalkan etkisizdir |
| `Dependencies` | `Name`, `Version`, `Ecosystem`, `Scope`, `Manifest`, `PURL`, `License`, `License Source` |
| `Licenses` | `Package`, `Version`, `Detected License`, `Normalized License`, `Risk`, `Policy`, `Status`, `Suppressed` |
| `Vulnerabilities` | `Package`, `Version`, `Advisory`, `Title`, `Severity`, `Fix Version`, `Fix Available`, `Status`, `Suppressed`, `Published At` |

- Sabit/enum değerli sütunlar (`Ecosystem`, `Scope`, `Risk`, `Status`,
  `Suppressed`, `Fix Available`, `Severity` vb.) tetikleyici karakterle
  başlamadığı için pratikte değişmez; kalkan uygulamada sütun ayrımı
  gerektirmemek için "tüm metin hücreleri" kuralı esastır. İleride eklenen her
  metin sütunu da bu kurala tabidir.
- **Sayı ve tarih hücreleri tiplerini korur:** `Dependencies.Depth`,
  `Vulnerabilities.CVSS` ve `Summary`'deki sayaçlar sayı olarak yazılmaya
  devam eder; kalkan yalnız `typeof value === 'string'` olan değerlere
  uygulanır. Bugün metin olarak yazılan tarih değerleri (`Completed At`,
  `Generated At`, `Published At`) metin kalır ve kalkandan geçer (rakamla
  başladıkları için değişmezler). Hiçbir hücre tipi metne veya sayıya
  dönüştürülmez.
- **Mevcut sütunların içeriği kalkan dışında değişmez:** mevcut sütunlara bu
  revizyonla bölüm 9 adım 1–3 (CR normalizasyonu, kontrol temizliği, tek satır
  katlama) **eklenmez**; kalkan ham değere uygulanır. Bu yüzden `\t`/`\r` ile
  başlayan ham değerler de kalkana takılır.
- Hücreler yine ExcelJS düz değerleri olarak yazılır; `{ formula }` hiçbir
  sayfada kullanılmaz.
- **D-63 ile ilişki:** D-63 "`Licenses` (bulgu) sayfası değişmez" der. Bu
  revizyon sayfanın yapısını (sütun adı, sırası, sayısı, satır kümesi) ve
  içerik anlamını değiştirmez; tek fark tetikleyici karakterle başlayan
  değerlere eklenen `'` önekidir. Bu, güvenlik bulgusu L-2 nedeniyle bilinçli
  bir çıktı değişikliğidir (karar C-15).
- `Summary`, `Licenses` ve `Vulnerabilities` sayfalarının yapısı **değişmez**
  (1.5.0 istisnası: `Summary` sonuna tek satır, bölüm 5.3; sütunlar ve mevcut satırlar aynı).

### 5.2 PDF bağımlılık tablosu

- Tablo: mevcut "Dependency Inventory" bölümü (yalnız `project_report` ve
  `audit_evidence` türlerinde bulunur; diğer türlerde bağımlılık tablosu yoktur,
  bu contract eklemez).
- Başlıklar: `Package | Eco | Scope | Manifest | Depth | License` (yeni sütun
  sonda).
- `License` değeri: `license_expression`; boş/`NULL` (F3 öncesi dahil) →
  `n/a`. Mevcut `writePdfRows` 28 karakter kesimi uygulanır.
- Değer bölüm 9 tek satırlık alan kuralından geçer.
- "License Findings" bölümü ve diğer bölümler değişmez (1.5.0: bölüm 5.3 ve 5.4 eklemeleri
  hariç).

### 5.3 `Vulnerability Data Status` satırı — Excel ve PDF `Summary` (1.5.0; REQ-007 AC-P24-10, D-187; ADR-009 Karar 9)

- **Kaynak:** `loadReportData` sorgusuna `s.vulnerability_data_status::text` eklenir;
  `ReportData.vulnerabilityDataStatus: string | null`. Göç yoktur (kolon REQ-005 göç `007`).
- **Değer eşlemesi** (tek tablo; Excel ve PDF aynı metni kullanır):

  | `scans.vulnerability_data_status` | Gösterilen metin (birebir) |
  | --- | --- |
  | `complete` | `complete` |
  | `partial` | `partial (some packages could not be checked)` |
  | `unavailable` | `unavailable (vulnerability source unreachable)` |
  | `disabled` | `disabled (lookup turned off)` |
  | `NULL` (F4 öncesi tarama) | `not checked` |
  | tanınmayan değer (savunma) | `not checked` |

- **Excel:** `Summary` sayfasının **son** satırı: `Metric` = `Vulnerability Data Status`,
  `Value` = eşleme metni (düz metin; bölüm 5.1a kalkanından geçer, sabit metinlerde etkisizdir).
  Mevcut 15 satırın (`Report Type` … `License Violations`) sırası, metni ve tipleri değişmez;
  yeni satır 16. veri satırıdır (başlık hariç). Tüm Excel rapor türlerinde (aynı
  `renderExcelReport`) bulunur.
- **PDF:** `Summary` anahtar-değer listesinin **son** öğesi:
  `Vulnerability Data Status: <eşleme metni>` (mevcut `writePdfKeyValues` biçimi; `License
  violations` satırından sonra). Tüm PDF rapor türlerinde bulunur.
- Asenkron (`ExportWorker`) ve eşzamanlı (REQ-007 `renderExport`) yollar aynı oluşturucuyu
  kullanır; satır her ikisinde de vardır.

### 5.4 PDF kesinti notu (1.5.0; REQ-007 AC-P24-11, D-188, N-7; ADR-009 Karar 9)

- Kesilen tablolar ve sınırlar (**değişmez**):

  | PDF bölümü | Sınır | Toplam `N` | Bulunduğu rapor türleri |
  | --- | --- | --- | --- |
  | `Security Findings` | 40 | taramadaki tüm (bağımlılık × güvenlik bulgusu) satırları | `license_inventory` dışındaki türler |
  | `License Findings` | 40 | tüm (bağımlılık × lisans bulgusu) satırları | `vulnerability_report` dışındaki türler |
  | `Dependency Inventory` | 50 | `scan_dependencies` satır sayısı | `project_report`, `audit_evidence` |

- Bir tablonun toplamı sınırı **aşıyorsa** (`N > sınır`), o tablonun son satırından hemen sonra,
  aynı yazı boyutuyla tek satır yazılır (birebir; `<n>` = sınır, `<N>` = toplam, ondalık tam
  sayı, binlik ayırıcı yok):

  `Showing first <n> of <N>; see the Excel or CSV export for the full list.`

- `N ≤ sınır` ise (`N = 0` ve `No records found.` dahil) satır **yoktur**. Not her tablo için
  ayrı değerlendirilir (bir PDF'te 0–3 not). Satır sayıları ve `writePdfRows` 28 karakter kesimi
  değişmez; not satırına kesim uygulanmaz.
- Asenkron ve eşzamanlı PDF'te aynıdır.

## 6. SBOM alan anlamları

Ortak: bağımlılıklar mevcut gibi purl'e göre tekilleştirilir. Etkin lisans,
`license_source`, ipucu ve telif bilgisi purl'ün ilk `scan_dependencies`
satırından okunur (aynı anahtarın satırları aynı değeri taşır). Telif
satırları `notice_archive_id` → `registry_archive_cache.copyright_lines`
üzerinden gelir; `packages.copyright_text` artık okunmaz (ADR-006 Karar 9).

**Etkin lisans girdisi (`L`):**

- F3 sonrası tarama: `license_expression` (boş/`NULL` → yok).
- **L-5 (1.2.0):** `lock_integrity = 'mismatch'` satırında `license_expression`
  `NULL` olduğu için `L` yoktur → SPDX `licenseDeclared`/`PackageLicenseDeclared`
  `NOASSERTION`, CycloneDX `licenses` yazılmaz. `notice_archive_id` `NULL` olduğu
  için telif satırı yoktur → SPDX `copyrightText` `NOASSERTION`, CycloneDX
  `copyright` yazılmaz. `license_source = 'none'` olduğu için `licenseComments`
  satırı (b) oluşmaz; uyuşmazlık için yeni `licenseComments` satırı **eklenmez**
  (SBOM'da `NOASSERTION` yeterli fail-safe sinyalidir; CycloneDX'te karşılığı yok).
  Uyuşmazlıklı anahtar için F3 öncesi kaynağa (`license_findings`) geri düşülmez.
- F3 öncesi tarama (`license_source IS NULL`): bugünkü kaynak — paketin
  `license_findings` değerlerinden (`normalizedLicense`, yoksa
  `detectedLicense`) tekrarsız, ilk görülme sırasıyla ` AND ` ile birleşik
  ifade; hiç yoksa yok.

- **NuGet (1.4.0):** `registry:nuget` satırında `L` = `.nuspec` ifadesi (normalleştirilmiş).
  `license_unclassified` dolu satırda `license_expression` `NULL` olduğu için `L` yoktur →
  SPDX `NOASSERTION`, CycloneDX `licenses` yazılmaz; yeni `licenseComments` satırı
  **eklenmez** (C-27). NuGet'te `lockfile (unverified)` kaynağı oluşmaz, bu yüzden
  `licenseComments` satırı (b) NuGet'te yazılmaz; satır (a) (geçersiz ifade) mevcut
  kuralla yazılabilir. Telif satırları doğrulanmış `.nupkg` arşiv kaydından gelir.

**Geçerlilik:** `spdxExpression.canonicalize(L)` (AC-P16-3). Geçerliyse
kanonik ifade `C`; değilse "geçersiz".

**purl (1.4.0; REQ-006 AC-P20-18, ADR-008 Karar 4 ve Karar 16 satır 6).** NuGet
bileşenlerinin purl'ü `pkg:nuget/<id>@<sürüm>` (sürüm bilinmiyorsa `pkg:nuget/<id>`):

- `<id>` kaynaktaki harf biçimini **korur** (küçük harfe çevrilmez; ör.
  `pkg:nuget/Newtonsoft.Json@13.0.3`). Ad alanı (namespace) bileşeni yoktur.
- `<sürüm>` NuGet normal biçimidir (baştaki sıfırlar atılmış, 2 parçalıya `.0` eklenmiş,
  4. parça `0` ise atılmış, yapı üst verisi `+…` yok); ön sürüm etiketi kaynaktaki harf
  biçimini korur. Değer `scan_dependencies` / `packages` satırındaki `version` ile aynıdır.
- `<id>` ve `<sürüm>` `npmPurl`/`pypiPurl` ile aynı yüzde kodlama yardımcısından geçer
  (NuGet kimlik/sürüm kuralları gereği pratikte değişmez).
- Purl SPDX `externalRefs` (`PACKAGE-MANAGER` / `purl`; tag-value `ExternalRef`),
  CycloneDX `purl` (ve mevcut kuralla `bom-ref`), Excel `PURL`, NOTICE `PURL:` alanlarında
  aynı değerdir. SBOM bileşen tekilleştirmesi mevcut purl kuralıyla yapılır (harf
  biçimi farklı iki purl iki bileşen olur; NOTICE tekilliği bölüm 3.3'teki NuGet
  anahtarını kullanır).
- **Doğrulanması gerekiyor (ADR-008 Karar 16 satır 6, güven orta-yüksek):** purl
  belirtiminin `nuget` tipi için küçük harf normalleştirmesi istemediği varsayılmıştır.
  Aksi teyit edilirse yalnız `nugetPurl` ve bu madde bir contract revizyonuyla
  değişir; parmak izi formülü (ADR-003) etkilenmez.

### 6.1 SPDX 2.3 (JSON ve tag-value)

| Alan | Kural |
| --- | --- |
| `licenseConcluded` / `PackageLicenseConcluded` | Her pakette, kök ve `dev` dahil, `NOASSERTION`. |
| `licenseDeclared` / `PackageLicenseDeclared` | `L` yoksa `NOASSERTION`; geçerliyse `C`; geçersizse `NOASSERTION`. |
| `licenseComments` / `PackageLicenseComments` | Satırlar (sırayla, `\n` ile birleşik): (a) `L` geçersizse `Declared license is not a valid SPDX expression: <L>`; (b) `license_source = lockfile (unverified)` ise `License source: lockfile (unverified)`. Hiç satır yoksa alan **yazılmaz**. `<L>` tek satırlık alan kuralıyla. |
| `copyrightText` / `PackageCopyrightText` | En az bir telif satırı varsa satırların `\n` ile birleşimi; yoksa `NOASSERTION`. F3 öncesi tarama ve `dev` paketler (arşivi toplanmaz) → `NOASSERTION`. Kök paket → `NOASSERTION`. |
| Diğer alanlar | Değişmez. |

**JSON:** yalnız `JSON.stringify` ile üretilir; `licenseComments` yalnız dolu
olduğunda anahtar olarak bulunur.

**Tag-value:**

- Paket içi sıra: mevcut satırlar korunur; `PackageLicenseDeclared`'dan sonra
  (varsa) `PackageLicenseComments`, sonra `PackageCopyrightText`.
- `PackageLicenseComments` her zaman `<text>…</text>` içinde yazılır.
- `PackageCopyrightText` `NOASSERTION` değilse her zaman `<text>…</text>`
  içinde yazılır (tek satır olsa da).
- `<text>` blok içeriğinde `<text>` ve `</text>` dizileri (büyük/küçük harfe
  duyarsız) sırasıyla `&lt;text&gt;` ve `&lt;/text&gt;` olur; çok satırlı
  değer blok dışına taşamaz (AC-P16-4).
- Tek satırlık alanlar (`PackageName`, `PackageVersion`, `SPDXID`,
  `PackageDownloadLocation`, `PackageLicenseDeclared`, `ExternalRef`,
  `PackageSupplier`, `PackageHomePage`, `DocumentName`, `Creator`) bölüm 9 tek
  satırlık alan kuralından geçer; satır sonu içermez.

**Tek satırlık değerlerde `<text>` kaçışı (1.1.0, L-1).** Tek satırlık bir
tag-value değeri `<text>` bloğu açamaz veya kapatamaz:

- **Kapsam:** `<text>…</text>` bloğu olarak yazılmayan **her** tag-value
  değeri — en az yukarıdaki listedeki alanlar ve `Relationship` satırlarının
  hedef kimliği; tarama, lock, kayıt defteri veya proje verisinden türeyen
  tüm tek satırlık değerler (paket adı, sürüm, purl'lü `ExternalRef`,
  `Organization: <yazar>` biçimli `PackageSupplier`, indirme konumu/ana sayfa,
  `SBOM-<proje adı>-<tarama>` biçimli `DocumentName`, `Organization: <proje
  adı>` biçimli `Creator`). Sabit değerli satırlara (`SPDXVersion`,
  `DataLicense`, `DocumentNamespace`, `Created` vb.) da uygulanabilir; orada
  etkisizdir.
- **Kaçış biçimi:** blok içi kuralla **birebir aynı** — `<text>` dizisi
  `&lt;text&gt;`, `</text>` dizisi `&lt;/text&gt;` olur. Eşleşme büyük/küçük
  harfe duyarsızdır (`<TEXT>`, `</Text>` …); çıktı her zaman küçük harfli
  `&lt;text&gt;` / `&lt;/text&gt;` biçimidir (blok içinde kullanılan düzenli
  ifade ve yer değiştirme: `/<(\/?)text>/gi` → `&lt;$1text&gt;`). Değerdeki
  diğer `<`, `>` ve `&` karakterleri kaçışlanmaz (blok içi kuralla aynı).
- **Sıra:** kaçış, bölüm 9 adım 1–3'ten **sonra** (adım 4) uygulanır. Böylece
  biçim karakterlerinin silinmesiyle oluşan diziler (ör. `<te` U+200B `xt>`
  → `<text>`) de yakalanır.
- **Değişmez:** hiçbir tek satırlık değer ham `<text>` (herhangi bir harf
  büyüklüğüyle) ile başlayamaz ve içinde ham `<text>`/`</text>` bulunduramaz.
  Örnek: `PackageName: <text>gizli` yerine `PackageName: &lt;text&gt;gizli`.
  Üretici tarafından yazılan `<text>` / `</text>` yalnız
  `PackageLicenseComments` ve `PackageCopyrightText` bloklarının sınırlarında
  bulunur.
- SPDX JSON, CycloneDX JSON ve CycloneDX XML çıktıları bu kuraldan
  **etkilenmez** (JSON yalnız `JSON.stringify`; XML kendi kaçışını kullanır).

### 6.2 CycloneDX 1.5 JSON

| Alan | Kural |
| --- | --- |
| `licenses` | `L` yoksa alan **yazılmaz**. Aksi hâlde **tek** girdili dizi: `C` bileşik ifadeyse (`AND`/`OR`/`WITH` içeriyor) `[{ "expression": C }]`; `C` tek kimlikse `[{ "license": { "id": C } }]`; geçersizse `[{ "license": { "name": <L> } }]`. `expression` hiçbir zaman başka bir girdiyle aynı dizide bulunmaz. |
| `copyright` | En az bir telif satırı varsa satırların `\n` ile birleşimi; yoksa alan yazılmaz. |
| Diğer alanlar | Değişmez. JSON anahtar sırası contract'ın parçası değildir. |

F3 öncesi tarama da aynı tek girdi kuralını izler (`L` F3 öncesi tanımıyla).

### 6.3 CycloneDX 1.5 XML

- Bileşen alt öğe sırası (CycloneDX 1.5 XSD; uygulama sırasında XSD'den teyit
  edilir, ADR-006 Karar 13): `author`, `name`, `version`, `description`,
  `scope`, `licenses`, `copyright`, `purl`. Değeri olmayan öğe yazılmaz.
- `<licenses>` tek çocuk içerir: `<expression>C</expression>`,
  `<license><id>C</id></license>` veya `<license><name>L</name></license>`
  (JSON ile aynı seçim).
- `<copyright>`: satırların `\n` ile birleşimi (öğe metninde LF korunur).
- **Geçersiz karakter temizliği:** tüm öğe metinlerinde ve öznitelik
  değerlerinde (metadata bileşeni dahil), kaçıştan **önce** XML 1.0'da izin
  verilmeyen karakterler çıkarılır: `#x9 | #xA | #xD | [#x20-#xD7FF] |
  [#xE000-#xFFFD] | [#x10000-#x10FFFF]` dışındaki her şey ve eşleşmeyen
  vekiller. Sonra `& < > " '` kaçışı (mevcut `xe`).
- JSON ve XML çıktıları aynı tarama için tutarlıdır (aynı `licenses` seçimi
  ve aynı `copyright`).

## 7. Arayüz: "NOTICE" bağlantısı

Dosya: `public/app.js`, fonksiyon `scanActions(row)` (frontend-engineer).

- **Ne zaman:** yalnız `row.status === 'completed'`. Diğer durumlarda (aktif
  durumlar ilerleme çubuğu, diğerleri `—`) bağlantı yoktur; mevcut dallar
  değişmez.
- **Yerleşim:** `completed` dalı mevcut "SBOM" bağlantısını ve yeni "NOTICE"
  bağlantısını, bu sırayla, tek bir sarmalayıcı içinde döndürür:
  `el('div', { style: 'display:inline-flex; align-items:center; gap:0.375rem;' }, sbomLink, noticeLink)`.
- **SBOM bağlantısı:** bugünküyle birebir aynı (`href`, sınıf, öznitelikler,
  metin).
- **NOTICE bağlantısı** — SBOM bağlantısıyla aynı biçim:

  | Öznitelik | Değer |
  | --- | --- |
  | Öğe | `a` |
  | `className` | `btn btn-sm` |
  | `href` | `apiPath('scans', row.id, 'notice')` → `/api/scans/<row.id>/notice` |
  | `target` | `_blank` |
  | `rel` | `noopener` |
  | `style` | `text-decoration:none; display:inline-flex; align-items:center; gap:0.25rem;` |
  | İçerik | `icon('download', 'width:12px;height:12px;')`, ardından metin `' NOTICE'` (görünen metin `NOTICE`) |

- Bağlantı kimlik bilgisini taşımaz; tarayıcının `SameSite=Strict` oturum
  çerezi aynı köken üst düzey gezinmede gönderilir (SBOM bağlantısıyla aynı).
  `fetch`/toast akışı eklenmez. Hata yanıtı yeni sekmede JSON olarak görünür
  (SBOM bağlantısıyla aynı, kabul edildi).
- Başka arayüz değişikliği yapılmaz (AC-P15-15).
- **1.5.0 (REQ-007 D-186, ADR-009 Karar 10; C-36):** `completed` dalı artık sırasıyla `PDF`,
  `Excel`, `CSV`, `NOTICE`, `SBOM` bağlantılarını döndürür; yerleşim, yeni bağlantılar ve
  öznitelikler `docs/contracts/REQ-007-cli-and-exports.md` bölüm 8'dedir ve bu bölümün üzerine
  geçer. NOTICE bağlantısında `href`, sınıf, stil ve içerik **aynı kalır**; değişen: `download`
  özniteliği (boş değer) eklenir, `target="_blank"` ve `rel="noopener"` **kaldırılır**,
  `aria-label="Download NOTICE file"` eklenir. Yukarıdaki tablodaki `target`/`rel` satırları
  1.5.0 ile geçersizdir. SBOM bağlantısı değişmez. Hata yanıtında tarayıcı indirmeyi başarısız
  gösterir (yeni sekmede JSON yerine; kabul edildi).
- **Paralel çalışma:** frontend bu bölüme göre, backend bölüm 2–3'e göre
  birbirini beklemeden çalışır. Ortak tek arayüz `GET /api/scans/{id}/notice`
  yoludur.

### 7.1 Proje formu: `.NET (NuGet)` teknoloji yığını seçeneği (1.4.0; REQ-006 AC-P20-17, D-130; ADR-008 Karar 15)

Dosya: `public/index.html` (frontend-engineer). `public/app.js` **değişmez**.

- "Technology Stack" çoklu seçim listesine (`<select id="ecosystems" class="form-control"
  multiple style="height: 80px;">`), mevcut iki seçenekten **sonra** tek satır eklenir:

  ```html
  <option value="dotnet">.NET (NuGet)</option>
  ```

  | Öğe | Değer (birebir) |
  | --- | --- |
  | `value` | `dotnet` (`tech_ecosystem` enum değeri; küçük harf) |
  | Görünen metin | `.NET (NuGet)` |
  | `selected` | **yok** — varsayılan seçim değişmez (`nodejs` seçili kalır) |
  | Sıra | `nodejs`, `python`, `dotnet` |

- Mevcut seçenekler (`<option value="nodejs" selected>Node.js (NPM / Yarn)</option>`,
  `<option value="python">Python (pip / PyPI)</option>`) ve listenin öznitelikleri
  (`id`, sınıf, `multiple`, `style`) bayt bayt aynı kalır. Başka arayüz değişikliği
  yapılmaz (rozet, sütun veya yeni metin yok; REQ-006 D-138, D-144).
- **Gönderim (mevcut, değişmez):** `public/app.js` seçili seçeneklerin `value`
  değerlerini toplar (`Array.from(byId('ecosystems').selectedOptions).map((o) =>
  o.value)`) ve `POST /api/projects` gövdesinde `ecosystems: string[]` olarak gönderir.
  `projectController` her değeri `$2::tech_ecosystem` ile `project_tech_stacks`'e yazar;
  `dotnet` enum'da zaten vardır. Proje listesi (`GET /api/projects`) `ecosystems`
  dizisinde `dotnet` değerini döndürür ve arayüz bunu mevcut `capsule` ile ham değer
  olarak (`dotnet`) gösterir.
- **API şeması değişmez:** `POST /api/projects` istek gövdesindeki `ecosystems` ve
  yanıttaki `ecosystems` zaten serbest `string[]`'dir (REQ-002 OpenAPI: "tech_ecosystem
  enum değerleri"); yeni alan, yeni zorunlu alan veya enum değişikliği yoktur. Yalnız
  arayüzün gönderebildiği değer kümesi `dotnet` ile genişler (additive).
- **Çalışma zamanı (bilgi, backend):** `supportedEcosystems` `['nodejs', 'python',
  'dotnet']`; yığını boş projenin varsayılan listesi `['nodejs', 'python', 'dotnet']`
  (ADR-008 Karar 15). Yığını yalnız `nodejs` olan proje .NET dosyalarını taramaz.
- **Paralel çalışma:** frontend bu bölüme göre, backend ADR-008'e göre birbirini
  beklemeden çalışır (manifest onayından sonra); ortak arayüz mevcut `POST /api/projects`
  gövdesidir.

## 8. `[registry]` uyarı satırı

Tamamlanmış taramanın `error_message` alanına, mevcut `parse_errors`
satırlarından **sonra**, `\n` ile ayrılmış **tek** satır olarak eklenir
(ADR-006 Karar 11). Satır `sanitizeErrorText`'ten geçer. Paket adı yazılmaz.
Sayılar benzersiz `(ekosistem, istek adı, sürüm)` anahtarlarıdır.

Zenginleştirme kapalıyken (`disabled`; tüm anahtarlar):

```
[registry] License enrichment disabled: <M> package(s) use the lockfile license (unverified), <K> have no license.
```

Diğer durumda, `unreachable`, `error` veya `budget_exceeded` durumunda en az
bir anahtar varsa:

```
[registry] Registry lookup incomplete for <T> package(s) (unreachable: <u>, error: <e>, time budget exceeded: <b>); license from lockfile (unverified): <M>, no license: <K>.
```

- `T = u + e + b`; `M` = bunlardan lock ipucuna düşen, `K = T − M`. Kapalı
  şablonda `M + K` = tüm anahtarlar.
- Sayılar binlik ayraçsız; `package(s)` sabittir (çoğul mantığı yok).
- Etkilenen anahtar yoksa ve zenginleştirme açıksa satır yoktur.
  Zenginleştirici enjekte edilmemişse (yalnız testler) satır yazılmaz.

**L-5 uyuşmazlık sayısı (1.2.0).** `X` = `lock_integrity = 'mismatch'` olan
benzersiz `(npm, istek adı, sürüm)` anahtar sayısı. Uyuşmazlıklı anahtarların
zenginleştirme durumu `ok`/`no_license` olduğundan `T`'ye girmezler. Satır yine
**tek** satırdır:

- Zenginleştirme açık, `T > 0` ve `X > 0` → "incomplete" şablonunun sonuna bir
  boşluk ve şu metin eklenir:

  ```
  Lockfile integrity mismatch: <X> package(s) (registry license and lockfile hint not used).
  ```

  Tam örnek:
  `[registry] Registry lookup incomplete for 3 package(s) (unreachable: 3, error: 0, time budget exceeded: 0); license from lockfile (unverified): 1, no license: 2. Lockfile integrity mismatch: 1 package(s) (registry license and lockfile hint not used).`
- Zenginleştirme açık, `T = 0` ve `X > 0` → üçüncü şablon:

  ```
  [registry] Lockfile integrity mismatch for <X> package(s); registry license and lockfile hint not used.
  ```

- `X = 0` → satır 1.1.0 ile bayt bayt aynıdır (veya yoktur). Zenginleştirme
  kapalıyken karşılaştırma yapılmaz (`lock_integrity` `NULL`, `X = 0`); kapalı
  şablon değişmez.
- Satır sırası ve arındırma değişmez: `parse_errors` → `[registry]`; REQ-005 ile
  ardından `[osv]` → `[nvd]` gelir (`docs/contracts/REQ-005-vulnerability-data.md`
  bölüm 3.4).

**NuGet (1.4.0; REQ-006 AC-P21-14, ADR-008 Karar 12).** Üç şablonun metni **değişmez**.

- NuGet anahtarları `(nuget, asciiLower(id), asciiLower(normal sürüm))` olarak mevcut
  sayımlara katılır: `u`, `e`, `b`, `T`, kapalı şablondaki `M + K` ve uyuşmazlık sayısı
  `X`. `X` 1.4.0 ile `lock_integrity = 'mismatch'` olan benzersiz npm **ve** NuGet
  anahtarlarının toplamıdır.
- NuGet'te lock ipucu olmadığından NuGet anahtarları `M`'ye hiç katılmaz, her zaman
  `K`'ye (`no license`) sayılır.
- `license_unclassified` (`file` / `url`) ayrı sayılmaz; bu anahtarlar `no_license`
  durumundadır ve `T`'ye girmez.
- Uyuşmazlık metnindeki `(registry license and lockfile hint not used)` ifadesi NuGet
  anahtarları için de aynen kullanılır (NuGet'te "registry license" `.nuspec` lisansıdır;
  ipucu yoktur). Paket adı yazılmaz.
- NuGet içermeyen taramada satır 1.3.0 ile bayt bayt aynıdır (veya yoktur).
- Ayrıştırıcının NuGet hata satırları `parse_errors` biçimindedir
  (`[dotnet] File <göreli yol>: <sabit metin>`; ADR-008 Karar 7) ve `[registry]`'den önce
  gelir; metinleri bu contract'ın kapsamında değildir (NuGet golden'larıyla donar).

## 9. Ortak metin kuralları

Güvenilmeyen her metin (paket adı, sürüm, purl, proje adı, lisans ifadesi,
ipucu, telif satırı, dosya yolu, lisans metni, meta veri lisans metni) her
çıktıda (NOTICE, Excel, PDF, SBOM) şu sırayla işlenir (ADR-006 Karar 8 ve 13):

1. `\r\n` ve tek `\r` → `\n`.
2. Kontrol/biçim temizliği: `src/lib/textSanitize.ts` `stripControl`
   (ESC/C1 dizileri, `\p{Cf}`, `\n`/`\t` dışı C0, `DEL`, C1); eşleşmeyen vekil
   → U+FFFD. Saklanırken uygulanmış olsa da çıktıda yeniden uygulanır.
3. **Tek satırlık alan kuralı:** `\n`, `\t`, U+0085 (NEL), U+2028 (LINE
   SEPARATOR) ve U+2029 (PARAGRAPH SEPARATOR) karakterlerinin **her biri**
   tek bir boşluk (U+0020) olur (1.1.0, I-3; karakter başına bir boşluk,
   ardışık boşluklar birleştirilmez — mevcut `\n`/`\t` davranışıyla aynı).
   Düzenli ifade karşılığı: `/[\n\t\u0085  ]/g` → `' '`. U+0085
   adım 2'de zaten silinir; listede savunma derinliği için yer alır. Kesim
   yalnız açıkça belirtilen yerlerde (ipucu 200 kod noktası, PDF 28 karakter)
   ve bu adımdan sonra yapılır.
4. Hedefe özgü kaçış: NOTICE ayraç kalkanı (3.6; çok satırlı metinde
   U+0085/U+2028/U+2029 sonrası dahil), tag-value `<text>` (6.1; hem blok
   içinde hem tek satırlık değerlerde, 1.1.0 L-1), XML geçersiz karakter +
   kaçış (6.3), Excel formül kalkanı (5.1a; tüm sayfalardaki metin
   hücreleri, 1.1.0 L-2), JSON yalnız `JSON.stringify`.

Çok satırlı serbest metin (NOTICE lisans dosyası ve meta veri lisans metni)
adım 3'ü uygulamaz; bu metinlerde U+2028/U+2029 korunur ve yalnız NOTICE
ayraç kalkanı açısından satır sonu sayılır (bölüm 3.6). Satırların `\n` ile
birleştirildiği alanlarda (telif satırları — NOTICE `Copyright:`, SPDX
`copyrightText`, CycloneDX `copyright`; `licenseComments` satırları) her
satır ayrı bir tek satırlık değerdir ve adım 3'ten geçer; birleştirici `\n`
üreticiye aittir.

Adım 3'ün genişletilmesi, adım 3'ün bugün uygulandığı her yerde geçerlidir
(NOTICE tek satırlık alanları, yeni Excel sütunları, PDF `License`, SPDX
tag-value tek satırlık alanları, lisans adı/ifadesi ve telif satırları).
Bugün yalnız adım 1–2'den geçen JSON/XML alanları (ör. SPDX/CycloneDX JSON
`name`, `version`) bu revizyonla değişmez. Bölüm 5.1a gereği mevcut Excel
sütunlarına adım 1–3 uygulanmaz.

## 10. Test yükümlülükleri

| Taraf | Yükümlülük |
| --- | --- |
| backend-engineer | Bu contract'a uygun uygulama: route/controller/`NoticeService`, rapor sütunları, SBOM değişiklikleri, `[registry]` satırı. Implementation sonunda lint, typecheck ve hedef test suite sonuçlarını raporlar. |
| frontend-engineer | Bölüm 7; lint. |
| qa-automation | **Uç nokta (contract testi):** `200` başlıkları (`Content-Type`, `Content-Disposition`, `Content-Length`, `X-Checksum-SHA256` = gövde özeti, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`); büyük harfli `scanId` ile istekte dosya adının küçük harf olması; `400`/`401`/`403`/`404` (tarama yok ve `running`/`failed` tarama) gövdeleri ve kodları, hata yanıtında `Content-Disposition` olmaması; API anahtarıyla erişim; istek sırasında ağ isteği yapılmaması ve `sbom_documents`/`reports`/disk yazımı olmaması. **Biçim:** golden NOTICE (`tests/fixtures/notice/*.txt`, `-text`) bayt bayt; iki istekte aynı bayt; BOM yok, CR yok, son satır LF; sıralama (büyük/küçük harfli adlar, sürümsüz paket); runtime tekilliği (girdi sayısı = tekil runtime anahtar sayısı; `dev`+runtime paket bir kez, yalnız `dev` yok); ayraç kalkanı (lisans metninde `ENTRY_SEP` ve `FILE_SEP` satırları); atlanmış dosya; `Reason:` tablosunun en az `no_license_file`, `limit_exceeded`, `version_unknown`, `unreachable`, F3 öncesi satırları; SPDX bağlantıları; PyPI meta veri metni bloğu; 64 MiB kesimi (test sırasında üretilen büyük metinle); F3 öncesi tarama notu. **Raporlar:** `.xlsx` geri okuma — `Dependencies` başlıkları 9 sütun ve sırası, değerler, uyuşmazlık ve `none (lockfile hint ignored: …)` hücreleri, formül kalkanı, F3 öncesi boş hücreler, `Licenses` sayfasının yapısının (sütunlar, sıra, satır kümesi) değişmediği; PDF üretiminin hatasız olduğu. **SBOM:** AC-P16-1…7; `licenseComments` iki satır kuralı; tag-value enjeksiyon testi; CycloneDX JSON tek girdi; XML öğe sırası ve geçersiz karakter. **Arayüz (jsdom):** `completed` satırda `a[href="/api/scans/<id>/notice"]` vardır, metni `NOTICE`, SBOM bağlantısı korunur; diğer durumlarda yoktur. **`[registry]`:** iki şablonun birebir metni. **Geriye uyumluluk:** mevcut contract testleri değiştirilmeden yeşil. |
| backend-engineer (1.1.0) | L-1: tag-value tek satırlık değerlerde `<text>`/`</text>` kaçışı (6.1). L-2: Excel kalkanının tüm sayfalardaki metin hücrelerine uygulanması, sayı hücrelerinin tipinin korunması (5.1a). I-3: adım 3'e U+0085/U+2028/U+2029 eklenmesi ve NOTICE ayraç kalkanının bu karakterlerden sonra da uygulanması (3.6, 9). M-1: NOTICE metinlerinin parti parti okunması ve kesimden sonra hiç okunmaması (3.7). Lint, typecheck ve hedef test sonuçları raporlanır. |
| qa-automation (1.1.0) | **L-1:** lock'ta adı `<text>gizli` (ve `<TEXT>…`, içinde `</text>` geçen ad/sürüm/yazar/ana sayfa) olan paketle SPDX tag-value: hiçbir tek satırlık değer ham `<text>` ile başlamaz ve ham `<text>`/`</text>` içermez; değer `&lt;text&gt;gizli`; ham `<text>` ve `</text>` sayısı yalnız üreticinin `PackageLicenseComments`/`PackageCopyrightText` blok sayısına eşit; sonraki paketin `PackageName` satırı belgede ayrı satır olarak bulunur; SPDX JSON ve CycloneDX çıktıları değişmez. **L-2:** `.xlsx` geri okuma — `Dependencies` `Name`/`Version`/`PURL`/`Manifest`, `Licenses` `Detected License`/`Normalized License`/`Package`, `Vulnerabilities` `Title`/`Advisory` ve `Summary` `Project` hücrelerinde `=`, `+`, `-`, `@`, `\t`, `\r` ile başlayan değerler `'` önekli; bu karakterlerle başlamayan değerler değişmemiş; `Depth`, `CVSS` ve `Summary` sayaçları sayı tipinde; hiçbir hücre formül değil. **I-3:** NOTICE tek satırlık alanlarında (ad, telif) U+2028/U+2029 → boşluk; lisans metninde U+2028 + `ENTRY_SEP` ve U+2029 + `FILE_SEP` → ayırıcıdan sonra tek boşluk; ayırıcı korunur; SPDX tag-value tek satırlık değerde U+2028 yok. **M-1:** çok sayıda büyük önbellek satırıyla (ör. 200 × 4 MiB) NOTICE üretiminde tepe heap kullanımının sınırlı kalması (güvenlik raporu hedefi < ~300 MB) ve çıktının 64 MiB kesim kuralına uyması; mevcut golden NOTICE'lar değişmeden geçer. |
| security-red-team | NOTICE ayraç sahteciliği, tag-value/XML/Excel enjeksiyonu, uç noktada yetki ve hata gövdesi sızıntısı incelemesi. 1.1.0 sonrası M-1 ve L-1 düzeltmelerinin merge öncesi yeniden incelenmesi (güvenlik raporu "Merge kararı"). 1.2.0: L-5 fail-safe'inin bulgu gizlemeye yol açmadığı (saldırgan lock değeri yalnız daha muhafazakâr çıktı üretir). |
| backend-engineer (1.2.0) | `lock_integrity` saklama (4.4); Excel `none (lockfile integrity mismatch)` metni ve önceliği (4.1, 5.1); NOTICE satır 15 seçimi ve uyuşmazlıklı anahtarda arşiv önbelleğinin okunmaması (4.3); `[registry]` `X` eki ve üçüncü şablon (8); SBOM'da `NOASSERTION` ve yeni `licenseComments` satırı olmaması (6). Lint, typecheck, hedef testler raporlanır. |
| qa-automation (1.2.0) | Lock'ta kayıt defterinden farklı `sha512` taşıyan npm paketiyle (sahte kayıt defteri): `lock_integrity = 'mismatch'`, arşiv isteği **sıfır** (önbellekte kayıt olsa bile NOTICE onu kullanmaz), Excel `License` boş ve `License Source` = `none (lockfile integrity mismatch)` (lock ipucu ve kayıt defteri lisansı metinde yok), NOTICE girdisi satır 15 nedeni ve `License: NOASSERTION`, SPDX `licenseDeclared`/`copyrightText` `NOASSERTION` ve `licenseComments` yok, CycloneDX `licenses`/`copyright` yok, PDF `n/a`, runtime pakette `NOASSERTION` lisans bulgusu, `[registry]` satırında `X` (yalnız uyuşmazlık → üçüncü şablon; erişilemeyen paketle birlikte → ekli "incomplete" şablonu). Eşleşen, yalnız `sha1`, bozuk, 1025 karakterlik lock değerinde ve PyPI paketinde çıktılar 1.1.0 ile aynı; mevcut NOTICE golden'ı ve P-10 golden'ları değişmeden yeşil (AC-L5-3, AC-L5-4). |

| backend-engineer (1.4.0) | `registry:nuget` kaynağı (4.1); `license_unclassified` yazılma kuralı (4.5); Excel `License Source` öncelik zinciri ve iki yeni metin (4.1, 5.1); NOTICE etiket `nuget`, NuGet tekillik anahtarı ve sıralama (3.3), `.nupkg` lisans dosyaları (3.5), satır 7a, satır 14 daraltması, `license_unclassified` öneki (4.3); `lock_integrity` NuGet değerleri (4.4); SBOM purl ve `NOASSERTION`, yeni `licenseComments` yok (6); `[registry]` sayımları (8). Lint, typecheck, hedef testler raporlanır. |
| database-engineer (1.4.0) | Göç `008`: `scan_dependencies.license_source` CHECK'e `registry:nuget`, `scan_dependencies.license_unclassified` kolonu ve CHECK'i (ADR-008 Karar 14 bağlayıcı adlar); `db/schema.sql`. Up → down → up testi qa ile. |
| frontend-engineer (1.4.0) | Bölüm 7.1 seçeneği; lint. |
| qa-automation (1.4.0) | **Sahte NuGet sunucusuyla (loopback):** `type="expression"` paket → Excel `License` = ifade, `License Source` = `registry:nuget`, NOTICE `License source: registry:nuget`, `Ecosystem: nuget`, `PURL: pkg:nuget/<Kaynak.Harf>@<sürüm>`; `type="file"` paket → Excel `License` boş + `License Source` = `none (license file in package, not classified)`, doğrulanmış `.nupkg`'de bildirilen `docs/EULA.md` ve kök `LICENSE.txt` NOTICE dosya bloklarında (`lib/net8.0/LICENSE` yok; `../LICENSE` bildirimi eşleşmez), lock'suz projede `Reason: license is a file inside the package (not classified); package archive not downloaded (no lockfile integrity value)`; sınıflandırılmamış URL → `none (license URL not classified)` ve URL metninin hiçbir çıktıda geçmediği (metin taraması); lock'suz NuGet paketi → satır 7a; NuGet paketi için `license enrichment not supported for this ecosystem` metninin **hiç** üretilmediği; farklı özet → `mismatch` fail-safe çıktılarının hepsi (Excel `none (lockfile integrity mismatch)`, NOTICE satır 15, SPDX `NOASSERTION`, CycloneDX `licenses` yok, `[registry]` `X` NuGet anahtarını içerir, `license_unclassified` `NULL`); ham özet ve imzalı içerik özeti → `match`; iki farklı lock özeti → `mismatch` ve indirme yok. **Sıralama:** npm, NuGet, PyPI karışık taramada NOTICE girdi sırası `npm` < `nuget` < `pypi`; `Newtonsoft.Json` ve `newtonsoft.json` (iki klasör) tek NOTICE girdisi. **`[registry]`:** NuGet hostu kapalıyken `unreachable` sayısı NuGet anahtarlarını içerir; şablon metinleri birebir. **Arayüz (jsdom veya statik HTML denetimi):** `#ecosystems` listesinde sırayla `nodejs` (selected), `python`, `dotnet` seçenekleri; `dotnet` metni `.NET (NuGet)` ve `selected` değil. **Geriye uyumluluk:** NuGet'siz taramalarda mevcut NOTICE, Excel, SBOM ve P-10 golden'ları değişmeden yeşil (REQ-006 AC-G-9); mevcut contract testleri değişmez. |
| security-red-team (1.4.0) | URL metni / bildirilen yolun çıktılara sızmadığı; `.nupkg` lisans dosyası seçiminde yol geçişi; fail-safe'in NuGet'te bulgu gizlemeye yol açmadığı. |
| backend-engineer (1.5.0) | `loadReportData` sorgusuna `vulnerability_data_status`; Excel `Summary` son satırı ve PDF `Summary` son öğesi, tek eşleme tablosuyla (5.3); üç PDF tablosunda kesinti notu (5.4). Lint, typecheck, hedef testler raporlanır. |
| frontend-engineer (1.5.0) | Bölüm 7'deki 1.5.0 NOTICE bağlantısı değişikliği (REQ-007 contract bölüm 8 ile birlikte); lint. |
| qa-automation (1.5.0) | **V-12:** beş değer (`complete`, `partial`, `unavailable`, `disabled`, `NULL`) için Excel `Summary` son satırı (`Metric`/`Value` metni birebir; satır 16) ve PDF metninde `Vulnerability Data Status: …` satırının `License violations` satırından sonra geldiği; mevcut 15 Excel `Summary` satırının değişmediği. **Kesinti notu:** güvenlik 41, lisans 41, bağımlılık 51 satırlı fixture'da üç notun birebir metni (`Showing first 40 of 41; …`, `Showing first 50 of 51; …`); tam 40/50 satırda ve boş tabloda notun olmadığı; `license_inventory` ve `vulnerability_report` türlerinde yalnız ilgili tabloların notu. **Arayüz (jsdom):** NOTICE bağlantısı `href` aynı, `download` var, `target` yok. **Regresyon:** güncellenen rapor testi beklenen değerleri handoff'ta listelenir (REQ-007 AC-G-7); NOTICE golden'ı ve SBOM testleri değişmeden yeşil. |

## 11. Sürümleme

- Güncel contract sürümü **1.5.0** (aşağıda; 1.3.0 yalnız yapılandırma ayrıştırmasıdır).
- **1.5.0 (REQ-007 V-12, kesinti notu):** contract sürümü minor artar: Excel `Summary`
  sonuna bir satır, PDF'e bir `Summary` öğesi ve koşullu not satırları, NOTICE bağlantısına
  öznitelik değişikliği. Mevcut satır/sütun sırası, metinleri ve değer kümeleri değişmez (major
  değil). `NOTICE format: 1` kalır (NOTICE baytları değişmez). OpenAPI `info.version` 1.1.0
  kalır. Bundan sonra `Summary` sayfasına yeni satır yalnız sona eklenir (minor); mevcut satır
  sırası değişikliği major sürümdür. 1.1.0 notu: (minor: güvenlik sertleştirmesi; uç nokta,
  şema, sütun ve değer kümeleri değişmez). API yolu sürümlenmez (`/api/...`,
  mevcut desen). OpenAPI `info.version` 1.0.0 kalır.
- **NOTICE biçim sürümü 1.1.0'da `1` kalır.** I-3 kalkan genişletmesi ve
  adım 3 değişikliği yalnız U+2028/U+2029 içeren girdilerde NOTICE baytlarını
  değiştirir. F3 henüz yayımlanmadığı (branch merge edilmediği) için
  `NOTICE format: 1` çıktısını görmüş bir tüketici yoktur; numara artırılmaz
  (karar C-17). Aşağıdaki kural F3 merge edildikten sonraki değişikliklere
  uygulanır. Golden dosyalar bu karakterleri içermiyorsa değişmez; içeriyorsa
  güncellenir.
- **1.2.0 (L-5):** contract sürümü minor artar (yeni saklanan kolon ve yeni çıktı
  metinleri; mevcut değer kümeleri ve anlamları değişmez). **`NOTICE format: 1`
  kalır** (karar C-20): bölüm 3'teki biçim — üst bilgi, girdi alanları, sıralama,
  ayraçlar, blok yapısı — değişmez; yalnız bölüm 4.3 `Reason:` tablosuna yeni bir
  **değer** (satır 15) eklenir ve bu değer yalnız F4 sonrası, uyuşmazlıklı
  girdilerde görünür. Mevcut tüm girdiler için çıktı baytları değişmez (golden
  değişmez). Aşağıdaki "her bayt değişikliği" kuralı bu nedenle **biçim**
  değişikliklerine (bölüm 3 yapısı, mevcut girdilerin baytları) uygulanır;
  bölüm 4 değer tablolarına yalnız yeni koşul için yeni değer eklemek minor
  contract revizyonudur ve biçim numarasını artırmaz. Excel'de yeni sütun yoktur.
- **1.4.0 (NuGet):** contract sürümü minor artar (D-144): yeni değer `registry:nuget`,
  yeni saklanan kolon `license_unclassified`, yeni metinler (Excel iki metin, NOTICE satır
  7a ve iki önek), NuGet etiket/tekillik/sıralama kuralı ve arayüz seçeneği. Mevcut
  değerlerin anlamı değişmez (major değil). **`NOTICE format: 1` kalır** (C-30): bölüm 3
  yapısı değişmez; NuGet etiketi, satır 7a ve önekler yalnız F5 sonrası NuGet girdilerinde
  görünür; NuGet'siz taramalarda baytlar 1.3.0 ile aynıdır. OpenAPI `info.version`
  1.0.0 → 1.1.0 (yalnız bilgi amaçlı şemalarda additive değişiklik; uç nokta yüzeyi
  aynı).
- NOTICE biçim sürümü üst bilgideki `NOTICE format: 1` satırıdır. Bölüm 3'te
  çıktı baytlarını değiştiren her değişiklik bu sayıyı artırır, golden
  dosyayı günceller ve bu contract'ın yeni sürümünü gerektirir.
- Bölüm 4'teki değer kümelerine ekleme göç ve contract revizyonu gerektirir
  (minor sürüm). Mevcut değerin anlamının değişmesi major sürümdür.
- Excel'de yeni sütunlar yalnız sona eklenir (minor). Mevcut sütun sırası
  değişikliği major sürümdür.
- SBOM `specVersion` yükseltmesi (ör. CycloneDX 1.6) bu contract'ın kapsamı
  dışındadır ve yeni karar gerektirir.

## 12. Karar kaydı ve REQ/ADR ile netleştirmeler

Tümü "kullanıcı daimi talimatı (önerilen seçenek), 2026-10-10".

| # | Konu | Karar | Dayanak |
| --- | --- | --- | --- |
| C-1 | Tamamlanmamış tarama | `404 not_found`, `409` yok | AC-P15-11, ADR-006 Karar 12, SBOM ile aynı |
| C-2 | Boyut sınırı | `413` yok; metin kesimi ile `200` | AC-P15-13, ADR-006 Karar 12 |
| C-3 | Önbellek başlığı | `Cache-Control: no-store`; ETag sözleşme dışı | Kimlik doğrulamalı indirme |
| C-4 | Dosya adındaki UUID | Küçük harfli kanonik (veritabanından) | Belirlenimcilik |
| C-5 | Biçim sürümü satırı | `NOTICE format: 1` üst bilgide | Tüketiciler için sürüm sinyali; REQ listesi sınırlayıcı değil |
| C-6 | Ayraç kalkanı | `ENTRY_SEP`e ek olarak `FILE_SEP` de korunur | ADR-006 Karar 12'nin savunma derinliği genişletmesi |
| C-7 | 64 MiB kesimi | İlk aşımdan sonra tüm metin blokları atlanır; yapı satırları her zaman yazılır | "sonraki girdilerin metinleri yazılmaz" (AC-P15-13) |
| C-8 | Kayıt defterinde lisans yokken ipucu | Excel `License Source` = `none (lockfile hint ignored: <ipucu>)` | AC-L6-2 "yalnızca raporda not olarak görünür"; ADR-006 Karar 13 bu durumu tanımlamıyordu |
| C-9 | Yeni Excel sütunlarının yeri | `PURL`'den sonra, sonda | Mevcut sütun konumlarına bağlı tüketiciler bozulmaz |
| C-10 | PDF `License` boş değeri | `n/a` (mevcut PDF deseni) | `writePdfRows` tutarlılığı |
| C-11 | SPDX lock kaynağı görünürlüğü | `licenseComments` satırı `License source: lockfile (unverified)` | L-6 görünürlüğü SBOM'da da |
| C-12 | F3 öncesi SBOM telifi | `NOASSERTION` (önbellek araması yok); NOTICE ise ADR-006 Karar 12'ye göre önbellekte arar | ADR-006 SBOM için F3 öncesi telif kaynağı tanımlamıyordu; `packages.copyright_text` hiç dolmadığı için bugünkü çıktı da `NOASSERTION` |
| C-13 | Desteklenmeyen ekosistem | NOTICE nedeni `license enrichment not supported for this ecosystem`; F3 ayrıştırıcıları yalnız `nodejs`/`python` ürettiği için bugün oluşmaz. **1.4.0:** `dotnet` için kalktı (NuGet zenginleştirilir); diğer enum değerleri için geçerli | `tech_ecosystem` enum'u daha geniş; REQ-006 AC-P21-11 |
| C-14 | Tag-value tek satırlık değerlerde `<text>` (1.1.0) | Önerilen seçenek: değerin yalnız başı değil **her yerindeki** `<text>`/`</text>` (harf duyarsız) blok içi kaçışla birebir aynı biçimde `&lt;text&gt;`/`&lt;/text&gt;` olur; adım 1–3'ten sonra uygulanır | Güvenlik raporu L-1; ADR-006 Karar 13 tag-value kaçışını yalnız bloklar için tanımlıyordu |
| C-15 | Excel formül kalkanının kapsamı (1.1.0) | Önerilen seçenek: tüm sayfalardaki tüm metin hücreleri; sayı hücreleri tipini korur; mevcut sütunlara yalnız kalkan eklenir (adım 1–3 eklenmez) | Güvenlik raporu L-2; ADR-006 Karar 13 "Mevcut sütunlar değişmez" ve D-63 "`Licenses` sayfası değişmez" ifadeleri bu güvenlik istisnasıyla daraltılır (yapı değişmez, yalnız tetikleyici önekli değerler) |
| C-16 | Unicode satır ayırıcıları (1.1.0) | U+0085/U+2028/U+2029 tek satırlık değerlerde boşluk; çok satırlı NOTICE metninde korunur ama ayraç kalkanı için satır sonu sayılır | Güvenlik raporu I-3 |
| C-17 | NOTICE biçim numarası (1.1.0) | `NOTICE format: 1` kalır | F3 yayımlanmadı; numarayı artırmak tüketicisi olmayan bir sürüm farkı yaratırdı |
| C-18 | NOTICE bellek sınırı (1.1.0) | Metinler parti parti okunur, ilk kesimden sonra hiç okunmaz; çıktı biçimi değişmez | Güvenlik raporu M-1 |
| C-19 | L-5 Excel metni (1.2.0) | `none (lockfile integrity mismatch)`; ipucu/kayıt defteri lisansı yazılmaz; `none (lockfile hint ignored: …)`'a göre öncelikli | AC-L5-2 "hücre uyuşmazlığı belirtir"; doğrulanmamış lisansı rapora taşımamak |
| C-20 | NOTICE biçim numarası (1.2.0) | `NOTICE format: 1` kalır; yeni `Reason:` değeri (satır 15) minor değer eklemesidir | Biçim/yapı değişmez, mevcut girdilerin baytları değişmez (AC-L5-4); F3 merge edildiği için kural netleştirildi (bölüm 11) |
| C-21 | `[registry]` uyuşmazlık sayısı (1.2.0) | Tek satır: "incomplete" şablonuna ek cümle veya yalnız uyuşmazlık için üçüncü şablon; `X = 0` iken 1.1.0 ile aynı | AC-L5-2, ADR-007 Karar 12; tek satır kuralı (ADR-006 Karar 11) |
| C-22 | SBOM'da uyuşmazlık açıklaması (1.2.0) | Yeni `licenseComments` satırı yok; yalnız `NOASSERTION` | AC-L5-2 yalnız `NOASSERTION` ister; CycloneDX'te karşılığı yok; değişiklik yüzeyini küçük tutmak |
| C-23 | NOTICE `Reason:` önceliği (1.2.0) | Satır 15, satır 14'ten sonra ve satır 1–2'den önce | Uyuşmazlık yalnız F4 sonrası taramalarda oluşur; `not_attempted` genel nedeninden daha belirgin |
| C-25 | Excel `License Source` NuGet metinleri (1.4.0) | `none (license file in package, not classified)` ve `none (license URL not classified)`; öncelik L-5 metni > `file` > `url` > ipucu metni > `none` | REQ-006 AC-P21-5/6 "sabit metin"; ADR-008 Karar 12 öncelik; mevcut `none (…)` deseni; kaynak değeri `none` ile tutarlı |
| C-26 | NOTICE'ta `type="file"` / sınıflandırılmamış URL (1.4.0) | Metinsiz girdide tek `Reason:` satırına sabit önek + `; ` + mevcut neden; metinli girdide satır yok | Tek `Reason:` satırı biçimi (bölüm 3.4) korunur; okuyucu hem lisansın nerede olduğunu hem dosyanın neden eklenmediğini görür |
| C-27 | SBOM'da `license_unclassified` (1.4.0) | Yalnız `NOASSERTION`; yeni `licenseComments` satırı yok | C-22 emsali; ADR-008 Karar 12 yalnız `NOASSERTION` tanımlar; CycloneDX'te karşılığı yok; değişiklik yüzeyi küçük |
| C-28 | NOTICE NuGet tekillik anahtarı (1.4.0) | `(dotnet, asciiLower(ad), asciiLower(sürüm))`; gösterilen ad/sürüm bayt sırasıyla en küçük satırınki | NuGet kimlik/sürümleri harf duyarsız (ADR-008 Karar 4, netleştirme 6); zenginleştirme anahtarı küçük harfli; "her anahtar tam bir kez" (bölüm 3.3) |
| C-29 | Excel `Dependencies.License` NuGet'te boşken (1.4.0) | Ekosistemden bağımsız mevcut kural: ifade yoksa boş metin; AC-P21-7 `License Source` + `NOASSERTION` bulgusuyla karşılanır | ADR-008 Karar 12 `License` sütununu değiştirmez; npm/PyPI golden'ları değişmez (AC-G-9). **Product-analyst REQ-006 r2'de AC-P21-7 metnini buna göre netleştirmelidir** (`Dependencies.License` değil, lisans bulgusu + kaynak metni) |
| C-30 | NOTICE biçim numarası (1.4.0) | `NOTICE format: 1` kalır | Bölüm 3 yapısı değişmez; yalnız değer/etiket eklemesi (C-20 kuralı) |
| C-31 | NuGet `no_candidate` nedeni (1.4.0) | `package archive not downloaded (no lockfile integrity value)` (satır 7a); npm/PyPI satır 7 değişmez | REQ-006 AC-P21-11 "bütünlük değeri olmadığı için arşiv indirilmedi"; noktalı virgülsüz biçim önekle birleşince tek ayraç kalır |
| C-32 | `lock_integrity` NuGet anlamı (1.4.0) | Varsayılan `not_comparable`; `match` = ham **veya** imzalı içerik özeti eşit; birden çok farklı lock değeri → `mismatch`; `integrity_failed` yok | ADR-008 Karar 10, netleştirme 1, 2, 12 |
| C-33 | Arayüz seçeneği (1.4.0) | `<option value="dotnet">.NET (NuGet)</option>`, sonda, seçili değil; `app.js` ve API şeması değişmez | REQ-006 AC-P20-17, D-130; ADR-008 Karar 15 |
| C-34 | V-12 satırı (1.5.0) | Excel `Summary` son satırı ve PDF `Summary` son öğesi `Vulnerability Data Status`; beş sabit metin; tanınmayan değer → `not checked` | REQ-007 AC-P24-10, D-187; ADR-009 Karar 9; sona ekleme 5.1 deseni (C-9) |
| C-35 | PDF kesinti notu (1.5.0) | Üç tablo ayrı ayrı (40/40/50), yalnız `N > sınır` iken, birebir metin; sınırlar değişmez | REQ-007 AC-P24-11 (iki tablo yazıyordu), D-188; ADR-009 N-7 (üç tablo) |
| C-36 | NOTICE bağlantısı (1.5.0) | `download` eklenir, `target`/`rel` kaldırılır, `aria-label` eklenir; `href` aynı | REQ-007 D-186, AC-P24-8/9; ADR-009 Karar 10 |

**Handoff:** Bu contract non-trivial'dir. Implementation ve doğrulama sonunda
`docs/handoffs/REQ-004.md` güncellenmelidir (integration-release; Delivery Lead
takip eder). Handoff'a yazılacaklar: golden NOTICE dosyasının yolu, CycloneDX
XSD sırası teyidi (bölüm 6.3) ve bu contract'tan sapma varsa gerekçesi.
1.1.0 için ek olarak: contract revizyonunun güvenlik bulgularına (L-1, L-2,
I-3, M-1) atfı, düzeltmelerin durumu ve M-1 kapatılmadan merge edilecekse
insan risk kabulü. 1.2.0 (L-5) uygulaması REQ-005 kapsamında yapıldığı için
kanıtı `docs/handoffs/REQ-005.md`'ye yazılır (uyuşmazlık testleri, golden'ların
değişmediği). 1.4.0 (NuGet) uygulaması REQ-006 kapsamındadır; kanıt
`docs/handoffs/REQ-006.md`'ye yazılır (NuGet NOTICE/Excel/SBOM testleri, NuGet'siz
golden'ların değişmediği, purl harf biçimi teyidi — ADR-008 Karar 16 satır 6, imzalı
paket `match` release kapısı — AC-P21-16). 1.5.0 (V-12, kesinti notu, NOTICE bağlantısı)
uygulaması REQ-007 kapsamındadır; kanıt `docs/handoffs/REQ-007.md`'ye yazılır (V-12 beş değer,
kesinti notu testleri, güncellenen rapor testi beklenen değerleri listesi).

**ADR uyumu (1.1.0):** C-14 ve C-15, ADR-006 Karar 13 tablosundaki SPDX
tag-value ve Excel satırlarından daha sıkıdır. Bu bir gevşetme değil güvenlik
sertleştirmesidir; ADR-006 Karar 13'ün bu kurallarla uyumlu hâle getirilmesi
(not veya revizyon) solution-architect'e bildirilmelidir.

**NotebookLM / Obsidian:** kullanılmadı. Kaynaklar git'teki REQ-004 r1,
ADR-006 ve repo kodu (`src/controllers/sbomController.ts`,
`src/sbom/sbomService.ts`, `src/sbom/formats/*`, `src/reports/reportService.ts`,
`src/middleware/rbac.ts`, `src/middleware/securityHeaders.ts`,
`src/lib/httpError.ts`, `src/config/permissions.ts`, `public/app.js`).
1.1.0 için ek kaynaklar: `docs/quality/security-reports/REQ-004-security-review.md`,
`src/lib/outputText.ts`, `src/sbom/formats/spdx.ts`, `src/reports/reportService.ts`.

## 13. Revizyon geçmişi

| Sürüm | Tarih | Değişiklik | Dayanak | Onay |
| --- | --- | --- | --- | --- |
| 1.0.0 | 2026-10-10 | İlk sürüm. | REQ-004, ADR-006 | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10 |
| 1.1.0 | 2026-10-10 | **L-1:** SPDX tag-value tek satırlık değerlerde `<text>`/`</text>` (harf duyarsız) → `&lt;text&gt;`/`&lt;/text&gt;`, blok içi kuralla aynı; hiçbir tek satırlık değer ham `<text>` ile başlayamaz (6.1, 9 adım 4; C-14). **L-2:** Excel formül kalkanı tüm sayfalardaki tüm metin hücrelerine genişletildi (`Summary`, `Dependencies`, `Licenses`, `Vulnerabilities`); sayı hücreleri tipini korur; mevcut içerik kalkan öneki dışında değişmez (1, 5.1, 5.1a; C-15). **I-3:** adım 3'te U+0085/U+2028/U+2029 → boşluk; NOTICE ayraç kalkanı bu karakterlerden sonra da uygulanır (3.5, 3.6, 9; C-16). **M-1:** NOTICE metinleri parti parti okunur ve kesimden sonra okunmaz; çıktı biçimi değişmez (3.7; C-18). `NOTICE format: 1` kalır (11; C-17). Test yükümlülükleri eklendi (10). | `docs/quality/security-reports/REQ-004-security-review.md` (M-1, L-1, L-2, I-3) | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10 |
| 1.2.0 | 2026-10-10 | **L-5:** `scan_dependencies.lock_integrity` değerleri ve `mismatch` fail-safe saklama kuralı (4.4); Excel `License Source` `none (lockfile integrity mismatch)` (4.1, 5.1; C-19); NOTICE `Reason:` satır 15 `lockfile integrity does not match registry; license not verified` ve önceliği (4.3; C-23); `[registry]` uyuşmazlık sayısı `X` (8; C-21); SBOM `NOASSERTION`, yeni yorum satırı yok (6; C-22); `NOTICE format: 1` kalır (11; C-20); test yükümlülükleri (10). `match`/`not_comparable`/`NULL` çıktıları 1.1.0 ile aynı. | `docs/product/REQ-005.md` L-5 (AC-L5-1…4, D-103), ADR-007 Karar 12, 14 | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10 |
| 1.3.0 | 2026-10-10 | **L-2 (REQ-005 güvenlik incelemesi):** `REGISTRY_ENRICHMENT` F4 anahtarlarıyla aynı ayrıştırmaya bağlandı: `on/off/true/false/1/0/yes/no` (harf duyarsız), boş/tanımsız → açık, **diğer değer → kapalı** + yalnız ad içeren tek uyarı (4.2 notu; C-24). F3'teki "geçersiz → açık" davranışı değişti. Çıktı biçimleri, OpenAPI ve `NOTICE format: 1` değişmez. ADR-006 Karar 14 ve REQ-004 AC-P14-16 metinlerinin bu karara göre güncellenmesi solution-architect / product-analyst işidir. | `docs/quality/security-reports/REQ-005-security-review.md` (L-2); REQ-005 contract 1.1.0 bölüm 7.1 | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10 |
| 1.4.0 | 2026-10-11 | **REQ-006 F5 (NuGet):** `license_source` += `registry:nuget` (4.1); yeni `scan_dependencies.license_unclassified` (`file`/`url`) ve gösterimi (4.5; C-25…C-27); Excel `License Source` öncelik zinciri ve iki yeni metin (4.1, 5.1); NOTICE etiketi `nuget`, sıralama `npm` < `nuget` < `pypi`, NuGet tekillik anahtarı (3.3; C-28), NuGet alan notları (3.4), `.nupkg` lisans dosyaları (3.5), satır 7a NuGet `no_candidate` metni (C-31), satır 14'ün `dotnet` için kalkması (C-13 daraltıldı), `license_unclassified` öneki (4.3); `lock_integrity` NuGet anlamı (4.4; C-32); SBOM NuGet `L` ve purl `pkg:nuget/<id>@<sürüm>` harf biçimi korunarak (6); proje formu `.NET (NuGet)` seçeneği (7.1; C-33); `[registry]` sayımlarına NuGet, şablonlar değişmeden (8); `Dependencies.License` kuralı değişmez (C-29); `NOTICE format: 1` kalır (11; C-30); test yükümlülükleri (10); OpenAPI `info.version` 1.1.0 (bilgi amaçlı `LicenseSource` enum'una additive `registry:nuget`, `LicenseUnclassified` şeması). NuGet'siz taramalarda çıktılar 1.3.0 ile bayt bayt aynı. | `docs/product/REQ-006.md` r1 (AC-P20-17, -18, AC-P21-5…14, D-130, D-133, D-134, D-137, D-139, D-144); ADR-008 Karar 4, 9–12, 14–16 ve netleştirmeler 1–3, 12, 13 | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-11 |
| 1.5.0 | 2026-10-11 | **REQ-007 F6:** Excel `Summary` son satırı ve PDF `Summary` son öğesi `Vulnerability Data Status` (beş sabit metin; 5.3; C-34); PDF `Security Findings` (40), `License Findings` (40), `Dependency Inventory` (50) tablolarında `N > sınır` iken `Showing first <n> of <N>; see the Excel or CSV export for the full list.` notu (5.4; C-35); NOTICE bağlantısı `download` + `aria-label`, `target`/`rel` kaldırıldı, `href` aynı; tarama satırı bağlantılarının tamamı REQ-007 contract bölüm 8'de (7; C-36); 5.1a ve 5.2'ye istisna notları; test yükümlülükleri (10); sürüm notu (11). Mevcut satır/sütunlar, NOTICE (`NOTICE format: 1`), SBOM ve OpenAPI (1.1.0) değişmez; göç yok. | `docs/product/REQ-007.md` r1 (AC-P24-8, -10, -11, -12; D-186, D-187, D-188); ADR-009 Karar 9, 10, N-7; `docs/contracts/REQ-007-cli-and-exports.md` 1.0.0 | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-11 |
