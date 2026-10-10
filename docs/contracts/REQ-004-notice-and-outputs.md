# REQ-004 NOTICE ve Çıktı Contract'ı (F3 — P-14, P-15, P-16, L-6)

- **Status:** Accepted — Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-10
- **status:** approved
- **Sürüm:** 1.1.0 (revizyon: bkz. bölüm 13)
- **Tarih:** 2026-10-10
- **Makine okunur contract:** `docs/contracts/REQ-004-notice-api.openapi.yaml` (OpenAPI 3.0.3;
  `info.version` 1.0.0 kalır — 1.1.0 revizyonu uç nokta yüzeyini değiştirmez)
- **Revizyon dayanağı (1.1.0):** `docs/quality/security-reports/REQ-004-security-review.md`
  bulguları L-1, L-2, I-3 ve M-1
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
- **Sıralama anahtarı:** `(ekosistem etiketi, küçük harfli ad, ad, sürüm)`.
  - Ekosistem etiketi: `nodejs` → `npm`, `python` → `pypi`, diğerleri enum
    değeri olduğu gibi.
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
| `lockfile (unverified)` | Lock ipucu, doğrulanmadı (AC-L6-3) | `lockfile (unverified)` | `lockfile (unverified)` |
| `none` | Etkin lisans yok | `none`; durum `no_license` ve ipucu varsa `none (lockfile hint ignored: <ipucu>)` | `none` |
| `NULL` | F3 öncesi tarama | boş hücre | `not recorded` |

- Uyuşmazlık: `license_hint_differs = true` (yalnız durum `ok` iken dolu).
- `<ipucu>` = `license_lock_hint`; tek satırlık alan kuralı (bölüm 9) ve 200
  kod noktası kesimi (saklanırken zaten kesilmiştir; çıktıda yeniden
  uygulanır).
- NOTICE'ta uyuşmazlık ve yok sayılan ipucu gösterilmez (NOTICE dağıtım
  belgesidir; L-6 görünürlüğü raporun işidir).

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

### 4.3 `notice_status` ve NOTICE `Reason:` metni

`Reason:` yalnız metinsiz girdide yazılır. Seçim sırası: önce satır 14, sonra
satır 1–2, sonra `notice_status` (satır 3–13); ilk eşleşen satır kazanır.

| # | Koşul | `Reason:` metni |
| --- | --- | --- |
| 1 | F3 öncesi tarama ve arşiv önbelleğinde kayıt yok | `scan predates license enrichment; rescan required` |
| 2 | `notice_archive_id` `NULL` ama `notice_status` önbelleğe yazılan bir sonuç (`collected`, `no_license_file`, `unsupported_format`, `limit_exceeded`) — önbellek temizlenmiş | `license file data no longer cached; rescan required` |
| 3 | `collected`, ama hiç metinli öğe yok (hepsi atlanmış) | `license files exceed size limits` |
| 4 | `no_license_file` | `no license file in package archive` |
| 5 | `unsupported_format` | `package archive format not supported` |
| 6 | `limit_exceeded` | `archive exceeds size limit` |
| 7 | `no_candidate` | `no verifiable package archive available` |
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
| 14 | Ekosistem `nodejs`/`python` dışında | `license enrichment not supported for this ecosystem` |

- Arşiv kaydının `outcome_detail` değeri NOTICE'a yazılmaz.
- Önbelleğe yazılan sonuçlar: `collected`, `no_license_file`,
  `unsupported_format`, `limit_exceeded`. Diğerleri geçicidir; tarama satırında
  durur, önbellekte yoktur (ADR-006 Karar 7, 10).

## 5. Excel ve PDF raporları

### 5.1 Excel `Dependencies` sayfası

Mevcut 7 sütun aynen kalır (1.1.0: formül kalkanı öneki hariç, bölüm
5.1a); iki yeni sütun **sona** eklenir:

| # | Başlık (birebir) | `key` | Genişlik | Değer |
| --- | --- | --- | --- | --- |
| 1–7 | `Name`, `Version`, `Ecosystem`, `Scope`, `Manifest`, `Depth`, `PURL` | mevcut | mevcut | mevcut |
| 8 | `License` | `license` | 32 | `license_expression`; boş/`NULL` → boş metin |
| 9 | `License Source` | `licenseSource` | 48 | bölüm 4.1 "Excel" sütunu; F3 öncesi → boş metin |

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
- `Summary`, `Licenses` ve `Vulnerabilities` sayfalarının yapısı **değişmez**.

### 5.2 PDF bağımlılık tablosu

- Tablo: mevcut "Dependency Inventory" bölümü (yalnız `project_report` ve
  `audit_evidence` türlerinde bulunur; diğer türlerde bağımlılık tablosu yoktur,
  bu contract eklemez).
- Başlıklar: `Package | Eco | Scope | Manifest | Depth | License` (yeni sütun
  sonda).
- `License` değeri: `license_expression`; boş/`NULL` (F3 öncesi dahil) →
  `n/a`. Mevcut `writePdfRows` 28 karakter kesimi uygulanır.
- Değer bölüm 9 tek satırlık alan kuralından geçer.
- "License Findings" bölümü ve diğer bölümler değişmez.

## 6. SBOM alan anlamları

Ortak: bağımlılıklar mevcut gibi purl'e göre tekilleştirilir. Etkin lisans,
`license_source`, ipucu ve telif bilgisi purl'ün ilk `scan_dependencies`
satırından okunur (aynı anahtarın satırları aynı değeri taşır). Telif
satırları `notice_archive_id` → `registry_archive_cache.copyright_lines`
üzerinden gelir; `packages.copyright_text` artık okunmaz (ADR-006 Karar 9).

**Etkin lisans girdisi (`L`):**

- F3 sonrası tarama: `license_expression` (boş/`NULL` → yok).
- F3 öncesi tarama (`license_source IS NULL`): bugünkü kaynak — paketin
  `license_findings` değerlerinden (`normalizedLicense`, yoksa
  `detectedLicense`) tekrarsız, ilk görülme sırasıyla ` AND ` ile birleşik
  ifade; hiç yoksa yok.

**Geçerlilik:** `spdxExpression.canonicalize(L)` (AC-P16-3). Geçerliyse
kanonik ifade `C`; değilse "geçersiz".

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
- **Paralel çalışma:** frontend bu bölüme göre, backend bölüm 2–3'e göre
  birbirini beklemeden çalışır. Ortak tek arayüz `GET /api/scans/{id}/notice`
  yoludur.

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
| security-red-team | NOTICE ayraç sahteciliği, tag-value/XML/Excel enjeksiyonu, uç noktada yetki ve hata gövdesi sızıntısı incelemesi. 1.1.0 sonrası M-1 ve L-1 düzeltmelerinin merge öncesi yeniden incelenmesi (güvenlik raporu "Merge kararı"). |

## 11. Sürümleme

- Contract sürümü **1.1.0** (minor: güvenlik sertleştirmesi; uç nokta,
  şema, sütun ve değer kümeleri değişmez). API yolu sürümlenmez (`/api/...`,
  mevcut desen). OpenAPI `info.version` 1.0.0 kalır.
- **NOTICE biçim sürümü 1.1.0'da `1` kalır.** I-3 kalkan genişletmesi ve
  adım 3 değişikliği yalnız U+2028/U+2029 içeren girdilerde NOTICE baytlarını
  değiştirir. F3 henüz yayımlanmadığı (branch merge edilmediği) için
  `NOTICE format: 1` çıktısını görmüş bir tüketici yoktur; numara artırılmaz
  (karar C-17). Aşağıdaki kural F3 merge edildikten sonraki değişikliklere
  uygulanır. Golden dosyalar bu karakterleri içermiyorsa değişmez; içeriyorsa
  güncellenir.
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
| C-13 | Desteklenmeyen ekosistem | NOTICE nedeni `license enrichment not supported for this ecosystem`; F3 ayrıştırıcıları yalnız `nodejs`/`python` ürettiği için bugün oluşmaz | `tech_ecosystem` enum'u daha geniş |
| C-14 | Tag-value tek satırlık değerlerde `<text>` (1.1.0) | Önerilen seçenek: değerin yalnız başı değil **her yerindeki** `<text>`/`</text>` (harf duyarsız) blok içi kaçışla birebir aynı biçimde `&lt;text&gt;`/`&lt;/text&gt;` olur; adım 1–3'ten sonra uygulanır | Güvenlik raporu L-1; ADR-006 Karar 13 tag-value kaçışını yalnız bloklar için tanımlıyordu |
| C-15 | Excel formül kalkanının kapsamı (1.1.0) | Önerilen seçenek: tüm sayfalardaki tüm metin hücreleri; sayı hücreleri tipini korur; mevcut sütunlara yalnız kalkan eklenir (adım 1–3 eklenmez) | Güvenlik raporu L-2; ADR-006 Karar 13 "Mevcut sütunlar değişmez" ve D-63 "`Licenses` sayfası değişmez" ifadeleri bu güvenlik istisnasıyla daraltılır (yapı değişmez, yalnız tetikleyici önekli değerler) |
| C-16 | Unicode satır ayırıcıları (1.1.0) | U+0085/U+2028/U+2029 tek satırlık değerlerde boşluk; çok satırlı NOTICE metninde korunur ama ayraç kalkanı için satır sonu sayılır | Güvenlik raporu I-3 |
| C-17 | NOTICE biçim numarası (1.1.0) | `NOTICE format: 1` kalır | F3 yayımlanmadı; numarayı artırmak tüketicisi olmayan bir sürüm farkı yaratırdı |
| C-18 | NOTICE bellek sınırı (1.1.0) | Metinler parti parti okunur, ilk kesimden sonra hiç okunmaz; çıktı biçimi değişmez | Güvenlik raporu M-1 |

**Handoff:** Bu contract non-trivial'dir. Implementation ve doğrulama sonunda
`docs/handoffs/REQ-004.md` güncellenmelidir (integration-release; Delivery Lead
takip eder). Handoff'a yazılacaklar: golden NOTICE dosyasının yolu, CycloneDX
XSD sırası teyidi (bölüm 6.3) ve bu contract'tan sapma varsa gerekçesi.
1.1.0 için ek olarak: contract revizyonunun güvenlik bulgularına (L-1, L-2,
I-3, M-1) atfı, düzeltmelerin durumu ve M-1 kapatılmadan merge edilecekse
insan risk kabulü.

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
