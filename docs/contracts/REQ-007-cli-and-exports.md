# REQ-007 CLI ve Tek Tık Çıktı Contract'ı (F6 — P-22, P-23, P-24, API anahtarı ekranı, V-12)

- **Status:** Accepted — Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-11
- **status:** approved
- **Sürüm:** 1.0.0 (revizyon: bkz. bölüm 14)
- **Tarih:** 2026-10-11
- **Makine okunur contract:** `docs/contracts/REQ-007-exports-api.openapi.yaml` (OpenAPI 3.0.3,
  `info.version` 1.0.0 — yalnız üç yeni `GET` uç noktası; CLI JSON çıktı şeması bölüm 5.6'dadır)
- **Dayanak:** `docs/product/REQ-007.md` r1 (AC-G-1…9, AC-P22-1…18, AC-P23-1…9, AC-P24-1…12,
  AC-AK-1…4; D-161…D-193), `docs/architecture/adr/ADR-009-cli-ci-ve-tek-tik-ciktilar.md`
  (Karar 1–11, "REQ-007 netleştirmeleri" N-1…N-8). REQ-007 r1 ile ADR-009'un ayrıştığı yerde
  ADR-009 ve bu contract'taki ana oturum notları izlenir (bölüm 13, X-1…X-4). Paralel yürüyen
  REQ-007 r2 bu contract'la hizalanmalıdır.
- **İlgili contract'lar:** `REQ-002-auth-api.md` (kimlik, API anahtarı biçimi, hata gövdesi,
  Host/Origin), `REQ-004-notice-and-outputs.md` **1.5.0** (V-12 satırı, PDF kesinti notu, NOTICE
  bağlantı öznitelikleri), `REQ-005-vulnerability-data.md` 1.2.0 (durum uç noktası; **değişmez**,
  bölüm 4.5).

> **Onay kaydı.** Kullanıcının 2026-10-11 daimi talimatı ("bana soru sorma önerilen seçeneklerle
> devam et"; REQ-007 ve ADR-009'da kayıtlı) gereği tüm seçimler önerilen seçenekle yapılmıştır.
> Karar ana oturum aracılığıyla iletilmiştir; kullanıcının bu dosyayı gözden geçirip commit etmesi
> kaydı kesinleştirir. Açık soru yoktur.
>
> **Paralel çalışma uyarısı.** Bu contract `Accepted` olsa da backend (`src/**`, `package.json`
> `bin`, `README.md`, `.github/workflows/**`), frontend (`public/**`) ve test (`tests/**`)
> çalışması `docs/ownership/REQ-007.json` `status: approved` olmadan **başlatılmamalıdır**
> (`devflow-manifest 007` kullanıcı tarafından). Manifest onaylandıktan sonra frontend (bölüm 8,
> 9) ve backend (bölüm 2–7) bu contract'a göre birbirini beklemeden çalışabilir; aynı branch'te
> tek yazar kuralı gereği sırayı Delivery Lead belirler.
>
> **İnsan onayı kapıları (contract onayıyla kapanmış sayılmaz):**
> - **Kimlik yüzeyi:** API anahtarı ekranı ve `bootstrap` (sunucu kimlik kuralı değişmez; yeni
>   rol/izin yok). `bootstrap` parolasız bir veritabanına bilinmeyen bir admin parolası koyar
>   (bölüm 3.3) — gerçek veriye sahip bir veritabanında çalıştırılması kullanıcı verisini
>   etkiler; bu nedenle `--new-database` açık beyanı zorunludur.
> - **Dış sistem:** GitHub'a push ve iş akışı çalıştırması (ana oturum); `online` kipte
>   OSV/kayıt defteri erişimi (yalnız elle, `workflow_dispatch`).
> - **Veritabanı:** göç **yoktur**; yeni bağımlılık **yoktur** (AC-G-5, AC-G-6).

## İçindekiler

1. Kapsam ve geriye uyumluluk
2. CLI: giriş noktası, komutlar, seçenekler
3. CLI: yapılandırma (adres, anahtar) ve `bootstrap`
4. CLI: `scan` akışı, `--fail-on`, veri tamlığı
5. CLI: çıkış kodları ve çıktı (text, JSON)
6. Eşzamanlı çıktı uç noktaları
7. CSV biçimi
8. Arayüz: tarama satırı indirme bağlantıları
9. Arayüz: API Keys ekranı
10. GitHub Actions iş akışları (contract'a bağlı noktalar)
11. Test yükümlülükleri
12. Sürümleme
13. Karar kaydı ve netleştirmeler
14. Revizyon geçmişi

## 1. Kapsam ve geriye uyumluluk

- **Yeni sunucu yüzeyi yalnız** bölüm 6'daki üç `GET` uç noktasıdır (AC-G-4, D-175, D-182).
  Mevcut uç noktaların JSON şemaları, durum kodları ve hata kodları değişmez; tek yeni hata kodu
  `export_busy`'dir (bölüm 6.5).
- CLI yalnız mevcut uç noktaları kullanır: `GET /api/projects`, `POST /api/projects`,
  `POST /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/findings`,
  `GET /api/vulnerability-data/status`, `POST /api/auth/setup`, `POST /api/auth/api-keys`,
  `POST /api/auth/logout`. Arayüz ayrıca `GET /api/auth/api-keys` ve
  `DELETE /api/auth/api-keys/{id}`'yi kullanır.
- Excel/PDF içeriği yalnız REQ-004 contract 1.5.0 bölüm 5.3–5.4 kadar değişir (V-12 satırı, PDF
  kesinti notu). NOTICE ve SBOM uç noktaları, asenkron rapor uç noktaları, ExportWorker ve
  `reports` satırları değişmez (AC-P24-12).
- Göç yok, yeni bağımlılık yok; `package.json`'a yalnız `"bin": { "oss-risk": "dist/cli/index.js" }`
  eklenir, sürüm `1.0.0` kalır (D-193).

## 2. CLI: giriş noktası, komutlar, seçenekler

### 2.1 Giriş noktası ve modül sınırı (AC-P22-1, ADR-009 Karar 1)

| Kural | Değer |
| --- | --- |
| Giriş dosyası | `src/cli/index.ts` → `dist/cli/index.js`; ilk satır `#!/usr/bin/env node`. `process.exit()` çağrılmaz; `process.exitCode` kullanılır. |
| Desteklenen çağrı | `node dist/cli/index.js <komut> …` (iş akışları ve README örnekleri). `npx oss-risk` repo içinde kolaylıktır, doğrulanması gerekir (N-5). |
| İçe aktarma | Yalnız Node yerleşikleri, `src/cli/**` ve `src/lib/outputText.ts` (+ geçişli `textSanitize.ts`). `express`, `pg`, `exceljs`, `pdfkit`, `dotenv`, `src/config/**`, `src/lib/apiKeys.ts` yasak. `.env` okunmaz. |
| Sürüm | `--version` çalışma anında `path.join(__dirname, '..', '..', 'package.json')` dosyasının `version` alanını yazar (`1.0.0`). |
| HTTP | `node:http`/`node:https` ve istemci başına ayrılmış `Agent({ keepAlive: false })`; `fetch` ve küresel agent yok; `HTTP(S)_PROXY`/`NODE_USE_ENV_PROXY` etkisiz; TLS doğrulaması kapatılamaz. |

### 2.2 Dilbilgisi (AC-P22-2)

```
oss-risk scan --project <id|ad> [--url <adres>] [--fail-on none|low|medium|high|critical]
              [--format text|json] [--timeout <saniye>] [--allow-incomplete]
oss-risk bootstrap --new-database --key-file <yol> [--url <adres>]
              [--project-name <ad> --project-path <klasör>]
oss-risk --help | -h | --version | -V
oss-risk <komut> --help | -h
```

| Komut | Seçenek | Değer | Zorunlu | Varsayılan | Geçersizse |
| --- | --- | --- | --- | --- | --- |
| `scan` | `--project` | UUID veya proje adı (bölüm 4.1) | evet | — | yoksa 2 |
| `scan` | `--url` | adres (bölüm 3.1) | hayır | `OSS_RISK_URL` > `http://127.0.0.1:3001` | 2 |
| `scan` | `--fail-on` | `none`, `low`, `medium`, `high`, `critical` (harf duyarlı) | hayır | `high` | 2 |
| `scan` | `--format` | `text`, `json` | hayır | `text` | 2 (çıktı text) |
| `scan` | `--timeout` | `^[0-9]+$`, 10–86 400 | hayır | `1800` | 2 |
| `scan` | `--allow-incomplete` | bayrak (değer almaz; `--allow-incomplete=x` → 2) | hayır | kapalı | 2 |
| `bootstrap` | `--new-database` | bayrak (değer almaz) | **evet** (X-1) | — | yoksa 2 |
| `bootstrap` | `--key-file` | dosya yolu | evet | — | yoksa 2 |
| `bootstrap` | `--url` | adres, yalnız loopback (bölüm 3.1) | hayır | `OSS_RISK_URL` > `http://127.0.0.1:3001` | 2 |
| `bootstrap` | `--project-name` | 1–255 karakter (sunucu doğrular) | `--project-path` ile birlikte | — | biri tek başına → 2 |
| `bootstrap` | `--project-path` | klasör yolu; `path.resolve` ile mutlaklaştırılır | `--project-name` ile birlikte | — | biri tek başına → 2 |

- Biçim `--ad değer` veya `--ad=değer`. `--` desteklenmez. Kısa biçim yalnız `-h` ve `-V`.
- **Kullanım hatası → 2:** komut yok, bilinmeyen komut, bilinmeyen seçenek, eksik değer (sonraki
  argüman `-` ile başlıyorsa değer sayılmaz), tekrarlanan seçenek, konumsal fazla argüman,
  bayrağa değer verilmesi, başka komutun seçeneği (ör. `scan --key-file`).
- **`--api-key`, `--key`, `--token`** (her iki biçimde, her komutta) → 2 ve sabit metin
  `API key must be provided via OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE`. Değer, uzunluğu veya
  argümanın kendisi hiçbir çıktıya kopyalanmaz. Bu denetim diğer kullanım hatalarından önce
  yapılır.
- **`--help`/`-h`** argüman listesinde varsa (ve `--api-key` ailesi yoksa): komut verilmişse o
  komutun, verilmemişse genel kullanım metni **stdout**'a yazılır, çıkış 0. **`--version`/`-V`**
  → `1.0.0\n` stdout'a, çıkış 0. İkisi birlikteyse `--help` kazanır. Bu yollar ağ isteği
  yapmaz, anahtar ve dosya okumaz.
- Kullanım hatası metni stderr'e tek satır:
  `oss-risk: error: <mesaj> (see: oss-risk <komut> --help)` (komut bilinmiyorsa `oss-risk --help`).
  `--format json` ayrıştırılabilmişse hata JSON olarak stdout'a yazılır (bölüm 5.5), aksi halde
  text.

## 3. CLI: yapılandırma (adres, anahtar) ve `bootstrap`

### 3.1 Sunucu adresi (AC-P22-4, ADR-009 Karar 2)

- Kaynak sırası: `--url` > `OSS_RISK_URL` (boş metin tanımsız sayılır) > `http://127.0.0.1:3001`.
- `new URL()` ile ayrıştırılır; ayrıştırılamazsa 2. Protokol `http:` veya `https:`;
  `username`, `password`, `search`, `hash` boş; `pathname` yalnız `/` (sondaki `/` serbest).
  Aksi halde 2 (`invalid_url`).
- **Loopback kümesi** (URL `hostname` biçimiyle): `127.0.0.1`, `localhost`, `[::1]`. Loopback
  dışı + `http:` → 2 (`insecure_url`), **sıfır bağlantı**.
- Etkin port: URL'deki port, yoksa `http` 80 / `https` 443.
- Loopback `http:` isteklerinde `Host: <hostname>:<etkin port>` açıkça gönderilir (ör.
  `127.0.0.1:3001`, `[::1]:3001`, port yazılmamışsa `localhost:80`). `Origin:
  http://<hostname>:<etkin port>` yalnız oturumlu yazma isteklerinde (bootstrap: setup,
  api-keys, logout) gönderilir; Bearer isteklerinde gönderilmez.
- Loopback dışı `https:` yalnız TLS sonlandıran bir ara katman `Host`'u sunucunun izin listesine
  uygun iletirse çalışır; aksi halde sunucu `403 host_rejected` döner → 2 (N-4).
- `3xx` yanıtı → 3 (`redirect`, "server responded with a redirect; not followed"); `Location`
  okunmaz, yazılmaz, izlenmez.

### 3.2 API anahtarı (AC-P22-3, D-164; yalnız `scan`)

| Kural | Değer |
| --- | --- |
| Kaynaklar | `OSS_RISK_API_KEY` (değer) **veya** `OSS_RISK_API_KEY_FILE` (dosya yolu). Boş metin tanımsız sayılır. |
| İkisi birden / hiçbiri | 2 (`invalid_api_key_config`): `set exactly one of OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE` |
| Dosya | UTF-8 okunur; boyut > 1024 bayt → 2; okunamıyor/yok → 2 (yol metne sanitize edilerek yazılabilir; içerik asla); baştaki/sondaki boşluk (`trim()`) atılır. |
| Biçim | `^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$`; uymazsa 2 (`API key has an invalid format`). Metin değeri, uzunluğu veya önekini içermez. Kalıp CLI'da ayrı sabittir; bir test `src/lib/apiKeys.ts` `API_KEY_RE` ile kaynak metninin eşitliğini doğrular. |
| İletim | Yalnız `Authorization: Bearer <anahtar>`. URL, gövde, hata nesnesi, log ve çıktıya konmaz. İstek seçenek nesnesi serileştirilmez. |
| Redaksiyon | `output.ts` yazmadan önce anahtarın tamamını ve gizli kısmı `S`'yi (ve bootstrap parolasını) arar, bulursa `[redacted]` koyar; testler bu yolun hiç tetiklenmediğini de doğrular. Yalnız `ossr_<P>` öneki görünebilir. |
| `bootstrap` | Anahtar ortam değişkenlerini okumaz ve yok sayar. |

Anahtar denetimi adres denetiminden sonra, ilk ağ isteğinden önce yapılır.

### 3.3 `bootstrap` (AC-P22-17, D-174, ADR-009 Karar 6, X-1)

Amaç: geçici bir CI veritabanında tarayıcı olmadan ilk kurulum + API anahtarı. Sunucuda hiçbir
kod veya kural değişmez; tarayıcıdaki ilk kurulumla aynı uç noktalar kullanılır.

**Ön koşullar (hepsi ağdan önce, sırayla):**

1. Kullanım denetimi (bölüm 2.2). `--new-database` yoksa → 2 (`new_database_required`), metin:
   `bootstrap requires --new-database: it sets an unknown admin password and is meant only for a new, temporary database`.
   Dosya oluşturulmaz, istek yapılmaz.
2. Adres denetimi; loopback değilse → 2 (`not_loopback`), sıfır bağlantı.
3. **Dosya rezervasyonu:** `fs.open(path, 'wx', 0o600)`. `EEXIST` → 2 (`key_file_exists`), sıfır
   istek. POSIX'te açıldıktan sonra `fstat` ile `mode & 0o077 === 0` doğrulanır (değilse dosya
   silinir, 2). Windows'ta mod biti yok sayılır (klasör ACL'i devralınır; alt süreç
   çalıştırılmaz).

**Akış:**

| # | İstek | Başlıklar / gövde | Başarı | Hata → çıkış |
| --- | --- | --- | --- | --- |
| 4 | — | Parola `randomBytes(32).toString('base64url')` (43 karakter), yalnız yerel değişkende | — | — |
| 5 | `POST /api/auth/setup` | `Host`, `Origin`, `Content-Type: application/json`, `{"password": …}` | `201`; `Set-Cookie`'nin ilk `ad=değer` çifti (ad `^[A-Za-z0-9_]+$`, değer boş değil; değilse 3) | `409 setup_already_done` → **4** (`already_initialised`, "database already initialised; bootstrap only works on an empty database"); `403 host_rejected`/`origin_rejected` → 2; diğer → 3 |
| 6 | `POST /api/auth/api-keys` | `Host`, `Origin`, `Cookie: <ad>=<değer>`, `{"name":"bootstrap"}` | `201`; `data.key` bölüm 3.2 kalıbına uymalı (değilse 3) | `401`/`403 forbidden` → 4; `403 host_rejected`/`origin_rejected` → 2; diğer → 3 |
| 7 | — | Anahtar rezerve dosyaya **yeni satırsız** yazılır, `fsync`, kapatılır | — | yazma hatası → 3 |
| 8 | `POST /api/projects` (yalnız iki proje seçeneği verildiyse) | `Host`, `Authorization: Bearer <yeni anahtar>`, `{"name": <ad>, "repoUrl": path.resolve(<klasör>), "ecosystems": []}` | `201`; `data.id` | `400` (ör. `path_not_allowed`) → 2, sunucu `message` sanitize edilerek; `401`/`403 forbidden` → 4; diğer → 3 |
| 9 | `POST /api/auth/logout` | `Host`, `Origin`, `Cookie` | `204` | yalnız uyarı (`logout failed; the session expires on its own`); çıkış kodu değişmez |

**Hata temizliği:** adım 5 başarısızsa (409 dahil) rezerve dosya silinir. Adım 5 başarılı olup
sonraki bir adım başarısızsa: dosya boşsa silinir, anahtar yazılmışsa dosya kalır (proje
oluşturma hatası) ve hata metnine şu ek eklenir:
`database is now initialised without a usable password; recreate the temporary database`
(yalnız adım 6–7 hatalarında). Adım 8 hatasında logout yine denenir.

**Çıktı (text; bootstrap'ta `--format` yoktur):**

- stdout, başarıda tam olarak:
  ```
  API key written to <mutlak dosya yolu>
  Project ID: <uuid>            (yalnız proje oluşturulduysa)
  ```
- stderr: ilerleme `oss-risk: initialising server <köken>`, uyarılar `oss-risk: warning: …`,
  hata `oss-risk: error: …`. Parola, anahtar, `S`, çerez değeri hiçbir satırda yoktur.
- Çıkış kodları: 0 başarı; 2, 3, 4 yukarıdaki gibi. 1 ve 5 kullanılmaz.

**Bilinen sınır (N-2):** sunucu setup'ı ADR-001 Karar 12 kurtarma dalında (parolası boşaltılmış
aktif admin) da `201` ile kabul eder ve istemci iki dalı ayıramaz; `bootstrap`'ın gerçek güvencesi
"parolası olmayan veritabanı"dır. `--new-database` bu riski kullanıcının açık beyanına bağlar;
README uyarısı zorunludur. Kurtarma tekrar Karar 12 yoluyla yapılabilir.

## 4. CLI: `scan` akışı, `--fail-on`, veri tamlığı

### 4.1 Akış ve kullanılan uç noktalar (AC-P22-5…8, ADR-009 Karar 3)

| # | Adım | Gerekli izin | Hata → çıkış |
| --- | --- | --- | --- |
| 1 | Kullanım, adres, anahtar denetimi (ağ yok) | — | 2 |
| 2 | `--project` `trim()` edilir. `/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i` ise kimlik olarak kullanılır (ad araması yapılmaz). Değilse `GET /api/projects` → `data[]` içinde `name` değerine kod noktası düzeyinde birebir eşit öğeler: 0 → 2 (`project_not_found`, "project not found"); >1 → 2 (`project_ambiguous`, "project name is ambiguous; use the project id"). | `projects:read` | `401` → 4; `403 forbidden` → 4; diğer bölüm 5.2 |
| 3 | `POST /api/scans`, gövde yalnız `{"projectId": "<id>"}`. **Yeniden denenmez.** Yanıt `data.id` = tarama kimliği; `data.project_name` UUID yolunda proje adıdır. | `scans:write` | `400` (`project_source_missing`, `path_not_allowed`, `repo_url_not_allowed`, `invalid_request`) → 2 (`project_rejected`, sunucu `message` sanitize); `404` → 2 (`project_not_found`); bağlantı hatası/zaman aşımı → 3 |
| 4 | Yoklama `GET /api/scans/{id}` her 2 sn; uç durumlar `completed`, `failed`, `cancelled`, `timeout`. Bütçe `--timeout` (POST başarısından uç duruma kadar, enjekte saat). Aşımda 3 (`wait_timeout`): `timed out waiting for scan <id>; the scan continues on the server`. | `scans:read` | `failed`/`cancelled`/`timeout` → 3 (`scan_failed`), metin `scan <id> ended with status <durum>: <error_message>` (`error_message` `singleLine` + C0/C1 silme + 500 kod noktası; `null` ise `: …` kısmı yok) |
| 5 | `GET /api/scans/{id}/findings` (tek yanıt, sayfalamasız). `data` dizi değilse 3. | `findings:read` | `401`/`403` → 4 |
| 6 | `GET /api/vulnerability-data/status` **her zaman** (N-8) | `scans:read` | **Hiçbir hata çıkış kodu üretmez**: `401`/`403` dahil her hata ve eşleşmeme durumu `unknown` sayılır (bölüm 4.4) |

- **Geçici hata ve yeniden deneme** (yalnız adım 2, 4, 5, 6'daki idempotent `GET`'ler): bağlantı
  hatası, 30 sn istek zaman aşımı, `5xx`. Art arda 3 geçici hata → 3 (`network_error`); başarılı
  yanıt sayacı sıfırlar. Denemeler arası bekleme 2 sn. `4xx` geçici değildir.
- Bulgu ve durum okumaları `--timeout` bütçesine dahil değildir (her biri 30 sn istek sınırıyla).
- CLI en fazla bir eşzamanlı istek yapar; komutlar sıralı `await` eder.
- CLI proje oluşturmaz; `--path` yoktur (D-166).

### 4.2 Sayılan bulgular (AC-P22-8, D-167)

Bulgu satırı alanları (mevcut `GET /api/scans/{id}/findings`; değişmez): `finding_type`,
`status`, `severity`, `cve_id`, `ghsa_id`, `risk_level`, `applied_policy`,
`normalized_license`, `detected_license`, `package_name`, `package_version`.

- Sayılan: `status ∈ {open, in_review}` **ve** `finding_type ∈ {security, license}`.
- Sayılmayan: `resolved`, `accepted`, `false_positive`, `wont_fix`; `copyright` ve tanınmayan
  türler.

### 4.3 Seviye eşlemesi (AC-P22-9, D-168)

Sıra `low < medium < high < critical`. "—" = seviye yok; hiçbir eşiği tetiklemez ve `counts`'a
girmez.

| Tür | Girdi | Etkin seviye |
| --- | --- | --- |
| security | `severity` ∈ `low`, `medium`, `high`, `critical` | aynen |
| security | `severity` = `none` | — |
| security | `severity` `null` veya tanınmayan | `high` |
| license | `risk_level` = `safe` | — (politika tabanı yoksa) |
| license | `risk_level` ∈ `low`, `medium`, `high`, `critical` | aynen |
| license | `risk_level` = `unknown`, `null` veya tanınmayan | `high` |
| license | `applied_policy` = `prohibited` / `restricted` / `review_required` | taban `critical` / `high` / `medium` |
| license | `applied_policy` = `approved`, `null` veya tanınmayan | taban yok |
| license | birleşim | etkin = max(risk seviyesi, politika tabanı); ikisi de yoksa — |

Zorunlu test satırları (AC-P22-9): `severity=critical` → critical; `severity=null` → high;
`risk_level=unknown` → high; `risk_level=safe, applied_policy=prohibited` → critical;
`risk_level=medium, applied_policy=review_required` → medium; `risk_level=safe,
applied_policy=null` → —.

**Kimlik (çıktı için):** security `cve_id ?? ghsa_id ?? "-"`; license
`normalized_license ?? detected_license ?? "unknown"`.

**Eşik (`--fail-on`, AC-P22-10):** `none` → eşik değerlendirilmez. Diğer değerlerde etkin
seviyesi ≥ eşik olan en az bir sayılan bulgu varsa **eşik aşılmıştır** (`breaching` kümesi bu
bulgulardır).

### 4.4 Veri tamlığı (AC-P22-13, D-171, N-8)

- Durum değeri: durum yanıtı `data.projects[]` içinde `latest_scan_id` (küçük harfe çevrilerek)
  taranan tarama kimliğine eşit öğenin `vulnerability_data_status`'u.

| Kaynak | Çıktıdaki `vulnerabilityDataStatus` | Sınıf |
| --- | --- | --- |
| `complete` | `complete` | tam |
| `disabled` | `disabled` | uyarı (`W-DISABLED`) |
| `partial` | `partial` | eksik |
| `unavailable` | `unavailable` | eksik |
| `null` | `not_checked` | eksik |
| Eşleşen öğe yok, `projects_truncated` sonucu eksik liste, uç nokta hatası (`401`/`403`/`5xx`/ağ/JSON değil), tanınmayan değer | `unknown` | eksik |

- **Çıkış koduna etki** yalnız `--fail-on ≠ none` **ve** eşik aşılmamışsa: tam → 0; uyarı → 0;
  eksik → **5**; eksik + `--allow-incomplete` → 0.
- **Uyarılar** (bölüm 5.4) tarama tamamlandığında durum `complete` değilse **her zaman** üretilir
  (`--fail-on none` ve eşik aşımı dahil); çıkış kodu kuralı bundan bağımsızdır.

### 4.5 REQ-005 durum uç noktasına bağımlılık (REQ-005 contract değişmez)

- CLI'ın kullandığı alanlar REQ-005 contract 1.2.0 bölüm 2.4'te **zaten sabittir**:
  `data.projects[].latest_scan_id` (uuid) ve `data.projects[].vulnerability_data_status` (enum,
  nullable). Yeni alan gerekmez (D-171, D-175); **REQ-005 contract'ı 1.2.0 kalır.** Bu iki alanın
  kaldırılması veya anlamının değişmesi REQ-005 bölüm 11 gereği major olur ve bu contract'ı da
  bozar.
- Bilinen sınırlar (kabul edildi, `unknown` → 5 ile güvenli tarafta kalır): (a) liste en fazla 500
  proje döndürür; 501. ve sonraki projeler (ad sırasıyla) eşleşmez; (b) aynı projenin daha yeni bir
  taraması CLI'ın durum okumasından önce tamamlanırsa `latest_scan_id` değişir. Her iki durumda
  çözüm yeniden çalıştırma veya bilinçli `--allow-incomplete`'tir. README bu iki sınırı yazar.

## 5. CLI: çıkış kodları ve çıktı

### 5.1 Çıkış kodları (AC-P22-12, D-170, N-1)

| Kod | Anlam | `result` (JSON) | Metin `Result:` |
| --- | --- | --- | --- |
| `0` | Tarama tamamlandı; eşik aşılmadı ve veri tamlığı sağlandı, muaf (`none`, `disabled`) veya `--allow-incomplete` ile düşürüldü. `--help`, `--version`, başarılı `bootstrap` da 0. | `pass` | `PASS` |
| `1` | Tarama tamamlandı; eşik aşıldı (veri eksik olsa da). | `fail` | `FAIL` |
| `2` | Kullanım/yapılandırma: argüman, `--api-key` ailesi, adres (biçim, loopback dışı `http`, bootstrap'ta loopback dışı), anahtar kaynağı/dosyası/biçimi, `--new-database` yok, proje bulunamadı/belirsiz, proje kaynağı reddedildi (`POST /api/scans` `400`/`404`, `POST /api/projects` `400`), anahtar dosyası zaten var, **`403 host_rejected` / `403 origin_rejected`**. | `error` | — |
| `3` | Tarama `failed`/`cancelled`/`timeout`; bekleme süresi doldu; bağlantı hatası, istek zaman aşımı, art arda 3 geçici hata; `3xx`; `429`; `5xx` (yeniden denenmeyen istekte veya 3. denemede); beklenmeyen durum kodu (`409` setup dışı, `413` vb.); JSON olmayan veya beklenen şekilde olmayan gövde; gövde > 32 MiB; anahtar dosyası yazma hatası. | `error` | — |
| `4` | Kimlik/yetki: `401` (`unauthenticated`, `setup_required`), `403 forbidden` ve `host_rejected`/`origin_rejected` dışındaki her `403`; `bootstrap`'ta `409 setup_already_done`. | `error` | — |
| `5` | Tarama tamamlandı; eşik aşılmadı; veri tamlığı eksik (bölüm 4.4) ve `--allow-incomplete` yok. | `incomplete` | `INCOMPLETE` |

**Öncelik:** 2/3/4 (oluştukları anda akış durur) → 1 → 5 → 0. `--fail-on none` iken 1 ve 5
üretilmez.

### 5.2 HTTP → çıkış kodu eşlemesi (tüm istekler)

| Yanıt | Çıkış |
| --- | --- |
| `2xx` (beklenen) | devam |
| `3xx` | 3 |
| `400`, `404` | yalnız `POST /api/scans` ve `POST /api/projects` için 2; diğer isteklerde 3 |
| `401` | 4 (durum uç noktası hariç: `unknown`) |
| `403` + `code` ∈ {`host_rejected`, `origin_rejected`} | **2** (`server_address_rejected`, "server rejected the address or port (<code>); check --url") |
| `403` diğer (`forbidden`, kodsuz) | 4 (durum uç noktası hariç: `unknown`) |
| `409 setup_already_done` (yalnız setup) | 4 |
| `429`, diğer `4xx` | 3 |
| `5xx` | `GET`: geçici (3 denemeden sonra 3); `POST`: 3 |
| bağlantı hatası, 30 sn istek zaman aşımı | `GET`: geçici; `POST`: 3 |
| gövde > 32 MiB (`Content-Length` ön denetimi veya akış sayacı) | 3 (`response_too_large`; bulgularda "findings response exceeds 32 MiB") |

Hata metinleri yalnız yöntem, yol, durum kodu, sunucu `code` değeri ve (bölüm 4.1'de belirtilen
yerlerde) sanitize edilmiş sunucu `message`'ından kurulur; başlık, anahtar, çerez veya istek
nesnesi içermez.

### 5.3 Metin çıktısı (`--format text`, AC-P22-14)

**stderr (ilerleme ve uyarılar):**

```
oss-risk: scan <scanId> queued for project <proje adı>
oss-risk: scan <scanId> status <durum>            (her durum değişiminde bir kez)
oss-risk: warning: <uyarı metni>                  (bölüm 5.4)
oss-risk: error: <mesaj>                          (2/3/4; stdout'a hiçbir şey yazılmaz)
```

**stdout (yalnız tarama tamamlandığında; 0, 1, 5), satırlar bu sırayla:**

```
Project: <proje adı> (<projectId>)
Scan: <scanId>
Status: completed
Dependencies: <total_dependencies | ->
Security findings: critical=<n> high=<n> medium=<n> low=<n>
License findings: critical=<n> high=<n> medium=<n> low=<n>
Vulnerability data: <vulnerabilityDataStatus>
Fail on: <none|low|medium|high|critical>
Findings at or above <eşik>: <toplam breaching sayısı>      (yalnız eşik ≠ none)
  <paket>@<sürüm | ->  <security|license>  <seviye>  <kimlik>   (en fazla 20 satır)
  ... and <N> more                                              (yalnız >20 ise)
Result: <PASS|FAIL|INCOMPLETE>
```

- Sayılar `counts` ile aynıdır (seviyesi olan sayılan bulgular; eşikten bağımsız).
- Liste sırası bölüm 5.6 `breaching` sırasıdır; ayırıcı iki boşluk.
- Satır sonu `\n` (platformdan bağımsız).

### 5.4 Uyarı metinleri (sabit; text'te stderr, JSON'da `warnings[]`, aynı metin)

| Kimlik | Koşul | Metin |
| --- | --- | --- |
| `W-DISABLED` | durum `disabled` | `vulnerability lookup is disabled on the server; security findings were not checked` |
| `W-INCOMPLETE` | durum `partial`, `unavailable`, `not_checked` veya `unknown` | `vulnerability data is <durum> for scan <scanId>; security findings may be missing` |
| `W-ALLOWED` | `W-INCOMPLETE` + `--allow-incomplete` + `--fail-on ≠ none` + eşik aşılmadı | `--allow-incomplete is set; incomplete vulnerability data does not change the exit code` |
| `W-LOGOUT` | yalnız bootstrap | `logout failed; the session expires on its own` |

### 5.5 Uçbirim güvenliği (AC-P22-16, ADR-009 Karar 5)

- Uzak/repo kaynaklı her metin (proje adı, paket adı, sürüm, lisans, kimlik, sunucu `message`,
  `error_message`, dosya yolu): `singleLine` → C0/C1 (U+0000–U+001F, U+007F–U+009F) silme →
  en fazla 200 kod noktası (`error_message` 500). ESC dahil ANSI dizileri bu yolla etkisizleşir.
- JSON'da değerler aynı arındırmadan geçer, ardından `JSON.stringify` kaçışı uygulanır.

### 5.6 JSON çıktısı (`--format json`, AC-P22-15, D-173)

- stdout'a **tek** JSON nesnesi + tek `\n`; stderr'e **hiçbir şey** (ilerleme ve uyarılar
  `warnings[]`'e). Hata durumunda da aynı şekil (`result: "error"`). Kullanım hatası
  `--format json` ayrıştırılmadan önce oluşursa çıktı text'tir.
- **Alan sırası sabittir** (aşağıdaki sırayla tek bir nesne kurucusundan). Tüm anahtarlar her
  zaman bulunur; ek alan yoktur.

| # | Alan | Tip | Anlam |
| --- | --- | --- | --- |
| 1 | `schemaVersion` | `1` | Sabit. |
| 2 | `result` | `pass` \| `fail` \| `incomplete` \| `error` | Bölüm 5.1. |
| 3 | `exitCode` | tam sayı 0–5 | Sürecin çıkış koduyla aynı. |
| 4 | `project` | nesne \| `null` | `{ "id": uuid, "name": string }`; proje çözülmeden hata olursa `null`. |
| 5 | `scan` | nesne \| `null` | `{ "id": uuid, "status": string, "totalDependencies": tam sayı \| null }`; tarama oluşturulmadan hata olursa `null`. `status` son bilinen durum. |
| 6 | `failOn` | `none` \| `low` \| `medium` \| `high` \| `critical` \| `null` | Etkin eşik; ayrıştırılamadıysa `null`. |
| 7 | `vulnerabilityDataStatus` | `complete` \| `partial` \| `unavailable` \| `disabled` \| `not_checked` \| `unknown` \| `null` | Bölüm 4.4; tarama tamamlanmadıysa `null`. |
| 8 | `counts` | nesne \| `null` | `{ "security": {"low","medium","high","critical"}, "license": {…} }` tam sayılar (bu anahtar sırasıyla); bulgular okunmadıysa `null`. |
| 9 | `breaching` | dizi (≤ 500) | Öğe: `{ "type": "security"\|"license", "package": string, "version": string \| null, "level": "low"\|"medium"\|"high"\|"critical", "id": string }`. Sıra: seviye azalan → `package` (kod noktası) → `version` (`null` en önde) → `id`. Eşik `none` veya aşım yoksa `[]`. |
| 10 | `breachingTruncated` | boolean | Eşiği aşan bulgu sayısı > 500. |
| 11 | `warnings` | string dizisi | Bölüm 5.4 metinleri, oluşma sırasıyla. |
| 12 | `error` | nesne \| `null` | `{ "code": string, "message": string }`; yalnız `result = "error"` iken dolu. |

**`error.code` kataloğu (CLI'a özgü; sunucu kodlarıyla karıştırılmaz):**

| `code` | Çıkış | `code` | Çıkış |
| --- | --- | --- | --- |
| `usage_error` | 2 | `scan_failed` | 3 |
| `api_key_argument_rejected` | 2 | `wait_timeout` | 3 |
| `invalid_api_key_config` | 2 | `network_error` | 3 |
| `invalid_url` | 2 | `redirect` | 3 |
| `insecure_url` | 2 | `unexpected_response` | 3 |
| `project_not_found` | 2 | `response_too_large` | 3 |
| `project_ambiguous` | 2 | `unauthorized` (401) | 4 |
| `project_rejected` | 2 | `forbidden` (403) | 4 |
| `server_address_rejected` | 2 | | |

(`new_database_required`, `not_loopback`, `key_file_exists`, `already_initialised` yalnız
`bootstrap` metin çıktısında kullanılır; bootstrap JSON üretmez.)

**JSON Schema (draft 2020-12; qa-automation bunu doğrulama için kullanır):**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "oss-risk-cli-scan-result-v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schemaVersion","result","exitCode","project","scan","failOn",
               "vulnerabilityDataStatus","counts","breaching","breachingTruncated","warnings","error"],
  "properties": {
    "schemaVersion": { "const": 1 },
    "result": { "enum": ["pass","fail","incomplete","error"] },
    "exitCode": { "type": "integer", "minimum": 0, "maximum": 5 },
    "project": { "oneOf": [ { "type": "null" }, { "type": "object", "additionalProperties": false,
      "required": ["id","name"], "properties": { "id": { "type": "string", "format": "uuid" },
      "name": { "type": "string", "maxLength": 200 } } } ] },
    "scan": { "oneOf": [ { "type": "null" }, { "type": "object", "additionalProperties": false,
      "required": ["id","status","totalDependencies"], "properties": {
      "id": { "type": "string", "format": "uuid" }, "status": { "type": "string" },
      "totalDependencies": { "type": ["integer","null"], "minimum": 0 } } } ] },
    "failOn": { "enum": ["none","low","medium","high","critical",null] },
    "vulnerabilityDataStatus": { "enum": ["complete","partial","unavailable","disabled","not_checked","unknown",null] },
    "counts": { "oneOf": [ { "type": "null" }, { "type": "object", "additionalProperties": false,
      "required": ["security","license"], "properties": {
      "security": { "$ref": "#/$defs/levelCounts" }, "license": { "$ref": "#/$defs/levelCounts" } } } ] },
    "breaching": { "type": "array", "maxItems": 500, "items": { "type": "object",
      "additionalProperties": false, "required": ["type","package","version","level","id"],
      "properties": { "type": { "enum": ["security","license"] },
      "package": { "type": "string", "maxLength": 200 },
      "version": { "type": ["string","null"], "maxLength": 200 },
      "level": { "enum": ["low","medium","high","critical"] },
      "id": { "type": "string", "maxLength": 200 } } } },
    "breachingTruncated": { "type": "boolean" },
    "warnings": { "type": "array", "items": { "type": "string" } },
    "error": { "oneOf": [ { "type": "null" }, { "type": "object", "additionalProperties": false,
      "required": ["code","message"], "properties": { "code": { "type": "string" },
      "message": { "type": "string", "maxLength": 600 } } } ] }
  },
  "$defs": { "levelCounts": { "type": "object", "additionalProperties": false,
    "required": ["low","medium","high","critical"], "properties": {
    "low": { "type": "integer", "minimum": 0 }, "medium": { "type": "integer", "minimum": 0 },
    "high": { "type": "integer", "minimum": 0 }, "critical": { "type": "integer", "minimum": 0 } } } }
}
```

Örnek (eşik aşıldı):

```json
{"schemaVersion":1,"result":"fail","exitCode":1,"project":{"id":"0b6e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b","name":"oss-risk-self"},"scan":{"id":"3f2b8c1e-5d4a-4b6f-9c2d-1a2b3c4d5e6f","status":"completed","totalDependencies":412},"failOn":"high","vulnerabilityDataStatus":"disabled","counts":{"security":{"low":0,"medium":0,"high":0,"critical":0},"license":{"low":3,"medium":1,"high":1,"critical":0}},"breaching":[{"type":"license","package":"left-pad","version":"1.3.0","level":"high","id":"unknown"}],"breachingTruncated":false,"warnings":["vulnerability lookup is disabled on the server; security findings were not checked"],"error":null}
```

## 6. Eşzamanlı çıktı uç noktaları (AC-P24-1, -2, -7, -12; ADR-009 Karar 7)

### 6.1 Uç noktalar

| Yol | İçerik | `Content-Type` | Dosya adı |
| --- | --- | --- | --- |
| `GET /api/scans/{scanId}/exports/project-report.pdf` | Mevcut `project_report` PDF oluşturucusu (REQ-004 1.5.0 V-12 ve kesinti notu dahil) | `application/pdf` | `project-report-<scanId>.pdf` |
| `GET /api/scans/{scanId}/exports/license-inventory.xlsx` | Mevcut `license_inventory` Excel oluşturucusu (dört sayfa; V-12 satırı dahil) | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `license-inventory-<scanId>.xlsx` |
| `GET /api/scans/{scanId}/exports/license-inventory.csv` | Excel `Dependencies` sayfasının izdüşümü (bölüm 7) | `text/csv; charset=utf-8` | `license-inventory-<scanId>.csv` |

- Üç açık rota (`src/routes/exportRoutes.ts`); parametreli dosya adı yoktur. Başka bir son ek
  (ör. `/exports/foo.pdf`) mevcut `/api` 404 davranışına düşer (`404 not_found`).
- NOTICE için mevcut `GET /api/scans/{scanId}/notice` (değişmez; sınırın dışında).
- Sorgu parametreleri ve `Accept` yok sayılır (`406` yok). `HEAD` Express `GET` eşlemesiyle
  döner; test zorunlu değildir (HEAD de yuva tüketir).

### 6.2 Kimlik ve yetki

| Kural | Değer |
| --- | --- |
| Kimlik | Oturum çerezi (`ossrisk_session`) veya `Authorization: Bearer <API anahtarı>`; global middleware. Yalnız çerez kuralı uygulanmaz. |
| İzin | `reports:read` (`guard('reports:read')`), her üç rotada. |
| Tarama erişimi | NOTICE ile aynı: proje bazında ek yetki yok; tarama var ve `completed` olmalı. |
| Origin | `GET` → Origin denetimi yok. Host izin listesi global (`403 host_rejected`). |

### 6.3 Yan etkisizlik

`reports` satırı, dosya, denetim (`audit_logs`) satırı, `sbom_documents` yazımı ve ağ isteği
**yoktur**. Gövde istek anında `ReportService.renderExport(scanId, kind, signal)` ile yalnız
veritabanından üretilir (içeride mevcut `loadReportData` + `renderContent`; kopya oluşturucu
yok).

### 6.4 Başarılı yanıt — `200`

| Başlık | Değer |
| --- | --- |
| `Content-Type` | bölüm 6.1, tam değer |
| `Content-Disposition` | `attachment; filename="<dosya adı>"`; `<scanId>` veritabanından okunan küçük harfli kanonik UUID; `filename*` yok; proje adı yok |
| `Content-Length` | gövde bayt sayısı |
| `X-Checksum-SHA256` | gövdenin SHA-256 özeti, 64 küçük harf hex |
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` (global; `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, CSP da global) |

- Başlıklar yalnız gövde tamamen üretildikten sonra yazılır; hata yanıtları `Content-Disposition`
  taşımaz.
- **Belirlenimcilik:** CSV aynı veri için bayt bayt aynıdır. PDF ve XLSX üretim zamanı içerdiği için
  (PDF `Generated:`, Excel `Generated At`, kitap/belge meta zamanı) istekten isteğe bayt ve özet
  değişebilir; içerik eşitliği AC-P24-3/4 kuralıyla (üretim zamanı hariç) test edilir.
- `ETag`/`Last-Modified` contract dışıdır.

### 6.5 Hata yanıtları ve değerlendirme sırası (N-6)

Tümü mevcut JSON zarfı `{ "error", "message", "code" }` (`sendError`). **Yeni kod:** `export_busy`
(`src/lib/httpError.ts` `ErrorCode` birleşimine eklenir; REQ-002 kod kataloğuna additive).

| Durum | `code` | `message` (sabit) | Ek başlık | Ne zaman |
| --- | --- | --- | --- | --- |
| `400` | `invalid_request` | `scanId must be a valid UUID` | — | `scanId` NOTICE düzenli ifadesine uymuyor: `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` (harf duyarsız) |
| `401` | `unauthenticated` / `setup_required` | `Authentication required` / `Initial password setup required` | — | REQ-002 |
| `403` | `forbidden` | `Permission "reports:read" is required` | — | Rol izni yok (RBAC ek alanları `required`, `userRoles` korunur) |
| `403` | `host_rejected` | `Host not allowed` | — | Global Host denetimi |
| `404` | `not_found` | `Scan not found or not yet completed` | — | Tarama yok veya `completed` değil |
| `429` | `export_busy` | `Too many exports in progress; retry shortly` | `Retry-After: 5` | Süreç genelinde 2 üretim sürerken |
| `500` | `internal_error` | `Internal server error` | — | Beklenmeyen hata veya üretim süresi aşımı (ayrıntı yalnız sunucu logunda, L-5 arındırmasıyla) |

**Sıra:** Host (`403 host_rejected`) → kimlik (`401`) → izin (`403 forbidden`) → UUID (`400`) →
eşzamanlılık yuvası (`429`) → tarama araması (`404`) → üretim (`200`/`500`). Meşgulken var olmayan
veya tamamlanmamış tarama için de `429` döner (bilinçli: DB'ye gitmeden reddetmek). `409` ve `413`
kullanılmaz. `429` ve `500` yanıtlarında `Cache-Control: no-store` önerilir, zorunlu değildir.

### 6.6 Kaynak sınırları (AC-P24-7, D-185)

| Sınır | Değer |
| --- | --- |
| Eşzamanlı üretim | En fazla **2** (üç uç nokta toplamı), `createApp` içinde kurulan örneğe ait `ExportLimiter` (modül düzeyi küresel durum yok). Yuva `try/finally` ile bırakılır; istemci bağlantıyı keserse üretim biter, yuva bırakılır, yanıt yazılmaz. NOTICE sınır dışıdır. |
| Süre | `EXPORT_WORKER_TIMEOUT_MS` (`exportWorkerConfig.timeoutMs`, varsayılan 600 000 ms) ile `AbortSignal`; adımlar arasında denetlenir (pdfkit/exceljs üretimi kesilemez). Tetiklenirse `500 internal_error`. |
| Boyut | Yeni boyut sınırı **yok**: PDF satır sınırlıdır (40/40/50), Excel/CSV bağımlılık sayısıyla doğrusaldır; gövde `Buffer` olarak tamamlanır. 10 000 bağımlılıklı fixture'da süre ve boyut ölçülüp handoff'a yazılır. |

## 7. CSV biçimi (AC-P24-5, AC-P24-6, D-183, D-184; ADR-009 Karar 8)

- **Kaynak:** Excel `Dependencies` sayfası ile aynı **ortak satır kurucusu**
  (`dependencyRowCells(dep)` veya eşdeğeri). Başlık, sütun sırası, satır sırası ve hücre metni
  yapısal olarak aynıdır. Formül kalkanı (`excelSafeText`) kurucuda bir kez uygulanır; CSV yeniden
  uygulamaz.
- **Sütunlar (birebir, bu sırayla):** `Name`, `Version`, `Ecosystem`, `Scope`, `Manifest`, `Depth`,
  `PURL`, `License`, `License Source`.
- **Hücre metni:** Excel hücresinin metin değeri (REQ-004 5.1, 5.1a): `Manifest` =
  `manifest_path || manifest_file`; `License` = `singleLine(license_expression)`; `License Source`
  = `licenseSourceCell`; `null`/boş → boş alan; `Depth` = `String(<tam sayı>)` (önek yok).
  Mevcut sütunlara tek satır katlama **eklenmez** (Excel ile aynı ham değer + kalkan).
- **Kodlama:** UTF-8, başta BOM `EF BB BF`. Ayırıcı `,` (yerel ayardan bağımsız). Satır sonu
  `\r\n`; ilk satır başlık; son satır da `\r\n` ile biter. Bağımlılığı olmayan tarama: BOM + başlık
  + `\r\n`.
- **RFC 4180 tırnaklama:** alan `,`, `"`, `\r` veya `\n` içeriyorsa ya da ilk veya son karakteri
  U+0020 veya U+0009 ise `"…"` içine alınır ve içteki her `"` → `""`. Alan içindeki satır sonları
  olduğu gibi kalır (normalize edilmez). Diğer alanlar tırnaksızdır.
- **Formül koruması:** `=`, `+`, `-`, `@`, U+0009 veya U+000D ile başlayan metne tırnaklamadan
  **önce** `'` eklenir (kurucuda). Örnek: `=cmd` → `'=cmd`; `-1` → `'-1`; `a,"b"` → `"a,""b"""`.
- Belirlenimci; zaman damgası, meta satırı veya toplam satırı yoktur.

## 8. Arayüz: tarama satırı indirme bağlantıları (AC-P24-8, AC-P24-9, D-186)

Dosya `public/app.js`, `scanActions(row)` (pano ve tarama geçmişi ortak). Aktif durum dalı
(ilerleme çubuğu) ve diğer durumlar (`—`) değişmez; `completed` olmayan satırda bağlantı yoktur.

`completed` dalı tek sarmalayıcı döndürür:
`el('div', { style: 'display:inline-flex; align-items:center; gap:0.375rem; flex-wrap:wrap;' }, pdf, excel, csv, notice, sbom)`
— **sıra sabit:** PDF, Excel, CSV, NOTICE, SBOM.

| Bağlantı | `href` (yalnız `apiPath(...)`) | `download` | `target`/`rel` | `aria-label` | Görünen metin |
| --- | --- | --- | --- | --- | --- |
| PDF | `apiPath('scans', row.id, 'exports', 'project-report.pdf')` | var, boş değer | yok | `Download project PDF report` | `PDF` |
| Excel | `apiPath('scans', row.id, 'exports', 'license-inventory.xlsx')` | var, boş değer | yok | `Download license inventory (Excel)` | `Excel` |
| CSV | `apiPath('scans', row.id, 'exports', 'license-inventory.csv')` | var, boş değer | yok | `Download license inventory (CSV)` | `CSV` |
| NOTICE | `apiPath('scans', row.id, 'notice')` (**değişmez**) | var, boş değer | **yok** (önceki `_blank`/`noopener` kaldırılır; REQ-004 1.5.0 bölüm 7) | `Download NOTICE file` | `NOTICE` |
| SBOM | `apiPath('scans', row.id, 'sbom', 'download')` | — | **değişmez** (`_blank`, `noopener`) | — (değişmez) | `SBOM` |

- Ortak biçim (dördü için de): öğe `a`, `className: 'btn btn-sm'`, `style:
  'text-decoration:none; display:inline-flex; align-items:center; gap:0.25rem;'`, içerik
  `icon('download', 'width:12px;height:12px;')` + `' <metin>'`. Boş `download` değeri sunucunun
  `Content-Disposition` dosya adının kullanılmasını sağlar.
- JS fetch/Blob indirmesi, ara iletişim kutusu veya üretim bekleme ekranı **yoktur**; tarayıcı
  `SameSite=Strict` çerezi aynı kökenli gezintide gönderir. `429`/`404`'te tarayıcı indirmeyi
  başarısız gösterir (kabul edilen sınırlama; README "birkaç saniye sonra tekrar deneyin").
- jsdom test seçicileri: `a[href="/api/scans/<id>/exports/project-report.pdf"][download]`,
  `…license-inventory.xlsx`, `…license-inventory.csv`, `a[href="/api/scans/<id>/notice"][download]`;
  sarmalayıcıdaki `a` öğelerinin metin sırası `PDF, Excel, CSV, NOTICE, SBOM`.

## 9. Arayüz: API Keys ekranı (AC-AK-1…4, D-189; ADR-009 Karar 10)

### 9.1 Yerleşim (statik işaretleme, `public/index.html`)

- Kenar çubuğu, `Users & Roles` düğmesinden **sonra**:
  `<button class="nav-item" type="button" data-view="api-keys"><i data-lucide="key-round"></i>API Keys</button>`
- Görünüm: `<div id="view-api-keys" class="view-section" style="display: none;">`.
- `VIEWS['api-keys']`: `title: 'API Keys'`, `subtitle: 'Personal API key for the oss-risk CLI and CI'`,
  `load` ve `refresh` = listeyi yükle; `headerActions` yok.

| Öğe kimliği | Tür | İçerik / öznitelik |
| --- | --- | --- |
| `api-keys-cli-hint` | `p` (statik) | `Use the key with the CLI: set OSS_RISK_API_KEY (or OSS_RISK_API_KEY_FILE) and run oss-risk scan --project <name>. Only one key is active at a time.` (`<name>` metin olarak `&lt;name&gt;`) |
| `api-key-create-form` | `form` (`novalidate`) | `submit` dinleyicisi `preventDefault()`; yerel gönderim yapılmaz (REQ-002: Origin `null` riski) |
| `api-key-name` | `input type="text"` | `maxlength="100"`, `autocomplete="off"`, etiket `Key name (optional)` |
| `api-key-create-btn` | `button type="submit"` | `Create API key`; istek sürerken `disabled` |
| `api-key-reveal-slot` | `div` (boş) | Tek gösterim paneli buraya dinamik eklenir (9.3) |
| `api-keys-body` | `div` | `data-state` ∈ `loading`, `error`, `empty`, `ready` |
| `api-keys-loading` | `div` | `Loading API keys...` (yalnız `loading`) |
| `api-keys-error` | `div role="alert"` | `Could not load API keys.` (yalnız `error`) |
| `api-keys-empty` | `div` | `No API keys yet.` (yalnız `empty`) |
| `api-keys-table` | `table` | Başlıklar: `Name`, `Prefix`, `Created`, `Last Used`, `Status`, `Actions`; gövde `api-keys-tbody` (yalnız `ready`) |

### 9.2 Liste (`GET /api/auth/api-keys`, oturum)

Yanıt `{ data: [{ id, name, keyPrefix, createdAt, lastUsedAt, revokedAt }] }` (mevcut, sıra
`createdAt DESC`). Satır hücreleri **yalnız `textContent`** ile (`innerHTML` yok):

| Sütun | Değer |
| --- | --- |
| Name | `name`; `null`/boş → `—` |
| Prefix | `keyPrefix` (`ossr_<16 hex>`) |
| Created | `createdAt` mevcut tarih biçimleyicisiyle |
| Last Used | `lastUsedAt` biçimli; `null` → `Never` |
| Status | `revokedAt === null` → `Active`; aksi `Revoked <biçimli revokedAt>` |
| Actions | Yalnız aktif satırda `button.btn.btn-sm` metni `Revoke`, `aria-label="Revoke API key <keyPrefix>"`; iptal edilmiş satırda boş |

### 9.3 Oluşturma ve tek gösterim (`POST /api/auth/api-keys`)

1. Ad `trim()`; boşsa gövde `{}`, değilse `{ "name": <ad> }` (sunucu > 100 → `400`).
2. Listede aktif anahtar varsa önce `window.confirm('Creating a new key revokes the current active key. Continue?')`;
   iptalde istek yapılmaz. (Uygulamada ortak onay modalı yoktur; `window.confirm` kullanılır.)
3. İstek mevcut `api()` fetch yardımcısıyla (aynı köken; tarayıcı Origin'i koyar).
4. Başarıda `#api-key-reveal-slot` içine **dinamik** olarak eklenir:
   `div#api-key-reveal` → `p` `Copy this key now. It will not be shown again.` +
   `input#api-key-value` (`type="text"`, `readonly`, `autocomplete="off"`, `spellcheck="false"`,
   `aria-label="New API key"`, `value` = `data.key`) + `button#api-key-copy-btn` (`Copy`) +
   `span#api-key-copy-status` (`aria-live="polite"`) + `button#api-key-dismiss-btn` (`Done`).
   Ardından liste yeniden yüklenir; ad alanı temizlenir.
5. **Copy:** `navigator.clipboard.writeText(value)` başarılıysa durum `Copied to clipboard`;
   API yoksa veya reddedilirse alan seçilir (`select()`) ve durum `Press Ctrl+C to copy`.
6. **Tek gösterim kuralı:** düz anahtar yalnız yanıtı işleyen işlevin yerel değişkeninde ve
   `#api-key-value`'nun `value`'sundadır. Modül düzeyi değişkene, `localStorage`,
   `sessionStorage`, URL, `console.*`, hata/toast metnine **yazılmaz**.
   `#api-key-reveal` şu anlarda DOM'dan kaldırılır: `Done`, başka görünüme geçiş (`switchView`),
   `pagehide`, oturum kapanışı (logout ve 401 yönlendirmesi). `refreshAll` paneli kaldırmaz ve
   yeniden oluşturmaz.

### 9.4 İptal (`DELETE /api/auth/api-keys/{id}`)

`window.confirm('Revoke API key <keyPrefix>? Clients using it will stop working.')`; onayda
istek, başarıda (`204`) liste yeniden yüklenir. İptal edilen anahtar açık panelde gösteriliyorsa
panel de kaldırılır.

### 9.5 Hata ve durumlar

| Durum | Davranış |
| --- | --- |
| Liste hatası | `data-state="error"` + mevcut `reportError(e, 'Could not load API keys')` |
| Oluşturma hatası | `reportError(e, 'Could not create API key')`; panel eklenmez; düğme yeniden etkin |
| İptal hatası | `reportError(e, 'Could not revoke API key')`; liste değişmez |
| `401` | mevcut `api()` davranışı (giriş ekranı); panel kaldırılır |

Hata metinleri anahtar içermez. Olaylar `addEventListener` ile; satır içi `on*` yok; yeni dış
kaynak yok; CSP değişmez. Sunucu uç noktaları değişmez (AC-AK-4, AC-G-4).

## 10. GitHub Actions iş akışları (contract'a bağlı noktalar; ADR-009 Karar 11)

İş akışı yapısının tamamı ADR-009 Karar 11 ve REQ-007 AC-P23-1…9'dadır. Bu contract yalnız CLI
yüzeyine bağlı kısımları sabitler:

- Örnek iş akışı çağrıları (`oss-risk-example.yml`):
  ```
  node dist/cli/index.js bootstrap --new-database --key-file "$RUNNER_TEMP/oss-risk.key" \
    --project-name oss-risk-self --project-path "$RUNNER_TEMP/oss-risk-target"
  OSS_RISK_API_KEY_FILE="$RUNNER_TEMP/oss-risk.key" node dist/cli/index.js scan \
    --project oss-risk-self --fail-on critical
  ```
  `--url` verilmez (varsayılan `http://127.0.0.1:3001`, sunucu `HOST=127.0.0.1 PORT=3001`).
- Varsayılan kipte (`push`/`pull_request`) CLI `W-DISABLED` uyarısını yazar, çıkış kodu
  etkilenmez. `online` kipte `--allow-incomplete` verilmez (eksik veri → 5).
- AC-P23-8 statik testi `--fail-on` değerinin bölüm 2.2 kümesinde olduğunu ve bootstrap satırında
  `--new-database` bulunduğunu da denetler.
- Sunucu logu (`tail -n 200`) anahtar içermez (AC-G-8).

## 11. Test yükümlülükleri

| Taraf | Yükümlülük |
| --- | --- |
| backend-engineer | Bölüm 2–7 uygulaması: `src/cli/**`, `exportRoutes`/`exportController`, `renderExport`, `ExportLimiter`, `csv.ts`, `dependencyRowCells`, `export_busy` kodu, `package.json` `bin`, README (CLI, çıkış kodları tablosu, `--new-database` ve N-2 uyarısı, bölüm 4.5 sınırları, `429` notu, GitHub Actions), iş akışları (bölüm 10). Lint, typecheck, hedef test sonuçlarını raporlar. REQ-004 1.5.0 değişiklikleri (V-12, kesinti notu). |
| frontend-engineer | Bölüm 8 ve 9; lint. |
| qa-automation | **CLI birim (enjekte):** dilbilgisi tablosu (her 2 vakası, `--api-key`/`--key`/`--token` iki biçim, `--help`/`--version` ağsız ve 0, bootstrap'ta `--new-database` yok → 2 ve dosya oluşmaması); adres kuralları (`http://example.com` → 2 sıfır bağlantı, `http://u:p@127.0.0.1:…` → 2, sorgu/parça/yol → 2); anahtar kuralları (ikisi/hiçbiri/biçim/1 KiB); bölüm 4.3 tablosu; eşik; bölüm 4.4 tüm satırları + `--allow-incomplete` + `--fail-on none`; öncelik (eşik aşımı + eksik veri → 1); yoklama (enjekte saat: zaman aşımı → 3 ve metin, 3×`503` → 3, 2×`503` + başarı → devam); `breaching` sırası, 20/500 kesimi; JSON şeması (bölüm 5.6) her çıkış kodunda; ANSI (`\u001b[2J` + yeni satır içeren paket adı). **İstemci (loopback test sunucusu):** `302` → 3 ve hedefe bağlantı yok; 32 MiB aşımı → 3; 30 sn istek süresi (sahte zamanlayıcı); `HTTP_PROXY` + `NODE_USE_ENV_PROXY=1` iken tuzak proxy'ye bağlantı yok; varsayılan portta `Host: <host>:80`; `403 host_rejected` → 2, `403 forbidden` → 4, `401` → 4, `429` → 3. **Uçtan uca (alt süreç, derlenmiş CLI, embedded PG):** AC-P22-11 (yüksek bulgu → 1; `false_positive` + yeni tarama → 0; seçeneksiz → 1); her çıkış kodu için ≥ 1 senaryo; bootstrap başarı (dosya içeriği yalnız anahtar, yeni satırsız; proje kimliği stdout'ta), ikinci çalıştırma → 4 ve dosya yok, var olan dosya → 2 ve sıfır istek, loopback dışı → 2; tüm senaryolarda stdout/stderr anahtar, `S`, parola içermez; `.env`'li klasörde anahtar `.env`'den alınmaz; `pg`/`express`/`dotenv` yüklenmez; `API_KEY_RE` kaynak eşitliği. **Export:** üç uç nokta oturum ve Bearer ile `200` + bölüm 6.4 başlıkları (dosya adı küçük harf, özet = gövde); `400`/`401`/`403`/`404` gövdeleri ve `Content-Disposition` olmaması; sıra (`429`'un `404`'ten önce); limiter (2 yuva dolu → `429` + `Retry-After: 5` + `export_busy`, NOTICE etkilenmez, yuva bırakılınca tekrar `200`); yan etkisizlik (`reports`/`audit_logs` satır sayısı ve çıktı klasörü değişmez); asenkron/eşzamanlı PDF metni ve Excel hücre eşitliği (üretim zamanı hariç); CSV ↔ Excel `Dependencies` hücre eşitliği; CSV bayt golden (virgül, tırnak, yeni satır, `=cmd`, `-1`, Türkçe karakter, emoji, baştaki boşluk). **Arayüz (jsdom):** bölüm 8 seçicileri ve sırası, SBOM bağlantısının değişmediği; bölüm 9 liste/boş/hata, oluşturma (onay, tek gösterim, `Done`/görünüm değişimi/`pagehide`/logout ile silinme), Copy iki yolu, iptal; depolama API'leri ve `console` casusları anahtarı görmez. **İş akışı statik testi:** AC-P23-8 + `persist-credentials: false` + bölüm 10. **Regresyon:** mevcut contract testleri değişmeden yeşil (AC-G-4, AC-G-7). |
| security-red-team | Anahtar sızıntısı yolları (argüman, hata metni, log, iş akışı logu), bootstrap Origin beyanı ve `--new-database` korumasının yeterliliği, export DoS (limiter, API anahtarlı döngü), CSV/Excel formül enjeksiyonu, uçbirim enjeksiyonu, API Keys ekranında anahtarın DOM ömrü, iş akışı güvenliği. Release öncesi zorunlu. |
| ana oturum | SHA doğrulaması, push, GitHub çalıştırması (AC-P23-6), yerel ön doğrulama (AC-P23-7), gerçek tarayıcıda dört indirme (AC-P24-9). |

## 12. Sürümleme

- Contract 1.0.0. API yolu sürümlenmez (`/api/...`). OpenAPI `info.version` 1.0.0.
- **CLI JSON şeması** `schemaVersion: 1`. Alan **eklemek** (isteğe bağlı olmayan dahil) minor
  contract revizyonudur ve `schemaVersion`'ı artırmaz; tüketiciler bilinmeyen alanları yok
  saymalıdır — **ancak** `additionalProperties: false` doğrulayan testler güncellenir. Alan
  kaldırmak/yeniden adlandırmak, tip veya enum anlamı değiştirmek `schemaVersion: 2` ve major
  contract sürümüdür.
- **Çıkış kodları ve `--fail-on` eşlemesi** (bölüm 4.3, 5.1): bir kodun veya seviye eşlemesinin
  anlamını değiştirmek major; yeni kod eklemek minor.
- **Metin çıktısı** insan içindir; satır ekleme minor, mevcut satır önekini (`Result:` vb.)
  değiştirmek major (betikler `Result:` satırına bağlanabilir).
- Export uç noktalarında başlık veya hata kodu eklemek minor; dosya adı, `Content-Type` veya CSV
  sütun sırası değişikliği major. CSV sütunları Excel `Dependencies` ile birlikte değişir
  (REQ-004 bölüm 11: yeni sütunlar yalnız sona).
- Bulgu veya proje uç noktasına sayfalama eklenmesi bu contract'ı bozar (CLI `data` dizisi
  bekler) ve major revizyon gerektirir.

## 13. Karar kaydı ve netleştirmeler

Tümü "kullanıcı daimi talimatı (önerilen seçenek), 2026-10-11".

| # | Konu | Karar | Dayanak |
| --- | --- | --- | --- |
| X-1 | Bootstrap onay bayrağı (N-2) | `--new-database` zorunlu; yoksa 2, dosya ve istek yok | Ana oturum notu (REQ-007 r2 ile hizalı); ADR-009 N-2 kararı Product Analyst'e bırakmıştı |
| X-2 | `403 host_rejected`/`origin_rejected` (N-1) | 2 (`server_address_rejected`); diğer `403` → 4 | ADR-009 Karar 2, N-1; REQ-007 r1 AC-P22-12 "403 → 4" metni daraltıldı |
| X-3 | Export hata sırası (N-6) | `403 → 400 → 429 → 404` (Host ve `401` önce) | ADR-009 Karar 7, N-6 |
| X-4 | Durum okuma (N-8) | Tamamlanan taramada her zaman okunur; çıkış etkisi yalnız `--fail-on ≠ none` ve eşik aşılmamışsa | ADR-009 Karar 4, N-8 |
| X-5 | Uyarıların kapsamı | `W-DISABLED`/`W-INCOMPLETE` durum `complete` değilse her zaman (`none` dahil) | Çıktının her zaman dürüst olması; çıkış kuralı değişmez |
| X-6 | JSON anahtarları | Tüm anahtarlar her zaman bulunur, `null` ile; `error` başarıda `null` | Sabit şekil, kolay ayrıştırma (AC-P22-15 "kesin şema contract'ta") |
| X-7 | CLI `error.code` | CLI'a özgü katalog (bölüm 5.6), sunucu kodundan ayrı | Ağdan önceki hatalar sunucu kodu taşımaz |
| X-8 | `null` `vulnerability_data_status` | Çıktıda `not_checked` (REQ-005 sayım adlandırması), eksik sınıfı | REQ-005 2.4 `project_status_counts.not_checked` |
| X-9 | REQ-005 sürümü | Değişmez (1.2.0); gerekli alanlar zaten sabit | D-171, D-175; ADR-009 Karar 12'deki "REQ-005 1.3.0" yalnız gerekirse — gerekmedi |
| X-10 | Bağlantılarda `download` değeri | Boş; dosya adı sunucudan | Dosya adı tek kaynakta |
| X-11 | NOTICE bağlantısı | `download` eklenir, `target`/`rel` kaldırılır, href aynı | ADR-009 Karar 10; REQ-004 7. bölüm 1.5.0'da güncellendi |
| X-12 | Onay deseni | `window.confirm` (ortak onay modalı yok) | ADR-009 Karar 10; `public/app.js` incelemesi |
| X-13 | Kesinti notu kapsamı (N-7) | Üç tablo ayrı ayrı (güvenlik 40, lisans 40, bağımlılık 50); tüm rapor türlerinde | REQ-004 1.5.0 bölüm 5.4 |

**Handoff:** Bu contract non-trivial'dir. Implementation ve doğrulama sonunda
`docs/handoffs/REQ-007.md` güncellenmelidir (integration-release; Delivery Lead takip eder):
bu contract'a ve ADR-009'a atıf, 10 000 bağımlılık ölçümleri (süre, boyut, bulgu yanıtı
boyutu), güncellenen rapor testleri listesi (AC-G-7), GitHub çalıştırma kanıtı, tarayıcı
indirme kanıtı, contract'tan sapma varsa gerekçesi.

**NotebookLM / Obsidian:** kullanılmadı. Kaynaklar: REQ-007 r1, ADR-009, REQ-002/004/005
contract'ları, `src/controllers/{scanController,authController,noticeController}.ts`,
`src/routes/{scanRoutes,projectRoutes}.ts`, `src/lib/{httpError,apiKeys}.ts`,
`src/reports/{reportService,worker.config}.ts`, `src/middleware/securityHeaders.ts`,
`public/app.js`, `public/index.html`.

## 14. Revizyon geçmişi

| Sürüm | Tarih | Değişiklik | Dayanak | Onay |
| --- | --- | --- | --- | --- |
| 1.0.0 | 2026-10-11 | İlk sürüm: CLI (`scan`, `bootstrap --new-database`), adres/anahtar kuralları, çıkış kodları 0–5 ve `403` ayrımı, `--fail-on` eşlemesi, veri tamlığı, text/JSON çıktı ve JSON Schema; üç export uç noktası (`export_busy`, sıra `403→400→429→404`), CSV biçimi; arayüz bağlantıları ve API Keys ekranı; iş akışı CLI çağrıları. | REQ-007 r1, ADR-009 (Karar 1–11, N-1…N-8), ana oturum notları (X-1…X-3) | Onaylandı (kullanıcı daimi talimatı, önerilen seçenek), 2026-10-11 |
