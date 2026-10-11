# ADR-009: `oss-risk` CLI (sunucu istemcisi), `--fail-on` değerlendirmesi, `bootstrap`, eşzamanlı tek tık çıktılar, API anahtarı ekranı ve GitHub Actions

- **ADR-ID:** ADR-009
- **Durum:** Accepted
- **Tarih:** 2026-10-11 (taslak ve karar)
- **İlgili:** REQ-007 r1 / P-22, P-23, P-24, API anahtarı ekranı, V-12 (52 AC);
  kararlar D-161…D-193 (özellikle D-162…D-175, D-176…D-180, D-182…D-189).
  Dayanaklar: ADR-001 Karar 4–10 ve 12 (çerez, CSRF/Host, API anahtarı
  biçimi/iletimi, tek aktif anahtar, muaf uç noktalar, bind, kurtarma),
  ADR-004 (tek süreç, tek örnek kilidi, göçlerin elle uygulanması), ADR-006
  Karar 12–13 (eşzamanlı NOTICE deseni, formül koruması), ADR-007 (L-5
  arındırma), REQ-005 contract §1–§3.1 ve V-12.
- **Superseded edilenler:** Yok. Önceki hiçbir ADR kararı değişmez; bu ADR
  mevcut kuralların içinde kalır (sunucuda kimlik/yetki kuralı değişmez).

## Bağlam

Repo üzerinde doğrulanan durum (branch `req-007-f6-cli-raporlar`, `afc43ee`):

- **Ara katman sırası** (`src/app.ts`): `securityHeaders` → `requireAllowedHost`
  (her istek; izin listesi `127.0.0.1`/`localhost`/`::1`/`HOST` × **bağlı
  port**, `host:port` biçiminde, `requestGuards.ts`) → `/health`, statik →
  `createPublicAuthRouter` (`POST /api/auth/setup|login`, koşulsuz
  `requireSameOrigin`) → `authenticate` → `requireSameOriginForSessionWrites`
  → router'lar.
- `requireSameOrigin`: `Origin` (yoksa `Referer` kökeni) izin listesindeki
  `http://<host>:<port>` değerlerinden biri olmalı; ikisi de yoksa `403
  origin_rejected`. Tarayıcı dışı bir istemci başlığı kendisi koyabilir —
  bu bir CSRF savunmasıdır, istemci kimliği değildir.
- `requireSameOriginForSessionWrites`: yalnız `authMethod === 'session'` ve
  `POST/PUT/PATCH/DELETE` için Origin ister; **Bearer istekleri muaftır**.
- `authenticate`: `Authorization` başlığı varsa yalnız Bearer sayılır, çerez
  yok sayılır. `requireSession()` `logout` ve üç `api-keys` uç noktasında
  Bearer'ı `403 forbidden` ile reddeder.
- `POST /api/auth/setup`: parola 12–1024 karakter; başarıda `201`, gövdesiz,
  `Set-Cookie: ossrisk_session=…; HttpOnly; SameSite=Strict; Path=/` (Secure
  yok). Setup **iki dalda** başarılı olur: ilk kurulum ve ADR-001 Karar 12
  kurtarma (parolası boşaltılmış aktif admin); iki dal istemciye aynı görünür.
- `POST /api/auth/api-keys` → `201 { data: { … düz anahtar … } }`,
  `Cache-Control: no-store`.
- `GET /api/scans/{id}/findings` **sayfalamasız** tüm satırları döndürür
  (her satırda `vuln_description` dahil); tarama yoksa `200 []`.
  `GET /api/projects` de sayfalamasızdır (silinmişler hariç, ada göre sıralı).
- `ReportService`: `loadReportData(scanId)` (yalnız `completed`; aksi `404
  "Scan not found or not yet completed"`) ve `renderContent(data, type,
  format)` özel (private) yöntemlerdir; `processReport` bunlara ek olarak dosya,
  `reports` satırı ve denetim yazar. PDF tabloları güvenlik 40, lisans 40,
  bağımlılık 50 satırla kesilir. Excel dört sayfa; `addDependencyWorksheet`,
  `licenseSourceCell`, `excelSafeText` mevcut.
- NOTICE (`noticeController.ts`): UUID doğrulaması (`400`), başlıklar gövde
  tamamen üretildikten sonra, `Cache-Control: no-store`, `X-Checksum-SHA256`.
- CSP: `script-src 'self'` (satır içi betik yok), `style-src 'self'
  'unsafe-inline'`, `connect-src 'self'`. `public/app.js` `scanActions` yalnız
  `SBOM` ve `NOTICE` bağlantısı üretir (`target="_blank"`).
- `tsconfig.json`: `rootDir: ./src`, `module: CommonJS`; `package.json`'da
  `bin` yok; `engines.node` `^22.21.0 || >=24.5.0`.
- `src/lib/outputText.ts` (`singleLine`, `excelSafeText`) yalnız
  `textSanitize.ts`'e bağlıdır (Node yerleşiği bile yüklemez);
  `src/lib/apiKeys.ts` `sessions.ts` üzerinden sunucu modüllerine bağlıdır.

## Kararlar

### 1. CLI modül yerleşimi ve sınır kuralı (D-162, D-163; AC-P22-1, AC-P22-2)

```
src/cli/
  index.ts        #!/usr/bin/env node; yalnız: process.exitCode = await main(realDeps())
  main.ts         main(deps): Promise<number> — komut seçimi, hata→çıkış kodu eşlemesi
  args.ts         elle ayrıştırıcı (komut + seçenek tablosu)
  config.ts       anahtar (env/dosya) ve adres kuralları
  client.ts       en küçük HTTP istemcisi (node:http / node:https)
  evaluate.ts     sayılan bulgular, seviye eşlemesi, eşik, veri tamlığı (saf)
  output.ts       text/json biçimleyici, uçbirim arındırma
  exitCodes.ts    sabitler 0–5 ve CliError(code, exitCode, message)
  commands/scan.ts
  commands/bootstrap.ts
```

- **Bağımlılık enjeksiyonu:** `main(deps)` şunları alır: `argv`, `env`,
  `stdout`/`stderr` yazıcıları, `now()`, `sleep(ms)`, `readFile`, `openExclusive`,
  `randomBytes`, `request` (istemci fabrikası). `index.ts` `process.exit()`
  çağırmaz; `process.exitCode` kullanır (Windows'ta boru hattına yazılan
  stdout'un kesilmemesi için).
- **İçe aktarma sınırı:** `src/cli/**` yalnız Node yerleşiklerini, `src/cli/**`
  modüllerini ve `src/lib/outputText.ts` (geçişli olarak `textSanitize.ts`)
  modülünü içe aktarabilir. `express`, `pg`, `exceljs`, `pdfkit`, `dotenv`,
  `src/config/**`, `src/lib/apiKeys.ts` yasaktır. Anahtar kalıbı CLI'da ayrı bir
  sabittir; bir test, `src/lib/apiKeys.ts` `API_KEY_RE` ile kaynak metninin
  eşit olduğunu doğrular. Test: derlenmiş CLI'ı alt süreçte `--version` ile
  çalıştırıp `require.cache` / `process.moduleLoadList` ile `pg`, `express`,
  `dotenv` yüklenmediğini doğrulamak (veya `src/cli/**` içe aktarma grafiğinin
  statik taraması).
- **Sürüm:** `package.json` `rootDir` dışında olduğundan içe aktarılmaz;
  çalışma anında `path.join(__dirname, '..', '..', 'package.json')` okunur
  (hem `dist/cli` hem `src/cli` aynı köke çözülür).
- **Ayrıştırıcı:** komut tablosu `{ scan: { url, project, 'fail-on', format,
  timeout, 'allow-incomplete'(bayrak) }, bootstrap: { url, 'key-file',
  'project-name', 'project-path' } }`; `--ad değer` ve `--ad=değer`; `--`
  desteklenmez. Bilinmeyen/tekrarlanan seçenek, eksik değer, fazla konumsal
  argüman → 2. `--api-key`, `--key`, `--token` (her iki biçimde) tanınır ve
  sabit metinle 2 döner; değer hiçbir yere kopyalanmaz. `--help`/`--version`
  ağ ve anahtar okumadan önce işlenir.
- **Giriş noktası:** `"bin": { "oss-risk": "dist/cli/index.js" }`. tsc shebang
  satırını korur. İş akışları ve README örnekleri `node dist/cli/index.js`
  kullanır (Linux'ta çalıştırma biti tsc tarafından konmaz; `npx oss-risk`
  repo içinde desteklenen kısayoldur — bkz. Karar 11).

### 2. HTTP istemcisi (D-164, D-165; AC-P22-3, AC-P22-4, AC-P22-18, AC-G-8)

`safeHttpClient` **yeniden kullanılmaz**: sunucu tarafı, dış host izin
listeli, SSRF odaklı ve sunucu yapılandırmasına bağlıdır; CLI'ın hedefi tek ve
kullanıcının verdiği sunucudur. CLI için ayrı, küçük bir istemci yazılır:

- **Taşıma:** `node:http` / `node:https` `request`, her istemci için ayrılmış
  `new http.Agent({ keepAlive: false })` / `new https.Agent(...)`. Küresel
  agent ve `fetch` kullanılmaz; böylece `HTTP(S)_PROXY` ve Node 24
  `NODE_USE_ENV_PROXY` hiçbir yoldan devreye girmez. TLS doğrulaması varsayılan
  (açık); kapatma seçeneği yoktur.
- **Adres doğrulaması** (istekten önce, `config.ts`): `new URL()`; protokol
  `http:`/`https:`; `username`/`password`/`search`/`hash` boş; `pathname` yalnız
  `/`. Loopback kümesi `127.0.0.1`, `localhost`, `[::1]` (URL `hostname`
  biçimiyle karşılaştırılır). Loopback dışı + `http:` → 2, sıfır bağlantı.
- **Host ve Origin:** loopback `http:` adreslerinde CLI `Host` başlığını
  **açıkça** `<hostname>:<etkin port>` olarak gönderir (port yazılmamışsa 80;
  sunucu izin listesi her zaman `host:port` bekler, Node varsayılan portta
  portu yazmaz). Oturumlu yazma isteklerinde (yalnız bootstrap) `Origin:
  http://<hostname>:<etkin port>` gönderilir. Bu, sunucunun izin listesinin
  meşru karşılığıdır: istemci tarayıcı değildir, kendi hedefinin kökenini
  beyan eder; sunucu kuralı değişmez. Bearer isteklerinde Origin gönderilmez
  (gerekmez).
- **Başlıklar:** `Accept: application/json`, `User-Agent:
  oss-risk-cli/<sürüm>`, gerekirse `Authorization: Bearer <anahtar>`; JSON
  gövdede `Content-Type: application/json`. Anahtar URL'ye, gövdeye, hata
  nesnesine veya log metnine konmaz; istek seçenek nesnesi hiçbir yerde
  serileştirilmez. Hata metinleri yalnız yöntem, yol ve durum kodundan kurulur.
- **Sınırlar:** istek başına 30 sn **toplam** süre (`setTimeout` +
  `req.destroy`, yalnız soket boşta kalma süresi değil); gövde 32 MiB
  (`Content-Length` ön denetimi + akış sayacı; aşımda bağlantı kesilir, 3).
  En fazla bir eşzamanlı istek (komutlar sıralı `await` eder).
- **Yönlendirme:** `3xx` → 3 ("server responded with a redirect; not
  followed"); `Location` okunmaz ve yazılmaz.
- **HTTP → çıkış kodu eşlemesi:** `401` → 4; `403 forbidden`/RBAC → 4;
  `403 host_rejected` ve `403 origin_rejected` → **2** (adres/port yapılandırma
  hatası; bkz. REQ netleştirmeleri N-1); `409 setup_already_done` (bootstrap)
  → 4; `POST /api/scans` ve `POST /api/projects` `400`/`404` → 2 (sunucu
  `message` metniyle, arındırılmış); bağlantı hatası, zaman aşımı, `5xx`,
  `429`, beklenmeyen durum veya JSON olmayan gövde → 3.

### 3. `scan` akışı, yoklama ve zaman aşımı (D-166, D-172; AC-P22-5…7)

1. Adres + anahtar doğrulaması (2'ler ağdan önce).
2. `--project` UUID biçimindeyse (`/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i`)
   doğrudan kimlik; değilse `GET /api/projects` ve kırpılmış değerle kod
   noktası düzeyinde birebir `name` eşleşmesi (0 → 2 "project not found",
   >1 → 2 "project name is ambiguous; use the project id"). UUID yolunda proje
   adı tarama yanıtındaki `project_name`'den alınır.
3. `POST /api/scans` gövde yalnız `{"projectId": …}`; **yeniden denenmez**
   (yinelenen tarama yaratmamak için; bağlantı hatası → 3).
4. Yoklama: `GET /api/scans/{id}` her 2 sn (`deps.sleep`), uç durumlar
   `completed|failed|cancelled|timeout`. Süre bütçesi (`--timeout`, 10–86 400,
   varsayılan 1800) POST başarısından uç duruma kadar `deps.now()` ile ölçülür;
   aşımda 3 ve "timed out waiting for scan <id>; the scan continues on the
   server". Bulgu ve durum okumaları bütçeye dahil değildir (her biri 30 sn
   istek sınırıyla).
5. Geçici hata (bağlantı, zaman aşımı, `5xx`) yalnız idempotent `GET`'lerde
   yeniden denenir: art arda 3 geçici hata → 3; başarılı yanıt sayacı sıfırlar.
   `4xx` geçici değildir.
6. `failed|cancelled|timeout` → 3; `error_message` `singleLine` ile katlanır, 500
   kod noktasıyla kesilir.

### 4. `--fail-on` değerlendirmesi ve veri tamlığı (D-167…D-171; AC-P22-8…13)

`evaluate.ts` saf işlevlerdir (ağ yok); girdi bulgu dizisi ve durum değeri.

- **Kaynak:** `GET /api/scans/{id}/findings` tek yanıt; sayfalama yoktur
  (Bağlam). Sunucu ileride sayfalama eklerse bu bir contract değişikliğidir;
  CLI yanıt `data` dizisi değilse 3 verir. 32 MiB sınırı aşılırsa 3 ve
  "findings response exceeds 32 MiB" (bkz. N-3).
- **Sayılan:** `status ∈ {open, in_review}` ve `finding_type ∈ {security,
  license}`; `copyright` ve diğer durumlar sayılmaz.
- **Seviye eşlemesi** (sıra `low < medium < high < critical`; `—` = seviye yok,
  hiçbir eşiği tetiklemez):

| Tür | Girdi | Etkin seviye |
| --- | --- | --- |
| security | `severity` = `low`/`medium`/`high`/`critical` | aynen |
| security | `severity` = `none` | — |
| security | `severity` `NULL` veya tanınmayan | `high` |
| license | `risk_level` = `safe` | — (politika tabanı yoksa) |
| license | `risk_level` = `low`/`medium`/`high`/`critical` | aynen |
| license | `risk_level` = `unknown`, `NULL` veya tanınmayan | `high` |
| license | `applied_policy` = `prohibited` / `restricted` / `review_required` | taban `critical` / `high` / `medium` |
| license | `applied_policy` = `approved`, `NULL` veya tanınmayan | taban yok |
| license | — | etkin = max(risk seviyesi, politika tabanı) |

- **Kimlik alanı** (çıktı için): güvenlik `cve_id ?? ghsa_id ?? "-"`; lisans
  `normalized_license ?? detected_license ?? "unknown"`.
- **Eşik:** `none` → eşik ve veri tamlığı değerlendirilmez, tarama
  tamamlandıysa 0. Aksi halde etkin seviyesi ≥ eşik olan sayılan bulgu varsa 1.
- **Veri tamlığı:** tarama `completed` olunca `GET
  /api/vulnerability-data/status` **her zaman** okunur (`scans:read`; çıktıdaki
  `vulnerabilityDataStatus` her zaman dolu olsun diye); `projects[]` içinde
  `latest_scan_id === scanId` öğesinin `vulnerability_data_status`'u. Çıkış
  koduna etkisi yalnız `--fail-on ≠ none` ve eşik aşılmadıysa vardır:
  `complete` → 0; `disabled` → uyarı, 0; `partial`/`unavailable`/`null`/eşleşme
  yok/uç nokta hatası (`unknown`) → 5, `--allow-incomplete` ile uyarı + 0.
  Uç nokta `401/403` dahil her hata `unknown` sayılır (AC-P22-13 metni).
- **Öncelik:** 2/3/4 her zaman önce; sonra 1; sonra 5; sonra 0.
- **Sıralama** (`breaching`): seviye azalan → paket adı (kod noktası) → sürüm
  → kimlik; metinde ilk 20, JSON'da ilk 500 (`breachingTruncated`).

### 5. Çıktı ve uçbirim güvenliği (D-173; AC-P22-14…16)

- `text`: özet stdout'a; ilerleme ve uyarılar stderr'e. `json`: stdout'a tek
  nesne + `\n`, stderr'e hiçbir şey; hata durumunda da (`result: "error"`,
  `error.code`, `error.message`). Kullanım hatasında (`--format` henüz
  ayrıştırılamamışsa) text varsayılır. Alan sırası contract'taki sırayla sabit
  bir nesne kurucudan gelir.
- Uzak/repo kaynaklı her metin: `singleLine` → C0/C1 (U+0000–U+001F,
  U+007F–U+009F) silme → 200 kod noktası. JSON'da `JSON.stringify` kaçışı.
- Anahtar ve parola için ek savunma: `output.ts` yazmadan önce bilinen sırları
  (anahtarın tamamı ve gizli kısmı `S`, bootstrap parolası) metinde arar;
  bulursa `[redacted]` koyar (test bunun hiç tetiklenmediğini de doğrular).

### 6. `bootstrap` (D-174; AC-P22-17)

Akış (tamamı loopback, sunucuda değişiklik yok):

1. Adres loopback değilse 2. `--key-file` zorunlu; `--project-name` ve
   `--project-path` birlikte ya da hiç.
2. **Dosya rezervasyonu ağdan önce:** `fs.open(path, 'wx', 0o600)` (POSIX'te
   umask ancak daraltır; açıldıktan sonra `fstat` ile `mode & 0o077 === 0`
   doğrulanır). `EEXIST` → 2, sıfır istek. Windows'ta mod biti yok sayılır;
   dosya bulunduğu klasörün ACL'ini devralır (`$RUNNER_TEMP` ve kullanıcı
   profili kullanıcıya özeldir). `icacls` gibi alt süreç **çalıştırılmaz**;
   README anahtar dosyasının kullanıcıya ait bir klasörde tutulmasını söyler.
3. Parola: `randomBytes(32).toString('base64url')` (43 karakter, politika
   12–1024 içinde); yalnız yerel değişkende, hiçbir yere yazılmaz.
4. `POST /api/auth/setup` (`Host` + `Origin` Karar 2'deki gibi, JSON gövde).
   `201` → `Set-Cookie` başlığının ilk `ad=değer` çifti alınır (ad
   `^[A-Za-z0-9_]+$`, değer boş olamaz; değilse 3). `409
   setup_already_done` → 4 ve rezerve edilen boş dosya silinir.
5. `POST /api/auth/api-keys` (`Cookie` + `Origin` + `{"name":"bootstrap"}`):
   `requireSameOriginForSessionWrites` oturumlu yazma olarak Origin ister ve
   eşleşen kökenle geçer. Yanıttaki anahtar CLI kalıbıyla doğrulanır.
6. Anahtar rezerve dosyaya yeni satırsız yazılır, `fsync`, kapatılır.
7. İsteğe bağlı proje: `POST /api/projects` **Bearer** ile (`name`, `repoUrl` =
   `path.resolve(projectPath)`, `ecosystems: []`); `400` (ör. `SCAN_ROOTS`
   dışı) → 2. Proje kimliği stdout'a yazılır (anahtar değil).
8. `POST /api/auth/logout` (`Cookie` + `Origin`); başarısızlık yalnız uyarıdır
   (oturum süre sonunda kendiliğinden düşer), çıkış kodunu değiştirmez.
9. Adım 4'ten sonraki bir hatada: rezerve dosya boşsa silinir, hata metni
   "database is now initialised without a usable password; recreate the
   temporary database" uyarısını içerir (geçici CI veritabanı varsayımı).

Not: setup ADR-001 Karar 12 kurtarma durumunda da başarılıdır ve istemci iki
dalı ayıramaz (tasarım gereği). Bu yüzden bootstrap'ın "yalnız boş veritabanı"
güvencesi aslında "parolası olmayan veritabanı"dır (bkz. N-2).

### 7. Eşzamanlı çıktı uç noktaları (D-182…D-185; AC-P24-1…7, AC-P24-12)

- **Yerleşim:** `src/routes/exportRoutes.ts` (üç açık `GET` rotası,
  parametreli dosya adı yok) + `src/controllers/exportController.ts`;
  `app.ts`'de `createNoticeRouter`'dan hemen sonra bağlanır. Her rota
  `guard('reports:read')`. Origin denetimi uygulanmaz (`GET`), Host izin
  listesi uygulanır; oturum veya Bearer.
- **Servis:** `ReportService`'e public `renderExport(scanId, kind, signal)`
  eklenir: `kind ∈ { 'project-report.pdf', 'license-inventory.xlsx',
  'license-inventory.csv' }`. İçeride mevcut `loadReportData` ve
  `renderContent(data, 'project_report', 'pdf')` /
  `renderContent(data, 'license_inventory', 'excel')` çağrılır; CSV yeni
  `src/reports/csv.ts`'den gelir. `reports` satırı, dosya, denetim satırı ve ağ
  isteği **yoktur**. Kopya PDF/Excel kodu yazılmaz.
- **Sıra:** RBAC (`403`) → UUID (`400`, NOTICE ile aynı düzenli ifade ve metin)
  → eşzamanlılık yuvası (`429`) → `loadReportData` (`404`) → üretim →
  başlıklar + gövde. Meşgulken var olmayan tarama için de `429` dönmesi
  bilinçlidir (DB'ye gitmeden reddetmek). Contract bu sırayı yazar.
- **Eşzamanlılık sınırı:** `createApp` içinde kurulan örneğe ait sayaç
  (`ExportLimiter`, en fazla 2; modül düzeyinde küresel durum yok, testler
  birbirini etkilemez — `LoginThrottle` emsali). Yuva `try/finally` ile
  bırakılır; istemci bağlantıyı keserse üretim biter, yuva bırakılır, yanıt
  yazılmaz. Fazlası `sendError(res, 429, 'Too many exports in progress; retry
  shortly', 'export_busy')` + `Retry-After: 5`. NOTICE sınırın dışındadır.
- **Süre:** `exportWorkerConfig.timeoutMs` ile bir `AbortSignal`; `processReport`
  gibi adımlar arasında denetlenir (pdfkit/exceljs üretimi kesilemez).
  Tetiklenirse `500 internal_error` (genel metin; yeni kod yok), ayrıntı yalnız
  sunucu logunda, L-5 arındırmasıyla.
- **Boyut ve bellek:** gövde `Buffer` olarak tamamlanır (`Content-Length` ve
  SHA-256 için gerekli). Yeni boyut sınırı konmaz: PDF satır sınırlıdır,
  Excel/CSV bağımlılık sayısıyla doğrusaldır; 2'lik sınır eşzamanlı tepe belleği
  sınırlar. 10 000 bağımlılıklı fixture'da süre ve boyut ölçülüp handoff'a
  yazılır.
- **Başlıklar:** yalnız başarıda ve gövde hazırken: `Content-Type`,
  `Content-Disposition: attachment; filename="<ad>-<scanId>.<uzantı>"`
  (`scanId` küçük harfe çevrilmiş, proje adı yok), `Content-Length`,
  `X-Checksum-SHA256` (hex), `Cache-Control: no-store`. Hata yanıtları mevcut
  JSON zarfıdır, `Content-Disposition` taşımaz.

### 8. CSV (D-183, D-184; AC-P24-5, AC-P24-6)

- `addDependencyWorksheet`'ten bir **ortak satır kurucusu** çıkarılır:
  `dependencyRowCells(dep): { header: string; value: string | number }[]` (veya
  eşdeğeri). Excel sayfası ve CSV aynı kurucuyu kullanır; böylece başlık,
  sıra ve hücre metni eşitliği yapısal olarak sağlanır (`License` = katlanmış
  etkin lisans, `License Source` = `licenseSourceCell`). Formül koruması
  (`excelSafeText`) kurucuda bir kez uygulanır; CSV tekrar uygulamaz (önek `'`
  ile başlayan metin zaten korumalıdır).
- `csv.ts`: `toCsv(rows): Buffer` — `EF BB BF` + satırlar `\r\n` ile birleşir,
  son satır da `\r\n`; alan `,` `"` `\r` `\n` içeriyorsa veya baştaki/sondaki
  karakter boşluksa `"…"` ve içteki `"` → `""`. `Depth` `String(int)`.
  Belirlenimci (zaman damgası yok).

### 9. V-12 satırı ve PDF kesinti notu (D-187, D-188; AC-P24-10, AC-P24-11)

- `loadReportData` sorgusuna `s.vulnerability_data_status::text` eklenir;
  `ReportData.vulnerabilityDataStatus: string | null`.
- Excel `Summary` sayfasının **son** satırı ve PDF `Summary` anahtar-değer
  listesinin **son** öğesi `Vulnerability Data Status`; değer tek bir eşleme
  tablosundan (`complete`, `partial (some packages could not be checked)`,
  `unavailable (vulnerability source unreachable)`, `disabled (lookup turned
  off)`, `NULL` → `not checked`; tanınmayan değer → `not checked`).
- PDF'teki üç kesilen tablonun (güvenlik 40, lisans 40, bağımlılık 50) her biri
  için toplam > sınır ise tablonun altına `Showing first <n> of <toplam>; see
  the Excel or CSV export for the full list.` Sınırlar değişmez. Asenkron ve
  eşzamanlı yol aynı oluşturucuyu kullandığından ikisinde de görünür.

### 10. Arayüz: indirme bağlantıları ve API anahtarı ekranı (D-186, D-189; AC-P24-8, AC-AK-1…4)

- **Bağlantılar:** `scanActions` `completed` satırında sırayla `PDF`, `Excel`,
  `CSV`, `NOTICE`, `SBOM`; yeni üçü ve NOTICE `download` özniteliği taşır,
  `target` taşımaz; `href` yalnız `apiPath(...)` ile kurulur; `aria-label`
  sabit İngilizce metin. SBOM ve NOTICE adresleri değişmez. Çerez `SameSite=Strict`
  aynı kökenli gezintide gönderilir; JS fetch/Blob indirmesi yapılmaz.
  `429`/`404` durumunda tarayıcı indirmeyi başarısız gösterir (kabul edilen
  sınırlama; README'de "birkaç saniye sonra tekrar deneyin").
- **API Keys görünümü:** `VIEWS`'e yeni görünüm, kenar çubuğu girişi
  `index.html`'de statik işaretlemeyle. Tüm metin `textContent`; olaylar
  `addEventListener` (satır içi `on*` yok, CSP `script-src 'self'` ile
  uyumlu); yeni dış kaynak yok. `POST`/`DELETE` mevcut fetch yardımcısıyla
  aynı kökenden gider; tarayıcı Origin'i kendisi koyar.
- **Tek gösterim:** düz anahtar yalnız oluşturma yanıtını işleyen işlevin yerel
  değişkeninde ve salt okunur `<input>`'un `value`'sundadır; modül düzeyi
  değişkene, `localStorage`/`sessionStorage`'a, URL'ye, `console`'a gitmez.
  Görünüm değişiminde, `pagehide`'da ve oturum kapanışında alan DOM'dan
  kaldırılır. "Copy": `navigator.clipboard.writeText` (loopback güvenli bağlam
  sayılır); yoksa alan seçilir ve kullanıcıya Ctrl+C ipucu gösterilir.
  Aktif anahtar varken oluşturma ve her iptal öncesi mevcut onay deseni
  (ortak modal varsa o, yoksa `window.confirm`).

### 11. GitHub Actions (D-176…D-181; AC-P23-1…9)

Ortak: `permissions: contents: read` (iş akışı düzeyi); tetikleyiciler
`push` (süzgeçsiz), `pull_request` (branch süzgeci yok — yığılı PR'lar için),
`workflow_dispatch`; `concurrency: { group: <workflow>-<ref>,
cancel-in-progress: true }`; yalnız `actions/checkout` ve `actions/setup-node`
(Node 22, `cache: npm`), her biri 40 hex SHA + sürüm yorumu. SHA'ları **ana
oturum** `git ls-remote https://github.com/actions/<ad> refs/tags/<etiket>`
ile doğrular (etiketin işaret ettiği commit; açıklamalı etiketlerde `^{}`
satırı). `actions/checkout` `persist-credentials: false`. `pull_request_target`,
secret, üçüncü taraf eylem yok; `${{ github.event.* }}` ve `${{ inputs.* }}`
yalnız `env:` üzerinden aktarılır. Sekme karakteri yok. `timeout-minutes`
≤ 30.

- **`ci.yml`** — `windows-latest`: checkout → setup-node → `npm ci` → `npm run
  lint` → `npm run typecheck` → `npm test` → `npm run build`. Testler mevcut
  `embedded-postgres` düzeniyle (`--locale=C`; çalıştırıcı yerel ayarı
  İngilizce olsa da bayrak zararsızdır). Ağ koruması aynen etkin.
- **`oss-risk-example.yml`** — `ubuntu-latest`, servis `postgres:17` (sabit
  majör etiket; isteğe bağlı digest sabitlemesi README'de önerilir),
  `POSTGRES_PASSWORD` iş dosyasında açık bir **test değeri** (yalnız iş ömrü
  boyunca yaşayan kapsayıcı; gerçek sır değil), `--health-cmd pg_isready`,
  port `5432:5432`. Adımlar: checkout → setup-node → `npm ci` → `npm run build`
  → hedef hazırlama (`mkdir "$RUNNER_TEMP/oss-risk-target"` ve kök
  `package.json` + `package-lock.json` kopyası) → `npm run db:migrate` →
  `nohup npm start > "$RUNNER_TEMP/server.log" 2>&1 &` (`HOST=127.0.0.1`,
  `PORT=3001`, `DATABASE_URL`, `SCAN_ROOTS`, ağ kipi değişkenleri) → `curl`
  ile `/health` döngüsü en fazla 60 sn → `node dist/cli/index.js bootstrap
  --key-file "$RUNNER_TEMP/oss-risk.key" --project-name oss-risk-self
  --project-path "$RUNNER_TEMP/oss-risk-target"` →
  `OSS_RISK_API_KEY_FILE="$RUNNER_TEMP/oss-risk.key" node dist/cli/index.js
  scan --project oss-risk-self --fail-on critical` (proje adla seçilir; boş
  veritabanında ad tekildir, adımlar arası değer taşınmaz) → `if: always()`
  `tail -n 200` server log.
- **Ağ kipi:** varsayılan `REGISTRY_ENRICHMENT=off`, `VULNERABILITY_LOOKUP=off`,
  `VULNERABILITY_RECHECK=off`; `workflow_dispatch` `online: true` girdisi
  `env: ONLINE: ${{ inputs.online }}` ile alınır ve betik içinde
  değişkenler `$GITHUB_ENV`'e açık değerlerle yazılır. `online`'da
  `--allow-incomplete` verilmez.
- **İlk Linux çalıştırma riski ve yedek:** uygulama şimdiye dek yalnız
  Windows'ta çalıştı (ADR-002 çalışma alanı, ADR-004 tek örnek kilidi, yol
  ayırıcıları). Kırmızıysa önce log incelemesiyle düzeltilir; düzeltilemezse
  iş `windows-latest`'e alınır ve PostgreSQL çalıştırıcıdaki önceden kurulu
  sürümle (`PGBIN`/`PGDATA` ortam değişkenleri, servis başlatma) çalıştırılır.
  Bu geçiş REQ-007'de yeni D-xx ve bu ADR'ye tarihli not gerektirir.
  `embedded-postgres`'i iş akışında başlatmak yeni betik kodu gerektirdiği için
  ikinci yedektir.
- **`npx oss-risk`:** npm 7+ `npm exec`'in kök paketin kendi `bin`'ini
  çözmesine dayanır (doğrulanması gerekiyor). Kabul kriteri ve iş akışları
  `node dist/cli/index.js`'e dayanır; `npx` README'de kolaylık olarak yer alır
  ve bir alt süreç testiyle doğrulanır, başarısızsa README'den çıkarılır.

> **REQ-007 ilk GitHub çalıştırması, D-202 (2026-10-11).** Yukarıdaki "İlk
> Linux çalıştırma riski ve yedek" maddesinin tersi gerçekleşti: Linux yeşil,
> Windows kırmızı. Olgular (commit `2d42488`):
>
> - `oss-risk-example.yml` (`ubuntu-latest`, servis `postgres:17`) ilk Linux
>   çalıştırmasında **yeşil** (run `38122856860`, 50 sn): `bootstrap` →
>   `scan`, 456 bağımlılık, güvenlik bulgusu 0, lisans bulgusu high=2,
>   `Vulnerability data: disabled` (çevrimdışı kip), `--fail-on critical` →
>   `Result: PASS`.
> - `ci.yml` (`windows-latest`) **kırmızı** (run `38122856862`): çalıştırıcı
>   yönetici hesabıyla (`runneradmin`) çalışır; `embedded-postgres`
>   `postgres.exe`'yi doğrudan başlattığı için PostgreSQL "Execution of
>   PostgreSQL by a user with administrative permissions is not permitted"
>   ile reddeder (`initdb` başarılı, başlatma başarısız). `pg_ctl` kısıtlı
>   token ile başlatabilirdi, ancak bu `tests/helpers/pgCluster.ts`'te yeni
>   kod demektir.
>
> **Karar (D-202):** `ci.yml` işi `ubuntu-latest`'e taşınır; adım sırası
> (checkout → setup-node → `npm ci` → lint → typecheck → test → build) ve
> bu bölümdeki ortak sertleştirme kurallarının tümü (izinler, SHA sabitleme,
> `persist-credentials: false`, `concurrency`, `timeout-minutes`, ağ
> koruması, `env:` aktarımı) aynen geçerlidir. Yukarıdaki `ci.yml`
> maddesindeki `windows-latest` ifadesi bu notla geçersizdir; maddenin
> geri kalanı değişmez.
>
> **Gerekçe:** Linux çalıştırıcısı root değildir, `embedded-postgres` orada
> sorunsuz başlar; uygulamanın Linux'ta çalıştığı örnek iş akışıyla
> kanıtlanmıştır; test yardımcısında değişiklik gerekmez.
>
> **Bedel:** CI artık Windows'a özgü yolları (yol ayırıcıları, Türkçe yerel
> ayar, `--locale=C` bayrağının Windows davranışı) sınamaz. Yerel geliştirme
> Windows'ta sürdüğü için bu kapsam yerel test koşularıyla sağlanır;
> handoff'ta Windows yerel test sonucu kanıt olarak yer almalıdır.
>
> **Takip işleri (bu ADR kapsamı dışında, ayrı iş olarak):**
>
> 1. İsteğe bağlı ikinci CI işi: `windows-latest` üzerinde testler — ya
>    `pg_ctl` ile kısıtlı token başlatma (test yardımcısında yeni kod), ya da
>    çalıştırıcıda önceden kurulu PostgreSQL servisi (`PGBIN`/`PGDATA`).
>    Eklenirse yeni D-xx ve tarihli not gerekir.
> 2. `actions/checkout@v4.2.2` ve `actions/setup-node@v4.4.0` node20
>    hedefler; GitHub bunları Node 24'te zorla çalıştırıp uyarı verir. v5
>    sürümlerine geçiş (yeni SHA'ların ana oturumca `git ls-remote` ile
>    doğrulanması dahil) takip işidir.

### 12. Yol sahipliği

| Agent | Yol | İş |
| --- | --- | --- |
| backend-engineer | `src/**` (`src/db/**` hariç), `package.json` (yalnız `bin`), `README.md`, `.github/workflows/**` | CLI, export uç noktaları, CSV, V-12/PDF notu, limiter, iş akışları, README |
| frontend-engineer | `public/**` | bağlantılar, API Keys görünümü |
| qa-automation | `tests/**` | CLI enjekte + alt süreç testleri, CSV golden, jsdom, export testleri, iş akışı statik testi |
| contract-broker | `docs/contracts/**` | REQ-007 contract (+OpenAPI), REQ-004 1.5.0, REQ-005 1.3.0 |
| ana oturum | push, SHA doğrulaması, GitHub çalıştırması, tarayıcı doğrulaması | agent'lara kapalı işler |

`database-engineer` gerekmez (göç yok). Aynı branch'te tek yazar kuralı
gereği backend ve frontend Delivery Lead tarafından sıralanır.

## Gerekçe

- Sunucu tek süreç ve tek örnek kilitlidir (ADR-004); CLI'ın taramayı kendisi
  yapması ikinci bir süreç ve doğrudan DB erişimi demektir. HTTP istemcisi
  yetki, denetim ve karar taşımayı tek yerde tutar.
- Bootstrap için yeni bir sunucu uç noktası açmak kimlik yüzeyini genişletirdi;
  mevcut setup zaten yalnız parolasız veritabanında çalışır. CLI'ın kendi
  hedefinin kökenini `Origin` olarak beyan etmesi CSRF kuralını zayıflatmaz:
  kural tarayıcıların çapraz site isteklerini engellemek içindir ve tarayıcı
  bu başlığı sahteleyemez.
- `node:http` + özel agent, proxy ve yönlendirme davranışını kodla değil
  yapıyla dışlar (fetch'te her ikisi de seçenekle kapatılmalıdır).
- Eşzamanlı çıktı için `ReportService`'in iç yöntemlerini açmak, asenkron ve
  eşzamanlı içeriğin aynılığını kodla garanti eder (AC-P24-3/4).
- Ortak satır kurucusu, CSV ↔ Excel eşitliğini test yerine yapı ile sağlar.

## Değerlendirilen alternatifler

| Alternatif | Neden seçilmedi |
| --- | --- |
| CLI'da `safeHttpClient` yeniden kullanımı | Sunucu yapılandırmasına ve dış host izin listesine bağlı; CLI'ı sunucu modüllerine bağlar, AC-P22-1 yükleme yasağını zorlaştırır. |
| `fetch` (undici) | `redirect: 'manual'` ve proxy dışlaması seçeneğe bağlı; Node 24 `NODE_USE_ENV_PROXY` ile davranış değişebilir; `Host` başlığı açıkça ayarlanamaz. |
| Yeni `POST /api/auth/bootstrap` veya test arka kapısı | Kimlik yüzeyini genişletir; D-174 ve AC-P22-17 "sunucu değişmez" der. |
| Bootstrap'ta `Referer` göndermek | Origin ile eşdeğer; Origin daha açık ve tek başlık yeter. |
| Export'ları asenkron işe bağlayıp CLI/arayüzde yoklamak | "Tek tık" kriterini karşılamaz (D-182). |
| Export'ta `reports` satırı ve dosya önbelleği | Yan etki, disk büyümesi, temizlik ihtiyacı; NOTICE emsali yan etkisizdir. |
| Modül düzeyi küresel limiter | Test yalıtımını bozar; uygulama örneği başına durum mevcut desendir. |
| `ci.yml`'i `ubuntu-latest`'te çalıştırmak | Tam test paketi yalnız Windows'ta yeşil bilinir; REQ Linux tam paket garantisini kapsam dışı bırakır. |
| Örnekte tüm çalışma alanını taramak | `tests/fixtures` bilerek riskli; ölçüt gürültüye bağlanırdı (D-177). |

## Sonuçlar / Uygulama etkisi

- **Yeni dosyalar:** `src/cli/**`, `src/routes/exportRoutes.ts`,
  `src/controllers/exportController.ts`, `src/reports/csv.ts`,
  `src/reports/exportLimiter.ts` (veya `src/lib/`), `.github/workflows/ci.yml`,
  `.github/workflows/oss-risk-example.yml`.
- **Değişen dosyalar:** `src/reports/reportService.ts` (`renderExport`,
  `dependencyRowCells`, V-12 satırı, PDF kesinti notu, sorguya bir sütun),
  `src/app.ts` (router bağlama, limiter örneği), `package.json` (`bin`),
  `README.md`, `public/app.js`, `public/index.html`, gerekirse `public/*.css`.
- **Değişmeyen:** kimlik/oturum/API anahtarı kuralları, mevcut uç nokta
  şemaları, `db/` (göç yok), bağımlılık kümeleri, `.env.example`.
- **Rapor testleri:** yalnız V-12 satırı ve kesinti notu için beklenen
  değerler güncellenir; liste handoff'a yazılır (AC-G-7).
- **Handoff:** non-trivial karar; `docs/handoffs/REQ-007.md` bu ADR'ye
  başvurmalı ve Linux yedeği kullanılırsa tarihli not eklenmelidir.

## Güvenlik etkisi

- **Anahtar sızıntısı:** yalnız env/dosya girişi; argüman reddi; Bearer
  dışında iletim yok; hata metinleri anahtarsız; çıktıda ek redaksiyon;
  loopback dışı `http` reddi; yönlendirme izlenmez; proxy yok. Sunucu logu
  `Authorization` başlığını yazmaz (mevcut davranış; test edilir).
- **Bootstrap:** yalnız loopback; parola bellek içi; anahtar `wx`/`0600`
  dosyada; sunucu kuralı değişmez. Kalıntı risk: kurtarma durumundaki gerçek
  bir veritabanında çalıştırılırsa admin parolası bilinmez hale gelir —
  kurtarma tekrar ADR-001 Karar 12 yoluyla yapılabilir (N-2).
- **Origin beyanı:** CLI'ın Origin göndermesi, yerel makinede kod çalıştırabilen
  herkesin zaten yapabileceği bir şeydir; tehdit modeli (çapraz site tarayıcı
  isteği, DNS rebinding) değişmez.
- **Export uç noktaları:** yan etkisiz `GET`, `reports:read`; `SameSite=Strict`
  ve Host listesi çapraz site/rebinding'i engeller; 2'lik sınır kaynak
  tüketimini sınırlar (API anahtarlı döngü dahil). Dosya adında kullanıcı
  verisi yok (başlık enjeksiyonu yok).
- **CSV/Excel formül enjeksiyonu:** tek kurucuda `excelSafeText`.
- **Uçbirim enjeksiyonu:** ANSI/C0/C1 temizliği, 200 kod noktası.
- **Arayüz:** `textContent`, satır içi olay yok, anahtar depolamaya/konsola
  gitmez; CSP değişmez.
- **İş akışları:** en az izin, SHA sabitleme, `persist-credentials: false`,
  `pull_request_target` yok, ifade enjeksiyonu yok, secret yok; çatal PR'lar
  `pull_request` ile salt okunur token alır. `online` kip paket adlarını OSV ve
  kayıt defterlerine gönderir (yalnız elle).
- Security Red Team incelemesi release öncesi zorunludur.

## Test stratejisi

- **Birim (enjekte, gerçek bekleme yok):** `args.ts` dilbilgisi tablosu (her 2
  vakası); `config.ts` adres/anahtar kuralları; `evaluate.ts` seviye tablosu
  (AC-P22-9'daki altı satır + politika/risk kombinasyonları), eşik, öncelik,
  veri tamlığı (dört durum + eşleşmeme + uç nokta hatası + `--allow-incomplete`);
  yoklama (enjekte saat/uyku: zaman aşımı, 3×`503` → 3, 2×`503` + başarı);
  `output.ts` sıralama, kesme, JSON şeması, ANSI temizliği.
- **İstemci:** `127.0.0.1`'de `node:http` test sunucusu: `302` → 3 ve hedefe
  bağlantı yok; 32 MiB aşımı; 30 sn süre (sahte zamanlayıcı); `HTTP_PROXY` +
  `NODE_USE_ENV_PROXY=1` ayarlıyken tuzak proxy'ye bağlantı olmaması;
  `http://example.com` → 2 ve sıfır bağlantı (ağ koruması ile birlikte);
  varsayılan portta `Host` başlığının `host:80` olması.
- **Uçtan uca (alt süreç, derlenmiş CLI, embedded PG test sunucusu):**
  AC-P22-11 (yüksek bulgu → 1, `false_positive` sonrası yeni tarama → 0,
  seçeneksiz → 1); her çıkış kodu için en az bir senaryo; bootstrap başarı,
  ikinci çalıştırma → 4, var olan dosya → 2, loopback dışı → 2; tüm
  senaryolarda stdout/stderr anahtar, `S` ve parola içermez; `.env`'li klasörde
  anahtar `.env`'den alınmaz; `pg` yüklenmez.
- **Export:** üç uç nokta oturum ve Bearer ile `200` + başlıklar; `400`/`404`;
  limiter (yuvalar dolu → `429` + `Retry-After: 5` + `export_busy`, NOTICE
  etkilenmez); yan etkisizlik (`reports`/`audit_logs` satır sayısı ve çıktı
  klasörü değişmez); asenkron/eşzamanlı PDF metni ve Excel hücre eşitliği;
  CSV ↔ Excel `Dependencies` hücre eşitliği; CSV bayt golden; V-12 beş değer;
  kesinti notu var/yok.
- **Arayüz (jsdom):** bağlantı `href`/`download`/`aria-label`; API Keys
  liste/oluşturma/tek gösterim/görünüm değişince silinme/iptal/hata; depolama
  ve `console` casusları anahtarı görmez.
- **İş akışı statik testi:** metin tabanlı (YAML bağımlılığı yok), AC-P23-8
  listesi + `persist-credentials: false`.
- **Ana oturum:** yerel ön doğrulama (AC-P23-7), GitHub çalıştırması
  (AC-P23-6), gerçek tarayıcıda dört indirme (AC-P24-9).

## Kanıt (Evidence)

- Repo kodu (`afc43ee`): `src/app.ts`, `src/middleware/{requestGuards,
  authenticate}.ts`, `src/routes/{authRoutes,scanRoutes,noticeRoutes,
  projectRoutes,reportRoutes,vulnerabilityStatusRoutes}.ts`,
  `src/controllers/{authController,scanController,projectController,
  noticeController}.ts`, `src/lib/{sessions,apiKeys,password,outputText}.ts`,
  `src/reports/{reportService,worker.config}.ts`, `src/config/env.ts`,
  `src/middleware/securityHeaders.ts`, `public/app.js` (`scanActions`),
  `db/schema.sql` (enum'lar), `package.json`, `tsconfig.json`.
- Genel bilgiye dayanan, **doğrulanması gereken** noktalar (güven orta-yüksek):
  GitHub servis kapsayıcılarının yalnız Linux çalıştırıcılarda olması;
  `windows-latest` imajında önceden kurulu PostgreSQL ve `PGBIN`/`PGDATA`;
  `workflow_dispatch`'in yalnız varsayılan branch'teki dosyayla elle
  tetiklenebilmesi; npm `exec`'in kök paket `bin`'ini çözmesi; Node 24
  `NODE_USE_ENV_PROXY`'nin özel agent'lara uygulanmaması; tarayıcıların
  `http://127.0.0.1`'i güvenli bağlam sayması (Clipboard API).
- NotebookLM ve Obsidian kaynağı kullanılmamıştır.

## İlgili REQ / AC

REQ-007 r1: AC-G-1…9, AC-P22-1…18, AC-P23-1…9, AC-P24-1…12, AC-AK-1…4;
D-161…D-193.

## REQ-007 netleştirmeleri

- **N-1 (AC-P22-12):** `403` her zaman 4 değildir. `403 host_rejected` /
  `403 origin_rejected` yanlış adres veya port demektir (sunucu izin listesi
  bağlı porttan türetilir); bu ADR bunları **2** sayar. Contract çıkış kodu
  tablosuna eklenmelidir.
- **N-2 (AC-P22-17, D-174):** "yalnız boş veritabanı" sunucuda "parolası olmayan
  veritabanı"dır: setup ADR-001 Karar 12 kurtarma dalında da `201` döner ve
  istemci ayırt edemez. Bootstrap kurtarma bekleyen gerçek bir veritabanında
  admin parolasını bilinmeyen bir değere ayarlar. README uyarısı zorunludur;
  ek bir onay bayrağı gerekip gerekmediği Product Analyst kararıdır (bu ADR
  eklemez).
- **N-3 (AC-P22-18):** bulgu ve proje listeleri sayfalamasızdır ve bulgu
  satırları `vuln_description` taşır; çok büyük taramalarda 32 MiB sınırı
  aşılabilir (→ 3, açık mesaj). D-175 gereği yeni uç nokta açılmaz; ölçülen
  boyut 10 000 bağımlılıklı fixture'da handoff'a yazılır.
- **N-4 (AC-P22-4):** loopback dışı `https` adresi yalnız TLS sonlandıran bir
  ara katman `Host`'u `127.0.0.1:<port>` (veya `HOST:<port>`) olarak iletirse
  çalışır; aksi halde `403 host_rejected` (→ 2). Uzak sunucu kapsam dışı
  olduğundan sunucu değişmez; README bunu söyler.
- **N-5 (AC-P22-1):** `npx oss-risk` doğrulanması gereken bir npm davranışına
  dayanır; ölçüt ve iş akışları `node dist/cli/index.js` kullanır.
- **N-6 (AC-P24-1/7):** hata önceliği `403 → 400 → 429 → 404`; meşgulken var
  olmayan tarama için de `429` döner. Contract bu sırayı yazmalıdır.
- **N-7 (AC-P24-11):** PDF'te kesilen tablo üçtür (güvenlik 40, lisans 40,
  bağımlılık 50); not her birine ayrı uygulanır.
- **N-8 (AC-P22-10, AC-P22-13–15):** `--fail-on none` "veri tamlığı
  değerlendirilmez" der, ama metin/JSON çıktısı `vulnerabilityDataStatus`
  ister. Bu ADR durumu tarama tamamlanınca **her zaman okur** (tek ek `GET`,
  çıktı her zaman dolu); çıkış koduna etkisi yalnız `--fail-on ≠ none` ve eşik
  aşılmadığında vardır. AC'lerin çıkış kodu kuralı değişmez.

## Açık noktalar

Yok. Kullanıcının 2026-10-11 daimi talimatı gereği önerilen seçenekler
alınmıştır; doğrulanacak dış davranışların yedekleri tanımlıdır.

## Onay (Approval)

- **Karar veren:** kullanıcı daimi talimatı (önerilen seçenek), 2026-10-11
  ("bana soru sorma önerilen seçeneklerle devam et"; REQ-007'de kayıtlı).
  Durum `Accepted`. Karar ana oturum aracılığıyla iletilmiştir; kullanıcının
  bu dosyayı gözden geçirip commit etmesi kaydı kesinleştirir.
- Implementation öncesi insan onayı gerektiren öğeler
  (`.claude/rules/autonomy-gates.md`):
  - **kimlik yüzeyi:** API anahtarı ekranı ve bootstrap (sunucu kuralı
    değişmez, yeni rol/izin yok);
  - **dış sistem:** GitHub'a push ve iş akışı çalıştırması; `online` kipte
    OSV/kayıt defteri erişimi (yalnız elle);
  - veri modeli değişikliği **yoktur** (göç yok), yeni bağımlılık **yoktur**.
- Gerekenler: `docs/ownership/REQ-007.json` `status: approved`
  (`devflow-manifest 007` kullanıcı tarafından); manifest `.github/workflows/**`
  ve `package.json` için sahibi açıkça belirtmeli; release öncesi Security Red
  Team incelemesi zorunlu.
- F4/F5 `main`'e birleşmeden F6 birleştirilmez. Merge insan onayıdır.
