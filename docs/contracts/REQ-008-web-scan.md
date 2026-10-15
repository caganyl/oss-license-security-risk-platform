# REQ-008 Contract — Web (URL) güvenlik taraması

- **Sürüm:** 1.0.0 (2026-10-15)
- **İlgili:** REQ-008, ADR-010
- **Kapsam:** ortam değişkenleri, veritabanı (göç `009_web_scan`), HTTP API,
  kural kataloğu, kütüphane imzaları, not hesabı, ZAP kullanımı, uyarı
  satırları, CSV biçimi.

## 1. Ortam değişkenleri

| Değişken | Varsayılan | Kural |
| --- | --- | --- |
| `WEB_SCAN_ALLOWED_HOSTS` | boş (kapalı) | Virgül/boşluk ayrılmış. Girdi: `host`, `*.alan`, IPv4, `[IPv6]`. Şema, port, yol, `*` tek başına, `*.` sonrası tek etiket (`*.com`) geçersizdir → başlangıç hatası: `WEB_SCAN_ALLOWED_HOSTS geçersiz bir girdi içeriyor.` |
| `WEB_SCAN_TIMEOUT_MS` | `15000` | 1000–120000 tam sayı; dışı → varsayılan + tek uyarı (değer yazılmaz). |
| `ZAP_API_URL` | boş (ZAP yok) | `https://…` veya `http://` + loopback host (`127.0.0.1`, `localhost`, `[::1]`). Yol yok sayılır, origin kullanılır. Geçersiz → uyarı `ZAP_API_URL geçersiz; ZAP kullanılmayacak.` |
| `ZAP_API_KEY` | boş | ZAP'a `X-ZAP-API-Key` başlığıyla gider. Hiçbir yere yazılmaz. |

Eşleşme: host küçük harfe çevrilir, sondaki `.` atılır; IPv6 köşeli
parantezsiz karşılaştırılır. `*.sirket.com` → `a.sirket.com`,
`a.b.sirket.com` eşleşir; `sirket.com` ve `kotusirket.com` eşleşmez.

## 2. Veritabanı (`009_web_scan`)

### 2.1 `projects`

| Sütun | Tür | Kural |
| --- | --- | --- |
| `web_url` | `TEXT NULL` | `projects_web_url_len_chk`: NULL veya 1–2048 karakter |
| `web_scan_mode` | `TEXT NOT NULL DEFAULT 'passive'` | `projects_web_scan_mode_chk`: `passive` \| `active` |

### 2.2 `scans`

| Sütun | Tür | Kural |
| --- | --- | --- |
| `scan_kind` | `TEXT NOT NULL DEFAULT 'dependency'` | `scans_scan_kind_chk`: `dependency` \| `web` |
| `target_url` | `TEXT NULL` | `scans_web_target_chk`: `(scan_kind = 'web') = (target_url IS NOT NULL)`; ≤ 2048 |
| `web_summary` | `JSONB NULL` | Yalnız tamamlanmış web taramasında dolu (§2.5) |

### 2.3 `web_findings`

| Sütun | Tür | Kural |
| --- | --- | --- |
| `id` | `UUID PK` | `gen_random_uuid()` |
| `scan_id` | `UUID NOT NULL` | → `scans(id)` `ON DELETE CASCADE` |
| `project_id` | `UUID NOT NULL` | → `projects(id)` `ON DELETE CASCADE` |
| `rule_id` | `TEXT NOT NULL` | `^(WEB-[A-Z]{3,4}-[0-9]{3}\|ZAP-[0-9]{1,9})$` |
| `source` | `TEXT NOT NULL` | `builtin` \| `zap` |
| `category` | `TEXT NOT NULL` | `transport`, `headers`, `disclosure`, `cookies`, `cors`, `exposure`, `content`, `components`, `zap` |
| `severity` | `TEXT NOT NULL` | `info`, `low`, `medium`, `high`, `critical` |
| `confidence` | `TEXT NOT NULL DEFAULT 'high'` | `low`, `medium`, `high` |
| `title` | `TEXT NOT NULL` | ≤ 300 |
| `description` | `TEXT NOT NULL` | ≤ 4000 |
| `recommendation` | `TEXT NOT NULL` | ≤ 4000 |
| `location` | `TEXT NULL` | ≤ 2048; sorgu dizesi ve parça olmadan URL |
| `evidence` | `TEXT NULL` | ≤ 2000 (yerleşik kurallar 500) |
| `cwe_id` | `INTEGER NULL` | > 0 |
| `owasp` | `TEXT NULL` | `^A(0[1-9]\|10):2021$` |
| `vulnerability_id` | `UUID NULL` | → `vulnerabilities(id)` |
| `component_name`, `component_version`, `fixed_version` | `TEXT NULL` | ≤ 214 |
| `cvss_score` | `NUMERIC(4,1) NULL` | 0–10 |
| `fingerprint` | `CHAR(64) NOT NULL` | küçük harf hex; `UNIQUE (scan_id, fingerprint)` |
| `status` | `finding_status NOT NULL DEFAULT 'open'` | |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT NOW()` | |

İndeks: `web_findings_project_fingerprint_idx (project_id, fingerprint)`.

### 2.4 `web_scan_components`

| Sütun | Tür | Kural |
| --- | --- | --- |
| `id` | `UUID PK` | |
| `scan_id` | `UUID NOT NULL` | → `scans(id)` `ON DELETE CASCADE` |
| `name` | `TEXT NOT NULL` | görünen ad (≤ 100) |
| `npm_name` | `TEXT NULL` | OSV'ye giden npm adı (≤ 214) |
| `version` | `TEXT NOT NULL` | ≤ 64 |
| `detection` | `TEXT NOT NULL` | `url`, `banner`, `html` |
| `location` | `TEXT NULL` | ≤ 2048 |
| `created_at` | `TIMESTAMPTZ` | |

`UNIQUE (scan_id, name, version)`.

### 2.5 `web_summary` (sürüm 1)

```json
{
  "version": 1,
  "requests": 57,
  "request_limit_reached": false,
  "final_url": "https://portal.sirket.local/Account/Login",
  "tls": { "protocol": "TLSv1.3", "valid_to": "2027-01-02T00:00:00.000Z", "issuer": "Sirket Ic CA" },
  "engines": { "builtin": "complete", "zap": "not_configured", "zap_mode": null },
  "vulnerability_lookup": "complete",
  "components": 3,
  "counts": { "critical": 0, "high": 1, "medium": 3, "low": 4, "info": 1 },
  "score": 56,
  "grade": "D"
}
```

- `engines.builtin`: `complete` | `partial` (istek bütçesi bitti veya TLS
  doğrulanamadığı için içerik kontrolleri atlandı).
- `engines.zap`: `not_configured` | `complete` | `partial` | `unavailable` |
  `failed`; `zap_mode`: `passive` | `active` | `null`.
- `vulnerability_lookup`: `complete` | `partial` | `unavailable` |
  `disabled` | `not_needed` (sorgulanacak bileşen yok).
- `tls` yalnız `https` hedefte ve sertifika okunabildiyse; aksi `null`.

## 3. HTTP API

Tümü mevcut kimlik doğrulama, Host/Origin ve RBAC kurallarıyla.

### 3.1 `GET /api/projects` (değişti)

Her öğeye `web_url` (string|null) ve `web_scan_mode` eklenir.

### 3.2 `POST /api/projects` (değişti)

Gövdeye isteğe bağlı `webUrl` (string). Kural ihlali `400 web_url_invalid`,
izin listesi dışı `400 web_url_not_allowed`. `repoUrl` eskisi gibi isteğe
bağlıdır (kaynaksız proje kaydı davranışı değişmez). `webUrl` denetimi
`repoUrl` denetiminden sonra, proje yazılmadan önce yapılır. Yanıtta
`web_url`, `web_scan_mode`.

### 3.3 `PATCH /api/projects/{id}` (yeni, `projects:write`)

Gövde: `{ "webUrl"?: string | null, "webScanMode"?: "passive" | "active" }`.
En az bir alan; başka anahtar → `400 invalid_request`. `id` UUID değil → `400`.
Proje yok/silinmiş → `404`. `200 { data: <proje, §3.1 biçimi> }`.
Denetim: `project_updated`, `old_data`/`new_data` = `{ web_url, web_scan_mode }`.

### 3.4 `POST /api/scans` (değişti)

Gövdeye isteğe bağlı `kind`: `"dependency"` (varsayılan) | `"web"`. Başka
değer `400 invalid_request`. `web` için: proje `web_url` yok →
`400 project_web_url_missing`; izin listesi dışı → `400 web_url_not_allowed`.
`ref`, `refType` web taramasında yok sayılır (`NULL`).

### 3.5 Tarama yanıtları (değişti)

`POST /api/scans`, `GET /api/scans`, `GET /api/scans/{id}` öğelerine
`scan_kind`, `target_url`, `web_summary` eklenir.

### 3.6 `GET /api/scans/{id}/web-findings` (yeni, `findings:read`)

`id` UUID değil → `400`; tarama yok, bağımlılık taraması veya tamamlanmamış
→ `404 Scan not found or not a completed web scan`.

```json
{
  "data": {
    "scan": { "id": "…", "project_id": "…", "project_name": "Portal", "target_url": "https://…/", "completed_at": "…" },
    "score": 56, "grade": "D",
    "counts": { "critical": 0, "high": 1, "medium": 3, "low": 4, "info": 1 },
    "summary": { "…": "web_summary" },
    "findings": [{
      "id": "…", "rule_id": "WEB-HDR-001", "source": "builtin", "category": "headers",
      "severity": "medium", "confidence": "high", "title": "…", "description": "…",
      "recommendation": "…", "location": "https://…/", "evidence": "…",
      "cwe_id": 319, "owasp": "A05:2021", "component_name": null, "component_version": null,
      "fixed_version": null, "cvss_score": null, "advisory_id": null, "status": "open"
    }],
    "components": [{ "name": "jQuery", "npm_name": "jquery", "version": "3.4.1", "detection": "url", "location": "https://…/js/jquery-3.4.1.min.js" }]
  }
}
```

Sıralama: önem (critical→info), sonra `rule_id`, sonra `location`.
`advisory_id` = `vulnerabilities.cve_id` ?? `ghsa_id` ?? `osv_id`.

### 3.7 Çıktılar (yeni)

| Uç nokta (`reports:read`) | İçerik | Dosya adı |
| --- | --- | --- |
| `GET /api/scans/{id}/exports/web-report.pdf` | Web güvenlik raporu | `web-report-<scanId>.pdf` |
| `GET /api/scans/{id}/exports/web-findings.csv` | Bulgular CSV (§9) | `web-findings-<scanId>.csv` |

Başlıklar, `429 export_busy` sınırı ve hata sırası REQ-007 contract §6 ile
aynı. Bağımlılık taraması için `404`.

Mevcut `project-report.pdf`, `license-inventory.xlsx`, `license-inventory.csv`,
`notice` ve SBOM üretimi web taraması için `404` döner
(`Scan not found or not yet completed` metni korunur).

## 4. Kural kataloğu (yerleşik motor)

| Kural | Kategori | Önem | Başlık | CWE | OWASP |
| --- | --- | --- | --- | --- | --- |
| WEB-TLS-001 | transport | high | Uygulama şifresiz HTTP üzerinden sunuluyor | 319 | A02:2021 |
| WEB-TLS-002 | transport | medium | HTTP istekleri HTTPS'e yönlendirilmiyor | 319 | A02:2021 |
| WEB-TLS-003 | transport | high | TLS sertifikası doğrulanamadı | 295 | A02:2021 |
| WEB-TLS-004 | transport | medium | TLS sertifikasının süresi 30 gün içinde doluyor | 298 | A02:2021 |
| WEB-TLS-005 | transport | medium | Eski TLS sürümü (1.0/1.1) kabul ediliyor | 327 | A02:2021 |
| WEB-HDR-001 | headers | medium | Strict-Transport-Security (HSTS) başlığı yok | 319 | A05:2021 |
| WEB-HDR-002 | headers | low | HSTS süresi kısa (180 günden az) | 319 | A05:2021 |
| WEB-HDR-003 | headers | medium | Content-Security-Policy (CSP) başlığı yok | 693 | A05:2021 |
| WEB-HDR-004 | headers | low | CSP betik kaynaklarına gevşek izin veriyor | 693 | A05:2021 |
| WEB-HDR-005 | headers | medium | Clickjacking koruması yok | 1021 | A05:2021 |
| WEB-HDR-006 | headers | low | X-Content-Type-Options: nosniff yok | 693 | A05:2021 |
| WEB-HDR-007 | headers | low | Referrer-Policy başlığı yok | 200 | A05:2021 |
| WEB-HDR-008 | headers | info | Permissions-Policy başlığı yok | 693 | A05:2021 |
| WEB-INF-001 | disclosure | low | Sunucu yazılımı ve sürümü ifşa ediliyor | 200 | A05:2021 |
| WEB-INF-002 | disclosure | low | X-Powered-By başlığı teknoloji bilgisi ifşa ediyor | 200 | A05:2021 |
| WEB-INF-003 | disclosure | low | ASP.NET sürüm başlıkları ifşa ediliyor | 200 | A05:2021 |
| WEB-INF-004 | disclosure | medium | Ayrıntılı hata sayfası veya yığın izi gösteriliyor | 209 | A05:2021 |
| WEB-INF-005 | disclosure | medium | Dizin listeleme açık | 548 | A05:2021 |
| WEB-CKE-001 | cookies | medium | Çerez Secure bayrağı olmadan gönderiliyor | 614 | A05:2021 |
| WEB-CKE-002 | cookies | medium (oturum çerezi) / low | Çerez HttpOnly bayrağı olmadan gönderiliyor | 1004 | A05:2021 |
| WEB-CKE-003 | cookies | low | Çerezde SameSite özniteliği yok | 1275 | A01:2021 |
| WEB-CORS-001 | cors | high | CORS her kaynağa kimlik bilgisiyle izin veriyor | 942 | A05:2021 |
| WEB-CORS-002 | cors | low | CORS her kaynağa izin veriyor | 942 | A05:2021 |
| WEB-EXP-001 | exposure | high | .git klasörü erişilebilir | 527 | A05:2021 |
| WEB-EXP-002 | exposure | high | .env dosyası erişilebilir | 538 | A05:2021 |
| WEB-EXP-003 | exposure | high | .NET yapılandırma dosyası erişilebilir | 538 | A05:2021 |
| WEB-EXP-004 | exposure | high | ASP.NET tanılama sayfası açık | 215 | A05:2021 |
| WEB-EXP-005 | exposure | medium | Sürüm kontrol veya sistem meta dosyası erişilebilir | 527 | A05:2021 |
| WEB-EXP-006 | exposure | medium | Sunucu durum/bilgi sayfası açık | 200 | A05:2021 |
| WEB-EXP-007 | exposure | low | API dokümantasyonu herkese açık | 200 | A05:2021 |
| WEB-CNT-001 | content | medium | HTTPS sayfası HTTP üzerinden içerik yüklüyor (karma içerik) | 319 | A02:2021 |
| WEB-CNT-002 | content | low | Harici betiklerde alt kaynak bütünlüğü (SRI) yok | 353 | A08:2021 |
| WEB-CNT-003 | content | medium | Form verisi HTTP üzerinden gönderiliyor | 319 | A02:2021 |
| WEB-LIB-001 | components | CVSS'ten (§4.4) | Bilinen açığı olan JavaScript kütüphanesi | 1104 | A06:2021 |

Açıklama ve öneri metinleri `src/webscan/rules.ts`'tedir (bu tablo ile birebir).

### 4.1 Tetikleme kuralları (özet)

- **Başlık kuralları** ana sayfanın son (yönlendirme sonrası) yanıtına
  uygulanır. `WEB-HDR-003/004/005/007/008` yalnız `Content-Type` `text/html`
  ise. `WEB-HDR-001/002` yalnız `https` yanıtında. `Content-Security-Policy-
  Report-Only` CSP sayılmaz (kanıtta belirtilir).
- **HSTS:** `max-age` yok/geçersiz → `WEB-HDR-001`; `< 15552000` →
  `WEB-HDR-002`.
- **CSP gevşek:** `script-src` (yoksa `default-src`) içinde `'unsafe-eval'`;
  veya nonce/hash/`'strict-dynamic'` olmadan `'unsafe-inline'`; veya `*`,
  `http:`, `https:`, `data:` kaynağı. Kanıt: eşleşen belirteçler.
- **Clickjacking:** `X-Frame-Options` `DENY`/`SAMEORIGIN` değil **ve** CSP'de
  `frame-ancestors` yok.
- **WEB-INF-001:** `Server` değerinde `\d+\.\d+` sürüm deseni.
- **WEB-INF-003:** `X-AspNet-Version` veya `X-AspNetMvc-Version` var.
- **WEB-INF-004:** iki yoklama (`<taban>oss-risk-<rastgele>.aspx` ve
  `<taban>%3C%3E`) ve ana sayfa gövdesinde §4.2 hata desenleri (durum kodundan
  bağımsız). Kanıt: desen etiketi.
- **WEB-INF-005:** ana sayfa ve aynı hosttaki betiklerin üst klasörleri (en
  fazla 3) için dizin listeleme desenleri.
- **Çerezler:** ana sayfa zincirindeki `Set-Cookie`; çerez adı başına.
  `WEB-CKE-001` yalnız `https` sayfada. Oturum çerezi adları REQ-008 D-239.
- **CORS:** ana sayfaya `Origin: https://oss-risk-cors-probe.invalid` ve
  `Origin: null` ile iki istek. `Access-Control-Allow-Origin` gönderilen
  değerle aynı (veya `null`) **ve** `Access-Control-Allow-Credentials: true`
  → `WEB-CORS-001`; aynı ama kimlik bilgisiz veya `*` → `WEB-CORS-002`.
- **WEB-TLS-002:** `https` hedefin `http://` varyantı `2xx` dönerse (ve
  `Location` `https://` değilse). Bağlantı hatası bulgu değildir.
- **WEB-TLS-004:** eş sertifikanın `valid_to` değeri tarama anından itibaren
  30 gün içinde.
- **İçerik:** `https` sayfada `http://` `script[src]`, `link[rel~=stylesheet][href]`,
  `iframe[src]` → `WEB-CNT-001`; başka hosttaki `script[src]` `integrity`
  özniteliksiz → `WEB-CNT-002` (tek bulgu, en fazla 10 adres);
  `form[action]` `http://` (sayfa `https`) → `WEB-CNT-003`.

### 4.2 Hata ve dizin listeleme desenleri

| Etiket | Desen |
| --- | --- |
| `aspnet-ysod` | `Server Error in '…' Application` |
| `aspnet-version-info` | `Version Information:` + `ASP.NET Version` |
| `aspnetcore-developer-page` | `An unhandled exception occurred while processing the request` |
| `stack-trace-dotnet` | `Stack Trace:` ve `at System.` |
| `python-traceback` | `Traceback (most recent call last)` |
| `werkzeug-debugger` | `Werkzeug Debugger` |
| `laravel-whoops` | `Whoops! There was an error` |
| `java-exception` | `java.lang.…Exception` ve satır başında `at ` |
| `sql-error` | `SQLSTATE[`, `ORA-0…`, `Microsoft OLE DB Provider`, `Unclosed quotation mark` |
| `dir-apache-nginx` | `<title>Index of /` |
| `dir-iis` | `[To Parent Directory]` |
| `dir-python` | `<title>Directory listing for` |

### 4.3 Yoklama yolları ve içerik doğrulaması

Her yol kökte ve (farklıysa) hedefin taban yolunda denenir. Bulgu için yanıt
`200`, gövde soft-404 gövdesinden farklı (SHA-256) ve doğrulama olumlu olmalıdır.

| Kural | Yol | Doğrulama | Kanıt |
| --- | --- | --- | --- |
| WEB-EXP-001 | `.git/HEAD` | `^ref: refs/` veya `^[0-9a-f]{40}\s*$` | `HEAD dosyası okunabiliyor` |
| WEB-EXP-002 | `.env` | HTML değil; boş/yorum olmayan satırların ≥ %50'si `^[A-Za-z_][A-Za-z0-9_.]*\s*=` ve ≥ 1 satır | `<n> anahtar; ör. DB_HOST, …` (yalnız ilk 5 anahtar adı) |
| WEB-EXP-003 | `appsettings.json`, `appsettings.Development.json`, `appsettings.Production.json` | JSON nesnesi ve `ConnectionStrings`, `Logging`, `AllowedHosts`, `Jwt`, `Kestrel` anahtarlarından biri | eşleşen üst düzey anahtar adları |
| WEB-EXP-003 | `web.config` | `<configuration` içerir | `web.config içeriği okunabiliyor` |
| WEB-EXP-004 | `elmah.axd` | `Error Log for` | `ELMAH hata günlüğü açık` |
| WEB-EXP-004 | `trace.axd` | `Application Trace` veya `Trace Information` | `ASP.NET izleme sayfası açık` |
| WEB-EXP-005 | `.svn/entries` | ilk satır sayı veya `dir` | dosya adı |
| WEB-EXP-005 | `.hg/requires` | `revlogv1` veya `store` | dosya adı |
| WEB-EXP-005 | `.DS_Store` | gövde `\x00\x00\x00\x01Bud1` ile başlar | dosya adı |
| WEB-EXP-006 | `server-status` | `Apache Server Status` | dosya adı |
| WEB-EXP-006 | `server-info` | `Apache Server Information` | dosya adı |
| WEB-EXP-006 | `phpinfo.php` | `phpinfo()` ve `PHP Version` | dosya adı |
| WEB-EXP-007 | `swagger/index.html`, `swagger-ui.html` | `swagger-ui` | dosya adı |
| WEB-EXP-007 | `swagger/v1/swagger.json`, `v3/api-docs`, `openapi.json` | JSON nesnesinde `openapi` veya `swagger` anahtarı | `OpenAPI <sürüm>` |

Bir kural birden çok yolda tetiklenirse her konum ayrı bulgudur
(parmak izi anahtarı = yol).

### 4.4 `WEB-LIB-001` önemi

OSV/NVD normalleştirmesinin önemi (`critical`…`low`); `none` → `low`.
Konum: bileşenin bulunduğu adres; kanıt: `<ad>@<sürüm> — <açık kimliği>`.

## 5. JavaScript kütüphane imzaları

| Ad | npm | Adres/dosya adı | Başlık yorumu / HTML |
| --- | --- | --- | --- |
| jQuery | `jquery` | `jquery[-.]X.Y.Z(.min\|.slim)*.js` | `jQuery (JavaScript Library )?vX.Y.Z` |
| jQuery UI | `jquery-ui` | `jquery-ui[-.]X.Y.Z…js` | `jQuery UI - vX.Y.Z` |
| Bootstrap | `bootstrap` | `bootstrap[-.]X.Y.Z…js` | `Bootstrap vX.Y.Z (https://getbootstrap.com` |
| AngularJS | `angular` | `angular[-.]X.Y.Z…js` | `@license AngularJS vX.Y.Z` |
| Angular | `@angular/core` | — | HTML `ng-version="X.Y.Z"` |
| Vue | `vue` | `vue[-.]X.Y.Z…js` | `Vue.js vX.Y.Z` |
| Lodash | `lodash` | `lodash[-.]X.Y.Z…js` | — |
| Moment | `moment` | `moment[-.]X.Y.Z…js` | `//! moment.js` + `//! version : X.Y.Z` |
| Handlebars | `handlebars` | `handlebars[-.]X.Y.Z…js` | `handlebars vX.Y.Z` |
| Knockout | `knockout` | `knockout[-.]X.Y.Z…js` | `Knockout JavaScript library vX.Y.Z` |
| DOMPurify | `dompurify` | `purify[-.]X.Y.Z…js` | `@license DOMPurify X.Y.Z` |
| Chart.js | `chart.js` | `chart[-.]X.Y.Z…js` | `Chart.js vX.Y.Z` |
| Select2 | `select2` | `select2[-.]X.Y.Z…js` | `Select2 X.Y.Z` |
| React | `react` | `react[-.]X.Y.Z…js` | — |
| React DOM | `react-dom` | `react-dom[-.]X.Y.Z…js` | — |
| Axios | `axios` | `axios[-.]X.Y.Z…js` | — |

CDN adresleri (indirilmez): jsDelivr `/npm/<paket>@<sürüm>/`, unpkg
`/<paket>@<sürüm>/` (paket adı olduğu gibi npm adıdır), cdnjs
`/ajax/libs/<lib>/<sürüm>/` (eşleme: `jquery`, `jqueryui`→`jquery-ui`,
`twitter-bootstrap`→`bootstrap`, `angular.js`→`angular`, `vue`,
`lodash.js`→`lodash`, `moment.js`→`moment`, `handlebars.js`→`handlebars`,
`knockout`, `dompurify`, `Chart.js`→`chart.js`, `select2`, `react`,
`react-dom`, `axios`). Sürüm `X.Y.Z` (isteğe bağlı `-ön sürüm`); başka biçim
bileşen sayılmaz.

## 6. Not ve skor

`skor = max(0, 100 − 40·critical − 20·high − 8·medium − 2·low)` (bulgu
sayıları, `info` hariç). Not: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.

## 7. ZAP kullanımı

Tüm çağrılar `GET <ZAP origin>/JSON/…` ve `X-ZAP-API-Key` başlığıyla.

| Adım | Uç nokta | Parametreler |
| --- | --- | --- |
| Erişim | `core/view/version/` | — |
| Oturum | `core/action/newSession/` | `name=oss-risk-<scanId>`, `overwrite=true` |
| Tohum | `core/action/accessUrl/` | `url`, `followRedirects=true` |
| Spider | `spider/action/scan/` | `url`, `recurse=true`, `subtreeOnly=true` |
| Durum | `spider/view/status/` | `scanId` |
| Durdur | `spider/action/stop/` | `scanId` |
| Pasif kuyruk | `pscan/view/recordsToScan/` | — |
| Aktif | `ascan/action/scan/` | `url`, `recurse=true`, `inScopeOnly=false` |
| Durum | `ascan/view/status/` | `scanId` |
| Durdur | `ascan/action/stop/` | `scanId` |
| Alarmlar | `alert/view/alerts/` | `baseurl`, `start`, `count=500` (en fazla 10 sayfa) |

Eşleme: `riskcode` 3→high, 2→medium, 1→low, 0→info; `confidence` `0`
(False Positive) atlanır, 1→low, 2→medium, 3/4→high. `cweid` > 0 → `cwe_id`;
`tags` içinde `OWASP_2021_Axx` → `Axx:2021`. Kural `ZAP-<pluginId>`, kategori
`zap`, başlık `alert`/`name`, açıklama `description`, öneri `solution`
(her biri 4000 karaktere kırpılır, kontrol karakterleri silinir), konum ilk
örnek adres, kanıt `n adres: <adres1>, <adres2>, …` (en fazla 10).

## 8. Uyarı satırları (`error_message`)

| Satır | Koşul |
| --- | --- |
| `[web] TLS sertifikası doğrulanamadığı için içerik kontrolleri yapılamadı (<KOD>).` | WEB-TLS-003 |
| `[web] İstek sınırına (120) ulaşıldı; bazı kontroller atlandı.` | bütçe bitti |
| `[web] Ana sayfa başka bir hosta yönlendiriyor; o host taranmadı.` | çapraz host yönlendirme |
| `[web] <n> istek başarısız oldu.` | ana sayfa dışı ağ hataları > 0 |
| `[web] JavaScript kütüphanesi açık sorgusu kapalı (VULNERABILITY_LOOKUP=off).` | |
| `[osv] …` | mevcut REQ-005 satırları (kütüphane sorgusu) |
| `[zap] ZAP API'ye ulaşılamadı (<KOD>); yalnız yerleşik kontroller çalıştı.` | |
| `[zap] ZAP taraması süre sınırında durduruldu; sonuçlar kısmi.` | |
| `[zap] ZAP adımı başarısız oldu (<KOD>).` | |

## 9. CSV (`web-findings.csv`)

UTF-8 + BOM, ayırıcı virgül, satır sonu CRLF, REQ-007 CSV alıntılama ve
formül kalkanı kuralları. Başlık:
`Severity,Rule,Category,Title,Location,Evidence,CWE,OWASP,Component,Version,Fixed Version,CVSS,Advisory,Source,Status,Recommendation`.
Sıralama §3.6 ile aynı.
