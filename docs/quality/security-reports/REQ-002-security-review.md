# REQ-002 — Güvenlik İncelemesi (F1: P-01…P-09)

- İnceleyen: Security Red Team (adversarial review, read-only)
- Tarih: 2026-10-09
- Branch: `req-002-f1-guvenli-temel` (HEAD: `70b863a`)
- Kapsam: P-01 (auth), P-02 (UI XSS), P-03/P-04 (tarama kaynağı, çalışma alanı, SCAN_ROOTS), P-09 (sırlar, `decryptToken`), bağımlılık riski
- Tehdit bağlamı: Yerel, tek kullanıcılı Windows aracı; varsayılan `127.0.0.1`; HTTPS kapsam dışı (kullanıcı kararı). Güvenilmeyen girdiler: taranan repo içeriği, uzak git URL'leri, API'den gelip arayüzde gösterilen veriler, başka sitelerden gelen tarayıcı istekleri (CSRF / DNS rebinding).

> Not: Bu oturumda Bash, rol sınırı hook'u tarafından tamamen engellendi. `npm audit`, `npm test`, `git log/diff`, `git --version` çalıştırılamadı; inceleme Read/Grep/Glob ile statik olarak yapıldı. Ayrıntı için "İncelenmedi / sınırlı incelendi" bölümüne bakın.

## Özet

| Ciddiyet | Sayı |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low | 7 |
| Info | 4 |

**Merge kararı önerisi: Conditional Go — blocker yok.** Critical veya High bulgu yok. Üç Medium bulgu (M-1 harici CDN betiği, M-2 clone sırasında git filtreleri/LFS üzerinden token sızma olasılığı, M-3 API anahtarının kullanıcı yönetimine tam erişimi) merge'ü teknik olarak engellemiyor. Ancak M-1 ve M-2'nin düzeltmesi küçük; merge'den önce kapatılmaları önerilir. Kapatılmadan merge edilecekse riskin insan tarafından kabul edildiği handoff'a yazılmalı.

## Doğrulanan kontroller (olumlu bulgular)

- Host allow-list (`requireAllowedHost`) statik dosyalar ve `/health` dahil ilk middleware olarak çalışıyor. DNS rebinding'e karşı etkili (`src/app.ts:57`, `src/middleware/requestGuards.ts:26-35`).
- Login/setup her durumda Origin kontrolünden geçiyor. Çerezle yapılan POST/PUT/PATCH/DELETE istekleri de Origin kontrolünden geçiyor. `Origin: null` ve Origin+Referer'ın ikisinin de olmadığı istekler reddediliyor (`requestGuards.ts:55-80`).
- Oturum çerezi `HttpOnly; SameSite=Strict; Path=/`. Token 32 rastgele bayt; DB'de yalnızca SHA-256 özeti tutuluyor. 12 saat boşta kalma ve 7 gün mutlak süre DB saatiyle uygulanıyor (`src/lib/sessions.ts`).
- Login ve setup sonrası her zaman yeni token üretiliyor; oturum sabitleme (session fixation) yolu bulunamadı.
- `Authorization` başlığı varken çerez yok sayılıyor; geçersiz anahtar tarayıcı oturumuna geri düşmüyor (`authenticate.ts:13-18`). Anahtar sorgu dizesinden okunmuyor.
- Parola scrypt (N=2^17) + tuz ile saklanıyor; karşılaştırma `timingSafeEqual` ile yapılıyor. Tek kullanıcı olduğundan kullanıcı adı sızdıran bir zamanlama farkı yok.
- API anahtarında yalnızca SHA-256 saklanıyor. Önek yalnızca görüntüleme amaçlı, arama için kullanılmıyor. Anahtar yenileme kullanıcı satırı kilitlenerek tek transaction'da yapılıyor ve kısmi unique index ile destekleniyor.
- Setup yarışı: aday satırlar `FOR UPDATE` ile kilitleniyor, `idx_users_single_password` ve `users.email` unique ihlalinde 409 dönüyor.
- 5xx yanıtları sabit metin dönüyor. `/health` ham DB mesajını döndürmüyor; log'a yalnızca sınıf/kod yazılıyor.
- Git `spawn(..., {shell:false})` ile çalışıyor. URL'den önce `--` kullanılıyor; `-` ile başlayan değer reddediliyor. Ref için allow-list regex var. `GIT_ALLOW_PROTOCOL=https`, `core.symlinks=false`, `credential.helper=` ayarlı; `--depth 1 --single-branch --no-tags` kullanılıyor ve submodule recursion yok.
- Token URL'de, argümanlarda veya `.git/config` içinde yer almıyor; `GIT_CONFIG_*` ortam değişkenleriyle aktarılıyor. stderr'den token hem ham hem base64 biçimiyle temizleniyor.
- `decryptToken` üç D-14 durumunun her birinde sabit mesajlı hata fırlatıyor; düz metne geri düşüş yok (`worker.ts:57-78`).
- Alt süreç ortamından `DATABASE_URL`, `PGPASSWORD`, `ENCRYPTION_KEY` vb. çıkarılıyor (`sanitizedChildEnv`).
- SCAN_ROOTS: `realpath.native` `..`, junction, subst ve 8.3 kısa adları çözüyor. Windows'ta yalnızca sürücü harfli yol kabul ediliyor; UNC, `\\?\` ve `\\.\` reddediliyor. Karşılaştırma büyük/küçük harfe duyarsız ve ayraç eklenmiş önekle yapılıyor (`…\kok\ab` kaçışı yok). Worker yolu yeniden doğruluyor (TOCTOU).
- Python ayrıştırıcıları yalnızca `json` ve `tomllib` kullanıyor; `setup.py` veya başka bir repo kodu çalıştırılmıyor. Ayrıştırıcının `cwd` ve `PYTHONPATH` değeri platform kökü; taranan repo `sys.path`'e girmiyor.
- UI: `el()` builder, `textContent`/`createTextNode`, `href` allow-list (`javascript:`, `data:`, `//host` reddediliyor) ve `dataset` kullanılıyor. API verisinden `innerHTML` ile HTML üretilmiyor; inline `on*` handler yok.
- Lock dosyasındaki çözülmüş sürümler güncel: express 4.22.2, body-parser 1.20.5, path-to-regexp 0.1.13, cookie 0.7.2, send 0.19.2, serve-static 1.16.3, qs 6.15.2. Bilinen 2024 CVE'leri (CVE-2024-43796, -45296, -52798, -45590, -43799, -43800, -47764) için düzeltilmiş sürümler kullanılıyor. `npm audit` çalıştırılamadı.
- Çalışma ağacında gerçek parola, token veya özel anahtar bulunamadı (`node_modules`, lock ve PDF hariç). `docker-compose.yml` değerleri `${…:?…}` ile `.env`'den alıyor; Postgres yalnızca `127.0.0.1` üzerinde yayınlanıyor. Test sabitleri (`tests/helpers/http.ts:11`, `tests/helpers/tokenCrypto.ts:24-25`) gizli değer değil, test verisi.

## Bulgular

### M-1 — Arayüz, sürüm sabitlenmemiş ve SRI'sız harici bir betik yüklüyor; CSP yok

- **Ciddiyet:** Medium
- **Konum:** `public/index.html:13` (`<script src="https://unpkg.com/lucide@latest"></script>`), `src/app.ts:55-81` (güvenlik başlığı / CSP yok)
- **Saldırı senaryosu:** unpkg, npm `lucide` paketi veya yayıncı hesabı ele geçirilirse (ya da `@latest` kötü niyetli bir sürüme işaret ederse) betik uygulama origin'inde (`http://127.0.0.1:3001`) çalışır. Çerez HttpOnly olsa da betik same-origin `fetch` ile `POST /api/auth/api-keys` çağırıp düz anahtarı yanıttan okuyabilir ve dışarı gönderebilir. Bu, kalıcı Bearer erişimi demektir. Ardından projeleri, bulguları ve kararları değiştirebilir (ör. false-positive işaretleme). P-02 ile kapatılan XSS sınıfı bu yoldan geri gelir.
- **Kanıt:** Sürüm yok, `integrity` ve `crossorigin` öznitelikleri yok. Yanıtlarda `Content-Security-Policy` başlığı üretilmiyor.
- **Önerilen düzeltme:** lucide'ı sabit bir sürümle `public/vendor/` altına alıp yerelden servis edin (internetsiz çalışma da kazanılır). Bu mümkün değilse en azından sabit sürüm + `integrity="sha384-…"` + `crossorigin="anonymous"` kullanın. Ek olarak `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'` ekleyin. Bunun için inline `<script>` bloğunu ayrı bir dosyaya taşımak veya hash/nonce kullanmak gerekir.
- **İlgili:** AC-P02-2 (ruhu), ADR-001 (oturum/anahtar modeli), K-6

### M-2 — `git clone` sırasında sistem/global git filtreleri (ör. git-lfs) repo içeriğiyle tetiklenebilir; token'ın başka bir hosta gitme olasılığı var

- **Ciddiyet:** Medium (koşullu: git-lfs kurulu olmalı. Git for Windows bunu varsayılan olarak kurar ve `filter.lfs.*` ayarlarını system config'e yazar)
- **Konum:** `src/scanner/workspace.ts:40-53` (`buildGitCloneArgs`), `src/scanner/workspace.ts:97-117` (`http.extraHeader`, env)
- **Saldırı senaryosu:** Kullanıcı bir integration token'ıyla (ör. geniş yetkili PAT) güvenilmeyen içerikli bir repoyu tarar. Repo, LFS işaretçileri, `.gitattributes` (`filter=lfs`) ve bir `.lfsconfig` (`lfs.url = https://saldirgan.example/…`) içerir. Checkout sırasında git-lfs smudge/process filtresi çalışır ve batch isteğini saldırganın URL'sine gönderir. `http.extraHeader` hosta göre sınırlandırılmadığından `Authorization: Basic …` başlığının bu isteğe eklenmesi olasıdır. git-lfs'in global `http.extraHeader` davranışı bu oturumda doğrulanamadı; **doğrulanması gerekiyor**. Ayrıca filtre çalıştırmak, güvenilmeyen içeriğin harici bir ikili dosyayı tetiklemesi anlamına gelir; saldırı yüzeyi büyür. Kurulu git sürümü kontrol edilmiyor; eski bir Git for Windows sürümü clone ile ilgili bilinen CVE'lere açık kalabilir.
- **Kanıt:** Argümanlarda `filter.lfs.*`, `GIT_LFS_SKIP_SMUDGE`, `core.fsmonitor`, `http.followRedirects` veya hosta sınırlı `http.<url>.extraHeader` yok. `GIT_ALLOW_PROTOCOL=https` yalnızca git transport'unu kısıtlar, git-lfs'in HTTP isteklerini kısıtlamaz.
- **Önerilen düzeltme:**
  - Ortama `GIT_LFS_SKIP_SMUDGE=1` ekleyin. Argümanlara `-c filter.lfs.smudge= -c filter.lfs.process= -c filter.lfs.required=false` ekleyin. Tarama için LFS içeriği gerekmez.
  - Başlığı hosta sınırlayın: `GIT_CONFIG_KEY_0=http.https://<host>/.extraHeader`.
  - `-c http.followRedirects=false` (veya en azından `initial`), `-c core.fsmonitor=false`, `-c protocol.file.allow=never` ekleyin. Global template hook'ları devre dışı bırakmak için `-c core.hooksPath=<boş klasör>` veya `--template=` kullanın.
  - Başlangıçta `git --version` ile minimum sürümü (güncel güvenlik sürümü) kontrol edip dokümante edin.
  - Test: `buildGitCloneArgs` çıktısında bu bayrakların ve env değerlerinin olduğunu doğrulayan bir birim testi.
- **İlgili:** ADR-002 karar 3 (token yalnızca ortam üzerinden), AC-P09-5 (token sızmaması), AC-P03-3

### M-3 — Bearer API anahtarı `/api/users` yönetimine tam erişiyor: tek kullanıcı kilitlenebilir, kurtarma akışı bozulabilir

- **Ciddiyet:** Medium
- **Konum:** `src/routes/userRoutes.ts:17-22`, `src/controllers/userController.ts:218-434`; karşılaştırma için `src/routes/authRoutes.ts:24-29` (anahtar yönetimi `requireSession` ile korunuyor)
- **Saldırı senaryosu:** CI log'undan veya ortamdan sızan bir API anahtarı ile:
  1. `PATCH /api/users/<kendi id>` `{"status":"inactive"}` veya `DELETE /api/users/<id>` çağrılır. Login sorgusu `status='active'` ister; `isSetupRequired` parola var olduğu için `false` döner. Sonuç: tüm oturumlar ve anahtarlar ölür, kullanıcı giriş yapamaz. Belgelenmiş kurtarma SQL'i bunu da düzeltmez (yalnızca `password_hash`'i boşaltır; aday sorgusu `status='active'` ister). Manuel DB onarımı gerekir.
  2. `POST /api/users` `{"status":"active","roles":["admin"]}` ile parolasız ikinci bir admin oluşturulur. Kurtarma SQL'inden sonra iki aday olacağından setup `setup_state_invalid` (500) döner; kurtarma kırılır.
  3. `PUT /api/users/:id/roles` ile kendi `admin` rolü kaldırılabilir.

  Kod yorumu (`authenticate.ts:51`) sızan bir CI anahtarının sınırlı olması gerektiğini söylüyor, ancak bu sınır kullanıcı yönetimini kapsamıyor.
- **Kanıt:** `guard('users:write')` gibi kontroller yalnızca rol kontrolü yapar; `authMethod` kontrol edilmez. Admin super-role olduğu için her izin geçer (`permissions.ts:85`).
- **Önerilen düzeltme:** F1 tek kullanıcı modelinde `/api/users` router'ını mount etmeyin (RBAC kodu silinmeden kalır; AC-P01-8 bunu engellemez) veya en az `requireSession()` ekleyin. İsteği yapanın kendi hesabını devre dışı bırakmasını, silmesini veya admin rolünü kaldırmasını yasaklayın. Test: Bearer ile `PATCH/DELETE/POST /api/users` → 403.
- **İlgili:** ADR-001 (oturum vs anahtar yetki ayrımı), AC-P01-8, AC-P01-16

### L-1 — Login throttle eşzamanlı isteklerle aşılabiliyor; global sayaç kilitleme DoS'una izin veriyor

- **Ciddiyet:** Low
- **Konum:** `src/controllers/authController.ts:131-152`, `src/lib/loginThrottle.ts`
- **Saldırı senaryosu:** Kilit durumu scrypt doğrulamasından önce okunuyor, başarısızlık ise doğrulama bittikten sonra kaydediliyor. Aynı anda gönderilen N istek kontrolü birlikte geçer ve hepsi doğrulanır. "5 hata → 30 sn" sınırı her kilit penceresinde topluca aşılır; hızı yalnızca scrypt/libuv havuzu sınırlar. Origin başlığı tarayıcı dışı istemcilerde serbestçe ayarlanabildiği için bu, makinedeki herhangi bir yerel süreç tarafından yapılabilir. Sayaç tek ve globaldir; yerel bir süreç sürekli yanlış denemeyle meşru kullanıcıyı 900 sn'lik kilitte tutabilir (ADR'de kabul edilmiş olabilir).
- **Önerilen düzeltme:** Doğrulama başlamadan önce "uçuştaki deneme" sayacını artırın veya login doğrulamalarını tek bir kuyrukla serileştirin (aynı anda tek scrypt). Kilit kontrolünü `failures + inFlight` üzerinden yapın. Test: paralel 20 yanlış istek → en fazla 5'i 401, kalanı 429.
- **İlgili:** ADR-001 karar 11, AC-P01-6

### L-2 — Parola kurtarma penceresi: setup kimliksiz açık, API anahtarları geçerli kalıyor (bilinen)

- **Ciddiyet:** Low (yerel erişim gerektiriyor; tasarım kararı)
- **Konum:** `db/README.md:159-184`, `src/controllers/authController.ts:45-123`
- **Saldırı senaryosu:** Kurtarma SQL'inden sonra uygulama `setup_required` durumundadır. Kullanıcıdan önce davranan herhangi bir yerel süreç `POST /api/auth/setup` ile (Origin'i elle ayarlayarak) parolayı belirler ve aynı kullanıcının kimliğini, verisini ve anahtar yönetimini ele geçirir. Ayrıca sızmış bir API anahtarı pencere boyunca ve sonrasında geçerlidir (`resolveUser` setup durumundan bağımsız çalışıyor). M-3 ile birleşince anahtar sahibi kurtarmayı bozabilir.
- **Önerilen düzeltme:** README'de kurtarmanın uygulama durdurulmuşken yapılmasını ve uygulama açılır açılmaz setup'ın tamamlanmasını önerin. SQL'e yorum satırı olarak isteğe bağlı bir adım ekleyin: `-- UPDATE api_keys SET revoked_at = now() WHERE revoked_at IS NULL;`. İleride: başlangıçta konsola tek seferlik setup kodu yazdırılıp setup'ta istenmesi.
- **İlgili:** AC-P01-4, AC-P01-16, D-11, D-15

### L-3 — HTTP güvenlik başlıkları yok (clickjacking / MIME sniffing)

- **Ciddiyet:** Low
- **Konum:** `src/app.ts:55-81`
- **Saldırı senaryosu:** `X-Frame-Options` / `frame-ancestors`, `X-Content-Type-Options: nosniff` ve `Referrer-Policy` yok. Cross-site framing'de `SameSite=Strict` çerezi gönderilmez; bu, etkiyi büyük ölçüde sınırlar. Ancak tarayıcılar aynı makinedeki **diğer portları** (ör. `http://localhost:5173`'te çalışan, güvenilmeyen içerik sunan bir dev sunucusu) same-site sayar. O sayfa uygulamayı oturumlu biçimde iframe'e alıp clickjacking deneyebilir (ör. "Generate API Key" butonu). Aynı nedenle same-site GET istekleri çerez taşır; `GET /api/scans/:scanId/sbom/download` (`sbomController.ts:94-126`) yan etki olarak SBOM üretir (yalnızca bütünlük/gürültü etkisi).
- **Önerilen düzeltme:** M-1'deki CSP'ye `frame-ancestors 'none'` + `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` ekleyin (helmet gerekmez, birkaç satır).
- **İlgili:** ADR-001 karar 5

### L-4 — Yerel taramada ağaç içindeki junction/symlink'ler SCAN_ROOTS dışına okumaya ve taramanın çökmesine yol açıyor

- **Ciddiyet:** Low
- **Konum:** `src/scanner/sandbox/parsers/common.py:44-73` (`relative_path`, `discover_manifests` → `Path.rglob`), `nodejs.py:29-30`, `python.py:35` (`scan_file_record` / `relative_path` `try` dışında)
- **Saldırı senaryosu:** SCAN_ROOTS kontrolü yalnızca kök dizin için yapılıyor. Kökün altındaki bir junction (`mklink /J dep C:\Users\x`) Python ≤3.12'de `rglob` tarafından izlenir (junction'lar `is_symlink()` sayılmaz). Dosya symlink'leri de `is_file()` ile izlenir. Kök dışındaki `package.json` / `requirements.txt` okunur ve hash'lenir. Ardından `relative_path` `ValueError` fırlatır; bu `try` dışında olduğu için ayrıştırıcının tamamı çöker. Traceback (kök dışı mutlak yol dahil) `scans.error_message`'a yazılır (`worker.ts:468`). Junction döngüsü uzun süreli taramaya veya DoS'a yol açar. Uzak clone'larda `core.symlinks=false` olduğu ve git junction oluşturamadığı için risk düşük; risk yerel klasörlerle sınırlı.
- **Önerilen düzeltme:** `os.walk(followlinks=False)` kullanın ve reparse point'leri (`os.path.isjunction` (3.12+) / `st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`) ile dosya symlink'lerini atlayın. Bulunan her dosyanın `resolve()` sonucunun kök altında olduğunu doğrulayın; değilse parse_error olarak işaretleyin. `relative_path` / `scan_file_record` çağrılarını `try` içine alın. Test: kök altında kök dışına işaret eden junction → dosya atlanır, tarama `completed`.
- **İlgili:** AC-P04-4, ADR-002 karar 4

### L-5 — Alt süreç çıktısı sınırsız ve ham olarak DB/UI'a yazılıyor

- **Ciddiyet:** Low
- **Konum:** `src/scanner/worker.ts:446` (`stdoutData` sınırsız), `worker.ts:468` (parser stderr → `error_message`), `src/scanner/workspace.ts:143-144` (git stderr → `error_message`)
- **Saldırı senaryosu:** Çok sayıda manifest içeren kötü niyetli bir repo, worker belleğini şişiren bir JSON çıktısı üretebilir. Git stderr'deki uzak sunucu `remote: …` metinleri ve Python traceback'leri (yerel yollar) ham olarak saklanıp gösteriliyor. Token temizleniyor; UI `textContent` kullandığı için XSS yok.
- **Önerilen düzeltme:** stdout için üst sınır koyun (ör. 64 MB; aşılırsa süreci öldürüp taramayı fail edin). `error_message`'a sabit bir özet ve stderr'in kısaltılmış, kontrol karakterlerinden arındırılmış hâlini yazın.
- **İlgili:** AC-P03-5, ADR-002

### L-6 — Lisans ve kapsam bilgisi güvenilmeyen lock dosyasından alınıyor (politika atlatma)

- **Ciddiyet:** Low (bütünlük; F1'de ürün kararı)
- **Konum:** `src/scanner/sandbox/parsers/nodejs.py:89-99`, `nodejs.py:267-283`
- **Saldırı senaryosu:** Taranan repo `package-lock.json` içinde GPL bir paket için `"license":"MIT"` veya (package.json'da beyan edilmemiş transitive paketler için) `"dev": true` yazarak lisans ihlali bulgusunun açılmasını engelleyebilir. Standart lock v2/v3 dosyaları genellikle `license` alanı içermez; bu yüzden değerin varlığı bile şüphelidir.
- **Önerilen düzeltme:** F3 lisans zenginleştirmesinde (npm/PyPI kayıt defteri) lock'taki `license` alanını yalnızca ipucu kabul edin. Rapora "lisans kaynağı: lock dosyası (doğrulanmadı)" bilgisini ekleyin.
- **İlgili:** AC-P06-1, AC-P07-2, ADR-003 b

### L-7 — `.env.example` yok; `.gitignore` yalnızca `.env`'i kapsıyor

- **Ciddiyet:** Low
- **Konum:** `.gitignore:7`; repo kökünde `.env*` dosyası yok
- **Saldırı senaryosu:** `.env.local` ve `.env.production` gibi varyantlar ignore edilmez ve yanlışlıkla commit edilebilir. `.env.example` olmadığı için kullanıcı değişkenleri tahmin eder (bilinen; 2 test kırmızı).
- **Önerilen düzeltme:** `.gitignore`'a `.env.*` + `!.env.example` ekleyin. Yer tutucu değerlerle `.env.example` oluşturun (`DATABASE_URL`, `ENCRYPTION_KEY`, `SCAN_ROOTS`, `HOST`, `PORT`, `POSTGRES_PASSWORD`, `PYTHON_BIN`, `SCAN_CLONE_TIMEOUT_MS`).
- **İlgili:** AC-P09-2, D-2

### I-1 — Uzak URL hedef host kısıtı yok (SSRF benzeri)

- **Ciddiyet:** Info
- **Konum:** `src/lib/scanSource.ts:85-100`
- **Açıklama:** `https://127.0.0.1/…`, `https://169.254.169.254/…` ve iç ağ hostları kabul ediliyor. Tek kullanıcılı yerel araçta kullanıcı zaten bu ağa erişebildiği için etkisi düşük. Token yalnızca integration kaydının URL'sine gidiyor.
- **Öneri:** Ağa açık kullanım (F-sonrası) düşünülürse loopback, link-local ve özel IP aralıklarını engelleyin.

### I-2 — `ENCRYPTION_KEY` için KDF ve entropi kontrolü yok

- **Ciddiyet:** Info
- **Konum:** `src/scanner/worker.ts:59-63`
- **Açıklama:** Anahtar `SHA-256(ENCRYPTION_KEY)` ile türetiliyor; zayıf bir değer kaba kuvvete açık. Uzunluk kontrolü yok.
- **Öneri:** `.env.example`'da 32 baytlık rastgele değer (`openssl rand -base64 32`) önerin; başlangıçta minimum uzunluk kontrolü ekleyin.

### I-3 — Saklanan parola parametreleri DB'den okunuyor

- **Ciddiyet:** Info
- **Konum:** `src/lib/password.ts:47-56`
- **Açıklama:** DB'ye yazabilen biri `N` değerini çok büyük veya 2'nin kuvveti olmayan bir değerle değiştirirse login CPU/bellek tüketir ya da scrypt hata fırlatır (500). DB yazma yetkisi gerektirdiği için Info.
- **Öneri:** `N ≤ 2^20`, `r ≤ 16`, `p ≤ 4` üst sınırları koyun ve aralık dışı değerde `false` dönün.

### I-4 — Bilinmeyen rol adı 500'e yol açıyor

- **Ciddiyet:** Info
- **Konum:** `src/config/permissions.ts:86`
- **Açıklama:** `ROLE_PERMISSIONS[role]` tanımsızsa `TypeError` oluşur. DB'de enum dışı bir rol yoksa tetiklenmez.
- **Öneri:** `ROLE_PERMISSIONS[role]?.has(permission) ?? false`.

## İncelenmedi / sınırlı incelendi

- **`npm audit`**: Çalıştırılamadı (Bash rol hook'u tarafından engellendi). Yalnızca `package-lock.json` çözülmüş sürümleri elle kontrol edildi (express zinciri güncel). `exceljs` 4.4.0 → `unzipper`/`archiver`/`tmp`/`jszip` transitive zincirinin advisory kontrolü yapılmadı.
- **`npm test` / `tsc` / `npm run lint`**: Çalıştırılamadı; test durumu (190/192) koordinatörün beyanından alındı ve doğrulanmadı.
- **Git geçmişi ve commit diff'leri** (`f29868e`, `e1c7ff5`, `3959bf6`, `70b863a`, `dfec2a7`, `9405ff9`): `git log/diff` çalıştırılamadı; inceleme HEAD'deki çalışma ağacı üzerinde yapıldı. Geçmişteki sırlar kapsam dışı (D-2) ve taranmadı.
- **Kurulu git / Python sürümü**: Doğrulanamadı (M-2 ve L-4'teki sürüme bağlı davranış).
- **ADR-001/002/003 ve `docs/contracts/REQ-002-auth-api.*`**: Ayrıntılı okunmadı; kod yorumlarındaki karar atıflarıyla ve REQ-002 AC'leriyle karşılaştırıldı. Contract muafiyet listesiyle birebir eşleşme doğrulanmadı.
- **`public/index.html`**: Satır 600-1280 ayrıntılı okundu; dosyanın geri kalanı (login/setup formu ~1690, API anahtarı ekranı, SBOM/rapor görünümleri) yalnızca grep ile tarandı (`innerHTML`, `href`, `setAttribute`, `on*=`). Tehlikeli desen bulunmadı.
- **`src/controllers/workflowController.ts`**, **`src/reports/*`**, **`src/sbom/*`**, **`src/analysis/vulnerabilityLookup.ts`** (OSV ağ çağrısı), **`src/reports/worker.ts`**: İncelenmedi (F1 değişikliği değil). Yalnızca indirme uç noktalarının `res.attachment` kullandığı ve `storage_key`'in API'den gelmediği görüldü.
- **Migration'lar `003`/`004`** ve `db/migrate.sh`: İncelenmedi. `002_local_auth` yalnızca grep ile kontrol edildi (format CHECK'leri, tek parola ve tek aktif anahtar index'leri mevcut).
- **Gitleaks benzeri tam tarama**: Yapılmadı; regex tabanlı grep ile yaklaşık tarama yapıldı (AC-P09-4 için araçla doğrulama önerilir).
- **Python ayrıştırıcısında `tomllib`/`json` derin iç içe yapı DoS'u**: `RecursionError` yakalanıyor gibi görünüyor; çalıştırılarak doğrulanmadı.

## Merge kararı

**Conditional Go — blocker yok.**

- Critical/High bulgu yok; hiçbir bulgu tek başına merge'ü engellemiyor.
- Merge öncesi kapatılması **önerilen** bulgular (düşük maliyetli): **M-1** (lucide'ı yerele almak + CSP), **M-2** (LFS/filtre devre dışı bırakma + hosta sınırlı `extraHeader`).
- **M-3** için insan kararı gerekiyor: `/api/users` F1'de kapatılsın mı, yoksa `requireSession` + kendi hesabını koruma mı uygulansın? Kapatılmadan merge edilecekse risk kabulü handoff'a yazılmalı.
- **İnsan onayı gerektiren riskler:** M-2'nin (token'ın üçüncü bir hosta gitmesi) düzeltilmeden kabulü; L-2 kurtarma penceresi (bilinen, D-11/D-15 ile kabul edilmiş; bu raporla yeniden teyit önerilir).
- Fix'ler ilgili implementer'lar (backend-engineer: M-2, M-3, L-1, L-3, L-5; frontend-engineer: M-1; ayrıştırıcı sahibi: L-4) tarafından yapılmalı ve Security Red Team fix sonrası yeniden incelemeli.

## Handoff notu

Bu inceleme non-trivial'dır; `docs/handoffs/REQ-002.md` bu rapora atıfla ve merge kararı/risk kabulleriyle güncellenmelidir. Security Red Team handoff'u kendisi güncellemez; Delivery Lead / Integration-Release'e bildirilmiştir.

## Yeniden doğrulama (2026-10-09)

- Kapsam: `71f1792` (M-2, M-3, L-3), `2d0075d` (D-20), `262976f` (M-1) sonrası çalışma ağacı.
- Yöntem: Yalnız Read/Grep (Bash rol hook'u bu oturumda da engelledi). `npm audit`, `npm test`, `git diff` çalıştırılamadı. Test sonucu (225/225) ve `npm audit` sonucu koordinatörün beyanıdır, doğrulanmadı.
- İncelenen dosyalar: `src/scanner/workspace.ts`, `src/lib/scanSource.ts` (`assertRemoteUrl`), `src/routes/userRoutes.ts`, `src/middleware/authenticate.ts` (`requireSession`), `src/middleware/securityHeaders.ts`, `src/app.ts`, `src/controllers/scanController.ts`, `public/index.html`, `public/` (grep), `.gitignore`, `.env.example`, `package-lock.json` (grep).

### Düzeltme: önceki rapordaki hatalı ifade

Önceki raporda "API anahtarı ekranı" (İncelenmedi bölümü) ve L-3'te "Generate API Key butonu" ifadeleri geçiyordu; bunlar **hatalı**. `public/` altında (vendor hariç) `/api/auth/api-keys` çağıran veya API anahtarı üreten bir arayüz yok (grep: `api-keys`, `apiKey` eşleşmesi yok). Bu düzeltme M-1'in saldırı senaryosunu geçersiz kılmaz: senaryo bir butona değil, aynı origin'de çalışan betiğin oturum çereziyle `POST /api/auth/api-keys` uç noktasını doğrudan çağırabilmesine dayanıyordu. L-3'teki clickjacking örneği ise bu UI için geçerli değildi; kalan clickjacking yüzeyi (logout, tarama/SBOM başlatma vb.) zaten L-3 düzeltmesiyle kapandı.

### Bulgu durumları

| Bulgu | Durum | Gerekçe |
| --- | --- | --- |
| M-1 / D-17 | **Kapandı** | `index.html` yalnız `/vendor/lucide-1.48.0.min.js` ve `/app.js` yüklüyor (sabit sürüm, same-origin). Inline `<script>`, `on*=` handler, harici URL ve Google Fonts yok. CSP `script-src 'self'` inline betiği engelliyor. `public/` (vendor hariç) içinde `innerHTML`/`insertAdjacentHTML`/`eval`/`new Function` yok. Vendored dosyanın bütünlüğü (resmi 1.48.0 paketiyle hash eşleşmesi) doğrulanmadı; bkz. N-3. |
| M-2 / D-18 | **Kapandı** (güvenilmeyen repo içeriği tehdidi için) | `filter.lfs.smudge/clean/process` boş ve `required=false`; git boş filtre komutunu "filtre yok" sayar. Ek olarak `GIT_LFS_SKIP_SMUDGE=1`. `http.followRedirects=false`. Token yalnız `http.https://<host>[:port]/.extraHeader` ile hosta sınırlı. Ayrıntı: aşağıdaki 1. ve 2. madde. Kalan risk kullanıcının kendi global/system git yapılandırmasından geliyor; N-1 (Low) olarak ayrıldı. Git sürüm kontrolü ve `core.hooksPath` önerisi uygulanmadı (N-1 kapsamında). |
| M-3 / K11 | **Kapandı** | `router.use(requireSession())` tüm rotalardan ve `guard()`'dan önce çalışıyor; `/api/users` altındaki eşleşmeyen yollar da (ör. `/api/users/x/y`) 403 alıyor. `Authorization` başlığı varsa çerez yok sayıldığından Bearer+çerez kombinasyonu da 403. `createUserRouter` yalnız `app.ts:93`'te mount ediliyor. "Kendi hesabını devre dışı bırakma/silme/admin rolünü kaldırma yasağı" uygulanmadı; artık yalnız oturum sahibi kendi kendini kilitleyebilir (Origin korumalı). Info düzeyinde kalıntı, bkz. N-4. |
| D-20 | **Kapandı** | `repo_url` `null` veya boşsa `INSERT`'ten önce `HttpError(400, …, 'project_source_missing')`; ardından `resolveScanSource` ile kaynak yeniden doğrulanıyor. `scans` satırı oluşmuyor. |
| L-3 / K13 | **Kapandı** | `securityHeaders()` `app.ts:60`'ta Host kontrolünden önce ilk middleware. Ayrıntı: aşağıdaki 3. madde. |
| npm audit | **Kısmen** (risk kabulü D-24) | Lock'ta `proxy-addr` 2.0.8 ve `brace-expansion` 1.1.21 çözülmüş; critical/high'ın kapandığı beyanı bununla tutarlı, ancak `npm audit` bu oturumda çalıştırılamadı. `exceljs` 4.4.0 → `uuid` 8.3.2 kaynaklı 2 moderate açık; D-24 ile F2'ye bırakıldı. Kabul ve hedef faz handoff'a yazılmalı. |

### Özellikle istenen kontroller

1. **Host kapsamlı `extraHeader`'ın türetilmesi (`headerScopeFor`):** Değer `new URL(url)` üzerinden `protocol//host/` olarak üretiliyor. `cloneRepo` önce `assertRemoteUrl` çağırıyor ve bu fonksiyon `username`/`password` dolu URL'yi, boş user-info'yu (`https://@host`) ve authority içinde `@` bulunan değeri reddediyor. Bu kontrol, `https://evil\@github.com` gibi ters eğik çizgi ayrıştırma farkını da kapsıyor (`\` ayraç değil, `@` yakalanıyor). Kaçış analizi:
   - **Kullanıcı bilgisi:** Reddediliyor. Kaçış yok.
   - **Büyük harf:** WHATWG URL ve git'in `url_normalize`'ı host'u küçük harfe çeviriyor. Anahtar ve clone URL'si eşleşiyor.
   - **Port:** `URL.host` varsayılan olmayan portu koruyor. `:443` her iki tarafta da düşüyor. Eşleşiyor.
   - **IDN, `0x7f.1` gibi IPv4 kısaltmaları, percent-encoded host:** Node normalize ediyor, git etmiyor. Sonuç uyuşmazlık, yani başlık **gönderilmiyor**: fail-closed. Token başka bir hosta gitmiyor; yalnız clone kimlik doğrulamasında başarısız oluyor.
   - **Yönlendirme:** `followRedirects=false` olduğundan clone, istenen hosttan ayrılamıyor.
   - **Sonuç:** Token'ın amaçlanan host dışına gitmesini sağlayan bir yol bulunamadı.
2. **`GIT_CONFIG_COUNT` ve global/system config:** `GIT_CONFIG_COUNT` yalnız ortamdan gelen `GIT_CONFIG_KEY_n/VALUE_n` girdilerini yönetiyor. `0` veya `1` olarak ezilmesi, üst süreçten miras kalan bu girdileri etkisiz kılıyor; bu doğru. Ancak system ve global config'i **devre dışı bırakmıyor**:
   - Kullanıcının global/system config'indeki kapsamsız `http.extraHeader` git tarafından listeye **ekleniyor**. Bu başlık, taranan her hosta bizim token'ımızla birlikte gidiyor.
   - `url.<base>.insteadOf` clone hedefini değiştirebiliyor. Hedef başka bir hosta yeniden yazılırsa bizim hosta sınırlı başlığımız eşleşmiyor (token sızmıyor, fail-closed). Ancak clone, doğrulanan URL'den farklı bir hosta gidiyor. SSH'a yeniden yazma `GIT_ALLOW_PROTOCOL=https` ile engelleniyor.
   - `http.proxy`, `http.sslVerify=false`, `include.path`, `core.hooksPath` / `init.templateDir` (clone sırasında `post-checkout` hook'u çalışır) de uygulanıyor.
   - Miras alınan `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`, `GIT_SSL_NO_VERIFY`, `GIT_DIR` gibi ortam değişkenleri `sanitizedChildEnv` tarafından temizlenmiyor; yalnız sır adlı olanlar temizleniyor.

   Bu girdilerin hepsi kullanıcının kendi (güvenilir) ortamından geliyor; saldırgan kontrollü repo içeriği bunları değiştiremiyor. Bu yüzden ayrı bir Low bulgu olarak açıldı (N-1).
3. **CSP'nin statik dosyalara ve hata yanıtlarına gelmesi:** `securityHeaders()` zincirin ilk elemanı. Başlıklar şu yanıtlara geliyor:
   - `express.static` dosyaları (`/`, `/app.js`, `/vendor/*`) ve `app.get('/')`.
   - `/health` (200/500) ve `403 host_rejected`.
   - `/api` 404 ve `errorHandler` yanıtları. Body-parser hataları (bozuk JSON, limit aşımı) da `errorHandler`'a düştüğü için bunlara dahil.

   `src/` içinde bu başlıkları kaldıran veya ezen bir `setHeader`/`removeHeader` yok. `/api` dışındaki eşleşmeyen yollarda ve dizin yönlendirmelerinde Express'in `finalhandler` / `serve-static` modülü CSP'yi `default-src 'none'` ile eziyor. Bu daha sıkı bir politika; `X-Frame-Options: DENY`, `nosniff` ve `Referrer-Policy` korunuyor. Sorun değil (Info, N-2).
4. **`requireSession`'ın kapsamı:** Router seviyesinde `router.use` ile eklendiği için GET/POST/PATCH/PUT/DELETE dahil `/api/users` altındaki her yol ve eşleşmeyen alt yollar kapsanıyor. `authenticate` önce çalışıyor (`app.ts:89`), dolayısıyla `req.user` her zaman dolu; `authMethod !== 'session'` olduğunda 403 dönüyor. Açık yol bulunamadı.

### Low bulguların güncel durumu

- **L-1:** Açık. `loginThrottle`/`authController`'da uçuştaki deneme sayacı veya serileştirme yok.
- **L-2:** Açık (bilinen, D-11/D-15). `db/README.md`'de isteğe bağlı `api_keys` iptal adımı yok.
- **L-4:** Açık. `common.py`'de `followlinks=False` veya reparse point/junction filtresi yok.
- **L-5:** Açık. `worker.ts:446`'da `stdoutData` hâlâ sınırsız.
- **L-6:** Açık (F3'e bırakılmış ürün kararı). Değişiklik yok.
- **L-7:** **Kısmen.** `.env.example` eklendi; yer tutucular boş ve sır içermiyor (AC-P09-2 karşılandı). Ancak `.gitignore` hâlâ yalnız `.env`'i kapsıyor; `.env.local`/`.env.production` gibi varyantlar ignore edilmiyor. Kapanış için `.env.*` + `!.env.example` gerekli. `ENCRYPTION_KEY` satırında güçlü rastgele değer önerisi (I-2) de yok.

### Yeni bulgular

#### N-1 — Clone, kullanıcının global/system git yapılandırmasından ve miras ortamdan yalıtılmamış

- **Ciddiyet:** Low (güvenilir kullanıcı ortamı gerektiriyor; saldırgan kontrollü repo içeriğinden tetiklenemiyor)
- **Kanıt:** `src/scanner/workspace.ts:119-142`. `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL`, `core.hooksPath` ve `http.extraHeader` sıfırlaması yok. `sanitizedChildEnv` `GIT_*` değişkenlerini geçiriyor.
- **Saldırı yolu:** Global config'te kurumsal bir kapsamsız `http.extraHeader` (ör. iç Git sunucusu token'ı) bulunan bir kullanıcı herhangi bir üçüncü taraf repo URL'sini tarar ve bu başlık o hosta gider. Benzer şekilde global `http.sslVerify=false` veya miras alınan `GIT_SSL_NO_VERIFY=1`, entegrasyon token'ını MITM'e açar. Global template'teki bir `post-checkout` hook'u clone sırasında çalışır.
- **Etkilenen alan:** Uzak tarama (P-03), token gizliliği (AC-P09-5)
- **Düzeltme gereksinimi:**
  - Clone ortamında `GIT_CONFIG_NOSYSTEM=1` ve boş bir `GIT_CONFIG_GLOBAL` (git ≥ 2.32) kullanın. Git for Windows'un system config'inden gelen `http.sslBackend=schannel` / `http.sslCAInfo` gibi değerler kaybolacağından bunları açıkça `-c` ile verin.
  - `-c core.hooksPath=<boş klasör>` ekleyin.
  - Üst ortamdan `GIT_*` değişkenlerini (bilinçli eklenenler hariç) çıkarın.
  - Başlangıçta minimum `git --version` kontrolü yapın.
  - Alternatif: Bu davranışı dokümante edip insan risk kabulüyle F2'ye bırakın.

#### N-2 — `finalhandler` / `serve-static` CSP'yi `default-src 'none'` ile eziyor

- **Ciddiyet:** Info
- **Açıklama:** `/api` dışındaki eşleşmeyen yollar ve dizin yönlendirmeleri bu yanıtları üretiyor. Ezilen politika daha sıkı, diğer başlıklar korunuyor. Aksiyon gerekmiyor.

#### N-3 — Vendored lucide dosyasının bütünlüğü doğrulanmamış

- **Ciddiyet:** Info
- **Açıklama:** `public/vendor/lucide-1.48.0.min.js` repoya eklendi; resmi npm paketiyle (`lucide@1.48.0` `dist/umd/lucide.min.js`) hash eşleşmesi bu oturumda kontrol edilemedi.
- **Öneri:** Kaynak URL'si ve SHA-256 değeri `public/vendor/` altında veya handoff'ta kayıt altına alınmalı. Dosya `index.html`'deki tek üçüncü taraf betik ve CSP `'self'` onu meşru sayıyor.

#### N-4 — Oturum sahibi kendi hesabını devre dışı bırakabiliyor veya silebiliyor (M-3 kalıntısı)

- **Ciddiyet:** Info
- **Açıklama:** Artık yalnız geçerli tarayıcı oturumu ve Origin kontrolüyle mümkün. Kendi kendine yapılan bir eylem; ancak kurtarma SQL'i bu durumu düzeltmiyor (bkz. M-3 madde 1).
- **Öneri:** `PATCH status=inactive` / `DELETE` / admin rolü kaldırma işlemlerinde hedef kendi hesabıysa 409 dönün (F2).

### Merge kararı (yeniden doğrulama sonrası)

**Conditional Go — blocker yok.**

- Critical, High veya Medium açık bulgu yok. M-1, M-2, M-3, D-20 ve L-3 kapandı.
- Koşullar (handoff'a yazılmalı, kod değişikliği gerektirmez):
  1. D-24 risk kabulü: `exceljs` → `uuid` kaynaklı 2 moderate açık ve hedef faz.
  2. Bu oturumda doğrulanamayan `npm audit` (critical/high = 0) ve `npm test` (225/225) çıktılarının Integration-Release tarafından kanıt olarak eklenmesi.
  3. N-1 için ya F1'de düzeltme ya da insan risk kabulü.
- Önerilen düşük maliyetli düzeltme: L-7 için `.gitignore`'a `.env.*` ve `!.env.example` eklenmesi (backend-engineer veya repo sahibi).
- **İnsan onayı gerektiren riskler:** N-1 (kullanıcı git ortamının clone'a etkisi), D-24 (moderate bağımlılık açıkları), L-2 (kurtarma penceresi; önceden kabul edildi).
- `docs/handoffs/REQ-002.md` bu bölüme atıfla güncellenmelidir. Security Red Team handoff'u kendisi güncellemez; Delivery Lead / Integration-Release'e bildirilir.
