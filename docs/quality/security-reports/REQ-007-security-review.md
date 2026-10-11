# REQ-007 — Güvenlik İncelemesi (F6: `oss-risk` CLI `scan --fail-on` / `bootstrap --new-database`, GitHub Actions iş akışları, tek tık PDF/XLSX/CSV/NOTICE çıktıları, API Keys görünümü)

- İnceleyen: Security Red Team (adversarial review, read-only)
- Tarih: 2026-10-11
- Branch: `req-007-f6-cli-raporlar`, base `main`
- İnceleme aralığı: `6996272^..2d5e209` (5 commit: `6996272` CLI, `38d77ac` exports, `2d42488` GitHub Actions, `964fbba` UI, `2d5e209` CI ubuntu). QA testleri inceleme sırasında çalışma ağacındaydı, sonra `c59a21c` olarak commit edildi. Testler yalnız kapsama kanıtı olarak okundu.
- Kaynaklar: `docs/product/REQ-007.md`, `docs/contracts/REQ-007-cli-and-exports.md`, `docs/contracts/REQ-007-exports-api.openapi.yaml`, `docs/contracts/REQ-004-notice-and-outputs.md` (1.5.0), ADR-009, ADR-001.
- İncelenen kod: `src/cli/{args,client,config,evaluate,exitCodes,index,main,output}.ts`, `src/cli/commands/{scan,bootstrap}.ts`, `src/controllers/exportController.ts`, `src/routes/exportRoutes.ts`, `src/reports/{csv,exportLimiter}.ts`, `src/reports/reportService.ts` (diff + `loadReportData`), `src/app.ts` (diff), `src/lib/outputText.ts` (`excelSafeText`, `singleLine`), `src/controllers/scanController.ts` (`getScanFindings`), `src/lib/sessions.ts` (çerez öznitelikleri), `public/app.js` ve `public/index.html` (diff), `.github/workflows/{ci,oss-risk-example}.yml`, `README.md` (CLI ve GitHub Actions bölümleri).
- Tehdit bağlamı: Kişisel, tek kullanıcılı, Docker'sız Windows aracı. Sunucu `127.0.0.1`'e bağlanır, Host/Origin izin listesi kullanır, oturum çerezi `HttpOnly; SameSite=Strict` ve `ossr_` API anahtarı (Bearer) ile çalışır (ADR-001). F6 ile bir CLI istemcisi, bir CI kalite kapısı ve oturum ya da anahtarla erişilen üç CPU-yoğun çıktı uç noktası eklendi.
- Saldırgan modelleri:
  - **(A1)** Kötü niyetli ya da ele geçirilmiş sunucu yanıtı (CLI açısından). Durum, mesaj, proje adı ve bulgu metinleri güvenilmeyen veridir: terminal enjeksiyonu, yönlendirme ve boyut riski taşır.
  - **(A2)** Taranan reponun sahibi ya da paket yayıncısı. Paket adı, sürüm ve manifest yolu gibi alanlar CSV/XLSX/PDF içine girer.
  - **(A3)** Kötü niyetli yerel web sayfası (tarayıcı). CSRF ya da cross-site download tetikleme dener.
  - **(A4)** Fork'tan PR açan kişi (GitHub Actions). Workflow ve script injection, token ya da secret sızdırma dener.
  - **(A5)** Ağ konumundaki saldırgan. Loopback dışı `https` hedefinde TLS devreye girer.

> **Yöntem kısıtı:** Rol sınırı hook'u Bash'te yalnız tek ve değiştirmeyen komutlara izin verdi. `pwd`, `git rev-parse` ve `git -C` engellendi, `git diff --stat` ve `git diff <range> -- <paths>` çalıştı. İnceleme Read/Grep ile statik yapıldı. Test çalıştırılmadı (ana oturum tam suite'i çalıştırıyordu). `npm audit` çalıştırılmadı (bu REQ yeni üretim bağımlılığı eklemiyor; `package.json` diff'i yalnız `bin` alanı). Action SHA'ları çevrimiçi doğrulanmadı. Koordinatör tur sınırı nedeniyle inceleme erken kapatıldı; incelenmeyen alanlar aşağıda ayrıca listelendi.

## Özet

| Ciddiyet | Sayı |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 5 |
| Info | 10 |

**Merge kararı önerisi: Go.** Blocking bulgu yok. Critical, High veya Medium bulgu bulunamadı. CLI istemcisi (adres doğrulama, yönlendirme reddi, gövde ve süre sınırları, proxy bağışıklığı, redaction, terminal temizliği, fail-closed çıkış kodları), çıktı uç noktalarının yetki ve sıralama düzeni ile GitHub Actions sertleştirmesi sağlam. Low bulgular merge'i engellemiyor. L-1'in (sözleşmedeki "TLS doğrulaması kapatılamaz" iddiası) bu REQ içinde tek satırlık bir düzeltmeyle ya da sözleşme/README metni düzeltilerek kapatılması **önerilir**. L-2 için handoff'ta insan risk kabulü önerilir.

## Doğrulanan kontroller (olumlu bulgular)

**CLI adres ve anahtar kuralları (`src/cli/config.ts`)**
- URL WHATWG `URL` ile ayrıştırılıyor. Yalnız `http:`/`https:` kabul ediliyor. Kullanıcı bilgisi, yol, sorgu ve parça reddediliyor (`config.ts:51-64`). Loopback dışı `http` hiç bağlantı kurmadan çıkış 2 ile reddediliyor (`config.ts:70-72`). `bootstrap` loopback dışı her adresi reddediyor (`config.ts:67-69`). `0x7f.1` ve `127.1` gibi biçimler WHATWG tarafından `127.0.0.1`'e normalize ediliyor, yani gerçekten loopback. `127.0.0.1.` loopback sayılmıyor ve `https` istiyor.
- API anahtarı yalnız ortam değişkeninden ya da dosyadan alınıyor. İkisinden tam olarak biri zorunlu. Dosya en fazla 1 KiB (`index.ts:24-36` hem `stat` hem okuma sayacıyla). Biçim regex'i sunucununkiyle aynı (`config.ts:17`). `--api-key/--key/--token` her biçimde ve her konumda, ayrıştırmanın ilk adımında reddediliyor (`args.ts:73-76`). Seçenek değerleri hata mesajlarına kopyalanmıyor.

**CLI HTTP istemcisi (`src/cli/client.ts`)**
- `node:http(s)`, istek başına `Agent({ keepAlive: false })` kullanılıyor; `fetch` ve küresel agent yok. Bu nedenle `HTTP(S)_PROXY`/`NODE_USE_ENV_PROXY` etkisiz (testle de kanıtlı: `cliClient.test.ts:262`).
- Yönlendirmeler izlenmiyor. 3xx yanıtı çıkış 3'e eşleniyor ve `Location` hedefine bağlantı kurulmuyor (`client.ts:136-138`, test `cliClient.test.ts:80`). Anahtarın üçüncü bir hosta yönlendirme yoluyla sızması mümkün değil.
- 30 sn toplam süre sınırı gövde okumayı da kapsıyor, bu da slowloris riskini sınırlıyor. 32 MiB sınırı hem `Content-Length` ön kontrolüyle hem akış sayacıyla uygulanıyor (`client.ts:73-84`). Yalnız GET'ler yeniden deneniyor (en fazla 3 kez); POST tek atış.
- Hata metinleri yalnız yöntem, yol, durum ve doğrulanmış sunucu `code` değerini (`^[a-z0-9_]{1,64}$`) taşıyor. Başlık, anahtar ve çerez yok (`client.ts:101-145`). Beklenmeyen istisnada hata nesnesi yazılmıyor (`main.ts:91-96`, `index.ts:73-76`).

**Terminal ve çıktı güvenliği (`src/cli/output.ts`, `evaluate.ts`, `commands/scan.ts`)**
- Uzak kaynaklı her metin `cleanText` ile işleniyor: `singleLine` (Cf/bidi dahil kontrol ve format karakterleri temizleniyor), C0/C1 silme (ANSI ESC dahil) ve kod noktası sınırı (`output.ts:18-29`). Proje adı, durum, `error_message`, bulgu paket/sürüm/kimliği ve sunucu `message` değeri bu yoldan geçiyor (`scan.ts:91,109,112,130,136,148`; `evaluate.ts:132-135`; `client.ts:108-112`). Tarama kimliği UUID regex'iyle doğrulandığı için yol enjeksiyonu yok (`scan.ts:104-107`).
- `Output` tek yazıcı. Anahtar, anahtarın gizli kısmı, bootstrap parolası ve çerez değeri her yazımda `[redacted]` ile değiştiriliyor (savunma derinliği, `output.ts:35-70`).
- Fail-closed karar mantığı: tanınmayan severity ya da risk değeri `high` sayılıyor. Durum endpoint'i hata verirse veya eşleşme bulunamazsa sonuç `unknown` olur ve çıkış 5 döner. Findings yanıtı 32 MiB'ı aşarsa çıkış 3 döner. Bulgu listesi sunucuda sınırsız (`scanController.ts:128-149`, `LIMIT` yok), bu yüzden kesilmiş liste nedeniyle yanlış "pass" çıkmıyor. Proje adı belirsizse ya da bulunamazsa çıkış 2.

**Bootstrap (`src/cli/commands/bootstrap.ts`)**
- Ağ isteğinden önce sırasıyla loopback kontrolü yapılıyor ve anahtar dosyası `wx` + `0600` ile rezerve ediliyor. `O_EXCL` var olan dosyayı ve symlink'i reddediyor. EEXIST durumunda dosya silinmiyor (`bootstrap.ts:83-98, 209`). POSIX'te izin biti kontrol ediliyor.
- Parola `randomBytes(32)`'den üretiliyor ve hiçbir çıktıya yazılmıyor. Hata yollarında anahtar dosyası siliniyor ve oturum kapatılıyor. Çerez adı regex'le sınırlı. Anahtar yanıtı biçim regex'iyle doğrulanıyor (`bootstrap.ts:149-152`). Veritabanı adı ya da URL'si CLI'dan sunucuya hiç geçmiyor; bootstrap yalnız HTTP setup akışını kullanıyor. DB/URL enjeksiyonu yüzeyi yok.

**Çıktı uç noktaları (`exportController.ts`, `exportRoutes.ts`, `reportService.ts`, `csv.ts`)**
- Üç sabit rota var, dosya adı parametresi yok. Global Host → kimlik doğrulama → `guard('reports:read')` → UUID (400) → limiter (429) → tarama (404) sırası uygulanıyor. Kimliği doğrulanmamış istek limiter'a ve render'a ulaşmıyor (test `exports.test.ts:226, 255`).
- `Content-Disposition` dosya adı yalnız DB'den okunan kanonik UUID ile sabit taban addan oluşuyor; proje adı kullanılmıyor (`reportService.ts` `renderExport`). Başlık enjeksiyonu yok. Hata yanıtı `Content-Disposition` taşımıyor. `Cache-Control: no-store` ve global `X-Content-Type-Options: nosniff` (`securityHeaders.ts:30`) uygulanıyor.
- CSV ve XLSX `Dependencies` sayfası, formül kalkanının bir kez uygulandığı ortak satır kurucusundan geliyor (`dependencyRowCells`). Kalkan `= + - @ \t \r` başlangıçlarını `'` ile koruyor. CSV alanları RFC 4180'e göre tırnaklanıyor. XLSX hücreleri hiçbir zaman `{ formula }` değil. Sorgular parametreli.
- `export_busy` limiter'ı `createApp` örneğine ait. Slot `finally` içinde idempotent biçimde bırakılıyor. Render hatası ham metin olmadan 500 dönüyor.

**CSRF / cross-site**
- Oturum çerezi `SameSite=Strict` (`sessions.ts:75`). Kötü niyetli bir sayfanın (A3) başlattığı cross-site GET çerez taşımıyor, bu nedenle export indirmesini ya da CPU tüketimini tetikleyemiyor. Durum değiştiren UI istekleri `fetch` ile gidiyor ve Origin kontrolüne tabi. Native form gönderimi `preventDefault` ile engelleniyor (`app.js` `bindHandlers`).

**UI — API Keys görünümü (`public/app.js`)**
- Anahtar yalnız POST yanıtını işleyen fonksiyonun yerel değişkeninde ve `input.value` property'sinde tutuluyor (attribute değil, serileştirilmiş markup'ta yok). Modül değişkenine, storage'a, URL'ye, console'a ya da toast metnine girmiyor. Panel; Done, görünüm değişimi, `pagehide`, oturum sonu ve ilgili anahtarın iptalinde kaldırılıyor. İstek sürerken görünümden çıkılmışsa anahtar gizli görünüme render edilmiyor.
- Tüm satır verileri `el()`/text node ile ekleniyor (`textContent`). `href`'ler `apiPath` ile `encodeURIComponent` ve `isAllowedHref` süzgecinden geçiyor. Yeni `innerHTML` yok (test `f6Ui.test.ts:419`).

**GitHub Actions**
- İzinler iş akışı düzeyinde yalnız `contents: read`. `pull_request_target` yok. Secret kullanılmıyor. Yalnız `actions/checkout` ve `actions/setup-node` var; her ikisi 40 karakterlik SHA'ya sabitli ve `persist-credentials: false`. `run:` içinde `${{ }}` ifadesi yok. `workflow_dispatch` girdisi yalnız `env:` üzerinden aktarılıyor ve literal karşılaştırılıyor. `GITHUB_ENV`'e yalnız sabit metinler yazılıyor (`oss-risk-example.yml:111-132`). `timeout-minutes: 30` ve `concurrency` tanımlı. Sunucu `HOST=127.0.0.1` ile başlıyor. Bunların hepsi `workflowsStatic.test.ts` ile statik olarak sabitlenmiş.

## Bulgular

### L-1 — "TLS doğrulaması kapatılamaz" iddiası `NODE_TLS_REJECT_UNAUTHORIZED=0` ortam değişkenine karşı geçerli değil (Low, öneri: bu REQ'te düzelt; blocking değil)

- **Evidence:** `src/cli/client.ts:70-71`. İstek seçeneklerinde `rejectUnauthorized` açıkça verilmiyor. Node, bu alan `undefined` olduğunda varsayılanı `NODE_TLS_REJECT_UNAUTHORIZED` ortam değişkeninden alıyor. Sözleşme `docs/contracts/REQ-007-cli-and-exports.md:83` ve `README.md:320` "TLS doğrulaması kapatılamaz" diyor. Test `tests/integration/cliClient.test.ts:218-221` kaynakta `rejectUnauthorized` kelimesini **yasaklıyor**; bu nedenle düzeltme testle de çelişiyor.
- **Attack path:** (A5) CI ya da kurumsal makinede başka bir araç için global `NODE_TLS_REJECT_UNAUTHORIZED=0` ayarlanmış olsun (yaygın bir kötü pratik). `OSS_RISK_URL=https://oss-risk.example` ile çalışan `scan`, sertifika doğrulamadan bağlanır. Ağ konumundaki saldırgan TLS'i sonlandırıp `Authorization: Bearer ossr_…` anahtarını ele geçirir ve sahte `completed` + boş bulgu yanıtıyla kapıyı yeşile çevirebilir. Ön koşul ortamın yanlış yapılandırılmasıdır; Node bu durumda stderr'e uyarı basar. Loopback `http` (varsayılan kullanım) etkilenmez.
- **Impacted area:** Loopback dışı `https` hedefli `scan` (anahtar gizliliği, kapı bütünlüğü).
- **Remediation requirement:** `mod.request` seçeneklerine yalnız `https:` için `rejectUnauthorized: true` eklenmeli. Böylece ortam değişkeni geçersiz kalır; `NODE_EXTRA_CA_CERTS` kurumsal CA için çalışmaya devam eder. `cliClient.test.ts:221` regex'i `rejectUnauthorized: false` biçimini yasaklayacak şekilde daraltılmalı ve env=0 iken self-signed sunucuya bağlantının reddedildiğini gösteren bir test eklenmeli. Alternatif (daha zayıf) yol: sözleşme ve README "ortam değişkeniyle kapatılmadıkça" diye düzeltilir.

### L-2 — Örnek iş akışında `push`/`pull_request` çalıştırmaları güvenlik açığı kapısını fiilen kapatıyor; `disabled` durumu çıkış 0 veriyor (Low, tasarım kararı; insan risk kabulü önerilir; blocking değil)

- **Evidence:** `.github/workflows/oss-risk-example.yml:111-132` (çevrimdışı kipte `VULNERABILITY_LOOKUP=off`), `src/cli/evaluate.ts:183-189` (`disabled` eksik veri sayılmıyor), sözleşme `REQ-007-cli-and-exports.md:277, 306, 372` ve AC-P23-4.
- **Attack path:** Bir kullanıcı örneği kendi reposuna kopyalar. Her push/PR'da kapı yalnız lisans bulgularını değerlendirir. Kritik CVE içeren bir bağımlılık `--fail-on critical` ile bile yeşil geçer; tek işaret stderr'deki `W-DISABLED` uyarısıdır. Benzer şekilde sunucuda `VULNERABILITY_LOOKUP=off` olan herhangi bir kurulumda `scan` güvenlik eşiğini sessizce atlar. Bu bir zafiyet değil, sahte güvence (false assurance) riskidir ve sözleşmeyle uyumludur.
- **Impacted area:** CI kalite kapısının güvenlik açığı bileşeni.
- **Remediation requirement:** Kod değişikliği zorunlu değil. Önerilenler: (a) README'de "kendi reponuza uyarlama" bölümüne çevrimdışı kipte güvenlik açığı kontrolü yapılmadığını kalın bir uyarıyla yazmak; (b) isteğe bağlı bir `--require-vulnerability-data` bayrağı (Product Analyst / Contract Broker kararı); (c) handoff'ta insan risk kabulü.

### L-3 — Çıktı render'ı ana event loop'ta senkron çalışıyor; limiter eşzamanlılığı sınırlıyor ama ardışık döngüyü ve bellek tepe noktasını sınırlamıyor (Low; blocking değil)

- **Evidence:** `src/controllers/exportController.ts:40-58`, `src/reports/exportLimiter.ts:12` (2 slot), `src/reports/reportService.ts:397-424` (`scan_dependencies` için satır sınırı yok; tüm satırlar belleğe alınıyor), `exportLimiter.ts:5-6` (render "kesilemez"). Süre sınırı yalnız adımlar arasında kontrol ediliyor.
- **Attack path:** Geçerli bir API anahtarına sahip istemci (ya da CI'da sızmış bir anahtar) büyük bir tarama (on binlerce bağımlılık) için `license-inventory.xlsx` isteklerini art arda gönderir. Her render event loop'u saniyelerce bloklar. Bu süre boyunca UI, tarama yönetimi ve diğer API çağrıları yanıt vermez; bellek tepe noktası da yükselir. Kimlik doğrulama gerektirdiği için tek kullanıcılı araçta etki kendine yönelik DoS düzeyinde kalır (doğrulanmadı, ölçüm yapılmadı).
- **Impacted area:** Sunucu yanıt verebilirliği.
- **Remediation requirement:** Takip işi: render'ı mevcut rapor worker'ı ya da `worker_threads` içine taşımak veya tarama başına bağımlılık sayısı için bir çıktı üst sınırı (aşılırsa 413 benzeri sabit hata) koymak. Ayrıca büyük tarama için zaman/bellek ölçen bir stres testi eklenmeli (QA). Alternatif: insan risk kabulü.

### L-4 — Örnek iş akışında PostgreSQL servis portu tüm arayüzlere bilinen bir parolayla açılıyor (Low; blocking değil)

- **Evidence:** `.github/workflows/oss-risk-example.yml:73-75, 85` (`ports: - 5432:5432`, `POSTGRES_PASSWORD: example-ci-test-only`).
- **Attack path:** GitHub-hosted runner'da gelen bağlantılar kapalı olduğu için risk yok. Ancak örneği **self-hosted** runner'a kopyalayan kullanıcıda, iş süresince aynı ağdaki herhangi bir makine bilinen parolayla veritabanına bağlanabilir, `users`/`api_keys` tablolarını okuyup değiştirebilir ve kapı sonucunu manipüle edebilir.
- **Impacted area:** Self-hosted runner kullanan kopyalayıcılar.
- **Remediation requirement:** `ports: - 127.0.0.1:5432:5432` ile yalnız loopback'e bağlamak ve README'ye self-hosted runner uyarısı eklemek. `workflowsStatic.test.ts` bu biçimi kabul edecek şekilde güncellenmeli.

### L-5 — "Kendi reponuza uyarlama" talimatı platform reposunun ikinci checkout'unu sabit bir ref olmadan öneriyor (Low; blocking değil)

- **Evidence:** `README.md:419-422`, `oss-risk-example.yml:16-22` (yorum).
- **Attack path:** Kullanıcı `actions/checkout` ile `repository: <sahip>/<oss-risk-reposu>` adımını `ref` olmadan ekler. Her CI çalıştırması platformun o anki varsayılan branch HEAD'ini derler ve `npm ci` ile kurar. Platform reposu ele geçirilirse ya da kötü niyetli bir commit merge edilirse, kullanıcının CI'ında keyfi kod çalışır. Bu, action'ları SHA'ya sabitleme disiplininin tersidir.
- **Impacted area:** Örneği kendi reposuna uyarlayan kullanıcıların tedarik zinciri.
- **Remediation requirement:** README ve yorum, platform checkout'u için `ref: <tam commit SHA>` (ya da imzalı etiket) kullanılmasını açıkça istemeli.

### Info

- **I-1 — Windows'ta anahtar dosyası ACL'i klasörden devralınıyor.** `bootstrap.ts:92-98` izin kontrolünü yalnız POSIX'te yapıyor. README `:363` bunu belgeliyor. Kabul edilebilir.
- **I-2 — Kurtarma durumundaki veritabanında `bootstrap`.** Gerçek veri içeren, parolası boşaltılmış (ADR-001 Karar 12) bir veritabanında bootstrap admin parolasını bilinmeyen bir değere ayarlar; istemci iki durumu ayıramaz. README `:361-370` belgeliyor, `--new-database` beyanı zorunlu. Kabul edilebilir.
- **I-3 — CI loglarında anahtar maskelenmiyor.** Bootstrap anahtarı `::add-mask::` ile kaydedilmiyor. CLI anahtarı hiçbir yere yazmıyor, anahtar job ömürlü ve geçici veritabanına ait. İsteğe bağlı sıkılaştırma olarak anahtar okunup maskelenebilir.
- **I-4 — Seçenek adı yankısı.** Kullanıcı yanlışlıkla `--ossr_<…>` yazarsa, ad `optionLabel` ile ilk 64 kod noktasına kadar stderr'e basılır (`args.ts:64-66, 106-109`). Bu aşamada redaction secret'ları henüz kaydedilmemiş durumda. Çok düşük olasılık. İsteğe bağlı: `ossr_` ile başlayan adları hiç yankılamamak.
- **I-5 — CSV formül kalkanının kapsamı.** `excelSafeText` (`outputText.ts:148-151`) baştaki boşluk, NBSP veya tam genişlikli `＝` ile başlayan değerleri korumuyor. Baştaki boşluk alanın tırnaklanmasını tetikliyor. Excel'in bu biçimleri formül olarak değerlendirmediği bilinen davranış, ancak bu oturumda doğrulanmadı. Değerler depolamada sanitize ediliyor (Cf silme).
- **I-6 — `localhost` OS çözücüsüyle çözülüyor.** `config.ts:19`. Hosts dosyasını değiştirebilen (yönetici) bir saldırgan tehdit modeli dışında. Bilgi amaçlı.
- **I-7 — Action SHA'ları.** `actions/checkout@11bd71901bbe…` (v4.2.2) ve `actions/setup-node@49933ea5288c…` (v4.4.0), yaygın biçimde yayımlanan değerlerle eşleşiyor ama bu oturumda çevrimiçi doğrulanmadı. `postgres:17` digest'e sabit değil (README `:410` öneriyor).
- **I-8 — PDF proje raporu `repo_url` (yerel mutlak yol, kullanıcı adı içerebilir) içeriyor.** REQ-007 öncesinden gelen davranış; tek tık PDF ile paylaşım kolaylaşıyor. Bilgi amaçlı.
- **I-9 — Pano geçmişi.** "Copy" ile kopyalanan anahtar Windows pano geçmişinde (Win+V) kalabilir. UI bunu kontrol edemez; README'de not düşülebilir.
- **I-10 — `npm ci` yaşam döngüsü script'leri job ortamında (`PGPASSWORD` test değeri dahil) çalışıyor.** Standart tedarik zinciri riski, değer yalnız test amaçlı. Bilgi amaçlı.

## İncelenmeyen / kapsam dışı kalan alanlar

Tur sınırı nedeniyle aşağıdakiler incelenmedi veya yalnız yüzeysel incelendi. Karar bu sınırlar içinde geçerlidir.

- `docs/product/REQ-007.md`, ADR-009 ve `REQ-007-exports-api.openapi.yaml` tam metin olarak AC'lerle satır satır karşılaştırılmadı (yalnız sözleşmede hedefli grep yapıldı).
- Sunucu tarafı API anahtarı uç noktaları (`/api/auth/api-keys` oluşturma/listeleme/iptal; REQ-002) ve bunların yetki modeli (örneğin bir API anahtarıyla yeni anahtar üretilip üretilemeyeceği) bu REQ'te değişmediği için yeniden incelenmedi.
- `isAllowedHref`, `/api/projects` listesinin sayfalama/limit davranışı, `/api/vulnerability-data/status` ve `src/cli/exitCodes.ts` ayrıntılı okunmadı.
- `tests/unit/cliMain.test.ts`, `cliPure.test.ts` ve `exportsPure.test.ts` içerikleri okunmadı; yalnız test başlıkları ve anahtar kelime sayımlarıyla kapsama değerlendirildi.
- Dinamik doğrulama yapılmadı: test çalıştırma, `npm audit`, büyük taramada render süresi/bellek ölçümü (L-3) ve Excel'in CSV davranışı (I-5).

## Merge kararı

**Go.** Critical, High veya Medium bulgu yok; blocking bulgu yok. İnsan onayı gerektiren güvenlik riski yalnız L-2 (tasarım gereği güvenlik açığı kapısının çevrimdışı kipte kapalı olması) için öneri düzeyinde. Önerilen takip:

1. **L-1** (bu REQ'te önerilir, Backend Engineer + QA): `rejectUnauthorized: true` ve test regex'inin daraltılması, ya da sözleşme/README metninin düzeltilmesi.
2. **L-2** (Delivery Lead / Product Analyst): README uyarısı ve handoff'ta insan risk kabulü.
3. **L-4, L-5** (küçük doküman/iş akışı düzeltmeleri, Backend Engineer veya Integration/Release).
4. **L-3** (takip işi): render'ın worker'a taşınması ya da satır sınırı; QA stres testi.

Fix'ler ilgili implementer tarafından yapılmalı; Security Red Team fix sonrası yeniden inceler.

**Handoff'a yazılması önerilen insan risk kabulü metni (L-2):** "Örnek `oss-risk-example.yml` iş akışı `push` ve `pull_request` tetiklemelerinde çevrimdışı çalışır; güvenlik açığı sorgusu kapalıdır, CLI `disabled` uyarısı verir ve kapı yalnız lisans bulgularına göre karar verir. Güvenlik açığı kontrolü yalnız `workflow_dispatch` + `online: true` ile yapılır. Bu davranış AC-P23-4 gereğidir ve kabul edilmiştir. — Onaylayan: ____ / Tarih: ____"

## Handoff notu

Bu inceleme non-trivial'dır. `docs/handoffs/REQ-007.md` güncellenmelidir: bu rapor yolu, Go kararı, L-1…L-5 takip listesi ve L-2 risk kabulü. Security Red Team handoff'u güncellemez; Delivery Lead / Integration-Release'e bildirilmiştir.
