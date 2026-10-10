# ADR-004: Tek süreç çalışma zamanı, tek örnek kilidi, yeniden deneme modeli ve Node göç aracı

- **ADR-ID:** ADR-004
- **Durum:** Accepted
- **Tarih:** 2026-10-10 (taslak ve karar)
- **İlgili:** REQ-003 / P-11 (AC-P11-1…16), P-12 (AC-P12-1…11), P-13 (AC-P13-1…8);
  kararlar D-32…D-42, D-46. ADR-003 (d) bu ADR ile superseded (bkz. Karar 12).

## Bağlam

- `npm start` yalnız API'yi (`dist/app.js`) başlatıyor. Tarama worker'ı
  (`src/scanner/worker.ts`) ve rapor worker'ı (`src/reports/worker.ts`) kendi
  `require.main` blokları ve `worker`/`export-worker` script'leriyle (ts-node) ayrı
  süreçlerde çalışıyor. Her birinin kendi `SIGINT`/`SIGTERM` işleyicisi var; süren
  işler kapanışta hiçbir duruma döndürülmüyor.
- `WORKER_ID` varsayılanı `${HOSTNAME}-${pid}` (`runner.config.ts`). Başlangıç
  kurtarması `WHERE worker_id = $1 AND status = 'running'` ile yalnız aynı kimliği
  arıyor; yeni PID önceki sürecin `running` taramalarını hiçbir zaman bulmuyor.
- `handleScanFailure` yeniden denenebilir hatada taramayı beklemeden `queued`
  yapıyor; `claimNextJob` `status IN ('pending','queued') AND retry_count < $max`
  ile hemen yeniden alıyor. `runner.config.ts`'teki `initialBackoffMs` (5 sn) ve
  `maxBackoffMs` (120 sn) kullanılmıyor.
- Deneme sayısı: `claimNextJob` `retry_count < max` filtreler; başarısızlıkta
  `nextRetry = retry_count + 1`, `nextRetry < max` ise yeniden kuyruk, değilse
  `failed`. `max` = `system_settings.scan.max_retries` (seed `3`; yedek
  `SCAN_MAX_RETRIES` env / `3`). Sonuç: toplam deneme = `max` (ilk deneme dahil).
- `scans` (göç 001): `queued_at`, `started_at`, `completed_at`, `timeout_at`
  (yazılmıyor), `retry_count INTEGER NOT NULL DEFAULT 0`, `worker_id TEXT`,
  `error_message TEXT`. İndeksler: `idx_scans_status_active (status) WHERE status IN
  ('pending','queued','running')`, `idx_scans_worker (worker_id)`.
  `system_settings.scan.timeout_minutes` seed `60`.
- `reports` tablosunda `worker_id` yok; rapor worker'ı `pending → generating →
  ready|failed` akışını kullanıyor, başlangıçta tüm `generating`'i `failed` yapıyor.
- `src/lib/db.ts` havuzu import anında kuruyor ve havuza `error` dinleyicisi
  bağlamıyor (boşta kopan bağlantı yakalanmamış `error` olayıyla süreci düşürebilir).
- Göçler `db/migrate.sh` (bash + psql) ile çalışıyor: `schema_migrations(version
  TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`, sürüm =
  dosya adı eksi `.up.sql`, her dosya + kaydı `psql --single-transaction` ile tek
  transaction, `down` hedefsiz ve `001` dahil her şeyi geri alıyor. Test yardımcısı
  `tests/helpers/migrations.ts` aynı davranışı `pg` ile taklit ediyor.
- `tsconfig.json`: `module: CommonJS`, `rootDir: src`, `outDir: dist`. AC-G-6
  `package.json` script'lerinde `ts-node` geçmesini yasaklıyor.

## Karar

### 1. Modül yapısı ve giriş noktası

| Dosya | Sahip | İçerik |
| --- | --- | --- |
| `src/main.ts` | backend-engineer | Tek giriş (`npm start` = `node dist/main.js`). `dotenv/config`, `installProcessHandlers`, `startRuntime`. Tek `require.main` bloğu burada. |
| `src/runtime.ts` | backend-engineer | `startRuntime(options): Promise<RuntimeHandle>` (başlangıç sırası, Karar 2) ve `RuntimeHandle.shutdown(reason): Promise<number>` (Karar 5). `process.exit` çağırmaz; çıkış fonksiyonu enjekte edilir (test). |
| `src/db/advisoryLock.ts` | database-engineer | Kilit anahtarı sabiti ve `tryAcquireInstanceLock(client)` / `releaseInstanceLock(client)`. Uygulama ve göç aracı bunu ortak kullanır. |
| `src/db/migrator.ts` | database-engineer | Kütüphane: klasör doğrulama, `readMigrationState`, `up`, `down`, `status`. Göç klasörü parametredir (AC-P11-4 testi). |
| `src/db/migrate.ts` | database-engineer | İnce CLI (`npm run db:migrate` = `node dist/db/migrate.js`). |
| `src/scanner/retryPolicy.ts` | backend-engineer | Saf `backoffSeconds(n)` ve hata sınıflandırması (Karar 7, 8). |

- `src/app.ts`'teki `require.main` bloğu ve `main()` kaldırılır; `createApp` /
  `startServer` kalır. `src/scanner/worker.ts` ve `src/reports/worker.ts` içindeki
  `require.main` blokları kaldırılır (AC-P12-3).
- `ExportWorker` da `ScanWorker` gibi bağımlılık enjeksiyonu alır (`db`, `logger`);
  modül düzeyindeki `pool`'u doğrudan kullanmaz.
- Havuz: çalışma zamanı tek bir `pg.Pool` kurar ve API'ye, iki worker'a enjekte
  eder. Havuza `pool.on('error', …)` bağlanır (yalnız sınıf/`code` log'lanır). Bu,
  AC-P12-8'in (veritabanı kesintisinde süreç kapanmaz) ön koşuludur.
- `package.json` `main` alanı `dist/main.js` olur.

### 2. Başlangıç sırası (D-37, AC-P12-6)

İşleyiciler önce kurulur, sonra adımlar sırayla çalışır. Adım 1–6'dan herhangi biri
başarısız olursa açılmış kaynaklar (kilit bağlantısı, havuz, sunucu) kapatılır,
tek satırlık açık bir mesaj yazılır ve süreç **exit code 1** ile çıkar; hiçbir worker
başlamaz, hiçbir tarama veya rapor durumu değişmez.

0. `installProcessHandlers`: sinyal işleyicileri (Karar 5) ve
   `unhandledRejection`/`uncaughtException` (Karar 6). Başlangıç sırasında gelen
   Ctrl+C başlangıcı iptal eder ve aynı kapanış yolunu kullanır.
1. **Ortam:** `assertRequiredEnv()` (`DATABASE_URL`; D-52 testi bu adımdadır).
2. **Veritabanı ve tek örnek kilidi:** ayrı kilit bağlantısı açılır, kilit alınır
   (Karar 3). Kilit alınamazsa: "Bu veritabanına bağlı başka bir örnek çalışıyor veya
   bir göç sürüyor." (AC-P12-4). Bağlantı hatası: yalnız hata sınıfı/kodu (ör.
   `ECONNREFUSED`, `28P01`), bağlantı dizesi asla.
3. **Göç kontrolü:** `readMigrationState` (Karar 10) kilit bağlantısı üzerinden.
   Bekleyen göç → "Bekleyen göç var: 005_… . Önce `npm run db:migrate` çalıştırın.";
   veritabanında dosyası olmayan sürüm → "Veritabanı bu koddan yeni (bilinmeyen
   sürüm: …)."; göç klasörü geçersiz → aynı doğrulama mesajı. Göç uygulanmaz (D-35).
4. **`SCAN_ROOTS`:** `canonicalizeScanRoots` (ADR-002 karar 4).
5. **Git sürümü:** `git --version` bir kez sorulur ve sonuç önbelleğe alınır
   (ADR-002 Ek, AC-T-3). Bu adım **başlangıcı durdurmaz**; git yoksa/eskiyse uyarı
   log'lanır.
6. **HTTP dinleme:** `startServer` (varsayılan `127.0.0.1`, AC-P12-2). Port dolu →
   çıkış; kuyruktaki tarama `queued` kalır.
7. **Worker'lar:** sırasıyla (a) sahipsiz tarama kurtarma (Karar 9), (b) rapor
   kurtarma (`generating → failed`, bugünkü davranış), (c) `ossrisk-scan-*`
   süpürmesi, (d) tarama ve rapor worker'larının yoklamaya başlaması. Bu adımdaki
   kurtarma hataları log'lanır ve worker yine başlar (bugünkü davranış); sonraki
   yoklamalardaki süpürme (Karar 9) eksik kalanı tamamlar.

Kurtarmanın dinlemeden **sonra** yapılması bilinçlidir: port doluysa veya önceki
adımlar başarısızsa veritabanında hiçbir tarama durumu değişmez.

> **REQ-003 güvenlik düzeltmesi (2026-10-10).** Adım 1 **PORT doğrulamasını** da
> içerir (güvenlik raporu I-1, commit `f32b00c`): ortam değişkeni `PORT`
> tanımlıysa 1–65535 aralığında bir tam sayı olmalıdır; `0`, aralık dışı veya
> sayı olmayan değer → `RuntimeStartupError`, exit code 1. Kod içinden verilen
> `port: 0` (işletim sisteminin boş port seçmesi) yalnız testler için kabul edilir;
> bu durumda Host/Origin izin listesi yapılandırılan değerden değil, sunucunun
> **gerçekte bağlandığı porttan** (`server.address().port`) kurulur. (Önceki
> davranışta `PORT=0` izin listesini `:0` ile kuruyor ve her isteği `403` ile
> reddediyordu.)

### 3. Tek örnek kilidi (D-34, AC-P11-11, AC-P12-4)

- **Kilit türü:** PostgreSQL **session-level** advisory lock, iki `int4` anahtarlı
  biçim, **bloklamayan** çağrı:
  `SELECT pg_try_advisory_lock(1330860882, 1) AS acquired`.
  - `1330860882` = `0x4F535352` (ASCII `OSSR`, "OSS Risk" ad alanı), `1` = tek örnek
    kilidi. İki anahtarlı biçim `pg_locks`'ta tek `bigint` biçiminden ayrı bir alanda
    durur (`objsubid = 2`), başka araçların `bigint` kilitleriyle çakışmaz.
  - Sabit tek yerde, `src/db/advisoryLock.ts` içinde tanımlanır; uygulama ve göç
    aracı aynı fonksiyonu çağırır. Değeri değiştirmek eski ve yeni sürümün aynı anda
    çalışmasına izin verir; bu yüzden sabit **dondurulmuştur**.
- **Neden session-level:** kilit sürecin ömrü boyunca (uygulama) veya birden çok
  transaction boyunca (göç aracı: her dosya ayrı transaction) tutulmalıdır.
  Transaction-level kilit (`pg_try_advisory_xact_lock`) transaction bitince düşer ve
  bu iki kullanımı karşılayamaz. Bloklayan `pg_advisory_lock` ikinci örneği sessizce
  bekletirdi; AC'ler hemen ret ister.
- **Ayrı bağlantı:** kilit, `pg.Pool`'dan **değil**, ayrı bir `pg.Client` üzerinden
  alınır (`application_name = 'oss-risk:instance'`, `keepAlive: true`). Gerekçe:
  havuz bağlantıları `idleTimeoutMillis` ile kapanır, yeniden kullanılır ve
  `pool.end()` ile kapanır; kilit rastgele bir havuz bağlantısına bağlanırsa ya
  sessizce düşer ya da beklenmedik bir sorguyla aynı oturumu paylaşır. Kilit
  bağlantısı başka iş için kullanılmaz (yalnız başlangıçtaki göç kontrolü ve kalp
  atışı).
- **Kalp atışı ve kilit kaybı:** kilit bağlantısında 10 sn'de bir `SELECT 1`
  (sorgu zaman aşımı 5 sn) çalışır; ayrıca `client.on('error'|'end')` dinlenir.
  Bağlantı koparsa kilit sunucu tarafında düşmüş sayılır ve uygulama **bozulmuş
  kipe** geçer:
  - Tarama ve rapor worker'ları yeni iş sahiplenmeyi durdurur (süren işler devam
    eder; son yazımları Karar 4'teki çitle korunur). API çalışmaya devam eder
    (`/health` veritabanı durumuna göre `200`/`500`).
  - Her 5 sn'de yeni bir `pg.Client` ile `pg_try_advisory_lock` denenir.
    `true` → worker'lar yeniden başlar (kurtarma **çalıştırılmaz**: `running`
    taramalar bu sürecindir). `false` (veritabanı erişilebilir ama kilit başkasında)
    → "kilit başka bir örneğe geçti" log'u, düzgün kapanış, exit code 1. Bağlantı
    hatası → denemeye devam.
  - **REQ-003 "Riskler / Advisory lock" maddesini netleştirir:** kilit bağlantısı
    koptuğunda süreç hemen kapanmaz (bu, AC-P12-8 "veritabanı kesintisinde süreç
    kapanmaz" ile çelişirdi); worker'lar durur, kilit geri alınamaz ve başkasında
    olduğu görülürse kapanış başlar.
- **Bırakma:** düzgün kapanışın en son adımında `pg_advisory_unlock(1330860882, 1)`
  ve `client.end()`. Süreç çökerse PostgreSQL oturum kapanınca kilidi kendisi
  bırakır.

### 4. Çalışma kimliği ve yazım çiti

- `worker_id` artık süreç başına üretilen bir **çalışma kimliğidir**:
  `${os.hostname()}:${process.pid}:${crypto.randomUUID().slice(0, 8)}`. `WORKER_ID`
  ve `EXPORT_WORKER_ID` ortam değişkenleri kaldırılır (`.env.example`'da yoktur).
- Kimlik bilgilendirme ve **çit** (fencing) içindir: bir taramanın sonucunu,
  hatasını veya kapanış iadesini yazan her `UPDATE scans` koşulu
  `WHERE id = $1 AND status = 'running' AND worker_id = $runId` içerir.
  `saveScanResults` transaction'ı ilk adımda `SELECT … FROM scans WHERE id = $1 AND
  status = 'running' AND worker_id = $runId FOR UPDATE` yapar; satır yoksa
  `ROLLBACK` ve sonuç atılır (log: "tarama başka bir örnek tarafından devralındı").
  Tek örnek kilidi varken bu yol normalde hiç çalışmaz; kilit kaybı penceresine
  (Karar 3) karşı savunmadır.

### 5. Düzgün kapanış (D-39, AC-P12-10)

- **Sinyaller:** `SIGINT`, `SIGTERM`, `SIGBREAK`, `SIGHUP` aynı `shutdown('signal')`
  çağrısına bağlanır. Windows davranışı (Node belgeleri; elle doğrulama
  AC-P12-10'da):
  - Ctrl+C → `SIGINT`; Ctrl+Break → `SIGBREAK`.
  - Konsol penceresinin kapatılması → `SIGHUP`; Windows süreci **yaklaşık 10 sn
    sonra koşulsuz sonlandırır**. 15 sn bütçesi bu durumda tamamlanamayabilir;
    yarım kalan taramalar sonraki başlangıçta Karar 9 ile kurtarılır (kabul edilen
    sonuç).
  - `SIGTERM` Windows'ta işletim sisteminden gelmez (dinlenebilir; Linux için
    tutulur). Görev Yöneticisi "Görevi sonlandır" veya `taskkill /F` işleyici
    çalıştırmaz; kurtarma Karar 9'dadır.
  - `npm start` altında Ctrl+C hem `npm`'e hem `node`'a gider. `npm` erken dönüp
    istemi gösterebilir; `node` kapanışı arka planda bitirir. cmd.exe'de
    "Terminate batch job (Y/N)?" sorusu çıkabilir; yanıt kapanışı etkilemez.
    README PowerShell'i önerir.
- **İkinci sinyal:** kapanış sürerken gelen ikinci sinyal veya ikinci ölümcül hata
  beklemeden `exit code 1` ile çıkar.
- **Sıra** (tek `Promise`, idempotent; ikinci çağrı aynı sözü döndürür):
  1. Durum `stopping`. 15 sn'lik **zorla çıkış zamanlayıcısı** kurulur (`unref`
     edilmez): süre dolarsa "kapanış 15 sn'de tamamlanamadı" log'u ve
     `exit code 1`.
  2. `server.close()` + `server.closeIdleConnections()`: yeni bağlantı kabul
     edilmez.
  3. İki worker yoklamayı bırakır (zamanlayıcılar temizlenir, kilit kalp atışı
     durur).
  4. Her süren tarama işinin `AbortController`'ı `reason = 'shutdown'` ile iptal
     edilir (Karar 7): clone süreç ağacı öldürülür (`taskkill /T /F`, `close`
     beklenir), ayrıştırıcı iş parçacığı `terminate()` edilir ve beklenir, OSV
     isteği iptal edilir, sonuç yazımı transaction'ı geri alınır; ardından
     `withTempWorkspace` geçici klasörü siler. İş, iptali **kapanış iadesi**
     olarak yazar: `status = 'queued'`, `retry_count` değişmez,
     `next_attempt_at = NULL`, `worker_id = NULL`, `updated_at = NOW()` (çitli).
  5. Süren raporlar iptal edilemez (pdfkit/exceljs ana iş parçacığında); en fazla
     10 sn'ye kadar (zorla çıkıştan önce kalan bütçe) tamamlanmaları beklenir.
     Kapanış kipinde rapor worker'ı hata yolunda `failed` yazmaz.
  6. Süpürme: hâlâ `running` + `worker_id = $runId` olan taramalar ve tüm
     `generating` raporlar tek sorguyla sırasıyla `queued` (yukarıdaki alanlarla)
     ve `pending` yapılır. (Raporlarda sahip kolonu yok; tek örnek kilidi tüm
     `generating` satırlarının bu sürece ait olduğunu garanti eder.)
  7. `server.closeAllConnections()`, `pool.end()`.
  8. Kilit bırakılır (Karar 3) ve kilit bağlantısı kapanır. Kilit **en son**
     bırakılır ki bu süreç hâlâ yazarken ikinci bir örnek başlayamasın.
  9. Zorla çıkış zamanlayıcısı temizlenir; `exit(0)` (ölümcül hatadan gelen
     kapanışta `exit(1)`). Açık kalan tutamaçlara güvenilmez, çıkış açıkça
     yapılır.
- Kapanış iadesinde `error_message` değiştirilmez (önceki deneme mesajı korunur).

> **REQ-003 güvenlik düzeltmesi (2026-10-10).** Rapor kapanışı iki noktada
> değişir (güvenlik raporu L-5, commit `f32b00c`):
>
> - **Rapor iptali:** `ReportService.processReport(reportId, signal)` bir
>   `AbortSignal` alır. Sinyali rapor worker'ının süre sınırı
>   (`EXPORT_WORKER_TIMEOUT_MS`) tetikler. Sinyal **adımlar arasında** denetlenir:
>   başlangıçta, veri yüklendikten sonra, çizimden sonra, dosya yazımından önce
>   ve sonra (`ready` güncellemesinden önce). Çizim (pdfkit/exceljs) sırasında
>   kesilemez; o adım biter, sonraki denetimde iptal uygulanır. Sinyal tetiklendikten
>   sonra dosya yazılmaz ve satır `ready` yapılmaz; süre sınırı iptali bugünkü gibi
>   `failed` olur. (Önceki `Promise.race` yalnız bekleyeni bırakıyor, üretim arka
>   planda sürüp satırı sonradan `ready` yapabiliyordu.) Kapanıştaki davranış
>   (adım 5: sınırlı bekleme, adım 6: kalanların `pending`'e süpürülmesi) değişmez.
> - **`lock-lost` kapanışı:** kilit başka bir örneğe geçtiği için yapılan
>   kapanışta (Karar 3) adım 6'daki **rapor süpürmesi atlanır**. `reports`
>   tablosunda sahip kolonu yoktur; kilit artık bu süreçte olmadığından
>   `generating` satırları yeni örneğe ait olabilir ve süpürme onun raporlarını
>   `pending`'e çekip iki kez ürettirirdi. Tarama süpürmesi çalışmaya devam eder,
>   çünkü `worker_id = $runId` ile çitlidir (Karar 4) ve yalnız bu sürecin
>   satırlarını etkiler. Diğer kapanış nedenlerinde (`signal`, `fatal`) rapor
>   süpürmesi değişmez. Raporlara sahip kolonu eklenmesi şema değişikliğidir ve
>   sonraki faza bırakılmıştır.

### 6. Hata yalıtımı (D-38, AC-P12-7…9)

- **İş düzeyi:** `processJob` ve `runExportJob` asla reddedilen söz döndürmez; tüm
  hatalar Karar 7–8 ile sınıflandırılıp yazılır. Yazım da başarısız olursa
  log'lanır; satır `running` kalır ve Karar 9'daki süpürme onu toplar.
- **Yoklama düzeyi:** sahiplenme sorgusu hataları log'lanır (yalnız hata sınıfı ve
  `code`), sonraki yoklamada yeniden denenir. Her `setTimeout`/olay geri çağrısı
  `.catch` ile sarılır.
- **Süreç düzeyi:** `process.on('unhandledRejection')` ve
  `process.on('uncaughtException')`:
  1. Hata, `scrubSecrets` + bağlantı dizesi maskeleme + L-5 arındırmasından
     (ADR-002 Ek) geçirilmiş tek bir log kaydına yazılır (ad, mesaj, yığın).
     `pg` hata nesnesi bütünüyle log'lanmaz.
  2. `shutdown('fatal')` başlatılır, çıkış kodu `1`.
  3. Kapanış sırasında ikinci bir ölümcül hata → hemen `exit(1)`.
  Gerekçe: Node belgeleri `uncaughtException` sonrası süreç durumunun güvenilir
  olmadığını söyler; çalışmaya devam etmek veri tutarlılığını riske atar. Düzgün
  kapanış süren işleri yine de `queued`'e iade eder.
- **Ayrıştırıcı iş parçacığı** hataları (çökme, bellek sınırı) iş parçacığının
  `error`/`exit` olaylarında yakalanır ve yalnız o taramayı etkiler (ADR-005).
- `installProcessHandlers(runtime, proc = process, exit = process.exit)` olarak
  yazılır; testler sahte bir `EventEmitter` ve sahte `exit` ile AC-P12-9'u doğrular.

### 7. İş iptali ve süre sınırı (D-42, AC-P13-6, AC-P10-14)

- Her tarama işi için bir `AbortController` vardır. İki kaynak onu iptal eder:
  - **Süre sınırı:** sahiplenmede okunan `scan.timeout_minutes` ile
    `setTimeout(timeoutMs)` → `abort('timeout')`.
  - **Kapanış:** `abort('shutdown')`.
- Sahiplenme `UPDATE`'i `timeout_at = NOW() + make_interval(mins => $n)` yazar.
  `timeout_at` bilgi amaçlıdır; karar yerel zamanlayıcıyla verilir (saat kayması
  önemsizdir). API'ye eklenmez (D-43).
- Sinyal clone'a (`CloneRepoFn` isteğe bağlı `signal` parametresi), ayrıştırıcıya
  (`RunParserFn` isteğe bağlı 4. parametre `signal`, ADR-005), OSV aramasına
  (`lookupDependencies(…, signal)`, mevcut istek zaman aşımıyla `AbortSignal.any`)
  ve `saveScanResults`'a iletilir. `saveScanResults` her bağımlılık döngüsü
  başında `signal.throwIfAborted()` çağırır; iptal transaction'ı geri alır.
  Mevcut 3 parametreli test taklitleri tip olarak uyumlu kalır.
- `SCAN_CLONE_TIMEOUT_MS` ayrıca geçerlidir; clone zaman aşımı **geçicidir**,
  iş süre sınırı **kalıcıdır** (D-41).
- Süre sınırında `error_message`: `Tarama süre sınırını aştı (60 dk).` (dakika
  değeri ayardan).

### 8. Hata sınıfları ve yeniden deneme (D-40, D-41, AC-P13-1…5, AC-P13-8)

**Sınıflandırma** (`retryPolicy.ts`, ilk eşleşen kazanır):

| Durum | Sınıf |
| --- | --- |
| İptal nedeni `shutdown` | kapanış iadesi (Karar 5) |
| İptal nedeni `timeout` | kalıcı |
| Token çözülemedi, kaynak/`SCAN_ROOTS`/ref geçersiz (`NonRetryableScanError`) | kalıcı |
| Ayrıştırıcı iş parçacığı çöktü / bellek sınırı / `status: 'failed'` sonucu | kalıcı |
| Git yok veya < 2.32 (yalnız uzak tarama) | kalıcı |
| Clone hatası (kimlik doğrulama/bulunamadı ayrımı yok), clone zaman aşımı | geçici |
| İşleme sırasında veritabanı hatası | geçici |
| Sahipsiz tarama (Karar 9) | geçici |
| Sınıflandırılmamış diğer hatalar | geçici (bugünkü varsayılan; deneme hakkıyla sınırlı) |

**Bekleme fonksiyonu** (saf, jitter yok):

```
backoffSeconds(n) = min(600, 30 * 2^(n-1))     // n = 1, 2, 3, …  (n. yeniden deneme)
                  → 30, 60, 120, 240, 480, 600, 600, …
```

`n < 1` veya tam sayı olmayan `n` için `RangeError`. Sabitler
`runner.config.ts`'teki `retry.initialBackoffMs = 30_000` ve
`retry.maxBackoffMs = 600_000` alanlarına taşınır (kullanılmayan 5 sn / 120 sn
değerleri değişir). Yeni ortam değişkeni eklenmez.

**Deneme sayısı (değişmez):** `max = scan.max_retries` (toplam deneme, ilk deneme
dahil; seed `3`). Varsayılanla bekleme yalnız 30 sn ve 60 sn olarak görülür.

**Yazımlar** (hepsi çitli, Karar 4; `error_message` L-5 arındırmasından geçer):

- *Geçici, hak var* (`n = retry_count + 1`, `n < max`):
  `status='queued', retry_count=n, next_attempt_at = NOW() + make_interval(secs => backoffSeconds(n)), error_message=…, worker_id=NULL, updated_at=NOW()`.
  Log: `Tarama <id> deneme <n>/<max> başarısız; sonraki deneme <next_attempt_at ISO>: <kısaltılmış hata>`.
- *Geçici, hak yok* veya *kalıcı*:
  `status='failed', completed_at=NOW(), next_attempt_at=NULL, error_message=…, updated_at=NOW()`
  ve aynı transaction'da `scan_failed` denetim kaydı. `retry_count` son başarısızlıkta
  artırılmaz (bugünkü davranış).
- Bekleme zamanı **veritabanı saatiyle** (`NOW()`) yazılır ve filtrelenir; uygulama
  saatine dayanılmaz.

**Sahiplenme sorgusu** (tam metin; yeni olanlar `next_attempt_at` koşulu ile
`timeout_at`/`next_attempt_at` yazımıdır):

```sql
SELECT s.id, …
FROM scans s
JOIN projects p ON p.id = s.project_id
LEFT JOIN integrations i ON i.id = s.integration_id
WHERE s.status IN ('pending', 'queued')
  AND s.retry_count < $1
  AND (s.next_attempt_at IS NULL OR s.next_attempt_at <= NOW())
ORDER BY s.created_at ASC
LIMIT 1
FOR UPDATE OF s SKIP LOCKED;

UPDATE scans
SET status = 'running', worker_id = $runId, started_at = NOW(),
    timeout_at = NOW() + make_interval(mins => $timeoutMinutes),
    next_attempt_at = NULL, updated_at = NOW()
WHERE id = $id;
```

Bekleyen bir yeniden deneme, sonra gelen yeni taramayı engellemez: filtre
satırı atlar, sıra `created_at`'tir (AC-P13-7).

> **REQ-003 güvenlik düzeltmesi (2026-10-10).** İki ek kural (güvenlik raporu
> I-3, commit `f32b00c`):
>
> - **Ayar üst sınırları:** `system_settings` ve ortam değişkenlerinden okunan
>   sayısal ayarlar aralık denetiminden geçer; aralık dışı, sonlu olmayan veya
>   tam sayı olması gerekirken tam sayı olmayan değer **varsayılana döner ve bir
>   uyarı log'lanır** (başlangıç durmaz).
>
>   | Ayar | Geçerli aralık |
>   | --- | --- |
>   | `scan.max_retries` | 1–10 (tam sayı) |
>   | `scan.timeout_minutes` | (0, 1440] |
>   | Süre sınırları (ms; clone, rapor, ayrıştırıcı) | 1 ms – 24 sa |
>   | Yoklama aralıkları (ms) | 1 ms – 1 sa |
>   | Eşzamanlılık (`WORKER_MAX_CONCURRENT`, `EXPORT_WORKER_MAX_CONCURRENT`) | 1–32 |
>
>   Gerekçe: üst sınırsız değerler `setTimeout` taşmasına (2^31−1 ms üstü
>   değer hemen tetiklenir) ve sonsuza yakın yeniden denemeye yol açıyordu.
> - **Deneme hakkı tükenmiş bekleyen satır:** sahiplenme transaction'ı, aynı
>   transaction içinde `status IN ('pending','queued') AND retry_count >= max`
>   olan satırları `failed` yapar (`completed_at = NOW()`, `next_attempt_at =
>   NULL`, açıklayıcı `error_message`) ve her biri için `scan_failed` denetim
>   kaydı yazar. Böylece `max_retries` düşürüldüğünde kuyrukta sonsuza kadar
>   bekleyen satır kalmaz (aşağıdaki "Kalan notlar 1" bu kuralla kapanır).

### 9. Sahipsiz tarama kurtarma (D-41, AC-P12-11)

- **Başlangıçta** (Karar 2 adım 7a) `status = 'running'` olan **her** tarama,
  `worker_id` değerinden bağımsız olarak sahipsizdir ve **geçici hata** olarak
  işlenir (Karar 8 yazımları; `error_message = 'Uygulama tarama sürerken durdu;
  tarama kurtarıldı.'`). Hak kalmadıysa `failed` + `scan_failed`. Tek transaction;
  `max` aynı sorguda `system_settings`'ten okunur.
- **Neden güvenli:** tek örnek kilidi (Karar 3) aynı veritabanında yalnız bu sürecin
  çalıştığını garanti eder ve bu süreç henüz hiçbir iş sahiplenmemiştir; dolayısıyla
  o anda `running` olan her satır ölmüş bir sürece aittir. Kilit olmadan bu kural
  başka bir canlı örneğin işini çalardı; PID'li `WORKER_ID` filtresi bu yüzden
  vardı ve bu yüzden bozuktu.
- **Çalışma sırasında süpürme (REQ-003 D-41'i genişletir):** her tarama yoklamasında,
  sahiplenmeden önce, `status = 'running'` olup bu sürecin bellek içi **etkin iş
  kümesinde** olmayan satırlar aynı kuralla kurtarılır. Etkin iş kümesine kimlik,
  sahiplenme transaction'ı commit edildikten hemen sonra (aynı tick'te) eklenir ve
  ancak son yazım başarıyla tamamlandıktan (veya vazgeçildikten) sonra çıkarılır.
  Sahiplenme yalnız sıralı yoklama döngüsünde yapıldığından yarış yoktur.
  Gerekçe: veritabanı kesintisinde son durum yazımı başarısız olan bir tarama
  aksi halde yeniden başlatmaya kadar `running` kalırdı (AC-P12-8'in amacı).
  Bozulmuş kipte (Karar 3) süpürme de durur.
- **Raporlar:** başlangıçta `generating → failed` (bugünkü davranış, AC-P12-11).
  Düzgün kapanışta `generating → pending` (Karar 5). Raporlar için yeniden deneme
  ve bekleme yoktur (REQ-003 Kapsam Dışı).

### 10. Göç aracı (D-32, D-33, AC-P11-1…15)

**Çalıştırma:** `npm run db:migrate` = `node dist/db/migrate.js` (**derlenmiş
çıktı**, D-32). `npm run build` önceden yapılmış olmalıdır; README akışı bunu
sağlar (`npm ci → npm run build → npm run db:migrate → npm start`). Komut
otomatik derleme yapmaz. Göç dosyaları derlenmez; araç ve uygulama
`path.resolve(__dirname, '..', '..', 'db', 'migrations')` ile okur (`src/db` ve
`dist/db` depo kökünden aynı derinlikte olduğu için hem testte hem üretimde aynı
klasörü gösterir).

**Komutlar ve argümanlar:**

| Komut | Davranış |
| --- | --- |
| *(yok)* veya `up` | Bekleyen sürümleri dosya adı sırasıyla uygular; her sürüm için `uygulandı <sürüm> (<ms> ms)` veya `atlandı <sürüm>`. |
| `status` | Uygulanmış (`applied_at` ile), bekleyen ve bilinmeyen sürümleri listeler. Hiçbir şey yazmaz; `schema_migrations` yoksa oluşturmaz, tüm sürümleri bekleyen sayar. |
| `down --to <hedef>` | Hedeften sonraki uygulanmış sürümleri ters sırayla geri alır; hedef uygulanmış kalır. `<hedef>` tam sürüm adı (`003_declared_range`) veya üç haneli numaradır (`003`). Geri alınacak listeyi önce yazdırır. |
| `down` (hedefsiz), bilinmeyen komut/argüman | Kullanım metni, değişiklik yok. |

**Çıkış kodları:**

| Kod | Anlam |
| --- | --- |
| 0 | Başarı (değişiklik olmasa da) |
| 1 | Göç SQL hatası veya bağlantı hatası |
| 2 | Kullanım/yapılandırma hatası (bilinmeyen komut, hedefsiz `down`, `DATABASE_URL` yok) |
| 3 | Durum reddi (klasör doğrulaması, bilinmeyen sürüm, geçersiz/uygulanmamış hedef, sıra dışı bekleyen sürüm) |
| 4 | Kilit başka süreçte ("uygulama çalışıyor veya başka bir göç sürüyor; önce durdurun") |

**Kilit:** her komut (`status` dahil) önce Karar 3'teki kilidi aynı anahtarla ve
`pg_try_advisory_lock` ile alır (`application_name = 'oss-risk:migrate'`); tüm
komut tek bağlantıda çalışır ve kilit sonunda bırakılır. `status`'ün de kilit
istemesi AC-P11-11'in düz okunuşudur; uygulama çalışırken bekleyen göç zaten
olamayacağı için kullanılabilirlik kaybı yoktur.

**Klasör doğrulaması** (herhangi bir değişiklikten önce, AC-P11-10):

- Dosya adı kuralı: `^(\d{3})_([a-z0-9_]+)\.(up|down)\.sql$`. Sürüm = `NNN_ad`
  (`migrate.sh` ile aynı: dosya adı eksi `.up.sql`/`.down.sql`).
- Klasördeki her `.sql` dosyası bu kurala uymalıdır; `.sql` olmayan dosyalar yok
  sayılır.
- Her `up`'ın `down` eşi vardır ve tersi.
- Üç haneli numara benzersizdir (iki farklı adla aynı `NNN` yasak). Sıralama
  numaraya göredir; sıfır dolgulu üç hane olduğu için metin sırasıyla aynıdır.
- İçerik kuralı: dosya kendi transaction'ını açamaz. Satır bazında
  `^\s*(BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION)\s*;` (büyük/küçük harf duyarsız)
  ve `psql` meta komutu (`^\s*\\`) içeren dosya reddedilir. (`DO $$ BEGIN … END $$`
  blokları noktalı virgülsüz `BEGIN` içerdiği için etkilenmez.) `CREATE INDEX
  CONCURRENTLY` gibi transaction dışı ifadeler kullanılmaz (db/README kuralı).

**Durum doğrulaması** (`readMigrationState`; uygulama da kullanır):

- `schema_migrations`'ta olup dosyası olmayan sürüm → **bilinmeyen sürüm**: `up`,
  `down` ve uygulama başlangıcı reddeder (AC-P11-9, AC-P12-5). `status` gösterir.
- **Sıra dışı bekleyen sürüm:** bekleyen bir sürümün numarası, uygulanmış en büyük
  numaradan küçükse `up` reddeder (ör. sonradan araya eklenmiş `004a`). Bu kural
  REQ-003'te yoktur; AC'lerle çelişmez ve göçlerin her ortamda aynı sırayla
  uygulanmasını garanti eder.

**Geriye uyumluluk (AC-P11-3):** tablo ve sürüm adları `migrate.sh` ile aynıdır.
`up`, tabloyu `migrate.sh` ile aynı DDL'le oluşturur:
`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY,
applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`. Tabloya kolon eklenmez.

**Checksum: saklanmaz.** Uygulanmış göç dosyasının sonradan değiştirilmesi riski
şöyle karşılanır: (a) `db/README.md` kuralı "uygulanmış göç dosyası değiştirilmez,
düzeltme yeni göçle yapılır"; (b) qa-automation, `001`…`005` dosyalarının
normalize edilmiş içeriğinin (BOM atılmış, CRLF→LF) SHA-256 değerlerini sabitleyen
bir statik test ekler. Tablo değişikliği gerekmediği için göç `005`'e veya araca
bootstrap mantığı eklenmez.

**Uygulama (`up`):** her bekleyen sürüm için tek bağlantıda:

```
BEGIN
  <dosya içeriği>                          -- parametresiz client.query(sql): simple query protokolü,
                                           -- çok ifadeli metin ve $$ blokları desteklenir
  INSERT INTO schema_migrations (version) VALUES ($1)
COMMIT                                     -- hata: ROLLBACK, sonraki sürümler denenmez, exit 1
```

- Dosya okuma: bayt → başta UTF-8 BOM varsa atılır → katı UTF-8 çözümü
  (`TextDecoder('utf-8', { fatal: true })`) → `\r\n` → `\n` (AC-P11-13).
- Hata mesajı: sürüm adı, PostgreSQL `code`, `message`, varsa `detail`/`hint` ve
  `position`'dan hesaplanan satır numarası. Bağlantı dizesi ve parola hiçbir
  çıktıda yer almaz; bağlantı hataları yalnız sınıf/kodla yazılır (AC-P11-12).
- `RAISE NOTICE` çıktıları (`client.on('notice')`) standart çıktıya yazılır.

**Geri alma (`down --to`):** hedef dosyası olmalı ve uygulanmış olmalıdır; değilse
exit 3. Hedeften büyük her uygulanmış sürüm, ters sırayla, ayrı transaction'da:
`BEGIN; <down dosyası>; DELETE FROM schema_migrations WHERE version = $1; COMMIT`.
Bir geri alma başarısız olursa o sürüm geri alınmamış kalır, öncekiler geri
alınmış kalır, exit 1. `001`'in altında hedef yoktur; `001` araçla geri alınamaz.
Tam sıfırlama veritabanını silip yeniden oluşturmaktır (`db/README.md`).

**Bağlantı:** `DATABASE_URL` ortam değişkeni veya `.env` (`dotenv/config`; npm
script'i depo kökünde çalışır). Parola URL'de veya `PGPASSWORD` ile (`pg` bunu
kendisi okur). `DATABASE_URL` yoksa exit 2.

### 11. Göç `005`: `scans.next_attempt_at` (D-40, AC-P11-16)

Dosyalar: `db/migrations/005_scan_next_attempt.up.sql` / `.down.sql`
(database-engineer; nihai metin onundur).

```sql
-- up
ALTER TABLE scans ADD COLUMN next_attempt_at TIMESTAMPTZ NULL;
COMMENT ON COLUMN scans.next_attempt_at IS
  'Earliest time a queued scan may be claimed again (retry backoff, REQ-003 P-13). NULL = immediately.';
```

```sql
-- down
-- Data lost: only the retry scheduling of queued scans (scans.next_attempt_at).
-- Queued scans become claimable immediately after this rollback.
ALTER TABLE scans DROP COLUMN next_attempt_at;
```

- **Veri:** mevcut satırlar `NULL` alır (hemen sahiplenilebilir); veri göçü yoktur.
- **İndeks eklenmez.** Kuyruk küçüktür ve mevcut kısmi indeks
  `idx_scans_status_active (status) WHERE status IN ('pending','queued','running')`
  sahiplenme sorgusunun aday kümesini zaten daraltır; `next_attempt_at` satır
  filtresi olarak uygulanır. Ek indeks yalnız yazım maliyeti getirirdi.
- **CHECK kısıtı eklenmez** (`next_attempt_at` yalnız kuyruktaki satırda dolu
  olmalı kuralı kodda ve testte sağlanır; filtre `status`'e de baktığı için
  bayat değer zararsızdır).
- `db/schema.sql` güncellenir. Göç `CONCURRENTLY` veya transaction dışı ifade
  içermez.

### 12. Kaldırılanlar ve ADR-003 (d) durumu

- `db/migrate.sh`, `docker-compose.yml`, `worker`/`worker:prod`/`export-worker`/
  `export-worker:prod` script'leri, worker `require.main` blokları kaldırılır
  (AC-P11-15, AC-P12-3, AC-P12-12).
- **ADR-003 (d) ("F1 migration'ları Git Bash + `db/migrate.sh`") bu ADR ile
  superseded'dır.** ADR-003'e durum notu eklenmiştir.
- `db/tests/f1_migrations_test.sql` bir `psql` betiğidir (`\ir`, `\set`); Vitest
  tarafından çalıştırılmaz ve yeni akışta çalıştırılamaz. database-engineer bunu
  siler veya kapsadığı doğrulamaları Vitest göç testlerine taşır (AC-G-2 ruhu: hiçbir
  test yolu `psql` gerektirmez).

## Gerekçe

Tek süreç, tek kilit ve tek kapanış yolu, üç süreçli düzenin bütün yarış ve
sahiplik sorunlarını tek bir değişmeze indirger: "bu veritabanında aynı anda tek
örnek çalışır". Sahipsiz kurtarma, göç/uygulama dışlaması ve rapor iadesi bu
değişmeze dayanır; çit (Karar 4) değişmezin bozulabildiği tek pencereyi (kilit
bağlantısının kopması) kapatır. Session-level advisory lock ek tablo veya dosya
kilidi gerektirmez, süreç ölünce kendiliğinden düşer ve PostgreSQL'in kendisi
tarafından uygulanır. Yeniden deneme beklemesi için ayrı kolon, mevcut kolonların
anlamını bozmadan veritabanı saatiyle deterministik filtre sağlar. Göç aracının
`migrate.sh` ile aynı tabloyu ve adları kullanması F1 veritabanlarını göçsüz
devralmayı mümkün kılar.

## Değerlendirilen alternatifler

- **Transaction-level advisory lock:** uygulama ömrü boyunca tutulamaz, göç aracının
  dosya başına transaction'ıyla da uyumsuz. Reddedildi.
- **Kilidi havuz bağlantısında tutmak:** boşta kapanma ve yeniden kullanım kilidi
  sessizce düşürür. Reddedildi.
- **Kilit tablosu (satır + kalp atışı) veya PID dosyası:** süreç ölünce temizlik
  ve saat sorunları; dosya kilidi farklı veritabanlarını ayıramaz. Reddedildi.
- **Kilit bağlantısı koptuğunda hemen kapanmak (REQ-003 risk notunun düz okunuşu):**
  AC-P12-8 ile çelişir. Bozulmuş kip + yeniden alma tercih edildi.
- **Göçleri `npm start`'ta otomatik uygulamak:** D-35 ile reddedildi.
- **`ts-node`/Node tür ayıklama (`--experimental-strip-types`) ile göç aracını
  derlemeden çalıştırmak:** AC-G-6 `ts-node`'u yasaklar; tür ayıklama CommonJS +
  uzantısız importlarla çalışmaz ve Node 22 alt sürümlerinde bayrağa bağlıdır.
  `db:migrate` içinde otomatik `npm run build`: her çağrıda `tsc` maliyeti ve
  dev bağımlılığı gerektirir; göç dosyaları zaten derlenmeden okunduğu için kazanç
  küçüktür. Reddedildi.
- **`schema_migrations`'a checksum kolonu:** tablo değişikliği (bootstrap sırası
  sorunu), CRLF/BOM normalizasyonu yüzünden belirsiz özet, tek geliştirici için
  sınırlı kazanç. Statik özet testi tercih edildi. Reddedildi.
- **Hazır göç kütüphanesi (`node-pg-migrate`, `postgrator` vb.):** yeni bağımlılık
  (NFR: yeni runtime bağımlılığı yalnız TOML), farklı kayıt tablosu. Reddedildi.
- **`next_attempt_at` yerine `queued_at` veya `timeout_at`'i yeniden kullanmak:**
  anlam çakışması (D-40). Reddedildi.
- **Jitter'lı bekleme:** tek kullanıcıda gereksiz, testi deterministik olmaktan
  çıkarır (D-40). Reddedildi.
- **`next_attempt_at` için indeks / CHECK kısıtı:** yukarıda Karar 11. Reddedildi.
- **Rapor üretimini iş parçacığına almak:** REQ-003 riskler bölümünde sonraki faza
  bırakıldı.

## Sonuçlar / Uygulama etkisi

- **Güvenilirlik:** ikinci örnek ve uygulama çalışırken göç reddedilir; çöken
  süreçten kalan taramalar her başlangıçta ve çalışma sırasında kurtarılır; kalıcı
  ağ sorunu deneme hakkını dakikalara yayar. Kapanış 15 sn ile sınırlıdır; konsol
  penceresi kapatıldığında Windows'un ~10 sn sınırı geçerlidir ve kalan iş sonraki
  başlangıçta kurtarılır.
- **Güvenlik:** varsayılan dinleme `127.0.0.1` kalır; yeni dinleyici yok. Log ve
  CLI çıktısında bağlantı dizesi/parola yok; ölümcül hata kaydı arındırılır.
- **Veri modeli:** yalnız `scans.next_attempt_at` eklenir; `timeout_at` artık
  yazılır. API yanıtları değişmez (D-43).
- **Test (qa-automation):**
  - AC-P13-1 tablo testi (`backoffSeconds`), `n = 0` ve kesirli değer için hata.
  - AC-P13-2/3/7: önce test commit'i (AC-G-5); `next_attempt_at` geçmişe
    çekilerek sahiplenme.
  - AC-P12-11: farklı `worker_id` ile `running` satır → başlangıçta kurtarılır;
    hak bitmiş satır → `failed` + `scan_failed`. Çalışma sırasında süpürme: son
    yazımı enjekte hatayla başarısız olan tarama sonraki yoklamada kurtarılır.
  - AC-P12-4 / AC-P11-11: kilit ayrı bir `pg.Client`'ta tutulurken `startRuntime`
    ve migrator reddeder (exit kodu 1 / 4), veritabanı değişmez.
  - AC-P12-6: `DATABASE_URL` yok (D-52), port dolu (tarama `queued` kalır),
    geçersiz `SCAN_ROOTS`; bekleyen göç ve bilinmeyen sürüm (AC-P12-5).
  - AC-P12-10: `shutdown()` çağrısı; bloklayan enjekte `cloneRepo`/`runParser` ile
    süren tarama `queued`, `retry_count` aynı, `next_attempt_at` NULL, geçici klasör
    yok; `generating` rapor `pending`; zorla çıkış yolu sahte zamanlayıcıyla.
  - AC-P12-9: sahte `process` ile `unhandledRejection` → log'da sır yok, çıkış 1.
  - Kilit kaybı: kilit bağlantısını `pg_terminate_backend` ile düşürüp worker'ların
    durması ve yeniden alımda devam etmesi; kilit başkasındaysa kapanış.
  - Göç aracı: AC-P11-1…13 ve 16; ayrıca sıra dışı bekleyen sürüm reddi, içerik
    kuralı (dosyada `BEGIN;`), `--to 003` numara biçimi, normalize göç özetleri
    testi.
- **Implementer'lar için kritik uyarılar:**
  1. Göç dosyası `client.query(sql)` ile **parametresiz** gönderilmelidir; değer
     dizisi verilirse `pg` extended protocol kullanır ve çok ifadeli dosya hata verir.
  2. Kilit bağlantısı havuzdan alınmaz ve havuza iade edilmez.
  3. Kilit **en son** bırakılır (havuz kapandıktan sonra).
  4. Etkin iş kümesi güncellemesi sahiplenme commit'i ile aynı tick'te yapılır;
     arada `await` olmamalıdır.
  5. İptal sonrası geçici klasör silinmeden önce clone süreç ağacının `close`'u ve
     iş parçacığının `terminate()` sözü beklenir (Windows dosya kilitleri).
  6. Zorla çıkış zamanlayıcısı `unref` edilmez; diğer tüm zamanlayıcılar kapanışta
     temizlenir.
  7. `pool.on('error')` ve kilit istemcisinde `on('error')` dinleyicisi zorunludur.
- **Ana oturum:** `.env.example`'a yeni değişken eklenmez. `npm run build`
  `npm run db:migrate`'ten önce çalıştırılır (README).
- **Handoff:** `docs/handoffs/REQ-003.md` bu kararların uygulanmasını, AC-P11-14 ve
  AC-P12-10 elle doğrulamalarını içermelidir.

## Kanıt (Evidence)

- Repo incelemesi (branch `req-003-f2-tek-runtime`): `src/scanner/worker.ts`
  (`claimNextJob`, `handleScanFailure`, `cleanupOrphanedScans`, `require.main`),
  `src/scanner/sandbox/runner.config.ts` (`workerId`, kullanılmayan backoff
  alanları, `maxAttempts`), `src/reports/worker.ts`, `src/reports/worker.config.ts`,
  `src/app.ts`, `src/lib/db.ts`, `src/config/env.ts`,
  `db/migrations/001_initial_core_schema.up.sql` (`scans`, `reports`,
  `system_settings` seed, indeksler), `db/migrate.sh`,
  `tests/helpers/migrations.ts`, `package.json`, `tsconfig.json`, `.env.example`
  (değişken adları).
- REQ-003 D-32…D-42, D-46 ve AC'ler.
- Dış kaynak (genel bilgi, doğrulanması önerilir): PostgreSQL advisory lock
  belgeleri (session/transaction düzeyi, iki `int4` anahtar biçimi), Node `process`
  sinyal belgeleri (Windows'ta `SIGHUP` ~10 sn, `SIGTERM` desteklenmez, `SIGBREAK`),
  `node-postgres` simple/extended query davranışı. NotebookLM veya Obsidian kaynağı
  kullanılmadı.

## İlgili REQ / AC

REQ-003: AC-G-2, AC-G-5, AC-G-6, AC-G-8; AC-P11-1…16; AC-P12-1…12; AC-P13-1…8;
AC-T-3 (başlangıç adımı); kararlar D-32…D-43, D-46, D-52.

## REQ-003 üzerindeki netleştirmeler

1. **Risk "Advisory lock":** kilit bağlantısı koptuğunda hemen kapanış yerine
   bozulmuş kip + yeniden alma; kilit başkasındaysa kapanış (Karar 3).
2. **D-41 genişletmesi:** sahipsiz kurtarma yalnız başlangıçta değil, her
   yoklamada etkin iş kümesi dışındaki `running` satırlar için de çalışır (Karar 9).
3. **Göç aracı ek kuralı:** sıra dışı bekleyen sürüm `up` ile reddedilir; dosyada
   `BEGIN/COMMIT/ROLLBACK` ve `psql` meta komutu doğrulamada reddedilir (Karar 10).
4. **`WORKER_ID`/`EXPORT_WORKER_ID` ortam değişkenleri kaldırılır**; `worker_id`
   süreç başına üretilen çalışma kimliğidir (Karar 4).
5. **Kapanış:** ikinci sinyal anında zorla çıkış; kapanış iadesinde `worker_id`
   boşaltılır (Karar 5).

## Kalan notlar (karar gerektirmeyen)

1. `scan.max_retries` düşürülürse `retry_count >= max` olan `queued` satırlar
   sahiplenilmez ve kuyrukta kalır (bugünkü davranış). Gerekirse sonraki fazda
   kurtarma kuralına eklenir. *(REQ-003 güvenlik düzeltmesi, 2026-10-10: kapandı —
   Karar 8 notu; bu satırlar sahiplenme transaction'ında `failed` olur.)*
2. `WORKER_MAX_CONCURRENT` (varsayılan 4) ile her tarama bir ayrıştırıcı iş
   parçacığı açar; bellek üst sınırı ADR-005'te.
3. Rapor üretimi ana iş parçacığında kalır (REQ-003 riskler).
4. Implementation tamamlandığında `docs/handoffs/REQ-003.md` güncellenmelidir.

## Onay (Approval)

- **Karar veren:** kullanıcı daimi talimatı (önerilen seçenek), 2026-10-10.
  Talimat REQ-003'te kayıtlıdır ("gerisi için de bana sorma, tavsiye edilen
  sistemle git"). Durum `Accepted`. Karar ana oturum aracılığıyla iletilmiştir;
  kullanıcının bu dosyayı gözden geçirip commit etmesi kaydı kesinleştirir.
- Bu karar **veri modelini** (göç `005`) ve **çalışma zamanı güvenilirlik
  sınırını** (tek örnek kilidi, kapanış, kurtarma) değiştirir. Implementation
  öncesi `docs/ownership/REQ-003.json` `status: approved` gerekir. `down --to`
  ile veri silen geri almalar kullanım anında insan kararıdır; production
  veritabanı kapsam dışıdır.
