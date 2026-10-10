# REQ-003 — Güvenlik İncelemesi (F2: "Windows'ta tek komut")

- İnceleyen: Security Red Team (adversarial review, read-only)
- Tarih: 2026-10-10
- Branch: `req-003-f2-tek-runtime` (HEAD: `df2af4f`)
- İnceleme aralığı: `git diff 73db78b..HEAD` (F1 merge sonrası her şey; 316 dosya)
- Kapsam: P-10 TS ayrıştırıcılar ve iş parçacığı yalıtımı, N-1/D-47 git clone yalıtımı, L-5 `error_message` arındırıcısı, P-11 göç aracı, P-12 tek süreç çalışma zamanı ve tek örnek kilidi, P-13 yeniden deneme/süre sınırı, D-43/AC-G-8 API değişmezliği, bağımlılıklar (`smol-toml`, `uuid` override), gizli değer taraması, README/`.env.example` yönlendirmeleri.
- Kaynaklar: `docs/product/REQ-003.md`, ADR-002 (Ek E1–E5), ADR-004, ADR-005, `docs/quality/security-reports/REQ-002-security-review.md`, `docs/handoffs/REQ-002.md`.
- Tehdit bağlamı: Kişisel, tek kullanıcılı, Docker'sız Windows aracı. Sunucu yalnız `127.0.0.1`'de dinliyor, PostgreSQL yerel. Güvenilmeyen girdiler: taranan repo içeriği (manifest dosyaları, dosya ağacı, symlink/junction), uzak git sunucusunun çıktısı (`remote:` satırları, yönlendirmeler), uzak repo URL'leri. Ayrıca tarayıcı kaynaklı istekler (DNS rebinding/CSRF; F1'de kapatıldı, burada yalnız gerileme açısından bakıldı). Güvenilir girdiler: kullanıcının kendi ortamı (`.env`, `system_settings`, göç dosyaları).

> **Yöntem kısıtı:** Bash bu oturumda rol sınırı hook'u tarafından büyük ölçüde engellendi. Yalnız `git diff --stat`, `git diff -- package.json src/controllers/scanController.ts src/types/scan.ts`, `npm audit --omit=dev` ve `npm audit` çalıştı. `npx vitest run`, `node -e` (ReDoS zamanlama ölçümü) ve `git rev-parse` engellendi. Bu yüzden testler bu oturumda çalıştırılmadı; dinamik doğrulama gerektiren bulgular "doğrulanmadı" olarak işaretlendi. Ek `npm audit` kanıtı ana oturumdan alındı.

## Özet

| Ciddiyet | Sayı |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 5 |
| Info | 9 |

**Merge kararı önerisi: Conditional Go.** Critical veya High bulgu yok.

- **M-1** (ayrıştırıcıdaki `pyStrip`/`pyRstrip` regex'lerinin karesel zamanlı olması): Kötü niyetli bir manifest, tarama iş parçacığını süre sınırına (varsayılan 60 dk) kadar CPU'da kilitleyebilir. Düzeltmesi küçük. Merge'den önce kapatılması önerilir; kapatılmayacaksa insan risk kabulü handoff'a yazılmalı.
- **L-1** (L-5 arındırıcısının sıralama açığı) güvenlik etkisi açısından düşük. Ancak AC-T-4'ün kırmızı testlerine karşılık geliyor; bu yüzden merge öncesi düzeltilmeli.
- **L-3** (testte gerçek profil adı) ve **L-4** (`.env.example`) kod değişikliği değil, ama merge öncesi düzeltilmeli.

## F1'den devreden bulguların durumu

| Bulgu | Durum | Gerekçe |
| --- | --- | --- |
| N-1 (clone, kullanıcı/sistem git yapılandırmasından yalıtılmamış) | **Kapandı** | `buildGitEnv` üst ortamı kopyalamıyor; yalnız izin listesi (`workspace.ts:121-145`). `GIT_CONFIG_NOSYSTEM=1`, iş başına boş `GIT_CONFIG_GLOBAL`, `HOME`, `XDG_CONFIG_HOME` var (`workspace.ts:196-207`). `core.hooksPath`=boş iş klasörü, `core.askPass=`, `credential.helper=` (`workspace.ts:98-109`). Git < 2.32 uzak taramada kalıcı hata veriyor (`gitVersion.ts:124-132`). Ayrıntı aşağıda. |
| L-4 (junction/symlink ile kök dışı okuma) | **Kapandı** | TS ağaç yürüyüşü her girdi için `lstat` kullanıyor. Link ve junction izlenmiyor. Her manifest dosyası `realpath` ile köke karşı yeniden denetleniyor (`common.ts:384-453`). Kalıntı için bkz. L-5. |
| L-5 (alt süreç çıktısı sınırsız ve ham) | **Büyük ölçüde kapandı** | Python alt süreci ve stdout yok; sonuç `postMessage` ile geliyor ve 512 MiB heap sınırıyla sınırlı. Git stderr 64 KiB kuyruk ve 1024 kod noktası (`workspace.ts:36-37, 241-254, 324-333`). Tüm `error_message` yazımları `sanitizeErrorText` hunisinden geçiyor (`worker.ts:335, 893, 1212`; `reports/worker.ts:231`). Arındırıcının kendi açığı için bkz. L-1. |
| D-24 (`exceljs` → `uuid` moderate) | **Kapandı** | `overrides.uuid=11.1.1`. `npm audit --omit=dev` → `found 0 vulnerabilities` (bu oturumda çalıştırıldı). |
| L-1, L-2, L-6, L-7 (F1) | Kapsam dışı / değişmedi | F2 diff'i bunlara dokunmuyor. L-7'nin `.env.example` kısmı için bkz. L-4. |

## Doğrulanan kontroller (olumlu bulgular)

**Git clone yalıtımı (N-1/D-47, ADR-002 Ek E1)**
- Ortam tamamen izin listesinden kuruluyor: `PATH`, `PATHEXT`, `SystemRoot`, `windir`, `SystemDrive`, `ComSpec`, `TEMP`, `TMP`, `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`, `OS` ve vekil değişkenleri. Windows'ta büyük/küçük harfe duyarsız. `GIT_*`, `USERPROFILE`, `SSH_ASKPASS`, `CURL_CA_BUNDLE`, `DATABASE_URL`, `PGPASSWORD`, `ENCRYPTION_KEY` geçmiyor (`workspace.ts:121-145`).
- `HOME` boş iş klasörü olduğundan `.netrc`/`_netrc` ve `~/.gitconfig` okunmuyor. `GIT_CONFIG_NOSYSTEM=1` Git for Windows'un `%PROGRAMDATA%\Git\config` dosyasını da kapatıyor; bu dosya sistem katmanında okunuyor. Bu yüzden GCM credential helper ve sistem `http.*` ayarları devre dışı.
- `core.askPass=` boş; git boş askpass değerini "yok" sayar ve `GIT_TERMINAL_PROMPT=0` ile terminal istemine de düşmez. Ana oturumun gözlemi (olmayan repo kullanıcı adı sormadan hata verdi) bununla tutarlı.
- `GIT_ALLOW_PROTOCOL=https`, `http.followRedirects=false`, LFS filtreleri boş ve `required=false`, `GIT_LFS_SKIP_SMUDGE=1`, `core.symlinks=false`, submodule recursion yok.
- Token yalnız `GIT_CONFIG_KEY_0=http.https://<host>[:port]/.extraHeader` ile, hosta sınırlı olarak iletiliyor. argv'de, URL'de ve `.git/config`'te yok. Token'sız klonda `GIT_CONFIG_COUNT=0` (`workspace.ts:189-214`).
- `ref` hem iş başında (`worker.ts:551-554`) hem argüman kurulurken (`workspace.ts:112-115`) `^[A-Za-z0-9._/-]+$` ile denetleniyor ve `-` ile başlayamıyor. Ayrıca `--branch <ref>` ayrı argv elemanı ve URL'den önce `--` var. `--upload-pack` gibi seçenek enjeksiyonu mümkün değil.
- stderr'de token hem ham hem Basic base64 biçimiyle tam eşleşmeyle (`split/join`) maskeleniyor. Kuyruk kesiminde ilk yarım satır atılıyor; yarım token sızmıyor (`workspace.ts:241-254`).
- Clone zaman aşımı ve iş iptali Windows'ta `taskkill /T /F` ile tüm süreç ağacını öldürüyor (shell yok). Çalışma alanı silinmeden önce bekleniyor (`workspace.ts:314-320, 341-354`).
- `git --version` yoklaması da izin listesi ortamıyla ve `GIT_CONFIG_NOSYSTEM=1` ile çalışıyor (`gitVersion.ts:53-91`).

**TS ayrıştırıcılar ve iş parçacığı (P-10, ADR-005)**
- Repo içeriği yalnız veri olarak işleniyor. `JSON.parse` ve `smol-toml` dışında yorumlayıcı yok; `setup.py` vb. çalıştırılmıyor.
- Prototip kirliliği: Ayrıştırıcılar güvenilmeyen anahtarlarla düz nesneye yazmıyor. Kapsam ve aralık tabloları `Map` (`nodejs.ts:298-326`), okuma `hasOwnProperty` ile (`common.ts:198-203`). `JSON.parse` `__proto__`'yu own property olarak üretiyor. `smol-toml` 1.9.0 `Object.create(null)` tabloları kullanıyor ve `__proto__` anahtarını `defineProperty` ile yazıyor (`node_modules/smol-toml/dist/index.cjs:450-473, 529-537`). Kirlilik yolu bulunamadı.
- Derin iç içelik: `smol-toml` `maxDepth` varsayılanı 1000 (`index.cjs:583`). npm v1 lock özyinelemesi (`nodejs.ts:159-179`) 4 MiB yığın sınırında `RangeError` fırlatır. Bu hata dosya başına `try` içinde kalır, yalnız o dosya `parse_errors`'a düşer (çalıştırılarak doğrulanmadı).
- Dosya boyutu: 32 MiB sınırı hem `lstat` boyutunda hem okumadan sonra uygulanıyor. Hash ve metin aynı tampondan üretiliyor (`common.ts:498-521`).
- Ağaç yürüyüşü yığın tabanlı (özyineleme yok). Link ve junction izlenmiyor (Windows'ta libuv junction'ları `isSymbolicLink()` olarak raporlar). Manifest dosyaları `realpath` ile köke karşı denetleniyor; Windows'ta büyük/küçük harfe duyarsız, ayraçlı önekle (`common.ts:361-368, 439-442`).
- Hata metinleri yol içermiyor: Dosya sistemi mesajları yerine sabit metin ve errno kodu kullanılıyor. Kütüphane mesajları `scrubRoot` ile temizleniyor (`common.ts:481-572`). İş parçacığı çökmesinde yalnız hata türü saklanıyor (`threadParser.ts:129-136`).
- İş parçacığı yalıtımı: `env: {}`, `argv: []`, `execArgv: []`, `resourceLimits` 512/64 MiB ve 4 MiB yığın (`threadParser.ts:157-164`, `runner.config.ts:140-146`). Kendi zamanlayıcısı yok; iş sinyaliyle `terminate()` ediliyor ve sonuç dönmeden önce bekleniyor (`threadParser.ts:185-187`).
- **Kaynak modu önyüklemesi üretimde devreye girmiyor.** `eval: true` + ts-node yalnız `__filename.endsWith('.ts')` iken kullanılıyor (`threadParser.ts:72-82, 156-158`). `npm start` = `node dist/main.js`; `package.json`'da ts-node ile çalışan bir script kalmadı (`worker`, `export-worker` scriptleri silindi). Önyükleme metnindeki yollar `JSON.stringify` ile gömülüyor; enjeksiyon yok. Kaynak modunda ortam yalnız `DISABLE_V8_COMPILE_CACHE=1`.

**Çalışma zamanı, kilit, göç**
- Tek örnek kilidi kendi `pg.Client`'ında. Anahtarlar sabit ve parametresiz (`advisoryLock.ts:36-47`). `error`/`end` dinleyicileri `connect`'ten önce bağlanıyor. Kilit kaybı yalnız sınıf/kodla raporlanıyor.
- Başlangıç sırası: önce ortam, sonra kilit, göç denetimi, SCAN_ROOTS, git, listen, worker'lar. Bağlantı hataları yalnız `errorCode` ile raporlanıyor (`runtime.ts:186-210`). Bekleyen veya bilinmeyen göçte başlangıç reddediliyor; göç otomatik uygulanmıyor (`migrator.ts:494-533`).
- `unhandledRejection`/`uncaughtException`: Tüm `pg` nesnesi değil, yalnız ad, mesaj ve yığın çerçeveleri yazılıyor. URL kullanıcı bilgisi, `DATABASE_URL`, `PGPASSWORD`, `ENCRYPTION_KEY`, `NVD_API_KEY` ve URL içindeki parola maskeleniyor (`redact.ts:15-71`, `runtime.ts:579-592`).
- Sonuç yazma çiti: `SELECT … WHERE status='running' AND worker_id=$runId FOR UPDATE` + koşullu `UPDATE` + `rowCount` kontrolü (`worker.ts:644-654, 916-936`). Hata ve iade yazımları da çitli (`worker.ts:1198-1250`). Kapanış süpürmesi taramalarda yalnız kendi `runId`'sini kapsıyor (`runtime.ts:452-456`). Kilit kaybında bozulmuş kipte claim ve sahipsiz süpürme duruyor.
- Göç aracı: dosya adı kuralı, çift (up/down) zorunluluğu, katı UTF-8, symlink reddi (`Dirent.isFile`). Her dosya tek transaction içinde ve kayıt satırıyla birlikte uygulanıyor. Bilinmeyen veya sıra dışı sürümde hiçbir değişiklik yapılmadan reddediliyor. `down` yalnız `--to` ile ve hedef uygulanmış kalacak şekilde çalışıyor; 001 geri alınamıyor. Çıkış kodları 0/1/2/3/4. Bağlantı hataları host, kullanıcı ve parola olmadan açıklanıyor (`migrate.ts:98-119`). `.env` yalnız CLI giriş noktasında yükleniyor (`migrate.ts:259`).
- `005_scan_next_attempt` yalnız nullable bir kolon ekliyor; `down` yalnız o kolonu siliyor.

**API değişmezliği (D-43/AC-G-8)**
- `POST /api/scans` ve `GET /api/scans/:id` açık kolon listesi kullanıyor; `next_attempt_at` ve `timeout_at` yanıtta yok (`scanController.ts:12-19`). `GET /api/scans` listesi zaten açık kolonlu ve iç alan içermiyor (`scanController.ts:31-35`). `worker_id` F1'de de `*` ile dönüyordu; içeriği değişti (bkz. I-2).

**Bağımlılıklar**
- `smol-toml@1.9.0`: exact pin, BSD-3-Clause, bağımlılığı yok, npm provenance ile yayımlanmış. `npm audit --omit=dev` → 0 açık.
- `overrides.uuid=11.1.1`: audit temiz. `exceljs` uyumluluğu `tests/integration/excelExport.test.ts` ile kapsanıyor (bu oturumda çalıştırılmadı).

**README**
- PostgreSQL için `trust` auth, `listen_addresses='*'` veya `pg_hba.conf` gevşetmesi önerilmiyor. Ayrı, parolalı ve süper kullanıcı olmayan bir rol (`CREATE USER ossrisk … ; CREATE DATABASE … OWNER ossrisk`) öneriliyor. Parolanın URL yerine `PGPASSWORD` ile verilmesi öneriliyor. `HOST`'u ağa açmanın riski belirtilmiş. Vekil ve CA davranışı doğru belgelenmiş (`README.md:53-102`). Yanlış güvenlik yönlendirmesi bulunamadı (`.env.example` uyumsuzluğu için bkz. L-4).

## Bulgular

### M-1 — `pyStrip` / `pyRstrip` regex'leri uzun boşluk dizilerinde karesel zamanlı: kötü niyetli manifest ile tarama iş parçacığında CPU DoS

- **Severity:** Medium (doğrulanmadı: statik analiz; `node -e` ile zamanlama ölçümü hook tarafından engellendi)
- **Evidence:** `src/scanner/parsers/common.ts:94-105`

  ```ts
  const STRIP_RE = new RegExp(`^[${PY_WS}]+|[${PY_WS}]+$`, 'gu');
  const RSTRIP_RE = new RegExp(`[${PY_WS}]+$`, 'u');
  ```

  `[WS]+$` alternatifi her başlangıç konumunda boşluk dizisinin sonuna kadar açgözlü eşleşiyor, `$` başarısız oluyor ve geri izliyor. n uzunluğunda, sonda olmayan bir boşluk dizisi için toplam adım sayısı ~n²/2. Bu, V8 irregexp'te bilinen "trim-right ReDoS" deseni (ör. `trim` paketi CVE-2020-7753). Python'un `str.strip()` işlemi doğrusal zamanlıydı; açık TS portuyla geldi (gerileme).
  Çağrı noktaları güvenilmeyen satırları doğrudan işliyor: `python.ts:188, 199` (her `requirements*.txt` satırı), `nodejs.ts:110, 197, 205, 321` (`package.json` specifier değerleri, her `yarn.lock` satırı). TOML/JSON metin değerleri de aynı yoldan geçiyor.
- **Attack path / reproduction:**
  1. Saldırgan bir repoya `requirements.txt` koyar: `a` + 1 000 000 boşluk + `b` (≈1 MB; 32 MiB sınırının çok altında).
  2. Kullanıcı bu repoyu tarar (aracın amacı zaten yabancı repo taramak).
  3. `pySplitLines` satırı tek parça bırakır. `parseRequirementLine` → `pyStrip(rawLine.split('#',1)[0])` ~5·10¹¹ geri izleme adımına girer; pratikte süre sınırına kadar bitmez.
  4. İş parçacığı `scan.timeout_minutes` (varsayılan 60 dk) dolana kadar bir CPU çekirdeğini %100 kullanır, ardından `terminate()` edilir ve tarama kalıcı `failed` olur (yeniden deneme yok).
  5. `WORKER_MAX_CONCURRENT=4` olduğundan, aynı içerikli 4 tarama tüm tarama kuyruğunu 60 dk boyunca kilitler.

  Doğrulama önerisi: `pyStrip('a' + ' '.repeat(N) + 'b')` için N=10k/20k/40k sürelerinin ~4 kat artması karesel davranışı kanıtlar. `terminate()`'in regex yürütmesini kesmesi V8 kesme mekanizmasıyla beklenir; o da doğrulanmalı.
- **Impacted area:** P-10 ayrıştırıcılar, tarama kuyruğu kullanılabilirliği (AC-P10-14 iş parçacığı sınırları yalnız belleği sınırlar, CPU'yu sınırlamaz)
- **Remediation requirement:**
  - `pyStrip`/`pyRstrip`'i regex'siz, doğrusal bir döngüyle yeniden yazın: `PY_WS` kümesini bir `Set<string>`/karakter testi olarak tutup baştan ve sondan indeks ilerletin (`pyStripChars` zaten bu desende, `common.ts:108-116`). Golden testler davranışın aynı kaldığını doğrular.
  - Aynı deseni `REQUIREMENT_RE`, `EXACT_PIN_RE`, `BARE_VERSION_RE` (`python.ts:38-45`) için de gözden geçirin. Bu ifadeler `^` ile çapalı ve tek geçişte bittiği için şu an karesel değiller, ancak `[WS]*` + `(?=\n?$)` bileşimleri değişikliklere karşı kırılgan.
  - Regresyon testi: 1–2 MB'lık tek boşluk dizisi içeren `requirements.txt` ve `yarn.lock` satırı → ayrıştırma < 1 sn.
  - İsteğe bağlı derinlemesine savunma: ayrıştırma aşaması için iş süre sınırından bağımsız, daha kısa bir iş parçacığı zaman aşımı (ör. 5 dk).
- **Merge decision:** Merge öncesi kapatılması önerilir. Kapatılmayacaksa insan risk kabulü (tek kullanıcı, kendi kendini sınırlayan DoS) handoff'a yazılmalı.

### L-1 — L-5 arındırıcısı sırları kontrol karakteri temizliğinden önce maskeliyor: ANSI'ye yapışık ve kontrol karakteriyle bölünmüş token/yol maskeden kaçıyor

- **Severity:** Low (QA bulgusu doğrulandı; kod incelemesiyle ve QA'nın kırmızı testleriyle)
- **Evidence:**
  - Sıra: `src/lib/errorText.ts:152`: `stripControl(maskPaths(maskSecrets(input)))`. ADR-002 Ek E3 de bu sırayı öngörüyor (`errorText.ts:9-19`).
  - Desenler `\b` ile başlıyor: `errorText.ts:56-60`. CSI son harfi `m` bir kelime karakteri; bu yüzden `\x1b[31mghp_…` içinde `ghp_` öncesinde kelime sınırı yok, desen eşleşmiyor. Ardından `stripControl` diziyi siliyor ve token açıkta kalıyor.
  - Kırmızı testler: `tests/unit/errorText.test.ts:161-174` (3 vaka).
- **Benzer atlatmalar (aynı kök neden veya desen kapsamı):**
  1. **CR/kontrol karakteriyle bölme:** `stripControl` tek başına duran `\r` dahil C0/C1 karakterlerini siliyor (test `'a\r\nb\rc' → 'a\nbc'`, `errorText.test.ts:179`). `ghp_AAAA\rBBBB…` maskeleme anında desenle eşleşmez, temizlikten sonra birleşir. Aynı durum `context.secrets`'teki tam eşleşmeli işin token'ı için de geçerli (`gh\x00p_…` → split eşleşmez → temizlik birleştirir). Aynı durum yollar için de geçerli: `C:\Users\qa\x00-user` → `C:\Users\qa-user`.
  2. **Kelime karakteri öneki:** `%3Aghp_…` (yüzde kodlanmış `:`; `A` kelime karakteri), `_ghp_…`, `xglpat-…` → `\b` yok, eşleşmiyor.
  3. **Büyük/küçük harf:** `\b(Bearer\s+)…` deseninde `i` bayrağı yok; `bearer abc…` maskelenmiyor (`errorText.ts:60`). `Authorization:` deseninde var.
  4. **Sıfır genişlikli karakter:** U+200B/U+2060/U+FEFF C0/C1 değil, silinmiyor; token deseni bölünüyor ve kayıtta token+ZW kalıyor. Bunu yalnız düşmanca bir kaynak üretir, o da işin token'ına sahip değildir; Info düzeyinde.
  5. **2000 sınırı:** Kesim en sonda yapılıyor. Clone ayrıntısı arındırmadan sonra kuyruktan kesiliyor (`workspace.ts:327-332`). Yarım sır sızıntısı yolu bulunamadı (olumlu).
  6. **Base64 Basic:** İşin token'ının Basic biçimi `secrets`'te var (`workspace.ts:177-180`). Başka bir token'ın çıplak base64'ü yalnız `Authorization:` başlığıyla birlikteyse maskeleniyor; desen dışı kalıyor (Info).
- **Attack path / reproduction:** `sanitizeErrorText('remote: \x1b[31mghp_' + 'A'.repeat(36) + '\x1b[0m denied')` → çıktıda `ghp_AAAA…` kalıyor (QA testi). Gerçek etki sınırlı: İşin kendi clone token'ı tam eşleşmeyle maskelendiği için, bu açık yalnız `secrets`'te olmayan token'ları (uzak sunucunun yankıladığı veya başka kaynaktan gelen metinler) ya da kontrol karakteriyle bölünmüş metinleri etkiliyor. Saldırgan kontrollü bir yolla kullanıcının kendi token'ını sızdırmak için somut bir zincir bulunamadı.
- **Impacted area:** AC-T-4, D-48, `scans.error_message`, `reports.error_message`, yeniden deneme log satırı
- **Remediation requirement:**
  - Sırayı değiştirin: önce `stripControl` (ANSI CSI + C0/C1; isteğe bağlı olarak `\p{Cf}` biçim karakterleri, yani ZW/BOM), sonra sırlar, sonra yollar, en son uzunluk. ADR-002 Ek E3 sıra maddesi buna göre güncellenmeli (solution-architect). Alternatif: maskeleme → temizlik → maskelemeyi tekrar et.
  - Token desenlerinde `\b` yerine `(?<![A-Za-z0-9])` kullanın. Yüzde kodlama için desenleri `%[0-9A-Fa-f]{2}` önekinden sonra da eşleşecek biçimde yazın veya önce yüzde kodunu çözülmüş bir kopyada arayın.
  - `Bearer` desenine `i` bayrağı ekleyin.
  - Testler: mevcut 3 kırmızı test + `\r` ile bölünmüş token + `%3Aghp_` + `bearer` küçük harf + `C:\Users\qa\x00-user`.
- **Merge decision:** Güvenlik etkisi Low. Ancak AC-T-4 kırmızı olduğundan merge öncesi düzeltilmeli (backend-engineer).

### L-2 — Symlink hedefi `statSync` ile çözülüyor: yerel taramada UNC hedefli bir link Windows'ta dışarıya SMB bağlantısı (NTLM) tetikleyebilir

- **Severity:** Low (doğrulanmadı; yalnız yerel klasör taraması, link oluşturma yetkisi gerekir)
- **Evidence:** `src/scanner/parsers/common.ts:416-429`. Link izlenmiyor, ancak türünü öğrenmek için `fs.statSync(abs)` hedefi çözüyor. `\\saldirgan\paylasim\x` hedefli bir dizin/dosya symlink'inde bu çağrı SMB oturum açmayı ve kullanıcının NTLMv2 özetinin gönderilmesini tetikleyebilir.
- **Attack path:** Kullanıcı `SCAN_ROOTS` altına güvenilmeyen bir arşivi açar (symlink'i koruyan bir araçla, Developer Mode açık) veya başka bir yerel süreç link yerleştirir, ardından klasörü tarar. Uzak clone'larda `core.symlinks=false` olduğundan bu yol yok.
- **Impacted area:** P-04/P-10 yerel tarama, kimlik bilgisi gizliliği
- **Remediation requirement:** Link hedefini hiç çözmeyin. `lstat` sonucu `isSymbolicLink()` ise ad bir manifest adıysa `fileLinks`'e, değilse `LINK_NOT_FOLLOWED_MESSAGE` kaydına yazın; dizin/dosya ayrımını `Dirent` tipinden veya hiç yapmadan raporlayın. Golden çıktı etkileniyorsa sapma D kaydı olarak belgelenmeli.

### L-3 — Test kodunda gerçek kullanıcının Windows profil adı var (kişisel veri)

- **Severity:** Low
- **Evidence:** `tests/unit/errorText.test.ts:99-101`: `homeDir` değeri ve "bir harf uzun kardeş ad" sınır vakası gerçek Windows profil adıyla yazılmış (bu raporda tekrar edilmiyor). Diğer testler sahte `qa-user` kullanıyor (`errorText.test.ts:18-20`, `gitIsolation.test.ts:111-159`). Yorum satırı ("the profile named in the task") adın görevden kopyalandığını gösteriyor.
- **Impacted area:** CLAUDE.md "kişisel veriyi yazma/commit etme" kuralı, AC-P09-4 ruhu
- **Remediation requirement:** Değerleri `qa-user` / `qa-userr` ile değiştirin (qa-automation). Dal henüz merge edilmediği için geçmişin yeniden yazılması gerekmez; ama bu satırların main'e girmemesi gerekir. Ayrıca `tests/fixtures/p10-golden/**` grep ile tarandı: gerçek görünümlü token, yerel mutlak yol veya kullanıcı adı bulunamadı (`ghp_/github_pat_/glpat-` + 20 karakter, `C:\Users\…`, `/Users/…`, özel anahtar başlıkları).

### L-4 — `.env.example` F2 ile uyumsuz: Docker/Python değişkenleri duruyor ve varsayılan bağlantı `postgres` süper kullanıcısıyla

- **Severity:** Low
- **Evidence:** `.env.example:5`: `DATABASE_URL=postgres://postgres@localhost:5432/oss_risk`; `.env.example:8-11`: `docker-compose.yml` yorumu ve `POSTGRES_*`; `.env.example:24-25`: `PYTHON_BIN`. README ise ayrı bir `ossrisk` rolü öneriyor (`README.md:59-60, 76`). Ayrıca `.env.example:22`'deki `SCAN_CLONE_TIMEOUT_MS=120000` değeri README'deki varsayılanla (5 dk) çelişiyor. Bir test bu nedenle kırmızı (koordinatör beyanı).
- **Attack path:** README yerine `.env.example`'ı izleyen kullanıcı uygulamayı ve göç aracını süper kullanıcıyla çalıştırır. Gelecekte olası bir SQL enjeksiyonunun etkisi (`COPY … PROGRAM`, dosya okuma/yazma) en yükseğe çıkar. En az yetki ilkesi ihlali.
- **Remediation requirement:** Ana oturum (DevFlow guard nedeniyle ajanlar yazamıyor) şunları yapmalı: `DATABASE_URL=postgres://ossrisk@localhost:5432/ossrisk` yapın; `POSTGRES_*`, docker yorumu ve `PYTHON_BIN` satırlarını silin; `SCAN_CLONE_TIMEOUT_MS` değerini README ile hizalayın veya yoruma alın; `ENCRYPTION_KEY` satırına "32 bayt rastgele değer" notu ekleyin (F1 I-2). `.gitignore`'a `.env.*` + `!.env.example` eklenmesi (F1 L-7) hâlâ açık.

### L-5 — Kapanış süpürmesi ve başlangıç kurtarması raporlarda çitsiz: kilit kaybı senaryosunda başka örneğin raporları etkileniyor

- **Severity:** Low (bütünlük; yalnız kilit kaybı ve çift örnek durumunda)
- **Evidence:** `src/runtime.ts:457-459`: `UPDATE reports SET status='pending' WHERE status='generating'`. Bu sorguda `worker_id` benzeri bir sahiplik koşulu yok (taramalarda var: `runtime.ts:452-456`). `src/reports/worker.ts:116-127` (`recoverOrphanedReports`) ve `reports/worker.ts:235-243` (hata yazımı `WHERE status != 'ready'`) de çitsiz. Ayrıca rapor zaman aşımı `Promise.race` ile uygulanıyor ve `processReport`'u iptal etmiyor (`reports/worker.ts:220-227`); zaman aşımından sonra `ready` yazılabilir.
- **Attack path:** A örneğinin kilit bağlantısı koptu, B başladı ve rapor üretiyor. A'nın `tryRelock`'u kilidin başka örnekte olduğunu görür ve `shutdown('lock-lost')` çalıştırır (`runtime.ts:367-369`). Süpürme B'nin `generating` raporlarını `pending` yapar ve rapor iki kez üretilir. Gizlilik etkisi yok.
- **Remediation requirement:** Rapor satırına sahiplik (run id) eklenmesi bir şema değişikliği gerektirir; F3'e bırakılabilir. Kısa vadede `lock-lost` kapanışında rapor süpürmesini atlayın (kilit artık bizde değil). Bu bulgu insan kararıyla ertelenebilir.

### I-1 — `PORT=0`: Host izin listesi `:0` portuyla kuruluyor, her istek 403 alıyor (işlevsel hata; güvenlik gevşemesi yok)

- **Evidence:** `src/config/env.ts:32-36` (`fromEnv >= 0` → 0 kabul ediliyor), `src/app.ts:51` (`buildAllowedOrigins(resolvePort(...))`), `src/middleware/requestGuards.ts:19-20`. İzin listesi socket'in gerçek portundan değil yapılandırılmış porttan türetiliyor (DNS rebinding savunmasının tasarımı).
- **Değerlendirme:** Fail-closed. Tarayıcı `Host: 127.0.0.1:0` gönderemez; başka bir sitenin Host'u eşleşmez. İzin listesi yanlış portla gevşemiyor. Yerel tarayıcı dışı süreçler zaten her Host'u yazabilir. Güvenlik etkisi yok.
- **Öneri:** `PORT=0` için başlangıçta açık bir hata verin (`PORT 1–65535 olmalı`) veya listen sonrası gerçek portla izin listesini kurun. İkincisini seçerseniz izin listesi yalnız gerçek porttan türetilmeli; istekten gelen bir değerle kurulmamalı.

### I-2 — API'deki `worker_id` artık `hostname:pid:rastgele` içeriyor

- **Evidence:** `src/lib/runId.ts:10-12`, `src/controllers/scanController.ts:16`. Kolon F1'de de dönüyordu (D-43 ile tutarlı). İçerik makine adını (çoğu zaman kullanıcı adı içerir, ör. `QA-PC`) API tüketicisine ve `GET /api/scans/:id` yanıtına taşıyor.
- **Değerlendirme:** Tek kullanıcılı araçta tüketici makine sahibidir; düşük. API anahtarı CI'da kullanılıyorsa CI loglarına makine adı yazılabilir.
- **Öneri:** F3'te kolon API'den çıkarılabilir veya yalnız rastgele kısım döndürülebilir (contract değişikliği; contract-broker).

### I-3 — `system_settings` değerleri üst sınırsız: zamanlayıcı taşması ve sonsuza yakın yeniden deneme

- **Evidence:** `src/scanner/retryPolicy.ts:139-140` (yalnız `>0`/`>=1` denetimi), `src/scanner/worker.ts:504-506` (`setTimeout(timeoutMinutes*60000)`). `scan.timeout_minutes` > ~35 791 olursa Node `TimeoutOverflowWarning` verir ve süreyi 1 ms'ye indirir; her tarama anında "süre sınırı" ile `failed` olur. Çok büyük `scan.max_retries` ulaşılamayan bir hosta 10 dk aralıkla sınırsız clone denemesi yapar. `max_retries` düşürülürse `retry_count >= max` olan `queued` satırlar hiç claim edilmez ve hiç `failed` olmaz (`worker.ts:442`). `SCAN_CLONE_TIMEOUT_MS` negatifse (`workspace.ts:278`) her clone hemen zaman aşımına düşer.
- **Değerlendirme:** `system_settings`'e API'den yazılmıyor (grep: yalnız okuma); DB yazma yetkisi gerekiyor. Sağlamlık sorunu.
- **Öneri:** `timeoutMinutes ≤ 24*60`, `maxAttempts ≤ 10` gibi üst sınırlar ve aralık dışında varsayılana düşme. Claim'de `retry_count >= max` olan satırları `failed`'e çeken bir temizlik adımı.

### I-4 — Dev bağımlılık zinciri: `tinypool` ≤2.1.1 (critical ×2) ve `@vitest/mocker` (moderate)

- **Evidence:** `npm audit` (bu oturumda çalıştırıldı, ana oturum da teyit etti): `tinypool` GHSA-5gmw-xhrv-c9v3 ve GHSA-85c8-ppgw-ccpr (worker/run seçeneklerinde prototip kirliliği gadget'ı ile RCE), `@vitest/mocker` GHSA-82fw-gwwq-j7x9 (redirect mock ile path traversal / dosya okuma), `vitest` 3.2.7 üzerinden. `npm audit --omit=dev` → 0.
- **Sömürülebilirlik:** Üretim artefaktına (`dist/`, `npm start`) girmiyor. tinypool gadget'ı, test sürecinde önceden bir prototip kirliliği kaynağı gerektiriyor; testler güvenilir yerel kodu çalıştırıyor ve saldırgan girdisi (fixture'lar) yalnız veri olarak okunuyor. Fixture ayrıştırması `Object.prototype`'a yazmıyor (bkz. olumlu bulgular). `@vitest/mocker` açığı kötü niyetli bir test dosyası veya yapılandırma gerektiriyor; bu, zaten kod çalıştırma demek. Pratik risk: tedarik zinciri (kötü niyetli bir dev bağımlılığı veya PR'daki test dosyası) ve CI'da güvenilmeyen PR çalıştırma. Tek geliştiricili yerel projede düşük.
- **Öneri:** Ana oturumun planladığı `vitest` yükseltmesi (≥ 4.1.11; audit aralığı "≤ 4.1.10") uygundur. Yükseltmeden sonra `npm audit` ile `tinypool` sürümünün > 2.1.1 olduğu teyit edilmeli (npm'in önerdiği düzeltme 5.0.3; 4.1.11'in yamalı `tinypool`'u çekip çekmediği **doğrulanmalı**). Yükseltme bu merge'ü engellememeli; yapılamazsa risk kabulü (dev-only) handoff'a yazılmalı.

### I-5 — Göç dosyası transaction denetimi satır başı tabanlı

- **Evidence:** `src/db/migrator.ts:45-52`. Aynı satırdaki `SELECT 1; COMMIT;` veya `/* x */ COMMIT;` yakalanmıyor. Simple query protokolünde dosya ortasındaki `COMMIT` dosyanın atomikliğini bozar.
- **Değerlendirme:** Göç dosyaları güvenilir girdi (geliştirici yazıyor); bu denetim bir lint, güvenlik sınırı değil.
- **Öneri:** Dokümante edin; isterseniz `;` sonrası deyimleri de tarayın.

### I-6 — `loadEcosystems` ham hata nesnesini logluyor

- **Evidence:** `src/scanner/worker.ts:607`: `this.logger.warn(…, err)`. `pg` hata nesnesi parola içermez, ancak ADR-004 Karar 6'nın "yalnız sınıf/kod" ilkesine aykırı (F1'den kalma satır olabilir).
- **Öneri:** `errorCode(err)` kullanın.

### I-7 — `taskkill /PID` için PID yeniden kullanımı penceresi

- **Evidence:** `src/scanner/workspace.ts:293-299, 341-353`. Zamanlayıcı veya iptal, git çıktıktan sonra ama `close` olayı işlenmeden önce tetiklenirse öldürme isteği yeniden kullanılmış bir PID'e gidebilir. Pencere milisaniyeler düzeyinde.
- **Öneri:** Aksiyon gerekmiyor; isterseniz `child.exitCode !== null` kontrolü ekleyin.

### I-8 — Sıfır genişlikli / biçim karakterleri kalıcı metinlerde korunuyor

- **Evidence:** `src/lib/errorText.ts:135` yalnız C0/C1'i siliyor. `\p{Cf}` (U+200B, U+202E RTL override vb.) `error_message`'a ve log'a geçiyor. Arayüz `textContent` kullandığı için XSS yok. RTL override log/arayüzde metni yanıltıcı gösterebilir.
- **Öneri:** L-1 düzeltmesiyle birlikte `\p{Cf}` (bidi kontrolleri dahil) temizliği.

### I-9 — Ayrıştırma aşamasında dosya sayısı ve ağaç boyutu sınırı yok

- **Evidence:** `src/scanner/parsers/common.ts:384-453`. Milyonlarca dizin/dosya içeren bir repo yürüyüşü uzatır. Bellek 512 MiB heap ile, süre iş sınırıyla sınırlı. Clone boyutu sınırsız (`runner.config.ts:37` `maxRepoSizeMb` tanımlı ama kullanılmıyor); disk doluluğu yalnız 5 dk clone zaman aşımıyla sınırlı.
- **Öneri:** F3'te yürüyüşe girdi sayısı sınırı (ör. 200k) ve `maxRepoSizeMb` için ya uygulama ya da ölü yapılandırmanın silinmesi.

## İncelenmedi / sınırlı incelendi

- **Testler** (`npx vitest run`): Hook tarafından engellendi. Koordinatörün beyanı (beklenen 5 kırmızı: 1 `.env.example`, 3 ANSI, 1 port 0) doğrulanmadı. L-1, L-4 ve I-1 bu kırmızılarla tutarlı.
- **Dinamik doğrulama:** M-1 zamanlaması, `terminate()`'in regex'i kesmesi, derin JSON/TOML'de `RangeError` davranışı ve gerçek clone (ana oturum yaptı) bu oturumda çalıştırılmadı.
- **`git diff` içeriği:** Yalnız `package.json`, `scanController.ts` ve `types/scan.ts` diff'i görüldü. Diğer dosyalar HEAD çalışma ağacında okundu. ADR-004/005 ve REQ-003 tam okunmadı; kod yorumlarındaki karar atıfları ve AC'lerle karşılaştırıldı.
- **İncelenmeyen dosyalar:** `src/reports/reportService.ts` (yalnız L-5 satırları grep ile), `src/analysis/vulnerabilityLookup.ts` diff'i (iptal sinyali eklenmesi), `src/lib/db.ts`, `db/schema.sql`, `db/README.md` (yalnız grep), test yardımcıları.
- **Gizli değer taraması:** Regex tabanlı grep ile yapıldı; gitleaks benzeri bir araç çalıştırılmadı. Snapshot lock dosyaları (`snapshot-73db78b/package-lock.json` vb.) yalnız desen grep'iyle tarandı; `resolved`/`integrity` alanlarında sır beklenmez.
- **Managed run sınırı:** `pwd`/`git rev-parse` engellendi. Konum ve branch, oturum bağlamındaki git durumuna dayanıyor (`req-003-f2-tek-runtime`, kök `<repo>`). Bu rapor dışında hiçbir dosyaya yazılmadı.

## Merge kararı

**Conditional Go — Critical/High yok.**

Merge öncesi **zorunlu**:
1. **L-1:** Arındırıcıda sıranın düzeltilmesi (önce kontrol karakteri temizliği; `\b` → `(?<![A-Za-z0-9])`; `Bearer` için `i` bayrağı) ve AC-T-4'ün 3 kırmızı testinin yeşile dönmesi. ADR-002 Ek E3 sıra maddesi güncellenmeli. Sahibi: backend-engineer + solution-architect.
2. **L-3:** `tests/unit/errorText.test.ts:99-101`'deki gerçek profil adının sahte adla değiştirilmesi. Sahibi: qa-automation.
3. **L-4:** `.env.example`'ın F2'ye göre güncellenmesi (süper kullanıcı yerine `ossrisk`, Docker/Python satırlarının silinmesi). Sahibi: ana oturum.

Merge öncesi **önerilen** (yapılmazsa insan risk kabulü gerekir):
4. **M-1:** `pyStrip`/`pyRstrip`'in doğrusal yeniden yazımı + regresyon testi. Sahibi: backend-engineer (ayrıştırıcı sahibi).
5. **I-1:** `PORT=0` için açık başlangıç hatası (işlevsel kırmızı test).

**İnsan onayı gerektiren riskler:** M-1 kapatılmadan merge edilecekse DoS risk kabulü. L-5 (rapor süpürmesi çitsiz) ve I-4'ün (dev-only `tinypool`/`vitest`) F3'e ertelenmesi.

Fix'ler ilgili implementer'lar tarafından yapılmalı. Security Red Team, L-1 ve M-1 düzeltmelerini merge öncesi yeniden incelemeli.

## Handoff notu

Bu inceleme non-trivial'dır. `docs/handoffs/REQ-003.md` bu rapora atıfla güncellenmeli; merge kararı, zorunlu düzeltmeler ve risk kabulleri (M-1, L-5, I-4) yazılmalı. F1'den devreden N-1, L-4 (F1), L-5 (F1) ve D-24'ün kapandığı da `docs/handoffs/REQ-002.md`'deki açık maddelere işlenmeli. Security Red Team handoff'u kendisi güncellemez; Delivery Lead / Integration-Release'e bildirilmiştir.

## Yeniden doğrulama (2026-10-10)

- Kapsam: `d6fbb84` (vitest 4.1.11), `f32b00c` (M-1, L-1, L-2, L-5, I-1, I-3, I-6), `71e70b7` (ADR-002 E3, ADR-004, ADR-005), `ec21693` (QA regresyon testleri + L-3), `88857dc` (L-1 kalıntısı: `[REDACTED]`'e yapışık token karakterleri). İncelenen aralık: `git diff d2f1dfb..HEAD` (30 dosya).
- Yöntem: Read/Grep ile kod ve test incelemesi. Ek olarak `git log`, `git diff d2f1dfb..HEAD` (kaynak dosyalar) ve `npm audit` çalıştırıldı. `npx vitest run` ve `node -e` bu oturumda da rol hook'u tarafından engellendi. Test sonucu (698 test: 695 geçti, 2 atlandı, 1 beklenen kırmızı) koordinatörün beyanıdır; doğrulanmadı.
- Kişisel veri düzeltmesi: Bu raporun önceki sürümünde geçen gerçek profil adı, makine adı ve yerel kök yolu sahte değerlerle (`qa-user`, `QA-PC`, `<repo>`) değiştirildi.

### Bulgu durumları

| Bulgu | Durum | Kanıt ve gerekçe |
| --- | --- | --- |
| M-1 | **Kapandı** | `pyStrip`/`pyRstrip` artık regex kullanmıyor; iki uçtan indeks taraması yapıyor. Her karakter en fazla bir kez inceleniyor, yani doğrusal (`src/scanner/parsers/common.ts:99-136`). `isPyWhitespace` kümesi eski `PY_WS` sınıfıyla birebir aynı ve BMP'nin tamamında test ediliyor. Taramadan ayrıca çıkan bulgu: `REQUIREMENT_RE` içinde `\n` bulunan TOML metinlerinde kübik geri izleme vardı. Bu da `matchRequirementLine` ile doğrusal bir taramaya çevrildi (`common.ts:168-197`, `python.ts:205`). Köşeli parantez döngüsünde her `]` sonrası boşluk taraması bir sonraki boşluk olmayan karaktere kadar gidiyor; ardışık taramalar örtüşmüyor, toplam doğrusal. Kalan `EXACT_PIN_RE`/`BARE_VERSION_RE`: `^` ile çapalı ve her `[WS]*` `PY_WS`'ten ayrık bir sınıfla komşu; doğrusal (önceki değerlendirmeyle aynı). `nodejs.ts` `EXACT_VERSION_RE` de çapalı ve doğrusal. Aynı tarama sırasında `redact.ts`'teki `CREDENTIAL_URL_RE` sınırsız şema tekrarı da sınırlandı (`{0,31}`) ve `\b` kaldırıldı (`src/lib/redact.ts:19-23`). Testler: `tests/unit/parserLinear.test.ts` (eski regex ile 20 000 + 30 000 + 10 000 rastgele girdide eşdeğerlik; 1–2 MB boşluk dizili `requirements.txt`, `yarn.lock`, `package.json`, `pyproject.toml` < 1 sn). |
| L-1 | **Kapandı** | Yeni sıra: ham metinde ön maskeleme → kontrol/biçim karakteri temizliği → tekrar maskeleme → kesim (`src/lib/errorText.ts:279-285`). `stripControl` tek geçişli; tüm 7/8-bit CSI, OSC/DCS/SOS/PM/APC ve iki karakterli ESC dizileri ile `\p{Cf}` siliniyor (`errorText.ts:184, 216-269`). Sonlanmamış dizi taraması `noEnd` belleğiyle doğrusal; zaman testleri 100–200 bin introducer içeriyor (`errorText.test.ts:261-274`). `\b` yerine `TOKEN_START` kullanılıyor: önünde harf/rakam olmayan konum, `%XX` sonrası ve CSI parametreleri sonrası (`errorText.ts:80-90`). Lookbehind uzunluğu sınırlı (`{0,16}`). `Authorization`/`Bearer`/`Basic` desenleri büyük/küçük harfe duyarsız. `REDACTED_TAIL_RE` placeholder'a yapışık token karakterlerini yutuyor (`errorText.ts:99, 111`); bu ifade belirsiz değil, doğrusal. Saldırgan gözüyle denediğim yollar: (a) kısa ilk parçalı `\r` bölmesi; (b) ilk parçası ≥ 20 karakterlik bölme; (c) `context.secrets` token'ının `\x00` ile bölünmesi; (d) CSI son baytının token'ın veya sürücü harfinin ilk karakterini yemesi (`ESC[1C:\…`, `ESC[ghp_…`); (e) `%3Aghp_`, `_ghp_`; (f) U+200B/U+2060/U+FEFF/U+202E; (g) OSC 8 bağlantısındaki kimlik bilgisi; (h) 8-bit CSI. Hepsi kod yolunda kapanıyor ve (a)–(h) için test var (`errorText.test.ts:186-257`). Backend'in 7 ayıraç × 12 sır türü matrisi bu testlerle tutarlı. **Kalan (Info, teorik):** Aynı sır hem bir kontrol karakteriyle bölünür hem ilk karakterleri bir CSI son/parametre baytı olarak yenirse ve sır bilinen bir token biçiminde değilse (ör. Azure DevOps PAT), parçası kalabilir. Bunun için çıktıyı üreten tarafın işin token'ını bilmesi ve bu biçimde yankılaması gerekir; git token'ı yankılamaz. Kategori Cf olmayan görünmez karakterlerle (U+034F, U+115F, U+3164, U+2800) bölünen desen token'ları da maskelenmez; bunu yalnız düşmanca bir kaynak üretebilir, o da işin token'ına sahip değildir. Aksiyon gerekmiyor. |
| L-2 | **Kapandı** | Link hedefi hiç çözülmüyor. `lstat` link derse karar yalnız ada göre veriliyor: manifest adı → ekosistem kaydı, `SKIP_DIRS` adı → sessiz atlama, diğer her ad → bir `filesystem` kaydı (`src/scanner/parsers/common.ts:509-527`). `realpath` ikinci savunması yalnız `lstat`'in normal dosya dediği girdilerde çalışıyor (`common.ts:536-544`). Test: `fs.statSync`/`realpathSync(.native)` çağrılarının hiçbir link yolu için yapılmadığı spy ile doğrulanıyor; pozitif kontrol olarak `lstat` çağrısı da kontrol ediliyor (`tests/unit/parsersDeviations.test.ts:262-311`). Dosya symlink'i gerektiren 2 test Windows'ta yetki yokken atlanıyor; junction testleri yetki istemiyor ve çalışıyor. **ADR-005 Karar 6 sapması** (ilgisiz adlı dosya bağlantısı artık sessizce atlanmıyor, `filesystem` kaydı üretiyor) ADR-005'te kayıtlı (satır 273-287, 469-472). **Kabul edilebilir:** Fazladan bir uyarı satırı üretiyor, veri veya yetki etkisi yok. Hedefi çözmeden dosya/dizin ayrımı yapılamayacağı için güvenlik açısından doğru taraf seçilmiş (fail-safe). Kayıt metni yol içermiyor, yalnız göreli yol var. |
| L-3 | **Kapandı** | `tests/` altında gerçek profil adı geçmiyor (büyük/küçük harfe duyarsız grep). Sınır vakaları `qa-user`/`qa-userr` ile yazılmış (`tests/unit/errorText.test.ts:96-101`). |
| L-4 | **Kısmen açık** | `.gitignore` artık `.env.*` + `!.env.example` içeriyor (`.gitignore:7-9`); F1 L-7 kapandı. `.env.example` henüz güncellenmedi (beklenen 1 kırmızı test). Hedef içerikte `PYTHON_BIN`, `POSTGRES_*` ve docker yorumu yok; bu yeterli. **`postgres` mi `ossrisk` mi kararı:** README rol oluşturmayı açıkça anlatıyor (`README.md:56-61`: `CREATE USER ossrisk …; CREATE DATABASE ossrisk OWNER ossrisk;`) ve örnek bağlantıyı `postgres://ossrisk@localhost:5432/ossrisk` olarak veriyor (`README.md:76`). `.env.example`'da `postgres://postgres@localhost:5432/oss_risk` kalırsa iki doküman çelişir; README'yi izleyen kullanıcı değeri değiştirmek zorunda kalır, `.env.example`'ı izleyen kullanıcı ise uygulamayı süper kullanıcıyla çalıştırır. **Karar:** Güvenlik kısmı **Low olarak açık kalır**; merge'ü engellemez. `.env.example`'daki değerin `postgres://ossrisk@localhost:5432/ossrisk` olması önerilir (aynı tek komutla kopyalanacak içerikte tek satır farkı). `postgres` kalacaksa README ile çelişkinin ve süper kullanıcı riskinin insan tarafından kabulü handoff'a yazılmalı. Merge koşulu: `.env.example`'ın Docker/Python satırlarından arındırılması (kırmızı testin yeşile dönmesi). |
| L-5 | **Kapandı** (kapsamı içinde) | `lock-lost` kapanışında rapor süpürmesi atlanıyor (`src/runtime.ts:472-485`); tarama süpürmesi run id ile çitli kalıyor. Rapor zaman sınırı artık `processReport`'u `AbortSignal` ile durduruyor: adımlar arası kontrol var, sinyal sonrası dosya yazılmıyor ve `ready` set edilmiyor (`src/reports/reportService.ts:158-187`, `src/reports/worker.ts:219-234`). Testler: `tests/integration/runtime.test.ts:767-850`, `tests/integration/reportTimeout.test.ts:77-113`. Kalan: Son `throwIfAborted` ile `UPDATE … ready` arasında milisaniyelik bir yarış penceresi var (Info). Rapor satırında sahiplik yok (F3, şema değişikliği). `recoverOrphanedReports` başlangıçta çitsiz, ama tek örnek kilidi altında çalışıyor. |
| I-1 | **Kapandı** | `PORT` başlangıçta 1–65535 tam sayısı olarak doğrulanıyor; değer mesaja yazılmıyor (`src/config/env.ts:31-58`, `src/runtime.ts:191-199`). Enjekte edilen `port: 0` için izin listesi socket'in **gerçek** portundan, `listening` geri çağrısında ve bağlantı kabulünden önce kuruluyor (`src/app.ts:131-145`). İstekten gelen hiçbir değer kullanılmıyor; DNS rebinding savunması korunuyor. Handler bağlanmadan bir istek gelseydi bile yanıtlanmazdı (fail-closed). Testler: `tests/unit/settingsBounds.test.ts:172-190`, `tests/integration/runtime.test.ts:529-583`. |
| I-3 | **Kapandı** | `boundedNumber` ile `scan.max_retries` 1–10, `scan.timeout_minutes` (0, 1440], ortam değişkenleri `SCAN_TIMEOUT_MS`, `SCAN_CLONE_TIMEOUT_MS`, `SCAN_MAX_RETRIES`, `WORKER_MAX_CONCURRENT`, `WORKER_POLL_INTERVAL_MS` sınırlı. Aralık dışı değerde varsayılana düşülüyor ve değeri değil yalnız adı yazan bir uyarı veriliyor (`src/lib/bounds.ts`, `src/scanner/retryPolicy.ts:131-166`, `src/scanner/sandbox/runner.config.ts:15-26, 126-175`, `src/scanner/workspace.ts:281-286`). En büyük türetilmiş zamanlayıcı 24 saat, `setTimeout` sınırının altında. Deneme hakkı biten `pending`/`queued` satırlar claim transaction'ında `failed` + `scan_failed` oluyor (`src/scanner/worker.ts:439-461, 469`); tek örnek kilidi altında ve `SKIP LOCKED`. `bounds.ts`'in import'u yok; ayrıştırıcı sınır kuralı (ADR-005 Karar 1) bozulmuyor. Test: `tests/unit/settingsBounds.test.ts`, `tests/integration/scanRetry.test.ts`. |
| I-4 | **Kapandı** | `vitest`/`@vitest/mocker` 4.1.11; lock'ta `tinypool` artık yok (`package-lock.json:35, 1674-1675, 5962-5963`). `npm audit` (tüm bağımlılıklar) → `found 0 vulnerabilities` (bu oturumda çalıştırıldı). |
| I-6 | **Kapandı** | `loadEcosystems` yalnız `errorCode(err)` logluyor (`src/scanner/worker.ts:648`). |
| I-8 | **Kapandı** | `\p{Cf}` (bidi override dahil) L-1 düzeltmesiyle siliniyor (`errorText.ts:184, 217`). |
| I-2 | **Ertelendi — F3 / insan risk kabulü** | `worker_id` API'de `hostname:pid:…` döndürüyor; kaldırılması contract değişikliği (D-43). Tek kullanıcı modelinde düşük. |
| I-5 | **Ertelendi — F3 / insan risk kabulü** | Göç dosyası transaction lint'i satır başı tabanlı; dosyalar güvenilir girdi. |
| I-7 | **Ertelendi — F3 / insan risk kabulü** | `taskkill` PID yeniden kullanımı penceresi (milisaniyeler). |
| I-9 | **Ertelendi — F3 / insan risk kabulü** | Ağaç girdi sayısı sınırı yok; `maxRepoSizeMb` kullanılmıyor. Süre ve heap sınırlarıyla kendini sınırlıyor. |

### Yeni bulgular

#### R-1 — `.devflow/project.json` gerçek profil adını içeren mutlak yollar barındırıyor (repo public)

- **Severity:** Low (gizlilik; izlenme durumu doğrulanmadı)
- **Evidence:** `.devflow/project.json:7-8` (`target_project_path`, `framework_repo_path`): kullanıcı profil klasörünü içeren mutlak Windows yolları. Bu raporda değerler tekrar edilmiyor. `.gitignore` yalnız `.devflow/cache/` ve `.devflow/logs/`'u kapsıyor (`.gitignore:1-2`). Oturum başındaki git durumunda dosya izlenmeyenler arasında görünmüyordu, bu yüzden büyük olasılıkla izleniyor. `git ls-files` bu oturumda engellendiği için doğrulanamadı.
- **Attack path:** Public repoda kullanıcının Windows profil adı ve klasör düzeni ifşa oluyor. `.claude/rules/target-project-boundaries.md` `.devflow/` içinde kişisel veri olmamasını istiyor.
- **Remediation requirement:** Dosya izleniyorsa ana oturum yolları göreli veya yer tutucu değerlerle değiştirmeli ya da dosyayı `.gitignore`'a alıp izlemeden çıkarmalı. Geçmişte de varsa ve repo public ise geçmişin temizlenmesi insan kararıdır (D-2: geçmişteki sırlar kapsam dışı; bu bir sır değil, kişisel veri). REQ-003 kod değişikliğinin merge'ünü teknik olarak engellemez; insan kararı gerekir.

### Merge kararı (yeniden doğrulama sonrası)

**Conditional Go.** Critical, High veya Medium açık bulgu yok. M-1, L-1, L-2, L-3, L-5, I-1, I-3, I-4, I-6 ve I-8 kapandı.

Kalan koşullar:
1. **L-4 (merge koşulu):** `.env.example` ana oturumda güncellenmeli (Docker/Python satırları yok) ve beklenen tek kırmızı test yeşile dönmeli. Önerilen `DATABASE_URL`: `postgres://ossrisk@localhost:5432/ossrisk`. `postgres` kalırsa L-4'ün süper kullanıcı kısmı Low olarak açık kalır ve risk kabulü handoff'a yazılır.
2. **R-1 ve geçmiş (insan kararı):** `.devflow/project.json`'daki kişisel yol. Dosyanın izlenip izlenmediği doğrulanmalı; izleniyorsa merge'den önce temizlenmesi önerilir. Ayrıca gerçek profil adı bu dalın **commit geçmişinde** hâlâ duruyor: L-3 öncesi test dosyası commit'leri ve bu raporun ilk sürümünü içeren `d2f1dfb`. Dal public bir remote'a gönderildiyse veya main'e normal merge ile girecekse geçmiş de yayımlanır. Squash merge veya dal geçmişinin yeniden yazılması insan kararıdır (force push onay gerektirir).
3. Test sonuçları (698 / 695 geçti / 2 atlandı / 1 beklenen kırmızı) Integration-Release tarafından kanıt olarak eklenmeli; bu oturumda çalıştırılamadı.

**İnsan risk kabulü / F3'e ertelenenler:** I-2 (`worker_id`'de makine adı; contract değişikliği), I-5, I-7, I-9; L-5 kalıntısı (rapor sahipliği, şema değişikliği); L-1'in teorik kalıntısı (Info).

`docs/handoffs/REQ-003.md` bu bölüme atıfla güncellenmeli. Security Red Team handoff'u kendisi güncellemez; Delivery Lead / Integration-Release'e bildirilir.
