# ADR-002: Docker'sız tarama çalışma alanı ve izinli kök dizinler (SCAN_ROOTS)

- **ADR-ID:** ADR-002
- **Durum:** Accepted
- **Tarih:** 2026-10-09 (taslak) · 2026-10-09 (karar)
- **İlgili:** REQ-002 / P-03 (AC-P03-1…6), P-04 (AC-P04-1…6), P-09 (AC-P09-5, D-14); rapor kararları K-4, K-3

## Bağlam

`src/scanner/worker.ts` `docker info` başarılı olursa Docker konteynerinde, değilse
yerel Python ayrıştırıcıyla tarıyor. Yerel yolda `workDir = localPathExists ? repoUrl : '.'`
olduğu için uzak repo verildiğinde ve Docker yoksa **platformun kendi klasörü**
taranıp sonuç hedef projeye yazılıyor (kritik hata). Yerel yol algılaması yalnız
`/` ve `.` önekine bakıyor (Windows sürücü yollarını tanımıyor) ve hiçbir kök
sınırı yok. K-4: Docker yok, tek makine. Özel repo token'ı `integrations.access_token_enc`
içinde (AES-256-GCM; tampon düzeni `IV(12) | tag(16) | ciphertext`). `decryptToken`
üç durumda tamponu olduğu gibi metne çevirip **düz metin olarak döndürüyor**:
(a) `ENCRYPTION_KEY` tanımsız, (b) şifre çözme başarısız (`catch` dalı),
(c) tampon 28 bayttan kısa. Python ayrıştırıcıları F1'de yerinde kalır (TS taşıma
F2/P-10).

## Karar

### 1. Docker yolu ve `'.'` geri dönüşü kaldırılır (AC-P03-1/2)

`dockerAvailable()`, Docker `spawn`/`docker kill`/`docker volume rm` kodu,
`buildDockerRunFlags` ve `runner.config.ts` içindeki `container` bölümü silinir
(`scan`, `retry`, `cleanup`, `worker` ayarları kalır). Tek yürütme yolu: kaynak
çözümle → çalışma klasörü → Python ayrıştırıcı → sonuç yaz. Kaynak
çözümlenemezse tarama `failed`; **hiçbir koşulda başka klasöre düşülmez**.

### 2. Kaynak sınıflandırma

`repo_url` (proje veya entegrasyon) şu kurallarla sınıflandırılır; eşleşmeyen
her biçim reddedilir (kayıtta `400`, worker'da `failed`):

- **Uzak:** yalnız `https://` (F1; **SSH ile clone kapalıdır** — kullanıcı kararı
  2026-10-09). `http://`, `file://`, `ssh://`, scp biçimi `git@host:…`,
  `ext::`/`fd::` gibi `::` taşıma sözdizimi ve `-` ile başlayan değerler
  reddedilir. `new URL()` ile ayrıştırılır; kullanıcı bilgisi
  (`https://user:token@…`) içeren URL reddedilir (token yalnız entegrasyon
  kaydından gelir).
- **Yerel:** mutlak Windows yolu (`path.win32.isAbsolute`, sürücü harfli). Göreli
  yollar (`.`, `./x`), UNC (`\\sunucu\paylaşım`) ve aygıt yolları (`\\?\`, `\\.\`)
  reddedilir.

### 3. Uzak repo: geçici klasöre sığ clone (AC-P03-3/4/5)

- Klasör: `fs.mkdtemp(path.join(os.tmpdir(), 'ossrisk-scan-'))`, clone hedefi
  `<tmp>/repo`.
- Komut: `child_process.spawn('git', args, { shell: false })`, argüman dizisi:
  `-c core.symlinks=false -c core.longpaths=true -c credential.helper=
  clone --depth 1 --single-branch --no-tags [--branch <ref>] -- <url> <hedef>`.
  `--` seçenek enjeksiyonunu keser; `ref` `^[A-Za-z0-9._/-]+$` ile doğrulanır ve
  `-` ile başlayamaz. `core.symlinks=false` repodaki sembolik bağlantıların
  çalışma alanı dışına işaret etmesini engeller.
- Ortam: `GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never` (Windows Git Credential
  Manager'ın GUI açıp zaman aşımına kadar asılmasını önler),
  `GIT_ALLOW_PROTOCOL=https` (alt modül dahil taşıma kısıtı).
- **Token:** URL'ye veya komut satırına konmaz (süreç listesi, git hata mesajı ve
  `.git/config` sızıntısı). Git'in ortam tabanlı yapılandırmasıyla verilir:
  `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=http.extraHeader`,
  `GIT_CONFIG_VALUE_0=Authorization: Basic <base64(kullanıcı:token)>` (git ≥ 2.31;
  kullanıcı adı sağlayıcıya göre — GitHub `x-access-token`, GitLab `oauth2`,
  Azure DevOps boş). Yakalanan stderr hem ham token hem base64 biçimi için
  `scrubLogs` ile maskelenir; hata mesajı en fazla ~1 KB tutulur.
- **Zaman aşımı:** ayrı clone süresi (`SCAN_CLONE_TIMEOUT_MS`, öneri 5 dk), genel
  tarama süresinin içinde. Windows'ta `child.kill()` alt süreçleri
  (`git-remote-https.exe`) öldürmez ve dosya kilitleri temizliği bozar; zaman
  aşımında `taskkill /PID <pid> /T /F` (argüman dizisiyle, shell yok) çalıştırılır
  ve `close` olayı beklenir.
- **Temizlik:** clone + ayrıştırma `try/finally` içinde; `finally`'de
  `fs.rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })`.
  Windows'ta `.git/objects/pack/*` salt-okunur ve antivirüs/indeksleyici geçici
  `EBUSY/EPERM` üretebilir: `EPERM`'de dosyalar `chmod 0o666` ile yazılabilir
  yapılıp yeniden denenir. Temizlik yine başarısızsa uyarı log'lanır (tarama
  sonucu değişmez) ve worker açılışında `os.tmpdir()` altındaki
  `ossrisk-scan-*` artıkları (ör. 24 saatten eski) süpürülür.
- **Hata:** clone başarısızsa tarama `failed`, `error_message` maskeli git
  hatası; `saveScanResults` çağrılmaz, paket/bulgu yazılmaz. Doğrulama hataları
  (geçersiz URL/yol) yeniden denenmez; ağ hataları mevcut retry politikasına
  tabidir.

### 4. Yerel klasör: SCAN_ROOTS (AC-P04-1…6)

- `SCAN_ROOTS`: `path.delimiter` ile ayrılmış liste (Windows'ta `;` — `:` sürücü
  harfiyle çakışır). Her kök mutlak olmalı ve var olmalı; başlangıçta
  `fs.promises.realpath.native` ile kanonik hale getirilir. Geçersiz kök →
  başlangıçta açık hata. **Tanımsız/boş → hiçbir yerel yol taranamaz.**
- Aday yol kontrolü: mutlak yol şartı → `realpath.native` (`..`, sembolik bağlantı,
  junction, `subst`, 8.3 kısa ad çözülür; yol yoksa ret) → dizin mi → Windows'ta
  her iki taraf küçük harfe çevrilerek `aday === kök` veya
  `aday.startsWith(kök + path.sep)` (kök zaten ayraçla bitiyorsa, ör. `C:\`,
  tekrar eklenmez). Önek+ayraç kuralı `C:\kok\a` kökünün `C:\kok\ab`'yi kabul
  etmesini engeller.
- Kontrol **iki kez** yapılır: proje/entegrasyon kaydı ve tarama isteğinde
  (`repo_url` dahil, AC-P04-5 → `400`, kuyruğa alınmaz) ve worker tarama
  başlarken (TOCTOU; ret → `failed`). Ayrıştırıcıya kullanıcı girdisi değil,
  doğrulanmış kanonik yol `--work-dir` olarak verilir.

### 5. Python ayrıştırıcı çağrısı (F1 ara durum)

`spawn(PYTHON_BIN, args, { shell: false })`; `PYTHON_BIN` env ile ayarlanır
(varsayılan Windows'ta `python`, diğerlerinde `python3`). Davranış F2'de TS
taşımasıyla (P-10, K-3) kalkar.

### 6. Token çözme: düz metin geri dönüşü yok (AC-P09-5, REQ-002 D-14)

- `decryptToken` (`src/scanner/worker.ts`) token'ı **hiçbir durumda düz metin geri
  dönüşüyle** (tamponun olduğu gibi metne çevrilmesiyle) döndürmez. Çözülecek bir
  token varken (boş olmayan `access_token_enc`) şu üç durumun **her birinde hata
  fırlatır**:
  - (a) `ENCRYPTION_KEY` tanımsız (veya boş);
  - (b) şifre çözme başarısız — `catch` dalı (yanlış anahtar, bozulmuş/değiştirilmiş
    veri, GCM doğrulama etiketi tutmuyor);
  - (c) tampon 28 bayttan kısa (IV + doğrulama etiketi için yetersiz; ör. daha önce
    şifresiz saklanmış bir token).
- **Sonuç her üç durumda aynıdır:** tarama `failed` olur; token çözme clone'dan
  **önce** yapılır, bu yüzden geçici klasör açılmaz ve `cloneRepo` çağrılmaz;
  `saveScanResults` çağrılmaz. Hata deterministik olduğu için yeniden denenmez
  (doğrulama hataları gibi).
- **Sızıntı yok:** hata mesajı, `scans.error_message` ve log çıktısı token değerini,
  tamponun metin/hex/base64 karşılığını veya ham kripto istisnasının ayrıntısını
  içermez; yalnız sabit, durum belirten bir mesaj kullanılır (ör. "entegrasyon
  token'ı çözülemedi: şifreleme anahtarı tanımsız" / "doğrulama başarısız" /
  "geçersiz şifreli veri"). Entegrasyon kimliği gibi gizli olmayan bağlam eklenebilir.
- **Token yoksa** (`access_token_enc` NULL veya boş) `decryptToken` hata fırlatmaz;
  tarama token'sız devam eder (genel https repoları için).
- Daha önce şifresiz saklanmış token'lar bu değişiklikten sonra kullanılamaz ((c)
  veya (b) ile `failed`); yerel kurulum sıfırdan başladığı için kabul edilen
  sonuçtur. Böyle bir kayıt varsa token yeniden girilmelidir.

## Gerekçe

Docker'ın kalkmasıyla izolasyon katmanı kalmıyor; bu yüzden güvenlik, girdi
sınıflandırması (izin listesi), shell'siz argüman dizisi, ortam üzerinden sır
iletimi ve kanonik yol karşılaştırmasıyla sağlanır. Tümü Node yerleşikleri
(`fs`, `os`, `path`, `child_process`) ve sistemdeki `git` ile yapılır; yeni paket
gerekmez.

## Değerlendirilen alternatifler

- **Docker yolunu isteğe bağlı bırakmak:** K-4 ile çelişir, iki yol bakım yükü.
  Reddedildi.
- **`isomorphic-git` / `simple-git`:** Yeni bağımlılık; `simple-git` yine `git`
  çağırır. Reddedildi.
- **Token'ı URL'ye gömmek:** Süreç listesi, hata mesajı ve `.git/config`
  sızıntısı. Reddedildi.
- **`path.resolve` + önek kontrolü (realpath olmadan):** junction/symlink ile kaçış
  açık kalır (AC-P04-4). Reddedildi.
- **SSH (`ssh://`, scp biçimi `git@…`) desteği:** Kullanıcının tüm SSH
  anahtarlarına (ve ssh-agent'a) örtük erişim, host key istemi ile asılma riski,
  `GIT_SSH_COMMAND` ile ek saldırı yüzeyi. Özel repolar entegrasyon token'ı ile
  https üzerinden zaten taranabildiği için kazanç sınırlı. **Reddedildi** (F1;
  yeniden değerlendirme ayrı bir ADR gerektirir).

## Sonuçlar / Uygulama etkisi

- **Güvenlik:** Platform klasörünün taranması ve kök dışı okuma kapanır. Kalan risk:
  izinli kök içindeki bir dosya sembolik bağlantıysa Python ayrıştırıcı onu
  izleyebilir — ayrıştırıcının bağlantı olan dosyaları atlaması (`lstat`) önerilir.
  `decryptToken`'ın üç düz metin geri dönüşü ((a) anahtar tanımsız, (b) şifre
  çözme başarısız, (c) tampon < 28 bayt) karar 6 ile kapanır: şifreli alan artık
  sessizce düz metin token kaynağı olarak kullanılamaz ve bozuk/yanlış anahtarlı
  veri clone'a sızmaz. Geçici klasör kullanıcının `%TEMP%`'inde olduğundan diğer
  kullanıcılara kapalıdır.
- **Test (AC-P03-6, AC-G-4):** clone işlemi enjekte edilebilir bir arayüz
  (`cloneRepo(url, ref, dest, token)`) arkasına alınır; testlerde taklit edilir
  (internetsiz). Senaryolar: clone hatası → `failed`, platformun kendi
  `package.json` bağımlılıkları hedef projeye yazılmaz; başarı ve hata sonrası
  geçici klasör yok; argüman dizisinde `--` ve token yok; URL izin listesi tablosu
  (`ext::`, `-u…`, `file://`, kullanıcı bilgili URL). SCAN_ROOTS: geçici dizinlerle
  kök içi kabul, kök dışı `400`, `..`, büyük/küçük harf varyantı, önek tuzağı,
  **junction** (`fs.symlink(hedef, yol, 'junction')` Windows'ta yönetici
  gerektirmez), tanımsız `SCAN_ROOTS` → ret. Token çözme (AC-P09-5): (a)
  `ENCRYPTION_KEY` tanımsız, (b) farklı anahtarla şifrelenmiş veya içeriği
  değiştirilmiş ≥ 28 baytlık tampon, (c) < 28 baytlık tampon — her birinde
  `decryptToken` hata fırlatır, tamponun metin karşılığını döndürmez, tarama
  `failed`, `cloneRepo` taklidi çağrılmaz, hata mesajı/log token değerini içermez;
  `access_token_enc` boşken hata yok ve tarama token'sız sürer.
- **Migration:** Bu ADR şema değişikliği gerektirmez. Yeni env değişkenleri
  `.env.example`'a eklenir: `SCAN_ROOTS`, `SCAN_CLONE_TIMEOUT_MS`, `PYTHON_BIN`
  (P-09 ile birlikte). Bu ADR'nin zorunlu kıldığı Git for Windows kurulumu, F1
  migration'larının çalıştırıldığı Git Bash'i de sağlar (yöntem: ADR-003 (d)).
- **Contract:** P-04 hata kodu adları (`path_not_allowed`, `repo_url_not_allowed`)
  ve `ssh://`/scp biçimli URL'lerin `400` ile reddi contract'ta yer almalıdır.

## Kanıt (Evidence)

- Repo incelemesi: `src/scanner/worker.ts` (`dockerAvailable`, `'.'` geri dönüşü,
  yerel yol algılaması), `runner.config.ts`, `integrations.access_token_enc`,
  `decryptToken` (anahtar tanımsızken, tampon 28 bayttan kısayken ve `catch`
  dalında `encryptedBuffer.toString('utf8')` döndürüyor).
- REQ-002 D-14 (kullanıcı kararı 2026-10-09) ve AC-P09-5.
- Dış kaynak: git belgeleri (`GIT_CONFIG_COUNT`, `GIT_ALLOW_PROTOCOL`,
  `http.extraHeader`) ve Node `fs.realpath.native` davranışı — genel bilgi,
  doğrulanması önerilir. NotebookLM veya Obsidian kaynağı kullanılmadı.

## İlgili REQ / AC

REQ-002: AC-P03-1…6, AC-P04-1…6, AC-P09-2/3/5, AC-G-3/4; karar kaydı D-14.

## Kalan notlar (karar gerektirmeyen)

1. **Python yürütücüsü (Windows):** `python3` çoğu Windows kurulumunda yoktur veya
   Microsoft Store takma adı (`WindowsApps\python3.exe`) Store'u açıp hata koduyla
   döner; `py` başlatıcısı ayrı argüman (`-3`) ister. Uygulama: `PYTHON_BIN` env +
   başlangıçta `--version` sınaması ve anlaşılır hata. Kalıcı çözüm F2/P-10.
2. Repo boyutu sınırı (`maxRepoSizeMb`) git tarafında güvenilir uygulanamıyor;
   F1'de yalnız zaman aşımıyla sınırlanır.
3. `git` sistemde (Git for Windows) kurulu ve PATH'te olmalı — kurulum ana oturum/
   kullanıcı işidir; başlangıçta `git --version` kontrolü önerilir.
4. Security Red Team review'u implementation sonrası, release öncesi önerilir;
   implementation tamamlandığında `docs/handoffs/REQ-002.md` güncellenmelidir.

## Onay (Approval)

- **Karar sahibi:** proje sahibi (kullanıcı). İnsan kararları **2026-10-09**
  tarihinde verildi: SSH ile clone "kapalı, yalnız https"; `decryptToken` düz metin
  geri dönüşlerinin üç durumda da hataya çevrilmesi (REQ-002 D-14, karar 6).
  Durum `Accepted`.
  Kararlar ana oturum aracılığıyla iletilmiştir; kullanıcının bu dosyayı gözden
  geçirip commit etmesi kaydı kesinleştirir.
- Bu karar **güvenlik sınırını** değiştirir (izolasyon katmanı kalkar, dosya sistemi
  erişim sınırı SCAN_ROOTS'a taşınır). Implementation öncesi ayrıca gereken kapılar:
  ilgili contract onayı ve `docs/ownership/REQ-002.json` `status: approved`.
