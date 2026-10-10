# ADR-006: Kayıt defteri lisans zenginleştirmesi, kalıcı önbellek, arşiv işleme ve NOTICE

- **ADR-ID:** ADR-006
- **Durum:** Accepted
- **Tarih:** 2026-10-10 (taslak ve karar)
- **İlgili:** REQ-004 / P-14, P-15, P-16, L-6 (56 AC); kararlar D-53…D-79
  (özellikle D-57, D-58, D-59, D-60, D-62, D-64, D-65, D-66, D-76, D-79).
  ADR-002 Ek E3 (metin arındırma), ADR-003 (c) (lisans parmak izi), ADR-004
  Karar 7–8 (iş iptali, hata sınıfları), ADR-005 Karar 1 ve 5 (iş parçacığı
  yalıtımı) bu ADR'nin dayanaklarıdır. ADR-005 Karar 1'deki sınır kuralı ve
  REQ-003 D-46'daki Node alt sürümü bu ADR ile kısmen superseded (bkz. Karar 16).

## Bağlam

Repo üzerinde doğrulanan durum (`f7727f6`, branch `req-004-f3-lisans-notice`):

- `src/scanner/worker.ts` `processJob`: kaynak çözümü → ayrıştırıcı iş
  parçacığı (`runParser(…, signal)`) → `persistResults`. `persistResults`
  önce OSV aramasını (`vulnerabilityLookupService.lookupDependencies(deps,
  signal)`) transaction dışında yapar, sonra tek bir `BEGIN … COMMIT` içinde
  `packages`, `scan_dependencies`, bulgular ve `scan_files`'ı yazar. Çit:
  `status = 'running' AND worker_id = $runId FOR UPDATE` (ADR-004 Karar 4).
  Her bağımlılık döngüsü başında `signal.throwIfAborted()` çağrılır.
- İş başına bir `AbortController` vardır (`registerJob`); süre sınırı
  `scan.timeout_minutes` ile `setTimeout`, kapanışta `abort('shutdown')`
  (ADR-004 Karar 7).
- Lisans yalnızca bulgu açılırken `license_findings`'e yazılır;
  `normalizeLicense` doğrudan lock lisansı (`dep.licenses`) ile çağrılır. Her
  lock lisans öğesi ayrı değerlendirilir; parmak izi
  `computeFindingFingerprint({ …, findingType: 'license', normalizedLicense })`
  (ADR-003 c).
- `src/scanner/parsers/threadParser.ts`: tarama başına bir `Worker`,
  `resourceLimits`, `env: {}` (kaynak modunda yalnız
  `DISABLE_V8_COMPILE_CACHE=1`), boş `argv`/`execArgv`, kaynak modunda
  `ts-node` bootstrap'ı (`eval: true`), iptalde `terminate()` beklenir,
  `ERR_WORKER_OUT_OF_MEMORY` ayrı sınıflandırılır.
- `src/analysis/vulnerabilityLookup.ts`: yerleşik `fetch`, istek başına
  `AbortController` zaman aşımı + iş sinyali `AbortSignal.any`, kendi
  `runWithConcurrency` yardımcısı. Vekil, izin listesi ve boyut sınırı yoktur
  (F4 kapsamı, bu ADR değiştirmez).
- `src/lib/bounds.ts` `boundedNumber` (I-3 aralık kuralları, yalnız ayar adı
  loglanır); `src/lib/errorText.ts` `stripControl`, `truncateCodePoints`,
  `sanitizeErrorText` (ADR-002 Ek E3).
- `db/migrations/`: son göç `005`. `packages` tablosunda `copyright_text`,
  `notice_text`, `metadata`, `enriched_at` kolonları `001`'den beri var, hiç
  doldurulmuyor. `packages.version` NOT NULL tanımlı ama sürümsüz satırlar
  `003` sonrası kısmi indeksle taşınıyor; satırlar tarama transaction'ında
  yazılıyor.
- `src/reports/reportService.ts`: `Dependencies` sayfasında lisans sütunu yok;
  hücreler düz metin olarak yazılıyor (formül kalkanı yok).
- `package.json`: `engines.node >=22`, yeni runtime bağımlılıkları yalnız
  `smol-toml@1.9.0` (ADR-005); `@types/node ^20`. Kurulu Node v26.8.1.
- `tests/fixtures/.gitattributes`: `* -text` (ikili fixture'lar için hazır).
  `vitest.config.ts`'te `setupFiles` yok.

## Karar

### 1. Modül yapısı ve sınır kuralı (D-76)

Yeni klasör `src/enrichment/` (backend-engineer):

| Dosya | İçerik |
| --- | --- |
| `index.ts` | `createDependencyEnricher(options): DependencyEnricher` — taramadan çağrılan tek giriş (Karar 2). Çıktı: anahtar başına `EnrichmentOutcome` haritası ve isteğe bağlı tek `[registry]` özet satırı. |
| `coordinates.ts` | Ekosistem eşlemesi (`nodejs → npm`, `python → pypi`), AC-P14-4 ad/sürüm doğrulaması, AC-P14-5 istek adı (npm scoped `@kapsam%2Fad`, PyPI PEP 503), önbellek anahtarı. Saf. |
| `registryClient.ts` | `node:https` üzerinde HTTP katmanı: izin listesi, yönlendirme, boyut sınırı, zaman aşımı, yeniden deneme, eşzamanlılık sınırlayıcı, süreç içi tekilleştirme, tarama başına ardışık hata eşiği (Karar 4). |
| `proxy.ts` | `resolveProxy(env)` ve saf `shouldUseProxy(url, noProxy)` (Karar 5). |
| `npmRegistry.ts` | Sürüm dokümanı isteği ve AC-P14-1 alan çıkarımı, `dist.tarball`/`dist.integrity`/`dist.shasum` (Karar 3, 6). |
| `pypiRegistry.ts` | Sürüm JSON isteği, AC-P14-2 öncelik sırası, `urls` aday sıralaması (Karar 3, 6). |
| `classifiers.ts` | AC-P14-3 trove eşleme tablosu (D-78). Saf. |
| `cache.ts` | Göç `006` tablolarına okuma/yazma (Karar 10). Tek `pg` erişim noktası. |
| `budget.ts` | Bütçe sinyali ve tarama başına sayaçlar (2 GiB indirme, hata eşiği). |
| `effectiveLicense.ts` | L-6 öncelik fonksiyonu `resolveEffectiveLicense(…)` (Karar 11). Saf. |
| `integrity.ts` | SRI/sha1/sha256 ayrıştırma ve akış hash doğrulaması (Karar 6). |
| `text.ts` | Metin çözme (UTF-8/UTF-16 BOM), kontrol/biçim karakteri temizliği, kod noktası kesimi (Karar 8). İçe aktarımsız, saf. |
| `copyright.ts` | Doğrusal telif satırı çıkarımı (AC-P15-9). İçe aktarımsız, saf. |
| `archive/thread.ts` | Arşiv iş parçacığı girişi (Karar 7). |
| `archive/archiveThread.ts` | Ana iş parçacığı tarafı: `runArchiveInThread(input, options)`. |
| `archive/gzip.ts`, `archive/tar.ts`, `archive/zip.ts` | Akışlı gzip+tar okuyucu ve merkezi dizin tabanlı zip okuyucu. |
| `archive/licenseFiles.ts` | Yol normalleştirme ve AC-P15-7 lisans dosyası seçimi. Saf. |
| `archive/extract.ts` | İş parçacığında çalışan birleşik akış: biçim → okuyucu → seçim → çözme → telif. |

Diğer yeni/değişen dosyalar:

| Dosya | Değişiklik |
| --- | --- |
| `src/lib/threadBootstrap.ts` (yeni) | `threadParser.ts`'teki `sourceModeBootstrap` ve `SOURCE_MODE_THREAD_ENV` buraya taşınır, giriş dosyası parametre olur: `threadEntry(compiledJs, sourceTs)`. Yalnız `node:path` içe aktarır. `threadParser.ts` davranış değişmeden bunu kullanır. |
| `src/lib/textSanitize.ts` (yeni) | `errorText.ts`'teki `stripControl`'ün içe aktarımsız yeni yeri (Karar 8); `errorText.ts` yeniden dışa aktarır. |
| `src/lib/spdxExpression.ts` (yeni) | AC-P16-3 doğrusal SPDX ifade doğrulayıcısı ve kanonikleştirici (tokenizer + özyinelemesiz yığınlı ayrıştırıcı, ≤ 16 düzey). |
| `src/lib/outputText.ts` (yeni) | Çıktıya özel kaçış yardımcıları (Karar 13). |
| `src/notice/noticeService.ts` (yeni) + mevcut SBOM uç noktasının controller/route katmanında yeni giriş | NOTICE üretimi ve uç nokta (Karar 12). |
| `src/scanner/worker.ts` | Zenginleştirme adımı, etkin lisansla politika, yeni kolonların yazımı (Karar 2, 11). |
| `src/analysis/licenseNormalizer.ts` | Trove tablosu bağlantısı, ` AND ` birleştirme (D-78). Mevcut eşlemeler değişmez. |
| `src/sbom/**`, `src/reports/reportService.ts` | Etkin lisans ve telif okuma, çıktı düzeltmeleri (Karar 13). |
| `src/scanner/sandbox/runner.config.ts` | `enrichment` bölümü: `REGISTRY_*` ayarları, sabit sınırlar (Karar 14). |
| `src/runtime.ts` | Zenginleştiricinin kablolanması (Karar 14). |

**Sınır kuralları** (qa-automation statik içe aktarım taramasıyla korur):

- İş parçacığında yüklenen modüller (`archive/thread.ts`, `archive/extract.ts`,
  `archive/gzip.ts`, `archive/tar.ts`, `archive/zip.ts`,
  `archive/licenseFiles.ts`, `text.ts`, `copyright.ts`) yalnız `node:zlib`,
  `node:worker_threads`, `node:buffer`, bu listedeki kardeş modülleri ve
  içe aktarımsız `src/lib/textSanitize.ts`'i içe aktarır. `node:fs`, `node:net`, `node:http(s)`, `node:child_process`,
  `pg`, `dotenv`, `src/lib/db` ve `src/`'nin başka çalışma zamanı modülleri
  **içe aktarılmaz**. Arşiv kodunun diske yazamaması ve ağa çıkamaması böylece
  yapısal olarak sağlanır (AC-P15-4).
- `effectiveLicense.ts`, `coordinates.ts`, `classifiers.ts`, `proxy.ts`,
  `src/lib/spdxExpression.ts` saf modüllerdir (yalnız `import type` ve
  `node:url` hariç içe aktarım yok).
- `src/enrichment/` içinde ağ erişimi yalnız `registryClient.ts`'tedir;
  `npmRegistry.ts`/`pypiRegistry.ts` istemciyi parametre olarak alır.

### 2. Taramadaki yeri, bütçe, iptal ve hata yalıtımı (D-60, D-64)

**Sıra** (`processJob`): kaynak → ayrıştırıcı → **zenginleştirme (meta veri,
sonra arşiv)** → OSV araması (değişmez) → sonuç transaction'ı.

- `ScanWorker` bağımlılıklarına isteğe bağlı `enricher?: DependencyEnricher`
  eklenir. Üretimde `runtime.ts` onu **her zaman** verir (`REGISTRY_ENRICHMENT=off`
  iken kapalı kipte, Karar 14). `enricher` verilmemişse (yalnız testler ve
  `saveScanResults` doğrudan çağrısı) zenginleştirme adımı hiç çalışmaz ve her
  anahtar için `disabled` sonucu üretilir; bu yolda `[registry]` satırı
  yazılmaz (satırı zenginleştirici üretir).
- `persistResults`'a isteğe bağlı `enrichment?: EnrichmentResult` seçeneği
  eklenir; transaction içinde etkin lisans ve NOTICE alanları bu sonuçtan
  yazılır (Karar 11).
- **Bütçe (AC-P14-14):** `registerJob` iş başlangıcını monoton saatle
  (`performance.now()`) kaydeder ve `job.deadlineMs` tutar. Zenginleştirme
  başladığında:

  ```
  timeoutMs = scan.timeout_minutes * 60_000
  budgetMs  = min(timeoutMs / 2, (job.deadlineMs - now) - timeoutMs / 4)
  ```

  `budgetMs ≤ 0` ise hiç istek yapılmaz, tüm adaylar `budget_exceeded` olur.
  İkinci terim, clone ve ayrıştırma uzun sürdüğünde sonuç yazımı için süre
  sınırının en az dörtte birinin kalmasını garanti eder; böylece "taramanın
  kendi süre sınırı zenginleştirme yüzünden aşılmaz" ölçütü yapısal olarak
  sağlanır.
- **Sinyaller:** zenginleştirme `enrichSignal = AbortSignal.any([jobSignal,
  budgetSignal])` ile çalışır; `budgetSignal` `AbortSignal.timeout(budgetMs)`
  ile üretilir (test için saat enjekte edilebilir bir `createBudget(clock)`
  sarmalayıcısı). Ayrım iptal nedenine göre yapılır:
  - `jobSignal` iptali (`timeout`/`shutdown`) → nedeni olduğu gibi **yeniden
    fırlatılır**; sınıflandırma ADR-004 Karar 8'e göre (kapanışta `queued`,
    AC-P14-15). O ana kadar yazılmış önbellek kayıtları kalıcıdır.
  - Yalnız bütçe iptali → kalan ve uçuştaki paketler `budget_exceeded`;
    zenginleştirme normal döner, tarama sonuç yazımına geçer.
- **Hata yalıtımı (AC-P14-13):** `enricher.enrich` çağrısı `processJob`'da
  `try/catch` içindedir. `jobSignal` iptali dışındaki **her** hata (beklenmeyen
  kod hatası, önbellek okuma/yazma `pg` hatası dahil) yakalanır, sınıf/kod
  düzeyinde loglanır (`errorCode`, ADR-004 Karar 6), sonuç olmayan her anahtar
  `error` sayılır ve tarama sürer. Zenginleştirme hiçbir koşulda
  `handleScanFailure`'a ulaşmaz ve yeniden denemeye yol açmaz.
- Önbellek yazım hatası (ör. veritabanı geçici kesintisi) yalnız o kaydın
  yazılmamasıdır; bellekteki sonuç bu tarama için kullanılır.

**Zenginleştirici iç akışı** (benzersiz anahtar `(ekosistem, istek adı,
sürüm)` başına):

1. Sınıflandırma (istek yok): kapalı kip → `disabled`; sürüm `NULL` →
   `version_unknown`; doğrulama dışı ad/sürüm → `invalid_coordinates`
   (AC-P14-4).
2. Meta veri önbelleğinin toplu okunması (tek sorgu, `unnest` dizileri).
3. Iskalayan anahtarlar için meta veri istekleri (Karar 4 sınırlayıcısı).
   Bulunan kayıt hemen önbelleğe yazılır.
4. Arşiv aşaması (AC-P15-1): runtime (manifestlerden en az birinde runtime
   kapsamlı; `isRuntimeScope` birleşimi), kesin sürümlü, meta verisi `found`
   anahtarlar. Önce arşiv önbelleği toplu okunur; ıskalayanlar için indirme +
   bütünlük + iş parçacığı (Karar 6, 7). Arşiv aşaması da aynı bütçe
   sinyalindedir.
5. Özet: herhangi bir anahtar `unreachable`, `error`, `budget_exceeded` veya
   `disabled` ise tek bir `[registry]` satırı (Karar 11).

### 3. Kayıt defteri uç noktaları ve alan çıkarımı (D-53)

- **npm:** `GET https://registry.npmjs.org/<istek adı>/<sürüm>`, `Accept:
  application/json`. Scoped ad tek yol bileşeni olarak `@kapsam%2Fad`
  (AC-P14-5). Alanlar AC-P14-1 sırasıyla; `licenses` dizisinde yalnız metin
  `type` değerleri alınır, en fazla 16 öğe.
  - **Scoped sürüm dokümanı doğrulanması gerekiyor** (REQ-004 Riskler). Tanımlı
    yedek: scoped bir adın sürüm dokümanı isteği `404` dönerse **yalnız scoped
    adlarda** tam paket dokümanı `GET /<@kapsam%2Fad>` aynı 8 MiB sınırıyla
    istenir ve `versions[<sürüm>]` okunur. Doküman var ama sürüm yoksa
    `not_found`; doküman 8 MiB'yi aşarsa `error` (önbelleğe yazılmaz). Scoped
    olmayan adlarda yedek yoktur (özel paket adlarının iki kez sızmasını ve
    gereksiz isteği önler). Gerçek davranış AC-P14-20 sırasında gözlenir ve
    handoff'a yazılır; yedek her iki durumda da doğru sonucu verir.
- **PyPI:** `GET https://pypi.org/pypi/<PEP 503 adı>/<sürüm>/json`. İstek
  zaten kanonik adla yapıldığı için yönlendirme beklenmez; PyPI yine de
  yönlendirirse aynı host içinde en fazla 3 adım izlenir (AC-P14-9). Alanlar
  AC-P14-2 sırasıyla (`info.license_expression`, `info.license`,
  `info.classifiers`); `urls` listesi Karar 6'ya göre süzülür.
- **Tip doğrulaması (AC-P14-11):** beklenen alanın tipi tutmazsa (ör. `license`
  sayı, `classifiers` dizi değil, `urls` dizi değil, `dist` nesne değil)
  yanıt o paket için `error`'dur ve önbelleğe yazılmaz. İsteğe bağlı alanın
  **yokluğu** hata değildir.
- **Metin alanları:** saklanmadan önce `text.ts` `sanitizeText` (Karar 8 adım
  2–3) ile temizlenir. Türetilmiş lisans beyanı (`declared_license`) en fazla
  1000 kod noktasıdır (fazlası kesilir; normalleştirici bu durumda bugünkü gibi
  `unknown` verir). PyPI uzun `license` metni (NOTICE yedeği) en fazla 1 MiB
  (UTF-8 bayt) saklanır; fazlası kesilir ve sonuna sabit "[truncated]" notu
  eklenir.
- `info.author`, `maintainers` vb. okunmaz (D-68).

### 4. HTTP istemcisi (D-58)

**Seçim: `node:https` (`https.request`) + kendi küçük katmanımız.** Yerleşik
`fetch` (paketli undici) seçilmedi; gerekçe Karar 5 ve "Değerlendirilen
alternatifler".

- **Uç nokta kümesi:** `RegistryEndpoints = { npm, pypi, files }` sabit bir
  nesnedir. Üretim değeri kodda donmuştur:
  `https://registry.npmjs.org`, `https://pypi.org`,
  `https://files.pythonhosted.org`. Ortam değişkeni, `system_settings`,
  `.npmrc`, `pip.conf`, lock `resolved` veya kayıt defteri yanıtı bunu
  değiştiremez.
- **Test enjeksiyonu:** `createDependencyEnricher({ endpoints })` yalnız kod
  içinden verilir; `assertInjectableEndpoint` her değeri doğrular: `https:` ise
  yalnız yukarıdaki üç kesin köken; `http:` ise yalnız `127.0.0.1` veya
  `[::1]` hostu (port serbest), yol/sorgu/kullanıcı bilgisi yok. Aksi `throw`.
  `runtime.ts` bu parametreyi hiçbir zaman vermez; ortamdan okuyan bir yol
  yoktur. Loopback uç noktalarında vekil hiçbir zaman kullanılmaz.
- **İstek anında izin listesi:** her istek (ilk istek ve **her yönlendirme
  adımı**) yapılmadan önce `assertAllowedUrl(url, purpose)` çağrılır:
  - `new URL()` ile ayrıştırılır; kullanıcı bilgisi (`user:pass@`) varsa red;
  - şema ve köken etkin uç nokta kümesindeki izinli kökenlerle **tam**
    karşılaştırılır (`url.origin`, varsayılan port normalize); amaca göre:
    `metadata-npm` → `npm`, `metadata-pypi` → `pypi`, `archive-npm` → `npm`
    kökeni ve `/` sonrası yol, `archive-pypi` → `files` kökeni.
  - Arşiv URL'si ayrıca AC-P15-2/AC-P15-3 önek kuralıyla
    (`https://registry.npmjs.org/`, `https://files.pythonhosted.org/`)
    eşleşmelidir. Kural dışı arşiv URL'si için istek yapılmaz.
- **Yönlendirme:** `https.request` yönlendirme izlemez; katman elle yönetir.
  Meta veri: `301/302/303/307/308` için `Location` mevcut URL'ye göre çözülür,
  aynı köken ve `https:` olmalıdır, en fazla 3 adım. Arşiv: herhangi bir 3xx →
  o aday için `download_failed`. Yönlendirme yanıtının gövdesi okunmadan soket
  `destroy` edilir.
- **Başlıklar:** sabit ve donmuş: `User-Agent: oss-risk-platform/<package.json
  sürümü> (license-enrichment)`, `Accept`, `Accept-Encoding`. Çerez deposu,
  `Authorization`, token veya API anahtarı yoktur; başlık nesnesi dışarıdan
  genişletilemez. Proxy kimlik bilgisi yalnız `Proxy-Authorization` olarak
  Node tarafından vekile gönderilir (Karar 5), hedef sunucuya gitmez.
- **Kodlama:** meta veride `Accept-Encoding: gzip`; yanıt `Content-Encoding`
  `gzip` ise `zlib.createGunzip()` akışından geçer, `identity`/yok ise doğrudan
  okunur, başka değer → `error`. Arşivde `Accept-Encoding: identity`; bütünlük
  sunulan baytlar üzerinden doğrulandığı için `identity` dışı
  `Content-Encoding` → `download_failed`.
- **Boyut sınırları (AC-P14-11, AC-P15-5):** meta veri 8 MiB, arşiv 64 MiB.
  Önce `Content-Length` (varsa ve sınırı aşıyorsa gövde okunmadan iptal), sonra
  akış sırasında okunan bayt sayısı (gzip'te hem ağ baytı hem açılmış bayt)
  sayılır; sınır aşıldığı an istek `destroy` edilir. Tampon parçalar dizide
  toplanır, sonda tek `Buffer.concat`.
- **İçerik doğrulaması:** meta veride `200` + `Content-Type` `json` içermeli;
  gövde `TextDecoder('utf-8')` ile çözülür, `JSON.parse` edilir; kök nesne
  değilse `error`. (8 MiB'lik `JSON.parse` ana iş parçacığında ~onlarca ms
  sürer; kabul edildi.)
- **Zaman aşımı (AC-P14-10):** `REGISTRY_TIMEOUT_MS` (varsayılan 15 000) her
  **deneme** için toplam süredir (bağlantı + başlık + gövde):
  `AbortSignal.any([AbortSignal.timeout(t), enrichSignal])`. Arşiv indirmesi
  için toplam süre `max(REGISTRY_TIMEOUT_MS, 60 000)`'dir (64 MiB'lik dosya
  yavaş bağlantıda 15 sn'ye sığmaz); bu ek sabit `runner.config.ts`'tedir.
- **Yeniden deneme:** ağ hatası, zaman aşımı, `429`, `5xx` → en fazla 2
  yeniden deneme; bekleme 1 sn, 2 sn. `Retry-After` (saniye veya HTTP tarihi)
  ≤ 30 sn ise bekleme `max(geri çekilme, Retry-After)` olur; > 30 sn veya
  ayrıştırılamaz ise paket için deneme bırakılır (`error`, önbelleğe yazılmaz).
  Bekleme `enrichSignal` ile iptal edilebilir ve saat/uyku fonksiyonu enjekte
  edilir (`clock.sleep`). `404`/`410` → `not_found`. Diğer `4xx` → yeniden
  denenmeyen `error`.
- **Hata sınıflandırması yalnız `err.code` ile yapılır** (`ENOTFOUND`,
  `EAI_AGAIN`, `ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`, `EPIPE`,
  `ERR_TLS_*`, `CERT_*`, `UNABLE_TO_*`, `DEPTH_ZERO_SELF_SIGNED_CERT`, zaman
  aşımı iptali). Hata `message`'ı hiçbir yere yazılmaz (vekil URL'si ve kimlik
  bilgisi içerebilir).
- **Ardışık hata eşiği (AC-P14-13):** tarama başına, host başına sayaç. Ağ
  düzeyindeki her **başarısız deneme** (yukarıdaki kodlar ve zaman aşımı)
  sayacı 1 artırır; herhangi bir HTTP yanıtı (durum kodu ne olursa olsun)
  sıfırlar. Sayaç 5 olunca o host bu tarama için kapanır: bekleyen ve sonraki
  meta veri istekleri `unreachable`, arşivler `download_failed` olur; istek
  denemesi yapılmaz.
- **Eşzamanlılık:** `REGISTRY_CONCURRENCY` (varsayılan 4) **süreç genelinde**
  tek bir semafordur; meta veri ve arşiv istekleri ve eşzamanlı taramalar onu
  paylaşır. `https.Agent({ keepAlive: true, maxSockets: REGISTRY_CONCURRENCY })`
  host başına bağlantı havuzu sağlar.
- **Süreç içi tekilleştirme (AC-P14-7 (3)):** istemci süreçte tektir; uçuştaki
  istekler `Map<önbellek anahtarı, Promise>` ile paylaşılır. Paylaşılan isteğin
  kendi iç `AbortController`'ı vardır ve yalnız **tüm** bekleyenler iptal
  olduğunda iptal edilir (referans sayımı); her bekleyen kendi sinyaliyle
  yarışır. Tamamlanan söz haritadan silinir. Paylaşılan istekteki ağ hatası
  her bekleyen taramanın kendi hata sayacına işlenir. Arşiv indirmeleri de
  `(ekosistem, ad, sürüm, özet)` anahtarıyla aynı şekilde tekilleştirilir.
- **TLS:** Node'un varsayılan CA deposu + `NODE_EXTRA_CA_CERTS`.
  `rejectUnauthorized: false` veya `NODE_TLS_REJECT_UNAUTHORIZED` hiçbir yolda
  kullanılmaz/önerilmez.

### 5. Vekil sunucu ve Node alt sürümü (D-59)

**Seçim: Node yerleşik vekil desteği, `https.Agent` `proxyEnv` seçeneğiyle,
ajan başına ve programatik.** Yeni paket yoktur.

- Node, `http.Agent`/`https.Agent` için `proxyEnv` seçeneğini (ve süreç geneli
  `NODE_USE_ENV_PROXY=1` / `--use-env-proxy` anahtarını) **v24.5.0**'da
  eklemiş ve **v22.21.0**'a geri taşımıştır (doğrulanması gerekiyor: Node
  sürüm notları; kurulu v26.8.1'de mevcut). Süreç geneli anahtar
  **kullanılmaz**: süreç başlangıcında verilmesi gerekir ve mevcut OSV/NVD
  `fetch` isteklerinin davranışını da değiştirirdi (REQ-004 Kapsam Dışı, F4).
- `proxy.ts`:
  - `resolveProxy(env)`: `https_proxy` sonra `HTTPS_PROXY`; `no_proxy` sonra
    `NO_PROXY` (Windows'ta ortam değişkenleri zaten harf duyarsızdır).
    `HTTP_PROXY`/`ALL_PROXY` okunmaz (README yalnız `HTTPS_PROXY`'yi tarif
    eder). Vekil değeri `http:` veya `https:` şemalı geçerli bir URL olmalıdır;
    değilse bir uyarı loglanır (yalnız ayar adı) ve **vekil hatalı** kipine
    geçilir.
  - `shouldUseProxy(targetUrl, noProxyList): boolean` (saf, AC-P14-12 testi):
    liste virgül ve/veya boşlukla ayrılır, boş öğeler atlanır, harf duyarsız.
    `*` → hiçbir hedef için vekil yok. Öğe `host`, `.alan`, `*.alan` veya
    `alan` biçimindedir; `alan` ve `.alan` hedefin kendisiyle veya etiket
    sınırında son ekiyle eşleşir (`example.com` → `a.example.com` eşleşir,
    `badexample.com` eşleşmez). İsteğe bağlı `:port` hedefin etkin portuyla
    (`https` için 443) eşleşmelidir. IP literalleri (`[::1]` köşeli parantezli
    dahil) tam eşleşir. CIDR desteklenmez (README'de belirtilir).
- Kullanım: istemci iki ajan tutar: `directAgent` ve vekil tanımlıysa
  `proxyAgent = new https.Agent({ keepAlive, maxSockets, proxyEnv: {
  HTTPS_PROXY: <vekil URL> } })`. Her istek için karar **bizim**
  `shouldUseProxy` fonksiyonumuzla verilir; `proxyAgent`'a `NO_PROXY`
  verilmez. Böylece Node'un iç `NO_PROXY` yorumuna bağımlılık olmaz ve test
  edilen fonksiyon tek doğruluk kaynağıdır. Hedef HTTPS olduğu için vekil
  üzerinden `CONNECT` tüneli kurulur; TLS uçtan uca hedef hosttadır, izin
  listesi hedef URL'ye uygulanır.
- **Vekil hatalı kipi ve desteklenmeyen Node:** vekil değeri geçersizse veya
  Node sürümü `proxyEnv`'i desteklemiyorsa (`process.versions.node`
  `^22.21.0 || >=24.5.0` dışında) ve vekil tanımlıysa, kayıt defteri
  hostlarına **hiç bağlantı açılmaz** (vekili sessizce atlayıp doğrudan
  bağlanmak kurumsal ağda politika ihlali olabilir); tüm meta veri istekleri
  `unreachable` olur ve başlangıçta tek uyarı loglanır.
- `HTTPS_PROXY` değeri (kimlik bilgisi içerebilir) hiçbir log, hata metni veya
  `error_message`'a yazılmaz.
- **`engines.node`:** `">=22"` → `"^22.21.0 || >=24.5.0"`. REQ-003 D-46'nın
  "Node ≥ 22" alt sınırını bu kadar daraltır. `@types/node` yükseltilmez;
  `proxyEnv` ve `zlib.crc32` için `registryClient.ts`/`zip.ts` içinde dar,
  yerel tip genişletmesi kullanılır (`https.AgentOptions & { proxyEnv?: … }`).
- PAC desteklenmez (D-59). Gerçek kurumsal vekille doğrulama yapılabilirse
  handoff'a yazılır (AC-P14-12).

### 6. Arşiv seçimi, indirme ve bütünlük (D-65)

- İndirme **ana iş parçacığındadır**, Karar 4 katmanıyla, akış olarak,
  64 MiB sınırla. Hash, akış sırasında `crypto.createHash` ile artımlı
  hesaplanır; tampon ancak bütünlük doğrulandıktan sonra iş parçacığına verilir
  (bütünlük ayrıştırmadan **önce**).
- **npm:** URL yalnız `dist.tarball`. `dist.integrity` SRI metnidir (boşlukla
  ayrılmış birden çok öğe olabilir); içindeki `sha512-<base64>` öğeleri
  ayrıştırılır, indirilen baytların sha512'si bunlardan biriyle eşleşmelidir.
  `integrity` yoksa **veya sha512 öğesi içermiyorsa** `dist.shasum` (40 hex,
  SHA-1) kabul edilir. İkisi de yoksa indirme yapılmaz (`no_candidate`).
  Önbellek özeti `sha512-<base64>` veya `sha1-<hex>`.
- **PyPI:** `urls[]` öğelerinden yalnız `url` `https://files.pythonhosted.org/`
  önekli, `digests.sha256` 64 hex olan, `packagetype` `bdist_wheel` veya
  `sdist` olan ve dosya adı `.whl`, `.tar.gz` veya `.zip` ile biten öğeler
  aday olur. Sıra AC-P15-3: `-none-any.whl` ile biten wheel → diğer wheel'ler
  `size` artan (eşitlikte dosya adı kod noktası sırası) → sdist (`.tar.gz`
  önce, sonra `.zip`, her grupta `size` artan). `size` > 64 MiB aday atlanır.
  Önbellekte en fazla 32 aday saklanır. İlk aday indirilir; **yalnız**
  `download_failed`/`integrity_failed`/`limit_exceeded` (boyut) durumunda
  sıradakine geçilir, en fazla 3 aday denenir. Özet `sha256-<hex>`.
- **Bütünlük uyuşmazlığı:** tampon atılır, önbelleğe yazılmaz, paket
  `integrity_failed`.
- **Tarama başına 2 GiB:** indirmeden önce `Content-Length` (yoksa 64 MiB)
  kadar kota ayrılır, sonunda gerçek bayta düzeltilir; kota dolarsa sonraki
  arşivler `limit_exceeded` (`outcome_detail = 'scan_download_quota'`, önbelleğe
  yazılmaz çünkü pakete değil taramaya özgüdür).

### 7. Arşiv iş parçacığı ve okuyucular (D-66, D-67)

**İş parçacığı:**

- **Arşiv başına bir `Worker`** (havuz yok, ADR-005 Karar 5 ilkesi):
  `new Worker(entry, { workerData: { kind, limits }, transferList, resourceLimits:
  { maxOldGenerationSizeMb: 512, maxYoungGenerationSizeMb: 64, stackSizeMb: 4 },
  env: {}, argv: [], execArgv: [] })`. Kaynak modunda `src/lib/threadBootstrap.ts`
  ile `ts-node` bootstrap'ı ve yalnız `DISABLE_V8_COMPILE_CACHE=1` (ADR-005
  ile aynı gerekçe). Arşiv baytları `postMessage(…, [arrayBuffer])` ile
  **aktarılır** (kopya yok).
- **Süreç geneli eşzamanlılık:** aynı anda en fazla **2** arşiv iş parçacığı
  (`runner.config.ts` sabiti, ortam değişkeni yok). En kötü durum yığın
  1 GiB + aktarılan tamponlar (≤ 2 × 64 MiB) + açma akışı parçaları.
- **Süre:** ana tarafta arşiv başına 60 sn zamanlayıcı → `terminate()`;
  `enrichSignal` iptali de `terminate()`. `terminate()` sözü her durumda
  beklenir.
- **Sonuç eşlemesi:**

  | Olay | Paket notu | Önbellek |
  | --- | --- | --- |
  | `{ ok: true, result }` (yapı ve sınırlar ana tarafta yeniden doğrulanır) | `collected` / `no_license_file` / `unsupported_format` / `limit_exceeded` | yazılır |
  | `{ ok: false }`, `error`, mesajsız `exit`, `ERR_WORKER_OUT_OF_MEMORY` | `processing_failed` | yazılmaz |
  | 60 sn zaman aşımı | `processing_failed` | yazılmaz (AC-P15-10) |
  | Bütçe iptali | `budget_exceeded` | yazılmaz |
  | İş iptali (`timeout`/`shutdown`) | — (neden yeniden fırlatılır) | yazılmaz |

  Bellek veya çökme hatası yalnız o paketi etkiler; süreç ayakta kalır
  (AC-P15-4). Bellek/çökme sonuçlarının önbelleğe yazılmaması bilinçlidir:
  kural "yalnız okuyucunun kendi verdiği sonuçlar kalıcıdır"; tekrar maliyeti
  bütçeyle sınırlıdır.

**Biçim tespiti:** npm → gzip'li tar. PyPI → dosya adı uzantısı (`.whl`,
`.zip` → zip; `.tar.gz` → gzip'li tar) ve sihirli baytlar (`1f 8b`, `PK\x03\x04`
veya boş zip `PK\x05\x06`) birlikte uymalıdır; uymazsa `unsupported_format`.

**gzip + tar (akışlı):**

- `zlib.createGunzip({ chunkSize: 64 KiB })` akışı; birleştirilmiş gzip
  üyeleri Node tarafından desteklenir. Açılmış bayt sayacı 512 MiB'yi aştığı an
  akış yok edilir → `limit_exceeded` (`decompressed`). Açılmış içerik bütün
  olarak bellekte **tutulmaz**; tar okuyucu parçaları durum makinesiyle işler
  ve yalnız seçilen lisans dosyalarının baytlarını biriktirir.
- Tar başlığı 512 bayt: sağlama toplamı (unsigned toplam, `chksum` alanı boşluk
  sayılarak) doğrulanır; hatalı başlık → `unsupported_format`. Ardışık iki sıfır
  blok veya akış sonu arşivi bitirir.
- Boyut alanı sekizlik; GNU base-256 kodlaması (ilk bayt `0x80`) **desteklenmez**
  → `unsupported_format` (64 MiB sınırı zaten bunu gereksiz kılar).
- Ad: ustar `prefix + '/' + name`; PAX `x` başlığındaki `path` (ve `size`)
  sonraki girdiye uygulanır; GNU `L` uzun adı sonraki girdiye uygulanır. PAX
  `x`/`g` ve GNU `L`/`K` gövdeleri en fazla 64 KiB; aşarsa `limit_exceeded`
  (`long_name`). PAX kayıtları `"<uzunluk> <anahtar>=<değer>\n"` biçiminde
  doğrusal ayrıştırılır; bozuk kayıt → `unsupported_format`. PAX/GNU adları
  UTF-8 olarak çözülür.
- Tür: `0`, `\0`, `7` düz dosya; `1`, `2` (hard/sym link), `3`, `4`, `5`, `6`
  ve bilinmeyen türler atlanır (gövde okunmadan geçilir).
- Girdi sayısı (meta başlıklar dahil) 100 000'i aşarsa `limit_exceeded`
  (`entries`).

**zip (merkezi dizin):**

- Tüm tampon (≤ 64 MiB) bellektedir. EOCD, son `22 + 65 535` bayt içinde
  sondan başa aranır; yorum uzunluğu dosya sonuna tam oturan ilk aday seçilir.
- **ZIP64:** EOCD alanlarından biri `0xFFFF`/`0xFFFFFFFF` ise, ZIP64 EOCD
  konumlayıcısı (`PK\x06\x07`) varsa veya bir girdinin ekstra alanı ZIP64
  (`0x0001`) içeriyorsa → `unsupported_format` (`zip64`). Çok diskli arşiv →
  `unsupported_format`.
- Merkezi dizin sınırları tampon içinde doğrulanır; girdi sayısı 100 000'i
  aşarsa `limit_exceeded`. Her girdi için ad, yöntem, bayraklar, boyutlar,
  CRC-32 ve yerel başlık ofseti okunur.
- **Yalnız seçilen lisans dosyası adayları açılır**; diğer girdilerin
  verisine hiç dokunulmaz (bu yüzden zip için "açılmış toplam akış" sınırına
  gerek yoktur; tek dosya ve paket toplam sınırları geçerlidir).
- Seçilen girdide: şifreleme bayrağı (bit 0) veya güçlü şifreleme (bit 6) →
  girdi atlanır ve paket notu `unsupported_format` (girdi bazında); yöntem
  yalnız `0` (stored) veya `8` (deflate), diğerleri atlanır. Yerel başlık
  imzası, ad ve yöntem merkezi dizinle tutarlı olmalı; veri aralığı tampon
  içinde olmalı. Deflate `zlib.inflateRawSync(veri, { maxOutputLength: min(bildirilen
  açılmış boyut, 1 MiB) + 1 })`. Gerçek boyut bildirilenle uyuşmazsa, sınır
  aşılırsa veya `zlib.crc32` uyuşmazsa girdi atlanır (AC-P15-6). Bildirilen
  açılmış boyut > 1 MiB ise açılmadan "file too large" notu düşülür.
- Bayrak bit 11 (UTF-8 ad) varsa ad UTF-8, değilse CP437 yerine **latin1**
  olarak çözülür (yalnız eşleştirme için; lisans dosyası adları ASCII'dir).

**Yol normalleştirme ve seçim (AC-P15-6, AC-P15-7):**

- `\` → `/`; baştaki `./` atılır. Mutlak yol (`/` ile başlayan), sürücü harfi
  (`^[A-Za-z]:`), `..` bileşeni, boş bileşen (`//`) veya NUL içeren ad
  **eşleştirilmez** (atlanır).
- Dosya adı (son bileşen) harf duyarsız olarak `LICENSE`, `LICENCE`, `COPYING`,
  `NOTICE` veya `COPYRIGHT` ile başlamalı.
- Konum: npm tar ve sdist → ilk düz dosya girdisinin ilk bileşeni "üst klasör"
  kabul edilir; yalnız `<üst klasör>/<ad>` (derinlik tam 2) alınır. Wheel →
  kökteki `*.dist-info/<ad>` ve `*.dist-info/licenses/**` (iç içe).
- En fazla 10 dosya; sıra normalleştirilmiş yolun kod noktası sırasıdır (tar
  akışında 10'dan fazla aday görülürse sıraya göre en küçük 10'u tutan sınırlı
  bir yapı kullanılır). Dosya 1 MiB'yi aşarsa alınmaz, `{ path, omitted:
  "file_too_large" }` kaydı düşülür. Paket toplam metni 4 MiB'yi aşacaksa
  kalan dosyalar `omitted: "package_text_limit"` olur.
- Hiç dosya bulunamazsa `no_license_file`.

### 8. Metin çözme, arındırma ve telif çıkarımı (D-67, D-68)

`text.ts` (iş parçacığında ve ana tarafta aynı kod):

1. **Çözme (AC-P15-8):** UTF-8 BOM (`EF BB BF`) atılır; UTF-16 LE/BE BOM varsa
   `TextDecoder('utf-16le'|'utf-16be')`; diğer her şey
   `TextDecoder('utf-8', { fatal: false })` (geçersiz dizi → U+FFFD). Latin-1
   yedeği **yoktur** (AC-P15-8). Çözülmüş metinde NUL varsa dosya ikili kabul
   edilir ve alınmaz.
2. `\r\n` ve tek `\r` → `\n`.
3. **Kontrol/biçim temizliği:** ADR-002 Ek E3 güncel adım 1 ile birebir
   (ESC/C1 dizileri sonlandırıcılarıyla, `\p{Cf}`, `\n`/`\t` dışı C0 —form
   feed dahil—, `DEL`, C1). Uygulama tek bir doğrusal tarayıcıdır:
   `errorText.ts` `stripControl` içe aktarımsız yeni `src/lib/textSanitize.ts`
   modülüne taşınır; `errorText.ts` ve `text.ts` onu kullanır, `errorText.ts`
   onu yeniden dışa aktarır (davranış ve testleri değişmez). Eşleşmeyen vekil
   (lone surrogate) U+FFFD olur (JSONB ve XML güvenliği).
4. Lisans dosyası metninde kesim yapılmaz (sınırlar bayt düzeyinde Karar 7'de).

**Telif çıkarımı** (`copyright.ts`, AC-P15-9): satırlar `indexOf('\n')` ile
dolaşılır; her satırda yalnız ilk 4096 kod birimi incelenir (2 MiB tek satır
1 sn altında). Baştaki boşluk ve yorum önekleri (`#`, `*`, `//`, `;`)
karakter karakter atılır; önek harf duyarsız `copyright`, `(c)` veya `©` ile
başlamalı; satırda 1970–2099 aralığında dört haneli yıl (rakam sınırlarında,
el yazımı tarama) veya `©`/`(c)` bulunmalı; yer tutucu listesi ve `Free
Software Foundation` harf duyarsız `includes` ile elenir. Boşluklar tek
boşluğa indirilir, 300 kod noktasına kesilir, `Set` ile tekrarsız, ilk görülme
sırası, paket başına 50 satır. Düzenli ifade kullanılmaz.

### 9. Göç `006` şeması (D-57, D-62, D-79)

Dosyalar: `db/migrations/006_registry_enrichment.up.sql` / `.down.sql`
(database-engineer; nihai metin onundur, aşağıdaki adlar ve kısıtlar
bağlayıcıdır).

```sql
-- up
CREATE TABLE registry_package_cache (
    ecosystem          TEXT        NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name               TEXT        NOT NULL,  -- request name: npm as-is, PyPI PEP 503
    version            TEXT        NOT NULL,
    outcome            TEXT        NOT NULL CHECK (outcome IN ('found', 'not_found')),
    declared_license   TEXT        NULL,      -- derived per AC-P14-1/2/3; NULL = registry has no license
    license_text       TEXT        NULL,      -- long PyPI license text (NOTICE fallback), <= 1 MiB
    archive_candidates JSONB       NOT NULL DEFAULT '[]'::jsonb,
    extractor_version  INTEGER     NOT NULL CHECK (extractor_version > 0),
    fetched_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NULL,      -- NULL = found (never expires); not_found = fetched_at + 24 h
    PRIMARY KEY (ecosystem, name, version),
    CONSTRAINT registry_package_cache_expiry
        CHECK ((outcome = 'not_found') = (expires_at IS NOT NULL)),
    CONSTRAINT registry_package_cache_not_found_empty
        CHECK (outcome = 'found' OR (declared_license IS NULL AND license_text IS NULL
                                     AND archive_candidates = '[]'::jsonb))
);

CREATE TABLE registry_archive_cache (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem         TEXT        NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name              TEXT        NOT NULL,
    version           TEXT        NOT NULL,
    archive_digest    TEXT        NOT NULL,   -- 'sha512-<b64>' | 'sha1-<hex>' | 'sha256-<hex>'
    archive_url       TEXT        NOT NULL,
    archive_size      BIGINT      NOT NULL CHECK (archive_size >= 0),
    outcome           TEXT        NOT NULL CHECK (outcome IN
                          ('collected', 'no_license_file', 'unsupported_format', 'limit_exceeded')),
    outcome_detail    TEXT        NULL,       -- fixed code, e.g. 'entries', 'decompressed', 'zip64'
    license_files     JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- [{path,text} | {path,omitted}]
    copyright_lines   TEXT[]      NOT NULL DEFAULT '{}',
    extractor_version INTEGER     NOT NULL CHECK (extractor_version > 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT registry_archive_cache_key UNIQUE (ecosystem, name, version, archive_digest)
);

ALTER TABLE scan_dependencies
    ADD COLUMN license_expression        TEXT    NULL,
    ADD COLUMN license_source            TEXT    NULL CHECK (license_source IN
        ('registry:npm', 'registry:pypi', 'lockfile (unverified)', 'none')),
    ADD COLUMN license_lock_hint         TEXT    NULL,
    ADD COLUMN license_hint_differs      BOOLEAN NULL,
    ADD COLUMN license_enrichment_status TEXT    NULL CHECK (license_enrichment_status IN
        ('ok', 'no_license', 'not_found', 'unreachable', 'error', 'disabled',
         'version_unknown', 'invalid_coordinates', 'budget_exceeded')),
    ADD COLUMN notice_status             TEXT    NULL CHECK (notice_status IN
        ('collected', 'no_license_file', 'unsupported_format', 'limit_exceeded',
         'no_candidate', 'integrity_failed', 'download_failed', 'processing_failed',
         'budget_exceeded', 'not_attempted', 'not_runtime')),
    ADD COLUMN notice_archive_id         UUID    NULL
        REFERENCES registry_archive_cache(id) ON DELETE SET NULL;

ALTER TABLE scan_dependencies ADD CONSTRAINT scan_dependencies_license_f3_together
    CHECK ((license_source IS NULL) = (license_enrichment_status IS NULL));

CREATE INDEX idx_scan_dependencies_notice_archive
    ON scan_dependencies (notice_archive_id) WHERE notice_archive_id IS NOT NULL;
```

```sql
-- down
-- Data lost: the registry metadata and archive caches (re-downloadable from
-- the public registries) and the effective-license / NOTICE fields of scans
-- completed after F3 (scan_dependencies.license_* and notice_*). Reports and
-- SBOMs of those scans fall back to license_findings; NOTICE needs a rescan.
DROP INDEX IF EXISTS idx_scan_dependencies_notice_archive;
ALTER TABLE scan_dependencies
    DROP CONSTRAINT IF EXISTS scan_dependencies_license_f3_together,
    DROP COLUMN notice_archive_id, DROP COLUMN notice_status,
    DROP COLUMN license_enrichment_status, DROP COLUMN license_hint_differs,
    DROP COLUMN license_lock_hint, DROP COLUMN license_source,
    DROP COLUMN license_expression;
DROP TABLE registry_archive_cache;
DROP TABLE registry_package_cache;
```

- Ekosistem kolonu `tech_ecosystem` enum'u değil `TEXT` + `CHECK`'tir: önbellek
  kayıt defteri kimliğidir (`npm`/`pypi`), proje ekosistemi değil; enum
  değişikliği F5'te (.NET) göç gerektirmez.
- `scan_dependencies`'e eklenen kolonlar varsayılansız `NULL`'dır (tablo
  yeniden yazılmaz); F3 öncesi satırlar `NULL` kalır ve "F3 öncesi tarama"
  işaretidir. Yeni FK mevcut satırlarda `NULL` olduğu için doğrulama ucuzdur.
- Etkin lisans **`scan_dependencies` satırında** tutulur (ayrı tablo değil):
  satır zaten tarama × paket × manifest kimliğidir, raporlar ve SBOM onu
  okur; aynı anahtarın tüm satırlarına aynı değer yazılır.
- Kullanılmayan `packages.copyright_text`, `notice_text`, `metadata`,
  `enriched_at` (D-79) **kullanılmaz ve silinmez**: `packages` satırları
  sürümsüz olabilir, tarama transaction'ında yazılır ve geri alınabilir;
  kalıcı önbellek ihtiyacını karşılamaz. SBOM'un `packages.copyright_text`
  okuması arşiv önbelleği okumasıyla değiştirilir. Silinmeleri ayrı bir
  temizlik kararıdır.
- Göç `CONCURRENTLY` veya transaction dışı ifade içermez. `db/schema.sql`
  güncellenir; `001`…`005` değişmez. `db/README.md`'ye temizleme SQL'i
  (`DELETE FROM registry_archive_cache; DELETE FROM registry_package_cache;`
  ve yalnız negatifleri silen `DELETE … WHERE outcome = 'not_found'`) eklenir.

### 10. Önbellek semantiği ve transaction sınırları (D-57)

- **Kod sabitleri:** `METADATA_EXTRACTOR_VERSION = 1`,
  `ARCHIVE_EXTRACTOR_VERSION = 1` (`cache.ts`). Çıkarım mantığını değiştiren
  her değişiklik ilgili sabiti artırır (ör. AC-P14-1/2/3 alan sırası, trove
  tablosu → meta veri; okuyucu, seçim, telif kuralı → arşiv).
- **Geçerlilik (okuma):** meta veri kaydı `extractor_version = güncel` ve
  (`expires_at IS NULL` veya `expires_at > NOW()`) ise isabettir. Arşiv kaydı
  `extractor_version = güncel` ise isabettir. Zaman **veritabanı saatiyle**
  (`NOW()`) değerlendirilir (ADR-004 ilkesi; testler `expires_at`'ı geçmişe
  çekerek AC-P14-7 (4)'ü doğrular).
- **Negatif önbellek:** `404`/`410` → `outcome = 'not_found'`,
  `expires_at = NOW() + INTERVAL '24 hours'`.
- **Geçici hatalar** (ağ, zaman aşımı, `429`, `5xx`, bozuk yanıt, bütünlük,
  iş parçacığı) yazılmaz.
- **Bayatken hata (stale-on-error):** yalnız tek bir durumda uygulanır:
  `outcome = 'found'` olup `extractor_version` eski olan kayıt yenilenmeye
  çalışılırken geçici hata alınırsa eski kayıt **o tarama için** kullanılır
  (durum `ok`/`no_license`, kaynak `registry:*`). Gerekçe: kayıt defteri
  verisi lock ipucundan her zaman daha güvenilirdir (L-6). Süresi dolmuş
  `not_found` kaydı hata durumunda kullanılmaz; sonuç her iki yolda da lock
  ipucudur (AC-L6-3), fark yoktur.
- **Yazım (upsert):** her kayıt **kendi otomatik transaction'ında**, istek
  sonuçlandığı anda havuzdan bir bağlantıyla yazılır (tarama transaction'ından
  bağımsız; AC-P14-8). Eşzamanlı taramalar için:

  ```sql
  INSERT INTO registry_package_cache (…) VALUES (…)
  ON CONFLICT (ecosystem, name, version) DO UPDATE SET …, fetched_at = NOW()
  WHERE registry_package_cache.extractor_version <= EXCLUDED.extractor_version;

  INSERT INTO registry_archive_cache (…) VALUES (…)
  ON CONFLICT ON CONSTRAINT registry_archive_cache_key DO UPDATE SET …, updated_at = NOW()
  WHERE registry_archive_cache.extractor_version <= EXCLUDED.extractor_version
  RETURNING id;
  ```

  Eski kodun yeni kaydı ezmesi `WHERE` ile önlenir. Aynı sürümde son yazan
  kazanır; iki yazım aynı kayıt defteri verisinden geldiği için zararsızdır.
  `RETURNING` boşsa (daha yeni kayıt var) `id` ayrı bir `SELECT` ile okunur.
- **Arşiv kaydı yerinde güncellenir:** çıkarım sürümü artınca aynı `id`
  korunur; eski taramaların NOTICE'ı aynı arşiv baytlarının güncel
  çıkarımını gösterir (içerik adresli özet aynı olduğu için kabul edildi).
- **Tarama transaction'ı:** `persistResults` içinde, mevcut
  `INSERT INTO scan_dependencies` ifadesi yeni kolonları da yazar
  (`ON CONFLICT … DO NOTHING` yolunda değerler aynı olduğu için güncelleme
  gerekmez). `notice_archive_id` FK'si, transaction sırasında önbellek
  temizlenirse ihlal verebilir; bu, ADR-004 Karar 8'e göre geçici veritabanı
  hatasıdır (elle temizlik ile tarama çakışması nadir; kabul edildi).

### 11. L-6 önceliği, etkin lisans, politika ve özet satırı (D-54, D-55, D-62, D-73)

`resolveEffectiveLicense({ status, declaredLicense, lockLicenses, ecosystem })`
(saf):

| Zenginleştirme durumu | Etkin lisans | `license_source` | Politika girdisi |
| --- | --- | --- | --- |
| `ok` (bulundu, lisans var) | `normalizeLicense(declared)` sonucu | `registry:npm` / `registry:pypi` | tek öğeli liste `[declared]` |
| `no_license` (bulundu, lisans yok) | boş | `none` | boş → runtime ise `NOASSERTION` bulgusu (AC-L6-2) |
| `not_found`, `unreachable`, `error`, `budget_exceeded`, `disabled` | ipucu varsa ipucu, yoksa boş | `lockfile (unverified)` / `none` | ipucu varsa **bugünkü `dep.licenses` dizisi** (F2 ile birebir), yoksa boş |
| `version_unknown`, `invalid_coordinates` | boş | `none` | boş → runtime ise `NOASSERTION` (AC-L6-3 listesi bu durumları kapsamaz) |

- Önce `disabled` sınıflandırılır: zenginleştirme kapalıyken sürümsüz paket de
  `disabled` olur ve ipucu kullanılır (AC-G-8, F2 ile aynı bulgular).
- **Lock ipucu metni:** `dep.licenses` öğeleri (ayrıştırıcı zaten tekil ve
  sıralı verir) Karar 8 temizliğinden geçer, birden çoksa ` AND ` ile birleşir,
  200 kod noktasına kesilir ve `license_lock_hint`'e yazılır.
- **Uyuşmazlık (AC-L6-4):** durum `ok` ve ipucu varsa, iki tarafın
  normalleştirilmiş biçimleri (öğe bazında `normalizeLicense(...).normalized`,
  büyük harfe çevrilmiş, sıralı, ` AND ` birleşik) karşılaştırılır; farklıysa
  `license_hint_differs = true`. Diğer durumlarda `NULL`.
- **Politika ve parmak izi:** `persistResults`'taki mevcut döngü değişmeden
  "politika girdisi" listesi üzerinde çalışır: her öğe için `normalizeLicense`
  → `licenses` tablosu → `license_policies` → ihlal kararı →
  `computeFindingFingerprint({ …, normalizedLicense })`. Parmak izi formülü
  **değişmez** (ADR-003 c, D-73); yalnız girdinin kaynağı değişir. Lisans
  bulguları yine yalnız runtime kapsamda açılır (ADR-003 b).
- **Özet satırı (AC-P14-13):** zenginleştirici, durumu `unreachable`, `error`,
  `budget_exceeded` veya `disabled` olan benzersiz anahtar sayısını ve bunların
  kaçının lock ipucuna düştüğünü sayar; sabit şablonlu **tek** satır üretir
  (`[registry]` önekli; kesin metin contract'tadır). Paket adı yazılmaz.
  Satır, mevcut `parse_errors` uyarılarının birleştirildiği yerde eklenir ve
  `sanitizeErrorText`'ten geçer (ADR-002 Ek E3). Tarama `completed` olur.
- Arşiv notu (`notice_status`) eşlemesi: runtime olmayan anahtar →
  `not_runtime`; meta verisi `found` olmayan runtime anahtar → `not_attempted`
  (NOTICE nedeni zenginleştirme durumundan türetilir: "registry unreachable
  during scan", "version unknown" vb.); diğerleri Karar 6–7 sonucu.

### 12. NOTICE uç noktası (D-69, D-70, D-74)

- `GET /api/scans/{scanId}/notice`, mevcut SBOM indirme uç noktasıyla aynı
  katmanlarda (route → controller → `NoticeService`), aynı kimlik doğrulama
  (oturum çerezi veya API anahtarı) ve `reports:read` izniyle. Proje/tarama
  erişim denetimi SBOM uç noktasındakiyle **aynıdır**; yeni yetki kuralı
  eklenmez. Hata gövdeleri mevcut biçimdedir (`400` geçersiz UUID, `401`,
  `403`, `404` yok veya `completed` değil).
- **Üretim:** istek anında, yalnız veritabanından, ağ isteği olmadan:
  1. tarama + proje adı + `completed_at`;
  2. runtime `scan_dependencies` satırları `(ekosistem, ad, sürüm)` anahtarına
     göre gruplanır (sürümsüzlerde `(ekosistem, ad)`); her anahtar için etkin
     lisans, kaynak, `notice_status`, `notice_archive_id`;
  3. `registry_archive_cache` satırları `id = ANY($ids)` ile tek sorguda;
  4. NOTICE yedeği için `registry_package_cache.license_text` (yalnız PyPI ve
     lisans dosyası yokken).
  F3 öncesi taramalarda (`license_source IS NULL`) arşiv kaydı
  `(ekosistem, istek adı, sürüm)` ile güncel çıkarım sürümünde aranır, üst
  bilgiye yeniden tarama notu eklenir (AC-P15-14).
- **Biçim:** contract'ta (D-74). Bu ADR'nin bağlayıcı kuralları: UTF-8 BOM'suz,
  LF, üretim zamanı yok, sıralama `(ekosistem, küçük harfli ad, ad, sürüm)` kod
  noktası (`localeCompare` **kullanılmaz**), her runtime anahtar tam bir kez.
  Güvenilmeyen metin satırlarından girdi ayracıyla (contract'taki sabit ayraç
  satırı) başlayanların başına tek boşluk eklenir; böylece paket metni sahte
  bir girdi başlığı üretemez.
- **Boyut:** gövde `Buffer` parçalarıyla kurulur ve bayt sayılır; 64 MiB'yi
  aşacak metinler yazılmaz, yerine "text omitted: NOTICE size limit" notu
  konur, girdiler her durumda listelenir. Gövde tamamlanınca SHA-256
  hesaplanır → `X-Checksum-SHA256`; `Content-Type: text/plain; charset=utf-8`,
  `Content-Disposition: attachment; filename="NOTICE-<scanId>.txt"`
  (`scanId` doğrulanmış UUID olduğu için kaçış gerekmez). Diske,
  `sbom_documents`'a veya `reports`'a yazılmaz; denetim kaydı yoktur.
- Üretim senkron CPU işi ağırlıklıdır (en kötü 64 MiB); tek kullanıcılı yerel
  araç için ana iş parçacığında kabul edilir.

### 13. Çıktılara kaçış ve biçim düzeltmeleri (D-63, D-71, D-72)

`src/lib/outputText.ts` (saf):

| Hedef | Kural |
| --- | --- |
| Ortak | Her güvenilmeyen metin (paket adı, sürüm, lisans, ipucu, telif, dosya yolu, lisans metni) saklanırken Karar 8 adım 2–3'ten geçmiştir; çıktıda yeniden uygulanır (F3 öncesi veri ve savunma derinliği). |
| SPDX JSON, CycloneDX JSON | Yalnız `JSON.stringify` (elle metin birleştirme yok). `copyrightText`/`copyright` = satırların `\n` ile birleşimi. |
| SPDX tag-value | Tek satırlık alanlarda `\n` → boşluk. Çok satırlı değerler `<text>…</text>` içinde; değerdeki `<text>` ve `</text>` (harf duyarsız) `&lt;text&gt;` / `&lt;/text&gt;` olur. |
| CycloneDX XML | Önce XML 1.0'da geçersiz karakterler çıkarılır (`#x9 #xA #xD [#x20-#xD7FF] [#xE000-#xFFFD] [#x10000-#x10FFFF]` dışı, eşleşmeyen vekiller dahil), sonra `& < > " '` kaçışı. Bileşen alt öğe sırası: `author`, `name`, `version`, `description`, `scope`, `licenses`, `copyright`, `purl` (CycloneDX 1.5 XSD; doğrulanması gerekiyor — uygulama sırasında XSD'den teyit edilir, AC-P16-6). |
| Excel | Yeni `License` ve `License Source` hücreleri düz metin (`{ formula }` asla kullanılmaz). Değer `=`, `+`, `-`, `@`, `\t` veya `\r` ile başlıyorsa başına `'` eklenir (CSV'ye dışa aktarımda formül enjeksiyonu kalkanı). Mevcut sütunlar değişmez. |
| PDF | Yeni `License` sütunu; metin Karar 8'den geçmiş düz metin, hücre genişliğine göre kesilir. |
| NOTICE | Karar 12 ayraç kuralı. |

- SPDX `licenseDeclared` = `spdxExpression.canonicalize(etkin lisans)`;
  geçersizse `NOASSERTION` + `licenseComments` (arındırılmış ham değer).
  `licenseConcluded` = `NOASSERTION`. F3 öncesi taramada kaynak
  `license_findings`, aynı doğrulamayla (AC-P16-2).
- CycloneDX `licenses`: tek girdi (`expression` / `license.id` /
  `license.name`), etkin lisans yoksa alan yok (AC-P16-5).
- `License Source` hücresi: `registry:<eko>`; uyuşmazlıkta
  `registry:<eko> (lockfile differs: <ipucu>)`; lock kaynağında
  `lockfile (unverified)`; F3 öncesi boş (AC-P14-18, AC-L6-4).

### 14. Yapılandırma ve kablolama (D-61)

- `runner.config.ts` → `enrichment` bölümü:
  - `REGISTRY_ENRICHMENT`: `on` (varsayılan) / `off`; başka değer → varsayılan
    + yalnız ayar adının loglanması.
  - `REGISTRY_TIMEOUT_MS`: `boundedNumber`, 1 ms – 24 sa, varsayılan 15 000.
  - `REGISTRY_CONCURRENCY`: `boundedNumber`, 1–32 tam sayı, varsayılan 4.
  - Sabitler (ortam değişkeni yok): meta veri 8 MiB, arşiv 64 MiB, açılmış
    512 MiB, 100 000 girdi, 1 MiB dosya, 4 MiB paket metni, 10 dosya,
    64 KiB uzun ad, 2 GiB tarama kotası, 60 sn iş parçacığı, 2 arşiv iş
    parçacığı, 60 sn arşiv indirme alt sınırı, hata eşiği 5, yeniden deneme
    2 (1 sn, 2 sn), `Retry-After` ≤ 30 sn, yönlendirme 3, NOTICE 64 MiB.
- `runtime.ts`, `ScanWorker`'ı kurarken `createDependencyEnricher({ config,
  db, logger })`'ı verir (`endpoints` parametresi **yok**). `off` iken
  zenginleştirici ağ istemcisini hiç oluşturmaz, önbelleği okumaz, tüm
  anahtarlar için `disabled` ve tek özet satırı döner (AC-P14-16).
- Vitest kurulumunda `REGISTRY_ENRICHMENT=off` varsayılandır; zenginleştirme
  testleri zenginleştiriciyi sahte sunucu uç noktasıyla açıkça enjekte eder.

### 15. Bağımlılıklar (D-76, AC-G-5)

- **Yeni runtime bağımlılığı yoktur.** HTTP (`node:https`), vekil (`proxyEnv`),
  gzip/deflate (`node:zlib`), CRC-32 (`zlib.crc32`, Node ≥ 22.2), hash
  (`node:crypto`), iş parçacığı (`node:worker_threads`), tar ve zip okuyucu
  (kendi kodumuz), SPDX doğrulayıcı (kendi kodumuz).
- Değişen tek paket meta verisi `engines.node`'dur (Karar 5). D-59'daki
  "exact pin'li paket" istisnası **kullanılmaz**; insan onayı gerektiren
  `npm install` yoktur. `npm audit --omit=dev` sonucu yine handoff'a yazılır.

### 16. Önceki ADR'lere etkiler ve yol sahipliği

- **ADR-005 Karar 1 sınır kuralı (kısmen superseded):**
  `src/scanner/parsers/threadParser.ts` (yalnız ana iş parçacığı tarafı)
  ortak `src/lib/threadBootstrap.ts`'i içe aktarabilir. İş parçacığında
  yüklenen `thread.ts` ve ayrıştırıcı modülleri için kural aynen geçerlidir.
  ADR-005'e tarihli not eklenmiştir.
- **ADR-005 Karar 5:** davranış değişmez; bootstrap kodu taşınır.
- **ADR-004 Karar 7:** iş sinyali zenginleştiriciye de iletilir; iş süre sınırı
  zenginleştirmeyi kapsar, bütçe bunun içindedir (Karar 2). Superseded değil,
  genişletme.
- **ADR-004 Karar 8:** zenginleştirme hiçbir sınıfa hata üretmez (Karar 2).
- **ADR-002 Ek E3:** aynen kullanılır; `stripControl` saf modüle taşınır,
  davranışı değişmez.
- **ADR-003 (c):** lisans parmak izi formülü değişmez.
- **REQ-003 D-46:** Node alt sınırı `^22.21.0 || >=24.5.0` olur.

**Yol sahipliği** (manifest önerisi; manifest'i agent yazmaz):

| Agent | Yollar |
| --- | --- |
| backend-engineer | `src/**` (`src/db` hariç): `src/enrichment/**`, `src/lib/{threadBootstrap,textSanitize,spdxExpression,outputText,errorText}.ts`, `src/notice/**`, `src/scanner/**`, `src/analysis/licenseNormalizer.ts`, `src/sbom/**`, `src/reports/**`, `src/runtime.ts`, controller/route; `README.md`; `package.json` **yalnız `engines` alanı** |
| database-engineer | `db/**` (göç `006`, `schema.sql`, `db/README.md`), `src/db/**` |
| qa-automation | `tests/**` (sahte kayıt defteri, ağ koruması, fixture'lar, golden NOTICE), `vitest.config.ts` (`setupFiles`) |
| frontend-engineer | `public/app.js` (AC-P15-15) |
| contract-broker | `docs/contracts/REQ-004-*` |
| Ana oturum | `.env.example`, gerçek ağ doğrulamaları (AC-P14-20), yerel veritabanına `006` |

## Gerekçe

Sabit uç nokta kümesi ve her yönlendirme adımında yeniden uygulanan izin
listesi, kullanıcı/repo/kayıt defteri kaynaklı adresleri yapısal olarak
dışarıda bırakır; SSRF'yi kural değil tasarım kapatır. `node:https`,
`proxyEnv`'i ajan başına ve süreç başlangıcı gerektirmeden kullanmaya izin
verdiği için vekili yalnız yeni istemciye uygular ve OSV davranışına (F4)
dokunmaz; yönlendirme, akış sınırı ve hata kodları üzerinde tam denetim verir.
Arşivlerin bütünlük doğrulamasından sonra, diske dokunmadan, ağ ve dosya
sistemi modülü içe aktaramayan bir iş parçacığında işlenmesi, kendi
okuyucularımızın (D-76) olası hatalarını süreç ve sır sınırının dışında tutar.
Zip'te yalnız seçilen girdilerin açılması ve tar'da akışlı okuma, bellek
sınırını sıkıştırma bombasından bağımsız kılar. Önbelleğin ayrı tablolarda ve
tarama transaction'ından bağımsız yazılması "ikinci kez sorgulanmıyor"
ölçütünü iptal/geri alma durumunda da korur; etkin lisansın tarama satırında
saklanması raporları önbellekten bağımsız tekrarlanabilir kılar. Politika
girdisinin lock kaynağında bugünkü diziyle aynı kalması, zenginleştirme
kapalıyken F2 bulgularıyla birebirliği ve parmak izi sürekliliğini sağlar.

## Değerlendirilen alternatifler

- **Yerleşik `fetch` (paketli undici):** vekil için ya süreç geneli
  `NODE_USE_ENV_PROXY=1`/`--use-env-proxy` (başlangıçta verilmeli, OSV'yi de
  değiştirir, `npm start` betiği ve test ortamını etkiler) ya da
  `EnvHttpProxyAgent` gerekir; ikincisi Node'un iç undici'sinden dışa
  aktarılmaz, `undici` paketi (yeni runtime bağımlılığı) ister. Reddedildi.
- **Vekil için exact pin'li paket (`https-proxy-agent`, `undici`):** yerleşik
  çözüm mevcutken tedarik zinciri yüzeyi ve insan onayı maliyeti. Reddedildi.
- **`engines` alt sınırını değiştirmeden vekili yok saymak:** README'nin
  kurumsal vekil tarifine (REQ-003 D-47) aykırı, AC-P14-12 karşılanmaz.
  Reddedildi.
- **Node'un `NO_PROXY` yorumuna güvenmek:** sürüme bağlı ayrıntılar (port,
  joker) test edilemez; saf fonksiyon gereksinimi (AC-P14-12) kendi kararımızı
  gerektirir. Reddedildi.
- **Arşivi geçici klasöre yazıp `tar`/`yauzl` paketleriyle açmak:** yeni
  bağımlılık, zip-slip ve temizlik riski, D-66'ya aykırı. Reddedildi.
- **Arşivi ana iş parçacığında açmak:** kötü niyetli girdi API'yi bloklar,
  bellek sınırı yoktur. Reddedildi.
- **Tarama başına tek, yeniden kullanılan arşiv iş parçacığı:** başlatma
  maliyetini düşürür ama bir arşivin yığın kirliliği/çökmesi sonrakileri
  etkiler ve yeniden başlatma mantığı gerekir. İlk sürümde arşiv başına iş
  parçacığı; AC-P14-20 ölçümü gerekirse ayrı karar. Reddedildi (şimdilik).
- **tar.gz'yi `gunzipSync` ile tek tampona açmak:** 512 MiB'lik tampon
  `resourceLimits` dışında (V8 dışı bellek) kalır; iki iş parçacığıyla 1 GiB
  ek bellek. Akışlı okuma seçildi.
- **Önbellek için `packages` kolonlarını kullanmak:** sürümsüz satırlar,
  tarama transaction'ında yazım ve geri alma (D-57). Reddedildi.
- **Etkin lisansı ayrı `scan_package_licenses` tablosunda tutmak:** ek join ve
  anahtar çoğaltması; satır başına kolon raporların mevcut sorgularına en az
  değişiklikle eklenir. Reddedildi.
- **Arşiv kaydını çıkarım sürümüyle birlikte anahtarlamak (eski satırları
  korumak):** sınırsız büyüme; içerik adresli özet aynı olduğu için yerinde
  güncelleme yeterli. Reddedildi.
- **Bellek/çökme sonuçlarını önbelleğe yazmak:** deterministik olmayabilir
  (eşzamanlı yük); muhafazakâr kural "yalnız okuyucu sonuçları kalıcı".
  Reddedildi.
- **Scoped olmayan npm adlarında da tam doküman yedeği:** özel paket adlarının
  ikinci istekle tekrar sızması ve gereksiz trafik. Reddedildi.
- **Metinlerde latin1 yedeği:** AC-P15-8 U+FFFD kuralı esas. Reddedildi.

## Sonuçlar / Uygulama etkisi

- **Davranış:** ilk F3 taramasında lisans bulguları değişir (Python
  `NOASSERTION`'ları kapanır, gerçek lisanslar görünür; npm'de lock ile kayıt
  defteri farklıysa yeni bulgu). Ayrıca zenginleştirme açıkken sürümü kesin
  olmayan lock girdilerinin (`file:`, git, etiket) lock lisansı artık
  kullanılmaz; runtime ise `NOASSERTION` bulgusu açılır (AC-L6-3'ün doğrudan
  sonucu). README ve handoff'ta belirtilir.
- **`error_message`:** tamamlanmış taramada en fazla bir `[registry]` satırı
  eklenir; zenginleştirme kapalıyken bulgular F2 ile aynıdır, `error_message`
  bu tek satır kadar farklıdır.
- **Performans:** ilk taramada paket başına bir meta veri isteği ve runtime
  paket başına bir arşiv indirmesi + iş parçacığı; ikinci taramada sıfır istek.
  Ölçüm handoff'a (AC-P14-20).
- **Veri:** önbellek tabloları kendiliğinden küçülmez; temizleme SQL'i
  `db/README.md`'dedir. Önbellek temizlenirse eski taramaların NOTICE metinleri
  "rescan" notuna düşer (`ON DELETE SET NULL`).
- **Implementer'lar için kritik uyarılar:**
  1. Hiçbir ağ hatasının `message`'ı loglanmaz/saklanmaz; yalnız `code`.
  2. İzin listesi her yönlendirme adımında yeniden uygulanır; arşivde
     yönlendirme izlenmez.
  3. Bütünlük, iş parçacığına vermeden **önce** doğrulanır.
  4. İş parçacığı modülleri `fs`/`net`/`http(s)`/`pg` içe aktarmaz.
  5. Önbellek yazımı tarama transaction'ının `client`'ını **kullanmaz**.
  6. `jobSignal` iptali yeniden fırlatılır, bütçe iptali yutulur.
  7. Politika döngüsü ve parmak izi fonksiyonu değişmez; yalnız girdi listesi.
  8. Sıralamalarda `localeCompare` değil kod noktası karşılaştırması.
  9. `zlib` çağrılarında `maxOutputLength` her zaman verilir.
  10. Düzenli ifadeler güvenilmeyen metinde iç içe/örtüşen niceleyici içermez.
- **Handoff:** `docs/handoffs/REQ-004.md` bu ADR'nin doğrulanması gereken
  noktalarını (scoped npm sürüm dokümanı, PyPI yönlendirmesi, Node `proxyEnv`
  sürümü, CycloneDX XSD sırası) ve ölçümleri kaydetmelidir. Non-trivial bir
  mimari karar olduğundan handoff güncellemesi zorunludur.

## Güvenlik etkisi

- **SSRF:** hedef URL'ler yalnız kod sabiti üç köken; test enjeksiyonu yalnız
  loopback `http` veya aynı üç köken; her adımda yeniden doğrulama; kullanıcı
  bilgisi içeren URL red. Lock `resolved`, `.npmrc`, ortam değişkeni ve kayıt
  defteri yanıtı hedefi genişletemez. Vekil yalnız işletmenin ortam
  değişkeninden gelir (taranan repodan değil).
- **Tedarik zinciri / bütünlük:** npm sha512 (yoksa sha1, aynı TLS kökeninden),
  PyPI sha256; uyuşmazlıkta hiçbir şey saklanmaz. Yeni runtime paketi yok.
- **Güvenilmeyen ikili girdi:** bütünlük → iş parçacığı (`env: {}`, 512 MiB,
  60 sn, ağ/fs modülü yok) → sınırlar (AC-P15-5) → yol normalleştirme → diske
  yazma yok. Sıkıştırma bombası: tar'da akışlı sayaç, zip'te yalnız seçilen
  girdi ve `maxOutputLength`. Kendi okuyucularımız Security Red Team
  incelemesinin zorunlu kapsamıdır (REQ-004 Riskler).
- **Metin enjeksiyonu:** tek arındırma noktası (Karar 8) + hedef biçime özgü
  kaçış (Karar 13): tag-value `<text>`, XML geçersiz karakterler, Excel formül
  kalkanı, NOTICE ayraç sahteciliği, `error_message` için ADR-002 Ek E3.
- **ReDoS:** telif çıkarımı, PAX ayrıştırma, SPDX doğrulama ve `NO_PROXY`
  eşleşmesi doğrusal el yazımı tarayıcılardır.
- **Sızıntı:** isteklerde kimlik bilgisi yok; vekil URL'si ve hata mesajları
  loglanmaz; özet satırında paket adı yok. Gizlilik: paket adları/sürümleri kamu
  kayıt defterlerine (ve vekile) gider — kabul edildi, README'de, `off` ile
  kapatılabilir (D-61).
- **L-6:** kayıt defteri her zaman kazanır; kayıt defterinde lisans yokken ipucu
  kullanılmaz; ipucu yalnız ağ/404/kapalı durumunda ve görünür işaretle. Kalan
  risk: `dev` bayrağı (D-55) ve ad çakışmasıyla yanlış atıf (REQ-004 Riskler).
- **Kaynak tüketimi:** süreç geneli istek semaforu, 2 arşiv iş parçacığı,
  tarama başına 2 GiB, bütçe = süre sınırının en fazla yarısı.
- **Yetki:** yeni uç nokta mevcut `reports:read` ve SBOM erişim denetimini
  kullanır; okuma işlemidir, denetim kaydı gerekmez (D-70).

## Test stratejisi

qa-automation (`tests/**`, `vitest.config.ts`):

- **Ağ koruması (AC-G-2):** `vitest.config.ts` `setupFiles:
  ['tests/setup/networkGuard.ts']`. Kurulum `net.Socket.prototype.connect`,
  `net.connect`/`createConnection`, `tls.connect` ve `dns.lookup`/
  `dns.promises.lookup`'ı sarar; hedef `127.0.0.1`, `::1` veya `localhost`
  değilse hata fırlatır ve testi başarısız yapar (embedded-postgres loopback
  kullanır). Bir test `https://registry.npmjs.org/` isteğinin engellendiğini
  doğrular. Kurulum ayrıca `process.env.REGISTRY_ENRICHMENT ??= 'off'` yapar.
  (İş parçacıkları kurulum dosyasını yüklemez; arşiv iş parçacığı ağ modülü
  içe aktarmadığı için statik içe aktarım testi bunu kapatır.)
- **Sahte kayıt defteri:** `tests/helpers/fakeRegistry.ts`, `127.0.0.1:0`'da
  `node:http` sunucusu; yol bazında yanıt tablosu (npm sürüm dokümanı, scoped
  404 + tam doküman yedeği, PyPI JSON, arşiv baytları), istek sayacı, gecikme,
  `429`/`5xx`/`Retry-After`, yönlendirme, bağlantı kesme, 9 MiB gövde,
  `Content-Length` yalanı. Zenginleştirici `endpoints` ile enjekte edilir.
  Bekleme süreleri enjekte saatle (AC-P14-10).
- **Birim testleri:** `coordinates` (AC-P14-4/5 tabloları), `classifiers`,
  `effectiveLicense` (Karar 11 tablosunun her satırı), `shouldUseProxy`
  (`*`, `.alan`, `*.alan`, etiket sınırı, port, IP, boş öğe, harf),
  `assertAllowedUrl`/`assertInjectableEndpoint`, `integrity` (çoklu SRI, sha512
  yok → shasum), `spdxExpression` (AC-P16-3), `text` (AC-P15-8 fixture'ları),
  `copyright` (AC-P15-9 fixture'ları + 2 MiB tek satır < 1 sn), `outputText`.
- **Arşiv okuyucuları:** `tests/fixtures/archives/` altında elle hazırlanmış
  küçük ikili fixture'lar (`* -text` zaten geçerli): ustar, PAX uzun ad, GNU
  `L`, symlink/hardlink/dizin, `..`/mutlak/sürücü harfi/NUL adlar, bozuk
  sağlama toplamı, base-256 boyut, wheel `dist-info/licenses/` iç içe, stored ve
  deflate zip, şifreli girdi, ZIP64 EOCD, bildirilen/gerçek boyut uyuşmazlığı,
  CRC hatası, kök dışı `node_modules/x/LICENSE`, `License.md`. Bombalar ve
  büyük girdiler (512 MiB açılım, 100 001 girdi, 64 KiB+ PAX, 1 MiB+ dosya,
  4 MiB paket toplamı, 64 MiB+ arşiv) **test sırasında** üretilir; repoya büyük
  dosya konmaz (AC-P15-5).
- **İş parçacığı:** ADR-005 deseniyle `tests/` altındaki düz CommonJS test
  iş parçacığı betikleri (sonsuz döngü → 60 sn sınırı enjekte edilebilir kısa
  değerle, bellek taşması, çökme); sonrasında `/health` `200` ve sonraki arşiv
  işlenir. Arşiv işleme sırasında `fs.writeFile*`/`fs.createWriteStream`/
  `fs.mkdtemp` casusları çağrılmaz, geçici klasör değişmez (AC-P15-4). Statik
  içe aktarım taraması (Karar 1 sınır kuralları).
- **Entegrasyon (embedded-postgres):** AC-P14-7 (1)–(5), AC-P14-8 (geri alınan
  tarama sonrası önbellek), AC-P14-13 (sunucu kapalı, eşik, tek satır),
  AC-P14-14 (küçük süre sınırı + yavaş sunucu), AC-P14-15 (istek sürerken
  kapanış → `queued`), AC-P14-16, AC-L6-1…5, AC-P15-1…3, AC-P15-10, göç `006`
  up → down → up, AC-G-8 regresyonu (zenginleştirme kapalı ve sahte sunucuyla).
- **Çıktılar:** NOTICE golden `tests/fixtures/notice/*.txt` bayt bayt
  (`-text`), iki istekte aynı bayt ve `X-Checksum-SHA256`; contract testleri
  (`tests/helpers/contracts.ts`, mevcutlar değişmeden); `.xlsx` geri okuma
  (AC-P14-18/19); SPDX/CycloneDX JSON ayrıştırma, tag-value enjeksiyon testi
  (AC-P16-4), XML öğe sırası (AC-P16-6), AC-P16-7.
- **Değişmeyenler:** P-10 golden'ları (AC-G-6) ve mevcut contract testleri
  değişiklik yapılmadan yeşil.
- **Elle:** AC-P14-20 ve AC-P16-7 gerçek ağ ölçümleri ana oturumda; varsa
  kurumsal vekil doğrulaması.

## Kanıt (Evidence)

- Repo incelemesi (`f7727f6`): `src/scanner/worker.ts` (`registerJob`,
  `processJob`, `persistResults`, lisans döngüsü), `src/scanner/parsers/
  threadParser.ts`, `src/analysis/vulnerabilityLookup.ts`, `src/lib/bounds.ts`,
  `src/lib/errorText.ts` dışa aktarımları, `src/scanner/sandbox/runner.config.ts`,
  `src/reports/reportService.ts`, `src/sbom/**` dışa aktarımları,
  `db/migrations/001` (`packages`, `scan_dependencies`, `licenses`), `005`,
  `package.json`, `vitest.config.ts`, `tests/fixtures/.gitattributes`.
- `docs/product/REQ-004.md` r1; ADR-002 Ek E3; ADR-004 Karar 7–8; ADR-005
  Karar 1, 5.
- Dış kaynak (genel bilgi, **doğrulanması gerekiyor**): Node `http.Agent`
  `proxyEnv` ve `NODE_USE_ENV_PROXY`/`--use-env-proxy` (v24.5.0, v22.21.0'a geri
  taşıma); `zlib.crc32` (v22.2.0); `zlib` `maxOutputLength`; `worker_threads`
  `resourceLimits`'in `Buffer` (V8 dışı) belleği kapsamaması; npm registry
  scoped sürüm dokümanı ve SRI `dist.integrity`; PyPI JSON API alanları
  (`info.license_expression`, `urls[].digests.sha256`, `packagetype`) ve ad
  yönlendirmesi; tar ustar/PAX/GNU ve zip APPNOTE (EOCD, ZIP64, bayrak bitleri);
  CycloneDX 1.5 XSD bileşen öğe sırası. NotebookLM veya Obsidian kaynağı
  kullanılmadı.

## İlgili REQ / AC

REQ-004: AC-G-1…8, AC-P14-1…20, AC-L6-1…5, AC-P15-1…16, AC-P16-1…7; kararlar
D-53…D-79.

## REQ-004 üzerindeki netleştirmeler

1. **Bütçe (AC-P14-14):** `min(süre sınırı / 2, kalan süre − süre sınırı / 4)`.
2. **Zaman aşımı (AC-P14-10):** `REGISTRY_TIMEOUT_MS` deneme başına toplam
   süredir; arşiv indirmesinde toplam süre en az 60 sn'dir.
3. **Ardışık hata eşiği:** her başarısız ağ denemesi sayılır, herhangi bir HTTP
   yanıtı sıfırlar.
4. **npm bütünlüğü:** `integrity` sha512 öğesi içermiyorsa `shasum` kuralı
   uygulanır.
5. **PyPI adayları:** en fazla 3 aday denenir; geçici indirme/bütünlük hatası
   sıradaki adaya geçirir.
6. **Scoped npm yedeği** yalnız scoped adlarda ve sürüm dokümanı `404`'ünde.
7. **Zip açılımı:** yalnız seçilen lisans dosyası girdileri açılır; "açılmış
   akış toplamı" sınırı yalnız tar.gz içindir (AC-P15-5 ile tutarlı).
8. **İş parçacığı bellek/çökme sonuçları** önbelleğe yazılmaz (AC-P15-10
   listesine eklenir).
9. **`version_unknown`/`invalid_coordinates`** durumlarında lock ipucu
   kullanılmaz (AC-L6-3 listesinin harfiyen uygulanması); zenginleştirme
   kapalıyken bu durumlar `disabled` sayılır.
10. **Zenginleştirici enjekte edilmemişse** (yalnız testler) `[registry]`
    satırı yazılmaz.
11. **`engines.node`** `^22.21.0 || >=24.5.0` (REQ-003 D-46 daralır).
12. **Lock ipucu birleşimi:** birden çok lock lisansı ` AND ` ile birleşik
    saklanır; politika yine öğe bazında değerlendirilir (F2 birebirliği).

## Açık noktalar

Yok. Kullanıcının daimi talimatı gereği tüm seçimler önerilen seçenekle karara
bağlanmıştır. "Doğrulanması gerekiyor" işaretli dış bilgilerin her biri için
tanımlı yedek veya uygulama sırasında teyit adımı vardır (Karar 3, 5, 13).

## REQ-004 güvenlik düzeltmesi (2026-10-10)

> **REQ-004 güvenlik düzeltmesi (2026-10-10).** Güvenlik incelemesi
> (`docs/quality/security-reports/REQ-004-security-review.md`) ve contract
> `docs/contracts/REQ-004-notice-and-outputs.md` 1.1.0 (C-14…C-18) sonrası
> Karar 6–7, 12, 13 ve normalleştirici aşağıdaki kurallarla sıkılaştırılır
> (commit `613295b` contract, `e526d6d` düzeltmeler, `a8b2614` testler;
> yeniden doğrulama `bb3c758`: Go). Bu bir gevşetme değil sertleştirmedir;
> çeliştiği yerde yukarıdaki metnin yerine geçer.
>
> - **Karar 13, SPDX tag-value (L-1; C-14, contract §6.1):** `<text>`/`</text>`
>   kaçışı yalnız çok satırlı bloklarda değil **tek satırlık değerlerde de**
>   uygulanır: değerin her yerindeki `<text>`/`</text>` (harf duyarsız), blok
>   içi kuralla aynı biçimde `&lt;text&gt;`/`&lt;/text&gt;` olur. Kaçış tek
>   satır katlamasından (contract §9 adım 1–3) **sonra** yapılır; böylece biçim
>   karakteri silinerek kurulan diziler de yakalanır.
> - **Karar 13, Excel (L-2; C-15, contract §5.1a):** formül kalkanı (`=`, `+`,
>   `-`, `@`, `\t`, `\r` ile başlayan değere `'` öneki) yalnız yeni `License`/
>   `License Source` hücrelerine değil, **her sayfanın** (`Summary`,
>   `Dependencies`, `Licenses`, `Vulnerabilities`) **her metin hücresine**
>   uygulanır. Sayı hücreleri tipini korur; `{ formula }` hiçbir sayfada
>   kullanılmaz. Tablodaki "Mevcut sütunlar değişmez" ifadesi (ve D-63
>   "`Licenses` sayfası değişmez") artık şu anlamdadır: yapı (sütun adı, sırası,
>   sayısı, satır kümesi) ve içerik anlamı değişmez; tek fark tetikleyici
>   karakterle başlayan değerlere eklenen `'` önekidir. Mevcut sütunlara §9
>   adım 1–3 eklenmez. Sonuç olarak npm scoped adları `'@kapsam/ad` olarak
>   görünür (N-2). Bu, kullanıcının daimi talimatı gereği önerilen seçenek (a)
>   olarak **kabul edilmiştir**; `quotePrefix` stili ve dar `@kapsam/`
>   muafiyeti seçilmedi.
> - **Karar 12, NOTICE belleği (M-1; C-18, contract §3.7):** üretim tek bir
>   `REPEATABLE READ READ ONLY` transaction içinde, yani tek anlık görüntü
>   üzerinden yapılır. Yapı sorguları metin döndürmez. Lisans dosyası ve PyPI
>   meta veri metinleri girdi sırasıyla **50 kayıtlık partiler** hâlinde okunur;
>   64 MiB kesimi gerçekleştikten sonra hiç metin okunmaz. Bellek artık girdi
>   sayısıyla büyümez (üst sınır: yazılmış gövde + bir parti). Çıktı baytları
>   değişmez (golden NOTICE aynı; `NOTICE format: 1` kalır, C-17).
> - **Karar 12–13, Unicode satır ayırıcıları (I-3; C-16, contract §3.6, §9):**
>   tek satırlık alan katlaması `\n` ve `\t`'ye ek olarak U+0085, U+2028 ve
>   U+2029'u da boşluğa çevirir (U+0085 kontrol temizliğinde C1 olarak zaten
>   silinir; listede savunma derinliği için yer alır). Çok satırlı NOTICE
>   metninde bu karakterler korunur, ancak ayraç kalkanı açısından satır sonu
>   sayılır: arkalarından gelen ayraç dizisinin başına da tek boşluk eklenir.
> - **Karar 6–7, arşiv indirme belleği (L-4):** süreç genelinde tek bir
>   **uçuştaki bayt bütçesi (256 MiB)** vardır. Arşiv indirmesi başlamadan önce
>   bilinen boyut kadar rezervasyon yapılır; boyut bilinmiyorsa arşiv başına
>   64 MiB sınırı rezerve edilir. Rezervasyon arşiv iş parçacığı bitene kadar
>   tutulur ve her yolda `finally` ile serbest bırakılır. Bekleyenler FIFO
>   sırasıyla ilerler; bekleme iş ve bütçe sinyaliyle iptal edilebilir. Tek bir
>   istek bütçeyi aşamadığı için tek başına her zaman ilerler (kilitlenme yok).
>   Tarama başına 2 GiB kotası (Karar 6) değişmez ve bütçe alındıktan sonra
>   ayrılır.
> - **Normalleştirici (B-2, L-3; `src/analysis/licenseNormalizer.ts`):**
>   operatör tespiti yalnız boşlukla ayrılmış `AND`/`OR`/`WITH`'i tanır (bölme
>   kuralıyla aynı). Bölünemeyen girdi özyinelemeye geri dönmez, özyinelemesiz
>   atomik normalleştirmeye düşer. Tablo aramaları (risk ve takma ad tabloları,
>   trove tablosu (I-6), CycloneDX kapsam ve NOTICE neden tabloları) yalnız
>   nesnenin kendi anahtarlarına bakar (`Object.hasOwn`); `constructor`,
>   `__proto__` gibi değerler `unknown` olur. B-2, **gerçek ağ duman testinde**
>   bulundu: `GPL-3.0-or-later` gibi `-or-` içeren kimliklerde sonsuz
>   özyineleme oluyor (`RangeError: Maximum call stack size exceeded`), tarama
>   `failed` oluyordu. Hata F1'den beri vardı; F3'teki kayıt defteri lisanslarıyla
>   dışarıdan tetiklenebilir hâle gelmişti. Karar 1'deki "Mevcut eşlemeler
>   değişmez" kuralı geçerlidir: eşleme sonuçları değişmez, yalnız sonlanma ve
>   anahtar araması düzeltilir.
> - **F3 dışında kalan takipler (bu ADR'yi değiştirmez):**
>   - **N-1:** Normalleştiricide F1'den kalma karesel regex (`_normalizeAtomic`
>     sondaki parantez temizliği) ve uzunluğu sınırlanmayan lock lisans
>     girdisi. Çözüm doğrusal tarama veya girdi kesimidir.
>   - **N-3:** NOTICE partisi kayıt sayısı yerine bayt bütçesiyle
>     tanımlanmalıdır. Havuz bağlantısı istek süresince tutulmaktadır; hata
>     yolunda `release(err)` kullanılmalıdır.
>   - **L-5:** Lock `integrity` ile kayıt defteri `dist.integrity` arasındaki
>     uyuşmazlık işaretlenmelidir (F4). İnsan risk kabulü metni handoff'a
>     yazılır.
>
>   N-4 (FIFO baş-hattı bekleme, `grow` aşımı) için değişiklik gerekmez.
> - **Etki:** yeni bağımlılık, göç, yetki veya dış uç nokta değişikliği
>   yoktur; Karar 15 ve 16 değişmez. Excel'deki `'` öneki görünür bir çıktı
>   değişikliğidir; README'de ve handoff'ta belirtilmelidir.
>   `docs/handoffs/REQ-004.md` bu nota, N-2 kararına ve L-5 kabulüne atıfla
>   güncellenmelidir. Karar veren: kullanıcının daimi talimatı (önerilen
>   seçenek), contract 1.1.0 ile aynı dayanak. ADR durumu `Accepted` kalır;
>   kayıt kullanıcının commit'iyle kesinleşir.

## Onay (Approval)

- **Karar veren:** kullanıcı daimi talimatı (önerilen seçenek), 2026-10-10.
  Talimat REQ-004'te kayıtlıdır. Durum `Accepted`. Karar ana oturum aracılığıyla
  iletilmiştir; kullanıcının bu dosyayı gözden geçirip commit etmesi kaydı
  kesinleştirir.
- Bu karar **dış hizmet entegrasyonu** (`registry.npmjs.org`, `pypi.org`,
  `files.pythonhosted.org`), **veri modeli değişikliği** (göç `006`) ve
  güvenilmeyen ikili girdiyi işleyen yeni bir **güvenlik sınırı** (arşiv
  okuyucuları) içerir. `.claude/rules/autonomy-gates.md` ve REQ-004 Notlar
  gereği implementation öncesi: dış hizmet kapısı için insan onayı ve
  `docs/ownership/REQ-004.json` `status: approved`; release öncesi Security Red
  Team incelemesi zorunludur. Yeni runtime bağımlılığı olmadığı için paket
  kurulum onayı gerekmez; `engines` değişikliği manifestte sahibine atanmalıdır.
