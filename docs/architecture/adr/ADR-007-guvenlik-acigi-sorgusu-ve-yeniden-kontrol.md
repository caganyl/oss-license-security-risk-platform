# ADR-007: Güvenlik açığı sorgusu (OSV toplu sorgu, güvenli OSV/NVD istemcisi), günlük yeniden kontrol ve süresi dolan risk kabulleri

- **ADR-ID:** ADR-007
- **Durum:** Accepted
- **Tarih:** 2026-10-10 (taslak ve karar)
- **İlgili:** REQ-005 r1 / P-17, P-18, P-19, L-5, N-1 (51 AC); kararlar D-84…D-108
  (özellikle D-85, D-86, D-87, D-88, D-89, D-90, D-91, D-92, D-94, D-95, D-96,
  D-99, D-100, D-102, D-103, D-104). Dayanaklar: ADR-002 Ek E3 (metin
  arındırma), ADR-003 (c) (güvenlik parmak izi, karar taşıma), ADR-004 Karar 2,
  3, 4, 5, 7, 8 (başlangıç sırası, bozulmuş kip, çit, kapanış, iptal, hata
  sınıfları), ADR-005 Karar 1 (iş parçacığı sınır kuralı), ADR-006 Karar 1, 4,
  5, 10, 11, 14 ve tarihli güvenlik notu (güvenli istemci, vekil, sınırlar,
  devre kesici, bütçe, ağ koruması).
- **Kısmen superseded edilenler:** ADR-003 "`CURRENT_DATE`, DB oturumunun saat
  dilimine göre değerlendirilir" maddesi (Karar 9); ADR-006 Karar 1 "ağ erişimi
  yalnız `registryClient.ts`'tedir" ve Karar 5 `proxy.ts` konumu (Karar 2).
  Her iki ADR'ye tarihli not eklenmiştir.

## Bağlam

Repo üzerinde doğrulanan durum (`c9f37d9`, branch `req-005-f4-guvenlik-aciklari`):

- `src/analysis/vulnerabilityLookup.ts`: `VulnerabilityLookupService` paket
  başına `POST {OSV_API_URL|https://api.osv.dev/v1}/query` (sayfalama
  `next_page_token`, sınırsız), eşzamanlılık `OSV_CONCURRENCY` (aralık
  denetimsiz `Number(...)`), istek başına `setTimeout` zaman aşımı + iş sinyali.
  Yerleşik `fetch`; vekil, izin listesi, boyut sınırı, yeniden deneme yok.
  Hata `console.warn(... error.message)` ile loglanıp paket `[]` sayılıyor
  (sessiz yanlış negatif). NVD: `NVD_API_URL`, `process.env.NVD_API_KEY`
  `apiKey` başlığı, hız sınırı yok. Modül düzeyinde tekil nesne
  (`vulnerabilityLookupService`); ECOSYSTEM_TO_OSV Maven/NuGet/Go/... da içeriyor
  (ayrıştırıcısı olmayan ekosistemler).
- `src/scanner/worker.ts` `persistResults`: zenginleştirmeden sonra, sonuç
  transaction'ından **önce** `lookupDependencies(result.dependencies, signal)`;
  transaction içinde bağımlılık döngüsünde `upsertVulnerability` (katalog
  satırını her seferinde başlık/önem/CVSS ile **üzerine yazar**),
  `openFinding` → `insertFinding` (tarama içi `seen` tekilleştirmesi,
  `findCarriedDecision` ile karar taşıma, `accepted_until >= CURRENT_DATE`),
  `security_findings` (`sla_deadline = new Date() + gün`), sayaçlar. Uyarı
  metni: `parse_errors` satırları + tek `[registry]` satırı, `scanErrorText`
  arındırması, `error_message = COALESCE(error_message, $8)`.
- `src/analysis/findingFingerprint.ts`: güvenlik anahtarı
  `(osvId ?? ghsaId ?? cveId ?? id).toUpperCase()`; kimlikler katalogda
  saklandığı biçimden (COALESCE) alınır.
- `src/enrichment/registryClient.ts`: `node:https` üzerinde güvenli katman
  (sabit uç noktalar, `assertInjectableEndpoint`/`assertAllowedUrl`, yönlendirme
  politikası, akış boyut sınırı, deneme başına zaman aşımı, 2 yeniden deneme +
  `Retry-After` ≤ 30 sn, `err.code` sınıflandırması, oturum başına host devre
  kesicisi, süreç geneli semafor, uçuştaki istek tekilleştirmesi, `proxyEnv`
  vekil ajanı, `RegistryClock` enjeksiyonu). Yalnız `GET` destekler; amaç
  kümesi (`RequestPurpose`) ve uç nokta kümesi (`npm/pypi/files`) sabittir.
  `proxy.ts` (`resolveProxy`, saf `shouldUseProxy`, `nodeSupportsProxyEnv`),
  `budget.ts` (`computeBudgetMs`, bütçe sinyali).
- `src/enrichment/cache.ts`: npm arşiv adayı `{ url, algorithm, digests[] }`
  olarak meta veri önbelleğinde saklanır; `algorithm = 'sha512'` iken
  `digests` kayıt defteri `dist.integrity`'nin tüm sha512 öğeleridir
  (`parseSriSha512`). Ayrıştırıcı lock `integrity` alanını okumuyor.
- `src/runtime.ts`: adım 7'de enricher oluşturulur, `ScanWorker` kurulur,
  yetim tarama/rapor kurtarması, çalışma alanı süpürmesi, polling,
  `state = 'running'`. Kilit kaybında `degraded` (worker'lar duraklar, uçuştaki
  taramalar çitle korunarak sürer), yeniden kilitte `running`; başka örnek
  kilidi aldıysa `shutdown('lock-lost')`. Kapanış adımları 1–9 (taramalar
  `abort('shutdown')`, enricher kapatma, havuz, en son kilit).
- `db/schema.sql`: `finding_status` (`open`, `accepted`, …), `audit_action`
  (`finding_opened`, `finding_updated` var), `scan_trigger` (`scheduled`
  kullanılmıyor), `finding_reviews.reviewer_id NOT NULL`,
  `accepted_until DATE`, `audit_logs.actor_id`/`actor_email` boş olabilir,
  `occurred_at DEFAULT NOW()`. Son göç `006`.
- `src/controllers/workflowController.ts`: kullanıcı geçişleri
  `fetchFindingForUpdate` (satır kilidi) → güncelleme → inceleme → denetim, tek
  transaction. `insertAudit` `actorId` boş kabul eder.
- `tests/helpers/parserGolden.ts`: golden karşılaştırma `dependencies`
  öğelerini anahtar varlığı dahil derin eşitlikle karşılaştırır; bağımlılık
  nesnesine yeni alan eklemek golden'ı kırar.
- `public/app.js`: Dashboard görünümü (`updateStats`, son taramalar);
  `error_message` gösterilmiyor.

## Karar

### 1. Modül yapısı (D-87, D-107; REQ-005 NFR "ortak bileşen")

**Ortak güvenli HTTP çekirdeği çıkarılır; F3 davranışı ve dışa aktarılan API'si
değişmez.** Kopya istemci yazılmaz.

| Dosya | İçerik |
| --- | --- |
| `src/lib/clock.ts` (yeni) | `AppClock { now(): number; sleep(ms, signal): Promise<void> }`, `systemClock`, `localDateString(ms): 'YYYY-MM-DD'` (Karar 9). `RegistryClock` bunun takma adı olur. |
| `src/lib/http/safeHttpClient.ts` (yeni) | `registryClient.ts`'teki çekirdeğin genelleştirilmiş hâli: köken kümesi ve **amaç tablosu** parametre olur (Karar 2). `GET` ve gövdeli `POST`, amaç başına yönlendirme politikası, boyut sınırı, `Accept`, kodlama, ek başlık sağlayıcısı; deneme, `Retry-After`, `err.code` sınıflandırması, oturum başına host devre kesicisi, semafor, uçuştaki tekilleştirme, vekil ajanları, loopback ajanı. |
| `src/lib/http/proxy.ts` (taşınır) | `src/enrichment/proxy.ts`'in içeriği. `src/enrichment/proxy.ts` yeniden dışa aktarır (mevcut içe aktarımlar ve testler değişmez). Saf modül kuralı (ADR-006 Karar 1) yeni konumda aynen geçerli. |
| `src/lib/http/endpoints.ts` (yeni) | `assertInjectableOrigin(value, productionOrigins)` — ADR-006 `assertInjectableEndpoint` mantığı köken kümesi parametreli. |
| `src/enrichment/registryClient.ts` | Çekirdek üzerinde ince adaptör. `PRODUCTION_ENDPOINTS`, `RequestPurpose`, `assertInjectableEndpoint`, `resolveEndpoints`, `assertAllowedUrl`, `parseRetryAfter`, `systemClock`, `createRegistryClient`, `RegistrySession` aynı imza ve davranışla kalır. F3 testleri **değiştirilmeden** yeşil kalmalıdır (çıkarımın kabul ölçütü). |
| `src/vulnerability/endpoints.ts` | OSV/NVD üretim kökenleri, amaç tablosu (`osv-querybatch` POST, `osv-vuln` GET, `nvd-cve` GET), URL kurucuları ve kalıp denetimleri (Karar 3, 6). |
| `src/vulnerability/client.ts` | `createVulnerabilityClient(options)`: çekirdeğin OSV/NVD örneği (kendi semaforu `OSV_CONCURRENCY`, kendi ajanları, `User-Agent` son eki `vulnerability-lookup`). `NVD_API_KEY` yalnız burada, kapanışta tutulur. |
| `src/vulnerability/osvClient.ts` | `querybatch` gönderimi, sayfalama, yanıt doğrulaması; ayrıntı isteği ve kayıt doğrulaması/kırpması (Karar 3, 4). |
| `src/vulnerability/nvdClient.ts` | CVE isteği, CVSS çıkarımı, hız sınırlayıcı kullanımı (Karar 6). |
| `src/vulnerability/rateLimiter.ts` | Süreç geneli kayan pencere sınırlayıcı, enjekte saat, iptal edilebilir bekleme. Saf mantık + `AppClock`. |
| `src/vulnerability/vulnCache.ts` | Göç `007` önbellek tablolarına okuma/yazma (ayrıntı + NVD). Önbellekler için tek `pg` erişim noktası; tarama transaction'ının `client`'ını **kullanmaz**. |
| `src/vulnerability/lookup.ts` | `createVulnerabilityLookup(...)`: tarama ve yeniden kontrolün ortak motoru (tekilleştirme, bütçe, toplu sorgu, ayrıntı, NVD, durum ve özet satırları) (Karar 4, 5). |
| `src/vulnerability/normalize.ts` | `vulnerabilityLookup.ts`'teki saf normalleştirme fonksiyonları (`normalizeOsvVulnerability`, `normalizeLegacyVulnerability`, CVSS/önem yardımcıları) + asgari kayıt (`minimalVulnerability`). |
| `src/vulnerability/findingWriter.ts` | Worker'dan çıkarılan güvenlik bulgusu yazımı: `upsertVulnerability`, `insertFinding` + `findCarriedDecision`, `security_findings` satırı, SLA. Tarama ve yeniden kontrol aynı kodu kullanır (ADR-003 tutarlılığı). |
| `src/vulnerability/summaryLines.ts` | `[osv]`, `[nvd]` satır şablonları ve çalıştırma hata özeti şablonları (değerler contract'ta). |
| `src/vulnerability/recheck.ts` | Tek yeniden kontrol çalıştırması (Karar 7). |
| `src/vulnerability/expiry.ts` | P-19 süre değerlendirmesi (Karar 9). |
| `src/vulnerability/scheduler.ts` | Zamanlayıcı: tetikler, saf `computeNextDue(...)`, tek çalıştırma kilidi, iptal (Karar 8). |
| `src/vulnerability/status.ts` | Durum uç noktasının salt okuma modeli (Karar 10). |
| `src/analysis/vulnerabilityLookup.ts` | Sınıf, tekil nesne, `fetch` ve ortam değişkeni okuması **silinir**. Dosya yalnız `normalize.ts`'i ve `NormalizedVulnerability` tipini yeniden dışa aktaran ince bir uyumluluk modülü olarak kalır. |
| `src/enrichment/lockIntegrity.ts` (yeni, saf) | L-5 karşılaştırması (Karar 12). |
| `src/scanner/parsers/{nodejs,thread,threadParser,index}.ts` | L-5 yan kanalı (Karar 12). Golden'a giren çıktı değişmez. |
| `src/analysis/licenseNormalizer.ts` | N-1 (Karar 13). |
| `src/controllers/vulnerabilityStatusController.ts`, `src/routes/vulnerabilityStatusRoutes.ts`, `src/app.ts` | Durum uç noktası (Karar 10). |
| `src/scanner/sandbox/runner.config.ts` | `vulnerability` bölümü ve `VULNERABILITY_LIMITS` sabitleri (Karar 11). |
| `src/runtime.ts` | İstemci, motor ve zamanlayıcının kablolanması; kilit kaybı ve kapanış (Karar 8, 11). |
| `src/lib/findingStateMachine.ts` | Yalnız "otomatik yeniden açma" yorumu (AC-P19-6); `FINDING_TRANSITIONS` değişmez. |

**Sınır kuralları** (qa-automation statik içe aktarım taramasıyla korur):

- `src/` altında ağ bağlantısı açan tek modül `src/lib/http/safeHttpClient.ts`'tir.
  `fetch(`, `node:http(s)` `request`/`get`, `undici` kullanımı başka hiçbir
  `src/` dosyasında bulunmaz (arşiv iş parçacığı ve ayrıştırıcı iş parçacığı
  kuralları ADR-005/ADR-006'daki gibi aynen geçerli).
- `src/vulnerability/` içinde ağ erişimi yalnız `client.ts` üzerinden; `osvClient.ts`
  ve `nvdClient.ts` oturumu parametre olarak alır.
- `rateLimiter.ts`, `normalize.ts`, `summaryLines.ts`, `lockIntegrity.ts`,
  `computeNextDue` ve `localDateString` saf fonksiyonlardır (yalnız `import type`).
- Hiçbir `src/` dosyası `OSV_API_URL` veya `NVD_API_URL` değerini okumaz; yalnız
  Karar 11'deki ad uyarısı bu adları geçirir (statik test).

### 2. Ortak güvenli HTTP çekirdeği (D-87)

- **Amaç tablosu** (`SafeHttpPurpose`): `{ originKey, method, redirect: 'none' |
  { sameOriginMax: 3 }, maxBytes, accept, acceptEncoding, contentType?,
  pathRule(url): boolean, extraHeaders?(): Record<string,string> }`. Tablo
  istemci oluşturulurken donar; çağıran yalnız amaç adı, URL ve (POST için)
  gövde verir. Başlık nesnesi dışarıdan genişletilemez.
- F3 amaçları (`metadata-npm`, `metadata-pypi`, `archive-npm`,
  `archive-pypi`) bugünkü değerlerle tanımlanır (meta veri: ≤ 3 aynı köken
  yönlendirme, 8 MiB, gzip; arşiv: yönlendirme yok, 64 MiB, identity, akış
  hash'i).
- F4 amaçları (Karar 3, 6):

  | Amaç | Yöntem | Köken | Yol kuralı | Yönlendirme | Sınır |
  | --- | --- | --- | --- | --- | --- |
  | `osv-querybatch` | POST | `https://api.osv.dev` | tam olarak `/v1/querybatch`, sorgu yok | yok (3xx → hata) | 16 MiB |
  | `osv-vuln` | GET | `https://api.osv.dev` | `/v1/vulns/<tek bileşen>`, sorgu yok | yok | 8 MiB |
  | `nvd-cve` | GET | `https://services.nvd.nist.gov` | tam olarak `/rest/json/cves/2.0`, sorgu yalnız `cveId=<CVE kalıbı>` | yok | 2 MiB |

- **Başlıklar:** `User-Agent: oss-risk-platform/<sürüm> (vulnerability-lookup)`
  (F3 ile aynı biçim), `Accept: application/json`, `Accept-Encoding: gzip`,
  POST'ta `Content-Type: application/json`. Çerez, `Authorization` yok.
  `apiKey` yalnız `nvd-cve` amacının `extraHeaders`'ı ile ve yalnız
  `NVD_API_KEY` tanımlıysa eklenir. Çekirdek, `extraHeaders` sonucunu
  **yalnız** o amacın izinli kökenine giden isteğe ekler (köken denetimi
  başlık eklemeden önce yapılır); loopback test kökeninde de aynı amaç
  kuralı geçerlidir.
- **POST gövdesi:** `Buffer` olarak önceden serileştirilir, `Content-Length`
  ile gönderilir; yeniden denemede aynı tampon kullanılır. `querybatch` salt
  okuma bir sorgudur; 429/5xx/ağ hatasında yeniden denenir.
- **Deneme, sınıflandırma, devre kesici, vekil, TLS:** ADR-006 Karar 4–5 ve
  tarihli notla birebir (2 yeniden deneme 1 sn/2 sn, `Retry-After` ≤ 30 sn ise
  `max(geri çekilme, Retry-After)`, daha uzun/ayrıştırılamaz → o istek için
  bırak; yalnız `err.code`; her HTTP yanıtı sayacı sıfırlar, 5 ardışık ağ
  düzeyi başarısız deneme hostu oturum için kapatır; vekil kararı
  `shouldUseProxy`, geçersiz vekil veya `proxyEnv`'siz Node'da hiç bağlantı
  yok, kod `PROXY_UNAVAILABLE`; `rejectUnauthorized` asla kapatılmaz).
  Bekleme süreleri `AppClock.sleep` ile, iş/bütçe sinyaliyle iptal edilebilir.
- **Oturum:** tarama başına ve yeniden kontrol çalıştırması başına bir oturum
  (`session()`); devre kesici oturum kapsamındadır (AC-P17-10).
- **Ayrı örnekler:** kayıt defteri ve güvenlik açığı istemcileri çekirdeğin
  **ayrı örnekleridir** (ayrı semafor, ajan, uçuştaki harita). Böylece
  `REGISTRY_CONCURRENCY` ve `OSV_CONCURRENCY` birbirini etkilemez ve F3
  davranışı değişmez.
- **Test enjeksiyonu (D-88):** `createVulnerabilityClient({ endpoints: { osv?,
  nvd? } })` yalnız koddan; `assertInjectableOrigin` değeri üretim kökeni veya
  `http://127.0.0.1:<port>` / `http://[::1]:<port>` (yol, sorgu, kullanıcı
  bilgisi yok) olarak kabul eder, aksi `throw`. `runtime.ts` bu parametreyi
  hiçbir zaman vermez; ortamdan okuyan yol yoktur. Loopback'te vekil yok.

### 3. OSV toplu sorgu akışı (D-85, D-89)

**Aday kümesi** (tarama ve yeniden kontrol aynı): ekosistemi `nodejs`/`python`
olan, sürümü kesin olan (bugünkü `isExactVersion`) ve ADR-006 `coordinates.ts`
ad/sürüm doğrulamasından (AC-P14-4) geçen bağımlılıklar. Anahtar
`(ekosistem, istek adı, sürüm)` (`enrichmentKeyOf` ile aynı). Diğer
ekosistemler sorgulanmaz (bugün ayrıştırıcıları yoktur; davranış değişikliği
fiilen yoktur).

**OSV gövdesindeki ad:** npm için **ham paket adı** (`@kapsam/ad`, URL
kodlaması yok — JSON gövdesidir), PyPI için PEP 503 normalleştirilmiş ad,
`ecosystem` `npm` / `PyPI`. (`%2F` biçimindeki istek adı yalnız tekilleştirme
anahtarında kalır; bkz. REQ-005 netleştirmesi 1.)

**Gönderim:**

1. Anahtarlar kod noktası sırasıyla `(ekosistem, ad, sürüm)` sıralanır
   (`localeCompare` değil). Gövde belirlenimcidir:
   `{"queries":[{"package":{"ecosystem","name"},"version"}, …]}`.
2. `VULNERABILITY_LIMITS.osvBatchMax = 1000` sorguluk partiler **sırayla**
   gönderilir (aynı anda tek toplu istek).
3. **Yanıt doğrulaması (AC-P17-4):** kök nesne; `results` dizi ve uzunluğu
   gönderilen sorgu sayısına eşit; her öğe nesne; `vulns` yok veya dizi; her
   vuln nesne, `id` metin ve `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`;
   `modified` yok veya ISO 8601 olarak ayrıştırılabilir metin;
   `next_page_token` yok veya 1–1024 karakter yazdırılabilir ASCII. Kök
   düzeyde bozukluk → o partideki tüm paketler "kontrol edilemedi". Öğe
   düzeyinde kalıp dışı kimlik → kimlik atılır, paket "kontrol edilemedi"
   sayılır ama aynı paketin geçerli kimlikleri yine işlenir (bulgu gizlemek
   yerine açmak). Bir sonuçta en fazla 1000 vuln; fazlası → paket "kontrol
   edilemedi" (ilk 1000 işlenir).
4. **Sayfalama (AC-P17-3):** `next_page_token` taşıyan sonuçların sorguları
   `page_token` ile **yalnız onlardan oluşan** yeni toplu isteklerde (yine
   ≤ 1000) gönderilir. Paket başına sayfa sayacı; 10. sayfadan sonra hâlâ token
   varsa paket "kontrol edilemedi" (toplanan kimlikler yine işlenir).
5. Bir partinin isteği başarısızsa (`unreachable`/`error`, devre kesici,
   bütçe) partideki tüm paketler "kontrol edilemedi". Kalan partiler denenmeye
   devam eder (devre kapandıysa istek yapılmadan "kontrol edilemedi").

**Sonuç modeli** (anahtar başına): `{ state: 'checked', ids: Map<id, modified|null> }`
veya `{ state: 'unchecked', ids }`. "Açık yok" yalnız `checked` + boş kümeden
türer; `unchecked` için hiçbir yerde "temiz" sonucu saklanmaz veya raporlanmaz.

**Doğrulanması gerekiyor (dış bilgi, güven orta-yüksek):** `querybatch`
yanıtının vuln başına yalnız `id` ve `modified` döndürmesi, sorgu başına
`next_page_token`, 1000 sorgu sınırı, PyPI adlarının OSV tarafında PEP 503 ile
eşleşmesi. **Tanımlı yedekler:** (a) sınır daha düşükse `osvBatchMax` sabiti
düşürülür (≥ 200 kaldıkça AC-P17-2 korunur); (b) yanıt tam kayıt döndürürse
fazladan alanlar yok sayılır, akış değişmez; (c) `modified` hiç dönmezse
önbellekte kaydı olan kimlik için ayrıntı istenmez, olmayan için istenir.
Gerçek davranış AC-P18-14 sırasında gözlenip handoff'a yazılır.

### 4. Ayrıntı alma, ayrıntı önbelleği, asgari kayıt (D-86, D-89, D-93)

- **Önbellek yeri: ayrı tablo `osv_vulnerability_cache`** (Karar 14). Mevcut
  `vulnerabilities` kataloğu kullanılmaz: tarama transaction'ında yazılır ve
  geri alınır (AC-P17-5 bağımsızlık şartını karşılamaz), UUID ve takma ad
  birleştirmesiyle anahtarlanır.
- **Ne zaman istenir:** toplu yanıtta dönen her farklı kimlik için önbellek tek
  sorguyla toplu okunur (`osv_id = ANY($1)`). Kayıt yok, `extractor_version`
  eski veya toplu yanıttaki `modified` > saklanan `modified` ise
  `GET /v1/vulns/<encodeURIComponent(id)>` (kalıp zaten `/` ve `..`'yı dışlar).
  Çalıştırma içinde kimlik başına en fazla bir istek: motor düzeyinde
  `Map<id, Promise>` + çekirdeğin uçuştaki tekilleştirmesi (`osv-vuln:<id>`).
  Eşzamanlılık `OSV_CONCURRENCY`.
- **Kayıt doğrulaması ve kırpma:** yanıt nesne; `id` istenen kimlikle aynı (harf
  duyarlı); alan tipleri tutmazsa → ayrıntı alınamadı (önbelleğe yazılmaz).
  Saklanan kayıt yalnız kullanılan alanlardır, metinler ADR-006 Karar 8
  `sanitizeText` ile temizlenir: `id`, `aliases` (≤ 64, her biri kimlik
  kalıbında), `summary` (≤ 1000 kod noktası), `details` (≤ 64 KiB),
  `severity` (≤ 8 öğe, `type`/`score` ≤ 256), `affected` (≤ 256 öğe; her
  öğede `package`, `ranges` ≤ 16 × `events` ≤ 64, `versions` ≤ 1000),
  `references` (≤ 64, yalnız `https:` URL'ler, ≤ 2048), `published`,
  `modified`, `withdrawn`. `database_specific` ve diğer alanlar saklanmaz.
  `NORMALIZED_RECORD_VERSION = 1` (`vulnCache.ts`); kırpma kuralı değişirse
  artırılır.
- Önbellek yazımı ayrıntı alındığı anda, tarama transaction'ından bağımsız
  (`INSERT … ON CONFLICT (osv_id) DO UPDATE`), tarama geri alınsa da kalır.
  Yazım hatası yalnız o kaydın yazılmamasıdır; bellekteki kayıt kullanılır.
- **404:** "kayıt yok" → ayrıntı eksik (negatif önbellek yok).
- **Asgari kayıt (AC-P17-11):** ayrıntısı alınamayan kimlik için önce
  önbellekteki **eski** kayıt varsa o kullanılır; yoksa
  `minimalVulnerability(id, dep)`: başlık = kimlik, açıklama boş, önem
  `medium`, CVSS boş, `sourceUrl = https://osv.dev/vulnerability/<id>`,
  kimlik türü önekten (`CVE-`, `GHSA-`, diğer → OSV), `advisoryData =
  { id, modified, detail_missing: true }`. Her iki durumda kimlik "ayrıntı
  eksik" sayılır (durum `partial`).
- **Katalog koruması:** asgari kayıt `upsertVulnerability`'de **mevcut katalog
  satırını güncellemez** (yalnız arama; satır yoksa ekler). Eski önbellek
  kaydı veya tam kayıt bugünkü güncelleme kuralıyla yazar. Böylece eksik
  ayrıntı daha önce bilinen başlık/önem/CVSS'i bozmaz.
- **Parmak izi:** asgari kayıt da aynı `upsertVulnerability` aramasından
  (kimlik + takma adlar) geçer ve parmak izi katalogda saklanan kimliklerden
  hesaplanır (bugünkü kural). Katalogda veya önbellekte kaydı hiç olmayan,
  birincil kimliği `CVE-` olan ve tam kaydında GHSA takma adı bulunan bir açık
  için asgari kaydın anahtarı (`CVE-…`) sonraki tam kaydın anahtarından
  (`GHSA-…`) farklı olabilir; bu kalıntı risktir (bkz. netleştirme 2).
  npm/PyPI için OSV birincil kimlikleri pratikte `GHSA-`/`PYSEC-`/`MAL-`
  olduğundan anahtar aynıdır.
- **Geri çekilen (AC-P17-6):** `withdrawn` dolu tam kayıttan yeni bulgu açılmaz
  (tarama ve yeniden kontrol). Asgari kayıtta `withdrawn` bilinemez; bulgu
  açılır (güvenli taraf).
- `vulnerabilities.advisory_data` bundan sonra ham OSV gövdesi yerine kırpılmış
  kaydı saklar (JSONB içeriği; API şeması değişmez, AC-G-4).

### 5. Taramadaki yer, bütçe, iptal, durum ve özet satırları (D-89, D-91, D-92)

- **Sıra** (`processJob`): kaynak → ayrıştırıcı → zenginleştirme (değişmez) →
  **güvenlik açığı sorgusu** → sonuç transaction'ı. Sorgu transaction dışıdır.
- `ScanWorkerDeps`'e `vulnerabilityLookup: VulnerabilityLookup | null` ve
  `clock?: AppClock` eklenir. `runtime.ts` motoru **her zaman** verir (açık
  veya kapalı kipte); `null` (yalnız testler, `saveScanResults`) iken sorgu
  hiç yapılmaz, `vulnerability_data_status` `NULL` kalır, `[osv]`/`[nvd]`
  satırı yazılmaz → F3 birebirliği (AC-G-8, REQ-004 D-82 deseni).
- **Bütçe (AC-P17-14):**

  ```
  timeoutMs = scan.timeout_minutes * 60_000
  vulnBudgetMs = min(timeoutMs / 4, (job.deadlineMs - now) - timeoutMs / 8)
  ```

  `≤ 0` ise istek yapılmaz; tüm adaylar "kontrol edilemedi". Zenginleştirme
  bütçesi (ADR-006 Karar 2) en az `timeoutMs/4` bıraktığı için sonuç yazımına
  her durumda en az `timeoutMs/8` kalır. Sinyal:
  `AbortSignal.any([jobSignal, budgetSignal])` (`createBudgetSignal`
  yeniden kullanılır). Bütçe NVD hız sınırı beklemelerini de kapsar.
- **İptal:** `jobSignal` iptali (`timeout`/`shutdown`) yeniden fırlatılır,
  ADR-004 Karar 8'e göre sınıflandırılır (kapanışta `queued`); bütçe iptali
  yutulur: kalan OSV sorguları "kontrol edilemedi", kalan NVD istekleri "CVSS
  alınamadı" olur ve tarama sonuç yazımına geçer.
- **Hata yalıtımı:** `lookup` çağrısı `try/catch` içindedir; `jobSignal` iptali
  dışındaki her hata (kod hatası, önbellek `pg` hatası) sınıf/kod düzeyinde
  loglanır, tüm adaylar "kontrol edilemedi" olur, tarama sürer. Sorgu hiçbir
  koşulda `handleScanFailure`'a ulaşmaz ve yeniden denemeye yol açmaz.
- **NVD sırası:** OSV kayıtları normalleştirildikten sonra, CVE kimliği olan ve
  CVSS'i olmayan açıklar için önce NVD önbelleği toplu okunur, ıskalayanlar
  Karar 6'ya göre istenir.
- **Durum** (`scans.vulnerability_data_status`, sonuç transaction'ında yazılır;
  `vulnerability_checked_at` = sorgunun başladığı an, enjekte saat):
  - `disabled`: `VULNERABILITY_LOOKUP=off`;
  - aday yoksa `complete`;
  - hiçbir aday `checked` değilse `unavailable`;
  - en az bir aday `unchecked` veya en az bir kimlik "ayrıntı eksik" ise
    `partial`;
  - aksi `complete`.
  NVD başarısızlığı durumu etkilemez (D-90).
- **Satırlar** (`summaryLines.ts`): durum `complete` değilse tek `[osv]` satırı
  (kontrol edilemeyen paket sayısı + ayrıntısı eksik kimlik sayısı; kapalıyken
  sabit "vulnerability lookup disabled" metni), CVSS alınamayan açık varsa tek
  `[nvd]` satırı (sayı). Sıra: `parse_errors` satırları → `[registry]` →
  `[osv]` → `[nvd]`; tamamı tek `scanErrorText` arındırmasından geçer. Paket
  adı, URL, hata mesajı içermez. Kesin metinler REQ-005 contract'ındadır.
- **Bulgular:** tarama döngüsü bugünkü gibidir; `findingWriter.ts`'e taşınan
  kodla yazılır. Parmak izi formülü, tarama içi tekilleştirme ve sayaçlar
  değişmez.

### 6. NVD istemcisi, hız sınırı ve CVSS önbelleği (D-90)

- İstek yalnız `cveId` `^CVE-\d{4}-\d{4,}$` kalıbına uyan, OSV kaydında CVSS
  puanı olmayan açık için (bugünkü kural); `NVD_ENABLED=false` iken hiç.
- **Hız sınırlayıcı** (`rateLimiter.ts`): süreç genelinde tek örnek (istemciyle
  birlikte oluşturulur; tarama ve yeniden kontrol paylaşır). Kayan pencere
  30 000 ms; `NVD_API_KEY` yokken 5, varken 50 **deneme başlangıcı**. Her
  deneme (yeniden denemeler dahil) bir yuva tüketir. Bekleme
  `clock.sleep(oldest + window - now, signal)`, iş/bütçe/kapanış sinyaliyle
  iptal edilebilir; FIFO. NVD istekleri sırayla yapılır (eşzamanlılık 1).
- `429` + `Retry-After` ≤ 30 sn uygulanır (Karar 2); hız sınırı penceresiyle
  birlikte en uzun bekleme geçerlidir.
- **Önbellek** `nvd_cvss_cache` (Karar 14): `found` 7 gün, `no_cvss` 24 saat;
  geçerlilik `expires_at > $now` (enjekte saat). Geçici hata (ağ, 429, 5xx,
  bütçe, devre kesici, bozuk yanıt) saklanmaz. Yanıt doğrulaması: kök nesne,
  `vulnerabilities` dizi; ilk öğenin `cve.metrics` alanından V4.0 → V3.1 →
  V3.0 → V2 sırası (bugünkü kural); `baseScore` 0–10 sayı, `vectorString` ≤ 256
  ve kontrol karakteri yok. `vulnerabilities` boş dizi veya metrik yok →
  `no_cvss`.
- `advisoryData.nvd` artık ham NVD `cve` nesnesi değil, yalnız
  `{ cvssScore, cvssVector, cvssVersion, baseSeverity }` saklar (güvenilmeyen
  büyük gövde kataloga girmez).
- `NVD_API_KEY` istemci oluşturulurken bir kez okunur, kapanışta tutulur;
  hiçbir log, `error_message`, denetim kaydı, API yanıtı, hata nesnesi veya
  önbellek satırına yazılmaz. Hata yollarında yalnız `err.code` kullanıldığı
  için başlık değeri mesaja sızamaz.
- **Doğrulanması gerekiyor:** NVD yayımlanmış kuralı (anahtarsız 5, anahtarlı
  50 istek / kayan 30 sn). Değerler `VULNERABILITY_LIMITS`'te tek yerdedir.

### 7. Yeniden kontrol çalıştırması (D-95, D-96)

`recheck.ts` `runRecheck({ runId, signal, now })`:

1. **Çalıştırma kaydı:** `INSERT INTO vulnerability_recheck_runs (runtime_run_id,
   status, started_at) VALUES ($rid, 'running', $now)`. Tekil kısmi indeks
   ikinci `running` satırını reddeder (eşzamanlı tetik → `23505` → çalıştırma
   başlatılmaz).
2. **P-19:** `expiry.evaluate(now)` (Karar 9); yeniden açılan sayısı kayda
   yazılır.
3. **Kapsam (AC-P18-3):** `SELECT DISTINCT ON (project_id) id, project_id,
   completed_at FROM scans WHERE status = 'completed' ORDER BY project_id,
   completed_at DESC, id DESC`. Bu taramaların aday bağımlılıkları (Karar 3
   kuralı, runtime ve `dev`) `scan_dependencies ⨝ packages` ile okunur; tarama
   başına anahtar kümesi bellekte tutulur. Projeler arası tekilleştirme;
   belirlenimci sıra; ilk 10 000 anahtar sorgulanır, fazlası "kontrol
   edilemedi". Okumalar tek bağlantıyla yapılır ve bağlantı **bırakılır**.
4. **Sorgu:** Karar 3–6 motoru, çalıştırma oturumuyla. Sinyal
   `AbortSignal.any([runSignal, timeout(30 dk)])`; süre dolunca kalanlar
   "kontrol edilemedi" (çalıştırma `partial`). Ağ beklenirken veritabanı
   bağlantısı tutulmaz (AC-P18-6).
5. **Proje başına yazım** (her biri ayrı transaction, aynı anda tek bağlantı):
   1. `SELECT id FROM vulnerability_recheck_runs WHERE id = $run AND status =
      'running' AND runtime_run_id = $rid FOR UPDATE` — satır yoksa
      (başlangıç süpürmesi veya başka örnek tarafından `interrupted`
      yapılmış) yazım durur, çalıştırma biter (**çit**).
   2. `SELECT … FROM scans WHERE id = $scan AND status = 'completed' FOR UPDATE`
      ve `NOT EXISTS (SELECT 1 FROM scans WHERE project_id = $p AND status =
      'completed' AND (completed_at, id) > ($c, $scan))` — daha yeni
      tamamlanmış tarama varsa veya tarama silinmişse proje atlanır (yeni
      tarama güncel veriyi içerir).
   3. Bu taramanın `scan_dependencies` satırları `created_at, id` sırasıyla
      (tarama yazım sırası) dolaşılır; `checked` anahtarların her geçerli
      (geri çekilmemiş) açığı için: `upsertVulnerability` (katalog bugünkü
      kuralla güncellenir; Karar 4 korumasıyla), parmak izi (ADR-003 c, aynı
      fonksiyon), `seen` kümesi **bu taramanın mevcut parmak izleriyle**
      başlatılır (`SELECT fingerprint FROM findings WHERE scan_id = $scan`),
      böylece aynı taramada aynı parmak izli bulgu varsa açılmaz.
      `insertFinding` aynı karar taşıma kuralıyla (Karar 9 "bugün" tanımı);
      `findings.recheck_run_id = $run`; `security_findings` SLA'sı enjekte
      saatin `now`'ından.
   4. Her yeni bulgu için `audit_logs` satırı: `action = 'finding_opened'`,
      `actor_id`/`actor_email` boş, `entity_type = 'finding'`, `entity_id`,
      `new_data = { source: 'vulnerability_recheck', recheck_run_id, scan_id,
      finding_id, fingerprint, vulnerability_id, status }`, `occurred_at =
      $now`. (Taramanın kendi bulgularında denetim davranışı değişmez.)
   5. Tarama sayaçları artırılır: `total_vulnerabilities += n`, önem derecesine
      göre `critical/high/medium/low_vulns += …` (tarama döngüsüyle aynı
      kural; `none` yalnız toplamı artırır). `error_message` değişmez.
   6. **Durum (AC-P18-7):** taramanın tüm aday anahtarları bu çalıştırmada
      `checked` ve ilgili kimliklerin hiçbiri "ayrıntı eksik" değilse
      `vulnerability_data_status = 'complete'`, `vulnerability_checked_at =
      $now`. Aksi hâlde: en az bir anahtar `checked` ise `unavailable`/`NULL`/
      `disabled` → `partial`; `partial` kalır; `complete` hiçbir zaman
      düşürülmez. Hiç `checked` yoksa durum değişmez (AC-P18-9).
   7. `COMMIT`. Proje transaction'ındaki veritabanı hatası yalnız o projeyi
      geri alır, sınıf/kod loglanır, çalıştırma `partial` olur ve sonraki
      projeye geçilir. `runSignal` iptali `COMMIT`'ten önce denetlenir;
      iptalde `ROLLBACK`.
6. **Bitiş:** `UPDATE vulnerability_recheck_runs SET status, finished_at,
   sayaçlar, error_summary WHERE id = $run AND status = 'running' AND
   runtime_run_id = $rid`. Durum: `failed` = aday vardı ve hiçbir toplu istek
   başarılı olmadı; `partial` = en az bir anahtar "kontrol edilemedi", 10 000
   sınırı, süre sınırı veya proje yazım hatası; `completed` = aksi (aday yoksa
   da). İptal → `interrupted`. `error_summary`: sabit şablonlu kod listesi
   (ör. `osv:unreachable`, `osv:budget`, `db:<SQLSTATE sınıfı>`), ≤ 500 kod
   noktası, ADR-002 Ek E3 arındırması; paket adı, URL, sır yok.
7. **Özet log satırı:** tek satır, sayılar ve durum; paket adı yok.

Yeniden kontrolde hiçbir bulgu silinmez, kapatılmaz veya anlık görüntüsü
güncellenmez (D-96); yeni tarama satırı oluşmaz (`scan_trigger` değişmez).

### 8. Zamanlayıcı ve çalışma zamanına yerleşim (D-94, D-98)

- **Konum:** `runtime.ts` adım 7'de, yetim tarama/rapor kurtarması ve çalışma
  alanı süpürmesinden **sonra**, polling başlarken
  `scheduler.start()` çağrılır. Zamanlayıcı yalnız tek örnek kilidini tutan
  süreçte bulunur (kilit alınmadan adım 7'ye gelinmez, ADR-004 Karar 2).
- **Başlangıç süpürmesi:** `start()` önce `UPDATE vulnerability_recheck_runs
  SET status = 'interrupted', finished_at = $now WHERE status = 'running'`
  (kilit tutulduğu için bu satırlar ölü bir sürecindir).
- **Tetikler** (`setTimeout` zinciri, `unref` edilmez, kapanışta temizlenir):
  - **Süre değerlendirmesi (P-19):** başlangıçta hemen (süpürmeden sonra), sonra
    her 60 dakikada bir, ayrıca her yeniden kontrolün başında. Ayardan
    bağımsız; kapatılamaz.
  - **Yeniden kontrol kontrolü:** başlangıçtan 60 sn sonra ilk kontrol
    (AC-P18-2 "≤ 2 dk"), sonra her 10 dakikada bir.
- **Tetik koşulları:** `runtime.state === 'running'` (bozulmuş kipte ve
  kapanışta yeni çalıştırma/değerlendirme yok); süreçte uçuşta çalıştırma yok
  (bellek bayrağı + Karar 7 tekil indeksi); `VULNERABILITY_RECHECK=on`.
- **Vade hesabı** (saf `computeNextDue(runs, now, settings)`; tüm zamanlar
  enjekte saatten):
  - `lastOk` = durumu `completed`, `partial` veya `disabled` olan en son
    kaydın `started_at`'i → vade `lastOk + interval`. Kayıt yoksa vade = şimdi.
  - `lastFailed` = `lastOk`'tan sonra başlayan en son `failed` kayıt → vade en
    erken `lastFailed.finished_at + 1 sa`.
  - `interrupted` kayıtlar vadeyi etkilemez (yeniden başlatma sonrası tek telafi).
  - Kaçırılan günler için tek çalıştırma yapılır (yalnız "vade geçti mi").
- **`VULNERABILITY_LOOKUP=off`:** vade gelmişse ağ isteği yapılmadan
  `status = 'disabled'`, `started_at = finished_at = now` olan tek kayıt
  yazılır (`disabled` vadeyi ilerlettiği için aralık başına en fazla bir).
  Süre değerlendirmesi yine çalışır.
- **`VULNERABILITY_RECHECK=off`:** kayıt yazılmaz, ağ isteği yok; süre
  değerlendirmesi sürer.
- **Kilit kaybı (ADR-004 Karar 3):** `onLockLost` → `scheduler.pause()`:
  yeni tetik yok ve **uçuştaki çalıştırma `abort('lock-lost')` ile iptal
  edilir** (taramalardan farklı olarak: çalıştırma ucuz ve tekrarlanabilir,
  bozulmuş kipte başka örneğin kilidi alması mümkündür). İptal edilen
  çalıştırma bitiş yazımını en iyi çabayla dener (`interrupted`); veritabanı
  yoksa satır `running` kalır ve sonraki başlangıç süpürmesi veya çit onu
  etkisiz kılar. Yeniden kilitte `resume()`: tetikler kaldığı yerden sürer.
- **Kapanış (ADR-004 Karar 5) yeni adım 4a:** taramalar iptal edildikten sonra
  `await scheduler.stop()` — zamanlayıcılar temizlenir, uçuştaki çalıştırma
  ve süre değerlendirmesi `abort('shutdown')` ile iptal edilir ve kalan
  kapanış bütçesi içinde beklenir (açık proje transaction'ı `ROLLBACK`,
  kayıt `interrupted`). Sonra güvenlik açığı istemcisi kapatılır (soketler),
  ardından mevcut adım 5–9. Kilit yine en son bırakılır.
- **Test enjeksiyonu:** `RuntimeOptions.vulnerabilityScheduler?: null |
  SchedulerOptions` (yalnız testler; `null` = oluşturma). Üretim girişi bu
  alanı hiçbir zaman vermez (statik test). Zamanlayıcı testleri gerçek zamanlayıcı
  beklemeden `scheduler.tick()`/`scheduler.expiryTick()` çağırır.

### 9. P-19 süre değerlendirmesi ve "bugün" (D-99, D-100, D-101)

- **"Bugün":** `localDateString(clock.now())` — sürecin yerel saat dilimindeki
  (Windows saat dilimi; Node `Date` yerel alıcıları) takvim tarihi,
  `YYYY-MM-DD`. SQL'e `$today::date` parametresi olarak verilir; `CURRENT_DATE`
  ve veritabanı oturum saat dilimi kullanılmaz. **Tarama sırasındaki
  `findCarriedDecision` da `accepted_until >= $today::date` kullanır**
  (ADR-003'ün `CURRENT_DATE` maddesi bu kadar superseded). Yaz saati
  geçişleri tarih karşılaştırmasını etkilemez.
- **Değerlendirme** (`expiry.evaluate(now)`, tek bağlantı, partiler):

  ```sql
  BEGIN;
  SELECT f.id, f.status FROM findings f
   WHERE f.status = 'accepted' AND f.id > $cursor
   ORDER BY f.id LIMIT 500
   FOR UPDATE SKIP LOCKED;
  SELECT DISTINCT ON (r.finding_id) r.finding_id, r.id, r.accepted_until
    FROM finding_reviews r
   WHERE r.finding_id = ANY($ids) AND r.decision = 'accept_risk'
   ORDER BY r.finding_id, r.created_at DESC, r.id DESC;
  -- süresi dolmuş: inceleme yok, accepted_until NULL veya accepted_until < $today
  UPDATE findings SET status = 'open', updated_at = NOW()
   WHERE id = ANY($expired) AND status = 'accepted';
  INSERT INTO audit_logs (action, actor_id, actor_email, entity_type, entity_id,
                          old_data, new_data, occurred_at) …;  -- satır başına
  COMMIT;
  ```

  Koşul satır kilidi altında okunur; kullanıcının eşzamanlı geçişi
  (`workflowController` aynı satırı `FOR UPDATE` ile kilitler ve incelemeyi
  aynı transaction'da yazar) ya önce biter (yeni `accept_risk` görülür, bulgu
  açılmaz; `reopen` sonrası durum `accepted` değildir, satır seçilmez) ya da
  `SKIP LOCKED` ile bu turda atlanır ve sonraki tetikte değerlendirilir.
  Anahtar kümesi imleciyle (`id`) parti parti ilerlenir; parti < 500 olunca
  biter. İkinci çalıştırma hiçbir satırı değiştirmez (yalnız `accepted`
  seçilir ve geçiş koşulludur).
- **Denetim (AC-P19-4):** `action = 'finding_updated'`, `actor_id`/`actor_email`
  boş, `entity_type = 'finding'`, `old_data = { status: 'accepted' }`,
  `new_data = { status: 'open', reason: 'risk_acceptance_expired',
  review_id | null, accepted_until: 'YYYY-MM-DD' | null, evaluated_for: $today }`,
  `occurred_at = $now` (enjekte saat). `finding_reviews` satırı yazılmaz;
  `assignee_id`, incelemeler ve yorumlar değişmez. Kesin JSON şekli REQ-005
  contract'ında sabitlenir.
- **Karar taşıma tutarlılığı:** yeniden açılan bulgu `open` olduğu için sonraki
  taramalar ve yeniden kontrol kararı taşımaz (ADR-003 tablosu); tarama
  sırasındaki kontrol de aynı "bugün" ile süresi geçmiş kabulü taşımaz. Bir
  taramanın taşıdığı kabul, kaynağı ile aynı `accepted_until`'ı kopyaladığı
  için aynı gün süresi dolar.
- **Hata (AC-P19-8):** parti hatası → `ROLLBACK`, sınıf/kod logu, değerlendirme
  o tetikte durur, süreç `running` kalır, sonraki tetikte yeniden denenir.
- **Son değerlendirme zamanı:** bellekte tutulur (`lastEvaluatedAt`); süreç
  başlangıcında saniyeler içinde değerlendirme yapıldığı için kalıcı saklama
  gerekmez. Durum uç noktası değerlendirme henüz bitmediyse `null` döner.
- Değerlendirme ve yeniden kontrol aynı süreç içi kilidi (mutex) paylaşır;
  çakışırsa ikinci çağrı ilkini bekler.

### 10. Durum uç noktası ve Dashboard paneli (D-97)

- **Uç nokta:** `GET /api/vulnerability-data/status` (öneri; kesin yol, şema ve
  örnekler contract-broker'ın `docs/contracts/REQ-005-*` dokümanındadır),
  `guard('scans:read')`. Salt okuma: tek `REPEATABLE READ READ ONLY`
  transaction, ağ yok, yazım yok.
- **Alanlar (asgari):**
  - `settings`: `lookup_enabled`, `recheck_enabled`, `interval_hours`,
    `nvd_enabled` (anahtarın varlığı dahil sır türevi bilgi yok);
  - `last_run`: Karar 7 kaydının alanları (`id`, `status`, `started_at`,
    `finished_at`, `projects_checked`, `packages_checked`,
    `packages_unchecked`, `findings_opened`, `acceptances_reopened`,
    `error_summary`) veya `null`;
  - `next_check_earliest_at` (`computeNextDue` sonucu; kapalıysa `null`);
  - `projects[]`: `project_id`, `project_name`, `latest_scan_id`,
    `vulnerability_data_status` (`null` = F4 öncesi), `vulnerability_checked_at`;
    proje görünürlüğü `GET /api/scans` ile aynı kuraldır; ad sırası, en fazla
    500 öğe + `truncated`;
  - `risk_acceptance_expiry`: `reopened_last_7_days` (`audit_logs`
    `action = 'finding_updated' AND new_data->>'reason' =
    'risk_acceptance_expired' AND occurred_at >= now - 7 gün`),
    `last_evaluated_at`.
- Yanıt sır, paket adı listesi, ham hata metni içermez. Mevcut uç noktaların
  şemaları değişmez; yeni kolonlar `scanController` açık kolon listelerine
  eklenmez (AC-G-4).
- **Panel:** `public/app.js` Dashboard'da "Vulnerability data" kartı; bu uç
  noktayı çağırır; son çalıştırma zamanı/durumu, yeni bulgu sayısı, durumu
  `complete` olmayan projeler için uyarı listesi, son 7 günde yeniden açılan
  kabul sayısı. Tüm metinler `textContent`; hata durumunda kart hata metni
  gösterir. Mevcut tasarım sınıfları kullanılır (yeniden tasarım yok).

### 11. Yapılandırma ve kablolama (D-88, D-91, D-98)

- `runner.config.ts` → `vulnerability` bölümü (geçersiz değer → varsayılan +
  yalnız ayar adının bir kez loglanması):
  - `VULNERABILITY_LOOKUP` `on`/`off` (varsayılan `on`);
  - `VULNERABILITY_RECHECK` `on`/`off` (varsayılan `on`);
  - `VULNERABILITY_RECHECK_INTERVAL_HOURS` tam sayı 1–168 (varsayılan 24);
  - `OSV_TIMEOUT_MS` `boundedNumber` 1 ms – 24 sa (varsayılan 15 000);
  - `OSV_CONCURRENCY` tam sayı 1–32 (varsayılan 4);
  - `NVD_ENABLED` (yalnız `false` kapatır, bugünkü anlam);
  - `NVD_API_KEY` (değer yalnız istemciye geçer, config nesnesinin loglanabilir
    kısmına girmez).
- **Sabitler** `VULNERABILITY_LIMITS` (ortam değişkeni yok): toplu 1000 sorgu,
  10 sayfa, toplu 16 MiB, ayrıntı 8 MiB, NVD 2 MiB, yeniden deneme 2 (1 sn,
  2 sn), `Retry-After` ≤ 30 sn, devre kesici 5, NVD penceresi 30 sn / 5 / 50,
  NVD önbelleği 7 gün / 24 sa, yeniden kontrol 10 000 paket ve 30 dk, tetik
  10 dk, ilk kontrol 60 sn, başarısızlık beklemesi 1 sa, süre değerlendirmesi
  60 dk ve 500'lük parti, Karar 4 kırpma sınırları.
- **Kaldırılan ayarlar:** `OSV_API_URL`, `NVD_API_URL` okunmaz. Tanımlıysa
  `runtime.ts` adım 1'de her biri için tek uyarı: "`OSV_API_URL` artık
  desteklenmiyor ve yok sayılıyor" (değer loglanmaz).
- **Kablolama:** `runtime.ts` adım 7'de `createVulnerabilityClient({ config,
  logger })` (kapalı kipte ağ ajanı oluşturmaz), `createVulnerabilityLookup({
  client, db: pool, config, clock, logger })`, `ScanWorker`'a `vulnerabilityLookup`
  ve `clock`, `createVulnerabilityScheduler({ lookup, db: pool, config, clock,
  runtimeRunId, isRunning })`. Durum controller'ı zamanlayıcının salt okuma
  arayüzünü (`nextDue`, `lastEvaluatedAt`) alır. `endpoints` parametresi
  üretimde verilmez.
- **Test kurulumu:** `tests/setup/networkGuard.ts`
  `process.env.VULNERABILITY_LOOKUP = 'off'` ve
  `process.env.VULNERABILITY_RECHECK = 'off'` değerlerini **koşulsuz**
  atar (D-91).

### 12. L-5: lock `integrity` yan kanalı ve fail-safe (D-103)

- **Yan kanal:** npm lock ayrıştırıcıları (`package-lock.json` v1–v3,
  `yarn.lock` v1) bağımlılık nesnesine alan **eklemez**. Bunun yerine
  isteğe bağlı bir toplayıcı (`IntegrityCollector`) parametresine
  `{ manifestPath, name, version, integrity }` kaydı ekler. İş parçacığı
  yanıtı `{ ok, result, sideChannel: { npmIntegrity: [...] } }` olur;
  `runParserInThread` `{ result, lockIntegrity }` döner. `SandboxScanResult`
  ve golden'a giren nesne değişmez; golden yardımcısı yalnız `result`'ı görür
  (AC-G-6, AC-L5-3). `resolved` okunmaz.
- **Sınırlar (iş parçacığında):** değer metin, ≤ 1024 karakter, yalnız SRI
  karakterleri (`[A-Za-z0-9+/=?\-. ]`) — aksi kayıt atılır; kayıt sayısı
  bağımlılık sayısıyla sınırlı.
- **Karşılaştırma** (`lockIntegrity.ts`, saf; zenginleştirmenin meta veri
  aşamasından sonra, arşiv aşamasından önce): anahtar `(npm, istek adı,
  sürüm)`. Lock tarafı: anahtara ait tüm kayıtların `parseSriSha512`
  değerleri. Kayıt defteri tarafı: meta veri `found` ve npm arşiv adayının
  `algorithm = 'sha512'` `digests`'i. Sonuç:
  - iki tarafta da sha512 yoksa (lock değeri yok/bozuk/sha1, aday yok) →
    `not_comparable` (F3 davranışı);
  - karşılaştırılabilir her lock kaydı kayıt defteri kümesiyle en az bir öğe
    paylaşıyorsa → `match`;
  - en az bir lock kaydı hiç paylaşmıyorsa → `mismatch` (muhafazakâr: aynı
    ad@sürüm iki manifestte farklı arşive işaret ediyorsa anahtar uyuşmaz
    sayılır).
- **Fail-safe (`mismatch`, AC-L5-2):** L-6 önceliği (ADR-006 Karar 11) bu
  anahtar için devre dışı: kayıt defteri lisansı ve lock ipucu politikaya
  girmez; `license_expression = NULL`, `license_source = 'none'`; runtime
  paket için `NOASSERTION` (`unknown`) lisans bulgusu (parmak izi ADR-003 c ile
  `NOASSERTION` anahtarı). Arşiv aşaması bu anahtar için hiç çalışmaz, önbellekteki
  arşiv sonucu da kullanılmaz; `notice_status = 'not_attempted'`,
  `notice_archive_id = NULL`. `scan_dependencies.lock_integrity` her satıra
  yazılır (`match`/`mismatch`/`not_comparable`; zenginleştirme kapalı veya
  npm dışı → `NULL`). NOTICE nedeni, SBOM `licenseDeclared = NOASSERTION`,
  Excel `License Source` metni ve `[registry]` satırındaki uyuşmazlık sayısı
  `lock_integrity = 'mismatch'`'ten türetilir; `license_source` ve
  `notice_status` CHECK kümeleri **değişmez**. Kesin metinler REQ-004 contract
  revizyonundadır.
- `match` ve `not_comparable` anahtarlarda tüm çıktılar F3 ile aynıdır
  (AC-L5-4). PyPI karşılaştırılmaz.

### 13. N-1: normalleştirici (D-104)

- `normalizeLicense` girişinde ham metin `truncateCodePoints(…, 1000)` ile
  kesilir (lock ipucu ve kayıt defteri metni aynı kapıdan geçer).
- `_normalizeAtomic` sondaki parantez temizliği düzenli ifade yerine tek geçişli
  el yazımı tarayıcıdır: sondaki boşluklar atılır; son karakter `)` ise sondan
  başa doğru ilk `(` aranır (aradaki metinde `)` yoksa — bugünkü `[^)]*`
  anlamı); bulunursa `(`'den önceki boşluklarla birlikte kesilir. O(n).
  1000 kod noktası ve altındaki tüm girdilerde sonuç bugünküyle aynıdır
  (mevcut testler + eşdeğerlik testi).
- İfade ayrıştırmasındaki diğer düzenli ifadeler iç içe/örtüşen niceleyici
  içermeyecek şekilde gözden geçirilir; ADR-006 notundaki özyinelemesiz
  atomik yol korunur.

### 14. Göç `007` (D-102)

Dosyalar: `db/migrations/007_vulnerability_recheck.up.sql` / `.down.sql`
(database-engineer; nihai metin onundur, aşağıdaki adlar ve kısıtlar
bağlayıcıdır).

```sql
-- up
CREATE TABLE vulnerability_recheck_runs (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    runtime_run_id       TEXT        NOT NULL,   -- process run id (fencing, ADR-004 Karar 4)
    status               TEXT        NOT NULL CHECK (status IN
                             ('running', 'completed', 'partial', 'failed', 'interrupted', 'disabled')),
    started_at           TIMESTAMPTZ NOT NULL,   -- injected application clock
    finished_at          TIMESTAMPTZ NULL,
    projects_checked     INTEGER     NOT NULL DEFAULT 0 CHECK (projects_checked >= 0),
    packages_checked     INTEGER     NOT NULL DEFAULT 0 CHECK (packages_checked >= 0),
    packages_unchecked   INTEGER     NOT NULL DEFAULT 0 CHECK (packages_unchecked >= 0),
    findings_opened      INTEGER     NOT NULL DEFAULT 0 CHECK (findings_opened >= 0),
    acceptances_reopened INTEGER     NOT NULL DEFAULT 0 CHECK (acceptances_reopened >= 0),
    error_summary        TEXT        NULL CHECK (error_summary IS NULL OR char_length(error_summary) <= 500),
    CONSTRAINT vulnerability_recheck_runs_finished
        CHECK ((status = 'running') = (finished_at IS NULL))
);
CREATE UNIQUE INDEX uq_vulnerability_recheck_runs_running
    ON vulnerability_recheck_runs ((TRUE)) WHERE status = 'running';
CREATE INDEX idx_vulnerability_recheck_runs_started
    ON vulnerability_recheck_runs (started_at DESC);

CREATE TABLE osv_vulnerability_cache (
    osv_id            TEXT        PRIMARY KEY
                          CHECK (osv_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    modified          TIMESTAMPTZ NULL,
    withdrawn         BOOLEAN     NOT NULL DEFAULT FALSE,
    record            JSONB       NOT NULL,      -- trimmed, sanitized record (ADR-007 Karar 4)
    record_version    INTEGER     NOT NULL CHECK (record_version > 0),
    fetched_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE nvd_cvss_cache (
    cve_id        TEXT         PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    outcome       TEXT         NOT NULL CHECK (outcome IN ('found', 'no_cvss')),
    cvss_score    NUMERIC(4,1) NULL CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_vector   TEXT         NULL CHECK (cvss_vector IS NULL OR char_length(cvss_vector) <= 256),
    cvss_version  TEXT         NULL CHECK (cvss_version IS NULL OR char_length(cvss_version) <= 8),
    base_severity TEXT         NULL CHECK (base_severity IN ('none', 'low', 'medium', 'high', 'critical')),
    fetched_at    TIMESTAMPTZ  NOT NULL,         -- injected application clock
    expires_at    TIMESTAMPTZ  NOT NULL,         -- found: +7 d, no_cvss: +24 h
    CONSTRAINT nvd_cvss_cache_found CHECK ((outcome = 'found') = (cvss_score IS NOT NULL))
);

ALTER TABLE scans
    ADD COLUMN vulnerability_data_status TEXT NULL CHECK (vulnerability_data_status IN
        ('complete', 'partial', 'unavailable', 'disabled')),
    ADD COLUMN vulnerability_checked_at  TIMESTAMPTZ NULL;

ALTER TABLE findings
    ADD COLUMN recheck_run_id UUID NULL
        REFERENCES vulnerability_recheck_runs(id) ON DELETE SET NULL;

ALTER TABLE scan_dependencies
    ADD COLUMN lock_integrity TEXT NULL CHECK (lock_integrity IN
        ('match', 'mismatch', 'not_comparable'));

CREATE INDEX idx_findings_recheck_run   ON findings (recheck_run_id) WHERE recheck_run_id IS NOT NULL;
CREATE INDEX idx_findings_accepted      ON findings (id) WHERE status = 'accepted';
CREATE INDEX idx_scans_project_completed ON scans (project_id, completed_at DESC, id DESC)
    WHERE status = 'completed';
```

```sql
-- down
-- Data lost: recheck run history (vulnerability_recheck_runs); the link of
-- recheck-opened findings to their run (findings.recheck_run_id; the findings
-- themselves, their reviews and audit rows are KEPT); scans' vulnerability
-- data status and last check time; L-5 lock integrity flags
-- (scan_dependencies.lock_integrity; NOTICE/Excel then show the plain
-- 'not_attempted' reason for those packages); the OSV detail and NVD CVSS
-- caches (re-fetchable). Findings reopened by risk-acceptance expiry stay open.
DROP INDEX IF EXISTS idx_scans_project_completed;
DROP INDEX IF EXISTS idx_findings_accepted;
DROP INDEX IF EXISTS idx_findings_recheck_run;
ALTER TABLE scan_dependencies DROP COLUMN lock_integrity;
ALTER TABLE findings DROP COLUMN recheck_run_id;
ALTER TABLE scans DROP COLUMN vulnerability_checked_at, DROP COLUMN vulnerability_data_status;
DROP TABLE nvd_cvss_cache;
DROP TABLE osv_vulnerability_cache;
DROP TABLE vulnerability_recheck_runs;
```

- Enum değişikliği yoktur (`finding_status`, `audit_action`, `scan_trigger`
  aynen). Mevcut kolonların CHECK kümeleri değişmez.
- Eklenen kolonlar varsayılansız `NULL` (tablo yeniden yazılmaz); F4 öncesi
  satırlar `NULL` kalır ve "F4 öncesi" işaretidir.
- Durum kolonları için `TEXT + CHECK` seçildi (enum değil): geri alma ve değer
  ekleme transaction içinde basittir (ADR-006 ile aynı gerekçe).
- Göç `CONCURRENTLY` veya transaction dışı ifade içermez. `db/schema.sql`
  güncellenir; `001`…`006` değişmez. `db/README.md`'ye önbellek temizleme
  SQL'i (`DELETE FROM osv_vulnerability_cache; DELETE FROM nvd_cvss_cache;`) ve
  çalıştırma geçmişi temizliği (`DELETE FROM vulnerability_recheck_runs WHERE
  status <> 'running'`; bağlantılar `ON DELETE SET NULL` ile boşa çekilir)
  eklenir.

## Gerekçe

Tek bir güvenli HTTP çekirdeği, F3'te incelenmiş ve güvenlik incelemesinden
geçmiş kuralları (izin listesi, yönlendirme, sınırlar, vekil, devre kesici)
OSV/NVD'ye kopya kod olmadan taşır; F3 adaptörünün dışa aktarımlarını
korumak ve F3 testlerini değiştirmeden yeşil tutmak, çıkarımın davranışı
değiştirmediğinin ölçülebilir kanıtıdır. Ayrı çekirdek örnekleri iki dış
hizmetin eşzamanlılık ve hata durumlarını birbirinden yalıtır. Toplu sorgu +
`modified` karşılaştırmalı ayrı ayrıntı önbelleği, istek sayısını paket
sayısından bağımsız kılar ve tarama geri alınsa bile kazancı korur.
"Kontrol edilemedi"nin anahtar düzeyinde ayrı bir durum olması, sessiz "temiz"
sonucu yapısal olarak imkânsız kılar; asgari kayıtla bulgu açmak bilinen bir
açığı gizlemekten güvenlidir, katalog koruması ise eksik veriyle iyi veriyi
bozmayı önler. Zamanlayıcının mevcut tek süreç kilidinin içinde, çitli
çalıştırma kaydıyla çalışması ADR-004'ün tek yazar garantisini arka plan işine
genişletir; aralık modeli ve başlangıç telafisi kişisel bilgisayarın açık/kapalı
döngüsüne uyar. Proje başına transaction ve "daha yeni tarama var mı" kontrolü,
yeniden kontrolün tarama ile yarışmasını ve eski veriye yazmasını engeller.
P-19'un denetim tablosuna yazılan bir sistem geçişi olması, kullanıcı karar
geçmişini (`finding_reviews`) değiştirmeden izlenebilirlik sağlar;
"bugün"ün tek bir enjekte saat tanımına bağlanması tarama ve süre
değerlendirmesinin gece yarısında farklı sonuç vermesini önler ve testleri
gerçek zamandan bağımsız kılar. L-5 için yan kanal, golden çıktısını
dondurma kararını (REQ-003 D-26, REQ-004 D-55) bozmadan bütünlük bilgisini taşır.

## Değerlendirilen alternatifler

- **OSV/NVD için ayrı, kopya güvenli istemci:** hızlı ama güvenlik kurallarının
  iki kopyası zamanla ayrışır; REQ-005 NFR "ortak bileşen" ister. Reddedildi.
- **`registryClient.ts`'i yerinde genişletmek (OSV amaçlarını oraya
  eklemek):** "kayıt defteri" modülü iki farklı alanın uç noktalarını taşır,
  semaforlar paylaşılır ve F3 davranışı (eşzamanlılık) değişir. Reddedildi.
- **Yerleşik `fetch` + `NODE_USE_ENV_PROXY`:** ADR-006'daki gerekçeyle
  (süreç geneli anahtar, boyut ve yönlendirme denetimi zayıf). Reddedildi.
- **Ayrıntı önbelleği olarak `vulnerabilities` kataloğu:** tarama
  transaction'ına bağlı, UUID/takma ad birleştirmeli; `modified`
  karşılaştırması ve bağımsız yazım için uygun değil. Reddedildi.
- **Ham OSV/NVD gövdesini saklamak:** güvenilmeyen ve büyük (8 MiB'ye kadar)
  veri kalıcı katmana ve katalog JSONB'sine girer. Kırpılmış kayıt seçildi.
- **OSV hatasında taramayı `failed` yapmak:** bağımlılık ve lisans sonucunu
  kaybettirir, yeniden deneme döngüsü yaratır (D-89). Reddedildi.
- **Yeniden kontrol için yeni tarama satırı (`trigger = scheduled`):** veri
  kopyası ve bulgu çoğalması (D-96). Reddedildi.
- **Cron benzeri günün saatine bağlı zamanlama veya cron kütüphanesi:**
  kapalı bilgisayarda kaçırılan çalıştırmalar ve yeni bağımlılık (D-94,
  D-107). Reddedildi.
- **Bozulmuş kipte uçuştaki yeniden kontrolün sürmesi (taramalar gibi):** çit
  yazımı korur ama başka örnek kilidi aldığında iki yazar aynı projelere aynı
  anda bulgu ekleyebilir; çalıştırma ucuz ve tekrarlanabilir olduğundan iptal
  daha basit ve güvenli. Reddedildi.
- **"Bugün" için `CURRENT_DATE`:** veritabanı oturumu saat dilimine bağlı ve
  enjekte saatle test edilemez. Reddedildi.
- **Sistem kullanıcısıyla `finding_reviews` satırı:** yeni kimlik/yetki yüzeyi,
  `reviewer_id` anlamını bozar (D-101). Reddedildi.
- **Son süre değerlendirmesi zamanını tabloda saklamak:** her saat yazım ve
  ek şema; başlangıçta zaten değerlendirme yapıldığı için bellek yeterli.
  Reddedildi.
- **`notice_status`/`license_source` CHECK kümelerine L-5 değeri eklemek:**
  mevcut CHECK'leri değiştirmek geri almada veri dönüştürmesi gerektirir; ayrı
  `lock_integrity` kolonu aynı bilgiyi ek kısıt değişikliği olmadan taşır.
  Reddedildi.
- **Bütünlüğü ayrıştırıcı çıktısına alan olarak eklemek:** golden'ı kırar
  (AC-G-6). Reddedildi. **Lock dosyasını ana iş parçacığında ikinci kez
  okumak:** güvenilmeyen girdiyi iş parçacığı yalıtımının dışında yeniden
  ayrıştırmak. Reddedildi.
- **NVD için eşzamanlı istekler:** 5/30 sn sınırında kazanç yok, 429 riski.
  Reddedildi.

## Sonuçlar / Uygulama etkisi

- **Davranış:** çevrimdışı veya OSV'ye ulaşılamayan taramalar `partial`/
  `unavailable` ve `[osv]` satırı alır (bilinçli değişiklik, README).
  `VULNERABILITY_LOOKUP=off` iken her taramada "disabled" satırı yazılır.
  Kurumsal vekil artık OSV/NVD için de zorunlu kapı olur (vekil hatalıysa
  güvenlik açığı verisi `unavailable`).
- **İlk F4 başlangıcı:** P-19 süresi dolmuş (süresiz ve incelemesiz dahil) tüm
  kabulleri açar; sayı handoff'a yazılır. İlk yeniden kontrol başlangıçtan
  ~60 sn sonra çalışır (son çalıştırma kaydı yoktur).
- **Yeniden kontrol tamamlanmış taramayı değiştirir:** yeni bulgular ve
  sayaçlar; önceden üretilmiş raporlar sonradan üretilenlerden farklı
  olabilir (REQ-005 Riskler). İzlenebilirlik `recheck_run_id` ve denetim
  kaydıyla.
- **Performans:** 200 paketlik tarama → 1 toplu istek; ısınmış önbellekte 0
  ayrıntı isteği; NVD anahtarsız 5/30 sn ile sınırlıdır ve önbellek 7 gün.
- **Veri:** önbellekler kendiliğinden küçülmez (temizleme SQL'i
  `db/README.md`'de); çalıştırma geçmişi günde bir satır büyür.
- **Implementer'lar için kritik uyarılar:**
  1. "Kontrol edilemedi" anahtarı için hiçbir yerde `[]` (temiz) üretilmez.
  2. Asgari kayıt mevcut katalog satırını güncellemez.
  3. Ağ hatalarında yalnız `err.code`; `NVD_API_KEY` ve vekil URL'si hiçbir
     yere yazılmaz; `apiKey` başlığı köken denetiminden sonra ve yalnız
     `nvd-cve` amacına eklenir.
  4. Önbellek yazımı ve yeniden kontrol okumaları tarama transaction'ının
     `client`'ını kullanmaz; yeniden kontrol ağ beklerken bağlantı tutmaz.
  5. Yeniden kontrolün her proje transaction'ı önce çalıştırma kaydını
     (`runtime_run_id` + `running`) kilitler (çit), sonra taramayı.
  6. Tüm zamanlar (vade, `started_at`, SLA, NVD TTL, "bugün", denetim
     `occurred_at`) enjekte saatten gelir; `CURRENT_DATE` kullanılmaz.
  7. `jobSignal`/`runSignal` iptali yeniden fırlatılır; bütçe ve 30 dk süre
     iptali yutulur ve "kontrol edilemedi"ye çevrilir.
  8. Sıralamalarda kod noktası karşılaştırması; toplu gövde belirlenimci.
  9. Zamanlayıcı `setTimeout`'ları kapanışta temizlenir, `unref` edilmez.
  10. P-19 güncellemesi `WHERE status = 'accepted'` koşulludur ve satır
      kilidi altında okunan incelemeye dayanır.
  11. F3 adaptörünün dışa aktarımları ve davranışı değişmez; F3 testleri
      düzenlenmez.
- **Handoff:** `docs/handoffs/REQ-005.md` şu doğrulamaları ve ölçümleri
  kaydetmelidir: OSV `querybatch` sınırı/yanıt biçimi, PyPI ad eşleşmesi, NVD
  hız sınırı (Karar 3, 6), AC-P18-14 ölçümleri, P-19 ilk açılış sayısı.
  Non-trivial mimari karar olduğundan handoff güncellemesi zorunludur.

## Güvenlik etkisi

- **SSRF:** hedefler yalnız kod sabiti iki köken ve üç amaç yolu; test
  enjeksiyonu yalnız loopback `http` veya aynı kökenler; ortam değişkeni,
  taranan repo, `system_settings` veya uzak yanıt hedefi değiştiremez;
  yönlendirme izlenmez. `OSV_API_URL`/`NVD_API_URL` kaldırıldı.
- **Sır:** `NVD_API_KEY` yalnız NVD kökenine; log/hata/denetim/API/önbellekte
  yok. Vekil kimlik bilgisi yalnız Node tarafından `Proxy-Authorization` ile
  vekile.
- **Güvenilmeyen yanıt:** boyut sınırları (16/8/2 MiB), tip ve kimlik kalıbı
  doğrulaması, sayfa ve vuln sayısı sınırları, kırpma ve metin arındırma
  (ADR-006 Karar 8) kalıcı katmandan önce; `id` yol bileşeni kodlanır.
  Çıktılarda mevcut kaçış kuralları (ADR-006 Karar 13 ve notu) geçerlidir.
- **Bütünlük ve yanlış negatif:** eksik veri görünür (`partial`/`unavailable`,
  `[osv]`, panel); asgari kayıtla bulgu açılır; geri çekilen kayıt bulgu açmaz.
- **Sistem geçişleri:** P-18 yeni bulgu ve P-19 yeniden açma her biri denetim
  satırıyla, `actor_id` boş, kullanıcı karar geçmişi değişmeden; satır kilidi
  kullanıcı geçişini ezmez. Otomatik durum değişikliği insan onayı kapısıdır.
- **Tek yazar:** zamanlayıcı yalnız kilit sahibi süreçte; çalıştırma kaydı çiti;
  bozulmuş kipte iptal.
- **DoS:** N-1 doğrusal normalleştirici ve 1000 kod noktası; L-5 değeri
  ≤ 1024 karakter ve kalıp; yeniden kontrol 10 000 paket / 30 dk; tarama
  bütçesi süre sınırının ≤ 1/4'ü; NVD hız sınırı.
- **L-5:** saldırgan lock değerini değiştirerek yalnız daha muhafazakâr sonuç
  (`NOASSERTION`, NOTICE yok) üretebilir; bulgu gizleyemez.
- **Gizlilik:** paket adları/sürümleri günde bir kez kullanıcı eylemi olmadan
  OSV'ye (ve vekile) gider; README, `VULNERABILITY_RECHECK=off` /
  `VULNERABILITY_LOOKUP=off`.
- **Yetki:** yeni uç nokta salt okuma, `scans:read`, proje görünürlüğü
  `GET /api/scans` ile aynı; denetim kaydı gerekmez.

## Test stratejisi

qa-automation (`tests/**`, `vitest.config.ts`):

- **Ağ koruması (AC-G-2):** mevcut `tests/setup/networkGuard.ts` korunur; yeni
  test `https://api.osv.dev/v1/querybatch` ve
  `https://services.nvd.nist.gov/...` isteklerinin engellendiğini doğrular.
  Kurulum `VULNERABILITY_LOOKUP=off`, `VULNERABILITY_RECHECK=off` atar
  (koşulsuz).
- **Sahte sunucular:** `tests/helpers/fakeOsv.ts` ve `tests/helpers/fakeNvd.ts`
  (`127.0.0.1:0`, `node:http`): yol/yöntem bazında yanıt tablosu, istek sayacı
  (toplu/ayrıntı/NVD ayrı), istek gövdesi kaydı, değiştirilebilir veri
  (`modified` ilerletme, yeni kayıt ekleme), gecikme, `429`/`5xx`/
  `Retry-After`, 3xx, bağlantı kesme, büyük gövde (17 MiB toplu,
  `Content-Length` yalanı), bozuk JSON, `results` uzunluk hatası, `../x`
  kimliği, `vulns` sayı, sayfalı yanıt. İstemci `endpoints` ile enjekte edilir.
- **Enjekte saat:** `tests/helpers/fakeClock.ts` (`now`, `advance`, `sleep`
  çözümlemesi saat ilerletilince); geri çekilme, `Retry-After`, NVD penceresi
  (6. istek 30 sn bekler), NVD TTL, zamanlayıcı vadesi, "bugün" (2026-10-10
  23:59 / 2026-10-11 00:00, `TZ` sabitlenmiş süreçte), süre değerlendirmesi.
  Gerçek bekleme gerektiren test yoktur; zamanlayıcı testleri `tick()`
  çağırır, `setTimeout` zinciri ayrı küçük bir testle (Vitest sahte
  zamanlayıcıları) doğrulanır.
- **Birim:** `computeNextDue` (23 sa 50 dk yok / 24 sa var; başarısızlıktan
  30 dk yok / 60 dk var; 3 gün önce → tek; `disabled` aralık başına bir),
  `rateLimiter`, `normalize` + `minimalVulnerability`, OSV yanıt doğrulayıcı,
  kayıt kırpma, `assertInjectableOrigin`, amaç yol kuralları (CVE kalıbı),
  `summaryLines`, `lockIntegrity` (çoklu SRI, sha1-only, bozuk, uzun,
  iki manifest farklı değer), `localDateString`, N-1 (100 000 karakterlik iki
  girdi < 1 sn, CI 2 sn; ≤ 1000 kod noktası eşdeğerlik).
- **Statik:** `src/`'de `fetch(` ve `OSV_API_URL`/`NVD_API_URL` okuması yok;
  ağ modülü içe aktaran tek dosya `safeHttpClient.ts`; `runtime.ts`
  güvenlik açığı motorunu her zaman oluşturup worker'a verir ve
  `endpoints`/`vulnerabilityScheduler` vermez.
- **Entegrasyon (embedded-postgres):** AC-P17-1…14 (200 paket → 1 toplu, 0
  `/v1/query`; 1000/1001; tekilleştirme; sayfalama; ayrıntı önbelleği 1→0→1;
  `withdrawn`; yönlendirme; `apiKey` yalnız NVD'de; `OSV_API_URL` uyarısı
  değersiz; vekil saf fonksiyonu OSV/NVD hostlarıyla; sınırlar; devre kesici;
  `unavailable`/`partial` ve tek `[osv]` satırı; `off`; NVD önbelleği; bütçe ve
  istek sürerken kapanış → `queued`), AC-P18-1…13 (yeniden tarama olmadan
  bulgu ve sayaç artışı; tekrarsız; `false_positive` taşıma; ortada yeni
  tarama → yazım yok; `complete`'e geçiş; çalıştırma kaydı ve `interrupted`
  süpürmesi; çevrimdışı `failed`; durum uç noktası 200/401/403 ve salt okuma;
  denetim satırı; `off`), AC-P19-1…8 (sınır günü; süresiz/incelemesiz;
  denetim; iki ardışık değerlendirme; eşzamanlı yeni `accept-risk`; yeniden
  kabul; enjekte hata sonrası `running`), AC-L5-1…4, göç `007` up → down → up,
  AC-G-8 (istemci enjekte edilmeden F3 birebir; kapalı kipte yalnız `[osv]`
  farkı), F3 kayıt defteri testleri değişmeden yeşil.
- **Arayüz (jsdom):** panel `partial` uyarısı, API hatası durumu,
  `textContent` kullanımı.
- **Değişmeyenler:** P-10 golden'ları, REQ-004 NOTICE golden'ı, mevcut contract
  testleri, AC-P08-* ve iş akışı testleri.
- **Elle (ana oturum):** AC-P18-14 gerçek ağ ölçümleri ve Karar 3/6
  doğrulamaları.

## Kanıt (Evidence)

- Repo incelemesi (`c9f37d9`): `src/analysis/vulnerabilityLookup.ts` (tamamı),
  `src/scanner/worker.ts` (`persistResults` güvenlik döngüsü,
  `upsertVulnerability`, `insertFinding`, `findCarriedDecision`, uyarı
  satırları ve sonuç güncellemesi), `src/analysis/findingFingerprint.ts`
  (güvenlik anahtarı), `src/enrichment/registryClient.ts` (dışa aktarımlar,
  çekirdek), `src/enrichment/{proxy,budget,integrity,cache,types}.ts`
  dışa aktarımları, `src/runtime.ts` (adım 7, kilit kaybı, kapanış),
  `src/controllers/workflowController.ts` (geçiş transaction'ı,
  `insertAudit`), `src/routes/scanRoutes.ts`, `src/config/permissions.ts`,
  `src/scanner/sandbox/runner.config.ts`, `db/schema.sql` (enum'lar, `scans`,
  `findings`, `security_findings`, `finding_reviews`, `audit_logs`,
  `vulnerabilities`, indeksler), `db/migrations/001…006` listesi,
  `tests/helpers/parserGolden.ts`, `public/app.js` (Dashboard).
- `docs/product/REQ-005.md` r1; ADR-002 Ek E3; ADR-003 (c) ve karar taşıma
  tablosu; ADR-004 Karar 2–8; ADR-006 (Karar 1–16 ve 2026-10-10 güvenlik notu).
- Dış kaynak (genel bilgi, **doğrulanması gerekiyor**): OSV API
  `/v1/querybatch` (`queries`/`results`/`next_page_token`/`page_token`, 1000
  sorgu sınırı, vuln başına `id`+`modified`), `/v1/vulns/{id}`, `withdrawn`;
  PyPI adlarının OSV'de PEP 503 ile eşleşmesi; NVD CVE API 2.0 `cveId`
  parametresi, `apiKey` başlığı ve hız sınırları (anahtarsız 5, anahtarlı 50
  istek / kayan 30 sn). NotebookLM veya Obsidian kaynağı kullanılmadı.

## İlgili REQ / AC

REQ-005: AC-G-1…9, AC-P17-1…14, AC-P18-1…14, AC-P19-1…8, AC-L5-1…4,
AC-N1-1…2; kararlar D-84…D-108.

## REQ-005 netleştirmeleri

1. **OSV istek adı (AC-P17-1):** tekilleştirme anahtarı `(ekosistem, istek adı,
   sürüm)`'dür; ancak OSV JSON gövdesindeki npm adı ham `@kapsam/ad`'dır
   (REQ-004 AC-P14-5'teki `%2F` yalnız URL yolu içindir). PyPI gövdede PEP 503.
2. **Asgari kaydın parmak izi (AC-P17-11):** "parmak izi tam kayıtla aynı
   anahtarı üretir" katalog/önbellekte önceki kaydı olan veya birincil kimliği
   OSV/GHSA olan açıklar için garanti edilir; hiç görülmemiş, birincil kimliği
   `CVE-` ve tam kaydında GHSA takma adı olan açıkta anahtar sonradan farklı
   olabilir (Karar 4). Ürün tarafında ifade "aynı anahtar kuralıyla" olarak
   yumuşatılmalıdır.
3. **Geçersiz kimlik (AC-P17-4):** paket "kontrol edilemedi" sayılır, ancak
   aynı paketin geçerli kimlikleri yine bulgu açar.
4. **Bütçe (AC-P17-14):** `min(süre sınırı / 4, kalan süre − süre sınırı / 8)`.
5. **"Başarılı çalıştırma" (AC-P18-1):** `completed` ve `partial` (ayrıca
   aralık sayımı için `disabled`). `partial`'ı başarısız saymak çevrimiçi ama
   kısmi çalıştırmayı 10 dakikada bir tekrarlatırdı. `interrupted` vadeyi
   etkilemez.
6. **İlk kontrol zamanı (AC-P18-2):** başlangıçtan 60 sn sonra.
7. **Durum geçişi (AC-P18-7):** kısmi yeniden kontrolde `unavailable`, `NULL`
   ve `disabled` → `partial`; `partial` kalır; `complete` hiç düşmez; hiç
   paket kontrol edilemezse değişmez. AC'deki "durum değişmez (veya `partial`
   kalır)" bu şekilde okunur.
8. **Bozulmuş kip (AC-P18-1):** yeni çalıştırma yok **ve** uçuştaki çalıştırma
   iptal edilir (`interrupted`).
9. **Son süre değerlendirmesi zamanı (AC-P18-10):** bellekte; süreç başladıktan
   sonraki ilk değerlendirme bitene kadar `null`.
10. **Denetim kaynağı (AC-P18-12):** `new_data.source = 'vulnerability_recheck'`.
11. **L-5 işareti (D-102):** `scan_dependencies.lock_integrity`; uyuşmazlıkta
    `notice_status = 'not_attempted'`, `license_source = 'none'`, mevcut CHECK
    kümeleri değişmez; NOTICE/Excel/`[registry]` metinleri bu kolondan türer
    (REQ-004 contract revizyonu).
12. **NVD yuvası:** hız sınırı deneme başına sayılır (yeniden denemeler dahil).
13. **Katalog ve NVD verisi:** `vulnerabilities.advisory_data` kırpılmış OSV
    kaydını ve yalnız CVSS özetini saklar (ham gövde değil); API şeması
    değişmez.

## Açık noktalar

Yok. Kullanıcının daimi talimatı gereği tüm seçimler önerilen seçenekle karara
bağlanmıştır. "Doğrulanması gerekiyor" işaretli dış bilgilerin (OSV
`querybatch` sınırı ve yanıt biçimi, PyPI ad eşleşmesi, NVD hız sınırı) her
biri için tanımlı yedek veya AC-P18-14 sırasında teyit adımı vardır (Karar 3,
6).

## REQ-005 güvenlik düzeltmesi (2026-10-11)

> **REQ-005 güvenlik düzeltmesi (2026-10-11).** Güvenlik incelemesi
> (`docs/quality/security-reports/REQ-005-security-review.md`; ilk karar
> Conditional Go, yeniden doğrulama 2026-10-11: **Go**) ve contract
> `docs/contracts/REQ-005-vulnerability-data.md` 1.1.0 (V-15…V-19) sonrası
> Karar 2–4, 6, 7, 8 ve 11 aşağıdaki kurallarla sıkılaştırılır (commit
> `3fdb538` düzeltmeler, `3cda79a` L-3, `f79d3d5` yeniden doğrulamanın takip
> bulguları Y-1…Y-3). Y-1…Y-3 yeniden doğrulamada merge'ü engellemeyen takip
> olarak açılmış ve `f79d3d5`'te giderilmiştir. Bu bir gevşetme değil
> sertleştirmedir; çeliştiği yerde yukarıdaki metnin yerine geçer.
>
> - **Karar 4, kimlik ve ayrıntı sınırları (M-1; V-15, contract §3.5.1):**
>   `VULNERABILITY_LIMITS`'e üç sabit eklenir (ortam değişkeni yok). Tarama
>   sorgusunda ve yeniden kontrol çalıştırmasında lookup başına ayrı ayrı
>   uygulanır:
>   - `osvMaxIdsPerPackage = 200`: paket başına (tüm sayfalar toplamı) benzersiz
>     kimlik. Aşılınca o paketin sayfalaması durur, paket `unchecked` olur ve
>     kimliklerinin **hiçbiri** işlenmez. Kod `osv:id_limit`.
>   - `osvMaxDistinctIds = 5 000`: lookup başına benzersiz kimlik. Kümeye yeni
>     kimlik ekleyip toplamı aşacak paket `unchecked` olur. Sayım referanslıdır:
>     düşürülen paket getirdiği kimlikleri serbest bırakır. Kimlikleri tümüyle
>     kümede olan paket `checked` kalır. Kod `osv:total_id_limit`.
>   - `osvMaxDetailRequests = 2 000`: lookup başına ağa çıkan ayrıntı isteği
>     (önbellek isabeti sayılmaz, bir isteğin yeniden denemeleri tek istektir).
>     Sınır dolunca kalan kimlikler önbellekteki (eski dahil) kayıtla, yoksa
>     asgari kayıtla yazılır ve "ayrıntı eksik" sayılır. Kod `osv:detail_limit`.
>
>   `[osv]` şablonları değişmez; sınırlar `U`/`D` sayımlarına yansır. Yeniden
>   kontrolde herhangi bir sınır aşılırsa çalıştırma `partial` olur. Böylece
>   bellek haritaları ve yazılan açık sayısı lookup başına ≤ 5 000 kimlikle
>   sınırlıdır.
> - **Karar 7, yazma fazının süresi (M-1, Y-1):** adım 4'teki
>   `timeout(30 dk)` yerine lookup, çalıştırma başlangıcından (P-19 ve kapsam
>   okuma dahil) itibaren en geç `runTimeoutMs × 5/6` = **25 dk**'da biter
>   (`lookupBudgetShare`). Böylece yazma fazına **en az 5 dk** kalır. Yazma
>   fazı da 30 dk çalıştırma sınırına bağlıdır. Son tarih her proje
>   transaction'ından ve proje içindeki her bağımlılık yazımından önce
>   denetlenir. Dolmuşsa o anki proje `ROLLBACK` edilir, kalan projeler
>   yazılmaz ve çalıştırma `partial` + `osv:time_limit` ile kapanır. Bu durum
>   vadeyi ilerletir; atlanan projeler sonraki çalıştırmada telafi edilir.
>   Daha önce commit edilmiş projeler kalır; bağlantı bozuk sayılmaz.
> - **Karar 3–4 ve 6, tarih ve puan doğrulaması (L-1; V-16, §3.5.2):**
>   `published`/`modified` (ayrıntı kaydı ve querybatch sonucu) yalnız **katı
>   RFC 3339** olarak kabul edilir. Buna takvim ve saat denetimi (yıl
>   0001–9999) eklenir; değer `toISOString()` ile UTC'ye normalleştirilir.
>   Geçersiz tarih alanı yok sayılır (`NULL`), kayıt reddedilmez. Geçersiz
>   querybatch `modified` değeri tazeliği "bilinmiyor" yapar ve ayrıntı yeniden
>   istenir (ayrıntı sınırına tabi). Karar 3 madde 3'teki "ISO 8601 olarak
>   ayrıştırılabilir" ifadesi bu kuralla okunur. Sayısal CVSS puanı (OSV
>   `severity[].score` ve NVD `baseScore`) yalnız sonlu ve **0–10** ise kabul
>   edilir; aksi hâlde o kaynakta puan yok sayılır ve sıradaki kaynağa geçilir.
>   Tek bozuk kayıt artık sonuç transaction'ını düşürmez.
> - **Karar 6, CVSS kaynağı ve yerel hesap (P-1; V-18, §3.5.3):** CVSS taban
>   puanı şu sırayla, ilk başarılı adımdan alınır:
>   1. OSV kaydındaki geçerli sayısal puan.
>   2. OSV kaydındaki ilk geçerli `CVSS_V3` vektöründen **yerel hesap**
>      (`src/vulnerability/cvss3.ts`, ağ yok, düzenli ifade yok). Vektör
>      `CVSS:3.0/` veya `CVSS:3.1/` önekli ve ≤ 256 karakter olmalı; 8 taban
>      metriğinin her biri tam bir kez bulunmalı. Temporal/environmental
>      metrikler yok sayılır. Formül FIRST CVSS v3.1 taban denklemleridir (v3.0
>      ile aynı). Yuvarlama, spesifikasyon Ek A'daki tam sayı tabanlı
>      `Roundup`'tır.
>   3. NVD, yalnız ilk iki adımda puan elde edilemezse (yalnız `CVSS_V4`/
>      `CVSS_V2` vektörü olan, geçersiz vektörlü veya `severity`'siz CVE).
>   4. Varsayılan (önem `medium`, CVSS boş).
>
>   Puanın kaynağı yalnız `advisory_data` CVSS özetinde `source`
>   (`osv_score` | `osv_vector` | `nvd`) olarak tutulur; API yanıt şemaları ve
>   `[nvd]` şablonu değişmez. Kabul edilen kalıntılar: OSV ve NVD vektörleri
>   farklıysa puan farklı olabilir; v3.0 vektörlerinde nadir kayan nokta
>   sınırlarında 0,1 fark çıkabilir. Gerçek ağ ölçümü (I-15, ana oturum beyanı,
>   **doğrulanmadı**): ilk tarama **649 sn → 326 sn**, NVD isteği **96 → 43**.
> - **Karar 11, tek açma/kapama ayrıştırıcısı (L-2; V-17, §7.1):**
>   `VULNERABILITY_LOOKUP`, `VULNERABILITY_RECHECK`, `NVD_ENABLED` ve
>   `REGISTRY_ENRICHMENT` aynı `parseSwitch`'i kullanır. Değer baş/son
>   boşlukları kırpılarak, harf duyarsız okunur:
>   - `on`/`true`/`1`/`yes` → açık;
>   - `off`/`false`/`0`/`no` → kapalı;
>   - boş veya tanımsız → açık (varsayılan);
>   - başka her değer → **kapalı** (gizlilik için fail-closed). Açılışta
>     değişken başına tek uyarı yazılır; uyarı yalnız adı içerir, değer
>     loglanmaz.
>
>   Karar 11'deki "geçersiz değer → varsayılan" ifadesi açma/kapama ayarları
>   için ve `NVD_ENABLED` "yalnız `false` kapatır" ifadesi bu kadar superseded.
>   Sayısal ayarların kuralı değişmez. `REGISTRY_ENRICHMENT` için ADR-006
>   Karar 14'e tarihli not eklendi.
> - **Karar 8, kilit kaybında P-19 (L-3):** `pause()` ve `stop()`, uçuştaki
>   yeniden kontrolün yanında canlı **her** P-19 değerlendirmesinin
>   denetleyicisini de iptal eder. Denetleyiciler bir kümede
>   (`expiryControllers`) izlenir; mutex arkasında bekleyen bir tetik, çalışan
>   değerlendirmenin denetleyicisini ezemez. `canTrigger()` sıradaki tetiği
>   de durdurur. Commit sırasında iptal edilen parti geri alınır.
> - **Karar 2, deneme başına devre kesici (L-4):** devre kesici her denemeden
>   önce denetlenir ve her denemeden sonra güncellenir (`AttemptBreaker`).
>   `429` ve `5xx` **başarısız deneme** sayılır; diğer HTTP yanıtları sayacı
>   sıfırlar. Art arda 5 başarısız deneme host'u oturum için kapatır. Böylece
>   sürekli 503 dönen bir uç da kapanır. Karar 2'deki "her HTTP yanıtı sayacı
>   sıfırlar, 5 ardışık ağ düzeyi başarısız deneme" ifadesi bu kadar
>   superseded. Paylaşılan uçuştaki istekte iz yalnız diğer oturumların
>   bekleyenlerine yeniden oynatılır, çift sayım olmaz (I-7). NVD `429`'u da
>   sayılmaya devam eder. NVD için `429`'u devre kesiciden ayırmak açık
>   seçenektir (aşağıdaki takipler).
> - **Karar 6 ve 11, NVD hız sınırlayıcısı (Y-2):** sınırlayıcı deneme
>   başlangıcını, NVD ise varışı saydığı için pencere **35 000 ms** olur
>   (NVD'nin 30 sn'si + 5 sn güvenlik payı). Anahtarsız kullanımda iki deneme
>   başlangıcı arasında **en az 6 sn** bırakılır. 5/50 değerleri değişmez.
>   Her NVD `429`'unda sınırlayıcı süreç genelinde tüm yeni NVD
>   başlangıçlarını durdurur (`pause`; bu oturumun yeniden denemesi ve diğer
>   oturumlar dahil). Süre, kullanılabilir `Retry-After` (≤ 30 sn) varsa o
>   kadar, yoksa (veya ayrıştırılamaz ya da daha uzunsa) bir pencere (35
>   sn)'dir. `pause` önceki duraklamayı yalnız uzatır, kısaltmaz. Karar 11
>   sabitlerindeki "NVD penceresi 30 sn" değeri 35 sn + 6 sn aralık olarak
>   okunur.
> - **Karar 4, 5 ve 7, eşzamanlı katalog yazımı (L-6, Y-3):**
>   - `upsertVulnerability` ekleme yolu hedefsiz `INSERT … ON CONFLICT DO
>     NOTHING` kullanır. Satır eklenmezse kayıt bir kez yeniden okunup
>     güncelleme yoluna gidilir; ikinci başarısızlık sentetik `23505` üretir.
>     Sonsuz döngü ve sessiz kayıp olmaz (I-11, kabul edildi).
>   - Upsert bir savepoint içinde çalışır ve `40P01` (deadlock) veya `40001`
>     (serileştirme) hatasında bir kez yeniden denenir. Bu kural tarama ve
>     yeniden kontrol için aynıdır.
>   - Yeniden kontrolde bir proje transaction'ı `40P01`/`40001` ile düşerse,
>     kısa rastgele bir beklemeden sonra bir kez daha denenir. İkinci
>     başarısızlık bugünkü gibi yalnız o projeyi geri alır (`db:40`,
>     `partial`).
>   - Küresel kilit sırası (açıkları upsert'ten önce birincil kimliğe göre
>     sıralamak) **eklenmedi**. Olasılık düşük ve yeniden deneme yeterli
>     olduğu için bu durum kabul edildi.
> - **Karar 7, sayfalı kapsam (L-7):** adım 3'te kapsam, benzersiz koordinatlar
>   üzerinden SQL'de keyset ile 5 000'lik sayfalar hâlinde okunur
>   (`COLLATE "C"`). 10 000 sınırı sayfalama sırasında uygulanır; bellekte en
>   fazla 10 000 temsilci ve bir sayfa tutulur. Proje başına anahtarlar yazım
>   transaction'ında yeniden hesaplanır. "Tarama başına anahtar kümesi
>   bellekte tutulur" ifadesi bu kadar superseded. (I-14: Türkçe
>   `LC_CTYPE`'ta `lower('I')` farkı yalnız `packages_unchecked` sayacını
>   etkileyebilir. `db/README.md`'deki C/en yereli önerisiyle etkisizdir.)
> - **F4 dışında kalan takipler (bu ADR'yi değiştirmez):**
>   - **NVD CVSS'in arka plan yeniden kontrolüne taşınması (I-16):** ilk
>     taramanın kalan gecikmesi büyük ölçüde anahtarsız NVD sınırından gelir
>     (43 istek ≥ ~258 sn; `NVD_API_KEY` ile ~26 sn). Taşınırsa koşullar:
>     (1) CVSS gelene kadar bulgu "CVSS bekleniyor" olarak görünür biçimde
>     işaretlenir, `medium` varsayılanı kesin değer gibi sunulmaz; (2) CVSS
>     geldiğinde açık bulguların `security_findings.severity`/`cvss_score`
>     değeri ve **SLA son tarihi** yeniden hesaplanır ve denetime yazılır;
>     (3) arka plan işi aynı sınırlayıcıyı ve devre kesiciyi paylaşır;
>     (4) contract ve ADR revizyonu gerekir.
>   - **NVD `429`'unun devre kesiciden ayrılması:** yalnız ağ hatası ve `5xx`
>     sayılır. Y-2 sınırlayıcı düzeltmesinden sonra açık seçenek olarak kalır.
>   - **Küresel kilit sırası:** Y-3'ün ikinci yolu; bugün yeniden denemeyle
>     yetinildi.
> - **Etki:** yeni bağımlılık, göç, yetki veya dış uç nokta değişikliği
>   yoktur. Durum uç noktası şeması ve `[osv]`/`[nvd]` şablonları değişmez.
>   Görünür davranış değişiklikleri şunlardır: geçersiz açma/kapama değeri
>   artık kapatır; vektörlü açıkta puan OSV vektöründen gelir; NVD daha yavaş
>   ama 429'suz ilerler. Bunlar README'de ve handoff'ta belirtilmelidir.
>   `docs/handoffs/REQ-005.md` bu nota ve yeniden doğrulamanın açık insan
>   onayı kapılarına (L-5 ön kontrol kabulü, `main` merge, I-15 gerçek ağ
>   beyanı) atıfla güncellenmelidir. Karar veren: kullanıcının daimi talimatı
>   (önerilen seçenek), contract 1.1.0 ile aynı dayanak. ADR durumu `Accepted`
>   kalır; kayıt kullanıcının commit'iyle kesinleşir.

## ADR-008 notu (2026-10-11)

> **ADR-008 ile kısmen superseded (2026-10-11).** REQ-006 (F5):
> - **Karar 3:** aday kümesi `dotnet` paketlerini de içerir (OSV ekosistemi
>   `NuGet`, anahtar küçük harfli kimlik ve sürüm). Gövdedeki ad `.nuspec`
>   `<id>` (kanonik ad), yoksa ilk kaydın kaynak harf biçimidir.
>   `bestAffected` NuGet için harf duyarsız bir adım kazanır.
> - **Karar 7:** `SCOPE_PAGE_SQL`'deki `CASE … ELSE 'pypi'` kaldırılır ve
>   üç değerli, `ELSE`'siz bir eşlemeyle değiştirilir. NuGet anahtarları
>   `lower(… COLLATE "C")` ile üretilir (I-14'ten bağımsız).
>   `registry_package_cache.canonical_name` ile `LEFT JOIN` yapılır.
> - **Karar 12:** L-5 artık yalnız npm için değildir. NuGet'te karşılaştırma
>   meta veri aşamasında değil, arşiv aşamasında indirilen baytlar üzerinde
>   yapılır: ham SHA-512 veya imzalı paket içerik özeti. Uyuşmazlıkta aynı
>   fail-safe ve aynı kolon/metinler kullanılır. Zenginleştirme açıkken NuGet
>   anahtarlarının varsayılan değeri `not_comparable`'dır ("npm dışı →
>   `NULL`" ifadesi PyPI için geçerli kalır). Birden çok farklı lock özeti
>   `mismatch` sayılır.
>
> Ayrıntı:
> `docs/architecture/adr/ADR-008-nuget-ayristirici-ve-zenginlestirme.md`
> Karar 6, 10, 13.

## Onay (Approval)

- **Karar veren:** kullanıcı daimi talimatı (önerilen seçenek), 2026-10-10.
  Talimat REQ-005'te kayıtlıdır. Durum `Accepted`. Karar ana oturum aracılığıyla
  iletilmiştir; kullanıcının bu dosyayı gözden geçirip commit etmesi kaydı
  kesinleştirir.
- Bu karar **dış hizmete zamanlanmış erişim** (`api.osv.dev`,
  `services.nvd.nist.gov`, kullanıcı eylemi olmadan), **veri modeli
  değişikliği** (göç `007`), **otomatik durum değişikliği / toplu veri
  güncellemesi** (P-19 kabulleri açar, P-18 tamamlanmış taramalara bulgu
  ekler) ve güvenilmeyen dış yanıtı işleyen bir **güvenlik sınırı** içerir.
  `.claude/rules/autonomy-gates.md` ve REQ-005 Notlar gereği implementation
  öncesi: bu kapılar için insan onayı ve `docs/ownership/REQ-005.json`
  `status: approved`; yerel veritabanına `007` uygulanması kullanıcı kararıdır;
  release öncesi Security Red Team incelemesi zorunludur. Yeni runtime
  bağımlılığı olmadığı için paket kurulum onayı gerekmez.
- **Yol sahipliği** (manifest önerisi; manifest'i agent yazmaz):

  | Agent | Yollar |
  | --- | --- |
  | backend-engineer | `src/**` (`src/db` hariç): `src/lib/{clock.ts,http/**,findingStateMachine.ts}`, `src/vulnerability/**`, `src/analysis/{vulnerabilityLookup,licenseNormalizer}.ts`, `src/enrichment/**` (adaptör, `proxy.ts` yeniden dışa aktarım, `lockIntegrity.ts`, L-5), `src/scanner/**` (worker, ayrıştırıcı yan kanalı, `runner.config.ts`), `src/notice/**`, `src/sbom/**`, `src/reports/**` (L-5), `src/controllers/vulnerabilityStatusController.ts`, `src/routes/vulnerabilityStatusRoutes.ts`, `src/app.ts`, `src/runtime.ts`; `README.md` |
  | database-engineer | `db/**` (göç `007`, `schema.sql`, `db/README.md`), `src/db/**` |
  | qa-automation | `tests/**` (sahte OSV/NVD, sahte saat, ağ koruması, fixture'lar), `vitest.config.ts` |
  | frontend-engineer | `public/app.js`, `public/index.html`, `public/styles.css` (AC-P18-11 paneli, contract onayından sonra) |
  | contract-broker | `docs/contracts/REQ-005-*` (durum uç noktası, `[osv]`/`[nvd]` şablonları, durum değerleri, P-18/P-19 denetim `new_data` şekli) ve `docs/contracts/REQ-004-*` revizyonu (L-5: Excel `License Source`, NOTICE nedeni, `[registry]` uyuşmazlık sayısı) |
  | Ana oturum | `.env.example`, gerçek ağ doğrulaması (AC-P18-14), yerel veritabanına `007` |

  `src` ve `src/db` çakışır; Delivery Lead sıralamalı veya backend görev
  paketinde `src/db`'ye yazmamayı açıkça belirtmelidir. Ortak çekirdek
  çıkarımı, zamanlayıcı, L-5 ve rapor/SBOM değişiklikleri tek
  backend-engineer'a aittir; paralel ikinci backend yazarı atanmaz.
