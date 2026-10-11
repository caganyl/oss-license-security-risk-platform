# REQ-005 — Güvenlik İncelemesi (F4: OSV querybatch, güvenli OSV/NVD istemcisi, günlük yeniden kontrol, P-19 risk kabulü süresi, durum uç noktası, L-5 lock bütünlüğü, N-1)

- İnceleyen: Security Red Team (adversarial review, read-only)
- Tarih: 2026-10-10
- Branch: `req-005-f4-guvenlik-aciklari` (HEAD: `1045dc5`)
- İnceleme aralığı: `git diff origin/main...HEAD` (`429c89d` sonrası; 69 dosya, +11 539 / −1 517)
- Kaynaklar: `docs/product/REQ-005.md` (r2), `docs/architecture/adr/ADR-007-guvenlik-acigi-sorgusu-ve-yeniden-kontrol.md`, `docs/contracts/REQ-005-vulnerability-data.md`, `docs/contracts/REQ-005-vulnerability-api.openapi.yaml`, `docs/contracts/REQ-004-notice-and-outputs.md` (1.2.0 §4.4), `docs/quality/security-reports/REQ-004-security-review.md`.
- Tehdit bağlamı: Kişisel, tek kullanıcılı Windows aracı. Sunucu yalnız `127.0.0.1`'de dinliyor (ADR-001). Express + TS + PostgreSQL, tek süreç ve tek örnek kilidi var. F4 ile araç **kullanıcı eylemi olmadan, zamanlanmış olarak** dış hizmetlere istek atıyor (OSV, NVD). Ayrıca kullanıcı kararlarını (risk kabulü) sistem kendisi değiştiriyor (P-19).
- Saldırgan modelleri:
  - **(A1)** Kötü niyetli paket yayıncısı. OSV kaydı yazamaz. Paket adını ve sürümünü kontrol eder.
  - **(A2)** Taranan reponun sahibi. Lock dosyasındaki ad, sürüm, `integrity` ve lisans ipucunu kontrol eder.
  - **(A3)** Ağ konumundaki saldırgan. TLS sayesinde yalnız erişilebilirliği etkileyebilir. İstisna: `NODE_EXTRA_CA_CERTS` ile kurumsal TLS denetimi yapan bir vekil. Bu vekil yanıt içeriğini görebilir ve değiştirebilir.
  - **(A4)** OSV/NVD hizmetinin kendisi veya ele geçirilmiş bir yanıt yolu. Güven çapası sayılıyor; yine de yanıtlar güvenilmeyen veri gibi sınırlandırılmalı (ADR-007 Karar 4).

> **Yöntem kısıtı:** Rol sınırı hook'u Bash'te yalnız tek ve değiştirmeyen komutlara izin verdi. `git diff --stat`, hedefli `git diff` komutları, `npm audit --omit=dev` ve `npm audit` çalıştı. `pwd`, `git rev-parse` ve `git -C` engellendi. Testler ve dinamik ölçümler (`npx vitest run`, `node -e`) bu oturumda çalıştırılmadı. Dinamik doğrulama isteyen bulgular "doğrulanmadı" olarak işaretlendi.

## Özet

| Ciddiyet | Sayı |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 7 |
| Info | 9 |

**Merge kararı önerisi: Conditional Go.** Critical veya High bulgu yok. Şunlar sağlam tasarlanmış: ortak güvenli HTTP çekirdeği (her istekte köken ve yol denetimi, yönlendirme yok), `apiKey` kapsamı, kayıt kırpma ve temizleme, durum uç noktasının bilgi sızdırmaması ve L-5 fail-safe.

Merge öncesi koşullar:

- **M-1** (OSV yanıtından gelen açık kimliği sayısının toplamda sınırsız olması): Kimlik sayısı, ayrıntı isteği ve bulgu yazımı tüm çalıştırma için sınırsız. Ele geçirilmiş veya araya giren bir yanıt yolu (A3 kurumsal TLS vekili / A4) bellek tükenmesine ve veritabanı şişmesine yol açabilir. Toplam bir sınır eklenmeli. Eklenmeyecekse insan risk kabulü handoff'a yazılmalı.
- **L-1** (`published`/`modified` ve CVSS puanı doğrulamasının PostgreSQL ile uyuşmaması): Tek bir bozuk OSV kaydı, o paketi içeren her taramanın sonuç transaction'ını düşürebilir. Düzeltmesi küçük; merge öncesi önerilir.

## Doğrulanan kontroller (olumlu bulgular)

**SSRF / izin listesi (ADR-007 Karar 1, 2; D-87, D-88)**
- Ağ bağlantısı açan tek modül `src/lib/http/safeHttpClient.ts`. Kayıt defteri ve açık istemcileri ayrı çekirdek örnekleri; semafor, ajan ve uçuştaki istek haritaları ayrı (`client.ts:66-83`).
- Amaç tablosu (`purposes`) ve köken kümesi oluşturulurken dondurulmuş (`safeHttpClient.ts:290-291`). Çağıran yalnız amaç adı, URL ve (POST için) gövde veriyor; başlık ekleyemiyor.
- `allowedUrl` her istekte çalışıyor (`safeHttpClient.ts:322-339, 586`). WHATWG `URL` kullanıyor. Kimlik bilgisi olan URL'yi reddediyor, kökeni birebir eşleştiriyor, `https:` zorunlu (yalnız loopback test kökeninde http), ardından amacın yol kuralını uyguluyor. Üç amacın üçünde de `redirect: 'none'` var; her 3xx `REDIRECT` hatası oluyor (`endpoints.ts:108, 118, 129`; `safeHttpClient.ts:498-499`).
- Yol kuralları: `osv-querybatch` için tam `/v1/querybatch`, sorgu ve parça yok. `osv-vuln` için tek segment; decode edilen değer `OSV_ID_RE` ile eşleşmeli. Bu desen `/` içermiyor ve alfanümerik başlamak zorunda, bu yüzden `..` tek başına segment olamıyor. `nvd-cve` için tam yol ve yalnız `?cveId=CVE-\d{4}-\d{4,}` kabul ediliyor (`endpoints.ts:68-91`). Kimlikler URL'ye girmeden önce de doğrulanıyor: `osvClient.ts:155` ve `lookup.ts:259`. `encodeURIComponent` uygulanıyor (`endpoints.ts:60`).
- GET amacına gövde verilirse istek reddediliyor (`safeHttpClient.ts:588`). POST gövdesi bir kez serileştiriliyor ve yeniden denemelerde aynen gönderiliyor.
- `OSV_API_URL`/`NVD_API_URL` hiçbir yerde okunmuyor. Tanımlıysa yalnız adını veren bir uyarı yazılıyor (`endpoints.ts:149-158`, `runtime.ts`). `runtime.ts` `endpoints` geçirmiyor. Test enjeksiyonu yalnız kodla yapılabiliyor ve yalnız iki üretim kökenini ya da `http://127.0.0.1|[::1]:<port>` adresini kabul ediyor (`lib/http/endpoints.ts:35-58`).
- Vekil: `shouldUseProxy` her istekte karar veriyor. Geçersiz vekil değerinde veya `proxyEnv` desteklemeyen Node'da hiç bağlantı açılmıyor (`PROXY_UNAVAILABLE`). Loopback adresleri vekile gitmiyor (`safeHttpClient.ts:303-347`). OSV ve NVD de vekili kullanıyor.
- TLS doğrulaması hiçbir yerde kapatılmıyor.

**`NVD_API_KEY` kapsamı (ADR-007 Karar 2)**
- Anahtar yalnız `client.ts:59-60`'ta, bir kez okunuyor ve yalnız `nvd-cve` amacının `extraHeaders` closure'ında tutuluyor (`endpoints.ts:134`). Loglanabilir `VulnerabilityConfig` nesnesinde yer almıyor (`runner.config.ts`).
- Çekirdek ek başlığı ancak URL amacın kendi köken denetiminden geçtiyse ekliyor. Ek başlık, var olan başlığı ezemiyor (`safeHttpClient.ts:356-361`). Yönlendirme olmadığı için başka bir kökene taşınamıyor. Vekil üzerinden HTTPS CONNECT tüneli kullanıldığı için vekil başlığı göremiyor (kurumsal TLS denetimi hariç; I-6).
- Hatalar yalnız `err.code` ile sınıflanıyor (`safeHttpClient.ts:172-175`). Uçuştaki istek anahtarı URL'den kuruluyor, anahtar içermiyor.
- Durum uç noktası ve arayüz anahtardan türetilen hiçbir şey döndürmüyor. Hız sınırı (5 veya 50) dışarıdan gözlenemiyor; `settings` yalnız `nvd_enabled` içeriyor (`status.ts:152-157`).

**Güvenilmeyen OSV/NVD JSON'u**
- Yanıt sınırları akış sırasında uygulanıyor: önce `Content-Length`, sonra ağ baytı ve açılmış gzip baytı ayrı ayrı sayılıyor (16/8/2 MiB). Bilinmeyen `Content-Encoding` reddediliyor (`safeHttpClient.ts:399-429`).
- `parseJsonBody` içerik türünü ve üst düzey nesneyi denetliyor. `JSON.parse` `__proto__` anahtarını sahip özellik olarak oluşturuyor; prototip kirlenmesi yok. `trimOsvRecord` yalnız izinli alanları yeni bir nesneye kopyalıyor; `database_specific` ve diğer alanlar atılıyor (`osvClient.ts:264-318`). V8'in JSON ayrıştırıcısı özyinelemeli değil; derin iç içe yapı yığını taşırmıyor.
- `results.length === batch.length` ve her öğenin nesne olması zorunlu. Sayfa jetonu `^[\x20-\x7e]{1,1024}$` biçiminde olmalı. Sayfa sayısı ≤ 10, sonuç başına kimlik ≤ 1000; aşılırsa paket `unchecked` sayılıyor ve hiçbir zaman "temiz" raporlanmıyor (`osvClient.ts:136-184`).
- Metin alanları `sanitizeText` ile temizlenip kesiliyor: özet 1000 kod noktası, ayrıntı 64 KiB. Referanslarda yalnız `https:` kalıyor (`osvClient.ts:276-310`). NVD puanı 0–10 aralığında ve sonlu olmalı; vektörde kontrol karakteri olmamalı (`nvdClient.ts:41-44`). Ham NVD gövdesi saklanmıyor.
- Excel: her string hücresi formül enjeksiyonu korumasından geçiyor (`reportService.ts:631-640`, `outputText.ts:144`). Dashboard paneli yalnız `el(..., { text })` (textContent) kullanıyor; HTML enjeksiyon yüzeyi yok (`public/app.js:525-637`). Hata durumunda sunucu mesajı gösterilmiyor.

**Durum uç noktası (ADR-007 Karar 10)**
- `guard('scans:read')`, global kimlik doğrulama middleware'inin arkasında (`vulnerabilityStatusRoutes.ts:17`). `REPEATABLE READ READ ONLY` transaction kullanıyor. Yazma, audit, ağ isteği veya tetik yok. `Cache-Control: no-store` hem 200'de hem 500'de var. 500 yanıtında ham hata metni yok; logda yalnız kod var (`vulnerabilityStatusController.ts`).
- `error_summary` dönmeden önce sabit kod regex'iyle yeniden süzülüyor (`status.ts:68, 176`). Proje adı `singleLine`'dan geçiyor ve en fazla 500 proje dönüyor.

**Yeniden kontrol ve eşzamanlılık**
- Tek `running` satırı kısmi unique index ile garanti ediliyor (`uq_vulnerability_recheck_runs_running`). Her proje transaction'ı önce çalışma satırını (`runtime_run_id` fence) `FOR UPDATE` ile, sonra taramayı kilitliyor. Fence kaybolursa `FenceLost` fırlatılıyor ve çalıştırma `interrupted` oluyor. Kapanış UPDATE'i de fence koşullu (`recheck.ts:271-291, 323-347`). Açılışta süpürme ile yetim `running` satırları `interrupted` yapılıyor.
- Yalnız en son tamamlanmış tarama yazılıyor. Hiçbir şey silinmiyor veya kapatılmıyor. Tarama içinde aynı parmak izi `seen` kümesiyle ikinci kez açılmıyor. Ağ beklenirken DB bağlantısı tutulmuyor.
- Kilit kaybında (`pause`) ve kapanışta (`stop`) çalışan yeniden kontrol iptal ediliyor. Degraded modda tetik yok (`canTrigger`).

**P-19**
- "Bugün" enjekte edilen saatten hesaplanıp `$today::date` olarak geçiliyor; taşıma kontrolü de aynı tanımı kullanıyor (`findingWriter.ts:308-317`). Geçiş koşullu (`AND status = 'accepted'`), bu yüzden tekrar çalıştırmak bir şey değiştirmiyor. `FOR UPDATE SKIP LOCKED` ve iş akışı tarafındaki `FOR UPDATE` (`workflowController.ts:333`) yeniden kabul ile yarışı sıraya koyuyor. Her geçiş için aynı transaction'da null aktörlü, gerekçeli bir audit satırı yazılıyor (`expiry.ts:129-153`).

**L-5 / N-1**
- Fail-safe uyuşmazlıkta kayıt defteri lisansını da lock ipucunu da politikadan çıkarıyor; runtime paketi `NOASSERTION` bulgusu alıyor (`worker.ts:823-831`). Yan kanal ana iş parçacığında yeniden doğrulanıyor: tür denetimi, uzunluk ≤ 1024, kayıt sayısı ≤ bağımlılık sayısı (`threadParser.ts:100-110`). Bağımlılık nesnelerine `integrity` alanı eklenmiyor; golden çıktı değişmiyor.

**Tedarik zinciri**
- `package.json`/`package-lock.json` değişmemiş; yeni bağımlılık yok. `npm audit --omit=dev`: 0 açık. `npm audit`: 0 açık.

## Bulgular

### M-1 — OSV yanıtından türeyen açık kimliği, ayrıntı isteği ve bulgu sayısı toplamda sınırsız (Medium)

- **Kanıt:** `osvClient.ts:153-184`: sonuç başına ≤ 1000 kimlik ve paket başına ≤ 10 sayfa sınırı var, yani paket başına en fazla 10 000 kimlik. Tüm çalıştırma için bir sınır yok. `lookup.ts:199-247`: her benzersiz kimlik için bir ayrıntı isteği atılıyor; bu isteklerin sayısı sınırsız. `recheck.ts:368-427` ve `worker.ts` sonuç transaction'ı her kimlik için katalog satırı, bulgu, `security_findings` ve (recheck'te) audit satırı yazıyor. Yazma fazında süre bütçesi yok. Ayrıntısı alınamayan kimlik de "asgari kayıt" olarak bulgu açıyor (AC-P17-11).
- **Saldırı yolu:** A3 (kurumsal TLS denetimli vekil, `NODE_EXTRA_CA_CERTS`) veya A4, querybatch yanıtında geçerli desene uyan rastgele kimlikler döndürür. 16 MiB'lık bir yanıta yaklaşık 1,5 milyon `{"id":"X…"}` sığar. 10 000 paketlik bir recheck'te 10 temel istek ve 90 sayfa isteğine kadar çıkılabilir. Sonuçlar: (1) `ids` haritaları ve `idModified` milyonlarca girdiyle şişer ve OOM riski doğar; (2) bütçe dolana kadar her kimlik için 8 MiB'a kadar ayrıntı isteği atılır; (3) bütçe dolunca geri kalan kimlikler asgari kayıtla bulgu olarak yazılır, bu da çok büyük ve süresiz bir yazma transaction'ı ile DB şişmesi demektir. Normal OSV verisinde hiçbir paketin 1000'den fazla açığı yok; bu yüzden gerçek veride tetiklenmez.
- **Etkilenen alan:** `src/vulnerability/osvClient.ts`, `lookup.ts`, `recheck.ts`, `scanner/worker.ts` sonuç yazımı.
- **Düzeltme gereksinimi:** Paket başına toplam kimlik sınırı (tüm sayfalar dahil, ör. 200). Lookup başına benzersiz kimlik ve ayrıntı isteği sınırı (ör. 5 000). Aşılınca ilgili paketler `unchecked` olmalı ve `[osv]` satırında görünmeli. İsteğe bağlı olarak tarama ve proje başına açılan bulgu sınırı. Sınır değerleri ADR-007 Karar 4'e eklenmeli (contract değişikliği: contract-broker). Fix: backend-engineer. Test: qa-automation (sahte OSV ile 2 000 kimlikli sonuç).
- **Merge kararı:** Conditional Go. Merge öncesi düzeltilmeli; düzeltilmeyecekse insan risk kabulü handoff'a yazılmalı.

### L-1 — `isIsoDate` ve CVSS puanı doğrulaması PostgreSQL ile uyuşmuyor; tek bozuk kayıt sonuç transaction'ını düşürür (Low)

- **Kanıt:** `osvClient.ts:50-52`: `isIsoDate` için `Date.parse` sonucunun `NaN` olmaması yetiyor. V8'in esnek ayrıştırıcısı `"1"`, `"2020"` dışı serbest metinler ve `"Tue Jan 01 2030 00:00:00 GMT+0300 (x)"` gibi değerleri kabul ediyor. Bu değerler `normalize.ts:174-175` ile `published_at`/`last_modified_at` (`TIMESTAMPTZ`) sütunlarına aynen gidiyor (`findingWriter.ts:127-128, 184-185`); PostgreSQL bir kısmını `22007/22008` ile reddeder. `normalize.ts:292-299`: `parseCvssBaseScore`, `Number(vector)` ile `"1000"`, `"-3"` veya `"12"` gibi değerleri puan kabul ediyor. `vulnerabilities.cvss_score NUMERIC(4,1)` sütununda CHECK yok (`db/schema.sql:487`): `≥ 999.95` taşma (`22003`) üretir, `-3` ve `12` ise sessizce saklanır (`severityFromCvss(12)` → `critical`).
- **Saldırı yolu:** A4/A3 (veya OSV'deki gerçek bir veri hatası) tek bir açık kaydında `published: "1"` ya da `severity[0].score: "1000"` döndürür. Bu paketi içeren her tarama, sonuç transaction'ında hata alır. Etki: tarama başarısız olur veya yeniden denenir (worker'ın hata yolu; doğrulanmadı). Recheck'te ilgili proje geri alınır (`db:22`, `partial`). Kayıt önbellekte 7 gün kaldığı için hata kalıcıdır.
- **Etkilenen alan:** `src/vulnerability/osvClient.ts`, `normalize.ts`, `findingWriter.ts`.
- **Düzeltme gereksinimi:** Tarih için katı RFC 3339 regex'i kullanılmalı (`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$` ve `Date.parse`). Geçmezse alan atılmalı (kayıt reddedilmemeli). Sayısal puan yalnız `0 ≤ x ≤ 10` aralığında kabul edilmeli, aksi hâlde `null` (CVSS yok) sayılmalı. İsteğe bağlı: `vulnerabilities.cvss_score` için CHECK (database-engineer, yeni göç).
- **Merge kararı:** Merge öncesi önerilir.

### L-2 — Açma/kapama ayarları geçersiz değerde "açık"a düşüyor; `NVD_ENABLED` diğerleriyle tutarsız (Low)

- **Kanıt:** `runner.config.ts` `parseOnOffSwitch`: yalnız `on`/`off` tanınıyor. `VULNERABILITY_LOOKUP=false`, `0` veya `no` gibi değerler bir uyarıyla **açık** sayılıyor. `nvdEnabled: source.NVD_ENABLED !== 'false'`: `NVD_ENABLED=off`, `0` veya `False` verilse bile NVD açık kalıyor.
- **Saldırı yolu / senaryo:** Gizlilik nedeniyle dış trafiği kapatmak isteyen bir kullanıcı `VULNERABILITY_LOOKUP=false` veya `NVD_ENABLED=off` yazar. Paket adları ve CVE kimlikleri, kullanıcı eylemi olmadan zamanlanmış olarak dışarı gitmeye devam eder. Uyarı yalnız açılış logunda görünür.
- **Etkilenen alan:** `src/scanner/sandbox/runner.config.ts`, `.env.example`, README.
- **Düzeltme gereksinimi:** Gizlilikle ilgili anahtarlarda bilinmeyen değer kapalı kabul edilmeli (fail-closed) veya `false/0/no` da `off` sayılmalı. `NVD_ENABLED` aynı ayrıştırıcıya bağlanmalı. Contract §7'deki davranış güncellenmeli (contract-broker).
- **Merge kararı:** Merge'ü engellemez; F4 içinde düzeltilmesi önerilir.

### L-3 — Kilit kaybında süren P-19 değerlendirmesi iptal edilmiyor ve fence'siz yazmaya devam ediyor (Low)

- **Kanıt:** `scheduler.ts:245-248`: `pause()` yalnız `runController`'ı iptal ediyor; `expiryController` iptal edilmiyor. `expiry.ts:87-172` batch'ler arasında kilit veya `runtime_run_id` denetimi yapmıyor.
- **Senaryo:** Kilit kaybolur (DB oturumu kopar) ve ikinci bir örnek kilidi alıp kendi değerlendirmesini başlatır. Eski süreç, tek yazıcı ilkesine (ADR-004/007) aykırı olarak durum değişikliği ve audit satırı yazmayı sürdürür. `SKIP LOCKED` ve koşullu UPDATE sayesinde aynı bulgu iki kez açılmaz ve audit satırı çiftlenmez. Bu yüzden etki düşük; ilke ihlali ise gerçek.
- **Düzeltme gereksinimi:** `pause()` içinde `expiryController?.abort('lock-lost')` çağrılmalı. Test: kilit kaybı sırasında değerlendirmenin bir sonraki batch'te durduğu doğrulanmalı.
- **Merge kararı:** Merge'ü engellemez; düşük maliyetli olduğu için merge öncesi önerilir.

### L-4 — Devre kesici yalnız istek başında denetleniyor; 5xx/429 sayacı sıfırlıyor (Low, QA gözlemi doğrulandı)

- **Kanıt:** `safeHttpClient.ts:589`: `isHostClosed` yalnız `request()` girişinde denetleniyor. Bir istek `maxRetries=2` ile 3 deneme yapıyor (`:484-492`). Sayaç ise ancak paylaşılan istek bittikten sonra güncelleniyor (`:596`). Eşik 5 olduğunda ilk istekten sonra sayaç 3 olur, ikinci istek açık devreye girer ve 3 deneme daha yapar: toplam 6 ağ denemesi. QA'nın gördüğü "6. deneme" budur. `OSV_CONCURRENCY` (≤ 32) paralel ayrıntı isteğinde, devre açılmadan önceki deneme sayısı `eşzamanlılık × 3`'e kadar çıkar. Ayrıca herhangi bir HTTP yanıtı (5xx, 429 dahil) sayacı sıfırlıyor (`:579`). Sürekli 503 dönen bir uç devreyi hiç açtırmaz; her istek 3 deneme yapar ve bütçe dolana kadar sürer.
- **Etki:** Yük ve süre bütçe, NVD sınırlayıcısı ve semaforla sınırlı. Güvenlik etkisi düşük; erişilemeyen hizmete gereksiz yük ve uzun süren taramalar oluşur.
- **Düzeltme gereksinimi:** `run()` içinde her yeniden denemeden önce oturum sayacına bakılmalı (sayaç oturum düzeyinde, deneme anında güncellenecek biçimde) ya da davranış ADR-007 Karar 2'de "istek başına" olarak açıkça belgelenmeli. 5xx/429'un devre kesiciye sayılıp sayılmayacağına mimar karar vermeli (solution-architect).
- **Merge kararı:** Merge'ü engellemez. Belgeleme veya düzeltme handoff'a yazılmalı.

### L-5 — P-19 toplu durum değişikliğinin kapatma anahtarı ve geri alma yolu yok (Low, insan onayı kapısı)

- **Kanıt:** `scheduler.ts:9-13, 241`: değerlendirme açılışta hemen, ayarlardan bağımsız çalışıyor; `VULNERABILITY_*` anahtarları bunu durdurmuyor. `007_vulnerability_recheck.down.sql` P-19 durum değişikliklerini geri almıyor (yalnız sütun ve tablo siliyor). Boş `accepted_until` değerli eski kabuller de açılıyor (D-99, `expiry.ts:124-127`).
- **Etki alanı:** F4'ün ilk açılışında süresi dolmuş **ve süresiz olan tüm** `accepted` bulgular (eski taramalar dahil) tek seferde `open` olur. Açık bulgu sayıları ve SLA görünümü değişir. Kapı onaylı (REQ-005 Notlar, manifest). Ancak dağıtımdan önce etki ölçülemiyor; hata (yanlış saat dilimi, ileri atlamış sistem saati) olursa geri dönüş elle SQL yazılarak yapılır. Audit satırları (`entity_id`, `reason=risk_acceptance_expired`, `evaluated_for`, `review_id`) geri dönüş için yeterli bilgi taşıyor.
- **Düzeltme gereksinimi:** (1) README/handoff'a bir ön kontrol sorgusu eklenmeli: dağıtımdan önce kaç bulgunun açılacağını sayan salt okunur SQL. (2) Audit satırlarından geri dönüşü yapan, belgelenmiş ve insan onaylı bir prosedür eklenmeli; bunu çalıştırmak yine "toplu veri güncellemesi" kapısıdır. (3) İsteğe bağlı: değerlendirme için bir kapatma anahtarı (ürün kararı: product-analyst). Sistem saatinin ileri atlamasına karşı koruma (ör. `today` önceki değerlendirmeden 2 günden fazla ilerideyse uyarı) değerlendirilmeli.
- **Merge kararı:** Merge'ü engellemez. **İnsan onayı gerektirir:** ilk dağıtımın etkisi ve geri dönüş prosedürü handoff'ta onaylanmalı.

### L-6 — Tarama ile recheck'in eşzamanlı katalog yazımı: unique çakışması ve kilitlenme riski (Low, doğrulanmadı)

- **Kanıt:** `findingWriter.ts:76-192`: `upsertVulnerability` önce SELECT, sonra INSERT/UPDATE yapıyor; `ON CONFLICT` yok. `vulnerabilities.cve_id/ghsa_id/osv_id UNIQUE` (`schema.sql:481-483`). F4 ile tarama sonuç transaction'ı ve recheck proje transaction'ı aynı anda, aynı katalog satırlarına farklı sırayla yazabiliyor.
- **Senaryo:** İki transaction aynı yeni CVE'yi aynı anda ekler; ikincisi ilki commit edince `23505` alır. Ya da iki açığı ters sırayla UPDATE eden iki transaction `40P01` (deadlock) üretir. Recheck tarafında proje geri alınır (`db:23`/`db:40`, `partial`; bir sonraki çalıştırma telafi eder). Tarama tarafında sonuç transaction'ı düşer; tarama başarısız olur veya yeniden denenir (worker hata yolu; dinamik olarak doğrulanmadı).
- **Düzeltme gereksinimi:** Katalog eklemesi `INSERT … ON CONFLICT DO NOTHING` ve ardından yeniden okuma ile yapılmalı. Açıklar deterministik sırada (ör. birincil kimliğe göre) işlenmeli. `40P01`/`23505` tarama tarafında geçici hata sayılıp yeniden denenmeli. Test: qa-automation (eşzamanlı tarama + recheck).
- **Merge kararı:** Merge'ü engellemez; takip işi olarak açılmalı.

### L-7 — Recheck kapsam sorgusu, 10 000 sınırından önce tüm bağımlılık satırlarını belleğe alıyor (Low)

- **Kanıt:** `recheck.ts:175-200`: kapsam sorgusu her projenin son taramasındaki tüm `scan_dependencies` satırlarını LIMIT olmadan döndürüyor. Tekilleştirme ve `maxPackages` kesmesi uygulama tarafında yapılıyor (`:201-205`). Proje başına `keys` kümeleri de tutuluyor.
- **Etki:** Çok sayıda proje ve bağımlılık içeren bir kurulumda (ör. 500 proje × 3 000 bağımlılık = 1,5 M satır) her gün bellek sıçraması olur. Yerel tek kullanıcılı araçta düşük.
- **Düzeltme gereksinimi:** Benzersiz anahtarlar SQL'de `DISTINCT` + `ORDER` + `LIMIT 10001` ile alınmalı. Proje başına anahtarlar yazma fazında (zaten proje transaction'ında okunuyor) yeniden hesaplanmalı.
- **Merge kararı:** Merge'ü engellemez.

### Info

- **I-1 — `NVD_API_KEY` başlık değeri doğrulanmıyor.** CR/LF içeren bir anahtar Node'un `ERR_INVALID_CHAR` hatasını üretir. Bu hata mesajında başlığın değeri değil, yalnız adı bulunur; mesaj loglanmaz ve NVD "unavailable" sayılır. Sızıntı yok. Açılışta biçim denetimi (`^[A-Za-z0-9-]{1,128}$`) ve "geçersiz anahtar" uyarısı önerilir.
- **I-2 — Test ağ koruması `NVD_API_KEY`'i silmiyor** (`tests/setup/networkGuard.ts:153-159`). Geliştiricinin ortamındaki gerçek anahtar, sahte NVD sunucusuna (loopback) giden test isteklerine eklenir. Dışarı çıkmaz, ama testin yakaladığı istek başlıklarında görünebilir. `delete process.env.NVD_API_KEY` eklenmesi önerilir (qa-automation).
- **I-3 — Durum uç noktası tüm proje adlarını döndürüyor (≤ 500).** `scans:read` yetkisine sahip her rolde `projects:read` de var (`config/permissions.ts`). Tek kullanıcılı modelde proje bazlı yetki olmadığı için mevcut `/api/projects` ile tutarlı; yeni bir sızıntı yok. Çok kullanıcılı moda geçilirse proje kapsamı eklenmeli.
- **I-4 — `findings` tablosunda `(scan_id, fingerprint)` unique kısıtı yok.** Tekrarsızlık uygulama düzeyinde sağlanıyor: `seen` kümesi, tarama `FOR UPDATE` ve tek `running` satırı. Derinlemesine savunma için kısmi unique index önerilir (database-engineer, contract değişikliği gerekir).
- **I-5 — L-5 fırsatçı bir kontrol.** Lock dosyasından `integrity` silinirse ya da sha1 kullanılırsa sonuç `not_comparable` olur ve F3 davranışı (kayıt defteri lisansı) uygulanır. REQ-005 Riskler'deki "saldırgan yalnız daha muhafazakâr bir sonuç üretebilir" cümlesi bu durumu kapsamıyor. Saldırgan bulgu gizleyemez, ama `NOASSERTION`'dan kaçınabilir. Lisans, ad@sürüm için kayıt defterinden geldiği için doğru kalır. Cümle REQ/ADR'de düzeltilmeli (product-analyst).
- **I-6 — Gizlilik / dışarı giden veri.** OSV'ye son taramalardaki tüm aday bağımlılıkların (runtime ve dev) `(ekosistem, ad, kesin sürüm)` bilgisi gider. NVD'ye CVE kimlikleri ve `User-Agent: oss-risk-platform/<sürüm> (vulnerability-lookup)` gider. Vekil tanımlıysa bağlantı vekil üzerinden kurulur; kurumsal TLS denetimi varsa vekil içeriği ve `apiKey`'i görür. Bu trafik kullanıcı eylemi olmadan, her gün oluşur (onaylı). README'de bu liste açıkça yazılmalı; L-2 düzeltilmeli.
- **I-7 — Paylaşılan istekte iz her bekleyen için kaydediliyor** (`safeHttpClient.ts:595-596`). Aynı başarısızlık birden çok kez sayılır ve devre daha erken açılır (fail-fast). Zararsız; belgelenmeli.
- **I-8 — Bellek.** 16 MiB querybatch gövdesi sırayla ayrıştırılıyor; geçici bellek kabaca 100–200 MiB. Ayrıntı istekleri `OSV_CONCURRENCY` (≤ 32) × 8 MiB. Varsayılan 4 ile kabul edilebilir. 32 değeri bellek açısından README'de uyarılmalı.
- **I-9 — N-1 / ReDoS.** `parseCvssBaseScore` içindeki `(?:.*\/)?BS:` deseni girdi ≤ 256 karakterle sınırlı olduğu için pratik risk yok. `PAGE_TOKEN_RE`, `OSV_ID_RE` ve `CVE_ID_RE` çapalı ve doğrusal. N-1 lisans normalleştiricisinin doğrusal davranışı testlerle (`tests/unit/lockIntegrityN1.test.ts`) kapsanıyor; bu oturumda dinamik olarak ölçülmedi.

## Test kapsamı kanıtı (statik okuma)

- `tests/unit/vulnLookup.test.ts`, `tests/helpers/fakeOsv.ts`: sahte OSV/NVD ile querybatch, sayfalama, sınırlar, güvenli istemci ve NVD sınırlayıcısı.
- `tests/integration/vulnRecheck.test.ts`: recheck uçtan uca, zamanlayıcı, P-19 süresi.
- `tests/security/f4Static.test.ts`: kaynakta `OSV_API_URL`/`NVD_API_URL` okunmadığını, `fetch(` kullanılmadığını ve tek ağ modülü kuralını statik olarak denetliyor.
- `tests/security/vulnPanel.test.ts`: zararlı proje adının yalnız metin olarak render edilmesi, `innerHTML`/`insertAdjacentHTML` kullanılmaması, hata durumunda sunucu mesajının gösterilmemesi. Uç noktanın no-store davranışı bu dosyada değil; `tests/integration/vulnStatusWorker.test.ts` içinde aranmalı (bu oturumda okunmadı).
- `tests/security/f4Static.test.ts` ayrıca `NVD_API_KEY`'in yalnız `client.ts`'te okunduğunu ve runtime'ın endpoint geçirmediğini denetliyor.
- Eksik ve önerilen testler: M-1 (çok sayıda kimlik), L-1 (bozuk tarih/puan), L-3 (kilit kaybında P-19), L-6 (eşzamanlı tarama ve recheck).

## Merge öncesi yapılacaklar

1. **M-1:** Toplam kimlik, ayrıntı isteği ve paket başı kimlik sınırı eklenmeli; yapılmayacaksa insan risk kabulü yazılmalı.
2. **L-1:** Katı tarih doğrulaması ve 0–10 CVSS aralığı uygulanmalı.
3. (Önerilen) **L-3:** `pause()` içinde P-19 değerlendirmesi de iptal edilmeli.
4. (İnsan onayı) **L-5:** İlk dağıtımın etkisi (ön kontrol sorgusu) ve geri dönüş prosedürü handoff'ta onaylanmalı.

## Handoff notu

Bu inceleme non-trivial. `docs/handoffs/REQ-005.md` dosyasının bu raporun bulgularıyla (M-1, L-1…L-7, kabul edilen riskler ve insan onayı gerektiren L-5) güncellenmesi gerekiyor. Security Red Team handoff'u kendisi güncellemez; Delivery Lead / Integration-Release bilgilendirilmeli. Düzeltmelerden sonra Security Red Team yeniden inceleme yapacak.

---

## Yeniden doğrulama (2026-10-11)

- İnceleme aralığı: `git diff 1045dc5..HEAD`. Kapsam: contract 1.1.0 (`6d9bac3`), kod `3fdb538` ve `3cda79a` (L-3 sıradaki tetik takibi), testler `d67b327` ve `ff1609b`. 25 dosya, +2 295 / −151.
- Okunan kod: `src/vulnerability/{cvss3,validate,normalize,osvClient,lookup,findingWriter,recheck,scheduler}.ts`, `src/lib/http/safeHttpClient.ts`, `src/scanner/sandbox/runner.config.ts`, `tests/setup/networkGuard.ts`.
- Okunan dokümanlar: README F3/F4 bölümleri, `docs/contracts/REQ-005-vulnerability-data.md` §7.2, `docs/contracts/REQ-004-notice-and-outputs.md` 1.3.0 (C-24).
- Test adları yalnız statik olarak okundu: `tests/unit/f4PostReview.test.ts`, `tests/unit/vulnLookupPostReview.test.ts`, `tests/integration/f4PostReview.test.ts`.
- **Yöntem kısıtı:** Bu oturumda test çalıştırılmadı. "1033 geçti / 2 atlandı / 0 kırmızı" sonucu QA'nın beyanıdır. Ana oturumun gerçek ağ ölçümleri de **beyan** olarak alındı, doğrulanmadı.

### Bulgu durumu

| ID | Durum | Kanıt / not |
| --- | --- | --- |
| **M-1** | **Kapandı** | Paket başına tüm sayfalar dahil ≤ 200 benzersiz kimlik (`id_limit`), lookup başına ≤ 5 000 benzersiz kimlik (`total_id_limit`, referans sayımlı; düşürülen paket kendi getirdiği kimlikleri serbest bırakıyor) (`osvClient.ts`, `runner.config.ts` `osvMaxIdsPerPackage/osvMaxDistinctIds`). Ağ ayrıntı isteği ≤ 2 000 (`detail_limit`, `lookup.ts`). Recheck yazma fazı 30 dk çalıştırma sınırına bağlı: her proje transaction'ından ve her bağımlılıktan önce `deadlineMs` denetleniyor, dolunca o anki proje `ROLLBACK` ediliyor ve sonuç `partial` + `osv:time_limit` oluyor (`recheck.ts` `WriteTimeLimit`). `WriteTimeLimit` bağlantıyı bozuk saymıyor; yalnız o proje geri alınıyor, daha önce commit edilen projeler kalıyor. Bellek ve yazma hacmi artık sınırlı. Testler: `vulnLookupPostReview` (201/200, sayfalar arası 101+100, 5001, 2001), `f4PostReview` entegrasyon (yazma sınırı geri alma). Kalan: Y-1. |
| **L-1** | **Kapandı** | `validate.ts`: katı RFC 3339 deseni, takvim ve saat denetimi, yıl 0001–9999, `toISOString()` ile normalleştirme. Geçersiz alan yok sayılıyor, kayıt korunuyor. `published`/`modified` (`osvClient.ts`, `normalize.ts`) ve querybatch `modified` için geçerli; geçersiz `modified` yalnız yeniden çekmeyi tetikliyor ve ayrıntı sınırına tabi. Sayısal puan yalnız sonlu ve `0 ≤ x ≤ 10` aralığında kabul ediliyor (`validCvssScore`); `BS:` yolu da aynı denetimden geçiyor. Kalan: `withdrawn` hâlâ esnek `isIsoDate` ile okunuyor (I-12). |
| **L-2** | **Kapandı** | Tek ayrıştırıcı `parseSwitch`: `on/true/1/yes` → açık, `off/false/0/no` → kapalı, boş → açık, diğer değer → **kapalı** + yalnız değişken adını içeren tek uyarı. `VULNERABILITY_LOOKUP`, `VULNERABILITY_RECHECK`, `NVD_ENABLED` ve `REGISTRY_ENRICHMENT` bunu kullanıyor. README ve REQ-004 contract 1.3.0 C-24 güncellendi. Bkz. I-10. |
| **L-3** | **Kapandı** | `pause()` ve `stop()`, canlı her P-19 değerlendirmesinin denetleyicisini iptal ediyor; mutex arkasında bekleyen tetik tek slotu ezemiyor (`expiryControllers` kümesi, `3cda79a`). `canTrigger()` sıradaki tetiği de durduruyor. Bir batch commit sırasında iptal edilirse o batch geri alınıyor (`expiry.ts:154-158`). |
| **L-4** | **Kapandı** | Devre kesici her denemede güncelleniyor ve her denemeden önce denetleniyor. `429`/`5xx` başarısız deneme sayılıyor (`fail`); diğer HTTP yanıtları sayacı sıfırlıyor (`safeHttpClient.ts` `AttemptBreaker`). Sürekli 503 dönen uç artık 5 denemede kapanıyor. Paylaşılan istekte izi yalnız başka oturumların bekleyenleri yeniden oynatıyor; çift sayım yok. Testler: kalıcı 503, uzun `Retry-After`'lı 429, 404 sıfırlaması. Yan etki: NVD 429'ları artık devreye sayılıyor (Y-2). |
| **L-5** | **Belgelendi; insan onayı bekliyor** | README'de ön kontrol SQL'i var (salt okunur transaction, `expiry.ts` ile aynı seçim kuralı, `<BUGUN>` = sunucunun yerel tarihi). Contract §7.2(b)'de insan onaylı geri alma prosedürü var: önce durdur, yedek al, nedeni düzelt, salt okunur sayım yap, tek transaction'da sayı uyuşmazsa `ROLLBACK`. Sonradan kullanıcı veya sistem işlemi görmüş bulgular hariç tutuluyor; yalnız `status = 'open'` olanlar geri dönüyor; telafi audit satırı (`risk_acceptance_expiry_reverted`) yazılıyor; orijinal audit satırları silinmiyor. Kapatma anahtarı bilinçli olarak eklenmedi (V-19, ürün kararı). Prosedürün iki zayıf noktası I-13'te. **İnsan kabul metni (önerilen, handoff'a):** "F4'ün ilk açılışında P-19, ön kontrol sorgusunun `would_reopen` sayısı kadar kabul edilmiş bulguyu (süresi geçmiş, süresiz ve incelemesiz olanlar dahil) kullanıcı eylemi olmadan `open` yapacaktır. Bu sayıyı `<tarih>` tarihinde `<N>` olarak gördüm ve kabul ediyorum. Değerlendirmenin kapatma anahtarı yoktur; yanlış değerlendirmede yalnız contract §7.2(b) prosedürü, ayrı insan onayıyla uygulanacaktır." |
| **L-6** | **Kısmen kapandı** | Unique yarışı kapandı: katalog eklemesi `ON CONFLICT DO NOTHING` kullanıyor; satır eklenmezse bir kez yeniden okunup güncelleme yoluna gidiliyor, ikinci başarısızlık sentetik `23505` üretiyor (`findingWriter.ts`). Entegrasyon testi iki eşzamanlı transaction'ın tek katalog satırıyla commit ettiğini gösteriyor. **Açık kalan:** ters sırada `UPDATE vulnerabilities` kaynaklı `40P01` (deadlock) riski. Sıralama veya yeniden deneme eklenmedi ve test yok (Y-3). Hedefsiz `ON CONFLICT` değerlendirmesi I-11'de. |
| **L-7** | **Kapandı** | Kapsam, SQL'de benzersiz koordinatlar üzerinden keyset ile sayfalanıyor (sayfa 5 000, `COLLATE "C"`). Proje başına anahtarlar yazma transaction'ında yeniden hesaplanıyor. Bellekte en fazla 10 000 temsilci ve bir sayfa tutuluyor. Test: 10 001 paket, hiçbir sorgu 5 000'den fazla satır döndürmüyor. Küçük sapmalar I-14'te. |
| I-1 | Kabul edildi | Anahtar biçimi hâlâ doğrulanmıyor; sızıntı yok (Node yalnız başlık adını bildiriyor, loglanmıyor). Düşük öncelikli iyileştirme. |
| I-2 | **Kapandı** | `tests/setup/networkGuard.ts` artık `NVD_API_KEY`'i siliyor; `tests/unit/networkGuard.test.ts` güncellendi. |
| I-3 | Kabul edildi | Tek kullanıcılı modelde `/api/projects` ile tutarlı. Çok kullanıcılı moda geçilirse yeniden açılmalı. |
| I-4 | Kabul edildi (takip) | `(scan_id, fingerprint)` unique kısıtı yok. Uygulama düzeyindeki koruma yeterli; derinlemesine savunma için takip işi. |
| I-5 | **Kapandı (belgelendi)** | README L-5 maddesine "Bilinen sınır" eklendi (`integrity` silinirse `not_comparable` ve F3 davranışı). REQ/ADR'deki "yalnız daha muhafazakâr sonuç" cümlesinin düzeltilmesi product-analyst'te. |
| I-6 | **Kapandı (belgelendi)** | README'de OSV/NVD'ye ne gidip ne gitmediği listelendi; zamanlanmış trafik ve kapatma ayarları yazıldı. Kurumsal TLS denetimli vekilin içeriği ve `apiKey`'i görebileceği açıkça yazılmamış; eklenmesi önerilir. |
| I-7 | **Kapandı** | L-4 düzeltmesiyle başlatan oturum izi yeniden oynatmıyor; çift sayım kalktı. |
| I-8 | Kabul edildi | M-1 sınırlarıyla kimlik haritaları da sınırlı. `OSV_CONCURRENCY=32` bellek uyarısı README'de yok; düşük öncelik. |
| I-9 | Kapandı | Değişiklik yok. Yeni CVSS hesaplayıcı için bkz. P-1 değerlendirmesi. |

### Düzeltmelerin getirdiği değişikliklerin değerlendirmesi

**P-1 — Yerel CVSS v3 hesaplayıcı (`src/vulnerability/cvss3.ts`): sorun bulunmadı**
- Girdi doğrulama: önek tam olarak `CVSS:3.0/` veya `CVSS:3.1/` olmalı, uzunluk ≤ 256. `split('/')` ile ayrıştırılıyor. Boş bileşen, sondaki `/`, `:` eksikliği, tekrarlanan metrik, bilinmeyen metrik ve geçersiz değer `null` döndürüyor. 8 taban metriğin hepsi zorunlu. Metrik adı `hasOwnProperty` ile aranıyor; `__proto__`/`constructor` adları reddediliyor. Regex yok, ReDoS yüzeyi yok. Döngü en fazla ~128 bileşen.
- Sayısal uç durumlar: ağırlıklar sabit tablodan geliyor. `impact ≤ 0` → 0; kapsam değiştiğinde ISS=0 için negatif etki 0'a düşüyor. `min(…, 10)` sonra `roundUp` uygulanıyor; sonuç her zaman 0.0–10.0 aralığında ve bir ondalıklı, yani `NUMERIC(4,1)` ile uyumlu. `roundUp` v3.1 Ek A'nın tamsayı yöntemi. v3.0 vektörlerinde NVD'nin v3.0 yuvarlamasından nadir kayan nokta sınır durumlarında 0.1 fark olabilir; güvenlik etkisi yok (sınıf eşiği yalnız tam sınırda değişebilir).
- Sıra: önce geçerli sayısal puan (0–10), sonra yalnız `type === 'CVSS_V3'` olan ilk geçerli vektör, sonra NVD. `CVSS_V4`/`CVSS_V2` vektörleri yerelde puanlanmıyor. Kaynak yalnız `advisory_data.cvss.source` içinde tanılama olarak tutuluyor.
- Testler: kayıtlı NVD vektör/puan çiftleri, sıra bağımsızlığı, geçersiz vektörler ve `roundUp`.
- Güven notu: Puanın kaynağı artık NVD değil, OSV'deki vektör. Kötü niyetli bir OSV kaydı (A4) zaten sayısal puanla aynı etkiyi yaratabiliyordu. Yeni bir güven genişlemesi yok.

**L-2 — `REGISTRY_ENRICHMENT` için de fail-closed: kabul edilebilir (I-10)**
- Davranış F3'ten farklı: geçersiz değer artık zenginleştirmeyi kapatıyor. Lisanslar lock ipucundan (doğrulanmamış) geliyor ve uyarılarda `[registry] License enrichment disabled` satırı çıkıyor. Lisans doğruluğu sessizce düşmüyor; görünür. Gizlilik açısından doğru yön. REQ-004 contract 1.3.0 C-24 ile onaylı. ADR-006 Karar 14 ve REQ-004 AC-P14-16 metinlerinin güncellenmesi açık (solution-architect / product-analyst).

**L-4 — Deneme başına devre kesici: doğru; NVD'de yan etkisi var (Y-2)**

**L-6 — Hedefsiz `ON CONFLICT DO NOTHING`: kabul edilebilir (I-11)**
- Hedefsiz ifade, `cve_id`/`ghsa_id`/`osv_id` unique kısıtlarının ve PK'nın hepsinde çakışmayı yutuyor. Bir kez yeniden okuma ve ardından sentetik `23505` ile sonsuz döngü ve sessiz veri kaybı engelleniyor: çakışan satır ikinci okumada bulunursa güncelleme yolu çalışıyor. İleride eklenecek başka bir unique kısıt da sessizce bu yola girer; kısıt adlarını açıkça yazmak (`ON CONFLICT ON CONSTRAINT …`) mümkün değil, çünkü birden çok hedef var. Bu yüzden mevcut biçim makul. Güncelleme yolundaki `COALESCE` ile başka bir satırın kimliğine çakışma F3'ten kalan bir davranış ve kapsam dışı.

**L-7 — Sayfalı kapsam SQL'i: doğru (I-14)**
- Parametreli; keyset karşılaştırmasında açık `COLLATE "C"` örtük collation'a baskın geliyor, ORDER BY ile tutarlı. Sayfalama SQL değerleri üzerinde tutarlı olduğu için satır atlanmıyor veya döngüye girilmiyor.

**M-1 — Yazma fazı sınırı ve geri alma: doğru (Y-1)**

### Yeni bulgular

#### Y-1 — Recheck yazma fazı, lookup'ın bütçesini tamamen tükettiği durumda hiç süre alamıyor (Low)
- **Kanıt:** `recheck.ts`: lookup `budgetMs: runTimeoutMs` (30 dk) ile, lookup başlangıcından itibaren çalışıyor. Yazma son tarihi ise `startMs + runTimeoutMs`; P-19 ve kapsam okuma süresi de buna dahil. Lookup bütçesini doldurursa (ör. anahtarsız NVD ile yüzlerce CVE: 5 istek / 30 sn) yazma döngüsü ilk projede `clock.now() >= deadlineMs` görüyor ve hiçbir şey yazmıyor. Başarılı OSV sonuçlarından gelen yeni bulgular atılıyor (`partial`, `osv:time_limit`).
- **Etki:** Büyük envanterde ilk günlerde yeni açık bulguları gecikir. OSV ayrıntı ve NVD önbelleği lookup'tan bağımsız yazıldığı için sonraki çalıştırmalar hızlanır ve sorun kendiliğinden düzelir. Güvenlik etkisi gecikme ile sınırlı.
- **Düzeltme:** Tarama tarafındaki formüle benzer şekilde yazma fazı için süre ayrılmalı, ör. `lookupBudget = min(runTimeoutMs × 3/4, deadline − now − 5 dk)`. Ya da NVD adımı bütçenin bir payıyla sınırlanmalı. Test: lookup bütçeyi doldurduğunda en az bir proje yazılmalı.
- **Merge kararı:** Merge'ü engellemez; takip işi.

#### Y-2 — NVD hız sınırlayıcısında güvenlik payı yok; 429'lar artık devre kesiciye sayılıyor (Low)
- **Kanıt ve analiz:** Sınırlayıcı, deneme **başlangıçlarını** yerel saatle tam 30 000 ms pencerede sayıyor ve slotu `starts[0] + windowMs` anında serbest bırakıyor (`rateLimiter.ts`). NVD ise isteklerin **varış** zamanını kendi kayan penceresinde sayıyor. Bağlantı, TLS el sıkışması veya vekil gecikmesi isteğe göre değişir. k. istek 0,8 sn'de, k+5. istek 30,1 sn'de varırsa NVD 29,3 sn'de 6 istek görür ve 429 döner. Ayrıca NVD'nin anahtarsız kullanımda istekler arasında yaklaşık 6 sn beklenmesini önerdiği ve gerçek eşiği değişken uyguladığı biliniyor (REQ-005 Riskler: "doğrulanmalıdır"). Beyan edilen 3–4 adet 429 bu açıklamayla tutarlı. L-4 sonrasında her 429 bir `fail` adımı: arada başarılı yanıt olmadan art arda 5 başarısızlık, oturum boyunca NVD hostunu kapatır ve kalan CVE'ler "CVSS unavailable" olur. Her 429 yeniden denemesi de bir sınırlayıcı slotu tüketiyor.
- **Etki:** Erişilebilirlik ve doğruluk. CVSS alınamayan açık `medium` varsayılanıyla yazılır; kritik bir açığın SLA'sı 90 gün olur. NVD'ye zarar veren bir yük yok.
- **Düzeltme:** Pencereye güvenlik payı eklenmeli (ör. 30 sn yerine 33–35 sn) veya anahtarsız kullanımda en az 6 sn aralık zorunlu olmalı. NVD 429'unda `Retry-After` yoksa en az bir pencere beklenmeli. NVD için 429'u devre kesicide ayrı tutmak (yalnız ağ hatası ve 5xx saymak) değerlendirilmeli (solution-architect). `NVD_API_KEY` önerisi README'de daha görünür olmalı.
- **Merge kararı:** Merge'ü engellemez; takip işi.

#### Y-3 — L-6'nın deadlock kısmı açık (Low, doğrulanmadı)
- **Kanıt:** Katalog güncellemeleri belirlenimci bir sırada yapılmıyor. Tarama veya recheck tarafında `40P01` için yeniden deneme yok (`src/vulnerability`, `scanner/worker.ts`: `40P01` geçmiyor).
- **Etki:** Tarama ile recheck'in aynı anda, ortak iki açığı ters sırayla güncellemesi gerekiyor; olasılık düşük. Recheck projesi `db:40` ile geri alınır ve bir sonraki çalıştırmada telafi edilir. Tarama sonuç transaction'ı düşerse tarama başarısız olur veya yeniden denenir.
- **Düzeltme:** Bir projenin veya taramanın açıkları upsert'ten önce birincil kimliğe göre sıralanmalı. Ya da `40P01` geçici hata sayılıp transaction bir kez yeniden denenmeli. Test eklenmeli.
- **Merge kararı:** Merge'ü engellemez; takip işi.

#### Info (yeni)
- **I-10:** `REGISTRY_ENRICHMENT` fail-closed davranış değişikliği (yukarıda). Kabul edildi; ADR-006/REQ-004 metin güncellemesi açık.
- **I-11:** Hedefsiz `ON CONFLICT DO NOTHING` (yukarıda). Kabul edildi.
- **I-12:** `withdrawn` hâlâ esnek `isIsoDate` ile okunuyor (`osvClient.ts` `trimOsvRecord`). Değer DB sütununa yazılmadığı için `22007` riski yok. Ancak `"x 2020"` gibi bir değer kaydı geri çekilmiş sayar ve bulguyu gizler. A4 kaydı zaten geri çekebildiği için yeni bir yüzey yok. Tutarlılık için `normalizeRfc3339` kullanılması önerilir.
- **I-13:** Geri alma prosedüründe (contract §7.2(b)) iki zayıf nokta var:
  - Eşit `occurred_at` durumunda sıra `audit_logs.id` ile ayrılıyor. `id` rastgele UUID ise bu sıra anlamsızdır (pratikte eşit zaman damgası çok düşük olasılık).
  - Senaryo "ileri atlamış sistem saati" ise P-19 audit satırlarının `occurred_at` değeri gelecekte olur. Sonraki kullanıcı işlemleri "önce" görünür ve "sonradan dokunulmuş" denetimi onları hariç tutmaz. `f.status = 'open'` koşulu kullanıcı kararlarının (accepted/false_positive/in_review) ezilmesini zaten engelliyor; kalan risk, kullanıcının bilerek `open` bıraktığı bir bulgunun eski kabul durumuna dönmesi. Prosedüre "saat atlaması senaryosunda karşılaştırmayı `occurred_at` yerine DB `NOW()` tabanlı bir sütunla veya elle gözden geçirerek yap" notu eklenmeli.
- **I-14:** Sayfalı kapsamda PyPI adı SQL'de `lower(regexp_replace(...))` ile kuruluyor. Veritabanı `LC_CTYPE` Türkçe ise `lower('I')` ≠ JS `toLowerCase`. Koordinat denetimi ASCII adlara izin verdiği için yalnız `I` harfi etkilenir. Etkisi: aynı JS anahtarı iki SQL grubunda görünebilir; `representative.has` tekilleştiriyor, ama sınır aşıldıktan sonra `overLimit` aynı anahtarı iki kez sayabilir (yalnız `packages_unchecked` sayacı). Satır atlanmıyor. Veritabanı C/en yereliyle kuruluysa (`db/README.md` önerisi) etkisiz.
- **I-15 — Gerçek ağ kanıtı (beyan, doğrulanmadı):**
  - İlk tarama 649 sn'den 326 sn'ye indi; NVD isteği 96'dan 43'e düştü; 3–4 adet 429 alındı.
  - Tarama başına 1 OSV querybatch; ikinci taramada 0 ayrıntı isteği (önbellek çalışıyor).
  - Yeniden başlatmadan 61 sn sonra telafi recheck'i 2,6 sn'de tamamlandı (758 paket, 0 yeni bulgu).
  - Durum uç noktası 200 ve `no-store` döndü, anahtardan söz etmedi; loglarda secret yok.
  - Bu değerler kod okumasıyla tutarlı: ilk kontrol gecikmesi 60 sn, `no-store` her iki yolda var, anahtar yalnız closure'da.
- **I-16 — Kalan ilk tarama gecikmesi ve "NVD'yi arka plana taşıma" takibi:** 43 NVD isteği anahtarsız sınırla (5 / 30 sn) en az ~258 sn sürer. Yani 326 sn'nin büyük kısmı hız sınırından kaynaklanıyor; `NVD_API_KEY` ile ~26 sn'ye iner. NVD CVSS'in arka plan recheck'ine taşınması güvenlik açısından şu koşullarla kabul edilebilir:
  1. CVSS gelene kadar bulgu "CVSS bekleniyor" olarak görünür işaretlenmeli; `medium` varsayılanı kesin bir değer gibi sunulmamalı.
  2. CVSS geldiğinde açık bulguların `security_findings.severity/cvss_score` ve **SLA son tarihi** yeniden hesaplanmalı ve audit'e yazılmalı. Aksi hâlde kritik bir açık 7 yerine 90 günlük SLA ile kalır.
  3. Arka plan işi aynı sınırlayıcıyı ve devre kesiciyi paylaşmalı (Y-2).
  4. Contract ve ADR revizyonu gerekir (contract-broker / solution-architect).

### Tedarik zinciri
- `package.json`/`package-lock.json` bu düzeltmelerde değişmedi; yeni bağımlılık yok. İlk incelemedeki `npm audit` sonuçları (0/0) geçerli. Bu turda yeniden çalıştırılmadı.

### Nihai karar: **Go**

- İlk incelemenin merge öncesi koşulları (M-1, L-1) kapandı. Önerilen L-3 kapandı. Critical, High veya Medium bulgu kalmadı.
- Kalan bulgular Low veya Info ve takip işi olarak açılmalı: Y-1, Y-2, Y-3, I-6 eki, I-12, I-13 notu.
- **Merge öncesi kalan zorunlu iş: yok** (kod tarafında).
- **İnsan onayı kapıları (açık):**
  1. L-5: ilk dağıtımdan önce ön kontrol sorgusunun çalıştırılması ve `would_reopen` sonucunun yukarıdaki kabul metniyle handoff'ta onaylanması.
  2. `main` merge onayı.
  3. Gerçek ağ doğrulamasının (I-15) handoff'a kullanıcı beyanı olarak işlenmesi.
- Handoff: `docs/handoffs/REQ-005.md` bu bölümle güncellenmeli (Delivery Lead / Integration-Release). Takip işleri (Y-1…Y-3, I-16 tasarım koşulları) backlog'a alınmalı.

### Takip doğrulaması (2026-10-11)

- İnceleme aralığı: `git diff 9aee953..f79d3d5 -- src/` ve README I-6 maddesi.
- Testlerin (`f0facaa`) "1048 geçti / 2 atlandı / 0 kırmızı" sonucu QA'nın beyanıdır.
- Gerçek ağ tekrarının sonuçları da ana oturumun beyanıdır, doğrulanmadı: ilk tarama 345 sn, 40 NVD isteği, **0 adet HTTP 429** (önce 3–4); ikinci tarama 4 sn ve 0 ayrıntı isteği; telafi recheck'i 2,7 sn (758 paket).
- Bu turda test çalıştırılmadı.

| ID | Durum | Kanıt / not |
| --- | --- | --- |
| **Y-1** | **Kapandı** | Lookup bütçesi, çalıştırma başlangıcından itibaren `runTimeoutMs × 5/6`'da bitecek şekilde hesaplanıyor; P-19 ve kapsam okuma süresi de buna dahil. Yazma fazına en az 5 dk kalıyor (`recheck.ts` `lookupBudgetMs`, `runner.config.ts` `lookupBudgetShare`). Önceki adımlar 25 dk'yı aşarsa bütçe 1 ms olur, lookup `time_limit` ile boş döner ve hiçbir şey yazılmaz. `time_limit` kodu yeni bütçeye göre veriliyor. |
| **Y-2** | **Kapandı** | Pencere 35 sn. Anahtarsız kullanımda iki başlangıç arası en az 6 sn; bu, ortalama 7 sn/istekle 5/35 sn'den daha sıkı değil, onunla uyumlu. NVD 429'u, sınırlayıcıyı tüm oturumlar için duraklatıyor: kullanılabilir bir `Retry-After` varsa (≤ 30 sn) o kadar, yoksa bir pencere boyu (`client.ts` `onNvdResponse`, `rateLimiter.ts` `pause`). `pause` yalnız uzatıyor, kısaltmıyor; geçersiz veya negatif değerleri yok sayıyor. `onResponse` yalnız `nvd-cve` amacına bağlı ve atmayan `parseRetryAfter` kullanıyor; duraklama süresi sunucu tarafından en fazla 30 sn veya bir pencereyle sınırlı, kötüye kullanım yüzeyi yok. NVD 429'ları devre kesicide sayılmaya devam ediyor (L-4 anlamı değişmedi). Duraklama ve aralık sayesinde art arda 5 adet 429 pratikte beklenmiyor; beyan edilen 0 adet 429 bununla tutarlı. Bekleme hâlâ abortable ve FIFO. |
| **Y-3** | **Kapandı (kalan risk düşük)** | `upsertVulnerability` bir savepoint içinde çalışıyor. `40P01` veya `40001` gelirse `ROLLBACK TO SAVEPOINT` yapılıyor, rastgele gecikmeyle bir kez yeniden deneniyor, ikinci hata yukarı atılıyor. Recheck ayrıca proje transaction'ını bir kez yeniden deniyor; deneme öncesinde iptal ve son tarih denetleniyor (`writeProjectWithRetry`). Savepoint geri alma, savepoint'ten **önce** alınmış kilitleri bırakmaz; bu yüzden aynı çift yeniden çakışabilir. Recheck tarafında bunu proje düzeyindeki yeniden deneme kapatıyor. Tarama tarafında yalnız savepoint denemesi var; ikinci bir deadlock, taramanın sonuç transaction'ını düşürür ve mevcut başarısızlık/yeniden deneme yoluna girer. Olasılık düşük, sonuç görünür ve veri bozulmuyor; kabul edildi. |
| **I-6** | **Kapandı** | README'ye "Kurumsal TLS denetimi yapan vekil istek içeriğini görür" notu eklendi. Not, paket adları ve sürümleri, açık ve CVE kimlikleri ile `NVD_API_KEY` tanımlıysa NVD isteklerindeki `apiKey` başlığının düz metin görünebileceğini açıkça söylüyor. |

**Yeni sorun:** Yok. `jitteredDelay` enjekte edilen saat yerine `setTimeout` kullanıyor ve iptal edilemiyor; bu yalnız 50–100 ms'lik bir gecikme, güvenlik etkisi yok (bilgi notu).

**Nihai karar: Go.** Kod tarafında merge öncesi zorunlu iş yok. Açık kalanlar yalnız insan onayı kapıları:
1. L-5: ilk dağıtımdan önce ön kontrol sorgusunun `would_reopen` sonucu kabul metniyle handoff'ta onaylanmalı.
2. `main` merge onayı.
3. Gerçek ağ kanıtları handoff'a kullanıcı beyanı olarak işlenmeli.

Takip işleri: I-12 (`withdrawn` için katı tarih), I-13 (geri alma prosedürü notu), I-16 (NVD'nin arka plana taşınması tasarım koşulları), I-4 (unique kısıt).
