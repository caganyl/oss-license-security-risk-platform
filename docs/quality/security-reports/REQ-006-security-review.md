# REQ-006 — Güvenlik İncelemesi (F5: NuGet ayrıştırıcı, güvenli XML okuyucu, nuspec/nupkg zenginleştirme, imzalı paket içerik hash'i, nupkg NOTICE, OSV NuGet)

- İnceleyen: Security Red Team (adversarial review, read-only)
- Tarih: 2026-10-11
- Branch: `req-006-f5-dotnet` (HEAD: `ea386fa`), `req-005-f4-guvenlik-aciklari` üzerine yığılı
- İnceleme aralığı: `req-005-f4-guvenlik-aciklari..HEAD` (5 commit: `986ecab`, `3b2f466`, `58f6a6f`, `2ae605b`, `ea386fa`)
- Kaynaklar: `docs/product/REQ-006.md` (r2), ADR-008, `docs/contracts/REQ-004-notice-and-outputs.md` (1.4.0), `docs/contracts/REQ-005-vulnerability-data.md` (1.2.0), `docs/quality/security-reports/REQ-005-security-review.md`.
- İncelenen kod: `src/scanner/parsers/{xmlReader,nugetIdentity,nugetLock,nugetAssets,msbuildProject,nuget,common,lockIntegrityValue}.ts`, `src/enrichment/{nugetRegistry,nugetLicenseUrls,coordinates,cache,index,archiveStage,registryClient}.ts`, `src/enrichment/archive/{nupkgHash,zip,extract,licenseFiles,thread}.ts`, `src/lib/http/safeHttpClient.ts` (gzip sınırı), `src/vulnerability/{lookup,recheck}.ts`, `db/migrations/008_nuget_enrichment.{up,down}.sql`, `public/index.html`.
- Tehdit bağlamı: Kişisel, tek kullanıcılı Windows aracı; sunucu yalnız `127.0.0.1` (ADR-001). F5 ile taranan repodaki XML/JSON .NET dosyaları ayrıştırılıyor ve `api.nuget.org` üzerinden `.nuspec`/`.nupkg` indiriliyor.
- Saldırgan modelleri:
  - **(A1)** Kötü niyetli NuGet paket yayıncısı: `.nuspec` içeriğini (id büyük/küçük harfi, lisans alanları) ve `.nupkg` içeriğini kontrol eder; nuget.org'un depo imzasını kontrol edemez.
  - **(A2)** Taranan reponun sahibi: `*.csproj`, `Directory.Packages.props`, `packages.config`, `packages.lock.json`, `obj/project.assets.json` içeriğini, dosya boyutlarını ve dizin yapısını kontrol eder.
  - **(A3)** Ağ konumundaki saldırgan: TLS nedeniyle yalnız erişilebilirliği etkiler; istisna `NODE_EXTRA_CA_CERTS` ile kurumsal TLS denetimi yapan vekil.
  - **(A4)** nuget.org/OSV hizmetinin kendisi veya ele geçirilmiş yanıt yolu: güven çapası, ama yanıtlar güvenilmeyen veri gibi sınırlandırılmalı.

> **Yöntem kısıtı:** Rol sınırı hook'u Bash'te yalnız tek ve değiştirmeyen komutlara izin verdi; `pwd`, `git rev-parse`, `git diff --stat` ve `git -C` engellendi. İnceleme Read/Grep/Glob ile statik yapıldı. `npm audit --omit=dev` çalıştı (0 açık). Testler ve dinamik ölçümler (bellek, süre) bu oturumda çalıştırılmadı; ana oturumun beyan ettiği kanıt (imzalı Newtonsoft.Json 13.0.3/13.0.1 içerik hash'i = lock `contentHash`, bitwarden/server ve MediatR gerçek ağ smoke'u, 1212 geçti / 3 atlandı) doğrulanmamış girdi olarak kabul edildi. Dinamik doğrulama isteyen bulgular "doğrulanmadı" olarak işaretlendi.

## Özet

| Ciddiyet | Sayı |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 5 |
| Info | 8 |

**Merge kararı önerisi: Go (koşulsuz; Low maddeler takip işi).** Critical, High veya Medium bulgu yok. En riskli yüzeyler (XML ayrıştırma, imzalı paket içerik hash'i ile bütünlük kabulü, nupkg içi yol eşleme, SSRF izin listesi) sağlam tasarlanmış ve statik incelemede atlatma yolu bulunamadı. Low bulgular (L-1…L-5) merge'i engellemez; L-1 ve L-2'nin bir sonraki iterasyonda kapatılması önerilir.

## Doğrulanan kontroller (olumlu bulgular)

**Güvenli XML okuyucu (`src/scanner/parsers/xmlReader.ts`)**
- DTD hiç işlenmiyor: yorum ve CDATA dışındaki her `<!` yapısı (`<!DOCTYPE`, `<!ENTITY`) `doctype` hatası (`xmlReader.ts:307`). Yalnız beş öntanımlı varlık ve sayısal karakter referansı çözülüyor; genişletme olmadığı için billion laughs / quadratic blowup / XXE yapısal olarak imkânsız (`xmlReader.ts:190-229`). Sayısal referans en fazla 8 hane ve `isXmlChar` ile sınırlı; vekil (surrogate) ve NUL kod noktaları reddediliyor.
- Harici kaynak, şema, `xml-stylesheet` veya ad alanı çözümü yok; `<?...?>` işlem talimatları atlanıyor (`xmlReader.ts:287-292`). Modülün hiç import'u yok.
- Tarama tek geçişli ve ileri yönlü; tüm sonlandırıcılar `indexOf` ile mevcut konumdan aranıyor, regex yok. Kapanmamış tırnak/yorum/CDATA en fazla bir kez dosya sonuna kadar taranıp hata veriyor; imleç geri gitmiyor, O(n).
- Sınırlar tarama sırasında: derinlik 64, eleman 200 000, değer/metin 64 KiB, öznitelik 256, ad 256 karakter (`xmlReader.ts:49-55`). Ayrıştırıcı yığın tabanlı (özyineleme yok); `msbuildProject.ts:86-96`'daki özyinelemeli `visit` derinlik 64 ile sınırlı.
- Kodlama: UTF-8 BOM, UTF-16 LE/BE BOM destekleniyor; BOM'suz UTF-16 (`3C 00` / `00 3C`) açıkça reddediliyor (UTF-32 de bu kontrole takılıyor). Çözücüler `fatal: true`; geçersiz bayt dizisi `encoding` hatası. Bildirilen kodlama UTF-8/16 dışındaysa yalnız saf ASCII metin kabul ediliyor (`xmlReader.ts:138-157`).
- `XmlError` mesajı yalnız sabit koddan üretiliyor; belge içeriği hiçbir hata metnine girmiyor (`xmlReader.ts:60-67`, `msbuildProject.ts:30-48` sabit `NUGET_MESSAGES`).

**MSBuild değerlendirmesi ve süreç başlatma**
- `src/scanner/parsers` altında `child_process`, `spawn`, `exec` yok; `dotnet` süreci başlatılmıyor. `Import`, `Sdk`, `PropertyGroup`, `Condition`, `$(…)` değerlendirilmiyor; `$(…)` içeren sürüm `unknown` sınıflanıyor (`msbuildProject.ts:6-11`, `nugetIdentity.ts:118-131`). `Target` altındaki `ItemGroup`'lar okunmuyor; `Exec` görevi hiçbir şekilde yorumlanmıyor.

**CPM yukarı yürüyüş ve symlink**
- `centralPackages` dosya sistemine gitmiyor; yalnız tarama yürüyüşünün ürettiği `dotnetByDir` haritasında `relDir`'den `''` (tarama kökü) değerine kadar yürüyor (`nuget.ts:124-147`). Tarama kökünün dışına çıkmak mümkün değil. Bağlantılar izlenmiyor; `dotnetLinks` sabit `LINK_NOT_FOLLOWED_MESSAGE` ile raporlanıyor (`nuget.ts:274-275`).

**JSON lock/assets kötüye kullanımı**
- `JSON.parse` `__proto__` anahtarını sahip özellik olarak oluşturuyor; tüm birikim `Map` ile yapılıyor (`nugetAssets.ts:30, 55`, `nugetLock.ts:66`); prototip kirlenmesi yok. `isValidNugetId` `__proto__`'yu geçerli id saysa da yalnız Map anahtarı ve metin olarak kullanılıyor.
- `project.assets.json`'dan yalnız `version`, `libraries.*.type`, `libraries.*.sha512` ve `project.frameworks.*.dependencies.*.version` okunuyor; `packageFolders`, `restore`, `logs`, `project.restore.projectPath` gibi mutlak yol içeren alanlar hiç okunmuyor ve çıktılara/hatalara girmiyor (`nugetAssets.ts:4-8`). Hatalar sabit metin.
- Dosya başına 32 MiB okuma sınırı (`common.ts:51`), klasör başına 20 000 bağımlılık sınırı (`common.ts:774`; `nugetLock.ts:104`, `nugetAssets.ts:81`, `nuget.ts:191`).
- Kimlik doğrulaması ASCII-only `^[A-Za-z0-9_]+([.-][A-Za-z0-9_]+)*$`, ≤ 100 karakter (`nugetIdentity.ts:32-53`); `/`, `\`, `%`, `..` ve Unicode harfler reddediliyor. Lock hash değeri `sha512-` + doğrulanmış base64 olmalı (`lockIntegrityValue.ts:80-82`).

**İmzalı paket içerik hash'i ve bütünlük kabulü (`src/enrichment/archive/nupkgHash.ts`)**
- Hash, imza girişi dışındaki her baytı kapsıyor: ilk yerel başlıktan önceki baytlar (a), diğer tüm yerel girişler (b), diğer merkezi kayıtlar (c), EOCD (d) ve yorum. Yerel girişlerin bitişik olması ve son girişin `cdOffset`'te bitmesi zorunlu (`nupkgHash.ts:107-111`): boşluk, örtüşme, gizli veri veya merkezi dizin dışı bölge kabul edilmiyor. Merkezi kayıtların `cdOffset`'ten EOCD'ye kesintisiz uzanması zorunlu (`nupkgHash.ts:79-88`).
- Hash'lenmeyen tek alanlar: imza girişinin yerel aralığı ve merkezi kaydı; diğer merkezi kayıtların ofset alanı ise gerçek ofsetten deterministik kaydırılarak hash'leniyor (enjektif), EOCD sayı/boyut/ofset alanları gerçek değerlerle tutarlılık kontrolünden sonra yeniden hesaplanıyor.
- Birden fazla veya hiç `.signature.p7s` yoksa `null` (`nupkgHash.ts:74-75`); ZIP64 (EOCD işaretleri, locator, 0x0001 ekstra alanı), çok diskli arşiv ve giriş sayısı sınırı `readCentralDirectory`'de reddediliyor (`zip.ts:63-89`). Ofsetler JS `number` (32 bit alanlar + uzunluklar < 2^53), taşma yok; her okuma öncesi sınır kontrolü var.
- **"Farklı lisans dosyası, aynı içerik hash'i" sorusu:** İmza girişi tek dışlanan bölge ve onun verisi hiçbir zaman açılmıyor: `isNupkgPackagingEntry` `.signature.p7s`, `[content_types].xml`, `_rels/`, `package/` ve kökteki `.nuspec`'i eşleşmeden önce eliyor; bu kontrol `.nuspec`'te beyan edilen `<license type="file">` yolundan da önce çalışıyor (`licenseFiles.ts:86-91, 115-121`). Lisans girişinin veri aralığı (`readZipEntry`, `zip.ts:121-131`) hash'te kapsanan kendi yerel aralığıyla aynı; aynı ofsetli iki giriş örtüşme kontrolüne takılıyor. Dolayısıyla lisans metnini değiştiren her müdahale içerik hash'ini değiştirir; SHA-512 çakışması pratik değil.
- Doğrulama, hiçbir giriş açılmadan arşiv thread'inde yapılıyor; eşleşmezse `integrity_mismatch`, önbelleğe yazım yok, NOTICE denenmiyor ve nuspec kaynaklı `license_unclassified` düşürülüyor (`thread.ts:37-48`, `archiveStage.ts:177-192`, `index.ts:535-536`). Ham eşleşme yoksa ve ekosistem NuGet değilse eski davranış korunuyor.
- Aday yalnız tarama lock/assets hash'inden üretiliyor; birden çok farklı hash `mismatch` (indirme yok), hash yoksa `no_candidate` (`index.ts:253-281`). Arşiv önbellek satırı yalnız doğrulanmış baytlardan ve lock hash'i anahtarıyla yazılıyor (`archiveStage.ts:207-208`).

**nupkg içi yol geçişi**
- `normalizeArchivePath` NUL, mutlak yol, sürücü harfi ve `..` bileşenini reddediyor (`licenseFiles.ts:60-73`); beyan edilen yol ayrıca ≤ 256 karakter (`nugetRegistry.ts:53-57`). Arşiv thread'inde `fs` yok (ADR-006 Karar 1); yol yalnız arşiv içi eşleşmede kullanılıyor, dosya sistemine hiç dokunmuyor. Zip-slip yüzeyi yok.

**SSRF / izin listesi**
- `nuget` uç noktası ortam değişkeninden okunmuyor; yalnız üretim kökeni veya kodla enjekte edilen loopback test kökeni (`registryClient.ts:104-116`). Her istek ve yönlendirme adımında köken, `https:` ve kimlik bilgisi kontrolü (`registryClient.ts:124-139`).
- `metadata-nuget`: ilk istek tam `/v3-flatcontainer/<id>/<ver>/<id>.nuspec`; en fazla 3 aynı-köken yönlendirme ve yönlendirme adımları `/v3-flatcontainer/` altında, sorgu/parça yok (`registryClient.ts:78-82, 279-295`). Boyut 1 MiB; gzip açılmış bayt ayrıca sayılıyor (`safeHttpClient.ts:434-446`), gzip bombası sınırlı.
- `archive-nuget`: yönlendirme yok, tam `/<id>/<ver>/<id>.<ver>.nupkg` yolu, `identity` kodlama (`registryClient.ts:84-88, 298`). URL bileşenleri `encodeURIComponent` ve doğrulanmış küçük harf id/sürümden kuruluyor (`nugetRegistry.ts:32-42`).
- `<licenseUrl>` hiçbir zaman istenmiyor ve saklanmıyor; yalnız tabloya karşı sınıflanıyor (`nugetRegistry.ts:72-80`, migration 008 yorumları).

**Önbellek ve OSV adı**
- Metadata önbellek anahtarı `('nuget', asciiLower(id), lower(version))`; ekosistem anahtarın parçası, npm/PyPI ile çakışma yok (`cache.ts:173-174`). `canonical_name` yalnız `asciiLower(<id>) === istenen id` ise ve geçerli NuGet id'siyse yazılıyor (`nugetRegistry.ts:96-104`); bu yüzden kötü niyetli nuspec OSV sorgusunu **başka bir pakete yönlendiremez**, yalnız büyük/küçük harfi seçebilir (bkz. L-2).
- Türkçe yerel ayar: JS tarafı `asciiLower` (yalnız A–Z), SQL tarafı `lower(p.name COLLATE "C")` ve `lower(p.version COLLATE "C")` (`recheck.ts:125-127`); noktalı/noktasız i sorunu yok. Migration 008 `canonical_name ≤ 100`, `license_file_path ≤ 256` ve NuGet alanlarının yalnız NuGet `found` satırlarında bulunmasını CHECK ile zorluyor.

**Çıktı enjeksiyonu**
- NuGet kaynaklı metinler: SPDX ifadesi kanonikleştirilmiş (`canonicalizeSpdxExpression`), paket adı/`canonical_name` ASCII id karakter kümesiyle sınırlı, nupkg lisans dosyaları REQ-004'ün mevcut çözme/temizleme yolundan geçiyor ve NUL içeren (ikili) dosyalar atılıyor (`licenseFiles.ts:172`). Excel formül koruması ve SBOM/XML kaçışı REQ-004/005'ten değişmeden geçerli. `public/index.html:599` yalnız statik bir `<option value="dotnet">`.

**Bağımlılıklar**
- `npm audit --omit=dev`: 0 açık. Yeni üretim bağımlılığı yok (XML okuyucu el yazımı).

## Bulgular

### L-1 — Taramada .NET bağımlılık sayısı için toplam üst sınır yok (Low)

- **Evidence:** `src/scanner/parsers/common.ts:774` (`NUGET_MAX_DEPENDENCIES_PER_FOLDER = 20_000`), `src/scanner/parsers/nuget.ts:278-283` (tüm klasörlerin bağımlılıkları sınırsız birleştiriliyor), `xmlReader.ts:49-55` (dosya başına 200 000 eleman).
- **Attack path:** (A2) Repo sahibi 100 klasörde her biri 20 000 benzersiz paket içeren `packages.lock.json` veya `obj/project.assets.json` koyar (her biri < 32 MiB). Ayrıştırıcı 2 milyon `ScannedDependency` üretir; bunlar sıralanır, worker'dan ana sürece aktarılır, DB'ye yazılır ve zenginleştirme kuyruğuna girer (dedupe sonrası yine ~20 000 × N benzersiz anahtar ağ isteği adayıdır; kota bunu sınırlar). Benzer şekilde birçok 32 MiB'lık csproj, her biri 200 000 elemanlı ağaç üretebilir. Etki: bellek tükenmesi / uzun tarama (doğrulanmadı). Tek kullanıcılı yerel araçta kendine yönelik DoS; güvenilmeyen üçüncü taraf repolar tarandığında anlamlı.
- **Impacted area:** Tarama worker'ı, sonuç yazımı, zenginleştirme kuyruğu.
- **Remediation requirement:** Tarama başına toplam .NET bağımlılık (veya tüm ekosistemler için toplam) sınırı ve aşıldığında sabit metinli `parse_errors` kaydı; ya da sandbox worker bellek sınırının (`resourceLimits`) bu senaryoyu kapsadığının testle gösterilmesi. Alternatif: insan risk kabulü handoff'a yazılır.

### L-2 — OSV adı yayıncının sürüm başına seçtiği `<id>` büyük/küçük harfinden geliyor (Low, doğrulanmadı)

- **Evidence:** `src/enrichment/nugetRegistry.ts:96-104`, `src/vulnerability/lookup.ts:132` (`canonicalNames?.get(key) ?? dep.name`), `src/vulnerability/recheck.ts:138`.
- **Attack path:** (A1) Bir paketin yayıncısı, belirli bir sürümün `.nuspec`'inde id'yi farklı harf düzeniyle yazar (ör. `Foo.BAR`; nuget.org id'yi büyük/küçük harf duyarsız eşler). Araç OSV'ye bu adı gönderir. OSV'nin NuGet ad eşlemesi büyük/küçük harf duyarlıysa (doğrulanmadı), GHSA kaydındaki kanonik adla (`Foo.Bar`) eşleşme kaçar ve paket "açık yok" görünür. Başka bir pakete yönlendirme mümkün değil.
- **Impacted area:** OSV taraması ve günlük yeniden kontrol (NuGet).
- **Remediation requirement:** OSV NuGet ad eşlemesinin büyük/küçük harf davranışı bir sözleşme testiyle (gerçek OSV veya belgeli davranış) sabitlenmeli. Duyarlıysa: kanonik ad ile lock/assets adı yalnız harf düzeninde farklıysa ikisi de sorgulanmalı ve sonuçlar birleştirilmeli (sorgu sayısı sınırı korunarak).

### L-3 — `.nuspec` sürümü istenen sürümle karşılaştırılmıyor; yönlendirme başka sürümün nuspec'ine gidebilir (Low)

- **Evidence:** `src/enrichment/nugetRegistry.ts:93-97` (yalnız `metadata/id` kontrol ediliyor), `src/enrichment/registryClient.ts:281-293` (yönlendirme adımları `/v3-flatcontainer/` altında herhangi bir yol).
- **Attack path:** (A4 veya A3-kurumsal TLS vekili) `GET /v3-flatcontainer/foo/2.0.0/foo.nuspec` isteği `302 /v3-flatcontainer/foo/1.0.0/foo.nuspec`'e yönlendirilir. Id eşleştiği için 1.0.0'ın lisansı 2.0.0 için önbelleğe (`registry_package_cache`) yazılır ve `registry:nuget` kaynağıyla raporlanır. Lisans değişikliği olan sürümlerde yanlış lisans uyumluluğu kararı. Lock bütünlüğü nupkg'yi koruduğu için NOTICE etkilenmez; yalnız beyan edilen lisans etkilenir.
- **Impacted area:** Lisans ifadesi, `license_unclassified`, `license_file_path` (yanlış dosya beklenir).
- **Remediation requirement:** `metadata/version` normalize edilip `lowerVersion` ile karşılaştırılmalı; uyuşmazlıkta `BAD_NUSPEC` (önbelleğe yazılmadan). Ek olarak yönlendirme adımlarının ilk isteğin id/sürüm segmentlerini değiştirmemesi zorunlu tutulabilir.

### L-4 — Migration 008 geri alımı `license_expression`'ı koruyup kaynağı `none` yapıyor (Low)

- **Evidence:** `db/migrations/008_nuget_enrichment.down.sql:36` ve başlık yorumu (satır 14-16).
- **Attack path:** Geri alım sonrası NuGet satırları "ifade var, kaynak `none`" gibi sözleşmenin (REQ-004 1.4.0 §4.1, `registry:nuget` her zaman boş olmayan ifade taşır; `none` ise doğrulanmış kaynak yok anlamında) öngörmediği bir bileşimde kalır; raporlar doğrulanmamış bir lisansı kaynaksız gösterir. Ayrıca `license_unclassified` kalıcı kaybolur. Güvenlik etkisi düşük (veri bütünlüğü/raporlama yanıltması); belgelenmiş ve insan onaylı toplu güncelleme olarak işaretlenmiş.
- **Impacted area:** Geri alım sonrası raporlar, NOTICE, SBOM.
- **Remediation requirement:** Geri alımda `license_source = 'registry:nuget'` satırlarında `license_expression` de `NULL`'a çekilmeli (ve gerekirse `license_enrichment_status` uygun değere) ya da mevcut davranış handoff'ta açık insan risk kabulüyle kayda geçirilmeli. Geri alım yalnız insan onayıyla çalıştırılmalı (D-158).

### L-5 — Beyan edilen `type="file"` yolu, paketleme girişleri dışında paketteki herhangi bir dosyayı NOTICE'a "lisans dosyası" olarak alabilir (Low)

- **Evidence:** `src/enrichment/archive/licenseFiles.ts:115-121`, `src/enrichment/nugetRegistry.ts:68-69`.
- **Attack path:** (A1) Yayıncı `<license type="file">lib/net8.0/readme-ad.txt</license>` (veya büyük bir metin dosyası) beyan eder. Dosya kök lisans adı kuralına uymasa da NOTICE'a lisans metni olarak girer; içinden "Copyright" satırları da çıkarılır. Bu NuGet semantiğine uygun (yayıncının beyanı) ve içerik hash'le doğrulanmış pakete ait; ikili dosyalar atılıyor ve dosya başına boyut sınırı var. Risk, NOTICE'a yanıltıcı/istenmeyen metin enjeksiyonu ile sınırlı.
- **Impacted area:** NOTICE dosyası, telif satırları.
- **Remediation requirement:** Kabul edilebilir; isteğe bağlı sıkılaştırma: beyan edilen yol için uzantı izin listesi (`.txt`, `.md`, uzantısız) ya da NOTICE'ta "paket tarafından beyan edilen dosya: <yol>" başlığıyla işaretleme. Sözleşme 1.4.0 ile tutarlılık için Product Analyst/Contract Broker kararı.

### Info

- **I-1 — İmza girişinin konumu kısıtlanmıyor ve imzanın varlığı/geçerliliği doğrulanmıyor.** NuGet `.signature.p7s`'i son giriş olarak bekler; burada herhangi bir konumda kabul ediliyor (`nupkgHash.ts:74-129`). İmzasız bir pakete rastgele içerikli `.signature.p7s` eklenmiş hali, orijinalin ham hash'ine eşit içerik hash'i üretir. Bu kabul edilebilir: dışlanan bayt hiçbir zaman açılmıyor ve güven çapası PKCS#7 imza doğrulaması değil, lock hash'idir. Dokümante edilmesi önerilir.
- **I-2 — Veri tanımlayıcı sezgisi.** `nupkgHash.ts:100-103` imzasız tanımlayıcının CRC'si `0x08074b50` ise 16 bayt varsayar; bitişiklik kontrolü bunu yakalar ve sonuç `mismatch` olur (güvenli yönde hatalı negatif).
- **I-3 — Ad alanı öneki yok sayılıyor.** `localName` son `:` sonrası; `<x:PackageReference>` normal `PackageReference` gibi okunur (`xmlReader.ts:231-234`). Etki: yalnız bağımlılık listesine ek giriş; güvenlik etkisi yok.
- **I-4 — XML bildiriminde `encoding` araması.** `checkDeclaredEncoding` `decl.indexOf('encoding')` kullanıyor; `version="encoding"` gibi yapay bir bildirim yanlış konumu bulup `malformed` verebilir veya ASCII yoluna düşer. Her iki sonuç da güvenli yönde.
- **I-5 — Bellek tepe noktası doğrulanmadı.** 32 MiB'lık tek bir csproj 200 000 elemanlı ağaç (eleman başına nesne + iki dizi + `Set`) üretebilir; tahmini onlarca MiB. Sandbox worker bellek sınırına karşı bir stres testi önerilir (bkz. L-1).
- **I-6 — Arşiv önbelleği isabeti yeniden doğrulanmıyor.** NuGet önbellek isabeti doğrudan `lock_integrity = 'match'` döndürüyor (`archiveStage.ts:128-130`). Satır yalnız doğrulanmış baytlardan yazıldığı için doğru; DB'ye yazma erişimi olan saldırgan tehdit modeli dışı.
- **I-7 — Önceden var olan (kapsam dışı) Türkçe yerel ayar riski.** `recheck.ts:124` PyPI dalında `lower(regexp_replace(p.name, …))` `COLLATE "C"` olmadan çalışıyor. Veritabanı `tr_TR` ctype ile oluşturulduysa `I` → `ı` olur ve PyPI adı içeren `I` harfli paketlerin önbellek/OSV anahtarı JS tarafındaki PEP 503 anahtarıyla uyuşmaz (doğrulanmadı; REQ-005 kodu). NuGet dalı doğru şekilde `COLLATE "C"` kullanıyor.
- **I-8 — Test kapsamı.** `tests/unit/nugetXmlReader.test.ts` DOCTYPE/kodlama, `tests/unit/nugetEnrichmentPure.test.ts` `.signature.p7s` ve örtüşme senaryolarını kapsıyor. Eksik görünenler (statik grep): .NET lock/assets'te `__proto__`/`constructor` paket id'si ve TFM anahtarı için golden; `<license type="file">.signature.p7s</license>` beyanının NOTICE'a girmediğini gösteren uçtan uca test; L-1 için toplam ölçek testi. QA Automation'a önerilir.

## Merge kararı

**Go.** Critical/High/Medium bulgu yok; insan onayı gerektiren güvenlik riski yok. Önerilen takip:

1. L-3: nuspec `<version>` kontrolü (küçük düzeltme, Backend Engineer).
2. L-2: OSV NuGet ad büyük/küçük harf davranışının sözleşme testiyle sabitlenmesi (QA + Backend).
3. L-1: Toplam bağımlılık sınırı veya insan risk kabulü (Delivery Lead kararı).
4. L-4: Geri alım semantiğinin düzeltilmesi veya handoff'ta risk kabulü (Database Engineer).
5. L-5 ve I-8: Contract/QA takibi.

Fix'ler ilgili implementer tarafından yapılmalı; Security Red Team fix sonrası yeniden inceler.

## Handoff notu

Bu inceleme non-trivial'dır; `docs/handoffs/REQ-006.md` güncellenmelidir (bu rapor yolu, Go kararı ve L-1…L-5 takip listesi). Security Red Team handoff'u güncellemez; Delivery Lead / Integration-Release'e bildirilmiştir.
