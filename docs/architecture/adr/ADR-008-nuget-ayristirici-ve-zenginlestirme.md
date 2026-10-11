# ADR-008: NuGet ayrıştırıcısı (lock/assets/proje dosyası/CPM/packages.config), güvenli XML okuyucu, `.nuspec` lisans zenginleştirmesi, `.nupkg` NOTICE ve OSV'de NuGet

- **ADR-ID:** ADR-008
- **Durum:** Accepted
- **Tarih:** 2026-10-11 (taslak ve karar)
- **İlgili:** REQ-006 r1 / P-20, P-21, NuGet güvenlik açığı sorgusu (48 AC);
  kararlar D-119…D-146 (özellikle D-120, D-121, D-123, D-125, D-126, D-128,
  D-129, D-131…D-137, D-139, D-140, D-143). Dayanaklar: ADR-003 (a, b, c)
  (kesin sürüm, runtime kapsam, parmak izi), ADR-005 Karar 1, 5, 6, 7 (iş
  parçacığı sınır kuralı, yürüyüş, hata metinleri, golden dondurma), ADR-006
  Karar 1, 3, 4, 6, 7, 8, 9, 10, 11 ve tarihli notları (kayıt defteri istemcisi,
  izin listesi, arşiv okuyucuları, D-67 lisans dosyası kuralları, etkin lisans
  tablosu, fail-closed anahtar), ADR-007 Karar 1, 2, 3, 7, 12 ve güvenlik
  düzeltmesi notu (ortak güvenli HTTP çekirdeği, OSV toplu sorgu, yeniden
  kontrol, L-5 yan kanalı ve fail-safe).
- **Kısmen superseded edilenler (tarihli not eklendi):** ADR-005 Karar 6
  (yürüyüş yalnız sabit adları tanır); ADR-006 Karar 1, 3, 6, 7, 9 (kayıt
  defteri kümesi `npm`/`pypi`, üç host, arşiv adayının kayıt defterinden
  gelmesi, iki arşiv yerleşimi, CHECK kümeleri); ADR-007 Karar 3, 7, 12 (aday
  kümesi `nodejs`/`python`, kapsam SQL'i, L-5'in yalnız npm olması).

## Bağlam

Repo üzerinde doğrulanan durum (branch `req-006-f5-dotnet`, `62092e9`):

- `src/scanner/parsers/index.ts` `PARSERS` yalnız `nodejs` ve `python`
  içerir. `parseManifests` yürüyüşü ilk desteklenen ekosistemde **bir kez**
  yapar (`walkTree(rootDir)`), ekosistem listesini yürüyüşe vermez.
- `src/scanner/parsers/common.ts` `walkTree`: `ALL_MANIFEST_NAMES` (sabit
  adlar) dışındaki dosyaları toplamaz. Bu kümede olmayan ada sahip bir
  sembolik bağlantı `{ ecosystem: 'filesystem', … }` kaydı üretir (sıra
  yürüyüş sırasıdır). `readManifest(file, ecosystem: 'nodejs' | 'python')`
  32 MiB sınırı ve SHA-256 kaydını üretir. `SKIP_DIRS` `obj`/`bin`
  içermez (`build`, `dist` içerir).
- `src/scanner/parsers/lockIntegrityValue.ts` `IntegrityCollector`
  (`records`, `add(manifestPath, name, version, integrity)`), `thread.ts`
  yanıtı `{ ok, result, sideChannel: { npmIntegrity } }`, `threadParser.ts`
  `sideChannelOf` yalnız `npmIntegrity`'yi okur ve değerleri yeniden sınırlar.
  İş parçacığı yalnız bu klasörün modüllerini yükleyebilir;
  `src/enrichment/lockIntegrity.ts` bu adları yeniden dışa aktarır (emsal).
- `src/enrichment/coordinates.ts`: `RegistryEcosystem = 'npm' | 'pypi'`;
  `registryEcosystemOf` `dotnet` için `null` (zenginleştirme dışı).
- İkili varsayımlar (yeni ekosistemde yanlış dala düşecek yerler):
  `effectiveLicense.ts` `ecosystem === 'npm' ? 'registry:npm' : 'registry:pypi'`;
  `archiveStage.ts` `purpose = npm ? 'archive-npm' : 'archive-pypi'` ve
  `triedCandidates`; `index.ts` `fetchNpmMetadata : fetchPypiMetadata`,
  `defaultLockIntegrity` (`npm` → `not_comparable`, diğer → `null`);
  `vulnerability/lookup.ts` `candidateQueries`
  `check.ecosystem === 'npm' ? 'npm' : 'PyPI'`; `vulnerability/recheck.ts`
  `SCOPE_PAGE_SQL` `CASE … WHEN 'nodejs' THEN 'npm' ELSE 'pypi' END`.
- `src/enrichment/index.ts`: L-5 karşılaştırması meta veri aşamasından
  sonra, arşiv aşamasından önce yapılır (kayıt defteri npm `dist.integrity`
  özetini **yayımladığı için**). `archiveStage.ts` `collectArchive`: önbellek
  (özet anahtarlı) → indirme (ana iş parçacığı, akış özeti) → `verifyDigest`
  → arşiv iş parçacığı → önbellek yazımı; uyuşmayan özet `integrity_failed`.
- `src/enrichment/registryClient.ts`: `RegistryEndpoints { npm, pypi, files }`,
  `RequestPurpose` dört değer, meta veri amacı `kind: 'json'`, 8 MiB,
  `pathRule: anyPath`; arşiv amacı yönlendirmesiz, 64 MiB, `underOrigin`.
  `src/lib/http/safeHttpClient.ts` ham gövdeyi döndürür; JSON ayrıştırma
  adaptördedir.
- `src/enrichment/archive/zip.ts` `readCentralDirectory` ZIP64, çok diskli
  arşiv ve sınır denetimlerini yapar; `licenseFiles.ts` yerleşimleri
  `top-folder` | `wheel`; `extract.ts` `ArchiveKind = 'npm' | 'pypi'`.
- `src/enrichment/cache.ts` `METADATA_EXTRACTOR_VERSION = 1`,
  `ARCHIVE_EXTRACTOR_VERSION = 1` (küresel).
- `src/vulnerability/normalize.ts` `bestAffected`: önce birebir ad, sonra
  ekosistem, sonra ilk girdi. `isExactVersion` `[<>=~^*,!\s]` içermeyen
  sürümleri kabul eder (NuGet kesin sürümleri geçer).
- `db/migrations/006_registry_enrichment.up.sql`: `registry_package_cache`
  ve `registry_archive_cache` `ecosystem IN ('npm','pypi')` (satır içi CHECK,
  PostgreSQL varsayılan adı `<tablo>_ecosystem_check`),
  `scan_dependencies.license_source` satır içi CHECK
  (`scan_dependencies_license_source_check`), `registry_package_cache_not_found_empty`.
  `007` `scan_dependencies.lock_integrity` ekler.
- Yerel geliştirme veritabanı Türkçe yerel ayarlarla kurulmuştur (ADR-007
  güvenlik notu I-14): `lower('I')` `LC_CTYPE`'a bağlıdır. NuGet kimliklerinde
  büyük `I` çok yaygındır (`Microsoft.Extensions.DependencyInjection`).

## Kararlar

### 1. Modül yapısı ve sınır kuralı (D-120, D-128, REQ-006 NFR "ortak bileşen")

Kopya istemci, kopya arşiv okuyucu veya kopya OSV istemcisi yazılmaz. NuGet,
F3/F4 bileşenlerine yeni bir ekosistem olarak eklenir.

| Dosya | İçerik |
| --- | --- |
| `src/scanner/parsers/xmlReader.ts` (yeni, saf) | Karar 3'teki güvenli XML okuyucu. İçe aktarımı yok. |
| `src/scanner/parsers/nugetIdentity.ts` (yeni, saf) | Kimlik kuralı, ASCII küçük harf, sürüm normalleştirmesi ve sınıflandırması, `nugetPurl` (Karar 4). İçe aktarımı yok (veya yalnız `./common`). |
| `src/scanner/parsers/nugetLock.ts` (yeni) | `packages.lock.json` v1/v2 okuyucu (Karar 5.2). |
| `src/scanner/parsers/nugetAssets.ts` (yeni) | `obj/project.assets.json` v3 okuyucu (Karar 5.3). |
| `src/scanner/parsers/msbuildProject.ts` (yeni) | Proje dosyası `PackageReference`, `Directory.Packages.props` (CPM) ve `packages.config` okuyucuları (Karar 5.4–5.6). |
| `src/scanner/parsers/nuget.ts` (yeni) | `parse(walk, collector)`: proje klasörlerini kurar, kaynak önceliği ve geri düşme, birleştirme, sıra, sınır (Karar 5, 7). |
| `src/scanner/parsers/{common,index,thread,threadParser,lockIntegrityValue}.ts` | Yürüyüş seçeneği (Karar 2), `PARSERS.dotnet`, `readManifest` ekosistem tipi, NuGet yan kanalı (Karar 6). |
| `src/scanner/worker.ts`, `src/scanner/sandbox/runner.config.ts` | `loadEcosystems`, `supportedEcosystems`, yan kanalın zenginleştirmeye iletilmesi, `ENRICHMENT_LIMITS.client.nuspecMaxBytes` (Karar 8, 15). |
| `src/enrichment/coordinates.ts` | `RegistryEcosystem = 'npm' \| 'pypi' \| 'nuget'`, `dotnet → nuget`, NuGet kimlik/sürüm denetimi `nugetIdentity.ts` yeniden dışa aktarımıyla (Karar 8). |
| `src/enrichment/registryClient.ts` | `nuget` kökeni, `metadata-nuget` ve `archive-nuget` amaçları, `getText` (Karar 8). |
| `src/enrichment/nugetRegistry.ts` (yeni) | `.nuspec` isteği ve çıkarımı (Karar 9). Oturumu parametre alır; ağ erişimi yalnız oturum üzerinden. |
| `src/enrichment/nugetLicenseUrls.ts` (yeni, saf) | Sabit `licenseUrl` tablosu ve `licenses.nuget.org` çözümü (Karar 9). |
| `src/enrichment/{index,archiveStage,cache,effectiveLicense,types,lockIntegrity}.ts` | NuGet meta veri ve arşiv akışı, NuGet bütünlük sonucu, önbellek kolonları, `registry:nuget` (Karar 10, 12). |
| `src/enrichment/archive/{extract,licenseFiles,thread,archiveThread}.ts` | `ArchiveKind 'nuget'`, `nupkg` yerleşimi, bildirilen yol, doğrulama isteği (Karar 10, 11). |
| `src/enrichment/archive/nupkgHash.ts` (yeni, saf + `node:crypto`) | NuGet imzalı paket içerik özeti (Karar 10.3). Yalnız arşiv iş parçacığında çağrılır. |
| `src/vulnerability/{lookup,osvClient,recheck,normalize}.ts` | `NuGet` ekosistemi, kanonik ad, `affected` seçimi, kapsam SQL'i (Karar 13). |
| `src/notice/**`, `src/reports/**`, `src/sbom/**` | `license_unclassified` ve NuGet metinleri (Karar 12; kesin metinler contract'ta). |

**Sınır kuralları** (qa-automation statik içe aktarım taramasıyla korur):

- Ayrıştırıcı iş parçacığının yüklediği yeni dosyalar (`xmlReader`,
  `nugetIdentity`, `nugetLock`, `nugetAssets`, `msbuildProject`, `nuget`)
  yalnız `./` göreli modülleri ve Node yerleşiklerini (`node:fs`,
  `node:path`, `node:crypto`) içe aktarır (ADR-005 Karar 1).
- `src/enrichment/` yalnız `xmlReader.ts` ve `nugetIdentity.ts`'i
  `src/scanner/parsers/`'tan içe aktarabilir (`lockIntegrityValue.ts`
  emsali); ayrıştırıcı klasörü `src/enrichment/`'ı içe aktarmaz.
- `src/` altında ağ bağlantısı açan tek modül `src/lib/http/safeHttpClient.ts`
  kalır (ADR-007 Karar 1). `nugetRegistry.ts` ve `archiveStage.ts` yalnız
  `RegistrySession` kullanır.
- `nugetLicenseUrls.ts`, `nugetIdentity.ts`, `xmlReader.ts` ağ, dosya veya
  ortam değişkeni erişimi içermez. `nupkgHash.ts` yalnız `node:crypto`
  kullanır.
- `child_process`, `dotnet`, `msbuild`, `nuget` adları hiçbir yeni `src/`
  dosyasında geçmez (statik test; AC-G-10).

**İkili varsayımların kaldırılması:** Bağlam'da sayılan her
`x === 'npm' ? … : …` ve `CASE … ELSE 'pypi'` biçimi, üç değerli ve
tükenmeli (`switch` + `never` denetimi) bir eşlemeyle değiştirilir. Bilinmeyen
değer sessizce bir ekosisteme düşmez, hata fırlatır (SQL'de `ELSE` yoktur,
Karar 13.4).

### 2. Yürüyüş: uzantıyla tanıma ve golden koruması (D-120, D-143; AC-P20-1, AC-G-6)

- `walkTree(rootDir, options?: { dotnet?: boolean })`. `parseManifests`
  normalleştirilmiş ekosistem listesini yürüyüşten **önce** hesaplar ve
  `dotnet: list.includes('dotnet')` geçirir. Seçenek verilmezse veya `false`
  ise yürüyüş F4 ile **bayt bayt aynıdır**: .NET adları hiç tanınmaz, .NET
  adlı bağlantılar bugünkü gibi `filesystem` kaydı üretir, kayıt sırası
  değişmez. Bu, AC-G-6'nın yapısal garantisidir.
- `dotnet: true` iken:
  - Normal dosya olarak toplananlar: `packages.lock.json`,
    `project.assets.json` (yalnız doğrudan üst klasörün adı tam olarak `obj`
    ise), `Directory.Packages.props`, `packages.config` (adlar harf duyarlı)
    ve adı `.csproj`, `.fsproj`, `.vbproj` ile biten dosyalar (uzantı ASCII
    harf duyarsız). Bunlar ayrı bir haritada (`walk.dotnetByDir`) tutulur;
    `byDir`, `discoverManifests` ve npm/Python yolları değişmez.
  - Aynı ikinci savunma (realpath kök denetimi) uygulanır; kökten çıkan dosya
    .NET bağlantısı sayılır.
  - .NET adlı bir sembolik bağlantı veya junction `filesystem` kaydı yerine
    `walk.dotnetLinks`'e girer; `dotnet` ayrıştırıcısı bunlar için
    `{ ecosystem: 'dotnet', file, error: LINK_NOT_FOLLOWED_MESSAGE }`
    üretir. Hedef hiçbir zaman çözülmez (ADR-005 Karar 6, L-2).
  - `project.assets.json` adlı ama üst klasörü `obj` olmayan dosya yok
    sayılır (kayıt yok).
- `SKIP_DIRS` değişmez (`obj`/`bin` eklenmez; `build`/`dist` atlanmaya devam
  eder — README'de belirtilir).
- `readManifest` ekosistem tipi `'nodejs' | 'python' | 'dotnet'` olur;
  davranış aynıdır.

### 3. Güvenli XML okuyucu (D-128; AC-P20-13, AC-P21-4)

`xmlReader.ts`, elle yazılmış, tek geçişli, indeks tabanlı bir tarayıcıdır.
Düzenli ifade yalnız tek karakter sınıfı denetimleri için kullanılabilir;
niceleyicili veya geri izlemeli desen yoktur.

- **API:** `parseXml(bytes: Uint8Array, limits?: Partial<XmlLimits>): XmlElement`
  (kök öğe) veya `XmlError` fırlatır. `XmlElement { name: string;
  localName: string; attributes: ReadonlyArray<[string, string]>;
  children: XmlElement[]; text: string }`. `XmlError.code` sabit küme:
  `doctype`, `encoding`, `limit`, `entity`, `malformed`. Hata nesnesi hiçbir
  zaman belge içeriğinden metin taşımaz.
- **Kodlama:** `EF BB BF` → UTF-8; `FF FE` → UTF-16LE; `FE FF` → UTF-16BE;
  BOM yoksa UTF-8. Çözme `TextDecoder(..., { fatal: true })` ile yapılır.
  Geçersiz bayt dizisi `encoding`. BOM'suz UTF-16 (`3C 00` / `00 3C`)
  `encoding`. XML bildirimindeki `encoding` değeri `utf-8`/`utf-16` dışında
  bir değerse (`windows-1252` vb.) ve çözülen metin ASCII dışı karakter
  içeriyorsa `encoding`; yalnız ASCII ise kabul edilir (ASCII bu kodlamaların
  alt kümesidir).
- **Biçim:**
  - `<?…?>` işleme yönergeleri ve XML bildirimi atlanır.
  - `<!--…-->` yorumları atlanır.
  - `<![CDATA[…]]>` ham metin olarak eklenir.
  - `<!` ile başlayan başka her yapı, özellikle `<!DOCTYPE` ve `<!ENTITY`,
    `doctype` hatasıdır. Belgenin hiçbir yerinde DTD işlenmez.
  - Sonlandırıcılar (`?>`, `-->`, `]]>`, kapanış tırnağı) geçerli konumdan
    `indexOf` ile aranır. Bulunamazsa hemen `malformed` döner. İmleç yalnız
    ileri gider, bu yüzden toplam iş O(n)'dir.
  - Ad: ilk karakter harf, `_`, `:` veya ≥ U+0080; sonrakiler ek olarak
    rakam, `.`, `-`. Ad en fazla 256 karakterdir.
  - Öznitelikler: `ad="değer"` veya `ad='değer'`. Değerde `<` bulunması,
    aynı adlı ikinci öznitelik ve eşittir işareti olmayan öznitelik
    `malformed`'dır. Öğe başına en fazla 256 öznitelik vardır.
  - Kapanış etiketi açılış etiketiyle eşleşmelidir. Tek bir kök öğe olmalıdır.
    Kök dışındaki metin yalnız boşluk olabilir. Dosya sonunda açık öğe kalırsa
    `malformed`.
- **Varlıklar:** yalnız `&lt;` `&gt;` `&amp;` `&quot;` `&apos;`, `&#N;` ve
  `&#xH;` çözülür. Sayısal başvuru geçerli bir XML karakteri olmalıdır (0,
  vekil çift yarısı ve U+FFFE/U+FFFF olamaz) ve en fazla 8 basamak
  taşıyabilir. Diğer her `&…;` ve `;` ile kapanmayan `&` `entity` hatasıdır.
  Genişletme yoktur, bu yüzden "milyar gülüş" yapısal olarak imkânsızdır.
- **Ad alanı:** çözülmez. `localName`, son `:`'den sonraki kısımdır. MSBuild
  ve nuspec varsayılan ad alanını önek olmadan kullanır. `xmlns` yalnız
  sıradan bir özniteliktir; şema veya dış kaynak yüklenmez.
- **Sınırlar (`XmlLimits`, varsayılan):** derinlik 64, öğe sayısı
  200 000, tek öznitelik değeri veya bir öğenin birikmiş metni 64 KiB
  (çözülmüş UTF-16 kod birimi olarak sayılır). Sınır taranırken denetlenir;
  aşım anında `limit` döner. Girdi boyutunu çağıran sınırlar: repo
  dosyaları için 32 MiB (yürüyüş), `.nuspec` için 1 MiB (Karar 8).
- **Kullanım yeri:** repo XML'i (proje dosyası, CPM, `packages.config`)
  ayrıştırıcı iş parçacığında okunur. `.nuspec` **ana iş parçacığında**
  okunur (Karar 9). Gerekçe: girdi 1 MiB ile sınırlıdır ve okuyucu doğrusaldır
  (birkaç ms). F3 zaten 8 MiB'a kadar PyPI JSON'unu ana iş parçacığında
  ayrıştırır. Arşiv iş parçacığına göndermek her paket için bir iş parçacığı
  başlatma maliyeti ve yeni bir mesaj sözleşmesi getirirdi.

### 4. NuGet kimlik ve sürüm kuralları (D-125, D-126; AC-P20-8, AC-P20-9, AC-P21-1)

`nugetIdentity.ts` (ayrıştırıcı ve zenginleştirme aynı kodu kullanır):

- **Kimlik:** `isValidNugetId(id)`: 1–100 karakter. Kural
  `^[A-Za-z0-9_]+([.-][A-Za-z0-9_]+)*$` el yazımı tek geçişli denetimle
  uygulanır (her ayraçtan sonra en az bir harf, rakam veya `_` gelmelidir).
  Bu kural `..`, `/`, `\`, `%` ve boşluk karakterlerini yapısal olarak
  dışlar.
- **Küçük harf:** `asciiLower(s)` yalnız `A–Z` aralığını dönüştürür.
  Yerel ayardan bağımsızdır, Türkçe `I` sorunu yoktur. Tüm NuGet anahtarları
  (tekilleştirme, istek yolu, önbellek, OSV anahtarı) bu fonksiyonla
  üretilir. SQL tarafında karşılığı `lower(x COLLATE "C")`'dir (Karar 13.4).
- **Sürüm sınıflandırması** `classifyNugetVersion(raw): { kind: 'exact';
  version } | { kind: 'unknown' }`:
  1. XML boşluğu kırpılır. Uzunluk 0 veya 128'den fazlaysa `unknown`.
  2. `[x]` biçiminde ve iç metinde `,` yoksa iç metin kullanılır (tam
     sabitleme).
  3. Kalan metinde `[ ] ( ) , * $ @ %`, boşluk veya kontrol karakteri varsa
     `unknown`. Bu kural aralıkları, kayan sürümleri ve MSBuild
     özelliklerini (`$(…)`) yakalar. Özellik hiçbir zaman çözülmez.
  4. İlk `+`'dan sonrası yapı üst verisidir ve atılır. Atılan kısım boş
     olmayan `[0-9A-Za-z-]` tanımlayıcılarından oluşmalıdır, aksi `unknown`.
  5. İlk `-`'den sonrası ön sürüm etiketidir: noktayla ayrılmış, boş olmayan
     `[0-9A-Za-z-]+` tanımlayıcıları. Harf biçimi korunur.
  6. Sayısal kısım 2–4 parçadır, her parça `[0-9]+` ve 0–2 147 483 647
     aralığındadır. Değer baştaki sıfırlar atıldıktan sonra uzunluk ve metin
     karşılaştırmasıyla denetlenir.
  7. Normal biçim: baştaki sıfırlar atılır, 2 parçalı sürüme `.0` eklenir,
     4. parça `0` ise atılır, sonra `-<ön sürüm>` eklenir.
  - REQ-006 AC-P20-8 test tablosu bu algoritmanın kabul testidir.
- **Anahtar sürümü:** `asciiLower(normalized)`. Gösterilen ve saklanan
  `version`, kaynaktaki harf biçimiyle normal biçimdir.
- **purl:** `nugetPurl(id, version)` = `pkg:nuget/<id>[@<sürüm>]`.
  `npmPurl`/`pypiPurl` ile aynı yüzde kodlama yardımcısını kullanır. Kimliğin
  harf biçimi korunur (Karar 16, satır 6).

### 5. Proje klasörü, kaynak önceliği ve birleştirme (D-121…D-124, D-127; AC-P20-2…AC-P20-7)

#### 5.1 Proje klasörleri ve öncelik

- Proje klasörü kümesi şunlardan oluşur: bir proje dosyası, bir
  `packages.lock.json` veya bir `packages.config` içeren her klasör ve her
  `obj/project.assets.json`'ın `obj` üstü klasörü. Kök klasör `.` olarak
  yazılır.
- Klasörler göreli yolun kod noktası sırasıyla işlenir. Her klasörde:
  1. `packages.lock.json` varsa okunur. Başarılıysa yalnız o kullanılır.
  2. Lock dosyası yoksa veya dosya hatası verdiyse, `obj/project.assets.json`
     varsa okunur.
  3. İkisi de yoksa veya ikisi de hata verdiyse, klasördeki tüm proje
     dosyaları (ad sırasıyla) ve `packages.config` birlikte okunur.
     Bunlardan biri hata verirse diğerleri yine kullanılır.
- "Dosya hatası" şunlardan biridir: okuma veya boyut hatası, JSON/XML hatası,
  desteklenmeyen sürüm, beklenmeyen kök yapısı veya klasör başına bağımlılık
  sınırının aşılması (Karar 7). Bir dosya hatası tek bir `parse_errors`
  kaydı üretir ve sıradaki kaynağa geçilir (AC-P20-2). Girdi düzeyindeki
  sorunlar (geçersiz kimlik, bilinmeyen `type`, eksik `resolved`) dosya hatası
  değildir. Girdi atlanır, dosya kullanılmaya devam eder ve **dosya başına,
  her sorun türü için** tek bir kayıt düşülür.
- `scan_files`'a yalnız kaynak olarak başarıyla kullanılan dosyalar ve
  kullanılan `Directory.Packages.props` dosyaları yazılır (yol başına bir
  kez, `ecosystem: 'dotnet'`). Hata verip atlanan dosya `scan_files`'a
  girmez; hata kaydı `parse_errors`'tadır.
- `ProjectReference`, lock `type: Project` ve assets `type: project` hiçbir
  zaman paket kaydı üretmez.

#### 5.2 `packages.lock.json` (AC-P20-3)

- `JSON.parse` başarısızsa sabit metin `JSON ayrıştırılamadı.` kullanılır.
  `err.message` **hiçbir zaman** kullanılmaz: V8'in yeni sürümleri hata
  mesajına kaynak metinden parça ekler, bu da mutlak yol sızdırabilir.
- Kök bir nesne olmalı ve `version` sayı olarak 1 veya 2 olmalıdır. Aksi
  durumda dosya hatasıdır.
- `dependencies` bir nesnedir. Her `<hedef>` (çerçeve veya çerçeve/RID)
  anahtarı, değeri nesne olan girdiler içerir. Hedefler kod noktası sırasıyla,
  girdiler JSON sırasıyla dolaşılır.
- Girdiler şöyle işlenir:
  - `type: Direct` → `direct`.
  - `Transitive` ve `CentralTransitive` → `transitive`.
  - `Project` → atlanır.
  - Başka bir değer → girdi atlanır.
  - Sürüm `resolved` alanından alınır ve Karar 4 kuralıyla sınıflandırılır.
    `resolved` eksikse veya `exact` değilse girdi atlanır. Bu girdiler bir
    "geçersiz girdi" kaydıyla raporlanır.
- `declared_range`: `Direct` girdinin `requested` değeridir. Değer
  arındırılır (`sanitizeText` eşdeğeri) ve en fazla 200 kod noktasına
  kesilir. Aynı anahtarın birden çok `Direct` girdisi varsa ilk hedefteki
  değer kullanılır.
- Tekilleştirme klasör içinde `(asciiLower(id), asciiLower(sürüm))`
  anahtarıyla yapılır. Bir hedefte `Direct` olan girdi `direct` sayılır.
  `name` ve `version` olarak, belirlenimci dolaşma sırasındaki ilk
  karşılaşmanın biçimi kullanılır.
- `contentHash` yan kanala gider (Karar 6).

#### 5.3 `obj/project.assets.json` (AC-P20-4)

- Kökte `version` 3 olmalıdır; aksi durumda dosya hatasıdır.
- `libraries` nesnesindeki her anahtar şöyle okunur:
  - Anahtar tam olarak bir `/` içerir: `<id>/<sürüm>`. Biçim uymazsa
    "geçersiz girdi" kaydı düşülür.
  - Değerde `type` `"package"` ise girdi kullanılır, `"project"` ise
    atlanır. Başka bir değer "bilinmeyen tür" kaydı üretir.
  - `sha512` yan kanala gider (Karar 6).
- `direct` küme: herhangi bir `project.frameworks.<hedef>.dependencies`
  nesnesinin anahtarları, `asciiLower` ile karşılaştırılır. Bu girdinin
  `version` değeri `declared_range` olur. Kümede olmayan kütüphaneler
  `transitive`'tir.
- Okunan alanlar yalnız şunlardır: `version`, `libraries.*.type`,
  `libraries.*.sha512`, `project.frameworks.*.dependencies.*.version`. Diğer
  hiçbir alan okunmaz, saklanmaz veya hata metnine yazılmaz. Bunlara
  `project.restore`, `packageFolders`, `logs`, `targets`, `libraries.*.path`
  ve `libraries.*.files` dahildir.

#### 5.4 Proje dosyası `PackageReference` (AC-P20-5)

- Kök öğenin `localName` değeri `Project` olmalıdır (ASCII harf duyarsız);
  aksi durumda dosya hatasıdır. MSBuild öğe ve öznitelik adları harf duyarsız
  karşılaştırılır.
- Okunan öğeler `Project` altındaki `ItemGroup` öğeleridir. Buna `Choose` /
  `When` / `Otherwise` içindeki `ItemGroup` öğeleri de dahildir (koşul yok
  sayılır, hepsi birleştirilir). **`Target` içindeki** `ItemGroup` öğeleri
  okunmaz, çünkü bunlar derleme zamanı adımlarıdır. `Condition` özniteliği her
  yerde yok sayılır. `Import`, `Sdk` ve özellik (`PropertyGroup`)
  değerlendirmesi yapılmaz.
- `PackageReference` öğesinde `Include` zorunludur. `Update` veya `Remove`
  taşıyan, `Include` taşımayan öğe atlanır. Birden çok kimlik içeren
  `Include="A;B"` geçersiz kimliktir (Karar 4).
- Sürüm şu sırayla aranır: `VersionOverride` (öznitelik, sonra alt öğe),
  `Version` (öznitelik, sonra alt öğe), sonra CPM tablosu. Ham metin
  `declared_range`'e yazılır (arındırılmış, en fazla 200 kod noktası). Sürüm
  Karar 4 ile sınıflandırılır. Değer bulunamazsa sürüm `NULL` ve
  `declared_range` `NULL` olur.
- Kapsam `direct`'tir. `manifest_file` proje dosyasının adıdır.

#### 5.5 Merkezi paket yönetimi (AC-P20-6)

- Yalnız kaynağı proje dosyası olan klasörler (5.1 adım 3) için arama
  yapılır. Proje klasöründen başlayıp tarama köküne kadar (kök dahil) yukarı
  çıkılır ve bulunan ilk **normal** `Directory.Packages.props` kullanılır.
  Bağlantılar kullanılmaz. Kökün üstüne hiçbir zaman çıkılmaz. Dosya tarama
  başına bir kez ayrıştırılır ve sonucu önbellekte tutulur. Ayrıştırma hatası
  dosya başına tek kayıt üretir ve o dosyayı bulan klasörler CPM'siz devam
  eder.
- `PackageVersion` öğeleri (`Include` + `Version` öznitelik/alt öğe) tabloya
  yazılır. Anahtar `asciiLower(id)`'dir; aynı anahtar tekrar ederse belge
  sırasındaki ilk değer geçerlidir. `Update` taşıyan `PackageVersion` yok
  sayılır.
- `GlobalPackageReference` (`Include` + `Version`) öğeleri, dosyayı bulan her
  proje dosyası kaynaklı klasöre `direct` kayıt olarak eklenir.
  `manifest_file` bu durumda `Directory.Packages.props` olur.
- `ManagePackageVersionsCentrally` değerlendirilmez; dosyanın varlığı
  yeterlidir. Dosyadaki `Import` izlenmez.

#### 5.6 `packages.config` (AC-P20-7)

Kök öğenin `localName` değeri `packages` olmalıdır. `package` alt öğelerinin
`id` ve `version` öznitelikleri okunur. Sürüm Karar 4 ile sınıflandırılır;
`exact` değilse sürüm `NULL` olur ve ham metin `declared_range`'e yazılır.
Kapsam `direct`'tir. `developmentDependency`, `targetFramework` ve
`allowedVersions` yok sayılır.

#### 5.7 Proje dosyası kaynaklı birleştirme

Bir klasörde birden çok proje dosyası, `packages.config` ve CPM
`GlobalPackageReference` kayıtları birlikte bulunabilir. Bunlar
`(asciiLower(id), asciiLower(sürüm ?? ''))` anahtarıyla tekilleştirilir.
İlk kaynak kazanır; sıra proje dosyaları (ad sırası), `packages.config`,
`GlobalPackageReference`'tır. Sürümü bilinmeyen ve bilinen kayıtlar ayrı
kalır (ADR-003 a).

### 6. Bütünlük yan kanalı (D-129; AC-P20-16)

- `IntegrityCollector`'a ayrı bir liste ve yöntem eklenir:
  `nugetRecords: LockIntegrityRecord[]` ve `addNuget(manifestPath, name,
  version, base64Sha512)`. Mevcut `records`, `add` ve imzaları **değişmez**,
  böylece L-5 testleri değiştirilmeden geçer (AC-G-9).
- Kabul kuralı iş parçacığında uygulanır: değer metin olmalı ve tam olarak
  `^[A-Za-z0-9+/]{86}==$` biçiminde olmalıdır (64 baytlık SHA-512'nin base64
  biçimi). Bu el yazımı uzunluk ve karakter denetimiyle yapılır. Kabul edilen
  değer `sha512-<base64>` biçimine çevrilir ve
  `isAcceptableLockIntegrity` 1024 karakter denetiminden de geçer. Geçersiz
  değer sessizce atılır. `name` kaynak biçimindedir; `version` normal
  biçimdir.
- `thread.ts` yanıtı: `sideChannel.nugetIntegrity` **yalnız boş değilse**
  eklenir. Böylece mevcut yanıt şekli (`npmIntegrity`) NuGet'siz taramalarda
  aynı kalır. Liste bağımlılık sayısıyla sınırlanır.
- `threadParser.ts` `sideChannelOf` `nugetIntegrity`'yi ayrı okur, aynı
  kalıbı yeniden doğrular ve `runParserInThread` dönüşüne isteğe bağlı
  `nugetIntegrity` alanını ekler. Mevcut alanlar değişmez.
- Değer `ScannedDependency`'ye, `SandboxScanResult`'a ve golden'a girmez.
  Worker değeri `EnrichOptions.nugetIntegrity` olarak zenginleştirmeye
  iletir.

### 7. Çıktı sırası, hata metinleri, sınırlar ve golden (D-143; AC-P20-10, -12, -14, -15)

- **Kayıt şekli:** `ecosystem: 'dotnet'`, `name`, `version` (normal biçim
  veya `null`), `purl`, `scope`, `licenses: []`, `manifest_file`,
  `manifest_path`, `declared_range`. Alan kümesi mevcut `ScannedDependency`
  ile aynıdır; yeni alan yoktur.
- **Sıra:**
  - `dependencies`: önce `manifest_path` (kod noktası), sonra
    `asciiLower(id)`, sonra `asciiLower(sürüm)` (`null` en sonda), sonra
    `manifest_file`.
  - `scan_files`: `file_path` kod noktası sırasıyla.
  - `parse_errors`: önce .NET bağlantıları (yol sırasıyla), sonra klasör
    sırasıyla ve klasör içinde işlenme sırasıyla dosya kayıtları.
- **Sınırlar:** dosya başına 32 MiB (yürüyüş), Karar 3'teki XML sınırları ve
  proje klasörü başına 20 000 bağımlılık. Bağımlılık sınırı aşılırsa o kaynak
  dosya hatası sayılır ve sıradaki kaynağa geçilir. İş parçacığı kaynak
  sınırları, iptal ve süre ADR-005 Karar 5 ile aynıdır (yeni havuz yok).
- **Sabit hata metinleri** (yol yok, içerik yok, paket adı yok; `file`
  alanında yalnız göreli yol bulunur; `sanitizeErrorText` hunisi aynen
  uygulanır):

  | Durum | Metin |
  | --- | --- |
  | bağlantı | `Sembolik bağlantı veya junction izlenmedi.` (mevcut) |
  | boyut / okuma | mevcut `FILE_TOO_LARGE_MESSAGE` / `Dosya okunamadı (<ERRNO>).` |
  | JSON | `JSON ayrıştırılamadı.` |
  | lock sürümü | `Desteklenmeyen packages.lock.json sürümü.` |
  | assets sürümü | `Desteklenmeyen project.assets.json sürümü.` |
  | kök yapısı | `Beklenmeyen dosya yapısı.` |
  | XML `malformed` / `entity` | `XML ayrıştırılamadı.` |
  | XML `doctype` | `XML belge türü bildirimi (DOCTYPE) desteklenmiyor.` |
  | XML `limit` | `XML boyut, derinlik veya öğe sınırı aşıldı.` |
  | XML `encoding` | `Desteklenmeyen XML kodlaması.` |
  | geçersiz kimlik | `Geçersiz paket kimliği içeren girdiler atlandı.` |
  | bilinmeyen tür | `Bilinmeyen bağımlılık türü içeren girdiler atlandı.` |
  | geçersiz girdi | `Geçersiz paket girdileri atlandı.` |
  | sınır | `Proje klasörü bağımlılık sınırını aşıyor (20 000).` |

  Bu metinler NuGet golden'larıyla donar. Contract kapsamında değildir.
- **Golden stratejisi:**
  - npm/PyPI golden'ları ve `parsersDeviations` değiştirilmez (AC-G-6).
  - NuGet golden'ları `tests/fixtures/dotnet/` altındaki her kaynak türü
    için ve `sample-solution/` için `parseManifests(root, ['dotnet'], …)`
    çıktısının JSON'udur (`dependencies`, `scan_files`, `parse_errors`).
    Mevcut `parserGolden` yardımcısıyla derin eşitlikle karşılaştırılır ve F5
    ile donar.
  - `scan_files` SHA-256 değerleri fixture baytlarına bağlı olduğundan
    fixture'lar `.gitattributes` ile `-text` (satır sonu dönüşümsüz)
    işaretlenir.

### 8. Koordinatlar, uç noktalar ve istek amaçları (D-125, D-131, D-132; AC-P21-1…3)

- `registryEcosystemOf('dotnet') = 'nuget'`. `checkCoordinates` NuGet için
  sırayla şunları yapar:
  - Sürüm `null` ise `version_unknown`.
  - `isValidNugetId` geçmezse veya sürüm Karar 4'e göre `exact` değilse
    `invalid_coordinates`.
  - Aksi durumda `{ kind: 'ok', ecosystem: 'nuget', requestName:
    asciiLower(id), version: asciiLower(normalized) }`. `isValidVersion`
    (F3) de ayrıca uygulanır.
  - `coordinateKey` bu küçük harfli değerleri kullanır.
- `RegistryEndpoints` `nuget` alanını kazanır; `PRODUCTION_ENDPOINTS.nuget =
  'https://api.nuget.org'`. `resolveEndpoints` ve `assertInjectableEndpoint`
  dört kökeni bilir. Enjeksiyon yalnız koddan, üretim kökeni veya loopback
  `http` olarak yapılabilir. Ortam değişkeni yoktur ve `runtime.ts` bu
  parametreyi vermez.
- Yeni amaçlar (`RequestPurpose` + çekirdek amaç tablosu):

  | Amaç | Köken | Yol kuralı (her istek ve her yönlendirme adımı) | Yönlendirme | Sınır | Kodlama |
  | --- | --- | --- | --- | --- | --- |
  | `metadata-nuget` | `nuget` | ilk istek tam olarak `/v3-flatcontainer/<id>/<ver>/<id>.nuspec`; yönlendirme adımı `/v3-flatcontainer/` altında, sorgu yok | ≤ 3, yalnız aynı köken | 1 MiB (`nuspecMaxBytes`, açılmış gövde) | gzip |
  | `archive-nuget` | `nuget` | tam olarak `/v3-flatcontainer/<id>/<ver>/<id>.<ver>.nupkg`, sorgu yok | yok (3xx → `download_failed`) | 64 MiB (F3 `archiveMaxBytes`) | identity, akış SHA-512 |

  `<id>` ve `<ver>` `asciiLower` değerlerdir ve tek yol bileşeni olarak
  `encodeURIComponent` ile yazılır. Karar 4 kuralları gereği bu işlem kimliği
  değiştirmez. Yol kuralı segment sayısını ve dosya adının `<id>` / `<id>.<ver>`
  ile eşitliğini denetler.
- `metadata-nuget`, çekirdekte yeni bir `kind: 'text'` değeri kullanır. Bu
  değer uçuştaki tekilleştirme önekidir ve özet hesaplanmaz.
  `RegistrySession.getText(target, 'metadata-nuget', options)` şunlardan
  birini döner: `{ kind: 'ok', body: Buffer }`, `not_found` (404/410),
  `unreachable` veya `error`. İçerik türü denetlenmez; gövde Karar 3
  okuyucusu ve Karar 9 kök/kimlik denetimiyle doğrulanır. `Accept:
  application/xml, text/xml;q=0.9, */*;q=0.1`. `User-Agent`, çerezsizlik,
  `Authorization` yokluğu, vekil, zaman aşımı, yeniden deneme, devre kesici
  ve uçuştaki tekilleştirme F3 ile aynıdır (AC-P21-3). `api.nuget.org` ayrı
  bir devre kesici hostudur.
- `nuget.config`, hizmet dizini (`/v3/index.json`), kayıt ve katalog API'leri
  hiçbir zaman okunmaz veya istenmez.

### 9. `.nuspec` meta verisi ve lisans önceliği (D-132…D-134; AC-P21-4…7, AC-P21-15)

`nugetRegistry.ts` `fetchNugetMetadata(session, lowerId, lowerVersion,
signal): Promise<MetadataOutcome>`:

- **Yanıt:** 404/410 `not_found` olur (24 saat önbellekte kalır). Boyut aşımı
  `error` (`TOO_LARGE`) olur. Gövde `parseXml` ile ayrıştırılır. XML hatası,
  kökün `package` olmaması, `metadata` alt öğesinin yokluğu veya
  `asciiLower(metadata/id) !== lowerId` durumlarında sonuç
  `{ kind: 'error', code: 'BAD_NUSPEC' }` olur ve **önbelleğe yazılmaz**
  (AC-P21-4). Nuspec öğe adları harf duyarlıdır (`package`, `metadata`, `id`,
  `license`, `licenseUrl`); karşılaştırma `localName` ile yapılır.
- **Lisans önceliği** (D-133):
  1. `metadata/license` ve `type="expression"`: metin kırpılır, `sanitizeText`
     uygulanır, 1000 kod noktasına kesilir. Boş değilse
     `declaredLicense = metin`. Durum `ok` olur; normalleştirme F3'teki gibi
     `normalizeLicense` ile worker'da yapılır.
  2. `metadata/license` ve `type="file"`: `licenseUnclassified = 'file'`,
     `declaredLicense = null`. Bildirilen yol `licenseFilePath` alanına
     yazılır. Bunun için önce `\` → `/` çevrilir, uzunluk en fazla 256 olmalıdır
     ve yol `normalizeArchivePath`'ten geçmelidir. Geçmezse alan `null` kalır
     ama `licenseUnclassified` yine `'file'` olur.
  3. `metadata/licenseUrl`: `nugetLicenseUrls.ts` `classifyLicenseUrl(url)`.
  4. Hiçbiri yoksa `declaredLicense = null` ve `licenseUnclassified = null`
     (F3 `no_license`).
  - `type` başka bir değerse veya ifade boşsa `license` öğesi yokmuş gibi
    sıradaki adıma geçilir. Birden çok `license` öğesi varsa belge sırasındaki
    ilk öğe kullanılır.
- **`classifyLicenseUrl`** (saf, ağ yok, URL hiçbir zaman istenmez):
  - Değer kırpılır ve `new URL` ile yalnız ayrıştırılır. Ayrıştırılamayan,
    `http`/`https` dışı veya 2000 karakterden uzun değer `unclassified` olur.
  - Host `licenses.nuget.org` ise yol baştaki `/` atılarak bir kez
    `decodeURIComponent` ile çözülür (hata → `unclassified`). Sonuç
    `src/lib/spdxExpression.ts` ile geçerli bir SPDX ifadesiyse
    `{ kind: 'expression', value }` döner.
  - Host `aka.ms` ve yol ASCII harf duyarsız `/deprecatelicenseurl` ise
    `{ kind: 'ignore' }` döner: `licenseUrl` yokmuş gibi işlenir.
  - Diğer durumlarda URL kanonik biçime getirilir ve sabit tabloda aranır.
    Kanonik biçim: şema yok sayılır, host küçük harfe çevrilir ve baştaki
    `www.` atılır, yol küçük harfe çevrilir, sondaki `/` ve tek bir
    `.html`/`.htm`/`.txt`/`.php` uzantısı atılır, sorgu ve parça
    reddedilir. Tablo anahtarları:
    - MIT: `opensource.org/licenses/mit`, `opensource.org/licenses/mit-license`
    - Apache-2.0: `opensource.org/licenses/apache-2.0`,
      `apache.org/licenses/license-2.0`
    - BSD-2-Clause: `opensource.org/licenses/bsd-2-clause`
    - BSD-3-Clause: `opensource.org/licenses/bsd-3-clause`
    - ISC: `opensource.org/licenses/isc`, `opensource.org/licenses/isc-license`
    - MPL-2.0: `opensource.org/licenses/mpl-2.0`, `mozilla.org/mpl/2.0`
    - `spdx.org/licenses/<id>`: `<id>` tek bir SPDX kimliğiyse, SPDX
      listesindeki kanonik harf biçimiyle döner.
  - Eşleşmeyen URL `{ kind: 'unclassified' }` olur ve
    `licenseUnclassified = 'url'` atanır. URL metni saklanmaz, loglanmaz ve
    çıktıya yazılmaz.
  - Tablo veya kurallar değişirse NuGet meta veri çıkarıcı sürümü artar
    (aşağıda).
- **Kanonik kimlik:** `metadata/id` değeri `isValidNugetId`'den geçerse
  `canonicalName` olarak saklanır (Karar 13.2). Geçmezse `null` olur.
  Kimlik eşitliği denetimi yine yapılır.
- **`RegistryMetadata`** NuGet için isteğe bağlı alanlarla genişler:
  `licenseUnclassified: 'file' | 'url' | null`, `licenseFilePath: string | null`
  ve `canonicalName: string | null`. `licenseText` `null`,
  `archiveCandidates` `[]` olur, çünkü NuGet adayı taramanın lock özetinden
  kurulur ve önbelleğe girmez (Karar 10.1).
- **Önbellek:** `found` ve `not_found` sonuçları F3 süreleriyle
  `registry_package_cache`'e `ecosystem = 'nuget'` ve küçük harfli
  ad/sürümle yazılır. Üç yeni kolon kullanılır (Karar 14). Çıkarıcı sürümü
  ekosistem başına tutulur: `METADATA_EXTRACTOR_VERSIONS = { npm: 1, pypi: 1,
  nuget: 1 }`. npm/PyPI değerleri değişmez, bu yüzden mevcut önbellek
  geçersizleşmez. `METADATA_EXTRACTOR_VERSION` dışa aktarımı npm/PyPI için
  aynı değerle kalır.

### 10. Arşiv aşaması, bütünlük ve L-5 fail-safe (D-135, D-136; AC-P21-9)

#### 10.1 Aday ve önkoşullar

npm'de kayıt defteri özeti yayımlar ve karşılaştırma indirmeden önce yapılır.
NuGet flat container özet yayımlamaz, bu yüzden NuGet'te karşılaştırma
**indirilen baytlar üzerinde** yapılır. Beklenen değer taramanın lock/assets
özetidir. Akış (`index.ts`, adım 3b'den sonra, yalnız NuGet anahtarları;
npm/PyPI akışı değişmez):

1. Anahtar runtime değilse veya meta verisi `found` değilse arşiv aşaması
   çalışmaz. Bu, F3 kuralıdır; NuGet'te tüm paketler runtime'dır (D-127).
2. Anahtarın yan kanal kayıtları toplanır (`enrichmentKeyOf({ ecosystem:
   'dotnet', … })`) ve ayrık `sha512-…` değerleri çıkarılır.
   - **0 değer:** indirme yapılmaz. `notice_status = 'no_candidate'`,
     `lock_integrity = 'not_comparable'` olur.
   - **1'den fazla farklı değer:** indirilen bayt dizisi en fazla birine
     eşit olabilir. npm'in "her lock kaydı eşleşmeli" kuralıyla tutarlı
     olarak anahtar **`mismatch`** sayılır ve indirme yapılmaz.
   - **Tek değer `d`:** aday `{ url: <archive-nuget URL'si>, algorithm:
     'sha512', digests: [d], size: null, filename: '<id>.<ver>.nupkg' }`
     olarak kurulur.
3. **Önbellek:** `registry_archive_cache` içinde `(nuget, id, ver,
   'sha512-'+d)` satırı varsa kullanılır ve `lock_integrity = 'match'` olur.
   Satır yalnız daha önce `d`'ye karşı doğrulanmış baytlardan yazılmış
   olabilir.

#### 10.2 İndirme ve doğrulama

`collectArchive` için NuGet dalı:

- F3 kuralları aynen geçerlidir: kota, uçuştaki bayt bütçesi, 64 MiB sınırı,
  yönlendirmesiz istek, devre kesici ve bütçe.
- İndirme hatası, boyut sınırı, kota veya bütçe aşımında sonuç
  `not_comparable` olur ve davranış F3 ile aynıdır: `.nuspec` lisansı
  kullanılır, NOTICE durumu ilgili F3 değerini alır.
- **Ham özet:** ana iş parçacığının akış SHA-512'si `d`'ye eşitse sonuç
  `match` olur ve arşiv iş parçacığı lisans dosyası çıkarımı için çalışır.
- **İmzalı paket içerik özeti:** ham özet eşit değilse baytlar arşiv iş
  parçacığına `verify: { nugetContentHash: [d] }` ile gönderilir. İş
  parçacığı önce `nupkgHash.ts` ile içerik özetini hesaplar (10.3). Bu adım
  hiçbir girdiyi açmaz ve sıkıştırma çözmez.
  - Özet `d`'ye eşitse sonuç `match` olur ve aynı iş parçacığı çıkarıma
    devam eder.
  - Eşit değilse veya hesaplanamıyorsa (imza girdisi yok, yapı beklenmedik,
    ZIP64) iş parçacığı `{ kind: 'integrity_mismatch' }` döner ve **hiçbir
    girdiyi açmaz**. "Arşiv içeriğine bütünlük doğrulanmadan dokunulmaz"
    ilkesi (ADR-006 Karar 6) böylece korunur: doğrulama öncesi yalnız yapısal
    üst veri okunur. Bu okuma sınırlıdır, sıkıştırma çözmez ve paket içeriğini
    yorumlamaz.
- **Uyuşmazlık (fail-safe):**
  - Tampon atılır ve önbelleğe yazılmaz.
  - Değerler: `lock_integrity = 'mismatch'`,
    `notice_status = 'not_attempted'`, `notice_archive_id = NULL`.
  - Worker bu anahtar için `.nuspec` lisansını ve `license_unclassified`
    değerini kullanmaz: `license_expression = NULL`,
    `license_source = 'none'`, runtime paket için `NOASSERTION` bulgusu.
  - SBOM, Excel, NOTICE ve `[registry]` satırı L-5 kuralıyla türetilir
    (ADR-007 Karar 12, aynı kolon ve metinler).
  - NuGet `integrity_failed` **üretmez**. Bu değer kayıt defterinin
    yayımladığı özetle uyuşmazlık içindir (npm/PyPI).
- `ArchiveStageResult` isteğe bağlı `lockIntegrity` alanıyla genişler.
  `ArchiveThreadOutcome` `integrity_mismatch` türünü kazanır.
  `defaultLockIntegrity` şöyle olur: zenginleştirme açıkken npm ve NuGet için
  `not_comparable`, PyPI için `null`; zenginleştirme kapalıyken `null`.
- Uyuşmazlık önbelleğe alınmadığı için özel kaynaktan gelen paketler her
  taramada yeniden indirilir. Bu kabul edildi, çünkü kota ve bütçe yükü
  sınırlar (Sonuçlar).

#### 10.3 NuGet içerik özeti algoritması (`nupkgHash.ts`)

NuGet, imzalı bir paketin `contentHash` değerini **imza girdisi hiç
eklenmemiş gibi** hesaplar (NuGet.Packaging
`SignedPackageArchiveUtility.GetPackageContentHash`). Uygulama şöyledir:

1. EOCD ve merkezi dizin `readCentralDirectory` kurallarıyla okunur: ZIP64
   ve çok disk reddedilir, `maxEntries` uygulanır. Her kaydın konumu ve uzunluğu
   tutulur.
2. Adı tam olarak `.signature.p7s` olan (kökte, harf duyarlı) **tek** bir
   kayıt olmalıdır; aksi durumda özet hesaplanamaz. İmza girdisinin yerel
   girdi uzunluğu şöyle hesaplanır: yerel başlık (30 + ad + ek alan),
   sıkıştırılmış veri ve bayrak bit 3 varsa veri tanımlayıcısı (12 veya
   imzalı 16 bayt).
3. SHA-512 akışına şunlar eklenir:
   - (a) dosya başından ilk yerel başlığa kadar olan baytlar;
   - (b) imza dışındaki her girdinin yerel başlık + veri (+ tanımlayıcı)
     baytları, yerel konum sırasıyla;
   - (c) imza dışındaki her merkezi dizin kaydı, konum sırasıyla: kaydın
     ilk 42 baytı, sonra "yerel başlık göreli konumu" alanı (yerel konumu
     imza girdisinden sonra gelen kayıtta imza girdisinin uzunluğu kadar
     azaltılmış değer, 4 bayt LE), sonra kaydın kalanı;
   - (d) EOCD'nin ilk 8 baytı, sonra güncellenmiş alanlar: diskteki ve
     toplam kayıt sayısı (sayı − 1, 2+2 bayt), merkezi dizin boyutu (imza
     kaydı uzunluğu çıkarılmış, 4 bayt), merkezi dizin konumu (imza yerel
     girdi uzunluğu çıkarılmış, 4 bayt). Ardından özgün EOCD'nin 20. baytından
     dosya sonuna kadar olan kısım eklenir (yorum uzunluğu ve yorum).
4. Sonuç base64 olarak `sha512-<base64>` biçiminde `d` ile karşılaştırılır.

Tüm konumlar tampon sınırları içinde denetlenir. Girdiler arasında
örtüşme varsa veya boşluk tutarsızsa sonuç "hesaplanamadı" olur. İş sabit
bellekle O(n)'dir. Güven düzeyi: orta (Karar 16, satır 3). Kabul kapısı
AC-P21-16'dır.

### 11. `.nupkg` lisans dosyası seçimi ve NOTICE (D-137; AC-P21-10, AC-P21-11)

- `ArchiveKind` `'nuget'` değerini kazanır. `detectFormat`: dosya adı
  `.nupkg` ile bitmeli (ASCII harf duyarsız) **ve** zip sihirli baytları
  (`PK\x03\x04`) bulunmalıdır; aksi durumda `unsupported_format`. Mevcut zip
  okuyucusunun ZIP64, şifreleme, yöntem, CRC-32, yol normalleştirme ve boyut
  kuralları aynen geçerlidir.
- `licenseFiles.ts` yeni bir yerleşim kazanır: `ArchiveLayout = 'top-folder'
  | 'wheel' | 'nupkg'`. `LicenseFileMatcher('nupkg', { declaredPath })`
  şu aday kurallarını uygular:
  - (a) Derinliği 1 olan (yolunda `/` bulunmayan) ve adı D-67 önek kuralıyla
    `LICENSE`, `LICENCE`, `COPYING`, `NOTICE` veya `COPYRIGHT` ile başlayan
    girdiler (mevcut `isLicenseFileName`).
  - (b) Normalleştirilmiş yolu `declaredPath` ile ASCII harf duyarsız eşit
    olan girdi, adı ne olursa olsun.
  - Hiçbir zaman aday olmayanlar: `[Content_Types].xml`, `_rels/` ve
    `package/` altındaki girdiler, `.signature.p7s` ve `<id>.nuspec`.
    Bunların verisi açılmaz.
- `declaredPath`, meta verideki `licenseFilePath`'tir ve iş parçacığı
  girdisine eklenir (`{ kind, filename, bytes, declaredLicensePath, verify? }`).
  Arşiv önbellek satırı özet anahtarlıdır. Bildirilen yol aynı (kimlik, sürüm)
  için sabit olduğundan satır belirlenimci kalır. `ARCHIVE_EXTRACTOR_VERSION`
  değişmez, çünkü npm/PyPI çıkarımı değişmez ve NuGet satırları yenidir.
- Sınırlar F3 ile aynıdır: en fazla 10 dosya, dosya başına 1 MiB, paket
  başına 4 MiB metin; çözme, arındırma ve telif çıkarımı ADR-006 Karar 8'e
  uyar.
- NOTICE: NuGet paketleri F3 kuralıyla girer. "license enrichment not
  supported for this ecosystem" nedeni NuGet için üretilmez. Ekosistemi
  `dotnet` olan `no_candidate` satırı için yeni bir neden metni kullanılır.
  Kesin metin REQ-004 contract revizyonundadır. Mevcut F3 NOTICE golden'ı
  değişmez.

### 12. Etkin lisans, `type="file"` / sınıflandırılmamış URL bilgisinin saklanması ve çıktılar (D-133, D-134, D-139; AC-P21-5, -7, -12)

- `resolveEffectiveLicense` ekosistemden kaynağa tükenmeli bir eşleme
  kullanır: `npm → 'registry:npm'`, `pypi → 'registry:pypi'`,
  `nuget → 'registry:nuget'`. NuGet'te `lockLicenses` her zaman boştur, bu
  yüzden ipucu yolları hiç tetiklenmez (AC-P21-12).
- `type="file"` ve sınıflandırılmamış URL **durum değeri değildir**. Durum
  `no_license`'tır. Bu, F3 tablosuna göre etkin lisansın boş,
  `license_source = 'none'` ve runtime paket için `NOASSERTION` olması
  demektir. Ek bilgi yeni kolonda tutulur: `scan_dependencies.license_unclassified
  TEXT NULL CHECK IN ('file', 'url')`. Böylece şunlar korunur:
  - `registry:*` kaynağı her zaman dolu bir ifade taşır;
  - mevcut `license_enrichment_status` ve `license_source` CHECK kümeleri
    yalnız `registry:nuget` ile genişler;
  - tarama satırı, önbellek temizlense bile nedeni kendi başına taşır.
- Kolonun yazılma kuralı (worker, sonuç transaction'ı): kolon yalnız
  `status = 'no_license'`, anahtar NuGet ve `lock_integrity <> 'mismatch'`
  ise meta verideki `licenseUnclassified` değerini alır. Diğer her durumda
  `NULL` olur. F5 öncesi satırlarda ve npm/PyPI satırlarında `NULL` kalır.
- `DependencyEnrichment` isteğe bağlı `licenseUnclassified` ve
  `canonicalName` alanlarını kazanır.
- Çıktılar:
  - **Excel `License Source`:** öncelik L-5 uyuşmazlık metni >
    `license_unclassified` (`file` / `url`) metni > mevcut kaynak metni.
  - **NOTICE:** `type="file"` metni toplanan lisans dosyalarından gelir.
  - **SBOM:** `licenseDeclared` değeri `NOASSERTION`'dır (`no_license`).
    purl `pkg:nuget/…` olur.
  - Kesin metinler REQ-004 contract revizyonundadır. API JSON şeması
    değişmez; yeni kolon API yanıtına eklenmez (AC-G-4).
- `[registry]` satırı: NuGet anahtarları mevcut sayımlara katılır.
  `licenseUnclassified` ayrı sayılmaz. Şablon değişmez (AC-P21-14).

### 13. OSV: toplu sorgu, kanonik ad, `affected` seçimi ve yeniden kontrol (D-140; AC-NV-1…4)

#### 13.1 Aday kümesi ve ekosistem

Aday kümesine kesin sürümlü ve `checkCoordinates` `ok` olan `dotnet`
paketleri eklenir. `candidateQueries` ekosistemi tükenmeli bir eşlemeyle
seçer: `npm → 'npm'`, `pypi → 'PyPI'`, `nuget → 'NuGet'`. `OsvPackageQuery`
tipinde `ecosystem` değeri `'npm' | 'PyPI' | 'NuGet'` olur.

#### 13.2 Gövdedeki ad ve sürüm

- Tekilleştirme anahtarı `coordinateKey('nuget', asciiLower(id),
  asciiLower(sürüm))`'dür.
- Gövdedeki `name` alanı şu sırayla seçilir:
  1. Bu taramanın zenginleştirmesinden gelen `canonicalName`, yani `.nuspec`
     `<id>` değeri. Lookup'a `canonicalNames: ReadonlyMap<key, string>`
     seçeneğiyle verilir.
  2. Yoksa anahtarın belirlenimci sıradaki ilk kaydının kaynak harf
     biçimi.
- Gövdedeki `version` alanı, o kaydın normal biçimli sürümüdür (küçük harfe
  çevrilmez).
- Gerekçe (Karar 16, satır 4): OSV'nin NuGet adlarını harf duyarsız eşleyip
  eşlemediği doğrulanamadı. Kanonik kimlik her iki durumda da doğru sonuç
  verir. Bu, D-140'ta tanımlanan yedeğin koşulsuz uygulanmasıdır.
- Sıralama mevcut iç anahtarla kod noktası sırasında yapılır (`npm` <
  `nuget` < `pypi`). Toplu sınır, sayfalama, kimlik sınırları, devre kesici ve
  `[osv]` satırı aynen geçerlidir. NuGet içermeyen taramada gövde F4 ile bayt
  bayt aynıdır (AC-NV-4).

#### 13.3 `affected` seçimi (AC-NV-2)

`bestAffected` yalnız `dotnet` için bir adım kazanır. Mevcut ilk adım
(birebir ad) korunur. Ardından `ecosystem === 'NuGet'` ve
`asciiLower(entry.package.name) === asciiLower(dep.name)` olan ilk girdi
seçilir. Sonra mevcut zincir (ekosistem, ilk girdi) devam eder. npm/PyPI
davranışı değişmez. Bulgunun açılması bu seçime bağlı değildir: toplu
sorgu sonucu sorgu sırasına göre eşlenir. `affected` seçimi yalnız
etkilenen/düzeltilmiş sürüm metnini belirler.

#### 13.4 Yeniden kontrol kapsamı (`SCOPE_PAGE_SQL`, AC-NV-3)

```sql
cand AS (
  SELECT CASE p.ecosystem::text WHEN 'nodejs' THEN 'npm'
                                WHEN 'python' THEN 'pypi'
                                WHEN 'dotnet' THEN 'nuget' END AS eco,          -- no ELSE
         CASE p.ecosystem::text
              WHEN 'python' THEN lower(regexp_replace(p.name, '[-_.]+', '-', 'g'))
              WHEN 'dotnet' THEN lower(p.name COLLATE "C")                      -- ASCII-only, locale-free
              ELSE p.name END AS req,
         CASE p.ecosystem::text WHEN 'dotnet' THEN lower(p.version COLLATE "C")
              ELSE p.version END AS version,
         p.version AS display_version,
         p.ecosystem::text AS ecosystem,
         p.name
    FROM latest s
    JOIN scan_dependencies sd ON sd.scan_id = s.scan_id
    JOIN packages p ON p.id = sd.package_id
   WHERE p.ecosystem::text IN ('nodejs', 'python', 'dotnet')
     AND p.version IS NOT NULL AND p.version <> ''
)
SELECT c.eco, c.req, c.version, min(c.ecosystem) AS ecosystem,
       COALESCE(max(r.canonical_name), min(c.name COLLATE "C")) AS name,
       min(c.display_version COLLATE "C") AS display_version
  FROM cand c
  LEFT JOIN registry_package_cache r
         ON c.eco = 'nuget' AND r.ecosystem = 'nuget' AND r.outcome = 'found'
        AND r.name = c.req AND r.version = c.version
 WHERE … (keyset unchanged) GROUP BY c.eco, c.req, c.version ORDER BY … (unchanged)
```

- npm/PyPI için `req`, `version`, `name` ifadeleri ve sıralama bugünküyle
  aynıdır. `display_version` bu ekosistemlerde `version`'a eşittir, bu yüzden
  gövde değişmez.
- `lower(… COLLATE "C")` yalnız ASCII harflerini küçültür ve yerel ayardan
  bağımsızdır. NuGet kimlik ve sürümleri ASCII olduğu için sonuç JS
  `asciiLower` ile birebir aynıdır (Türkçe `LC_CTYPE`'ta I-14 sorunu NuGet
  için oluşmaz).
- JS tarafında her satır yine `vulnerabilityKeyOf` denetiminden geçer.
  Satırın `eco` değeri ile JS anahtarının ekosistemi farklıysa satır
  atlanır ve sayılır. Test: hiçbir `dotnet` paketi `pypi` olarak
  etiketlenmez.
- 10 000 paket sınırı, sayfa boyutu ve süre sınırları değişmez.

### 14. Göç `008` (D-139; AC-G-7)

Dosyalar: `db/migrations/008_nuget_enrichment.up.sql` / `.down.sql`. Nihai
metin database-engineer'ındır. Aşağıdaki adlar ve kısıtlar bağlayıcıdır.
Satır içi CHECK adları PostgreSQL varsayılanıdır; database-engineer gerçek
adları `pg_constraint` üzerinden doğrular ve göçte `DROP CONSTRAINT`'i
**`IF EXISTS` olmadan** yazar (ad yanlışsa göç başarısız olmalıdır, sessizce
iki CHECK kalmamalıdır).

```sql
-- up
ALTER TABLE registry_package_cache
    DROP CONSTRAINT registry_package_cache_ecosystem_check,
    ADD  CONSTRAINT registry_package_cache_ecosystem_check
         CHECK (ecosystem IN ('npm', 'pypi', 'nuget')),
    ADD COLUMN license_unclassified TEXT NULL
         CHECK (license_unclassified IN ('file', 'url')),
    ADD COLUMN license_file_path    TEXT NULL
         CHECK (license_file_path IS NULL OR char_length(license_file_path) <= 256),
    ADD COLUMN canonical_name       TEXT NULL
         CHECK (canonical_name IS NULL OR char_length(canonical_name) <= 100),
    ADD CONSTRAINT registry_package_cache_nuget_fields
         CHECK ((ecosystem = 'nuget' AND outcome = 'found')
                OR (license_unclassified IS NULL AND license_file_path IS NULL
                    AND canonical_name IS NULL));

ALTER TABLE registry_archive_cache
    DROP CONSTRAINT registry_archive_cache_ecosystem_check,
    ADD  CONSTRAINT registry_archive_cache_ecosystem_check
         CHECK (ecosystem IN ('npm', 'pypi', 'nuget'));

ALTER TABLE scan_dependencies
    DROP CONSTRAINT scan_dependencies_license_source_check,
    ADD  CONSTRAINT scan_dependencies_license_source_check
         CHECK (license_source IN ('registry:npm', 'registry:pypi', 'registry:nuget',
                                   'lockfile (unverified)', 'none')),
    ADD COLUMN license_unclassified TEXT NULL
         CHECK (license_unclassified IN ('file', 'url'));
```

```sql
-- down
-- Data lost: NuGet license metadata cache rows and NuGet archive (NOTICE)
-- cache rows (re-downloadable; scan_dependencies.notice_archive_id of NuGet
-- rows becomes NULL via ON DELETE SET NULL, a NOTICE then needs a rescan);
-- license_source 'registry:nuget' is rewritten to 'none' (license_expression
-- is KEPT, so those rows show an expression with source 'none' until
-- rescanned); the 'license file in package' / 'unclassified license URL'
-- markers (scan_dependencies.license_unclassified) are dropped. No scan,
-- dependency, package, finding or license_findings row is deleted.
DELETE FROM registry_archive_cache WHERE ecosystem = 'nuget';
DELETE FROM registry_package_cache WHERE ecosystem = 'nuget';
UPDATE scan_dependencies SET license_source = 'none' WHERE license_source = 'registry:nuget';
ALTER TABLE scan_dependencies
    DROP COLUMN license_unclassified,
    DROP CONSTRAINT scan_dependencies_license_source_check,
    ADD  CONSTRAINT scan_dependencies_license_source_check
         CHECK (license_source IN ('registry:npm', 'registry:pypi',
                                   'lockfile (unverified)', 'none'));
ALTER TABLE registry_archive_cache
    DROP CONSTRAINT registry_archive_cache_ecosystem_check,
    ADD  CONSTRAINT registry_archive_cache_ecosystem_check CHECK (ecosystem IN ('npm', 'pypi'));
ALTER TABLE registry_package_cache
    DROP CONSTRAINT registry_package_cache_nuget_fields,
    DROP COLUMN canonical_name,
    DROP COLUMN license_file_path,
    DROP COLUMN license_unclassified,
    DROP CONSTRAINT registry_package_cache_ecosystem_check,
    ADD  CONSTRAINT registry_package_cache_ecosystem_check CHECK (ecosystem IN ('npm', 'pypi'));
```

- Enum değişikliği yoktur (`tech_ecosystem` `dotnet`'i içerir).
  `notice_status`, `license_enrichment_status` ve `lock_integrity` kümeleri
  değişmez. `001`…`007` değişmez; `db/schema.sql` güncellenir.
- Göç tek transaction'da çalışır ve `CONCURRENTLY` içermez. Eklenen kolonlar
  varsayılansız ve `NULL`'dur (tablo yeniden yazılmaz). CHECK doğrulaması
  tabloları bir kez tarar; uygulama durdurulduktan sonra uygulanır.
- Down betiği toplu veri güncellemesi içerir (`UPDATE … 'none'`). REQ-006
  Notlar gereği yalnız açık insan onayıyla çalıştırılır. Göçün yerel
  veritabanına uygulanması kullanıcı kararıdır.
- `db/README.md`: NuGet önbellek temizleme SQL'i eklenir
  (`DELETE FROM registry_archive_cache WHERE ecosystem = 'nuget';
  DELETE FROM registry_package_cache WHERE ecosystem = 'nuget';`).

### 15. Teknoloji yığını, arayüz ve yapılandırma (D-130, D-138; AC-P20-17, AC-P21-13)

- `runner.config.ts` `supportedEcosystems: ['nodejs', 'python', 'dotnet']`.
  `loadEcosystems` desteklenenlerle süzer. Yığın boşsa varsayılan
  `['nodejs', 'python', 'dotnet']` olur (sıra korunur).
- `public/index.html` "Technology Stack" listesine
  `<option value="dotnet">.NET (NuGet)</option>` eklenir. Varsayılan seçim
  değişmez.
- Yeni ayar anahtarı yoktur. `ENRICHMENT_LIMITS.client.nuspecMaxBytes =
  1 MiB` bir koddaki sabittir. `REGISTRY_ENRICHMENT=off` (veya fail-closed
  geçersiz değer) iken istemci kurulmaz, NuGet anahtarları `disabled` olur ve
  `api.nuget.org`'a bağlantı açılmaz. `VULNERABILITY_LOOKUP=off` iken NuGet
  için de OSV/NVD bağlantısı yoktur.
- `.env.example` değişmez. README güncellemeleri D-141'de sayılanlardır
  (dışarı giden bağlantılar listesine `api.nuget.org` eklenir).

### 16. "Doğrulanması gerekiyor" dış bilgiler: güven ve yedek

Bu oturumda ağ erişimi kullanılmadı. Değerler genel bilgiye dayanır ve
**doğrulanması gerekiyor**. Gerçek ağ teyidi AC-P21-16'da ana oturumda
yapılır ve handoff'a yazılır.

| # | Bilgi | Güven | Yedek / teyit adımı |
| --- | --- | --- | --- |
| 1 | Flat container yolları: `https://api.nuget.org/v3-flatcontainer/{id}/{ver}/{id}.nuspec` ve `…/{id}/{ver}/{id}.{ver}.nupkg`. `{id}` ve `{ver}` küçük harflidir; sürüm NuGet normal biçimindedir (4. parça sıfırsa yok, yapı üst verisi yok). | yüksek | Yol yanlışsa her istek `not_found` olur ve `[registry]` satırında görünür. Düzeltme yalnız kod sabitidir (yeni host değil). AC-P21-16'da `.nuspec`/`.nupkg` istek sayıları ve 200 oranı raporlanır. |
| 2 | `api.nuget.org` flat container, `.nuspec` ve `.nupkg` için yönlendirmesiz 200 döner (CDN önde). | orta-yüksek | Farklı hosta yönlendirme o istek için hatadır (meta veri `error`, arşiv `download_failed`) ve görünür kalır. Yeni host yalnız REQ revizyonu (yeni D-xx), ADR ve güvenlik incelemesiyle eklenir. Aynı köken yönlendirmesi meta veride ≤ 3 adımla izlenir. |
| 3 | `packages.lock.json` `contentHash` ve `project.assets.json` `libraries.*.sha512`, `.nupkg`'nin base64 SHA-512'sidir. **Ancak** imzalı paketlerde (nuget.org 2018'den beri tüm paketleri depo imzasıyla imzalar) bu değer, imza girdisi çıkarılmış arşivin özetidir (Karar 10.3). Ham dosya özetine eşit değildir. | ham özet: orta (imzasız paketler için); imzalı paket içerik özeti algoritması: orta | Çift kabul: ham özet **veya** içerik özeti eşitse `match`. Algoritma yanlışsa sonuç sessiz bir hata olmaz: lock'lu tüm paketler `mismatch` olur, `NOASSERTION` alır ve `[registry]` uyuşmazlık sayısında görünür. **Release kapısı:** AC-P21-16'da depo imzalı en az bir nuget.org paketi `match` vermelidir ve uyuşmazlık oranı raporlanmalıdır. Oran yüksekse REQ-006 release'i durur; ADR revizyonuyla algoritma düzeltilir. Ara yedek olarak NuGet doğrulaması kapatılıp `no_candidate` davranışına dönülebilir (yeni D-xx gerekir). |
| 4 | OSV `querybatch`'te NuGet ad eşleşmesinin harf duyarlılığı. OSV yalnız PyPI adlarını normalleştirir; NuGet için birebir eşleşme olasılığı yüksektir (harf duyarsızlık güveni: düşük-orta). | düşük-orta | Kanonik ad (`.nuspec` `<id>`) koşulsuz kullanılır (Karar 13.2). Yanıt eşleşmesi sorgu sırasına göredir, `affected` seçimi harf duyarsızdır. AC-P21-16'da ana oturum bilinen açıklı bir paketle (ör. `Newtonsoft.Json` 12.0.1, GHSA-5crp-9r3c-p9vr) kanonik ve küçük harfli adla sorguyu karşılaştırıp sonucu handoff'a yazar. |
| 5 | `licenses.nuget.org/<ifade>`: `type="expression"` paketlerde nuget.org'un ürettiği kanonik adres. İfade yüzde kodludur (`(MIT%20OR%20Apache-2.0)`). `type="file"` paketlerde `licenseUrl` `https://aka.ms/deprecateLicenseUrl`'dir. | yüksek | Çözülemeyen yol `unclassified` → `NOASSERTION` (muhafazakâr). |
| 6 | purl `nuget` tipi: ad alanı yoktur ve purl belirtimi ad için küçük harf normalleştirmesi istemez (örnek `pkg:nuget/EnterpriseLibrary.Common@6.0.1304`). | orta-yüksek | Belirtim küçük harf isterse yalnız `nugetPurl` değişir. purl golden'ları ve SBOM bileşenleri bir contract/REQ revizyonuyla güncellenir; parmak izi formülü (ADR-003) purl'e bağlı değilse etkilenmez. |
| 7 | `packages.lock.json` `version` 1 (CPM'siz) / 2 (CPM, `CentralTransitive`); `project.assets.json` `version` 3. | yüksek | Bilinmeyen sürüm dosya hatasıdır ve sıradaki kaynağa geçilir (görünür). |
| 8 | NuGet sürüm normalleştirmesi ve kimlik kuralı (REQ-006 AC-P20-8/9). | yüksek | REQ test tablosu kabul testidir. |
| 9 | `bitwarden/server` reposunun `packages.lock.json` dosyalarını sürüm kontrolünde tuttuğu (Renovate kilit bakımı). | orta | Ana oturum taramadan önce klonda `packages.lock.json` varlığını doğrular. Yoksa lock yolu yalnız AC-P20-11 fixture'ıyla kanıtlanır ve handoff'a yazılır. İkincil aday `jbogard/MediatR` lock'suz yolu (proje dosyası, CPM varsa CPM) gösterir. `dotnet restore` hiçbir koşulda çalıştırılmaz. |

### 17. Önceki ADR'lere etkiler ve yol sahipliği

- ADR-005, ADR-006 ve ADR-007'ye tarihli "ADR-008 notu (2026-10-11)"
  eklendi (kısmen superseded maddeler başlıkta).
- Yol sahipliği (manifest önerisi; manifest'i agent yazmaz):

  | Agent | Yollar |
  | --- | --- |
  | backend-engineer | `src/**` (`src/db` hariç): `src/scanner/**`, `src/enrichment/**`, `src/vulnerability/**`, `src/notice/**`, `src/reports/**`, `src/sbom/**`, `src/lib/**`, `src/types/**`; `README.md` |
  | database-engineer | `db/**` (göç `008`, `schema.sql`, `db/README.md`), `src/db/**` |
  | qa-automation | `tests/**`, `vitest.config.ts`, `tests/fixtures/dotnet/**` (`.gitattributes` satırı ana oturum veya qa'nın manifestine eklenmelidir) |
  | frontend-engineer | `public/index.html` |
  | contract-broker | `docs/contracts/**` (REQ-004 notice contract 1.3.0 → 1.4.0, REQ-005 vulnerability data contract 1.1.0 → 1.2.0) |
  | solution-architect | `docs/architecture/adr/**` |

  `src` ile `src/db` alanları çakışır. backend-engineer `src/db`'ye yazmaz.
  database-engineer göçü backend'den önce veya ayrı sırada teslim eder. Aynı
  branch'te tek yazar kuralı geçerlidir.

## Gerekçe

- **Yürüyüşe ekosistem seçeneği,** npm/PyPI çıktısının bayt birebirliğini
  (AC-G-6) testle umut etmek yerine yapısal olarak garanti eder. `dotnet`
  istenmediğinde yürüyüş kodu F4 yoludur.
- **Elle yazılmış doğrusal XML okuyucu,** bağımlılık yasağına (D-128) uyar.
  DTD'yi baştan reddetmek XXE ve varlık bombasını sınır denetimine gerek
  kalmadan imkânsız kılar. Sonlandırıcıların `indexOf` ile aranması ve
  imlecin yalnız ileri gitmesi doğrusal zamanı kanıtlanabilir yapar.
- **Kaynak önceliği ve geri düşme,** NuGet'in gerçek çözümlemesini (lock,
  assets) beyandan (proje dosyası) üstün tutar. Bozuk bir dosya paketleri
  sessizce kaybettirmez.
- **İndirme sonrası doğrulama, NuGet'te tek güvenilir yoldur.** Flat
  container özet yayımlamaz. Kayıt/katalog API'si ek yüzey demektir (D-131).
  Lock/assets özeti kurulu arşivi temsil eder. İmzalı paket içerik özetinin
  eklenmesi, yalnız ham özete bakan bir uygulamanın nuget.org paketlerinin
  neredeyse tamamını `mismatch` sayıp lisans sütununu `NOASSERTION`'la
  doldurmasını önler (rapor kriteri P-21'in fiilen boşa düşmesi).
- **`license_unclassified` kolonu,** `registry:*` ⇒ "dolu ifade"
  değişmezini ve F3 durum kümesini korur. Çıktıların ihtiyaç duyduğu "neden"
  bilgisini de tarama satırında kalıcı tutar.
- **Kanonik ad,** OSV davranışı doğrulanamadığı için iki olasılıkta da doğru
  sonuç veren seçenektir. Maliyeti bir önbellek kolonu ve bir `LEFT JOIN`'dir.
- **`COLLATE "C"`,** yerel geliştirme veritabanının Türkçe yerel ayarında
  `I` harfinin yanlış küçülmesini NuGet anahtarları için kökten engeller.

## Değerlendirilen alternatifler

| Alternatif | Neden seçilmedi |
| --- | --- |
| npm'deki `fast-xml-parser` / `sax` gibi bir XML kütüphanesi | Yeni runtime bağımlılığı yasak (AC-G-5, D-128). Kütüphanelerin varsayılan varlık davranışı da ayrıca denetlenmeliydi. |
| Düzenli ifadelerle XML çıkarımı | Yorum, CDATA ve öznitelik sırası karşısında kırılgandır; geri izleme DoS riski taşır (D-128). |
| `dotnet list package --include-transitive` veya `dotnet restore` | MSBuild hedefleri kod çalıştırır; kapsam dışıdır (D-142, AC-G-10). |
| Yürüyüşte .NET adlarını her zaman tanımak ve npm/PyPI çıktısını sonradan süzmek | `filesystem` kayıt sırası ve varlığı değişirdi; AC-G-6 bayt birebirliği kırılgan olurdu. |
| `.nuspec`'i arşiv iş parçacığında ayrıştırmak | 1 MiB doğrusal girdi için iş parçacığı başlatma maliyeti ve yeni mesaj sözleşmesi gerekirdi. Ana iş parçacığında PyPI JSON emsali var (Karar 3). |
| Lisansı doğrulanmış `.nupkg` içindeki `.nuspec`'ten okumak (flat container `.nuspec`'i hiç istememek) | Lock'suz projelerde lisans sütunu boş kalırdı (P-21 kriteri). İkinci tarama sıfır istek ölçütü arşiv önbelleğine bağlanırdı. REQ D-131/D-132 flat container `.nuspec`'i tanımlar. Uyuşmazlıkta fail-safe zaten `.nuspec` lisansını devre dışı bırakır. |
| Yalnız ham SHA-512 ile doğrulama (REQ-006 ilk varsayımı) | Depo imzalı paketlerde `contentHash` imzasız içerik özetidir (Karar 16, satır 3). Bu, toplu yanlış `mismatch` ve `NOASSERTION` riski taşır. |
| İçerik özeti hesaplanamadığında `not_comparable` (F3 davranışı) | Beklenen özet vardır ama baytlar onu üretmiyor. Bu bir uyuşmazlıktır; kamu lisansına güvenmek yanlış atıf olurdu (D-136). |
| NuGet kayıt (registration) API'sinden `packageContent`/özet almak | Ek uç nokta ve istek demektir. Kayıt API'si `.nupkg` özeti yayımlamaz; katalog ayrıca `packageHash` taşır ama bu yeni bir yüzeydir (D-131). |
| `type="file"`/URL için yeni `license_enrichment_status` veya `license_source` değerleri | F3 etkin lisans tablosu, özet satırı ve contract'taki durum kümesi değişirdi. Kaynak değeri dolu ama ifade boş satırlar oluşurdu. |
| Bilgiyi yalnız önbellekten türetmek (yeni `scan_dependencies` kolonu yok) | Önbellek temizlenince eski taramaların Excel/NOTICE nedeni kaybolurdu. Tarama satırı kendi başına yeterli olmalıdır. |
| `.nuspec` `<copyright>` alanını NOTICE'e yazmak | F3 telif kuralı yalnız doğrulanmış arşivden çıkarımdır (ADR-006 Karar 8). Lock'suz projede doğrulanmamış meta veriden telif yazmak tutarsız olurdu. REQ kapsamında değildir. |
| OSV gövdesinde küçük harfli ad | OSV büyük olasılıkla birebir eşler (Karar 16, satır 4). Bu durumda sessiz yanlış negatif oluşurdu. |
| Kapsam SQL'inde `lower(p.name)` | Türkçe `LC_CTYPE`'ta `I` → `ı` dönüşümü olur ve anahtar JS anahtarıyla uyuşmaz (I-14). |

## Sonuçlar / Uygulama etkisi

- **Olumlu:**
  - .NET projeleri npm/PyPI ile aynı raporlara girer: bağımlılık, lisans,
    NOTICE, SBOM, OSV ve yeniden kontrol.
  - npm/PyPI ayrıştırma ve OSV gövdesi bayt bayt aynı kalır.
  - Yeni dış host tektir ve yol kuralı tam eşleşmeyle dardır.
- **Olumsuz / kabul edilen:**
  - Lock'lu projelerde her NuGet paketi için `.nupkg` indirilir (ilk tarama
    yavaşlar; arşiv önbelleği tekrarı önler).
  - Uyuşmazlık önbelleğe alınmaz. Özel kaynaktan gelen aynı kimlikli
    paketler her taramada yeniden indirilir ve `NOASSERTION` alır.
  - Lock'suz projelerde NOTICE yoktur (`no_candidate`).
  - `type="file"` ve bilinmeyen URL `NOASSERTION` alır.
  - Proje dosyasındaki düz sürüm "en düşük uygulanabilir" sürümdür (NU1603
    riski).
  - `Condition` birleştirmesi fazla paket raporlayabilir. `Import` ve
    `Directory.Build.props` ile gelen paketler lock/assets yoksa görünmez.
  - .NET 8 "artifacts" çıktı düzeninde `artifacts/obj/<Proje>/project.assets.json`
    tanınmaz (üst klasör `obj` değildir).
  - Göç down'ı NuGet satırlarında ifadeyi `none` kaynağıyla bırakır.
- **İçerik özeti riski:** Karar 10.3'ün doğruluğu AC-P21-16'ya kadar
  kanıtlanamaz. Hata durumu görünür ve muhafazakârdır.
- **Uygulama sırası:**
  1. contract-broker: iki contract revizyonu.
  2. insan: manifest `approved`; `api.nuget.org` erişimi açıkça kapsanmalıdır.
  3. database-engineer: `008`.
  4. backend-engineer, tek yazar olarak sırayla: ayrıştırıcı (Karar 2–7) →
     zenginleştirme (8–12) → OSV (13) → README.
  5. frontend-engineer: seçenek.
  6. qa-automation.
  7. security-red-team.
  8. integration-release.
- Non-trivial bir mimari karar olduğundan `docs/handoffs/REQ-006.md` bu
  ADR'ye ve Karar 16'daki teyit adımlarına atıfla güncellenmelidir
  (integration-release; takibi Delivery Lead yapar).

## Güvenlik etkisi

- **XML (XXE, varlık bombası, DoS):**
  - DOCTYPE ve `<!ENTITY` reddedilir. Varlık genişletmesi yoktur; yalnız beş
    önceden tanımlı varlık ve sayısal başvuru çözülür.
  - Dış kaynak, şema veya ad alanı çözümlemesi yoktur.
  - Derinlik, öğe ve değer sınırları tarama sırasında uygulanır. Okuyucu
    doğrusal zamanlıdır.
  - Repo XML'i yalıtılmış ayrıştırıcı iş parçacığında okunur. `.nuspec` en
    fazla 1 MiB'tır.
- **Arşiv:**
  - `.nupkg` mevcut zip okuyucusunun tüm sınırlarından geçer (ZIP64 yok,
    şifreleme yok, yöntem 0/8, CRC-32, girdi sayısı, açılmış boyut, iş
    parçacığı kaynak sınırları ve süre).
  - İçerik özeti yalnız yapısal üst veriyi okur. Konumlar tampon sınırları
    içinde denetlenir; örtüşme reddedilir.
  - Doğrulanmadan hiçbir girdi açılmaz. Arşiv diske yazılmaz, hiçbir girdi
    yürütülmez (`tools/`, `build/`, `*.ps1`, `.props`/`.targets`
    okunmaz).
- **Yol geçişi:**
  - Bildirilen lisans dosyası yolu `\` → `/` çevrimi, 256 karakter sınırı ve
    `normalizeArchivePath` kuralları (mutlak yol, sürücü harfi, `..`, boş
    bileşen, NUL) uygulandıktan sonra yalnız arşiv içi bir **eşleştirme
    anahtarıdır**. Hiçbir zaman dosya sistemi yolu olarak kullanılmaz.
  - Repo tarafında bağlantılar izlenmez ve CPM araması tarama kökünün üstüne
    çıkmaz.
- **SSRF:**
  - `licenseUrl` hiçbir koşulda istenmez; yalnız ayrıştırılır ve tabloyla
    eşlenir.
  - `nuget.config` okunmaz. Taban adres koddadır ve yalnız koddan
    enjekte edilebilir.
  - İstek yolları kimlik ve sürüm kurallarından geçmiş değerlerle kurulur ve
    tam eşleşen yol kuralıyla denetlenir. Farklı hosta yönlendirme hatadır.
  - Uzak yanıt veya repo başka bir hosta istek yaptıramaz.
- **Kod çalıştırma:** `dotnet`, `msbuild` ve `nuget` hiçbir zaman çağrılmaz.
  MSBuild özellikleri, koşulları ve `Import` değerlendirilmez. Statik test
  ve AC-G-10 alt süreç izleyicisi bunu doğrular.
- **Bütünlük:**
  - Arşiv yalnız lock/assets özetiyle (ham özet veya imzalı içerik özeti)
    doğrulanırsa kullanılır.
  - Uyuşmazlıkta fail-safe uygulanır: saldırgan yalnız daha muhafazakâr bir
    sonuç (`NOASSERTION`) üretebilir.
  - Birden çok farklı özet `mismatch` sayılır. Önbellek isabeti doğrulanmış
    özete bağlıdır. Paket imzası doğrulanmaz (kapsam dışı); içerik özeti
    yalnız bütünlük içindir, köken kanıtı değildir.
- **Gizlilik ve sızıntı:**
  - `project.assets.json`'da yalnız sayılan alanlar okunur.
  - JSON/XML hata metinleri sabittir; `err.message` kullanılmaz.
  - URL metni ve paket adları hata metnine veya loga yazılmaz.
  - Kesin sürümlü NuGet adları `api.nuget.org`'a ve `api.osv.dev`'e gider
    (README; mevcut anahtarlarla kapatılabilir).
- **Yeni dış host:** `api.nuget.org` (autonomy gates "external service
  entegrasyonu başlatma"). Erişim manifest onayıyla açılır.

## Test stratejisi

- **Birim (saf):**
  - `xmlReader`:
    - kodlamalar (UTF-8 BOM'lu/BOM'suz, UTF-16LE/BE, BOM'suz UTF-16 reddi,
      `windows-1252` + ASCII kabulü, ASCII dışı ret);
    - beş varlık ve sayısal başvuru (geçersiz kod noktası reddi);
    - CDATA, yorum ve işleme yönergesi;
    - çift öznitelik, eşleşmeyen etiket ve ikinci kök reddi.
  - XML güvenlik testleri:
    - `<!DOCTYPE x SYSTEM "file:///…">`;
    - milyar gülüş;
    - 1 MiB iç içe `<a>`;
    - 32 MiB tek öznitelik.
    - Her biri ≤ 1 sn içinde (CI payıyla 2 sn) hata döner. Dosya ve ağ
      erişimi olmadığı `fs`/`net` sarmalayıcı izleyicisiyle doğrulanır.
  - `nugetIdentity`: AC-P20-8 tablosu, sınır değerleri (2 147 483 647 ve
    bir fazlası, 128/129 karakter), kimlik kuralı (100/101, `..`, `a.`,
    `.a`), `asciiLower('I')`.
  - `nugetLicenseUrls`: tablo satırlarının her biçimi, `licenses.nuget.org`
    yüzde kodlu ifade, `aka.ms/deprecateLicenseUrl`, bilinmeyen URL, sorgulu
    URL.
  - `nupkgHash`:
    - test içinde üretilen zip ve buna eklenen `.signature.p7s` girdisi
      (girdi sonda ve ortada);
    - beklenen değer imza eklenmeden önceki zip'in ham SHA-512'sidir. Bu,
      algoritmanın "imzasız hâlin özeti" tanımıyla öz-tutarlılığını kanıtlar;
    - iki imza girdisi, örtüşen konum, ZIP64.
- **Ayrıştırıcı golden'ları (AC-P20-11, -12):**
  - `tests/fixtures/dotnet/`: lock v1, lock v2 (çok hedefli, RID'li,
    `Direct`/`Transitive`/`CentralTransitive`/`Project`, bilinmeyen tür),
    assets v3 (mutlak kullanıcı yolu içeren `project.restore` ve
    `packageFolders`), csproj + CPM (`VersionOverride`, `GlobalPackageReference`,
    `$(…)`, aralık, `Choose/When`, `Target` içindeki `ItemGroup`),
    `packages.config`, bozuk ve tip hatalı dosyalar;
  - `sample-solution/`;
  - her biri için beklenen JSON.
  - Mutlak yolun çıktının hiçbir alanında geçmediği metin taramasıyla
    doğrulanır.
- **Öncelik ve geri düşme (AC-P20-2):** lock + assets + csproj → yalnız lock;
  bozuk lock → assets + tek hata; CPM yukarı arama kökte durur; sınır aşımı.
- **AC-G-6:** F4 fixture'ının kopyasına .NET dosyaları ve .NET adlı
  bağlantılar (mevcut bağlantı oluşturma yardımcısıyla; ayrıcalık yoksa
  mevcut atlama kuralı) eklenir. `['nodejs','python']` çıktısı F4 beklenen
  çıktısıyla bayt bayt aynı olmalıdır. Aynı ağaç `['dotnet']` ile taranınca
  `dotnet` bağlantı kayıtları görülür.
- **Yan kanal:** geçerli/geçersiz `contentHash` (85 karakter, `=` eksik,
  1025 karakter); golden'a girmediği; `nugetIntegrity` yokken iş parçacığı
  yanıt şeklinin F4 ile aynı olduğu.
- **Sahte NuGet sunucusu** (loopback, istek sayaçlı; `.nuspec`, `.nupkg`,
  aynı/farklı köken yönlendirmesi, 404/410, 2 MiB yanıt, DOCTYPE'lı yanıt,
  farklı `<id>`, gzip):
  - AC-P21-2…9, AC-P21-13, -14;
  - ikinci taramada `.nuspec` isteği 0;
  - `licenseUrl` için istek 0;
  - eşleşen ham özet → `match`/`collected`;
  - imzalı test paketi → içerik özetiyle `match`;
  - farklı özet → fail-safe sonuçlarının hepsi;
  - özet yok → istek yok, `no_candidate`;
  - iki farklı özet → istek yok, `mismatch`.
  - Fixture `.nupkg`'ler testte üretilen küçük zip'lerdir; gerçek paket
    kopyalanmaz.
- **OSV ve yeniden kontrol:**
  - Mevcut sahte OSV sunucusu genişletilir: karışık 200 paket → tek toplu
    istek, NuGet sorgularında `NuGet` ve kanonik ad.
  - `affected` girdisi `newtonsoft.json` olsa da `Newtonsoft.Json`
    paketinin sürüm metni seçilir.
  - NuGet'siz gövde F4 ile bayt bayt aynıdır.
  - Yeniden kontrolde `dotnet` paketi `NuGet` olur, hiçbiri `pypi`
    olmaz.
  - Kapsam SQL'i Türkçe yerel ayar benzetimine dayanmaz; `COLLATE "C"`
    ifadesi statik olarak denetlenir, `I` içeren bir kimlikle uçtan uca test
    yapılır.
- **Ağ ve alt süreç:**
  - `tests/setup/networkGuard.ts` korunur ve `api.nuget.org` isteğini
    engellediği test edilir.
  - Koşulsuz `REGISTRY_ENRICHMENT=off`, `VULNERABILITY_LOOKUP=off` ve
    `VULNERABILITY_RECHECK=off` korunur (D-145).
  - AC-G-10: yerel klasör taramasında `child_process` fonksiyonları sarılır
    ve çağrı sayısı 0 olmalıdır.
- **Göç:** `008` up → down → up; down sonrası NuGet satırlarının silinmesi
  ve `registry:nuget` → `none` dönüşümü; CHECK ad doğrulaması.
- **Regresyon:** AC-G-9 listesi değiştirilmeden yeşil kalmalıdır.
- **Gerçek ağ (ana oturum, AC-P21-16):** Karar 16'daki teyit adımlarının
  hepsi uygulanır, özellikle satır 3'teki release kapısı ve satır 4'teki OSV
  harf denemesi.

## Kanıt (Evidence)

- Repo incelemesi (`62092e9`):
  - `src/scanner/parsers/{index,common,lockIntegrityValue,thread,threadParser}.ts`
    (`parseManifests`, `walkTree`, `ALL_MANIFEST_NAMES`, `SKIP_DIRS`,
    `readManifest`, yan kanal);
  - `src/enrichment/{index,archiveStage,coordinates,lockIntegrity,effectiveLicense,types,registryClient}.ts`;
  - `src/enrichment/archive/zip.ts` (`readCentralDirectory`) ve
    `archive/` dışa aktarımları;
  - `src/lib/http/safeHttpClient.ts` (`kind`, yönlendirme ve köken
    denetimi);
  - `src/vulnerability/{lookup,recheck,normalize}.ts` (`candidateQueries`,
    `SCOPE_PAGE_SQL`, `bestAffected`, `isExactVersion`);
  - `src/enrichment/cache.ts` (çıkarıcı sürümleri);
  - `src/scanner/sandbox/runner.config.ts`;
  - `db/migrations/006_registry_enrichment.{up,down}.sql`, ADR-007 Karar 14
    (`007`).
- `docs/product/REQ-006.md` r1; ADR-005, ADR-006 (notlar dahil), ADR-007
  (Karar 1–3, 7, 12, güvenlik düzeltmesi notu, I-14).
- Dış kaynak (genel bilgi, **doğrulanması gerekiyor**, Karar 16):
  - NuGet Package Content (flat container) kaynağı;
  - `.nuspec` `license`/`licenseUrl` öğeleri ve `licenses.nuget.org`;
  - `packages.lock.json` v1/v2 ve `project.assets.json` v3 alanları;
  - NuGet.Packaging `SignedPackageArchiveUtility.GetPackageContentHash`
    davranışı;
  - nuget.org depo imzalama;
  - NuGet sürüm normalleştirmesi;
  - purl `nuget` tipi;
  - OSV `NuGet` ekosistemi ve ad eşleşmesi;
  - `bitwarden/server` lock dosyaları.
  - NotebookLM veya Obsidian kaynağı kullanılmadı.

## İlgili REQ / AC

REQ-006: AC-G-1…10, AC-P20-1…18, AC-P21-1…16, AC-NV-1…4; kararlar
D-119…D-146.

## REQ-006 netleştirmeleri

1. **İmzalı paket içerik özeti (AC-P20-16, AC-P21-9, D-135, Riskler):**
   - REQ, `contentHash`'i ".nupkg dosyasının SHA-512'si" olarak varsayar.
     Depo imzalı paketlerde değer imzasız içerik özetidir.
   - "İndirilen baytların SHA-512'si eşleşmelidir" ifadesi "ham SHA-512
     **veya** NuGet içerik özeti eşleşmelidir" olarak okunur (Karar 10.2,
     10.3).
   - AC-P21-16'ya release kapısı eklenir: en az bir depo imzalı paket
     `match` vermelidir. Product-analyst AC metnini r2'de güncellemelidir.
2. **Birden çok farklı lock özeti:** aynı anahtar için farklı özetler
   indirmeden `mismatch` sayılır (npm "her kayıt" kuralı). REQ bu durumu
   tanımlamıyordu.
3. **`type="file"` saklama (AC-P21-5, D-133, D-139):** durum `no_license`
   olur, `license_source = 'none'` olur ve yeni
   `scan_dependencies.license_unclassified` kolonu kullanılır. Önbellekte üç
   yeni kolon vardır. `registry:nuget` yalnız ifadeli satırlarda bulunur.
4. **OSV gövde adı (AC-NV-1):** "ilk kaydın kaynak harf biçimi" yerine
   `.nuspec` `<id>` (zenginleştirme veya önbellek) önceliklidir; yoksa ilk
   kayıt kullanılır. Bu, D-140 yedeğinin koşulsuz uygulanmasıdır.
5. **AC-NV-2 test ifadesi:** bulgunun açılması toplu sorgu sırasına
   bağlıdır, `affected` adına bağlı değildir. Harf duyarsız eşleşme yalnız
   etkilenen/düzeltilmiş sürüm metnini seçer. Test buna göre yazılır.
6. **Sürüm anahtarında harf (AC-P20-3, AC-P21-1):** klasör içi
   tekilleştirme ve tüm anahtarlar `(asciiLower(id), asciiLower(sürüm))`
   kullanır. REQ AC-P20-3 yalnız id'yi küçültüyordu. NuGet ön sürüm etiketleri
   harf duyarsızdır; gösterilen biçim ilk karşılaşmanınkidir.
7. **Ön sürüm kalıbı (AC-P20-8):** REQ `[0-9A-Za-z.-]` karakter kümesini
   verir. Karar 4 bunu "noktayla ayrılmış, boş olmayan `[0-9A-Za-z-]+`
   tanımlayıcıları" olarak sıkılaştırır (`1.0.0-a..b` geçersizdir).
   Tek parçalı sürüm (`1`) REQ'e uygun olarak `NULL`'dır.
8. **AC-P21-2 uç nokta yolu:** arşiv yolu `{id}.{sürüm}.nupkg`'dir; REQ'in
   bu yazımı doğrudur. Kapsam bölümündeki ve görev tanımındaki
   `{id}.nupkg` kısaltmaları bu biçimle okunur.
9. **Hata ayrıntısı (AC-P20-3, -4, -9):** "dosya başına tek kayıt" kuralı
   her sorun türü için ayrı uygulanır (geçersiz kimlik, bilinmeyen tür,
   geçersiz girdi). Bir dosyada en fazla üç girdi kaydı olabilir. Kesin
   metinler Karar 7'dedir.
10. **`Choose`/`When` ve `Target` (AC-P20-5):** "tüm `ItemGroup`" ifadesi
    `Choose`/`When`/`Otherwise` içindekileri kapsar, `Target`
    içindekileri kapsamaz.
11. **`project.assets.json` keşfi (AC-P20-1):** `obj` adı harf duyarlıdır
    (REQ ile aynı). .NET 8 artifacts düzeni tanınmaz (Sonuçlar).
12. **`lock_integrity` NuGet değerleri:** zenginleştirme açıkken NuGet
    anahtarları varsayılan olarak `not_comparable` taşır (ADR-007'de "npm
    dışı → `NULL`" idi). `match` yalnız arşiv doğrulandığında yazılır.
13. **Contract sürümleri:** REQ-004 notice contract 1.3.0 → **1.4.0**
    (`registry:nuget`, `license_unclassified` metinleri, NuGet
    `no_candidate` nedeni, C-13'ün NuGet için kalkması, `lock_integrity`
    NuGet anlamı). REQ-005 vulnerability data contract 1.1.0 → **1.2.0**
    (`NuGet`, kanonik ad, kapsam). İki revizyon da küçük sürümdür, çünkü
    şemalar değişmez (D-144).
14. **`.gitattributes`:** NuGet golden fixture'larının SHA-256 kararlılığı
    için gereklidir. Yol sahipliği manifestte ayrıca belirtilmelidir.

## Açık noktalar

Yok. Kullanıcının daimi talimatı gereği tüm seçimler önerilen seçenekle karara
bağlanmıştır. "Doğrulanması gerekiyor" işaretli dış bilgilerin her biri için
tanımlı bir yedek veya AC-P21-16 sırasında yapılacak bir teyit adımı vardır
(Karar 16). İçerik özeti için bir release kapısı tanımlıdır.

## Onay (Approval)

- **Karar veren:** kullanıcı daimi talimatı (önerilen seçenek), 2026-10-11
  ("bana soru sorma önerilen seçeneklerle devam et"; REQ-006'da kayıtlı).
  Durum `Accepted`. Karar ana oturum aracılığıyla iletilmiştir; kullanıcının
  bu dosyayı gözden geçirip commit etmesi kaydı kesinleştirir.
- Bu karar implementation öncesi insan onayı gerektiren öğeler içerir
  (`.claude/rules/autonomy-gates.md`, REQ-006 Notlar):
  - **yeni dış hizmet entegrasyonu** (`api.nuget.org`; paket adları dışarı
    gider, günlük yeniden kontrol kullanıcı eylemi olmadan OSV'ye NuGet
    paketleri gönderir);
  - **veri modeli değişikliği** (göç `008`; down betiği toplu veri
    güncellemesi yapar);
  - güvenilmeyen XML ve ikili girdiyi işleyen yeni bir **güvenlik sınırı**.

  Gerekenler:
  - `docs/ownership/REQ-006.json` `status: approved`; manifest
    `api.nuget.org` erişimini açıkça kapsamalıdır (`devflow-manifest 006`
    kullanıcı tarafından çalıştırılır);
  - `008`'in yerel veritabanına uygulanması kullanıcı kararıdır;
  - release öncesi Security Red Team incelemesi zorunludur (XML, arşiv ve
    içerik özeti, SSRF, yan kanal).
  - Yeni runtime bağımlılığı olmadığı için paket kurulum onayı gerekmez.
- F4 (PR #4) `main`'e birleşmeden F5 birleştirilmez. Merge insan onayıdır.
