# ADR-005: Bağımlılık ayrıştırıcılarının TypeScript'e taşınması, iş parçacığı yalıtımı ve TOML kütüphanesi

- **ADR-ID:** ADR-005
- **Durum:** Accepted
- **Tarih:** 2026-10-10 (taslak ve karar)
- **İlgili:** REQ-003 / P-10 (AC-P10-1…17), AC-P13-4, AC-G-6; kararlar D-25…D-31,
  D-42, D-49. ADR-002 karar 5 bu ADR ile superseded. ADR-003 (purl/parmak izi)
  sürekliliği bu ADR'nin eşdeğerlik kurallarına bağlıdır.

## Bağlam

- Ayrıştırıcılar Python'da: `src/scanner/sandbox/parsers/{common,nodejs,python,scan}.py`.
  Worker bunları `runPythonParser` ile `spawn(PYTHON_BIN, ['-m', …])` olarak
  çalıştırıyor, son stdout satırını JSON olarak okuyor. Süre sınırı alt sürecin
  `SIGKILL`'i.
- `scan.py` çıktısı `SandboxScanResult` (`src/types/scan.ts`) ile aynı yapıda;
  `status` her zaman `completed`, `total_deps = len(dependencies)`, JSON
  `sort_keys=True`.
- `ScanWorker` ayrıştırıcıyı `deps.runParser: RunParserFn = (workDir, ecosystems,
  scanId) => Promise<SandboxScanResult>` ile enjekte ediyor; testler bunu taklit
  ediyor.
- `common.py` incelemesi:
  - `SKIP_DIRS` mutlak yolun tüm bileşenlerine uygulanıyor (D-28 b hatası).
  - `discover_manifests` `root.rglob(name)` + `is_file()` (sembolik bağlantıyı
    izler), ardından `sorted`. Python 3.12+ `rglob` Windows'ta **büyük/küçük harfe
    duyarsız** eşleşir.
  - `scan_file_record` dosyayı `read_bytes` ile okuyup SHA-256 hex ve bayt sayısı
    üretiyor; `package.json` ve `requirements*.txt` için `try` dışında (D-28 a).
  - `relative_path` `resolve()` kullanıyor; kök dışını gösteren bağlantıda
    `ValueError` ile tüm ayrıştırma çöküyor (L-4).
  - `parse_error.error = str(exc)`: işletim sistemi hatalarında mutlak yol
    içeriyor (D-28 c).
  - **Dosya boyutu sınırı yok**; tek sınır alt süreç süre sınırı.
  - `unique_dependencies` anahtarı `(ecosystem, str(name).lower(), str(version),
    str(manifest_path))`; `version = None` için `str(None) == "None"`.
  - purl: `quote(name, safe="@/")` / `quote(version, safe="")` (npm);
    `name.replace("_","-").lower()` + `quote(…, safe="")` (PyPI).
- Python'un TOML'u `tomllib` (TOML 1.0, standart kütüphane). Node'da yerleşik TOML
  yok; D-29 tek bir npm paketi öngörüyor.
- Derleme `module: CommonJS`; testler Vitest ile kaynaktan (`.ts`) çalışıyor.

## Karar

### 1. Modül yapısı (D-25, AC-P10-1)

`src/scanner/parsers/` (backend-engineer):

| Dosya | İçerik |
| --- | --- |
| `index.ts` | `parseManifests(rootDir, ecosystems, scanId): SandboxScanResult` — saf, **senkron** giriş (yalnız `fs` okur). `scan.py`'nin karşılığı: ekosistemleri verilen sırayla işler, desteklenmeyen ekosistem için `{ ecosystem, file: '', error }` kaydı, `status: 'completed'`, `total_deps = dependencies.length`. |
| `common.ts` | `SKIP_DIRS`, dosya ağacı yürüyüşü (Karar 6), dosya kaydı, `parseError`, `uniqueDependencies`, `npmPurl`, `pypiPurl`, `manifestDir`, Python uyum yardımcıları (Karar 3). |
| `nodejs.ts`, `python.ts` | `nodejs.py` / `python.py`'nin satır satır karşılıkları; aynı fonksiyon adları (camelCase). |
| `toml.ts` | TOML kütüphanesinin tek içe aktarım noktası (Karar 8). |
| `thread.ts` | İş parçacığı girişi: `workerData` alır, `parseManifests`'i çağırır, sonucu `parentPort.postMessage` ile döner. |
| `threadParser.ts` | Ana iş parçacığı tarafı: `createThreadParser(options): RunParserFn` (Karar 5). |

- **Sınır kuralı:** `src/scanner/parsers/` yalnız `node:fs`, `node:path`,
  `node:crypto`, `node:worker_threads`, TOML kütüphanesi ve `import type` içe
  aktarır (`SandboxScanResult` vb.). `dotenv`, `lib/db`, `pg` veya `src/`'nin
  başka bir çalışma zamanı modülü içe aktarılmaz. Böylece iş parçacığı sırlara ve
  veritabanına dokunan kodu yüklemez ve test için tek başına derlenebilir.
  qa-automation bunu statik bir testle (içe aktarım taraması) korur.

> **REQ-004 / ADR-006 notu (2026-10-10).** Sınır kuralı kısmen superseded:
> yalnız ana iş parçacığı tarafındaki `threadParser.ts`, kaynak modu
> bootstrap'ının taşındığı ortak `src/lib/threadBootstrap.ts`'i (yalnız
> `node:path` içe aktarır) içe aktarabilir. İş parçacığında yüklenen
> `thread.ts` ve ayrıştırıcı modülleri için kural aynen geçerlidir. Karar 5
> davranışı değişmez. Ayrıntı: ADR-006 Karar 1 ve 16.
- **Çıktı tipi:** `SandboxScanResult` değişmez. `RunParserFn`'e isteğe bağlı
  dördüncü parametre `signal?: AbortSignal` eklenir (ADR-004 Karar 7); mevcut üç
  parametreli test taklitleri tip uyumlu kalır. `ScanWorker` varsayılan
  `runParser`'ı `createThreadParser()` olur; `runPythonParser`, `PYTHON_BIN`,
  `parserTimeouts` haritası ve `sanitizedChildEnv({ PYTHONPATH })` çağrısı
  kaldırılır.
- `src/types/scan.ts` içindeki "printed to stdout by entrypoint.sh" yorumu
  güncellenir; tip alanları değişmez.

### 2. Eşdeğerlik kuralları (D-26, D-27, AC-P10-3…9)

- **Golden karşılaştırma:** TS çıktısı `JSON.parse(JSON.stringify(x))` ile
  normalize edilir ve golden JSON'la derin eşitlikle karşılaştırılır.
  - `dependencies` ve `scan_files`: her öğe anahtarları sıralanmış JSON metnine
    göre sıralanır, sonra eşitlik.
  - `parse_errors`: her kayıttan `error` çıkarılır, `(ecosystem, file)` çiftleri
    sıralanıp karşılaştırılır; her `error` boş olmayan metin olmalıdır.
  - `scan_id`, `status`, `total_deps` birebir.
- **Anahtar varlığı birebir:** `declared_range` her bağımlılıkta **vardır** (`null`
  olabilir); `licenses` yalnız boş değilse vardır ve `sorted(set(…))` gibi
  tekilleştirilip kod noktası sırasıyla sıralanır; `vulnerabilities` anahtarı
  üretilmez. `undefined` değerli anahtar bırakılmaz.
- **purl birebir (AC-P10-6):** `encodeURIComponent` **kullanılmaz**. `pyQuote(s,
  safe)` yazılır: metin UTF-8 baytlarına çevrilir; `A–Z a–z 0–9 _ . - ~` ve
  `safe` içindeki karakterler olduğu gibi, diğer her bayt büyük harfli `%XX`
  olur. Böylece `! ' ( ) *` kodlanır (Python gibi), `+` sürümde `%2B` olur.
  Eşleşmeyen vekil (lone surrogate) içeren ad/sürüm Python'da `UnicodeEncodeError`
  verdiği için TS'te de hata fırlatılır (o dosya için `parse_errors`).
- **PyPI adı:** yalnız `_ → -` ve küçük harf (D-27). Küçük harf dönüşümü ASCII
  dışı adlarda Python `str.lower` ile birebir garanti edilmez; golden kapsamı ASCII.
- **Tekilleştirme (AC-P10-7):** anahtar `ecosystem | pyStr(name).toLowerCase() |
  pyStr(version) | pyStr(manifest_path)`; `pyStr(null) === "None"`. İlk gelen
  kazanır; tekilleştirme Python'daki gibi **ekosistem ayrıştırıcısının sonunda**
  yapılır.
- **İşlem sırası:** Python algoritmasının sırası birebir korunur (karşılaştırma
  sıradan bağımsız olsa da ilk-gelen-kazanır kuralı sıraya bağlıdır): ekosistemler
  worker'ın verdiği sırayla; npm'de her `package.json` için `package-lock.json`
  (önce v2/v3 `packages`, sonra v1 `dependencies` ağacı), sonra `yarn.lock`, sonra
  `declared_range` doldurma, kilit yoksa `package.json` bölümleri
  (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`);
  Python'da `requirements.txt`, `requirements-dev.txt`, `requirements-test.txt`,
  `pyproject.toml`, `poetry.lock`.
- **`try` kapsamları birebir:** her dosya grubunun hata kapsamı Python'daki gibidir.
  Özellikle kilit dosyası (`package-lock.json`/`yarn.lock`) okuma/ayrıştırma hatası
  **`package.json` yolunu** taşıyan tek bir `parse_errors` kaydı üretir ve o
  `package.json` için hiçbir bağımlılık eklenmez (kilit dosyasının `scan_files`
  kaydı, hata kilit ayrıştırmasındaysa eklenmiş kalır). Golden `file` alanını
  karşılaştırdığı için bu kritik.
- **Yollar (AC-P10-9):** `file_path`/`manifest_path` `/` ayırıcılı, köke göre
  göreli; kökteki manifest için `manifest_path = "."`.
- **Tip olarak geçersiz girdiler** (ör. sözlük beklenen yerde dizi/metin, metin
  olmayan sürüm): birebir eşitlik aranmaz (REQ-003 riskler). Kural: Python'un
  `AttributeError`/`TypeError` vereceği her yerde TS de hata fırlatır ve sonuç o
  dosyanın `parse_errors` kaydıdır; Python'un metni karakter karakter dolaşacağı
  yerlerde (ör. `project.dependencies` metin) TS hata fırlatır. Ayrıştırıcı hiçbir
  girdide iş parçacığını çökertmez.

### 3. Python davranışının taklidi (uyum yardımcıları)

`common.ts`'te yalnız gereken kadar, testli yardımcılar:

| Python | TS karşılığı | Neden |
| --- | --- | --- |
| `str.strip()` / `rstrip()` | `pyStrip`/`pyRstrip`: Python `str.isspace` kümesi (ASCII boşluklar, `\x1c-\x1f`, `\x85`, `\xa0`, Unicode Z*) | `trim()` `﻿`'i siler, `\x1c-\x1f`'i silmez |
| `str.splitlines()` | `pySplitLines`: `\r\n`, `\n`, `\r`, `\v`, `\f`, `\x1c`, `\x1d`, `\x1e`, `\x85`, ` `, ` `; sondaki boş öğe üretilmez | `split('\n')` farklı |
| Doğruluk (`if x`, `x or y`) | `pyTruthy`: `null/undefined`, `false`, `0`, `''`, boş dizi, boş nesne yanlış | JS'te `[]`/`{}` doğru |
| `str(x)` | `pyStr`: metin aynen; `null → "None"`, `true → "True"`; diğer tipler yalnız tekilleştirme anahtarında | `String(null) === "null"` |
| `dict.get(k, d)` / `.items()` | `pyGet`/`pyItems`: nesne değilse (dizi, `null`, metin) hata fırlatır | Python `AttributeError` |
| `isinstance(x, dict)` | düz nesne (dizi ve `null` değil) | |
| `re` `\s` | açık karakter sınıfı (`[ \t\n\r\f\v\x1c-\x1f\x85\xa0…]`) veya girdide önceden `pyStrip`; düzenli ifadeler `u` bayraklı | JS `\s` kümesi farklı |
| `read_text(encoding="utf-8", errors="replace")` (requirements, yarn.lock) | `TextDecoder('utf-8', { fatal: false, ignoreBOM: true })` + evrensel satır sonu (`\r\n`/`\r` → `\n`) | BOM korunmalı (Python korur) |
| `read_text(encoding="utf-8")`, `json.load` (JSON, TOML) | `TextDecoder('utf-8', { fatal: true, ignoreBOM: true })`; geçersiz UTF-8 → dosya hatası | Python katı çözer |
| `tomllib.loads` BOM'lu metin | BOM ile başlayan TOML metni açıkça hata sayılır | Kütüphaneden bağımsız birebirlik |

- **BOM davranışı birebir korunur** (bilinen Python kusuru dahil): BOM'lu
  `requirements.txt`'nin ilk satırı Python'da eşleşmez ve atlanır; BOM'lu
  `package.json` JSON hatasıdır. qa-automation, Python'un bu davranışlarını
  kanıtlamak için BOM'lu `requirements.txt`, `package.json` ve `pyproject.toml`
  fixture'larını golden kümesine ekler (golden'ı ana oturum üretir). BOM'un
  doğru işlenmesi sonraki fazın kararıdır.
- **JSON ayrıntıları:** Python `json` `NaN`/`Infinity` kabul eder, `JSON.parse`
  etmez; yinelenen anahtarda ikisi de sonuncuyu alır. Tam sayı biçimli nesne
  anahtarları (`"123"`) JS'te sırayı değiştirir; yalnız aynı manifestteki
  ilk-gelen-kazanır kararını etkileyebilir. Bu iki fark kabul edilen sınırdır.
> **REQ-003 güvenlik düzeltmesi (2026-10-10).** Yardımcıların uygulama biçimi
> netleşir (güvenlik raporu M-1, commit `f32b00c`):
>
> - `pyStrip`/`pyRstrip` **düzenli ifade kullanmaz**; Python `str.isspace`
>   kümesini karakter karakter tarayan doğrusal (O(n)) döngülerdir. Önceki
>   regex biçimi uzun boşluk dizilerinde karesel zamanlıydı.
> - `REQUIREMENT_RE` düzenli ifadesi yerine doğrusal `matchRequirementLine`
>   kullanılır (aynı gruplar: ad, isteğe bağlı extras, kalan belirteç). Eski
>   regex `\n` içeren metinde kübik zamanlıydı.
> - Eşdeğerlik, eski regex uygulamasına karşı 800 bin rastgele girdi ve tüm BMP
>   karakterleriyle doğrulanmıştır; golden testleri yeşildir.
> - Kural: ayrıştırıcıda güvenilmeyen girdiye uygulanan yeni düzenli ifadeler
>   iç içe/örtüşen niceleyici içermez; şüpheli durumda doğrusal tarama yazılır.

- `pyproject.toml`'daki tablo biçimli sürüm (`{ version = "^1.2" }`), `python`
  girdisinin yalnız `tool.poetry.dependencies` içinde atlanması, bare sürüm
  (`1.2.3` → kesin), `poetry.lock` `category = "dev"` → `dev`, aksi `transitive`
  birebir korunur.

### 4. Korunacak ayrıştırma davranışları (özet)

- **`requirements*.txt`:** satır satır (`pySplitLines`); `#`'tan sonrası atılır
  (URL parçası dahil — Python davranışı); `-` ile başlayan satırlar atlanır (bu
  yüzden `-r`/`-c` **izlenmez**, `-e` editable ve `--hash` satırları atlanır);
  `git+`, `http://`, `https://`, `.` ile başlayanlar atlanır; `;` ortam işaretçisi
  atılır; `REQUIREMENT_RE = ^\s*([A-Za-z0-9_.-]+)\s*(\[.*?\])?\s*(.*)$` (extras
  addan düşer); kesin sürüm yalnız tek `==X`/`===X` ifadesi
  (`EXACT_PIN_RE = ^\s*={2,3}\s*([^,;\s*]+)\s*$`), aksi `version = null` ve
  `declared_range` belirteç metnidir. `pkg @ https://…` → `declared_range = "@ https://…"`.
  Aynı satırdaki `--hash` belirteçe dahil olur (kesin sayılmaz) — birebir korunur.
  Satır devamı (`\`) desteklenmez. `requirements.txt` → `direct`,
  `-dev`/`-test` → `dev`.
- **`yarn.lock` (v1):** `rstrip` sonrası boş veya `#` satırı atlanır; boşlukla
  başlamayan satır yeni girdi başlığıdır (`rstrip(":")`, tırnak dışı virgülle
  bölme, tırnak kırpma, scoped ad için `^(@[^/]+/[^@]+)`, aksi `^([^@]+)`);
  girdi içinde `version ` satırı sürümü verir; kapsam `package.json`'daki bölüme
  göre, yoksa `transitive`. Sekmeyle girintili satır başlık sayılır (Python gibi).
- **`package-lock.json`:** `packages` haritasında boş anahtar (kök) atlanır; ad
  `name` alanı veya son `node_modules/` sonrası (scoped iki parça); kapsam önce
  `package.json` bölümü (iç içe kopyalar dahil — Python davranışı), yoksa
  `dev`/`peer`/`optional` bayrakları, yoksa `transitive`; `license` metin veya
  dizi. v1 `dependencies` ağacında kapsam miras alınır.
- **Kesin sürüm (npm):** `^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`;
  kesin olmayan kilit değeri (`file:`, git URL, etiket) `version = null`,
  `declared_range = değer`. Kilitliyken `declared_range` `package.json`'dan
  doldurulur.

### 5. İş parçacığı yalıtımı (D-30, AC-P10-14)

- **Tarama başına bir `Worker`** (havuz yok): `new Worker(threadScript, {
  workerData: { rootDir, ecosystems, scanId }, resourceLimits, env: {}, argv: [],
  execArgv: [] })`. İş bitince iş parçacığı kendiliğinden çıkar; hata veya iptalde
  `terminate()` edilir ve sözü **beklenir** (Windows'ta açık dosya tutamaçları
  geçici klasör silmeyi bozar).
- **`resourceLimits`:** `maxOldGenerationSizeMb: 512`, `maxYoungGenerationSizeMb:
  64`, `stackSizeMb: 4`. Tek kullanıcılı geliştirici makinesi için 512 MiB,
  dosya başı 32 MiB sınırıyla (Karar 7) en büyük gerçekçi `package-lock.json`'ın
  nesne grafiğine yeter. `WORKER_MAX_CONCURRENT=4` ile en kötü durum ~2 GiB
  yığın; değerler `runner.config.ts`'te sabittir (yeni ortam değişkeni yok).
  `Buffer` (V8 dışı bellek) bu sınıra girmez; dosya boyutu sınırı bunu kapatır.
- **`env: {}`:** iş parçacığı `process.env` kopyası almaz (güvenilmeyen girdiyi
  işleyen kod `DATABASE_URL`/`ENCRYPTION_KEY`'i görmez).
- **Süre sınırı:** iş parçacığının kendi zamanlayıcısı yoktur; iş düzeyindeki
  `AbortSignal` (ADR-004 Karar 7, `scan.timeout_minutes`, varsayılan 60 dk) gelince
  `terminate()`. Kapanış iptali aynı yoldan gelir.
- **Sonuç ve hata eşlemesi** (`threadParser.ts`):

  | Olay | Sonuç |
  | --- | --- |
  | `message` `{ ok: true, result }` | Asgari yapı doğrulaması (dizi alanları, `scan_id` eşitliği) → çözülür |
  | `message` `{ ok: false }` (beklenmeyen iç hata) | `ParserFailedError` → kalıcı |
  | `error`, `code === 'ERR_WORKER_OUT_OF_MEMORY'` | `ParserMemoryLimitError` → kalıcı ("ayrıştırıcı bellek sınırını aştı (512 MB)") |
  | diğer `error` veya mesajsız sıfır dışı `exit` | `ParserCrashedError` → kalıcı |
  | iptal (`timeout`/`shutdown`) | iptal nedeni yeniden fırlatılır; sınıflandırma ADR-004 Karar 8 |

  Hata nesnesinin mesajı `error_message`'a yazılmadan önce L-5 arındırmasından
  geçer (ADR-002 Ek).
- **İş parçacığı betiği yolu enjekte edilir:** üretimde
  `path.join(__dirname, 'thread.js')` (`dist/scanner/parsers/thread.js`).
  Vitest kaynaktan çalıştığı için:
  - ayrıştırma mantığı ve golden testleri `parseManifests`'i **doğrudan** çağırır;
  - `threadParser` testleri (süre sınırı, bellek sınırı, çökme, normal sonuç,
    `/health 200` ve sonraki taramanın işlenmesi) `tests/` altındaki düz CommonJS
    `.js` test iş parçacığı betikleriyle yapılır;
  - gerçek `thread.ts`'in uçtan uca denenmesi için qa-automation, mevcut
    `typescript` paketiyle (`ts.transpileModule`) `src/scanner/parsers/*.ts`'i bir
    Vitest `globalSetup`'ında geçici klasöre derleyebilir (sınır kuralı bunu tek
    klasörlük iş yapar).

### 6. Dosya ağacı yürüyüşü, symlink/junction politikası (D-28 a, b; AC-P10-10, AC-P10-11)

- Kök, ADR-002 karar 4 ile doğrulanmış kanonik yoldur (yerel) veya clone hedefidir
  (uzak; clone `core.symlinks=false` ile bağlantı üretmez).
- Yürüyüş **tek sefer** yapılır (ekosistemler arasında paylaşılır), yığın tabanlı
  (özyinelemesiz), `fs.readdirSync(dir, { withFileTypes: true })` ile; her girdi
  için `Dirent` türüne güvenilmez, `fs.lstatSync` kullanılır.
- **Bağlantı izlenmez:** `lstat().isSymbolicLink()` olan her girdi (Windows'ta
  Node/libuv dizin junction'larını ve sembolik bağlantıları bu şekilde bildirir)
  atlanır. Dizin bağlantılarına inilmez; dosya bağlantıları okunmaz ve
  hash'lenmez. Kendine işaret eden junction döngüsü bu yüzden sonlanır.
- **Kayıt:** atlanan **dizin** bağlantısı ve adı desteklenen bir manifest adı olan
  **dosya** bağlantısı için bir `parse_errors` kaydı açılır:
  `{ ecosystem, file: <köke göre göreli yol, '/' ayırıcılı>, error: 'Sembolik bağlantı veya junction izlenmedi.' }`.
  `ecosystem`, dosya bağlantısında ilgili ekosistem (`nodejs`/`python`), dizin
  bağlantısında `filesystem`'dır. İlgisiz dosya bağlantıları sessizce atlanır
  (gürültü ve `error_message` uzunluğu). Tarama `completed` olur.
- **İkinci savunma:** her dosya okunmadan önce `fs.realpathSync.native(dosya)`
  kökün kanonik yoluyla ADR-002 karar 4'teki önek+ayraç kuralıyla (Windows'ta
  büyük/küçük harf duyarsız) karşılaştırılır; kök dışıysa bağlantı gibi
  işlenir. Bu, `isSymbolicLink()`'in bildirmediği yeniden ayrıştırma noktalarına
  karşıdır.
- **Atlanan klasörler:** `SKIP_DIRS` yalnız köke göre göreli **dizin** adlarına,
  büyük/küçük harfe duyarlı uygulanır ve o dizine hiç inilmez (D-28 b; Python her
  şeyi dolaşıp sonra süzüyordu — sonuç aynı, maliyet düşük).
- **Dosya adı eşleşmesi büyük/küçük harfe duyarlıdır** (`package.json`,
  `requirements.txt` vb. tam ad). Kilit dosyasının varlığı yürüyüşün ürettiği
  dizinden okunur; `fs.existsSync` gibi bağlantı izleyen kontroller
  **kullanılmaz** (bağlantı olan `package-lock.json` yok sayılır ve `package.json`
  tek başına ayrıştırılır).
- **Sıralama:** keşfedilen manifestler göreli yol metnine göre sıralanır. Çıktı
  eşitliğine etkisi yoktur (tekilleştirme anahtarı `manifest_path` içerir).
- Kalan risk: aynı birim üzerindeki **sabit bağlantı** (hard link) ayırt edilemez;
  kök dışı bir dosyaya sabit bağlantı oluşturmak o dizine yazma yetkisi gerektirir
  ve clone'da oluşmaz. Kabul edildi.

> **REQ-003 güvenlik düzeltmesi (2026-10-10).** Bu kararın bağlantı kayıt ve
> ikinci savunma kuralları şöyle değişir (güvenlik raporu L-2, commit `f32b00c`):
>
> - **Bağlantı hedefi hiçbir koşulda çözülmez** (`stat`, `statSync`, `realpath`,
>   `readlink` bağlantı girdisinde çağrılmaz). Gerekçe: yerel taramada hedefi UNC
>   yolu (`\\sunucu\paylaşım`) olan bir bağlantıyı çözmek Windows'ta dışarıya SMB
>   bağlantısı ve NTLM kimlik doğrulaması tetikleyebilir.
> - Karar yalnız **`lstat` sonucu + girdi adıyla** verilir. Windows'ta `lstat`
>   junction'ı dosya/dizin sembolik bağlantısından ayırmaz (ölçüldü); bu yüzden
>   bağlantının "dizin mi dosya mı" olduğuna bakılmaz:
>   - adı desteklenen bir manifest adıysa → ilgili ekosistem (`nodejs`/`python`)
>     için bir `parse_errors` kaydı;
>   - adı `SKIP_DIRS` içindeyse → kayıtsız atlanır;
>   - diğer **her** bağlantı → bir `filesystem` kaydı.
>   Önceki "ilgisiz dosya bağlantıları sessizce atlanır" ve "dizin bağlantısında
>   `filesystem`" ayrımı **geçersizdir**.
> - `realpath.native` ikinci savunması yalnız `lstat` sonucu **düz dosya** olan
>   girdilerde çalışır (bağlantı olmayan yeniden ayrıştırma noktalarına karşı).
>   Bağlantı olarak bildirilen girdiye hiç uygulanmaz.

### 7. Dosya okuma, boyut sınırı ve hata metinleri (D-28 a, c; AC-P10-12, AC-P10-13)

- Her dosya **bir kez** okunur (`readFileSync`); aynı tampondan hem SHA-256/
  `size_bytes` hem metin çözümü yapılır (Python iki kez okuyordu; hash ile içerik
  arasındaki TOCTOU kapanır).
- **Dosya başı boyut sınırı: 32 MiB** (`lstat().size` okumadan önce). Aşan dosya
  okunmaz, `scan_files` kaydı açılmaz, `parse_errors`'a "dosya boyut sınırını
  aşıyor (32 MiB)" yazılır ve okuma hatası gibi işlenir (kilit dosyasında
  `package.json` kapsamı, Karar 2). Python'da sınır yoktu (Bağlam); sınır D-30'un
  bellek sınırının dosya bazlı hata yalıtımıyla (AC-P10-12) birlikte çalışmasını
  sağlar: tek bir dev dosya taramayı kalıcı `failed` yapmak yerine yalnız kendisini
  etkiler. `73db78b` golden çıktısını değiştirmez.
- **Dosya kaydı hatası** (`EACCES`, `EBUSY` vb.) yalnız o dosyanın `parse_errors`
  kaydıdır; tarama sürer (D-28 a). `package.json`/`requirements*.txt` kaydı artık
  `try` içindedir.
- **Hata metinleri mutlak yol içermez (D-28 c):** `fs` hatalarının `message`'ı
  **kullanılmaz** (yol içerir); sabit metin + `code` yazılır
  (`Dosya okunamadı (EACCES).`). JSON hatası: `JSON.parse` mesajı (yol içermez,
  içerikten kısa parça içerebilir). TOML hatası: kütüphane mesajının ilk satırı,
  en fazla 200 karakter. Son güvence olarak her `error` metni kök yolu, `%TEMP%`
  ve kullanıcı profil yolu için ADR-002 Ek'teki yer tutucu değişiminden geçer.

> **REQ-003 güvenlik düzeltmesi (2026-10-10).** Maskelemenin yeri netleşir:
> iş parçacığı `env: {}` ile çalıştığı için `%TEMP%` ve kullanıcı profil yolunu
> güvenilir biçimde bilemez. İş parçacığı içinde yalnız **tarama kökü** yer
> tutucuyla değiştirilir; `%TEMP%`, çalışma klasörü, `SCAN_ROOTS` ve profil yolu
> **ana iş parçacığında** `sanitizeErrorText` (ADR-002 Ek E3) ile maskelenir.

### 8. TOML kütüphanesi (D-29, AC-P10-15)

| Kriter | `smol-toml` | `@iarna/toml` | `toml` |
| --- | --- | --- | --- |
| Lisans | BSD-3-Clause | ISC | MIT |
| Runtime bağımlılığı | yok | yok | yok |
| TOML sürümü | 1.0.0 (toml-test uyum paketini geçtiğini belirtir) | 1.0.0-rc.1 | tarihsel olarak 0.4 hedefli |
| Bakım | sürüyor (son yayınlar 2026-08, 2026-09, 2026-10) | 2.2.5; son yayın 2023, bakımsız | 5.0.0; TOML 1.0 tam uyumu kanıtlanmadı |
| Güvenlik geçmişi | derin iç içe yapıyla DoS bildirimi geçmişte düzeltildi (1.3.1); seçilen sürüm sonrası | bilinen düzeltme gelmez (bakımsız) | — |

- **Seçim: `smol-toml`, sürüm `1.9.0`, exact pin** (`"smol-toml": "1.9.0"`,
  `package-lock.json`'da sabit). Ana oturumun registry doğrulaması (2026-10-10):
  `1.9.1` 2026-10-09'da yayımlandı (2 haftalık bekleme kuralını sağlamaz,
  kullanılmaz); `1.9.0` 2026-09-22 (≥ 2 hafta); lisans BSD-3-Clause; runtime
  bağımlılığı yok. Sürüm yükseltmesi ayrı bir karar ve golden testlerinin yeşil
  kalmasıyla yapılır.
- **CommonJS uyumu:** proje CommonJS derlenir. Ana oturum kurulumdan sonra
  `require('smol-toml')`'un çalıştığını doğrular. Paket yalnız ESM ise Node ≥ 22.12
  `require(esm)` desteği (D-46 Node ≥ 22) yedek yoldur; ikisi de olmazsa
  `toml.ts` içinde dinamik `import()` kullanılır (iş parçacığı girişi asenkron
  başlatılabilir). Bu yalnız `toml.ts`'i etkiler.
- **Kullanım:** yalnız `parse(text)`; dönen değerler yalnız metin olarak kullanılır
  (`pyStr`). Tarih/saat ve büyük tam sayı değerleri (kütüphane `Date`/`bigint`
  döndürebilir) bağımlılık alanında tip olarak geçersiz sayılır (Karar 2).
- **Güvenlik:** kütüphane güvenilmeyen girdiyi iş parçacığında, bellek ve yığın
  sınırıyla işler; derin iç içe yapıdan doğan `RangeError` o dosyanın
  `parse_errors` kaydı olur. Security Red Team incelemesine dahildir (REQ-003
  riskler).
- **Spesifikasyon farkı:** `tomllib` (Python 3.14) TOML 1.0'dır. Kütüphanenin
  ileride TOML 1.1 sözdizimini kabul etmesi, Python'un reddettiği girdiyi
  kabul etmek anlamına gelebilir; golden fixture'lar 1.0 sözdizimiyle yazılır.
  Doğrulanması gerekiyor (kütüphane belgesi).

### 9. Python'un kaldırılması (D-31, AC-P10-16, AC-P10-17)

- Sıra: (1) ana oturum golden'ları Python ile üretir; (2) TS ayrıştırıcı + golden
  testleri yeşil; (3) **ayrı commit'te** `src/scanner/sandbox/parsers/*.py`,
  `__init__.py`, `__pycache__`, `runPythonParser`, `PYTHON_BIN` kaldırılır.
- `tests/unit/pythonParsers.test.ts` TS ayrıştırıcıya taşınır; P-05/P-06/P-07
  testleri yeşil kalır.
- `__pycache__` git'te izleniyorsa silinir; `.gitignore`'a eklenmesi gerekmez
  (Python kalmıyor).

### 10. Ek: D-49 (D-24) bağımlılık kararı

REQ-003 D-49'u netleştirir: tercih (1) uygulanamaz — `exceljs 4.4.0` registry'deki
en son sürümdür ve `uuid ^8.3.0` ister (ana oturum doğrulaması, 2026-10-10).
**Seçilen yol (2):** `package.json` `overrides: { "uuid": "11.1.1" }` (11.1.1,
2026-04-29, CommonJS `require` destekli). Gerekçe: `exceljs` yalnız
`require('uuid').v4` kullanır; `v4` `uuid` 11'de aynı imzayla vardır. Kanıt
AC-T-5'teki `.xlsx` geri okuma testi ve `npm audit --omit=dev`. Kurulum ana
oturumun işidir. Bu, NFR'deki "yeni runtime bağımlılığı yalnız TOML" kuralının
D-24 istisnasıdır (yeni paket değil, geçişli sürüm değişikliği).

## Gerekçe

Bire bir taşıma, eşdeğerliğin golden ile ölçülebilmesini ve purl/parmak izi
sürekliliğini (ADR-003) korur; Python'a özgü dönüşümlerin açık yardımcılarla
taklidi, farkların sessizce sızmasını önler. Tek dil ve tek test aracı bakım
yükünü azaltır, Python kurulum karmaşasını (`PYTHON_BIN`) ortadan kaldırır.
`worker_threads`, alt sürecin verdiği süre ve bellek yalıtımını tek süreç içinde
sağlar ve API'yi yanıt verebilir tutar; `terminate()` iş parçacığını işbirliği
gerektirmeden sonlandırır. Bağlantı izlememe ve kök içi doğrulama, Docker'sız
düzende dosya sistemi sınırını ayrıştırıcı seviyesinde de uygular (L-4).

## Değerlendirilen alternatifler

- **Ayrıştırıcıyı ana iş parçacığında çalıştırmak:** büyük/kötü niyetli girdi API'yi
  bloklar, süre sınırı uygulanamaz (senkron döngü kesilemez). Reddedildi.
- **Alt süreç (`child_process.fork`) ile Node ayrıştırıcı:** yalıtım güçlü ama
  süreç başlatma, IPC ve Windows süreç ağacı temizliği maliyeti; D-30 iş
  parçacığını seçti. Reddedildi.
- **İş parçacığı havuzu (`piscina` vb.):** yeni bağımlılık; tarama başına bir iş
  parçacığı yeterli. Reddedildi.
- **Asenkron `fs` ile iş parçacığı içi yürüyüş:** iş parçacığı zaten ana döngüyü
  bloklamaz; senkron kod Python'la satır satır eşlemeyi kolaylaştırır. Reddedildi.
- **`encodeURIComponent` ile purl:** `! ' ( ) *` farkı parmak izini bozar.
  Reddedildi.
- **Dosya boyutu sınırı koymamak (Python'la birebir):** dev dosya bellek sınırını
  aşar ve tüm tarama kalıcı `failed` olur; AC-P10-12'nin amacına aykırı.
  Reddedildi.
- **Windows'ta büyük/küçük harfe duyarsız dosya adı eşleşmesi (Python 3.12+
  `rglob` davranışı):** platforma göre değişen sonuç; Python'da bu yol ayrıca
  `manifest_dir`'i ters bölü ayırıcıya düşürüyordu (AC-P10-9 ihlali). Reddedildi.
- **Elle TOML ayrıştırıcı:** D-29 ile reddedildi. **`@iarna/toml`:** bakımsız,
  TOML 1.0 öncesi. **`toml`:** TOML 1.0 tam uyumu kanıtsız. Reddedildi.
- **BOM'u düzeltmek (ilk satırı kurtarmak):** golden ile ölçülen birebirliği bozar;
  sonraki faz. Reddedildi.

## Sonuçlar / Uygulama etkisi

- **Güvenlik:** kök dışı okuma ve bağlantı döngüsü kapanır (L-4); hata
  metinlerinden mutlak yol çıkar; iş parçacığı sır içeren ortamı görmez; yeni
  tedarik zinciri yüzeyi tek paket (`smol-toml@1.9.0`) ve exact pin'dir.
- **Uyumluluk:** `73db78b` golden çıktısı değişmez. Bilinçli sapmalar (D-28 a/b/c
  ve aşağıdaki netleştirmeler) yalnız bağlantı, üst klasör adı, büyük/küçük harf
  farklı dosya adı, 32 MiB üstü dosya ve hata metni durumlarında görülür.
- **Test (qa-automation):** AC-P10-3…14 golden ve davranış testleri; ek olarak
  BOM'lu fixture'lar (golden'a), `pyQuote` tablo testi (`! ' ( ) * + @ / ~` ve
  ASCII dışı), `pySplitLines`/`pyStrip` tablo testleri, `str(None)` çakışması
  (`foo==None` ile sürümsüz `foo` aynı klasörde tek kayıt), kilit dosyası hatasında
  `file = package.json yolu`, 32 MiB sınırı (seyrek dosya ile), bağlantı olan
  `package-lock.json`, sınır kuralı için içe aktarım taraması.
- **Implementer'lar için kritik uyarılar:**
  1. `encodeURIComponent`, `trim`, `split('\n')`, JS doğruluk kuralı ve
     `String(null)` ayrıştırıcıda kullanılmaz; Karar 3 yardımcıları kullanılır.
  2. `TextDecoder` varsayılanı BOM'u **siler**; `ignoreBOM: true` zorunludur.
  3. `declared_range: null` açıkça yazılır; `undefined` bırakılmaz.
  4. Kilit dosyası hata kapsamı `package.json` yolunu taşır.
  5. `fs` hata `message`'ı hiçbir yere yazılmaz.
  6. İş parçacığı `terminate()` sözü geçici klasör silinmeden önce beklenir.
  7. `parsers/` klasörü veritabanı/`dotenv` içe aktarmaz.
  8. `String.prototype.isWellFormed` ES2022 hedefinde tipli değildir; eşleşmeyen
     vekil denetimi düzenli ifadeyle yapılır.
- **Ana oturum:** `npm install --save-exact smol-toml@1.9.0`; `overrides.uuid =
  11.1.1`; golden üretimi (BOM fixture'ları dahil); CJS doğrulaması.
- **Handoff:** `docs/handoffs/REQ-003.md` golden sayısını (AC-P10-3) ve
  sapmaları kaydetmelidir.

## Kanıt (Evidence)

- Repo incelemesi: `src/scanner/sandbox/parsers/common.py`, `nodejs.py`,
  `python.py`, `scan.py`; `src/scanner/worker.ts` (`RunParserFn`,
  `runPythonParser`, `parserTimeouts`); `src/types/scan.ts`; `tsconfig.json`;
  `package.json`.
- Ana oturumun npm registry doğrulaması (2026-10-10): `smol-toml` 1.9.1
  (2026-10-09), 1.9.0 (2026-09-22), 1.8.0 (2026-08-11), BSD-3-Clause, bağımlılık
  yok; `@iarna/toml` 2.2.5 (son yayın 2023); `toml` 5.0.0 (MIT); `exceljs` 4.4.0
  (`uuid ^8.3.0`, yalnız `v4`); `uuid` 11.1.1 (2026-04-29).
- Dış kaynak (genel bilgi, doğrulanması önerilir): Python `pathlib.rglob` büyük/küçük
  harf davranışı (3.12+), `urllib.parse.quote` güvenli karakter kümesi,
  `str.splitlines`/`str.isspace` kümeleri, Node `worker_threads` `resourceLimits` ve
  `ERR_WORKER_OUT_OF_MEMORY`, libuv'nin Windows junction'larını bağlantı olarak
  bildirmesi, `smol-toml` TOML 1.0 uyumu ve geçmiş DoS düzeltmesi. NotebookLM veya
  Obsidian kaynağı kullanılmadı.

## İlgili REQ / AC

REQ-003: AC-P10-1…17, AC-P13-4, AC-T-4, AC-T-5, AC-G-2, AC-G-6; kararlar D-25…D-31,
D-42, D-49.

## REQ-003 üzerindeki netleştirmeler

1. **D-28 (d) — dosya adı eşleşmesi:** büyük/küçük harfe duyarlı tam ad (Python
   Windows'ta duyarsızdı). Golden'ı değiştirmez.
2. **D-28 (e) — dosya başı 32 MiB boyut sınırı:** aşan dosya yalnız kendi
   `parse_errors` kaydını üretir. Python'da sınır yoktu.
3. **AC-P10-11 kayıt kapsamı:** `parse_errors` kaydı dizin bağlantıları ve
   manifest adlı dosya bağlantıları için açılır; ilgisiz dosya bağlantıları
   sessizce atlanır. Dizin bağlantısı kaydında `ecosystem = 'filesystem'`.
   *(REQ-003 güvenlik düzeltmesi, 2026-10-10: geçersiz. Güncel kural Karar 6
   notunda — manifest adlı bağlantı → ekosistem kaydı, `SKIP_DIRS` adlı → atlanır,
   diğer her bağlantı → `filesystem` kaydı; hedef çözülmez.)*
4. **BOM:** Python davranışı (BOM'lu ilk `requirements` satırının atlanması)
   birebir korunur; düzeltme sonraki faz.
5. **D-49:** yol (2) seçildi (`overrides.uuid = 11.1.1`).
6. **`RunParserFn`:** isteğe bağlı `signal` parametresi eklenir (enjeksiyon noktası
   korunur).

## Kalan notlar (karar gerektirmeyen)

1. Golden donmuştur; beklenen çıktının değişmesi yeni bir D-xx gerektirir.
2. Python'da `rglob` kök dışındaki bağlantılı dizinlere inebiliyordu; TS inmez —
   bu D-28 a'nın kendisidir.
3. Implementation tamamlandığında `docs/handoffs/REQ-003.md` güncellenmelidir.

## Onay (Approval)

- **Karar veren:** kullanıcı daimi talimatı (önerilen seçenek), 2026-10-10.
  Talimat REQ-003'te kayıtlıdır. Durum `Accepted`. Karar ana oturum aracılığıyla
  iletilmiştir; kullanıcının bu dosyayı gözden geçirip commit etmesi kaydı
  kesinleştirir.
- Bu karar **yeni bir runtime bağımlılığı** (`smol-toml`) ve geçişli bağımlılık
  sürüm değişikliği (`uuid` override) içerir ve güvenilmeyen girdiyi işleyen
  **güvenlik sınırını** (dosya sistemi erişimi) değiştirir. REQ-003 insan onayı
  kapısı gereği implementation öncesi `docs/ownership/REQ-003.json`
  `status: approved` gerekir; release öncesi Security Red Team incelemesi önerilir.
