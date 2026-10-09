# P-10 biçim fixture'ları (REQ-003 AC-P10-4…10)

Python ayrıştırıcının (`src/scanner/sandbox/parsers/{common,nodejs,python}.py`)
her dalını en az bir girdiyle kapsayan, **dondurulmuş** biçim fixture'ları. Her
üst düzey klasör ayrı bir **tarama köküdür** (`--work-dir`). Golden çıktıyı ana
oturum Python ile üretir (D-26). TypeScript ayrıştırıcının çıktısı AC-P10-5
kurallarıyla golden'a eşit olmalıdır.

## İçindekiler

- [Kurallar](#kurallar)
- [Klasör yapısı](#klasör-yapısı)
- [Golden vakaları: npm](#golden-vakaları-npm)
- [Golden vakaları: Python](#golden-vakaları-python)
- [Golden vakaları: ortak / dosya sistemi](#golden-vakaları-ortak--dosya-sistemi)
- [Sapma vakaları (`deviation-`)](#sapma-vakaları-deviation-)
- [Kapsanmayan dallar](#kapsanmayan-dallar)

## Kurallar

- **Bayt dönüşümü önce gelir.** BOM, CRLF/CR, kontrol karakteri ve geçersiz
  UTF-8 içeren dosyalar şablondur. Golden üretilmeden önce
  [`MANIFEST-bytes.md`](MANIFEST-bytes.md) betiği çalıştırılmalıdır.
- **Golden üretimi.** Her vaka klasörü için
  `python -m src.scanner.sandbox.parsers.scan --scan-id <id> --work-dir formats/<vaka> --ecosystems nodejs,python`
  çalıştırılır (Python 3.11+, Windows). Kök yolunun hiçbir bileşeni `SKIP_DIRS`
  adı (`build`, `dist`, `env`, …) olmamalıdır. Python bu kusuru taşır (D-28 b).
- **Golden kümesi.** `deviation-` ile başlamayan her klasör golden'a girer.
  `deviation-` klasörleri golden karşılaştırmasından **hariçtir**. Bunlar
  D-28 sapmaları ve "tip olarak geçersiz girdi" (REQ-003 Riskler) için ayrı
  davranış testlerinin girdisidir. Python çıktıları yine de bilgi amaçlı
  üretilebilir.
- **Symlink/junction (D-28 a) ve 32 MiB (D-28 e)** için fixture yoktur. Test
  bunları çalışma anında geçici klasörde oluşturur: junction/symlink ve seyrek
  dosya.
- **`.gitignore`.** Kök `.gitignore`, `node_modules/`, `dist/` ve
  `__pycache__/` klasörlerini dışlar. Bu klasördeki `.gitignore` bu üç adı
  yeniden dahil eder, çünkü `skipdirs` ve `deviation-skipdirs-ancestor`
  vakaları bu klasörlerin commit edilmesini gerektirir.
- Paket adları gerçek ya da uydurmadır, sürümler sabittir. URL'ler
  `example.invalid` ya da `github.com/example`'dır. Hash/`integrity` değerleri
  sahtedir (`0000…`, `FIXTURE`). Sır yoktur.
- Satır numaraları bu fixture'ların yazıldığı commit'teki Python dosyalarına
  aittir: `C` = `common.py`, `N` = `nodejs.py`, `P` = `python.py`.

## Klasör yapısı

| Klasör | Tür | Kök |
| --- | --- | --- |
| `npm-lock-v1-nested` | golden | vaka klasörü |
| `npm-lock-v2` | golden | vaka klasörü |
| `npm-lock-v3-flags` | golden | vaka klasörü |
| `npm-lock-v3-versions` | golden | vaka klasörü |
| `npm-purl-chars` | golden | vaka klasörü |
| `npm-no-lock-specifiers` | golden | vaka klasörü |
| `npm-prototype-keys` | golden | vaka klasörü |
| `npm-yarn-v1-basic` | golden | vaka klasörü |
| `npm-yarn-v1-crlf` | golden | vaka klasörü |
| `npm-yarn-v1-quirks` | golden | vaka klasörü |
| `npm-yarn-separators` | golden | vaka klasörü |
| `npm-lock-and-yarn` | golden | vaka klasörü |
| `npm-monorepo` | golden | vaka klasörü |
| `npm-errors` | golden | vaka klasörü |
| `py-requirements-basic` | golden | vaka klasörü |
| `py-requirements-crlf` | golden | vaka klasörü |
| `py-requirements-quirks` | golden | vaka klasörü |
| `py-requirements-separators` | golden | vaka klasörü |
| `py-requirements-cr-only` | golden | vaka klasörü |
| `py-requirements-mixed-eol` | golden | vaka klasörü |
| `py-requirements-invalid-utf8` | golden | vaka klasörü |
| `py-requirements-names` | golden | vaka klasörü |
| `py-pyproject-pep621` | golden | vaka klasörü |
| `py-pyproject-poetry` | golden | vaka klasörü |
| `py-pyproject-crlf` | golden | vaka klasörü |
| `py-pyproject-cr-only` | golden | vaka klasörü |
| `py-poetry-lock` | golden | vaka klasörü |
| `py-poetry-project-and-lock` | golden | vaka klasörü |
| `py-errors` | golden | vaka klasörü |
| `bom-manifests` | golden | vaka klasörü |
| `skipdirs` | golden | vaka klasörü |
| `unicode-path` | golden | vaka klasörü |
| `deviation-case-mismatch` | sapma D-28 d | vaka klasörü |
| `deviation-skipdirs-ancestor` | sapma D-28 b | **iç klasörler**: `build/project`, `dist/project`, `env/project`, `node_modules/project` |
| `deviation-typeinvalid-npm` | tip geçersiz | vaka klasörü |
| `deviation-typeinvalid-python` | tip geçersiz | vaka klasörü |
| `deviation-json-nan` | JSON sınırı (ADR-005 Karar 3) | vaka klasörü |

## Golden vakaları: npm

| Vaka | Kapsadığı Python dalları | Not (beklenen davranış ipucu, golden esastır) |
| --- | --- | --- |
| `npm-lock-v1-nested` | N103-105 v1 ağacı; N110-129 (N118 sözlük olmayan girdi atlanır, N121 kapsam: bildirilen > `dev` > miras, N122 sürümsüz ebeveyn atlanır ama çocukları işlenir, N126-128 iç içe miras ve sözlük olmayan `dependencies` atlanır); N222-224 kesin olmayan kilit değeri (`file:`, `github:`); N49-52 `declared_range` yalnız `None` ise ada göre doldurulur (iç içe `ms@2.0.0` da `^2.1.3` alır); N277-283 lisans metin/dizi/nesne; C84-98 tekilleştirme | v1'de `optional` bayrağı yok sayılır (`nan` → `transitive`); `fsevents`/`react` bildirilen kapsamı alır |
| `npm-lock-v2` | N84-101 ve N103-105 birlikte; `packages` önce işlenir, v1 kopyaları tekilleştirmede düşer; `devOptional` dikkate alınmaz (N267-274); yalnız v1'de olan girdi eklenir | `source-map`: `packages`'tan `transitive` kazanır, v1'deki `dev` düşer |
| `npm-lock-v3-flags` | N87 kök (`""`), `null` ve metin girdisi atlanır; N89 `name` alanı (takma ad `real-pkg`, çalışma alanı `packages/my-workspace`) veya yol; N201-208 iç içe ve scoped `node_modules` yolu, `@lonely` tek parça scoped, `node_modules/` boş ad, `node_modules` içermeyen yol; N91 sürümsüz/boş sürüm; `link: true` girdisi atlanır; N98 bildirilen kapsam iç içe kopyaya da uygulanır (`semver@6.3.1` → `direct`); N267-274 bayrak önceliği `dev` > `peer` > `optional`; N235-236 ve N277-283 lisans dizi tekilleştirme, kod noktası sırası, boş öğe ve boş metin; C101-105 `+` sürüm | |
| `npm-lock-v3-versions` | N286-287 / N22 `EXACT_VERSION_RE`: `v` öneki, büyük `V`, baştaki sıfır, 2 ve 4 parçalı, `-`, `--`, `+`, ön sürüm+derleme; `strip` kümesi (boşluk, `\n`, `\x1c`, `\x1f`, NBSP kesin sayılır, sürüm ham kalır; U+FEFF ve U+200B kesin değil); **Python `\d` Unicode `Nd` eşler** (Arapça-Hint ve tam genişlik rakam kesin, üst simge `¹` değil); N49-52 kesin olmayan kilit değeri `declared_range`'i korur | purl'de ham sürüm kodlanır (`%201.2.3`, `%0A`, `%1C`) |
| `npm-purl-chars` | C101-105 `quote(name, safe="@/")`: `! ' ( ) * ~ + % : # ? & = ; , $ \ "`, boşluk, ASCII dışı (`ç`), vekil çifti (emoji), büyük harfli scoped ad; sürümde `+`, ön sürüm, `v`; C88-93 küçük harf tekilleştirme (`Dup-Name`/`dup-name`) | AC-P10-6 |
| `npm-no-lock-specifiers` | N55-56 ve N64-73 kilitsiz `package.json`: N70 `strip() or None` (boş, yalnız boşluk, `\x1c`, `\x1f`, NEL, LS, U+3000 kırpılır; U+FEFF kırpılmaz), N71 kesin aralık; aralık/etiket/URL/git/`file:`/`link:`/`workspace:`/`npm:` takma ad; dört bölüm ve kapsamları (N258-264); aynı ad iki bölümde (ilk gelen kazanır); C88-93 `str(None)` anahtarı (`Case-Dup`/`case-dup` farklı aralıkla tek kayıt); JSON yinelenen anahtar (sonuncusu) | P-05 davranışı: `version` boş, `declared_range` dolu |
| `npm-prototype-keys` | N240-255 sözlük üyeliği (`__proto__`, `toString`, `constructor`, `hasOwnProperty`, `valueOf`, `isPrototypeOf`); kilit, kilitsiz ve `yarn.lock` yollarında | JS nesne prototipi tuzağı: bildirilmemiş `constructor` için `declared_range` `null`, kapsam `transitive` olmalı |
| `npm-yarn-v1-basic` | N132-164 Yarn v1: yorum ve boş satır (N143), virgülle birleşik anahtar (N177-190), tırnaklı scoped (N193-198), `@types/node@*`, boşluklu tırnaklı aralık, `dependencies` alt bloğu, son girdi (N158-162); kapsam `package.json` bölümünden (N149) | AC-P10-8 LF ikizi |
| `npm-yarn-v1-crlf` | `npm-yarn-v1-basic` ile aynı içerik, CRLF | AC-P10-8: bağımlılık listesi LF ikiziyle aynı |
| `npm-yarn-v1-quirks` | Başlıktan önce girintili `version` (sahipsiz, N146 boş ad listesi); `npm:` takma ad, git ve `file:` tanımlayıcısı; tırnak içi virgül (N181-186); tırnaksız `version 1.0.0` (N156); kesin olmayan `version "latest"`; sürümsüz girdi; bozuk scoped `@malformed@1.0.0` (N195 eşleşmez → ad yok); `dependencies` altında `version` adlı bağımlılık sürümü ezer; satır sonu boşlukları (N142 `rstrip`); yalnız boşluk satırı akışı bozmaz; **sekmeyle girintili satır başlık sayılır** (N145); dosya sonunda satır sonu yok | Bayt şablonu |
| `npm-yarn-separators` | N141 `splitlines` (NEL, VT, LS) ve N142 `rstrip` (`\x1f`, NBSP); `errors="replace"` ile geçersiz bayt içeren ad (`caf\ufffd`); `version` değerinde sondaki U+200B kırpılmaz | Bayt şablonu |
| `npm-lock-and-yarn` | N38-46 iki kilit birlikte: önce `package-lock.json`, sonra `yarn.lock`; ortak `(ad, sürüm)` tekilleşir, farklı sürüm kalır; `scan_files` 3 kayıt | AC-P10-7 |
| `npm-monorepo` | C55-62 çoklu `package.json` (kök, `packages/*`, `apps/*`, derin boş `{}`); C48-52 `manifest_path`; kök kilidindeki çalışma alanı girdileri (`apps/web`, `packages/app-a`); alt pakette kendi `yarn.lock`'u; sahipsiz `package-lock.json`/`yarn.lock` (yanında `package.json` yok → yok sayılır); **`package.json` adlı klasör** (C60 `is_file`); **`package-lock.json` ve `yarn.lock` adlı klasör** (N39/N44 `is_file` false → kilitsiz yol) | |
| `npm-errors` | N57-58 hata kapsamı, her alt klasör ayrı `package.json`: bozuk JSON, boş dosya, üst düzey dizi/`null`/metin, bölüm dizi/metin/`null` (`AttributeError`/`TypeError`); bozuk/boş/dizi kilit dosyası (**kayıt `package.json` yolunda**, kilit `scan_files`'ta kalır, `yarn.lock` `scan_files`'a girmez, bağımlılık yok); `packages` dizi ve `dependencies` metin sessizce atlanır; çöp ve boş `yarn.lock` (hata yok, bağımlılık yok); `package.json`'da eşleşmeyen vekil (C102 `quote` → `UnicodeEncodeError`); kilitte eşleşmeyen vekilli **ad** (hata) ve **kesin olmayan sürüm** (hata yok, `declared_range` vekili taşır); geçersiz UTF-8 JSON (C40 katı okuma); sağlam komşu ayrıştırılmaya devam eder | AC-P10-12; `error` metni karşılaştırılmaz (AC-P10-5) |

## Golden vakaları: Python

| Vaka | Kapsadığı Python dalları | Not |
| --- | --- | --- |
| `py-requirements-basic` | P138-146 (P139 `#` ve satır sonu yorumu, P140 `-r`/`--requirement`/`-c`/`-e`/`--index-url`/`git+`/`http://`/`https://`/`.`/`./`/`../` atlanır, P142 `;` işaretçi), P20 extras ve boşluklu extras, P149-159 (`==`, `===`, `== X` boşluklu, `>=`, `~=`, `!=`, `<`, virgüllü aralık, `==2.1.*`, belirteçsiz ad); `pkg @ URL` ve `#` ile kesilen URL; girintili yorum ve sekmeyle girintili satır; C108-112 `_`→`-` ve küçük harf, `.` korunur | AC-P10-8 LF ikizi |
| `py-requirements-crlf` | `py-requirements-basic` ile aynı içerik, CRLF | AC-P10-8 |
| `py-requirements-quirks` | C84-98 büyük/küçük harf tekilleştirme (`Requests`/`requests`); **`str(None)` çakışması** (`nonepkg==None` sonra `nonepkg` → tek kayıt, sürüm `"None"`); aynı satırda `--hash` (kesin değil); satır devamı `\` desteklenmez (devam satırı `-` ile atlanır); boşluksuz `==3.0.0\` → sürüm ters bölüyle; eski `(==1.0)`; `==*`; `===` yerel sürüm; epoch `1!2.0.0` (purl `%21`); kapanmamış/fazla köşeli parantez; yalnız `-`, `--`, `;…`, `==1.0` satırları; **ASCII dışı ad** `türkçe-paket` → ad `t`; `C:\…` → ad `C`; `/abs/…` eşleşmez; `file:///…` → ad `file`; yorum içindeki `;` | |
| `py-requirements-separators` | P66 `splitlines` (VT, FF, FS, GS, RS, NEL, LS, PS); P139 `strip` ve P20 `\s` (`\x1f`, NBSP, U+3000, U+2003); P22 `[^,;\s*]`; U+200B ve dosya ortasındaki U+FEFF boşluk sayılmaz (satır başındaki U+FEFF satırı düşürür) | Bayt şablonu |
| `py-requirements-cr-only` | Python evrensel satır sonu (`read_text`): yalnız CR | Bayt şablonu |
| `py-requirements-mixed-eol` | LF, CR, CRLF ve art arda CR karışımı | Bayt şablonu |
| `py-requirements-invalid-utf8` | P66 `errors="replace"`: tek geçersiz bayt, yarım çok baytlı dizi, UTF-8 kodlu vekil (`ED A0 80` → 3×U+FFFD); U+FFFD'nin addan sonra `declared_range`'e ve kesin sürüme düşmesi | Bayt şablonu |
| `py-requirements-names` | P26/P32 yalnız `requirements.txt` (`direct`), `requirements-dev.txt` ve `requirements-test.txt` (`dev`); `dev-requirements.txt`, `requirements_dev.txt`, `requirements.in`, `requirements-prod.txt`, `requirements.txt.bak`, `constraints.txt`, `requirements/base.txt`, `Pipfile.lock`, `uv.lock`, `pnpm-lock.yaml` **yok sayılır** (AC-P10-2); `requirements` klasörü içindeki `requirements.txt`; alt klasör `manifest_path`; **AC-P10-7** aynı sürüm `requirements.txt` + `-dev` → tek kayıt `direct`, farklı sürüm iki kayıt, sürümsüz aralıklar `str(None)` ile tekilleşir; `requirements.txt` adlı klasör (C60) | |
| `py-pyproject-pep621` | P90-92 `project.dependencies` (`==`, `===`, aralık, extras+işaretçi, `@ URL`, `#` kesilmesi, `-`/`git+`/`.` ile başlayan, boş metin, `#` yorum, `python==3.11` **atlanmaz**); P94-98 `optional-dependencies` (`optional`, boş grup); alt klasörler: tablo olmayan `optional-dependencies` sessizce atlanır, bağımlılık anahtarı olmayan proje | |
| `py-pyproject-poetry` | P100-104 `tool.poetry.dependencies` ve `python` atlanması; P162-170 Poetry belirteci: bare sürüm (`0.27.0`, `4.2`, `1.2.3.post1`, `1!2.0`, `1.0+cpu`, `1.0a1`, `" 1.2.3 "`), `*`, `~`, `^`, `==`, `===`, aralık, `v1.0.0`, `1.0 \|\| 2.0`, boş ve boşluk metni; tablo biçimi `{ version = … }`, sürümsüz tablo, `git`/`path`/`url` tablosu, çoklu kısıt dizisi, tamsayı değer (hepsi `None`); P106-107 `dev-dependencies`; P109-113 `group.*` (`main` grubu dahil hepsi `dev`, bağımlılıksız grup); grup içindeki `python` **atlanmaz**; alt klasörler: `Python`/`PYTHON` atlanır ama PEP 621 `Python==3.11` atlanmaz; PEP 621 ve Poetry aynı dosyada (tekilleştirme sırası, `optional` kapsamı kazanır) | |
| `py-pyproject-crlf` | CRLF `pyproject.toml` ve `poetry.lock` | Bayt şablonu |
| `py-pyproject-cr-only` | Yalnız CR satır sonlu TOML. Python `read_text` evrensel satır sonu ile CR'yi LF'ye çevirir ve dosya **geçerli** okunur | Bayt şablonu. TS'te TOML'dan önce satır sonu çevirisi gerektirir (bkz. Kapsanmayan dallar) |
| `py-poetry-lock` | P118-135: `category = "dev"` → `dev`, `"main"`, kategorisiz, Poetry 2 `groups` (yok sayılır → `transitive`), `"Dev"` (büyük harf → `transitive`); P123 `strip`; boş sürüm, sürüm anahtarı yok, ad yok, boş ad atlanır; `post`, yerel `+cpu`, PEP 440 olmayan sürüm (kesinlik denetimi yok); `[package.dependencies]`, `[package.extras]`, `[metadata.files]`; tekilleştirme (`certifi` iki kez, `CERTIFI`) | `pyproject.toml` olmadan da keşfedilir |
| `py-poetry-project-and-lock` | AC-P10-7 Python sırası: `requirements.txt` → `pyproject.toml` → `poetry.lock`; ilk gelen kapsam kazanır (`direct` > kilitteki `transitive`/`dev`); kilit girdisi hiçbir zaman `pyproject` kapsamını almaz; iç klasörde yalnız `poetry.lock` | |
| `py-errors` | P41-42/P49-50/P57-58 hata kapsamları: bozuk TOML (kapanmamış tablo, sürüm değeri, yinelenen anahtar, kapanmamış metin); boş `pyproject.toml`/`poetry.lock`/`requirements.txt` (hata yok); yalnız yorum/seçenek satırlı `requirements-dev.txt`; geçersiz UTF-8 TOML (P76/P119 katı okuma); `tool.poetry` metin, grup değeri metin, `tool.poetry.dependencies` dizi, `poetry.lock` `package` metin/tablo (`AttributeError`); `group` metin sessizce atlanır; sağlam komşu | AC-P10-12 |

## Golden vakaları: ortak / dosya sistemi

| Vaka | Kapsadığı Python dalları | Not |
| --- | --- | --- |
| `bom-manifests` | AC-P10-4 BOM davranışı: BOM'lu `package.json` JSON hatası (C40 `utf-8`); BOM'lu `package-lock.json` → `package.json` yolunda hata; BOM'lu `yarn.lock` BOM'u ilk girdinin adına yapıştırır (`\ufefflodash`, purl `%EF%BB%BF`) veya yorum satırını başlık yapar; BOM'lu `requirements.txt` ilk satırı düşürür, ilk satır yorumsa kayıp yok, tek satırlıksa bağımlılık yok; BOM'lu `pyproject.toml` (yorumla başlasa da) ve `poetry.lock` TOML hatası | Bayt şablonu |
| `skipdirs` | C11-24 / C58 `SKIP_DIRS` (kökün altında): `node_modules`, `dist`, `build`, `.venv`, `venv`, `env`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.hg`, `.svn`, iç içe `src/node_modules`, `packages/a/dist`; **büyük/küçük harfe duyarlı** küme: `Build`, `Node_Modules`, `ENV` atlanmaz; `builds`, `my-env`, `dist-tools`, `.github` atlanmaz | `.git` git tarafından eklenemediği için kapsanmaz |
| `unicode-path` | Türkçe ve boşluklu klasör adları (`şirket-ürün/çekirdek`, `ğüşiöç`, `İstanbul Ofis`) ile `file_path`/`manifest_path` (C44-52, `/` ayırıcı); npm ASCII dışı ad ve scoped ad purl kodlaması; küçük harf tekilleştirme `Çiçek`/`çiçek`; Poetry'de ASCII dışı ad (C108-112); requirements ve PEP 621'de ASCII dışı ad eşleşmez | |

## Sapma vakaları (`deviation-`)

Golden karşılaştırmasından hariçtir. TS beklentisi ayrı davranış testinde
yazılır.

| Vaka | Python davranışı | TS beklentisi (ADR-005) |
| --- | --- | --- |
| `deviation-case-mismatch` | Windows'ta `rglob` harfe duyarsız: `Package.json`, `PACKAGE.JSON`, `Requirements.txt`, `REQUIREMENTS-DEV.txt`, `PyProject.toml`, `Poetry.lock` bulunur. `Package-Lock.json`/`Yarn.lock` küçük harfli adla okunur. `nested/deeper/Package.json` için `manifest_path` ters bölü olabilir | D-28 d / AC-P10-18: bu dosyalar ayrıştırılmaz ve `scan_files`'a girmez. `upper-lock` ve `upper-yarn`'da `package.json` kilitsiz ayrıştırılır |
| `deviation-skipdirs-ancestor` | Kök `build/project` vb. olduğunda C58 mutlak yol bileşenlerine bakar ve **tüm** manifestleri gizler | D-28 b / AC-P10-10: kök `deviation-skipdirs-ancestor/<build\|dist\|env\|node_modules>/project` iken manifestler bulunur |
| `deviation-typeinvalid-npm` | `null`/sayı/bool/nesne/dizi belirteç `str()` ile metne döner (`"None"`, `"1.0"`, `"True"`, `"{'version': …}"`). Kilitte sayı sürüm/ad ve karışık lisans dizisi aynı şekilde döner | REQ-003 Riskler: birebirlik aranmaz. Ayrıştırıcı çökmez, sonuç `parse_errors` kaydı veya atlamadır |
| `deviation-typeinvalid-python` | `project.dependencies` metin (karakter karakter dolaşılır), sayı/bool/tarih öğeleri, tablo (anahtarlar); `optional-dependencies` grubu metin; `poetry.lock` sayı/tarih/bool sürüm, sayı ad, dizi `category` | ADR-005 Karar 2: TS hata fırlatır veya atlar, çökmez |
| `deviation-json-nan` | Python `json` `NaN`/`Infinity`/`-Infinity` kabul eder ve ayrıştırır | ADR-005 Karar 3 kabul edilen sınır: `JSON.parse` hatası → `parse_errors` (kilit için `package.json` yolunda) |

## Kapsanmayan dallar

| Dal | Neden |
| --- | --- |
| Symlink, junction ve döngü (C45 `resolve`, C60 `is_file` bağlantıyı izler; L-4) | Windows'ta oluşturmak yetki ister. Test çalışma anında oluşturur (AC-P10-11) |
| 32 MiB üstü dosya (D-28 e) | Depoya konmaz. Test seyrek dosya üretir (AC-P10-19) |
| `.git` klasörü (C12) | Git, `.git` bileşenli yolu depoya eklemez. Test çalışma anında oluşturabilir |
| Okunamayan dosya (`EACCES`/`EBUSY`, C66 `read_bytes` `try` dışında) | İzin durumu fixture'la taşınamaz. AC-P10-12 testi çalışma anında üretir. Python'da bu durum taramayı çökertir (D-28 a) |
| `scan.py` desteklenmeyen ekosistem kaydı | Dosya girdisi değil, `--ecosystems` parametresidir; birim testte ele alınır |
| JSON tamsayı biçimli nesne anahtarlarının sırası (ADR-005 Karar 3) | Kabul edilen sınır; yalnız aynı manifestteki ilk-gelen-kazanır kararını etkiler. Golden'a konursa bilinçli sapmayı kırmızıya çevirir |
| TOML 1.1 sözdizimi | ADR-005 Karar 8: golden fixture'lar TOML 1.0 ile yazılır |
| ASCII dışı PyPI adında `str.lower` farkı (ör. `İ`) | ADR-005 Karar 2: golden kapsamı ASCII. Requirements/PEP 621'de ASCII dışı ad zaten eşleşmez. Poetry'de yalnız `ç` gibi tek eşlemeli harfler kullanıldı |
