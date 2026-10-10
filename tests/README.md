# REQ-002 (F1) ve REQ-003 (F2) test paketi

REQ-002 P-01…P-09 için **test-first** Vitest paketi. Testler bugünkü kodda
hatayı yeniden üretir (KIRMIZI); backend/frontend düzeltmesi bu dosyada
tanımlanan arayüzleri uyguladığında YEŞİL olmalıdır (AC-G-2, AC-G-3).
REQ-003 P-10 (TypeScript ayrıştırıcılar, ADR-005) için golden eşdeğerlik,
sapma ve iş parçacığı testleri; P-11 (Node göç aracı), P-12 (tek süreçli
çalışma zamanı, tek örnek kilidi, kapanış) ve P-13 (yeniden deneme, bekleme,
süre sınırı) testleri de buradadır (ADR-004).

## İçindekiler

- [Çalıştırma](#çalıştırma)
- [Klasör yapısı](#klasör-yapısı)
- [Test veritabanı](#test-veritabanı)
- [Beklenen arayüzler](#beklenen-arayüzler)
- [AC → test eşlemesi](#ac--test-eşlemesi)
- [Kurallar](#kurallar)

## Çalıştırma

```sh
npm test            # vitest run (tests/**/*.test.ts)
npm run typecheck   # tsc -p tsconfig.test.json (src + tests)
npm run lint
```

Ön koşullar: Node ≥ 22, `git` (yalnız `git ls-files` için). Python, Docker,
Git Bash ve `PATH`'te `psql` gerekmez; hiçbir test bunları çağırmaz
(REQ-003 AC-G-2). İnternet gerekmez (AC-G-4): OSV/NVD çağrıları `fetch`
taklidiyle, clone işlemi enjekte edilen sahte `cloneRepo` ile yapılır.

## Klasör yapısı

| Yol | İçerik |
| --- | --- |
| `helpers/paths.ts` | `REPO_ROOT`, `FIXTURES_DIR` |
| `helpers/loadSrc.ts` | `loadSrc` / `loadSrcGuarded`: `src/` modüllerini dinamik yükler; yoksa `MissingImplementationError` |
| `helpers/contracts.ts` | Testlerin beklediği TypeScript arayüzleri (aşağıdaki tablonun makine okunur hâli) |
| `helpers/pgCluster.ts` | embedded-postgres kümesi, migrate edilmiş şablon DB, CREATE/DROP DATABASE |
| `helpers/db.ts` | `useTestDatabase({ scope: 'file' \| 'test' })` — dosya ya da test başına DB; `useScratchDatabases(base)` — test başına ek geçici DB'ler (boş / F1 durumu / göç edilmiş, testten sonra `DROP … WITH (FORCE)`) |
| `helpers/pgGlobalSetup.ts` | İsteğe bağlı Vitest `globalSetup` (tek küme) — henüz kayıtlı değil |
| `helpers/migrations.ts` | Kaldırılan F1 `db/migrate.sh`'in kayıt biçiminin testteki bağımsız eşi: `db/migrations/*.up.sql`'i sürüm sırasıyla, dosya başına bir transaction ve `schema_migrations` kaydıyla uygular; `{ through: '004_finding_fingerprint' }` ile AC-P11-3'ün "F1 veritabanı"nı kurar. Ürün göç aracını (`src/db/migrator.ts`) kullanmaz; şablon DB'yi kurar (yalnız geçici test DB'leri) |
| `helpers/parserGolden.ts` | P-10 golden karşılaştırıcısı (AC-P10-5): JSON gidiş-dönüş, sıradan bağımsız diziler, `parse_errors` yalnız `(ecosystem, file)`, hata metninde mutlak yol denetimi |
| `helpers/psqlScript.ts` | psql betiğini düz SQL'e çevirir (`\ir` içe alınır, `\set`/`\echo` atılır) |
| `helpers/http.ts` | supertest yardımcıları (Host/Origin, çerez, setup/login, hata gövdesi kontrolü) |
| `helpers/tokenCrypto.ts` | AES-256-GCM token şifreleme (test verisi, gerçek sır değil) |
| `fixtures/p05-ranges-no-lockfile` | Kilit dosyasız iki `package.json` (aynı paketin iki aralığı) + `requirements.txt` |
| `fixtures/p07-dev-scope` | devDependency, `requirements-dev.txt`, Poetry dev grubu |
| `fixtures/p10-golden/formats` | REQ-003 P-10 biçim fixture'ları: her klasör ayrı tarama kökü; `deviation-*` golden dışı. Kapsam: `formats/README.md`, bayt dönüşümü: `formats/MANIFEST-bytes.md` |
| `fixtures/p10-golden/snapshot-*` | AC-P10-3 repo anlık görüntüleri (`1b2b934`: 219, `73db78b`: 496 bağımlılık) |
| `fixtures/p10-golden/expected` | Dondurulmuş golden çıktılar (eski Python ayrıştırıcı, D-26); değişmesi yeni bir D-xx gerektirir |
| `unit/` | Saf fonksiyonlar ve TypeScript ayrıştırıcı (`parseManifests`) çıktısı |
| `unit/parsersGolden.test.ts` | AC-P10-3…9: her `expected/*.json` için golden eşitliği, 219/496 sayıları, sonuç biçimi, CRLF ikizleri, karşılaştırıcının negatif kontrolü |
| `unit/parsersDeviations.test.ts` | D-28 sapmaları: büyük/küçük harf (AC-P10-18), göreli `SKIP_DIRS` (AC-P10-10), junction/symlink (AC-P10-11), 32 MiB (AC-P10-19), dosya bazlı hata ve mutlak yol (AC-P10-12/13), derin TOML/JSON, tip-geçersiz ve NaN girdiler |
| `unit/parserThread.test.ts` | AC-P10-14: iş parçacığında normal çalışma (kaynak modu ve `typescript` ile geçici klasöre derlenmiş `thread.js`), `env: {}`, AbortSignal iptali, bellek sınırı, çökme eşlemesi, `undefined/` regresyonu |
| `unit/pythonParsers.test.ts` | P-05/P-07 ayrıştırıcı sözleşmesi ve AC-P10-7 tekilleştirme; REQ-003'ten beri TypeScript ayrıştırıcıyla (ad REQ-002'den kaldı) |
| `unit/retryPolicy.test.ts` | AC-P13-1 bekleme tablosu, hata sınıflandırması (ADR-004 Karar 8), `decideRetry`, süre sınırı mesajı |
| `unit/processHandlers.test.ts` | AC-P12-9/10: `installProcessHandlers` sahte süreç (EventEmitter) ve sahte çalışma zamanıyla — dört sinyal, ikinci sinyal, ölümcül hata günlüğünün arındırılması |
| `integration/` | Gerçek PostgreSQL ile HTTP ve worker testleri, migration testi |
| `integration/migrateTool.test.ts` | P-11: `runMigrateCli` (süreç içi) ve `typescript` ile geçici klasöre derlenmiş `migrate.js` (gerçek `node` süreci); tek örnek kilidi ve kilit kaybı yapı taşları |
| `integration/runtime.test.ts` | P-12: `createRuntime` ile süreç içi başlatma; sahte `exit`, sabit boş port, sahte clone/ayrıştırıcı/rapor servisi; kapanış, bozulmuş kip, `pg_terminate_backend` |
| `integration/scanRetry.test.ts` | P-13: `ScanWorker.runOnce` ile geri çekilme, kalıcı/geçici hatalar, süre sınırı, yoklamada sahipsiz kurtarma, `worker_id` çiti, AC-G-8 |
| `unit/gitIsolation.test.ts` | N-1 (AC-T-1, AC-T-2): saf `buildGitCloneArgs`/`buildGitBaseEnv`/`buildGitEnv` (izin listesi, iki harf biçimli vekil, `win32`'de harf duyarsız ad, schannel yalnız `win32`, token yalnız env'de); sahte `spawn` ile `cloneRepo` ortamı ve yalıtım dosyaları; AC-T-4 clone hata kuyruğu (1024) |
| `integration/gitIsolationReal.test.ts` | N-1 gerçek kanıt (ağsız): "kötü" global/XDG/`GIT_CONFIG_*` yapılandırması negatif kontrolde etkili, `buildGitEnv` ile `git config` çıktısında görünmez; git < 2.32 ya da yoksa atlanır |
| `unit/errorText.test.ts` | L-5 (AC-T-4): `sanitizeErrorText` — 2000 kod noktası, yollar (iki ayırıcı, harf duyarsız, sınır kuralı), sırlar, kontrol karakterleri |
| `unit/gitVersion.test.ts` | AC-T-3: `parseGitVersion` tablosu, gereksinim mesajı, `GitUnavailableError`, `defaultCheckGit` (yalnız log), gerçek `git --version` |
| `unit/mainEntry.test.ts` | D-52 / REQ-002 AC-P09-3: `main()` `DATABASE_URL` yokken tek hata satırı + `exit(1)` (`dotenv/config` taklit edilir, `.env` okunmaz) |
| `integration/errorTextPersistence.test.ts` | L-5 uçtan uca: tarama (clone, ayrıştırıcı, `parse_errors`) ve rapor (`ReportService` dosya hatası, atılan hata) `error_message` yazımları |
| `integration/excelExport.test.ts` | AC-T-5: `uuid` 11.1.1 ile Excel raporu üretilir, `.xlsx` ExcelJS ile geri okunur (sayfa, başlık, satır) |
| `security/followUpItems.test.ts` | AC-T-5 statik (`overrides.uuid`, lock, çalışma anı çözümü), AC-T-6 (`db/README.md` kurtarma bölümü) |
| `security/` | XSS (jsdom), sır taraması, kaynak kodu korumaları |

## Test veritabanı

- `embedded-postgres` ile `os.tmpdir()` altında geçici küme, rastgele port ve
  çalıştırma başına rastgele parola; `initdb --locale=C --encoding=UTF8`
  (Türkçe Windows locale'inde zorunlu). Geliştirme DB'si hiç kullanılmaz
  (AC-G-5).
- Tüm migration'lar bir kez şablon DB'ye uygulanır; testler
  `CREATE DATABASE … TEMPLATE ossr_template` ile kopya alır.
- `vitest.config.ts` şu an `globalSetup` içermiyor; bu yüzden DB kullanan her
  test dosyası kendi kümesini açar (~5–8 sn). Tek küme için ana oturum
  `vitest.config.ts`'e `globalSetup: ['tests/helpers/pgGlobalSetup.ts']`
  ekleyebilir; `helpers/db.ts` bunu `inject()` ile otomatik kullanır.
- `integration/migrations.test.ts`, `db/tests/f1_migrations_test.sql`'i psql
  olmadan çalıştırır (embedded-postgres psql içermez).
- Tek örnek kilidi (`pg_try_advisory_lock(1330860882, 1)`) veritabanı
  başınadır; kilit ve çalışma zamanı testleri her senaryoda ayrı geçici DB
  kullandığı için paralel dosyalar birbirini kilitlemez.

### Çalışma zamanı testlerinde dikkat (REQ-003 P-12)

- `createRuntime` her zaman `exit: vi.fn()` ile kurulur: 15 sn'lik zorla
  çıkış zamanlayıcısı gerçek `process.exit`'e ulaşmamalıdır.
- `port: 0` verilmez: Host izin listesi `options.port`'tan kurulur, 0 ile her
  istek `403 host_rejected` olur. Testler boş bir sabit port alır. Bu davranış
  ürün hatası olarak raporlandı; "Observation (product bug): Host allow-list
  with an ephemeral port" testi düzeltmeye kadar kırmızıdır.
- `checkGit` enjekte edilir (`git --version` alt süreci açılmaz).
- `runtime.test.ts`, `WORKER_POLL_INTERVAL_MS=200`'ü `vi.hoisted` ile modüller
  yüklenmeden önce ayarlar ve `afterAll`'da geri alır.

## Beklenen arayüzler

Testler bu export'ları **dinamik import** ile yükler (`helpers/loadSrc.ts`):
henüz olmayan modüller `npm run typecheck`'i kırmaz, çalışma anında
`MissingImplementationError` ile anlaşılır biçimde kırmızı olur. Tipler
`helpers/contracts.ts` içindedir. Proje CommonJS + Express düzenini korur;
yeni klasör açılmaz.

### `src/app.ts` — P-01, P-04 (HTTP), AC-G-8, AC-G-9

```ts
export interface AppDeps {
  db: Pool;              // zorunlu; global pool'a düşülmez
  port?: number;         // Host/Origin izin listesi için (vars. PORT env veya 3001)
  host?: string;         // vars. HOST env veya '127.0.0.1'
  scanRoots?: string[];  // vars. parseScanRoots(process.env.SCAN_ROOTS)
}
export function createApp(deps: AppDeps): express.Express;           // listen ETMEZ
export function startServer(options: AppDeps): Promise<http.Server>; // listen olunca resolve; host vars. 127.0.0.1
export function listenApp(options: AppDeps, env?: NodeJS.ProcessEnv): Promise<http.Server>; // ortam kontrolsüz; çalışma zamanı adım 6
// Süreç girişi REQ-003'ten beri src/main.ts'tir (`npm start` = node dist/main.js); app.ts yan etkisizdir
// ve kendi başına süreç olarak çalıştırılmaz.
```

- İçe aktarma yan etkisiz olmalı (bugünkü `app.listen` modül düzeyinde kalmamalı).
  Test, bu iki export kaynakta görünmeden modülü içe aktarmaz.
- Testler her istekte `Host: 127.0.0.1:3001` ve yazma isteklerinde
  `Origin: http://127.0.0.1:3001` gönderir; izin listesi `deps.port`'tan
  hesaplanmalıdır (supertest'in geçici portundan değil).
- Brute-force sayacı (`429`) ve benzeri bellek içi durum **her `createApp`
  örneğine özgü** olmalıdır (modül düzeyi tekil durum testleri birbirine
  bağlar).
- Oturum geçerliliği DB'deki `sessions.last_seen_at` / `expires_at` ile
  değerlendirilir; testler bu kolonları geriye çekerek süreleri sınar.
- `/health` `deps.db.query` hata fırlatınca contract'taki sabit `500`
  gövdesini döner.
- Rotalar ve contract kodları: `docs/contracts/REQ-002-auth-api.md`.

### `src/lib/scanSource.ts` — P-03 (AC-P03-7), P-04

```ts
export type ScanSource = { kind: 'remote'; url: string } | { kind: 'local'; path: string /* realpath.native */ };
export class ScanSourceError extends Error {
  constructor(code: 'path_not_allowed' | 'repo_url_not_allowed', message?: string);
  readonly code: 'path_not_allowed' | 'repo_url_not_allowed';
  readonly statusCode: 400;
}
export function parseScanRoots(value: string | undefined): string[];   // path.delimiter ile böler, boşları atar
export function resolveScanSource(value: string, scanRoots: readonly string[]): Promise<ScanSource>;
```

- `scanRoots` ham mutlak yollar olabilir; fonksiyon kökleri de
  `realpath.native` ile kanonikleştirir. Windows'ta karşılaştırma büyük/küçük
  harf duyarsız, önek+ayraç kuralıyla.
- Hata mesajları contract'taki sabit metinlerdir; yol veya `SCAN_ROOTS`
  içermez. Hem controller'lar (`POST /api/projects`, `POST /api/scans`) hem
  worker (TOCTOU) bunu kullanır.

### `src/scanner/workspace.ts` — P-03

```ts
export type CloneRepoFn = (url: string, ref: string | null, dest: string, token: string | null) => Promise<void>;
export const cloneRepo: CloneRepoFn;   // gerçek git; testlerde çağrılmaz (ağ yok)
export function buildGitCloneArgs(url: string, ref: string | null, dest: string): string[]; // saf; token parametresi yok
export function withTempWorkspace<T>(fn: (dir: string) => Promise<T>, options?: { tmpRoot?: string }): Promise<T>;
```

- `buildGitCloneArgs`: `-c core.symlinks=false -c credential.helper= … clone --depth 1 --single-branch --no-tags [--branch <ref>] -- <url> <dest>`;
  geçersiz `ref` (`^[A-Za-z0-9._/-]+$` dışı veya `-` ile başlayan) → hata.
- `withTempWorkspace`: `<tmpRoot>/ossrisk-scan-XXXX` açar, başarıda da hatada da
  siler (salt-okunur dosyalar dahil), `fn`'in hatasını aynen yeniden fırlatır.

#### Clone sertleştirmesi — AC-P03-8…10 (D-18, güvenlik incelemesi M-2)

`unit/cloneRepoConfig.test.ts`, `child_process`'i taklit edip (`vi.mock`)
`cloneRepo`'nun `spawn('git', args, { env })` çağrısını yakalar ve git'in
**etkin yapılandırmasını** iki kanaldan birleştirir: `clone`'dan önceki
`-c key=value` çiftleri + `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`.
Anahtar karşılaştırması git kuralıyla (bölüm/değişken büyük-küçük harf duyarsız,
alt bölüm/URL duyarlı); aynı anahtarda son değer geçerlidir. Beklenen küme:

| Ayar | Değer | Kanal |
| --- | --- | --- |
| `GIT_LFS_SKIP_SMUDGE` (ortam değişkeni) | `1` | env |
| `filter.lfs.smudge` | `` (boş) | args veya `GIT_CONFIG_*` |
| `filter.lfs.clean` | `` (boş) | args veya `GIT_CONFIG_*` |
| `filter.lfs.process` | `` (boş) | args veya `GIT_CONFIG_*` |
| `filter.lfs.required` | `false` | args veya `GIT_CONFIG_*` |
| `http.followRedirects` | `false` | **`buildGitCloneArgs` çıktısında** `-c http.followRedirects=false` (`clone`'dan önce) |
| `http.<https://host/>.extraHeader` | `Authorization: Basic <base64(user:token)>` | **yalnız `GIT_CONFIG_*`** (token argümanlarda ham ya da base64 olarak görünmez) |

- Token varken tam olarak **bir** `extraHeader` girdisi olur; alt bölümü hedef
  URL'nin `https://<host>/` kökenidir (ör. `http.https://github.com/.extraHeader`).
  Hosttan bağımsız `http.extraHeader` **bulunmaz**. Token yoksa hiç
  `extraHeader` yoktur.
- Ayarlar token'lı ve token'sız clone'da aynıdır. Önerilen yer: LFS/filtre ve
  yönlendirme ayarları `buildGitCloneArgs` içinde `-c` olarak (saf, test edilebilir),
  token başlığı `cloneRepo` ortamında.
- Test `cloneRepo`'nun tam olarak bir `git` süreci başlatmasını bekler.

### `src/scanner/worker.ts` — P-03, P-04 (worker), P-05…P-09

```ts
export function decryptToken(encrypted: Buffer | null | undefined, keyString?: string): string | null;
export interface ScanWorkerDeps {
  db: Pool;                                  // vars. ../lib/db pool
  cloneRepo: CloneRepoFn;                    // vars. workspace.cloneRepo
  runParser: (workDir: string, ecosystems: string[], scanId: string, signal?: AbortSignal) => Promise<SandboxScanResult>; // vars. createThreadParser() (REQ-003 P-10)
  scanRoots: string[];                       // vars. parseScanRoots(process.env.SCAN_ROOTS)
  tmpRoot: string;                           // vars. os.tmpdir()
  logger: Pick<Console, 'log' | 'warn' | 'error'>; // vars. console
}
export class ScanWorker {
  constructor(deps?: Partial<ScanWorkerDeps>);
  runOnce(): Promise<string | null>;  // sıradaki pending/queued taramayı alır, sonuna kadar işler, DB güncellendikten sonra id döner; poll döngüsü başlatmaz
  saveScanResults(scanId: string, projectId: string, result: SandboxScanResult): Promise<void>; // public
  start(): Promise<void>; stop(): void;  // mevcut davranış
}
```

- `decryptToken`: `null`/`undefined`/boş tampon → `null`. Diğer her durumda ya
  çözülmüş token ya da **hata**; anahtar `SHA-256(ENCRYPTION_KEY)`, düzen
  `IV(12) | tag(16) | ciphertext` (bugünkü düzen korunur).
- `runOnce` akışı: token çöz (hata → `failed`, yeniden deneme yok, clone yok) →
  kaynak sınıflandır (`resolveScanSource`; ret → `failed`) → uzaksa
  `withTempWorkspace` + `cloneRepo(url, ref, <ws>/repo, token)` → `runParser`
  → `saveScanResults`. Kaynak yoksa `failed`; `'.'`'ya asla düşülmez. Ağ/clone
  hataları mevcut retry politikasına tabidir (`system_settings.scan.max_retries`).
- Token yalnız `cloneRepo`'nun 4. argümanıdır; URL'de, hata mesajında, log'da yer almaz.
- `saveScanResults`: `version` null olabilir, `declared_range`
  `scan_dependencies.declared_range`'e yazılır, upsert `ON CONFLICT (purl)`;
  lisans politikası yalnız runtime kapsam (`direct/transitive/peer/optional`);
  lisanssız runtime paket → `unknown` bulgusu (`normalized_license='NOASSERTION'`,
  `license_id NULL`); her bulguya `fingerprint`; aynı taramada parmak izi başına
  tek bulgu; karar taşıma ADR-003 (c) tablosuna göre, `carried_from_finding_id`
  doldurulur, kaynak review kopyalanır.
- Güvenlik açığı girdisi testlerde ayrıştırıcı sözleşmesindeki
  `dependencies[].vulnerabilities` alanıyla verilir; OSV istekleri `fetch`
  taklidiyle "açık yok" döner.

### `src/analysis/findingFingerprint.ts` — P-08

```ts
export interface FingerprintInput {
  projectId: string;
  purl: string;                 // packages.purl
  version: string | null;       // packages.version (kırpılmamış hâli verilebilir)
  findingType: 'license' | 'security';
  normalizedLicense?: string | null;
  vulnerability?: { id: string; osvId?: string | null; ghsaId?: string | null; cveId?: string | null };
}
export function computeFindingFingerprint(input: FingerprintInput): string; // 64 küçük harf hex
```

`db/migrations/004_finding_fingerprint.up.sql` ile bayt düzeyinde aynı sonuç;
referans değerler `db/tests/f1_migrations_test.sql` içindeki `_expected_fp`.

### Ayrıştırıcı çıktı sözleşmesi (P-05, P-07; REQ-003 P-10)

`parseManifests(rootDir, ecosystems, scanId)` (`src/scanner/parsers`)
çıktısında her bağımlılık:
`version` = kesin sürüm veya `null` (`'unknown'` yok), `declared_range` =
manifestteki aralık veya `null`, sürüm `null` ise purl sürümsüz.
`requirements-dev.txt` ve Poetry dev grupları `scope: 'dev'`. `src/types/scan.ts`
buna göre güncellenir (`version: string | null; declared_range?: string | null`).

### Frontend (`public/index.html`) — P-02

Ek export yok. Test, sayfayı jsdom'da `fetch` taklidiyle açar ve
`[data-view="projects|findings|users"]` gezinme öğelerine tıklar; açılışta
`GET /api/auth/me` `401` ise sayfada `input[type="password"]` beklenir; formun
gönderimi (`requestSubmit` ya da formdaki buton) `POST /api/auth/login` çağırır.

#### Sayfa yapısı — AC-P02-5…7 (D-17, AC-P02-7 seçenek (a))

- Sayfa betiği **`public/app.js`** dosyasına taşınır ve
  `<script src="/app.js">` ile yüklenir (`defer` serbest). `index.html`'de
  inline `<script>` gövdesi, `on*=` özniteliği ve `javascript:` URL'si kalmaz;
  olay işleyiciler `addEventListener` ile bağlanır.
- `lucide` yalnız `<script src="/vendor/lucide-1.48.0.min.js">` ile yüklenir;
  hiçbir `<script src>` şema (`http:`, `https:`, `data:`, `javascript:`) ya da
  `//` ile başlamaz.
- Harici `<link>` (preconnect, stylesheet, font) ve satır içi `<style>`'da
  harici `@import`/`url()` yoktur; `fonts.googleapis.com`/`fonts.gstatic.com`
  sayfada geçmez (Google Fonts tamamen kaldırılır).
- jsdom yükleyicisi (`security/xss.test.ts` → `PublicDirLoader`) aynı kökenli
  `<script src="/…">` / `<link href="/…">` dosyalarını `public/` altından okuyup
  çalıştırır; `public/vendor/*` ve harici URL'ler yüklenmez (`window.lucide`
  taklit edilir). Bu yüzden `app.js`, `window.lucide` yoksa da çalışmalıdır.

### HTTP güvenlik başlıkları — contract K13 (AC-P02-6, AC-P02-7)

`integration/securityHeaders.test.ts`. **Her** yanıtta (HTML, statik `.js`,
`/health`, `200`/`204`, `400` bozuk JSON, `401`, `404`, yabancı Host `403`):
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`. `GET /` ve `GET /index.html` yanıtında
`Content-Security-Policy`; test şu direktifleri **tam değerle** bekler:
`default-src 'self'`, `script-src 'self'`, `object-src 'none'`, `base-uri 'none'`,
`frame-ancestors 'none'`, `form-action 'self'`. Herhangi bir direktifte yalnız
`'self'`, `'none'`, `data:` izinlidir; `'unsafe-inline'` yalnız `style-src`'de
kabul edilir; harici köken, `https:`, `*`, `'unsafe-eval'` yoktur.

### HTTP davranışları — contract K11, K12

- **K11 / AC-P01-18** (`integration/auth.test.ts`): `/api/users` altındaki
  6 rota geçerli Bearer ile `403 forbidden`, mesaj
  `This endpoint requires a browser session`; aynı istekte geçerli çerez olsa
  da `403`; kullanıcı/durum/rol anlık görüntüsü değişmez. Geçersiz ya da eksik
  kimlik `401 unauthenticated`; çerezle `GET` `200`.
- **K12 / AC-P03-11** (`integration/scanSourceHttp.test.ts`): `repo_url`
  `NULL` ya da `''` olan proje için `POST /api/scans` → `400 project_source_missing`,
  mesaj `Project has no repository URL or local path`, `scans` satırı oluşmaz;
  bilinmeyen `projectId` → `404 not_found`.

## AC → test eşlemesi

| Kalem | Dosya |
| --- | --- |
| P-01, AC-G-8, AC-G-9 | `integration/auth.test.ts`, `security/staticCode.test.ts` |
| AC-P01-18 (K11) | `integration/auth.test.ts` |
| P-02 | `security/xss.test.ts` |
| AC-P02-5…7 (D-17) | `security/xss.test.ts` (sayfa yapısı), `integration/securityHeaders.test.ts` (CSP) |
| K13 güvenlik başlıkları | `integration/securityHeaders.test.ts` |
| P-03 | `unit/workspace.test.ts`, `unit/scanSource.test.ts`, `integration/worker.test.ts`, `security/staticCode.test.ts` |
| AC-P03-8…10 (D-18) | `unit/cloneRepoConfig.test.ts` |
| AC-P03-11 (K12) | `integration/scanSourceHttp.test.ts` |
| AC-P08-12 (D-21) | `integration/worker.test.ts` |
| P-04 | `unit/scanSource.test.ts`, `integration/scanSourceHttp.test.ts`, `integration/worker.test.ts` |
| P-05 | `unit/pythonParsers.test.ts`, `integration/worker.test.ts`, `integration/migrations.test.ts` |
| P-06, P-07 | `integration/worker.test.ts`, `unit/pythonParsers.test.ts` |
| P-08 | `unit/findingFingerprint.test.ts`, `integration/worker.test.ts`, `integration/migrations.test.ts` |
| P-09 | `unit/decryptToken.test.ts`, `integration/worker.test.ts`, `security/credentialScan.test.ts` |
| REQ-003 AC-P10-1, AC-P10-3…9 | `unit/parsersGolden.test.ts` |
| REQ-003 AC-P10-7 | `unit/pythonParsers.test.ts`, `unit/parsersGolden.test.ts` |
| REQ-003 AC-P10-10…13, AC-P10-15, AC-P10-18, AC-P10-19 | `unit/parsersDeviations.test.ts` |
| REQ-003 AC-P10-14 | `unit/parserThread.test.ts` |
| REQ-003 AC-P10-15, ADR-005 Karar 1, AC-G-6 | `security/staticCode.test.ts` |
| REQ-003 AC-P10-16, AC-P12-12 (`.env.example`) | `security/staticCode.test.ts`, `security/credentialScan.test.ts` |
| REQ-003 AC-P11-1…13, 15…18 | `integration/migrateTool.test.ts` (AC-P11-14 elle doğrulama: handoff) |
| REQ-003 AC-P12-1, 2, 4…8, 10, 11, 15 | `integration/runtime.test.ts` |
| REQ-003 AC-P12-3 (tek giriş, `WORKER_ID` yok, scripts) | `security/staticCode.test.ts` |
| REQ-003 AC-P12-9, AC-P12-10 (sinyaller) | `unit/processHandlers.test.ts`, `integration/runtime.test.ts` |
| REQ-003 AC-P12-11 (yoklamada kurtarma), ADR-004 Karar 4 (çit) | `integration/scanRetry.test.ts` |
| REQ-003 AC-P13-1 | `unit/retryPolicy.test.ts` |
| REQ-003 AC-P13-2…8, AC-G-8 | `integration/scanRetry.test.ts`, `unit/retryPolicy.test.ts` |
| REQ-003 AC-T-1 (N-1) | `unit/gitIsolation.test.ts`, `integration/gitIsolationReal.test.ts` |
| REQ-003 AC-T-2 (D-18 korunur) | `unit/cloneRepoConfig.test.ts`, `unit/gitIsolation.test.ts`, `integration/gitIsolationReal.test.ts` |
| REQ-003 AC-T-3 (git sürümü) | `unit/gitVersion.test.ts`, `integration/runtime.test.ts`, `integration/scanRetry.test.ts` |
| REQ-003 AC-T-4 (L-5), AC-P13-8 (log) | `unit/errorText.test.ts`, `unit/gitIsolation.test.ts`, `integration/errorTextPersistence.test.ts` |
| REQ-003 AC-T-5 (D-24) | `security/followUpItems.test.ts`, `integration/excelExport.test.ts` (`npm audit --omit=dev` ağ ister; handoff'ta) |
| REQ-003 AC-T-6 (L-2) | `security/followUpItems.test.ts` |
| REQ-003 AC-P12-6 / D-52 (REQ-002 AC-P09-3) | `integration/runtime.test.ts`, `unit/mainEntry.test.ts` |

Bilinen kırmızılar (ürün düzeltmesi bekleniyor): `security/credentialScan.test.ts`
AC-P12-12 (`.env.example`, ana oturum), `unit/errorText.test.ts` "secrets glued
to ANSI colour sequences" (L-5 boşluğu) ve `integration/runtime.test.ts`
"Host allow-list with an ephemeral port" (`port: 0`).

Test adları AC kimliğiyle başlar (`AC-P01-13: …`). Bugün yeşil olan birkaç test
bilinçli regresyon korumasıdır (ör. AC-P07-3, AC-P06-3, hata mesajının
`textContent` ile gösterilmesi, migration testi).

## Kurallar

- Testler `src/`, `public/`, `db/` dosyalarını değiştirmez; yalnız geçici
  dizinlere ve geçici veritabanlarına yazar.
- Ağ çağrısı yok: `fetch` taklit edilir, clone enjekte edilir.
- `tests/` içindeki parola/token benzeri değerler gerçek değildir ve sır
  taramasının dışındadır; gerçek görünümlü (ör. `ghp_…`) değer yazılmaz.
- Sır taraması bulguları yalnız `dosya:satır:kural` olarak raporlar, değeri göstermez.
