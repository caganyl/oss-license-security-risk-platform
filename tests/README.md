# REQ-002 (F1) test paketi

REQ-002 P-01…P-09 için **test-first** Vitest paketi. Testler bugünkü kodda
hatayı yeniden üretir (KIRMIZI); backend/frontend düzeltmesi bu dosyada
tanımlanan arayüzleri uyguladığında YEŞİL olmalıdır (AC-G-2, AC-G-3).

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

Ön koşullar: Node ≥ 20, Python 3.11+ (`PYTHON_BIN`, yoksa Windows'ta
`python`), `git` (yalnız `git ls-files` için). İnternet gerekmez (AC-G-4):
OSV/NVD çağrıları `fetch` taklidiyle, clone işlemi enjekte edilen sahte
`cloneRepo` ile yapılır.

## Klasör yapısı

| Yol | İçerik |
| --- | --- |
| `helpers/paths.ts` | `REPO_ROOT`, `FIXTURES_DIR` |
| `helpers/loadSrc.ts` | `loadSrc` / `loadSrcGuarded`: `src/` modüllerini dinamik yükler; yoksa `MissingImplementationError` |
| `helpers/contracts.ts` | Testlerin beklediği TypeScript arayüzleri (aşağıdaki tablonun makine okunur hâli) |
| `helpers/pgCluster.ts` | embedded-postgres kümesi, migrate edilmiş şablon DB, CREATE/DROP DATABASE |
| `helpers/db.ts` | `useTestDatabase({ scope: 'file' \| 'test' })` — dosya ya da test başına DB |
| `helpers/pgGlobalSetup.ts` | İsteğe bağlı Vitest `globalSetup` (tek küme) — henüz kayıtlı değil |
| `helpers/migrations.ts` | `db/migrations/*.up.sql`'i `migrate.sh` gibi uygular |
| `helpers/psqlScript.ts` | psql betiğini düz SQL'e çevirir (`\ir` içe alınır, `\set`/`\echo` atılır) |
| `helpers/http.ts` | supertest yardımcıları (Host/Origin, çerez, setup/login, hata gövdesi kontrolü) |
| `helpers/tokenCrypto.ts` | AES-256-GCM token şifreleme (test verisi, gerçek sır değil) |
| `fixtures/p05-ranges-no-lockfile` | Kilit dosyasız iki `package.json` (aynı paketin iki aralığı) + `requirements.txt` |
| `fixtures/p07-dev-scope` | devDependency, `requirements-dev.txt`, Poetry dev grubu |
| `unit/` | Saf fonksiyonlar ve Python ayrıştırıcı çıktısı |
| `integration/` | Gerçek PostgreSQL ile HTTP ve worker testleri, migration testi |
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
// `npm start` (node dist/app.js) için: if (require.main === module) startServer({ db: pool })
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

### `src/scanner/worker.ts` — P-03, P-04 (worker), P-05…P-09

```ts
export function decryptToken(encrypted: Buffer | null | undefined, keyString?: string): string | null;
export interface ScanWorkerDeps {
  db: Pool;                                  // vars. ../lib/db pool
  cloneRepo: CloneRepoFn;                    // vars. workspace.cloneRepo
  runParser: (workDir: string, ecosystems: string[], scanId: string) => Promise<SandboxScanResult>; // vars. Python ayrıştırıcı (PYTHON_BIN)
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

### Python ayrıştırıcı çıktı sözleşmesi (P-05, P-07)

`python -m src.scanner.sandbox.parsers.scan` çıktısında her bağımlılık:
`version` = kesin sürüm veya `null` (`'unknown'` yok), `declared_range` =
manifestteki aralık veya `null`, sürüm `null` ise purl sürümsüz.
`requirements-dev.txt` ve Poetry dev grupları `scope: 'dev'`. `src/types/scan.ts`
buna göre güncellenir (`version: string | null; declared_range?: string | null`).

### Frontend (`public/index.html`) — P-02

Ek export yok. Test, sayfayı jsdom'da `fetch` taklidiyle açar ve
`[data-view="projects|findings|users"]` gezinme öğelerine tıklar; açılışta
`GET /api/auth/me` `401` ise sayfada `input[type="password"]` beklenir; formun
gönderimi (`requestSubmit` ya da formdaki buton) `POST /api/auth/login` çağırır.

## AC → test eşlemesi

| Kalem | Dosya |
| --- | --- |
| P-01, AC-G-8, AC-G-9 | `integration/auth.test.ts`, `security/staticCode.test.ts` |
| P-02 | `security/xss.test.ts` |
| P-03 | `unit/workspace.test.ts`, `unit/scanSource.test.ts`, `integration/worker.test.ts`, `security/staticCode.test.ts` |
| P-04 | `unit/scanSource.test.ts`, `integration/scanSourceHttp.test.ts`, `integration/worker.test.ts` |
| P-05 | `unit/pythonParsers.test.ts`, `integration/worker.test.ts`, `integration/migrations.test.ts` |
| P-06, P-07 | `integration/worker.test.ts`, `unit/pythonParsers.test.ts` |
| P-08 | `unit/findingFingerprint.test.ts`, `integration/worker.test.ts`, `integration/migrations.test.ts` |
| P-09 | `unit/decryptToken.test.ts`, `integration/worker.test.ts`, `security/credentialScan.test.ts` |

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
