# Veritabanı ve Göçler

PostgreSQL 15+ beklenir. Şema `db/migrations/` altındaki sıralı göç
dosyalarıyla yönetilir ve Node göç aracıyla (`npm run db:migrate`,
`src/db/migrate.ts`) uygulanır. Uygulanan sürümler hedef veritabanındaki
`schema_migrations` tablosunda tutulur. Araç yalnız Node.js ve `pg` kullanır;
Git Bash, `bash` veya `PATH`'te `psql` gerekmez (REQ-003 P-11, ADR-004).

## İçindekiler

- [Dosyalar](#dosyalar)
- [Göç kataloğu](#göç-kataloğu)
- [Windows'ta çalıştırma (PowerShell)](#windowsta-çalıştırma-powershell)
- [Komutlar ve çıkış kodları](#komutlar-ve-çıkış-kodları)
- [Kilit davranışı](#kilit-davranışı)
- [Geri alma (`down --to`)](#geri-alma-down---to)
- [Tam sıfırlama](#tam-sıfırlama)
- [Göç testleri](#göç-testleri)
- [Kayıt defteri önbelleği (`006`)](#kayıt-defteri-önbelleği-006)
- [Parola kurtarma (SQL adımı)](#parola-kurtarma-sql-adımı)
- [Kurallar](#kurallar)

## Dosyalar

| Yol | Amaç |
| --- | --- |
| `migrations/NNN_ad.up.sql` / `.down.sql` | İleri / geri göç. Araç her dosyayı, `schema_migrations` kaydıyla (`up`'ta `INSERT`, `down`'da `DELETE`) birlikte **tek transaction** içinde çalıştırır: ya ikisi birden işlenir ya hiçbiri. Dosyalarda `BEGIN/COMMIT` yoktur. |
| `schema.sql` | `001`–`006` sonrası şemanın **referans görüntüsü**. Araçla yönetilen bir veritabanına yüklenmez (`schema_migrations` doldurmaz; sonraki `npm run db:migrate` her nesneyi yeniden oluşturmaya çalışıp hata verir, `npm start` de tüm göçleri bekleyen görüp başlamaz). Her yeni göçle senkron tutulur. |
| `tests/f1_migrations_test.sql` | `002`–`004` için up → assert → down → up senaryosu. `psql` gerektirmez: `npm test` bunu `tests/integration/migrations.test.ts` içinde gömülü PostgreSQL'e karşı çalıştırır (`\ir` satırları satır içine alınır). Bulgu parmak izi referans değerleri de buradadır. |
| `../src/db/migrate.ts` | CLI (`npm run db:migrate` = `node dist/db/migrate.js`). |
| `../src/db/migrator.ts` | Göç kütüphanesi: klasör doğrulama, durum okuma, `up`, `down`, `status`, `npm start` için bekleyen göç kontrolü. |
| `../src/db/advisoryLock.ts` | Uygulama ve göç aracının ortak tek örnek kilidi. |

## Göç kataloğu

| Sürüm | Kapsam | Karar | Geri alma veri kaybı |
| --- | --- | --- | --- |
| `001_initial_core_schema` | Çekirdek şema, enum'lar, rol/lisans/ayar tohumları | — | **Tüm veri** (araç `001`'i geri almaz; bkz. [Tam sıfırlama](#tam-sıfırlama)) |
| `002_local_auth` | `users.password_hash`, `password_changed_at`; `sessions`; `api_keys` (kullanıcı başına tek aktif anahtar) | ADR-001, D-16 | Parola, tüm oturumlar ve tüm API anahtarları |
| `003_declared_range` | `packages.version` NULL olabilir; `scan_dependencies.declared_range`; sürümsüz paket için kısmi benzersiz indeks; mevcut veride aralıkların taşınması | ADR-003 (a) | Manifest başına aralıklar (yalnız en son aralık `version`'a geri yazılır) |
| `004_finding_fingerprint` | `findings.fingerprint` (backfill + NOT NULL), `carried_from_finding_id`, indeksler | ADR-003 (c), D-1 | Parmak izi (yeniden hesaplanabilir) ve karar taşıma bağlantısı (kalıcı) |
| `005_scan_next_attempt` | `scans.next_attempt_at TIMESTAMPTZ NULL` (yeniden deneme bekleme zamanı); indeks ve CHECK yok | ADR-004 Karar 11, D-40 | Yalnız kuyruktaki taramaların yeniden deneme zamanlaması (bekleyenler hemen sahiplenilebilir olur) |
| `006_registry_enrichment` | `registry_package_cache` (kayıt defteri lisans meta veri önbelleği), `registry_archive_cache` (arşivden çıkarılan lisans dosyaları ve telif satırları); `scan_dependencies`'e 7 kolon: `license_expression`, `license_source`, `license_lock_hint`, `license_hint_differs`, `license_enrichment_status`, `notice_status`, `notice_archive_id` (FK, `ON DELETE SET NULL`); `idx_scan_dependencies_notice_archive`. Veri taşıma yok; eski satırlar `NULL` kalır (= F3 öncesi tarama) | ADR-006 Karar 9–10, D-57, D-62, D-79 | İki önbellek (kayıt defterlerinden yeniden indirilebilir) ve F3 sonrası taramaların etkin lisans / NOTICE alanları (kalıcı; bu taramalar F3 öncesi gibi görünür, NOTICE için yeniden tarama gerekir) |

**Dağıtım sırası:**

- `004` sonrasında `findings.fingerprint` zorunludur; parmak izi yazmayan eski
  worker kodu her taramada hata alır. `004`, REQ-002 worker değişikliğiyle
  birlikte uygulanır.
- `005`, REQ-003 çalışma zamanından **önce** uygulanır. `npm start` bekleyen göç
  varsa başlamaz ve `npm run db:migrate` komutunu söyler (D-35); göçleri
  kendisi uygulamaz. `005`'i geri almak REQ-003 kodunu geri almakla birlikte
  yapılır (yeni worker kolonu okur/yazar). REQ-003 öncesi kod kolonu yok sayar.
- `006`, REQ-004 çalışma zamanından **önce** uygulanır (worker, SBOM, rapor ve
  NOTICE kodu yeni tabloları ve kolonları okur/yazar; `npm start` göç bekliyorsa
  başlamaz). `006`'yı geri almak REQ-004 kodunu geri almakla birlikte yapılır.
  REQ-004 öncesi kod yeni tabloları ve kolonları yok sayar.
- Veritabanında dosyası olmayan bir sürüm varsa (veritabanı koddan yeni) ne
  araç (`up`/`down`) ne `npm start` çalışır; önce kodu güncelleyin.

## Windows'ta çalıştırma (PowerShell)

### Ön koşullar

1. Node.js `^22.21.0 || >=24.5.0` (REQ-004, ADR-006 Karar 5) ve yerel PostgreSQL ≥ 15 (Windows kurulum paketi). `psql`'in
   `PATH`'te olması gerekmez.
2. Repo kökünde `.env` (`.env.example`'dan kopyalanır) veya oturumda
   `DATABASE_URL`. Parola URL içinde ya da `PGPASSWORD` ile verilir:

   ```powershell
   # .env (git'e girmez) — yer tutucuları kendi değerlerinizle değiştirin
   # DATABASE_URL=postgres://<kullanici>:<parola>@localhost:5432/<veritabani>

   # veya yalnız bu oturum için, parolasız URL + PGPASSWORD:
   $env:DATABASE_URL = "postgres://<kullanici>@localhost:5432/<veritabani>"
   $env:PGPASSWORD   = "<parola>"      # iş bitince: Remove-Item Env:PGPASSWORD
   ```

   Parolayı bu dosyaya veya commit edilen başka bir dosyaya yazmayın. Araç
   hiçbir çıktıda bağlantı dizesini, parolayı, sunucu ya da veritabanı adını
   yazmaz; bağlantı hataları yalnız kodla (`ECONNREFUSED`, `28P01`, `3D000` …)
   bildirilir.

### Uygulama adımları

1. Uygulamayı (`npm start`) durdurun. Çalışırken araç kilit nedeniyle reddeder
   (çıkış kodu 4); bkz. [Kilit davranışı](#kilit-davranışı).
2. **Yedek alın** (özellikle veri dönüştüren göçlerden ve her `down`'dan önce).
   `pg_dump`, PostgreSQL kurulumunun `bin` klasöründedir (sürüm klasörünü kendi
   kurulumunuza göre değiştirin; parola sorulursa girin veya `PGPASSWORD`
   kullanın). pgAdmin'in "Backup…" menüsü de aynı işi yapar.

   ```powershell
   & "C:\Program Files\PostgreSQL\<sürüm>\bin\pg_dump.exe" `
       --host=localhost --port=5432 --username=<kullanici> --dbname=<veritabani> `
       --format=custom --file="oss_risk_$(Get-Date -Format yyyyMMdd_HHmmss).dump"
   ```

3. Derleyin ve göçleri uygulayın (repo kökünden). Araç derlenmiş çıktıyla
   çalışır ve kendisi derleme yapmaz; kod değiştiyse önce `npm run build`:

   ```powershell
   npm ci
   npm run build
   npm run db:migrate
   ```

   Her sürüm için `uygulandı <sürüm> (<ms> ms)` veya `atlandı <sürüm>` yazılır.
   İkinci çalıştırmada hepsi `atlandı` olur ve çıkış kodu 0'dır. Bir göç hata
   verirse o sürümün değişiklikleri ve kaydı birlikte geri alınır, önceki
   sürümler uygulanmış kalır, sonrakiler denenmez; mesaj sürüm adını,
   PostgreSQL hata kodunu ve varsa satır numarasını içerir (çıkış kodu 1).
4. Durumu kontrol edin:

   ```powershell
   npm run db:migrate -- status
   ```

5. Uygulamayı başlatın (`npm start`).

`F1`'de `db/migrate.sh` ile uygulanmış bir veritabanı (aynı `schema_migrations`
tablosu ve sürüm adları) araç tarafından olduğu gibi tanınır: yalnız eksik
sürümler (`005`) uygulanır, hiçbir tablo yeniden oluşturulmaz.

`003` ve `004`, beklenmeyen veri bulduğunda açık bir hatayla durur (ör. aynı
paket için birden çok sürümsüz satır, parmak izi üretilemeyen bulgu); bu
durumda veri insan kararıyla düzeltilmeden tekrar denenmez.

Göçler (ve `schema.sql`) hiçbir kullanıcı tohumlamaz; yalnız roller, lisans
kataloğu ve sistem ayarları tohumlanır. İlk (yerel admin) kullanıcıyı yalnız
uygulamanın ilk açılış (setup) akışı oluşturur (ADR-001 karar 2).

Production veritabanına göç uygulamak insan onayı gerektirir.

## Komutlar ve çıkış kodları

| Komut | Davranış |
| --- | --- |
| `npm run db:migrate` veya `npm run db:migrate -- up` | Bekleyen sürümleri dosya adı sırasıyla uygular. `schema_migrations` yoksa oluşturur. |
| `npm run db:migrate -- status` | Uygulanmış (`applied_at` ile), bekleyen ve bilinmeyen sürümleri listeler. **Hiçbir şey yazmaz**; `schema_migrations` yoksa oluşturmaz, tüm sürümleri bekleyen gösterir. |
| `npm run db:migrate -- down --to <hedef>` | Hedeften sonraki uygulanmış sürümleri ters sırayla geri alır; hedef uygulanmış kalır. `<hedef>`: tam ad (`003_declared_range`) veya üç haneli numara (`003`); `--to=003` biçimi de kabul edilir. |
| `npm run db:migrate -- down` (hedefsiz), bilinmeyen komut/argüman | Kullanım metni yazar, hiçbir şey yapmaz (çıkış kodu 2). |
| `npm run db:migrate -- --help` | Kullanım metni (çıkış kodu 0). |

PowerShell `--` ayracını yutarsa (bazı npm/PowerShell sürüm birleşimlerinde
argümanlar araca ulaşmaz) aynı komutu doğrudan çalıştırın:
`node dist/db/migrate.js status`, `node dist/db/migrate.js down --to 003`.

| Kod | Anlam |
| --- | --- |
| 0 | Başarı (değişiklik olmasa da) |
| 1 | Göç SQL hatası veya bağlantı hatası |
| 2 | Kullanım/yapılandırma hatası: bilinmeyen komut, hedefsiz `down`, `DATABASE_URL` yok |
| 3 | Durum reddi: klasör doğrulaması, bilinmeyen sürüm, geçersiz/uygulanmamış hedef, sıra dışı bekleyen sürüm (hiçbir değişiklik yapılmaz) |
| 4 | Kilit başka süreçte: uygulama çalışıyor veya başka bir göç sürüyor (hiçbir değişiklik yapılmaz) |

Araç her komuttan önce göç klasörünü doğrular (kural ihlalinde çıkış kodu 3):
dosya adı `^(\d{3})_([a-z0-9_]+)\.(up|down)\.sql$`, her `up`'ın `down` eşi (ve
tersi), üç haneli numara benzersiz, dosyada satır başında `BEGIN;`, `COMMIT;`,
`ROLLBACK;`, `START TRANSACTION` ya da `\` ile başlayan `psql` meta komutu yok,
geçerli UTF-8. Baştaki UTF-8 BOM atılır, CRLF satır sonları LF'ye çevrilir.
`.sql` olmayan dosyalar yok sayılır.

**Sıra dışı bekleyen sürüm:** bekleyen bir sürümün numarası, uygulanmış en
büyük numaradan küçükse `up` hiçbir şey uygulamadan reddeder. Yeni göç her
zaman en büyük numaradan sonra eklenir.

## Kilit davranışı

- Uygulama (`npm start`) ve göç aracı aynı PostgreSQL oturum düzeyi advisory
  lock'u kullanır: `pg_try_advisory_lock(1330860882, 1)` (anahtar sabittir,
  değiştirilmez). Kilit veritabanı başınadır.
- Araç `status` dahil her komutta kilidi alır, komut boyunca tek bağlantıda
  tutar ve sonunda bırakır. Kilit başkasındaysa beklemeden çıkış kodu 4 ile
  reddeder. Uygulama da kilit başkasındaysa (çalışan başka bir örnek veya süren
  bir göç) başlamaz.
- Süreç çökerse veya bağlantı koparsa PostgreSQL kilidi oturumla birlikte
  bırakır; ayrıca temizlik gerekmez.
- Kilidi kimin tuttuğunu görmek için (salt okuma):

  ```sql
  SELECT a.pid, a.application_name, a.backend_start
  FROM   pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
  WHERE  l.locktype = 'advisory' AND l.classid = 1330860882 AND l.objid = 1
    AND  l.objsubid = 2 AND l.granted;
  ```

  `application_name` uygulama için `oss-risk:instance`, araç için
  `oss-risk:migrate`'tir.
- Göç sırasında Ctrl+C ile kesilirse PostgreSQL açık transaction'ı geri alır;
  o sürüm uygulanmamış kalır, öncekiler uygulanmış kalır. Durumu
  `status` ile kontrol edip `up`'ı yeniden çalıştırın.

## Geri alma (`down --to`)

> **Uyarı:** `down` veri siler (her sürümün kaybı [Göç kataloğu](#göç-kataloğu)
> tablosunda ve `.down.sql` dosyasının başında yazılıdır). Geri alma kararı
> insan onayı gerektirir; önce uygulamayı durdurun ve **yedek alın**.

Örnek: `005` ve `004`'ü geri al, `003` uygulanmış kalsın:

```powershell
npm run db:migrate -- down --to 003
```

- Araç geri alınacak sürümleri işe başlamadan önce listeler
  (`geri alınacak (sırayla): 005_…, 004_…`), sonra her birini ayrı
  transaction'da (`.down.sql` + `DELETE FROM schema_migrations`) geri alır.
- Bir geri alma başarısız olursa o sürüm uygulanmış kalır, öncekiler geri
  alınmış kalır (çıkış kodu 1).
- Hedef uygulanmamışsa veya böyle bir sürüm yoksa hiçbir şey yapılmaz (çıkış
  kodu 3). Hedefsiz `down` reddedilir (çıkış kodu 2).
- `001` araçla geri alınamaz (`001`'in altında hedef yoktur); en fazla
  `down --to 001` ile `002` ve sonrası geri alınır.
- Geri alınan sürümler `npm run db:migrate` ile yeniden uygulanır.

## Tam sıfırlama

Bütün tabloları ve verileri silip sıfırdan başlamak (yalnız geliştirme
veritabanı; production için insan onayı gerekir):

1. Uygulamayı durdurun, yedek alın.
2. Veritabanını silip yeniden oluşturun: pgAdmin'de veritabanına sağ tıklayıp
   "Delete (Force)" ve "Create > Database…", ya da `postgres` veritabanına
   bağlıyken şu SQL (yer tutucuları değiştirin):

   ```sql
   DROP DATABASE IF EXISTS <veritabani> WITH (FORCE);
   CREATE DATABASE <veritabani> OWNER <kullanici>;
   ```

3. `npm run db:migrate` ile tüm göçleri uygulayın, `npm start` ile başlatıp
   ilk açılış (setup) akışından admin parolasını belirleyin.

## Göç testleri

Göç testleri `npm test` (Vitest) içinde gömülü PostgreSQL'e karşı çalışır;
`psql`, Git Bash veya Docker gerekmez. Test kümeleri, Türkçe locale'li
Windows'ta `initdb` başarısız olduğu için `--locale=C --encoding=UTF8` ile
açılır. Testler uygulamanın kendi veritabanına asla bağlanmaz.

- `db/tests/f1_migrations_test.sql`: `001`–`004` up, eski biçimli örnek veri,
  doğrulamalar, `004` → `003` → `002` down, yeniden up; tek transaction'da
  çalışır ve sonda `ROLLBACK` edilir.
- Göç aracı ve `005` (up → down → up, kilit, çıkış kodları, klasör
  doğrulaması, BOM/CRLF): REQ-003 Vitest göç testleri (`tests/`).
- `006` (up → down → up, CHECK kümeleri, `ON DELETE SET NULL`, `schema.sql`
  eşitliği): REQ-004 AC-G-7 Vitest göç testleri (`tests/`, qa-automation).

## Kayıt defteri önbelleği (`006`)

REQ-004 (F3) lisans zenginleştirmesi, npm ve PyPI'dan aldığı sonuçları iki
tabloda kalıcı olarak önbelleğe alır (ADR-006 Karar 9–10, D-57). Kayıtlar
tarama sonucu transaction'ından **bağımsız**, istek sonuçlandığı anda kendi
transaction'ında yazılır; iptal edilen veya geri alınan bir tarama önbelleği
silmez (AC-P14-8). İçerik herkese açık kayıt defterlerinden yeniden
indirilebilir; önbellek her zaman güvenle temizlenebilir.

| Tablo | Anahtar | İçerik | Geçerlilik |
| --- | --- | --- | --- |
| `registry_package_cache` | `(ecosystem, name, version)` — `ecosystem` `npm`/`pypi`, `name` istek adı (npm olduğu gibi, PyPI PEP 503), kesin sürüm | `outcome` (`found`/`not_found`), türetilmiş `declared_license`, PyPI uzun lisans metni `license_text` (NOTICE yedeği, ≤ 1 MiB), `archive_candidates` (arşiv URL'si, özet, boyut), `extractor_version` | `found`: süresiz (koddaki `METADATA_EXTRACTOR_VERSION` artınca yenilenir). `not_found` (404/410): `expires_at` = yazım + 24 saat, veritabanı saatiyle. Geçici hatalar hiç yazılmaz. |
| `registry_archive_cache` | `id` (UUID); benzersiz `registry_archive_cache_key` = `(ecosystem, name, version, archive_digest)` | `outcome` (`collected`/`no_license_file`/`unsupported_format`/`limit_exceeded`), `outcome_detail`, `license_files` (`[{path,text}` \| `{path,omitted}]`), `copyright_lines`, arşiv URL'si/boyutu, `extractor_version` | Süresiz; `ARCHIVE_EXTRACTOR_VERSION` artınca aynı `id` ile yerinde güncellenir. İndirme/bütünlük/iş parçacığı hataları ve bütçe aşımı yazılmaz. |

Taramaya bağlı alanlar `scan_dependencies` satırındadır (`license_expression`,
`license_source`, `license_lock_hint`, `license_hint_differs`,
`license_enrichment_status`, `notice_status`, `notice_archive_id`). Değer
kümeleri `docs/contracts/REQ-004-notice-and-outputs.md` bölüm 4 ile birebir
aynıdır ve `CHECK` kısıtlarıyla korunur. `license_source` ile
`license_enrichment_status` birlikte yazılır (`scan_dependencies_license_f3_together`);
ikisi de `NULL` ise tarama F3 öncesidir. `notice_archive_id`,
`registry_archive_cache(id)`'ye `ON DELETE SET NULL` ile bağlıdır.

### Önbelleği temizleme (SQL)

pgAdmin Query Tool'unda (uygulamanın veritabanına bağlıyken) veya `psql` ile
çalıştırılır. Production veritabanında veri silmek insan onayı gerektirir.
Temizlik sırasında süren bir tarama, sonuç yazımında silinmiş arşiv kaydına
başvurursa geçici veritabanı hatası alıp yeniden denenir (ADR-006 Karar 10);
bunu önlemek için önce uygulamayı durdurun.

```sql
-- Tüm önbellek (sonraki taramalar kayıt defterlerinden yeniden indirir):
BEGIN;
DELETE FROM registry_archive_cache;
DELETE FROM registry_package_cache;
COMMIT;

-- Yalnız negatif kayıtlar (404/410; yeni yayımlanmış bir paketin hemen
-- yeniden sorgulanması için):
DELETE FROM registry_package_cache WHERE outcome = 'not_found';

-- Yalnız süresi dolmuş negatif kayıtlar (isteğe bağlı bakım; süresi dolmuş
-- kayıt zaten ıskalama sayılır ve bir sonraki sorguda üzerine yazılır):
DELETE FROM registry_package_cache WHERE outcome = 'not_found' AND expires_at <= NOW();
```

- `registry_archive_cache` silindiğinde eski taramaların
  `scan_dependencies.notice_archive_id` değeri otomatik olarak `NULL` olur;
  taramanın etkin lisansı ve `notice_status` değişmez. Bu taramaların NOTICE
  dosyasında ilgili girdiler `license file data no longer cached; rescan required`
  notuyla listelenir; metin için yeniden tarama gerekir. SBOM telif alanı da
  önbellekten okunduğu için aynı şekilde boşalır.
- `registry_package_cache` silmek eski taramaları etkilemez; yalnız PyPI
  NOTICE yedek lisans metni (`license_text`) okunamaz hale gelir.
- Çıkarım mantığı değiştiğinde önbelleği elle silmek gerekmez: kod sabiti
  (`METADATA_EXTRACTOR_VERSION` / `ARCHIVE_EXTRACTOR_VERSION`) artırılır, eski
  sürümlü kayıtlar ıskalama sayılır.

### Kullanılmayan `packages` kolonları (D-79)

`packages.copyright_text`, `notice_text`, `metadata` ve `enriched_at`
kolonları `001`'den beri vardır ve hiç doldurulmaz. `006` bunları
**kullanmaz ve silmez**: `packages` satırları sürümsüz olabilir ve tarama
transaction'ında yazılıp geri alınabilir, bu yüzden kalıcı önbellek ihtiyacını
karşılamaz (ADR-006 Karar 9). SBOM telif bilgisi artık
`registry_archive_cache.copyright_lines`'tan okunur. Kolonların silinmesi ayrı
bir temizlik kararı ve ayrı bir göçtür; `006` geri alındığında da dokunulmaz.

## Parola kurtarma (SQL adımı)

Arayüz veya API üzerinden parola kurtarma ya da değiştirme yoktur (ADR-001
karar 12, D-11, D-15, AC-P01-16). Unutulan parola, makineye ve veritabanına
erişimi olan kişi tarafından aşağıdaki tek transaction ile sıfırlanır.

> **Önce uygulamayı durdurun** (`npm start` penceresinde Ctrl+C). Kurtarmadan
> sonra uygulama açılır açılmaz ilk açılış (setup) akışını **hemen**
> tamamlayın: parolasız durumda uygulamaya ilk erişen kişi admin parolasını
> belirleyebilir.

SQL'i pgAdmin'in Query Tool'unda (uygulamanın veritabanına bağlıyken) veya
varsa `psql` ile çalıştırın:

```sql
BEGIN;
-- Parolayı temizle: ilk açılış (setup) akışı yeniden açılır.
UPDATE users
SET    password_hash = NULL,
       password_changed_at = NULL,
       updated_at = NOW()
WHERE  password_hash IS NOT NULL;
-- Tüm tarayıcı oturumlarını kapat.
DELETE FROM sessions;
-- api_keys tablosuna varsayılan olarak DOKUNULMAZ. Anahtarın ele geçirildiğinden
-- şüpheleniyorsanız aşağıdaki satırın yorumunu kaldırın (tüm aktif anahtarlar
-- iptal edilir; setup sonrası yeni anahtar üretilir):
-- UPDATE api_keys SET revoked_at = NOW() WHERE revoked_at IS NULL;
COMMIT;
```

Sonrasında:

1. `SELECT count(*) FROM users WHERE password_hash IS NOT NULL;` sonucu `0`
   olmalıdır. Uygulama korumalı isteklerde `401` + `code: "setup_required"`
   döner; arayüz parola belirleme ekranını gösterir.
2. Uygulamayı başlatın ve yeni parolayı ilk açılış akışıyla hemen belirleyin
   (en az 12 karakter). Parola aynı kullanıcıya atanır; mevcut kayıtların
   atıfları korunur.
3. **API anahtarları kurtarmadan etkilenmez** (yukarıdaki isteğe bağlı satır
   çalıştırılmadıysa). Anahtarın ele geçirildiğinden şüpheleniliyorsa yeni
   parolayla giriş yaptıktan sonra anahtar `DELETE /api/auth/api-keys/{id}`
   ile de iptal edilebilir.

## Kurallar

- Yeni şema değişikliği yalnız yeni bir `NNN_ad.up.sql` + `.down.sql` çiftiyle,
  uygulanmış en büyük numaradan sonra yapılır; **uygulanmış bir göç dosyası
  değiştirilmez**, düzeltme yeni göçle yapılır (araç checksum saklamaz; `001`…
  `005`'in normalize içerik özetleri testle sabitlenir).
- Her `.down.sql`, kaybolacak veriyi dosya başında açıkça yazar.
- Göç dosyaları `BEGIN/COMMIT/ROLLBACK/START TRANSACTION` ve `psql` meta
  komutu içermez; araç her dosyayı kendi transaction'ında çalıştırır.
  `DO $$ BEGIN … END $$` blokları serbesttir.
- `CREATE INDEX CONCURRENTLY`, `VACUUM` gibi transaction dışında çalışması
  gereken ifadeler kullanılmaz.
- Beklenmeyen veri sessizce düzeltilmez; göç `RAISE EXCEPTION` ile durur.
- Bu klasördeki hiçbir dosyada gerçek parola, token veya bağlantı sırrı
  bulunmaz; örneklerde yalnız `<kullanici>`, `<veritabani>`, `<parola>` gibi
  yer tutucular kullanılır.
- `schema.sql` her yeni göçle güncellenir.
