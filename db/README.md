# Veritabanı ve Migration'lar

PostgreSQL 15+ beklenir. Şema `db/migrations/` altındaki sıralı migration
dosyalarıyla yönetilir ve `db/migrate.sh` ile uygulanır; uygulanan sürümler
hedef veritabanındaki `schema_migrations` tablosunda tutulur.

## İçindekiler

- [Dosyalar](#dosyalar)
- [Migration kataloğu](#migration-kataloğu)
- [Windows'ta çalıştırma (Git Bash + migrate.sh)](#windowsta-çalıştırma-git-bash--migratesh)
- [Geri alma (rollback)](#geri-alma-rollback)
- [Migration testi](#migration-testi)
- [Parola kurtarma (SQL adımı)](#parola-kurtarma-sql-adımı)
- [Kurallar](#kurallar)

## Dosyalar

| Yol | Amaç |
| --- | --- |
| `migrations/NNN_ad.up.sql` / `.down.sql` | İleri / geri migration; `migrate.sh` her dosyayı tek transaction içinde çalıştırır (dosyalarda `BEGIN/COMMIT` yoktur). |
| `migrate.sh` | Bash + `psql` ile migration çalıştırıcı (F1 yöntemi, AC-G-10; Node aracı F2/P-11). |
| `schema.sql` | 001–004 sonrası şemanın **referans görüntüsü**. `migrate.sh` ile yönetilen bir veritabanına yüklenmez (`schema_migrations` doldurmaz; sonraki `up` hata verir). Her yeni migration'la senkron tutulur. |
| `tests/f1_migrations_test.sql` | 002–004 için up → down → up testi; yalnız boş, atılabilir test veritabanında çalışır. |

## Migration kataloğu

| Sürüm | Kapsam | Karar | Geri alma veri kaybı |
| --- | --- | --- | --- |
| `001_initial_core_schema` | Çekirdek şema, enum'lar, rol/lisans/ayar tohumları | — | **Tüm veri** (bütün tablolar silinir) |
| `002_local_auth` | `users.password_hash`, `password_changed_at`; `sessions`; `api_keys` (kullanıcı başına tek aktif anahtar) | ADR-001, D-16 | Parola, tüm oturumlar ve tüm API anahtarları |
| `003_declared_range` | `packages.version` NULL olabilir; `scan_dependencies.declared_range`; sürümsüz paket için kısmi benzersiz indeks; mevcut veride aralıkların taşınması | ADR-003 (a) | Manifest başına aralıklar (yalnız en son aralık `version`'a geri yazılır) |
| `004_finding_fingerprint` | `findings.fingerprint` (backfill + NOT NULL), `carried_from_finding_id`, indeksler | ADR-003 (c), D-1 | Parmak izi (yeniden hesaplanabilir) ve karar taşıma bağlantısı (kalıcı) |

**Dağıtım sırası:** `004` sonrasında `findings.fingerprint` zorunludur; parmak
izi yazmayan eski worker kodu her taramada hata alır. `004`, REQ-002 worker
değişikliğiyle birlikte uygulanır. `002` ve `003` mevcut kodla geriye dönük
uyumludur.

## Windows'ta çalıştırma (Git Bash + migrate.sh)

F1'de migration'lar yalnızca Git Bash içinden `db/migrate.sh` ile çalıştırılır
(ADR-003 (d), AC-G-10). PowerShell'den elle `psql -f` birincil yöntem değildir
(sıra ve `schema_migrations` kaydı kaçabilir).

### Ön koşullar

1. **Git for Windows** (Git Bash) kurulu.
2. **`psql` PATH'te.** PostgreSQL'in Windows kurulumu PATH'e eklemez; Git Bash
   oturumunda ekleyin (sürüm klasörünü kendi kurulumunuza göre değiştirin):

   ```sh
   export PATH="/c/Program Files/PostgreSQL/<sürüm>/bin:$PATH"
   psql --version
   ```

3. **İstemci kodlaması UTF-8:**

   ```sh
   export PGCLIENTENCODING=UTF8
   ```

4. **LF satır sonları.** Repodaki `.gitattributes`, `*.sh` ve `*.sql` için
   `eol=lf` zorlar; CRLF `set -euo pipefail`'i ve SQL'i bozar. Depo bu ayardan
   önce klonlandıysa dosyaları yeniden çıkarın.
5. **Bağlantı bilgisi ve parola.** Parolayı komut satırına veya bu dosyaya
   yazmayın. `DATABASE_URL`'i parolasız verin; parolayı `PGPASSWORD` ortam
   değişkeni (yalnız o oturum için) ya da `%APPDATA%\postgresql\pgpass.conf`
   dosyasıyla sağlayın:

   ```sh
   export DATABASE_URL="postgres://<kullanici>@localhost:5432/<veritabani>"
   read -rs PGPASSWORD && export PGPASSWORD   # parolayı ekrana basmadan girer
   ```

### Uygulama adımları

1. API sunucusunu ve tarama worker'ını durdurun (migration'lar `users`,
   `packages`, `scan_dependencies`, `findings` üzerinde transaction boyunca
   özel kilit tutar).
2. Yedek alın:

   ```sh
   pg_dump --format=custom --file="oss_risk_$(date +%Y%m%d_%H%M%S).dump" "$DATABASE_URL"
   ```

3. Bekleyen migration'ları uygulayın (repo kökünden):

   ```sh
   bash db/migrate.sh up
   ```

   Çıktıda her sürüm için `Applying …` veya `Skipping …` görünür. Bir hata
   olursa o migration'ın transaction'ı geri alınır ve betik durur.
4. Uygulanan sürümleri kontrol edin:

   ```sh
   psql "$DATABASE_URL" -c "SELECT version, applied_at FROM schema_migrations ORDER BY version;"
   ```

`003` ve `004`, beklenmeyen veri bulduğunda açık bir hata mesajıyla durur
(ör. aynı paket için birden çok sürümsüz satır, parmak izi üretilemeyen bulgu);
bu durumda veri insan kararıyla düzeltilmeden tekrar denenmez.

Production veritabanına migration uygulamak insan onayı gerektirir.

## Geri alma (rollback)

> **Uyarı:** `bash db/migrate.sh down` uygulanmış **tüm** migration'ları ters
> sırayla geri alır; `001` dahil olduğundan **bütün tablolar ve veriler
> silinir**. Tek bir migration'ı geri almak için bu komutu kullanmayın.

Yalnız en son migration'ı geri almak (örnek: `004`), Git Bash'te:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction \
  -f db/migrations/004_finding_fingerprint.down.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "DELETE FROM schema_migrations WHERE version = '004_finding_fingerprint';"
```

Geri alma her zaman ters sırayla yapılır (`004` → `003` → `002`). Her
`.down.sql` dosyasının başında hangi verinin kaybolacağı yazılıdır; geri
almadan önce yedek alın. Rollback kararı insan onayı gerektirir.

## Migration testi

`tests/f1_migrations_test.sql` boş bir test veritabanında `001` + `002`'yi
uygular, eski biçimde (aralığın `version`'da durduğu) örnek veri yükler,
`003` ve `004`'ü uygulayıp sonucu doğrular, bağımsız hesaplanmış referans
parmak izleriyle karşılaştırır, `004` → `003` → `002` geri alıp yeniden
uygular. Tümü tek transaction'dadır ve sonda `ROLLBACK` edilir.

```sh
export TEST_DATABASE_URL="postgres://<kullanici>@localhost:5432/<bos_test_veritabani>"
psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f db/tests/f1_migrations_test.sql
```

Başarılı çalışmada son satır `F1 migration test: ALL ASSERTIONS PASSED` olur.
Uygulamanın kendi veritabanında çalıştırmayın.

## Parola kurtarma (SQL adımı)

Arayüz veya API üzerinden parola kurtarma ya da değiştirme yoktur (ADR-001
karar 12, D-11, D-15, AC-P01-16). Unutulan parola, makineye ve veritabanına
erişimi olan kişi tarafından aşağıdaki tek transaction ile sıfırlanır:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
-- Parolayı temizle: ilk açılış (setup) akışı yeniden açılır.
UPDATE users
SET    password_hash = NULL,
       password_changed_at = NULL,
       updated_at = NOW()
WHERE  password_hash IS NOT NULL;
-- Tüm tarayıcı oturumlarını kapat.
DELETE FROM sessions;
-- api_keys tablosuna DOKUNULMAZ.
COMMIT;
SQL
```

Sonrasında:

1. `SELECT count(*) FROM users WHERE password_hash IS NOT NULL;` sonucu `0`
   olmalıdır. Uygulama korumalı isteklerde `401` + `code: "setup_required"`
   döner; arayüz parola belirleme ekranını gösterir.
2. Yeni parola ilk açılış akışıyla belirlenir (en az 12 karakter). Parola aynı
   kullanıcıya atanır; mevcut kayıtların atıfları korunur.
3. **API anahtarları kurtarmadan etkilenmez.** Anahtarın ele geçirildiğinden
   şüpheleniliyorsa yeni parolayla giriş yaptıktan sonra anahtar
   `DELETE /api/auth/api-keys/{id}` ile iptal edilir.

## Kurallar

- Yeni şema değişikliği yalnız yeni bir `NNN_ad.up.sql` + `.down.sql` çiftiyle
  yapılır; uygulanmış bir migration dosyası değiştirilmez.
- Her `.down.sql`, kaybolacak veriyi dosya başında açıkça yazar.
- Migration dosyaları `BEGIN/COMMIT` içermez (`migrate.sh --single-transaction`).
- Beklenmeyen veri sessizce düzeltilmez; migration `RAISE EXCEPTION` ile durur.
- Bu klasördeki hiçbir dosyada gerçek parola, token veya bağlantı sırrı
  bulunmaz; örneklerde yalnız `<kullanici>`, `<veritabani>` gibi yer tutucular
  kullanılır.
- `schema.sql` her yeni migration'la güncellenir.
