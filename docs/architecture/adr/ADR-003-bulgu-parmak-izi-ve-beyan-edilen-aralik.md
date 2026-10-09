# ADR-003: Beyan edilen sürüm aralığı, runtime kapsamı, bulgu parmak izi ve F1 migration yöntemi

- **ADR-ID:** ADR-003
- **Durum:** Accepted
- **Tarih:** 2026-10-09 (taslak) · 2026-10-09 (karar)
- **İlgili:** REQ-002 / P-05, P-06, P-07, P-08 (AC-P05-*, AC-P06-*, AC-P07-*, AC-P08-*); açık sorular 1 ve 4; K-2

## Bağlam

- Kilit dosyası yoksa ayrıştırıcılar aralığı (`^1.2.0`, `>=2,<3`) `version` olarak
  gönderiyor; purl ise sürümsüz (`pkg:npm/x`) üretiliyor. `packages` hem
  `UNIQUE(ecosystem,name,version)` hem `purl UNIQUE` taşıyor; worker
  `ON CONFLICT (ecosystem,name,version)` kullandığı için iki farklı aralık aynı
  sürümsüz purl'de çakışıyor ve tüm tarama transaction'ı geri alınıyor.
- Lisansı olmayan paket için bulgu açılmıyor; `dev` kapsamı da ihlal sayılıyor.
- `findings` her taramada yeniden `open` ekleniyor; önceki `false_positive` /
  `accepted` kararı kayboluyor. `findings` tablosunda `project_id` yok (`scan_id`
  üzerinden), `accepted_until` `finding_reviews` (append-only) içinde. Risk kabulü
  (`accept_risk`) için `acceptedUntil` zorunludur ve ileri tarih olmalıdır
  (`src/lib/findingStateMachine.ts`).
- Node tabanlı göç aracı (P-11) F2'de; F1'de yalnız `db/migrate.sh` (bash + psql) var.

## Karar

### (a) Beyan edilen aralık (P-05)

- `packages.version` **yalnızca kesin çözülmüş sürüm** taşır; bilinmiyorsa `NULL`
  (kolon `NOT NULL`'dan nullable'a çevrilir). Sürüm `NULL` ise purl sürümsüzdür
  (AC-P05-3).
- Aralık, manifest'e özgü bir olgu olduğu için **`scan_dependencies.declared_range
  TEXT NULL`** kolonunda tutulur (`packages` taramalar arası kanonik katalogdur).
  Aynı paketin iki manifestteki farklı aralıkları, `manifest_path` farklı olduğundan
  iki ayrı `scan_dependencies` satırı olarak izlenir (AC-P05-4).
- Benzersizlik: `(ecosystem,name)` başına tek sürümsüz satır, kısmi benzersiz indeks
  `packages(ecosystem,name) WHERE version IS NULL` ile (PostgreSQL'de NULL'lar
  `UNIQUE`'te ayrık sayıldığı için gerekli). Worker upsert hedefi **`ON CONFLICT
  (purl)`** olur: purl `(ecosystem, normalize(name), version)`'un deterministik
  fonksiyonudur; böylece PyPI ad normalizasyonu (`Foo_Bar` / `foo-bar`) kaynaklı
  çakışma da kapanır.
- Ayrıştırıcı çıktı sözleşmesi: `version` (kesin veya `null`) + `declared_range`
  (varsa). Kilit dosyası varsa `version` kilitten, `declared_range` manifestten.
- Sürümü bilinmeyen paket için OSV sorgusu yapılmaz (aralıkla sorgu yanlış pozitif
  seli üretir); envanterde "sürüm bilinmiyor (aralık: …)" görünür.

### (b) Runtime kapsamı ve lisans bulgusu (P-06, P-07)

- `dependency_scope` eşlemesi: **runtime = `direct`, `transitive`, `peer`,
  `optional`**; **runtime değil = `dev`**. `peer` ve `optional` üretimde kurulup
  çalıştığı için runtime sayılır (muhafazakâr seçim). Ekosistemin test/geliştirme
  grupları (Poetry dev grupları, `requirements-dev` vb.) ayrıştırıcıda `dev`'e
  eşlenir; enum'a yeni değer eklenmez.
- Lisans politikası değerlendirmesi ve bulgu açma **yalnız runtime** satırlar için
  yapılır; `dev` paket envanterde kalır, ihlal listesinde yer almaz (AC-P07-1/2/3).
- Lisansı bulunamayan runtime paket için `license` bulgusu açılır:
  `license_findings.license_id = NULL`, `detected_license = NULL`,
  `normalized_license = 'NOASSERTION'`, `risk_level = 'unknown'` (AC-P06-1).
  `dev` paket için bulgu yok, envanterde "bilinmiyor" (AC-P06-3).

### (c) Bulgu parmak izi ve karar taşıma (P-08)

#### Formül

```
fingerprint = lower_hex( sha256( UTF-8(
    "v1|" + project_id + "|" + purl_scope + "|" + finding_type + "|" + key
) ) )                                   -- 64 karakter, küçük harf hex
```

#### Bulgu tipine göre purl kapsamı (kullanıcı kararı 2026-10-09)

| `finding_type` | `purl_scope` | `key` |
| --- | --- | --- |
| `license` | **sürümsüz**: `purl_base` | `lower(COALESCE(normalized_license, 'NOASSERTION'))` → bilinmeyen için `noassertion` |
| `security` | **sürümlü**: `purl_base + "@" + version` (`version` NULL ise — yalnız eski veride mümkün — `purl_base`) | `upper(COALESCE(osv_id, ghsa_id, cve_id, vulnerabilities.id::text))` |
| `copyright` | F1'de üretilmiyor; kapsam dışı. Üretilmeye başlanırsa kapsamı ayrı kararla belirlenir. | — |

- **`project_id`:** `scans.project_id`, küçük harf UUID metni.
- **`purl_base`:** `packages.purl`'den türetilir: qualifier (`?…`) ve subpath
  (`#…`) atılır, son `/`'dan sonra gelen `@sürüm` atılır (scoped npm
  `pkg:npm/@scope/ad@1.0.0` → `pkg:npm/@scope/ad`), tümü küçük harfe çevrilir;
  PyPI'da ad kısmı PEP 503'e göre normalize edilir (`[-_.]+` → `-`).
- **`version`:** `packages.version`, baş/son boşluk kırpılmış, **büyük/küçük harf
  korunur**, başka sürüm normalizasyonu yapılmaz. Sürüm purl'ün sürüm parçasından
  değil `packages.version` kolonundan alınır (yüzde kodlama farklarından
  bağımsız olmak için).
- **Ayraç güvenliği:** `purl_scope` içinde `|` geçerse `%7C` olarak kodlanır;
  `project_id` ve `finding_type` `|` içeremez; `key` son alandır. Böylece
  birleştirme belirsiz değildir.
- **`v1` öneki** algoritma değişirse eski/yeni izlerin ayırt edilmesini sağlar.
  Formül henüz uygulanmadığı için önceki taslağa göre sürüm artırılmaz.
- TS (worker) ve SQL (backfill) aynı kuralları uygular; aynı fixture'larla
  **eşitlik testi**ne bağlanır (scoped npm, PyPI `Foo_Bar`, qualifier'lı purl,
  NULL sürüm, `|` içeren değer, NOASSERTION).

#### Sonuç olarak

- **Lisans kararları sürüm yükseltmesinde taşınır** (aynı paket, aynı lisans → aynı
  iz). Lisans değişirse `key` değiştiği için taşıma olmaz. Kilit dosyası eklenip
  sürüm `NULL`'dan kesin değere geçtiğinde de lisans kararları korunur.
- **Güvenlik kararları sürüme bağlıdır:** bir CVE için verilen false positive veya
  risk kabulü yalnız aynı paket sürümünde taşınır; sürüm değişince (yükseltme veya
  düşürme) bulgu yeniden `open` açılır ve yeniden değerlendirilir. Sürümü bilinmeyen
  paket için güvenlik bulgusu üretilmediğinden ((a) son madde) sürümsüz güvenlik
  izi yalnız eski veride oluşur.

#### Saklama ve mükerrer engeli

- **Saklama:** `findings.fingerprint CHAR(64)`. **`project_id` denormalize
  edilmez**: proje kimliği zaten özetin içinde olduğundan `findings(fingerprint,
  created_at DESC)` indeksi seçicidir; sorgu ayrıca `JOIN scans` ile
  `s.project_id = $1` koşulunu savunma amaçlı uygular.
- **Mükerrer engeli (AC-P08-2):** worker bir taramada aynı parmak izi için tek bulgu
  açar (bellek içi küme; aynı paket birden çok manifestte olsa da ilk runtime
  `scan_dependency` bağlanır, diğerleri envanterde görünür). Eski verideki
  mükerrerler nedeniyle `UNIQUE(scan_id, fingerprint)` F1'de eklenmez.

#### Karar taşıma kuralları (AC-P08-3/4; kullanıcı kararı 2026-10-09)

Yeni bulgu eklenmeden önce aynı projede aynı parmak izli, başka taramaya ait
**en son** bulgu (`created_at DESC`) okunur ve durumuna göre:

| Önceki bulgunun durumu | Yeni bulgu | Taşınan kayıt |
| --- | --- | --- |
| `false_positive` | `false_positive` | son `false_positive` review'u |
| `accepted` ve son `accept_risk` review'unda `accepted_until >= CURRENT_DATE` (**süresi geçmemiş**) | `accepted` | son `accept_risk` review'u (aynı `accepted_until`) |
| `accepted` ve `accepted_until < CURRENT_DATE` (**süresi geçmiş**) veya `accepted_until` NULL | `open` | yok |
| `wont_fix` | `open` | yok |
| `open` (ör. `reopen` sonrası), `in_review`, `resolved` | `open` | yok |
| önceki bulgu yok | `open` | yok |

- Taşımada kaynak review yeni bulguya kopyalanır (aynı `decision`, `reviewer_id`,
  `accepted_until`; `notes`'a "<finding_id> bulgusundan taşındı") ve
  `findings.carried_from_finding_id` doldurulur.
- Taşınmayan durumlarda eski bulguya dokunulmaz. `reopen` sonrası en son bulgu
  `open` olduğu için kullanıcının yeniden açma kararı korunur.
- `CURRENT_DATE`, DB oturumunun saat dilimine göre değerlendirilir (tek makine).
- Mevcut kabullerin süre dolunca otomatik yeniden açılması P-19/F4'tür.

#### Backfill (AC-P08-5)

Migration `004` içinde, P-05 migration'ından (`003`) sonra, tek transaction'da SQL
ile yapılır. Aşağıdaki SQL **yaklaşım taslağıdır**; nihai metin
database-engineer'ındır.

```sql
ALTER TABLE findings ADD COLUMN fingerprint CHAR(64);

WITH src AS (
  SELECT f.id,
         f.finding_type,
         lower(s.project_id::text) AS project_id,
         -- purl_base (ham): qualifier/subpath ve son '/'dan sonraki '@sürüm' atılır
         lower(regexp_replace(split_part(split_part(p.purl, '#', 1), '?', 1),
                              '@[^/]*$', '')) AS base_raw,
         p.ecosystem,
         NULLIF(btrim(p.version), '') AS version,
         lf.normalized_license,
         upper(COALESCE(v.osv_id, v.ghsa_id, v.cve_id, v.id::text)) AS vuln_key
  FROM findings f
  JOIN scans s              ON s.id  = f.scan_id
  JOIN scan_dependencies sd ON sd.id = f.scan_dependency_id
  JOIN packages p           ON p.id  = sd.package_id
  LEFT JOIN license_findings  lf ON lf.finding_id = f.id
  LEFT JOIN security_findings sf ON sf.finding_id = f.id
  LEFT JOIN vulnerabilities   v  ON v.id = sf.vulnerability_id
), norm AS (
  SELECT id, finding_type, project_id, version, normalized_license, vuln_key,
         CASE WHEN ecosystem = 'python' AND base_raw LIKE 'pkg:pypi/%'
              THEN 'pkg:pypi/' || regexp_replace(substr(base_raw, 10), '[-_.]+', '-', 'g')
              ELSE base_raw END AS purl_base
  FROM src
)
UPDATE findings f
SET fingerprint = encode(sha256(convert_to(
      'v1|' || n.project_id || '|' ||
      replace(CASE WHEN n.finding_type = 'security' AND n.version IS NOT NULL
                   THEN n.purl_base || '@' || n.version      -- güvenlik: sürümlü
                   ELSE n.purl_base END,                      -- lisans: sürümsüz
              '|', '%7C') || '|' ||
      n.finding_type::text || '|' ||
      CASE n.finding_type
        WHEN 'license'  THEN lower(COALESCE(n.normalized_license, 'NOASSERTION'))
        WHEN 'security' THEN n.vuln_key
      END,
    'UTF8')), 'hex')
FROM norm n
WHERE f.id = n.id;

-- İz üretilemeyen satır (ör. copyright tipi, detay satırı eksik güvenlik bulgusu)
-- varsa migration açık hatayla durur; sessizce NULL bırakılmaz.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM findings WHERE fingerprint IS NULL) THEN
    RAISE EXCEPTION 'findings.fingerprint backfill eksik';
  END IF;
END $$;

ALTER TABLE findings ALTER COLUMN fingerprint SET NOT NULL;
CREATE INDEX findings_fingerprint_created_idx ON findings (fingerprint, created_at DESC);
```

- Özet fonksiyonu `sha256(bytea)` PostgreSQL ≥ 11 yerleşiktir; uzantı gerekmez.
- `003` sonrası `packages.version` aralık değerlerinden temizlenmiş olur; bu yüzden
  eski verideki aralık "sürümlü" güvenlik bulguları sürümsüz `purl_scope` ile
  izlenir ve yeni (sürümlü) izlerle eşleşmez — o bulguların kararları taşınmaz
  (kabul edilen sonuç; güvenli yön).
- Backfill mevcut bulguların **durumunu değiştirmez**; yalnız iz kolonunu doldurur.

### (d) F1 migration'larının Windows'ta çalıştırılması (açık soru 4 — kullanıcı kararı 2026-10-09)

- **Yöntem: Git Bash + `db/migrate.sh`.** F1'de tüm migration'lar (`002`, `003`,
  `004`) Git Bash içinden `db/migrate.sh` ile çalıştırılır. Git for Windows ADR-002
  (P-03) için zaten zorunludur; bash, `find`, `sort` içerir. `schema_migrations`
  takibi tutarlı kalır, yeni kod yazılmaz.
- **Koşullar:** `psql` PATH'te (PostgreSQL Windows kurulumu PATH'e eklemez),
  `PGCLIENTENCODING=UTF8`, `.gitattributes` ile `*.sh` ve `*.sql` için `eol=lf`
  (CRLF `set -euo pipefail`'i ve SQL'i bozar). Bu adımlar `db/README.md`'de
  belgelenir.
- **Node tabanlı göç aracı F2/P-11'dir;** geldiğinde `migrate.sh`'nin yerini alır ve
  `schema_migrations` kayıtlarını devralır.
- Sıra: `002_local_auth` (ADR-001), `003_declared_range`, `004_finding_fingerprint`;
  her birinin `.down.sql`'i olur. `db/schema.sql` ile senkron tutulması
  database-engineer'ın kararıdır.
- Production DB'ye migration uygulanması insan onayı gerektirir (autonomy gates);
  test DB'sine uygulama implementer akışının parçasıdır.

## Gerekçe

Aralık, paket kimliği değil manifest beyanıdır; `scan_dependencies`'e koymak
katalogu temiz tutar ve benzersizlik çakışmasını kökten kaldırır. Parmak izinin
projeyi içermesi denormalizasyonu gereksiz kılar. Hibrit purl kapsamı, lisans
kararlarını (paketin sürümleri arasında genellikle sabit olan bir olgu) korurken
güvenlik kararlarını (sürüme özgü bir olgu) sürüm değişiminde yeniden
değerlendirmeye zorlar; yanlış taşıma riski en yüksek olan alanda temkinli kalır.
Süresi geçmiş kabul ve `wont_fix`'in taşınmaması, kararların sessizce
süresizleşmesini önler. Karar geçmişini mevcut append-only `finding_reviews`
üzerinden taşımak mevcut iş akışı kodunu (`workflowController` `accepted_until`'ı
oradan okur) değiştirmez.

## Değerlendirilen alternatifler

- **Aralığı `packages.version`'da sentinel (`*`, `''`) ile tutmak:** purl ve raporları
  kirletir, aralık bilgisi kaybolur. Reddedildi.
- **`packages.declared_range`:** aynı paket için birden çok aralık katalogda
  temsil edilemez. Reddedildi.
- **Ayrı `declared_dependencies` tablosu:** ek join, kazanç yok. Reddedildi.
- **Parmak izinde her tipte sürümsüz purl (önceki taslağın önerisi):** güvenlik
  kararları (FP/kabul) sürüm değişiminde sessizce taşınır; yeni sürümde aynı CVE'nin
  durumu farklı olabilir. Reddedildi.
- **Parmak izinde her tipte sürümlü purl:** her sürüm yükseltmesinde lisans
  kararları da sıfırlanır; kilit dosyası eklenince tüm lisans kararları kaybolur.
  Reddedildi.
- **Sürümü purl'ün sürüm parçasından almak:** yüzde kodlama farkları izi
  bozabilir. Reddedildi; `packages.version` kullanılır.
- **Süresi geçmiş kabulü taşıyıp `open`'a düşürmek / `wont_fix`'i taşımak:**
  kararın süresizleşmesi veya kullanıcı fark etmeden kapalı gelmesi. Reddedildi.
- **`findings.project_id` denormalizasyonu:** ek kolon + backfill + tutarlılık riski.
  Reddedildi.
- **`findings.accepted_until` kolonu:** karar geçmişini iki yere böler. Reddedildi.
- **Node backfill betiği:** AC-P08-5 yöntemin migration'da tanımlı olmasını ister;
  SQL tercih edildi.
- **PowerShell'den elle `psql` (migration yöntemi):** sıra ve `schema_migrations`
  kaydı unutma riski. Birincil yöntem olarak reddedildi.
- **F1'de Node göç aracını öne çekmek:** P-11 kapsamını F1'e taşır. Reddedildi.

## Sonuçlar / Uygulama etkisi

- **Güvenlik/doğruluk:** sürümü bilinmeyen paketlerde güvenlik açığı tespiti yapılmaz
  (bilinçli yanlış negatif; kilit dosyası önerisi rapora/UI'a yansıtılmalı). Karar
  taşıma bir bulguyu kapalı getirebildiği için parmak izinin deterministik olması
  güvenlik açısından kritiktir. Güvenlik izinin sürümlü olması, bir sürümde
  verilen FP/kabulün başka sürüme sızmasını engeller.
- **Kullanıcı etkisi:** sürüm yükseltmesinden sonra güvenlik bulguları yeniden
  `open` görünür (aynı CVE yeni sürümde de varsa yeniden karar gerekir); lisans
  kararları korunur. Bu davranış UI/rapor metninde açıklanmalıdır.
- **Test:** AC-P05-1 (iki manifest, iki aralık, kilit yok → `completed`),
  AC-P06-4, AC-P07-4 + AC-P07-3 regresyonu, AC-P08-2/3/4/6; ayrıca: lisans FP'si
  sürüm yükseltmesinde taşınır; güvenlik FP'si/kabulü sürüm değişiminde taşınmaz,
  aynı sürümde taşınır; süresi geçmiş kabul ve `wont_fix` taşınmaz (`open`);
  `reopen` sonrası taşımama; TS↔SQL parmak izi eşitliği (fixture tablosu);
  migration'ın dolu bir test DB'sinde hatasız uygulanması (AC-P05-5).
- **Migration (database-engineer):** aşağıdaki tablo. Mevcut veri (`003`):
  `packages` satırlarından purl'ü sürümsüz olanların `version`'ı `NULL` yapılır,
  eski değer bağlı `scan_dependencies.declared_range`'e kopyalanır. Dikkat: scoped
  npm purl'ü (`pkg:npm/@scope/ad`) `@` içerir — "sürüm var mı" tespiti son `/`'dan
  sonraki `@`'ya bakmalıdır. Çalıştırma: Git Bash + `db/migrate.sh` ((d)).

### Şema değişiklikleri

| Migration | Nesne | Değişiklik |
| --- | --- | --- |
| 003 | `packages.version` | `DROP NOT NULL` + veri düzeltme |
| 003 | `packages` | kısmi benzersiz indeks `(ecosystem, name) WHERE version IS NULL` |
| 003 | `scan_dependencies` | `declared_range TEXT NULL` |
| 004 | `findings` | `fingerprint CHAR(64)` (backfill sonrası `NOT NULL`) |
| 004 | `findings` | indeks `(fingerprint, created_at DESC)` |
| 004 | `findings` | `carried_from_finding_id UUID NULL → findings(id) ON DELETE SET NULL` |

## Kanıt (Evidence)

- Repo incelemesi: `db/migrations/001_initial_core_schema.up.sql` (`packages`,
  `scan_dependencies`, `findings`, `security_findings`, `license_findings`,
  `vulnerabilities`, `finding_reviews`, `finding_type`/`finding_status` enum'ları),
  `src/lib/findingStateMachine.ts` (`acceptedUntil` zorunlu ve ileri tarih),
  `src/controllers/workflowController.ts`, `src/scanner/worker.ts`, `db/migrate.sh`.
- Dış kaynak: purl spesifikasyonu ve PEP 503 — genel bilgi, doğrulanması önerilir.
  NotebookLM veya Obsidian kaynağı kullanılmadı.

## İlgili REQ / AC

REQ-002: AC-P05-1…5, AC-P06-1…4, AC-P07-1…4, AC-P08-1…6, AC-G-3/4/5.

## Kalan notlar (karar gerektirmeyen)

1. Eski mükerrer bulgular temizlenirse `UNIQUE(scan_id, fingerprint)` eklenebilir;
   veri silme insan onayı gerektirir.
2. Güvenlik bulgusu anahtarı danışma kimliğine bağlıdır; aynı açık farklı kaynaktan
   farklı kimlikle gelirse ayrı iz oluşur (alias birleştirme F4+).
3. Sürüm metni normalize edilmediğinden aynı sürümün farklı yazımı (ör. PyPI
   `1.0RC1` / `1.0rc1`) farklı güvenlik izi üretir; kabul edilen sınır.
4. Implementation tamamlandığında `docs/handoffs/REQ-002.md` güncellenmelidir.

## Onay (Approval)

- **Karar sahibi:** proje sahibi (kullanıcı). Açık insan kararları **2026-10-09**
  tarihinde verildi ve bu ADR'ye işlendi: (1) parmak izinde lisans bulgusu için
  sürümsüz, güvenlik bulgusu için sürümlü purl; (2) süresi geçmiş risk kabulü ve
  `wont_fix` taşınmaz, false positive ve süresi geçmemiş risk kabulü taşınır;
  (3) F1 migration yöntemi Git Bash + `db/migrate.sh`. Durum `Accepted`. Kararlar
  ana oturum aracılığıyla iletilmiştir; kullanıcının bu dosyayı gözden geçirip
  commit etmesi kaydı kesinleştirir.
- Bu karar **veri modelini** değiştirir ve mevcut veriye backfill uygular.
  Implementation öncesi `docs/ownership/REQ-002.json` `status: approved` gerekir;
  production DB'ye migration uygulanması ayrıca insan onayı gerektirir.
