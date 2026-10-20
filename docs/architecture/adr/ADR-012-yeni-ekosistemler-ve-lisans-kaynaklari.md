# ADR-012: Yeni ekosistemler, OSV ayrımı ve yeni lisans kaynakları

- **Durum:** Kabul edildi (REQ-011, 2026-10-20)
- **İlgili:** ADR-005 (TypeScript ayrıştırıcılar), ADR-006 (kayıt defteri
  zenginleştirme, sabit origin), ADR-007 (güvenlik açığı sorgusu), ADR-008
  (NuGet, XML okuyucu)

## Bağlam

Ürün yalnız npm, PyPI ve NuGet'i anlıyor. Kullanıcı Java/Kotlin, Go, PHP,
Rust, Ruby, Dart ve Swift desteğini ve bu ekosistemlerde lisans bilgisini
istedi. İki yapısal engel var:

1. OSV sorgusu zenginleştirme koordinatına bağlı (`registryEcosystemOf`);
   zenginleştirmesi olmayan ekosistem güvenlik açığı sorgusundan sessizce
   düşüyor.
2. Kayıt defteri istemcisi sabit bir origin/amaç tablosuyla çalışıyor
   (ADR-006); her yeni kaynak bu tabloya ve statik testlere girmek zorunda.

## Karar

1. **Ayrıştırıcılar:** Her ekosistem ayrı dosyada; walker yeni dosya adlarını
   .NET'teki gibi ekosistem seçimine göre ayrı haritada toplar. Derleme aracı
   çalıştırılmaz. XML için ADR-008 okuyucusu, TOML için `smol-toml`, YAML için
   çapa/etiket/çok belge reddeden alt küme okuyucu; yeni bağımlılık yok.
2. **OSV ayrımı:** `osvCoordinateOf(ecosystem, name, version)` zenginleştirmeden
   bağımsızdır ve tüm desteklenen ekosistemleri kapsar: `Maven`, `Go`,
   `Packagist`, `crates.io`, `RubyGems`, `Pub`, `SwiftURL` (+ mevcut `npm`,
   `PyPI`, `NuGet`). Günlük yeniden kontrol SQL'i aynı eşlemeyi kullanır.
3. **Lisans kaynakları (yeni origin'ler):**
   - `https://api.deps.dev` — `GET /v3/systems/{GO|MAVEN|CARGO|RUBYGEMS}/packages/{name}/versions/{version}`;
     `licenses` (SPDX) alanı. Tek origin, dört ekosistem.
   - `https://pub.dev` — `GET /api/packages/{name}/score`; `tags` içindeki
     `license:<spdx>`.
   - Her iki origin mevcut sertleştirilmiş istemcide (yalnız HTTPS, sabit
     origin + amaç, yönlendirme izlenmez, yanıt boyutu ve süre sınırı, vekil
     kuralları) yeni amaçlar olarak tanımlanır; `REGISTRY_ENRICHMENT=off`
     tümünü kapatır.
   - PHP: lisans `composer.lock`'tan (ayrı istemci yok). Swift: kaynak yok.
4. **Veri:** Göç `010`: `tech_ecosystem` += `rust`, `dart`, `swift`;
   önbellek ve `license_source` CHECK kümeleri += `depsdev`, `pubdev`.

## Sonuçlar

- (+) Yeni dillerde de paket listesi, güvenlik açığı ve lisans.
- (+) OSV sorgusu artık zenginleştirmenin varlığına bağlı değil.
- (−) İki yeni üçüncü taraf hedef (paket adı + sürüm gider); gizlilik
  sınıfı npm/PyPI/NuGet ile aynı, README ve Sistem Durumu'nda listelenir.
- (−) `build.gradle` ve üst POM'lu `pom.xml` tam çözülemez; kilit dosyası
  önerilir.

## Değerlendirilen alternatifler

- **Her ekosistem için kendi kayıt defteri** (Maven Central POM, crates.io,
  rubygems.org, proxy.golang.org): 4–5 yeni origin ve istemci; deps.dev tek
  origin ile aynı veriyi verir. Reddedildi.
- **Derleme aracını çalıştırmak** (`mvn dependency:tree`, `go list`): repo
  kodunu çalıştırır (ADR-002 ihlali). Reddedildi.
- **YAML kütüphanesi eklemek:** bağımlılık yasağı ve saldırı yüzeyi;
  gereken alt küme küçük. Reddedildi.
