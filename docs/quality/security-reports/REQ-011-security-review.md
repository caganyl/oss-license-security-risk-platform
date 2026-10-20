# REQ-011 Güvenlik İncelemesi

- **Tarih:** 2026-10-20 / 21
- **Kapsam:** Güvenilmeyen repo dosyalarını okuyan yeni ayrıştırıcılar (Java,
  Go, PHP, Rust, Ruby, Dart, Swift; pnpm/bun; Pipfile/uv/requirements*), ortak
  kit, PURL, YAML alt küme okuyucusu, walker; OSV ayrımı ve yeniden kontrol
  SQL'i; göç 010; yeni dış hedefler `api.deps.dev` ve `pub.dev`; proje API
  ekosistem allowlist'i; arayüz kartları.
- **Yöntem:** Salt okunur, karşıt kod incelemesi (ayrı inceleme agent'ı;
  `devflow-plugin:security-red-team` bu oturumda yüklü değildi). Düzeltmeler
  ayrı bir agent tarafından regresyon testleriyle yapıldı.
- **Sonuç:** İlk karar **Conditional Go**; tüm Medium ve Low bulgular
  düzeltildikten sonra **Go**. Critical/High yok.

## Bulgular

| ID | Önem | Bulgu | Durum |
| --- | --- | --- | --- |
| M-1 | Medium | `golang.ts` `replace` çözümü O(require × replace): 32 MiB go.mod ayrıştırıcı iş parçacığını süre sınırına kadar kilitler. | **Düzeltildi** (`408b32c`): eski yola göre harita; 50k+50k satır testi. |
| M-2 | Medium | `rust.ts` workspace üyeliği `.some` taraması: üye × kaynaksız paket kuadratik. | **Düzeltildi** (`408b32c`): lock başına `Set`; 1 000 üye × 300k paket testi. |
| M-3 | Medium | `java.ts` `${}` genişlemesi: 64 KiB `${e}` × binlerce bağımlılık; derinlik sınırı sonucu sıraya bağlı önbellekleniyordu. | **Düzeltildi** (`2d94bd2`): 1024 karakter üstü çözülmez, metne göre önbellek, `(derinlik, ad)` anahtarı; testler. |
| M-4 | Medium | `yamlSubset.ts` her satır için önceden nesne: 32 MiB `\n` → bellek taşması, tüm tarama düşer. | **Düzeltildi** (`408b32c`): `maxLines` (2 000 000) bölmeden önce; boş/yorum satırı nesnesi yok; 32 MiB testleri. |
| M-5 | Medium | Gizlilik: özel pub sunucusu ve özel gem kaynağı paket adları deps.dev/pub.dev'e gidiyordu. | **Düzeltildi** (`71a3805`): `private_source` işaretli paketler lisans sorgusuna girmez (durum `disabled`); OSV sorgusu sürer — README'de açıkça yazılı. |
| L-1 | Low | pub.dev lisansı en son sürüme ait. | README notu (`71a3805`). |
| L-2 | Low | Yalnız noktalardan oluşan gem adları kabul ediliyordu (SSRF yok, istek reddediliyordu). | **Düzeltildi** (`71a3805`). |
| L-3 | Low | `composer.lock` lisans metinleri sınırsız. | **Düzeltildi** (`71a3805`): 16 öğe × 256 karakter. |
| L-4 | Low | Göç 010 down betiği yıkıcı. | `db/README.md` uyarısı (yedek, insan onayı) (`71a3805`). |

## Doğrulanan (sorun yok)

- ReDoS yok: Ruby/Go/PHP regex'leri doğrusal; gradle lexer tek geçiş, şablon
  derinliği 16; bun JSONC iki doğrusal geçiş; YAML okuyucu `indexOf` ve
  derinlik 64.
- Prototip kirliliği yok: YAML anahtarları `defineProperty`, okumalar
  `hasOwnProperty`; Ruby/Rust `Map`.
- XML: `pom.xml` ADR-008 okuyucusu (DOCTYPE reddi, 64 KiB metin, 200 bin öğe).
- Walker: `lstat` + `realpath` içeride kontrolü; bağlantılar izlenmez.
- Hata metinleri sabit Türkçe; dosya içeriği veya mutlak yol sızmaz.
- Dış istekler: ad/sürüm tek yol parçası (`encodeURIComponent`), sorgu ve
  fragment yasak, yönlendirme izlenmez, 1 MiB sınır, origin + yol allowlist'i;
  vekil/TLS çekirdeği ortak ve değişmedi. Önbellekte deps.dev adları sistem
  önekli; ekosistemler arası çakışma yok. `REGISTRY_ENRICHMENT=off` hiç istemci
  oluşturmaz.
- Yeniden kontrol SQL'i statik; kullanıcı girdisi yok.
- Proje API'si ekosistem allowlist'i; arayüz metinleri statik, `innerHTML` yok.
