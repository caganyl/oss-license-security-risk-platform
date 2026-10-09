# REQ-002 Auth API Contract (F1 — P-01, P-02, P-04)

- **Status:** Proposed
- **Sürüm:** 0.2.2-draft
- **Tarih:** 2026-10-09
- **Makine okunur contract:** `docs/contracts/REQ-002-auth-api.openapi.yaml` (OpenAPI 3.0.3)
- **İlgili:** REQ-002 (AC-P01-1…10, AC-P02-2/4, AC-P04-2…6, AC-P09-3), ADR-001, ADR-002

> **UYARI — paralel implementation başlatılmamalı.** Bu contract "Proposed"
> durumundadır (dayandığı ADR-001 ve ADR-002 `Accepted`).
> Contract insan tarafından açıkça onaylanıp (`Status: Accepted`)
> `docs/ownership/REQ-002.json` `status: approved` olmadan backend (`src/`) ve
> frontend (`public/index.html`) implementation'ı başlamaz.
>
> **İnsan onayı gereken unsurlar:** kimlik doğrulama sınırı (parola ve API
> anahtarı saklama = kullanıcı verisi), veritabanı migration'ı (`002_local_auth`,
> ADR-001), oturum/anahtar politikası. Onay sonrası `docs/handoffs/REQ-002.md`
> güncellenmelidir; Security Red Team review önerilir.

## Karar kaydı (2026-10-09)

Kullanıcının 2026-10-09 tarihli kararları bu sürümde işlendi; önceki "onay
bekliyor" işaretleri kaldırıldı. Bu kararlar contract içeriğini sabitler;
contract'ın bütün olarak `Accepted` yapılması ayrıca açık insan onayı ister.

| # | Konu | Karar |
| --- | --- | --- |
| K1 | Setup sonrası giriş | `201` + `Set-Cookie`: otomatik giriş (oturum açılır) |
| K2 | Logout kapsamı | Yalnız mevcut oturum kapatılır |
| K3 | `GET /api/auth/me` | Contract'ta kalır |
| K4 | Oturum süreleri | 12 saat boşta, 7 gün mutlak |
| K5 | Parola alt sınırı | En az 12 karakter; ihlal `400 invalid_password` (sabit mesaj) |
| K6 | API anahtarı | Tek aktif anahtar; **yeni anahtar öncekini otomatik iptal eder (409 dönülmez)**; `DELETE /api/auth/api-keys/{id}` ile iptal |
| K7 | Anahtar biçimi / `keyPrefix` | ADR-001 karar 6: anahtar `ossr_<P>_<S>` (P = 16 küçük harf hex / 64 bit, S = bağımsız 43 karakter base64url / 256 bit, toplam 65); `keyPrefix` = `ossr_<P>` (21 karakter), yalnız gösterim |
| K8 | P-04 hata kodları | SCAN_ROOTS dışı yerel yol → `400 path_not_allowed`; https dışı (SSH dahil) veya kabul edilmeyen yerel biçim → `400 repo_url_not_allowed` |
| K9 | Hata gövdeleri | Tüm hata yanıtları JSON (`{error, message, code}`); `/health` ham DB mesajı döndürmez |
| K10 | Setup ve kurtarma (ADR-001 karar 2) | Tek aday (kurtarma sonrası) → parola o kullanıcıya, 201 + `Set-Cookie`; kullanıcı yoksa yeni kullanıcı, 201; parolalı kullanıcı varsa 409; geçersiz kullanıcı durumu → `500 setup_state_invalid` |

## Kapsam

Tek yerel parola + oturum çerezi + CLI/CI API anahtarı (P-01), arayüzün bu
mekanizmayla çalışması (P-02 / AC-P02-4), `POST /api/projects` /
`POST /api/scans` için P-04 `400` davranışı ve uygulama genelinde JSON hata
gövdesi. Mevcut korumalı uç noktaların istek/yanıt şemaları bu contract'ın
konusu değildir; yalnız ortak `401`/`403`/JSON hata davranışını devralırlar
(OpenAPI'de global `security`).

## Uç noktalar

| Method / path | Kimlik | Başarılı | Hatalar (code) |
| --- | --- | --- | --- |
| `GET /health` | muaf | 200 `{status:healthy, database:connected}` | 403 host_rejected, 500 internal_error (sabit gövde, ham DB mesajı yok) |
| `POST /api/auth/setup` | muaf | 201 + `Set-Cookie` (otomatik giriş) | 400 invalid_password / invalid_request, 403 origin_rejected/host_rejected, 409 setup_already_done, 413, 500 setup_state_invalid / internal_error |
| `POST /api/auth/login` | muaf | 204 + `Set-Cookie` | 400 invalid_request, 401 invalid_credentials / setup_required, 403 origin_rejected/host_rejected, 413, 429 too_many_attempts + `Retry-After`, 500 |
| `POST /api/auth/logout` | yalnız çerez | 204 + çerez temizleme (yalnız mevcut oturum) | 401 unauthenticated, 403 forbidden (Bearer) / origin_rejected, 500 |
| `GET /api/auth/me` | çerez veya Bearer | 200 `{data:{id,email,displayName,roles}}` | 401 unauthenticated / setup_required, 403 host_rejected, 500 |
| `POST /api/auth/api-keys` | yalnız çerez | 201 `{data:{id,key,keyPrefix,createdAt}}` (önceki aktif anahtar iptal) | 400 invalid_request, 401, 403 forbidden (Bearer) / origin_rejected, 500 |
| `GET /api/auth/api-keys` | yalnız çerez | 200 metadata listesi | 401, 403 forbidden, 500 |
| `DELETE /api/auth/api-keys/{id}` | yalnız çerez | 204 | 401, 403 forbidden / origin_rejected, 404 not_found, 500 |
| `POST /api/projects` | çerez veya Bearer | 201 (mevcut) | **400 path_not_allowed / repo_url_not_allowed** / invalid_request, 401, 403, 500 |
| `POST /api/scans` | çerez veya Bearer | 201 (mevcut) | **400 path_not_allowed / repo_url_not_allowed** / invalid_request, 401, 403, 404 not_found, 500 |
| diğer tüm `/api/*` | çerez veya Bearer | mevcut | 401 unauthenticated / setup_required, 403, 404 not_found, 500 internal_error |

**Muaf olanlar yalnızca:** `GET /health`, `POST /api/auth/login`,
`POST /api/auth/setup`, statik `public/` dosyaları ve `GET /` (AC-P01-1, ADR-001
karar 9). Ayrı bir `GET /api/auth/status` yoktur.

## Kimlik doğrulama kuralları

- **Çerez:** `ossrisk_session=<32 bayt base64url>; HttpOnly; SameSite=Strict;
  Path=/; Max-Age=604800`; `Secure` ve `Domain` yok. Sunucu yalnız SHA-256
  özetini saklar. Her login ve başarılı setup yeni token üretir.
- **Oturum süreleri (K4):** boşta kalma **12 saat** (`last_seen_at + 12 sa`),
  mutlak **7 gün** (`expires_at = created_at + 7 gün`). Hangisi önce dolarsa
  oturum geçersizdir → `401 unauthenticated`. Her doğrulanmış istek
  `last_seen_at`'i günceller; mutlak süre uzatılmaz (kayan pencere yok).
- **API anahtarı (K7, ADR-001 karar 6):** biçim `ossr_<P>_<S>`.
  - `P`: 8 bayt CSPRNG, küçük harf hex, 16 karakter (64 bit).
  - `S`: `P`'den bağımsız 32 bayt CSPRNG, dolgusuz base64url, 43 karakter (256 bit).
  - Desen `^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$`, toplam 65 karakter.
  - İletim yalnız `Authorization: Bearer <anahtar>`; query string ile kabul
    edilmez. Düz metin yalnız oluşturma yanıtında bir kez döner
    (`Cache-Control: no-store`).
  - Saklama: `api_keys.key_hash` = tam anahtar metninin (UTF-8) SHA-256 hex
    özeti; `api_keys.key_prefix` = `ossr_<P>`. Düz metin saklanmaz.
  - Doğrulama: değer önce desenle kontrol edilir (uymazsa özet hesaplanmadan
    `401 unauthenticated`); ardından **tam anahtarın SHA-256 özeti** `key_hash`
    ile aranır (`revoked_at IS NULL`).
- **`keyPrefix` (K7):** `ossr_<P>`, **21** karakter, desen `^ossr_[0-9a-f]{16}$`;
  tam anahtarın ilk 21 karakterine eşittir. `P` gizli kısımdan bağımsız
  üretildiği için gösterilmesi `S`'nin entropisini azaltmaz. **Yalnız gösterim**
  içindir (UI listesi, denetim kaydı, log korelasyonu); kimlik doğrulamada, arama
  anahtarı olarak veya karşılaştırmada **kullanılmaz**.
- **Öncelik (öneri):** `Authorization` başlığı varsa yalnız Bearer değerlendirilir,
  çerez yok sayılır; geçersiz/iptal edilmiş anahtar veya Bearer dışı şema →
  `401 unauthenticated`.
- **Anahtar yönetimi ve logout** yalnız çerezle; `Authorization` ile çağrı →
  `403 forbidden`.
- **401 gövdesi:** parola hiç belirlenmemişse `code: setup_required`, aksi halde
  `unauthenticated` (login'de yanlış parola: `invalid_credentials`). Kullanıcı
  yok / parola yanlış ayrımı yapılmaz. Hatalı login `Set-Cookie` üretmez.
- **Setup (K1, K5, K10):**
  - Parola en az **12**, en fazla 1024 karakter; trim edilmez.
  - Akış (ADR-001 karar 2, tek transaction): aday = `admin` rollü,
    `password_hash IS NULL`, `status='active'`, `deleted_at IS NULL` kullanıcı;
    adaylar önce `FOR UPDATE` ile kilitlenir. Dallar sırayla:
    1. Parolası olan kullanıcı var → `409 setup_already_done`, hiçbir şey değişmez.
    2. `admin` rol satırı yok → `500 setup_state_invalid`.
    3. Tam olarak bir aday (SQL kurtarma sonrası durum) → parola **o kullanıcıya**
       atanır; yeni kullanıcı oluşturulmaz; id, roller, geçmiş kayıtlar ve API
       anahtarları korunur → `201` + `Set-Cookie`.
    4. Hiç kullanıcı yok → yeni yerel kullanıcı + `admin` `user_roles` →
       `201` + `Set-Cookie`.
    5. Birden fazla aday **veya** kullanıcı var ama aday yok (yalnız
       inactive/silinmiş ya da admin rolsüz) → `500 setup_state_invalid`;
       transaction geri alınır, parola atanmaz, kullanıcı oluşturulmaz; durum
       parola içermeden log'lanır.
  - `setup_state_invalid` mesajı sabittir ve iç ayrıntı (kullanıcı sayısı, id,
    rol, durum) taşımaz:
    `Setup cannot proceed: user state requires manual repair (see db/README.md)`.
  - 4. dalda eşzamanlı ikinci istek kısmi benzersiz indekse takılır → `409`.
  - İhlalde `400`, `code: invalid_password`, sabit mesajlar:
    - alan yok / string değil → `Password is required`
    - uzunluk < 12 → `Password must be at least 12 characters`
    - uzunluk > 1024 → `Password must be at most 1024 characters`
  - Başarıda `201` + `Set-Cookie`: login ile aynı kurallarla yeni oturum açılır
    (otomatik giriş). Parola ataması ve oturum kaydı aynı transaction'dadır;
    oturum oluşturulamazsa parola da atanmaz (`500 internal_error`).
  - Parola belirlendikten sonra her çağrı `409 setup_already_done` (oturum olsa
    bile). Eşzamanlı ikinci istek DB kısmi benzersiz indeksiyle `409`.
- **Brute-force:** art arda 5 hatalı login → `429` + `Retry-After` (sn); 30 sn'den
  başlar, ikiye katlanır, üst sınır 900 sn; başarılı login'de sıfırlanır; bekleme
  süresince doğru parola da `429`. Sayaç bellek içi.
- **Logout (K2):** yalnız isteği yapan oturumun `sessions` satırı silinir
  (`sessions.id = req.user.sessionId`); aynı kullanıcının diğer oturumları ve API
  anahtarları etkilenmez. Çerez `Max-Age=0` ile temizlenir. Geçersiz/süresi
  dolmuş çerezle `401 unauthenticated`. ADR-001 karar 3 ile tutarlıdır; tüm
  oturumların silinmesi yalnız ADR-001 karar 12'deki parola kurtarma SQL
  adımında olur (HTTP contract'ı dışında).
- **RBAC:** `req.user` yalnız doğrulanmış oturum/anahtardan türetilir; tek rol
  `admin`. Mevcut `rbac.ts` 401/403 gövdelerine `code` eklenir
  (`unauthenticated`, `forbidden`).

## API anahtarı yaşam döngüsü (K6)

- **Seçilen davranış: otomatik iptal (409 değil).** `POST /api/auth/api-keys`
  kullanıcının aktif (`revoked_at IS NULL`) anahtarı varsa onu aynı transaction
  içinde `revoked_at = now()` ile iptal eder ve yenisini oluşturur; her zaman
  `201` döner. "Aktif anahtar zaten var" için `409` yoktur.
- Eşzamanlı iki oluşturma isteği sunucuda serileştirilir (ör. kullanıcı satırı
  `SELECT … FOR UPDATE`); en son tamamlanan aktif kalır. "Tek aktif" DB'de kısmi
  benzersiz indeksle (`api_keys(user_id) WHERE revoked_at IS NULL`) ayrıca zorlanır.
- `DELETE /api/auth/api-keys/{id}`: yalnız kullanıcının kendi anahtarı; satır
  silinmez, `revoked_at` doldurulur; zaten iptal edilmişse `204` (idempotent —
  öneri); yok / başkasına ait / geçersiz UUID → `404 not_found` (ayrım yapılmaz —
  öneri). Aktif anahtar iptal edilince aktif anahtar kalmaz.
- İptal edilen (otomatik veya `DELETE` ile) anahtarla sonraki istekler →
  `401 unauthenticated`.
- `GET /api/auth/api-keys` iptal edilmişler dahil metadata döner; en fazla bir
  öğede `revokedAt` null'dır. `key` veya özet asla dönmez.

## CSRF / Host kuralı

- **Host:** her istekte (muaf uçlar ve statik dosyalar dahil) `Host` başlığı şu
  listede olmalı: `127.0.0.1:<PORT>`, `localhost:<PORT>`, `[::1]:<PORT>` ve
  `HOST` env bunlardan farklıysa `<HOST>:<PORT>`. Değilse `403 host_rejected`
  (JSON gövde).
- **Origin:** çerezle doğrulanan `POST/PUT/PATCH/DELETE` ile `login`/`setup`
  isteklerinde `Origin` (yoksa `Referer` kökeni) şu listede olmalı:
  `http://127.0.0.1:<PORT>`, `http://localhost:<PORT>`, `http://[::1]:<PORT>`
  (ve `HOST` farklıysa `http://<HOST>:<PORT>`). Uyuşmazsa, `Origin: null` ise
  veya ikisi de yoksa `403 origin_rejected`. Bearer isteklerine uygulanmaz.
- CORS başlığı hiç verilmez.
- Middleware sırası (ADR-001 karar 8): Host → statik/`/health` → login/setup →
  çerez/Bearer doğrulama → `req.user` → router'lar ve RBAC → `/api` 404 →
  merkezi JSON error handler.

## Hata gövdesi (K9)

`{ "error": "<HTTP durum adı>", "message": "<insan okunur>", "code": "<makine kodu>" }`

- **Tüm hata yanıtları** (4xx/5xx; `/health`, statik dosya Host reddi ve muaf uçlar
  dahil) `Content-Type: application/json` ve bu gövdeyle döner. HTML veya düz
  metin hata gövdesi yoktur. `code` her hata yanıtında zorunludur.
- `app.ts`'e merkezi JSON error handler eklenir: kodsuz fırlatılan mevcut
  hatalara (`throw {statusCode}`) HTTP durumuna göre varsayılan kod atanır:
  400 `invalid_request`, 401 `unauthenticated`, 403 `forbidden`, 404 `not_found`,
  409 `conflict`, 413 `payload_too_large`, 5xx `internal_error`. Mevcut 400/404
  mesajları (ör. `Project name is required`) korunur.
- Tanımsız `/api` rotası → `404 not_found`; bozuk JSON → `400 invalid_request`;
  body-parser sınır aşımı → `413 payload_too_large`; beklenmeyen hata →
  `500 internal_error`, mesaj sabit `Internal server error`.
- `message` parola, token, anahtar, çerez, kanonik/gerçek yol, `SCAN_ROOTS`
  içeriği, ham DB/sistem hata mesajı veya stack trace içermez.
- **`/health` 500** gövdesi sabittir:
  `{ "status": "unhealthy", "database": "disconnected", "error": "Internal Server Error", "message": "Database unavailable", "code": "internal_error" }`.
  Bugünkü `error: err.message` alanı kaldırılır; ayrıntı yalnız sunucu log'una
  (sır içermeden) yazılır.

### `code` kataloğu

| HTTP | code | Nerede |
| --- | --- | --- |
| 400 | `invalid_request` | bozuk JSON, mevcut genel doğrulama hataları |
| 400 | `invalid_password` | setup: parola yok / < 12 / > 1024 |
| 400 | `path_not_allowed` | P-04: yerel yol SCAN_ROOTS dışı / tanımsız kök / traversal / yok |
| 400 | `repo_url_not_allowed` | P-04: https dışı şema (SSH dahil), kabul edilmeyen yerel biçim |
| 401 | `unauthenticated` | geçersiz/eksik/süresi dolmuş kimlik |
| 401 | `setup_required` | parola hiç belirlenmemiş |
| 401 | `invalid_credentials` | login: yanlış parola |
| 403 | `origin_rejected` | Origin/Referer reddi |
| 403 | `host_rejected` | Host reddi |
| 403 | `forbidden` | RBAC reddi, çerez-only uca Bearer |
| 404 | `not_found` | anahtar iptalinde bulunamayan id, tanımsız `/api` rotası, mevcut 404'ler |
| 409 | `setup_already_done` | setup tekrar |
| 409 | `conflict` | mevcut kodun kodsuz 409'ları için varsayılan |
| 413 | `payload_too_large` | body sınırı |
| 429 | `too_many_attempts` | login brute-force |
| 500 | `internal_error` | beklenmeyen hata, `/health` sağlıksız |
| 500 | `setup_state_invalid` | setup: birden fazla aday, aday yok ama kullanıcı var, `admin` rol satırı eksik |

## P-04 — 400 davranışı (ADR-002, K8)

`POST /api/projects` (`repoUrl` doluysa) ve `POST /api/scans` (etkin kaynak:
entegrasyon `repo_url`, yoksa proje `repo_url` — worker ile aynı öncelik)
kayıttan/kuyruktan **önce** sınıflandırılır:

1. **`https://` ile başlayan, kullanıcı bilgisi içermeyen URL** → uzak kaynak,
   kabul.
2. **Sürücü harfiyle başlayan mutlak Windows yolu** (`X:\…`) → yerel tarama yolu;
   SCAN_ROOTS kontrolü. Başarısızsa **`path_not_allowed`**:
   `SCAN_ROOTS` tanımsız/boş (AC-P04-6); `realpath.native` sonrası hiçbir kökün
   altında değil (AC-P04-3; büyük/küçük harf duyarsız, önek+ayraç kuralı);
   `..`, symlink, junction, `subst` ile kök dışına çıkıyor (AC-P04-4); yol yok veya
   dizin değil.
3. **Diğer her biçim** → **`repo_url_not_allowed`**. **SSH açıkça reddedilir
   (ADR-002):** `ssh://…` ve scp biçimli `git@host:path` (ör.
   `git@github.com:org/repo.git`) her zaman `400 repo_url_not_allowed` döner.
   Ayrıca: `http://`, `git://`, `file://`; `ext::`/`fd::`;
   `-` ile başlayan değer; kullanıcı bilgisi içeren URL (`https://user@…`);
   göreli yol, UNC (`\\server\share`), aygıt yolu (`\\?\`, `\\.\`) gibi kabul
   edilmeyen yerel yol biçimleri; sınıflandırılamayan biçim.

- Ret durumunda proje kaydedilmez / `scans` satırı oluşmaz. Worker kontrolü
  (TOCTOU) ayrıca `failed` üretir; bu HTTP contract'ının dışındadır.
- Sabit mesajlar: `Local path is not under an allowed scan root`,
  `Repository URL is not allowed; only https URLs are accepted`. Mesaj kanonik
  yolu veya `SCAN_ROOTS` içeriğini taşımaz.
- Not: UNC/göreli/aygıt yolları 0.1.0'da `path_not_allowed` idi; K8 gereği
  `repo_url_not_allowed`'a taşındı (bkz. Açık noktalar 1).

## Backend yükümlülükleri

- Mock `req.user` middleware'i ve controller'lardaki sabit UUID geri dönüşleri
  kaldırılır (AC-P01-7).
- Parola, çerez değeri, `Authorization` başlığı ve anahtar log'a yazılmaz;
  login/setup gövdeleri loglanmaz.
- Merkezi JSON error handler + `/api` 404 handler eklenir; HTML hata gövdesi
  kalmaz. `/health` 500 gövdesi sabit (ham DB mesajı yok).
- Setup: parola ataması + oturum oluşturma tek transaction.
- Logout: yalnız mevcut oturum satırı silinir.
- API anahtarı oluşturma: önceki aktifi iptal + yeni ekleme tek transaction,
  serileştirilmiş. Anahtar `ossr_<P>_<S>` (P ve S bağımsız CSPRNG);
  `key_hash` = tam anahtarın SHA-256 hex özeti, `key_prefix` = `ossr_<P>`
  (21 karakter). Bearer doğrulaması desen kontrolü + `key_hash` araması;
  `key_prefix` aramada/karşılaştırmada kullanılmaz.
- Varsayılan bind `127.0.0.1` (AC-P01-9); loopback dışı `HOST`'ta uyarı.

## Frontend (`public/index.html`) yükümlülükleri

- Açılışta `GET /api/auth/me`: `200` → uygulama; `401 setup_required` → setup
  formu; `401 unauthenticated` → login formu (AC-P02-4).
- Setup `201` sonrası kullanıcı oturum açmış sayılır (çerez set edilmiştir);
  ayrıca login çağrılmaz, uygulama ekranına geçilir (doğrulama için `/me`
  çağrılabilir). Setup formunda istemci tarafı 12 karakter kontrolü yapılabilir;
  sunucunun `400 invalid_password` mesajı `textContent` ile gösterilir.
- Herhangi bir `/api` çağrısında `401` → ilgili forma dön ve kullanıcıya hata
  göster; `403 origin_rejected/host_rejected` ve `429` (Retry-After süresiyle)
  hata olarak gösterilir. Hata yanıtları her zaman JSON'dur; `code` ile dallanılır.
- Logout yalnız bu tarayıcı oturumunu kapatır; UI başka oturumların da
  kapandığını iddia etmez.
- `fetch` `credentials: 'same-origin'` (varsayılan; açıkça `omit` verilmez).
  Çerez JS ile okunmaz/yazılmaz (HttpOnly).
- Yeni anahtar oluşturmadan önce kullanıcıya "mevcut aktif anahtar iptal
  edilecek" uyarısı gösterilir. Anahtar yalnız oluşturma yanıtında gösterilir;
  `localStorage`/`sessionStorage`'a yazılmaz, `console`'a basılmaz, ekrandan
  çıkınca bellekten atılır. Liste yalnız metadata (`keyPrefix` = `ossr_<16 hex>`, 21 karakter)
  gösterir; iptal butonu `DELETE /api/auth/api-keys/{id}` çağırır.
- Sunucu `message` dahil tüm dinamik metinler `textContent` (veya tek merkezi
  kaçışlama fonksiyonu) ile yazılır; kaçışlanmamış `innerHTML` yok (AC-P02-2).

## Versiyonlama ve migration etkisi

- URL'de sürüm öneki yok (`/api`). Contract sürümü `info.version`; breaking
  değişiklik yeni contract sürümü + insan onayı gerektirir.
- 0.2.1 → 0.2.2 değişiklikleri: setup akışı güncellenmiş ADR-001 karar 2'ye
  uyduruldu (K10): kurtarma sonrası tek adaya parola atanır (yeni kullanıcı
  yok, 201 + `Set-Cookie`); kullanıcı yoksa yeni kullanıcı (201); geçersiz
  kullanıcı durumunda yeni kod `500 setup_state_invalid`.
- 0.2.0 → 0.2.1 değişiklikleri: API anahtarı biçimi Accepted ADR-001 karar 6'ya
  uyduruldu: anahtar `ossr_<16 hex>_<43 base64url>` (65 karakter, desen
  `^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$`); `keyPrefix` = `ossr_<16 hex>`
  (21 karakter, desen `^ossr_[0-9a-f]{16}$`), yalnız gösterim; doğrulama tam
  anahtarın SHA-256 özetiyle. 0.2.0'daki 13 karakterlik önek tanımı geçersizdir.
  SSH (`ssh://`, scp `git@host:path`) reddi açıkça yazıldı.
- 0.1.0 → 0.2.0 değişiklikleri: setup `Set-Cookie` zorunlu; logout semantiği
  (yalnız mevcut oturum); `ErrorBody.code` her hata
  yanıtında zorunlu, yeni kodlar (`invalid_request`, `conflict`,
  `payload_too_large`, `internal_error`); `/health` 500 gövdesi sabitlendi;
  UNC/göreli/aygıt yolları `repo_url_not_allowed`. Henüz implementation olmadığı
  için tüketici kırılması yoktur.
- Migration `002_local_auth` (ADR-001 şema tablosu: `users.password_hash`,
  `sessions`, `api_keys`, kısmi benzersiz indeksler). K6 ile
  `api_keys(user_id) WHERE revoked_at IS NULL` kısmi benzersiz indeksi
  **zorunlu** hale gelir; `key_prefix` `ossr_<16 hex>` (21 karakter), `key_hash`
  tam anahtarın SHA-256 hex özetini saklar (ADR-001 şema tablosu). Ayrı database
  contract'ı bu belgenin kapsamında değildir; migration insan onayı gerektirir.

## Test yükümlülükleri (qa-automation, Vitest, ayrı test DB — AC-G-5)

- Girişsiz `/api` → 401 + `code`; parola yokken `setup_required`.
- Geçerli çerez → 200; geçerli Bearer → 200; geçersiz/iptal Bearer → 401;
  query string anahtarı → 401.
- Oturum süreleri: `last_seen_at` 12 saatten eski → 401; `expires_at` geçmiş
  (son kullanım yeni olsa bile) → 401; 12 saat içinde kullanılan oturum geçerli.
- Yanlış parola → 401 `invalid_credentials`, `Set-Cookie` yok; 6. deneme → 429 +
  `Retry-After`.
- Setup: 11 karakter → 400 `invalid_password` + `Password must be at least 12 characters`;
  12 karakter → 201 + `Set-Cookie`, ardından aynı çerezle `/api/auth/me` → 200;
  1025 karakter → 400; ikinci kez → 409, `Set-Cookie` yok.
- Setup dalları (ADR-001 karar 2):
  - Boş `users` → 201 + `Set-Cookie`, tek kullanıcı + `admin` rolü oluşur.
  - Kurtarma sonrası (önce setup + API anahtarı oluştur, sonra kurtarma SQL
    adımıyla `password_hash`/`password_changed_at` NULL ve oturumlar silinir) →
    setup 201 + `Set-Cookie`; **kullanıcı id'si aynı kalır**, **kullanıcı sayısı
    artmaz**, roller ve geçmiş kayıt atıfları korunur, kurtarma öncesi oluşturulan
    **API anahtarı Bearer ile 200 almaya devam eder**; eski oturum çerezi 401.
  - İki aday (iki admin, ikisi de parolasız/aktif) → 500 `setup_state_invalid`,
    sabit mesaj; hiçbir kullanıcıda `password_hash` dolmaz; kullanıcı sayısı değişmez.
  - Yalnız inactive / silinmiş / admin rolsüz kullanıcı varken → 500
    `setup_state_invalid`, yeni kullanıcı oluşmaz.
  - `admin` rol satırı yok → 500 `setup_state_invalid`.
  - `setup_state_invalid` gövdesi kullanıcı id'si, sayı veya rol ayrıntısı içermez;
    `Set-Cookie` yok.
  - Eşzamanlı iki setup (hem kurtarma hem boş DB dalında) → biri 201, diğeri 409.
- Logout: iki ayrı login ile iki oturum; birinden logout → o çerez 401, diğeri
  hâlâ 200; API anahtarı hâlâ geçerli.
- API anahtarı: ikinci `POST` → 201, ilk anahtar 401, ikinci 200; listede tek
  `revokedAt: null`; `DELETE` → 204, anahtar 401; tekrar `DELETE` → 204;
  bilinmeyen id → 404 `not_found`; `key` `^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$`
  (65 karakter); `keyPrefix` `^ossr_[0-9a-f]{16}$` ve anahtarın ilk 21 karakterine
  eşit; `keyPrefix` gizli kısmı (`S`) içermez; doğru önek + yanlış gizli kısım →
  401; desene uymayan Bearer → 401; eşzamanlı iki `POST` sonrası tek aktif anahtar.
- Bearer ile `POST /api/auth/api-keys`, `DELETE`, logout → 403 `forbidden`;
  anahtar yanıtı yalnız oluşturmada `key` içerir, liste içermez.
- Çapraz `Origin` ile çerezli POST → 403 `origin_rejected`; Origin+Referer yok →
  403; Bearer'lı POST Origin'siz → kabul.
- Yabancı `Host` → 403 `host_rejected` JSON (`/health` ve statik dosya dahil).
- JSON hata: bozuk JSON → 400 `invalid_request` JSON; tanımsız `/api/x` → 404
  JSON; zorlanmış iç hata → 500 `internal_error`, gövdede stack/ham mesaj yok;
  `/health` DB kapalıyken 500 sabit gövde, ham DB mesajı yok.
- Muaf olmayan hiçbir `/api` ucunun girişsiz 200 dönmediğini doğrulayan
  route tablosu testi.
- P-04: kök dışı yol, `..`, junction, önek tuzağı, `SCAN_ROOTS` tanımsız →
  400 `path_not_allowed`; `http://`, `ssh://git@host/x`, `git@host:org/repo.git`, `ext::`, `file://`,
  kullanıcı bilgili URL, UNC, göreli yol → 400 `repo_url_not_allowed`; her
  durumda kayıt/kuyruk yok. SCAN_ROOTS altındaki geçerli yol → 201 (AC-P04-2).
- DB'de parola/anahtar özetinin düz metinle eşleşmemesi.

## Açık noktalar

1. **K8 yorumu:** "repo_url yerel yolsa `repo_url_not_allowed`" kararı,
   REQ-002 AC-P04-2/AC-P04-5 (SCAN_ROOTS altındaki yerel yol `repo_url`
   üzerinden kabul edilir) ile birlikte okunarak şöyle uygulandı: sürücü harfli
   mutlak Windows yolu SCAN_ROOTS kontrolüne girer (`path_not_allowed`); diğer
   yerel biçimler (`file://`, UNC, göreli, aygıt yolu) `repo_url_not_allowed`.
   Bu yorum Accepted ADR-002'nin "Yerel: mutlak Windows yolu (sürücü harfli)"
   sınıflandırmasıyla uyumludur. Kullanıcı `repo_url`'de **hiçbir** yerel yolun
   kabul edilmemesini kastettiyse ayrı bir yerel yol alanı gerekir; bu REQ-002
   değişikliği (product-analyst) ve contract sürüm artışı ister.
2. **ADR-001 (Accepted) ile tutarlılık — doğrulandı (0.2.1):** karar 2 (setup
   otomatik giriş), karar 3 (logout yalnız mevcut oturum), karar 6 (anahtar
   biçimi, `key_prefix`, tam anahtar özetiyle doğrulama), karar 7 (tek aktif
   anahtar + otomatik iptal + `DELETE`), karar 1/3 (parola ≥ 12, 12 sa / 7 gün).
3. **Hâlâ öneri niteliğinde (kullanıcı kararına konu olmadı):** Bearer önceliği,
   idempotent `DELETE` (204), `404`'te yok/başkasına ait ayrımı yapılmaması,
   login'de > 1024 parola için scrypt'siz 401, `name` üst sınırı 100, parola
   uzunluğunun `string.length` ile ölçülmesi, liste sıralaması.
4. P-04 kod adları (`path_not_allowed`, `repo_url_not_allowed`) ADR-002 ile
   aynıdır. `repoUrl` boş projelerin ve `POST /api/scans` `ref` doğrulamasının (ADR-002
   deseni) istek anında yapılıp yapılmayacağı açık.
