# ADR-001: Yerel kimlik doğrulama — tek parola, oturum çerezi, API anahtarı

- **ADR-ID:** ADR-001
- **Durum:** Accepted
- **Tarih:** 2026-10-09 (taslak) · 2026-10-09 (karar)
- **İlgili:** REQ-002 / P-01 (AC-P01-1…10), AC-P02-4, AC-P09-3; rapor kararı K-5 (ve K-2, K-4)
- **İlgili contract:** `docs/contracts/REQ-002-auth-api.md` (bu karara göre güncellenmeli — bkz. Uygulama etkisi)

## Bağlam

`src/app.ts` tüm `/api` isteklerine sabit bir mock admin `req.user` atıyor; gerçek
kimlik doğrulama yok. K-5 kararı verilmiştir: ilk açılışta belirlenen tek yerel
parola + oturum çerezi, CLI/CI için API anahtarı, RBAC kodu kalır, tek rol `admin`.
Kısıtlar: tek Windows makine, tek kullanıcı, HTTP (TLS yok), varsayılan bind
`127.0.0.1`, Docker yok, PostgreSQL var. Bağımlılık listesi yalnızca `dotenv`,
`express`, `pg`, `exceljs`, `pdfkit`; yeni paket eklememe eğilimi var.
Ne `db/schema.sql` ne de migration'lar kullanıcı tohumlar: önceki sabit UUID'li
tohum admin kullanıcısı ve ona ait `user_roles` satırı kullanıcı kararıyla
kaldırılmıştır (commit `9405ff9`). Yalnız rol tohumları (`admin` dahil) durur.
İlk kullanıcıyı yalnız setup akışı oluşturur.

## Karar

1. **Parola saklama:** `node:crypto` `scrypt` (asenkron sürüm; event loop
   bloklanmaz). Parametreler: `N=2^17, r=8, p=1`, `keylen=64`, 16 bayt rastgele
   tuz, `maxmem=256 MiB` (varsayılan 32 MiB bu N için yetmez). Saklama biçimi tek
   metin: `scrypt$<N>$<r>$<p>$<salt_b64>$<hash_b64>` — parametreler kayıtla birlikte
   tutulur, ileride yükseltilebilir. Doğrulama `crypto.timingSafeEqual` ile.
   **Parola uzunluğu: en az 12, en fazla 1024 karakter** (alt sınır kullanıcı
   kararıdır; üst sınır scrypt DoS'una karşı).
2. **Kullanıcı kaydı ve setup:** Parola `users.password_hash` kolonunda tutulur.
   Setup (`POST /api/auth/setup`) hem ilk açılışı hem de kurtarma (karar 12)
   sonrasını aynı akışla karşılar (kullanıcı kararı 2026-10-09, seçenek (b)).
   Tümü **tek transaction** içinde çalışır:
   1. **Kilit:** aday satırlar kilitlenir —
      `SELECT u.id FROM users u JOIN user_roles ur … JOIN roles r … WHERE
      r.name = 'admin' AND u.password_hash IS NULL AND u.status = 'active' AND
      u.deleted_at IS NULL FOR UPDATE OF u`. Eşzamanlı ikinci setup aynı satırda
      bekler; ilki commit edince satırın koşulu yeniden değerlendirilir ve satır
      artık aday değildir.
   2. **Parolası olan kullanıcı varsa** (`password_hash IS NOT NULL`, kilitten
      **sonra** okunur) → `409 setup_already_done`; hiçbir şey değişmez
      (AC-P01-4). Kilitlenen eşzamanlı istek de bu adımda `409` alır.
   3. **Tam olarak bir aday varsa** → yeni parola özeti **o kullanıcıya** yazılır
      (`password_hash`, `password_changed_at`). Yeni kullanıcı oluşturulmaz; geçmiş
      kayıtlar (`finding_reviews.reviewer_id`, `projects.owner_id` vb.), rol ve
      API anahtarları aynı kullanıcıda kalır. Kurtarma (karar 12) sonrası yol
      budur.
   4. **Birden fazla aday varsa** (veri bozukluğu) → setup açık bir hatayla durur,
      transaction geri alınır, **parola atanmaz**; durum log'lanır (parola
      log'lanmadan). Elle düzeltme gerekir.
   5. **Hiç kullanıcı yoksa** (`users` boş) → **yeni bir yerel kullanıcı**
      (`status='active'`, parola özeti dolu) ve tohumlanmış `admin` rolüne bağlanan
      `user_roles` kaydı oluşturulur. İlk kurulum yolu budur (kullanıcı tohumu
      yoktur).
   6. **Kullanıcı var ama aday yok ve parolası olan da yok** (ör. yalnız
      `inactive`/silinmiş veya admin rolsüz kullanıcılar) → 4. maddedeki gibi açık
      hatayla durur; sessizce yeni kullanıcı oluşturulmaz.
   - `admin` rol satırı yoksa setup açık hatayla durur (rol tohumu şema
     bütünlüğünün parçasıdır).
   - Son savunma hattı: `users` üzerinde "en fazla bir kullanıcıda `password_hash`
     dolu" kısmi benzersiz indeksi. Kilitlenecek satır olmayan yolda (5. madde)
     eşzamanlı iki setup'tan ikincisinin yazması bu indekse takılır ve `409`
     olarak döner. Parola belirlendikten sonra setup her zaman `409` döner.
   **Setup sonrası otomatik giriş:** başarılı setup, aynı transaction'da bir
   `sessions` satırı oluşturur ve yanıtta oturum çerezini (`Set-Cookie`) verir;
   kullanıcı ayrıca login olmaz. Setup'a login ile aynı Host/Origin kontrolleri
   uygulanır (karar 5).
3. **Oturum:** Oturumlar **PostgreSQL'de `sessions` tablosunda** tutulur (bellek
   değil). Gerekçe: F1'de API süreci `ts-node` ile sık yeniden başlatılır (bellek
   oturumu her restartta düşer); oturum iptali sunucu tarafında tek `DELETE` ile
   yapılır; test DB'si ile deterministik test edilir; `express-session` gibi yeni
   paket gerekmez. Çerez değeri 32 bayt rastgele (base64url); DB'de yalnızca
   SHA-256 hex özeti saklanır (DB okuması oturum çalmaya yetmez). Her login ve setup
   yeni token üretir (session fixation yok).
   **Süre:** boşta kalma **12 saat** (`last_seen_at`), mutlak **7 gün**
   (`expires_at`); süresi dolanlar login sırasında temizlenir. `Cookie` başlığı
   küçük bir yerel fonksiyonla ayrıştırılır (`cookie-parser` eklenmez).
   **Logout (`POST /api/auth/logout`) yalnız mevcut oturumu kapatır:**
   `DELETE FROM sessions WHERE id = <mevcut sessions.id>` + çerez temizleme. Diğer
   tarayıcı/oturumlar ve API anahtarları etkilenmez. Logout yalnız çerezle
   çağrılabilir. Oturum bilgisi `GET /api/auth/me` ile okunur (UI'ın açılış
   kontrolü; ayrıntı contract'ta).
4. **Çerez:** ad `ossrisk_session`; `HttpOnly; SameSite=Strict; Path=/;
   Max-Age=604800`; `Domain` yok; **`Secure` yok** (HTTP/localhost — K-4/kapsam dışı
   TLS). `__Host-` öneki `Secure` gerektirdiği için kullanılmaz.
5. **CSRF / DNS rebinding:** (a) `SameSite=Strict`; (b) çerezle doğrulanan
   durum değiştiren isteklerde (`POST/PUT/PATCH/DELETE`) ve login/setup'ta `Origin`
   (yoksa `Referer` kökeni) izinli köken listesinde olmalı, ikisi de yoksa `403`;
   (c) **tüm isteklerde `Host` başlığı izin listesinde olmalı** (`127.0.0.1:<PORT>`,
   `localhost:<PORT>`, `[::1]:<PORT>`, ve `HOST` farklıysa o değer) — DNS rebinding
   ile setup penceresinin ele geçirilmesini önler. CORS başlığı hiç verilmez.
   `Authorization` başlıklı (API anahtarlı) istekler Origin kontrolünden muaftır
   (tarayıcı bu başlığı çapraz kökenli olarak preflight'sız gönderemez).
6. **API anahtarı — biçim ve doğrulama:**
   - **Biçim:** `ossr_<P>_<S>`
     - `P` = 8 bayt CSPRNG (`crypto.randomBytes`), **küçük harf hex, 16 karakter
       (64 bit)** — görüntüleme/ayırt etme öneki.
     - `S` = 32 bayt CSPRNG, **base64url (dolgusuz), 43 karakter (256 bit)** — gizli kısım.
     - `P` ve `S` birbirinden **bağımsız** üretilir; `P`'nin gösterilmesi `S`'nin
       entropisinden hiçbir şey eksiltmez.
     - Doğrulama düzenli ifadesi (sabit uzunluk; `S` içindeki `_`/`-` belirsizlik
       yaratmaz): `^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$` (toplam 65 karakter).
       Aynı ifade gitleaks özel kuralı olarak kullanılabilir.
   - **Saklama:** `api_keys.key_hash` = tam anahtar metninin (`ossr_<P>_<S>`, UTF-8)
     SHA-256 hex özeti; `api_keys.key_prefix` = `ossr_<P>` (21 karakter). Düz metin
     anahtar saklanmaz. Yüksek entropi nedeniyle yavaş özet (scrypt) gerekmez.
   - **Doğrulama:** gelen değer önce düzenli ifadeyle biçim kontrolünden geçer
     (uymazsa özet hesaplanmadan `401`); ardından **tam anahtarın SHA-256 özeti**
     `key_hash` ile aranır (`revoked_at IS NULL`). `key_prefix` kimlik doğrulamada,
     arama anahtarı olarak veya karşılaştırmada **kullanılmaz** — yalnızca UI
     listesinde, denetim kaydında ve log korelasyonunda gösterim içindir. Bu
     sayede önek sızsa da (log, ekran görüntüsü) anahtar tahmin edilemez.
   - **İletim:** **yalnız** `Authorization: Bearer <anahtar>`; query string kabul
     edilmez. Anahtar oluşturma yanıtında **bir kez** gösterilir, log'a yazılmaz
     (log'da yalnız `key_prefix` veya `apikey:<api_keys.id>` görünebilir).
     Anahtar yönetimi uç noktaları yalnızca oturum çereziyle çağrılabilir (sızmış
     bir CI anahtarı yeni anahtar üretemez veya iptal edemez).
7. **Rotasyon/iptal (F1 kapsamında):**
   - Kullanıcı başına **tek aktif anahtar**. Yeni anahtar üretmek
     (`POST /api/auth/api-keys`), aynı transaction'da mevcut aktif anahtarı
     `revoked_at = now()` ile iptal eder.
   - Açık iptal: **`DELETE /api/auth/api-keys/{id}`** — satırı silmez,
     `revoked_at` doldurur (denetim izi korunur). Yanıt kodları ve idempotentlik
     ayrıntısı contract'ın konusudur.
   - "Tek aktif" kuralı kısmi benzersiz indeksle `(user_id) WHERE revoked_at IS NULL`
     DB seviyesinde zorlanır; şema ileride çoklu anahtara açılabilir.
8. **Kimlik türetme (AC-P01-7/8):** Mock middleware silinir. Auth middleware
   sırası: Host kontrolü → statik dosyalar ve `/health` → `/api/auth/login`,
   `/api/auth/setup` → çerez veya Bearer doğrulama → `req.user` (DB'den kullanıcı +
   roller; `status='active'`, `deleted_at IS NULL`) → mevcut router'lar ve RBAC
   guard'ları. `sessionId` alanı: oturumda `sessions.id`, API anahtarında
   `apikey:<api_keys.id>`. Controller'lardaki sabit UUID geri dönüşleri
   (`req.user?.id || '0000…'`) kaldırılır.
9. **Muaf uç noktalar (yalnız bunlar):** `GET /health` (`/api` dışı),
   `POST /api/auth/login`, `POST /api/auth/setup`; statik `public/` dosyaları ve
   `/` (veri içermez). UI'ın "login mi setup mı" kararı ayrı muaf uç nokta
   olmadan verilir: parola hiç belirlenmemişse her `/api` `401` yanıtının gövdesi
   `code: "setup_required"`, aksi halde `code: "unauthenticated"` taşır.
10. **Bind:** `HOST` env (varsayılan `127.0.0.1`), `app.listen(port, host)`.
    Loopback dışı bir değer verilirse başlangıçta "HTTP üzerinden düz metin"
    uyarısı log'lanır.
11. **Brute-force:** Basit, bellek içi, tek sayaçlı yavaşlatma: art arda 5 hatalı
    denemeden sonra `429` + `Retry-After`; bekleme 30 sn'den başlayıp iki katına
    çıkar (üst sınır 15 dk), başarılı login'de sıfırlanır. Yeni paket gerekmez;
    restartta sıfırlanması kabul edilir (tehdit modeli: yerel süreç/zararlı sayfa).
12. **Parola kurtarma ve değiştirme:**
    - Unutulan parola, **belgelenmiş bir SQL adımıyla** kurtarılır (UI/API yok).
      Adım tek transaction'dır: ilgili kullanıcının `password_hash` ve
      `password_changed_at` alanları `NULL` yapılır ve **tüm `sessions` satırları
      silinir**; böylece setup yeniden açılır ve uygulama `setup_required` döner.
      Bu adımdan sonra setup, karar 2 madde 3 gereği yeni parolayı **aynı
      kullanıcıya** atar (yeni kullanıcı oluşturulmaz).
      API anahtarlarına dokunulmaz (kurtarma ele geçirme anlamına gelmez); ele
      geçirme şüphesinde yeni parolayla girildikten sonra anahtar
      `DELETE /api/auth/api-keys/{id}` ile iptal edilir. Adım makineye ve DB'ye
      erişimi olan kişi tarafından `psql` ile çalıştırılır ve `db/README.md`
      (veya eşdeğer operasyon notu) içinde belgelenir.
    - Oturumlu parola değiştirme uç noktası **F1 kapsamı dışıdır**.

## Gerekçe

Tek kullanıcı ve loopback bind ile asıl tehditler: tarayıcıdaki zararlı sayfa
(CSRF, DNS rebinding, ilk açılış penceresinin ele geçirilmesi) ve repoya/log'a sızan
sırlar. `SameSite=Strict` + Origin + Host kontrolü bu sınıfı yeni bağımlılık
olmadan kapatır. scrypt Node içinde yerleşiktir ve OWASP'ın scrypt asgari
parametrelerini karşılar. DB oturumu, PostgreSQL zaten zorunlu olduğundan ek
bileşen getirmez. Bağımsız rastgele önekli anahtar biçimi, gösterim kolaylığı ile
gizli kısmın entropisini birbirinden ayırır.

## Değerlendirilen alternatifler

- **Bellek içi oturum:** Daha basit; ama restartta oturum kaybı, F2'ye kadar
  süreç ayrımı ve iptal semantiği zayıf. Reddedildi.
- **İmzalı/stateless çerez (HMAC, JWT):** Sunucu tarafı iptal yok, ek gizli anahtar
  yönetimi gerekir. Reddedildi.
- **argon2 / bcrypt paketleri:** Native derleme (Windows'ta node-gyp riski) ve yeni
  bağımlılık. scrypt yeterli. Reddedildi.
- **`express-session`, `cookie-parser`, `express-rate-limit`, `csurf`:** Yeni
  bağımlılık; ihtiyaç birkaç düzine satırlık yerel kodla karşılanıyor. Reddedildi.
- **Setup için konsola basılan tek kullanımlık kod:** İlk açılış penceresini yerel
  diğer kullanıcılara karşı da kapatır; tek kullanıcılı makinede ek karmaşıklık.
  F1'de seçilmedi; ileride eklenebilir.
- **Ayrı muaf `GET /api/auth/status`:** AC-P01-1'in muafiyet listesini genişletir.
  Reddedildi; `401` gövdesindeki `code` alanı aynı işi görür.
- **Setup sonrası ayrı login adımı:** Ek ekran, kullanıcı değeri yok; setup zaten
  aynı Host/Origin korumalarına tabi. Reddedildi (otomatik giriş seçildi).
- **Logout'ta kullanıcının tüm oturumlarını silmek:** Tek kullanıcılı yerel
  kullanımda başka tarayıcı/oturumları gereksiz yere düşürür; toplu iptal ihtiyacı
  kurtarma SQL adımında karşılanır. Reddedildi.
- **API anahtarı `ossr_` + 32 bayt base64url, `key_prefix` = ilk 8 karakter
  (önceki taslak):** Görüntülenen önekte yalnız 3 rastgele karakter (~18 bit)
  kalıyordu; ayırt edicilik zayıf. Reddedildi.
- **Öneki gizli kısmın ilk N karakterinden almak:** Gösterilen önek gizli kısmın
  entropisini azaltır. Reddedildi; önek bağımsız üretilir.
- **Önekle arama + gizli kısmın ayrı özeti (iki aşamalı doğrulama):** Ek kolon ve
  mantık, kazanç yok (tam anahtar özeti zaten benzersiz indeksli). Reddedildi.
- **Çoklu aktif anahtar:** F1 tek kullanıcı/tek CI için gereksiz yüzey. Reddedildi
  (şema genişlemeye açık).
- **Oturumlu parola değiştirme / e-posta ile kurtarma:** F1'de gereksiz; e-posta
  altyapısı yok. Reddedildi (F1 dışı).
- **Kurtarmada eski kullanıcıyı devre dışı bırakıp setup'ta yeni kullanıcı
  oluşturmak (seçenek (a)):** Kurtarma adımı eski kullanıcıyı `inactive` yapar ve
  API anahtarlarını iptal ederdi. Geçmiş kayıtların atıfları pasif kullanıcıda
  kalır, CI anahtarı her kurtarmada yeniden üretilmek zorunda kalır ve
  `users.email UNIQUE` yüzünden yeni kullanıcıya farklı e-posta gerekir.
  Reddedildi (kullanıcı kararı 2026-10-09).
- **Mevcut hâli kabul edip sonuçları belgelemek (seçenek (c)):** Kurtarma sonrası
  setup ikinci bir aktif admin oluşturur; eski kullanıcının rolü ve API anahtarı
  geçerli kalır, atıflar ikiye bölünür. Reddedildi (kullanıcı kararı 2026-10-09).

## Sonuçlar / Uygulama etkisi

- **Güvenlik:** Parola ve API anahtarı düz metin saklanmaz/loglanmaz (AC-P01-5).
  Login hatalarında parola veya token log'a yazılmaz; `401` yanıtı "kullanıcı yok"
  ile "parola yanlış"ı ayırt etmez. `Secure` bayrağı olmadığı için ağa açık
  kullanım (`HOST=0.0.0.0`) çerez/anahtar sızıntısına açıktır — kapsam dışı ve
  başlangıç uyarısıyla belgelenir. `/health` hata durumunda ham DB hata mesajı
  döndürmemeli (bilgi sızıntısı; küçük düzeltme önerisi). Logout yalnız mevcut
  oturumu kapattığından, çalınmış bir çerezin iptali kurtarma SQL adımı veya
  oturumun süre dolumu ile olur (tek kullanıcılı yerel tehdit modelinde kabul).
- **Test (Vitest, AC-P01-10):** girişsiz `/api` → `401` (+ `code`); geçerli çerez →
  `200`; geçerli Bearer → `200`; geçersiz/iptal edilmiş Bearer → `401`; biçime
  uymayan Bearer → `401`; yanlış parola → `401` ve `Set-Cookie` yok; setup →
  `Set-Cookie` ile oturum açılır; setup ikinci kez → `409`; parola < 12 → `400`;
  boş DB'de setup yeni kullanıcı + `admin` rolü oluşturur; kurtarma SQL adımı
  sonrası setup aynı kullanıcıya (aynı `id`) parola atar, kullanıcı sayısı artmaz
  ve mevcut API anahtarı çalışmaya devam eder; birden fazla aday ve "kullanıcı var
  ama aday yok" durumlarında açık hata, parola atanmaz; `admin` rolü yokken açık
  hata; eşzamanlı iki setup'ta biri başarılı, diğeri `409`;
  çapraz `Origin` ile POST → `403`; yabancı `Host` → `400/403`; logout sonrası aynı
  çerez `401`, ikinci oturum hâlâ geçerli; yeni anahtar üretimi eskisini iptal
  eder; `DELETE /api/auth/api-keys/{id}` sonrası anahtar `401`; boşta 12 sa / mutlak
  7 gün sınırı (saat enjeksiyonuyla); varsayılan bind `127.0.0.1`; DB'de özetin
  düz metinle eşleşmediği; `key_prefix`'in anahtarın gizli kısmını içermediği.
  Testler ayrı test DB'sinde (AC-G-5).
- **Migration (database-engineer):** aşağıdaki şema değişiklikleri. Migration'lar
  kullanıcı tohumlamaz; `users` için yalnızca kolon/indeks eklenir. Çalıştırma yöntemi ADR-003 (d).
- **Contract (contract-broker):** `docs/contracts/REQ-002-auth-api.md` ve
  `REQ-002-auth-api.openapi.yaml` bu karara göre güncellenmelidir: setup `201` +
  `Set-Cookie` kesinleşti; logout yalnız mevcut oturum (contract şu an "tüm
  oturumlar" diyor); anahtar biçimi `ossr_<16 hex>_<43 base64url>` ve
  `keyPrefix` = `ossr_<16 hex>`; `DELETE /api/auth/api-keys/{id}` kapsamda.

### Şema değişiklikleri (migration `002_local_auth`)

| Nesne | Değişiklik |
| --- | --- |
| `users` | `password_hash TEXT NULL`, `password_changed_at TIMESTAMPTZ NULL` |
| `users` | kısmi benzersiz indeks: en fazla bir satırda `password_hash IS NOT NULL` (ör. `ON users ((true)) WHERE password_hash IS NOT NULL`) |
| `sessions` (yeni) | `id UUID PK`, `user_id UUID NOT NULL → users ON DELETE CASCADE`, `token_hash TEXT NOT NULL UNIQUE` (sha256 hex), `created_at`, `last_seen_at`, `expires_at TIMESTAMPTZ NOT NULL`; indeks `(expires_at)`, `(user_id)` |
| `api_keys` (yeni) | `id UUID PK`, `user_id UUID NOT NULL → users ON DELETE CASCADE`, `name TEXT`, `key_hash TEXT NOT NULL UNIQUE` (tam anahtarın sha256 hex'i), `key_prefix TEXT NOT NULL` (`ossr_<16 hex>`), `created_at`, `last_used_at`, `revoked_at TIMESTAMPTZ NULL` |
| `api_keys` | kısmi benzersiz indeks `(user_id) WHERE revoked_at IS NULL` (tek aktif anahtar) |
| `roles` | `admin` satırının varlığı (001 tohumluyor; migration doğrular) |

## Kanıt (Evidence)

- Repo incelemesi: `src/app.ts` (mock `req.user`), `db/schema.sql` ve
  `db/migrations/001_initial_core_schema.up.sql` (`users`, `roles`, `user_roles`;
  yalnız rol tohumları — kullanıcı tohumu commit `9405ff9` ile kaldırıldı), `docs/contracts/REQ-002-auth-api.md` açık noktaları 1–8.
- Dış kaynak: OWASP Password Storage Cheat Sheet (scrypt asgari parametreleri) —
  genel bilgi, doğrulanması önerilir. NotebookLM veya Obsidian kaynağı kullanılmadı.

## İlgili REQ / AC

REQ-002: AC-P01-1…AC-P01-10, AC-P02-4, AC-P09-1/3 (yeni sır üretilmez; anahtarlar
yalnız özet olarak saklanır), AC-G-3/4/5.

## Kalan notlar (karar gerektirmeyen)

1. Setup için konsol kodu (Jenkins tarzı) ileride eklenebilir.
2. Security Red Team review'u implementation sonrası, release öncesi önerilir.
3. Implementation tamamlandığında `docs/handoffs/REQ-002.md` güncellenmelidir.

## Onay (Approval)

- **Karar sahibi:** proje sahibi (kullanıcı). Açık kalan insan kararları
  (API anahtarı rotasyon/iptal kapsamı, parola kurtarma/değiştirme, oturum
  süreleri, parola alt sınırı, setup sonrası otomatik giriş, logout kapsamı,
  anahtar öneki, kurtarma sonrası setup'ın aynı kullanıcıya parola ataması —
  seçenek (b)) **2026-10-09** tarihinde verildi ve bu ADR'ye işlendi; durum
  `Accepted`. Kararlar ana oturum aracılığıyla iletilmiştir; kullanıcının bu
  dosyayı gözden geçirip commit etmesi kaydı kesinleştirir.
- Bu karar **güvenlik sınırını ve veri modelini** değiştirir. Implementation
  başlamadan önce ayrıca gereken kapılar: güncellenmiş auth contract'ın onayı ve
  `docs/ownership/REQ-002.json` `status: approved`.
