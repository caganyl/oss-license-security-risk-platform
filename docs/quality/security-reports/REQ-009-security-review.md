# REQ-009 Güvenlik İncelemesi

- **Tarih:** 2026-10-20
- **Kapsam:** `PUT /api/projects/{id}/repo-credential`, `has_repo_credential`,
  tarama–entegrasyon bağlantısı, `ref = NULL`, `GIT_WINDOWS_AUTH_HOSTS`
  (Windows kimliği), klon hata sınıflandırması, `/_git/` Basic kullanıcı adı
  kuralı, arayüz değişiklikleri.
- **Yöntem:** Salt okunur, karşıt kod incelemesi (ayrı inceleme agent'ı;
  `devflow-plugin:security-red-team` bu oturumda yüklü değildi). Ağ isteği
  yapılmadı.
- **Sonuç:** **Go** (M1 düzeltildikten sonra). Critical ve High bulgu yok.

## Bulgular

| ID | Önem | Bulgu | Durum |
| --- | --- | --- | --- |
| M1 | Medium | Windows kimliği, listedeki hostun her portuna veriliyordu (`https://tfs.corp:8443/…` de kimlik alıyordu). Aynı hosttaki başka bir servis NTLM/Negotiate hedefi olabilirdi. | **Düzeltildi:** `windowsAuthOriginFor` yalnız varsayılan (443) portta origin döndürür; birim testi eklendi. |
| L1 | Low | Sunucu 401 dönerse git `credential reject` çağırır, GCM kullanıcının kayıtlı TFS kimliğini silebilir. Sızıntı değil. | Kabul; ADR-011'e not düşüldü. PAT yolu bu riski taşımaz. |
| L2 | Low | GCM `GCM_INTERACTIVE=never`'ı yok sayarsa klon zaman aşımına kadar bekler. | Kabul; zaman aşımı + süreç ağacı sonlandırma mevcut. Gerçek TFS'te elle doğrulanacak. |
| L3 | Low | IDN host adları listeye yazılamaz (yalnız ASCII). Güvenli yönde kısıt. | ADR-011'de punycode notu. |
| L4 | Low | Sunucunun `remote:` satırları sınıflandırmayı yanıltabilir (yanlış yönlendirme cümlesi). Metin düz metin olarak gösterilir, XSS yok. | Kabul. |
| L5 | Low | Proje oluşturma ve token kaydı ayrı adımlar; token kaydı başarısızsa proje kalır. | **Düzeltildi:** arayüz bu durumda taramayı başlatmaz, kullanıcıya token'ı Projeler ekranından eklemesini söyler. |

## Doğrulanan (sorun yok)

- Token argv, URL, `.git/config`, yanıt, denetim kaydı ve hata metninde yok;
  host kapsamlı `extraHeader` olarak yalnız klon ortamında.
- SQL parametrik; `hasRepoCredentialSql` yalnız sabit tablo adı alır.
- Yetki `integrations:write` (yalnız admin); oturumlu yazmalarda
  `sameOrigin` genel olarak uygulanıyor. `repo_url` PATCH ile değişmediği için
  token başka hosta kaydırılamaz; tarama bağlantısı `i.repo_url = p.repo_url`.
- Windows kimliği origin kapsamlı; yönlendirme kapalı, alt modül yok,
  `GIT_ALLOW_PROTOCOL=https`, userinfo reddi, token varsa mod kapalı.
- `/_git/` kuralı yalnız Basic kullanıcı adını belirler, hedef host'u değil.
- Arayüz: `scanErrorDetail` ve modal metinleri düz metin; `innerHTML` yok.
