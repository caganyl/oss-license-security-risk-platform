# Contract: REQ-009 — Repo erişim anahtarı ve tarama ref'i

- **Sürüm:** 1.0.0 (2026-10-20)
- **İlgili:** REQ-009, ADR-011, REQ-002 auth contract (oturum, `sameOrigin`,
  API anahtarı), REQ-008 web scan contract (proje alanları)

## 1. `PUT /api/projects/{id}/repo-credential`

- **Yetki:** `integrations:write`. Çerezle çağrıda `sameOrigin` zorunlu.
- **Gövde:** `{ "token": string }` — başka alan yok. 1…1024 karakter;
  boşluk ve kontrol karakteri (U+0000–U+001F, U+007F) içermez.
- **200:** `{ "data": { "has_repo_credential": true, "provider": "azure_devops" | "github" | "gitlab" | "bitbucket" } }`
- **400 `invalid_token`:** gövde/token kuralına aykırı.
- **400 `repo_credential_not_applicable`:** projenin `repo_url`'i https değil.
- **400:** `id` geçerli UUID değil.
- **401 / 403:** kimlik yok / yetki yok.
- **404:** proje yok veya silinmiş.
- **Yan etki:** projenin etkin entegrasyonu yoksa oluşturulur
  (`name = 'repo-credential'`, `repo_url = projects.repo_url`,
  `is_active = true`, `created_by = kullanıcı`), varsa `provider`,
  `repo_url`, `access_token_enc`, `updated_at` güncellenir. Denetim kaydı
  `integration_updated` (enum'da yoksa en yakın mevcut eylem), veri:
  `{ provider, has_repo_credential }`.

## 2. Silme

Silme uç noktası yoktur (REQ-009 D-262). Token yalnız §1 ile değiştirilir.

## 3. `GET /api/projects` (genişletme)

Her proje nesnesine `has_repo_credential: boolean` eklenir: projenin
`repo_url`'ine eşit `repo_url`'li, `is_active` ve `access_token_enc IS NOT NULL`
entegrasyonu var mı. Token veya şifreli değer hiçbir alanda yoktur.
`POST /api/projects` ve `PATCH /api/projects/{id}` yanıtları aynı alanı
taşır.

## 4. `POST /api/scans` (dependency, değişiklik)

- `ref` yok, `null` veya boş dize → `scans.ref = NULL`, `ref_type = 'branch'`.
  Worker `--branch` vermeden klonlar (uzak HEAD).
- Projenin §3 kuralıyla eşleşen etkin entegrasyonu varsa
  `scans.integration_id` = o kaydın `id`'si.
- Yanıt şekli değişmez (`ref` artık `null` olabilir).

## 5. Klon hata metni (`scans.error_message`)

Biçim: `<sınıf cümlesi> <temizlenmiş git ayrıntısı>`. Sınıf cümleleri:

| Sınıf | Cümle | Kalıcı |
| --- | --- | --- |
| auth | `Repository requires authentication: add a repo access token to the project, or list the host in GIT_WINDOWS_AUTH_HOSTS.` | evet |
| branch | `Branch not found in the repository.` | evet |
| repo | `Repository not found or no access.` | evet |
| tls | `TLS certificate of the git server is not trusted.` | evet |
| network | `Git server could not be reached.` | hayır |
| diğer | (cümle yok, bugünkü `git clone failed (exit code N): …`) | hayır |

## 6. Yapılandırma

| Değişken | Biçim | Varsayılan |
| --- | --- | --- |
| `GIT_WINDOWS_AUTH_HOSTS` | Virgül/boşlukla ayrılmış tam host adları (`tfs.sirket.local`). Joker, port, şema yasak. | boş (kapalı) |
