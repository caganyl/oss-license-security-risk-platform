# Contract: REQ-010 — Sistem durumu (özellikler)

- **Sürüm:** 1.0.0 (2026-10-20)
- **İlgili:** REQ-010 P-35, REQ-002 auth contract

## `GET /api/system/features`

- **Yetki:** oturum veya API anahtarı + `settings:read`.
- **200:**

```json
{
  "data": {
    "local_scan":        { "enabled": true,  "roots": 1 },
    "web_scan":          { "enabled": false, "allowed_hosts": 0 },
    "zap":               { "enabled": false },
    "registry_enrichment": { "enabled": true },
    "vulnerability_lookup": { "enabled": true },
    "vulnerability_recheck": { "enabled": true },
    "nvd":               { "enabled": true, "api_key": false },
    "repo_tokens":       { "enabled": true },
    "windows_git_auth":  { "enabled": false, "hosts": 0 }
  }
}
```

| Alan | Anlamı | Kaynak |
| --- | --- | --- |
| `local_scan.enabled` / `roots` | Yerel klasör taraması; izinli kök sayısı | `SCAN_ROOTS` (uygulamanın kullandığı liste) |
| `web_scan.enabled` / `allowed_hosts` | Web (URL) taraması; izinli girdi sayısı | `WEB_SCAN_ALLOWED_HOSTS` |
| `zap.enabled` | OWASP ZAP bağlayıcısı tanımlı | `ZAP_API_URL` (+ `ZAP_API_KEY`) |
| `registry_enrichment.enabled` | Kayıt defterinden lisans/telif zenginleştirme | `REGISTRY_ENRICHMENT` |
| `vulnerability_lookup.enabled` | Tarama sırasında OSV sorgusu | `VULNERABILITY_LOOKUP` |
| `vulnerability_recheck.enabled` | Günlük yeniden kontrol | `VULNERABILITY_RECHECK` |
| `nvd.enabled` / `api_key` | NVD CVSS sorgusu açık mı; API anahtarı tanımlı mı (değer değil) | `NVD_ENABLED`, `NVD_API_KEY` |
| `repo_tokens.enabled` | Repo erişim anahtarı (PAT) kaydedilebilir | `ENCRYPTION_KEY` tanımlı mı |
| `windows_git_auth.enabled` / `hosts` | Windows kimliğiyle git; host sayısı | `GIT_WINDOWS_AUTH_HOSTS` |

- Yanıt **hiçbir** ortam değişkeni değeri, host adı, yol, anahtar veya token
  içermez; yalnız boolean ve sayı.
- Geçersiz bir değer başlangıçta zaten reddedildiği için uç nokta yalnız
  çalışan uygulamanın etkin ayarını yansıtır.
- **401 / 403:** kimlik yok / yetki yok.
