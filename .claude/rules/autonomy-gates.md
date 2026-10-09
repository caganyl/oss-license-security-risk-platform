# Autonomy Gates

Bu kurallar hangi işlemlerin otomatik, hangilerinin insan onaylı olduğunu tanımlar.

## Otomatik (İnsan Onayı Gerektirmez)

Aşağıdaki işlemler agent'lar tarafından bağımsız yürütülebilir:

### Araştırma ve Planlama
- Kod okuma, grep, glob, dosya keşfi
- Requirement analizi ve acceptance criteria çıkarımı
- Risk analizi ve bağımlılık haritası
- Context pack üretimi
- Task graph oluşturma

### Draft Üretimi
- Requirement taslağı (PR açmadan)
- ADR taslağı (PR açmadan)
- Contract taslağı (PR açmadan)
- Test taslağı (commit etmeden)
- Handoff güncellemesi taslağı

### Local Geliştirme
- Feature branch'te kod yazma
- Feature branch'te test yazma
- Local test çalıştırma (read-only)
- Lint ve typecheck

### Review
- Security review raporu üretimi
- Design review raporu üretimi
- EvalOps scorecard taslağı
- Release scorecard taslağı

## İnsan Onayı Gerektirir

Aşağıdaki işlemler insan onayı olmadan yapılmaz:

### Git ve Deployment
- main branch merge
- Production deployment
- Force push
- Branch silme

### Veritabanı ve Altyapı
- Production database migration
- Cloud resource oluşturma veya silme
- Production altyapı değişikliği
- Rollback kararı

### Güvenlik ve Kimlik
- Secret veya API key değişikliği
- Permission ve role değişikliği
- External service entegrasyonu başlatma

### Dış Sistemler
- Gerçek MCP bağlantısı kurma
- External API'ye write işlemi
- Ödeme veya billing işlemi
- E-posta, Slack veya bildirim gönderme (üretim ortamında)

### Geri Döndürülemez İşlemler
- Veri silme veya toplu veri güncellemesi
- Log veya audit trail temizleme
- Production ortamında destructive operasyon

## Approval Gate Süreci

Bir işlem insan onayı gerektirdiğinde:
1. Agent durur ve gerekçeyi açıkça açıklar
2. Yapılacak işlemi ve etkisini özetler
3. Alternatif daha güvenli yaklaşım varsa önerir
4. Onay beklenmeden devam etmez

## Recovery Yaklaşımı

Agent session kesilirse:
1. Run summary ve açık task listesi üzerinden devam edilir
2. Yarım kalan işler tamamlanmadan delivery bitmiş ilan edilmez
3. Otomatik/onaylı sınır ihlali olup olmadığı kontrol edilir
