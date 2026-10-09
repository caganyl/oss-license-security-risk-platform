# Context Distribution Rules

Bu kurallar agent'lara hangi bağlamın nasıl dağıtılacağını tanımlar.

## Temel İlke

Her agent yalnızca kendi görevini tamamlamak için gereken minimum bağlamı alır.
Tüm vault, tüm doküman seti veya tam repo içeriği asla tek bir agent'a gönderilmez.

## Context Pack İçeriği

Her task-specific context pack şunları içermelidir:

```yaml
context_pack:
  req_id: REQ-XXX
  task_summary: "kısa görev tanımı"
  relevant_requirements:
    - req_id: REQ-XXX
      summary: "..."
      ac_snippet: "ilgili acceptance criteria"
  relevant_contracts:
    - path: "docs/contracts/..."
      summary: "..."
  relevant_decisions:
    - path: "docs/architecture/adr/..."
      summary: "..."
  evidence_from_notebooklm:
    - finding: "..."
      source: "doküman adı"
      confidence: "high/medium/low"
      note: "doğrulanması gerekiyor"
  strategic_context_from_obsidian:
    - note: "..."
      relevance: "neden dahil edildi"
  known_risks: []
  out_of_scope: []
```

## Dağıtım Kuralları

### Product Analyst
- PRD geçmişi, rakip analiz, kullanıcı araştırması özeti
- Mevcut requirement'lar (ilgili REQ'ler)
- Obsidian: stratejik ürün bağlamı (seçili notlar)

### Solution Architect
- Mevcut ADR'lar
- Sistem sınırları ve dependency grafiği
- NotebookLM: teknik araştırma bulguları

### Contract Broker
- Mevcut contract'lar (OpenAPI, event, DB schema)
- Frontend + Backend interface beklentileri özeti
- Requirement'tan gelen data model ipuçları

### Frontend Engineer
- Onaylı contract (API spec, event spec)
- Design spec veya mockup referansı
- Yalnızca frontend dosya alanı ile ilgili ADR'lar

### Backend Engineer
- Onaylı contract (API spec, event spec, DB schema)
- Yalnızca backend ve service layer ile ilgili ADR'lar
- Security kısıtlamaları özeti

### Database Engineer
- DB schema contract
- Migration geçmişi özeti
- Rollback gereksinimleri

### AI/Data Engineer
- AI/ML ile ilgili ADR'lar
- Eval konfigürasyonları
- Model ve provider kısıtlamaları

### QA Automation
- Acceptance criteria (tam liste)
- Mevcut test coverage durumu
- Regression risk alanları

### Security Red Team
- Tehdit modeli (varsa)
- Auth/authz contract'ları
- Bilinen güvenlik kısıtlamaları

### Design Reviewer
- UI mockup/spec referansları
- Erişilebilirlik gereksinimleri
- Marka ve tasarım sistemi referansları

## Hassas Veri Kuralları

Hiçbir agent'a şunlar gönderilmez:
- API key, token veya secret
- Production credential'ları
- Kişisel kullanıcı verisi
- Ham NotebookLM belgesi (yalnızca evidence summary)
- Tam Obsidian vault içeriği (yalnızca seçilen notlar özeti)

## Context Yaşam Döngüsü

```
1. Delivery Lead context ihtiyacını belirler
2. project-context-synthesis skill çalışır
3. source-register güncellenir
4. task-specific context pack üretilir
5. İlgili agent'a iletilir
6. Agent görevini tamamlar
7. Output git artefaktına dönüştürülür
8. Context pack sonraki task için güncellenir
```
