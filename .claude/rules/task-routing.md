# Task Routing Rules

Bu kurallar hangi task türünde hangi agent rollerinin devreye alınacağını tanımlar.

## Routing Tablosu

| Task türü             | Ana roller                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------ |
| Yeni ürün fikri       | Delivery Lead, Product Analyst, Design Reviewer, Solution Architect                        |
| Yeni feature          | Delivery Lead, Product Analyst, Solution Architect, Contract Broker, Frontend, Backend, QA |
| AI/RAG özelliği       | Delivery Lead, AI/Data Engineer, EvalOps Reviewer, Security Red Team, Backend Engineer     |
| Veri dashboard'u      | Delivery Lead, AI/Data Engineer, Design Reviewer, Backend Engineer, QA Automation         |
| Bug                   | Delivery Lead, QA Automation, ilgili domain engineer (Frontend/Backend/Database/AI)        |
| Güvenlik riski        | Security Red Team, Backend Engineer, Delivery Lead, gerekirse Database Engineer            |
| Release               | QA Automation, Security Red Team, Integration/Release                                      |
| Maliyet optimizasyonu | Delivery Lead, Solution Architect, AI/Data Engineer, Integration/Release                   |

## Minimum Rol Seçimi İlkesi

Her task'te tüm roller çağrılmaz. Delivery Lead şu faktörlere göre minimum rol setini seçer:

1. **Task türü** — yukarıdaki tablo temel seti belirler
2. **Bağımlılıklar** — hangi rol diğerinden önce gelir
3. **Risk seviyesi** — yüksek risk → daha fazla review rolü
4. **Ownership sınırları** — aynı dosya alanına paralel assignment yapılmaz
5. **Mevcut artefaktlar** — contract varsa Contract Broker atlanabilir

## Rol Seçimi Karar Ağacı

```
Task geldiğinde:
  1. Task türünü belirle (yukarıdaki tablo)
  2. Requirement (REQ-ID) var mı?
     → Hayır: Product Analyst devreye al
  3. Acceptance criteria tanımlı mı?
     → Hayır: Product Analyst devreye al
  4. Mimari karar gerekiyor mu?
     → Evet: Solution Architect devreye al
  5. Frontend + Backend paralel çalışacak mı?
     → Evet: Contract Broker önce devreye al
  6. AI/ML/LLM bileşen var mı?
     → Evet: EvalOps Reviewer ekle
  7. Security-sensitive alan mı?
     → Evet: Security Red Team ekle
  8. Release hazırlığı mı?
     → Evet: Integration/Release ekle
```

## Paralel Çalışma Kuralları

Paralel assignment yalnızca ownership path'leri ayrık olduğunda kullanılır:

**Paralel olabilir:**
- Frontend + Backend (contract onayı sonrası, farklı dosya alanları)
- QA + Backend (test ve implementation, farklı dosya alanları)
- Design Reviewer + Implementation (review ve kod, farklı dosya alanları)

**Paralel olamaz:**
- Aynı modül veya dosyaya dokunacak iki implementation rolü
- Contract tanımlanmadan Frontend + Backend
- Security review tamamlanmadan release

## Approval Gate Noktaları

Her routing planında şu gate'ler belirtilir:
- Contract review gate (frontend/backend paralel başlamadan önce)
- Security review gate (release öncesi)
- Human approval gate (main merge öncesi)
- QA acceptance gate (completion öncesi)
