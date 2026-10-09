# Target Project Boundaries

Bu kurallar framework repo ile target project repo arasındaki sınırları tanımlar.

## Framework Repo

`~/Developer/agentic-devflow-os` (bu repo)

**İçerir:**
- Agent rol tanımları (`.claude/agents/`)
- Workflow tanımları (`.claude/workflows/`)
- Skill tanımları (`.claude/skills/`)
- Rule tanımları (`.claude/rules/`)
- Context ve task packet şablonları (`.claude/templates/`)
- Plugin build sistemi (`scripts/build_devflow_plugin.py`)
- Governance ve operations dokümantasyonu (`docs/`)

**İçermez:**
- Target project kaynak kodu
- Target project migration dosyaları
- Target project credential veya secret
- Gerçek external MCP bağlantıları

## Target Project Repo

Örnek: `~/Developer/projects/startup-crm`

**Target project içinde framework bu sınırları takip eder:**
- `.devflow/` altında state, context, task packets, runs ve reports tutulur
- Framework'ün yalnızca dışa aktarılan artefaktları (agent, skill, template, workflow) kullanılır
- Framework repo'ya doğrudan referans verilmez; plugin output üzerinden çalışılır

## Target Project `.devflow/` Alanı

```
.devflow/
├── context/          ← context pack'ler ve source register
├── tasks/            ← task packet'ler
├── runs/             ← agent run summary'leri
└── reports/          ← scorecard ve merge recommendation'lar
```

Bu alan Git'te takip edilir ama içinde secret, credential veya kişisel veri bulunmaz.

## Geçiş Sınırları

- Framework repo → target project: yalnızca plugin output (dist/devflow-plugin/)
- Target project → framework repo: geri bildirim ve governance güncellemesi (PR ile)
- Credential, API key veya secret hiçbir yönde geçiş yapmaz
- MCP bağlantısı gerçek external sistemlere framework repo üzerinden kurulmaz

## İlk Target Project Kurulumu

Target project'e framework uygulanmadan önce:
1. Plugin build çalıştırılır: `python3 scripts/build_devflow_plugin.py`
2. `dist/devflow-plugin/` target project'e kopyalanır veya referans gösterilir
3. Target project'te `.devflow/` yapısı oluşturulur
4. Delivery Lead ilk context pack ve source register'ı hazırlar
