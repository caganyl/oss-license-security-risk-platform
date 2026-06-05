# OSS License & Security Risk Platform

**Projenin Amacı ve Detaylı Açıklaması**

**OSS License & Security Risk Platform** projesinin ana amacı; şirket içerisindeki yazılım uygulamalarında kullanılan açık kaynak bileşenleri merkezi olarak tespit eden, lisans ve güvenlik risklerini analiz eden, SBOM (Yazılım Malzeme Listesi) üreten, telif (copyright) ve bildirim (notice) yükümlülüklerini kontrol eden kurumsal bir platform geliştirmektir [1]. Platformun temel vizyonu, şirket genelindeki tüm yazılım uygulamalarının açık kaynak bileşenlerini görünür hale getirmek ve riskleri merkezi olarak yönetmektir [2]. 

Bu ürün, sadece "hangi kütüphane kullanılmış" sorusuna yanıt veren klasik bir tarama aracı olmanın ötesinde, şirket uygulamalarındaki açık kaynak kullanımını uçtan uca yöneten bir **OSS Risk & Compliance Management Platform** olarak tasarlanmıştır [1, 3]. Gelişen projelerde sıklıkla karşılaşılan görünürlük eksikliği, GPL/AGPL gibi lisansların oluşturduğu yasal riskler, zafiyet içeren paketlerden doğan güvenlik tehditleri, telif yükümlülüklerinin atlanması, iç denetimlerdeki zorluklar ve riskin kim tarafından yönetileceğinin bilinmemesi (sahiplik belirsizliği) gibi kritik sorunları tek bir merkezi yapıda çözmeyi amaçlamaktadır [2, 4]. Sistem, teknik ekiplere detaylı analiz ekranları sunarken; yönetim kademesi için özet risk panelleri, hukuk/uyum ekipleri için lisans değerlendirme sayfaları ve güvenlik ekipleri için zafiyet takip ekranları sağlayarak çoklu bir kontrol merkezi işlevi görür [1, 5].

**Projenin Kapsamı**

Platformun kapsamı, ilk sürüm olan "MVP Kapsamı" ve "Sonraki Faz Kapsamı" olarak iki aşamada detaylandırılmıştır:

*   **MVP (İlk Versiyon) Kapsamı:** Sistemin çekirdek yapısını oluşturan Dashboard, proje yönetimi, repository ve dosya tabanlı tarama, bağımlılık envanteri (dependency inventory), lisans risk motoru (license risk engine), güvenlik zafiyeti yönetimi (security finding), copyright/notice kontrolü, SBOM üretimi, inceleme ve onay iş akışları (review workflow), raporlama merkezi, kullanıcı/rol yönetimi, denetim izi (audit log), sistem ayarları ve temel entegrasyon altyapısını içerir [6].
*   **MVP Dışı (Sonraki Faz) Kapsamı:** İlerleyen süreçte CI/CD pipeline (GitHub/GitLab, Azure DevOps) entegrasyonları, otomatik kural zorlama (policy enforcement), Pull Request (PR) seviyesinde lisans kontrolü eklenecektir [7]. Ayrıca Jira üzerinden task oluşturma, Teams/Slack bildirimleri, gelişmiş SBOM karşılaştırmaları, yapay zeka destekli düzeltme (remediation) önerileri, risk trend analitiği, tedarikçi bazlı risk yönetimi ve şirket uygulama portföyünün genel risk haritası projeye dahil edilecektir [7].

**Tüm Gereksinimleri**

Sistemin tüm gereksinimleri fonksiyonel, fonksiyonel olmayan ve güvenlik olmak üzere üç ana başlıkta son derece detaylı şekilde ele alınmıştır:

**1. Fonksiyonel Gereksinimler:**
*   **Proje Yönetimi ve Tarama:** Kullanıcılar proje oluşturabilmeli, düzenleyebilmeli, proje sahibi ve teknik sorumlu atayabilmeli, teknoloji yığınını (stack) ve uygulamanın kritiklik seviyesini (Low, Medium, High, Critical) belirleyebilmelidir [8, 9]. Tarama işlemleri manuel, zamanlanmış, release öncesi, PR esnasında, dosya yükleme veya repo bağlantısı üzerinden yapılabilmelidir [10]. Taramaların durumu izlenebilmeli ve tarama geçmişi saklanmalıdır [9, 11].
*   **Lisans ve Güvenlik Analizi:** Motor, tespit edilen paket lisanslarını normalize etmeli, tanımlanmış politikalara göre lisans risk seviyesi hesaplamalı ve "Unknown license" (bilinmeyen lisans) bulgularını tespit etmelidir [11]. Güvenlik açısından paket zafiyetleri (CVE bilgileri ve CVSS skorları) çekilmeli, severity (kritiklik) bilgisi tutulmalı, düzeltilmiş versiyon önerilmeli (fix version) ve güvenlik onarım hedefleri için SLA süreleri hesaplanmalıdır [11, 12]. 
*   **İnceleme (Review) İş Akışları:** Tespit edilen her güvenlik ve lisans bulgusu için kayıt açılmalı, kullanıcılar düzeltme, versiyon yükseltme, riski süreli olarak kabul etme veya "false positive" (hatalı bulgu) olarak işaretleme gibi kararlar verebilmelidir [13, 14]. Kararlar için yorum yapılabilmeli, sorumlu atanabilmeli, son tarih (deadline) belirlenebilmeli ve karar geçmişi görüntülenebilmelidir [15].
*   **Raporlama ve SBOM:** Platform, şirket genel risk yönetimi için yönetici özetleri (executive summary), projeye özel raporlar, hukuk ekipleri için lisans envanteri, denetçiler için kanıt raporları (audit evidence) üretebilmelidir [15, 16]. Tüm raporlar PDF, Excel, CSV, JSON gibi formatlarda alınabilmelidir [16].

**2. Fonksiyonel Olmayan Gereksinimler:**
*   **Performans ve Ölçeklenebilirlik:** Büyük projelerde binlerce dependency sorunsuz yönetilebilmelidir [15]. Platform paralel taramaları desteklemeli, tarama işlemleri arka planda kuyruk tabanlı (queue tabanlı) bir mimari ile (worker'lar kullanılarak) çalışmalı ve büyük dışa aktarım (export) işlemleri asenkron işlenmelidir [15, 17].
*   **Güvenilirlik ve Kullanılabilirlik:** Başarısız job'lar tekrar denenebilmeli, tarama yarıda kesilirse durum güncellenmeli ve her işlem için zaman aşımı (timeout) kuralları uygulanmalıdır [17]. Hukuk ve güvenlik kullanıcılarının teknik detaylarda boğulmadan aksiyon alabileceği bir arayüz sunulmalıdır [17, 18].

**3. Güvenlik Gereksinimleri:**
*   **Güvenli Sistem Altyapısı:** NIST SSDF (Güvenli Yazılım Geliştirme Çerçevesi) ve OWASP SCVS (Tedarik Zinciri Kontrol Çerçevesi) standartları referans alınacaktır [19]. Kimlik doğrulama için SSO, SAML, OAuth 2.0/OIDC ve Çok Faktörlü Kimlik Doğrulama (MFA) desteklenmelidir [20]. RBAC (Rol Bazlı Erişim Kontrolü) ile Admin, Security Analyst, Legal Reviewer gibi yetki sınırları net roller tanımlanacaktır [20].
*   **İzolasyon ve Veri Gizliliği:** Repository'lerden çekilen kaynak kod kopyalama (clone) işlemleri kısıtlanmış ve izole bir alan olan Sandbox içerisinde gerçekleştirilmeli, tarama tamamlandıktan sonra tüm geçici workspace dosyaları kalıcı olarak temizlenmelidir [21, 22]. Erişim token'ları veritabanında şifreli tutulmalı ve arayüzde (UI) maskelenmelidir [21].
*   **Denetim İzi (Audit Log):** Sisteme giriş yapılması, poliçe değişikliği, kritik CVE bulunması, lisans risk onayları veya tarama başlatılması gibi tüm eylemler değiştirilemez ve silinemez bir Audit Log'a yazılmalıdır [23, 24].
*   **Kendi Güvenliği (Supply Chain):** Ürünün kendisi de bir tedarik zinciri ögesi olduğu için kendi SBOM'unu üretebilmeli, kod kalite ve konteyner imaj taramalarından geçirilmeli ve CI/CD içerisinde secret scanning yapılmalıdır [22].

**Kullanılan Teknolojiler ve Standartlar**

*   **Tarama Motorunun Desteklediği Ekosistemler:** Sistem yazılımların bağımlılık dosyalarını (örneğin Node.js için `package.json`, `yarn.lock`; Python için `requirements.txt`, `pyproject.toml`; Java için `pom.xml`; .NET için `.csproj`; Containerlar için `Dockerfile` vb.) okuyacak bir yapıda tasarlanmıştır [10]. **İlk MVP versiyonunda sadece Node.js ve Python teknolojileri ile başlanacaktır**, ilerleyen fazlarda Java, .NET, Go, PHP ve Ruby gibi diğer diller de sisteme entegre edilecektir [10].
*   **BOM ve SBOM Standartları:** Platform, uluslararası standart haline gelen ve ISO/IEC 5962:2021 olarak bilinen açık kaynaklı **SPDX** (JSON ve Tag/Value formatları) ile OWASP tarafından desteklenen tedarik zinciri odaklı genişletilmiş **CycloneDX** (JSON ve XML formatları) formatlarını kullanacak ve üretecektir [3, 25].
*   **Entegrasyon Teknolojileri:** Kaynak kod yönetimi için ilk etapta **GitHub, GitLab, Azure DevOps** ve lokal dosya yükleme (Local upload) kullanılacaktır [26]. Gelecek fazlarda Bitbucket eklenecektir [26]. CI/CD otomasyon testleri için GitHub Actions, Azure DevOps Pipeline, GitLab CI ve Jenkins kullanılacaktır [27]. İletişim ve iş takibi adına Microsoft Teams, Slack, Jira ve ServiceNow ile entegre çalışacaktır [26].

_Agentic Development Orchestrator ile oluşturuldu._
