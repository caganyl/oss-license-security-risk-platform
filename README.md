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

**Yerel Kurulum (tek kullanıcı, REQ-002 F1)**

Uygulama F1'de tek yerel kullanıcı modeliyle çalışır: API varsayılan olarak yalnız `127.0.0.1` üzerinde dinler, giriş tek bir yerel parola ve oturum çereziyle yapılır, CLI/CI erişimi için API anahtarı üretilir.

1.  `.env.example` dosyasını `.env` olarak kopyalayın ve değerleri yalnız yerel `.env` içinde doldurun (`.env` git'e girmez). Parola gibi gizli değerler bağlantı URL'sine yazılmaz: `DATABASE_URL` parolasız tutulur (`postgres://<kullanici>@localhost:5432/<veritabani>`), parola `PGPASSWORD` ile verilir. Docker Compose için `POSTGRES_PASSWORD` zorunludur; `ENCRYPTION_KEY` yalnız şifreli repository token'ı çözülürken gerekir.
2.  Veritabanını başlatın ve migration'ları uygulayın (`docker compose up -d db`, ardından `db/README.md`).
3.  `npm install`, `npm run build`, `npm start`. `DATABASE_URL` tanımlı değilse API değerini yazmadan anlaşılır bir hatayla başlamaz.
4.  Tarayıcıda `http://127.0.0.1:3001` adresini açın. İlk açılışta parola belirleme (setup) formu gelir; en az 12 karakterlik parola belirledikten sonra oturum otomatik açılır. Sonraki açılışlarda aynı parolayla giriş yapılır.
5.  CLI/CI için API anahtarı, tarayıcıda giriş yaptıktan sonra API ile oluşturulur: `POST /api/auth/api-keys`. Bu uç nokta yalnız oturum çereziyle çalışır (Bearer ile `403 forbidden`) ve izin verilen bir `Origin` başlığı ister: `http://127.0.0.1:<PORT>`, `http://localhost:<PORT>` veya `http://[::1]:<PORT>`. `Origin` yoksa ya da `null` ise istek `403 origin_rejected` alır; `Host` başlığı da aynı loopback adreslerinden biri olmalıdır (aksi halde `403 host_rejected`). Oturum çerezinin (`ossrisk_session`) değerini tarayıcının geliştirici araçlarından alın. İstek gövdesi isteğe bağlıdır ve yalnız en fazla 100 karakterlik bir `name` alanı alır:

    ```bash
    curl -X POST http://127.0.0.1:3001/api/auth/api-keys \
      -H "Origin: http://127.0.0.1:3001" \
      -H "Cookie: ossrisk_session=<tarayicidaki-oturum-cerezi>" \
      -H "Content-Type: application/json" \
      -d '{"name":"ci"}'
    ```

    Yanıttaki `data.key` (`ossr_` ile başlar) yalnız bu yanıtta bir kez gösterilir, sonradan tekrar alınamaz. Yeni anahtar oluşturmak önceki aktif anahtarı otomatik iptal eder (D-16). Anahtarı CLI/CI isteklerinde `Authorization: Bearer <api-anahtari>` başlığıyla gönderin. Bir anahtarı iptal etmek için yanıttaki `data.id` ile, aynı çerez ve `Origin` başlığıyla `DELETE /api/auth/api-keys/{id}` çağırın. Anahtar yönetimi için arayüz ekranı F6'da gelecektir (D-22).

**Tarama (Docker'sız, REQ-002 P-03/P-04)**

Tarama worker'ı (`npm run worker`) Docker kullanmaz; makinede `git` bulunmalıdır. Python gerekmez (REQ-003 P-10).

- **Uzak repo:** Yalnız `https://` adresleri kabul edilir. `http`, SSH (`ssh://`, `git@host:yol`), `file://`, kullanıcı bilgisi içeren URL ve benzeri biçimler `400 repo_url_not_allowed` döner. Repo, `os.tmpdir()` altında `ossrisk-scan-*` adlı geçici bir klasöre sığ (`--depth 1`) olarak clone edilir ve tarama bitince (hata alsa bile) silinir. Özel repo token'ı URL'ye yazılmaz, git'e ortam üzerinden verilir. `ENCRYPTION_KEY` yoksa ya da token çözülemiyorsa tarama `failed` olur. Clone zaman aşımı `SCAN_CLONE_TIMEOUT_MS` ile ayarlanır (varsayılan 5 dk).
- **Clone sertleştirmesi:** Git LFS dosyaları indirilmez (yalnız işaretçi dosyaları gelir, LFS filtreleri çalışmaz) ve HTTP yönlendirmeleri izlenmez; yönlendiren bir sunucu taramayı `failed` yapar. Erişim token'ı yalnız repo adresinin hostuna gönderilir. Token ortam değişkeniyle (`GIT_CONFIG_COUNT`) iletildiği için `git` 2.31 veya üstü gerekir; daha eski sürümlerde token gönderilmez ve özel repo clone'u başarısız olur.
- **Yerel klasör:** Yalnız `SCAN_ROOTS` altındaki mutlak klasörler taranabilir. Liste `path.delimiter` ile ayrılır, yani Windows'ta `;` kullanılır (ör. `SCAN_ROOTS=C:\repos;D:\work`). `SCAN_ROOTS` tanımsız ya da boşsa hiçbir yerel yol taranamaz (`400 path_not_allowed`). Yollar `realpath` ile çözülür; `..`, junction ve symlink ile kök dışına çıkılamaz. Kontrol hem kayıt/tarama isteğinde hem worker taramayı başlatırken yapılır. Var olmayan bir kök API'nin ve worker'ın başlangıçta hata vermesine yol açar.
- **Ayrıştırıcılar:** Bağımlılık dosyaları TypeScript ayrıştırıcılarıyla (`src/scanner/parsers/`), tarama başına açılan bir `worker_threads` iş parçacığında okunur. İş parçacığının bellek sınırı 512 MiB'dir ve ortam değişkenlerini görmez. Sembolik bağlantı ve junction izlenmez, 32 MiB'den büyük dosya okunmaz; bu durumlar taramanın uyarılarına yazılır.
- Kaynak çözümlenemezse tarama `failed` olur. Platform klasörüne (`.`) geri dönüş yapılmaz.

**Bulgular ve kararlar (REQ-002 P-05…P-08)**

- **Kilit dosyası yoksa:** Paketin kesin sürümü bilinmez. Sürüm boş (`NULL`) kalır, purl sürümsüz yazılır (`pkg:npm/lodash`), manifestteki aralık (`^4.17.0`, `>=2,<3`) taranan bağımlılığın `declared_range` alanında manifest başına saklanır. Sürümü bilinmeyen paket için güvenlik açığı sorgusu yapılmaz; doğru sonuç için `package-lock.json`/`yarn.lock`/`poetry.lock` ekleyin veya sürümü `==` ile sabitleyin.
- **Geliştirme kapsamı:** `devDependencies`, `requirements-dev.txt`/`requirements-test.txt` ve Poetry grupları `dev` kapsamıyla envantere girer ama lisans ihlali sayılmaz. `direct`, `transitive`, `peer` ve `optional` çalışma zamanı (runtime) kapsamıdır.
- **Lisansı bilinmeyen paket:** Lisansı bulunamayan runtime paket için `unknown` riskli lisans bulgusu (`NOASSERTION`) açılır; `dev` paket için açılmaz.
- **Kararların taşınması:** Her bulgunun proje, paket ve bulgu türünden türetilen bir parmak izi vardır (lisansta sürümsüz, güvenlik açığında sürümlü). Sonraki taramada aynı parmak izli bulgu, önceki karar false positive ya da süresi geçmemiş risk kabulü ise o durumla açılır. Süresi geçmiş kabul ve `wont_fix` taşınmaz; bulgu `open` açılır. Güvenlik kararları paket sürümü değişince yeniden değerlendirilir, lisans kararları sürüm yükseltmesinde korunur.

Notlar: `HOST` değerini loopback dışına (ör. `0.0.0.0`) çekmek API'yi düz HTTP ile ağa açar ve başlangıçta uyarı verir. Unutulan parola, `db/README.md`'deki kurtarma SQL adımıyla sıfırlanır; ardından setup aynı kullanıcıya yeni parola atar.

_Agentic Development Orchestrator ile oluşturuldu._
