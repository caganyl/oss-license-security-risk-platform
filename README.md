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

**Windows'ta Kurulum (tek kullanıcı, REQ-003 F2)**

Uygulama tek yerel kullanıcı modeliyle, tek bir Node süreci olarak çalışır: `npm start` API'yi, tarama worker'ını ve rapor worker'ını birlikte başlatır. API varsayılan olarak yalnız `127.0.0.1` üzerinde dinler, giriş tek bir yerel parola ve oturum çereziyle yapılır, CLI/CI erişimi için API anahtarı üretilir. Komutların tamamı **PowerShell** içindir.

*Ön koşullar*

- **Node.js `^22.21.0` veya `>=24.5.0`** (`node --version`). Kayıt defteri istemcisinin vekil desteği (`proxyEnv`) bu sürümlerde gelir; daha eski 22.x sürümleri desteklenmez.
- **Git for Windows 2.32 veya üstü** (`git --version`). Yalnız uzak (`https`) repo taraması için gerekir; git yoksa veya daha eskiyse uygulama yine başlar ve uyarı yazar, yerel klasör taramaları çalışır, uzak taramalar ise yeniden denenmeden `Uzak tarama için git 2.32 veya üstü gerekli (bulunan: …).` mesajıyla `failed` olur. Git sonradan kurulursa uygulamayı yeniden başlatın.
- **PostgreSQL 15 veya üstü**, Windows kurulum paketiyle (EDB installer).
- **Gerekmeyenler:** Python, Docker, Git Bash ve `PATH` üzerinde `psql`.

*PostgreSQL kurulumu*

1. Kurulum sihirbazında yerel ayar (Locale) adımında **`C`** seçin. Türkçe yerel ayarlı Windows'ta varsayılan ayar küme oluşturmayı bozabilir veya büyük/küçük harf karşılaştırmalarını (`I`/`ı`) değiştirebilir.
2. Kurulumla gelen **"SQL Shell (psql)"** kısayolunu (Başlat menüsü) veya **pgAdmin**'i açıp `postgres` kullanıcısıyla bağlanın; uygulama için bir kullanıcı ve veritabanı oluşturun (`PATH` ayarı gerekmez):

    ```sql
    CREATE USER ossrisk WITH PASSWORD '<güçlü-bir-parola>';
    CREATE DATABASE ossrisk OWNER ossrisk;
    ```

*İlk kurulum*

```powershell
git clone <repo-adresi> oss-risk
cd oss-risk
Copy-Item .env.example .env
notepad .env          # DATABASE_URL, PGPASSWORD (ve gerekirse SCAN_ROOTS, ENCRYPTION_KEY) doldurun
npm ci
npm run build
npm run db:migrate
npm start
```

- `.env` git'e girmez; gizli değerleri yalnız orada tutun. Parola bağlantı URL'sine yazılmaz: `DATABASE_URL` parolasız tutulur (`postgres://ossrisk@localhost:5432/ossrisk`), parola `PGPASSWORD` ile verilir. `ENCRYPTION_KEY` yalnız şifreli repository token'ı çözülürken gerekir. `DATABASE_URL` tanımlı değilse uygulama değeri yazmadan anlaşılır bir hatayla başlamaz.
- `npm run db:migrate` derlenmiş çıktıyla (`dist/`) çalışır; bu yüzden önce `npm run build` gerekir. Göçler `npm start` sırasında **otomatik uygulanmaz**: bekleyen göç varsa uygulama `Bekleyen göç var: … Önce npm run db:migrate çalıştırın.` mesajıyla başlamaz. Göç aracının diğer komutları (`status`, `down --to <sürüm>`) `db/README.md`'dedir.
- Tarayıcıda `http://127.0.0.1:3001` adresini açın. İlk açılışta parola belirleme (setup) formu gelir; en az 12 karakterlik parola belirledikten sonra oturum otomatik açılır. Sonraki açılışlarda aynı parolayla giriş yapılır.
- **Durdurma:** uygulamanın çalıştığı pencerede **Ctrl+C**. Süren taramalar iptal edilip kuyruğa geri bırakılır, süren raporlar en fazla 10 sn beklenir, kapanış en geç 15 sn'de biter; ikinci Ctrl+C beklemeden çıkar. `npm` istemi kapanış bitmeden geri gelebilir; uygulama arka planda kapanışı tamamlar. cmd.exe'de çıkan "Terminate batch job (Y/N)?" sorusunun yanıtı kapanışı etkilemez (PowerShell önerilir). Pencereyi kapatmak da kapanış başlatır, ancak Windows süreci yaklaşık 10 sn sonra sonlandırır; yarım kalan taramalar sonraki başlangıçta otomatik kurtarılır.
- **Tek örnek:** aynı veritabanına bağlı ikinci bir `npm start` `Bu veritabanına bağlı başka bir örnek çalışıyor veya bir göç sürüyor.` mesajıyla durur. Uygulama çalışırken `npm run db:migrate` da reddedilir; önce uygulamayı durdurun.

*Güncelleme*

```powershell
git pull
npm ci
npm run build
npm run db:migrate
npm start
```

*Kurumsal vekil sunucu (proxy)*

Ağınız internete vekil sunucuyla çıkıyorsa, `npm start`'tan önce aynı PowerShell oturumunda ortam değişkenlerini tanımlayın (PAC/otomatik yapılandırma desteklenmez):

```powershell
$env:HTTPS_PROXY = "http://proxy.sirket.local:8080"
$env:NO_PROXY = "localhost,127.0.0.1"
npm start
```

Clone yalıtımı nedeniyle git'in kendi `http.proxy`, `http.sslCAInfo` ve `http.sslVerify` ayarları (kullanıcı ve sistem `gitconfig`'i) **okunmaz**; vekil yalnız bu ortam değişkenleriyle verilir. TLS denetimi yapan kurumsal ağlarda şirket kök sertifikasının **Windows sertifika deposunda** olması gerekir (git Windows'ta `schannel` ile çalıştırılır); ayrı bir CA dosyası (`CURL_CA_BUNDLE`, `SSL_CERT_FILE`) aktarılmaz.

*CLI/CI erişimi*

1.  CLI/CI için API anahtarı, tarayıcıda giriş yaptıktan sonra API ile oluşturulur: `POST /api/auth/api-keys`. Bu uç nokta yalnız oturum çereziyle çalışır (Bearer ile `403 forbidden`) ve izin verilen bir `Origin` başlığı ister: `http://127.0.0.1:<PORT>`, `http://localhost:<PORT>` veya `http://[::1]:<PORT>`. `Origin` yoksa ya da `null` ise istek `403 origin_rejected` alır; `Host` başlığı da aynı loopback adreslerinden biri olmalıdır (aksi halde `403 host_rejected`). Oturum çerezinin (`ossrisk_session`) değerini tarayıcının geliştirici araçlarından alın. İstek gövdesi isteğe bağlıdır ve yalnız en fazla 100 karakterlik bir `name` alanı alır:

    ```bash
    curl -X POST http://127.0.0.1:3001/api/auth/api-keys \
      -H "Origin: http://127.0.0.1:3001" \
      -H "Cookie: ossrisk_session=<tarayicidaki-oturum-cerezi>" \
      -H "Content-Type: application/json" \
      -d '{"name":"ci"}'
    ```

    Yanıttaki `data.key` (`ossr_` ile başlar) yalnız bu yanıtta bir kez gösterilir, sonradan tekrar alınamaz. Yeni anahtar oluşturmak önceki aktif anahtarı otomatik iptal eder (D-16). Anahtarı CLI/CI isteklerinde `Authorization: Bearer <api-anahtari>` başlığıyla gönderin. Bir anahtarı iptal etmek için yanıttaki `data.id` ile, aynı çerez ve `Origin` başlığıyla `DELETE /api/auth/api-keys/{id}` çağırın. Arayüzden de yönetilebilir (REQ-007 F6): anahtarlar kenar çubuğundaki **API Keys** görünümünden oluşturulur ve iptal edilir; anahtar orada da yalnız oluşturma anında bir kez gösterilir.

**Tarama (Docker'sız, REQ-002 P-03/P-04)**

Tarama worker'ı `npm start` ile aynı süreçte çalışır ve Docker kullanmaz; uzak repo taraması için makinede `git` 2.32 veya üstü bulunmalıdır. Python gerekmez (REQ-003 P-10).

- **Yeniden deneme ve süre sınırı (REQ-003 P-13):** Geçici hatalar (clone hatası veya clone zaman aşımı, veritabanı hatası, yarıda kalmış tarama) beklemeyle yeniden denenir: 30 sn, 60 sn, 120 sn, … en fazla 10 dk. Toplam deneme sayısı `scan.max_retries` ayarıdır (varsayılan 3, ilk deneme dahil). Kalıcı hatalar (token çözülemedi, geçersiz kaynak/ref, ayrıştırıcı çökmesi/bellek sınırı, süre sınırı, git yok veya 2.32'den eski) hemen `failed` olur. Bir taramanın toplam süresi `scan.timeout_minutes` ayarıyla sınırlıdır (varsayılan 60 dk); aşılırsa tarama `Tarama süre sınırını aştı (60 dk).` mesajıyla `failed` olur.

- **Uzak repo:** Yalnız `https://` adresleri kabul edilir. `http`, SSH (`ssh://`, `git@host:yol`), `file://`, kullanıcı bilgisi içeren URL ve benzeri biçimler `400 repo_url_not_allowed` döner. Repo, `os.tmpdir()` altında `ossrisk-scan-*` adlı geçici bir klasöre sığ (`--depth 1`) olarak clone edilir ve tarama bitince (hata alsa bile) silinir. Özel repo token'ı URL'ye yazılmaz, git'e ortam üzerinden verilir. `ENCRYPTION_KEY` yoksa ya da token çözülemiyorsa tarama `failed` olur. Clone zaman aşımı `SCAN_CLONE_TIMEOUT_MS` ile ayarlanır (varsayılan 5 dk).
- **Özel repolar ve şirket içi Azure DevOps Server / TFS (REQ-009):** Giriş isteyen bir repo için iki yol vardır:
  1. **Repo erişim anahtarı (PAT), önerilen.** Projeler ekranında https repolu projenin satırındaki **Add token** düğmesiyle (veya proje oluştururken "Repo access token" alanıyla) bir Personal Access Token kaydedin. Azure DevOps / TFS'te: kullanıcı menüsü → *Personal access tokens* → *New Token*, kapsam olarak yalnız **Code → Read**. Token `ENCRYPTION_KEY` ile şifreli saklanır, hiçbir yanıtta ve ekranda geri gösterilmez, yalnız repo adresinin hostuna gönderilir. Yeni token kaydetmek eskisinin yerine geçer; silme uç noktası yoktur (API: `PUT /api/projects/{id}/repo-credential`, yalnız admin).
  2. **Windows oturumu (isteğe bağlı).** Şirket sunucusu Windows kimlik doğrulamasını (Negotiate/NTLM) kabul ediyorsa `.env`'de `GIT_WINDOWS_AUTH_HOSTS=tfs.sirket.local` gibi tam host adlarını listeleyin. Token tanımlı olmayan ve hostu listede olan repolarda git, oturum açmış Windows kullanıcısının kimliğini ve Git Credential Manager'daki kayıtlı bilgiyi etkileşimsiz kullanır. Joker, port ve şema kabul edilmez; geçersiz liste uygulamanın başlamasını durdurur. Liste boşsa (varsayılan) bu mod kapalıdır.
  - Dal belirtilmezse reponun **varsayılan dalı** taranır (`main` varsayılmaz).
  - Klon hatası tarama satırında yol gösteren bir cümleyle görünür: kimlik doğrulama gerekli, dal bulunamadı, repo bulunamadı, TLS sertifikası güvenilmiyor (bu dördü yeniden denenmez) veya sunucuya ulaşılamadı (yeniden denenir).
- **.NET 10:** `obj/project.assets.json` sürüm 3 ve 4 (.NET 10 SDK) okunur.
- **Clone sertleştirmesi:** Git LFS dosyaları indirilmez (yalnız işaretçi dosyaları gelir, LFS filtreleri çalışmaz) ve HTTP yönlendirmeleri izlenmez; yönlendiren bir sunucu taramayı `failed` yapar. Erişim token'ı yalnız repo adresinin hostuna gönderilir. Token ortam değişkeniyle (`GIT_CONFIG_COUNT`) iletilir; desteklenen en düşük git sürümü 2.32'dir.
- **Clone yalıtımı (REQ-003 N-1):** git, kullanıcının ve sistemin git yapılandırmasını, credential helper'ı, askpass programını, `.netrc` dosyasını ve kancaları görmez (iş başına boş `gitconfig`, `HOME` ve `hooks` klasörü). Git sürecine yalnız bir izin listesindeki ortam değişkenleri (`PATH`, `SystemRoot`, `TEMP` vb. ve vekil değişkenleri) aktarılır; diğer `GIT_*` değişkenleri ve sırlar aktarılmaz. Vekil/CA etkisi için yukarıdaki "Kurumsal vekil sunucu" notuna bakın.
- **Hata mesajları (L-5):** Tarama ve rapor `error_message` alanı en fazla 2000 karakterdir; token, API anahtarı, URL içindeki kullanıcı bilgisi ve kontrol karakterleri silinir, geçici klasör / `SCAN_ROOTS` / kullanıcı profil yolları `<workspace>`, `<scan-root>`, `<temp>`, `<home>` ile değiştirilir.
- **Yerel klasör:** Yalnız `SCAN_ROOTS` altındaki mutlak klasörler taranabilir. Liste `path.delimiter` ile ayrılır, yani Windows'ta `;` kullanılır (ör. `SCAN_ROOTS=C:\repos;D:\work`). `SCAN_ROOTS` tanımsız ya da boşsa hiçbir yerel yol taranamaz (`400 path_not_allowed`). Yollar `realpath` ile çözülür; `..`, junction ve symlink ile kök dışına çıkılamaz. Kontrol hem kayıt/tarama isteğinde hem worker taramayı başlatırken yapılır. Var olmayan bir kök uygulamanın başlangıçta açık bir hatayla durmasına yol açar.
- **Ayrıştırıcılar:** Bağımlılık dosyaları TypeScript ayrıştırıcılarıyla (`src/scanner/parsers/`), tarama başına açılan bir `worker_threads` iş parçacığında okunur. İş parçacığının bellek sınırı 512 MiB'dir ve ortam değişkenlerini görmez. Sembolik bağlantı ve junction izlenmez, 32 MiB'den büyük dosya okunmaz; bu durumlar taramanın uyarılarına yazılır.
- Kaynak çözümlenemezse tarama `failed` olur. Platform klasörüne (`.`) geri dönüş yapılmaz.

**Bulgular ve kararlar (REQ-002 P-05…P-08)**

- **Kilit dosyası yoksa:** Paketin kesin sürümü bilinmez. Sürüm boş (`NULL`) kalır, purl sürümsüz yazılır (`pkg:npm/lodash`), manifestteki aralık (`^4.17.0`, `>=2,<3`) taranan bağımlılığın `declared_range` alanında manifest başına saklanır. Sürümü bilinmeyen paket için güvenlik açığı sorgusu yapılmaz; doğru sonuç için `package-lock.json`/`yarn.lock`/`poetry.lock` ekleyin veya sürümü `==` ile sabitleyin.
- **Desteklenen diller ve dosyalar (REQ-011):** Teknoloji yığını boş bırakılan (Otomatik algıla) projelerde aşağıdaki ekosistemlerin hepsi taranır. Her klasörde kilit dosyası bildirim dosyasından önce gelir; derleme aracı (`mvn`, `gradle`, `go`, `cargo`, `dotnet restore`) hiçbir zaman çalıştırılmaz.

  | Ekosistem | Okunan dosyalar | Güvenlik açığı (OSV) | Lisans kaynağı |
  | --- | --- | --- | --- |
  | Node.js | `package-lock.json` > `pnpm-lock.yaml` (v6/v9) > `yarn.lock` > `bun.lock`; `package.json` | npm | registry.npmjs.org |
  | Python | `poetry.lock`, `Pipfile.lock`, `uv.lock`, `requirements*.txt`, `pyproject.toml` | PyPI | pypi.org |
  | .NET | `packages.lock.json` > `obj/project.assets.json` > `*.csproj` (aşağıda) | NuGet | api.nuget.org |
  | Java / Kotlin | `gradle.lockfile` > `pom.xml` > `build.gradle(.kts)` | Maven | api.deps.dev |
  | Go | `go.mod` | Go | api.deps.dev |
  | PHP | `composer.lock` > `composer.json` | Packagist | `composer.lock` içindeki lisans |
  | Rust | `Cargo.lock` > `Cargo.toml` | crates.io | api.deps.dev |
  | Ruby | `Gemfile.lock` | RubyGems | api.deps.dev |
  | Dart / Flutter | `pubspec.lock` | Pub | pub.dev |
  | Swift | `Package.resolved` | SwiftURL | yok (lisans "belirsiz") |

  Sınırlar: yalnız bildirim dosyası (`pom.xml`, `build.gradle`, `composer.json`, `Cargo.toml`) varsa sürümler kesin değildir ve dolaylı paketler görünmez; kesin sonuç için kilit dosyasını repoya ekleyin (Gradle: `dependencyLocking`; Maven'in kilit dosyası yoktur). Gradle sürüm kataloğu (`gradle/libs.versions.toml`, `implementation(libs.x)`) henüz okunmaz. `pom.xml`'de üst POM ve BOM içe aktarmaları çözülmez. Yerel yol/git kaynaklı paketler (Go `replace`, Cargo `path`/`git`, Gemfile `GIT`/`PATH`, pubspec `git`/`path`, SwiftPM yerel paketler) envantere girmez. pnpm 7'nin eski kilit biçimi (5.4) ve ikili `bun.lockb` okunmaz. Java, Go, Rust, Ruby ve Dart lisansları için dışarıya yalnız paket adı ve sürümü gönderilir; `REGISTRY_ENRICHMENT=off` bunu kapatır.
- **.NET (NuGet) taraması (REQ-006):** Projenin teknoloji yığınında `dotnet` varsa (yığını boş projelerde tüm desteklenen ekosistemlerle birlikte) şu dosyalar okunur: `packages.lock.json`, `obj/project.assets.json`, `*.csproj`/`*.fsproj`/`*.vbproj` (`PackageReference`), `Directory.Packages.props` (merkezi paket yönetimi, proje klasöründen tarama köküne kadar en yakın dosya) ve `packages.config`. Her proje klasöründe öncelik lock dosyası > `project.assets.json` > proje dosyaları + `packages.config` sırasıdır; okunamayan dosyada bir sonrakine geçilir. `dotnet restore`, `msbuild` veya `nuget` hiçbir zaman çalıştırılmaz: MSBuild özellikleri (`$(Ad)`), `Condition`, `Import`, `Directory.Build.props` ve `Target` içindeki öğeler değerlendirilmez; özellikle verilen sürüm bilinmiyor (`NULL`) sayılır. `Choose`/`When`/`Otherwise` içindeki `ItemGroup`'lar koşul gözetmeden okunur. Kesin sürüm için `RestorePackagesWithLockFile` ile `packages.lock.json` üretip repoya ekleyin. `DOCTYPE` içeren XML dosyaları reddedilir. `build` ve `dist` klasörleri (diğer ekosistemlerde olduğu gibi) taranmaz; `obj` ve `bin` taranır. NuGet'te `dev` kapsamı yoktur, tüm paketler runtime sayılır. NuGet lisans zenginleştirmesi, NOTICE ve OSV sorgusu için aşağıdaki "NuGet lisans zenginleştirmesi ve OSV (REQ-006 F5)" bölümüne bakın.
- **Geliştirme kapsamı:** `devDependencies`, `requirements-dev.txt`/`requirements-test.txt` ve Poetry grupları `dev` kapsamıyla envantere girer ama lisans ihlali sayılmaz. `direct`, `transitive`, `peer` ve `optional` çalışma zamanı (runtime) kapsamıdır.
- **Lisansı bilinmeyen paket:** Lisansı bulunamayan runtime paket için `unknown` riskli lisans bulgusu (`NOASSERTION`) açılır; `dev` paket için açılmaz.
- **Kararların taşınması:** Her bulgunun proje, paket ve bulgu türünden türetilen bir parmak izi vardır (lisansta sürümsüz, güvenlik açığında sürümlü). Sonraki taramada aynı parmak izli bulgu, önceki karar false positive ya da süresi geçmemiş risk kabulü ise o durumla açılır. Süresi geçmiş kabul ve `wont_fix` taşınmaz; bulgu `open` açılır. Güvenlik kararları paket sürümü değişince yeniden değerlendirilir, lisans kararları sürüm yükseltmesinde korunur.

**NuGet lisans zenginleştirmesi ve OSV (REQ-006 F5)**

- **Host ve istekler:** Yalnız `https://api.nuget.org`, iki sabit yol: `/v3-flatcontainer/<id>/<sürüm>/<id>.nuspec` (paket meta verisi; en fazla 3 aynı-köken yönlendirme, 1 MiB) ve `/v3-flatcontainer/<id>/<sürüm>/<id>.<sürüm>.nupkg` (paket arşivi; yönlendirme yok, 64 MiB). Kimlik ve sürüm küçük harfle gönderilir. Hizmet dizini, kayıt/katalog API'leri ve `nuget.config` hiçbir zaman okunmaz; özel NuGet kaynaklarına bağlanılmaz. Gönderilen tek bilgi kesin sürümlü paket kimliği ve sürümüdür; `User-Agent`, çerezsizlik ve `Authorization` yokluğu npm/PyPI ile aynıdır. `REGISTRY_ENRICHMENT=off` NuGet trafiğini de kapatır.
- **Lisans önceliği (`.nuspec`):** `<license type="expression">` > `<license type="file">` > `<licenseUrl>`. `licenses.nuget.org/<ifade>` adresi SPDX ifadesine çevrilir, `aka.ms/deprecateLicenseUrl` yok sayılır, birkaç bilinen lisans sayfası küçük bir sabit tabloyla eşlenir. `licenseUrl` adresi **hiçbir zaman indirilmez**, loglanmaz ve çıktıya yazılmaz. Dosya tipli lisans ve eşlenemeyen URL "sınıflandırılmamış" kalır: etkin lisans boş, kaynak `none`, runtime paket için `NOASSERTION` bulgusu; Excel `License Source` hücresinde `none (license file in package, not classified)` / `none (license URL not classified)` yazar. Lisans kaynağı ifade varsa `registry:nuget`'tır.
- **Arşiv ve NOTICE:** `.nupkg` yalnız taramanın `packages.lock.json` / `project.assets.json` içindeki SHA-512 değeri varsa indirilir; bu değer olmayan projelerde NOTICE nedeni `package archive not downloaded (no lockfile integrity value)` olur. Aynı paket sürümü için birden çok farklı değer varsa indirme yapılmaz ve bütünlük uyuşmazlığı sayılır. İndirilen baytlar **ayrıştırılmadan önce** doğrulanır: ham SHA-512 veya NuGet içerik özeti eşleşmelidir. İmzalı paketlerde NuGet içerik özeti `.signature.p7s` girdisi hiç eklenmemiş gibi hesaplanır; uygulama bunu arşivi açmadan, yalnız zip yapısından yeniden hesaplar. Uyuşmazlıkta arşiv atılır, önbelleğe yazılmaz, `.nuspec` lisansı da kullanılmaz (`none (lockfile integrity mismatch)`). Doğrulanmış arşivden kökteki `LICENSE*`/`LICENCE`/`COPYING`/`NOTICE`/`COPYRIGHT` dosyaları ve `.nuspec`'te bildirilen lisans dosyası NOTICE'e girer; NOTICE'te NuGet girdileri `npm` ile `pypi` arasında sıralanır ve kimlik/sürüm harf duyarsız tekilleştirilir.
- **`.nuspec` kimlik/sürüm kontrolü:** `<id>` (harf duyarsız) ve NuGet kurallarıyla normalize edilmiş `<version>` (harf duyarsız) istenen paketle aynı olmalıdır; değilse (ör. başka sürümün `.nuspec`'ine yönlendirme) yanıt `BAD_NUSPEC` sayılır ve önbelleğe yazılmaz.
- **Bildirilen lisans dosyası:** `<license type="file">` ile bildirilen yol, NuGet semantiğine uygun olarak paketteki ikili olmayan herhangi bir dosya olabilir (kök lisans adı kuralı aranmaz); dosya doğrulanmış arşivden ve dosya başına boyut sınırıyla okunur, NUL içeren dosyalar atılır.
- **OSV:** Kesin sürümlü NuGet paketleri `NuGet` ekosistemiyle sorgulanır. Gövdedeki ad `.nuspec` `<id>` değeridir (yoksa taramadaki ilk yazımı); küçük harfe çevrilmez. Bu yazım paketi yayınlayanın `.nuspec`'te seçtiği büyük/küçük harf düzenidir (başka bir pakete yönlendiremez); gerçek ağla yapılan smoke testte bu adla güvenlik açıkları bulunmuştur.
- **Sınırlamalar:** Proje dosyasının yanındaki `obj/` (artifacts düzeni değil) varsayılır; `UseArtifactsOutput` / ortak `artifacts/` klasörü ayrıca aranmaz. MSBuild değerlendirmesi yapılmaz ve `dotnet restore` çalıştırılmaz; kesin sürüm ve arşiv doğrulaması için lock dosyası önerilir. NuGet bütünlük uyuşmazlığı önbelleğe alınmadığından özel kaynaktan gelen paketler her taramada yeniden indirilir (kota ve süre bütçesiyle sınırlı). Bir taramada en fazla 100 000 .NET bağımlılığı alınır (proje klasörü başına 20 000 sınırına ek olarak); sınırı aşacak klasör ve sonrakiler atlanır, tarama uyarısına dosya yolu içermeyen tek bir sabit metin yazılır.
- **Migration 008 geri alımı:** `008_nuget_enrichment.down.sql` lisans kaynağı `registry:nuget` olan satırlarda `license_expression` değerini korur, kaynağı `none` yapar ve `license_unclassified` sütununu kaldırır; geri alım sonrası raporlar bu ifadeleri kaynaksız gösterir. Geri alım yalnız insan onayıyla çalıştırılır.

**Yeni ekosistemlerde lisans (REQ-011 P-43)**

- **Kaynaklar:** Go, Java/Kotlin (Maven), Rust (Cargo) ve Ruby (RubyGems) paketlerinin lisansı `https://api.deps.dev`'den, Dart/Flutter paketlerininki `https://pub.dev`'den alınır. Etkin lisans kaynağı sırasıyla `registry:depsdev` ve `registry:pubdev` olarak saklanır ve Excel `License Source` hücresinde ve NOTICE'te bu adla görünür.
- **İstekler ve dışarı gidenler:** deps.dev'e kesin sürümlü her paket için tek bir `GET /v3/systems/{GO|MAVEN|CARGO|RUBYGEMS}/packages/<ad>/versions/<sürüm>` (ad ve sürüm URL kodlamalı tek yol parçası: Maven `grup:artefakt`, Go modül yolu, crate, gem); pub.dev'e paket başına tek bir `GET /api/packages/<ad>/score`. Gönderilen tek bilgi **paket adı ve sürümüdür** (pub.dev'e yalnız ad); proje adı, repo adresi, dosya yolu, kaynak kod, çerez, `Authorization` başlığı, token veya API anahtarı gönderilmez. `User-Agent` ve diğer sabit başlıklar npm/PyPI ile aynıdır.
- **Sertleştirme:** İki adres kodda sabittir (ortamdan okunmaz); yalnız HTTPS, yalnız yukarıdaki yol biçimi (sorgu dizesi yok), **yönlendirme izlenmez**, yanıt en fazla 1 MiB ve JSON olmalıdır. Zaman aşımı (`REGISTRY_TIMEOUT_MS`), yeniden deneme, ardışık hata eşiği, eşzamanlılık (`REGISTRY_CONCURRENCY`), tarama süre bütçesi, vekil (`HTTPS_PROXY`/`NO_PROXY`) ve TLS kuralları npm/PyPI/NuGet ile aynıdır. Sonuçlar aynı kalıcı önbelleğe (`registry_package_cache`, ekosistem `depsdev`/`pubdev`) yazılır; aynı paket sürümü sonraki taramada yeniden sorulmaz. `REGISTRY_ENRICHMENT=off` bu iki hosta giden tüm trafiği de kapatır.
- **Lisansın okunması:** deps.dev yanıtındaki `licenses` listesi tek bir SPDX ifadesine (`AND` ile) birleştirilir; deps.dev'in eşleyemediği `non-standard` işareti atlanır. pub.dev'de `tags` içindeki `license:<spdx>` etiketleri okunur; `license:osi-approved`, `license:fsf-libre`, `license:unknown` gibi sınıflandırma etiketleri lisans sayılmaz. pub.dev puan belgesi paketin en son sürümünü anlatır; lisans taranan sürüm için bu belgeden alınır.
- **Hata durumu:** Host ulaşılamazsa veya yanıt bozuksa tarama düşmez: lisans "belirsiz" kalır (durum `unreachable`/`error`, kaynak `none`; runtime pakette `NOASSERTION` bulgusu) ve taramanın uyarılarına tek `[registry] Registry lookup incomplete …` satırı yazılır. Paket bulunamazsa (404) durum `not_found`'dır.
- **PHP:** Ayrı bir kayıt defteri istemcisi yoktur; lisans `composer.lock`'taki `license` alanından gelir, kaynak `lockfile (unverified)`.
- **Swift:** Standart bir lisans kaynağı yoktur (GitHub API istek sınırlıdır); Swift paketlerinin lisansı **belirsiz** görünür (kaynak `none`, NOTICE nedeni `license enrichment not supported for this ecosystem`).
- **NOTICE:** Yeni ekosistemlerde paket arşivi indirilmez; NOTICE'te yalnız SPDX kimliği ve kaynağı yazılır, lisans metni bulunmaz.

**Lisans zenginleştirme ve NOTICE (REQ-004 F3)**

Tarama, bağımlılıkları ayrıştırdıktan sonra her paketin lisansını herkese açık kayıt defterlerinden (npm, PyPI) doğrular ve paket arşivlerindeki LICENSE/NOTICE dosyalarını ve telif satırlarını toplar. Sonuçlar veritabanında kalıcı önbelleğe yazılır; aynı paket sürümü sonraki taramalarda yeniden indirilmez.

- **Gizlilik — dışarı ne gönderilir:** Yalnız paket adı ve sürümü, şu hostlara HTTPS ile: `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org` (paket arşivi indirme), `api.nuget.org`, `api.deps.dev` ve `pub.dev` (REQ-011 yeni ekosistem lisansları). Proje adı, repo adresi, dosya yolları, kaynak kod, token veya API anahtarı gönderilmez. İzin listesi dışındaki hosta (yönlendirmeler dahil) bağlanılmaz. Her istekte sabit `User-Agent: oss-risk-platform/<sürüm> (license-enrichment)` başlığı gider (`<sürüm>`, `package.json`'daki sürümdür; şu an `1.0.0`). Çerez, `Authorization` başlığı, token veya API anahtarı gönderilmez. Bu dış erişimi istemiyorsanız `REGISTRY_ENRICHMENT=off` kullanın.
- **Dışarı giden bağlantıların tam listesi:** Uzak repo clone'u (yalnız taranan repo adresinin hostu) dışında uygulama tarama sırasında yalnız şu hostlara HTTPS ile bağlanır:
  - `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `api.nuget.org` — lisans zenginleştirme (bu bölüm ve yukarıdaki NuGet bölümü). Adresler kodda sabittir; `REGISTRY_ENRICHMENT=off` ile kapanır.
  - `api.deps.dev` (Go, Maven, Cargo, RubyGems) ve `pub.dev` (Dart) — yeni ekosistemlerde lisans (yukarıdaki "Yeni ekosistemlerde lisans (REQ-011 P-43)" bölümü). Yalnız paket adı ve sürüm gönderilir; adresler kodda sabittir; `REGISTRY_ENRICHMENT=off` ile kapanır.
  - `api.osv.dev` — güvenlik açığı sorgusu. Kesin sürümü bilinen her paket için ekosistem, paket adı ve sürüm gönderilir. `REGISTRY_ENRICHMENT=off` bu sorguyu **kapatmaz**; F4'ten beri kendi kapatma ayarı vardır: `VULNERABILITY_LOOKUP=off` (aşağıdaki F4 bölümü).
  - `services.nvd.nist.gov` — OSV kaydından CVSS puanı elde edilemeyen CVE'ler için CVSS sorgusu (OSV'de sayısal puan veya geçerli bir `CVSS_V3` vektörü varsa puan yerelde hesaplanır ve NVD'ye gidilmez). Yalnız CVE kimliği gönderilir; `NVD_API_KEY` tanımlıysa `apiKey` başlığı da eklenir. `NVD_ENABLED=off` ile kapanır.
  - **OSV/NVD'ye ne gider, ne gitmez (I-6):** OSV'ye yalnız ekosistem (`npm`/`PyPI`), paket adı (npm'de olduğu gibi, PyPI'de PEP 503 biçimi), kesin sürüm ve sayfalama belirteci (toplu sorgu) ile açık kimliği (ayrıntı isteği; ör. `GHSA-…`); NVD'ye yalnız CVE kimliği (ve tanımlıysa `apiKey` başlığı). Proje adı, repo adresi, dosya yolları, kaynak kod, kullanıcı bilgisi, oturum çerezi veya uygulama API anahtarı **gönderilmez**. Günlük yeniden kontrol bu bilgileri kullanıcı eylemi olmadan da gönderir; kapatmak için `VULNERABILITY_RECHECK=off` (yalnız zamanlanmış kontrol) veya `VULNERABILITY_LOOKUP=off` (tüm OSV/NVD trafiği).

  F4'ten itibaren OSV ve NVD adresleri kodda sabittir: `OSV_API_URL` ve `NVD_API_URL` **artık okunmaz** (`.env`'inizde kaldıysa silebilirsiniz). Bu iki istemci de kayıt defteri istemcisiyle aynı güvenli HTTP katmanını kullanır: host izin listesi, yönlendirme kısıtı, yanıt boyutu sınırları ve aşağıdaki vekil ayarları.
- **Ayarlar** (`.env` veya ortam değişkeni):
  - `REGISTRY_ENRICHMENT` — `on` (varsayılan) / `off` (kabul edilen değerler aşağıdaki "Açma/kapama ayarları" notunda). `off` iken hiçbir ağ isteği yapılmaz, önbellek okunmaz; lisans F2'deki gibi lock dosyasından alınır ve taramanın uyarılarına tek bir `[registry] License enrichment disabled: …` satırı yazılır. **Geçersiz değer artık kapalı (`off`) sayılır** (F3'te açık sayılıyordu).
  - `REGISTRY_TIMEOUT_MS` — istek başına zaman aşımı, varsayılan `15000` (1 ms – 24 sa).
  - `REGISTRY_CONCURRENCY` — eşzamanlı kayıt defteri isteği, varsayılan `4` (1–32).
- **Vekil sunucu:** Kayıt defteri istemcisi ve (F4'ten beri) OSV/NVD istemcisi yalnız `HTTPS_PROXY`/`https_proxy` ve `NO_PROXY`/`no_proxy` okur (`HTTP_PROXY`/`ALL_PROXY` okunmaz; tüm uç noktalar HTTPS'tir). `NO_PROXY` girdileri virgül ve/veya boşlukla ayrılır, büyük/küçük harf duyarsızdır: `*` (hiç vekil kullanma), `host`, `.alan`, `*.alan` veya `alan` (`example.com`, `a.example.com`'u kapsar, `badexample.com`'u kapsamaz); isteğe bağlı `:port` hedefin portuyla eşleşmelidir. IP adresleri birebir eşleşir; **CIDR (`10.0.0.0/8`) desteklenmez.** `HTTPS_PROXY` geçerli bir `http(s)://` adresi değilse hiçbir kayıt defteri/OSV/NVD bağlantısı açılmaz; paketler `unreachable` (kayıt defteri) veya "kontrol edilemedi" (OSV) sayılır. Vekil adresi kimlik bilgisi içerebilir; loglara ve hata metinlerine yazılmaz.
- **Kurumsal HTTPS denetimi yapan vekil (REQ-010 r2):** Bazı şirket vekilleri HTTPS trafiğini
  kendi kök sertifikalarıyla yeniden imzalar. Uygulama açılışta işletim sisteminin (Windows
  sertifika deposu) güvenilir köklerini Node'un listesine ekler; ek ayar gerekmez ve sertifika
  doğrulaması kapatılmaz. Açılışta `Sistem sertifika deposundan N kök sertifika eklendi` yazar.
  Kapatmak için `USE_SYSTEM_CA=off`. Bu olmadan OSV/NVD istekleri sertifika hatasıyla düşer ve
  tarama satırında **Kontrol edilemedi** görünür ("✓ Temiz" yalnız sorgu tamamlandıysa yazar).
- **.NET ve git repoları:** `obj/project.assets.json` derleme çıktısıdır, git'e girmez. Bu yüzden
  aynı proje yerel klasörden (derlenmişse) tam bağımlılık ağacıyla, git/TFS'ten ise yalnız
  `.csproj`'daki doğrudan paketlerle taranır. TFS/git taramasında da tam ağaç için projede NuGet
  kilit dosyasını açın (`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`) ve
  oluşan `packages.lock.json` dosyalarını commit edin. Next.js/Nuxt derleme klasörleri (`.next`,
  `.nuxt`) taranmaz.
- **Vekil ve OSV/NVD (F4 ile değişti):** F3'te OSV/NVD istekleri vekil kullanmıyordu ve vekilli ağda sessizce "açık yok" sonucu verebiliyordu. F4'ten itibaren bu istekler de yukarıdaki `HTTPS_PROXY`/`NO_PROXY` kurallarıyla gider; ulaşılamayan OSV artık "açık yok" sayılmaz, taramanın güvenlik açığı verisi `partial`/`unavailable` olarak işaretlenir (aşağıdaki F4 bölümü).
- **Kurumsal TLS denetimi:** Node kendi kök sertifika deposunu kullanır, Windows sertifika deposunu okumaz (Windows deposu yalnız git/clone için geçerlidir, yukarıdaki "Kurumsal vekil sunucu" notuna bakın). TLS denetimi yapan ağda şirket kök sertifikasını PEM dosyası olarak verin. Değişken süreç başlarken okunur, bu yüzden `npm start`'tan önce aynı PowerShell oturumunda tanımlanmalıdır:

  ```powershell
  $env:NODE_EXTRA_CA_CERTS = "C:\sertifikalar\sirket-kok-ca.pem"
  npm start
  ```

  Bu sertifika Node'un varsayılan deposuna eklenir ve hem kayıt defteri hem OSV/NVD bağlantılarında geçerli olur. Sertifika doğrulaması hiçbir durumda kapatılmaz.

  **TLS denetimi yapan vekil istek içeriğini görür (I-6):** Şirket kök sertifikasıyla TLS'i açıp yeniden şifreleyen bir vekil, uçtan uca şifrelemeyi kendi üzerinde sonlandırır. Bu vekil (ve onun loglarına erişen herkes) kayıt defteri, OSV ve NVD isteklerinin tamamını düz metin olarak görebilir: paket adları ve sürümleri, açık kimlikleri, CVE kimlikleri ve **`NVD_API_KEY` tanımlıysa NVD isteklerindeki `apiKey` başlığının değeri** dahil. Böyle bir ağda anahtarı vekil işletmecisiyle paylaşılmış sayın; gerekirse anahtar kullanmayın (yalnız NVD daha yavaş olur) veya `services.nvd.nist.gov`'u TLS denetiminden muaf tutturun.
- **Lock lisansı yalnız ipucudur (L-6):** Kayıt defterinin lisansı her zaman önceliklidir. Kayıt defterine ulaşılamazsa lock dosyasındaki lisans `lockfile (unverified)` kaynağıyla kullanılır ve taramanın uyarılarına `[registry] Registry lookup incomplete for …` satırı eklenir.
- **Kesin sürüm gereksinimi:** Zenginleştirme (kayıt defteri sorgusu ve arşivden LICENSE/NOTICE toplama) yalnız sürümü kesin bilinen paketler için yapılır. Kesin sürüm lock dosyasından (`package-lock.json`, `yarn.lock`, `poetry.lock`) ya da manifestteki tek bir tam sabitlemeden gelir: Python'da `==1.2.3` (veya `===1.2.3`), Poetry'de çıplak `1.2.3`, `package.json`'da `^`/`~` olmadan `1.2.3`. Aralık (`^4.17.0`, `>=2,<3`) veya sürümsüz bildirimde sürüm `NULL` kalır ve paket hiçbir istek yapılmadan `version_unknown` durumuna düşer. Bu paketin lisans kaynağı `none` olur, NOTICE'ta "version unknown" nedeniyle listelenir; runtime ise `NOASSERTION` lisans bulgusu açılır. Doğru sonuç için lock dosyası ekleyin veya sürümü sabitleyin.
- **`dev` kapsamı hâlâ lock dosyasından gelir (L-6 kalan riski, D-55):** Zenginleştirme lisansı doğrular, paketin kapsamını doğrulamaz. `package.json`'da runtime olarak (`dependencies`) beyan edilmiş doğrudan bağımlılık, lock dosyası `dev: true` dese de runtime kalır. Geçişli paketlerde ise `dev` bayrağı (npm lock'taki `dev`, `poetry.lock`'taki `category = "dev"`) olduğu gibi kullanılır ve doğrulanamaz. Taranan repo, runtime'da kullanılan geçişli bir paketi lock dosyasında `dev` işaretleyerek lisans politikasının dışına çıkarabilir: `dev` paket için lisans bulgusu açılmaz ve paket NOTICE'a girmez. Güvenilmeyen repoların lock dosyalarını bu gözle değerlendirin.
- **Davranış değişikliği (D-81):** Zenginleştirme açıkken sürümü kesin olmayan lock girdilerinin (`file:`, git, etiket — durum "sürüm bilinmiyor" veya "geçersiz ad/sürüm") lock lisansı artık kullanılmaz. Bu paketler runtime ise F2'de olmayan yeni `NOASSERTION` lisans bulguları açılabilir; gerekirse false positive kararıyla kapatın.
- **NOTICE indirme:** Tamamlanmış her taramanın satırında "NOTICE" bağlantısı vardır; API'de `GET /api/scans/{scanId}/notice` (`reports:read` izni, oturum çerezi veya `Authorization: Bearer <api-anahtari>`). Yanıt `NOTICE-<scanId>.txt` adlı UTF-8 düz metindir (`X-Checksum-SHA256` başlığıyla); yalnız runtime paketleri, lisans dosyası metinleri, telif satırları ve lisans dosyası olmayan paketler için neden satırı içerir. Tamamlanmamış veya olmayan tarama `404` döner. Metin 64 MiB'yi aşarsa kalan lisans metinleri `[text omitted: NOTICE size limit]` ile kısaltılır. F3 öncesi taramalarda NOTICE eksik olabilir (üst bilgide not yazar); tam NOTICE için projeyi yeniden tarayın. NOTICE otomatik üretilir, hukuki görüş değildir; dağıtmadan önce gözden geçirin.
- **Rapor sütunları:** Excel raporunun `Dependencies` sayfasına sonda iki sütun eklendi: `License` (etkin lisans) ve `License Source` (`registry:npm`, `registry:pypi`, `lockfile (unverified)`, `none`; lock ipucu kayıt defterinden farklıysa `registry:npm (lockfile differs: …)`, kayıt defterinde lisans yoksa `none (lockfile hint ignored: …)`). F3 öncesi taramalarda bu hücreler boştur. PDF'in "Dependency Inventory" tablosuna (`project_report`, `audit_evidence`) `License` sütunu eklendi (boşsa `n/a`). Diğer sayfalar değişmedi.
- **Excel formül kalkanı ve scoped npm adları (N-2):** Excel raporunda her sayfanın her metin hücresi, `=`, `+`, `-`, `@`, sekme (`\t`) veya satır başı (`\r`) ile başlıyorsa başına `'` eklenerek yazılır (formül enjeksiyonuna karşı). Bu yüzden scoped npm adları `Dependencies` sayfasının `Name`, `Licenses` ve `Vulnerabilities` sayfalarının `Package` sütunlarında `'@scope/ad` olarak görünür (ör. `'@types/node`). Excel çıktısını paket adına göre başka verilerle eşleştiriyorsanız baştaki `'` karakterini atın. PDF, SBOM ve NOTICE çıktıları bu kalkandan etkilenmez.
- **SBOM:** Yeni üretilen SPDX 2.3 dokümanlarında `licenseDeclared` etkin lisansın geçerli SPDX ifadesidir (değilse `NOASSERTION` ve `licenseComments`), `licenseConcluded` her zaman `NOASSERTION`, `copyrightText` arşivden çıkarılan telif satırlarıdır. CycloneDX 1.5'te her bileşende tek bir `licenses` girdisi ve `copyright` alanı bulunur. Daha önce üretilmiş SBOM dosyaları yeniden üretilmez.
- **Önbelleği temizleme:** Kayıt defteri ve arşiv önbelleğini silme SQL'i `db/README.md`'dedir. Temizlikten sonra eski taramaların NOTICE'ında "license file data no longer cached; rescan required" nedeni görünür.

**Güvenlik açığı verisi, günlük yeniden kontrol ve risk kabulü süresi (REQ-005 F4)**

- **OSV toplu sorgu:** Tarama, kesin sürümü bilinen paketleri `api.osv.dev`'in toplu sorgu uç noktasıyla (`/v1/querybatch`, istek başına en fazla 1000 paket) sorgular; açık ayrıntıları ve NVD CVSS sonuçları veritabanında önbelleğe alınır (OSV kaydı `modified` değişmedikçe yeniden indirilmez, NVD sonucu 7 gün / CVSS yoksa 24 saat geçerlidir). Önbelleği silme SQL'i `db/README.md`'dedir.
- **Güvenlik açığı verisi durumu ve `[osv]`/`[nvd]` satırları:** Her taramanın güvenlik açığı verisi `complete` (tüm paketler kontrol edildi), `partial` (bir kısmı kontrol edilemedi), `unavailable` (hiçbiri kontrol edilemedi) veya `disabled` (`VULNERABILITY_LOOKUP=off`) olarak işaretlenir. `complete` dışındaki durumlarda taramanın uyarılarına tek bir `[osv] …` satırı, NVD sorunu varsa bir `[nvd] …` satırı eklenir. OSV'ye ulaşılamaması artık "açık yok" anlamına gelmez; kontrol edilemeyen paketler sayıyla belirtilir. NVD hatası durumu düşürmez, yalnız CVSS puanını boş bırakır.
- **Günlük yeniden kontrol:** Uygulama çalışırken her projenin son tamamlanmış taramasındaki paketleri, varsayılan olarak 24 saatte bir (`VULNERABILITY_RECHECK_INTERVAL_HOURS`, 1–168) yeni açıklara karşı yeniden sorgular; yeni açık için bulgu açılır, depo yeniden clone edilmez. İlk kontrol başlangıçtan yaklaşık 1 dakika sonra, sonra 10 dakikada bir "vade geldi mi" diye bakılır; uygulama kapalıyken kaçırılan kontrol açılışta telafi edilir (birikmiş günler için tek bir çalıştırma). Başarısız çalıştırmadan sonra en az 1 saat beklenir; tek çalıştırma 30 dakika ve 10 000 paketle sınırlıdır. Veritabanı kilidi kaybedilip uygulama bozulmuş kipe geçerse zamanlayıcı durur, kilit geri alınınca devam eder. `VULNERABILITY_RECHECK=off` yeniden kontrolü kapatır (tarama sırasındaki sorgu sürer).
- **Risk kabulü süresi dolunca otomatik yeniden açma (P-19):** `accepted_until` tarihi geçmiş risk kabulleri saatte bir değerlendirilir ve bulgu yeniden `open` yapılır; her yeniden açma `audit_logs`'a `risk_acceptance_expired` nedeniyle yazılır. Tarih **makinenin yerel takvim gününe** göre karşılaştırılır (kabul, `accepted_until` gününün sonuna kadar geçerlidir). Bu davranışın kapatma ayarı **yoktur**.
- **Ayarlar** (`.env` veya ortam değişkeni):
  - `VULNERABILITY_LOOKUP` — `on` (varsayılan) / `off`. `off` iken OSV/NVD'ye hiç istek gitmez; taramalar `disabled` işaretlenir ve `[osv]` satırı bunu belirtir.
  - `VULNERABILITY_RECHECK` — `on` (varsayılan) / `off`.
  - `VULNERABILITY_RECHECK_INTERVAL_HOURS` — varsayılan `24` (1–168).
  - `NVD_API_KEY` — isteğe bağlı, **büyük envanterlerde önerilir**. NVD 30 saniyede anahtarsız 5, anahtarla 50 isteğe izin verir. Uygulama NVD'nin saydığı varış zamanıyla kendi saydığı başlangıç zamanı arasındaki farka karşı güvenlik payı bırakır: 35 saniyede en fazla 5 (anahtarla 50) istek, anahtarsız kullanımda iki istek arasında en az 6 saniye. NVD `429` dönerse tüm NVD istekleri `Retry-After` süresi kadar, bu başlık yoksa (veya kullanılamıyorsa) 35 saniye bekler. Anahtarsız ilk taramada 40 CVE'lik NVD sorgusu yaklaşık 4 dakika sürer; anahtarla yarım dakikanın altına iner. Art arda başarısız NVD denemeleri (`429` dahil) o tarama veya yeniden kontrol için NVD'yi devre dışı bırakır; kalan CVE'lerin CVSS'i boş kalır. Anahtar hiçbir logda, hata metninde, API yanıtında veya durum ekranında gösterilmez; tanımlı olup olmadığı bile dönmez. TLS denetimli vekil notuna bakın (yukarıda, "Kurumsal TLS denetimi").
  - `NVD_ENABLED` — `on` (varsayılan) / `off`; `off` yalnız NVD'yi kapatır (OSV ve yerel CVSS hesabı sürer). `OSV_TIMEOUT_MS` (varsayılan `15000`) ve `OSV_CONCURRENCY` (varsayılan `4`, 1–32) OSV/NVD istek sınırlarıdır.
  - `OSV_API_URL` / `NVD_API_URL` kaldırıldı (okunmaz).
- **Açma/kapama ayarları (`VULNERABILITY_LOOKUP`, `VULNERABILITY_RECHECK`, `NVD_ENABLED`, `REGISTRY_ENRICHMENT`; L-2):** Dördü aynı kuralla okunur; baş/son boşluk kırpılır, büyük/küçük harf duyarsızdır. `on`, `true`, `1`, `yes` → açık; `off`, `false`, `0`, `no` → kapalı; boş veya tanımsız → açık (varsayılan). **Başka her değer kapalı sayılır** (gizlilik için) ve açılışta yalnız değişken adını içeren tek uyarı yazılır (değer loglanmaz). Önceki sürümden farklar: `VULNERABILITY_LOOKUP`/`VULNERABILITY_RECHECK`/`REGISTRY_ENRICHMENT` için geçersiz değer artık açık değil kapalıdır ve `false`/`0`/`no` da kapatır; `NVD_ENABLED` için `off`/`0`/`no` (her harf biçiminde) de kapatır ve ör. `NVD_ENABLED=False` artık kapalıdır.
- **CVSS puanı kaynağı (P-1):** Puan sırasıyla OSV kaydındaki geçerli sayısal puandan (0–10), OSV kaydındaki ilk geçerli `CVSS_V3` vektöründen yerel hesapla (CVSS v3.0/v3.1 taban denklemleri, NVD'nin aynı vektör için verdiği puanla aynı) ve ancak bunlar yoksa (yalnız `CVSS_V4`/`CVSS_V2` vektörü veya hiç önem bilgisi) NVD'den alınır; hiçbiri yoksa önem `medium`, CVSS boştur. Bu, NVD hız sınırı nedeniyle uzayan ilk taramaları belirgin biçimde kısaltır. OSV ve NVD vektörleri farklıysa puan F4 öncesinden farklı olabilir.
- **OSV veri sınırları (M-1):** Bir sorgu (tarama veya yeniden kontrol) başına: paket başına en fazla 200 benzersiz açık kimliği (aşan paket "kontrol edilemedi" sayılır ve ondan bulgu yazılmaz), toplam 5 000 benzersiz kimlik ve 2 000 ayrıntı isteği (kalan kimlikler önbellekteki veya asgari kayıtla yazılır, "ayrıntı eksik" sayılır). Yeniden kontrolün yazma aşaması da 30 dakika sınırına tabidir; süre dolunca o anki proje geri alınır, kalan projeler bir sonraki çalıştırmada yazılır. Yazmaya süre kalması için sorgu aşaması çalıştırmanın başından itibaren en geç 25. dakikada kesilir (kalan paketler "kontrol edilemedi" sayılır); son 5 dakika yazma aşamasına ayrılmıştır. Eşzamanlı bir taramayla kilitlenme (`deadlock`) olursa açık kataloğu yazımı ve yeniden kontrolün proje transaction'ı birer kez yeniden denenir. Geçersiz `published`/`modified` tarihleri ve 0–10 dışındaki CVSS puanları yok sayılır.
- **Lock `integrity` uyuşmazlığı (L-5):** npm lock dosyasındaki (`package-lock.json` v1–v3, `yarn.lock` v1) `integrity` değeri, kayıt defterinin aynı sürüm için yayımladığı `sha512` değeriyle karşılaştırılır. Uyuşmazsa o paket için kayıt defteri lisansı da lock ipucu da kullanılmaz: lisans kaynağı `none` olur, arşiv indirilmez ve önbellekteki arşiv kullanılmaz, runtime paket için `NOASSERTION` lisans bulgusu açılır. Excel `License Source` hücresi `none (lockfile integrity mismatch)`, NOTICE nedeni `lockfile integrity does not match registry; license not verified` olur, SBOM'da lisans `NOASSERTION` kalır; taramanın uyarılarındaki `[registry]` satırı uyuşmazlık sayısını verir. Değer yoksa, yalnız `sha1` ise veya karşılaştırılamıyorsa davranış F3 ile aynıdır. PyPI karşılaştırılmaz. **Bilinen sınır (I-5):** Bu denetim yalnız lock dosyasında `integrity` bulunduğunda çalışır; taranan repo lock dosyasından `integrity` alanını silerse sonuç `not_comparable` olur ve paket F3 gibi kayıt defteri lisansıyla işlenir (uyuşmazlık uyarısı çıkmaz). Güvenilmeyen repolarda `integrity`'siz lock dosyalarını bu gözle değerlendirin.
- **P-19 ilk dağıtım — ön kontrol ve geri alma:** F4 ilk kez başladığında süresi geçmiş, süresiz (`accepted_until` boş) ve incelemesiz kabul edilmiş bulgular yeniden `open` yapılır. Etkiyi önceden görmek için F4'ü başlatmadan önce salt okunur ön kontrol sorgusunu çalıştırın (`<BUGUN>` = uygulama sunucusunun **yerel** tarihi, `YYYY-MM-DD`):

  ```sql
  BEGIN TRANSACTION READ ONLY;
  WITH latest AS (
    SELECT DISTINCT ON (r.finding_id) r.finding_id, r.accepted_until
      FROM finding_reviews r
     WHERE r.decision = 'accept_risk'
     ORDER BY r.finding_id, r.created_at DESC, r.id DESC
  )
  SELECT count(*)                                                        AS would_reopen,
         count(*) FILTER (WHERE l.finding_id IS NULL)                    AS no_review,
         count(*) FILTER (WHERE l.finding_id IS NOT NULL
                            AND l.accepted_until IS NULL)                AS no_expiry,
         count(*) FILTER (WHERE l.accepted_until < DATE '<BUGUN>')       AS expired
    FROM findings f
    LEFT JOIN latest l ON l.finding_id = f.id
   WHERE f.status = 'accepted'
     AND (l.finding_id IS NULL OR l.accepted_until IS NULL
          OR l.accepted_until < DATE '<BUGUN>');
  ROLLBACK;
  ```

  Yanlış bir değerlendirmeyi (ileri atlamış sistem saati, yanlış saat dilimi, kod hatası) geri alma prosedürü bir **toplu veri güncellemesidir** ve yalnız açık insan onayıyla, uygulama durdurulup yedek alındıktan ve neden düzeltildikten sonra çalıştırılır. Adımlar ve SQL: `docs/contracts/REQ-005-vulnerability-data.md` bölüm 7.2 (b). Geri alma kullanıcı kararlarını ezmez, orijinal denetim satırlarını silmez ve her geri alınan bulgu için `risk_acceptance_expiry_reverted` nedenli telafi denetim satırı yazar. Kabulün süresi gerçekten dolmuşsa geri alma anlamsızdır; kabul yeni bir `accept_risk` incelemesiyle uzatılmalıdır.
- **Durum uç noktası ve Dashboard paneli:** `GET /api/vulnerability-data/status` (`scans:read` izni, oturum çerezi veya `Authorization: Bearer <api-anahtari>`) ayarları, zamanlayıcının bir sonraki kontrol zamanını, son yeniden kontrol çalıştırmasını, projelerin son taramalarının güvenlik açığı verisi durumunu (en fazla 500 proje, sayımlar tüm projeler üzerinden) ve son 7 günde süresi dolup yeniden açılan risk kabulü sayısını salt okunur olarak döner (`Cache-Control: no-store`). Hiçbir şey yazmaz, ağ isteği yapmaz. Dashboard'daki güvenlik açığı verisi paneli bu uç noktayı kullanır.

Notlar: `HOST` değerini loopback dışına (ör. `0.0.0.0`) çekmek API'yi düz HTTP ile ağa açar ve başlangıçta uyarı verir. Unutulan parola, `db/README.md`'deki kurtarma SQL adımıyla sıfırlanır; ardından setup aynı kullanıcıya yeni parola atar.

## Web (URL) güvenlik taraması (REQ-008)

Bağımlılık taramasına ek olarak platform, **çalışan bir web uygulamasını adresi
üzerinden** denetleyebilir (kodu elde olmayan yayındaki sistemler dahil).
Ayrıntılar: `docs/product/REQ-008.md`, `docs/architecture/adr/ADR-010-web-url-guvenlik-taramasi.md`,
`docs/contracts/REQ-008-web-scan.md`.

> **Yalnız kendi sistemlerinizi tarayın.** Sahibi olmadığınız veya yazılı izin
> almadığınız bir sisteme tarama yapmak suç olabilir (TCK 243–244). Bu yüzden
> web taraması varsayılan olarak **kapalıdır** ve yalnız `.env`'deki izin
> listesine yazılan hostlara istek atar.

**Kurulum**

1. `.env`'e taranabilecek hostları yazın ve uygulamayı yeniden başlatın:

    ```
    WEB_SCAN_ALLOWED_HOSTS=portal.sirket.local, *.sirket.com.tr, 10.1.2.3
    ```

   Girdi biçimleri: tam host, `*.alan` (yalnız alt alan adları; `alan`'ın kendisi
   ayrıca yazılır), IPv4, `[IPv6]`. Şema, port veya yol yazılmaz (hostun her
   portu kapsanır). Geçersiz bir girdi uygulamanın başlangıçta durmasına yol
   açar; liste boşsa web adresleri `400 web_url_not_allowed` alır.
2. İç sistemleriniz şirket iç sertifika otoritesiyle imzalıysa kök sertifikayı
   `NODE_EXTRA_CA_CERTS` ile verin (yukarıdaki "Kurumsal TLS denetimi" notu).
   Aksi halde tarama `WEB-TLS-003` (sertifika doğrulanamadı) bulgusu yazar ve
   içerik kontrollerini atlar; sertifika doğrulaması hiçbir zaman kapatılmaz.
3. Arayüzde **New Project Scan** penceresine "Web URL" girin (repo yolu
   isteğe bağlıdır) veya **Projects** ekranında **Web URL** düğmesiyle mevcut
   projeye adres ekleyin. **Web Scan** düğmesi taramayı kuyruğa alır.
   API: `POST /api/projects` (`webUrl`), `PATCH /api/projects/{id}`
   (`webUrl`, `webScanMode`), `POST /api/scans` (`"kind": "web"`).

**Ne kontrol edilir (yerleşik, pasif)**

Yalnız zararsız `GET` istekleri atılır (form gönderilmez, çerez saklanmaz,
kimlik bilgisi gönderilmez), taramada en fazla 120 istek, aynı anda en fazla 3.
`User-Agent: oss-risk-platform/<sürüm> (web-scan)`; sunucu loglarında bu adla
görünür. 34 kural (tam katalog contract §4):

- **HTTPS/TLS:** şifresiz HTTP, HTTP→HTTPS yönlendirmesi, sertifika geçerliliği
  ve 30 gün içinde bitiş, TLS 1.0/1.1 kabulü.
- **Güvenlik başlıkları:** HSTS, CSP (yok veya gevşek), clickjacking koruması,
  `nosniff`, `Referrer-Policy`, `Permissions-Policy`.
- **Bilgi ifşası:** `Server` sürümü, `X-Powered-By`, `X-AspNet-Version`,
  ayrıntılı hata sayfaları/yığın izleri (ASP.NET YSOD, .NET Core geliştirici
  sayfası, SQL hataları …), dizin listeleme.
- **Çerezler:** `Secure`, `HttpOnly` (oturum çerezlerinde orta önem), `SameSite`.
- **CORS:** her kaynağın (ve `null`'ın) kimlik bilgisiyle yansıtılması.
- **Açıkta kalan dosyalar:** `.git`, `.env`, `appsettings*.json`, `web.config`,
  `elmah.axd`, `trace.axd`, `.svn`/`.hg`/`.DS_Store`, `server-status`,
  `phpinfo.php`, Swagger/OpenAPI. İçerik doğrulanır (yalnız `200` yetmez) ve
  rastgele bir yola verilen yanıtla karşılaştırılır. **Dosya içerikleri
  saklanmaz**; kanıtta yalnız eşleşen anahtar adları bulunur.
- **Sayfa içeriği:** karma içerik, harici betiklerde SRI eksikliği, HTTP'ye
  giden formlar.
- **JavaScript kütüphaneleri:** sayfadaki jQuery, Bootstrap, AngularJS/Angular,
  Vue, Lodash, Moment, React … adres, dosya başlığı veya HTML özniteliğinden
  tespit edilir ve OSV'de (npm) bilinen açıklar sorgulanır (`WEB-LIB-001`).
  Üçüncü taraf (CDN) betikleri **indirilmez**, sürüm adresten okunur.
  Paketlenmiş (webpack) uygulamalarda tespit sınırlıdır; bu durumda
  bağımlılık taraması kullanın.

**Sonuçlar ve rapor**

- Tarama satırında `Web` etiketi, hedef host ve **güvenlik notu (A–F)** görünür.
  Not: `100 − 40·kritik − 20·yüksek − 8·orta − 2·düşük` (en az 0);
  A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.
- **Vulnerabilities** ekranında web taraması seçilince not kartı, bulgular
  (kural, önem, OWASP 2021, CWE, konum, kanıt, öneri) ve tespit edilen
  kütüphaneler gösterilir. API: `GET /api/scans/{id}/web-findings`.
- Satırdaki **PDF** yönetici odaklı rapordur (ilk sayfa: not, önem dağılımı,
  öne çıkan bulgular, "ne yapılmalı"); **CSV** tüm bulgulardır.
  `GET /api/scans/{id}/exports/web-report.pdf` ve `…/web-findings.csv`.
  PDF, Türkçe karakterler için Windows'ta Arial/Segoe UI, Linux'ta DejaVu
  fontunu kullanır.
- Web taramasının `scans` sayaçları web bulgularının önem dağılımıdır;
  bağımlılık çıktıları (Excel, NOTICE, SBOM) web taraması için `404` döner.
  Günlük CVE yeniden kontrolü ve durum paneli yalnız **bağımlılık**
  taramalarını "son tarama" sayar.

**OWASP ZAP ile derin tarama (isteğe bağlı, Docker'sız)**

Yerleşik kontroller yapılandırma hatalarını bulur; XSS/SQL injection gibi
uygulama açıklarına yaklaşmak için makinede bir **OWASP ZAP** daemon'u
çalıştırıp bağlayabilirsiniz:

1. ZAP'ı Windows kurulum paketiyle kurun (`https://www.zaproxy.org/download/`).
2. API anahtarıyla daemon olarak başlatın (PowerShell):

    ```powershell
    & "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat" -daemon -host 127.0.0.1 -port 8090 -config api.key=<uzun-rastgele-anahtar>
    ```

3. `.env`: `ZAP_API_URL=http://127.0.0.1:8090` ve `ZAP_API_KEY=<aynı anahtar>`;
   uygulamayı yeniden başlatın.

Her web taramasında ZAP'ta **yeni oturum** açılır (ZAP örneği bu araca ayrılmış
olmalı) ve ZAP yalnız hedef hostu kapsayan bir bağlamda (context) çalıştırılır;
site gezdirilir (spider, en fazla 5 dk, form gönderilmez), pasif tarama
sonuçları alınır. ZAP istekleri kendi hostundan atar: ZAP'ı aracın çalıştığı
makinede `127.0.0.1`'e bağlayın ve ağda yalıtılmış tutun.
Projede tarama modu **Active** seçildiyse ayrıca **aktif tarama** (saldırı
simülasyonu, en fazla 30 dk) yapılır. Aktif tarama sisteme gerçek saldırı
istekleri gönderir ve kayıt/veri oluşturabilir: **canlı sistemlerde değil, test
ortamında kullanın.** ZAP'a ulaşılamazsa tarama yerleşik sonuçlarla tamamlanır
ve `[zap] …` uyarısı yazılır. ZAP alarmları eklenti başına tek bulgu olarak
(`ZAP-<pluginId>`) aynı listeye düşer; ZAP'ın "False Positive" işaretledikleri
ve izin listesi dışındaki adresler atılır.

**Sınırlamalar**

- Bir host adı `127.0.0.1`, `169.254.x.x` gibi loopback/link-local bir adrese
  çözülürse istek atılmaz; bunu bilerek tarayacaksanız IP'yi listeye açıkça
  yazın. Ana sayfa yönlendirmeleri yalnız aynı adrese (veya http ↔ https)
  izlenir.
- Kimlik doğrulama arkasındaki sayfalar taranmaz (giriş sayfasına kadar).
- Web bulgularında henüz karar akışı (false positive / risk kabulü) yoktur.
- Zamanlanmış web taraması ve CLI'da `--kind web` sonraki fazdadır.
- Otomatik tarama, sızma testinin (pentest) yerini tutmaz.

## Tek tıkla çıktılar (PDF, Excel, CSV, NOTICE)

REQ-007 (F6) P-24 / ADR-009 Karar 7–9; REQ-010 P-38. Tamamlanmış her tarama satırında (pano ve
tarama geçmişi) tek bir **Raporlar** menüsü vardır; her seçenek bir cümleyle açıklanır:
*Yönetici raporu (PDF)*, *Ayrıntılı tablo (Excel)*, *Paket listesi (CSV)*, *Lisans bildirimi
(NOTICE)* ve *SBOM*. İlk dördü dosyayı ara ekran olmadan doğrudan indirir (düz `<a download>`
bağlantıları). Web taraması satırında yalnız web raporu (PDF) ve bulgu listesi (CSV) bulunur. Çıktılar istek anında yalnız veritabanından üretilir:
`reports` satırı, dosya, denetim satırı veya ağ isteği oluşmaz (Raporlar ekranındaki asenkron
raporlar aynen sürer).

| Uç nokta (`reports:read`, oturum çerezi veya `Authorization: Bearer <api-anahtari>`) | İçerik | Dosya adı |
| --- | --- | --- |
| `GET /api/scans/{scanId}/exports/project-report.pdf` | `project_report` PDF'i | `project-report-<scanId>.pdf` |
| `GET /api/scans/{scanId}/exports/license-inventory.xlsx` | `license_inventory` Excel'i (dört sayfa) | `license-inventory-<scanId>.xlsx` |
| `GET /api/scans/{scanId}/exports/license-inventory.csv` | Excel `Dependencies` sayfasının CSV'si | `license-inventory-<scanId>.csv` |
| `GET /api/scans/{scanId}/notice` (değişmedi) | NOTICE metni | `NOTICE-<scanId>.txt` |

- **Yanıt:** `Content-Disposition: attachment`, `Content-Length`, `X-Checksum-SHA256` (gövdenin
  SHA-256'sı) ve `Cache-Control: no-store`. Dosya adında proje adı yoktur. Geçersiz `scanId` →
  `400`; olmayan veya tamamlanmamış tarama → `404` ("Scan not found or not yet completed").
- **Eşzamanlı üretim sınırı:** Sunucu aynı anda en fazla **2** PDF/Excel/CSV üretir (üç uç nokta
  toplamı; NOTICE sınır dışıdır). Fazlası `429` (`code: export_busy`, `Retry-After: 5`) alır; bu
  durumda tarayıcı indirmeyi başarısız gösterir — **birkaç saniye sonra tekrar deneyin.** Sınır
  doluyken var olmayan bir tarama için de `429` döner. Tek üretim `EXPORT_WORKER_TIMEOUT_MS`
  (varsayılan 10 dakika) ile sınırlıdır; aşılırsa `500`.
- **CSV biçimi:** UTF-8 + BOM, ayırıcı virgül (yerel ayardan bağımsız), satır sonu CRLF (son satır
  dahil), ilk satır `Name,Version,Ecosystem,Scope,Manifest,Depth,PURL,License,License Source`.
  Virgül, çift tırnak veya satır sonu içeren ya da başında/sonunda boşluk/sekme olan alan çift
  tırnağa alınır (içteki `"` → `""`). Hücre metinleri Excel `Dependencies` sayfasıyla aynıdır;
  `=`, `+`, `-`, `@`, sekme veya satır başı ile başlayan değerlerin başında Excel'deki gibi `'`
  bulunur (formül enjeksiyonu kalkanı). Aynı tarama için CSV bayt bayt aynıdır; PDF ve Excel üretim
  zamanını içerdiği için istekten isteğe özet değişebilir. Türkçe yerel ayarlı Excel'de (ayırıcı
  `;`) `.xlsx` çıktısını kullanın.
- **Yönetici raporu (PDF, REQ-010):** PDF Türkçedir ve yöneticiye göre kurgulanmıştır:
  - **Genel durum:** tek cümlelik sade değerlendirme (kritik açık var / yüksek riskli bulgu var /
    iyileştirme önerileri var / belirgin risk yok), paket, güvenlik açığı (önem dağılımıyla) ve
    lisans uyarısı sayıları; son satır `Güvenlik açığı verisi` (`tam`, `kısmi …`, `alınamadı …`,
    `kapalı …`, `kontrol edilmedi`).
  - **Ne yapılmalı?:** en fazla 10 maddelik öncelikli aksiyon listesi ("X paketini A sürümünden B
    sürümüne yükseltin", düzeltmesi olmayan açıklar için alternatif değerlendirme, yüksek riskli
    lisanslar için hukuk birimi).
  - Türkçe başlıklı, sütun hizalı tablolar: `Güvenlik açıkları` (40 satır), `Lisans bulguları` (40)
    ve `Paket envanteri` (50). Kesilen tablonun altında `İlk <n> / <toplam> kayıt gösteriliyor; tam
    liste için Excel veya CSV çıktısına bakın.` yazar.
  - Sonda kısa `Terimler` kutusu, "hukuki görüş değildir" notu ve tarama kimliği.
  - Türkçe karakterler için sistem fontu (Arial/Segoe UI; Linux'ta DejaVu/Liberation) kullanılır;
    font yoksa ş/ğ/ı/İ ASCII'ye katlanır. Asenkron raporlarda da aynıdır.
- **Excel, CSV, NOTICE, SBOM:** makine tarafından okunan biçimler olduğu için İngilizce
  başlıklarını korur. Excel `Summary` sayfasının son satırı `Vulnerability Data Status`'tur:
  `complete`, `partial (some packages could not be checked)`, `unavailable (vulnerability source
  unreachable)`, `disabled (lookup turned off)` veya (F4 öncesi taramalar) `not checked`.
- **Sistem durumu (REQ-010):** Arayüzdeki *Sistem Durumu* ekranı hangi özelliğin açık/kapalı
  olduğunu ve kapalıysa hangi `.env` ayarıyla açılacağını gösterir (`GET /api/system/features`;
  yalnız açık/kapalı ve sayı döner, ayar değerleri, host adları veya anahtarlar dönmez).

## Komut satırı istemcisi (`oss-risk` CLI)

REQ-007 (F6) / ADR-009. CLI, çalışan bir sunucuya karşı mevcut bir projenin taramasını başlatır,
bitmesini bekler ve `--fail-on` eşiğine göre çıkış kodu döner; CI'da kalite kapısı olarak
kullanılır. Yalnız Node yerleşik modüllerini kullanır (yeni bağımlılık yok), `.env` okumaz,
sunucu modüllerini içe aktarmaz.

**Desteklenen çağrı:** `npm run build` sonrası `node dist/cli/index.js <komut> …`
(`package.json` `bin` alanı `oss-risk` adını tanımlar; `npx oss-risk` repo içinde bir
kolaylıktır ve doğrulanması gerekir). `--help`/`-h` ve `--version`/`-V` ağ isteği yapmaz.

```bash
# Tarama (anahtar yalnız ortam değişkeninden)
OSS_RISK_API_KEY_FILE=~/.config/oss-risk.key \
  node dist/cli/index.js scan --project my-service --fail-on high
node dist/cli/index.js scan --project 0b6e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b --format json

# Geçici CI veritabanında ilk kurulum + API anahtarı (yalnız YENİ veritabanı!)
node dist/cli/index.js bootstrap --new-database --key-file "$RUNNER_TEMP/oss-risk.key" \
  --project-name my-service --project-path .
```

`scan` seçenekleri: `--project <uuid|ad>` (zorunlu; UUID değilse birebir ad eşleşmesi),
`--url <adres>`, `--fail-on none|low|medium|high|critical` (varsayılan `high`),
`--format text|json` (varsayılan `text`), `--timeout <saniye>` (10–86400, varsayılan 1800),
`--allow-incomplete`. `bootstrap` seçenekleri: `--new-database` (zorunlu), `--key-file <yol>`
(zorunlu, dosya var olmamalı), `--url`, `--project-name` + `--project-path` (birlikte).

**Ortam değişkenleri**

| Değişken | Anlam |
| --- | --- |
| `OSS_RISK_API_KEY` | API anahtarı değeri (`scan`). |
| `OSS_RISK_API_KEY_FILE` | API anahtarını içeren dosyanın yolu (en fazla 1 KiB, baştaki/sondaki boşluk atılır). İkisinden **tam olarak biri** verilmelidir. |
| `OSS_RISK_URL` | Sunucu adresi; `--url` önce gelir; varsayılan `http://127.0.0.1:3001`. |

Anahtar komut satırından **verilemez**: `--api-key`, `--key`, `--token` çıkış 2 ile reddedilir.
Anahtar yalnız `Authorization: Bearer` başlığıyla gönderilir; çıktıya, log'a veya hata metnine
yazılmaz. `bootstrap` anahtar ortam değişkenlerini okumaz.

**Adres kuralları:** `http(s)://host[:port]` (kullanıcı bilgisi, yol, sorgu, parça yok).
Loopback (`127.0.0.1`, `localhost`, `[::1]`) dışındaki adresler `https` olmalıdır; loopback dışı
`http` hiç bağlantı kurmadan 2 ile reddedilir. CLI loopback isteklerinde `Host: <host>:<port>`
başlığını açıkça gönderir. **Loopback dışı `https` sınırı:** sunucu yalnız kendi Host izin
listesini kabul eder; loopback dışı `https` ancak TLS sonlandıran bir ara katman `Host`'u izin
listesine uygun iletirse çalışır, aksi halde `403 host_rejected` → çıkış 2. Vekil sunucu
(`HTTP(S)_PROXY`) kullanılmaz, yönlendirmeler izlenmez (çıkış 3), TLS doğrulaması kapatılamaz.

**Çıkış kodları**

| Kod | Anlam |
| --- | --- |
| `0` | Tarama tamamlandı; eşik aşılmadı ve veri tamlığı sağlandı (veya `--fail-on none`, `disabled`, `--allow-incomplete`). `--help`, `--version`, başarılı `bootstrap`. |
| `1` | Tarama tamamlandı; `--fail-on` eşiği aşıldı. |
| `2` | Kullanım/yapılandırma: argüman, `--api-key` ailesi, adres, anahtar kaynağı/biçimi, `--new-database` yok, proje bulunamadı/belirsiz/reddedildi, anahtar dosyası zaten var, `403 host_rejected`/`origin_rejected`. |
| `3` | Tarama `failed`/`cancelled`/`timeout`, bekleme süresi doldu, bağlantı hatası/istek zaman aşımı (GET'lerde art arda 3), `3xx`, `429`, `5xx`, beklenmeyen yanıt, gövde > 32 MiB. |
| `4` | Kimlik/yetki: `401`, diğer `403`; `bootstrap`'ta veritabanı zaten kurulmuş (`409`). |
| `5` | Tarama tamamlandı, eşik aşılmadı ama güvenlik açığı verisi eksik (`partial`, `unavailable`, `not_checked`, `unknown`) ve `--allow-incomplete` yok. |

Öncelik: 2/3/4 → 1 → 5 → 0. `--fail-on none` iken 1 ve 5 üretilmez.

**`--fail-on` eşlemesi.** Yalnız `open`/`in_review` durumundaki `security` ve `license`
bulguları sayılır. Etkin seviye ≥ eşik olan en az bir bulgu varsa eşik aşılır
(`low < medium < high < critical`).

| Tür | Girdi | Etkin seviye |
| --- | --- | --- |
| security | `severity` = `low`/`medium`/`high`/`critical` | aynen |
| security | `severity` = `none` | yok (eşik tetiklenmez) |
| security | `severity` boş veya tanınmayan | `high` |
| license | `risk_level` = `safe` | yok (politika tabanı yoksa) |
| license | `risk_level` = `low`/`medium`/`high`/`critical` | aynen |
| license | `risk_level` = `unknown`, boş veya tanınmayan | `high` |
| license | `applied_policy` = `prohibited` / `restricted` / `review_required` | taban `critical` / `high` / `medium` |
| license | birleşim | max(risk seviyesi, politika tabanı) |

**Veri tamlığı.** Tamamlanan taramada `GET /api/vulnerability-data/status` her zaman okunur;
durum `complete` değilse uyarı yazılır. Bilinen sınırlar: durum listesi en fazla 500 proje
döndürür (sonrakiler eşleşmez) ve aynı projenin daha yeni bir taraması okumadan önce biterse
eşleşme kaybolur; her iki durumda sonuç `unknown` → 5'tir. Çözüm yeniden çalıştırmak veya
bilinçli olarak `--allow-incomplete` kullanmaktır.

**Çıktı.** `text`: özet stdout'a, ilerleme/uyarı/hata stderr'e. `json`: stdout'a tek JSON nesnesi
(`schemaVersion: 1`; şema `docs/contracts/REQ-007-cli-and-exports.md` bölüm 5.6), stderr boş.
Uzak kaynaklı tüm metinler tek satıra indirilir, kontrol karakterleri (ANSI dahil) silinir ve
200 kod noktasıyla kesilir.

**`bootstrap` uyarısı (ADR-001 Karar 12).** `bootstrap`, parolası olmayan bir veritabanına
**bilinmeyen rastgele bir admin parolası** koyar ve API anahtarını `--key-file`'a (`wx`, POSIX'te
0600; Windows'ta klasör ACL'i devralınır) yazar. Yalnız **yeni, boş, geçici** (CI) bir
veritabanında çalıştırın; bu yüzden `--new-database` beyanı zorunludur. Sunucu setup'ı, parolası
kurtarma için boşaltılmış (ADR-001 Karar 12 kurtarma durumundaki) bir veritabanında da kabul eder
ve istemci bu iki durumu ayıramaz: gerçek veriye sahip, kurtarma durumundaki bir veritabanına karşı
`bootstrap` çalıştırmak admin parolasını bilinmeyen bir değere ayarlar. Bu olursa kurtarma yeniden
`db/README.md`'deki Karar 12 adımıyla yapılır. Veritabanı zaten kuruluysa `bootstrap` 4 ile
çıkar; anahtar dosyası varsa hiç istek yapmadan 2 ile çıkar. Anahtar dosyasını kullanıcıya ait
bir klasörde tutun.

## GitHub Actions

REQ-007 (F6) P-23 / ADR-009 Karar 11. Repoda iki iş akışı vardır:

| Dosya | Çalıştırıcı | Amaç |
| --- | --- | --- |
| `.github/workflows/ci.yml` | `ubuntu-latest` | Bu reponun CI'ı: `npm ci` → `npm run lint` → `npm run typecheck` → `npm test` → `npm run build`. Testler kendi `embedded-postgres` kümelerini başlatır (`--locale=C`); harici PostgreSQL hizmeti yoktur, ağ koruması (`tests/setup/networkGuard.ts`) CI'da da etkindir. |
| `.github/workflows/oss-risk-example.yml` | `ubuntu-latest` | Kendi repoların için örnek kalite kapısı: `postgres:17` servis kapsayıcısı → `npm ci` → `npm run build` → `npm run db:migrate` → `npm start` (arka planda, `HOST=127.0.0.1`, `PORT=3001`, log `$RUNNER_TEMP/server.log`'a) → `/health` en fazla 60 sn beklenir → `bootstrap --new-database` → `scan --fail-on critical` → sunucu logunun son 200 satırı (her durumda). |

Örnekteki CLI çağrıları:

```bash
node dist/cli/index.js bootstrap --new-database --key-file "$RUNNER_TEMP/oss-risk.key" \
  --project-name oss-risk-self --project-path "$RUNNER_TEMP/oss-risk-target"
OSS_RISK_API_KEY_FILE="$RUNNER_TEMP/oss-risk.key" node dist/cli/index.js scan \
  --project oss-risk-self --fail-on critical
```

**CI neden Linux'ta (D-202).** Yerel geliştirme Windows'ta sürer; ancak GitHub'ın
`windows-latest` çalıştırıcısı yönetici hesabıyla çalışır ve `embedded-postgres` orada
"Execution of PostgreSQL by a user with administrative permissions is not permitted" hatasıyla
açılmaz. `ubuntu-latest` çalıştırıcısının kullanıcısı root değildir; bu yüzden `ci.yml` Linux'ta
koşar (örnek iş akışı da aynı commit'te Linux'ta uçtan uca geçmiştir).

**Tetikleyiciler ve güvenlik.** Her iki iş akışı `push` (tüm branch'ler), `pull_request` (branch
süzgeci yok; yığılı PR'larda da çalışır) ve `workflow_dispatch` ile tetiklenir; aynı ref'teki eski
çalıştırma `concurrency` ile iptal edilir. İzinler iş akışı düzeyinde yalnız `contents: read`'dir;
hiçbir GitHub secret'ı gerekmez. Yalnız GitHub'ın birinci taraf `actions/checkout` ve
`actions/setup-node` eylemleri kullanılır, her biri tam 40 karakterlik commit SHA'sına sabitlidir
(yanında sürüm yorumu); `actions/checkout` `persist-credentials: false` ile çalışır. Ayrıcalıklı PR
tetikleyicisi (`pull_request_target`) yoktur. İş akışı girdileri betiklere yalnız `env:` üzerinden
aktarılır. Eylemleri güncellerken yeni SHA'yı etiketten doğrulayın:
`git ls-remote https://github.com/actions/checkout refs/tags/<etiket>` (açıklamalı etikette `^{}`
satırındaki commit).

**Test parolası.** Örnekteki `POSTGRES_PASSWORD`/`PGPASSWORD` değeri (`example-ci-test-only`)
gerçek bir sır değildir: yalnız iş süresince yaşayan, yalnız çalıştırıcıdan erişilen ve iş bitince
silinen geçici kapsayıcıya aittir. Gerçek bir veritabanı parolasını iş akışı dosyasına yazmayın.
`postgres:17` sabit majör etikettir; daha sıkı tedarik zinciri denetimi için imajı digest ile
sabitleyebilirsiniz (`postgres:17@sha256:…`).

**Tarama hedefi.** Bu repoda örnek yalnız kök `package.json` + `package-lock.json` kopyasını
(`$RUNNER_TEMP/oss-risk-target`) tarar; `tests/fixtures` altındaki bilerek riskli manifestler
taranmaz.

**Kendi reponuza uyarlama.**

1. Platformu ve kendi kodunuzu çekin: ikinci bir `actions/checkout` adımıyla (`repository:
   <sahip>/<oss-risk-reposu>`, `path: oss-risk`, `persist-credentials: false`) platformu alt
   klasöre çekin; `npm ci`, `npm run build`, `npm run db:migrate`, `npm start` ve
   `node dist/cli/index.js …` adımlarını `working-directory: oss-risk` ile çalıştırın.
2. "Prepare scan target" kopyalama adımını silin; `SCAN_ROOTS` ve `--project-path` değerini
   `$GITHUB_WORKSPACE`'e (veya taranacak repoyu ayrı bir `actions/checkout` ile çektiğiniz
   klasöre) verin.
3. **Eşik:** örnek `--fail-on critical` ile yalnız kritik bulguda kırmızı olur. Kapıyı
   sıkılaştırmak için `--fail-on high` kullanın (CLI varsayılanı); çıkış kodları ve
   `--fail-on` eşlemesi için yukarıdaki CLI bölümüne bakın.

**Ağ kipi ve gizlilik.** `push` ve `pull_request` çalıştırmaları çevrimdışıdır:
`REGISTRY_ENRICHMENT=off`, `VULNERABILITY_LOOKUP=off`, `VULNERABILITY_RECHECK=off`. CLI `disabled`
uyarısını yazar, çıkış kodu etkilenmez; sonuç dış hizmet kesintisine veya günlük yeni CVE'lere
bağlı değildir. GitHub arayüzünde **Actions → oss-risk example → Run workflow** ile `online`
girdisi işaretlenerek elle başlatılan çalıştırmada kayıt defteri zenginleştirmesi ve OSV/NVD
güvenlik açığı sorgusu açılır; bu durumda **paket adları ve sürümleri** `registry.npmjs.org`,
`pypi.org`, `files.pythonhosted.org`, `api.nuget.org`, `api.deps.dev`, `pub.dev` ve `api.osv.dev`'e, CVE kimlikleri
`services.nvd.nist.gov`'a gider (yukarıdaki "Dışarı giden bağlantıların tam listesi"). `online`
kipte `--allow-incomplete` verilmez: güvenlik açığı verisi `partial`/`unavailable` ise iş 5 ile
kırmızı biter. `workflow_dispatch` düğmesi yalnız iş akışı dosyası varsayılan branch'te
(`main`) olduğunda görünür.

**İlk Linux çalıştırması.** Uygulama şimdiye dek Windows'ta geliştirildi; örnek iş akışı onu
ilk kez Linux'ta çalıştırır. Kırmızı biterse önce "Server log (last 200 lines)" adımına bakın.

_Agentic Development Orchestrator ile oluşturuldu._
