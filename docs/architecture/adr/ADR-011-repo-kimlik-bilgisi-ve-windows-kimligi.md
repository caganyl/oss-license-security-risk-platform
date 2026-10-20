# ADR-011: Repo erişim anahtarı ve Windows kimliğiyle klon

- **Durum:** Kabul edildi (REQ-009, 2026-10-20)
- **İlgili:** ADR-002 (Docker'sız tarama çalışma alanı, Ek E1 yalıtılmış git
  ortamı), REQ-002 N-1, REQ-009 P-29/P-30/P-31

## Bağlam

ADR-002 klon sürecini kullanıcının git ayarlarından ve kimlik deposundan
yalıtır: `GIT_CONFIG_NOSYSTEM=1`, boş `GIT_CONFIG_GLOBAL`, yalıtılmış `HOME`,
`GIT_TERMINAL_PROMPT=0`, izin listeli ortam. Tek kimlik kaynağı
`integrations.access_token_enc`'dir ve host kapsamlı
`http.<origin>.extraHeader` olarak verilir. Ancak bu kaydı oluşturan bir yol
yoktur; şirket içi Azure DevOps Server (TFS) repoları bu yüzden hiç
taranamaz. Kullanıcı iki yolu birden istedi: PAT ve Windows oturum kimliği.

## Karar

1. **PAT (varsayılan yol).** Proje başına tek etkin `integrations` kaydı,
   `PUT /api/projects/{id}/repo-credential` ile yönetilir (silme uç noktası
   yok; kullanıcı kararı). Token
   AES-256-GCM ile şifrelenir (ADR-002 karar 6 düzeni), hiçbir yanıtta dönmez.
   Tarama oluşturulurken projenin `repo_url`'ine birebir eşit `repo_url`'li
   etkin entegrasyon taramaya bağlanır. Basic kullanıcı adı: Azure DevOps
   (bulut, `*.visualstudio.com` ve yolunda `/_git/` geçen her adres) için boş
   dize, GitLab için `oauth2`, diğerleri için `x-access-token`.
2. **Windows kimliği (açıkça açılan istisna).** `GIT_WINDOWS_AUTH_HOSTS` tam
   host adı listesidir. Klon hostu listedeyse ve token yoksa, yalnız o origin
   için iki ayar eklenir:
   - `http.<origin>.emptyAuth=true`: libcurl, Negotiate/NTLM ile oturum
     açmış Windows kullanıcısının kimliğini (SSPI) kullanır; parola
     saklanmaz, istenmez.
   - `credential.<origin>.helper=manager`: Git Credential Manager,
     kullanıcının Windows Credential Manager'daki kayıtlı bilgisini
     etkileşimsiz (`GCM_INTERACTIVE=never`) okur.

   GCM'nin çalışabilmesi için bu durumda `USERPROFILE`, `APPDATA`,
   `LOCALAPPDATA`, `USERNAME`, `USERDOMAIN` ortam değişkenleri geçirilir.
   Diğer yalıtım ayarlarının hiçbiri gevşetilmez: sistem/genel git ayarı,
   kancalar, `GIT_*` değişkenleri yine okunmaz. Ayarlar origin kapsamlı
   olduğundan başka bir hosta (ör. alt modül veya yönlendirme) kimlik
   gönderilmez.
3. **Varsayılan dal.** Ref belirtilmeyen tarama `--branch` olmadan klonlar.
4. **Hata sınıflandırması.** Klon katmanı temizlenmiş stderr'i sınıflandırır
   (kimlik, dal, repo, sertifika, bağlantı) ve yol gösteren bir cümle ekler;
   kimlik/dal/repo/sertifika kalıcıdır.

## Sonuçlar

- (+) Özel repolar taranabilir; kullanıcı şirket ağındaki TFS'i ya PAT ile ya
  da ek bir şey girmeden Windows kimliğiyle kullanabilir.
- (+) Varsayılan davranış değişmez: liste boşsa ve token yoksa ortam ADR-002
  ile birebir aynıdır.
- (−) Windows kimliği modu, listelenen hostlara kullanıcının kimliğini sunar.
  Bu, yöneticinin bilinçli seçimidir; joker kabul edilmez.
- (−) GCM'nin davranışı Git for Windows sürümüne bağlıdır; doğrulama
  kullanıcının makinesinde elle yapılır.
- (−) Sunucu 401 dönerse git `credential reject` çağırır; GCM kullanıcının
  Windows Credential Manager'daki o host kaydını silebilir (güvenlik
  incelemesi L1). Kimlik sızmaz ama kullanıcı TFS bilgisini yeniden girmek
  zorunda kalabilir. PAT yolu bu riski taşımaz.
- (−) GCM `GCM_INTERACTIVE=never`'ı yok sayarsa klon en fazla
  `SCAN_CLONE_TIMEOUT_MS` kadar bekler ve süreç ağacı sonlandırılır (L2).

## Ek (güvenlik incelemesi, 2026-10-20)

- **M1 düzeltildi:** Windows kimliği yalnız listedeki hostun varsayılan
  (443) portuna verilir; aynı hostta standart dışı porttaki bir servis
  kimlik almaz.
- **L3:** IDN host adları listeye punycode (`xn--…`) biçiminde yazılır.

## Değerlendirilen alternatifler

- **Yalıtımı tümden kaldırmak (kullanıcının git ayarlarını kullanmak):**
  N-1 kararını geri alır; kancalar ve genel ayarlar klona sızar. Reddedildi.
- **Token'ı URL'ye gömmek:** log ve `.git/config`'e sızma riski. Reddedildi
  (ADR-002 karar 3).
- **Ayrı entegrasyon CRUD ekranı:** tek kullanıcılı araç için gereksiz
  karmaşıklık; proje başına tekil kaynak yeterli.
