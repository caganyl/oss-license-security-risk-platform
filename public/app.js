'use strict';

// ════════════════════════════════════════════════════════════════════
// Page script (REQ-002 P-02, D-17 / AC-P02-6). Served as /app.js so the
// page runs under `script-src 'self'` with no inline <script>. Loaded with
// `defer` after /vendor/lucide-1.48.0.min.js, so the DOM is parsed when it runs.
//
// Safe rendering (REQ-002 P-02). Data returned by the API reaches the DOM
// only as text nodes (textContent / createTextNode) or as attribute values
// set through setAttribute/dataset. No HTML string is ever built from API
// data, so no escaping helper is needed; inline on* handlers are not used.
// ════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════
// User-visible texts (REQ-010 P-33, D-271): every string the page shows is
// kept in this one dictionary. Turkish only; no multi-language machinery.
// Parameterised texts are small functions; their arguments are rendered as
// text by el()/textContent like any other value.
// ════════════════════════════════════════════════════════════════════
const TEXT = {
  product: 'OSS Risk Platformu',
  locale: 'tr-TR',
  common: {
    dash: '—',
    unexpected: 'Beklenmeyen bir hata oluştu.',
    unknownError: 'bilinmeyen hata',
    requestFailed: (status) => `İstek başarısız oldu (HTTP ${status}).`,
    retryAfter: (seconds) => ` ${seconds} saniye sonra tekrar deneyin.`,
    network: 'Sunucuya ulaşılamadı. Bağlantınızı kontrol edip tekrar deneyin.',
    unexpectedResponse: 'Sunucudan beklenmeyen bir yanıt geldi.',
    defaultBranch: 'varsayılan dal',
  },
  health: {
    ok: 'Veritabanı bağlı',
    dbError: 'Veritabanı hatası',
    offline: 'Sunucuya ulaşılamıyor',
  },
  time: {
    justNow: 'az önce',
    minutes: (n) => `${n} dk önce`,
    hours: (n) => `${n} saat önce`,
    days: (n) => `${n} gün önce`,
  },
  bytes: ['bayt', 'KB', 'MB'],
  status: {
    pending: 'Bekliyor',
    queued: 'Sırada',
    running: 'Taranıyor',
    completed: 'Tamamlandı',
    failed: 'Başarısız',
    cancelled: 'İptal',
    timeout: 'Zaman aşımı',
  },
  severity: { critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', info: 'Bilgi', none: 'Yok' },
  licenseRisk: { critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', safe: 'Güvenli', unknown: 'Bilinmiyor' },
  findingStatus: {
    open: 'Açık',
    in_review: 'İncelemede',
    resolved: 'Çözüldü',
    accepted: 'Risk kabul edildi',
    false_positive: 'Hatalı tespit',
    wont_fix: 'Düzeltilmeyecek',
  },
  findingType: { security: 'Güvenlik açığı', license: 'Lisans', copyright: 'Telif' },
  trigger: {
    manual: 'Elle',
    scheduled: 'Zamanlanmış',
    pre_release: 'Sürüm öncesi',
    pull_request: 'Pull request',
    file_upload: 'Dosya yükleme',
  },
  ecosystem: {
    nodejs: 'Node.js', python: 'Python', java: 'Java', dotnet: '.NET', go: 'Go', php: 'PHP', ruby: 'Ruby', container: 'Konteyner', other: 'Diğer',
  },
  role: {
    admin: 'Yönetici',
    security_analyst: 'Güvenlik analisti',
    legal_reviewer: 'Hukuk inceleyici',
    developer: 'Geliştirici',
    manager: 'Yönetici (iş birimi)',
  },
  userStatus: { active: 'Etkin', inactive: 'Pasif', pending: 'Onay bekliyor' },

  // AC-P33-4 (D-272): API messages stay English; the page shows these texts by `code`.
  errors: {
    unauthenticated: 'Oturumunuz yok veya sona erdi. Lütfen yeniden giriş yapın.',
    invalid_credentials: 'Parola hatalı. Kontrol edip tekrar deneyin.',
    invalid_password: 'Parola kurallara uymuyor. En az 12 karakterlik, tahmin edilmesi zor bir parola seçin.',
    forbidden: 'Bu işlem için yetkiniz yok. Gerekirse yöneticinizden yetki isteyin.',
    not_found: 'Kayıt bulunamadı; silinmiş olabilir. Sayfayı yenileyip tekrar deneyin.',
    path_not_allowed: 'Bu yerel klasör taranamaz: klasör, sunucuda SCAN_ROOTS ayarıyla izin verilen bir kökün altında olmalı. Yöneticinizden klasörü eklemesini isteyin veya https repo adresi girin.',
    repo_url_not_allowed: 'Bu repo adresi kabul edilmedi. Yalnız https:// ile başlayan, kullanıcı adı veya parola içermeyen bir repo adresi girin (Azure DevOps / TFS, GitHub, GitLab).',
    project_source_missing: 'Projede taranacak kod konumu yok. Projeye bir yerel klasör veya https repo adresi ekleyin.',
    web_url_invalid: 'Web adresi geçersiz. http:// veya https:// ile başlayan, kullanıcı bilgisi ve # içermeyen tam bir adres girin.',
    web_url_not_allowed: 'Bu web adresi taranamaz: sunucu WEB_SCAN_ALLOWED_HOSTS listesinde değil. Yöneticinizden eklemesini isteyin (Sistem Durumu ekranına bakın).',
    project_web_url_missing: 'Projede web adresi tanımlı değil. Projeler ekranındaki “Web adresi” düğmesiyle ekleyin.',
    invalid_token: 'Token geçersiz: boşluk içermemeli ve en fazla 1024 karakter olmalı. Token’ı yeniden kopyalayıp yapıştırın.',
    repo_credential_not_applicable: 'Token yalnız https:// ile başlayan repo adresleri için kaydedilebilir.',
    too_many_attempts: 'Çok fazla deneme yapıldı. Biraz bekleyip tekrar deneyin.',
    payload_too_large: 'Gönderilen veri çok büyük. Daha kısa bir değerle tekrar deneyin.',
    export_busy: 'Sunucu şu anda başka raporlar hazırlıyor. Birkaç saniye sonra tekrar deneyin.',
    origin_rejected: 'İstek güvenlik nedeniyle reddedildi. Sayfayı sunucunun kendi adresinden açıp tekrar deneyin.',
    host_rejected: 'İstek güvenlik nedeniyle reddedildi. Sayfayı sunucunun kendi adresinden açıp tekrar deneyin.',
    internal_error: 'Sunucuda beklenmeyen bir hata oluştu. Tekrar deneyin; sürerse yöneticinizden sunucu kayıtlarını kontrol etmesini isteyin.',
  },

  // AC-P33-5 (D-283): REQ-009 contract section 5 class sentences -> Turkish headline.
  cloneErrors: [
    ['Repository requires authentication: add a repo access token to the project, or list the host in GIT_WINDOWS_AUTH_HOSTS.',
      'Repo giriş istiyor: projeye bir repo erişim anahtarı (PAT) ekleyin veya yöneticinizden sunucuyu GIT_WINDOWS_AUTH_HOSTS listesine eklemesini isteyin.'],
    ['Branch not found in the repository.', 'İstenen dal (branch) repoda bulunamadı.'],
    ['Repository not found or no access.', 'Repo bulunamadı veya erişim izni yok. Adresi ve token’ın Code → Read yetkisini kontrol edin.'],
    ['TLS certificate of the git server is not trusted.', 'Git sunucusunun TLS sertifikasına güvenilmiyor. Yöneticiniz kurumun kök sertifikasını sunucuya tanıtmalı.'],
    ['Git server could not be reached.', 'Git sunucusuna ulaşılamadı. Ağ/VPN bağlantısını kontrol edip taramayı yeniden başlatın.'],
  ],

  auth: {
    checking: 'Oturum kontrol ediliyor...',
    setupTitle: 'Yönetici parolasını belirleyin',
    loginTitle: 'Giriş yap',
    setupIntro: 'Bu kurulum için henüz parola belirlenmemiş. Kurulumu tamamlamak için bir parola seçin; ardından otomatik olarak giriş yapılır.',
    loginIntro: 'Devam etmek için parolanızı girin.',
    newPassword: 'Yeni parola',
    passwordLabel: 'Parola',
    confirmPassword: 'Parolayı tekrar girin',
    passwordHint: (min) => `En az ${min} karakter. Sunucu da ayrıca doğrular.`,
    tooShort: (min) => `Parola en az ${min} karakter olmalı.`,
    tooLong: (max) => `Parola en fazla ${max} karakter olabilir.`,
    mismatch: 'Parolalar eşleşmiyor.',
    required: 'Parola gerekli.',
    submitSetup: ' Parolayı kaydet ve devam et',
    submitLogin: ' Giriş yap',
    alreadySet: 'Parola zaten belirlenmiş. Lütfen giriş yapın.',
    notSetYet: 'Henüz parola belirlenmemiş. Devam etmek için bir parola oluşturun.',
    sessionEnded: 'Oturumunuz sona erdi. Lütfen yeniden giriş yapın.',
    signedOut: 'Bu tarayıcı oturumundan çıkış yaptınız.',
    alreadyEnded: 'Oturumunuz zaten sona ermişti. Lütfen yeniden giriş yapın.',
    logoutFailed: 'Çıkış yapılamadı',
    verifyFailed: (msg) => `Oturum doğrulanamadı: ${msg}`,
    signedIn: 'Giriş yapıldı',
    requestFailed: 'İstek başarısız oldu',
  },

  views: {
    dashboard: { title: 'Genel Bakış', subtitle: 'Tüm projelerinizin lisans ve güvenlik durumunu tek bakışta gösterir; sayılar her projenin en son tamamlanmış bağımlılık taramasından hesaplanır.' },
    scans: { title: 'Tarama Geçmişi', subtitle: 'Başlatılan taramaları (en yeni 50) durumları, sonuçları ve raporlarıyla birlikte listeler.' },
    findings: { title: 'Güvenlik ve Lisans Bulguları', subtitle: 'Seçtiğiniz taramada bulunan güvenlik açıklarını ve lisans risklerini, düzeltme bilgisiyle birlikte gösterir.' },
    projects: { title: 'Projeler', subtitle: 'Taranan kod tabanlarını ve web adreslerini yönetir; buradan tarama başlatabilir, repo erişim anahtarı ekleyebilirsiniz.' },
    sbom: { title: 'SBOM Merkezi', subtitle: 'Bir taramanın yazılım malzeme listesini (SBOM) müşteri ve denetimler için standart biçimlerde üretip indirmenizi sağlar.' },
    users: { title: 'Kullanıcılar ve Roller', subtitle: 'Platforma erişebilen kullanıcıları ve rollerini (yetkilerini) gösterir.' },
    'api-keys': { title: 'API Anahtarları', subtitle: 'oss-risk komut satırı aracı ve CI hatları için kişisel API anahtarınızı oluşturur veya iptal eder.' },
    system: { title: 'Sistem Durumu', subtitle: 'Hangi özelliklerin açık veya kapalı olduğunu ve kapalı olanların nasıl açılacağını gösterir.' },
    help: { title: 'Yardım', subtitle: 'Platformun nasıl kullanılacağını adım adım anlatır ve ekranlarda geçen terimleri açıklar.' },
  },

  scans: {
    lastUpdated: (time) => `Son güncelleme: ${time}`,
    kindWeb: 'Web',
    kindWebTitle: 'Web (URL) taraması',
    grade: (g) => `Güvenlik notu ${g}`,
    clean: '✓ Temiz',
    unchecked: 'Kontrol edilemedi',
    uncheckedHint: 'Güvenlik açığı kaynağına (OSV) ulaşılamadı veya sorgu kapalı; paketler kontrol edilmedi. Sistem Durumu ekranına ve proxy/sertifika ayarlarına bakın, sonra yeniden tarayın.',
    partial: 'Kısmen kontrol edildi',
    partialHint: 'Bazı paketler kontrol edilemedi; sonuç eksik olabilir. Yeniden taramayı deneyin.',
    critical: (n) => `${n} Kritik`,
    high: (n) => `${n} Yüksek`,
    medLow: (n) => `${n} Orta/Düşük`,
    licenseOk: 'Sorun yok',
    licenseAlerts: (n) => `${n} uyarı`,
    warnings: (n) => `${n} uyarı`,
    noPackages: 'Paket bulunamadı',
    noPackagesHint: 'Olası nedenler: yanlış klasör veya repo seçildi; seçilen ekosistem projeyi kapsamıyor (boş bırakmak tümünü algılar); projede kilit/manifest dosyası yok (ör. package-lock.json, packages.lock.json veya *.csproj, requirements.txt).',
    historyEmpty: 'Henüz tarama yok. Genel Bakış ekranındaki “Yeni proje taraması” düğmesiyle veya Projeler ekranındaki “Şimdi tara” düğmesiyle bir tarama başlatın.',
    historyFailed: 'Tarama geçmişi yüklenemedi',
    notFound: 'Tarama bulunamadı',
    completedToast: (name) => `"${name}" taraması tamamlandı.`,
    failedToast: (name) => `"${name}" taraması başarısız oldu.`,
    scheduling: (name) => `"${name}" için tarama planlanıyor...`,
    schedulingWeb: (name) => `"${name}" için web taraması planlanıyor...`,
    queued: 'Tarama kuyruğa alındı.',
    webQueued: 'Web taraması kuyruğa alındı.',
    triggerFailed: 'Tarama başlatılamadı',
    webTriggerFailed: 'Web taraması başlatılamadı',
  },

  // P-38: one "Raporlar" menu per completed scan row; descriptions are one sentence each.
  reports: {
    button: ' Raporlar',
    menuLabel: 'Raporlar',
    pdf: ['Yönetici raporu (PDF)', 'Genel durum, risk özeti ve “Ne yapılmalı?” listesi; yöneticilerle paylaşmak için.'],
    excel: ['Ayrıntılı tablo (Excel)', 'Tüm paketler, lisanslar ve bulgular; filtreleyip ayrıntılı incelemek için.'],
    csv: ['Paket listesi (CSV)', 'Paket ve lisans listesi; başka araçlara aktarmak için düz metin.'],
    notice: ['Lisans bildirimi (NOTICE)', 'Lisans ve telif bildirimleri; ürünle birlikte dağıtmak için.'],
    sbom: ['SBOM', 'Müşteri ve denetimler için makine okunur yazılım malzeme listesi (CycloneDX JSON).'],
    webPdf: ['Web güvenlik raporu (PDF)', 'Güvenlik notu, bulgular ve öneriler; yöneticilerle paylaşmak için.'],
    webCsv: ['Bulgu listesi (CSV)', 'Tüm web bulguları; takip etmek veya başka araçlara aktarmak için.'],
  },

  stats: { unavailable: '—' },

  vuln: {
    runLabels: {
      completed: 'Tamamlandı',
      partial: 'Kısmi',
      failed: 'Başarısız',
      interrupted: 'Yarıda kesildi',
      disabled: 'Atlandı (sorgu kapalı)',
    },
    projectStatus: {
      partial: 'güvenlik açığı verisi kısmi',
      unavailable: 'güvenlik açığı verisine ulaşılamadı',
      disabled: 'güvenlik açığı sorgusu kapalı',
    },
    notChecked: 'henüz kontrol edilmedi',
    rowRecheck: 'Günlük yeniden kontrol',
    rowLastRun: 'Son yeniden kontrol',
    rowNewFindings: 'Yeni bulgular (son kontrol)',
    rowUnchecked: 'Kontrol edilemeyen paketler (son kontrol)',
    rowNext: 'Sonraki kontrol',
    rowReopened: 'Yeniden açılan risk kabulleri (son 7 gün)',
    rowExpiry: 'Son süre dolumu kontrolü',
    recheckOff: 'Kapalı (VULNERABILITY_RECHECK=off)',
    lookupOff: 'Kapalı (VULNERABILITY_LOOKUP=off)',
    every: (h) => `Her ${h} saatte bir`,
    runningSince: (t) => `Sürüyor (başlangıç: ${t})`,
    neverRun: 'Henüz çalışmadı',
    paused: 'Duraklatıldı',
    dueNow: 'Şimdi bekleniyor',
    notEvaluated: 'Henüz yapılmadı',
    allComplete: 'Tüm projelerin güvenlik açığı verisi tam.',
    incomplete: (n) => `Güvenlik açığı verisi eksik projeler (${n})`,
    truncated: 'İlk 500 proje gösteriliyor.',
    loading: 'Güvenlik açığı verisi durumu yükleniyor...',
    loadFailed: 'Güvenlik açığı verisi durumu alınamadı.',
  },

  projects: {
    empty: 'Henüz proje yok. Yukarıdaki “Proje ekle” düğmesiyle ilk projenizi ekleyin.',
    loadFailed: 'Projeler yüklenemedi',
    scanNow: ' Şimdi tara',
    webScan: ' Web taraması',
    webUrl: ' Web adresi',
    webUrlAria: 'Web adresini düzenle',
    tokenSet: ' Token tanımlı',
    tokenAdd: ' Token ekle',
    tokenSetTitle: 'Bu repo için bir erişim anahtarı (PAT) tanımlı; değiştirmek için yenisini kaydedin.',
    tokenAddTitle: 'Özel (giriş isteyen) bir repo için erişim anahtarı (PAT) ekleyin.',
    activeMode: 'aktif',
    activeModeTitle: 'Aktif web taraması (OWASP ZAP ile gerçek saldırı istekleri)',
    subtitle: (name) => `Proje: ${name}`,
    tokenSubtitle: (name, repo) => `Proje: ${name} · ${repo}`,
    tokenStateSet: 'Bu repo için zaten bir token tanımlı.',
    tokenStateNone: 'Henüz token tanımlı değil.',
    enterToken: 'Bir token girin',
    tokenSaved: 'Repo erişim anahtarı kaydedildi. Kullanmak için taramayı başlatın.',
    tokenSaveFailed: 'Token kaydedilemedi',
    webSaved: 'Web hedefi kaydedildi.',
    webSaveFailed: 'Web adresi kaydedilemedi',
  },

  modal: {
    nameRequired: 'Proje adı gerekli',
    sourceRequired: 'Bir repo yolu, bir web adresi veya ikisini birden girin',
    creating: 'Oluşturuluyor...',
    launch: 'Taramayı başlat',
    launchFailed: 'Proje oluşturulamadı',
    tokenNotSaved: (name, reason) => `"${name}" projesi oluşturuldu ancak token kaydedilemedi${reason}. Projeler ekranındaki token düğmesiyle ekleyip taramayı başlatın.`,
    queued: (name) => `"${name}" için tarama kuyruğa alındı. Sonuçlar kısa süre içinde görünecek.`,
    // AC-P35-3: shown only when /api/system/features says the feature is off.
    localScanOff: 'Yerel klasör taraması şu anda kapalı (sunucuda SCAN_ROOTS boş); yalnız https repo adresi girebilirsiniz. Açmak için yöneticiniz .env dosyasındaki SCAN_ROOTS ayarına izinli klasörleri yazıp uygulamayı yeniden başlatmalı.',
    webScanOff: 'Web taraması şu anda kapalı (sunucuda WEB_SCAN_ALLOWED_HOSTS boş); girilen adres taranamaz. Açmak için yöneticiniz .env dosyasındaki WEB_SCAN_ALLOWED_HOSTS ayarına kendi/şirket sunucularını yazıp uygulamayı yeniden başlatmalı.',
    repoTokensOff: 'Token kaydı şu anda kapalı: sunucuda ENCRYPTION_KEY tanımlı değil, girilen token kaydedilemez. Açmak için yöneticiniz .env dosyasına ENCRYPTION_KEY ekleyip uygulamayı yeniden başlatmalı.',
  },

  findings: {
    loadingScans: 'Tamamlanmış taramalar yükleniyor...',
    noCompleted: 'Tamamlanmış tarama yok',
    fetchFailed: 'Taramalar alınamadı',
    webOption: (project, host, date) => `${project} - Web ${host} (${date})`,
    depOption: (project, ref, date) => `${project} - ${ref} (${date})`,
    cvss: (score) => `CVSS ${score}`,
    licenseAlert: 'Lisans uyarısı',
    risk: (level) => `Risk: ${level}`,
    licenseDescription: (pkg, license, policy) => `"${pkg}" paketi "${license}" lisansını kullanıyor; bu lisans etkin politika ("${policy}") kapsamında risk oluşturuyor. Hukuk birimiyle değerlendirin.`,
    defaultPolicy: 'Varsayılan yasaklı lisans listesi',
    unknownRisk: 'Bilinmeyen politika riski',
    package: 'Paket: ',
    type: 'Tür: ',
    status: 'Durum: ',
    purl: 'PURL: ',
    fixedIn: 'Düzeltildiği sürüm: ',
    noScanTitle: 'Tarama seçilmedi',
    noScanHint: 'Bulgularını görmek için yukarıdan tamamlanmış bir tarama seçin. Liste boşsa önce Projeler ekranından bir tarama başlatın.',
    cleanTitle: 'Bulgu yok',
    cleanHint: 'Bu taramada güvenlik açığı veya lisans riski bulunmadı.',
    loadFailed: 'Bulgular yüklenemedi',
    webLoadFailed: 'Web bulguları yüklenemedi',
  },

  web: {
    engines: {
      complete: 'tamamlandı',
      partial: 'kısmi',
      not_configured: 'tanımlı değil',
      unavailable: 'ulaşılamadı',
      failed: 'başarısız',
      disabled: 'kapalı',
      not_needed: 'gerekmedi',
    },
    engineLine: (builtin, zap, active, lookup, requests) =>
      `Yerleşik kontroller: ${builtin} · OWASP ZAP: ${zap}${active ? ' (aktif)' : ''} · Kütüphane açık sorgusu: ${lookup} · İstek sayısı: ${requests}`,
    gradeAria: (g) => `Güvenlik notu ${g}`,
    heading: (g, score) => `Güvenlik notu ${g} · ${score}/100`,
    target: (t) => `Hedef: ${t}`,
    location: 'Konum: ',
    source: 'Kaynak: ',
    sourceZap: 'OWASP ZAP',
    sourceBuiltin: 'Yerleşik',
    component: 'Bileşen: ',
    evidence: (e) => `Kanıt: ${e}`,
    recommendation: (r) => `Öneri: ${r}`,
    noFindingsTitle: 'Web bulgusu yok',
    noFindingsHint: 'Bu hedef için çalışan kontroller bir sorun bulmadı.',
    components: 'Tespit edilen JavaScript kütüphaneleri',
  },

  sbom: {
    download: ' İndir',
    generating: 'Üretiliyor...',
    generate: 'Belge üret',
    generated: 'SBOM belgesi üretildi.',
    generateFailed: 'SBOM üretilemedi',
    loadFailed: 'SBOM belgeleri yüklenemedi',
    preparing: 'CycloneDX JSON SBOM hazırlanıyor...',
    downloaded: 'SBOM indirildi.',
    downloadFailed: 'SBOM indirilemedi',
  },

  users: {
    empty: 'Henüz kullanıcı yok.',
    loadFailed: 'Kullanıcılar yüklenemedi',
  },

  apiKeys: {
    revoke: 'İptal et',
    revokeAria: (prefix) => `${prefix} API anahtarını iptal et`,
    never: 'Hiç kullanılmadı',
    active: 'Etkin',
    revoked: (date) => `İptal edildi ${date}`,
    loadFailed: 'API anahtarları yüklenemedi',
    fieldAria: 'Yeni API anahtarı',
    copy: ' Kopyala',
    done: 'Tamam',
    copied: 'Panoya kopyalandı',
    pressCtrlC: 'Kopyalamak için Ctrl+C’ye basın',
    copyNow: 'Bu anahtarı şimdi kopyalayın. Bir daha gösterilmeyecek.',
    confirmReplace: 'Yeni anahtar oluşturmak mevcut etkin anahtarı iptal eder. Devam edilsin mi?',
    notShown: 'Yeni bir API anahtarı oluşturuldu ancak sayfa değiştiği için gösterilmedi. Görmek için yeni bir anahtar oluşturun.',
    createFailed: 'API anahtarı oluşturulamadı',
    confirmRevoke: (prefix) => `${prefix} API anahtarı iptal edilsin mi? Bu anahtarı kullanan istemciler çalışmayı durduracak.`,
    revokedToast: 'API anahtarı iptal edildi',
    revokeFailed: 'API anahtarı iptal edilemedi',
  },

  // P-35: one entry per feature of docs/contracts/REQ-010-system-features.md.
  system: {
    on: 'Açık',
    off: 'Kapalı',
    unknown: 'Bilinmiyor',
    howTo: 'Nasıl açılır: ',
    loadFailedTitle: 'Sistem durumu alınamadı',
    loadFailedHint: 'Sunucuya ulaşılamadı veya bu bilgiyi görme yetkiniz (settings:read) yok. Sayfayı yenileyip tekrar deneyin; sürerse yöneticinize başvurun.',
    restartNote: 'Ayar değişikliklerinin geçerli olması için uygulama yeniden başlatılmalıdır.',
    features: [
      {
        key: 'local_scan',
        name: 'Yerel klasör taraması',
        description: 'Sunucunun erişebildiği bir klasördeki kodu tarar.',
        enable: '.env dosyasındaki SCAN_ROOTS ayarına izin verilen klasör köklerini yazın (Windows’ta ; ile ayrılır, ör. C:\\Projeler) ve uygulamayı yeniden başlatın.',
        count: ['roots', (n) => `İzinli klasör kökü: ${n}`],
      },
      {
        key: 'web_scan',
        name: 'Web (URL) güvenlik taraması',
        description: 'Çalışan bir web uygulamasını adresinden güvenli (pasif) kontrollerle tarar.',
        enable: '.env dosyasındaki WEB_SCAN_ALLOWED_HOSTS ayarına taranabilecek kendi/şirket sunucularınızı virgülle ayırarak yazın ve uygulamayı yeniden başlatın.',
        count: ['allowed_hosts', (n) => `İzinli sunucu girdisi: ${n}`],
      },
      {
        key: 'zap',
        name: 'OWASP ZAP (aktif web taraması)',
        description: 'Aktif modda gerçek saldırı simülasyonu yapan OWASP ZAP aracına bağlanır.',
        enable: '.env dosyasında ZAP_API_URL (gerekiyorsa ZAP_API_KEY) ayarını çalışan ZAP adresine göre tanımlayın ve uygulamayı yeniden başlatın.',
      },
      {
        key: 'registry_enrichment',
        name: 'Lisans bilgisi zenginleştirme',
        description: 'Eksik lisans ve telif bilgisini paket kayıt defterlerinden (npm, PyPI, NuGet) tamamlar.',
        enable: '.env dosyasında REGISTRY_ENRICHMENT=on yapın ve uygulamayı yeniden başlatın.',
      },
      {
        key: 'vulnerability_lookup',
        name: 'Güvenlik açığı sorgusu',
        description: 'Tarama sırasında paketleri OSV veritabanındaki bilinen açıklara karşı kontrol eder.',
        enable: '.env dosyasında VULNERABILITY_LOOKUP=on yapın ve uygulamayı yeniden başlatın.',
      },
      {
        key: 'vulnerability_recheck',
        name: 'Günlük yeniden kontrol',
        description: 'Taranmış projeleri, kodu yeniden indirmeden, yeni duyurulan açıklara karşı her gün yeniden kontrol eder.',
        enable: '.env dosyasında VULNERABILITY_RECHECK=on yapın ve uygulamayı yeniden başlatın.',
      },
      {
        key: 'nvd',
        name: 'NVD CVSS puanları',
        description: 'Açıkların önem puanını (CVSS) ABD NVD veritabanından tamamlar.',
        enable: '.env dosyasında NVD_ENABLED=true yapın ve uygulamayı yeniden başlatın.',
      },
      {
        key: 'repo_tokens',
        name: 'Repo erişim anahtarı (PAT) saklama',
        description: 'Özel repolar için girilen erişim anahtarlarını şifreli saklar.',
        enable: '.env dosyasında ENCRYPTION_KEY ayarına uzun, rastgele bir değer yazın ve uygulamayı yeniden başlatın.',
      },
      {
        key: 'windows_git_auth',
        name: 'Windows kimliğiyle git erişimi',
        description: 'Şirket içi TFS / Azure DevOps sunucusuna tokensız, sunucunun Windows oturumuyla bağlanır.',
        enable: '.env dosyasındaki GIT_WINDOWS_AUTH_HOSTS ayarına git sunucusunun tam adını yazın (ör. tfs.sirket.local) ve uygulamayı yeniden başlatın.',
        count: ['hosts', (n) => `Tanımlı sunucu: ${n}`],
      },
    ],
    nvdKeySet: 'NVD API anahtarı: tanımlı',
    nvdKeyMissing: 'NVD API anahtarı: tanımlı değil (isteğe bağlı; NVD_API_KEY tanımlanırsa sorgular hızlanır)',
  },

  // P-34 (AC-P34-3/4, D-281): glossary used for the Help view and the term tooltips.
  glossary: {
    sbom: ['SBOM', 'Yazılım malzeme listesi: bir üründe kullanılan tüm açık kaynak paketlerin, sürümlerinin ve lisanslarının makine tarafından okunabilir listesi. Müşteriler ve denetimler giderek daha sık ister.'],
    cyclonedx: ['CycloneDX', 'OWASP’ın geliştirdiği yaygın bir SBOM biçimi (JSON veya XML); güvenlik araçlarıyla paylaşım için uygundur.'],
    spdx: ['SPDX', 'Linux Foundation’ın SBOM standardı (ISO/IEC 5962); özellikle lisans uyumu ve hukuki süreçlerde tercih edilir.'],
    cve: ['CVE', 'Kamuya duyurulmuş bir güvenlik açığının standart kimliği (ör. CVE-2024-12345); aynı açığı farklı araçlarda aynı adla bulmanızı sağlar.'],
    cvss: ['CVSS', 'Bir güvenlik açığının ciddiyetini 0–10 arasında puanlayan standart: 9,0 ve üzeri Kritik, 7,0–8,9 Yüksek, 4,0–6,9 Orta, altı Düşük.'],
    purl: ['PURL', 'Paket adresi (package URL): bir paketi ekosistemi, adı ve sürümüyle tek satırda tanımlayan kimlik (ör. pkg:npm/lodash@4.17.21).'],
    license: ['Lisans riski / copyleft', 'Bir paketin lisansının ürününüzü dağıtmanızı ne kadar kısıtladığı. Copyleft lisanslar (ör. GPL) türetilen ürünün de aynı lisansla açık kaynak paylaşılmasını isteyebilir; hukuk birimiyle değerlendirilmelidir.'],
    dependency: ['Doğrudan / dolaylı bağımlılık', 'Doğrudan bağımlılık projenizin kendisinin eklediği pakettir; dolaylı (geçişli) bağımlılık o paketlerin kullandığı paketlerdir. Dolaylı paketlerdeki açıklar da ürününüzü etkiler.'],
    notice: ['NOTICE', 'Kullanılan açık kaynak paketlerin lisans ve telif bildirimlerini toplayan dosya; çoğu lisans ürünle birlikte dağıtılmasını şart koşar.'],
    owasp: ['OWASP', 'Web uygulaması güvenliği için açık standartlar yayımlayan vakıf. “OWASP Top 10” en yaygın web güvenlik risklerinin listesidir (ör. A05:2021 güvenlik yanlış yapılandırması).'],
    cwe: ['CWE', 'Yazılım zayıflık türlerinin kataloğu (ör. CWE-79 siteler arası betik çalıştırma); bir bulgunun hangi hata türünden kaynaklandığını gösterir.'],
    grade: ['Güvenlik notu (A–F)', 'Web taramasındaki bulguların önem ve sayısına göre hesaplanan 0–100 puanın harf karşılığı; A en iyi, F en kötü durumdur.'],
    webscan: ['Pasif / aktif web taraması', 'Pasif tarama yalnız okuma yapan güvenli kontrollerdir, canlı sistemde kullanılabilir. Aktif tarama OWASP ZAP ile gerçek saldırı istekleri gönderir; yalnız test ortamında kullanılmalıdır.'],
    pat: ['PAT', 'Kişisel erişim anahtarı (personal access token): özel bir repoya parola yerine kullanılan, yetkisi sınırlandırılabilen anahtar. Bu platform için yalnız Code → Read (okuma) yetkisi yeterlidir.'],
  },

  help: {
    stepsTitle: 'İlk adımlar',
    steps: [
      ['Proje ekleyin', 'Genel Bakış ekranındaki “Yeni proje taraması” veya Projeler ekranındaki “Proje ekle” düğmesiyle projenin adını, kod konumunu (yerel klasör veya https repo adresi) ve isterseniz web adresini girin. Özel repolar için bir PAT ekleyin.'],
      ['Taramayı başlatın', 'Proje oluşturulunca tarama otomatik olarak kuyruğa alınır; daha sonra Projeler ekranındaki “Şimdi tara” düğmesiyle yeniden tarayabilirsiniz. İlerleme Genel Bakış ekranında görünür.'],
      ['Sonuçları inceleyin', 'Bulgular ekranında taramayı seçin: güvenlik açıkları önem derecesine, lisans sorunları risk düzeyine göre listelenir; düzeltme sürümü biliniyorsa gösterilir.'],
      ['Rapor indirin', 'Tarama satırındaki “Raporlar” menüsünden yöneticiler için PDF, ayrıntılı Excel/CSV listeleri, NOTICE dosyası veya SBOM indirin.'],
    ],
    troubleTitle: 'Bir şey çalışmıyorsa',
    trouble: 'Sistem Durumu ekranı hangi özelliklerin kapalı olduğunu ve nasıl açılacağını gösterir. Başarısız bir taramanın nedeni tarama satırında yazar.',
    glossaryTitle: 'Sözlük',
  },
};

/** Text for `key` in a TEXT label map, or `fallback` (default: the raw value as text). */
function label(map, key, fallback) {
  if (map !== null && typeof map === 'object' && typeof key === 'string' && Object.prototype.hasOwnProperty.call(map, key)) return map[key];
  if (fallback !== undefined) return fallback;
  return key === null || key === undefined || key === '' ? TEXT.common.dash : String(key);
}

/** Tooltip text of a glossary term (AC-P34-3). */
function termTitle(key) {
  const entry = label(TEXT.glossary, key, null);
  return entry ? `${entry[0]}: ${entry[1]}` : undefined;
}

/** True for same-origin absolute paths and http(s) URLs; anything else (javascript:, data:, mailto:, //host) is refused. */
function isAllowedHref(value) {
  const s = String(value);
  if (s.startsWith('/') && !s.startsWith('//') && !s.startsWith('/\\')) return true;
  return safeExternalHref(s) !== null;
}

/** Returns a normalised http/https URL or null. */
function safeExternalHref(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

/** Builds an /api path; every dynamic segment is URL-encoded. */
function apiPath(...segments) {
  return '/api/' + segments.map((s) => encodeURIComponent(String(s))).join('/');
}

/**
 * Element builder. `props.text` and string children become text nodes.
 * `style` must only receive literal style strings from this file, never API data.
 */
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'className') node.className = value;
      else if (key === 'style') node.style.cssText = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'href') { if (isAllowedHref(value)) node.setAttribute('href', String(value)); }
      else node.setAttribute(key, value === true ? '' : String(value));
    }
  }
  return append(node, children);
}

function append(parent, children) {
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

function icon(name, style, className) {
  return el('i', { 'data-lucide': name, style, className });
}

function clear(node) {
  if (node) node.textContent = '';
  return node;
}

function byId(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const node = byId(id);
  if (node) node.textContent = String(text);
}

/** lucide is vendored (/vendor/lucide-1.48.0.min.js); the page must keep working if it is missing. */
function refreshIcons() {
  try {
    if (typeof lucide !== 'undefined' && lucide && typeof lucide.createIcons === 'function') lucide.createIcons();
  } catch {
    /* icons are decorative */
  }
}

function setButtonContent(button, iconName, text, spinning) {
  if (!button) return;
  clear(button);
  append(button, [icon(iconName, undefined, spinning ? 'spin' : undefined), ' ' + text]);
  refreshIcons();
}

function emptyState(iconName, title, hint, iconStyle) {
  return el('div', { className: 'empty-state' },
    icon(iconName, 'display:block; margin:0 auto 1rem;' + (iconStyle || '')),
    el('p', { text: title }),
    hint ? el('small', { text: hint }) : null);
}

function emptyRow(tbody, colspan, text) {
  tbody.appendChild(el('tr', null,
    el('td', { colspan, style: 'text-align:center; color:var(--text-muted);' }, text)));
}

function setPlaceholderOption(select, text) {
  clear(select);
  select.appendChild(el('option', { value: '' }, text));
}

// ════════════════════════════════════════════════════════════════════
// Error plumbing. Every async entry point (listener, timer, init) goes
// through fire() so no promise rejection is ever left unhandled.
// ════════════════════════════════════════════════════════════════════

function onUnexpectedError(err) {
  if (err && err.authRedirect) return;
  try {
    if (document && document.getElementById('toast-msg')) {
      showToast(err && err.message ? err.message : TEXT.common.unexpected, 'error');
    }
  } catch {
    /* page is being torn down */
  }
}

function fire(fn) {
  return function (...args) {
    try {
      const result = fn.apply(this, args);
      if (result && typeof result.then === 'function') result.catch(onUnexpectedError);
    } catch (err) {
      onUnexpectedError(err);
    }
  };
}

/** Central error display: ApiError messages are already the Turkish text for their `code` (see api()). */
function reportError(err, fallback) {
  if (err && err.authRedirect) return; // the auth form already explains what happened
  showToast(err && err.message ? err.message : fallback, 'error');
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
    this.authRedirect = false;
  }
}

/**
 * Message shown for an API error (AC-P33-4): a known `code` becomes its Turkish
 * text from TEXT.errors; an unknown code keeps the server message, which is
 * only ever rendered as text.
 */
function apiErrorMessage(status, code, serverMessage) {
  const known = label(TEXT.errors, code, null);
  if (known) return known;
  return serverMessage || TEXT.common.requestFailed(status);
}

/**
 * fetch wrapper. Session cookie is HttpOnly + SameSite=Strict: JS never
 * reads it, the browser sends it (credentials: 'same-origin').
 * Error bodies are {error, message, code}; we branch on `code`.
 * A 401 setup_required / unauthenticated switches to the matching form
 * unless `authRedirect: false` (login/setup/logout handle 401 themselves).
 */
async function api(path, options = {}) {
  const { method = 'GET', body, authRedirect = true } = options;
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    // Browser network errors carry English text ("Failed to fetch"); show ours instead.
    throw new ApiError(0, 'network_error', TEXT.common.network);
  }
  let payload = null;
  if (response.status !== 204) {
    try { payload = await response.json(); } catch { payload = null; }
  }
  if (!response.ok) {
    const code = payload && typeof payload.code === 'string' ? payload.code : '';
    const serverMessage = payload && typeof payload.message === 'string' ? payload.message : '';
    let message = apiErrorMessage(response.status, code, serverMessage);
    if (response.status === 429) {
      const retryAfter = Number.parseInt(response.headers.get('Retry-After') || '', 10);
      if (Number.isFinite(retryAfter) && retryAfter > 0) message += TEXT.common.retryAfter(retryAfter);
    }
    const err = new ApiError(response.status, code, message);
    if (response.status === 401 && authRedirect) {
      err.authRedirect = true;
      if (code === 'setup_required') showAuth('setup', '');
      else showAuth('login', currentUser ? TEXT.auth.sessionEnded : '');
    }
    throw err;
  }
  return payload || {};
}

// ── Global states
const pollingScans = new Map(); // scanId -> interval id
let currentActiveView = 'dashboard';
let currentUser = null;
let authMode = null; // 'login' | 'setup' | null
let toastTimer = null;

// ── Toast notifier (message always rendered as text)
function showToast(msg, type = 'success') {
  const t = byId('toast');
  const msgEl = byId('toast-msg');
  if (!t || !msgEl) return;
  const kind = type === 'error' ? 'error' : 'success';
  msgEl.textContent = String(msg ?? '');
  t.className = `show ${kind}`;
  const toastIcon = byId('toast-icon');
  if (toastIcon) toastIcon.setAttribute('data-lucide', kind === 'success' ? 'check-circle' : 'alert-circle');
  refreshIcons();
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 4500);
}

// ── Health checker
async function checkHealth() {
  const dot = byId('db-dot');
  try {
    const r = await fetch('/health', { credentials: 'same-origin' });
    const data = await r.json();
    if (data.status === 'healthy') {
      if (dot) {
        dot.style.background = 'var(--success)';
        dot.style.boxShadow = '0 0 6px var(--success)';
      }
      setText('db-status-text', TEXT.health.ok);
    } else {
      if (dot) dot.style.background = 'var(--danger)';
      setText('db-status-text', TEXT.health.dbError);
    }
  } catch {
    if (dot) dot.style.background = 'var(--danger)';
    setText('db-status-text', TEXT.health.offline);
  }
}

// ── Formatter helpers (AC-P33-3: tr-TR dates/numbers, Turkish relative time)
function timeAgo(iso) {
  if (!iso) return TEXT.common.dash;
  const diff = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(diff)) return TEXT.common.dash;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return TEXT.time.justNow;
  if (mins < 60) return TEXT.time.minutes(mins);
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return TEXT.time.hours(hrs);
  return TEXT.time.days(Math.floor(hrs / 24));
}

function formatNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString(TEXT.locale) : TEXT.common.dash;
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!n || !Number.isFinite(n)) return `0 ${TEXT.bytes[0]}`;
  const k = 1024;
  const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), TEXT.bytes.length - 1);
  return (n / Math.pow(k, i)).toLocaleString(TEXT.locale, { maximumFractionDigits: 2 }) + ' ' + TEXT.bytes[i];
}

function formatDate(value) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? TEXT.common.dash : d.toLocaleString(TEXT.locale);
}

/** Maps API severity / risk strings onto the fixed set of tag classes. */
function tagLevel(value) {
  const s = String(value || 'medium').toLowerCase();
  return ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : 'low';
}

/** Host of a web scan target for display (REQ-008); never a link. */
function webHost(value) {
  try {
    return new URL(String(value)).host;
  } catch {
    return TEXT.common.dash;
  }
}

/** URL without query string and fragment (they may carry tokens; never displayed). */
function webLocation(value) {
  try {
    const u = new URL(String(value));
    return `${u.origin}${u.pathname}`;
  } catch {
    return TEXT.common.dash;
  }
}

function isWebScan(row) {
  return row && row.scan_kind === 'web';
}

function securityLabel(row) {
  // REQ-010 r2: zero findings only means "clean" when the lookup actually ran.
  const data = row.vulnerability_data_status;
  if (!row.total_vulnerabilities && (data === 'unavailable' || data === 'disabled')) {
    return el('span', { style: 'color: var(--warning);', title: TEXT.scans.uncheckedHint }, TEXT.scans.unchecked);
  }
  if (!row.total_vulnerabilities && data === 'partial') {
    return el('span', { style: 'color: var(--warning);', title: TEXT.scans.partialHint }, TEXT.scans.partial);
  }
  if (!row.total_vulnerabilities) return el('span', { style: 'color: var(--success);' }, TEXT.scans.clean);
  const parts = [];
  if (row.critical_vulns) parts.push(el('span', { style: 'color: var(--danger);' }, TEXT.scans.critical(formatNumber(row.critical_vulns))));
  if (row.high_vulns) parts.push(el('span', { style: 'color: var(--warning);' }, TEXT.scans.high(formatNumber(row.high_vulns))));
  if (!parts.length) parts.push(el('span', { style: 'color: var(--text-muted);' }, TEXT.scans.medLow(formatNumber(row.total_vulnerabilities))));
  const wrap = el('span');
  parts.forEach((p, i) => append(wrap, [i ? ' / ' : null, p]));
  return wrap;
}

function licenseLabel(row) {
  const n = Number(row.license_violations) || 0;
  if (n === 0) return el('span', { style: 'color: var(--success);' }, TEXT.scans.licenseOk);
  return el('span', { style: 'color: var(--warning);' }, TEXT.scans.licenseAlerts(formatNumber(n)));
}

const STATUS_BADGES = {
  completed: { cls: 'status-healthy', icon: 'check-circle', label: TEXT.status.completed },
  running: { cls: 'status-scanning', icon: 'refresh-cw', label: TEXT.status.running, spin: true },
  pending: { cls: 'status-pending', icon: 'clock', label: TEXT.status.pending },
  queued: { cls: 'status-pending', icon: 'clock', label: TEXT.status.queued },
  failed: { cls: 'status-critical', icon: 'x-circle', label: TEXT.status.failed },
  cancelled: { cls: 'status-pending', icon: 'minus-circle', label: TEXT.status.cancelled },
  timeout: { cls: 'status-critical', icon: 'x-circle', label: TEXT.status.timeout },
};

function statusBadge(status) {
  const def = Object.prototype.hasOwnProperty.call(STATUS_BADGES, status) ? STATUS_BADGES[status] : null;
  if (!def) return el('span', { className: 'status-badge status-pending' }, String(status ?? TEXT.common.dash));
  return el('span', { className: `status-badge ${def.cls}` },
    icon(def.icon, 'width:13px;height:13px;', def.spin ? 'spin' : undefined), def.label);
}

function isActiveStatus(status) {
  return ['pending', 'queued', 'running'].includes(status);
}

// ── Reports menu (REQ-010 P-38, D-276): one native menu button per completed
// scan row. Items are the same <a> links as before (same href, download,
// target/rel), only grouped and described.
let reportsMenuSeq = 0;
let openReports = null; // { button, menu } of the open menu

function reportsItem(href, text, linkProps) {
  return el('a', {
    role: 'menuitem',
    className: 'reports-item',
    tabindex: '-1',
    href,
    ...linkProps,
  },
  el('span', { className: 'reports-item-title' }, text[0]),
  el('span', { className: 'reports-item-desc' }, text[1]));
}

function reportsMenu(items) {
  const menuId = `reports-menu-${++reportsMenuSeq}`;
  const button = el('button', {
    type: 'button',
    className: 'btn btn-sm reports-btn',
    'aria-haspopup': 'menu',
    'aria-expanded': 'false',
    'aria-controls': menuId,
  }, icon('file-down', 'width:12px;height:12px;'), TEXT.reports.button, icon('chevron-down', 'width:12px;height:12px;'));
  const menu = el('div', { className: 'reports-menu', id: menuId, role: 'menu', 'aria-label': TEXT.reports.menuLabel, hidden: true }, items);
  return el('div', { className: 'reports' }, button, menu);
}

function scanActions(row) {
  if (isActiveStatus(row.status)) {
    return el('div', { className: 'progress-bar-container', style: 'width:80px;' },
      el('div', { className: 'progress-bar', style: `width: ${row.status === 'running' ? '65' : '15'}%;` }));
  }
  // One-click exports (REQ-007 AC-P24-8, contract section 8): plain same-origin
  // <a download> links, no fetch/Blob and no waiting screen. An empty `download`
  // value lets the browser use the server's Content-Disposition file name.
  // On 429 export_busy / 404 the browser reports the download as failed; the
  // README tells the user to retry after a few seconds (accepted limitation).
  const download = { download: true };
  if (row.status === 'completed' && isWebScan(row)) {
    // REQ-008 AC-P27-5 / REQ-010 AC-P38-1: web scans offer only their own PDF and CSV.
    return reportsMenu([
      reportsItem(apiPath('scans', row.id, 'exports', 'web-report.pdf'), TEXT.reports.webPdf, download),
      reportsItem(apiPath('scans', row.id, 'exports', 'web-findings.csv'), TEXT.reports.webCsv, download),
    ]);
  }
  if (row.status === 'completed') {
    return reportsMenu([
      reportsItem(apiPath('scans', row.id, 'exports', 'project-report.pdf'), TEXT.reports.pdf, download),
      reportsItem(apiPath('scans', row.id, 'exports', 'license-inventory.xlsx'), TEXT.reports.excel, download),
      reportsItem(apiPath('scans', row.id, 'exports', 'license-inventory.csv'), TEXT.reports.csv, download),
      reportsItem(apiPath('scans', row.id, 'notice'), TEXT.reports.notice, { ...download, title: termTitle('notice') }),
      reportsItem(apiPath('scans', row.id, 'sbom', 'download'), TEXT.reports.sbom, { target: '_blank', rel: 'noopener', title: termTitle('sbom') }),
    ]);
  }
  return el('span', { style: 'color: var(--text-muted); font-size:0.8rem;' }, TEXT.common.dash);
}

function reportsMenuItems(menu) {
  return Array.from(menu.querySelectorAll('[role="menuitem"]'));
}

function focusReportsItem(menu, index) {
  const items = reportsMenuItems(menu);
  if (items.length === 0) return;
  items[((index % items.length) + items.length) % items.length].focus();
}

function closeReportsMenu(focusButton) {
  if (!openReports) return;
  const { button, menu } = openReports;
  openReports = null;
  menu.hidden = true;
  button.setAttribute('aria-expanded', 'false');
  if (focusButton && button.isConnected) button.focus();
}

function openReportsMenu(button, focusFirst) {
  const menu = byId(button.getAttribute('aria-controls') || '');
  if (!menu) return;
  closeReportsMenu(false);
  menu.hidden = false;
  button.setAttribute('aria-expanded', 'true');
  openReports = { button, menu };
  if (focusFirst) focusReportsItem(menu, 0);
}

function onReportsClick(e) {
  const target = e.target instanceof Element ? e.target : null;
  const button = target ? target.closest('.reports-btn') : null;
  if (button) {
    if (openReports && openReports.button === button) closeReportsMenu(false);
    // detail === 0: activated from the keyboard (Enter/Space) -> focus moves into the menu.
    else openReportsMenu(button, e.detail === 0);
    return;
  }
  if (!openReports) return;
  const inside = target !== null && openReports.menu.contains(target);
  // Choosing an item lets the browser follow the link (download), then closes the menu.
  if (inside && target.closest('[role="menuitem"]')) closeReportsMenu(true);
  else if (!inside) closeReportsMenu(false);
}

function onReportsKeydown(e) {
  const target = e.target instanceof Element ? e.target : null;
  if (!openReports) {
    if (target && target.matches('.reports-btn') && e.key === 'ArrowDown') {
      e.preventDefault();
      openReportsMenu(target, true);
    }
    return;
  }
  const { button, menu } = openReports;
  if (!button.isConnected) { openReports = null; return; }
  if (e.key === 'Escape') {
    e.preventDefault();
    closeReportsMenu(true);
    return;
  }
  if (e.key === 'Tab') { closeReportsMenu(false); return; }
  if (!target || !(target === button || menu.contains(target))) return;
  const index = reportsMenuItems(menu).indexOf(target);
  if (e.key === 'ArrowDown') { e.preventDefault(); focusReportsItem(menu, index + 1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); focusReportsItem(menu, index < 0 ? -1 : index - 1); }
  else if (e.key === 'Home') { e.preventDefault(); focusReportsItem(menu, 0); }
  else if (e.key === 'End') { e.preventDefault(); focusReportsItem(menu, -1); }
  else if (e.key === ' ' && index >= 0) { e.preventDefault(); target.click(); }
}

// ── Direct Download helper (failsafe)
function downloadDoc(docId) {
  window.location.href = apiPath('sbom', docId, 'download');
}

// ── Generate and download CycloneDX JSON (default fast download)
async function downloadCycloneDxSbom(scanId) {
  showToast(TEXT.sbom.preparing, 'success');
  try {
    const { data } = await api(apiPath('scans', scanId, 'sbom'), { method: 'POST', body: { format: 'cyclonedx_json' } });
    downloadDoc(data.id);
    showToast(TEXT.sbom.downloaded);
  } catch (e) {
    reportError(e, TEXT.sbom.downloadFailed);
  }
}

/**
 * Why a scan failed, or that it finished with warnings (REQ-009 AC-UI-3).
 * A classified clone error (REQ-009 contract section 5) gets its Turkish
 * headline (REQ-010 AC-P33-5, D-283); the git detail that follows the class
 * sentence is kept as it is, in muted text. Other messages: the first sentence
 * is the headline. Text only: the message is server data and never becomes markup.
 */
function scanErrorDetail(row) {
  const message = typeof row.error_message === 'string' ? row.error_message.trim() : '';
  if (!message) return null;
  if (row.status === 'failed') {
    const known = TEXT.cloneErrors.find(([sentence]) => message.startsWith(sentence));
    let headline;
    let rest;
    if (known) {
      headline = known[1];
      rest = message.slice(known[0].length).trim();
    } else {
      const cut = message.search(/\.\s/);
      headline = cut > 0 && cut < 220 ? message.slice(0, cut + 1) : message.slice(0, 220);
      rest = message.slice(headline.length).trim();
    }
    return el('div', { className: 'scan-error' }, el('strong', null, headline), rest ? el('span', null, rest) : null);
  }
  if (row.status === 'completed') {
    const count = message.split('\n').filter((line) => line.trim() !== '').length;
    return el('div', { className: 'scan-warning', title: message }, TEXT.scans.warnings(formatNumber(count)));
  }
  return null;
}

/** AC-P36-3: a completed dependency scan that found no package says so and why that may be. */
function noPackagesNote(row) {
  if (row.status !== 'completed' || isWebScan(row)) return null;
  if (row.total_dependencies === null || row.total_dependencies === undefined || Number(row.total_dependencies) !== 0) return null;
  return el('div', { className: 'scan-nopkg' },
    el('strong', null, TEXT.scans.noPackages),
    el('span', null, TEXT.scans.noPackagesHint));
}

// ── Scan rows (dashboard + history share one renderer)
function buildScanRow(row, idPrefix, withTrigger) {
  const tr = el('tr', { className: 'scan-row', id: `${idPrefix}-${row.id}` });
  const web = isWebScan(row);
  const grade = web && row.web_summary && typeof row.web_summary.grade === 'string' ? row.web_summary.grade : null;
  return append(tr, [
    el('td', null,
      el('strong', null, row.project_name || TEXT.common.dash),
      web ? el('span', { className: 'kind-web', title: TEXT.scans.kindWebTitle }, TEXT.scans.kindWeb) : null,
      el('br'),
      el('small', { style: 'color:var(--text-muted);' }, web ? webHost(row.target_url) : (row.ref || TEXT.common.defaultBranch))),
    el('td', null, statusBadge(row.status), scanErrorDetail(row), noPackagesNote(row)),
    el('td', null, !web && row.total_dependencies ? formatNumber(row.total_dependencies) : TEXT.common.dash),
    el('td', null, web ? el('span', { style: 'color: var(--text-muted);' }, TEXT.common.dash) : licenseLabel(row)),
    el('td', null, grade ? el('span', { className: 'capsule', style: 'margin-right:0.35rem;', title: termTitle('grade') }, TEXT.scans.grade(grade)) : null, securityLabel(row)),
    withTrigger
      ? el('td', null, el('span', { className: 'capsule' }, label(TEXT.trigger, row.trigger || 'manual')))
      : null,
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, timeAgo(row.completed_at || row.started_at || row.queued_at)),
    el('td', null, scanActions(row)),
  ]);
}

function renderScanRow(row) {
  return buildScanRow(row, 'scan-row', false);
}

function renderHistoryRow(row) {
  return buildScanRow(row, 'history-row', true);
}

// ── Poll individual scan details until completed/failed
function stopPolling(scanId) {
  clearInterval(pollingScans.get(scanId));
  pollingScans.delete(scanId);
}

function stopAllPolling() {
  for (const id of Array.from(pollingScans.keys())) stopPolling(id);
}

function pollScanUntilDone(scanId) {
  if (pollingScans.has(scanId)) return;
  const interval = setInterval(fire(async () => {
    try {
      const { data } = await api(apiPath('scans', scanId));
      if (!data) throw new Error(TEXT.scans.notFound);

      const rowDashboard = byId(`scan-row-${scanId}`);
      if (rowDashboard) rowDashboard.replaceWith(renderScanRow(data));
      const rowHistory = byId(`history-row-${scanId}`);
      if (rowHistory) rowHistory.replaceWith(renderHistoryRow(data));
      refreshIcons();

      if (!isActiveStatus(data.status)) {
        stopPolling(scanId);
        if (data.status === 'completed') showToast(TEXT.scans.completedToast(data.project_name));
        else if (data.status === 'failed') showToast(TEXT.scans.failedToast(data.project_name), 'error');
        if (currentActiveView === 'dashboard') await updateStats();
      }
    } catch {
      stopPolling(scanId);
    }
  }), 2000);
  pollingScans.set(scanId, interval);
}

// ── Load Dashboard Scans (Recent)
async function loadScans() {
  const loading = byId('table-loading');
  const container = byId('table-container');
  const empty = byId('table-empty');
  const tbody = byId('scans-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';
  empty.style.display = 'none';

  try {
    const { data } = await api('/api/scans');

    loading.style.display = 'none';
    clear(tbody);

    if (!Array.isArray(data) || data.length === 0) {
      empty.style.display = 'block';
      return;
    }

    container.style.display = 'block';
    // Display top 10 recent scans on dashboard
    for (const scan of data.slice(0, 10)) {
      tbody.appendChild(renderScanRow(scan));
      if (isActiveStatus(scan.status)) pollScanUntilDone(scan.id);
    }
    refreshIcons();
    setText('last-updated', TEXT.scans.lastUpdated(new Date().toLocaleTimeString(TEXT.locale)));
  } catch {
    loading.style.display = 'none';
    empty.style.display = 'block';
  }
}

/**
 * AC-P36-1 (D-274): per project only the most recent completed dependency
 * scan counts; web scans and older scans of the same project are ignored.
 * /api/scans is ordered newest first, so on equal timestamps the first wins.
 */
function latestDependencyScans(scans) {
  const latest = new Map();
  for (const s of scans) {
    if (!s || typeof s !== 'object' || s.status !== 'completed' || isWebScan(s)) continue;
    const key = String(s.project_id ?? s.project_name ?? s.id);
    const time = new Date(s.completed_at || s.started_at || s.queued_at || 0).getTime() || 0;
    const prev = latest.get(key);
    if (!prev || time > prev.time) latest.set(key, { time, scan: s });
  }
  return Array.from(latest.values()).map((v) => v.scan);
}

// ── Update Dashboard statistics counters
async function updateStats() {
  try {
    const projData = await api('/api/projects');
    animateNumber('stat-projects', Array.isArray(projData.data) ? projData.data.length : 0);

    const scanData = await api('/api/scans');
    const scans = latestDependencyScans(Array.isArray(scanData.data) ? scanData.data : []);

    const totalPkgs = scans.reduce((acc, s) => acc + (Number(s.total_dependencies) || 0), 0);
    const totalLicAlerts = scans.reduce((acc, s) => acc + (Number(s.license_violations) || 0), 0);
    const totalCritical = scans.reduce((acc, s) => acc + (Number(s.critical_vulns) || 0), 0);

    animateNumber('stat-packages', totalPkgs);
    animateNumber('stat-license-alerts', totalLicAlerts);
    animateNumber('stat-critical-cves', totalCritical);
  } catch {
    ['stat-projects', 'stat-packages', 'stat-license-alerts', 'stat-critical-cves'].forEach(resetStat);
  }
}

function resetStat(id) {
  const node = byId(id);
  if (!node) return;
  node.textContent = TEXT.stats.unavailable;
  delete node.dataset.value;
}

function animateNumber(id, target) {
  const node = byId(id);
  if (!node) return;
  // The shown text is tr-TR formatted ("1.234"), so the raw value is kept in data-value.
  const start = Number.parseInt(node.dataset.value || '0', 10) || 0;
  node.dataset.value = String(target);
  if (start === target) { node.textContent = formatNumber(target); return; }
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduceMotion || typeof requestAnimationFrame !== 'function') { node.textContent = formatNumber(target); return; }
  const duration = 600;
  const startTime = performance.now();
  function step(now) {
    const p = Math.min((now - startTime) / duration, 1);
    node.textContent = formatNumber(Math.round(start + (target - start) * p));
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Dashboard "Vulnerability data" panel (REQ-005 contract section 6).
// Read-only: one GET, no write request. Every API value reaches the DOM
// as text only (el()/textContent); none goes into style/href/className.

// Guards against an older response overwriting a newer one (load + 30 s refresh can overlap).
let vulnDataRequestSeq = 0;

function hasOwn(obj, key) {
  return obj !== null && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);
}

/** tr-TR time for an ISO timestamp; null/invalid -> `fallback`. */
function vulnTime(iso, fallback) {
  if (typeof iso !== 'string' || iso === '') return fallback;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? fallback : d.toLocaleString(TEXT.locale);
}

function vulnNumber(value) {
  return Number(value).toLocaleString(TEXT.locale);
}

function vulnMutedParagraph(text) {
  return el('p', { style: 'color: var(--text-muted);', text });
}

function setVulnDataBody(state, children) {
  const body = byId('vuln-data-body');
  if (!body) return;
  clear(body);
  body.dataset.state = state;
  append(body, children);
}

function vulnRecheckValue(settings) {
  if (settings.recheck_enabled === false) return TEXT.vuln.recheckOff;
  if (settings.lookup_enabled === false) return TEXT.vuln.lookupOff;
  return TEXT.vuln.every(vulnNumber(settings.interval_hours));
}

function vulnLastRunValue(scheduler, lastRun) {
  if (scheduler.current_run) return TEXT.vuln.runningSince(vulnTime(scheduler.current_run.started_at, TEXT.common.dash));
  if (lastRun === null || lastRun === undefined) return TEXT.vuln.neverRun;
  const runLabel = hasOwn(TEXT.vuln.runLabels, lastRun.status) ? TEXT.vuln.runLabels[lastRun.status] : String(lastRun.status ?? TEXT.common.dash);
  return `${runLabel} · ${vulnTime(lastRun.finished_at, TEXT.common.dash)}`;
}

function vulnNextCheckValue(scheduler, generatedAt) {
  if (scheduler.paused === true) return TEXT.vuln.paused;
  const next = scheduler.next_check_earliest_at;
  if (next === null || next === undefined) return TEXT.common.dash;
  const nextMs = new Date(next).getTime();
  const nowMs = new Date(generatedAt).getTime();
  if (Number.isNaN(nextMs)) return TEXT.common.dash;
  if (!Number.isNaN(nowMs) && nextMs <= nowMs) return TEXT.vuln.dueNow;
  return vulnTime(next, TEXT.common.dash);
}

function vulnDataRows(data) {
  const settings = data.settings || {};
  const scheduler = data.scheduler || {};
  const lastRun = data.last_run ?? null;
  const expiry = data.risk_acceptance_expiry || {};

  const rows = [
    [TEXT.vuln.rowRecheck, vulnRecheckValue(settings)],
    [TEXT.vuln.rowLastRun, vulnLastRunValue(scheduler, lastRun)],
    [TEXT.vuln.rowNewFindings, lastRun === null ? TEXT.common.dash : vulnNumber(lastRun.findings_opened)],
  ];
  if (lastRun !== null && Number(lastRun.packages_unchecked) > 0) {
    rows.push([TEXT.vuln.rowUnchecked, vulnNumber(lastRun.packages_unchecked)]);
  }
  rows.push(
    [TEXT.vuln.rowNext, vulnNextCheckValue(scheduler, data.generated_at)],
    [TEXT.vuln.rowReopened, vulnNumber(expiry.reopened_last_7_days)],
    [TEXT.vuln.rowExpiry, vulnTime(expiry.last_evaluated_at, TEXT.vuln.notEvaluated)],
  );

  return el('table', null,
    el('tbody', null, rows.map(([rowLabel, value]) => el('tr', null,
      el('th', { scope: 'row', style: 'width: 45%; padding: 0.75rem 1rem;', text: rowLabel }),
      el('td', { style: 'padding: 0.75rem 1rem;', text: value })))));
}

function vulnDataWarnings(data) {
  const projects = Array.isArray(data.projects) ? data.projects : [];
  const incomplete = projects.filter((p) => p && p.vulnerability_data_status !== 'complete');
  const counts = data.project_status_counts || {};
  let total = 0;
  for (const [key, value] of Object.entries(counts)) {
    if (key !== 'complete') total += Number(value) || 0;
  }

  const nodes = [];
  if (incomplete.length === 0 && total === 0) {
    nodes.push(el('p', { style: 'margin-top: 1rem;', text: TEXT.vuln.allComplete }));
  } else {
    nodes.push(el('p', { style: 'margin-top: 1rem; font-weight: 600;', text: TEXT.vuln.incomplete(vulnNumber(total)) }));
    nodes.push(el('ul', { id: 'vuln-data-warnings', style: 'margin: 0.5rem 0 0 1.25rem;' },
      incomplete.map((p) => {
        const status = p.vulnerability_data_status;
        let description;
        if (status === null || status === undefined) description = TEXT.vuln.notChecked;
        else if (hasOwn(TEXT.vuln.projectStatus, status)) description = TEXT.vuln.projectStatus[status];
        else description = String(status);
        return el('li', { text: `${String(p.project_name ?? '')}: ${description}` });
      })));
  }
  if (data.projects_truncated === true) {
    nodes.push(vulnMutedParagraph(TEXT.vuln.truncated));
  }
  return nodes;
}

async function loadVulnerabilityDataStatus() {
  const body = byId('vuln-data-body');
  if (!body) return;
  const seq = ++vulnDataRequestSeq;
  // Loading text only until the first successful render; a refresh keeps the current panel.
  if (body.dataset.state !== 'ready') {
    setVulnDataBody('loading', [vulnMutedParagraph(TEXT.vuln.loading)]);
  }
  try {
    const { data } = await api('/api/vulnerability-data/status');
    if (seq !== vulnDataRequestSeq) return;
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('malformed body');
    const content = [vulnDataRows(data), ...vulnDataWarnings(data)];
    setVulnDataBody('ready', content);
  } catch (err) {
    if (seq !== vulnDataRequestSeq) return;
    if (err && err.authRedirect) return; // the auth form already explains what happened
    // Server message is intentionally not shown (contract 6.3); previous content is dropped.
    setVulnDataBody('error', [vulnMutedParagraph(TEXT.vuln.loadFailed)]);
  }
}

// ── Load Scan History Tab
async function loadAllScansHistory() {
  const loading = byId('scans-list-loading');
  const container = byId('scans-list-container');
  const tbody = byId('scans-list-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api('/api/scans');

    loading.style.display = 'none';
    clear(tbody);
    container.style.display = 'block';

    if (!Array.isArray(data) || data.length === 0) {
      emptyRow(tbody, 8, TEXT.scans.historyEmpty);
      return;
    }

    for (const scan of data) {
      tbody.appendChild(renderHistoryRow(scan));
      if (isActiveStatus(scan.status)) pollScanUntilDone(scan.id);
    }
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, TEXT.scans.historyFailed);
  }
}

// ── Load Projects Tab
const CRITICALITY_STYLES = {
  critical: 'color: var(--danger); background: rgba(239,68,68,0.1);',
  high: 'color: var(--danger); background: rgba(239,68,68,0.1);',
  medium: 'color: var(--warning); background: rgba(245,158,11,0.1);',
};

function renderProjectRow(p) {
  const critStyle = Object.prototype.hasOwnProperty.call(CRITICALITY_STYLES, p.criticality)
    ? CRITICALITY_STYLES[p.criticality]
    : 'color: var(--success); background: rgba(16,185,129,0.1);';

  // Only http/https URLs become links; local paths and anything else stay plain text.
  const repoHref = safeExternalHref(p.repo_url);
  const repoContent = repoHref
    ? el('a', { href: repoHref, target: '_blank', rel: 'noopener noreferrer', style: 'color: var(--primary); text-decoration: none;' }, p.repo_url)
    : (p.repo_url || TEXT.common.dash);

  const ecosystems = (Array.isArray(p.ecosystems) ? p.ecosystems : [])
    .map((e) => el('span', { className: 'capsule', style: 'margin-right:0.25rem;' }, label(TEXT.ecosystem, e)));

  // Values travel in data-* attributes and are read back from dataset — never interpolated into code.
  const data = { projectId: String(p.id ?? ''), projectName: String(p.name ?? '') };
  const scanButton = p.repo_url
    ? el('button', { className: 'btn btn-sm', type: 'button', dataset: { action: 'scan-project', ...data } },
      icon('play', 'width:12px;height:12px;'), TEXT.projects.scanNow)
    : null;
  const webScanButton = p.web_url
    ? el('button', { className: 'btn btn-sm', type: 'button', dataset: { action: 'web-scan-project', ...data } },
      icon('globe', 'width:12px;height:12px;'), TEXT.projects.webScan)
    : null;
  const webEditButton = el('button', { className: 'btn btn-sm btn-ghost', type: 'button', dataset: { action: 'edit-web-url', ...data }, 'aria-label': TEXT.projects.webUrlAria },
    icon('pencil', 'width:12px;height:12px;'), TEXT.projects.webUrl);
  // REQ-009 AC-UI-2: https repositories can carry a token; its value is never shown.
  const tokenButton = isHttpsRepo(p.repo_url)
    ? el('button', {
      className: 'btn btn-sm btn-ghost',
      type: 'button',
      dataset: { action: 'edit-repo-token', ...data },
      title: p.has_repo_credential ? TEXT.projects.tokenSetTitle : TEXT.projects.tokenAddTitle,
    }, icon('key-round', 'width:12px;height:12px;'), p.has_repo_credential ? TEXT.projects.tokenSet : TEXT.projects.tokenAdd)
    : null;

  // REQ-008: the web address is shown as text with its scan mode, never as a link.
  const webContent = p.web_url
    ? el('span', null, String(p.web_url),
      p.web_scan_mode === 'active'
        ? el('span', { className: 'capsule', style: 'margin-left:0.35rem; color: var(--warning);', title: TEXT.projects.activeModeTitle }, TEXT.projects.activeMode)
        : null)
    : TEXT.common.dash;

  return el('tr', null,
    el('td', null, el('strong', null, p.name ?? TEXT.common.dash)),
    el('td', null, el('span', { className: 'status-badge', style: critStyle }, label(TEXT.severity, p.criticality))),
    el('td', { style: 'font-family: monospace; font-size: 0.8rem; color: var(--text-muted);' }, repoContent),
    el('td', { style: 'font-family: monospace; font-size: 0.8rem; color: var(--text-muted); word-break: break-all;' }, webContent),
    el('td', null, ecosystems.length ? ecosystems : el('span', { style: 'color:var(--text-muted)' }, TEXT.common.dash)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, timeAgo(p.created_at)),
    el('td', null, el('div', { style: 'display:inline-flex; gap:0.375rem; flex-wrap:wrap;' }, scanButton, webScanButton, webEditButton, tokenButton)));
}

function isHttpsRepo(value) {
  return typeof value === 'string' && /^https:\/\//i.test(value);
}

async function loadProjectsList() {
  const loading = byId('projects-loading');
  const container = byId('projects-container');
  const tbody = byId('projects-list-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api('/api/projects');

    loading.style.display = 'none';
    clear(tbody);
    container.style.display = 'block';

    projectsById.clear();
    if (!Array.isArray(data) || data.length === 0) {
      emptyRow(tbody, 7, TEXT.projects.empty);
      return;
    }

    for (const p of data) {
      projectsById.set(String(p.id), p);
      tbody.appendChild(renderProjectRow(p));
    }
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, TEXT.projects.loadFailed);
  }
}

/** Last loaded projects by id (Web URL modal prefill). */
const projectsById = new Map();
let webModalProjectId = null;

async function triggerWebScan(projectId, name) {
  showToast(TEXT.scans.schedulingWeb(name), 'success');
  try {
    await api('/api/scans', { method: 'POST', body: { projectId, trigger: 'manual', kind: 'web' } });
    showToast(TEXT.scans.webQueued);
    await switchView('dashboard');
  } catch (e) {
    reportError(e, TEXT.scans.webTriggerFailed);
  }
}

function syncWebModeWarning() {
  byId('webScanModeWarning').classList.toggle('show', byId('webScanMode').value === 'active');
}

function openWebUrlModal(projectId) {
  const p = projectsById.get(String(projectId));
  if (!p) return;
  webModalProjectId = String(projectId);
  setText('webUrlModal-subtitle', TEXT.projects.subtitle(p.name ?? TEXT.common.dash));
  byId('webUrlInput').value = p.web_url || '';
  byId('webScanMode').value = p.web_scan_mode === 'active' ? 'active' : 'passive';
  syncWebModeWarning();
  byId('webUrlModal').classList.add('open');
  byId('webUrlInput').focus();
}

function closeWebUrlModal() {
  byId('webUrlModal').classList.remove('open');
  webModalProjectId = null;
}

// ── Repo access token modal (REQ-009 AC-UI-2). There is no remove action (D-262).
let tokenModalProjectId = null;

function openRepoTokenModal(projectId) {
  const p = projectsById.get(String(projectId));
  if (!p) return undefined;
  tokenModalProjectId = String(projectId);
  setText('repoTokenModal-subtitle', TEXT.projects.tokenSubtitle(p.name ?? TEXT.common.dash, p.repo_url ?? ''));
  setText('repoTokenModal-state', p.has_repo_credential ? TEXT.projects.tokenStateSet : TEXT.projects.tokenStateNone);
  byId('repoTokenInput').value = '';
  applyFeatureHints(systemFeatures);
  byId('repoTokenModal').classList.add('open');
  byId('repoTokenInput').focus();
  return refreshFeatureHints('repoTokenModal');
}

function closeRepoTokenModal() {
  byId('repoTokenModal').classList.remove('open');
  byId('repoTokenInput').value = '';
  tokenModalProjectId = null;
}

async function saveRepoToken() {
  if (!tokenModalProjectId) return;
  const token = byId('repoTokenInput').value.trim();
  if (!token) { showToast(TEXT.projects.enterToken, 'error'); return; }
  const button = byId('token-modal-save-btn');
  button.disabled = true;
  try {
    await api(apiPath('projects', tokenModalProjectId, 'repo-credential'), { method: 'PUT', body: { token } });
    closeRepoTokenModal();
    showToast(TEXT.projects.tokenSaved);
    await loadProjectsList();
  } catch (e) {
    reportError(e, TEXT.projects.tokenSaveFailed);
  } finally {
    button.disabled = false;
  }
}

function syncRepoTokenField() {
  const https = isHttpsRepo(byId('repoPath').value.trim());
  byId('repoTokenGroup').hidden = !https;
  if (!https) byId('repoToken').value = '';
}

async function saveWebUrl() {
  if (!webModalProjectId) return;
  const webUrl = byId('webUrlInput').value.trim();
  const webScanMode = byId('webScanMode').value === 'active' ? 'active' : 'passive';
  const button = byId('web-modal-save-btn');
  button.disabled = true;
  try {
    await api(apiPath('projects', webModalProjectId), { method: 'PATCH', body: { webUrl: webUrl === '' ? null : webUrl, webScanMode } });
    closeWebUrlModal();
    showToast(TEXT.projects.webSaved);
    await loadProjectsList();
  } catch (e) {
    reportError(e, TEXT.projects.webSaveFailed);
  } finally {
    button.disabled = false;
  }
}

async function triggerManualScan(projectId, name) {
  showToast(TEXT.scans.scheduling(name), 'success');
  try {
    await api('/api/scans', { method: 'POST', body: { projectId, trigger: 'manual' } });
    showToast(TEXT.scans.queued);
    // Return to main dashboard view to display scanning progress
    await switchView('dashboard');
  } catch (e) {
    reportError(e, TEXT.scans.triggerFailed);
  }
}

// ── Dropdowns Populator for Scans (Vulnerabilities and SBOM)
async function populateScansDropdown(selectId, loader, options = {}) {
  const select = byId(selectId);
  setPlaceholderOption(select, TEXT.findings.loadingScans);

  try {
    const { data } = await api('/api/scans');
    // The SBOM Center lists dependency scans only (a web scan has no SBOM).
    const completed = (Array.isArray(data) ? data : [])
      .filter((s) => s.status === 'completed' && (options.includeWeb !== false || !isWebScan(s)));
    clear(select);

    if (completed.length === 0) {
      setPlaceholderOption(select, TEXT.findings.noCompleted);
    } else {
      for (const scan of completed) {
        const web = isWebScan(scan);
        select.appendChild(el('option', { value: String(scan.id), dataset: { kind: web ? 'web' : 'dependency' } },
          web
            ? TEXT.findings.webOption(scan.project_name, webHost(scan.target_url), formatDate(scan.completed_at))
            : TEXT.findings.depOption(scan.project_name, scan.ref || TEXT.common.defaultBranch, formatDate(scan.completed_at))));
      }
    }
  } catch (e) {
    setPlaceholderOption(select, TEXT.findings.fetchFailed);
    reportError(e, TEXT.findings.fetchFailed);
    return;
  }
  // Load the view for the first (pre-selected) scan; with no scan it shows the empty state.
  await loader();
}

// ── Load Vulnerabilities Tab
function severityIcon(sev) {
  if (sev === 'critical' || sev === 'high') return ['var(--danger)', 'rgba(239,68,68,0.15)'];
  if (sev === 'medium') return ['var(--warning)', 'rgba(245,158,11,0.15)'];
  return ['var(--text-muted)', 'rgba(255,255,255,0.06)'];
}

function renderFinding(f) {
  const badges = el('div');
  let iconName;
  let iconColor;
  let iconBg;

  if (f.finding_type === 'security') {
    const sev = tagLevel(f.severity);
    append(badges, [
      el('span', { className: `tag tag-${sev}` }, label(TEXT.severity, String(f.severity ?? 'medium').toLowerCase())),
      ' ',
      el('span', { className: `tag tag-${sev}`, title: termTitle('cvss') }, TEXT.findings.cvss(f.cvss_score || TEXT.common.dash)),
    ]);
    if (f.cve_id) append(badges, [' ', el('span', { className: 'capsule', title: termTitle('cve') }, f.cve_id)]);
    iconName = 'shield-alert';
    [iconColor, iconBg] = severityIcon(sev);
  } else {
    iconName = 'scale';
    iconColor = 'var(--warning)';
    iconBg = 'rgba(245,158,11,0.15)';
    const riskText = String(f.risk_level || 'medium').toLowerCase();
    append(badges, [
      el('span', { className: 'tag tag-violation', title: termTitle('license') }, TEXT.findings.licenseAlert),
      ' ',
      el('span', { className: `tag tag-${tagLevel(riskText)}` }, TEXT.findings.risk(label(TEXT.licenseRisk, riskText))),
    ]);
    if (f.detected_license) append(badges, [' ', el('span', { className: 'capsule' }, f.detected_license)]);
  }

  const description = f.vuln_description
    || TEXT.findings.licenseDescription(f.package_name, f.detected_license, f.applied_policy || TEXT.findings.defaultPolicy);

  return el('div', { className: 'finding-item' },
    el('div', { className: 'finding-icon', style: `background: ${iconBg}; color: ${iconColor};` }, icon(iconName)),
    el('div', { className: 'finding-info' },
      el('div', { className: 'finding-title-row' },
        el('h4', { className: 'finding-title' }, f.vuln_title || f.normalized_license || TEXT.findings.unknownRisk),
        badges),
      el('div', { className: 'finding-meta' },
        el('span', null, TEXT.findings.package, el('strong', null, `${f.package_name}@${f.package_version}`)),
        el('span', null, TEXT.findings.type, el('span', { className: 'capsule' }, label(TEXT.findingType, f.finding_type))),
        el('span', null, TEXT.findings.status, el('span', { className: 'capsule', style: 'color:var(--danger);' }, label(TEXT.findingStatus, f.status))),
        f.purl ? el('span', { title: termTitle('purl') }, TEXT.findings.purl, el('code', null, f.purl)) : null),
      el('p', { className: 'finding-description' }, description),
      f.fix_version
        ? el('div', { style: 'margin-top:0.4rem; font-size:0.8rem; color:var(--success);' }, TEXT.findings.fixedIn, el('strong', null, f.fix_version))
        : null));
}

// ── Web scan findings (REQ-008 AC-P27-5)
function renderWebSummary(data) {
  const grade = ['A', 'B', 'C', 'D', 'F'].includes(data.grade) ? data.grade : 'F';
  const summary = data.summary && typeof data.summary === 'object' ? data.summary : {};
  const engines = summary.engines && typeof summary.engines === 'object' ? summary.engines : {};
  const counts = data.counts && typeof data.counts === 'object' ? data.counts : {};
  const chips = ['critical', 'high', 'medium', 'low', 'info'].map((s) =>
    el('span', { className: `tag tag-${tagLevel(s)}` }, `${TEXT.severity[s]}: ${formatNumber(Number(counts[s]) || 0)}`));
  const engineText = TEXT.web.engineLine(
    label(TEXT.web.engines, engines.builtin, TEXT.common.dash),
    label(TEXT.web.engines, engines.zap, TEXT.common.dash),
    engines.zap_mode === 'active',
    label(TEXT.web.engines, summary.vulnerability_lookup, TEXT.common.dash),
    formatNumber(Number(summary.requests) || 0));
  return el('div', { className: 'web-summary' },
    el('div', { className: `web-grade web-grade-${grade}`, 'aria-label': TEXT.web.gradeAria(grade), title: termTitle('grade') }, grade),
    el('div', { className: 'web-summary-text' },
      el('h3', null, TEXT.web.heading(grade, Number(data.score) || 0)),
      el('p', null, TEXT.web.target(data.scan && data.scan.target_url ? webLocation(data.scan.target_url) : TEXT.common.dash)),
      el('p', null, engineText),
      el('div', { className: 'web-counts' }, chips)));
}

function renderWebFinding(f) {
  const sev = tagLevel(f.severity);
  const badges = el('div', null,
    el('span', { className: `tag tag-${sev}` }, label(TEXT.severity, f.severity, TEXT.common.dash)),
    ' ',
    el('span', { className: 'capsule' }, f.rule_id ?? TEXT.common.dash),
    f.owasp ? [' ', el('span', { className: 'capsule', title: termTitle('owasp') }, `OWASP ${f.owasp}`)] : null,
    f.cwe_id ? [' ', el('span', { className: 'capsule', title: termTitle('cwe') }, `CWE-${f.cwe_id}`)] : null,
    f.advisory_id ? [' ', el('span', { className: 'capsule' }, f.advisory_id)] : null);
  const [iconColor, iconBg] = severityIcon(sev);
  return el('div', { className: 'finding-item' },
    el('div', { className: 'finding-icon', style: `background: ${iconBg}; color: ${iconColor};` }, icon(f.source === 'zap' ? 'radar' : 'globe')),
    el('div', { className: 'finding-info' },
      el('div', { className: 'finding-title-row' }, el('h4', { className: 'finding-title' }, f.title ?? TEXT.common.dash), badges),
      el('div', { className: 'finding-meta' },
        f.location ? el('span', null, TEXT.web.location, el('strong', { style: 'word-break: break-all;' }, f.location)) : null,
        el('span', null, TEXT.web.source, el('span', { className: 'capsule' }, f.source === 'zap' ? TEXT.web.sourceZap : TEXT.web.sourceBuiltin)),
        f.component_name ? el('span', null, TEXT.web.component, el('strong', null, `${f.component_name}@${f.component_version ?? '?'}`)) : null),
      el('p', { className: 'finding-description' }, f.description ?? ''),
      f.evidence ? el('div', { className: 'web-finding-ev' }, TEXT.web.evidence(f.evidence)) : null,
      f.fixed_version ? el('div', { style: 'margin-top:0.4rem; font-size:0.8rem; color:var(--success);' }, TEXT.findings.fixedIn, el('strong', null, f.fixed_version)) : null,
      el('div', { className: 'web-finding-rec' }, TEXT.web.recommendation(f.recommendation ?? ''))));
}

async function loadWebFindings(scanId, container) {
  const { data } = await api(apiPath('scans', scanId, 'web-findings'));
  clear(container);
  container.appendChild(renderWebSummary(data));
  const findings = Array.isArray(data.findings) ? data.findings : [];
  if (findings.length === 0) {
    container.appendChild(emptyState('shield-check', TEXT.web.noFindingsTitle, TEXT.web.noFindingsHint, ' color:var(--success); opacity:1;'));
  }
  for (const f of findings) container.appendChild(renderWebFinding(f));
  const components = Array.isArray(data.components) ? data.components : [];
  if (components.length > 0) {
    container.appendChild(el('div', { className: 'web-components' },
      el('h4', null, TEXT.web.components),
      components.map((c) => el('span', { className: 'capsule', style: 'margin:0 0.35rem 0.35rem 0;' }, `${c.name} ${c.version}`))));
  }
  refreshIcons();
}

async function loadScanFindings() {
  const scanId = byId('findings-scan-select').value;
  const container = byId('findings-container');
  const loading = byId('findings-loading');

  if (!scanId) {
    clear(container).appendChild(emptyState('alert-triangle', TEXT.findings.noScanTitle, TEXT.findings.noScanHint));
    refreshIcons();
    return;
  }

  loading.style.display = 'block';
  container.style.display = 'none';

  const selected = byId('findings-scan-select').selectedOptions[0];
  if (selected && selected.dataset.kind === 'web') {
    try {
      await loadWebFindings(scanId, container);
      loading.style.display = 'none';
      container.style.display = 'block';
    } catch (e) {
      loading.style.display = 'none';
      container.style.display = 'block';
      clear(container).appendChild(el('div', { className: 'empty-state' }, el('p', null, TEXT.findings.webLoadFailed)));
      reportError(e, TEXT.findings.webLoadFailed);
    }
    return;
  }

  try {
    const { data } = await api(apiPath('scans', scanId, 'findings'));

    loading.style.display = 'none';
    container.style.display = 'block';
    clear(container);

    if (!Array.isArray(data) || data.length === 0) {
      container.appendChild(emptyState('shield-check', TEXT.findings.cleanTitle, TEXT.findings.cleanHint, ' color:var(--success); opacity:1;'));
      refreshIcons();
      return;
    }

    for (const f of data) container.appendChild(renderFinding(f));
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    container.style.display = 'block';
    clear(container).appendChild(el('div', { className: 'empty-state' }, el('p', null, TEXT.findings.loadFailed)));
    reportError(e, TEXT.findings.loadFailed);
  }
}

// ── Load SBOM Tab
const SBOM_FORMAT_LABELS = {
  cyclonedx_json: 'CycloneDX (JSON)',
  cyclonedx_xml: 'CycloneDX (XML)',
  spdx_json: 'SPDX (JSON)',
  spdx_tag_value: 'SPDX (Tag-Value)',
};

function renderSbomRow(doc) {
  const formatLabel = Object.prototype.hasOwnProperty.call(SBOM_FORMAT_LABELS, doc.format) ? SBOM_FORMAT_LABELS[doc.format] : doc.format;
  return el('tr', null,
    el('td', null, el('strong', null, formatLabel ?? TEXT.common.dash)),
    el('td', null, el('span', { className: 'capsule' }, doc.specVersion ?? TEXT.common.dash)),
    el('td', null, formatBytes(doc.fileSizeBytes)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, formatDate(doc.generatedAt)),
    el('td', { style: 'font-family: monospace; font-size: 0.78rem; color: var(--text-muted);' }, `${String(doc.checksumSha256 ?? '').slice(0, 16)}...`),
    el('td', null,
      el('a', {
        className: 'btn btn-sm',
        href: apiPath('sbom', doc.id, 'download'),
        target: '_blank',
        rel: 'noopener',
        style: 'text-decoration:none; display:inline-flex; align-items:center; gap:0.25rem;',
      }, icon('download', 'width:12px;height:12px;'), TEXT.sbom.download)));
}

async function loadScanSboms() {
  const scanId = byId('sbom-scan-select').value;
  const container = byId('sbom-manager-container');
  const empty = byId('sbom-empty-state');
  const loading = byId('sbom-loading');
  const tbody = byId('sbom-documents-tbody');
  const tableEmpty = byId('sbom-docs-empty');
  const tableWrapper = byId('sbom-table-wrapper');

  if (!scanId) {
    container.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  loading.style.display = 'block';
  container.style.display = 'none';
  empty.style.display = 'none';

  try {
    const { data } = await api(apiPath('scans', scanId, 'sbom'));

    loading.style.display = 'none';
    container.style.display = 'block';
    clear(tbody);

    if (!Array.isArray(data) || data.length === 0) {
      tableEmpty.style.display = 'block';
      tableWrapper.style.display = 'none';
      return;
    }

    tableEmpty.style.display = 'none';
    tableWrapper.style.display = 'block';
    for (const doc of data) tbody.appendChild(renderSbomRow(doc));
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, TEXT.sbom.loadFailed);
  }
}

async function generateNewSbom() {
  const scanId = byId('sbom-scan-select').value;
  const format = byId('sbom-format-select').value;
  const genBtn = byId('generate-sbom-btn');

  if (!scanId) return;

  genBtn.disabled = true;
  setButtonContent(genBtn, 'loader-2', TEXT.sbom.generating, true);

  try {
    await api(apiPath('scans', scanId, 'sbom'), { method: 'POST', body: { format } });
    showToast(TEXT.sbom.generated);
    await loadScanSboms();
  } catch (e) {
    reportError(e, TEXT.sbom.generateFailed);
  } finally {
    genBtn.disabled = false;
    setButtonContent(genBtn, 'plus', TEXT.sbom.generate);
  }
}

// ── Load Users & Roles Tab
function renderUserRow(u) {
  const roles = (Array.isArray(u.roles) ? u.roles : []).map((role) => el('span', {
    className: 'capsule',
    style: 'background:rgba(139,92,246,0.1); color:var(--primary); font-weight:600; margin-right:0.25rem;',
  }, label(TEXT.role, role)));
  return el('tr', null,
    el('td', null, el('strong', null, u.display_name || TEXT.common.dash)),
    // Plain text: only http/https may be used as href (no mailto: built from API data).
    el('td', { style: 'color:var(--primary);' }, u.email || TEXT.common.dash),
    el('td', null, roles),
    el('td', null, el('span', { className: 'status-badge status-healthy' }, label(TEXT.userStatus, u.status || 'active'))),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, timeAgo(u.created_at)));
}

async function loadUsersList() {
  const loading = byId('users-loading');
  const container = byId('users-container');
  const tbody = byId('users-list-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api('/api/users');

    loading.style.display = 'none';
    container.style.display = 'block';
    clear(tbody);

    if (!Array.isArray(data) || data.length === 0) {
      emptyRow(tbody, 5, TEXT.users.empty);
      return;
    }

    for (const u of data) tbody.appendChild(renderUserRow(u));
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, TEXT.users.loadFailed);
  }
}

// ════════════════════════════════════════════════════════════════════
// System status (REQ-010 P-35, contract docs/contracts/REQ-010-system-features.md).
// The endpoint returns booleans and counts only. 401 goes to the login form
// like every call; 403/404/network/malformed -> "Sistem durumu alınamadı".
// ════════════════════════════════════════════════════════════════════

/** Last successful `data` of GET /api/system/features, or null when unknown. */
let systemFeatures = null;
let systemFeaturesSeq = 0;

async function loadSystemFeatures() {
  try {
    const { data } = await api('/api/system/features');
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('malformed body');
    systemFeatures = data;
  } catch (err) {
    if (err && err.authRedirect) throw err;
    systemFeatures = null;
  }
  return systemFeatures;
}

/** True only when the API explicitly reports the feature as off. */
function featureOff(features, key) {
  return hasOwn(features, key) && features[key] !== null && typeof features[key] === 'object' && features[key].enabled === false;
}

function setFeatureWarning(id, text) {
  const node = byId(id);
  if (!node) return;
  node.textContent = text || '';
  node.classList.toggle('show', Boolean(text));
}

/** AC-P35-3: field hints of the new-project and token modals follow the feature switches. */
function applyFeatureHints(features) {
  setFeatureWarning('repoPath-feature-warning', featureOff(features, 'local_scan') ? TEXT.modal.localScanOff : '');
  setFeatureWarning('webUrl-feature-warning', featureOff(features, 'web_scan') ? TEXT.modal.webScanOff : '');
  const tokensOff = featureOff(features, 'repo_tokens') ? TEXT.modal.repoTokensOff : '';
  setFeatureWarning('repoToken-feature-warning', tokensOff);
  setFeatureWarning('repoTokenModal-feature-warning', tokensOff);
}

async function refreshFeatureHints(modalId) {
  const features = await loadSystemFeatures();
  const modal = byId(modalId);
  if (modal && modal.classList.contains('open')) applyFeatureHints(features);
}

function renderFeature(def, value) {
  const known = value !== null && typeof value === 'object' && typeof value.enabled === 'boolean';
  const enabled = known && value.enabled;
  let badge;
  if (!known) badge = el('span', { className: 'status-badge status-pending' }, TEXT.system.unknown);
  else if (enabled) badge = el('span', { className: 'status-badge status-healthy' }, icon('check-circle', 'width:13px;height:13px;'), TEXT.system.on);
  else badge = el('span', { className: 'status-badge status-critical' }, icon('x-circle', 'width:13px;height:13px;'), TEXT.system.off);

  const meta = [];
  if (known && def.count && Number.isFinite(Number(value[def.count[0]]))) meta.push(def.count[1](formatNumber(value[def.count[0]])));
  if (known && def.key === 'nvd' && typeof value.api_key === 'boolean') meta.push(value.api_key ? TEXT.system.nvdKeySet : TEXT.system.nvdKeyMissing);

  return el('div', { className: 'feature-item', dataset: { feature: def.key, enabled: known ? String(enabled) : 'unknown' } },
    el('div', { className: 'feature-head' }, el('h3', { className: 'feature-name' }, def.name), badge),
    el('p', { className: 'feature-desc' }, def.description),
    meta.map((m) => el('p', { className: 'feature-meta' }, m)),
    known && !enabled ? el('p', { className: 'feature-enable' }, el('strong', null, TEXT.system.howTo), def.enable) : null);
}

async function loadSystemStatus() {
  const body = byId('system-status-body');
  if (!body) return;
  const seq = ++systemFeaturesSeq;
  const features = await loadSystemFeatures();
  if (seq !== systemFeaturesSeq) return;
  clear(body);
  if (!features) {
    body.dataset.state = 'error';
    body.appendChild(el('div', { className: 'empty-state', role: 'alert' },
      icon('server-cog', 'display:block; margin:0 auto 1rem;'),
      el('p', null, TEXT.system.loadFailedTitle),
      el('small', null, TEXT.system.loadFailedHint)));
    refreshIcons();
    return;
  }
  body.dataset.state = 'ready';
  append(body, [
    el('div', { className: 'feature-list' }, TEXT.system.features.map((def) => renderFeature(def, hasOwn(features, def.key) ? features[def.key] : null))),
    el('p', { className: 'form-hint', style: 'margin-top:1rem;' }, TEXT.system.restartNote),
  ]);
  refreshIcons();
}

// ── Help view (P-34 AC-P34-4, D-281): static content from TEXT, no server call.
function renderHelp() {
  const body = byId('help-body');
  if (!body || body.dataset.rendered === 'true') return;
  body.dataset.rendered = 'true';
  append(clear(body), [
    el('section', { className: 'help-section', 'aria-labelledby': 'help-steps-title' },
      el('h3', { id: 'help-steps-title' }, TEXT.help.stepsTitle),
      el('ol', { className: 'help-steps' }, TEXT.help.steps.map(([title, text]) =>
        el('li', null, el('strong', null, title), el('span', null, text))))),
    el('section', { className: 'help-section', 'aria-labelledby': 'help-trouble-title' },
      el('h3', { id: 'help-trouble-title' }, TEXT.help.troubleTitle),
      el('p', null, TEXT.help.trouble)),
    el('section', { className: 'help-section', 'aria-labelledby': 'help-glossary-title' },
      el('h3', { id: 'help-glossary-title' }, TEXT.help.glossaryTitle),
      el('dl', { className: 'glossary', id: 'help-glossary' }, Object.entries(TEXT.glossary).map(([key, [term, text]]) =>
        el('div', { className: 'glossary-entry', dataset: { term: key } }, el('dt', null, term), el('dd', null, text))))),
  ]);
}

/** Static markup marks glossary terms with data-term; their tooltip comes from TEXT.glossary. */
function applyTermTitles() {
  document.querySelectorAll('[data-term]').forEach((node) => {
    if (node.closest('#help-glossary')) return;
    const title = termTitle(node.dataset.term);
    if (title) node.setAttribute('title', title);
  });
}

// ════════════════════════════════════════════════════════════════════
// API Keys view (REQ-007 AC-AK-1…4, contract section 9; REQ-002 D-22).
// One-time reveal rule: the plain key lives only in the local variable of the
// function that handles the POST response and in the `value` property of
// #api-key-value. It is never assigned to a module-level variable, written to
// localStorage/sessionStorage/URL/console, or put into an error/toast text.
// The reveal panel is removed on Done, view switch, pagehide and session end.
// ════════════════════════════════════════════════════════════════════

/** Metadata only: true/false once the list has loaded, null while unknown. */
let apiKeysHasActive = null;
let apiKeysLoadSeq = 0;

function removeApiKeyReveal() {
  const panel = byId('api-key-reveal');
  if (!panel) return;
  const field = byId('api-key-value');
  if (field) field.value = '';
  panel.remove();
}

function setApiKeysState(state) {
  const body = byId('api-keys-body');
  if (!body) return;
  body.dataset.state = state;
  const parts = { loading: 'api-keys-loading', error: 'api-keys-error', empty: 'api-keys-empty', ready: 'api-keys-table' };
  for (const [name, id] of Object.entries(parts)) {
    const node = byId(id);
    if (node) node.hidden = name !== state;
  }
}

function renderApiKeyRow(row) {
  const prefix = String(row.keyPrefix ?? '');
  const active = row.revokedAt === null || row.revokedAt === undefined;
  let action = null;
  if (active) {
    action = el('button', {
      type: 'button',
      className: 'btn btn-sm',
      'aria-label': TEXT.apiKeys.revokeAria(prefix),
    }, TEXT.apiKeys.revoke);
    action.addEventListener('click', fire(() => revokeApiKey(row.id, prefix, action)));
  }
  return el('tr', null,
    el('td', null, row.name ? String(row.name) : TEXT.common.dash),
    el('td', null, el('code', null, prefix)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, formatDate(row.createdAt)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, row.lastUsedAt ? formatDate(row.lastUsedAt) : TEXT.apiKeys.never),
    el('td', null, active
      ? el('span', { className: 'status-badge status-healthy' }, TEXT.apiKeys.active)
      : el('span', { className: 'status-badge status-pending' }, TEXT.apiKeys.revoked(formatDate(row.revokedAt)))),
    el('td', null, action));
}

async function loadApiKeys() {
  const seq = ++apiKeysLoadSeq;
  setApiKeysState('loading');
  try {
    const { data } = await api('/api/auth/api-keys');
    if (seq !== apiKeysLoadSeq) return;
    const rows = Array.isArray(data) ? data.filter((r) => r && typeof r === 'object') : [];
    apiKeysHasActive = rows.some((r) => r.revokedAt === null || r.revokedAt === undefined);
    const tbody = clear(byId('api-keys-tbody'));
    for (const r of rows) tbody.appendChild(renderApiKeyRow(r));
    setApiKeysState(rows.length ? 'ready' : 'empty');
    refreshIcons();
  } catch (e) {
    if (seq !== apiKeysLoadSeq) return;
    apiKeysHasActive = null;
    setApiKeysState('error');
    reportError(e, TEXT.apiKeys.loadFailed);
  }
}

/** Builds the one-time reveal panel. `keyValue` is only held by this call and the input's value property. */
function showApiKeyReveal(keyId, keyValue) {
  removeApiKeyReveal();
  const slot = byId('api-key-reveal-slot');
  if (!slot) return;

  const field = el('input', {
    type: 'text',
    id: 'api-key-value',
    className: 'form-control',
    readonly: true,
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': TEXT.apiKeys.fieldAria,
    style: 'flex:1; min-width:240px; font-family:monospace;',
  });
  // Property, not attribute: the key does not appear in serialised markup.
  field.value = keyValue;

  const status = el('span', { id: 'api-key-copy-status', 'aria-live': 'polite', style: 'color:var(--text-muted); font-size:0.85rem;' });
  const copyBtn = el('button', { type: 'button', id: 'api-key-copy-btn', className: 'btn btn-sm' }, icon('copy', 'width:12px;height:12px;'), TEXT.apiKeys.copy);
  const doneBtn = el('button', { type: 'button', id: 'api-key-dismiss-btn', className: 'btn btn-sm btn-ghost' }, TEXT.apiKeys.done);

  copyBtn.addEventListener('click', fire(async () => {
    const current = byId('api-key-value');
    if (!current) return;
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(current.value);
      status.textContent = TEXT.apiKeys.copied;
    } catch {
      current.focus();
      current.select();
      status.textContent = TEXT.apiKeys.pressCtrlC;
    }
  }));
  doneBtn.addEventListener('click', () => {
    removeApiKeyReveal();
    const createBtn = byId('api-key-create-btn');
    if (createBtn) createBtn.focus();
  });

  const panel = el('div', {
    id: 'api-key-reveal',
    dataset: { keyId: String(keyId ?? '') },
    style: 'background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.35); border-radius:14px; padding:1rem 1.25rem; margin-top:1rem;',
  },
    el('p', { style: 'margin-bottom:0.75rem; font-weight:600;' }, TEXT.apiKeys.copyNow),
    el('div', { style: 'display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;' }, field, copyBtn, doneBtn),
    el('div', { style: 'margin-top:0.5rem; min-height:1.2rem;' }, status));
  slot.appendChild(panel);
  refreshIcons();
  field.focus();
  field.select();
}

async function createApiKey() {
  const btn = byId('api-key-create-btn');
  const nameInput = byId('api-key-name');
  if (!btn || !nameInput || btn.disabled) return;
  const name = nameInput.value.trim();
  // Unknown list state (still loading or failed) is treated as "may have an active key".
  if (apiKeysHasActive !== false
    && !window.confirm(TEXT.apiKeys.confirmReplace)) return;

  btn.disabled = true;
  const viewAtStart = currentActiveView;
  try {
    const { data } = await api('/api/auth/api-keys', { method: 'POST', body: name ? { name } : {} });
    const valid = data && typeof data.key === 'string' && data.key !== '';
    if (!valid) throw new Error(TEXT.common.unexpectedResponse);
    nameInput.value = '';
    if (!currentUser || currentActiveView !== 'api-keys' || viewAtStart !== 'api-keys') {
      // The view was left (or the session ended) while the request was in flight:
      // the key is not rendered into a hidden view.
      showToast(TEXT.apiKeys.notShown, 'error');
    } else {
      showApiKeyReveal(data.id, data.key);
    }
    await loadApiKeys();
  } catch (e) {
    reportError(e, TEXT.apiKeys.createFailed);
  } finally {
    btn.disabled = false;
  }
}

async function revokeApiKey(id, prefix, button) {
  if (!window.confirm(TEXT.apiKeys.confirmRevoke(prefix))) return;
  if (button) button.disabled = true;
  try {
    await api(apiPath('auth', 'api-keys', id), { method: 'DELETE' });
    const panel = byId('api-key-reveal');
    if (panel && panel.dataset.keyId === String(id)) removeApiKeyReveal();
    showToast(TEXT.apiKeys.revokedToast);
    await loadApiKeys();
  } catch (e) {
    if (button && button.isConnected) button.disabled = false;
    reportError(e, TEXT.apiKeys.revokeFailed);
  }
}

// ── Modal Handlers
function openModal() {
  byId('scanModal').classList.add('open');
  applyFeatureHints(systemFeatures);
  const nameInput = byId('projectName');
  if (nameInput) nameInput.focus();
  return refreshFeatureHints('scanModal');
}
function closeModal() {
  const modal = byId('scanModal');
  if (!modal) return;
  modal.classList.remove('open');
  byId('projectName').value = '';
  byId('repoPath').value = '';
  byId('webUrl').value = '';
  byId('repoToken').value = '';
  byId('repoTokenGroup').hidden = true;
  // AC-P36-2: the next project starts again with auto-detect (no ecosystem selected).
  ecoInputs().forEach((input) => { input.checked = input.value === 'auto'; });
}

function ecoInputs() {
  return Array.from(byId('ecosystems').querySelectorAll('input[name="eco"]'));
}

/** Selected ecosystems; auto-detect (or nothing) -> [] which the server reads as "all" (D-275). */
function selectedEcosystems() {
  return ecoInputs().filter((input) => input.checked && input.value !== 'auto').map((input) => input.value);
}

/** "Otomatik algıla" and the technology cards exclude each other; clearing every card returns to auto. */
function syncEcosystemChoice(e) {
  const changed = e && e.target instanceof HTMLInputElement ? e.target : null;
  if (!changed || changed.name !== 'eco') return;
  const inputs = ecoInputs();
  const auto = inputs.find((input) => input.value === 'auto');
  if (changed === auto && auto.checked) inputs.forEach((input) => { if (input !== auto) input.checked = false; });
  if (changed !== auto && changed.checked) auto.checked = false;
  if (!inputs.some((input) => input.checked)) auto.checked = true;
}

// ── New project modal submission
async function launchScan() {
  const name = byId('projectName').value.trim();
  const repoPath = byId('repoPath').value.trim();
  const webUrl = byId('webUrl').value.trim();
  const ecosystems = selectedEcosystems();

  if (!name) { showToast(TEXT.modal.nameRequired, 'error'); return; }
  if (!repoPath && !webUrl) { showToast(TEXT.modal.sourceRequired, 'error'); return; }

  const launchBtn = byId('launch-btn');
  launchBtn.disabled = true;
  setButtonContent(launchBtn, 'loader-2', TEXT.modal.creating, true);

  try {
    // 1. Create project (an empty ecosystem list means "detect all", D-275).
    const body = { name, ecosystems };
    if (repoPath) body.repoUrl = repoPath;
    if (webUrl) body.webUrl = webUrl;
    const { data: project } = await api('/api/projects', { method: 'POST', body });
    // 1b. Token for a private https repository (REQ-009 AC-UI-1), before the first scan.
    const token = byId('repoToken').value.trim();
    if (token && isHttpsRepo(repoPath)) {
      try {
        await api(apiPath('projects', project.id, 'repo-credential'), { method: 'PUT', body: { token } });
      } catch (e) {
        // The project exists already; a scan without the token would only fail on authentication.
        closeModal();
        if (e && e.authRedirect) return;
        const reason = e && e.message ? ` (${e.message})` : '';
        showToast(TEXT.modal.tokenNotSaved(name, reason), 'error');
        await switchView('projects');
        return;
      }
    }
    // 2. Queue scans: dependency scan for the code, web scan for the address (REQ-008).
    if (repoPath) await api('/api/scans', { method: 'POST', body: { projectId: project.id, trigger: 'manual' } });
    if (webUrl) await api('/api/scans', { method: 'POST', body: { projectId: project.id, trigger: 'manual', kind: 'web' } });

    closeModal();
    showToast(TEXT.modal.queued(name));
    // Force switch to Dashboard to view progress
    await switchView('dashboard');
  } catch (e) {
    reportError(e, TEXT.modal.launchFailed);
  } finally {
    launchBtn.disabled = false;
    setButtonContent(launchBtn, 'play', TEXT.modal.launch);
  }
}

// ── View router (titles and one-sentence purposes come from TEXT.views, AC-P34-1)
const VIEWS = {
  dashboard: {
    headerActions: true,
    load: () => Promise.all([loadScans(), updateStats(), loadVulnerabilityDataStatus()]),
    refresh: () => Promise.all([loadScans(), updateStats(), loadVulnerabilityDataStatus()]),
  },
  scans: {
    load: () => loadAllScansHistory(),
    refresh: () => loadAllScansHistory(),
  },
  findings: {
    load: () => populateScansDropdown('findings-scan-select', loadScanFindings),
    refresh: () => loadScanFindings(),
  },
  projects: {
    load: () => loadProjectsList(),
    refresh: () => loadProjectsList(),
  },
  sbom: {
    load: () => populateScansDropdown('sbom-scan-select', loadScanSboms, { includeWeb: false }),
    refresh: () => loadScanSboms(),
  },
  users: {
    load: () => loadUsersList(),
    refresh: () => loadUsersList(),
  },
  'api-keys': {
    // refreshAll only reloads the list; it never removes or rebuilds the reveal panel.
    load: () => loadApiKeys(),
    refresh: () => loadApiKeys(),
  },
  system: {
    load: () => loadSystemStatus(),
    refresh: () => loadSystemStatus(),
  },
  help: {
    load: async () => renderHelp(),
    refresh: async () => renderHelp(),
  },
};

async function switchView(targetView) {
  if (!Object.prototype.hasOwnProperty.call(VIEWS, targetView)) return;
  const cfg = VIEWS[targetView];
  const texts = TEXT.views[targetView];
  // A freshly created API key is shown only while the API Keys view stays open.
  if (!(targetView === 'api-keys' && currentActiveView === 'api-keys')) removeApiKeyReveal();
  closeReportsMenu(false);

  document.querySelectorAll('#sidebar-nav .nav-item').forEach((b) => {
    const active = b.dataset.view === targetView;
    b.classList.toggle('active', active);
    if (active) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  currentActiveView = targetView;

  document.querySelectorAll('.view-section').forEach((sec) => { sec.style.display = 'none'; });
  byId(`view-${targetView}`).style.display = 'block';

  setText('page-title', texts.title);
  setText('page-subtitle', texts.subtitle);
  document.querySelector('.header-actions').style.display = cfg.headerActions ? 'flex' : 'none';

  await cfg.load();
}

// ── Global refresher
async function refreshAll() {
  const refreshIcon = byId('refresh-icon');
  if (refreshIcon) refreshIcon.classList.add('spin');
  try {
    await Promise.all([VIEWS[currentActiveView].refresh(), checkHealth()]);
  } finally {
    const iconAfter = byId('refresh-icon');
    if (iconAfter) iconAfter.classList.remove('spin');
  }
}

// ════════════════════════════════════════════════════════════════════
// Auth (AC-P02-4): 401 setup_required -> setup form, 401 unauthenticated
// -> login form. Password values are never stored or logged; the fields
// are cleared after each attempt.
// ════════════════════════════════════════════════════════════════════

const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 1024;

function setAuthMessage(text, kind) {
  const box = byId('auth-error');
  if (!box) return;
  box.textContent = text ? String(text) : '';
  box.className = `auth-message ${kind === 'info' ? 'info' : 'error'}`;
}

/** Clears data rendered for the previous session so it does not linger in the DOM. */
function clearAppData() {
  ['scans-tbody', 'scans-list-tbody', 'projects-list-tbody', 'users-list-tbody', 'sbom-documents-tbody', 'api-keys-tbody'].forEach((id) => clear(byId(id)));
  apiKeysHasActive = null;
  systemFeatures = null;
  openReports = null;
  const keyName = byId('api-key-name');
  if (keyName) keyName.value = '';
  ['findings-scan-select', 'sbom-scan-select'].forEach((id) => clear(byId(id)));
  const findings = byId('findings-container');
  if (findings) clear(findings).appendChild(emptyState('alert-triangle', TEXT.findings.noScanTitle, TEXT.findings.noScanHint));
  const system = byId('system-status-body');
  if (system) clear(system);
  ['stat-projects', 'stat-packages', 'stat-license-alerts', 'stat-critical-cves'].forEach(resetStat);
  setText('current-user-name', '');
  setText('last-updated', '');
}

function showAuth(mode, notice) {
  const wasInApp = currentUser !== null;
  currentUser = null;
  stopAllPolling();
  closeModal();
  // Session ended (logout or 401 redirect): drop any one-time API key display.
  removeApiKeyReveal();
  if (wasInApp) clearAppData();

  const appRoot = byId('app-root');
  const screen = byId('auth-screen');
  if (!appRoot || !screen) return;
  appRoot.hidden = true;
  screen.hidden = false;

  if (authMode === mode && byId('auth-form')) {
    if (notice) setAuthMessage(notice, 'info');
    return;
  }
  authMode = mode;
  renderAuthForm(screen, mode, notice);
}

function renderAuthForm(screen, mode, notice) {
  const isSetup = mode === 'setup';

  const password = el('input', {
    type: 'password',
    id: 'auth-password',
    name: 'password',
    className: 'form-control',
    autocomplete: isSetup ? 'new-password' : 'current-password',
    maxlength: MAX_PASSWORD_LENGTH,
    required: true,
    'aria-describedby': isSetup ? 'auth-password-hint auth-error' : 'auth-error',
  });
  const confirmField = isSetup
    ? el('input', {
      type: 'password',
      id: 'auth-password-confirm',
      name: 'password-confirm',
      className: 'form-control',
      autocomplete: 'new-password',
      maxlength: MAX_PASSWORD_LENGTH,
      required: true,
      'aria-describedby': 'auth-error',
    })
    : null;
  const message = el('p', { id: 'auth-error', className: 'auth-message error', role: 'alert', 'aria-live': 'assertive' });
  const submit = el('button', { type: 'submit', className: 'btn', id: 'auth-submit' },
    icon(isSetup ? 'key-round' : 'log-in'), isSetup ? TEXT.auth.submitSetup : TEXT.auth.submitLogin);

  const form = el('form', { id: 'auth-form', novalidate: true, 'aria-labelledby': 'auth-title' },
    el('div', { className: 'form-group' },
      el('label', { for: 'auth-password' }, isSetup ? TEXT.auth.newPassword : TEXT.auth.passwordLabel),
      password,
      isSetup ? el('small', { id: 'auth-password-hint', className: 'auth-hint' }, TEXT.auth.passwordHint(MIN_PASSWORD_LENGTH)) : null),
    isSetup
      ? el('div', { className: 'form-group' }, el('label', { for: 'auth-password-confirm' }, TEXT.auth.confirmPassword), confirmField)
      : null,
    message,
    el('div', { className: 'form-actions' }, submit));

  form.addEventListener('submit', fire(async (ev) => {
    ev.preventDefault();
    const value = password.value;

    if (isSetup) {
      if (value.length < MIN_PASSWORD_LENGTH) {
        setAuthMessage(TEXT.auth.tooShort(MIN_PASSWORD_LENGTH), 'error');
        password.focus();
        return;
      }
      if (value.length > MAX_PASSWORD_LENGTH) {
        setAuthMessage(TEXT.auth.tooLong(MAX_PASSWORD_LENGTH), 'error');
        password.focus();
        return;
      }
      if (confirmField && value !== confirmField.value) {
        setAuthMessage(TEXT.auth.mismatch, 'error');
        confirmField.focus();
        return;
      }
    } else if (!value) {
      setAuthMessage(TEXT.auth.required, 'error');
      password.focus();
      return;
    }

    submit.disabled = true;
    setAuthMessage('', 'info');
    try {
      await api(isSetup ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST',
        body: { password: value },
        authRedirect: false,
      });
      // Setup 201 already sets the session cookie (auto login); no separate login call.
      await enterApp();
    } catch (e) {
      if (e && e.authRedirect) return;
      if (e && e.code === 'setup_already_done') {
        showAuth('login', TEXT.auth.alreadySet);
      } else if (!isSetup && e && e.code === 'setup_required') {
        showAuth('setup', TEXT.auth.notSetYet);
      } else {
        setAuthMessage(e && e.message ? e.message : TEXT.auth.requestFailed, 'error');
        password.focus();
      }
    } finally {
      password.value = '';
      if (confirmField) confirmField.value = '';
      submit.disabled = false;
    }
  }));

  const card = el('section', { className: 'auth-card', 'aria-labelledby': 'auth-title' },
    el('div', { className: 'logo-container' },
      el('div', { className: 'logo-icon' }, icon('shield-alert')),
      el('div', { className: 'logo-text' }, TEXT.product)),
    el('h2', { className: 'modal-title', id: 'auth-title' }, isSetup ? TEXT.auth.setupTitle : TEXT.auth.loginTitle),
    el('p', { className: 'modal-subtitle' }, isSetup ? TEXT.auth.setupIntro : TEXT.auth.loginIntro),
    form);

  clear(screen).appendChild(card);
  if (notice) setAuthMessage(notice, 'info');
  refreshIcons();
  password.focus();
}

async function enterApp() {
  const { data } = await api('/api/auth/me');
  currentUser = data || {};
  authMode = null;

  const screen = byId('auth-screen');
  clear(screen).hidden = true;
  byId('app-root').hidden = false;

  const userLabel = currentUser.displayName || currentUser.email || TEXT.auth.signedIn;
  setText('current-user-name', userLabel);
  const nameEl = byId('current-user-name');
  if (nameEl) nameEl.title = currentUser.email ? String(currentUser.email) : '';

  await switchView('dashboard');
}

async function logout() {
  const btn = byId('logout-btn');
  if (btn) btn.disabled = true;
  try {
    await api('/api/auth/logout', { method: 'POST', authRedirect: false });
    // Only this browser session is closed; other sessions are not affected.
    showAuth('login', TEXT.auth.signedOut);
  } catch (e) {
    if (e && e.status === 401) showAuth('login', TEXT.auth.alreadyEnded);
    else reportError(e, TEXT.auth.logoutFailed);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Event wiring (no inline handlers)
function bindHandlers() {
  document.querySelectorAll('#sidebar-nav .nav-item').forEach((btn) => {
    btn.addEventListener('click', fire(() => switchView(btn.dataset.view)));
  });
  byId('refresh-btn').addEventListener('click', fire(refreshAll));
  byId('new-scan-btn').addEventListener('click', fire(openModal));
  byId('empty-new-scan-btn').addEventListener('click', fire(openModal));
  byId('add-project-btn').addEventListener('click', fire(openModal));
  byId('modal-close-btn').addEventListener('click', fire(closeModal));
  byId('modal-cancel-btn').addEventListener('click', fire(closeModal));
  byId('launch-btn').addEventListener('click', fire(launchScan));
  byId('generate-sbom-btn').addEventListener('click', fire(generateNewSbom));
  byId('logout-btn').addEventListener('click', fire(logout));
  byId('findings-scan-select').addEventListener('change', fire(loadScanFindings));
  byId('sbom-scan-select').addEventListener('change', fire(loadScanSboms));
  // No native form submission (REQ-002: a null Origin would be rejected); fetch only.
  byId('api-key-create-form').addEventListener('submit', fire((e) => {
    e.preventDefault();
    return createApiKey();
  }));
  window.addEventListener('pagehide', removeApiKeyReveal);

  // Reports menus are rebuilt with their rows, so their events are delegated (P-38).
  document.addEventListener('click', onReportsClick);
  document.addEventListener('keydown', onReportsKeydown);

  byId('scanModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && byId('scanModal').classList.contains('open')) closeModal();
  });

  // Web URL modal (REQ-008).
  byId('web-modal-close-btn').addEventListener('click', fire(closeWebUrlModal));
  byId('web-modal-cancel-btn').addEventListener('click', fire(closeWebUrlModal));
  byId('web-modal-save-btn').addEventListener('click', fire(saveWebUrl));
  byId('webScanMode').addEventListener('change', syncWebModeWarning);
  byId('webUrlModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeWebUrlModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && byId('webUrlModal').classList.contains('open')) closeWebUrlModal();
  });

  // Repo access token (REQ-009).
  byId('repoPath').addEventListener('input', syncRepoTokenField);
  byId('ecosystems').addEventListener('change', syncEcosystemChoice);
  byId('token-modal-close-btn').addEventListener('click', fire(closeRepoTokenModal));
  byId('token-modal-cancel-btn').addEventListener('click', fire(closeRepoTokenModal));
  byId('token-modal-save-btn').addEventListener('click', fire(saveRepoToken));
  byId('repoTokenModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeRepoTokenModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && byId('repoTokenModal').classList.contains('open')) closeRepoTokenModal();
  });

  // Delegated: per-project buttons carry their values in data-* attributes.
  byId('projects-list-tbody').addEventListener('click', fire((e) => {
    const target = e.target instanceof Element ? e.target.closest('button[data-action]') : null;
    if (!target) return undefined;
    const { action, projectId, projectName } = target.dataset;
    if (action === 'scan-project') return triggerManualScan(projectId, projectName);
    if (action === 'web-scan-project') return triggerWebScan(projectId, projectName);
    if (action === 'edit-web-url') return openWebUrlModal(projectId);
    if (action === 'edit-repo-token') return openRepoTokenModal(projectId);
    return undefined;
  }));
}

// ── Initialize App
async function init() {
  applyTermTitles();
  refreshIcons();
  bindHandlers();
  await checkHealth();
  try {
    await enterApp();
  } catch (e) {
    if (e && e.authRedirect) return; // setup/login form is already shown
    showAuth('login', TEXT.auth.verifyFailed(e && e.message ? e.message : TEXT.common.unknownError));
  }
}

fire(init)();

// Auto-refresh stats/scans every 30 seconds (not while a reports menu is open: the rows would be rebuilt under it)
setInterval(fire(async () => {
  if (currentUser && currentActiveView === 'dashboard' && !openReports) {
    await loadScans();
    await updateStats();
    await loadVulnerabilityDataStatus();
  }
}), 30000);
