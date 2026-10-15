/**
 * Built-in web rule catalogue (REQ-008 AC-P26-5; contract section 4 table).
 * Identifier, category, severity, CWE and OWASP mapping are 1:1 with the
 * contract; the description and recommendation texts live only here.
 */
import { sanitizeText } from '../lib/textSanitize';
import type { WebCategory, WebConfidence, WebFindingDraft, WebSeverity } from './types';

export interface WebRule {
  id: string;
  category: WebCategory;
  severity: WebSeverity;
  title: string;
  description: string;
  recommendation: string;
  cwe: number;
  owasp: string;
}

const rule = (
  id: string,
  category: WebCategory,
  severity: WebSeverity,
  cwe: number,
  owasp: string,
  title: string,
  description: string,
  recommendation: string,
): WebRule => ({ id, category, severity, cwe, owasp, title, description, recommendation });

export const WEB_RULES: Readonly<Record<string, WebRule>> = Object.freeze(
  Object.fromEntries(
    [
      rule('WEB-TLS-001', 'transport', 'high', 319, 'A02:2021', 'Uygulama şifresiz HTTP üzerinden sunuluyor',
        'Sayfa HTTP ile sunuluyor. Ağdaki herkes oturum çerezlerini, parolaları ve sayfa içeriğini okuyabilir veya değiştirebilir.',
        'Uygulamayı yalnız HTTPS üzerinden sunun, HTTP isteklerini 301 ile HTTPS adresine yönlendirin ve HSTS başlığı ekleyin. İç ağdaki sistemler için şirket iç sertifika otoritesinden sertifika alınabilir.'),
      rule('WEB-TLS-002', 'transport', 'medium', 319, 'A02:2021', "HTTP istekleri HTTPS'e yönlendirilmiyor",
        "Aynı adres HTTP ile de içerik döndürüyor. Kullanıcı adresi 'http://' ile yazarsa veya eski bir bağlantıya tıklarsa trafik şifresiz gider.",
        "HTTP (80) üzerindeki tüm istekleri kalıcı (301) olarak HTTPS'e yönlendirin; IIS'te URL Rewrite kuralı veya ASP.NET Core'da UseHttpsRedirection kullanılabilir."),
      rule('WEB-TLS-003', 'transport', 'high', 295, 'A02:2021', 'TLS sertifikası doğrulanamadı',
        'Sunucunun sertifikası güvenilir bir zincire bağlanamadı, süresi dolmuş veya adla eşleşmiyor. Tarayıcılar uyarı gösterir; kullanıcıların uyarıyı geçmeye alışması ortadaki adam saldırısını kolaylaştırır.',
        "Geçerli, adı eşleşen ve süresi dolmamış bir sertifika kurun; ara sertifikaları zincire ekleyin. Şirket iç CA'sı kullanılıyorsa kök sertifikayı bu aracın çalıştığı makinede NODE_EXTRA_CA_CERTS ile tanıtın."),
      rule('WEB-TLS-004', 'transport', 'medium', 298, 'A02:2021', 'TLS sertifikasının süresi 30 gün içinde doluyor',
        'Sertifika yakında geçersiz olacak. Süre dolduğunda kullanıcılar siteye erişemez veya güvenlik uyarısı görür.',
        'Sertifikayı yenileyin ve yenilemeyi otomatikleştirin (ör. ACME/Let’s Encrypt veya iç CA otomasyonu); bitiş tarihleri için takvim uyarısı kurun.'),
      rule('WEB-TLS-005', 'transport', 'medium', 327, 'A02:2021', 'Eski TLS sürümü (1.0/1.1) kabul ediliyor',
        'Sunucu, bilinen zayıflıkları olan ve tarayıcıların desteği bıraktığı TLS 1.0 veya 1.1 ile bağlantı kabul ediyor.',
        "TLS 1.0 ve 1.1'i kapatın, yalnız TLS 1.2 ve 1.3'e izin verin (Windows'ta IIS Crypto veya SCHANNEL kayıt defteri ayarları; nginx/Apache'de ssl_protocols)."),
      rule('WEB-HDR-001', 'headers', 'medium', 319, 'A05:2021', 'Strict-Transport-Security (HSTS) başlığı yok',
        'HSTS olmadan tarayıcı, kullanıcı adresi http:// ile yazdığında ilk isteği şifresiz gönderir; bu ilk istek ele geçirilebilir.',
        "HTTPS yanıtlarına 'Strict-Transport-Security: max-age=31536000; includeSubDomains' ekleyin (ASP.NET Core: app.UseHsts())."),
      rule('WEB-HDR-002', 'headers', 'low', 319, 'A05:2021', 'HSTS süresi kısa (180 günden az)',
        'HSTS max-age değeri kısa; koruma kısa sürede sona erer.',
        'max-age değerini en az 15552000 (180 gün), tercihen 31536000 (1 yıl) yapın.'),
      rule('WEB-HDR-003', 'headers', 'medium', 693, 'A05:2021', 'Content-Security-Policy (CSP) başlığı yok',
        'CSP, sayfada hangi kaynaklardan betik çalışabileceğini sınırlar ve XSS açıklarının etkisini büyük ölçüde azaltır. Başlık yok.',
        "Önce 'Content-Security-Policy-Report-Only' ile başlayıp ihlalleri izleyin, sonra ör. \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'\" gibi bir politikayı zorunlu hale getirin."),
      rule('WEB-HDR-004', 'headers', 'low', 693, 'A05:2021', 'CSP betik kaynaklarına gevşek izin veriyor',
        "CSP var ama betikler için 'unsafe-inline', 'unsafe-eval' veya joker kaynaklara izin veriyor; XSS'e karşı koruma zayıf.",
        "Satır içi betikleri dış dosyalara taşıyın veya nonce/hash kullanın; 'unsafe-eval' ve joker (*, https:, data:) kaynakları kaldırın."),
      rule('WEB-HDR-005', 'headers', 'medium', 1021, 'A05:2021', 'Clickjacking koruması yok',
        'Sayfa başka bir sitenin içine görünmez çerçeve (iframe) olarak gömülebilir; kullanıcı farkında olmadan düğmelere tıklatılabilir.',
        "'X-Frame-Options: SAMEORIGIN' veya CSP'de \"frame-ancestors 'self'\" ekleyin."),
      rule('WEB-HDR-006', 'headers', 'low', 693, 'A05:2021', 'X-Content-Type-Options: nosniff yok',
        'Tarayıcı içerik türünü tahmin edebilir (MIME sniffing); yüklenen bir dosya betik olarak yorumlanabilir.',
        "Tüm yanıtlara 'X-Content-Type-Options: nosniff' ekleyin."),
      rule('WEB-HDR-007', 'headers', 'low', 200, 'A05:2021', 'Referrer-Policy başlığı yok',
        'Sayfadan çıkan bağlantılarda tam adres (sorgu parametreleri dahil) üçüncü taraflara Referer olarak gidebilir.',
        "'Referrer-Policy: strict-origin-when-cross-origin' (veya daha sıkı) ekleyin."),
      rule('WEB-HDR-008', 'headers', 'info', 693, 'A05:2021', 'Permissions-Policy başlığı yok',
        'Kamera, mikrofon, konum gibi tarayıcı özelliklerinin sayfada ve gömülü çerçevelerde kullanımı sınırlanmamış.',
        "Kullanılmayan özellikleri kapatın, ör. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."),
      rule('WEB-INF-001', 'disclosure', 'low', 200, 'A05:2021', 'Sunucu yazılımı ve sürümü ifşa ediliyor',
        'Server başlığı yazılım adını ve sürümünü gösteriyor; saldırgan bilinen açıkları hedeflemek için bu bilgiyi kullanabilir.',
        "Server başlığını kaldırın veya sürümsüz hale getirin (IIS: removeServerHeader; nginx: server_tokens off; Kestrel: AddServerHeader = false)."),
      rule('WEB-INF-002', 'disclosure', 'low', 200, 'A05:2021', 'X-Powered-By başlığı teknoloji bilgisi ifşa ediyor',
        'X-Powered-By başlığı kullanılan çatıyı/sürümü gösteriyor.',
        "X-Powered-By başlığını kaldırın (IIS: web.config <customHeaders><remove name=\"X-Powered-By\"/>; Express: app.disable('x-powered-by'))."),
      rule('WEB-INF-003', 'disclosure', 'low', 200, 'A05:2021', 'ASP.NET sürüm başlıkları ifşa ediliyor',
        'X-AspNet-Version veya X-AspNetMvc-Version başlığı .NET/MVC sürümünü gösteriyor.',
        'web.config\'te <httpRuntime enableVersionHeader="false" /> ayarlayın ve Global.asax\'ta MvcHandler.DisableMvcResponseHeader = true yapın.'),
      rule('WEB-INF-004', 'disclosure', 'medium', 209, 'A05:2021', 'Ayrıntılı hata sayfası veya yığın izi gösteriliyor',
        'Hata durumunda sunucu iç ayrıntıları (yığın izi, sürüm, dosya yolları, SQL hatası) gösteriyor. Bu bilgi saldırganın işini kolaylaştırır.',
        'Canlı ortamda özel hata sayfası kullanın (ASP.NET: customErrors mode="RemoteOnly"/"On"; ASP.NET Core: geliştirici hata sayfasını yalnız Development ortamında açın) ve ayrıntıları yalnız sunucu loguna yazın.'),
      rule('WEB-INF-005', 'disclosure', 'medium', 548, 'A05:2021', 'Dizin listeleme açık',
        'Bir klasörün içeriği listelenebiliyor; yedek, yapılandırma veya kaynak dosyaları bulunabilir.',
        "Dizin listelemeyi kapatın (IIS: directoryBrowse enabled=\"false\"; Apache: Options -Indexes; nginx: autoindex off)."),
      rule('WEB-CKE-001', 'cookies', 'medium', 614, 'A05:2021', 'Çerez Secure bayrağı olmadan gönderiliyor',
        'Secure bayrağı olmayan çerez, şifresiz HTTP isteklerinde de gönderilir ve ele geçirilebilir.',
        "HTTPS sitelerinde tüm çerezlere Secure ekleyin (ASP.NET: <httpCookies requireSSL=\"true\"/>; ASP.NET Core: CookieSecurePolicy.Always)."),
      rule('WEB-CKE-002', 'cookies', 'low', 1004, 'A05:2021', 'Çerez HttpOnly bayrağı olmadan gönderiliyor',
        'HttpOnly olmayan çerez JavaScript ile okunabilir; bir XSS açığında oturum çalınabilir.',
        "Oturum ve kimlik çerezlerine HttpOnly ekleyin (ASP.NET: <httpCookies httpOnlyCookies=\"true\"/>; ASP.NET Core: HttpOnly = HttpOnlyPolicy.Always)."),
      rule('WEB-CKE-003', 'cookies', 'low', 1275, 'A01:2021', 'Çerezde SameSite özniteliği yok',
        'SameSite belirtilmemiş; çerez başka sitelerden gelen isteklerle gönderilebilir (CSRF riski, tarayıcı varsayılanına bağlı).',
        "Çerezlere 'SameSite=Lax' (veya uygun ise Strict) ekleyin."),
      rule('WEB-CORS-001', 'cors', 'high', 942, 'A05:2021', 'CORS her kaynağa kimlik bilgisiyle izin veriyor',
        'Sunucu, isteği yapan herhangi bir kaynağı (Origin) Access-Control-Allow-Origin olarak geri yansıtıyor ve kimlik bilgilerine izin veriyor. Kötü niyetli bir site, oturumu açık kullanıcı adına bu uygulamadan veri okuyabilir.',
        "İzin verilen kaynakları sabit bir listeyle sınırlayın; 'null' kaynağına izin vermeyin; Access-Control-Allow-Credentials yalnız güvenilen kaynaklar için gönderilsin."),
      rule('WEB-CORS-002', 'cors', 'low', 942, 'A05:2021', 'CORS her kaynağa izin veriyor',
        'Sunucu her kaynağa (Origin) kimlik bilgisi olmadan okuma izni veriyor. Herkese açık veri için sorun değildir; iç ağdaki veriler için dışarıya sızıntı yolu olabilir.',
        'Yanıtın gerçekten herkese açık olması gerekmiyorsa CORS iznini bilinen kaynaklarla sınırlayın.'),
      rule('WEB-EXP-001', 'exposure', 'high', 527, 'A05:2021', '.git klasörü erişilebilir',
        "Web kökünde .git klasörü sunuluyor. Saldırgan uygulamanın tüm kaynak kodunu ve geçmişini (içine girmiş parolalar dahil) indirebilir.",
        ".git klasörünü yayın paketinden çıkarın ve sunucuda nokta ile başlayan klasörlere erişimi engelleyin. Depoda parola varsa değiştirin."),
      rule('WEB-EXP-002', 'exposure', 'high', 538, 'A05:2021', '.env dosyası erişilebilir',
        '.env dosyası indirilebiliyor. Bu dosyalar genellikle veritabanı parolaları ve API anahtarları içerir.',
        '.env dosyasını web kökünden kaldırın, erişimi sunucu yapılandırmasıyla engelleyin ve içindeki tüm gizli değerleri değiştirin.'),
      rule('WEB-EXP-003', 'exposure', 'high', 538, 'A05:2021', '.NET yapılandırma dosyası erişilebilir',
        'appsettings.json veya web.config indirilebiliyor. Bağlantı dizeleri, anahtarlar ve iç adresler açığa çıkabilir.',
        'Yapılandırma dosyalarının statik dosya olarak sunulmadığından emin olun (ASP.NET Core: dosyalar wwwroot dışında olmalı; IIS: requestFiltering ile .json/.config engeli). İçerdiği gizli değerleri değiştirin.'),
      rule('WEB-EXP-004', 'exposure', 'high', 215, 'A05:2021', 'ASP.NET tanılama sayfası açık',
        'ELMAH (elmah.axd) veya ASP.NET izleme (trace.axd) sayfası uzaktan erişilebilir. Bu sayfalar istek ayrıntılarını, çerezleri ve hata yığınlarını gösterir.',
        'Canlı ortamda trace\'i kapatın (<trace enabled="false"/>) ve ELMAH için allowRemoteAccess="false" veya yetkilendirme ekleyin.'),
      rule('WEB-EXP-005', 'exposure', 'medium', 527, 'A05:2021', 'Sürüm kontrol veya sistem meta dosyası erişilebilir',
        'Sürüm kontrol (.svn, .hg) veya işletim sistemi meta dosyası (.DS_Store) sunuluyor; dosya ve klasör yapısı ortaya çıkabilir.',
        'Bu dosyaları yayın paketinden çıkarın ve nokta ile başlayan yollara erişimi engelleyin.'),
      rule('WEB-EXP-006', 'exposure', 'medium', 200, 'A05:2021', 'Sunucu durum/bilgi sayfası açık',
        'server-status, server-info veya phpinfo gibi bir sayfa sunucu yapılandırmasını, modülleri ve iç adresleri gösteriyor.',
        'Bu sayfaları kapatın veya yalnız yönetim ağından erişilebilir yapın.'),
      rule('WEB-EXP-007', 'exposure', 'low', 200, 'A05:2021', 'API dokümantasyonu herkese açık',
        'Swagger/OpenAPI dokümanı kimlik doğrulamasız erişilebilir; tüm uç noktalar ve parametreler listeleniyor.',
        'Canlı ortamda Swagger arayüzünü kapatın veya kimlik doğrulama arkasına alın (ASP.NET Core: UseSwagger/UseSwaggerUI yalnız Development ortamında).'),
      rule('WEB-CNT-001', 'content', 'medium', 319, 'A02:2021', 'HTTPS sayfası HTTP üzerinden içerik yüklüyor (karma içerik)',
        'HTTPS sayfası betik, stil veya çerçeveyi şifresiz HTTP ile yüklüyor; bu içerik yolda değiştirilip sayfanın tamamı ele geçirilebilir. Tarayıcılar çoğunu engeller ve sayfa bozulur.',
        "Tüm kaynak adreslerini https:// veya göreli yola çevirin; CSP'ye 'upgrade-insecure-requests' ekleyin."),
      rule('WEB-CNT-002', 'content', 'low', 353, 'A08:2021', 'Harici betiklerde alt kaynak bütünlüğü (SRI) yok',
        'Başka sunuculardan (CDN) yüklenen betiklerde integrity özniteliği yok; CDN ele geçirilirse değiştirilmiş betik sayfada çalışır.',
        "Harici <script> etiketlerine integrity=\"sha384-…\" ve crossorigin=\"anonymous\" ekleyin veya betikleri kendi sunucunuzdan sunun."),
      rule('WEB-CNT-003', 'content', 'medium', 319, 'A02:2021', 'Form verisi HTTP üzerinden gönderiliyor',
        'HTTPS sayfasındaki bir form verisini http:// adresine gönderiyor; girilen bilgiler (parola dahil) şifresiz iletilir.',
        "Form action adreslerini https:// veya göreli yol yapın."),
      rule('WEB-LIB-001', 'components', 'medium', 1104, 'A06:2021', 'Bilinen açığı olan JavaScript kütüphanesi',
        'Sayfada kullanılan bir JavaScript kütüphanesinin bu sürümünde yayımlanmış bir güvenlik açığı var.',
        'Kütüphaneyi açığın düzeltildiği sürüme veya en güncel kararlı sürüme yükseltin; kullanılmıyorsa sayfadan kaldırın.'),
    ].map((r) => [r.id, Object.freeze(r)]),
  ),
);

export const EVIDENCE_MAX_CHARS = 500;
const TEXT_MAX_CHARS = 4000;

/** Single-line, control-free text cut to `max` code points (contract 2.3, AC-P26-8). */
export function cleanText(value: string | null | undefined, max: number): string | null {
  if (value === null || value === undefined) return null;
  const single = sanitizeText(String(value)).replace(/[\n\t]+/g, ' ').trim();
  if (single.length === 0) return null;
  const chars = Array.from(single);
  return chars.length <= max ? single : `${chars.slice(0, Math.max(0, max - 1)).join('')}…`;
}

/** Multi-line text (ZAP description/solution) cleaned and cut. */
export function cleanBlock(value: string | null | undefined, max: number = TEXT_MAX_CHARS): string {
  const cleaned = sanitizeText(String(value ?? '')).trim();
  const chars = Array.from(cleaned);
  return chars.length <= max ? cleaned : `${chars.slice(0, Math.max(0, max - 1)).join('')}…`;
}

export interface FindingOptions {
  location: string | null;
  evidence?: string | null;
  /** Fingerprint key; default = location (or rule id). */
  key?: string;
  severity?: WebSeverity;
  confidence?: WebConfidence;
  componentName?: string | null;
  componentVersion?: string | null;
  fixedVersion?: string | null;
  cvssScore?: number | null;
}

/** A finding draft of a built-in rule. Throws on an unknown rule id (programming error). */
export function finding(ruleId: string, options: FindingOptions): WebFindingDraft {
  const r = WEB_RULES[ruleId];
  if (!r) throw new Error(`Unknown web rule ${ruleId}`);
  return {
    ruleId: r.id,
    source: 'builtin',
    category: r.category,
    severity: options.severity ?? r.severity,
    confidence: options.confidence ?? 'high',
    title: r.title,
    description: r.description,
    recommendation: r.recommendation,
    location: options.location,
    evidence: cleanText(options.evidence ?? null, EVIDENCE_MAX_CHARS),
    cweId: r.cwe,
    owasp: r.owasp,
    key: options.key ?? options.location ?? r.id,
    componentName: options.componentName ?? null,
    componentVersion: options.componentVersion ?? null,
    fixedVersion: options.fixedVersion ?? null,
    cvssScore: options.cvssScore ?? null,
  };
}
