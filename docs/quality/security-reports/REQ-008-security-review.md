# REQ-008 Güvenlik İncelemesi — Web (URL) güvenlik taraması

- **Tarih:** 2026-10-15
- **Kapsam:** branch `req-008-web-guvenlik-taramasi`; `src/webscan/**`,
  worker web hattı, proje/tarama controller değişiklikleri, web bulguları ve
  çıktı uç noktaları, `public/app.js` web arayüzü, `009_web_scan`,
  yeniden kontrol/durum kapsam filtreleri, `guardProxyTunnelErrors`.
- **Yöntem:** Uygulamayı yazandan bağımsız bir inceleme ajanı (salt okuma) +
  yerel loopback sunucularla doğrulama betikleri. Bulgular kodla
  doğrulanmadıysa atıldı. Düzeltmelerden sonra her bulgu bir regresyon
  testiyle kilitlendi.

## Bulgular ve durum

| ID | Önem | Bulgu | Durum | Kanıt (test) |
| --- | --- | --- | --- | --- |
| H-1 | Yüksek | Hedef sitenin döndürdüğü gövdelerde karesel regex'ler (`(^|\n)\s*at …`, `<(script…)[^>]*>`, `<!--[\s\S]*?-->`): 2 MiB'lık gövde tek süreçli uygulamayı dakikalar–saatler boyunca dondurabiliyordu (200 k karakterde 59 sn ölçüldü). | **Düzeltildi:** HTML tarama `indexOf` tabanlı doğrusal tarayıcı, etiket başına 8 KiB öznitelik sınırı; Java deseni `m` bayrağı + sınırlı girinti. 2 MiB saldırgan girdiler artık < 150 ms. | `tests/unit/webScanHardening.test.ts` (H-1) |
| M-2 | Orta | ZAP izin listesine bağlı değildi: `accessUrl followRedirects=true` ve `inScopeOnly=false` ile açık yönlendirme üzerinden ZAP hostundan kör SSRF. | **Düzeltildi:** her taramada hedef hostla sınırlı ZAP bağlamı, spider `contextName`, aktif tarama `inScopeOnly=true` + `contextId`, tohum `followRedirects=false`. README: ZAP 127.0.0.1'e bağlı ve yalıtılmış olmalı. | `tests/integration/webScan.test.ts` (P-28), `webScanHardening` (M-2) |
| M-3 | Orta | Pasif modda ZAP spider'ı varsayılan ayarlarla form gönderebilirdi. | **Düzeltildi:** `spider/action/setOptionProcessForm` ve `setOptionPostForm` = false. | `webScan.test.ts` (P-28) |
| M-4 | Orta | ZAP kilidini bekleyen iş, süre sınırını ve kapanışı dinlemiyordu. | **Düzeltildi:** bekleme iş sinyaliyle yarışır; iptal edilen iş sıradaki işi bekletmez. | `webScanHardening` (M-4) |
| L-5 | Düşük | Ana sayfa yönlendirmesi yalnız host adına bakıyordu; hedef site port/şema seçebiliyordu. | **Düzeltildi:** aynı origin veya varsayılan portlarda http ↔ https. | `webScanHardening` (L-5) |
| L-6 | Düşük | İzin listesi yalnız adla eşleşiyordu; joker altındaki bir DNS kaydı (veya rebinding) loopback/meta veri adresine yönlendirebilirdi. | **Düzeltildi:** korumalı `lookup`: loopback, link-local, belirsiz adresler açıkça listelenmedikçe reddedilir; özel ağlar serbest. | `webScanHardening` (L-6) |
| L-7 | Düşük | `NODE_TLS_REJECT_UNAUTHORIZED=0` ortamdan miras alınırsa sertifika doğrulaması sessizce kapanırdı. | **Düzeltildi:** ajanlarda ve isteklerde `rejectUnauthorized: true` açıkça. | statik: `tests/security/f4Static.test.ts` (`rejectUnauthorized: false` yalnız `tlsProbe.ts`) |
| L-8 | Düşük | Yeniden denenen web taraması tamamlanınca eski hata metni kalıyor, `[web]`/`[zap]` satırları kayboluyordu. | **Düzeltildi:** tamamlanan web taramasında `error_message` o denemenin satırlarıdır. | `webScan.test.ts` (AC-P26-1…9, AC-P28-3) |
| I-9 | Bilgi | Hedef URL'nin sorgu dizesi PDF/arayüzde görünüyordu. | **Düzeltildi:** PDF ve arayüz sorgu dizesini göstermez (API ham değeri döner). | — |
| X-1 | Yüksek (mevcut kod) | Node 22.22 `proxyEnv`: vekil `CONNECT`'i reddedince (ör. 403) ham soket dinleyicisiz kalıyor, gecikmeli `ECONNRESET` `uncaughtException` olup **uygulamayı kapatıyordu**. Kurumsal vekil arkasında OSV/kayıt defteri isteği engellenen her taramayı etkiler. Uçtan uca demo sırasında bulundu. | **Düzeltildi:** `guardProxyTunnelErrors` (`safeHttpClient` ve prob istemcisi vekil ajanları). | `tests/unit/webScanZap.test.ts` (guard) |
| X-2 | Orta (yeni etkileşim) | Günlük CVE yeniden kontrolü ve durum paneli "projenin son tamamlanan taraması"nı kullanıyordu; bir web taraması bağımlılık taramasını kapsam dışına itebilirdi. | **Düzeltildi:** `scan_kind = 'dependency'` filtresi (`recheck.ts`, `status.ts`). | `webScan.test.ts` (recheck/status scope) |

## Kabul edilen kalan riskler

- **ZAP hostunun ağ konumu:** ZAP kendi hostundan istek atar; araç kapsamı ve
  sonuçları denetler, ZAP'ın ağ erişimini denetleyemez. README ZAP'ın
  127.0.0.1'e bağlanıp yalıtılmasını ister.
- **Aktif tarama:** Kullanıcı rızasıyla (proje `active`) gerçek saldırı
  istekleri gönderir; arayüz uyarısı ve README notu vardır.
- **Aynı ZAP'ı paylaşan iki çalışma zamanı** birbirinin oturumunu sıfırlar
  (tek örnek kilidi zaten tek uygulama örneğine izin verir).
- **Vekil üzerinden giden HTTPS** isteklerinde adres kuralı (L-6) vekilde
  uygulanamaz; host adı izin listesi kuralı geçerlidir.

## Sağlam bulunanlar

URL kuralları (kullanıcı bilgisi, boş `@`, parça, ondalık/onaltılık IPv4,
sondaki nokta), her istekte izin listesi denetimi (yönlendirme, `<base href>`,
betik adresleri, TLS yoklaması), gövde/sıkıştırma bombası sınırları (500 MiB
gzip 2 MiB'da kesildi), sır sızıntısı yok (çerez değerleri, yapılandırma
içerikleri, ZAP anahtarı), arayüz yalnız metin düğümü kullanır, CSV formül
kalkanı, parametreli SQL, RBAC + CSRF (PATCH dahil), bağımlılık özellikleri
`scan_kind` ile ayrılmış, yazma çiti, `rejectUnauthorized: false` yalnız
eski protokol el sıkışmasında.
