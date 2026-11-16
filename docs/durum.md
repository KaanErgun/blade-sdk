# Blade SDK durumu

Bu dosya tek yaşayan durum kaydıdır. Kaynak ve public README ürün/paket sözleşmesini anlatır; test sonucu burada tutulur.

## Tamamlanan kapsam

- SDK geliştirme sürümü `0.1.0-dev`; uygulama ve katalog format sürümü `1`.
- Python standart kütüphanesi ve OpenSSL 3 CLI ile Ed25519 anahtar üretimi, imzalı ZIP `.bladeapp` üretimi/doğrulaması ve statik imzalı katalog.
- Haricî güvenilen public key, manifest/payload hash ve boyut bütünlüğü, canonical JSON, arşiv/path/izin sınırları. Root paketi varsayılan değildir; açık manifest ve `--allow-root` gerekir.
- `/bin/sh` script ve AArch64 ELF giriş doğrulaması; Python API çalıştırma veya kurulum yapmaz; native C kütüphanesi doğrulanmış payload'ı boş staging dizinine güvenli açar. TAR/TAR.GZ açıkça reddedilir.
- MIT lisansı, bağımsız public README, CLI örneği, kısa AGENTS ve sürümlü JSON şemaları.

## Yerel doğrulama

2026-11-15, ilk commit öncesi çalışma ağacı: Python 3.14.7 ve OpenSSL 3.6.4 ile `./scripts/check.sh` **28 test / 1,456 saniye / exit 0** tamamlandı. Gate Python derlemesi, gerçek CLI paket/katalog turu, imza ve payload değişikliği, dış güven anahtarı, root opt-in, arşiv ve boyut sınırları, geçersiz JSON/deflate, ELF/script, mevcut çıktı koruma ve şema sabitlerinin eşliğini sınar. Bu çalışma ağ veya cihaz erişimi yapmaz; test anahtarları geçici dizinlerde üretilir ve temizlenir. Kaynak envanterinde özel anahtar, firmware veya hosted CI dosyası yoktur.

2026-11-16, native çalışma ağacı (henüz commit edilmedi): C11 `-Wall -Wextra -Werror` ve Python derlemesi; **36 test / 2,254 s / exit 0** ve **170 native SemVer/kimlik kontrolü** geçti. Native/Python limit eşliği, geçerli Unicode manifest, dış trust anahtarı, yanlış imza, canonical JSON, imzalı bozuk metadata, ZIP başlık/boyut/yol ve root opt-in sınırları gerçek CLI ile sınandı. Cihaz veya yayın işlemi yapılmadı. Native kaynak `package.c` SHA256 `fbda4b67f159167983dda73b14628db8ff77745672ae0a68a5b4fe1c618a94b0`; `package.h` `6c325ad5132cece9999f5381e565c349592db027421062be47acb7ae9fc1e858`.

2026-11-16 HUD örneği çalışma ağacı (taban `5b8e8bf`, henüz commit edilmedi): Türkçe kaynak dosyası ve `hud` izinli hello paketiyle `./scripts/check.sh` **37 test / 2,486 s / exit 0** ve **170 native kontrol** geçti. Gerçek CLI örnek paket turu yeni iki payload dosyasını doğrular. Kanonik 46 girdilik BLD1 fixture ve public v1 uygulama/owner protokol belgesi eklendi; fixture başlık/UTF-8/izin eşliği SDK kapısında, gerçek C/Android serializer eşliği tüketici kapılarında sınanır. Bu yerel kapı tek başına cihaz kabulü değildir; ardından gelen gerçek OS ölçümleri aşağıda ayrı belirtilmiştir.

2026-11-16, `5b8e8bf` tabanlı native/protokol/HUD/katalog çalışma ağacı: kanonik `./scripts/check.sh` **38 test / 2,213 s**, **170 native kontrol** ve C11 `-Wall -Wextra -Werror` derlemesiyle **exit 0** verdi; toplam komut süresi 3,15 s. İmzalı katalog fixture'ının açık Ed25519 doğrulama anahtarı dar `.gitignore` istisnasıyla kaynak envanterine alındı; temiz checkout bu test için git dışında bir anahtara ihtiyaç duymaz. Özel anahtarlar geçici kalır. Native `package.c` ve `package.h` yukarıdaki SHA256 değerleriyle değişmedi. Commit indexinden alınan temiz, geçici checkout içinde aynı kapı **38 test / 2,233 s**, **170 native kontrol**, toplam **3,130 s / exit 0** verdi; doğrulama çalışma ağacındaki ignored dosyalara bağlı değildir.

2026-11-16, `9cfa48b` tabanlı onay süresi düzeltmesi: yükleme toplam300s/boşta15s/doğrulanmış paket onayı120s sabitleri kanonik fixture'a eklendi;49girdinin C/Android eşliği tüketici kapılarında doğrulanıyor. SDK `./scripts/check.sh` **38 test / 2,321s / exit0** ve170native kontrol geçti. İlk koşuda eski46girdi sayısı varsayımı başarısız oldu; test yeni üç sürenin değerini de açıkça doğrulayacak şekilde güncellendi. Paket biçimi ve kriptografik doğrulayıcı değişmedi.

## Gerçek OS tüketicisi doğrulaması

2026-11-16'da RAM04 üzerinde normal uygulama kurulum/çalıştırma/güncelleme/devre dışı bırakma/kaldırma ve izolasyon akışı; RAM06'da hello uygulamasının gerçek HUD çıktısı doğrulandı. SDK kütüphanesi bu OS akışının paket doğrulama ve extraction bileşenidir; kendi başına süreç izolasyonu veya cihaz yönetimi yapmaz. Güncel cihaz kapsamı, ilgili sürüm/kanıt dosyaları ve kalan kabuller tek yerde [Blade OS durum kaydında](https://github.com/KaanErgun/blade-os/blob/main/docs/durum.md) tutulur. Buradaki yerel kapı kamera, fiziksel dokunma veya telefondan katalog→kurulum kabulünün yerine geçmez.

## Kalan kapsam

- OS yaşam döngüsü `blade-os/userspace/apps` katmanındadır; SDK native doğrulayıcı/extraction API'sini tüketir. Gerçek cihaz kabulü OS durum belgesinde ayrıca tutulur.
- Katalog revision'ına göre kalıcı anti-rollback kararı ve paketlerin indirilmesi tüketicinin sorumluluğudur.
- Normal uygulama SDK örneği yalnız imzalı `hud` izniyle sınırlı stdout metni üretir; uygulamaya owner kamera/yönetim tokenı verilmez. Kamera ve mikrofon normal uygulama izinleri desteklenmez; Swift çalışma zamanı eklenmedi.
- Python 3.10–3.13 ve farklı OpenSSL/platform birleşimleri ayrıca sınanmadı. Telefondan katalog→kurulum uçtan uca kabulü OS/companion çalışmalarında ayrıca izlenir.
- Kaynak deposu `github.com/KaanErgun/blade-sdk`, dal `main`; bu doğrulama sürüm artırma, tag veya push içermez. Yerel commit yayımlanmış ürün sürümü anlamına gelmez.
