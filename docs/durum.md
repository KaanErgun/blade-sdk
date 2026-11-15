# Blade SDK durumu

Bu dosya tek yaşayan durum kaydıdır. Kaynak ve public README ürün/paket sözleşmesini anlatır; test sonucu burada tutulur.

## Tamamlanan kapsam

- SDK geliştirme sürümü `0.1.0-dev`; uygulama ve katalog format sürümü `1`.
- Python standart kütüphanesi ve OpenSSL 3 CLI ile Ed25519 anahtar üretimi, imzalı ZIP `.bladeapp` üretimi/doğrulaması ve statik imzalı katalog.
- Haricî güvenilen public key, manifest/payload hash ve boyut bütünlüğü, canonical JSON, arşiv/path/izin sınırları. Root paketi varsayılan değildir; açık manifest ve `--allow-root` gerekir.
- `/bin/sh` script ve AArch64 ELF giriş doğrulaması; çalıştırma, extraction veya kurulum yapılmaz. TAR/TAR.GZ açıkça reddedilir.
- MIT lisansı, bağımsız public README, CLI örneği, kısa AGENTS ve sürümlü JSON şemaları.

## Yerel doğrulama

2026-11-15, ilk commit öncesi çalışma ağacı: Python 3.14.7 ve OpenSSL 3.6.4 ile `./scripts/check.sh` **28 test / 1,456 saniye / exit 0** tamamlandı. Gate Python derlemesi, gerçek CLI paket/katalog turu, imza ve payload değişikliği, dış güven anahtarı, root opt-in, arşiv ve boyut sınırları, geçersiz JSON/deflate, ELF/script, mevcut çıktı koruma ve şema sabitlerinin eşliğini sınar. Bu çalışma ağ veya cihaz erişimi yapmaz; test anahtarları geçici dizinlerde üretilir ve temizlenir. Kaynak envanterinde özel anahtar, firmware veya hosted CI dosyası yoktur.

## Kalan kapsam

- OS kurucusu: güvenli extraction, sahiplik/izolasyon, izin verme, atomik etkinleştirme, güncelleme geri dönüşü ve kaldırma/veri koruma davranışı SDK dışında uygulanacak.
- Katalog revision'ına göre kalıcı anti-rollback kararı ve paketlerin indirilmesi tüketicinin sorumluluğudur.
- Ölçülmüş cihaz API'si olmadığı için kamera/HUD RPC endpoint'i, Android/Swift istemci çatısı veya market backend'i üretilmedi.
- Python 3.10–3.13 ve farklı OpenSSL/platform birleşimleri ayrıca sınanmadı. Gerçek Blade üzerinde paket kurulumu veya çalıştırılması doğrulanmadı.
- Git init/remote/push ve public depo doğrulaması koordinatör tarafından yürütülür; yerel kaynak hazır olması yayımlanmış sürüm anlamına gelmez.
