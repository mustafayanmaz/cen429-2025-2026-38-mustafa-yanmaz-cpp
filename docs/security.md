# Project Security Model

## 🔒 Güvenlik Dokümantasyonu

PetCare uygulaması kapsamlı bir güvenlik modeli ile tasarlanmıştır. Detaylı güvenlik dokümantasyonuna aşağıdaki bağlantılardan ulaşabilirsiniz:

### 📚 Güvenlik Belgeleri

| Belge | Açıklama |
|-------|----------|
| [Güvenlik Raporu](security/report.md) | 15 güvenlik gereksiniminin uygulama analizi |
| [Varlık Yönetimi](security/assets.md) | Tüm varlıkların kapsamlı kataloğu |
| [Güvenlik Sertifikasyonu](security/security_certification.md) | ETSI, EMV, OWASP uyumluluk analizi |
| [Penetrasyon Test Planı](security/penetration_test_plan.md) | Test senaryoları ve sonuçları |

---

## 🛡️ Güvenlik Özellikleri Özeti

### 1. Kimlik Doğrulama ve Oturum Yönetimi
- ✅ Şifrelenmiş parola depolama (XOR + PBKDF2)
- ✅ Device-bound session management
- ✅ Cihaz parmak izi doğrulama

### 2. Veri Şifreleme
- ✅ Whitebox AES-128 (cascade: AES-DES-AES)
- ✅ HMAC-SHA256 bütünlük kontrolü
- ✅ Database encryption at rest

### 3. Runtime Protection (RASP)
- ✅ Anti-debugging mekanizmaları
- ✅ Control Flow Integrity (CFI)
- ✅ Tamper detection
- ✅ Hook detection

### 4. Kod Sertleştirme
- ✅ Opaque predicates
- ✅ Mixed Boolean-Arithmetic (MBA)
- ✅ Dead code injection
- ✅ String obfuscation

### 5. Bellek Güvenliği
- ✅ Secure memory allocation
- ✅ Automatic memory wiping (SecureAutoWipe)
- ✅ Guard pages

### 6. Varlık Yönetimi
- ✅ 14 farklı varlık kategorisi dokümante edildi
- ✅ Her varlık için 9 özellik tanımlandı
- ✅ Koruma şemaları (Gizlilik, Bütünlük, Kimlik Doğrulama)

---

## 📊 Güvenlik Metrikleri

| Metrik | Değer |
|--------|-------|
| Toplam Güvenlik Testi | 181 |
| Geçen Test | 181 (100%) |
| Kod Kapsama | >70% |
| OWASP ASVS Uyumluluk | Level 2 |
| ETSI EN 303 645 | 13/13 provision |

---

## 🔗 İlgili Dosyalar

### Header Dosyaları
- `src/utility/header/assetProtection.h` - Varlık koruma API
- `src/utility/header/whiteboxCrypto.h` - Whitebox şifreleme
- `src/utility/header/raspSecurity.h` - RASP özellikleri
- `src/utility/header/secureMemory.h` - Güvenli bellek
- `src/utility/header/codeObfuscation.h` - Kod sertleştirme

### Kaynak Dosyaları
- `src/utility/src/assetProtection.cpp` - Varlık koruma implementasyonu
- `src/utility/src/whiteboxCrypto.cpp` - Şifreleme implementasyonu
- `src/utility/src/raspSecurity.cpp` - RASP implementasyonu
- `src/utility/src/secureMemory.cpp` - Bellek yönetimi
- `src/utility/src/securityTest.cpp` - Güvenlik test framework

### Test Dosyaları
- `src/tests/utility/asset_protection_test.cpp`
- `src/tests/utility/security_test_test.cpp`
- `src/tests/utility/rasp_security_test.cpp`
