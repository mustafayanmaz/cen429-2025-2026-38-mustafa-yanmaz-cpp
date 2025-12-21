# Developer Guide

## PetCare Application - Geliştirici Kılavuzu

**Versiyon:** 1.0  
**Son Güncelleme:** 21 Aralık 2025

---

## 👥 Proje Ekibi

### Danışman

| | Bilgi |
|---|---|
| **İsim** | Dr. Uğur CORUH |
| **Rol** | R&D Engineer and System Architecture |
| **Kurum** | CORUH ARGE VE TEKNOLOJI |

### Geliştirici Ekibi

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/mustafayanmaz">
        <img src="https://avatars.githubusercontent.com/u/114070977?v=4" width="100px;" alt="Mustafa Yanmaz"/><br />
        <sub><b>Mustafa Yanmaz</b></sub>
      </a><br/>
      <sub>Full Stack Developer -
            Test Engineer - Application Security Engineer</sub>
    </td>
    <td align="center">
      <a href="https://github.com/onurcakirtr">
        <img src="https://avatars.githubusercontent.com/onurcakirtr" width="100px;" alt="Onur Çakır"/><br />
        <sub><b>Onur Çakır</b></sub>
      </a><br/>
      <sub>Security Software Developer - DevOps Engineer</sub>
    </td>
    <td align="center">
      <a href="https://github.com/AliTopcuu">
        <img src="https://avatars.githubusercontent.com/u/114070829?v=4" width="100px;" alt="Ali Ufuktan Topçu"/><br />
        <sub><b>Ali Ufuktan Topçu</b></sub>
      </a><br/>
      <sub>A Random Guy</sub>
    </td>
    <td align="center">
      <a href="https://github.com/mrfiratatalay">
        <img src="https://avatars.githubusercontent.com/mrfiratatalay" width="100px;" alt="Fırat Atalay"/><br />
        <sub><b>Fırat Atalay</b></sub>
      </a><br/>
      <sub>QA Engineer</sub>
    </td>
  </tr>
</table>

---

## 🛠️ Geliştirme Ortamı Kurulumu

### Gereksinimler

| Araç | Minimum Versiyon | Açıklama |
|------|------------------|----------|
| **Visual Studio** | 2019+ | MSVC derleyici |
| **CMake** | 3.12+ | Build sistemi |
| **Git** | 2.30+ | Versiyon kontrolü |
| **Python** | 3.8+ | Script'ler için |
| **Doxygen** | 1.9+ | Dokümantasyon |

### Windows Kurulum Adımları

#### 1. Repository'yi Klonlayın

```bash
git clone https://github.com/[username]/cen429-2025-2026-38-mustafa-yanmaz-cpp.git
cd cen429-2025-2026-38-mustafa-yanmaz-cpp
```

#### 2. Git Hook'ları Yapılandırın

```bash
.\1-configure-git-hooks.bat
```

#### 3. Submodule'leri Başlatın

```bash
.\0-init-submodules.bat
```

#### 4. Geliştirme Ortamını Kurun

```bash
.\4-install-windows-enviroment.bat
```

Bu script şunları yükler:
- Chocolatey paket yöneticisi
- Visual Studio Build Tools
- CMake
- Doxygen
- Python bağımlılıkları

---

## 🔨 Build İşlemleri

### Windows Build

#### Debug Build

```bash
cd build_win
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Debug
```

#### Release Build

```bash
.\7-build-app-windows.bat
```

Veya manuel olarak:

```bash
cd build_win
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Linux Build (WSL)

```bash
./7-build-app-linux.sh
```

### Build Çıktıları

| Çıktı | Konum | Açıklama |
|-------|-------|----------|
| `petcareapp.exe` | `build_win/build/Release/` | Ana uygulama |
| `petcare_tests.exe` | `build_win/build/Release/` | Petcare testleri |
| `utility_tests.exe` | `build_win/build/Release/` | Utility testleri |
| `petcare.lib` | `build_win/build/Release/` | Static library |
| `utility.lib` | `build_win/build/Release/` | Utility library |

---

## 🧪 Test Çalıştırma

### Tüm Testleri Çalıştır

```bash
.\8-build-test-windows.bat
```

### Belirli Test Suite'i Çalıştır

```bash
# Utility testleri
.\build_win\build\Release\utility_tests.exe

# Petcare testleri
.\build_win\build\Release\petcare_tests.exe
```

### Belirli Test Filtresi

```bash
# Sadece RASP testleri
.\build_win\build\Release\utility_tests.exe --gtest_filter="RASP*"

# Sadece başarısız testleri göster
.\build_win\build\Release\petcare_tests.exe --gtest_filter="*" --gtest_brief=1
```

### Test Kapsamı

```bash
# Coverage raporu oluştur
OpenCppCoverage --sources src\ --export_type=cobertura:coverage.xml -- .\build_win\build\Release\utility_tests.exe
```

---

## 📁 Proje Yapısı

```
cen429-2025-2026-38-mustafa-yanmaz-cpp/
├── 📂 src/
│   ├── 📂 utility/              # Güvenlik kütüphanesi
│   │   ├── 📂 header/
│   │   │   ├── assetProtection.h
│   │   │   ├── codeObfuscation.h
│   │   │   ├── commonTypes.h
│   │   │   ├── raspSecurity.h
│   │   │   ├── secureMemory.h
│   │   │   ├── securityTest.h
│   │   │   ├── sha256.h
│   │   │   └── whiteboxCrypto.h
│   │   └── 📂 src/
│   │       └── [implementasyonlar]
│   │
│   ├── 📂 petcare/              # İş mantığı
│   │   ├── 📂 header/
│   │   │   ├── petcare.h
│   │   │   ├── database.h
│   │   │   └── methods.h
│   │   └── 📂 src/
│   │       └── [implementasyonlar]
│   │
│   ├── 📂 petcareapp/           # Ana uygulama
│   │   └── 📂 src/
│   │       └── petcareapp.cpp
│   │
│   └── 📂 tests/                # Test dosyaları
│       ├── 📂 utility/
│       │   ├── asset_protection_test.cpp
│       │   ├── rasp_security_test.cpp
│       │   ├── secure_memory_test.cpp
│       │   ├── security_test_test.cpp
│       │   ├── utility_test.cpp
│       │   └── whitebox_crypto_test.cpp
│       └── 📂 petcare/
│           ├── petcare_test.cpp
│           └── database_encryption_test.cpp
│
├── 📂 docs/                     # Dokümantasyon
│   ├── index.md
│   ├── architecture.md
│   ├── security.md
│   ├── developers.md
│   └── 📂 security/
│       ├── report.md
│       ├── assets.md
│       ├── security_certification.md
│       └── penetration_test_plan.md
│
├── 📂 external/                 # Harici kütüphaneler
│   └── sqlite3/
│
├── 📂 build_win/                # Windows build çıktıları
├── 📂 build_linux/              # Linux build çıktıları
│
├── CMakeLists.txt              # Ana CMake dosyası
├── mkdocs.yml                  # Dokümantasyon yapılandırması
└── README.md                   # Proje README
```

---

## 📝 Kodlama Standartları

### Genel Kurallar

| Kural | Açıklama |
|-------|----------|
| **İsimlendirme** | snake_case (fonksiyonlar), camelCase (değişkenler) |
| **Girinti** | 4 boşluk (tab kullanılmaz) |
| **Satır Uzunluğu** | Maksimum 100 karakter |
| **Dosya Kodlaması** | UTF-8 |
| **Satır Sonu** | LF (Unix style) |

### C++ Stil Kılavuzu

```cpp
/**
 * @brief Fonksiyon açıklaması
 * @param param1 Parametre açıklaması
 * @return Dönüş değeri açıklaması
 */
int function_name(int param1, const char* param2) {
    // Değişken tanımları en üstte
    int result = 0;
    
    // Guard clause kullan
    if (!param2) {
        return -1;
    }
    
    // Ana mantık
    for (int i = 0; i < param1; i++) {
        result += process(param2[i]);
    }
    
    return result;
}
```

### Header Guard Formatı

```cpp
#ifndef MODULE_NAME_H
#define MODULE_NAME_H

// İçerik

#endif // MODULE_NAME_H
```

### Astyle Formatı

Proje otomatik kod formatlama için Astyle kullanır:

```bash
.\5-format-code.bat
```

Konfigürasyon: `astyle-options.txt`

---

## 🔒 Güvenlik Geliştirme Kılavuzu

### Güvenli Kod Yazma Kuralları

#### 1. Bellek Yönetimi

```cpp
// ✅ Doğru: Güvenli bellek kullanımı
SecureAutoWipe<char[256]> password;
// ... kullanım
// Otomatik olarak temizlenir

// ❌ Yanlış: Manuel yönetim
char* password = (char*)malloc(256);
// ... kullanım
free(password);  // Bellek temizlenmedi!
```

#### 2. String İşlemleri

```cpp
// ✅ Doğru: Güvenli string kopyalama
char buffer[64];
strncpy(buffer, source, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';

// ❌ Yanlış: Buffer overflow riski
char buffer[64];
strcpy(buffer, source);  // Tehlikeli!
```

#### 3. Obfuscation Kullanımı

```cpp
// Hassas işlemler için obfuscation kullan
if (opaque_true(rand())) {
    // Gerçek işlem
    result = obf_add(a, b);
}

// Dead code injection
inject_dead_code(3);
```

#### 4. RASP Entegrasyonu

```cpp
// Uygulama başlangıcında
rasp_init();
if (rasp_comprehensive_check() != RASP_SUCCESS) {
    // Güvenli çıkış
    exit(1);
}

// Kritik işlemlerden önce
if (rasp_detect_debugger(NULL) == RASP_SUCCESS) {
    // Debugger algılandı, güvenli mod
}
```

---

## 🧪 Test Yazma Kılavuzu

### Google Test Yapısı

```cpp
#include <gtest/gtest.h>

// Test Fixture
class MyFeatureTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Her testten önce çalışır
    }
    
    void TearDown() override {
        // Her testten sonra çalışır
    }
    
    // Test değişkenleri
    int testValue = 0;
};

// Parametreli olmayan test
TEST_F(MyFeatureTest, BasicFunctionality) {
    // Arrange
    int input = 5;
    
    // Act
    int result = my_function(input);
    
    // Assert
    EXPECT_EQ(result, 10);
}

// Parametreli test
class MyParameterizedTest : public ::testing::TestWithParam<int> {};

TEST_P(MyParameterizedTest, MultipleValues) {
    int param = GetParam();
    EXPECT_GT(my_function(param), 0);
}

INSTANTIATE_TEST_SUITE_P(
    Values,
    MyParameterizedTest,
    ::testing::Values(1, 2, 5, 10, 100)
);
```

### Test Kategorileri

| Kategori | Dosya | Açıklama |
|----------|-------|----------|
| Unit Tests | `*_test.cpp` | Tek fonksiyon testleri |
| Integration Tests | `*_integration_test.cpp` | Modül entegrasyon testleri |
| Security Tests | `security_test_test.cpp` | Güvenlik senaryoları |

---

## 📚 API Dokümantasyonu

### Doxygen Oluşturma

```bash
.\7-build-doc-windows.bat
```

### Dokümantasyon Formatı

```cpp
/**
 * @file filename.cpp
 * @brief Dosya açıklaması
 * @author Yazar adı
 * @date Tarih
 */

/**
 * @class ClassName
 * @brief Sınıf açıklaması
 * 
 * Detaylı açıklama burada yazılır.
 * Birden fazla paragraf olabilir.
 */

/**
 * @brief Fonksiyon kısa açıklaması
 * 
 * Detaylı açıklama.
 * 
 * @param[in] param1 Girdi parametresi açıklaması
 * @param[out] param2 Çıktı parametresi açıklaması
 * @param[in,out] param3 Girdi/çıktı parametresi
 * 
 * @return Dönüş değeri açıklaması
 * @retval 0 Başarılı
 * @retval -1 Hata durumu
 * 
 * @throws std::runtime_error Hata durumunda
 * 
 * @note Önemli notlar
 * @warning Uyarılar
 * @see İlgili fonksiyonlar
 * 
 * @code
 * // Kullanım örneği
 * int result = function_name(42, buffer);
 * @endcode
 */
```

---

## 🔄 Git Workflow

### Branch Stratejisi

```
main (production)
  │
  ├── develop (integration)
  │     │
  │     ├── feature/user-auth
  │     ├── feature/pet-management
  │     ├── bugfix/login-crash
  │     └── hotfix/security-patch
  │
  └── release/v1.0
```

### Commit Mesaj Formatı

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Type'lar:**
- `feat`: Yeni özellik
- `fix`: Bug düzeltme
- `docs`: Dokümantasyon
- `style`: Kod formatı
- `refactor`: Refactoring
- `test`: Test ekleme
- `chore`: Build, config değişiklikleri

**Örnek:**

```
feat(auth): implement session management

- Add device fingerprint binding
- Implement session timeout
- Add session validation on each request

Closes #123
```

### Pull Request Süreci

1. Feature branch oluştur
2. Değişiklikleri yap
3. Testleri çalıştır
4. PR oluştur
5. Code review bekle
6. CI/CD kontrol et
7. Merge

---

## 🐛 Debugging

### Visual Studio Debugger

1. Debug build yap
2. Breakpoint koy
3. F5 ile başlat

### GDB (Linux/WSL)

```bash
gdb ./petcareapp
(gdb) break main
(gdb) run
(gdb) next
(gdb) print variable
(gdb) backtrace
```

### Memory Debugging

```bash
# Valgrind (Linux)
valgrind --leak-check=full ./petcareapp

# Dr. Memory (Windows)
drmemory -- .\petcareapp.exe
```

---

## 📊 Performans Analizi

### Profiling

```bash
# Visual Studio Profiler
# Debug > Performance Profiler

# gprof (Linux)
g++ -pg -o petcareapp main.cpp
./petcareapp
gprof petcareapp gmon.out > analysis.txt
```

---

## 🔗 Faydalı Linkler

| Kaynak | Link |
|--------|------|
| C++ Reference | [cppreference.com](https://en.cppreference.com/) |
| Google Test | [Google Test Docs](https://google.github.io/googletest/) |
| CMake | [CMake Documentation](https://cmake.org/documentation/) |
| SQLite | [SQLite Documentation](https://sqlite.org/docs.html) |
| OWASP | [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/) |

---

## ❓ SSS (Sıkça Sorulan Sorular)

### Build Hataları

**Q: "CMake not found" hatası alıyorum**

A: CMake'i PATH'e ekleyin veya `4-install-windows-enviroment.bat` çalıştırın.

**Q: "Visual Studio not found" hatası**

A: VS Build Tools 2019+ yükleyin veya VS 2022 kullanın.

### Test Hataları

**Q: Testler başarısız oluyor**

A: Debug modda derleyip debugger ile inceleyin. Test izolasyonu için her testten önce state'i sıfırlayın.

### Güvenlik

**Q: RASP kontrolleri false positive veriyor**

A: Development modda bazı RASP kontrolleri devre dışı bırakılabilir:

```cpp
#ifdef DEBUG
// Geliştirme ortamında bazı kontrolleri atla
#endif
```

---

## 📞 İletişim

Sorularınız için:

- **GitHub Issues:** Proje repository'sinde issue açın
- **E-mail:** Proje danışmanı ile iletişime geçin
