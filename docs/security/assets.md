# PetCare Application - Asset Management Documentation

## Varlık Yönetimi Kataloğu

**Versiyon:** 1.0  
**Tarih:** 21 Aralık 2025  
**Durum:** Aktif

---

## 1. Kullanıcı Kimlik Bilgileri Varlıkları

### 1.1 Kullanıcı Adı (Username)

| Özellik | Değer |
|---------|-------|
| **Adı** | `username` |
| **Açıklaması** | Kullanıcıyı benzersiz şekilde tanımlayan metin değeri |
| **Konumu** | `petcare.db` → `users` tablosu → `username` sütunu |
| **Kaynağı** | Kullanıcı kaydı sırasında kullanıcı tarafından girilen değer |
| **Boyutu** | Maksimum 50 byte (VARCHAR(50)) |
| **Oluşturulma Zamanı** | Kullanıcı kayıt anı (INSERT işlemi) |
| **Silinme Zamanı** | Kullanıcı silme işlemi / Manuel müdahale |
| **Varsayılan Değeri** | `NULL` (zorunlu alan) |
| **Koruma Şeması** | |
| ├─ Gizlilik | Plaintext (şifrelenmemiş) - DB encryption at rest |
| ├─ Bütünlük | PRIMARY KEY constraint, UNIQUE constraint |
| └─ Kimlik Doğrulama | Login sırasında doğrulanır |

### 1.2 Şifrelenmiş Parola (Encrypted Password)

| Özellik | Değer |
|---------|-------|
| **Adı** | `encrypted_password` |
| **Açıklaması** | XOR tabanlı şifreleme ile korunan kullanıcı parolası |
| **Konumu** | `petcare.db` → `users` tablosu → `encrypted_password` sütunu |
| **Kaynağı** | Kullanıcı kayıt/güncelleme sırasında girilen parola → `encryptPassword()` fonksiyonu |
| **Boyutu** | Maksimum 256 byte (VARCHAR(256)) |
| **Oluşturulma Zamanı** | Kullanıcı kayıt anı |
| **Silinme Zamanı** | Kullanıcı silme işlemi |
| **Varsayılan Değeri** | `NULL` (zorunlu alan) |
| **Koruma Şeması** | |
| ├─ Gizlilik | XOR şifreleme + Whitebox DB encryption |
| ├─ Bütünlük | Şifreleme işlemi sırasında implicit doğrulama |
| └─ Kimlik Doğrulama | `loginUser()` / `loginUserWithSession()` ile karşılaştırma |

**Kod Referansı:**
```c
// src/petcare/src/petcare.cpp
void encryptPassword(const char* password, char* encrypted);
int decryptPassword(const char* encrypted, char* decrypted);
```

---

## 2. Oturum Yönetimi Varlıkları

### 2.1 Oturum Verisi (Session Data)

| Özellik | Değer |
|---------|-------|
| **Adı** | `SessionData` |
| **Açıklaması** | Kullanıcı oturumunu yöneten ve cihaza bağlı güvenlik yapısı |
| **Konumu** | Bellek (RAM) - `src/utility/header/assetProtection.h` |
| **Kaynağı** | `create_session()` fonksiyonu |
| **Boyutu** | 152 byte (struct boyutu) |
| **Oluşturulma Zamanı** | `loginUserWithSession()` başarılı login sonrası |
| **Silinme Zamanı** | `logoutUserSession()` çağrısı veya `expiry_time` dolduğunda |
| **Varsayılan Değeri** | Tüm alanlar sıfırlanmış (memset 0) |
| **Koruma Şeması** | |
| ├─ Gizlilik | AES şifreleme (`session_key`) |
| ├─ Bütünlük | CRC32 checksum (`integrity_check`) |
| └─ Kimlik Doğrulama | Device fingerprint binding (`fingerprint_hash`) |

**Yapı Detayı:**
```c
typedef struct {
    uint8_t session_id[32];         // 32 byte - Benzersiz oturum ID
    uint8_t session_key[32];        // 32 byte - Şifrelenmiş oturum anahtarı
    uint8_t encryption_iv[16];      // 16 byte - IV
    uint64_t creation_time;         //  8 byte - Oluşturma zamanı (Unix timestamp)
    uint64_t expiry_time;           //  8 byte - Bitiş zamanı (Unix timestamp)
    uint32_t access_count;          //  4 byte - Erişim sayısı
    uint8_t fingerprint_hash[32];   // 32 byte - Cihaz parmak izi hash'i
    uint32_t integrity_check;       //  4 byte - CRC32 bütünlük kontrolü
} SessionData;                      // Toplam: 152 byte
```

### 2.2 Cihaz Parmak İzi (Device Fingerprint)

| Özellik | Değer |
|---------|-------|
| **Adı** | `DeviceFingerprint` |
| **Açıklaması** | Cihazı benzersiz şekilde tanımlayan donanım ve yazılım özellikleri |
| **Konumu** | Bellek (RAM) - `src/utility/header/assetProtection.h` |
| **Kaynağı** | `generate_device_fingerprint()` fonksiyonu |
| **Boyutu** | 144 byte (struct boyutu) |
| **Oluşturulma Zamanı** | `init_petcare_session()` çağrısı |
| **Silinme Zamanı** | Uygulama kapanışı |
| **Varsayılan Değeri** | Sistem bilgilerinden dinamik olarak üretilir |
| **Koruma Şeması** | |
| ├─ Gizlilik | Hash ile gizleme |
| ├─ Bütünlük | `integrity_hash` ile self-check |
| └─ Kimlik Doğrulama | `verify_device_fingerprint()` ile doğrulama |

**Yapı Detayı:**
```c
typedef struct {
    uint8_t hardware_id[32];        // 32 byte - CPU, RAM, Disk bilgisi hash'i
    uint8_t software_id[32];        // 32 byte - OS, Username, Hostname hash'i
    uint8_t combined_fingerprint[64]; // 64 byte - Birleşik parmak izi
    uint64_t creation_timestamp;    //  8 byte - Oluşturma zamanı
    uint32_t integrity_hash;        //  4 byte - Self-integrity check
} DeviceFingerprint;                // Toplam: 140 byte + padding = 144 byte
```

**Windows Kaynakları:**
- `GetVolumeInformationA()` - Disk serial number
- `GetComputerNameA()` - Bilgisayar adı
- `GetUserNameA()` - Kullanıcı adı
- `GetCurrentProcessId()` - Process ID

---

## 3. Veritabanı Varlıkları

### 3.1 Veritabanı Dosyası

| Özellik | Değer |
|---------|-------|
| **Adı** | `petcare.db` / `petcare.db.enc` |
| **Açıklaması** | SQLite veritabanı dosyası (şifreli veya düz) |
| **Konumu** | Uygulama çalıştırma dizini |
| **Kaynağı** | `init_petcare_database()` fonksiyonu |
| **Boyutu** | Değişken (tipik: 50KB - 10MB) |
| **Oluşturulma Zamanı** | İlk uygulama başlatma |
| **Silinme Zamanı** | Manuel silme |
| **Varsayılan Değeri** | Boş tablolar ile başlatılır |
| **Koruma Şeması** | |
| ├─ Gizlilik | Whitebox AES-128 (cascade) şifreleme |
| ├─ Bütünlük | HMAC-SHA256 doğrulama |
| └─ Kimlik Doğrulama | Device fingerprint + app hash tabanlı key derivation |

### 3.2 Veritabanı Şifreleme Anahtarı

| Özellik | Değer |
|---------|-------|
| **Adı** | `db_encryption_key` |
| **Açıklaması** | Veritabanı dosyasını şifrelemek için türetilen anahtar |
| **Konumu** | Bellek (RAM) - `petcareapp.cpp` → `derive_database_key()` |
| **Kaynağı** | Device fingerprint + App integrity hash + PBKDF2 |
| **Boyutu** | 64 byte (hex encoded: 32 byte raw) |
| **Oluşturulma Zamanı** | Her uygulama başlatmada yeniden türetilir |
| **Silinme Zamanı** | `secure_wipe()` ile bellek temizleme |
| **Varsayılan Değeri** | Yok (her zaman türetilir) |
| **Koruma Şeması** | |
| ├─ Gizlilik | Bellekte kısa süreli tutulur, `SecureAutoWipe` ile temizlenir |
| ├─ Bütünlük | Key derivation parametreleri sabit |
| └─ Kimlik Doğrulama | Cihaz + uygulama bağlı |

**Anahtar Türetme:**
```c
// KDF parametreleri
#define DEFAULT_KDF_ITERATIONS 20000
#define MIN_KDF_ITERATIONS 1000
#define MAX_KDF_ITERATIONS 1000000

// Türetme formülü
key = PBKDF2(app_hash, device_fingerprint_salt, iterations)
```

---

## 4. Evcil Hayvan Varlıkları

### 4.1 Evcil Hayvan Kaydı (Pet)

| Özellik | Değer |
|---------|-------|
| **Adı** | `Pet` |
| **Açıklaması** | Evcil hayvan bilgilerini içeren kayıt |
| **Konumu** | `petcare.db` → `pets` tablosu |
| **Kaynağı** | `addPet()` fonksiyonu / Kullanıcı girişi |
| **Boyutu** | ~200 byte (struct) / Değişken (DB row) |
| **Oluşturulma Zamanı** | "Add Pet" işlemi |
| **Silinme Zamanı** | "Delete Pet" işlemi |
| **Varsayılan Değeri** | `NULL` değerler |
| **Koruma Şeması** | |
| ├─ Gizlilik | Database encryption at rest |
| ├─ Bütünlük | Foreign key constraints |
| └─ Kimlik Doğrulama | Owner kontrolü (`isPetOwnedByUser()`) |

**Veritabanı Şeması:**
```sql
CREATE TABLE pets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- 4 byte
    name TEXT NOT NULL,                     -- Max 50 byte
    type TEXT NOT NULL,                     -- Max 50 byte
    age INTEGER,                            -- 4 byte
    owner TEXT NOT NULL,                    -- Max 50 byte (FK → users.username)
    FOREIGN KEY (owner) REFERENCES users(username)
);
```

**Bellek Yapısı:**
```c
typedef struct Pet {
    char* name;           // Dinamik: ~50 byte
    char* type;           // Dinamik: ~50 byte
    int age;              // 4 byte
    char* owner;          // Dinamik: ~50 byte
    struct Pet* prev;     // 8 byte (pointer)
    struct Pet* next;     // 8 byte (pointer)
} Pet;                    // ~170 byte (ortalama)
```

---

## 5. Randevu Varlıkları

### 5.1 Veteriner Randevusu (Appointment)

| Özellik | Değer |
|---------|-------|
| **Adı** | `Appointment` (XOR Linked List Node) |
| **Açıklaması** | Veteriner randevu bilgisi |
| **Konumu** | `petcare.db` → `appointments` tablosu + Bellek (XOR linked list) |
| **Kaynağı** | `addAppointment()` fonksiyonu |
| **Boyutu** | ~300 byte (struct) |
| **Oluşturulma Zamanı** | "Add Appointment" işlemi |
| **Silinme Zamanı** | "Cancel Appointment" işlemi |
| **Varsayılan Değeri** | `NULL` |
| **Koruma Şeması** | |
| ├─ Gizlilik | XOR linked list obfuscation + DB encryption |
| ├─ Bütünlük | Tarih çakışma kontrolü (`db_is_date_occupied()`) |
| └─ Kimlik Doğrulama | Owner kontrolü |

**Veritabanı Şeması:**
```sql
CREATE TABLE appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pet_name TEXT NOT NULL,
    description TEXT,
    day INTEGER NOT NULL,
    month INTEGER NOT NULL,
    owner TEXT NOT NULL,
    UNIQUE(day, month)  -- Aynı tarihte tek randevu
);
```

---

## 6. Program Varlıkları (Feeding/Medicine/Exercise)

### 6.1 Besleme Programı (Feeding Schedule)

| Özellik | Değer |
|---------|-------|
| **Adı** | `FeedingSchedule` (Queue Node) |
| **Açıklaması** | Evcil hayvan besleme programı |
| **Konumu** | `petcare.db` → `feeding_schedules` + Bellek (Queue) |
| **Kaynağı** | `enqueue()` fonksiyonu |
| **Boyutu** | ~200 byte |
| **Oluşturulma Zamanı** | "Add Feeding Schedule" işlemi |
| **Silinme Zamanı** | "Delete Feeding Schedule" işlemi |
| **Varsayılan Değeri** | `NULL` |
| **Koruma Şeması** | |
| ├─ Gizlilik | DB encryption |
| ├─ Bütünlük | Queue veri yapısı FIFO garantisi |
| └─ Kimlik Doğrulama | Owner kontrolü |

### 6.2 İlaç Programı (Medicine Schedule)

| Özellik | Değer |
|---------|-------|
| **Adı** | `MedicineSchedule` (Queue Node) |
| **Açıklaması** | Evcil hayvan ilaç programı |
| **Konumu** | `petcare.db` → `medicine_schedules` + Bellek (Queue) |
| **Kaynağı** | `addMedicineSchedule()` fonksiyonu |
| **Boyutu** | ~200 byte |
| **Oluşturulma Zamanı** | "Add Medicine Schedule" işlemi |
| **Silinme Zamanı** | "Delete Medicine Schedule" işlemi |
| **Varsayılan Değeri** | `NULL` |
| **Koruma Şeması** | |
| ├─ Gizlilik | DB encryption |
| ├─ Bütünlük | SCC analizi ile bağımlılık kontrolü |
| └─ Kimlik Doğrulama | Owner kontrolü |

### 6.3 Egzersiz Rutini (Exercise Routine)

| Özellik | Değer |
|---------|-------|
| **Adı** | `ExerciseRoutine` (Stack Node) |
| **Açıklaması** | Evcil hayvan egzersiz rutini |
| **Konumu** | `petcare.db` → `exercise_routines` + Bellek (Stack) |
| **Kaynağı** | `addExerciseRoutine()` fonksiyonu |
| **Boyutu** | ~200 byte |
| **Oluşturulma Zamanı** | "Add Exercise Routine" işlemi |
| **Silinme Zamanı** | "Undo Last Exercise" işlemi (LIFO) |
| **Varsayılan Değeri** | `NULL` |
| **Koruma Şeması** | |
| ├─ Gizlilik | DB encryption |
| ├─ Bütünlük | Stack LIFO garantisi |
| └─ Kimlik Doğrulama | Owner kontrolü |

---

## 7. Sahiplendirme Varlıkları

### 7.1 Başıboş Hayvan (Stray Animal)

| Özellik | Değer |
|---------|-------|
| **Adı** | `StrayAnimal` |
| **Açıklaması** | Sahiplendirmeye uygun başıboş hayvan kaydı |
| **Konumu** | `petcare.db` → `stray_animals` + Bellek (Linked List) |
| **Kaynağı** | `addStrayAnimalToList()` fonksiyonu |
| **Boyutu** | ~150 byte |
| **Oluşturulma Zamanı** | "Add stray animals" işlemi |
| **Silinme Zamanı** | "Delete stray animals" veya sahiplendirme işlemi |
| **Varsayılan Değeri** | Auto-increment ID |
| **Koruma Şeması** | |
| ├─ Gizlilik | DB encryption |
| ├─ Bütünlük | Unique ID constraint |
| └─ Kimlik Doğrulama | Admin erişimi (herkes ekleyebilir) |

### 7.2 Sahiplenilen Hayvan (Adopted Animal)

| Özellik | Değer |
|---------|-------|
| **Adı** | `AdoptedAnimal` |
| **Açıklaması** | Sahiplenilmiş hayvan kaydı |
| **Konumu** | `petcare.db` → `adopted_animals` + Bellek (Linked List) |
| **Kaynağı** | `adoptStrayAnimal()` fonksiyonu (StrayAnimal'dan dönüşüm) |
| **Boyutu** | ~200 byte |
| **Oluşturulma Zamanı** | "Adopt stray animals" işlemi |
| **Silinme Zamanı** | Manuel silme |
| **Varsayılan Değeri** | Stray animal verilerini miras alır |
| **Koruma Şeması** | |
| ├─ Gizlilik | DB encryption |
| ├─ Bütünlük | Orijinal stray_id referansı |
| └─ Kimlik Doğrulama | Owner bilgisi kaydedilir |

---

## 8. Doğum Günü Varlıkları

### 8.1 Evcil Hayvan Doğum Günü (Pet Birthday)

| Özellik | Değer |
|---------|-------|
| **Adı** | `BirthdayRecord` (B+ Tree Node) |
| **Açıklaması** | Evcil hayvan doğum günü kaydı |
| **Konumu** | `petcare.db` → `birthdays` + Bellek (B+ Tree) |
| **Kaynağı** | `insertBirthday()` fonksiyonu |
| **Boyutu** | ~100 byte |
| **Oluşturulma Zamanı** | "Record Pet Birthday" işlemi |
| **Silinme Zamanı** | Manuel silme |
| **Varsayılan Değeri** | `NULL` |
| **Koruma Şeması** | |
| ├─ Gizlilik | DB encryption |
| ├─ Bütünlük | B+ Tree index yapısı |
| └─ Kimlik Doğrulama | Owner kontrolü |

---

## 9. Şifreleme Varlıkları

### 9.1 Obfuscated String

| Özellik | Değer |
|---------|-------|
| **Adı** | `ObfuscatedString` |
| **Açıklaması** | Statik string değerleri için XOR tabanlı koruma yapısı |
| **Konumu** | Bellek - `src/utility/header/assetProtection.h` |
| **Kaynağı** | `create_obfuscated_string()` fonksiyonu |
| **Boyutu** | 324 byte (struct) |
| **Oluşturulma Zamanı** | Runtime string obfuscation |
| **Silinme Zamanı** | Scope dışına çıkınca |
| **Varsayılan Değeri** | Sıfırlanmış struct |
| **Koruma Şeması** | |
| ├─ Gizlilik | XOR şifreleme (32 byte key) |
| ├─ Bütünlük | CRC32 checksum |
| └─ Kimlik Doğrulama | `verify_obfuscated_string()` |

**Yapı Detayı:**
```c
typedef struct {
    uint8_t data[256];   // 256 byte - Şifrelenmiş veri
    size_t length;       //   8 byte - Orijinal uzunluk
    uint8_t key[32];     //  32 byte - XOR anahtarı
    uint32_t checksum;   //   4 byte - CRC32 bütünlük kontrolü
} ObfuscatedString;      // Toplam: 300 byte + padding = 324 byte
```

### 9.2 Whitebox Şifreleme Context

| Özellik | Değer |
|---------|-------|
| **Adı** | `WB_Cascade_Context` |
| **Açıklaması** | AES-DES-AES cascade şifreleme için context |
| **Konumu** | Bellek - `src/utility/header/whiteboxCrypto.h` |
| **Kaynağı** | `wb_cascade_init()` fonksiyonu |
| **Boyutu** | ~50KB (precomputed tables) |
| **Oluşturulma Zamanı** | Şifreleme başlatma |
| **Silinme Zamanı** | Scope dışına çıkınca |
| **Varsayılan Değeri** | Precomputed lookup tables |
| **Koruma Şeması** | |
| ├─ Gizlilik | Whitebox implementation (key embedded in tables) |
| ├─ Bütünlük | HMAC-SHA256 file verification |
| └─ Kimlik Doğrulama | Password-based key derivation |

---

## 10. RASP Güvenlik Varlıkları

### 10.1 CFI Counter

| Özellik | Değer |
|---------|-------|
| **Adı** | `CFICounter` |
| **Açıklaması** | Control Flow Integrity sayacı |
| **Konumu** | Bellek - Global array `g_cfi_counters[]` |
| **Kaynağı** | `rasp_create_cfi_counter()` fonksiyonu |
| **Boyutu** | 40 byte (struct) |
| **Oluşturulma Zamanı** | Kritik fonksiyon girişlerinde |
| **Silinme Zamanı** | `rasp_shutdown()` veya uygulama kapanışı |
| **Varsayılan Değeri** | `expected_value = 0, current_value = 0` |
| **Koruma Şeması** | |
| ├─ Gizlilik | Bellekte gizli tutulur |
| ├─ Bütünlük | Counter value comparison |
| └─ Kimlik Doğrulama | Checkpoint address binding |

### 10.2 Checksum Verification

| Özellik | Değer |
|---------|-------|
| **Adı** | `CodeBlockChecksum` |
| **Açıklaması** | Kod bloğu bütünlük doğrulama yapısı |
| **Konumu** | Bellek - `src/utility/header/raspSecurity.h` |
| **Kaynağı** | `rasp_calculate_checksum()` fonksiyonu |
| **Boyutu** | 72 byte |
| **Oluşturulma Zamanı** | Uygulama başlatma (`initialize_rasp_security()`) |
| **Silinme Zamanı** | Uygulama kapanışı |
| **Varsayılan Değeri** | Hesaplanan hash değerleri |
| **Koruma Şeması** | |
| ├─ Gizlilik | Hash değerleri bellekte |
| ├─ Bütünlük | SHA-256 hash + CRC32 |
| └─ Kimlik Doğrulama | `rasp_verify_checksum()` ile doğrulama |

---

## 11. Dosya Varlıkları

### 11.1 Şifreli Dosya Header

| Özellik | Değer |
|---------|-------|
| **Adı** | `WB_FileHeader` |
| **Açıklaması** | Whitebox şifreli dosya başlık yapısı |
| **Konumu** | `.enc` uzantılı dosyaların başlangıcı |
| **Kaynağı** | `wb_encrypt_file()` fonksiyonu |
| **Boyutu** | 80 byte |
| **Oluşturulma Zamanı** | Dosya şifreleme işlemi |
| **Silinme Zamanı** | Dosya silindiğinde |
| **Varsayılan Değeri** | Magic: 0x57424358 ("WBCX") |
| **Koruma Şeması** | |
| ├─ Gizlilik | Salt + IV rastgele üretilir |
| ├─ Bütünlük | HMAC-SHA256 (32 byte) |
| └─ Kimlik Doğrulama | Version kontrolü |

**Yapı Detayı:**
```c
typedef struct WB_FileHeader {
    uint32_t magic;          //  4 byte - 0x57424358 ("WBCX")
    uint16_t version;        //  2 byte - Dosya format versiyonu
    uint8_t layer_type;      //  1 byte - WB_LAYER_CASCADE
    uint8_t padding_size;    //  1 byte - PKCS#7 padding
    uint64_t original_size;  //  8 byte - Orijinal dosya boyutu
    uint8_t salt[16];        // 16 byte - Key derivation salt
    uint8_t iv[16];          // 16 byte - Initialization vector
    uint8_t hmac[32];        // 32 byte - HMAC-SHA256
} WB_FileHeader;             // Toplam: 80 byte
```

### 11.2 Legacy .dat Dosyaları

| Özellik | Değer |
|---------|-------|
| **Adı** | `*.dat` dosyaları |
| **Açıklaması** | Eski format veri dosyaları (migration için) |
| **Konumu** | Uygulama dizini (`users.dat`, `pets.dat`, etc.) |
| **Kaynağı** | Eski versiyon uygulamalar |
| **Boyutu** | Değişken |
| **Oluşturulma Zamanı** | Eski versiyon kayıt işlemleri |
| **Silinme Zamanı** | `migrate_dat_to_sqlite()` sonrası manuel |
| **Varsayılan Değeri** | Binary format |
| **Koruma Şeması** | |
| ├─ Gizlilik | XOR şifreleme (bazı dosyalar) |
| ├─ Bütünlük | Yok (legacy) |
| └─ Kimlik Doğrulama | Yok (legacy) |

---

## 12. Varlık Koruma Özet Tablosu

| Varlık | Gizlilik | Bütünlük | Kimlik Doğrulama |
|--------|----------|----------|------------------|
| Username | DB Encryption | UNIQUE Constraint | Login |
| Password | XOR + Whitebox | Implicit | comparePasswords() |
| Session | AES-256 | CRC32 | Device Binding |
| Device Fingerprint | Hash | integrity_hash | verify_device_fingerprint() |
| DB File | Whitebox Cascade | HMAC-SHA256 | KDF + Device |
| DB Key | SecureAutoWipe | KDF Parameters | Device + App Hash |
| Pet Records | DB Encryption | FK Constraints | isPetOwnedByUser() |
| Appointments | XOR List + DB | Date Uniqueness | Owner Check |
| Schedules | DB Encryption | Queue/Stack | Owner Check |
| Stray/Adopted | DB Encryption | ID Constraints | Owner Record |
| Birthdays | DB Encryption | B+ Tree Index | Owner Check |
| ObfuscatedString | XOR-32 | CRC32 | verify_obfuscated_string() |
| WB Context | Whitebox Tables | HMAC | Password KDF |
| CFI Counter | Memory | Value Compare | Checkpoint Address |
| Code Checksum | Memory | SHA-256 + CRC32 | rasp_verify_checksum() |
| File Header | Salt + IV | HMAC-SHA256 | Version Check |

---

## 13. Varlık Yaşam Döngüsü Diyagramı

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VARLIK YAŞAM DÖNGÜSÜ                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Oluştur  │───▶│  Kullan  │───▶│ Güncelle │───▶│   Sil    │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │               │                     │
│       ▼               ▼               ▼               ▼                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Şifrele  │    │ Doğrula  │    │ Re-enc   │    │ Wipe     │              │
│  │ (Create) │    │ (Access) │    │ (Update) │    │ (Delete) │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │               │                     │
│       ▼               ▼               ▼               ▼                     │
│  ┌──────────────────────────────────────────────────────────┐              │
│  │                    AUDIT LOG (RASP)                      │              │
│  │  rasp_log_event("CREATE/ACCESS/UPDATE/DELETE", msg)      │              │
│  └──────────────────────────────────────────────────────────┘              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 14. Referanslar

### Kaynak Dosyalar
| Dosya | Açıklama |
|-------|----------|
| `src/utility/header/assetProtection.h` | Statik ve dinamik varlık koruması |
| `src/utility/header/whiteboxCrypto.h` | Whitebox şifreleme |
| `src/utility/header/raspSecurity.h` | RASP güvenlik özellikleri |
| `src/utility/header/secureMemory.h` | Güvenli bellek yönetimi |
| `src/petcare/header/database.h` | Veritabanı API |
| `src/petcare/header/petcare.h` | Ana uygulama API |

### İlgili Standartlar
- OWASP ASVS v4.0 - Application Security Verification Standard
- ETSI EN 303 645 - Consumer IoT Security
- NIST SP 800-57 - Key Management Recommendations

