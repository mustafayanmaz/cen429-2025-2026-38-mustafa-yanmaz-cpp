# Project Design and Architecture

## PetCare Application - Mimari Dokümantasyonu

**Versiyon:** 1.0  
**Tarih:** 21 Aralık 2025  
**Durum:** Aktif

---

## 1. Genel Bakış

PetCare, güvenli yazılım geliştirme prensiplerine göre tasarlanmış çok katmanlı bir masaüstü uygulamasıdır. Uygulama, evcil hayvan yönetimi, veteriner randevuları, sağlık takibi ve sahiplendirme işlemlerini güvenli bir şekilde gerçekleştirir.

### 1.1 Mimari Prensipler

| Prensip | Açıklama |
|---------|----------|
| **Katmanlı Mimari** | Sunum, İş Mantığı, Veri Erişim katmanları ayrılmış |
| **Defense in Depth** | Çok katmanlı güvenlik (RASP, Crypto, Memory) |
| **Secure by Design** | Güvenlik tasarım aşamasında entegre edilmiş |
| **Least Privilege** | Her kullanıcı sadece kendi verilerine erişebilir |
| **Fail Secure** | Hata durumlarında güvenli kapanış |

---

## 2. Üst Düzey Mimari

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PETCARE APPLICATION                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                    PRESENTATION LAYER                              │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │     │
│  │  │   CLI Menu   │  │   Input      │  │   Output     │             │     │
│  │  │   System     │  │   Handler    │  │   Formatter  │             │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                    BUSINESS LOGIC LAYER                            │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │     │
│  │  │    User      │  │     Pet      │  │  Appointment │             │     │
│  │  │  Management  │  │  Management  │  │   Management │             │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │     │
│  │  │   Schedule   │  │   Adoption   │  │   Birthday   │             │     │
│  │  │  Management  │  │  Management  │  │   Tracking   │             │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                      SECURITY LAYER                                │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │     │
│  │  │    RASP      │  │   Whitebox   │  │    Secure    │             │     │
│  │  │  Protection  │  │    Crypto    │  │    Memory    │             │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │     │
│  │  │    Asset     │  │     Code     │  │   Session    │             │     │
│  │  │  Protection  │  │  Obfuscation │  │  Management  │             │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                      DATA ACCESS LAYER                             │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │     │
│  │  │   Database   │  │     File     │  │    Memory    │             │     │
│  │  │   Handler    │  │   Handler    │  │   Structures │             │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                      STORAGE LAYER                                 │     │
│  │  ┌──────────────────────┐  ┌──────────────────────┐               │     │
│  │  │   SQLite Database    │  │     .dat Files       │               │     │
│  │  │   (Encrypted)        │  │     (Legacy)         │               │     │
│  │  └──────────────────────┘  └──────────────────────┘               │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Modül Yapısı

### 3.1 Kaynak Kod Organizasyonu

```
src/
├── utility/                 # Güvenlik Kütüphanesi
│   ├── header/
│   │   ├── assetProtection.h      # Varlık koruma API
│   │   ├── codeObfuscation.h      # Kod sertleştirme makroları
│   │   ├── commonTypes.h          # Ortak tip tanımları
│   │   ├── raspSecurity.h         # RASP özellikleri
│   │   ├── secureMemory.h         # Güvenli bellek API
│   │   ├── securityTest.h         # Güvenlik test framework
│   │   ├── sha256.h               # SHA-256 implementasyonu
│   │   └── whiteboxCrypto.h       # Whitebox şifreleme
│   └── src/
│       └── [Implementasyonlar]
│
├── petcare/                 # İş Mantığı Kütüphanesi
│   ├── header/
│   │   ├── petcare.h              # Ana uygulama API
│   │   ├── database.h             # Veritabanı wrapper
│   │   └── methods.h              # Huffman kodlama
│   └── src/
│       ├── petcare.cpp            # 3286 satır, 50+ fonksiyon
│       ├── database.cpp           # SQLite işlemleri
│       └── methods.cpp            # Algoritma implementasyonları
│
├── petcareapp/              # Uygulama Katmanı
│   └── src/
│       └── petcareapp.cpp         # CLI arayüzü, 1700+ satır
│
└── tests/                   # Test Kütüphanesi
    ├── utility/                   # 181 güvenlik testi
    └── petcare/                   # 264 iş mantığı testi
```

### 3.2 Modül Bağımlılıkları

```
┌─────────────────────────────────────────────────────────────────┐
│                      DEPENDENCY GRAPH                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                     ┌─────────────┐                            │
│                     │ petcareapp  │                            │
│                     └──────┬──────┘                            │
│                            │                                    │
│              ┌─────────────┼─────────────┐                     │
│              │             │             │                      │
│              ▼             ▼             ▼                      │
│      ┌───────────┐  ┌───────────┐  ┌───────────┐              │
│      │  petcare  │  │  utility  │  │  sqlite3  │              │
│      └─────┬─────┘  └─────┬─────┘  └───────────┘              │
│            │              │                                     │
│            └──────┬───────┘                                    │
│                   │                                             │
│                   ▼                                             │
│            ┌───────────┐                                       │
│            │  stdlib   │                                       │
│            └───────────┘                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Veri Yapıları

### 4.1 Temel Veri Yapıları

| Veri Yapısı | Kullanım Alanı | Karmaşıklık |
|-------------|----------------|-------------|
| **Hash Table** | Kullanıcı yönetimi | O(1) ortalama |
| **Doubly Linked List** | Pet listesi | O(n) arama |
| **Queue (FIFO)** | Feeding/Medicine schedules | O(1) enqueue/dequeue |
| **Stack (LIFO)** | Exercise routines | O(1) push/pop |
| **XOR Linked List** | Appointments | O(n) bellek optimizasyonu |
| **B+ Tree** | Birthday tracking | O(log n) arama |
| **Directed Graph** | Medicine dependencies | SCC analizi |

### 4.2 Veri Yapısı Diyagramları

#### Hash Table (Kullanıcılar)
```
┌─────────────────────────────────────────────────────────────────┐
│                      HASH TABLE (Size: 100)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Index 0: NULL                                                  │
│  Index 1: [User1] → [User101] → NULL                           │
│  Index 2: NULL                                                  │
│  Index 3: [User3] → NULL                                       │
│  ...                                                           │
│  Index 99: [User99] → NULL                                     │
│                                                                 │
│  Hash Function: sum(char * position) % TABLE_SIZE              │
│  Collision Resolution: Chaining (Linked List)                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Doubly Linked List (Pets)
```
┌─────────────────────────────────────────────────────────────────┐
│                    DOUBLY LINKED LIST (Pets)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NULL ← [Pet1] ↔ [Pet2] ↔ [Pet3] ↔ [Pet4] → NULL              │
│           │        │        │        │                          │
│           ▼        ▼        ▼        ▼                          │
│         name     name     name     name                         │
│         type     type     type     type                         │
│         age      age      age      age                          │
│         owner    owner    owner    owner                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### B+ Tree (Birthdays)
```
┌─────────────────────────────────────────────────────────────────┐
│                      B+ TREE (Order: 4)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                         [15|30]                                 │
│                        /   |   \                                │
│                       /    |    \                               │
│               [5|10]    [20|25]    [35|40]                      │
│               /  |  \    /  |  \    /  |  \                     │
│              ↓   ↓   ↓  ↓   ↓   ↓  ↓   ↓   ↓                    │
│             [1] [7] [12][17][23][28][33][38][45]                │
│                         (Leaf nodes linked)                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Veritabanı Mimarisi

### 5.1 Entity-Relationship Diyagramı

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATABASE SCHEMA (SQLite)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐         ┌──────────────┐                     │
│  │    users     │         │     pets     │                     │
│  ├──────────────┤    1    ├──────────────┤                     │
│  │ *username PK │◄────────┤ *id PK       │                     │
│  │  password    │    N    │  name        │                     │
│  └──────────────┘         │  type        │                     │
│         │                 │  age         │                     │
│         │                 │  owner FK    │────┐                │
│         │                 └──────────────┘    │                │
│         │                                     │                │
│         │  ┌──────────────┐                   │                │
│         │  │ appointments │                   │                │
│         │  ├──────────────┤                   │                │
│         └──┤ *id PK       │◄──────────────────┤                │
│            │  pet_name FK │                   │                │
│            │  description │                   │                │
│            │  day         │                   │                │
│            │  month       │                   │                │
│            │  owner FK    │                   │                │
│            └──────────────┘                   │                │
│                                               │                │
│  ┌──────────────┐    ┌──────────────┐        │                │
│  │feeding_sched │    │medicine_sched│        │                │
│  ├──────────────┤    ├──────────────┤        │                │
│  │ *id PK       │    │ *id PK       │        │                │
│  │  pet_name FK │    │  pet_name FK │        │                │
│  │  details     │    │  details     │        │                │
│  │  owner FK    │    │  owner FK    │        │                │
│  └──────────────┘    └──────────────┘        │                │
│                                               │                │
│  ┌──────────────┐    ┌──────────────┐        │                │
│  │stray_animals │    │adopted_animal│        │                │
│  ├──────────────┤    ├──────────────┤        │                │
│  │ *id PK       │───▶│ *id PK       │        │                │
│  │  type        │    │  type        │        │                │
│  │  gender      │    │  gender      │        │                │
│  │  arrival_date│    │  arrival_date│        │                │
│  │  age         │    │  age         │        │                │
│  └──────────────┘    │  owner FK    │────────┘                │
│                      │  adopt_date  │                          │
│                      └──────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Veritabanı Tabloları

| Tablo | Amaç | Satır Boyutu |
|-------|------|--------------|
| `users` | Kullanıcı kimlik bilgileri | ~300 byte |
| `pets` | Evcil hayvan kayıtları | ~200 byte |
| `appointments` | Veteriner randevuları | ~250 byte |
| `feeding_schedules` | Besleme programları | ~200 byte |
| `medicine_schedules` | İlaç programları | ~200 byte |
| `exercise_routines` | Egzersiz rutinleri | ~200 byte |
| `grooming_routines` | Bakım rutinleri | ~200 byte |
| `birthdays` | Doğum günü kayıtları | ~150 byte |
| `stray_animals` | Başıboş hayvanlar | ~200 byte |
| `adopted_animals` | Sahiplenilen hayvanlar | ~250 byte |

---

## 6. Güvenlik Mimarisi

### 6.1 Güvenlik Katmanları

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: RASP (Runtime Application Self-Protection)           │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ • Anti-debugging (IsDebuggerPresent, ptrace)              │ │
│  │ • Control Flow Integrity (CFI counters)                   │ │
│  │ • Tamper Detection (checksum verification)                │ │
│  │ • Hook Detection (inline/IAT hooks)                       │ │
│  │ • Device Trust Assessment (root/emulator detection)       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│  Layer 2: Code Hardening                                       │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ • Opaque Predicates (always true/false)                   │ │
│  │ • Mixed Boolean-Arithmetic (MBA)                          │ │
│  │ • Dead Code Injection                                     │ │
│  │ • String Obfuscation (XOR encoding)                       │ │
│  │ • Control Flow Obfuscation (state machines)               │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│  Layer 3: Cryptography                                         │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ • Whitebox AES-128 (key hidden in tables)                 │ │
│  │ • Whitebox DES (cascade encryption)                       │ │
│  │ • HMAC-SHA256 (integrity verification)                    │ │
│  │ • PBKDF2 (key derivation)                                 │ │
│  │ • XOR Password Encryption                                  │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│  Layer 4: Memory Protection                                    │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ • Secure Allocation (canary values)                       │ │
│  │ • Automatic Memory Wiping (SecureAutoWipe)                │ │
│  │ • Guard Pages (overflow detection)                        │ │
│  │ • Constant-Time Comparison                                │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│  Layer 5: Asset Protection                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ • Device Fingerprinting (hardware binding)                │ │
│  │ • Session Management (device-bound tokens)                │ │
│  │ • Obfuscated Strings (runtime decryption)                 │ │
│  │ • Integrity Hash (app verification)                       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Kimlik Doğrulama Akışı

```
┌─────────────────────────────────────────────────────────────────┐
│                  AUTHENTICATION FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │  User   │───▶│   Input      │───▶│  Validate    │           │
│  │  Input  │    │  Username    │    │  Format      │           │
│  └─────────┘    │  Password    │    └──────┬───────┘           │
│                 └──────────────┘           │                    │
│                                            ▼                    │
│                                   ┌──────────────┐              │
│                                   │  Hash Table  │              │
│                                   │   Lookup     │              │
│                                   └──────┬───────┘              │
│                                          │                      │
│                    ┌─────────────────────┼─────────────────┐   │
│                    │ Found               │ Not Found       │   │
│                    ▼                     ▼                 │   │
│           ┌──────────────┐      ┌──────────────┐          │   │
│           │   Decrypt    │      │    Return    │          │   │
│           │   Password   │      │    Failure   │          │   │
│           │   (XOR)      │      └──────────────┘          │   │
│           └──────┬───────┘                                │   │
│                  │                                        │   │
│                  ▼                                        │   │
│           ┌──────────────┐                               │   │
│           │   Compare    │                               │   │
│           │   Passwords  │                               │   │
│           └──────┬───────┘                               │   │
│                  │                                        │   │
│       ┌──────────┼──────────┐                            │   │
│       │ Match    │ No Match │                            │   │
│       ▼          ▼          │                            │   │
│  ┌──────────┐  ┌──────────┐ │                            │   │
│  │ Generate │  │  Return  │ │                            │   │
│  │ Device   │  │  Failure │ │                            │   │
│  │Fingerprint│  └──────────┘ │                            │   │
│  └────┬─────┘               │                            │   │
│       │                     │                            │   │
│       ▼                     │                            │   │
│  ┌──────────┐               │                            │   │
│  │ Create   │               │                            │   │
│  │ Session  │               │                            │   │
│  │ (Bound)  │               │                            │   │
│  └────┬─────┘               │                            │   │
│       │                     │                            │   │
│       ▼                     │                            │   │
│  ┌──────────┐               │                            │   │
│  │ SUCCESS  │               │                            │   │
│  └──────────┘               │                            │   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Şifreleme Mimarisi

### 7.1 Cascade Encryption (AES-DES-AES)

```
┌─────────────────────────────────────────────────────────────────┐
│               CASCADE ENCRYPTION PIPELINE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Plaintext                                                      │
│      │                                                          │
│      ▼                                                          │
│  ┌──────────────────────────┐                                  │
│  │      PKCS#7 Padding      │                                  │
│  │   (16-byte alignment)    │                                  │
│  └────────────┬─────────────┘                                  │
│               │                                                 │
│               ▼                                                 │
│  ┌──────────────────────────┐                                  │
│  │    Whitebox AES-128      │  Key: K1 (embedded in tables)    │
│  │       (Layer 1)          │  Mode: CBC                       │
│  └────────────┬─────────────┘                                  │
│               │                                                 │
│               ▼                                                 │
│  ┌──────────────────────────┐                                  │
│  │    Whitebox DES          │  Key: K2 (embedded in tables)    │
│  │       (Layer 2)          │  Mode: ECB                       │
│  └────────────┬─────────────┘                                  │
│               │                                                 │
│               ▼                                                 │
│  ┌──────────────────────────┐                                  │
│  │    Whitebox AES-128      │  Key: K3 (embedded in tables)    │
│  │       (Layer 3)          │  Mode: CBC                       │
│  └────────────┬─────────────┘                                  │
│               │                                                 │
│               ▼                                                 │
│  ┌──────────────────────────┐                                  │
│  │    HMAC-SHA256           │  Integrity verification          │
│  │    (Append to header)    │                                  │
│  └────────────┬─────────────┘                                  │
│               │                                                 │
│               ▼                                                 │
│           Ciphertext                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Key Derivation (Veritabanı Anahtarı)

```
┌─────────────────────────────────────────────────────────────────┐
│                KEY DERIVATION PROCESS                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │ Device Info     │    │ App Binary      │                    │
│  │ - Disk Serial   │    │ - .text section │                    │
│  │ - Computer Name │    │ - Code hash     │                    │
│  │ - Username      │    │                 │                    │
│  │ - Process ID    │    │                 │                    │
│  └────────┬────────┘    └────────┬────────┘                    │
│           │                      │                              │
│           ▼                      ▼                              │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │ Device          │    │ App Integrity   │                    │
│  │ Fingerprint     │    │ Hash            │                    │
│  │ (64 bytes)      │    │ (32 bytes)      │                    │
│  └────────┬────────┘    └────────┬────────┘                    │
│           │                      │                              │
│           └──────────┬───────────┘                             │
│                      │                                          │
│                      ▼                                          │
│           ┌─────────────────┐                                  │
│           │     PBKDF2      │                                  │
│           │ - Iterations:   │                                  │
│           │   20,000        │                                  │
│           │ - Salt: FP[0:16]│                                  │
│           │ - Hash: SHA-256 │                                  │
│           └────────┬────────┘                                  │
│                    │                                            │
│                    ▼                                            │
│           ┌─────────────────┐                                  │
│           │  Database Key   │                                  │
│           │  (32 bytes)     │                                  │
│           └─────────────────┘                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Uygulama Akışı

### 8.1 Başlatma Sırası

```
┌─────────────────────────────────────────────────────────────────┐
│                 APPLICATION STARTUP SEQUENCE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. main() Entry                                               │
│      │                                                          │
│      ▼                                                          │
│  2. obf_init()           ──▶ Code obfuscation warmup           │
│      │                                                          │
│      ▼                                                          │
│  3. initialize_rasp_security()                                 │
│      ├── rasp_init()                                           │
│      ├── verify_application_integrity()                        │
│      ├── rasp_comprehensive_check()                            │
│      └── rasp_assess_device_trust()                            │
│      │                                                          │
│      ▼                                                          │
│  4. verify_or_bootstrap_app_hash()                             │
│      │                                                          │
│      ▼                                                          │
│  5. init_petcare_session()                                     │
│      │                                                          │
│      ▼                                                          │
│  6. derive_database_key()                                      │
│      │                                                          │
│      ▼                                                          │
│  7. init_petcare_database()                                    │
│      ├── db_init()                                             │
│      └── db_create_tables()                                    │
│      │                                                          │
│      ▼                                                          │
│  8. migrate_dat_to_sqlite() (if needed)                        │
│      │                                                          │
│      ▼                                                          │
│  9. navigateUserAuthentication()                               │
│      │                                                          │
│      ▼                                                          │
│  10. navigateMainMenu()                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Test Mimarisi

### 9.1 Test Organizasyonu

```
tests/
├── utility/                         # 181 Güvenlik Testi
│   ├── asset_protection_test.cpp    # 24 test
│   ├── rasp_security_test.cpp       # 32 test
│   ├── secure_memory_test.cpp       # 18 test
│   ├── security_test_test.cpp       # 30 test
│   ├── utility_test.cpp             # 45 test
│   └── whitebox_crypto_test.cpp     # 32 test
│
└── petcare/                         # 264 İş Mantığı Testi
    ├── petcare_test.cpp             # 250 test
    └── database_encryption_test.cpp # 14 test
```

### 9.2 Test Piramidi

```
                    ┌─────────────┐
                   /│   E2E (5)   │\
                  / └─────────────┘ \
                 /   Integration     \
                /    ┌─────────────┐  \
               /     │   (45)      │   \
              /      └─────────────┘    \
             /         Unit Tests        \
            /      ┌─────────────────┐    \
           /       │      (395)      │     \
          /        └─────────────────┘      \
         ──────────────────────────────────────
```

---

## 10. Performans Metrikleri

| Metrik | Değer |
|--------|-------|
| Toplam Satır Sayısı | ~15,000 |
| Fonksiyon Sayısı | 200+ |
| Test Sayısı | 445 |
| Kod Kapsama | >70% |
| Build Süresi (Release) | ~30 saniye |
| Çalıştırılabilir Boyutu | ~2 MB |

---

## 11. Platform Desteği

| Platform | Durum | Notlar |
|----------|-------|--------|
| Windows 10/11 | ✅ | Tam destek |
| Ubuntu 20.04+ | ✅ | Tam destek |
| macOS | ⚠️ | Deneysel |

---

## 12. İlgili Belgeler

- [Güvenlik Raporu](security/report.md)
- [Varlık Yönetimi](security/assets.md)
- [Güvenlik Sertifikasyonu](security/security_certification.md)
- [Penetrasyon Test Planı](security/penetration_test_plan.md)
