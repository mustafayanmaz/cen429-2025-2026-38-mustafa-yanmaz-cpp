# 🔐 PetCare Security Architecture Diagrams

**Proje:** PetCare Management System - Security Architecture  
**Tarih:** 2025-12-25  
**Versiyon:** 1.0

---

## 📋 İçindekiler

1. [Genel Sistem Mimarisi](#1-genel-sistem-mimarisi)
2. [Güvenlik Katmanları](#2-güvenlik-katmanları)
3. [Kimlik Doğrulama Akışı](#3-kimlik-doğrulama-akışı)
4. [Whitebox Kriptografi Akışı](#4-whitebox-kriptografi-akışı)
5. [RASP Güvenlik Mekanizmaları](#5-rasp-güvenlik-mekanizmaları)
6. [Bellek Güvenliği Akışı](#6-bellek-güvenliği-akışı)
7. [Veritabanı Şifreleme Mimarisi](#7-veritabanı-şifreleme-mimarisi)
8. [Session Yönetimi](#8-session-yönetimi)
9. [Kod Sertleştirme (Obfuscation)](#9-kod-sertleştirme-obfuscation)
10. [Tehdit Modeli](#10-tehdit-modeli)
11. [Veri Akış Diyagramları](#11-veri-akış-diyagramları)
12. [Saldırı Yüzeyi Analizi](#12-saldırı-yüzeyi-analizi)

---

## 1. Genel Sistem Mimarisi

### 1.1 Yüksek Seviye Sistem Mimarisi

```mermaid
graph TB
    subgraph "🖥️ PetCare Application"
        subgraph "Presentation Layer"
            CLI[📟 CLI Interface<br/>petcareapp.cpp]
        end
        
        subgraph "Business Logic Layer"
            AUTH[🔐 Authentication<br/>Module]
            PET[🐾 Pet Management]
            APT[📅 Appointment<br/>System]
            SCHED[⏰ Schedule<br/>Management]
            STRAY[🐕 Stray Animal<br/>Management]
        end
        
        subgraph "Security Layer"
            RASP[🛡️ RASP Security]
            CRYPTO[🔒 Whitebox Crypto]
            MEM[💾 Secure Memory]
            OBF[🎭 Code Obfuscation]
            ASSET[📦 Asset Protection]
        end
        
        subgraph "Data Layer"
            DB[(🗄️ SQLite DB<br/>Encrypted)]
            SESSION[🎫 Session Store]
            FP[👆 Device Fingerprint]
        end
    end
    
    CLI --> AUTH
    CLI --> PET
    CLI --> APT
    CLI --> SCHED
    CLI --> STRAY
    
    AUTH --> RASP
    AUTH --> SESSION
    AUTH --> FP
    
    PET --> CRYPTO
    APT --> CRYPTO
    SCHED --> CRYPTO
    STRAY --> CRYPTO
    
    CRYPTO --> DB
    CRYPTO --> MEM
    
    RASP --> OBF
    RASP --> ASSET
    
    style RASP fill:#ff6b6b,color:#fff
    style CRYPTO fill:#4ecdc4,color:#fff
    style MEM fill:#45b7d1,color:#fff
    style DB fill:#96ceb4,color:#fff
```

### 1.2 Modül Bağımlılık Diyagramı

```mermaid
graph LR
    subgraph "External"
        SQLITE[SQLite3]
        GTEST[GoogleTest]
    end
    
    subgraph "Utility Layer"
        WBC[whiteboxCrypto]
        SM[secureMemory]
        RASP[raspSecurity]
        CO[codeObfuscation]
        AP[assetProtection]
        SHA[sha256]
        ST[securityTest]
    end
    
    subgraph "Core Layer"
        PC[petcare]
        DBC[database]
    end
    
    subgraph "Application Layer"
        APP[petcareapp]
    end
    
    APP --> PC
    APP --> RASP
    
    PC --> DBC
    PC --> AP
    PC --> SM
    
    DBC --> SQLITE
    DBC --> WBC
    
    WBC --> SM
    WBC --> SHA
    
    RASP --> SHA
    RASP --> CO
    
    AP --> SM
    AP --> WBC
    
    ST --> WBC
    ST --> RASP
    ST --> SM
    
    style WBC fill:#e74c3c,color:#fff
    style RASP fill:#9b59b6,color:#fff
    style SM fill:#3498db,color:#fff
```

---

## 2. Güvenlik Katmanları

### 2.1 Defense in Depth (Derinlemesine Savunma)

```mermaid
graph TB
    subgraph "Layer 6: Application Security"
        L6[🎭 Code Obfuscation<br/>Opaque Predicates<br/>Control Flow Flattening]
    end
    
    subgraph "Layer 5: Runtime Protection"
        L5[🛡️ RASP<br/>Debugger Detection<br/>Hook Detection<br/>Tamper Detection]
    end
    
    subgraph "Layer 4: Memory Security"
        L4[💾 Secure Memory<br/>Encrypted Buffers<br/>Secure Wipe<br/>Memory Locking]
    end
    
    subgraph "Layer 3: Cryptography"
        L3[🔐 Whitebox Crypto<br/>AES-128 / RSA / DES<br/>Cascade Encryption<br/>HMAC Integrity]
    end
    
    subgraph "Layer 2: Access Control"
        L2[🔑 Authentication<br/>Session Management<br/>Device Binding<br/>Owner Verification]
    end
    
    subgraph "Layer 1: Data Protection"
        L1[🗄️ Database Encryption<br/>Encrypted at Rest<br/>Secure Temp Files]
    end
    
    ATTACKER((☠️ Attacker)) --> L6
    L6 --> L5
    L5 --> L4
    L4 --> L3
    L3 --> L2
    L2 --> L1
    L1 --> DATA[(🏆 Protected Data)]
    
    style ATTACKER fill:#e74c3c,color:#fff
    style DATA fill:#27ae60,color:#fff
    style L6 fill:#f39c12,color:#fff
    style L5 fill:#e74c3c,color:#fff
    style L4 fill:#3498db,color:#fff
    style L3 fill:#9b59b6,color:#fff
    style L2 fill:#1abc9c,color:#fff
    style L1 fill:#2ecc71,color:#fff
```

### 2.2 Güvenlik Bileşenleri İlişki Diyagramı

```mermaid
graph TD
    subgraph "Detection"
        DD[🔍 Debugger Detection]
        HD[🪝 Hook Detection]
        TD[🔧 Tamper Detection]
        ED[📱 Emulator Detection]
        RD[🔓 Root Detection]
    end
    
    subgraph "Prevention"
        CFI[🔄 Control Flow Integrity]
        CS[✅ Checksum Verification]
        SV[✍️ Signature Verification]
    end
    
    subgraph "Response"
        LOG[📝 Log Event]
        ALERT[⚠️ Alert]
        BLOCK[🚫 Block Operation]
        TERM[💀 Terminate App]
    end
    
    DD --> LOG
    DD --> TERM
    HD --> ALERT
    HD --> BLOCK
    TD --> TERM
    ED --> LOG
    RD --> BLOCK
    
    CFI --> ALERT
    CS --> TERM
    SV --> BLOCK
    
    style DD fill:#e74c3c,color:#fff
    style HD fill:#e74c3c,color:#fff
    style TD fill:#e74c3c,color:#fff
    style TERM fill:#c0392b,color:#fff
```

---

## 3. Kimlik Doğrulama Akışı

### 3.1 Login Flow (Oturum Açma Akışı)

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant CLI as 📟 CLI
    participant AUTH as 🔐 Auth Module
    participant RASP as 🛡️ RASP
    participant FP as 👆 Fingerprint
    participant SESSION as 🎫 Session
    participant DB as 🗄️ Database
    
    U->>CLI: Enter username/password
    CLI->>RASP: Security Check
    
    alt Debugger Detected
        RASP-->>CLI: ❌ Security Violation
        CLI-->>U: Application Terminated
    end
    
    RASP-->>CLI: ✅ Security OK
    CLI->>AUTH: loginUserWithSession()
    AUTH->>FP: generate_device_fingerprint()
    FP-->>AUTH: DeviceFingerprint
    
    AUTH->>DB: db_get_user_password()
    DB-->>AUTH: encrypted_password
    
    AUTH->>AUTH: encryptPassword(input)
    
    alt Password Match
        AUTH->>SESSION: create_session()
        SESSION->>SESSION: Generate session_id
        SESSION->>SESSION: Encrypt session_key
        SESSION->>SESSION: Bind to fingerprint
        SESSION-->>AUTH: SessionData
        AUTH-->>CLI: ✅ Login Success
        CLI-->>U: Welcome Message
    else Password Mismatch
        AUTH-->>CLI: ❌ Authentication Failed
        CLI-->>U: Invalid Credentials
    end
```

### 3.2 Session Doğrulama Akışı

```mermaid
flowchart TD
    START([🚀 Operation Request]) --> CHECK{isSessionValid?}
    
    CHECK -->|No Session| FAIL1[❌ No Active Session]
    
    CHECK -->|Has Session| EXPIRY{Session Expired?}
    
    EXPIRY -->|Yes| FAIL2[❌ Session Expired]
    EXPIRY -->|No| FP_CHECK{Fingerprint Match?}
    
    FP_CHECK -->|No| FAIL3[❌ Device Mismatch]
    FP_CHECK -->|Yes| INTEGRITY{Integrity Check?}
    
    INTEGRITY -->|Fail| FAIL4[❌ Session Tampered]
    INTEGRITY -->|Pass| SUCCESS[✅ Session Valid]
    
    FAIL1 --> REDIRECT[Redirect to Login]
    FAIL2 --> REDIRECT
    FAIL3 --> TERMINATE[🚨 Security Alert]
    FAIL4 --> TERMINATE
    
    SUCCESS --> PROCEED[Continue Operation]
    
    style FAIL1 fill:#e74c3c,color:#fff
    style FAIL2 fill:#e74c3c,color:#fff
    style FAIL3 fill:#c0392b,color:#fff
    style FAIL4 fill:#c0392b,color:#fff
    style SUCCESS fill:#27ae60,color:#fff
    style TERMINATE fill:#8e44ad,color:#fff
```

---

## 4. Whitebox Kriptografi Akışı

### 4.1 Cascade Encryption (AES → DES → AES)

```mermaid
graph LR
    subgraph "Input"
        PT[📄 Plaintext]
    end
    
    subgraph "Layer 1: AES-128"
        AES1_K[🔑 AES Key 1<br/>Obfuscated in<br/>Lookup Tables]
        AES1[🔒 WB-AES<br/>Encrypt]
    end
    
    subgraph "Layer 2: DES"
        DES_K[🔑 DES Key<br/>Obfuscated in<br/>S-Box Tables]
        DES[🔒 WB-DES<br/>Encrypt]
    end
    
    subgraph "Layer 3: AES-128"
        AES2_K[🔑 AES Key 2<br/>Obfuscated in<br/>Lookup Tables]
        AES2[🔒 WB-AES<br/>Encrypt]
    end
    
    subgraph "Output"
        CT[🔐 Ciphertext]
        HMAC[✓ HMAC-SHA256]
    end
    
    PT --> AES1
    AES1_K -.-> AES1
    AES1 --> DES
    DES_K -.-> DES
    DES --> AES2
    AES2_K -.-> AES2
    AES2 --> CT
    CT --> HMAC
    
    style PT fill:#3498db,color:#fff
    style CT fill:#27ae60,color:#fff
    style HMAC fill:#f39c12,color:#fff
    style AES1 fill:#9b59b6,color:#fff
    style DES fill:#e74c3c,color:#fff
    style AES2 fill:#9b59b6,color:#fff
```

### 4.2 Dosya Şifreleme Yapısı

```mermaid
graph TB
    subgraph "Encrypted File Structure"
        subgraph "Header (88 bytes)"
            MAGIC[Magic: 0x57424358<br/>'WBCX']
            VER[Version: 0x0001]
            LAYER[Layer Type:<br/>CASCADE]
            PAD[Padding Size]
            ORIG[Original Size]
            SALT[Salt: 16 bytes]
            IV[IV: 16 bytes]
            HMAC_H[HMAC: 32 bytes]
        end
        
        subgraph "Encrypted Payload"
            DATA[🔐 Cascade Encrypted Data<br/>AES → DES → AES]
        end
    end
    
    MAGIC --> VER --> LAYER --> PAD --> ORIG --> SALT --> IV --> HMAC_H --> DATA
    
    style MAGIC fill:#e74c3c,color:#fff
    style HMAC_H fill:#f39c12,color:#fff
    style DATA fill:#27ae60,color:#fff
```

### 4.3 Anahtar Türetme (Key Derivation)

```mermaid
flowchart LR
    subgraph "Inputs"
        PWD[🔑 Password]
        SALT[🧂 Random Salt<br/>16 bytes]
        ITER[🔄 Iterations<br/>20,000+]
    end
    
    subgraph "PBKDF2 Process"
        HMAC1[HMAC-SHA256<br/>Round 1]
        HMAC2[HMAC-SHA256<br/>Round 2]
        HMACN[HMAC-SHA256<br/>Round N]
        XOR[⊕ XOR All Rounds]
    end
    
    subgraph "Output Keys"
        AES1_OUT[AES Key 1<br/>16 bytes]
        DES_OUT[DES Key<br/>8 bytes]
        AES2_OUT[AES Key 2<br/>16 bytes]
    end
    
    PWD --> HMAC1
    SALT --> HMAC1
    HMAC1 --> HMAC2 --> HMACN
    HMAC1 --> XOR
    HMAC2 --> XOR
    HMACN --> XOR
    
    XOR --> AES1_OUT
    XOR --> DES_OUT
    XOR --> AES2_OUT
    
    style PWD fill:#3498db,color:#fff
    style XOR fill:#9b59b6,color:#fff
```

---

## 5. RASP Güvenlik Mekanizmaları

### 5.1 RASP Genel Akışı

```mermaid
flowchart TD
    START([🚀 Application Start]) --> INIT[Initialize RASP]
    
    INIT --> CONFIG[Load RASPConfig]
    CONFIG --> CHECKS
    
    subgraph CHECKS [Parallel Security Checks]
        direction TB
        C1[🔍 Debugger Check]
        C2[🪝 Hook Scan]
        C3[✅ Checksum Verify]
        C4[📱 Emulator Check]
        C5[🔓 Root Detection]
        C6[📁 System File Check]
    end
    
    CHECKS --> SCORE[Calculate Trust Score]
    
    SCORE --> DECISION{Trust Score >= 70?}
    
    DECISION -->|Yes| SAFE[✅ Trusted Environment]
    DECISION -->|No| UNSAFE[❌ Untrusted Environment]
    
    SAFE --> MONITOR[Start Continuous Monitoring]
    UNSAFE --> ACTION{Default Action?}
    
    ACTION -->|LOG| LOG_ACT[📝 Log and Continue]
    ACTION -->|ALERT| ALERT_ACT[⚠️ Show Warning]
    ACTION -->|BLOCK| BLOCK_ACT[🚫 Block Features]
    ACTION -->|TERMINATE| TERM_ACT[💀 Exit Application]
    
    LOG_ACT --> MONITOR
    ALERT_ACT --> MONITOR
    BLOCK_ACT --> LIMITED[Run in Limited Mode]
    TERM_ACT --> EXIT([Exit])
    
    MONITOR --> PERIODIC{Every 10 Iterations}
    PERIODIC --> CHECKS
    
    style SAFE fill:#27ae60,color:#fff
    style UNSAFE fill:#e74c3c,color:#fff
    style TERM_ACT fill:#c0392b,color:#fff
```

### 5.2 Debugger Detection Mekanizmaları

```mermaid
graph TD
    subgraph "Windows Detection"
        W1["IsDebuggerPresent API"]
        W2["CheckRemoteDebuggerPresent"]
        W3["NtQueryInformationProcess"]
        W4["PEB.BeingDebugged Flag"]
    end
    
    subgraph "Linux Detection"
        L1["/proc/self/status<br/>TracerPid Check"]
        L2["ptrace PTRACE_TRACEME"]
        L3["/proc/self/exe Verification"]
    end
    
    subgraph "Generic Detection"
        G1["Hardware Breakpoints<br/>DR0–DR7 Registers"]
        G2["Software Breakpoints<br/>INT3 (0xCC) Scan"]
        G3["Timing Anomaly<br/>RDTSC Check"]
    end
    
    W1 --> RESULT{Any Detected?}
    W2 --> RESULT
    W3 --> RESULT
    W4 --> RESULT
    L1 --> RESULT
    L2 --> RESULT
    L3 --> RESULT
    G1 --> RESULT
    G2 --> RESULT
    G3 --> RESULT
    
    RESULT -->|Yes| DETECTED["🚨 Debugger Detected"]
    RESULT -->|No| CLEAN["✅ No Debugger"]
    
    style DETECTED fill:#e74c3c,color:#fff
    style CLEAN fill:#27ae60,color:#fff
```

### 5.3 Hook Detection Akışı

```mermaid
sequenceDiagram
    participant APP as 📟 Application
    participant RASP as 🛡️ RASP
    participant MEM as 💾 Memory
    participant FUNC as 🔧 Protected Function
    
    APP->>RASP: rasp_scan_all_hooks()
    
    loop For Each Critical Function
        RASP->>MEM: Read function bytes
        MEM-->>RASP: Current bytes
        
        RASP->>RASP: Compare with<br/>original bytes
        
        alt JMP/CALL Detected at Start
            RASP->>RASP: Check for E9 (JMP rel32)
            RASP->>RASP: Check for FF 25 (JMP [addr])
            RASP->>RASP: Check for 68 C3 (PUSH RET)
            RASP-->>APP: ⚠️ Inline Hook Detected
        end
        
        alt IAT Modified (Windows)
            RASP->>RASP: Verify IAT entries
            RASP-->>APP: ⚠️ IAT Hook Detected
        end
    end
    
    RASP-->>APP: HookInfo[] results
    
    APP->>APP: Log detected hooks
    APP->>APP: Take protective action
```

### 5.4 Control Flow Integrity (CFI)

```mermaid
stateDiagram-v2
    [*] --> Init: rasp_init_cfi()
    
    Init --> Checkpoint1: Create counter #1
    Checkpoint1 --> Checkpoint2: Increment
    Checkpoint2 --> Checkpoint3: Increment
    Checkpoint3 --> Verify: rasp_verify_cfi_counter()
    
    Verify --> Valid: Counter matches expected
    Verify --> Violation: Counter mismatch
    
    Valid --> Continue: ✅ Continue execution
    Violation --> Alert: ⚠️ CFI Violation
    
    Alert --> Log: Log attack
    Log --> Terminate: 💀 Terminate
    
    Continue --> Checkpoint1: Next iteration
    
    state Checkpoint1 {
        [*] --> Counter0
        Counter0 --> Counter1: +1
    }
    
    state Checkpoint2 {
        [*] --> Counter1
        Counter1 --> Counter2: +1
    }
    
    state Checkpoint3 {
        [*] --> Counter2
        Counter2 --> Counter3: +1
    }
```

---

## 6. Bellek Güvenliği Akışı

### 6.1 Secure Memory Lifecycle

```mermaid
graph TD
    subgraph "Allocation"
        A1[secure_malloc]
        A2[Allocate memory]
        A3[Zero-initialize]
    end
    
    subgraph "Usage"
        U1[secure_buffer_create]
        U2[secure_buffer_write]
        U3[Encrypt in memory]
        U4[secure_buffer_read]
        U5[Decrypt temporarily]
    end
    
    subgraph "Protection"
        P1[secure_mlock]
        P2[Prevent swap to disk]
        P3[In-memory encryption]
    end
    
    subgraph "Cleanup"
        C1[secure_wipe]
        C2[Pass 1: 0xFF]
        C3[Pass 2: 0x00]
        C4[Pass 3: Random]
        C5[secure_free]
    end
    
    A1 --> A2 --> A3 --> U1
    U1 --> U2 --> U3 --> U4 --> U5
    
    A3 --> P1 --> P2
    U3 --> P3
    
    U5 --> C1 --> C2 --> C3 --> C4 --> C5
    
    style A1 fill:#3498db,color:#fff
    style C1 fill:#e74c3c,color:#fff
    style P3 fill:#9b59b6,color:#fff
```

### 6.2 SecureBuffer Yapısı

```mermaid
classDiagram
    class SecureBuffer {
        +unsigned char* data
        +size_t size
        +unsigned char key[32]
        +unsigned char iv[16]
        +int is_encrypted
        +create(size) SecureBuffer*
        +write(data, size) int
        +read(out_size) void*
        +destroy() void
    }
    
    class SecureAutoWipe {
        +void* ptr
        +size_t len
        +SecureAutoWipe(ptr, len)
        +~SecureAutoWipe()
    }
    
    SecureBuffer --> "uses" SecureAutoWipe : RAII cleanup
    
    note for SecureBuffer "Data is always encrypted\nwhen stored in memory"
    note for SecureAutoWipe "Automatically wipes memory\non scope exit"
```

### 6.3 Memory Wipe Process

```mermaid
flowchart LR
    subgraph "Original Data"
        ORIG[S E C R E T]
    end
    
    subgraph "Pass 1"
        P1[0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
    end
    
    subgraph "Pass 2"
        P2[0x00 0x00 0x00 0x00 0x00 0x00]
    end
    
    subgraph "Pass 3"
        P3[🎲 Random bytes]
    end
    
    subgraph "Final"
        CLEAN[Memory freed]
    end
    
    ORIG -->|"memset 0xFF"| P1
    P1 -->|"memset 0x00"| P2
    P2 -->|"random bytes"| P3
    P3 -->|"free()"| CLEAN
    
    style ORIG fill:#e74c3c,color:#fff
    style CLEAN fill:#27ae60,color:#fff
```

---

## 7. Veritabanı Şifreleme Mimarisi

### 7.1 Database Encryption Flow

```mermaid
sequenceDiagram
    participant APP as 📟 Application
    participant DB as 🗄️ Database Module
    participant WBC as 🔐 Whitebox Crypto
    participant FS as 📁 File System
    
    Note over APP,FS: Database Open (Secure Mode)
    
    APP->>DB: db_init(path, password)
    DB->>FS: Check if .db.enc exists
    FS-->>DB: File exists
    
    DB->>WBC: wb_decrypt_file()
    WBC->>WBC: Verify HMAC
    WBC->>WBC: Cascade Decrypt
    WBC->>FS: Write temp plaintext
    FS-->>WBC: Temp file created
    WBC-->>DB: Decryption success
    
    DB->>DB: sqlite3_open(temp_path)
    DB-->>APP: Database* handle
    
    Note over APP,FS: Database Operations
    
    APP->>DB: db_add_pet(...)
    DB->>DB: sqlite3_exec(INSERT)
    DB-->>APP: Success
    
    Note over APP,FS: Database Close
    
    APP->>DB: db_close()
    DB->>DB: sqlite3_close()
    DB->>WBC: wb_encrypt_file()
    WBC->>WBC: Cascade Encrypt
    WBC->>WBC: Generate HMAC
    WBC->>FS: Write .db.enc
    WBC->>FS: Delete temp file
    DB-->>APP: Closed and encrypted
```

### 7.2 Veritabanı Şema Güvenliği

```mermaid
erDiagram
    USERS ||--o{ PETS : owns
    USERS ||--o{ APPOINTMENTS : has
    USERS ||--o{ FEEDING_SCHEDULES : manages
    USERS ||--o{ MEDICINE_SCHEDULES : manages
    USERS ||--o{ ADOPTED_ANIMALS : adopts
    
    USERS {
        int id PK
        string username UK "Encrypted at rest"
        string encrypted_password "XOR + Whitebox"
    }
    
    PETS {
        int id PK
        string name "Encrypted"
        string type "Encrypted"
        int age
        string owner FK "References USERS"
    }
    
    APPOINTMENTS {
        int id PK
        string pet_name FK "Encrypted"
        string description "Encrypted"
        int day
        int month
        string owner FK
    }
    
    STRAY_ANIMALS {
        int id PK
        string type
        string gender
        string arrival_date
        int age
    }
    
    ADOPTED_ANIMALS {
        int id PK
        string type
        string owner FK
        string adoption_date
    }
```

---

## 8. Session Yönetimi

### 8.1 Session Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NoSession: Application Start
    
    NoSession --> Creating: Login Request
    Creating --> Active: Session Created
    
    Active --> Validating: Operation Request
    Validating --> Active: ✅ Valid
    Validating --> Expired: ⏰ Timeout
    Validating --> Invalid: ❌ Tampered
    
    Active --> Rotating: Key Rotation
    Rotating --> Active: New Key Applied
    
    Active --> Destroying: Logout Request
    
    Expired --> Destroying: Auto-cleanup
    Invalid --> Destroying: Security cleanup
    
    Destroying --> NoSession: Session Destroyed
    
    state Active {
        [*] --> Idle
        Idle --> InUse: Access
        InUse --> Idle: Complete
        InUse --> Idle: access_count++
    }
```

### 8.2 Session Data Structure

```mermaid
graph TD
    subgraph "SessionData Structure"
        SID["session_id<br/>32 bytes<br/>🆔 Unique identifier"]
        SKEY["session_key<br/>32 bytes<br/>🔐 Encrypted"]
        IV["encryption_iv<br/>16 bytes<br/>🎲 Random"]
        CTIME["creation_time<br/>64 bits<br/>⏰ Timestamp"]
        ETIME["expiry_time<br/>64 bits<br/>⌛ Deadline"]
        ACOUNT["access_count<br/>32 bits<br/>📊 Usage"]
        FPHASH["fingerprint_hash<br/>32 bytes<br/>👆 Device binding"]
        ICHK["integrity_check<br/>32 bits<br/>✅ Tamper detect"]
    end
    
    subgraph "Validation Rules"
        R1["current_time < expiry_time"]
        R2["hash(current_fp) == fingerprint_hash"]
        R3["crc32(session) == integrity_check"]
    end
    
    SID --> R2
    FPHASH --> R2
    ETIME --> R1
    ICHK --> R3
    
    R1 --> VALID{All Pass?}
    R2 --> VALID
    R3 --> VALID
    
    VALID -->|Yes| OK["✅ Session Valid"]
    VALID -->|No| FAIL["❌ Session Invalid"]
    
    style SID fill:#3498db,color:#fff
    style SKEY fill:#9b59b6,color:#fff
    style FPHASH fill:#e74c3c,color:#fff
```

---

## 9. Kod Sertleştirme (Obfuscation)

### 9.1 Obfuscation Teknikleri

```mermaid
mindmap
  root(("Code Obfuscation"))
    Opaque Predicates
      opaque_true
        always_even_property
      opaque_false
        impossible_condition
      opaque_complex
        algebraic_identity
    MBA Operations
      obf_add
        bitwise_equivalent
      obf_sub
        complement_and_add
      obf_mul_const
        shift_add_method
    Control Flow
      CFDispatcher
      cf_transition
      random_exit_points
    String Obfuscation
      xor_encoding
      evolving_key
      runtime_decode
    Dead Code
      inject_dead_code
      fake_operation
      never_executes
    Stdlib Wrappers
      obf_strcpy
      obf_memcpy
      obf_strlen
      obf_strcmp
```

### 9.2 Opaque Predicate Akışı

```mermaid
graph TD
    subgraph "opaque_true(x)"
        IN1["Input: x"]
        CALC1["a = x^2 + x"]
        MOD1["result = a mod 2"]
        CHECK1{"result == 0?"}
        OUT1_T["Return TRUE"]
        OUT1_F["Never reached"]
    end
    
    subgraph "Mathematical Proof"
        PROOF["x^2 + x = x(x + 1)<br/>Product of consecutive integers<br/>Always even"]
    end
    
    IN1 --> CALC1 --> MOD1 --> CHECK1
    CHECK1 -->|Always| OUT1_T
    CHECK1 -.->|Never| OUT1_F
    
    PROOF -.-> CHECK1
    
    style OUT1_T fill:#27ae60,color:#fff
    style OUT1_F fill:#7f8c8d,color:#fff
    style PROOF fill:#f39c12,color:#fff
```

### 9.3 Control Flow Flattening

```mermaid
graph TD
    subgraph "Original Code"
        O1[Statement 1]
        O2[Statement 2]
        O3{Condition}
        O4[Then branch]
        O5[Else branch]
        O6[Statement 3]
    end
    
    O1 --> O2 --> O3
    O3 -->|True| O4
    O3 -->|False| O5
    O4 --> O6
    O5 --> O6
    
    subgraph "Flattened Code"
        INIT[state = 0]
        SW{Switch state}
        S0[Case 0: Statement 1<br/>state = 1]
        S1[Case 1: Statement 2<br/>state = 2]
        S2[Case 2: Check condition<br/>state = 3 or 4]
        S3[Case 3: Then branch<br/>state = 5]
        S4[Case 4: Else branch<br/>state = 5]
        S5[Case 5: Statement 3<br/>state = -1]
        LOOP{state >= 0?}
    end
    
    INIT --> SW
    SW --> S0
    SW --> S1
    SW --> S2
    SW --> S3
    SW --> S4
    SW --> S5
    S0 --> LOOP
    S1 --> LOOP
    S2 --> LOOP
    S3 --> LOOP
    S4 --> LOOP
    S5 --> LOOP
    LOOP -->|Yes| SW
    
    style SW fill:#9b59b6,color:#fff
```

---

## 10. Tehdit Modeli

### 10.1 STRIDE Threat Model

```mermaid
graph TD
    subgraph "STRIDE Threats"
        S[🎭 Spoofing<br/>Identity falsification]
        T[🔧 Tampering<br/>Data modification]
        R[🚫 Repudiation<br/>Deny actions]
        I[📖 Info Disclosure<br/>Data leakage]
        D[💣 DoS<br/>Service disruption]
        E[👑 Elevation<br/>Privilege escalation]
    end
    
    subgraph "Mitigations"
        M_S[Session + Device Binding<br/>Password Hashing]
        M_T[HMAC Integrity<br/>Checksum Verification<br/>Tamper Detection]
        M_R[Audit Logging<br/>Digital Signatures]
        M_I[Encryption at Rest<br/>Secure Memory<br/>Memory Wipe]
        M_D[Rate Limiting<br/>Resource Management]
        M_E[Owner Verification<br/>Access Control<br/>CFI]
    end
    
    S --> M_S
    T --> M_T
    R --> M_R
    I --> M_I
    D --> M_D
    E --> M_E
    
    style S fill:#e74c3c,color:#fff
    style T fill:#e74c3c,color:#fff
    style R fill:#e74c3c,color:#fff
    style I fill:#e74c3c,color:#fff
    style D fill:#e74c3c,color:#fff
    style E fill:#e74c3c,color:#fff
    
    style M_S fill:#27ae60,color:#fff
    style M_T fill:#27ae60,color:#fff
    style M_R fill:#27ae60,color:#fff
    style M_I fill:#27ae60,color:#fff
    style M_D fill:#27ae60,color:#fff
    style M_E fill:#27ae60,color:#fff
```

### 10.2 Attack Tree

```mermaid
graph TD
    GOAL[🎯 Compromise PetCare App]
    
    GOAL --> A1[Extract Sensitive Data]
    GOAL --> A2[Bypass Authentication]
    GOAL --> A3[Inject Malicious Code]
    GOAL --> A4[Reverse Engineer App]
    
    A1 --> A1_1[Memory Dump]
    A1 --> A1_2[Database File Access]
    A1 --> A1_3[Debug & Inspect]
    
    A2 --> A2_1[Brute Force Password]
    A2 --> A2_2[Session Hijack]
    A2 --> A2_3[Spoof Device Fingerprint]
    
    A3 --> A3_1[DLL Injection]
    A3 --> A3_2[Hook Critical Functions]
    A3 --> A3_3[Modify Binary]
    
    A4 --> A4_1[Static Analysis]
    A4 --> A4_2[Dynamic Analysis]
    A4 --> A4_3[Extract Crypto Keys]
    
    subgraph "Defenses"
        D1[🛡️ Secure Memory Wipe]
        D2[🔐 Whitebox Encryption]
        D3[🔍 Debugger Detection]
        D4[⏱️ Rate Limiting]
        D5[👆 Device Binding]
        D6[🪝 Hook Detection]
        D7[✅ Checksum Verify]
        D8[🎭 Code Obfuscation]
    end
    
    A1_1 -.->|Blocked by| D1
    A1_2 -.->|Blocked by| D2
    A1_3 -.->|Blocked by| D3
    A2_1 -.->|Blocked by| D4
    A2_3 -.->|Blocked by| D5
    A3_2 -.->|Blocked by| D6
    A3_3 -.->|Blocked by| D7
    A4_1 -.->|Blocked by| D8
    
    style GOAL fill:#c0392b,color:#fff
    style A1 fill:#e74c3c,color:#fff
    style A2 fill:#e74c3c,color:#fff
    style A3 fill:#e74c3c,color:#fff
    style A4 fill:#e74c3c,color:#fff
```

---

## 11. Veri Akış Diyagramları

### 11.1 Pet Management Data Flow

```mermaid
flowchart LR
    subgraph "User Input"
        UI[👤 User]
    end
    
    subgraph "Application Layer"
        CLI[📟 CLI]
        VAL[✅ Validation]
        AUTH[🔐 Auth Check]
    end
    
    subgraph "Business Layer"
        PET_ADD[addPet()]
        PET_UPD[updatePet()]
        PET_DEL[deletePet()]
        OWNER_CHK[isPetOwnedByUser()]
    end
    
    subgraph "Security Layer"
        RASP[🛡️ RASP Check]
        ENC[🔐 Encrypt Data]
    end
    
    subgraph "Data Layer"
        DB[(🗄️ SQLite)]
    end
    
    UI -->|"Pet info"| CLI
    CLI --> VAL
    VAL -->|Valid| AUTH
    AUTH -->|Authenticated| RASP
    
    RASP -->|Secure| PET_ADD
    RASP -->|Secure| PET_UPD
    RASP -->|Secure| PET_DEL
    
    PET_UPD --> OWNER_CHK
    PET_DEL --> OWNER_CHK
    OWNER_CHK -->|Authorized| ENC
    PET_ADD --> ENC
    
    ENC -->|Encrypted| DB
    
    DB -->|Response| ENC
    ENC -->|Decrypted| CLI
    CLI -->|Display| UI
```

### 11.2 Appointment Scheduling Flow

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant C as 📟 CLI
    participant A as 📅 Appointment
    participant V as ✅ Validator
    participant D as 🗄️ Database
    participant E as 🔐 Encryption
    
    U->>C: Create appointment
    C->>V: Validate date (1-30, 1-12)
    
    alt Invalid Date
        V-->>C: ❌ Invalid date
        C-->>U: Error message
    end
    
    V->>D: db_is_date_occupied()
    
    alt Date Occupied
        D-->>C: ❌ Date busy
        C-->>U: Choose another date
    end
    
    V->>A: isPetOwnedByUser()
    
    alt Not Owner
        A-->>C: ❌ Permission denied
        C-->>U: Cannot schedule others' pets
    end
    
    A->>E: Encrypt description
    E->>D: db_add_appointment()
    D-->>A: ✅ Success
    A-->>C: Appointment created
    C-->>U: Confirmation
```

---

## 12. Saldırı Yüzeyi Analizi

### 12.1 Attack Surface Components

```mermaid
pie title Attack Surface Distribution
    "User Input (CLI)" : 25
    "File I/O (Database)" : 20
    "Memory (Sensitive Data)" : 20
    "Binary (Code)" : 15
    "Runtime (Process)" : 10
    "Configuration" : 10
```

### 12.2 Security Controls Matrix

```mermaid
graph TB
    subgraph "Assets"
        AS1[User Credentials]
        AS2[Pet Data]
        AS3[Session Keys]
        AS4[Encryption Keys]
        AS5[Application Binary]
    end
    
    subgraph "Threats"
        TH1[Credential Theft]
        TH2[Data Breach]
        TH3[Session Hijacking]
        TH4[Key Extraction]
        TH5[Code Tampering]
    end
    
    subgraph "Controls"
        C1[Password Hashing<br/>XOR Encryption]
        C2[Whitebox Crypto<br/>HMAC Integrity]
        C3[Device Binding<br/>Expiry Check]
        C4[Whitebox Tables<br/>Obfuscation]
        C5[Checksum Verify<br/>Anti-Debug]
    end
    
    AS1 --> TH1 --> C1
    AS2 --> TH2 --> C2
    AS3 --> TH3 --> C3
    AS4 --> TH4 --> C4
    AS5 --> TH5 --> C5
    
    style AS1 fill:#3498db,color:#fff
    style AS2 fill:#3498db,color:#fff
    style AS3 fill:#3498db,color:#fff
    style AS4 fill:#3498db,color:#fff
    style AS5 fill:#3498db,color:#fff
    
    style TH1 fill:#e74c3c,color:#fff
    style TH2 fill:#e74c3c,color:#fff
    style TH3 fill:#e74c3c,color:#fff
    style TH4 fill:#e74c3c,color:#fff
    style TH5 fill:#e74c3c,color:#fff
    
    style C1 fill:#27ae60,color:#fff
    style C2 fill:#27ae60,color:#fff
    style C3 fill:#27ae60,color:#fff
    style C4 fill:#27ae60,color:#fff
    style C5 fill:#27ae60,color:#fff
```

### 12.3 Compliance Mapping

```mermaid
graph LR
    subgraph "OWASP ASVS"
        V1[V1: Architecture]
        V2[V2: Authentication]
        V3[V3: Session]
        V4[V4: Access Control]
        V6[V6: Cryptography]
        V7[V7: Error Handling]
        V8[V8: Data Protection]
        V9[V9: Communication]
    end
    
    subgraph "Implementation"
        I1[Modular Design]
        I2[Password Hash + Session]
        I3[SessionData + DeviceBinding]
        I4[isPetOwnedByUser]
        I6[Whitebox AES/DES]
        I7[RASP Logging]
        I8[Secure Memory]
        I9[Local Only]
    end
    
    V1 --> I1
    V2 --> I2
    V3 --> I3
    V4 --> I4
    V6 --> I6
    V7 --> I7
    V8 --> I8
    V9 --> I9
    
    style V1 fill:#9b59b6,color:#fff
    style V2 fill:#9b59b6,color:#fff
    style V3 fill:#9b59b6,color:#fff
    style V4 fill:#9b59b6,color:#fff
    style V6 fill:#9b59b6,color:#fff
    style V7 fill:#9b59b6,color:#fff
    style V8 fill:#9b59b6,color:#fff
    style V9 fill:#9b59b6,color:#fff
```
