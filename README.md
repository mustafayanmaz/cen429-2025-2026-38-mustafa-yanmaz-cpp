# 🐾 PetCare Management System - Secure Application Development

## 🎓 CEN429 Secure Software Development Course - Final Project (2025-2026)

<div align="center">
  <img src="https://img.shields.io/badge/C++-11-blue.svg?style=flat&logo=c%2B%2B" alt="C++"/>
  <img src="https://img.shields.io/badge/CMake-3.12+-064F8C.svg?style=flat&logo=cmake" alt="CMake"/>
  <img src="https://img.shields.io/badge/SQLite3-Encrypted-003B57.svg?style=flat&logo=sqlite" alt="SQLite3"/>
  <img src="https://img.shields.io/badge/Tests-330%2F330%20Passing-success.svg?style=flat" alt="Tests"/>
</div>

---

## 👥 Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/mustafayanmaz">
        <img src="https://avatars.githubusercontent.com/u/114070977?v=4" width="100px;" alt="Mustafa Yanmaz"/><br />
        <sub><b>Mustafa Yanmaz</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/onurcakirtr">
        <img src="https://avatars.githubusercontent.com/onurcakirtr" width="100px;" alt="Onur Çakır"/><br />
        <sub><b>Onur Çakır</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/AliTopcuu">
        <img src="https://avatars.githubusercontent.com/u/114070829?v=4" width="100px;" alt="Ali Ufuktan Topçu"/><br />
        <sub><b>Ali Ufuktan Topçu</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/mrfiratatalay">
        <img src="https://avatars.githubusercontent.com/mrfiratatalay" width="100px;" alt="Fırat Atalay"/><br />
        <sub><b>Fırat Atalay</b></sub>
      </a>
    </td>
  </tr>
</table>

## 📋 Project Description

This project demonstrates a comprehensive **PetCare Management System** with advanced security features. It showcases:

- 🔒 **Code Hardening**: 50+ obfuscated functions with opaque predicates, MBA operations, CFI
- 🛡️ **Secure Database**: Encrypted SQLite3 with whitebox cryptography
- 🔐 **Memory Protection**: Secure memory management, key derivation, anti-tampering
- 🧪 **High Test Coverage**: 330/330 tests passing (122 utility + 208 petcare tests)
- 📝 **Comprehensive Documentation**: Doxygen-generated API docs with coverage reports
- 🎯 **RASP Security**: Runtime Application Self-Protection with debugger detection

## 🛠️ Technical Requirements

- ⚙️ CMake >= 3.12
- 🔄 C++ Standard >= 11
- 🧪 GoogleTest (for testing modules)
- 💾 SQLite3 (embedded with encryption)
- 💻 Visual Studio Community Edition (for Windows)
- 🐧 GCC/Clang (for WSL/Linux)

## 📊 Status

### 🚀 Build Status

![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Tests](https://img.shields.io/badge/tests-330%2F330-success.svg)

### 📈 Coverage Reports

<div align="center">
  <img src="assets/codecoveragelibwin/badge_linecoverage.svg" alt="Code Coverage"/>
  <img src="assets/doccoveragelibwin/badge_linecoverage.svg" alt="Doc Coverage"/>
</div>

## 💻 Installation

```bash
# Clone the repository
git clone https://github.com/mustafayanmaz/cen429-2025-2026-38-mustafa-yanmaz-cpp.git
cd cen429-2025-2026-38-mustafa-yanmaz-cpp

# Run setup scripts
# For Windows:
.\3-install-package-manager.bat
.\4-install-windows-enviroment.bat
.\7-build-app-windows.bat

# For Linux/WSL:
./4-install-wsl-environment.sh
./7-build-app-linux.sh
```

## ✨ Features

### 🔐 Security Features

- **Code Obfuscation**: Opaque predicates, MBA operations, control flow integrity
- **Encrypted Database**: SQLite3 with AES encryption and HMAC integrity verification
- **Secure Memory**: Automatic wiping, secure allocation, key derivation (PBKDF2)
- **Anti-Tampering**: Checksum verification, debugger detection, hook detection
- **Session Management**: Device fingerprinting, session tokens, replay protection

### 👤 User Management

- 🔐 Secure user registration with encrypted password storage
- 🔑 Authentication with session management
- 👥 User profile management

### 🐾 Pet Management

- ✏️ Add, update, delete pets with owner verification
- 🔍 Search pets by name, type, or owner
- 📊 List all pets with sorting (Heap Sort)
- 🎂 Birthday tracking with B+ Tree indexing

### 📅 Appointment System

- 📆 Schedule appointments with date validation
- ✏️ Update and cancel appointments
- 📋 View all appointments with filtering

### 💊 Healthcare Management

- 💉 Medicine schedules with queue-based management
- 🍽️ Feeding schedules with priority queue
- 🏃 Exercise routines with stack-based tracking

### 🐕 Stray Animal Management

- 📝 Register stray animals
- 🔍 Search with KMP algorithm
- 🏠 Adoption workflow with transaction recording

## 🔒 Security Implementation Details

### Code Hardening Techniques

- **Opaque Predicates**: Always-true/false conditions for control flow obfuscation
- **Mixed Boolean-Arithmetic (MBA)**: Arithmetic operations for simple computations
- **Control Flow Integrity (CFI)**: State machine dispatcher for indirect calls
- **Dead Code Injection**: Non-functional code blocks to confuse static analysis
- **Conditional Logging**: Security-sensitive logs only in debug mode

### Database Security

- **Encryption at Rest**: SQLite database encrypted with whitebox crypto
- **Secure Mode**: Temporary plaintext file during runtime, re-encrypted on close
- **Key Derivation**: Device fingerprint + app integrity hash for unique keys
- **HMAC Verification**: Integrity checking for all encrypted data

### Memory Protection

- **Secure Wipe**: Memory cleared after use (prevents memory dumps)
- **Guard Pages**: Detection of buffer overflows
- **Auto-Wipe Classes**: RAII pattern for automatic cleanup

## Setup Development Environment

### Step-1: Configure Git Hooks (Windows/WSL)

Run `1-configure-git-hooks.bat` to copy pre-commit script that checks README.md, gitignore, and formats code with AStyle

### Step-2: Create Git Ignore (Windows/WSL)

Run `2-create-git-ignore.bat` to generate .gitignore file

### Step-3: Install Package Managers (Windows Only)

Run `3-install-package-manager.bat` to install Chocolatey and Scoop

### Step-4: Install Development Tools

- **Windows**: Run `4-install-windows-enviroment.bat`
- **WSL/Linux**: Run `4-install-wsl-environment.sh`



## 🏗️ Build Instructions

### Generate Visual Studio Project (Windows)

```bash
.\9-clean-configure-app-windows.bat
```

Or use CMake with Visual Studio Community Edition directly

### Build, Test and Package (Windows)

```bash
# Build application
.\7-build-app-windows.bat

# Generate documentation only
.\7-build-doc-windows.bat

# Run tests only
.\8-build-test-windows.bat
```

### Build, Test and Package (Linux/WSL)

```bash
./7-build-app-linux.sh
```

### Clean Project

```bash
# Windows
.\9-clean-project.bat

# Linux/WSL
./9-clean-project.sh
```

## 🧪 Testing

The project includes comprehensive test suites:

### Test Coverage

- **Utility Tests**: 122 tests covering security, crypto, and memory management
- **PetCare Tests**: 208 tests covering business logic and database operations
- **Total**: 330/330 tests passing (100% success rate)

### Run Tests

```bash
# Windows
cd build_win
ctest -C Release

# Linux/WSL
cd build_linux
ctest
```

### Test Categories

- ✅ **Security Tests**: RASP, anti-tampering, debugger detection
- ✅ **Crypto Tests**: AES, DES, whitebox crypto, file encryption
- ✅ **Database Tests**: CRUD operations, transactions, encryption
- ✅ **Memory Tests**: Secure allocation, wiping, buffer management
- ✅ **Business Logic Tests**: User auth, pet management, appointments
- ✅ **Algorithm Tests**: Sorting, searching, compression (Huffman)

## 📁 Project Structure

```
cen429-2025-2026-38-mustafa-yanmaz-cpp/
├── src/
│   ├── utility/           # Security utilities
│   │   ├── header/
│   │   │   ├── codeObfuscation.h      # Code hardening primitives
│   │   │   ├── secureMemory.h         # Secure memory management
│   │   │   ├── whiteboxCrypto.h       # Encryption library
│   │   │   ├── raspSecurity.h         # RASP features
│   │   │   └── assetProtection.h      # Asset obfuscation
│   │   └── src/
│   ├── petcare/           # Core business logic
│   │   ├── header/
│   │   │   ├── petcare.h              # Main API
│   │   │   └── database.h             # Database wrapper
│   │   └── src/
│   │       ├── petcare.cpp            # 3286 lines, 50+ obfuscated functions
│   │       └── database.cpp           # SQLite3 with encryption
│   ├── petcareapp/        # Main application
│   │   └── src/
│   │       └── petcareapp.cpp         # CLI interface
│   └── tests/             # Test suites
│       ├── utility/       # 122 utility tests
│       └── petcare/       # 208 petcare tests
├── external/
│   └── sqlite3/           # Embedded SQLite3
├── build_win/             # Windows build output
├── build_linux/           # Linux build output
└── docs/                  # Generated documentation
``` 



## 🖥️ Supported Platforms

<div align="center">
  <img src="assets/badge-windows.svg" alt="Windows"/>
  <img src="assets/badge-ubuntu.svg" alt="Ubuntu"/>
  <img src="assets/badge-macos.svg" alt="macOS"/>
</div>

### Test Coverage Ratios

> **Note** : There is a known bug on doxygen following badges are in different folder but has same name for this reason in doxygen html report use same image for all content [Images with same name overwrite each other in output directory · Issue #8362 · doxygen/doxygen · GitHub](https://github.com/doxygen/doxygen/issues/8362). README.md and WebPage show correct badges.

| Coverage Type | Windows OS                                                             | Linux OS (WSL-Ubuntu 20.04)                                              |
| ------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Line Based    | ![Line Coverage](assets/codecoveragelibwin/badge_linecoverage.svg)     | ![Line Coverage](assets/codecoverageliblinux/badge_linecoverage.svg)     |
| Branch Based  | ![Branch Coverage](assets/codecoveragelibwin/badge_branchcoverage.svg) | ![Branch Coverage](assets/codecoverageliblinux/badge_branchcoverage.svg) |
| Method Based  | ![Method Coverage](assets/codecoveragelibwin/badge_methodcoverage.svg) | ![Method Coverage](assets/codecoverageliblinux/badge_methodcoverage.svg) |

### Documentation Coverage Ratios

|                    | Windows OS                                                        | Linux OS (WSL-Ubuntu 20.04)                                         |
| ------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Coverage Ratio** | ![Line Coverage](assets/doccoveragelibwin/badge_linecoverage.svg) | ![Line Coverage](assets/doccoverageliblinux/badge_linecoverage.svg) |



#### Install Test Results to HTML Converter

We are using [GitHub - inorton/junit2html: Turn Junit XML reports into self contained HTML reports](https://github.com/inorton/junit2html) to convert junit xml formatted test results to HTML page for reporting also we store logs during test. Use following commands to install this module with pip

```bash
pip install junit2html
```

### Github Actions

This project also compiled and tested with Github Actions. If there is a missing setup or problem follow github action script for both Windows and WSL under

`.github/workflows/cpp.yml`

Github actions take too much time more than 1 hour take to complete build for Windows, MacOS and Linux. Also its paid operation for this reason we use offline batch scripts easy to use. 

### Build App on Windows

We have already configured script for build operations. `7-build-app-windows.bat` have complete all required tasks and copy outputs to release folder.  

**Operation Completed in 11-15 minutes.**

- Clean project outputs

- Create required folders

- Run doxygen for documentation

- Run coverxygen for document coverage report

- Run Report Generator for Documentation Coverage Report

- Configure project for Visual Studio Community Edition

- Build Project Debug and Release

- Install/Copy Required Library and Headers

- Run Tests 

- Run OpeCppCoverage for Coverage Data Collection

- Run Reportgenerator for Test Coverage Report

- Copy output report to webpage folder

- Run mkdocs to build webpage

- Compress outputs to release folder, everything is ready for deployment. 

### Build App on WSL/Linux

We are running WSL on Windows 10 and solve our virtual machine problem. We make cross-platform development. After development before commit we run and test app on Windows and WSL with this scripts. To run on WSL you need to install WSL first. 

you can use our public notes

- https://github.com/coruhtech/vs-docker-wsl-cpp-development

- [GitHub - musalon/ns3-wsl-win10-setup: ns3 windows 10 WSL2 setup and usage](https://github.com/musalon/ns3-wsl-win10-setup)

After WSL installation, right click and open WSL bash and run `7-build-app-linux.sh` this will provide similart task with windows and will generate report and libraries on release folder. 



## 🔐 Security Configuration

### KDF Iteration Tuning

The application uses **PBKDF2-HMAC-SHA256** for key derivation. Configure iterations via environment variable:

```powershell
# Windows PowerShell
$env:PETCARE_KDF_ITERS = "50000"

# Linux/WSL
export PETCARE_KDF_ITERS=50000
```

**Settings:**
- Default: 20,000 iterations
- Minimum: 1,000 iterations
- Maximum: 1,000,000 iterations

⚠️ **Note**: Higher iterations = stronger security but slower key derivation

### Database Encryption

Database files are encrypted using:
- **Algorithm**: AES-256-CBC cascade with DES
- **Key Derivation**: Device fingerprint + app integrity hash
- **Format**: `.db.enc` encrypted container
- **Runtime**: Temporary plaintext, re-encrypted on close

### Security Documentation

For detailed security analysis:
- `docs/security/threat_model.md` - Threat modeling and attack vectors
- `docs/security/risk_matrix.md` - Risk assessment matrix
- `docs/security/vulnerabilities.md` - Known vulnerabilities and mitigations

## 🧑‍🏫 Course Supervisor

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/ugurcoruh">
        <img src="https://avatars.githubusercontent.com/u/7415667?v=4" width="100px;" alt="Uğur Coruh"/><br />
        <sub><b>Uğur Coruh</b></sub>
      </a><br />
      <sub>CEN429 Instructor</sub>
    </td>
  </tr>
</table>

## 📄 License

This project is developed as part of CEN429 Secure Software Development course.

---

<div align="center">
  <sub>Built with 🔒 by the PetCare Security Team</sub>
  <br />
  <sub>© 2025-2026 | Karabük University</sub>
</div>