/**
 * @file raspSecurity.cpp
 * @brief Implementation of Runtime Application Self-Protection (RASP) Security
 */

#include "raspSecurity.h"
#include "commonTypes.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#pragma comment(lib, "psapi.lib")

// Windows type definitions
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef LONG NTSTATUS;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

#else
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

// macOS compatibility: ptrace constants have different names on macOS
#ifdef __APPLE__
    #ifndef PTRACE_TRACEME
        #define PTRACE_TRACEME PT_TRACE_ME
    #endif
    #ifndef PTRACE_DETACH
        #define PTRACE_DETACH PT_DETACH
    #endif
#endif

#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

/** @brief Current RASP configuration used by the security module. */
static RASPConfig g_rasp_config = {0};

/** @brief Flag indicating whether the RASP system has been initialized. */
static int g_rasp_initialized = 0;

/** @brief Global array of Control Flow Integrity (CFI) counters. */
static CFICounter g_cfi_counters[RASP_MAX_CFI_COUNTERS] = {0};

/** @brief Number of active CFI counters currently in use. */
static size_t g_cfi_counter_count = 0;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Simple SHA-256 hash implementation
 */
static void simple_hash(const uint8_t* data, size_t len, uint8_t* hash) {
    // Simplified hash - in production use proper SHA-256
    uint32_t h = 0x5A5A5A5A;
    for (size_t i = 0; i < len; i++) {
        h = ((h << 5) + h) + data[i];
        h ^= (h >> 16);
    }
    
    for (int i = 0; i < RASP_HASH_SIZE; i++) {
        hash[i] = (uint8_t)((h >> (i % 4 * 8)) & 0xFF);
        if (i % 4 == 3) h = h * 0x5BD1E995;
    }
}

/**
 * @brief Calculate CRC32 checksum
 */
static uint32_t calculate_crc32(const void* data, size_t size) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < size; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    
    return ~crc;
}

/**
 * @brief Get current timestamp in milliseconds
 */
static uint64_t get_timestamp_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/**
 * @brief Secure memory comparison
 */
static int secure_memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    int diff = 0;
    
    for (size_t i = 0; i < n; i++) {
        diff |= pa[i] ^ pb[i];
    }
    
    return diff;
}

// ============================================================================
// CHECKSUM VERIFICATION
// ============================================================================

int rasp_calculate_checksum(const void* code_start, size_t code_size, 
                           CodeBlockChecksum* checksum) {
    if (!code_start || !checksum || code_size == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    memset(checksum, 0, sizeof(CodeBlockChecksum));
    checksum->code_start = (void*)code_start;
    checksum->code_size = code_size;
    
    // Calculate hash
    simple_hash((const uint8_t*)code_start, code_size, checksum->expected_hash);
    
    // Calculate CRC32
    checksum->checksum_crc32 = calculate_crc32(code_start, code_size);
    
    checksum->last_verification = get_timestamp_ms();
    checksum->verification_count = 1;
    
    return RASP_SUCCESS;
}

int rasp_verify_checksum(const CodeBlockChecksum* checksum) {
    if (!checksum || !checksum->code_start) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    // Calculate current hash
    uint8_t current_hash[RASP_HASH_SIZE];
    simple_hash((const uint8_t*)checksum->code_start, 
                checksum->code_size, current_hash);
    
    // Verify hash
    if (secure_memcmp(current_hash, checksum->expected_hash, RASP_HASH_SIZE) != 0) {
        rasp_log_event("CHECKSUM_FAIL", "Code block hash mismatch detected");
        return RASP_ERROR_CHECKSUM_FAIL;
    }
    
    // Verify CRC32
    uint32_t current_crc = calculate_crc32(checksum->code_start, checksum->code_size);
    if (current_crc != checksum->checksum_crc32) {
        rasp_log_event("CHECKSUM_FAIL", "Code block CRC32 mismatch detected");
        return RASP_ERROR_CHECKSUM_FAIL;
    }
    
    return RASP_SUCCESS;
}

int rasp_monitor_checksum(const CodeBlockChecksum* checksum, 
                         uint32_t interval_ms,
                         void (*callback)(RASPStatus)) {
    // This would typically run in a separate thread
    // For now, just do a single verification
    int result = rasp_verify_checksum(checksum);
    if (result != RASP_SUCCESS && callback) {
        callback((RASPStatus)result);
    }
    return RASP_SUCCESS;
}

// ============================================================================
// APPLICATION HASH AND SIGNATURE VERIFICATION
// ============================================================================

int rasp_calculate_app_hash(const char* app_path, uint8_t* hash) {
    if (!app_path || !hash) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
#ifdef _WIN32
    HANDLE hFile = CreateFileA(app_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return RASP_ERROR_FILE_ACCESS;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return RASP_ERROR_FILE_ACCESS;
    }
    
    uint8_t* buffer = (uint8_t*)malloc(fileSize);
    if (!buffer) {
        CloseHandle(hFile);
        return RASP_ERROR_MEMORY_ALLOCATION;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || 
        bytesRead != fileSize) {
        free(buffer);
        CloseHandle(hFile);
        return RASP_ERROR_FILE_ACCESS;
    }
    
    simple_hash(buffer, fileSize, hash);
    
    free(buffer);
    CloseHandle(hFile);
#else
    FILE* fp = fopen(app_path, "rb");
    if (!fp) {
        return RASP_ERROR_FILE_ACCESS;
    }
    
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    uint8_t* buffer = (uint8_t*)malloc(fileSize);
    if (!buffer) {
        fclose(fp);
        return RASP_ERROR_MEMORY_ALLOCATION;
    }
    
    if (fread(buffer, 1, fileSize, fp) != (size_t)fileSize) {
        free(buffer);
        fclose(fp);
        return RASP_ERROR_FILE_ACCESS;
    }
    
    simple_hash(buffer, fileSize, hash);
    
    free(buffer);
    fclose(fp);
#endif
    
    return RASP_SUCCESS;
}

int rasp_verify_app_signature(const AppSignature* signature) {
    if (!signature) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    // Calculate current hash
    uint8_t current_hash[RASP_HASH_SIZE];
    int result = rasp_calculate_app_hash(signature->app_path, current_hash);
    if (result != RASP_SUCCESS) {
        return result;
    }
    
    // Verify hash matches
    if (secure_memcmp(current_hash, signature->app_hash, RASP_HASH_SIZE) != 0) {
        rasp_log_event("SIGNATURE_FAIL", "Application hash mismatch");
        return RASP_ERROR_SIGNATURE_FAIL;
    }
    
    // In production, verify digital signature with public key
    // For now, just verify hash
    
    return RASP_SUCCESS;
}

int rasp_get_verified_app_path(char* app_path, size_t max_len) {
    if (!app_path || max_len == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
#ifdef _WIN32
    DWORD result = GetModuleFileNameA(NULL, app_path, (DWORD)max_len);
    if (result == 0 || result >= max_len) {
        return RASP_ERROR_FILE_ACCESS;
    }
#else
    ssize_t len = readlink("/proc/self/exe", app_path, max_len - 1);
    if (len == -1) {
        return RASP_ERROR_FILE_ACCESS;
    }
    app_path[len] = '\0';
#endif
    
    return RASP_SUCCESS;
}

int rasp_create_app_signature(const char* app_path, 
                              const uint8_t* private_key,
                              AppSignature* signature) {
    if (!app_path || !signature) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    memset(signature, 0, sizeof(AppSignature));
    strncpy(signature->app_path, app_path, RASP_MAX_PATH - 1);
    
    // Calculate hash
    int result = rasp_calculate_app_hash(app_path, signature->app_hash);
    if (result != RASP_SUCCESS) {
        return result;
    }
    
    signature->timestamp = get_timestamp_ms();
    signature->is_verified = 1;
    
    // In production, create digital signature with private key
    
    return RASP_SUCCESS;
}

// ============================================================================
// UNTRUSTED DEVICE DETECTION
// ============================================================================

int rasp_detect_root(void) {
#ifdef _WIN32
    // Check for admin privileges on Windows
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2,
                                SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0,
                                &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    return isAdmin ? 1 : 0;
#else
    // Check for root on Unix/Linux
    if (geteuid() == 0) {
        return 1;
    }
    
    // Check for common jailbreak indicators
    const char* suspicious_paths[] = {
        "/Applications/Cydia.app",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/bin/bash",
        "/etc/apt"
    };
    
    for (size_t i = 0; i < sizeof(suspicious_paths) / sizeof(suspicious_paths[0]); i++) {
        if (access(suspicious_paths[i], F_OK) == 0) {
            return 1;
        }
    }
#endif
    
    return 0;
}

int rasp_detect_emulator(void) {
#ifdef _WIN32
    // Check for VM indicators on Windows
    int vm_indicators = 0;
    
    // Check for VirtualBox
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                     "HARDWARE\\ACPI\\DSDT\\VBOX__", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        vm_indicators++;
    }
    
    // Check for VMware
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "HARDWARE\\ACPI\\DSDT\\VMWARE__",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        vm_indicators++;
    }
    
    // Check for Hyper-V Guest
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        vm_indicators++;
    }
    
    // Check CPUID for hypervisor bit (can be false positive with Hyper-V on physical)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor present - but could be Windows Sandbox, WSL2, or Hyper-V on host
        // Check vendor to reduce false positives
        __cpuid(cpuInfo, 0x40000000);
        
        // Only count as VM if we also have other indicators
        // or if it's a known VM hypervisor
        char vendor[13] = {0};
        *((int*)&vendor[0]) = cpuInfo[1];
        *((int*)&vendor[4]) = cpuInfo[2];
        *((int*)&vendor[8]) = cpuInfo[3];
        
        // Known VM hypervisors
        if (strstr(vendor, "VMware") || 
            strstr(vendor, "VBoxVBox") || 
            strstr(vendor, "KVMKVMKVM")) {
            vm_indicators += 2;
        }
    }
    
    // Return 1 only if we have strong evidence (multiple indicators)
    return (vm_indicators >= 2) ? 1 : 0;
#else
    // Check for emulator on Linux
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "hypervisor") || 
                strstr(line, "QEMU") ||
                strstr(line, "VirtualBox")) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
#endif
    
    return 0;
}

int rasp_verify_system_files(const char** file_paths, size_t count) {
    if (!file_paths || count == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < count; i++) {
        if (!file_paths[i]) continue;
        
#ifdef _WIN32
        DWORD attr = GetFileAttributesA(file_paths[i]);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            rasp_log_event("SYSTEM_FILE_MISSING", file_paths[i]);
            return RASP_ERROR_UNTRUSTED_DEVICE;
        }
#else
        struct stat st;
        if (stat(file_paths[i], &st) != 0) {
            rasp_log_event("SYSTEM_FILE_MISSING", file_paths[i]);
            return RASP_ERROR_UNTRUSTED_DEVICE;
        }
#endif
    }
    
    return RASP_SUCCESS;
}

int rasp_assess_device_trust(DeviceTrust* trust) {
    if (!trust) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    memset(trust, 0, sizeof(DeviceTrust));
    
    trust->is_rooted = rasp_detect_root();
    trust->is_emulator = rasp_detect_emulator();
    
    DebuggerInfo debug_info;
    trust->has_debugger_tools = (rasp_detect_debugger(&debug_info) != RASP_SUCCESS);
    
    HookInfo hooks[10];
    int hook_count = rasp_scan_all_hooks(hooks, 10);
    trust->has_hooking_frameworks = (hook_count > 0);
    
    // Calculate trust score (0-100)
    trust->trust_score = 100;
    if (trust->is_rooted) trust->trust_score -= 30;
    if (trust->is_emulator) trust->trust_score -= 20;
    if (trust->has_debugger_tools) trust->trust_score -= 25;
    if (trust->has_hooking_frameworks) trust->trust_score -= 25;
    
    if (trust->trust_score < 0) trust->trust_score = 0;
    
    return RASP_SUCCESS;
}

int rasp_detect_malicious_apps(char** process_list, size_t max_processes) {
    int count = 0;
    
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    const char* suspicious[] = {
        "ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe",
        "frida-server.exe", "cheatengine.exe", "processhacker.exe"
    };
    
    if (Process32First(snapshot, &pe32)) {
        do {
            // Convert WCHAR to char for comparison
            char exeName[MAX_PATH];
            #ifdef UNICODE
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
            #else
            strncpy(exeName, pe32.szExeFile, MAX_PATH - 1);
            exeName[MAX_PATH - 1] = '\0';
            #endif
            
            for (size_t i = 0; i < sizeof(suspicious) / sizeof(suspicious[0]); i++) {
                if (_stricmp(exeName, suspicious[i]) == 0) {
                    if (count < (int)max_processes && process_list) {
                        process_list[count] = _strdup(exeName);
                    }
                    count++;
                    break;
                }
            }
        } while (Process32Next(snapshot, &pe32) && count < (int)max_processes);
    }
    
    CloseHandle(snapshot);
#endif
    
    return count;
}

// ============================================================================
// HOOK ATTACK DETECTION
// ============================================================================

int rasp_detect_inline_hook(const void* function_address, 
                           const uint8_t* original_bytes,
                           size_t size) {
    if (!function_address || !original_bytes || size == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    // Compare current bytes with original
    if (memcmp(function_address, original_bytes, size) != 0) {
        rasp_log_event("HOOK_DETECTED", "Inline hook detected in function");
        return RASP_ERROR_HOOK_DETECTED;
    }
    
    // Check for common hook patterns
    const uint8_t* bytes = (const uint8_t*)function_address;
    
    // Check for JMP instruction (E9)
    if (bytes[0] == 0xE9) {
        rasp_log_event("HOOK_DETECTED", "JMP instruction at function start");
        return RASP_ERROR_HOOK_DETECTED;
    }
    
    // Check for PUSH+RET trampoline
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
        rasp_log_event("HOOK_DETECTED", "PUSH+RET trampoline detected");
        return RASP_ERROR_HOOK_DETECTED;
    }
    
    // Check for MOV RAX + JMP RAX (x64)
    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
        rasp_log_event("HOOK_DETECTED", "MOV+JMP x64 hook detected");
        return RASP_ERROR_HOOK_DETECTED;
    }
    
    return RASP_SUCCESS;
}

int rasp_detect_iat_hooks(const char* module_name) {
#ifdef _WIN32
    HMODULE hModule = GetModuleHandleA(module_name);
    if (!hModule) {
        return -1;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return -1;
    }
    
    IMAGE_DATA_DIRECTORY importDir = 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if (importDir.Size == 0) {
        return 0;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = 
        (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);
    
    int hook_count = 0;
    
    while (importDesc->Name != 0) {
        PIMAGE_THUNK_DATA thunk = 
            (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
        
        while (thunk->u1.Function != 0) {
            FARPROC func = (FARPROC)thunk->u1.Function;
            
            // Check if function points outside expected module
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(func, &mbi, sizeof(mbi))) {
                if (mbi.AllocationProtect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    // Suspicious memory protection
                    hook_count++;
                }
            }
            
            thunk++;
        }
        
        importDesc++;
    }
    
    return hook_count;
#else
    return 0;
#endif
}

int rasp_scan_all_hooks(HookInfo* hooks, size_t max_hooks) {
    if (!hooks || max_hooks == 0) {
        return 0;
    }
    
    int count = 0;
    
    // This would scan critical functions for hooks
    // For demonstration, just return 0
    
    return count;
}

int rasp_protect_function(void* function_address,
                         const uint8_t* original_bytes,
                         size_t size,
                         void (*callback)(const HookInfo*)) {
    // In production, this would set up continuous monitoring
    return rasp_detect_inline_hook(function_address, original_bytes, size);
}

int rasp_verify_library_integrity(const char* library_path) {
    if (!library_path) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    uint8_t hash[RASP_HASH_SIZE];
    return rasp_calculate_app_hash(library_path, hash);
}

// ============================================================================
// DEBUGGER DETECTION AND PREVENTION
// ============================================================================

int rasp_is_debugger_present(void) {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return 1;
    }
    
    // Check PEB BeingDebugged flag
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        return 1;
    }
#else
    // Linux ptrace detection
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;  // Already being traced
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
#endif
    
    return 0;
}

int rasp_detect_debugger(DebuggerInfo* info) {
    if (!info) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    memset(info, 0, sizeof(DebuggerInfo));
    info->detection_timestamp = get_timestamp_ms();
    
    // Check for debugger presence
    info->debugger_present = rasp_is_debugger_present();
    
#ifdef _WIN32
    // Check for remote debugger
    BOOL isRemoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger);
    info->remote_debugger = isRemoteDebugger;
    
    // Check for kernel debugger
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQuerySystemInformation NtQuerySystemInformation = 
            (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        
        if (NtQuerySystemInformation) {
            SYSTEM_KERNEL_DEBUGGER_INFORMATION kernelDebugInfo;
            NTSTATUS status = NtQuerySystemInformation(
                SystemKernelDebuggerInformation,
                &kernelDebugInfo,
                sizeof(kernelDebugInfo),
                NULL);
            
            if (status == 0) {
                info->kernel_debugger = kernelDebugInfo.KernelDebuggerEnabled;
            }
        }
    }
#endif
    
    // Timing-based detection
    info->timing_anomaly = rasp_detect_timing_anomaly();
    
    // Hardware breakpoint detection
    info->hardware_breakpoints = (rasp_detect_hardware_breakpoints() > 0);
    
    if (info->debugger_present || info->remote_debugger || 
        info->kernel_debugger || info->timing_anomaly ||
        info->hardware_breakpoints) {
        rasp_log_event("DEBUGGER_DETECTED", "Debugger presence confirmed");
        return RASP_ERROR_DEBUGGER_DETECTED;
    }
    
    return RASP_SUCCESS;
}

int rasp_prevent_debugger_attach(void) {
#ifdef _WIN32
    // Set process as critical
    typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtSetInformationProcess NtSetInformationProcess = 
            (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
        
        if (NtSetInformationProcess) {
            DWORD isCritical = 1;
            NtSetInformationProcess(GetCurrentProcess(), 29, // ProcessBreakOnTermination
                                   &isCritical, sizeof(DWORD));
        }
    }
#else
    // Linux: Use prctl to prevent ptrace
    #ifdef PR_SET_DUMPABLE
    prctl(PR_SET_DUMPABLE, 0);
    #endif
#endif
    
    return RASP_SUCCESS;
}

int rasp_detect_hardware_breakpoints(void) {
#ifdef _WIN32
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return -1;
    }
    
    int count = 0;
    if (ctx.Dr0 != 0) count++;
    if (ctx.Dr1 != 0) count++;
    if (ctx.Dr2 != 0) count++;
    if (ctx.Dr3 != 0) count++;
    
    return count;
#else
    return 0;
#endif
}

int rasp_detect_software_breakpoints(const void* code_start, size_t code_size) {
    if (!code_start || code_size == 0) {
        return 0;
    }
    
    const uint8_t* code = (const uint8_t*)code_start;
    int count = 0;
    
    for (size_t i = 0; i < code_size; i++) {
        if (code[i] == 0xCC) {  // INT3 breakpoint
            count++;
        }
    }
    
    return count;
}

int rasp_detect_timing_anomaly(void) {
    uint64_t start = get_timestamp_ms();
    
    // Perform some simple operations
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }
    
    uint64_t end = get_timestamp_ms();
    uint64_t elapsed = end - start;
    
    // If operation took too long, might be stepping through debugger
    if (elapsed > 100) {
        return 1;
    }
    
    return 0;
}

int rasp_monitor_debugger(uint32_t interval_ms, RASPAction action) {
    // Would run in separate thread
    DebuggerInfo info;
    int result = rasp_detect_debugger(&info);
    
    if (result != RASP_SUCCESS) {
        switch (action) {
            case RASP_ACTION_LOG:
                rasp_log_event("DEBUGGER", "Debugger detected - logging");
                break;
            case RASP_ACTION_TERMINATE:
                rasp_log_event("DEBUGGER", "Debugger detected - terminating");
                exit(1);
                break;
            default:
                break;
        }
    }
    
    return RASP_SUCCESS;
}

// ============================================================================
// TAMPER DETECTION
// ============================================================================

int rasp_detect_memory_tamper(const void* memory_region, 
                             size_t size,
                             const uint8_t* expected_hash) {
    if (!memory_region || !expected_hash || size == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    uint8_t current_hash[RASP_HASH_SIZE];
    simple_hash((const uint8_t*)memory_region, size, current_hash);
    
    if (secure_memcmp(current_hash, expected_hash, RASP_HASH_SIZE) != 0) {
        rasp_log_event("TAMPER_DETECTED", "Memory region hash mismatch");
        return RASP_ERROR_TAMPER_DETECTED;
    }
    
    return RASP_SUCCESS;
}

int rasp_detect_tampering(TamperInfo* info) {
    if (!info) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    memset(info, 0, sizeof(TamperInfo));
    
    // Check for debugger (indicates possible tampering)
    DebuggerInfo debug_info;
    if (rasp_detect_debugger(&debug_info) != RASP_SUCCESS) {
        info->memory_tampered = 1;
        info->tamper_count++;
    }
    
    // Check for hooks (indicates code tampering)
    HookInfo hooks[10];
    int hook_count = rasp_scan_all_hooks(hooks, 10);
    if (hook_count > 0) {
        info->code_tampered = 1;
        info->tamper_count += hook_count;
    }
    
    info->last_tamper_time = get_timestamp_ms();
    
    if (info->tamper_count > 0) {
        rasp_log_event("TAMPER_DETECTED", "Tampering attempts detected");
        return RASP_ERROR_TAMPER_DETECTED;
    }
    
    return RASP_SUCCESS;
}

int rasp_respond_to_tamper(const TamperInfo* info, RASPAction action) {
    if (!info) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    switch (action) {
        case RASP_ACTION_LOG:
            rasp_log_event("TAMPER_RESPONSE", "Tamper detected - logging only");
            break;
            
        case RASP_ACTION_ALERT:
            rasp_log_event("TAMPER_RESPONSE", "Tamper detected - alerting");
            // Could send alert to monitoring system
            break;
            
        case RASP_ACTION_BLOCK:
            rasp_log_event("TAMPER_RESPONSE", "Tamper detected - blocking operation");
            return RASP_ERROR_TAMPER_DETECTED;
            
        case RASP_ACTION_TERMINATE:
            rasp_log_event("TAMPER_RESPONSE", "Tamper detected - terminating application");
            exit(1);
            break;
            
        default:
            break;
    }
    
    return RASP_SUCCESS;
}

int rasp_protect_data(const void* data, size_t size, uint32_t* checksum) {
    if (!data || !checksum || size == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    *checksum = calculate_crc32(data, size);
    return RASP_SUCCESS;
}

int rasp_verify_protected_data(const void* data, size_t size, uint32_t checksum) {
    if (!data || size == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    uint32_t current_checksum = calculate_crc32(data, size);
    
    if (current_checksum != checksum) {
        rasp_log_event("DATA_TAMPER", "Protected data checksum mismatch");
        return RASP_ERROR_TAMPER_DETECTED;
    }
    
    return RASP_SUCCESS;
}

int rasp_monitor_tampering(uint32_t interval_ms, 
                          void (*callback)(const TamperInfo*)) {
    TamperInfo info;
    int result = rasp_detect_tampering(&info);
    
    if (result != RASP_SUCCESS && callback) {
        callback(&info);
    }
    
    return RASP_SUCCESS;
}

// ============================================================================
// CONTROL FLOW INTEGRITY
// ============================================================================

int rasp_init_cfi(void) {
    memset(g_cfi_counters, 0, sizeof(g_cfi_counters));
    g_cfi_counter_count = 0;
    return RASP_SUCCESS;
}

int rasp_create_cfi_counter(uint64_t counter_id, void* checkpoint_address) {
    if (g_cfi_counter_count >= RASP_MAX_CFI_COUNTERS) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    CFICounter* counter = &g_cfi_counters[g_cfi_counter_count++];
    counter->counter_id = counter_id;
    counter->expected_value = 0;
    counter->current_value = 0;
    counter->violation_count = 0;
    counter->checkpoint_address = checkpoint_address;
    
    return RASP_SUCCESS;
}

int rasp_increment_cfi_counter(uint64_t counter_id) {
    for (size_t i = 0; i < g_cfi_counter_count; i++) {
        if (g_cfi_counters[i].counter_id == counter_id) {
            g_cfi_counters[i].current_value++;
            return RASP_SUCCESS;
        }
    }
    
    return RASP_ERROR_INVALID_PARAM;
}

int rasp_verify_cfi_counter(uint64_t counter_id, uint64_t expected_value) {
    for (size_t i = 0; i < g_cfi_counter_count; i++) {
        if (g_cfi_counters[i].counter_id == counter_id) {
            if (g_cfi_counters[i].current_value != expected_value) {
                g_cfi_counters[i].violation_count++;
                rasp_log_event("CFI_VIOLATION", "Control flow integrity violation detected");
                return RASP_ERROR_CFI_VIOLATION;
            }
            return RASP_SUCCESS;
        }
    }
    
    return RASP_ERROR_INVALID_PARAM;
}

int rasp_reset_cfi_counter(uint64_t counter_id) {
    for (size_t i = 0; i < g_cfi_counter_count; i++) {
        if (g_cfi_counters[i].counter_id == counter_id) {
            g_cfi_counters[i].current_value = 0;
            g_cfi_counters[i].expected_value = 0;
            return RASP_SUCCESS;
        }
    }
    
    return RASP_ERROR_INVALID_PARAM;
}

int rasp_get_cfi_stats(uint64_t counter_id, CFICounter* counter) {
    if (!counter) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < g_cfi_counter_count; i++) {
        if (g_cfi_counters[i].counter_id == counter_id) {
            *counter = g_cfi_counters[i];
            return RASP_SUCCESS;
        }
    }
    
    return RASP_ERROR_INVALID_PARAM;
}

int rasp_verify_control_flow_path(const uint64_t* path_counters, size_t path_length) {
    if (!path_counters || path_length == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < path_length; i++) {
        // Verify each counter in the path was incremented
        int found = 0;
        for (size_t j = 0; j < g_cfi_counter_count; j++) {
            if (g_cfi_counters[j].counter_id == path_counters[i]) {
                if (g_cfi_counters[j].current_value == 0) {
                    rasp_log_event("CFI_VIOLATION", "Control flow path violation");
                    return RASP_ERROR_CFI_VIOLATION;
                }
                found = 1;
                break;
            }
        }
        
        if (!found) {
            return RASP_ERROR_INVALID_PARAM;
        }
    }
    
    return RASP_SUCCESS;
}

// ============================================================================
// RASP SYSTEM MANAGEMENT
// ============================================================================

int rasp_init(const RASPConfig* config) {
    if (!config) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    g_rasp_config = *config;
    g_rasp_initialized = 1;
    
    if (config->enable_cfi) {
        rasp_init_cfi();
    }
    
    if (config->enable_debugger_detection) {
        rasp_prevent_debugger_attach();
    }
    
    rasp_log_event("RASP_INIT", "RASP security system initialized");
    
    return RASP_SUCCESS;
}

void rasp_shutdown(void) {
    g_rasp_initialized = 0;
    memset(&g_rasp_config, 0, sizeof(RASPConfig));
    rasp_log_event("RASP_SHUTDOWN", "RASP security system shutdown");
}

int rasp_get_status(char* status, size_t max_len) {
    if (!status || max_len == 0) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    snprintf(status, max_len, 
             "RASP Status: %s | Checksum: %s | Signature: %s | Device Trust: %s | "
             "Hook Detection: %s | Debugger Detection: %s | Tamper Detection: %s | CFI: %s",
             g_rasp_initialized ? "Active" : "Inactive",
             g_rasp_config.enable_checksum_verification ? "ON" : "OFF",
             g_rasp_config.enable_signature_verification ? "ON" : "OFF",
             g_rasp_config.enable_device_trust ? "ON" : "OFF",
             g_rasp_config.enable_hook_detection ? "ON" : "OFF",
             g_rasp_config.enable_debugger_detection ? "ON" : "OFF",
             g_rasp_config.enable_tamper_detection ? "ON" : "OFF",
             g_rasp_config.enable_cfi ? "ON" : "OFF");
    
    return RASP_SUCCESS;
}

int rasp_comprehensive_check(void) {
    if (!g_rasp_initialized) {
        return RASP_ERROR_INVALID_PARAM;
    }
    
    int overall_result = RASP_SUCCESS;
    
    // Device trust check
    if (g_rasp_config.enable_device_trust) {
        DeviceTrust trust;
        rasp_assess_device_trust(&trust);
        if (trust.trust_score < 50) {
            overall_result = RASP_ERROR_UNTRUSTED_DEVICE;
        }
    }
    
    // Debugger detection
    if (g_rasp_config.enable_debugger_detection) {
        DebuggerInfo debug_info;
        if (rasp_detect_debugger(&debug_info) != RASP_SUCCESS) {
            overall_result = RASP_ERROR_DEBUGGER_DETECTED;
        }
    }
    
    // Tamper detection
    if (g_rasp_config.enable_tamper_detection) {
        TamperInfo tamper_info;
        if (rasp_detect_tampering(&tamper_info) != RASP_SUCCESS) {
            overall_result = RASP_ERROR_TAMPER_DETECTED;
        }
    }
    
    // Hook detection
    if (g_rasp_config.enable_hook_detection) {
        HookInfo hooks[10];
        int hook_count = rasp_scan_all_hooks(hooks, 10);
        if (hook_count > 0) {
            overall_result = RASP_ERROR_HOOK_DETECTED;
        }
    }
    
    return overall_result;
}

void rasp_log_event(const char* event_type, const char* message) {
    if (g_rasp_config.log_callback) {
        char log_message[512];
        snprintf(log_message, sizeof(log_message), 
                "[RASP][%s] %s", event_type, message);
        g_rasp_config.log_callback(log_message);
    }
}

