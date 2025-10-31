/**
 * @file rasp_security_test.cpp
 * @brief Comprehensive unit tests for RASP (Runtime Application Self-Protection) Security
 */

#include "gtest/gtest.h"
extern "C" {
#include "raspSecurity.h"
}
#include <cstring>
#include <cstdlib>
#include <thread>
#include <chrono>

/**
 * @brief Test fixture for RASP security tests
 */
class RASPSecurityTest : public ::testing::Test {
protected:
    RASPConfig config;
    
    void SetUp() override {
        // Setup RASP configuration
        memset(&config, 0, sizeof(RASPConfig));
        config.enable_checksum_verification = 1;
        config.enable_signature_verification = 1;
        config.enable_device_trust = 1;
        config.enable_hook_detection = 1;
        config.enable_debugger_detection = 1;
        config.enable_tamper_detection = 1;
        config.enable_cfi = 1;
        config.monitoring_interval_ms = 1000;
        config.default_action = RASP_ACTION_LOG;
        config.log_callback = nullptr;
    }

    void TearDown() override {
        rasp_shutdown();
    }
};

// ============================================================================
// CHECKSUM VERIFICATION TESTS
// ============================================================================

/**
 * @brief Test application integrity verification workflow
 */
TEST_F(RASPSecurityTest, ApplicationIntegrityVerification) {
    // Simulate main function code block
    const char* mock_main_code = 
        "int main(int argc, char* argv[]) {\n"
        "    initialize_security();\n"
        "    return run_application();\n"
        "}\n";
    
    CodeBlockChecksum app_checksum;
    
    // Phase 1: Initial checksum calculation (startup)
    ASSERT_EQ(rasp_calculate_checksum(mock_main_code, strlen(mock_main_code), &app_checksum), 
              RASP_SUCCESS) << "Initial checksum calculation should succeed";
    
    EXPECT_GT(app_checksum.verification_count, 0) << "Verification count should be initialized";
    EXPECT_NE(app_checksum.checksum_crc32, 0) << "CRC32 should be calculated";
    
    // Phase 2: Verify integrity (runtime check)
    EXPECT_EQ(rasp_verify_checksum(&app_checksum), RASP_SUCCESS) 
        << "Integrity verification should pass for unmodified code";
    
    // Phase 3: Simulate code modification (tampering)
    char* tampered_code = strdup(mock_main_code);
    tampered_code[10] = 'X'; // Modify code
    
    CodeBlockChecksum tampered_checksum;
    rasp_calculate_checksum(tampered_code, strlen(tampered_code), &tampered_checksum);
    
    // Original checksum should fail when verified against tampered code
    CodeBlockChecksum verification_checksum = app_checksum;
    verification_checksum.code_start = (void*)tampered_code;
    
    EXPECT_NE(rasp_verify_checksum(&verification_checksum), RASP_SUCCESS)
        << "Integrity verification should fail for modified code";
    
    free(tampered_code);
}

/**
 * @brief Test periodic integrity checks
 */
TEST_F(RASPSecurityTest, PeriodicIntegrityChecks) {
    const char* code = "void critical_function() { secure_operation(); }";
    CodeBlockChecksum checksum;
    
    // Initial calculation
    ASSERT_EQ(rasp_calculate_checksum(code, strlen(code), &checksum), RASP_SUCCESS);
    
    // Simulate multiple periodic checks (like every 10 iterations in main loop)
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(rasp_verify_checksum(&checksum), RASP_SUCCESS)
            << "Periodic check #" << i << " should pass";
    }
    
    // Verification count should increase
    EXPECT_GT(checksum.verification_count, 0);
}

/**
 * @brief Test checksum with different code block sizes
 */
TEST_F(RASPSecurityTest, ChecksumDifferentSizes) {
    // Small block (like a single function)
    const char* small_code = "int add(int a, int b) { return a + b; }";
    CodeBlockChecksum small_checksum;
    EXPECT_EQ(rasp_calculate_checksum(small_code, strlen(small_code), &small_checksum), 
              RASP_SUCCESS);
    
    // Large block (like 4KB of main function - real scenario)
    char large_code[4096];
    memset(large_code, 'A', sizeof(large_code) - 1);
    large_code[4095] = '\0';
    CodeBlockChecksum large_checksum;
    EXPECT_EQ(rasp_calculate_checksum(large_code, 4096, &large_checksum), 
              RASP_SUCCESS);
    
    // Verify both
    EXPECT_EQ(rasp_verify_checksum(&small_checksum), RASP_SUCCESS);
    EXPECT_EQ(rasp_verify_checksum(&large_checksum), RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, CalculateChecksumValidInput) {
    const char* code = "This is a test code block for checksum calculation";
    CodeBlockChecksum checksum;
    
    int result = rasp_calculate_checksum(code, strlen(code), &checksum);
    
    EXPECT_EQ(result, RASP_SUCCESS);
    EXPECT_EQ(checksum.code_start, (void*)code);
    EXPECT_EQ(checksum.code_size, strlen(code));
    EXPECT_NE(checksum.checksum_crc32, 0u);
    EXPECT_EQ(checksum.verification_count, 1u);
}

TEST_F(RASPSecurityTest, CalculateChecksumNullPointer) {
    CodeBlockChecksum checksum;
    
    int result = rasp_calculate_checksum(nullptr, 100, &checksum);
    EXPECT_EQ(result, RASP_ERROR_INVALID_PARAM);
}

TEST_F(RASPSecurityTest, CalculateChecksumZeroSize) {
    const char* code = "test";
    CodeBlockChecksum checksum;
    
    int result = rasp_calculate_checksum(code, 0, &checksum);
    EXPECT_EQ(result, RASP_ERROR_INVALID_PARAM);
}

TEST_F(RASPSecurityTest, VerifyChecksumValid) {
    const char* code = "Test code for verification";
    CodeBlockChecksum checksum;
    
    rasp_calculate_checksum(code, strlen(code), &checksum);
    
    int result = rasp_verify_checksum(&checksum);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, VerifyChecksumModified) {
    char code[128] = "Original code for tamper detection";
    CodeBlockChecksum checksum;
    
    rasp_calculate_checksum(code, strlen(code), &checksum);
    
    // Modify the code
    code[0] = 'X';
    
    int result = rasp_verify_checksum(&checksum);
    EXPECT_EQ(result, RASP_ERROR_CHECKSUM_FAIL);
}

TEST_F(RASPSecurityTest, MonitorChecksumCallback) {
    const char* code = "Monitored code block";
    CodeBlockChecksum checksum;
    bool callback_invoked = false;
    
    rasp_calculate_checksum(code, strlen(code), &checksum);
    
    auto callback = [](RASPStatus status) {
        // Callback function for monitoring
    };
    
    int result = rasp_monitor_checksum(&checksum, 100, callback);
    EXPECT_EQ(result, RASP_SUCCESS);
}

// ============================================================================
// APPLICATION HASH AND SIGNATURE TESTS
// ============================================================================

TEST_F(RASPSecurityTest, CalculateAppHashValidPath) {
    uint8_t hash[RASP_HASH_SIZE];
    
    // Get current executable path
    char app_path[RASP_MAX_PATH];
    int path_result = rasp_get_verified_app_path(app_path, sizeof(app_path));
    
    if (path_result == RASP_SUCCESS) {
        int result = rasp_calculate_app_hash(app_path, hash);
        EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_FILE_ACCESS);
    }
}

TEST_F(RASPSecurityTest, CalculateAppHashInvalidPath) {
    uint8_t hash[RASP_HASH_SIZE];
    
    int result = rasp_calculate_app_hash("/nonexistent/path/to/app.exe", hash);
    EXPECT_EQ(result, RASP_ERROR_FILE_ACCESS);
}

TEST_F(RASPSecurityTest, CalculateAppHashNullPointer) {
    int result = rasp_calculate_app_hash(nullptr, nullptr);
    EXPECT_EQ(result, RASP_ERROR_INVALID_PARAM);
}

TEST_F(RASPSecurityTest, GetVerifiedAppPath) {
    char app_path[RASP_MAX_PATH];
    
    int result = rasp_get_verified_app_path(app_path, sizeof(app_path));
    EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_FILE_ACCESS);
    
    if (result == RASP_SUCCESS) {
        EXPECT_GT(strlen(app_path), 0u);
    }
}

TEST_F(RASPSecurityTest, CreateAppSignature) {
    AppSignature signature;
    uint8_t private_key[RASP_SIGNATURE_SIZE] = {0};
    
    char app_path[RASP_MAX_PATH];
    int path_result = rasp_get_verified_app_path(app_path, sizeof(app_path));
    
    if (path_result == RASP_SUCCESS) {
        int result = rasp_create_app_signature(app_path, private_key, &signature);
        EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_FILE_ACCESS);
    }
}

TEST_F(RASPSecurityTest, VerifyAppSignature) {
    AppSignature signature;
    memset(&signature, 0, sizeof(AppSignature));
    
    char app_path[RASP_MAX_PATH];
    int path_result = rasp_get_verified_app_path(app_path, sizeof(app_path));
    
    if (path_result == RASP_SUCCESS) {
        strncpy(signature.app_path, app_path, sizeof(signature.app_path) - 1);
        rasp_calculate_app_hash(app_path, signature.app_hash);
        
        int result = rasp_verify_app_signature(&signature);
        EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_FILE_ACCESS);
    }
}

// ============================================================================
// DEVICE TRUST TESTS
// ============================================================================

TEST_F(RASPSecurityTest, DetectRoot) {
    int result = rasp_detect_root();
    EXPECT_TRUE(result == 0 || result == 1);
}

TEST_F(RASPSecurityTest, DetectEmulator) {
    int result = rasp_detect_emulator();
    EXPECT_TRUE(result == 0 || result == 1);
}

TEST_F(RASPSecurityTest, VerifySystemFilesValid) {
#ifdef _WIN32
    const char* system_files[] = {
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\ntdll.dll"
    };
#else
    const char* system_files[] = {
        "/bin/sh",
        "/lib"
    };
#endif
    
    int result = rasp_verify_system_files(system_files, 2);
    EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_UNTRUSTED_DEVICE);
}

TEST_F(RASPSecurityTest, VerifySystemFilesInvalid) {
    const char* nonexistent_files[] = {
        "/nonexistent/file1",
        "/nonexistent/file2"
    };
    
    int result = rasp_verify_system_files(nonexistent_files, 2);
    EXPECT_EQ(result, RASP_ERROR_UNTRUSTED_DEVICE);
}

TEST_F(RASPSecurityTest, AssessDeviceTrust) {
    DeviceTrust trust;
    
    int result = rasp_assess_device_trust(&trust);
    EXPECT_EQ(result, RASP_SUCCESS);
    EXPECT_GE(trust.trust_score, 0);
    EXPECT_LE(trust.trust_score, 100);
}

TEST_F(RASPSecurityTest, DetectMaliciousApps) {
    char* process_list[10];
    
    int count = rasp_detect_malicious_apps(process_list, 10);
    EXPECT_GE(count, 0);
}

// ============================================================================
// HOOK DETECTION TESTS
// ============================================================================

TEST_F(RASPSecurityTest, DetectInlineHookNoHook) {
    uint8_t original_bytes[16] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83,
                                  0xEC, 0x20, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9};
    
    // Using the original_bytes as both function and reference
    int result = rasp_detect_inline_hook(original_bytes, original_bytes, 16);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, DetectInlineHookWithJMP) {
    uint8_t function_bytes[16] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90,
                                  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    uint8_t original_bytes[16] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x90, 0x90, 0x90,
                                  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    
    int result = rasp_detect_inline_hook(function_bytes, original_bytes, 16);
    EXPECT_EQ(result, RASP_ERROR_HOOK_DETECTED);
}

TEST_F(RASPSecurityTest, DetectInlineHookWithPushRet) {
    uint8_t function_bytes[16] = {0x68, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90,
                                  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    uint8_t original_bytes[16] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x90, 0x90,
                                  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    
    int result = rasp_detect_inline_hook(function_bytes, original_bytes, 16);
    EXPECT_EQ(result, RASP_ERROR_HOOK_DETECTED);
}

TEST_F(RASPSecurityTest, DetectIATHooks) {
#ifdef _WIN32
    int result = rasp_detect_iat_hooks("kernel32.dll");
    EXPECT_GE(result, 0);
#else
    GTEST_SKIP() << "IAT hooks only applicable on Windows";
#endif
}

TEST_F(RASPSecurityTest, ScanAllHooks) {
    HookInfo hooks[RASP_MAX_HOOKS];
    
    int count = rasp_scan_all_hooks(hooks, RASP_MAX_HOOKS);
    EXPECT_GE(count, 0);
    EXPECT_LE(count, (int)RASP_MAX_HOOKS);
}

/**
 * @brief Test periodic hook scanning (runtime monitoring)
 */
TEST_F(RASPSecurityTest, PeriodicHookScanning) {
    // Simulate periodic scanning (like every 10 iterations in main loop)
    for (int iteration = 0; iteration < 5; iteration++) {
        HookInfo hooks[5];
        int hook_count = rasp_scan_all_hooks(hooks, 5);
        
        EXPECT_GE(hook_count, 0) << "Iteration " << iteration << " should return valid count";
        EXPECT_LE(hook_count, 5) << "Hook count should not exceed buffer size";
        
        // Verify hook info structure if hooks detected
        for (int i = 0; i < hook_count; i++) {
            EXPECT_NE(hooks[i].target_address, nullptr) 
                << "Hook " << i << " should have valid function address";
            EXPECT_GT(strlen(hooks[i].function_name), 0) 
                << "Hook " << i << " should have function name";
        }
    }
}

/**
 * @brief Test runtime monitoring integration
 */
TEST_F(RASPSecurityTest, RuntimeMonitoringIntegration) {
    // Simulate application loop with security checks
    const int loop_iterations = 100;
    int integrity_checks = 0;
    int hook_scans = 0;
    
    for (int i = 0; i < loop_iterations; i++) {
        // Every 10 iterations, perform security checks (like in petcareapp.cpp)
        if (i % 10 == 0) {
            // Check 1: Code integrity (simulated)
            const char* code = "main_loop_code";
            CodeBlockChecksum checksum;
            if (rasp_calculate_checksum(code, strlen(code), &checksum) == RASP_SUCCESS) {
                if (rasp_verify_checksum(&checksum) == RASP_SUCCESS) {
                    integrity_checks++;
                }
            }
            
            // Check 2: Hook detection
            HookInfo hooks[5];
            int hook_count = rasp_scan_all_hooks(hooks, 5);
            if (hook_count >= 0) {
                hook_scans++;
            }
        }
    }
    
    // Verify monitoring occurred
    EXPECT_GT(integrity_checks, 0) << "Should perform integrity checks";
    EXPECT_GT(hook_scans, 0) << "Should perform hook scans";
    EXPECT_EQ(integrity_checks, 10) << "Should check integrity every 10 iterations";
    EXPECT_EQ(hook_scans, 10) << "Should scan hooks every 10 iterations";
}

/**
 * @brief Test hook detection with detailed logging
 */
TEST_F(RASPSecurityTest, HookDetectionWithLogging) {
    HookInfo hooks[10];
    int hook_count = rasp_scan_all_hooks(hooks, 10);
    
    // Log details for each detected hook (simulating petcareapp.cpp behavior)
    for (int i = 0; i < hook_count; i++) {
        EXPECT_NE(hooks[i].target_address, nullptr);
        EXPECT_GT(strlen(hooks[i].function_name), 0);
        
        // Verify timestamp is reasonable
        EXPECT_GT(hooks[i].detection_time, 0) << "Detection timestamp should be set";
    }
}

TEST_F(RASPSecurityTest, ProtectFunction) {
    uint8_t original_bytes[16] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83,
                                  0xEC, 0x20, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9};
    
    auto callback = [](const HookInfo* info) {
        // Hook detected callback
    };
    
    int result = rasp_protect_function((void*)original_bytes, original_bytes, 16, callback);
    EXPECT_EQ(result, RASP_SUCCESS);
}

// ============================================================================
// DEBUGGER DETECTION TESTS
// ============================================================================

TEST_F(RASPSecurityTest, IsDebuggerPresent) {
    int result = rasp_is_debugger_present();
    EXPECT_TRUE(result == 0 || result == 1);
}

TEST_F(RASPSecurityTest, DetectDebugger) {
    DebuggerInfo info;
    
    int result = rasp_detect_debugger(&info);
    // Result can be SUCCESS or DEBUGGER_DETECTED depending on environment
    EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_DEBUGGER_DETECTED);
    EXPECT_GT(info.detection_timestamp, 0u);
}

TEST_F(RASPSecurityTest, PreventDebuggerAttach) {
    int result = rasp_prevent_debugger_attach();
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, DetectHardwareBreakpoints) {
    int result = rasp_detect_hardware_breakpoints();
    EXPECT_GE(result, 0);
    EXPECT_LE(result, 4); // x86/x64 has max 4 hardware breakpoints
}

TEST_F(RASPSecurityTest, DetectSoftwareBreakpoints) {
    uint8_t code_no_bp[16] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83,
                               0xEC, 0x20, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9};
    
    int result = rasp_detect_software_breakpoints(code_no_bp, 16);
    EXPECT_EQ(result, 0);
}

TEST_F(RASPSecurityTest, DetectSoftwareBreakpointsWithINT3) {
    uint8_t code_with_bp[16] = {0xCC, 0x89, 0x5C, 0x24, 0x08, 0x57, 0xCC, 0x83,
                                0xEC, 0x20, 0x48, 0x8B, 0xDA, 0xCC, 0x8B, 0xF9};
    
    int result = rasp_detect_software_breakpoints(code_with_bp, 16);
    EXPECT_EQ(result, 3); // 3 INT3 instructions
}

TEST_F(RASPSecurityTest, DetectTimingAnomaly) {
    int result = rasp_detect_timing_anomaly();
    EXPECT_TRUE(result == 0 || result == 1);
}

TEST_F(RASPSecurityTest, MonitorDebugger) {
    int result = rasp_monitor_debugger(100, RASP_ACTION_LOG);
    EXPECT_EQ(result, RASP_SUCCESS);
}

// ============================================================================
// TAMPER DETECTION TESTS
// ============================================================================

TEST_F(RASPSecurityTest, DetectMemoryTamperNoTamper) {
    const char* data = "Protected memory region for testing";
    uint8_t hash[RASP_HASH_SIZE];
    
    // Calculate hash of original data
    memset(hash, 0, sizeof(hash));
    uint32_t h = 0x5A5A5A5A;
    for (size_t i = 0; i < strlen(data); i++) {
        h = ((h << 5) + h) + data[i];
        h ^= (h >> 16);
    }
    for (int i = 0; i < RASP_HASH_SIZE; i++) {
        hash[i] = (uint8_t)((h >> (i % 4 * 8)) & 0xFF);
        if (i % 4 == 3) h = h * 0x5BD1E995;
    }
    
    int result = rasp_detect_memory_tamper(data, strlen(data), hash);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, DetectMemoryTamperWithTamper) {
    char data[128] = "Protected memory that will be modified";
    uint8_t hash[RASP_HASH_SIZE];
    
    // Calculate hash of original
    uint32_t h = 0x5A5A5A5A;
    for (size_t i = 0; i < strlen(data); i++) {
        h = ((h << 5) + h) + data[i];
        h ^= (h >> 16);
    }
    for (int i = 0; i < RASP_HASH_SIZE; i++) {
        hash[i] = (uint8_t)((h >> (i % 4 * 8)) & 0xFF);
        if (i % 4 == 3) h = h * 0x5BD1E995;
    }
    
    // Modify data
    data[0] = 'X';
    
    int result = rasp_detect_memory_tamper(data, strlen(data), hash);
    EXPECT_EQ(result, RASP_ERROR_TAMPER_DETECTED);
}

TEST_F(RASPSecurityTest, DetectTampering) {
    TamperInfo info;
    
    int result = rasp_detect_tampering(&info);
    EXPECT_TRUE(result == RASP_SUCCESS || result == RASP_ERROR_TAMPER_DETECTED);
}

TEST_F(RASPSecurityTest, RespondToTamperLog) {
    TamperInfo info;
    memset(&info, 0, sizeof(info));
    info.tamper_count = 1;
    
    int result = rasp_respond_to_tamper(&info, RASP_ACTION_LOG);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, RespondToTamperBlock) {
    TamperInfo info;
    memset(&info, 0, sizeof(info));
    info.tamper_count = 1;
    
    int result = rasp_respond_to_tamper(&info, RASP_ACTION_BLOCK);
    EXPECT_EQ(result, RASP_ERROR_TAMPER_DETECTED);
}

TEST_F(RASPSecurityTest, ProtectData) {
    const char* data = "Data to protect with checksum";
    uint32_t checksum = 0;
    
    int result = rasp_protect_data(data, strlen(data), &checksum);
    EXPECT_EQ(result, RASP_SUCCESS);
    EXPECT_NE(checksum, 0u);
}

TEST_F(RASPSecurityTest, VerifyProtectedDataValid) {
    const char* data = "Verified protected data";
    uint32_t checksum = 0;
    
    rasp_protect_data(data, strlen(data), &checksum);
    
    int result = rasp_verify_protected_data(data, strlen(data), checksum);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, VerifyProtectedDataTampered) {
    char data[128] = "Data that will be tampered";
    uint32_t checksum = 0;
    
    rasp_protect_data(data, strlen(data), &checksum);
    
    // Tamper with data
    data[0] = 'X';
    
    int result = rasp_verify_protected_data(data, strlen(data), checksum);
    EXPECT_EQ(result, RASP_ERROR_TAMPER_DETECTED);
}

// ============================================================================
// CONTROL FLOW INTEGRITY TESTS
// ============================================================================

TEST_F(RASPSecurityTest, InitCFI) {
    int result = rasp_init_cfi();
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, CreateCFICounter) {
    rasp_init_cfi();
    
    int result = rasp_create_cfi_counter(1, (void*)0x1000);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, IncrementCFICounter) {
    rasp_init_cfi();
    rasp_create_cfi_counter(1, (void*)0x1000);
    
    int result = rasp_increment_cfi_counter(1);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, VerifyCFICounterValid) {
    rasp_init_cfi();
    rasp_create_cfi_counter(1, (void*)0x1000);
    rasp_increment_cfi_counter(1);
    
    int result = rasp_verify_cfi_counter(1, 1);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, VerifyCFICounterViolation) {
    rasp_init_cfi();
    rasp_create_cfi_counter(1, (void*)0x1000);
    rasp_increment_cfi_counter(1);
    
    // Expect different value
    int result = rasp_verify_cfi_counter(1, 5);
    EXPECT_EQ(result, RASP_ERROR_CFI_VIOLATION);
}

TEST_F(RASPSecurityTest, ResetCFICounter) {
    rasp_init_cfi();
    rasp_create_cfi_counter(1, (void*)0x1000);
    rasp_increment_cfi_counter(1);
    
    int result = rasp_reset_cfi_counter(1);
    EXPECT_EQ(result, RASP_SUCCESS);
    
    // After reset, value should be 0
    result = rasp_verify_cfi_counter(1, 0);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, GetCFIStats) {
    rasp_init_cfi();
    rasp_create_cfi_counter(1, (void*)0x1000);
    rasp_increment_cfi_counter(1);
    rasp_increment_cfi_counter(1);
    
    CFICounter counter;
    int result = rasp_get_cfi_stats(1, &counter);
    
    EXPECT_EQ(result, RASP_SUCCESS);
    EXPECT_EQ(counter.counter_id, 1u);
    EXPECT_EQ(counter.current_value, 2u);
}

TEST_F(RASPSecurityTest, VerifyControlFlowPath) {
    rasp_init_cfi();
    
    // Create path of counters
    rasp_create_cfi_counter(1, (void*)0x1000);
    rasp_create_cfi_counter(2, (void*)0x2000);
    rasp_create_cfi_counter(3, (void*)0x3000);
    
    // Increment counters in path
    rasp_increment_cfi_counter(1);
    rasp_increment_cfi_counter(2);
    rasp_increment_cfi_counter(3);
    
    uint64_t path[] = {1, 2, 3};
    int result = rasp_verify_control_flow_path(path, 3);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, VerifyControlFlowPathViolation) {
    rasp_init_cfi();
    
    // Create counters but don't increment all
    rasp_create_cfi_counter(1, (void*)0x1000);
    rasp_create_cfi_counter(2, (void*)0x2000);
    rasp_create_cfi_counter(3, (void*)0x3000);
    
    rasp_increment_cfi_counter(1);
    // Skip counter 2
    rasp_increment_cfi_counter(3);
    
    uint64_t path[] = {1, 2, 3};
    int result = rasp_verify_control_flow_path(path, 3);
    EXPECT_EQ(result, RASP_ERROR_CFI_VIOLATION);
}

// ============================================================================
// RASP SYSTEM MANAGEMENT TESTS
// ============================================================================

TEST_F(RASPSecurityTest, InitRASPSystem) {
    int result = rasp_init(&config);
    EXPECT_EQ(result, RASP_SUCCESS);
}

TEST_F(RASPSecurityTest, InitRASPNullConfig) {
    int result = rasp_init(nullptr);
    EXPECT_EQ(result, RASP_ERROR_INVALID_PARAM);
}

TEST_F(RASPSecurityTest, ShutdownRASP) {
    rasp_init(&config);
    rasp_shutdown();
    // No assertion, just verify it doesn't crash
}

TEST_F(RASPSecurityTest, GetStatus) {
    char status[512];
    
    rasp_init(&config);
    
    int result = rasp_get_status(status, sizeof(status));
    EXPECT_EQ(result, RASP_SUCCESS);
    EXPECT_GT(strlen(status), 0u);
    EXPECT_NE(strstr(status, "Active"), nullptr);
}

TEST_F(RASPSecurityTest, ComprehensiveCheck) {
    rasp_init(&config);
    
    int result = rasp_comprehensive_check();
    // Result depends on environment, just verify it doesn't crash
    EXPECT_TRUE(result == RASP_SUCCESS || 
                result == RASP_ERROR_DEBUGGER_DETECTED ||
                result == RASP_ERROR_TAMPER_DETECTED ||
                result == RASP_ERROR_UNTRUSTED_DEVICE ||
                result == RASP_ERROR_HOOK_DETECTED);
}

TEST_F(RASPSecurityTest, LogEvent) {
    bool callback_called = false;
    std::string logged_message;
    
    config.log_callback = [](const char* msg) {
        // Callback captured in closure won't work with C function pointer
        // This is just to demonstrate the API
    };
    
    rasp_init(&config);
    rasp_log_event("TEST_EVENT", "Test message");
    
    // No assertion, just verify it doesn't crash
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

TEST_F(RASPSecurityTest, IntegrationFullProtection) {
    // Initialize RASP with all protections enabled
    int result = rasp_init(&config);
    ASSERT_EQ(result, RASP_SUCCESS);
    
    // Create some protected code
    const char* code = "Protected function code";
    CodeBlockChecksum checksum;
    rasp_calculate_checksum(code, strlen(code), &checksum);
    
    // Verify checksum
    EXPECT_EQ(rasp_verify_checksum(&checksum), RASP_SUCCESS);
    
    // Initialize CFI
    rasp_create_cfi_counter(100, (void*)0x10000);
    rasp_increment_cfi_counter(100);
    
    // Verify CFI
    EXPECT_EQ(rasp_verify_cfi_counter(100, 1), RASP_SUCCESS);
    
    // Check device trust
    DeviceTrust trust;
    rasp_assess_device_trust(&trust);
    EXPECT_GE(trust.trust_score, 0);
    
    // Run comprehensive check
    rasp_comprehensive_check();
    
    // Clean up
    rasp_shutdown();
}

TEST_F(RASPSecurityTest, IntegrationDetectionResponseFlow) {
    config.default_action = RASP_ACTION_LOG;
    rasp_init(&config);
    
    // Simulate tamper detection
    TamperInfo tamper_info;
    memset(&tamper_info, 0, sizeof(tamper_info));
    
    rasp_detect_tampering(&tamper_info);
    
    if (tamper_info.tamper_count > 0) {
        rasp_respond_to_tamper(&tamper_info, RASP_ACTION_LOG);
    }
    
    rasp_shutdown();
}

TEST_F(RASPSecurityTest, StressTestMultipleCFICounters) {
    rasp_init(&config);
    
    // Create many CFI counters
    const int num_counters = 100;
    for (int i = 0; i < num_counters; i++) {
        int result = rasp_create_cfi_counter(i, (void*)(uintptr_t)(0x10000 + i * 0x1000));
        EXPECT_EQ(result, RASP_SUCCESS);
    }
    
    // Increment all counters
    for (int i = 0; i < num_counters; i++) {
        rasp_increment_cfi_counter(i);
    }
    
    // Verify all counters
    for (int i = 0; i < num_counters; i++) {
        int result = rasp_verify_cfi_counter(i, 1);
        EXPECT_EQ(result, RASP_SUCCESS);
    }
    
    rasp_shutdown();
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

TEST_F(RASPSecurityTest, PerformanceChecksumCalculation) {
    const size_t test_size = 1024 * 1024; // 1MB
    char* large_data = (char*)malloc(test_size);
    ASSERT_NE(large_data, nullptr);
    
    memset(large_data, 0xAA, test_size);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    CodeBlockChecksum checksum;
    rasp_calculate_checksum(large_data, test_size, &checksum);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should complete in reasonable time (< 100ms for 1MB)
    EXPECT_LT(duration.count(), 100);
    
    free(large_data);
}

TEST_F(RASPSecurityTest, PerformanceCFIOperations) {
    rasp_init(&config);
    rasp_create_cfi_counter(1, (void*)0x1000);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Perform many CFI operations
    const int iterations = 10000;
    for (int i = 0; i < iterations; i++) {
        rasp_increment_cfi_counter(1);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should be very fast (< 10ms for 10000 increments)
    EXPECT_LT(duration.count(), 10);
    
    rasp_shutdown();
}

// Run all tests
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

