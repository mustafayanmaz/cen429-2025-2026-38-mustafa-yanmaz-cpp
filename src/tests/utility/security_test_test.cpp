/**
 * @file security_test_test.cpp
 * @brief Unit tests for the Security Testing Framework
 */

#include <gtest/gtest.h>
#include "securityTest.h"
#include "secureMemory.h"
#include "raspSecurity.h"
#include <cstring>

/**
 * @brief Test fixture for Security Testing Framework tests
 */
class SecurityTestFrameworkTest : public ::testing::Test {
protected:
    /**
     * @brief Sets up the test fixture
     * Initializes the security test framework
     */
    void SetUp() override {
        security_test_init();
    }
    
    /**
     * @brief Tears down the test fixture
     * Shuts down the security test framework
     */
    void TearDown() override {
        security_test_shutdown();
    }
};

// ============================================================================
// FRAMEWORK INITIALIZATION TESTS
// ============================================================================

/**
 * @brief Test successful framework initialization
 */
TEST_F(SecurityTestFrameworkTest, Init_Success) {
    // Already initialized in SetUp
    int result = security_test_init();
    EXPECT_EQ(result, 0);
}

/**
 * @brief Test successful framework shutdown and re-initialization
 */
TEST_F(SecurityTestFrameworkTest, Shutdown_Success) {
    security_test_shutdown();
    // Re-init should work
    int result = security_test_init();
    EXPECT_EQ(result, 0);
}

// ============================================================================
// AUTHENTICATION TESTS
// ============================================================================

/**
 * @brief Test authentication brute force protection
 */
TEST_F(SecurityTestFrameworkTest, Auth_BruteForce) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_auth_brute_force(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "AUTH-001");
}

/**
 * @brief Test secure password storage verification
 */
TEST_F(SecurityTestFrameworkTest, Auth_PasswordStorage) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_auth_password_storage(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "AUTH-002");
}

/**
 * @brief Test session hijacking protection
 */
TEST_F(SecurityTestFrameworkTest, Auth_SessionHijacking) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_auth_session_hijacking(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "AUTH-003");
}

// ============================================================================
// CRYPTOGRAPHY TESTS
// ============================================================================

/**
 * @brief Test whitebox cryptography key protection
 */
TEST_F(SecurityTestFrameworkTest, Crypto_WhiteboxKey) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_crypto_whitebox_key(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "CRYPTO-001");
}

/**
 * @brief Test cascade encryption functionality
 */
TEST_F(SecurityTestFrameworkTest, Crypto_Cascade) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_crypto_cascade(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "CRYPTO-003");
}

// ============================================================================
// RASP TESTS
// ============================================================================

/**
 * @brief Test RASP debugger detection security
 */
TEST_F(SecurityTestFrameworkTest, RASP_Debugger) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_rasp_debugger(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "RASP-001");
}

/**
 * @brief Test RASP tampering detection security
 */
TEST_F(SecurityTestFrameworkTest, RASP_Tampering) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_rasp_tampering(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "RASP-002");
}

/**
 * @brief Test RASP hook detection security
 */
TEST_F(SecurityTestFrameworkTest, RASP_Hooks) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_rasp_hooks(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "RASP-003");
}

/**
 * @brief Test RASP Control Flow Integrity (CFI) protection
 */
TEST_F(SecurityTestFrameworkTest, RASP_CFI) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_rasp_cfi(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "RASP-004");
}

// ============================================================================
// MEMORY SECURITY TESTS
// ============================================================================

/**
 * @brief Test memory buffer overflow protection
 */
TEST_F(SecurityTestFrameworkTest, Memory_BufferOverflow) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_mem_buffer_overflow(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "MEM-001");
}

/**
 * @brief Test sensitive data residue clearing in memory
 */
TEST_F(SecurityTestFrameworkTest, Memory_SensitiveResidue) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_mem_sensitive_residue(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "MEM-002");
}

/**
 * @brief Test memory disclosure prevention
 */
TEST_F(SecurityTestFrameworkTest, Memory_Disclosure) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_mem_disclosure(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "MEM-003");
}

// ============================================================================
// DATABASE TESTS
// ============================================================================

/**
 * @brief Test SQL injection prevention in database layer
 */
TEST_F(SecurityTestFrameworkTest, Database_SQLInjection) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_db_sql_injection(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "DB-001");
}

/**
 * @brief Test database encryption functionality
 */
TEST_F(SecurityTestFrameworkTest, Database_Encryption) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_db_encryption(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "DB-002");
}

// ============================================================================
// OBFUSCATION TESTS
// ============================================================================

/**
 * @brief Test string extraction obfuscation protection
 */
TEST_F(SecurityTestFrameworkTest, Obfuscation_StringExtraction) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_obf_string_extraction(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "OBF-001");
}

/**
 * @brief Test control flow obfuscation protection
 */
TEST_F(SecurityTestFrameworkTest, Obfuscation_ControlFlow) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = sec_test_obf_control_flow(&result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_EQ(result.status, SEC_TEST_PASS);
    EXPECT_STREQ(result.test_id, "OBF-002");
}

// ============================================================================
// TEST RUNNER TESTS
// ============================================================================

/**
 * @brief Test running all security tests successfully
 */
TEST_F(SecurityTestFrameworkTest, RunAll_Success) {
    SecurityTestSummary summary;
    memset(&summary, 0, sizeof(summary));
    
    int failed = security_test_run_all(&summary);
    
    EXPECT_GE(summary.total_tests, 17);
    EXPECT_EQ(failed, summary.failed);
    EXPECT_EQ(summary.failed, 0);
    EXPECT_GT(summary.total_duration_ms, 0);
}

/**
 * @brief Test running authentication category tests
 */
TEST_F(SecurityTestFrameworkTest, RunCategory_Auth) {
    SecurityTestSummary summary;
    memset(&summary, 0, sizeof(summary));
    
    int failed = security_test_run_category(SEC_CAT_AUTH, &summary);
    
    EXPECT_EQ(summary.total_tests, 3);
    EXPECT_EQ(failed, 0);
}

/**
 * @brief Test running RASP category tests
 */
TEST_F(SecurityTestFrameworkTest, RunCategory_RASP) {
    SecurityTestSummary summary;
    memset(&summary, 0, sizeof(summary));
    
    int failed = security_test_run_category(SEC_CAT_RASP, &summary);
    
    EXPECT_EQ(summary.total_tests, 4);
    EXPECT_EQ(failed, 0);
}

/**
 * @brief Test running a single valid security test
 */
TEST_F(SecurityTestFrameworkTest, RunSingle_Valid) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = security_test_run_single("AUTH-001", &result);
    
    EXPECT_EQ(failed, 0);
    EXPECT_STREQ(result.test_id, "AUTH-001");
}

/**
 * @brief Test running single test with invalid test ID
 */
TEST_F(SecurityTestFrameworkTest, RunSingle_Invalid) {
    SecurityTestResult result;
    memset(&result, 0, sizeof(result));
    
    int failed = security_test_run_single("INVALID-999", &result);
    
    EXPECT_EQ(failed, -1);
    EXPECT_EQ(result.status, SEC_TEST_ERROR);
}

// ============================================================================
// COMPLIANCE TESTS
// ============================================================================

/**
 * @brief Test ASVS Level 1 compliance check
 */
TEST_F(SecurityTestFrameworkTest, ASVS_Level1_Compliance) {
    ASVSComplianceResult result;
    memset(&result, 0, sizeof(result));
    
    float compliance = security_check_asvs_compliance(1, &result);
    
    EXPECT_GT(compliance, 90.0f);
    EXPECT_EQ(result.level, 1);
    EXPECT_GT(result.met_requirements, 0);
}

/**
 * @brief Test ASVS Level 2 compliance check
 */
TEST_F(SecurityTestFrameworkTest, ASVS_Level2_Compliance) {
    ASVSComplianceResult result;
    memset(&result, 0, sizeof(result));
    
    float compliance = security_check_asvs_compliance(2, &result);
    
    EXPECT_GT(compliance, 85.0f);
    EXPECT_EQ(result.level, 2);
}

/**
 * @brief Test ASVS Level 3 compliance check
 */
TEST_F(SecurityTestFrameworkTest, ASVS_Level3_Compliance) {
    ASVSComplianceResult result;
    memset(&result, 0, sizeof(result));
    
    float compliance = security_check_asvs_compliance(3, &result);
    
    EXPECT_GT(compliance, 85.0f);
    EXPECT_EQ(result.level, 3);
}

/**
 * @brief Test ETSI compliance check
 */
TEST_F(SecurityTestFrameworkTest, ETSI_Compliance) {
    ETSIComplianceResult result;
    memset(&result, 0, sizeof(result));
    
    float compliance = security_check_etsi_compliance(&result);
    
    EXPECT_GT(compliance, 90.0f);
    EXPECT_EQ(result.total_provisions, 13);
}

// ============================================================================
// REPORT GENERATION TESTS
// ============================================================================

/**
 * @brief Test JSON security report generation
 */
TEST_F(SecurityTestFrameworkTest, GenerateJSONReport) {
    SecurityTestSummary summary;
    memset(&summary, 0, sizeof(summary));
    summary.total_tests = 17;
    summary.passed = 17;
    summary.failed = 0;
    summary.total_duration_ms = 100;
    
    const char* path = "docs/security/evidence/test_report.json";
    int result = security_generate_json_report(&summary, NULL, 0, path);
    
    EXPECT_EQ(result, 0);
    
    // Verify file exists
    FILE* f = fopen(path, "r");
    EXPECT_NE(f, nullptr);
    if (f) fclose(f);
}

/**
 * @brief Test Markdown security report generation
 */
TEST_F(SecurityTestFrameworkTest, GenerateMDReport) {
    SecurityTestSummary summary;
    memset(&summary, 0, sizeof(summary));
    summary.total_tests = 17;
    summary.passed = 17;
    summary.failed = 0;
    summary.total_duration_ms = 100;
    
    const char* path = "docs/security/evidence/test_report.md";
    int result = security_generate_md_report(&summary, NULL, 0, path);
    
    EXPECT_EQ(result, 0);
    
    // Verify file exists
    FILE* f = fopen(path, "r");
    EXPECT_NE(f, nullptr);
    if (f) fclose(f);
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

/**
 * @brief Test full security audit integration with all tests and compliance checks
 */
TEST_F(SecurityTestFrameworkTest, FullSecurityAudit) {
    // Run all tests
    SecurityTestSummary summary;
    security_test_run_all(&summary);
    
    // Check ASVS compliance
    ASVSComplianceResult asvs;
    security_check_asvs_compliance(3, &asvs);
    
    // Check ETSI compliance
    ETSIComplianceResult etsi;
    security_check_etsi_compliance(&etsi);
    
    // Generate reports
    security_generate_json_report(&summary, NULL, 0, 
                                   "docs/security/evidence/full_audit.json");
    security_generate_md_report(&summary, NULL, 0,
                                 "docs/security/evidence/full_audit.md");
    
    // All tests should pass
    EXPECT_EQ(summary.failed, 0);
    EXPECT_GT(asvs.compliance_percentage, 85.0f);
    EXPECT_GT(etsi.compliance_percentage, 90.0f);
}

