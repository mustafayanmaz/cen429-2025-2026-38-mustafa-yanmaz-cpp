/**
 * @file securityTest.h
 * @brief Security Testing Framework for PetCare Application
 * 
 * This module provides automated security testing capabilities including:
 * - Penetration test scenarios
 * - Security certification validation
 * - OWASP ASVS compliance checking
 */

#ifndef SECURITY_TEST_H
#define SECURITY_TEST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// TEST RESULT STRUCTURES
// ============================================================================

/**
 * @brief Test result status
 */
typedef enum SecurityTestStatus {
    SEC_TEST_PASS = 0,   /**< Test passed successfully */
    SEC_TEST_FAIL = 1,   /**< Test failed */
    SEC_TEST_SKIP = 2,   /**< Test was skipped */
    SEC_TEST_ERROR = 3   /**< Test encountered an error */
} SecurityTestStatus;

/**
 * @brief Test severity level
 */
typedef enum SecurityTestSeverity {
    SEC_SEVERITY_CRITICAL = 0,  /**< Critical severity - immediate action required */
    SEC_SEVERITY_HIGH = 1,      /**< High severity - important security issue */
    SEC_SEVERITY_MEDIUM = 2,    /**< Medium severity - moderate risk */
    SEC_SEVERITY_LOW = 3,       /**< Low severity - minor issue */
    SEC_SEVERITY_INFO = 4       /**< Informational - no security impact */
} SecurityTestSeverity;

/**
 * @brief Individual test result
 */
typedef struct SecurityTestResult {
    char test_id[32];           /**< Test identifier (e.g., AUTH-001) */
    char test_name[128];        /**< Test description */
    SecurityTestStatus status;   /**< Pass/Fail/Skip/Error */
    SecurityTestSeverity severity; /**< Test severity */
    char details[512];          /**< Detailed result message */
    uint64_t duration_ms;       /**< Test execution time */
} SecurityTestResult;

/**
 * @brief Test suite summary
 */
typedef struct SecurityTestSummary {
    int total_tests;            /**< Total number of tests executed */
    int passed;                 /**< Number of tests that passed */
    int failed;                 /**< Number of tests that failed */
    int skipped;                /**< Number of tests that were skipped */
    int errors;                 /**< Number of tests that encountered errors */
    uint64_t total_duration_ms; /**< Total execution time in milliseconds */
    char report_path[256];      /**< Path to the generated report file */
} SecurityTestSummary;

// ============================================================================
// TEST CATEGORIES
// ============================================================================

/**
 * @brief Test category flags
 */
typedef enum SecurityTestCategory {
    SEC_CAT_AUTH        = 0x0001,  /**< Authentication tests */
    SEC_CAT_CRYPTO      = 0x0002,  /**< Cryptography tests */
    SEC_CAT_RASP        = 0x0004,  /**< RASP protection tests */
    SEC_CAT_MEMORY      = 0x0008,  /**< Memory security tests */
    SEC_CAT_DATABASE    = 0x0010,  /**< Database security tests */
    SEC_CAT_OBFUSCATION = 0x0020,  /**< Code obfuscation tests */
    SEC_CAT_ALL         = 0xFFFF   /**< All categories */
} SecurityTestCategory;

// ============================================================================
// TEST RUNNER API
// ============================================================================

/**
 * @brief Initialize security test framework
 * @return 0 on success, -1 on failure
 */
int security_test_init(void);

/**
 * @brief Shutdown security test framework
 */
void security_test_shutdown(void);

/**
 * @brief Run all security tests
 * @param summary Output summary of test results
 * @return Number of failed tests (0 = all passed)
 */
int security_test_run_all(SecurityTestSummary* summary);

/**
 * @brief Run tests for specific category
 * @param category Test category to run
 * @param summary Output summary of test results
 * @return Number of failed tests
 */
int security_test_run_category(SecurityTestCategory category, SecurityTestSummary* summary);

/**
 * @brief Run single test by ID
 * @param test_id Test identifier (e.g., "AUTH-001")
 * @param result Output test result
 * @return 0 if test passed, 1 if failed
 */
int security_test_run_single(const char* test_id, SecurityTestResult* result);

// ============================================================================
// INDIVIDUAL TEST FUNCTIONS
// ============================================================================

// Authentication Tests

/**
 * @brief Test brute force attack protection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_auth_brute_force(SecurityTestResult* result);

/**
 * @brief Test password storage security
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_auth_password_storage(SecurityTestResult* result);

/**
 * @brief Test session hijacking protection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_auth_session_hijacking(SecurityTestResult* result);

// Cryptography Tests

/**
 * @brief Test whitebox AES key protection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_crypto_whitebox_key(SecurityTestResult* result);

/**
 * @brief Test HMAC integrity bypass prevention
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_crypto_hmac_bypass(SecurityTestResult* result);

/**
 * @brief Test cascade encryption mechanism
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_crypto_cascade(SecurityTestResult* result);

// RASP Tests

/**
 * @brief Test debugger detection mechanism
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_rasp_debugger(SecurityTestResult* result);

/**
 * @brief Test code tampering detection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_rasp_tampering(SecurityTestResult* result);

/**
 * @brief Test inline hook detection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_rasp_hooks(SecurityTestResult* result);

/**
 * @brief Test control flow integrity mechanism
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_rasp_cfi(SecurityTestResult* result);

// Memory Security Tests

/**
 * @brief Test buffer overflow protection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_mem_buffer_overflow(SecurityTestResult* result);

/**
 * @brief Test sensitive data residue wiping
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_mem_sensitive_residue(SecurityTestResult* result);

/**
 * @brief Test memory disclosure prevention
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_mem_disclosure(SecurityTestResult* result);

// Database Tests

/**
 * @brief Test SQL injection protection
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_db_sql_injection(SecurityTestResult* result);

/**
 * @brief Test database encryption
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_db_encryption(SecurityTestResult* result);

// Obfuscation Tests

/**
 * @brief Test string extraction prevention
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_obf_string_extraction(SecurityTestResult* result);

/**
 * @brief Test control flow obfuscation
 * @param result Output test result structure
 * @return 0 if test passed, 1 if failed
 */
int sec_test_obf_control_flow(SecurityTestResult* result);

// ============================================================================
// CERTIFICATION VALIDATION
// ============================================================================

/**
 * @brief OWASP ASVS compliance result
 */
typedef struct ASVSComplianceResult {
    int level;                    /**< ASVS level (1, 2, or 3) */
    int total_requirements;       /**< Total number of requirements for the level */
    int met_requirements;         /**< Number of requirements that are met */
    int not_applicable;           /**< Number of requirements not applicable */
    float compliance_percentage;  /**< Calculated compliance percentage (0-100) */
    char details[1024];           /**< Detailed compliance report message */
} ASVSComplianceResult;

/**
 * @brief Check OWASP ASVS compliance
 * @param level ASVS level to check (1, 2, or 3)
 * @param result Output compliance result
 * @return Compliance percentage (0-100)
 */
float security_check_asvs_compliance(int level, ASVSComplianceResult* result);

/**
 * @brief ETSI compliance result
 */
typedef struct ETSIComplianceResult {
    int total_provisions;         /**< Total number of ETSI provisions */
    int met_provisions;           /**< Number of provisions that are met */
    int not_applicable;           /**< Number of provisions not applicable */
    float compliance_percentage;  /**< Calculated compliance percentage (0-100) */
} ETSIComplianceResult;

/**
 * @brief Check ETSI EN 303 645 compliance
 * @param result Output compliance result
 * @return Compliance percentage (0-100)
 */
float security_check_etsi_compliance(ETSIComplianceResult* result);

// ============================================================================
// REPORT GENERATION
// ============================================================================

/**
 * @brief Generate JSON security test report
 * @param summary Test summary
 * @param results Array of test results
 * @param result_count Number of results
 * @param output_path Output file path
 * @return 0 on success
 */
int security_generate_json_report(
    const SecurityTestSummary* summary,
    const SecurityTestResult* results,
    int result_count,
    const char* output_path
);

/**
 * @brief Generate markdown security test report
 * @param summary Test summary
 * @param results Array of test results
 * @param result_count Number of results
 * @param output_path Output file path
 * @return 0 on success
 */
int security_generate_md_report(
    const SecurityTestSummary* summary,
    const SecurityTestResult* results,
    int result_count,
    const char* output_path
);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_TEST_H

