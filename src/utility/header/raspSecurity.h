/**
 * @file raspSecurity.h
 * @brief Runtime Application Self-Protection (RASP) Security Module
 * 
 * This module provides comprehensive runtime security protections including:
 * - Checksum verification for code integrity
 * - Application hash and signature verification
 * - Untrusted device detection
 * - HOOK attack detection
 * - Debugger detection and prevention
 * - Tamper detection and response
 * - Control flow integrity verification
 */

#ifndef RASP_SECURITY_H
#define RASP_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

#define RASP_HASH_SIZE 32
#define RASP_SIGNATURE_SIZE 256
#define RASP_MAX_PATH 512
#define RASP_MAX_HOOKS 64
#define RASP_MAX_CFI_COUNTERS 256

/**
 * @brief RASP Security Status Codes
 */
typedef enum {
    RASP_SUCCESS = 0,
    RASP_ERROR_INVALID_PARAM = -1,
    RASP_ERROR_CHECKSUM_FAIL = -2,
    RASP_ERROR_SIGNATURE_FAIL = -3,
    RASP_ERROR_UNTRUSTED_DEVICE = -4,
    RASP_ERROR_HOOK_DETECTED = -5,
    RASP_ERROR_DEBUGGER_DETECTED = -6,
    RASP_ERROR_TAMPER_DETECTED = -7,
    RASP_ERROR_CFI_VIOLATION = -8,
    RASP_ERROR_MEMORY_ALLOCATION = -9,
    RASP_ERROR_FILE_ACCESS = -10
} RASPStatus;

/**
 * @brief RASP Response Actions
 */
typedef enum {
    RASP_ACTION_NONE = 0,           /**< No action */
    RASP_ACTION_LOG = 1,            /**< Log the event */
    RASP_ACTION_ALERT = 2,          /**< Alert and continue */
    RASP_ACTION_BLOCK = 3,          /**< Block the operation */
    RASP_ACTION_TERMINATE = 4       /**< Terminate the application */
} RASPAction;

// ============================================================================
// CHECKSUM VERIFICATION (Runtime Code Block Control)
// ============================================================================

/**
 * @brief Structure for storing code block checksum information
 */
typedef struct {
    void* code_start;               /**< Start address of code block */
    size_t code_size;               /**< Size of code block in bytes */
    uint8_t expected_hash[RASP_HASH_SIZE]; /**< Expected hash value */
    uint32_t checksum_crc32;        /**< CRC32 checksum */
    uint64_t verification_count;    /**< Number of verifications performed */
    uint64_t last_verification;     /**< Timestamp of last verification */
} CodeBlockChecksum;

/**
 * @brief Calculate checksum for a code block
 * 
 * @param code_start Start address of code block
 * @param code_size Size of code block
 * @param checksum Output checksum structure
 * @return RASP_SUCCESS on success, error code on failure
 */
int rasp_calculate_checksum(const void* code_start, size_t code_size, 
                           CodeBlockChecksum* checksum);

/**
 * @brief Verify code block integrity using checksum
 * 
 * @param checksum Checksum structure to verify
 * @return RASP_SUCCESS if valid, error code if tampered
 */
int rasp_verify_checksum(const CodeBlockChecksum* checksum);

/**
 * @brief Continuous checksum monitoring in background
 * 
 * @param checksum Checksum to monitor
 * @param interval_ms Verification interval in milliseconds
 * @param callback Function to call on verification failure
 * @return RASP_SUCCESS on success
 */
int rasp_monitor_checksum(const CodeBlockChecksum* checksum, 
                         uint32_t interval_ms,
                         void (*callback)(RASPStatus));

// ============================================================================
// APPLICATION HASH AND SIGNATURE VERIFICATION
// ============================================================================

/**
 * @brief Application signature information
 */
typedef struct {
    uint8_t app_hash[RASP_HASH_SIZE];           /**< Application hash (SHA-256) */
    uint8_t signature[RASP_SIGNATURE_SIZE];     /**< Digital signature */
    char app_path[RASP_MAX_PATH];               /**< Application file path */
    uint8_t public_key[RASP_SIGNATURE_SIZE];    /**< Public key for verification */
    uint64_t file_size;                         /**< Application file size */
    uint64_t timestamp;                         /**< Signature timestamp */
    int is_verified;                            /**< Verification status */
} AppSignature;

/**
 * @brief Calculate hash of the calling application
 * 
 * @param app_path Path to application executable
 * @param hash Output buffer for hash (32 bytes)
 * @return RASP_SUCCESS on success
 */
int rasp_calculate_app_hash(const char* app_path, uint8_t* hash);

/**
 * @brief Verify application signature
 * 
 * @param signature Application signature structure
 * @return RASP_SUCCESS if valid, error code if invalid
 */
int rasp_verify_app_signature(const AppSignature* signature);

/**
 * @brief Get current application path and verify it
 * 
 * @param app_path Output buffer for application path
 * @param max_len Maximum length of buffer
 * @return RASP_SUCCESS on success
 */
int rasp_get_verified_app_path(char* app_path, size_t max_len);

/**
 * @brief Create application signature
 * 
 * @param app_path Path to application
 * @param private_key Private key for signing
 * @param signature Output signature structure
 * @return RASP_SUCCESS on success
 */
int rasp_create_app_signature(const char* app_path, 
                              const uint8_t* private_key,
                              AppSignature* signature);

// ============================================================================
// UNTRUSTED DEVICE DETECTION
// ============================================================================

/**
 * @brief Device trust indicators
 */
typedef struct {
    int is_rooted;                  /**< Device is rooted/jailbroken */
    int is_emulator;                /**< Running in emulator/VM */
    int has_debugger_tools;         /**< Debugger tools detected */
    int has_hooking_frameworks;     /**< Hooking frameworks detected */
    int system_files_modified;      /**< System files tampered */
    int certificate_pinning_bypass; /**< Cert pinning bypass detected */
    int trust_score;                /**< Overall trust score (0-100) */
} DeviceTrust;

/**
 * @brief Check if device is rooted/jailbroken
 * 
 * @return 1 if rooted, 0 if not, -1 on error
 */
int rasp_detect_root(void);

/**
 * @brief Check if running in emulator/VM
 * 
 * @return 1 if emulator, 0 if not, -1 on error
 */
int rasp_detect_emulator(void);

/**
 * @brief Verify critical system files
 * 
 * @param file_paths Array of file paths to check
 * @param count Number of files
 * @return RASP_SUCCESS if all valid, error code if modified
 */
int rasp_verify_system_files(const char** file_paths, size_t count);

/**
 * @brief Perform comprehensive device trust assessment
 * 
 * @param trust Output trust structure
 * @return RASP_SUCCESS on success
 */
int rasp_assess_device_trust(DeviceTrust* trust);

/**
 * @brief Check for known malicious applications
 * 
 * @param process_list Output buffer for detected processes
 * @param max_processes Maximum number of processes to return
 * @return Number of suspicious processes found
 */
int rasp_detect_malicious_apps(char** process_list, size_t max_processes);

// ============================================================================
// HOOK ATTACK DETECTION
// ============================================================================

/**
 * @brief Information about a detected hook
 */
typedef struct {
    void* target_address;           /**< Address of hooked function */
    void* hook_address;             /**< Address of hook handler */
    char function_name[128];        /**< Name of hooked function */
    uint8_t original_bytes[16];     /**< Original function bytes */
    uint8_t current_bytes[16];      /**< Current function bytes */
    uint64_t detection_time;        /**< When hook was detected */
} HookInfo;

/**
 * @brief Detect inline hooks in a function
 * 
 * @param function_address Address of function to check
 * @param original_bytes Expected original bytes
 * @param size Number of bytes to check
 * @return RASP_SUCCESS if no hook, error code if hooked
 */
int rasp_detect_inline_hook(const void* function_address, 
                           const uint8_t* original_bytes,
                           size_t size);

/**
 * @brief Detect IAT (Import Address Table) hooks
 * 
 * @param module_name Name of module to check
 * @return Number of hooks detected, -1 on error
 */
int rasp_detect_iat_hooks(const char* module_name);

/**
 * @brief Scan for all types of hooks in critical functions
 * 
 * @param hooks Output array for detected hooks
 * @param max_hooks Maximum number of hooks to return
 * @return Number of hooks detected
 */
int rasp_scan_all_hooks(HookInfo* hooks, size_t max_hooks);

/**
 * @brief Monitor function for hooking attempts
 * 
 * @param function_address Function to protect
 * @param original_bytes Original function bytes
 * @param size Size to monitor
 * @param callback Function to call if hook detected
 * @return RASP_SUCCESS on success
 */
int rasp_protect_function(void* function_address,
                         const uint8_t* original_bytes,
                         size_t size,
                         void (*callback)(const HookInfo*));

/**
 * @brief Verify integrity of system libraries
 * 
 * @param library_path Path to library
 * @return RASP_SUCCESS if valid, error code if modified
 */
int rasp_verify_library_integrity(const char* library_path);

// ============================================================================
// DEBUGGER DETECTION AND PREVENTION
// ============================================================================

/**
 * @brief Debugger detection result
 */
typedef struct {
    int debugger_present;           /**< Debugger is attached */
    int remote_debugger;            /**< Remote debugger detected */
    int kernel_debugger;            /**< Kernel debugger detected */
    int timing_anomaly;             /**< Timing-based detection */
    int hardware_breakpoints;       /**< Hardware breakpoints detected */
    int software_breakpoints;       /**< Software breakpoints detected */
    uint64_t detection_timestamp;   /**< When detection occurred */
} DebuggerInfo;

/**
 * @brief Check if debugger is currently attached
 * 
 * @return 1 if debugger present, 0 if not, -1 on error
 */
int rasp_is_debugger_present(void);

/**
 * @brief Advanced multi-method debugger detection
 * 
 * @param info Output debugger information
 * @return RASP_SUCCESS if no debugger, error code if detected
 */
int rasp_detect_debugger(DebuggerInfo* info);

/**
 * @brief Prevent debugger from attaching
 * 
 * @return RASP_SUCCESS on success
 */
int rasp_prevent_debugger_attach(void);

/**
 * @brief Detect hardware breakpoints
 * 
 * @return Number of breakpoints detected, -1 on error
 */
int rasp_detect_hardware_breakpoints(void);

/**
 * @brief Detect software breakpoints (0xCC, INT3)
 * 
 * @param code_start Start of code region to check
 * @param code_size Size of code region
 * @return Number of breakpoints detected
 */
int rasp_detect_software_breakpoints(const void* code_start, size_t code_size);

/**
 * @brief Timing-based debugger detection
 * 
 * Uses execution timing to detect debugger presence
 * @return 1 if suspicious timing, 0 if normal
 */
int rasp_detect_timing_anomaly(void);

/**
 * @brief Continuous debugger monitoring
 * 
 * @param interval_ms Check interval in milliseconds
 * @param action Action to take if debugger detected
 * @return RASP_SUCCESS on success
 */
int rasp_monitor_debugger(uint32_t interval_ms, RASPAction action);

// ============================================================================
// TAMPER DETECTION
// ============================================================================

/**
 * @brief Tamper detection result
 */
typedef struct {
    int memory_tampered;            /**< Memory modification detected */
    int code_tampered;              /**< Code modification detected */
    int data_tampered;              /**< Data modification detected */
    int config_tampered;            /**< Configuration tampered */
    int resource_tampered;          /**< Resources modified */
    uint64_t tamper_count;          /**< Number of tamper attempts */
    uint64_t last_tamper_time;      /**< Last tamper detection time */
} TamperInfo;

/**
 * @brief Detect memory tampering
 * 
 * @param memory_region Address of memory to check
 * @param size Size of memory region
 * @param expected_hash Expected hash of the region
 * @return RASP_SUCCESS if valid, error code if tampered
 */
int rasp_detect_memory_tamper(const void* memory_region, 
                             size_t size,
                             const uint8_t* expected_hash);

/**
 * @brief Comprehensive tamper detection
 * 
 * @param info Output tamper information
 * @return RASP_SUCCESS if no tampering, error code if detected
 */
int rasp_detect_tampering(TamperInfo* info);

/**
 * @brief Respond to detected tampering
 * 
 * @param info Tamper information
 * @param action Response action to take
 * @return RASP_SUCCESS on success
 */
int rasp_respond_to_tamper(const TamperInfo* info, RASPAction action);

/**
 * @brief Protect critical data with checksums
 * 
 * @param data Pointer to data to protect
 * @param size Size of data
 * @param checksum Output checksum
 * @return RASP_SUCCESS on success
 */
int rasp_protect_data(const void* data, size_t size, uint32_t* checksum);

/**
 * @brief Verify protected data
 * 
 * @param data Pointer to data to verify
 * @param size Size of data
 * @param checksum Expected checksum
 * @return RASP_SUCCESS if valid, error code if tampered
 */
int rasp_verify_protected_data(const void* data, size_t size, uint32_t checksum);

/**
 * @brief Monitor for tampering attempts
 * 
 * @param interval_ms Check interval in milliseconds
 * @param callback Function to call on tamper detection
 * @return RASP_SUCCESS on success
 */
int rasp_monitor_tampering(uint32_t interval_ms, 
                          void (*callback)(const TamperInfo*));

// ============================================================================
// CONTROL FLOW INTEGRITY (CFI)
// ============================================================================

/**
 * @brief Control flow counter structure
 */
typedef struct {
    uint64_t counter_id;            /**< Unique counter identifier */
    uint64_t expected_value;        /**< Expected counter value */
    uint64_t current_value;         /**< Current counter value */
    uint64_t violation_count;       /**< Number of violations */
    void* checkpoint_address;       /**< Code checkpoint address */
} CFICounter;

/**
 * @brief Initialize control flow integrity system
 * 
 * @return RASP_SUCCESS on success
 */
int rasp_init_cfi(void);

/**
 * @brief Create a CFI counter at a checkpoint
 * 
 * @param counter_id Unique identifier for this counter
 * @param checkpoint_address Address of code checkpoint
 * @return RASP_SUCCESS on success
 */
int rasp_create_cfi_counter(uint64_t counter_id, void* checkpoint_address);

/**
 * @brief Increment CFI counter at checkpoint
 * 
 * @param counter_id Counter to increment
 * @return RASP_SUCCESS on success, error if violation detected
 */
int rasp_increment_cfi_counter(uint64_t counter_id);

/**
 * @brief Verify CFI counter value
 * 
 * @param counter_id Counter to verify
 * @param expected_value Expected value
 * @return RASP_SUCCESS if valid, error code if violation
 */
int rasp_verify_cfi_counter(uint64_t counter_id, uint64_t expected_value);

/**
 * @brief Reset CFI counter
 * 
 * @param counter_id Counter to reset
 * @return RASP_SUCCESS on success
 */
int rasp_reset_cfi_counter(uint64_t counter_id);

/**
 * @brief Get CFI statistics
 * 
 * @param counter_id Counter ID
 * @param counter Output counter structure
 * @return RASP_SUCCESS on success
 */
int rasp_get_cfi_stats(uint64_t counter_id, CFICounter* counter);

/**
 * @brief Verify control flow path
 * 
 * @param path_counters Array of counter IDs representing expected path
 * @param path_length Number of counters in path
 * @return RASP_SUCCESS if path is valid, error code if violated
 */
int rasp_verify_control_flow_path(const uint64_t* path_counters, size_t path_length);

// ============================================================================
// RASP SYSTEM MANAGEMENT
// ============================================================================

/**
 * @brief RASP configuration
 */
typedef struct {
    int enable_checksum_verification;
    int enable_signature_verification;
    int enable_device_trust;
    int enable_hook_detection;
    int enable_debugger_detection;
    int enable_tamper_detection;
    int enable_cfi;
    uint32_t monitoring_interval_ms;
    RASPAction default_action;
    void (*log_callback)(const char* message);
} RASPConfig;

/**
 * @brief Initialize RASP security system
 * 
 * @param config Configuration parameters
 * @return RASP_SUCCESS on success
 */
int rasp_init(const RASPConfig* config);

/**
 * @brief Shutdown RASP security system
 */
void rasp_shutdown(void);

/**
 * @brief Get RASP system status
 * 
 * @param status Output buffer for status string
 * @param max_len Maximum length of buffer
 * @return RASP_SUCCESS on success
 */
int rasp_get_status(char* status, size_t max_len);

/**
 * @brief Perform comprehensive security check
 * 
 * Runs all enabled security checks
 * @return RASP_SUCCESS if all checks pass, error code otherwise
 */
int rasp_comprehensive_check(void);

/**
 * @brief Log security event
 * 
 * @param event_type Type of security event
 * @param message Event message
 */
void rasp_log_event(const char* event_type, const char* message);

#ifdef __cplusplus
}
#endif

#endif // RASP_SECURITY_H

