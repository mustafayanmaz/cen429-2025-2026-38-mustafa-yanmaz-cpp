/**
 * @file assetProtection.h
 * @brief Static and Dynamic Asset Protection
 * 
 * This module provides protection for:
 * - Static Assets: Secret keys, hash values, source code constants
 * - Dynamic Assets: Device fingerprints, session data, dynamic keys
 */

#ifndef ASSET_PROTECTION_H
#define ASSET_PROTECTION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// STATIC ASSET PROTECTION
// ============================================================================

/**
 * @brief Maximum size for obfuscated strings
 */
#define OBFUSCATED_STRING_MAX_SIZE 256

/**
 * @brief Structure for storing obfuscated static strings
 */
typedef struct {
    uint8_t data[OBFUSCATED_STRING_MAX_SIZE];  /**< Encrypted data */
    size_t length;                              /**< Original length */
    uint8_t key[32];                            /**< XOR key for obfuscation */
    uint32_t checksum;                          /**< Integrity checksum */
} ObfuscatedString;

/**
 * @brief Create an obfuscated string from plaintext
 * 
 * @param plaintext Input plaintext string
 * @param obf Output obfuscated string structure
 * @return 0 on success, -1 on failure
 */
int create_obfuscated_string(const char* plaintext, ObfuscatedString* obf);

/**
 * @brief Reveal (decrypt) an obfuscated string
 * 
 * @param obf Obfuscated string structure
 * @param output Buffer to store decrypted string
 * @param output_size Size of output buffer
 * @return 0 on success, -1 on failure or tampering detected
 */
int reveal_obfuscated_string(const ObfuscatedString* obf, char* output, size_t output_size);

/**
 * @brief Verify integrity of obfuscated string
 * 
 * @param obf Obfuscated string structure
 * @return 1 if valid, 0 if tampered
 */
int verify_obfuscated_string(const ObfuscatedString* obf);

/**
 * @brief Derive a key from multiple static sources
 * 
 * This combines various compile-time and runtime constants to create
 * a derived key that's harder to extract from memory dumps.
 * 
 * @param app_id Application identifier
 * @param version_code Version code
 * @param build_timestamp Build timestamp
 * @param derived_key Output buffer for derived key (32 bytes)
 * @return 0 on success, -1 on failure
 */
int derive_static_key(const char* app_id, 
                      uint32_t version_code,
                      uint64_t build_timestamp,
                      uint8_t* derived_key);

/**
 * @brief Store a hash value securely
 * 
 * @param hash Input hash (32 bytes)
 * @param stored Output protected hash structure
 * @return 0 on success, -1 on failure
 */
int protect_hash_value(const uint8_t* hash, ObfuscatedString* stored);

/**
 * @brief Verify a hash value against stored protected hash
 * 
 * @param hash Input hash to verify
 * @param stored Stored protected hash
 * @return 1 if match, 0 if mismatch or tampered
 */
int verify_hash_value(const uint8_t* hash, const ObfuscatedString* stored);

// ============================================================================
// DYNAMIC ASSET PROTECTION
// ============================================================================

/**
 * @brief Maximum length for fingerprint string
 */
#define FINGERPRINT_MAX_LENGTH 128

/**
 * @brief Structure for device/application fingerprint
 */
typedef struct {
    uint8_t hardware_id[32];        /**< Hardware-based identifier */
    uint8_t software_id[32];        /**< Software-based identifier */
    uint8_t combined_fingerprint[64]; /**< Combined unique fingerprint */
    uint64_t creation_timestamp;    /**< When fingerprint was created */
    uint32_t integrity_hash;        /**< Self-integrity check */
} DeviceFingerprint;

/**
 * @brief Generate device/application fingerprint
 * 
 * Creates a unique fingerprint based on:
 * - Hardware characteristics (CPU, memory, disk)
 * - Software environment (OS, username, hostname)
 * - Application-specific data
 * 
 * @param fingerprint Output fingerprint structure
 * @return 0 on success, -1 on failure
 */
int generate_device_fingerprint(DeviceFingerprint* fingerprint);

/**
 * @brief Verify device fingerprint hasn't changed
 * 
 * @param current Current fingerprint
 * @param stored Previously stored fingerprint
 * @return 1 if match (same device), 0 if different, -1 on error
 */
int verify_device_fingerprint(const DeviceFingerprint* current, 
                              const DeviceFingerprint* stored);

/**
 * @brief Session data structure
 */
typedef struct {
    uint8_t session_id[32];         /**< Unique session identifier */
    uint8_t session_key[32];        /**< Encrypted session key */
    uint8_t encryption_iv[16];      /**< IV for session encryption */
    uint64_t creation_time;         /**< Session creation timestamp */
    uint64_t expiry_time;           /**< Session expiry timestamp */
    uint32_t access_count;          /**< Number of times accessed */
    uint8_t fingerprint_hash[32];   /**< Hash of device fingerprint */
    uint32_t integrity_check;       /**< Tamper detection */
} SessionData;

/**
 * @brief Create a new encrypted session
 * 
 * @param fingerprint Device fingerprint for binding
 * @param lifetime_seconds Session lifetime in seconds
 * @param session Output session data
 * @return 0 on success, -1 on failure
 */
int create_session(const DeviceFingerprint* fingerprint,
                  uint32_t lifetime_seconds,
                  SessionData* session);

/**
 * @brief Validate and decrypt session data
 * 
 * @param session Session to validate
 * @param fingerprint Current device fingerprint
 * @param decrypted_key Output buffer for decrypted session key (32 bytes)
 * @return 0 on success, -1 if invalid/expired/tampered
 */
int validate_session(SessionData* session,
                    const DeviceFingerprint* fingerprint,
                    uint8_t* decrypted_key);

/**
 * @brief Invalidate (destroy) a session
 * 
 * @param session Session to invalidate
 */
void invalidate_session(SessionData* session);

/**
 * @brief Generate a dynamic key based on runtime state
 * 
 * Creates a key that changes based on:
 * - Current timestamp
 * - Memory state
 * - Process ID
 * - Random entropy
 * 
 * @param seed Initial seed value
 * @param dynamic_key Output buffer for dynamic key (32 bytes)
 * @return 0 on success, -1 on failure
 */
int generate_dynamic_key(uint64_t seed, uint8_t* dynamic_key);

/**
 * @brief Rotate session key dynamically
 * 
 * @param session Session to rotate key for
 * @param new_key New key to use (32 bytes)
 * @return 0 on success, -1 on failure
 */
int rotate_session_key(SessionData* session, const uint8_t* new_key);

// ============================================================================
// ANTI-TAMPERING
// ============================================================================

/**
 * @brief Check for debugging/tampering attempts
 * 
 * @return 0 if clean, 1 if debugger detected, 2 if tampering detected
 */
int detect_tampering(void);

/**
 * @brief Get current application integrity hash
 * 
 * @param integrity_hash Output buffer (32 bytes)
 * @return 0 on success, -1 on failure
 */
int get_app_integrity_hash(uint8_t* integrity_hash);

/**
 * @brief Verify application hasn't been modified
 * 
 * @param expected_hash Expected integrity hash (32 bytes)
 * @return 1 if valid, 0 if tampered
 */
int verify_app_integrity(const uint8_t* expected_hash);

#ifdef __cplusplus
}
#endif

#endif // ASSET_PROTECTION_H

