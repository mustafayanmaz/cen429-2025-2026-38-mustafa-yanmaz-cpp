/**
 * @file assetProtection.cpp
 * @brief Implementation of static and dynamic asset protection
 */

#include "assetProtection.h"
#include "secureMemory.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * @brief Simple CRC32 implementation for checksums
 */
static uint32_t crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    
    return ~crc;
}

/**
 * @brief XOR obfuscation with key
 */
static void xor_obfuscate(uint8_t* data, size_t len, const uint8_t* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// ============================================================================
// STATIC ASSET PROTECTION IMPLEMENTATION
// ============================================================================

int create_obfuscated_string(const char* plaintext, ObfuscatedString* obf) {
    if (!plaintext || !obf) return -1;
    
    size_t len = strlen(plaintext);
    if (len >= OBFUSCATED_STRING_MAX_SIZE) return -1;
    
    // Generate random key
    secure_random_bytes(obf->key, 32);
    
    // Copy and obfuscate
    memcpy(obf->data, plaintext, len);
    obf->data[len] = '\0';
    obf->length = len;
    
    // XOR encrypt
    xor_obfuscate(obf->data, len, obf->key, 32);
    
    // Calculate checksum
    uint8_t temp[OBFUSCATED_STRING_MAX_SIZE + 32];
    memcpy(temp, obf->data, len);
    memcpy(temp + len, obf->key, 32);
    obf->checksum = crc32(temp, len + 32);
    
    secure_wipe(temp, sizeof(temp));
    
    return 0;
}

int reveal_obfuscated_string(const ObfuscatedString* obf, char* output, size_t output_size) {
    if (!obf || !output) return -1;
    if (obf->length >= output_size) return -1;
    
    // Verify integrity first
    if (!verify_obfuscated_string(obf)) {
        return -1;  // Tampering detected!
    }
    
    // Copy encrypted data
    memcpy(output, obf->data, obf->length);
    output[obf->length] = '\0';
    
    // XOR decrypt
    xor_obfuscate((uint8_t*)output, obf->length, obf->key, 32);
    
    return 0;
}

int verify_obfuscated_string(const ObfuscatedString* obf) {
    if (!obf) return 0;
    
    uint8_t temp[OBFUSCATED_STRING_MAX_SIZE + 32];
    memcpy(temp, obf->data, obf->length);
    memcpy(temp + obf->length, obf->key, 32);
    
    uint32_t calc_checksum = crc32(temp, obf->length + 32);
    secure_wipe(temp, sizeof(temp));
    
    return (calc_checksum == obf->checksum) ? 1 : 0;
}

int derive_static_key(const char* app_id, 
                      uint32_t version_code,
                      uint64_t build_timestamp,
                      uint8_t* derived_key) {
    if (!app_id || !derived_key) return -1;
    
    // Combine multiple sources
    size_t app_id_len = strlen(app_id);
    size_t total_len = app_id_len + sizeof(version_code) + sizeof(build_timestamp);
    
    uint8_t* combined = (uint8_t*)malloc(total_len);
    if (!combined) return -1;
    
    size_t offset = 0;
    memcpy(combined + offset, app_id, app_id_len);
    offset += app_id_len;
    memcpy(combined + offset, &version_code, sizeof(version_code));
    offset += sizeof(version_code);
    memcpy(combined + offset, &build_timestamp, sizeof(build_timestamp));
    
    // Use PBKDF2-like derivation
    const unsigned char salt[] = "PetCareStaticSalt2024";
    secure_derive_key((const char*)combined, total_len, 
                     salt, sizeof(salt) - 1, 
                     5000, derived_key);
    
    secure_wipe(combined, total_len);
    free(combined);
    
    return 0;
}

int protect_hash_value(const uint8_t* hash, ObfuscatedString* stored) {
    if (!hash || !stored) return -1;
    
    // Convert hash to hex string
    char hex_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_str + (i * 2), "%02x", hash[i]);
    }
    hex_str[64] = '\0';
    
    return create_obfuscated_string(hex_str, stored);
}

int verify_hash_value(const uint8_t* hash, const ObfuscatedString* stored) {
    if (!hash || !stored) return 0;
    
    char revealed[OBFUSCATED_STRING_MAX_SIZE];
    if (reveal_obfuscated_string(stored, revealed, sizeof(revealed)) != 0) {
        return 0;  // Tampered
    }
    
    // Convert input hash to hex
    char hex_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_str + (i * 2), "%02x", hash[i]);
    }
    hex_str[64] = '\0';
    
    int result = (strcmp(revealed, hex_str) == 0) ? 1 : 0;
    
    secure_wipe(revealed, sizeof(revealed));
    secure_wipe(hex_str, sizeof(hex_str));
    
    return result;
}

// ============================================================================
// DYNAMIC ASSET PROTECTION IMPLEMENTATION
// ============================================================================

int generate_device_fingerprint(DeviceFingerprint* fingerprint) {
    if (!fingerprint) return -1;
    
    memset(fingerprint, 0, sizeof(DeviceFingerprint));
    
    // Hardware ID components
    uint8_t hw_components[256];
    size_t hw_offset = 0;
    
#ifdef _WIN32
    // Windows: Use computer name, username, processor info
    char computer_name[256];
    DWORD size = sizeof(computer_name);
    GetComputerNameA(computer_name, &size);
    
    char username[256];
    size = sizeof(username);
    GetUserNameA(username, &size);
    
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    memcpy(hw_components + hw_offset, computer_name, strlen(computer_name));
    hw_offset += strlen(computer_name);
    memcpy(hw_components + hw_offset, &sys_info.dwProcessorType, sizeof(DWORD));
    hw_offset += sizeof(DWORD);
    memcpy(hw_components + hw_offset, &sys_info.dwNumberOfProcessors, sizeof(DWORD));
    hw_offset += sizeof(DWORD);
#else
    // Linux/Unix: Use hostname, uid
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    uid_t uid = getuid();
    pid_t pid = getpid();
    
    memcpy(hw_components + hw_offset, hostname, strlen(hostname));
    hw_offset += strlen(hostname);
    memcpy(hw_components + hw_offset, &uid, sizeof(uid));
    hw_offset += sizeof(uid);
    memcpy(hw_components + hw_offset, &pid, sizeof(pid));
    hw_offset += sizeof(pid);
#endif
    
    // Hash hardware components
    const unsigned char hw_salt[] = "HardwareFingerprintSalt";
    secure_derive_key((const char*)hw_components, hw_offset,
                     hw_salt, sizeof(hw_salt) - 1,
                     1000, fingerprint->hardware_id);
    
    // Software ID components
    uint8_t sw_components[256];
    size_t sw_offset = 0;
    
    const char* app_name = "PetCareApp";
    const char* app_version = "1.0.0";
    
    memcpy(sw_components + sw_offset, app_name, strlen(app_name));
    sw_offset += strlen(app_name);
    memcpy(sw_components + sw_offset, app_version, strlen(app_version));
    sw_offset += strlen(app_version);
    
    // Hash software components
    const unsigned char sw_salt[] = "SoftwareFingerprintSalt";
    secure_derive_key((const char*)sw_components, sw_offset,
                     sw_salt, sizeof(sw_salt) - 1,
                     1000, fingerprint->software_id);
    
    // Combine both
    uint8_t combined[64];
    memcpy(combined, fingerprint->hardware_id, 32);
    memcpy(combined + 32, fingerprint->software_id, 32);
    
    const unsigned char combined_salt[] = "CombinedFingerprintSalt";
    secure_derive_key((const char*)combined, 64,
                     combined_salt, sizeof(combined_salt) - 1,
                     2000, fingerprint->combined_fingerprint);
    
    fingerprint->creation_timestamp = (uint64_t)time(NULL);
    fingerprint->integrity_hash = crc32(fingerprint->combined_fingerprint, 64);
    
    secure_wipe(hw_components, sizeof(hw_components));
    secure_wipe(sw_components, sizeof(sw_components));
    secure_wipe(combined, sizeof(combined));
    
    return 0;
}

int verify_device_fingerprint(const DeviceFingerprint* current, 
                              const DeviceFingerprint* stored) {
    if (!current || !stored) return -1;
    
    // Verify integrity first
    uint32_t calc_hash = crc32(current->combined_fingerprint, 64);
    if (calc_hash != current->integrity_hash) return -1;
    
    calc_hash = crc32(stored->combined_fingerprint, 64);
    if (calc_hash != stored->integrity_hash) return -1;
    
    // Compare fingerprints
    if (memcmp(current->combined_fingerprint, stored->combined_fingerprint, 64) == 0) {
        return 1;  // Match
    }
    
    return 0;  // Different device
}

int create_session(const DeviceFingerprint* fingerprint,
                  uint32_t lifetime_seconds,
                  SessionData* session) {
    if (!fingerprint || !session) return -1;
    
    memset(session, 0, sizeof(SessionData));
    
    // Generate unique session ID
    secure_random_bytes(session->session_id, 32);
    
    // Generate session key
    uint8_t temp_key[32];
    secure_generate_key(temp_key);
    
    // Generate IV
    secure_generate_iv(session->encryption_iv);
    
    // Encrypt session key with device fingerprint
    memcpy(session->session_key, temp_key, 32);
    xor_obfuscate(session->session_key, 32, fingerprint->combined_fingerprint, 64);
    
    // Set timestamps
    session->creation_time = (uint64_t)time(NULL);
    session->expiry_time = session->creation_time + lifetime_seconds;
    session->access_count = 0;
    
    // Hash device fingerprint for binding
    const unsigned char salt[] = "SessionFingerprintBinding";
    secure_derive_key((const char*)fingerprint->combined_fingerprint, 64,
                     salt, sizeof(salt) - 1,
                     1000, session->fingerprint_hash);
    
    // Calculate integrity
    uint8_t integrity_data[sizeof(SessionData) - sizeof(uint32_t)];
    memcpy(integrity_data, session, sizeof(SessionData) - sizeof(uint32_t));
    session->integrity_check = crc32(integrity_data, sizeof(integrity_data));
    
    secure_wipe(temp_key, sizeof(temp_key));
    secure_wipe(integrity_data, sizeof(integrity_data));
    
    return 0;
}

int validate_session(SessionData* session,
                    const DeviceFingerprint* fingerprint,
                    uint8_t* decrypted_key) {
    if (!session || !fingerprint || !decrypted_key) return -1;
    
    // Verify integrity
    uint8_t integrity_data[sizeof(SessionData) - sizeof(uint32_t)];
    memcpy(integrity_data, session, sizeof(SessionData) - sizeof(uint32_t));
    uint32_t calc_integrity = crc32(integrity_data, sizeof(integrity_data));
    secure_wipe(integrity_data, sizeof(integrity_data));
    
    if (calc_integrity != session->integrity_check) {
        return -1;  // Tampered!
    }
    
    // Check expiry
    uint64_t current_time = (uint64_t)time(NULL);
    if (current_time > session->expiry_time) {
        return -1;  // Expired
    }
    
    // Verify device binding
    uint8_t current_fp_hash[32];
    const unsigned char salt[] = "SessionFingerprintBinding";
    secure_derive_key((const char*)fingerprint->combined_fingerprint, 64,
                     salt, sizeof(salt) - 1,
                     1000, current_fp_hash);
    
    if (memcmp(current_fp_hash, session->fingerprint_hash, 32) != 0) {
        secure_wipe(current_fp_hash, sizeof(current_fp_hash));
        return -1;  // Different device
    }
    secure_wipe(current_fp_hash, sizeof(current_fp_hash));
    
    // Decrypt session key
    memcpy(decrypted_key, session->session_key, 32);
    xor_obfuscate(decrypted_key, 32, fingerprint->combined_fingerprint, 64);
    
    // Update access count
    session->access_count++;
    
    // Recalculate integrity
    memcpy(integrity_data, session, sizeof(SessionData) - sizeof(uint32_t));
    session->integrity_check = crc32(integrity_data, sizeof(integrity_data));
    secure_wipe(integrity_data, sizeof(integrity_data));
    
    return 0;
}

void invalidate_session(SessionData* session) {
    if (session) {
        secure_wipe(session, sizeof(SessionData));
    }
}

int generate_dynamic_key(uint64_t seed, uint8_t* dynamic_key) {
    if (!dynamic_key) return -1;
    
    // Combine multiple dynamic sources
    uint8_t sources[128];
    size_t offset = 0;
    
    // Seed
    memcpy(sources + offset, &seed, sizeof(seed));
    offset += sizeof(seed);
    
    // Current time with high precision
    uint64_t current_time = (uint64_t)time(NULL);
    memcpy(sources + offset, &current_time, sizeof(current_time));
    offset += sizeof(current_time);
    
    // Process ID
#ifdef _WIN32
    DWORD pid = GetCurrentProcessId();
    memcpy(sources + offset, &pid, sizeof(pid));
    offset += sizeof(pid);
#else
    pid_t pid = getpid();
    memcpy(sources + offset, &pid, sizeof(pid));
    offset += sizeof(pid);
#endif
    
    // Random entropy
    uint8_t random_bytes[32];
    secure_random_bytes(random_bytes, 32);
    memcpy(sources + offset, random_bytes, 32);
    offset += 32;
    
    // Derive key from all sources
    const unsigned char salt[] = "DynamicKeyGeneration2024";
    secure_derive_key((const char*)sources, offset,
                     salt, sizeof(salt) - 1,
                     3000, dynamic_key);
    
    secure_wipe(sources, sizeof(sources));
    secure_wipe(random_bytes, sizeof(random_bytes));
    
    return 0;
}

int rotate_session_key(SessionData* session, const uint8_t* new_key) {
    if (!session || !new_key) return -1;
    
    // This would require the fingerprint to re-encrypt
    // For now, just update the encrypted key directly
    memcpy(session->session_key, new_key, 32);
    
    // Recalculate integrity
    uint8_t integrity_data[sizeof(SessionData) - sizeof(uint32_t)];
    memcpy(integrity_data, session, sizeof(SessionData) - sizeof(uint32_t));
    session->integrity_check = crc32(integrity_data, sizeof(integrity_data));
    secure_wipe(integrity_data, sizeof(integrity_data));
    
    return 0;
}

// ============================================================================
// ANTI-TAMPERING IMPLEMENTATION
// ============================================================================

int detect_tampering(void) {
#ifdef _WIN32
    // Check for debugger
    if (IsDebuggerPresent()) {
        return 1;  // Debugger detected
    }
    
    // Check for remote debugger
    BOOL remote_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
    if (remote_debugger) {
        return 1;  // Remote debugger detected
    }
#endif
    
    // Additional checks could include:
    // - Timing attacks (execution should be fast)
    // - Memory scanning
    // - Checksum verification
    
    return 0;  // Clean
}

int get_app_integrity_hash(uint8_t* integrity_hash) {
    if (!integrity_hash) return -1;
    
    // This is a simplified version
    // In production, you'd hash the executable file
    
    const char* app_signature = "PetCareApp_v1.0_Release";
    const unsigned char salt[] = "AppIntegrityCheck";
    
    secure_derive_key(app_signature, strlen(app_signature),
                     salt, sizeof(salt) - 1,
                     5000, integrity_hash);
    
    return 0;
}

int verify_app_integrity(const uint8_t* expected_hash) {
    if (!expected_hash) return 0;
    
    uint8_t current_hash[32];
    if (get_app_integrity_hash(current_hash) != 0) {
        return 0;
    }
    
    int result = (memcmp(current_hash, expected_hash, 32) == 0) ? 1 : 0;
    
    secure_wipe(current_hash, sizeof(current_hash));
    
    return result;
}

