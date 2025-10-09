/**
 * @file asset_protection_test.cpp
 * @brief Unit tests for static and dynamic asset protection
 */

#include "gtest/gtest.h"
extern "C" {
#include "assetProtection.h"
#include "secureMemory.h"
}
#include <cstring>
#include <cstdlib>

/**
 * @brief Test fixture for asset protection tests
 */
class AssetProtectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }
};

// ============================================================================
// STATIC ASSET PROTECTION TESTS
// ============================================================================

/**
 * @brief Test obfuscated string creation and reveal
 */
TEST_F(AssetProtectionTest, ObfuscatedString_CreateAndReveal) {
    const char* secret = "MySecretAPIKey12345";
    ObfuscatedString obf;
    
    // Create obfuscated string
    ASSERT_EQ(create_obfuscated_string(secret, &obf), 0);
    
    // Verify it's obfuscated (not plaintext)
    EXPECT_NE(memcmp(obf.data, secret, strlen(secret)), 0);
    
    // Reveal and verify
    char revealed[256];
    ASSERT_EQ(reveal_obfuscated_string(&obf, revealed, sizeof(revealed)), 0);
    EXPECT_STREQ(revealed, secret);
    
    // Clean up
    secure_wipe(revealed, sizeof(revealed));
}

/**
 * @brief Test obfuscated string integrity verification
 */
TEST_F(AssetProtectionTest, ObfuscatedString_IntegrityCheck) {
    const char* secret = "SecretPassword123";
    ObfuscatedString obf;
    
    ASSERT_EQ(create_obfuscated_string(secret, &obf), 0);
    
    // Verify integrity
    EXPECT_EQ(verify_obfuscated_string(&obf), 1);
    
    // Tamper with data
    obf.data[0] ^= 0xFF;
    EXPECT_EQ(verify_obfuscated_string(&obf), 0);
}

/**
 * @brief Test tamper detection in obfuscated string
 */
TEST_F(AssetProtectionTest, ObfuscatedString_TamperDetection) {
    const char* secret = "TamperTestSecret";
    ObfuscatedString obf;
    
    ASSERT_EQ(create_obfuscated_string(secret, &obf), 0);
    
    // Tamper with checksum
    obf.checksum ^= 0x12345678;
    
    // Attempt to reveal should fail
    char revealed[256];
    EXPECT_NE(reveal_obfuscated_string(&obf, revealed, sizeof(revealed)), 0);
}

/**
 * @brief Test static key derivation
 */
TEST_F(AssetProtectionTest, StaticKey_Derivation) {
    const char* app_id = "com.petcare.app";
    uint32_t version = 100;
    uint64_t timestamp = 1234567890;
    
    uint8_t key1[32];
    uint8_t key2[32];
    
    // Derive same key twice
    ASSERT_EQ(derive_static_key(app_id, version, timestamp, key1), 0);
    ASSERT_EQ(derive_static_key(app_id, version, timestamp, key2), 0);
    
    // Should be deterministic
    EXPECT_EQ(memcmp(key1, key2, 32), 0);
    
    // Different version should produce different key
    uint8_t key3[32];
    ASSERT_EQ(derive_static_key(app_id, version + 1, timestamp, key3), 0);
    EXPECT_NE(memcmp(key1, key3, 32), 0);
    
    secure_wipe(key1, sizeof(key1));
    secure_wipe(key2, sizeof(key2));
    secure_wipe(key3, sizeof(key3));
}

/**
 * @brief Test hash value protection
 */
TEST_F(AssetProtectionTest, HashValue_ProtectionAndVerification) {
    uint8_t hash[32];
    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)i;
    }
    
    ObfuscatedString protected_hash;
    ASSERT_EQ(protect_hash_value(hash, &protected_hash), 0);
    
    // Verify correct hash
    EXPECT_EQ(verify_hash_value(hash, &protected_hash), 1);
    
    // Verify incorrect hash
    hash[0] ^= 0xFF;
    EXPECT_EQ(verify_hash_value(hash, &protected_hash), 0);
}

// ============================================================================
// DYNAMIC ASSET PROTECTION TESTS
// ============================================================================

/**
 * @brief Test device fingerprint generation
 */
TEST_F(AssetProtectionTest, DeviceFingerprint_Generation) {
    DeviceFingerprint fp1, fp2;
    
    // Generate fingerprints
    ASSERT_EQ(generate_device_fingerprint(&fp1), 0);
    ASSERT_EQ(generate_device_fingerprint(&fp2), 0);
    
    // Should be consistent on same device
    EXPECT_EQ(memcmp(fp1.combined_fingerprint, fp2.combined_fingerprint, 64), 0);
    
    // Verify fingerprints match
    EXPECT_EQ(verify_device_fingerprint(&fp1, &fp2), 1);
}

/**
 * @brief Test device fingerprint verification
 */
TEST_F(AssetProtectionTest, DeviceFingerprint_Verification) {
    DeviceFingerprint fp1, fp2;
    
    ASSERT_EQ(generate_device_fingerprint(&fp1), 0);
    ASSERT_EQ(generate_device_fingerprint(&fp2), 0);
    
    // Should match
    EXPECT_EQ(verify_device_fingerprint(&fp1, &fp2), 1);
    
    // Tamper with fingerprint
    fp2.combined_fingerprint[0] ^= 0xFF;
    fp2.integrity_hash = 0;  // Invalid integrity
    
    // Should fail verification
    EXPECT_NE(verify_device_fingerprint(&fp1, &fp2), 1);
}

/**
 * @brief Test session creation and validation
 */
TEST_F(AssetProtectionTest, Session_CreateAndValidate) {
    DeviceFingerprint fp;
    ASSERT_EQ(generate_device_fingerprint(&fp), 0);
    
    SessionData session;
    ASSERT_EQ(create_session(&fp, 3600, &session), 0);  // 1 hour
    
    // Validate session
    uint8_t decrypted_key[32];
    ASSERT_EQ(validate_session(&session, &fp, decrypted_key), 0);
    
    // Access count should increment
    EXPECT_EQ(session.access_count, 1);
    
    secure_wipe(decrypted_key, sizeof(decrypted_key));
    invalidate_session(&session);
}

/**
 * @brief Test session device binding
 */
TEST_F(AssetProtectionTest, Session_DeviceBinding) {
    DeviceFingerprint fp1, fp2;
    ASSERT_EQ(generate_device_fingerprint(&fp1), 0);
    
    // Create different fingerprint by tampering
    memcpy(&fp2, &fp1, sizeof(DeviceFingerprint));
    fp2.combined_fingerprint[0] ^= 0xFF;  // Simulate different device
    
    // Create session with fp1
    SessionData session;
    ASSERT_EQ(create_session(&fp1, 3600, &session), 0);
    
    // Try to validate with fp1 - should succeed
    uint8_t key1[32];
    EXPECT_EQ(validate_session(&session, &fp1, key1), 0);
    
    // Try to validate with fp2 - should fail (different device)
    uint8_t key2[32];
    EXPECT_NE(validate_session(&session, &fp2, key2), 0);
    
    secure_wipe(key1, sizeof(key1));
    secure_wipe(key2, sizeof(key2));
    invalidate_session(&session);
}

/**
 * @brief Test session expiry
 */
TEST_F(AssetProtectionTest, Session_Expiry) {
    DeviceFingerprint fp;
    ASSERT_EQ(generate_device_fingerprint(&fp), 0);
    
    SessionData session;
    ASSERT_EQ(create_session(&fp, 0, &session), 0);  // Already expired
    
    // Should fail validation due to expiry
    uint8_t key[32];
    // Note: This might pass if system clock is very fast, so we manually set expiry
    session.expiry_time = session.creation_time - 1;
    
    EXPECT_NE(validate_session(&session, &fp, key), 0);
    
    invalidate_session(&session);
}

/**
 * @brief Test session tampering detection
 */
TEST_F(AssetProtectionTest, Session_TamperingDetection) {
    DeviceFingerprint fp;
    ASSERT_EQ(generate_device_fingerprint(&fp), 0);
    
    SessionData session;
    ASSERT_EQ(create_session(&fp, 3600, &session), 0);
    
    // Tamper with session data
    session.session_id[0] ^= 0xFF;
    
    // Validation should fail
    uint8_t key[32];
    EXPECT_NE(validate_session(&session, &fp, key), 0);
    
    invalidate_session(&session);
}

/**
 * @brief Test dynamic key generation
 */
TEST_F(AssetProtectionTest, DynamicKey_Generation) {
    uint8_t key1[32], key2[32];
    
    // Generate with same seed
    ASSERT_EQ(generate_dynamic_key(12345, key1), 0);
    ASSERT_EQ(generate_dynamic_key(12345, key2), 0);
    
    // Should be different due to time/entropy
    EXPECT_NE(memcmp(key1, key2, 32), 0);
    
    // Generate with different seed
    uint8_t key3[32];
    ASSERT_EQ(generate_dynamic_key(67890, key3), 0);
    EXPECT_NE(memcmp(key1, key3, 32), 0);
    
    secure_wipe(key1, sizeof(key1));
    secure_wipe(key2, sizeof(key2));
    secure_wipe(key3, sizeof(key3));
}

/**
 * @brief Test session key rotation
 */
TEST_F(AssetProtectionTest, Session_KeyRotation) {
    DeviceFingerprint fp;
    ASSERT_EQ(generate_device_fingerprint(&fp), 0);
    
    SessionData session;
    ASSERT_EQ(create_session(&fp, 3600, &session), 0);
    
    // Save original session key
    uint8_t original_key[32];
    memcpy(original_key, session.session_key, 32);
    
    // Rotate key
    uint8_t new_key[32];
    secure_random_bytes(new_key, 32);
    ASSERT_EQ(rotate_session_key(&session, new_key), 0);
    
    // Key should be different
    EXPECT_NE(memcmp(original_key, session.session_key, 32), 0);
    
    secure_wipe(original_key, sizeof(original_key));
    secure_wipe(new_key, sizeof(new_key));
    invalidate_session(&session);
}

// ============================================================================
// ANTI-TAMPERING TESTS
// ============================================================================

/**
 * @brief Test tampering detection
 */
TEST_F(AssetProtectionTest, AntiTampering_Detection) {
    int result = detect_tampering();
    
    // In normal execution, should return 0 (clean)
    // In debugging, might return 1
    EXPECT_GE(result, 0);
    EXPECT_LE(result, 2);
}

/**
 * @brief Test application integrity hash
 */
TEST_F(AssetProtectionTest, AppIntegrity_HashGeneration) {
    uint8_t hash1[32], hash2[32];
    
    ASSERT_EQ(get_app_integrity_hash(hash1), 0);
    ASSERT_EQ(get_app_integrity_hash(hash2), 0);
    
    // Should be deterministic
    EXPECT_EQ(memcmp(hash1, hash2, 32), 0);
    
    secure_wipe(hash1, sizeof(hash1));
    secure_wipe(hash2, sizeof(hash2));
}

/**
 * @brief Test application integrity verification
 */
TEST_F(AssetProtectionTest, AppIntegrity_Verification) {
    uint8_t expected_hash[32];
    ASSERT_EQ(get_app_integrity_hash(expected_hash), 0);
    
    // Should verify successfully
    EXPECT_EQ(verify_app_integrity(expected_hash), 1);
    
    // Tamper with hash
    expected_hash[0] ^= 0xFF;
    EXPECT_EQ(verify_app_integrity(expected_hash), 0);
}

/**
 * @brief Test obfuscated string with special characters
 */
TEST_F(AssetProtectionTest, ObfuscatedString_SpecialCharacters) {
    const char* secret = "Special!@#$%^&*()_+-=[]{}|;:',.<>?/~`\n\t";
    ObfuscatedString obf;
    
    ASSERT_EQ(create_obfuscated_string(secret, &obf), 0);
    
    char revealed[256];
    ASSERT_EQ(reveal_obfuscated_string(&obf, revealed, sizeof(revealed)), 0);
    EXPECT_STREQ(revealed, secret);
    
    secure_wipe(revealed, sizeof(revealed));
}

/**
 * @brief Test session invalidation
 */
TEST_F(AssetProtectionTest, Session_Invalidation) {
    DeviceFingerprint fp;
    ASSERT_EQ(generate_device_fingerprint(&fp), 0);
    
    SessionData session;
    ASSERT_EQ(create_session(&fp, 3600, &session), 0);
    
    // Invalidate session
    invalidate_session(&session);
    
    // All data should be wiped
    uint8_t zero_check[sizeof(SessionData)];
    memset(zero_check, 0, sizeof(zero_check));
    EXPECT_EQ(memcmp(&session, zero_check, sizeof(SessionData)), 0);
}

