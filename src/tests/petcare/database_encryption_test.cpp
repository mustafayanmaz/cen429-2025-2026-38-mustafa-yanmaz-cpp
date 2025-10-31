/**
 * @file database_encryption_test.cpp
 * @brief Unit tests for database encryption key obfuscation integration
 */

#include "gtest/gtest.h"
extern "C" {
#include "database.h"
#include "assetProtection.h"
#include "secureMemory.h"
}
#include <cstring>
#include <cstdio>

/**
 * @brief Test fixture for database encryption tests
 */
class DatabaseEncryptionTest : public ::testing::Test {
protected:
    const char* test_db_path = "test_encryption.db";
    
    void SetUp() override {
        // Clean up any existing test database
        remove(test_db_path);
    }
    
    void TearDown() override {
        // Clean up test database
        close_petcare_database();
        remove(test_db_path);
    }
};

/**
 * @brief Test database encryption key is properly obfuscated
 */
TEST_F(DatabaseEncryptionTest, EncryptionKeyObfuscation) {
    // The database module should use an obfuscated key internally
    // We test this by ensuring the database initializes successfully
    // which requires the obfuscated key to be revealed correctly
    
    int result = init_petcare_database(test_db_path);
    
#ifdef SQLITE3_HEADER_ONLY
    EXPECT_NE(result, 0) << "Should fail when SQLite is not available";
#else
    EXPECT_EQ(result, 0) << "Database should initialize with obfuscated key";
    
    Database* db = get_petcare_database();
    EXPECT_NE(db, nullptr) << "Database handle should be valid";
#endif
}

/**
 * @brief Test database operations work with obfuscated key
 */
TEST_F(DatabaseEncryptionTest, DatabaseOperationsWithObfuscatedKey) {
    int result = init_petcare_database(test_db_path);
    
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_EQ(result, 0) << "Database initialization should succeed";
    
    Database* db = get_petcare_database();
    ASSERT_NE(db, nullptr);
    
    // Test basic database operations
    result = db_add_user(db, "test_user", "encrypted_password");
    EXPECT_EQ(result, 0) << "Should add user with encrypted database";
    
    // Verify user was added
    int exists = db_user_exists(db, "test_user");
    EXPECT_EQ(exists, 1) << "User should exist in encrypted database";
    
    // Test adding pet
    result = db_add_pet(db, "TestPet", "Dog", 3, "test_user");
    EXPECT_EQ(result, 0) << "Should add pet to encrypted database";
    
    // Verify pet count
    int count = db_count_user_pets(db, "test_user");
    EXPECT_EQ(count, 1) << "Should have 1 pet in encrypted database";
#endif
}

/**
 * @brief Test multiple database connections with same obfuscated key
 */
TEST_F(DatabaseEncryptionTest, MultipleConnectionsWithSameKey) {
    // Initialize database
    int result1 = init_petcare_database(test_db_path);
    
#ifndef SQLITE3_HEADER_ONLY
    ASSERT_EQ(result1, 0);
    
    Database* db1 = get_petcare_database();
    ASSERT_NE(db1, nullptr);
    
    // Add data
    db_add_user(db1, "user1", "pass1");
    
    // Close and reopen (simulating app restart)
    close_petcare_database();
    
    int result2 = init_petcare_database(test_db_path);
    ASSERT_EQ(result2, 0) << "Should reopen database with same obfuscated key";
    
    Database* db2 = get_petcare_database();
    ASSERT_NE(db2, nullptr);
    
    // Verify data persists
    int exists = db_user_exists(db2, "user1");
    EXPECT_EQ(exists, 1) << "User should persist across connections";
#endif
}

/**
 * @brief Test key revelation and secure wiping
 */
TEST_F(DatabaseEncryptionTest, KeyRevelationAndWiping) {
    // Create an obfuscated key similar to database module
    const char* test_key = "TestDatabaseKey123!@#";
    ObfuscatedString obf_key;
    
    ASSERT_EQ(create_obfuscated_string(test_key, &obf_key), 0);
    
    // Reveal key (simulating database initialization)
    char revealed[256];
    ASSERT_EQ(reveal_obfuscated_string(&obf_key, revealed, sizeof(revealed)), 0);
    EXPECT_STREQ(revealed, test_key);
    
    // Secure wipe after use
    secure_wipe(revealed, sizeof(revealed));
    
    // Verify wipe
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(revealed); i++) {
        if (revealed[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    EXPECT_EQ(all_zero, 1) << "Revealed key should be wiped";
}

/**
 * @brief Test database initialization with tampered obfuscated key
 */
TEST_F(DatabaseEncryptionTest, TamperedKeyDetection) {
    // This test verifies that tampering with the obfuscated key
    // would be detected during revelation
    
    const char* original_key = "OriginalKey123";
    ObfuscatedString obf_key;
    
    ASSERT_EQ(create_obfuscated_string(original_key, &obf_key), 0);
    
    // Tamper with the obfuscated data
    obf_key.data[0] ^= 0xFF;
    
    // Attempt to reveal should fail
    char revealed[256];
    EXPECT_NE(reveal_obfuscated_string(&obf_key, revealed, sizeof(revealed)), 0)
        << "Tampering should be detected";
}

/**
 * @brief Test obfuscated key persistence across function calls
 */
TEST_F(DatabaseEncryptionTest, ObfuscatedKeyPersistence) {
    // Initialize database multiple times (simulating restart)
    for (int i = 0; i < 3; i++) {
        int result = init_petcare_database(test_db_path);
        
#ifndef SQLITE3_HEADER_ONLY
        EXPECT_EQ(result, 0) << "Iteration " << i << " should initialize successfully";
        
        Database* db = get_petcare_database();
        EXPECT_NE(db, nullptr) << "Iteration " << i << " should have valid handle";
        
        close_petcare_database();
#endif
    }
}

/**
 * @brief Test encryption key is not exposed in memory dumps
 */
TEST_F(DatabaseEncryptionTest, KeyNotExposedInMemory) {
    const char* plaintext_key = "ExposedKey123!@#$";
    ObfuscatedString obf_key;
    
    ASSERT_EQ(create_obfuscated_string(plaintext_key, &obf_key), 0);
    
    // Verify the key is not stored in plaintext
    const uint8_t* obf_data = obf_key.data;
    size_t obf_len = obf_key.length;
    
    // Search for plaintext key pattern in obfuscated data
    bool found_plaintext = false;
    for (size_t i = 0; i + strlen(plaintext_key) <= obf_len; i++) {
        if (memcmp(obf_data + i, plaintext_key, strlen(plaintext_key)) == 0) {
            found_plaintext = true;
            break;
        }
    }
    
    EXPECT_FALSE(found_plaintext) << "Plaintext key should not be found in obfuscated data";
}

// Run all tests
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

