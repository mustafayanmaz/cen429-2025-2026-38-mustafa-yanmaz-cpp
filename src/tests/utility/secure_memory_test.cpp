/**
 * @file secure_memory_test.cpp
 * @brief Unit tests for secure memory management functions
 */

#include "gtest/gtest.h"
extern "C" {
#include "secureMemory.h"
}
#include <cstring>
#include <cstdlib>

/**
 * @brief Test fixture for secure memory tests
 */
class SecureMemoryTest : public ::testing::Test {
protected:
    /**
     * @brief Sets up the test fixture
     * Prepares test environment for secure memory operations
     */
    void SetUp() override {
        // Setup code if needed
    }

    /**
     * @brief Tears down the test fixture
     * Cleans up after secure memory tests
     */
    void TearDown() override {
        // Cleanup code if needed
    }
};

/**
 * @brief Test secure_wipe function
 */
TEST_F(SecureMemoryTest, SecureWipeTest) {
    const size_t size = 256;
    char* buffer = (char*)malloc(size);
    ASSERT_NE(buffer, nullptr);
    
    // Fill buffer with known pattern
    for (size_t i = 0; i < size; i++) {
        buffer[i] = 0xAA;
    }
    
    // Verify the pattern
    for (size_t i = 0; i < size; i++) {
        EXPECT_EQ((unsigned char)buffer[i], 0xAA);
    }
    
    // Wipe the buffer
    secure_wipe(buffer, size);
    
    // After wiping, the buffer should be zeroed
    for (size_t i = 0; i < size; i++) {
        EXPECT_EQ((unsigned char)buffer[i], 0x00);
    }
    
    free(buffer);
}

/**
 * @brief Test secure_wipe with NULL pointer (should not crash)
 */
TEST_F(SecureMemoryTest, SecureWipeNullPointerTest) {
    EXPECT_NO_THROW(secure_wipe(nullptr, 100));
}

/**
 * @brief Test secure_wipe with zero size (should not crash)
 */
TEST_F(SecureMemoryTest, SecureWipeZeroSizeTest) {
    char buffer[10];
    EXPECT_NO_THROW(secure_wipe(buffer, 0));
}

/**
 * @brief Test secure_malloc and secure_free
 */
TEST_F(SecureMemoryTest, SecureMallocFreeTest) {
    const size_t size = 512;
    void* ptr = secure_malloc(size);
    
    ASSERT_NE(ptr, nullptr);
    
    // Memory should be initialized to zero
    unsigned char* buf = (unsigned char*)ptr;
    for (size_t i = 0; i < size; i++) {
        EXPECT_EQ(buf[i], 0);
    }
    
    // Write some data
    memset(ptr, 0xBB, size);
    
    // Free securely
    secure_free(ptr, size);
}

/**
 * @brief Test secure_malloc with zero size
 */
TEST_F(SecureMemoryTest, SecureMallocZeroSizeTest) {
    void* ptr = secure_malloc(0);
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @brief Test secure_generate_key
 */
TEST_F(SecureMemoryTest, SecureGenerateKeyTest) {
    unsigned char key1[SECURE_KEY_SIZE];
    unsigned char key2[SECURE_KEY_SIZE];
    
    int result1 = secure_generate_key(key1);
    int result2 = secure_generate_key(key2);
    
    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 0);
    
    // Keys should be different (with very high probability)
    bool different = false;
    for (size_t i = 0; i < SECURE_KEY_SIZE; i++) {
        if (key1[i] != key2[i]) {
            different = true;
            break;
        }
    }
    EXPECT_TRUE(different) << "Generated keys should be different";
}

/**
 * @brief Test secure_generate_key with NULL pointer
 */
TEST_F(SecureMemoryTest, SecureGenerateKeyNullTest) {
    int result = secure_generate_key(nullptr);
    EXPECT_EQ(result, -1);
}

/**
 * @brief Test secure_generate_iv
 */
TEST_F(SecureMemoryTest, SecureGenerateIVTest) {
    unsigned char iv1[SECURE_IV_SIZE];
    unsigned char iv2[SECURE_IV_SIZE];
    
    int result1 = secure_generate_iv(iv1);
    int result2 = secure_generate_iv(iv2);
    
    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 0);
    
    // IVs should be different
    bool different = false;
    for (size_t i = 0; i < SECURE_IV_SIZE; i++) {
        if (iv1[i] != iv2[i]) {
            different = true;
            break;
        }
    }
    EXPECT_TRUE(different) << "Generated IVs should be different";
}

/**
 * @brief Test secure_encrypt_inplace and secure_decrypt_inplace
 */
TEST_F(SecureMemoryTest, EncryptDecryptTest) {
    const char* original = "This is a secret message!";
    size_t len = strlen(original);
    
    unsigned char* data = (unsigned char*)malloc(len + 1);
    strcpy((char*)data, original);
    
    unsigned char key[SECURE_KEY_SIZE];
    unsigned char iv[SECURE_IV_SIZE];
    
    secure_generate_key(key);
    secure_generate_iv(iv);
    
    // Encrypt
    secure_encrypt_inplace(data, len, key, iv);
    
    // After encryption, data should be different
    EXPECT_STRNE((char*)data, original);
    
    // Decrypt
    secure_decrypt_inplace(data, len, key, iv);
    
    // After decryption, should match original
    EXPECT_STREQ((char*)data, original);
    
    secure_wipe(data, len + 1);
    free(data);
}

/**
 * @brief Test encryption with different keys produces different ciphertext
 */
TEST_F(SecureMemoryTest, DifferentKeysProduceDifferentCiphertextTest) {
    const char* original = "Secret data";
    size_t len = strlen(original);
    
    unsigned char* data1 = (unsigned char*)malloc(len + 1);
    unsigned char* data2 = (unsigned char*)malloc(len + 1);
    strcpy((char*)data1, original);
    strcpy((char*)data2, original);
    
    unsigned char key1[SECURE_KEY_SIZE];
    unsigned char key2[SECURE_KEY_SIZE];
    unsigned char iv[SECURE_IV_SIZE];
    
    secure_generate_key(key1);
    secure_generate_key(key2);
    secure_generate_iv(iv);
    
    // Encrypt with different keys
    secure_encrypt_inplace(data1, len, key1, iv);
    secure_encrypt_inplace(data2, len, key2, iv);
    
    // Ciphertexts should be different
    EXPECT_NE(memcmp(data1, data2, len), 0) << "Different keys should produce different ciphertext";
    
    secure_wipe(data1, len + 1);
    secure_wipe(data2, len + 1);
    free(data1);
    free(data2);
}

/**
 * @brief Test secure_derive_key
 */
TEST_F(SecureMemoryTest, SecureDeriveKeyTest) {
    const char* password = "MySecurePassword123";
    const unsigned char salt[] = "randomsalt";
    unsigned char key1[SECURE_KEY_SIZE];
    unsigned char key2[SECURE_KEY_SIZE];
    
    // Derive key with same password and salt
    int result1 = secure_derive_key(password, strlen(password), 
                                     salt, strlen((char*)salt), 
                                     1000, key1);
    int result2 = secure_derive_key(password, strlen(password), 
                                     salt, strlen((char*)salt), 
                                     1000, key2);
    
    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 0);
    
    // Keys should be the same (deterministic)
    EXPECT_EQ(memcmp(key1, key2, SECURE_KEY_SIZE), 0) << "Same password/salt should produce same key";
    
    // Different password should produce different key
    unsigned char key3[SECURE_KEY_SIZE];
    const char* different_password = "DifferentPassword";
    secure_derive_key(different_password, strlen(different_password), 
                     salt, strlen((char*)salt), 
                     1000, key3);
    
    EXPECT_NE(memcmp(key1, key3, SECURE_KEY_SIZE), 0) << "Different password should produce different key";
}

/**
 * @brief Test secure_buffer_create and destroy
 */
TEST_F(SecureMemoryTest, SecureBufferCreateDestroyTest) {
    const size_t size = 1024;
    SecureBuffer* buffer = secure_buffer_create(size);
    
    ASSERT_NE(buffer, nullptr);
    EXPECT_NE(buffer->data, nullptr);
    EXPECT_EQ(buffer->size, size);
    
    secure_buffer_destroy(buffer);
}

/**
 * @brief Test secure_buffer_write and read
 */
TEST_F(SecureMemoryTest, SecureBufferWriteReadTest) {
    const char* test_data = "Sensitive information that needs encryption";
    size_t data_len = strlen(test_data) + 1;
    
    SecureBuffer* buffer = secure_buffer_create(data_len);
    ASSERT_NE(buffer, nullptr);
    
    // Write data
    int write_result = secure_buffer_write(buffer, test_data, data_len);
    EXPECT_EQ(write_result, 0);
    
    // Buffer should be encrypted (different from original)
    EXPECT_NE(memcmp(buffer->data, test_data, data_len), 0) 
        << "Buffer data should be encrypted";
    
    // Read data back
    size_t read_size;
    void* read_data = secure_buffer_read(buffer, &read_size);
    ASSERT_NE(read_data, nullptr);
    EXPECT_EQ(read_size, data_len);
    
    // Read data should match original
    EXPECT_STREQ((char*)read_data, test_data);
    
    secure_free(read_data, read_size);
    secure_buffer_destroy(buffer);
}

/**
 * @brief Test secure_strdup and secure_str_free
 */
TEST_F(SecureMemoryTest, SecureStrdupFreeTest) {
    const char* original = "Test string for duplication";
    
    char* dup = secure_strdup(original);
    ASSERT_NE(dup, nullptr);
    EXPECT_STREQ(dup, original);
    EXPECT_NE(dup, original) << "Should be a different pointer";
    
    secure_str_free(dup);
}

/**
 * @brief Test secure_strdup with NULL
 */
TEST_F(SecureMemoryTest, SecureStrdupNullTest) {
    char* dup = secure_strdup(nullptr);
    EXPECT_EQ(dup, nullptr);
}

/**
 * @brief Test multiple encrypt/decrypt operations
 */
TEST_F(SecureMemoryTest, MultipleEncryptDecryptTest) {
    const char* messages[] = {
        "First message",
        "Second message with more text",
        "Third message!",
        "123456789",
        "Special chars: @#$%^&*()"
    };
    
    unsigned char key[SECURE_KEY_SIZE];
    unsigned char iv[SECURE_IV_SIZE];
    
    secure_generate_key(key);
    secure_generate_iv(iv);
    
    for (const char* msg : messages) {
        size_t len = strlen(msg);
        unsigned char* data = (unsigned char*)malloc(len + 1);
        strcpy((char*)data, msg);
        
        // Encrypt
        secure_encrypt_inplace(data, len, key, iv);
        
        // Should be different
        EXPECT_NE(memcmp(data, msg, len), 0);
        
        // Decrypt
        secure_decrypt_inplace(data, len, key, iv);
        
        // Should match
        EXPECT_STREQ((char*)data, msg);
        
        secure_wipe(data, len + 1);
        free(data);
    }
}

/**
 * @brief Test that encryption is not just XOR with constant
 */
TEST_F(SecureMemoryTest, EncryptionNotSimpleXORTest) {
    const char* msg = "AAAAAAAAAAAAAAAA"; // Repeating pattern
    size_t len = strlen(msg);
    
    unsigned char* data = (unsigned char*)malloc(len + 1);
    strcpy((char*)data, msg);
    
    unsigned char key[SECURE_KEY_SIZE];
    unsigned char iv[SECURE_IV_SIZE];
    
    secure_generate_key(key);
    secure_generate_iv(iv);
    
    secure_encrypt_inplace(data, len, key, iv);
    
    // Check that encrypted data is not a simple repeating pattern
    // (which would indicate simple XOR encryption)
    bool has_variation = false;
    for (size_t i = 1; i < len; i++) {
        if (data[i] != data[0]) {
            has_variation = true;
            break;
        }
    }
    
    EXPECT_TRUE(has_variation) << "Encryption should not produce simple patterns";
    
    secure_wipe(data, len + 1);
    free(data);
}

/**
 * @brief Test secure_buffer with zero size
 */
TEST_F(SecureMemoryTest, SecureBufferZeroSizeTest) {
    SecureBuffer* buffer = secure_buffer_create(0);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @brief Test secure_buffer_write with oversized data
 */
TEST_F(SecureMemoryTest, SecureBufferWriteOversizeTest) {
    const size_t buffer_size = 10;
    const char* large_data = "This is a very long string that exceeds the buffer size";
    
    SecureBuffer* buffer = secure_buffer_create(buffer_size);
    ASSERT_NE(buffer, nullptr);
    
    // Writing oversized data should fail
    int result = secure_buffer_write(buffer, large_data, strlen(large_data));
    EXPECT_EQ(result, -1);
    
    secure_buffer_destroy(buffer);
}

/**
 * @brief Memory leak test - allocate and free many times
 */
TEST_F(SecureMemoryTest, NoMemoryLeakTest) {
    const int iterations = 1000;
    const size_t size = 256;
    
    for (int i = 0; i < iterations; i++) {
        void* ptr = secure_malloc(size);
        ASSERT_NE(ptr, nullptr);
        
        memset(ptr, i % 256, size);
        
        secure_free(ptr, size);
    }
}

/**
 * @brief Test that wipe actually changes memory (not optimized away)
 */
TEST_F(SecureMemoryTest, WipeNotOptimizedAwayTest) {
    const size_t size = 128;
    volatile unsigned char* buffer = (volatile unsigned char*)malloc(size);
    
    // Fill with pattern
    for (size_t i = 0; i < size; i++) {
        buffer[i] = 0xFF;
    }
    
    // Verify pattern
    for (size_t i = 0; i < size; i++) {
        EXPECT_EQ(buffer[i], 0xFF);
    }
    
    // Wipe
    secure_wipe((void*)buffer, size);
    
    // Verify wiped
    for (size_t i = 0; i < size; i++) {
        EXPECT_EQ(buffer[i], 0x00);
    }
    
    free((void*)buffer);
}

