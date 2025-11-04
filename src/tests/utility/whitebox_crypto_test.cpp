/**
 * @file whitebox_crypto_test.cpp
 * @brief Unit tests for whitebox cryptography and file encryption
 */

#include "gtest/gtest.h"
extern "C" {
#include "whiteboxCrypto.h"
#include "secureMemory.h"
}
#include <cstring>
#include <cstdlib>
#include <cstdio>

/**
 * @brief Test fixture for whitebox crypto tests
 */
class WhiteboxCryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup test files
    }

    void TearDown() override {
        // Cleanup test files
        remove("test_plain.txt");
        remove("test_encrypted.dat");
        remove("test_decrypted.txt");
    }
};

/**
 * @brief Test AES initialization
 */
TEST_F(WhiteboxCryptoTest, AES_InitTest) {
    WB_AES_Context ctx;
    uint8_t key[WB_AES_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    int result = wb_aes_init(&ctx, key);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.is_initialized, 1);
    
    wb_aes_cleanup(&ctx);
}

/**
 * @brief Test AES encrypt/decrypt block
 */
TEST_F(WhiteboxCryptoTest, AES_EncryptDecryptBlockTest) {
    WB_AES_Context ctx;
    uint8_t key[WB_AES_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[WB_AES_BLOCK_SIZE] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t ciphertext[WB_AES_BLOCK_SIZE];
    uint8_t decrypted[WB_AES_BLOCK_SIZE];
    
    ASSERT_EQ(wb_aes_init(&ctx, key), 0);
    
    // Encrypt
    ASSERT_EQ(wb_aes_encrypt_block(&ctx, plaintext, ciphertext), 0);
    
    // Ciphertext should be different from plaintext
    EXPECT_NE(memcmp(plaintext, ciphertext, WB_AES_BLOCK_SIZE), 0);
    
    // Decrypt
    ASSERT_EQ(wb_aes_decrypt_block(&ctx, ciphertext, decrypted), 0);
    
    // Decrypted should match original plaintext
    EXPECT_EQ(memcmp(plaintext, decrypted, WB_AES_BLOCK_SIZE), 0);
    
    wb_aes_cleanup(&ctx);
}

/**
 * @brief Test AES-CBC mode encryption/decryption
 */
TEST_F(WhiteboxCryptoTest, AES_CBC_Test) {
    WB_AES_Context ctx;
    uint8_t key[WB_AES_KEY_SIZE];
    uint8_t iv[WB_AES_BLOCK_SIZE];
    
    // Generate full key and copy only needed bytes
    uint8_t temp_key[SECURE_KEY_SIZE];
    secure_generate_key(temp_key);
    memcpy(key, temp_key, WB_AES_KEY_SIZE);
    secure_wipe(temp_key, SECURE_KEY_SIZE);
    secure_generate_iv(iv);
    
    const char* message = "This is a test message for AES-CBC encryption!";
    size_t msg_len = strlen(message);
    
    uint8_t* ciphertext = (uint8_t*)malloc(msg_len + WB_AES_BLOCK_SIZE * 2);
    uint8_t* decrypted = (uint8_t*)malloc(msg_len + WB_AES_BLOCK_SIZE * 2);
    
    ASSERT_EQ(wb_aes_init(&ctx, key), 0);
    
    // Encrypt
    int cipher_len = wb_aes_encrypt_cbc(&ctx, (const uint8_t*)message, msg_len, ciphertext, iv);
    ASSERT_GT(cipher_len, 0);
    EXPECT_GE((size_t)cipher_len, msg_len);
    
    // Decrypt
    int plain_len = wb_aes_decrypt_cbc(&ctx, ciphertext, cipher_len, decrypted, iv);
    ASSERT_GT(plain_len, 0);
    EXPECT_EQ((size_t)plain_len, msg_len);
    
    // Verify decrypted matches original
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
    
    wb_aes_cleanup(&ctx);
    secure_free(ciphertext, msg_len + WB_AES_BLOCK_SIZE * 2);
    secure_free(decrypted, msg_len + WB_AES_BLOCK_SIZE * 2);
}

/**
 * @brief Test DES initialization
 */
TEST_F(WhiteboxCryptoTest, DES_InitTest) {
    WB_DES_Context ctx;
    uint8_t key[WB_DES_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    int result = wb_des_init(&ctx, key);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.is_initialized, 1);
    
    wb_des_cleanup(&ctx);
}

/**
 * @brief Test DES encrypt/decrypt block
 */
TEST_F(WhiteboxCryptoTest, DES_EncryptDecryptBlockTest) {
    WB_DES_Context ctx;
    uint8_t key[WB_DES_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    
    uint8_t plaintext[WB_DES_BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t ciphertext[WB_DES_BLOCK_SIZE];
    uint8_t decrypted[WB_DES_BLOCK_SIZE];
    
    ASSERT_EQ(wb_des_init(&ctx, key), 0);
    
    // Encrypt
    ASSERT_EQ(wb_des_encrypt_block(&ctx, plaintext, ciphertext), 0);
    
    // Ciphertext should be different
    EXPECT_NE(memcmp(plaintext, ciphertext, WB_DES_BLOCK_SIZE), 0);
    
    // Decrypt
    ASSERT_EQ(wb_des_decrypt_block(&ctx, ciphertext, decrypted), 0);
    
    // Should match original
    EXPECT_EQ(memcmp(plaintext, decrypted, WB_DES_BLOCK_SIZE), 0);
    
    wb_des_cleanup(&ctx);
}

/**
 * @brief Test cascaded encryption initialization
 */
TEST_F(WhiteboxCryptoTest, Cascade_InitTest) {
    WB_Cascade_Context ctx;
    uint8_t aes_key1[WB_AES_KEY_SIZE];
    uint8_t des_key[WB_DES_KEY_SIZE];
    uint8_t aes_key2[WB_AES_KEY_SIZE];
    
    // Generate full keys and copy only needed bytes
    uint8_t temp_key1[SECURE_KEY_SIZE];
    uint8_t temp_key2[SECURE_KEY_SIZE];
    secure_generate_key(temp_key1);
    secure_generate_key(temp_key2);
    memcpy(aes_key1, temp_key1, WB_AES_KEY_SIZE);
    memcpy(aes_key2, temp_key2, WB_AES_KEY_SIZE);
    memcpy(des_key, aes_key1, WB_DES_KEY_SIZE);
    secure_wipe(temp_key1, SECURE_KEY_SIZE);
    secure_wipe(temp_key2, SECURE_KEY_SIZE);
    
    int result = wb_cascade_init(&ctx, aes_key1, des_key, aes_key2);
    EXPECT_EQ(result, 0);
    
    wb_cascade_cleanup(&ctx);
}

/**
 * @brief Test cascaded encryption/decryption
 */
TEST_F(WhiteboxCryptoTest, Cascade_EncryptDecryptTest) {
    WB_Cascade_Context ctx;
    uint8_t aes_key1[WB_AES_KEY_SIZE];
    uint8_t des_key[WB_DES_KEY_SIZE];
    uint8_t aes_key2[WB_AES_KEY_SIZE];
    uint8_t iv[WB_AES_BLOCK_SIZE];
    
    // Generate full keys and copy only needed bytes
    uint8_t temp_key1[SECURE_KEY_SIZE];
    uint8_t temp_key2[SECURE_KEY_SIZE];
    secure_generate_key(temp_key1);
    secure_generate_key(temp_key2);
    memcpy(aes_key1, temp_key1, WB_AES_KEY_SIZE);
    memcpy(aes_key2, temp_key2, WB_AES_KEY_SIZE);
    secure_generate_iv(iv);
    memcpy(des_key, aes_key1, WB_DES_KEY_SIZE);
    secure_wipe(temp_key1, SECURE_KEY_SIZE);
    secure_wipe(temp_key2, SECURE_KEY_SIZE);
    
    ASSERT_EQ(wb_cascade_init(&ctx, aes_key1, des_key, aes_key2), 0);
    
    const char* message = "Cascaded encryption test with AES->DES->AES layers!";
    size_t msg_len = strlen(message);
    
    uint8_t* ciphertext = (uint8_t*)secure_malloc(msg_len + WB_AES_BLOCK_SIZE * 3);
    uint8_t* decrypted = (uint8_t*)secure_malloc(msg_len + WB_AES_BLOCK_SIZE * 3);
    
    // Encrypt
    int cipher_len = wb_cascade_encrypt(&ctx, (const uint8_t*)message, msg_len, ciphertext, iv);
    ASSERT_GT(cipher_len, 0);
    
    // Decrypt
    int plain_len = wb_cascade_decrypt(&ctx, ciphertext, cipher_len, decrypted, iv);
    ASSERT_GT(plain_len, 0);
    EXPECT_EQ((size_t)plain_len, msg_len);
    
    // Verify
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
    
    wb_cascade_cleanup(&ctx);
    secure_free(ciphertext, msg_len + WB_AES_BLOCK_SIZE * 3);
    secure_free(decrypted, msg_len + WB_AES_BLOCK_SIZE * 3);
}

/**
 * @brief Test file encryption/decryption
 */
TEST_F(WhiteboxCryptoTest, File_EncryptDecryptTest) {
    // Create test file
    const char* test_data = "This is sensitive data that needs to be encrypted!\n"
                           "It contains multiple lines and special characters: @#$%^&*()";
    
    FILE* f = fopen("test_plain.txt", "w");
    ASSERT_NE(f, nullptr);
    fputs(test_data, f);
    fclose(f);
    
    const char* password = "SecurePassword123!";
    
    // Encrypt file
    int result = wb_encrypt_file("test_plain.txt", "test_encrypted.dat", 
                                 password, strlen(password));
    EXPECT_EQ(result, 0);
    
    // Verify encrypted file exists
    f = fopen("test_encrypted.dat", "rb");
    ASSERT_NE(f, nullptr);
    fclose(f);
    
    // Decrypt file
    result = wb_decrypt_file("test_encrypted.dat", "test_decrypted.txt",
                             password, strlen(password));
    EXPECT_EQ(result, 0);
    
    // Read decrypted file
    f = fopen("test_decrypted.txt", "r");
    ASSERT_NE(f, nullptr);
    
    char buffer[1024];
    size_t len = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    
    // Verify decrypted matches original
    EXPECT_EQ(strlen(test_data), len);
    EXPECT_EQ(memcmp(test_data, buffer, len), 0);
}

/**
 * @brief Test wrong password for decryption
 */
TEST_F(WhiteboxCryptoTest, File_WrongPasswordTest) {
    const char* test_data = "Secret message";
    
    FILE* f = fopen("test_plain.txt", "w");
    ASSERT_NE(f, nullptr);
    fputs(test_data, f);
    fclose(f);
    
    const char* password = "CorrectPassword";
    const char* wrong_password = "WrongPassword";
    
    // Encrypt
    ASSERT_EQ(wb_encrypt_file("test_plain.txt", "test_encrypted.dat",
                              password, strlen(password)), 0);
    
    // Try to decrypt with wrong password
    int result = wb_decrypt_file("test_encrypted.dat", "test_decrypted.txt",
                                wrong_password, strlen(wrong_password));
    
    // Should succeed but produce garbage
    // (In real implementation, HMAC would catch this)
    if (result == 0) {
        f = fopen("test_decrypted.txt", "r");
        if (f) {
            char buffer[1024];
            size_t len = fread(buffer, 1, sizeof(buffer), f);
            fclose(f);
            
            // Decrypted data should NOT match original
            EXPECT_NE(memcmp(test_data, buffer, strlen(test_data)), 0);
        }
    }
}

/**
 * @brief Test buffer encryption/decryption
 */
TEST_F(WhiteboxCryptoTest, Buffer_EncryptDecryptTest) {
    const char* message = "Buffer encryption test message";
    const char* password = "TestPassword123";
    
    size_t cipher_len;
    uint8_t* encrypted = wb_encrypt_buffer((const uint8_t*)message, strlen(message),
                                          password, strlen(password), &cipher_len);
    
    ASSERT_NE(encrypted, nullptr);
    EXPECT_GT(cipher_len, strlen(message));
    
    size_t plain_len;
    uint8_t* decrypted = wb_decrypt_buffer(encrypted, cipher_len,
                                          password, strlen(password), &plain_len);
    
    ASSERT_NE(decrypted, nullptr);
    EXPECT_EQ(plain_len, strlen(message));
    
    EXPECT_EQ(memcmp(message, decrypted, plain_len), 0);
    
    secure_free(encrypted, cipher_len);
    secure_free(decrypted, plain_len);
}

/**
 * @brief Test file integrity verification
 */
TEST_F(WhiteboxCryptoTest, File_IntegrityVerificationTest) {
    const char* test_data = "Data for integrity test";
    const char* password = "TestPassword";
    
    FILE* f = fopen("test_plain.txt", "w");
    ASSERT_NE(f, nullptr);
    fputs(test_data, f);
    fclose(f);
    
    ASSERT_EQ(wb_encrypt_file("test_plain.txt", "test_encrypted.dat",
                              password, strlen(password)), 0);
    
    // Verify file integrity
    int valid = wb_verify_file_integrity("test_encrypted.dat", password, strlen(password));
    EXPECT_EQ(valid, 1);
    
    // Test with non-encrypted file
    valid = wb_verify_file_integrity("test_plain.txt", password, strlen(password));
    EXPECT_NE(valid, 1);
}

TEST_F(WhiteboxCryptoTest, DecryptFailsOnTamperedHmac) {
    const char* password = "P@ssw0rd!";
    // Prepare plain file
    FILE* fp = fopen("tamper_plain.txt", "wb");
    ASSERT_TRUE(fp != nullptr);
    fputs("Secret payload for HMAC tamper test", fp);
    fclose(fp);

    // Encrypt
    ASSERT_EQ(wb_encrypt_file("tamper_plain.txt", "tamper_encrypted.dat",
                              password, strlen(password)), 0);

    // Tamper HMAC (flip first byte)
    FILE* fe = fopen("tamper_encrypted.dat", "rb+");
    ASSERT_TRUE(fe != nullptr);
    // Skip to HMAC in header: read header, modify hmac[0]
    typedef struct { uint32_t magic; uint16_t version; uint16_t layer_type; uint32_t padding_size; uint32_t original_size; uint8_t salt[16]; uint8_t iv[16]; uint8_t hmac[32]; } LocalHeader;
    LocalHeader hdr;
    ASSERT_EQ(fread(&hdr, sizeof(hdr), 1, fe), 1u);
    long back = ftell(fe);
    hdr.hmac[0] ^= 0xFF;
    fseek(fe, 0, SEEK_SET);
    ASSERT_EQ(fwrite(&hdr, sizeof(hdr), 1, fe), 1u);
    fclose(fe);

    // Decrypt should fail
    int dec = wb_decrypt_file("tamper_encrypted.dat", "tamper_decrypted.txt",
                              password, strlen(password));
    EXPECT_NE(dec, 0);
}

/**
 * @brief Test IV and salt generation
 */
TEST_F(WhiteboxCryptoTest, IV_Salt_GenerationTest) {
    uint8_t iv1[16], salt1[16];
    uint8_t iv2[16], salt2[16];
    
    ASSERT_EQ(wb_generate_iv_salt(iv1, salt1), 0);
    ASSERT_EQ(wb_generate_iv_salt(iv2, salt2), 0);
    
    // IVs and salts should be different
    EXPECT_NE(memcmp(iv1, iv2, 16), 0);
    EXPECT_NE(memcmp(salt1, salt2, 16), 0);
}

/**
 * @brief Test large file encryption
 */
TEST_F(WhiteboxCryptoTest, Large_File_Test) {
    // Create a larger test file (10KB)
    FILE* f = fopen("test_plain.txt", "wb");
    ASSERT_NE(f, nullptr);
    
    for (int i = 0; i < 10240; i++) {
        fputc('A' + (i % 26), f);
    }
    fclose(f);
    
    const char* password = "LargeFilePassword";
    
    // Encrypt
    ASSERT_EQ(wb_encrypt_file("test_plain.txt", "test_encrypted.dat",
                              password, strlen(password)), 0);
    
    // Decrypt
    ASSERT_EQ(wb_decrypt_file("test_encrypted.dat", "test_decrypted.txt",
                              password, strlen(password)), 0);
    
    // Verify file sizes match
    f = fopen("test_plain.txt", "rb");
    fseek(f, 0, SEEK_END);
    long orig_size = ftell(f);
    fclose(f);
    
    f = fopen("test_decrypted.txt", "rb");
    fseek(f, 0, SEEK_END);
    long decrypt_size = ftell(f);
    fclose(f);
    
    EXPECT_EQ(orig_size, decrypt_size);
}

/**
 * @brief Test encryption with special characters
 */
TEST_F(WhiteboxCryptoTest, Special_Characters_Test) {
    const char* message = "Special chars: !@#$%^&*()_+-=[]{}|;:',.<>?/~`\n\t\r\0Binary\xFF\xFE";
    size_t msg_len = 60;  // Include binary data
    
    const char* password = "SpecialTest";
    
    size_t cipher_len;
    uint8_t* encrypted = wb_encrypt_buffer((const uint8_t*)message, msg_len,
                                          password, strlen(password), &cipher_len);
    
    ASSERT_NE(encrypted, nullptr);
    
    size_t plain_len;
    uint8_t* decrypted = wb_decrypt_buffer(encrypted, cipher_len,
                                          password, strlen(password), &plain_len);
    
    ASSERT_NE(decrypted, nullptr);
    EXPECT_EQ(plain_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, plain_len), 0);
    
    secure_free(encrypted, cipher_len);
    secure_free(decrypted, plain_len);
}

