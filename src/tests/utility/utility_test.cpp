/**
 * @file utility_test.cpp
 *
 * @brief Provides test functions for  utilities
 */

#include "gtest/gtest.h"
#include "codeObfuscation.h"
#include <cstring>
#include <cstdlib>

// ============================================================================
// CODE OBFUSCATION TESTS
// ============================================================================

/**
 * @brief Test fixture for code obfuscation tests
 */
class CodeObfuscationTest : public ::testing::Test {
protected:
    void SetUp() override {
        obf_init();
    }
};

// ============================================================================
// ARITHMETIC OBFUSCATION TESTS
// ============================================================================

TEST_F(CodeObfuscationTest, ObfMulConstZero) {
    int result = obf_mul_const(5, 0);
    EXPECT_EQ(result, 0);
}

TEST_F(CodeObfuscationTest, ObfMulConstOne) {
    int result = obf_mul_const(7, 1);
    EXPECT_EQ(result, 7);
}

TEST_F(CodeObfuscationTest, ObfMulConstPositive) {
    int result = obf_mul_const(3, 4);
    EXPECT_EQ(result, 12);
}

TEST_F(CodeObfuscationTest, ObfMulConstLargeNumbers) {
    int result = obf_mul_const(100, 10);
    EXPECT_EQ(result, 1000);
}

TEST_F(CodeObfuscationTest, ObfMulConstPowerOfTwo) {
    int result = obf_mul_const(5, 8);
    EXPECT_EQ(result, 40);
}

// ============================================================================
// PARAMETER ENCODING TESTS
// ============================================================================

TEST_F(CodeObfuscationTest, EncodeParamBasic) {
    uint32_t param = 12345;
    uint32_t seed = 0xABCD1234;
    
    uint32_t encoded = encode_param(param, seed);
    
    // Encoded should be different from original
    EXPECT_NE(encoded, param);
}

TEST_F(CodeObfuscationTest, EncodeParamZero) {
    uint32_t param = 0;
    uint32_t seed = 0x12345678;
    
    uint32_t encoded = encode_param(param, seed);
    
    // Even zero should produce non-zero encoded value
    EXPECT_NE(encoded, 0u);
}

TEST_F(CodeObfuscationTest, EncodeParamDifferentSeeds) {
    uint32_t param = 100;
    
    uint32_t encoded1 = encode_param(param, 0x11111111);
    uint32_t encoded2 = encode_param(param, 0x22222222);
    
    // Different seeds should produce different encoded values
    EXPECT_NE(encoded1, encoded2);
}

TEST_F(CodeObfuscationTest, EncodeParamMaxValue) {
    uint32_t param = 0xFFFFFFFF;
    uint32_t seed = 0x12345678;
    
    uint32_t encoded = encode_param(param, seed);
    
    EXPECT_NE(encoded, param);
}

// ============================================================================
// OBFUSCATED STRING OPERATIONS TESTS
// ============================================================================

TEST_F(CodeObfuscationTest, ObfStrcpyBasic) {
    const char* src = "Hello World";
    char dest[32] = {0};
    
    obf_strcpy(dest, src);
    
    EXPECT_STREQ(dest, src);
}

TEST_F(CodeObfuscationTest, ObfStrcpyEmptyString) {
    const char* src = "";
    char dest[32] = "garbage";
    
    obf_strcpy(dest, src);
    
    EXPECT_STREQ(dest, "");
}

TEST_F(CodeObfuscationTest, ObfStrcpyLongString) {
    const char* src = "This is a longer test string for obfuscated strcpy";
    char dest[64] = {0};
    
    obf_strcpy(dest, src);
    
    EXPECT_STREQ(dest, src);
}

TEST_F(CodeObfuscationTest, ObfMemcpyBasic) {
    const char* src = "Test data for memcpy";
    char dest[32] = {0};
    
    obf_memcpy(dest, src, strlen(src) + 1);
    
    EXPECT_STREQ(dest, src);
}

TEST_F(CodeObfuscationTest, ObfMemcpyBinaryData) {
    uint8_t src[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t dest[16] = {0};
    
    obf_memcpy(dest, src, 16);
    
    EXPECT_EQ(memcmp(dest, src, 16), 0);
}

TEST_F(CodeObfuscationTest, ObfMemcpyPartial) {
    const char* src = "Full string content";
    char dest[32] = {0};
    
    obf_memcpy(dest, src, 4);
    dest[4] = '\0';
    
    EXPECT_STREQ(dest, "Full");
}

TEST_F(CodeObfuscationTest, ObfStrlenBasic) {
    const char* str = "Hello";
    
    size_t len = obf_strlen(str);
    
    EXPECT_EQ(len, 5u);
}

TEST_F(CodeObfuscationTest, ObfStrlenEmptyString) {
    const char* str = "";
    
    size_t len = obf_strlen(str);
    
    EXPECT_EQ(len, 0u);
}

TEST_F(CodeObfuscationTest, ObfStrlenLongString) {
    const char* str = "This is a much longer string to test the obfuscated strlen function";
    
    size_t len = obf_strlen(str);
    
    EXPECT_EQ(len, strlen(str));
}

TEST_F(CodeObfuscationTest, ObfMemsetBasic) {
    char buffer[16];
    
    obf_memset(buffer, 'A', sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        EXPECT_EQ(buffer[i], 'A');
    }
}

TEST_F(CodeObfuscationTest, ObfMemsetZero) {
    char buffer[16] = "Initial content";
    
    obf_memset(buffer, 0, sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        EXPECT_EQ(buffer[i], 0);
    }
}

TEST_F(CodeObfuscationTest, ObfMemsetPartial) {
    char buffer[16] = {0};
    
    obf_memset(buffer, 0xFF, 8);
    
    for (size_t i = 0; i < 8; i++) {
        EXPECT_EQ((unsigned char)buffer[i], 0xFF);
    }
    for (size_t i = 8; i < 16; i++) {
        EXPECT_EQ(buffer[i], 0);
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

TEST_F(CodeObfuscationTest, ObfuscatedOperationsChain) {
    // Test a chain of obfuscated operations
    int a = 10, b = 5;
    
    int sum = obf_add(a, b);
    int diff = obf_sub(a, b);
    int product = obf_mul_const(sum, 2);
    
    EXPECT_EQ(sum, 15);
    EXPECT_EQ(diff, 5);
    EXPECT_EQ(product, 30);
}

TEST_F(CodeObfuscationTest, StringOperationsChain) {
    const char* original = "Test String";
    char buffer1[32] = {0};
    char buffer2[32] = {0};
    
    // Copy using obfuscated strcpy
    obf_strcpy(buffer1, original);
    
    // Get length using obfuscated strlen
    size_t len = obf_strlen(buffer1);
    
    // Copy using obfuscated memcpy
    obf_memcpy(buffer2, buffer1, len + 1);
    
    EXPECT_STREQ(buffer1, original);
    EXPECT_STREQ(buffer2, original);
    EXPECT_EQ(len, strlen(original));
}

// Note: main() is provided by gtest_main library