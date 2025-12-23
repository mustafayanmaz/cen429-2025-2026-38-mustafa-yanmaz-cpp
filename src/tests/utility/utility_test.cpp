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
    /**
     * @brief Sets up the test fixture
     * Initializes the code obfuscation system
     */
    void SetUp() override {
        obf_init();
    }
};

// ============================================================================
// ARITHMETIC OBFUSCATION TESTS
// ============================================================================

/**
 * @brief Test obfuscated multiplication with constant zero
 */
TEST_F(CodeObfuscationTest, ObfMulConstZero) {
    int result = obf_mul_const(5, 0);
    EXPECT_EQ(result, 0);
}

/**
 * @brief Test obfuscated multiplication with constant one
 */
TEST_F(CodeObfuscationTest, ObfMulConstOne) {
    int result = obf_mul_const(7, 1);
    EXPECT_EQ(result, 7);
}

/**
 * @brief Test obfuscated multiplication with positive numbers
 */
TEST_F(CodeObfuscationTest, ObfMulConstPositive) {
    int result = obf_mul_const(3, 4);
    EXPECT_EQ(result, 12);
}

/**
 * @brief Test obfuscated multiplication with large numbers
 */
TEST_F(CodeObfuscationTest, ObfMulConstLargeNumbers) {
    int result = obf_mul_const(100, 10);
    EXPECT_EQ(result, 1000);
}

/**
 * @brief Test obfuscated multiplication with power of two
 */
TEST_F(CodeObfuscationTest, ObfMulConstPowerOfTwo) {
    int result = obf_mul_const(5, 8);
    EXPECT_EQ(result, 40);
}

// ============================================================================
// PARAMETER ENCODING TESTS
// ============================================================================

/**
 * @brief Test basic parameter encoding functionality
 */
TEST_F(CodeObfuscationTest, EncodeParamBasic) {
    uint32_t param = 12345;
    uint32_t seed = 0xABCD1234;
    
    uint32_t encoded = encode_param(param, seed);
    
    // Encoded should be different from original
    EXPECT_NE(encoded, param);
}

/**
 * @brief Test parameter encoding with zero value
 */
TEST_F(CodeObfuscationTest, EncodeParamZero) {
    uint32_t param = 0;
    uint32_t seed = 0x12345678;
    
    uint32_t encoded = encode_param(param, seed);
    
    // Even zero should produce non-zero encoded value
    EXPECT_NE(encoded, 0u);
}

/**
 * @brief Test parameter encoding with different seeds produces different results
 */
TEST_F(CodeObfuscationTest, EncodeParamDifferentSeeds) {
    uint32_t param = 100;
    
    uint32_t encoded1 = encode_param(param, 0x11111111);
    uint32_t encoded2 = encode_param(param, 0x22222222);
    
    // Different seeds should produce different encoded values
    EXPECT_NE(encoded1, encoded2);
}

/**
 * @brief Test parameter encoding with maximum 32-bit value
 */
TEST_F(CodeObfuscationTest, EncodeParamMaxValue) {
    uint32_t param = 0xFFFFFFFF;
    uint32_t seed = 0x12345678;
    
    uint32_t encoded = encode_param(param, seed);
    
    EXPECT_NE(encoded, param);
}

// ============================================================================
// OBFUSCATED STRING OPERATIONS TESTS
// ============================================================================

/**
 * @brief Test basic obfuscated string copy
 */
TEST_F(CodeObfuscationTest, ObfStrcpyBasic) {
    const char* src = "Hello World";
    char dest[32] = {0};
    
    obf_strcpy(dest, src);
    
    EXPECT_STREQ(dest, src);
}

/**
 * @brief Test obfuscated string copy with empty string
 */
TEST_F(CodeObfuscationTest, ObfStrcpyEmptyString) {
    const char* src = "";
    char dest[32] = "garbage";
    
    obf_strcpy(dest, src);
    
    EXPECT_STREQ(dest, "");
}

/**
 * @brief Test obfuscated string copy with long string
 */
TEST_F(CodeObfuscationTest, ObfStrcpyLongString) {
    const char* src = "This is a longer test string for obfuscated strcpy";
    char dest[64] = {0};
    
    obf_strcpy(dest, src);
    
    EXPECT_STREQ(dest, src);
}

/**
 * @brief Test basic obfuscated memory copy
 */
TEST_F(CodeObfuscationTest, ObfMemcpyBasic) {
    const char* src = "Test data for memcpy";
    char dest[32] = {0};
    
    obf_memcpy(dest, src, strlen(src) + 1);
    
    EXPECT_STREQ(dest, src);
}

/**
 * @brief Test obfuscated memory copy with binary data
 */
TEST_F(CodeObfuscationTest, ObfMemcpyBinaryData) {
    uint8_t src[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t dest[16] = {0};
    
    obf_memcpy(dest, src, 16);
    
    EXPECT_EQ(memcmp(dest, src, 16), 0);
}

/**
 * @brief Test obfuscated memory copy with partial data
 */
TEST_F(CodeObfuscationTest, ObfMemcpyPartial) {
    const char* src = "Full string content";
    char dest[32] = {0};
    
    obf_memcpy(dest, src, 4);
    dest[4] = '\0';
    
    EXPECT_STREQ(dest, "Full");
}

/**
 * @brief Test basic obfuscated string length calculation
 */
TEST_F(CodeObfuscationTest, ObfStrlenBasic) {
    const char* str = "Hello";
    
    size_t len = obf_strlen(str);
    
    EXPECT_EQ(len, 5u);
}

/**
 * @brief Test obfuscated string length with empty string
 */
TEST_F(CodeObfuscationTest, ObfStrlenEmptyString) {
    const char* str = "";
    
    size_t len = obf_strlen(str);
    
    EXPECT_EQ(len, 0u);
}

/**
 * @brief Test obfuscated string length with long string
 */
TEST_F(CodeObfuscationTest, ObfStrlenLongString) {
    const char* str = "This is a much longer string to test the obfuscated strlen function";
    
    size_t len = obf_strlen(str);
    
    EXPECT_EQ(len, strlen(str));
}

/**
 * @brief Test basic obfuscated memory set
 */
TEST_F(CodeObfuscationTest, ObfMemsetBasic) {
    char buffer[16];
    
    obf_memset(buffer, 'A', sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        EXPECT_EQ(buffer[i], 'A');
    }
}

/**
 * @brief Test obfuscated memory set with zero value
 */
TEST_F(CodeObfuscationTest, ObfMemsetZero) {
    char buffer[16] = "Initial content";
    
    obf_memset(buffer, 0, sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        EXPECT_EQ(buffer[i], 0);
    }
}

/**
 * @brief Test obfuscated memory set with partial buffer
 */
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

/**
 * @brief Test chain of obfuscated arithmetic operations
 */
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

/**
 * @brief Test chain of obfuscated string operations
 */
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