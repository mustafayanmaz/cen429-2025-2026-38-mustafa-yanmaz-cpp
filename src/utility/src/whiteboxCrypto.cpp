/**
 * @file whiteboxCrypto.cpp
 * @brief Implementation of whitebox cryptography for secure file storage
 */

#include "whiteboxCrypto.h"
#include "secureMemory.h"
#include "sha256.h"
#include "codeObfuscation.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// ============================================================================
// AES Constants and Tables
// ============================================================================

// AES S-box
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box
static const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon for key expansion
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ============================================================================
// DES Constants
// ============================================================================

// DES S-boxes (simplified)
static const uint8_t DES_SBOX[8][64] = {
    // S1
    {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
      0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
      4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
     15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
    // S2-S8 (simplified for brevity)
    {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
      3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
    {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
     13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
    { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
     13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
    { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
     14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
    {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
     10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
    { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
     13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
    {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
      1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
};

// ============================================================================
// Helper Functions
// ============================================================================

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void aes_add_round_key(uint8_t* state, const uint8_t* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void aes_sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

static void aes_inv_sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = AES_INV_SBOX[state[i]];
    }
}

static void aes_shift_rows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

static void aes_inv_shift_rows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

static void aes_mix_columns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];
        
        state[i * 4] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[i * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

static void aes_inv_mix_columns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];
        
        state[i * 4] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9);
        state[i * 4 + 1] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
        state[i * 4 + 2] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11);
        state[i * 4 + 3] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14);
    }
}

static void aes_key_expansion(const uint8_t* key, uint8_t round_keys[11][16]) {
    memcpy(round_keys[0], key, 16);
    
    for (int round = 1; round <= 10; round++) {
        uint8_t temp[4];
        memcpy(temp, &round_keys[round - 1][12], 4);
        
        // RotWord
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;
        
        // SubWord
        for (int i = 0; i < 4; i++) {
            temp[i] = AES_SBOX[temp[i]];
        }
        
        // XOR with Rcon
        temp[0] ^= RCON[round];
        
        // Generate round key
        for (int i = 0; i < 4; i++) {
            round_keys[round][i] = round_keys[round - 1][i] ^ temp[i];
        }
        for (int i = 4; i < 16; i++) {
            round_keys[round][i] = round_keys[round - 1][i] ^ round_keys[round][i - 4];
        }
    }
}

// ============================================================================
// Whitebox AES Implementation
// ============================================================================

int wb_aes_init(WB_AES_Context* ctx, const uint8_t* key) {
    if (!ctx || !key) return -1;
    
    memset(ctx, 0, sizeof(WB_AES_Context));
    
    // Generate round keys
    aes_key_expansion(key, ctx->round_keys);
    
    // Build obfuscated lookup tables (simplified whitebox)
    // In real whitebox, these would be much more complex
    for (int round = 0; round < 11; round++) {
        for (int pos = 0; pos < 16; pos++) {
            for (int val = 0; val < 256; val++) {
                // Combine S-box with key material
                uint8_t result = AES_SBOX[val] ^ ctx->round_keys[round][pos];
                ctx->lookup_tables[round][pos][val] = result;
            }
        }
    }
    
    ctx->is_initialized = 1;
    return 0;
}

int wb_aes_encrypt_block(const WB_AES_Context* ctx, const uint8_t* plaintext, uint8_t* ciphertext) {
    if (!ctx || !ctx->is_initialized || !plaintext || !ciphertext) return -1;
    
    uint8_t state[16];
    memcpy(state, plaintext, 16);
    
    // Initial round
    aes_add_round_key(state, ctx->round_keys[0]);
    
    // Main rounds
    for (int round = 1; round < 10; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ctx->round_keys[round]);
    }
    
    // Final round
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, ctx->round_keys[10]);
    
    memcpy(ciphertext, state, 16);
    secure_wipe(state, sizeof(state));
    
    return 0;
}

int wb_aes_decrypt_block(const WB_AES_Context* ctx, const uint8_t* ciphertext, uint8_t* plaintext) {
    if (!ctx || !ctx->is_initialized || !ciphertext || !plaintext) return -1;
    
    uint8_t state[16];
    memcpy(state, ciphertext, 16);
    
    // Initial round
    aes_add_round_key(state, ctx->round_keys[10]);
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    
    // Main rounds
    for (int round = 9; round > 0; round--) {
        aes_add_round_key(state, ctx->round_keys[round]);
        aes_inv_mix_columns(state);
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
    }
    
    // Final round
    aes_add_round_key(state, ctx->round_keys[0]);
    
    memcpy(plaintext, state, 16);
    secure_wipe(state, sizeof(state));
    
    return 0;
}

int wb_aes_encrypt_cbc(const WB_AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_len,
                       uint8_t* ciphertext, const uint8_t* iv) {
    if (!ctx || !plaintext || !ciphertext || !iv) return -1;
    
    // Calculate padded length
    size_t padding = WB_AES_BLOCK_SIZE - (plaintext_len % WB_AES_BLOCK_SIZE);
    size_t padded_len = plaintext_len + padding;
    
    uint8_t* padded = (uint8_t*)secure_malloc(padded_len);
    if (!padded) return -1;
    
    memcpy(padded, plaintext, plaintext_len);
    // PKCS#7 padding
    for (size_t i = plaintext_len; i < padded_len; i++) {
        padded[i] = (uint8_t)padding;
    }
    
    uint8_t prev_block[WB_AES_BLOCK_SIZE];
    memcpy(prev_block, iv, WB_AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < padded_len; i += WB_AES_BLOCK_SIZE) {
        uint8_t block[WB_AES_BLOCK_SIZE];
        
        // XOR with previous ciphertext block (or IV)
        for (int j = 0; j < WB_AES_BLOCK_SIZE; j++) {
            block[j] = padded[i + j] ^ prev_block[j];
        }
        
        // Encrypt block
        wb_aes_encrypt_block(ctx, block, &ciphertext[i]);
        
        // Save for next iteration
        memcpy(prev_block, &ciphertext[i], WB_AES_BLOCK_SIZE);
        
        secure_wipe(block, sizeof(block));
    }
    
    secure_free(padded, padded_len);
    secure_wipe(prev_block, sizeof(prev_block));
    
    return (int)padded_len;
}

int wb_aes_decrypt_cbc(const WB_AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_len,
                       uint8_t* plaintext, const uint8_t* iv) {
    if (!ctx || !ciphertext || !plaintext || !iv) return -1;
    if (ciphertext_len % WB_AES_BLOCK_SIZE != 0) return -1;
    
    uint8_t prev_block[WB_AES_BLOCK_SIZE];
    memcpy(prev_block, iv, WB_AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < ciphertext_len; i += WB_AES_BLOCK_SIZE) {
        uint8_t block[WB_AES_BLOCK_SIZE];
        
        // Decrypt block
        wb_aes_decrypt_block(ctx, &ciphertext[i], block);
        
        // XOR with previous ciphertext block (or IV)
        for (int j = 0; j < WB_AES_BLOCK_SIZE; j++) {
            plaintext[i + j] = block[j] ^ prev_block[j];
        }
        
        // Save current ciphertext block for next iteration
        memcpy(prev_block, &ciphertext[i], WB_AES_BLOCK_SIZE);
        
        secure_wipe(block, sizeof(block));
    }
    
    // Remove PKCS#7 padding
    uint8_t padding = plaintext[ciphertext_len - 1];
    if (padding > 0 && padding <= WB_AES_BLOCK_SIZE) {
        secure_wipe(&plaintext[ciphertext_len - padding], padding);
        ciphertext_len -= padding;
    }
    
    secure_wipe(prev_block, sizeof(prev_block));
    
    return (int)ciphertext_len;
}

void wb_aes_cleanup(WB_AES_Context* ctx) {
    if (ctx) {
        secure_wipe(ctx, sizeof(WB_AES_Context));
    }
}

// ============================================================================
// Whitebox DES Implementation (Simplified)
// ============================================================================

int wb_des_init(WB_DES_Context* ctx, const uint8_t* key) {
    if (!ctx || !key) return -1;
    
    memset(ctx, 0, sizeof(WB_DES_Context));
    
    // Build S-box lookup tables
    for (int box = 0; box < 8; box++) {
        for (int val = 0; val < 64; val++) {
            ctx->sbox_tables[box][val] = DES_SBOX[box][val];
        }
    }
    
    // Generate round keys (simplified)
    uint64_t key_64 = 0;
    for (int i = 0; i < 8; i++) {
        key_64 = (key_64 << 8) | key[i];
    }
    
    for (int i = 0; i < 16; i++) {
        ctx->round_keys[i] = key_64 ^ (i * 0x0123456789ABCDEFULL);
    }
    
    ctx->is_initialized = 1;
    return 0;
}

int wb_des_encrypt_block(const WB_DES_Context* ctx, const uint8_t* plaintext, uint8_t* ciphertext) {
    if (!ctx || !ctx->is_initialized || !plaintext || !ciphertext) return -1;
    
    // Simplified DES (for demonstration)
    // Real implementation would do full DES rounds with permutations
    uint64_t data = 0;
    for (int i = 0; i < 8; i++) {
        data = (data << 8) | plaintext[i];
    }
    
    // 16 rounds (simplified)
    for (int round = 0; round < 16; round++) {
        data ^= ctx->round_keys[round];
        // Rotate
        data = (data << 1) | (data >> 63);
    }
    
    for (int i = 7; i >= 0; i--) {
        ciphertext[i] = (uint8_t)(data & 0xFF);
        data >>= 8;
    }
    
    return 0;
}

int wb_des_decrypt_block(const WB_DES_Context* ctx, const uint8_t* ciphertext, uint8_t* plaintext) {
    if (!ctx || !ctx->is_initialized || !ciphertext || !plaintext) return -1;
    
    // Simplified DES decryption
    uint64_t data = 0;
    for (int i = 0; i < 8; i++) {
        data = (data << 8) | ciphertext[i];
    }
    
    // 16 rounds in reverse
    for (int round = 15; round >= 0; round--) {
        data = (data >> 1) | (data << 63);
        data ^= ctx->round_keys[round];
    }
    
    for (int i = 7; i >= 0; i--) {
        plaintext[i] = (uint8_t)(data & 0xFF);
        data >>= 8;
    }
    
    return 0;
}

void wb_des_cleanup(WB_DES_Context* ctx) {
    if (ctx) {
        secure_wipe(ctx, sizeof(WB_DES_Context));
    }
}

// ============================================================================
// Cascaded Encryption Implementation
// ============================================================================

int wb_cascade_init(WB_Cascade_Context* ctx, const uint8_t* aes_key1, 
                    const uint8_t* des_key, const uint8_t* aes_key2) {
    if (!ctx || !aes_key1 || !des_key || !aes_key2) return -1;
    
    if (wb_aes_init(&ctx->aes1, aes_key1) != 0) return -1;
    if (wb_des_init(&ctx->des, des_key) != 0) {
        wb_aes_cleanup(&ctx->aes1);
        return -1;
    }
    if (wb_aes_init(&ctx->aes2, aes_key2) != 0) {
        wb_aes_cleanup(&ctx->aes1);
        wb_des_cleanup(&ctx->des);
        return -1;
    }
    
    return 0;
}

int wb_cascade_encrypt(const WB_Cascade_Context* ctx, const uint8_t* plaintext, 
                       size_t plaintext_len, uint8_t* ciphertext, const uint8_t* iv) {
    if (!ctx || !plaintext || !ciphertext || !iv) return -1;
    
    // Allocate temporary buffers
    size_t max_len = plaintext_len + WB_AES_BLOCK_SIZE * 2;
    uint8_t* temp1 = (uint8_t*)secure_malloc(max_len);
    uint8_t* temp2 = (uint8_t*)secure_malloc(max_len);
    
    if (!temp1 || !temp2) {
        if (temp1) secure_free(temp1, max_len);
        if (temp2) secure_free(temp2, max_len);
        return -1;
    }
    
    // Layer 1: AES encryption
    int len1 = wb_aes_encrypt_cbc(&ctx->aes1, plaintext, plaintext_len, temp1, iv);
    if (len1 < 0) {
        secure_free(temp1, max_len);
        secure_free(temp2, max_len);
        return -1;
    }
    
    // Layer 2: DES encryption (process in blocks)
    for (int i = 0; i < len1; i += WB_DES_BLOCK_SIZE) {
        int remaining = len1 - i;
        if (remaining >= WB_DES_BLOCK_SIZE) {
            wb_des_encrypt_block(&ctx->des, &temp1[i], &temp2[i]);
        } else {
            // Pad last block
            uint8_t padded[WB_DES_BLOCK_SIZE] = {0};
            memcpy(padded, &temp1[i], remaining);
            wb_des_encrypt_block(&ctx->des, padded, &temp2[i]);
            secure_wipe(padded, sizeof(padded));
        }
    }
    
    // Layer 3: AES encryption
    uint8_t iv2[WB_AES_BLOCK_SIZE];
    memcpy(iv2, iv, WB_AES_BLOCK_SIZE);
    // Modify IV slightly for second AES layer
    for (int i = 0; i < WB_AES_BLOCK_SIZE; i++) {
        iv2[i] ^= 0xAA;
    }
    
    int final_len = wb_aes_encrypt_cbc(&ctx->aes2, temp2, len1, ciphertext, iv2);
    
    secure_free(temp1, max_len);
    secure_free(temp2, max_len);
    secure_wipe(iv2, sizeof(iv2));
    
    return final_len;
}

int wb_cascade_decrypt(const WB_Cascade_Context* ctx, const uint8_t* ciphertext,
                       size_t ciphertext_len, uint8_t* plaintext, const uint8_t* iv) {
    if (!ctx || !ciphertext || !plaintext || !iv) return -1;
    
    // Allocate temporary buffers
    uint8_t* temp1 = (uint8_t*)secure_malloc(ciphertext_len);
    uint8_t* temp2 = (uint8_t*)secure_malloc(ciphertext_len);
    
    if (!temp1 || !temp2) {
        if (temp1) secure_free(temp1, ciphertext_len);
        if (temp2) secure_free(temp2, ciphertext_len);
        return -1;
    }
    
    // Layer 3 (reverse): AES decryption
    uint8_t iv2[WB_AES_BLOCK_SIZE];
    memcpy(iv2, iv, WB_AES_BLOCK_SIZE);
    for (int i = 0; i < WB_AES_BLOCK_SIZE; i++) {
        iv2[i] ^= 0xAA;
    }
    
    int len1 = wb_aes_decrypt_cbc(&ctx->aes2, ciphertext, ciphertext_len, temp1, iv2);
    if (len1 < 0) {
        secure_free(temp1, ciphertext_len);
        secure_free(temp2, ciphertext_len);
        secure_wipe(iv2, sizeof(iv2));
        return -1;
    }
    
    // Layer 2 (reverse): DES decryption
    for (int i = 0; i < len1; i += WB_DES_BLOCK_SIZE) {
        int remaining = len1 - i;
        if (remaining >= WB_DES_BLOCK_SIZE) {
            wb_des_decrypt_block(&ctx->des, &temp1[i], &temp2[i]);
        } else {
            uint8_t padded[WB_DES_BLOCK_SIZE] = {0};
            memcpy(padded, &temp1[i], remaining);
            wb_des_decrypt_block(&ctx->des, padded, &temp2[i]);
            secure_wipe(padded, sizeof(padded));
        }
    }
    
    // Layer 1 (reverse): AES decryption
    int final_len = wb_aes_decrypt_cbc(&ctx->aes1, temp2, len1, plaintext, iv);
    
    secure_free(temp1, ciphertext_len);
    secure_free(temp2, ciphertext_len);
    secure_wipe(iv2, sizeof(iv2));
    
    return final_len;
}

void wb_cascade_cleanup(WB_Cascade_Context* ctx) {
    if (ctx) {
        wb_aes_cleanup(&ctx->aes1);
        wb_des_cleanup(&ctx->des);
        wb_aes_cleanup(&ctx->aes2);
        secure_wipe(ctx, sizeof(WB_Cascade_Context));
    }
}

// ============================================================================
// File Encryption Functions
// ============================================================================

int wb_generate_iv_salt(uint8_t* iv, uint8_t* salt) {
    if (!iv || !salt) return -1;
    
    // Generate random IV and salt
    if (secure_generate_iv(iv) != 0) return -1;
    
    // Generate salt
    unsigned char salt_temp[SECURE_KEY_SIZE];
    if (secure_generate_key(salt_temp) != 0) return -1;
    memcpy(salt, salt_temp, 16);
    secure_wipe(salt_temp, sizeof(salt_temp));
    
    return 0;
}

int wb_encrypt_file(const char* input_path, const char* output_path,
                    const char* password, size_t password_len) {
    if (!input_path || !output_path || !password) return -1;
    
    // Read input file
    FILE* fin = fopen(input_path, "rb");
    if (!fin) return -1;
    
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(fin);
        return -1;
    }
    
    uint8_t* plaintext = (uint8_t*)secure_malloc(file_size);
    if (!plaintext) {
        fclose(fin);
        return -1;
    }
    
    if (fread(plaintext, 1, file_size, fin) != (size_t)file_size) {
        secure_free(plaintext, file_size);
        fclose(fin);
        return -1;
    }
    fclose(fin);
    
    // Generate keys from password
    uint8_t salt[16], iv[16];
    wb_generate_iv_salt(iv, salt);
    
    uint8_t aes_key1[WB_AES_KEY_SIZE];
    uint8_t des_key[WB_DES_KEY_SIZE];
    uint8_t aes_key2[WB_AES_KEY_SIZE];
    
    // Derive full keys and copy only needed bytes
    uint8_t temp_key1[SECURE_KEY_SIZE];
    uint8_t temp_key2[SECURE_KEY_SIZE];
    secure_derive_key(password, password_len, salt, 16, 10000, temp_key1);
    secure_derive_key(password, password_len, iv, 16, 5000, temp_key2);
    memcpy(aes_key1, temp_key1, WB_AES_KEY_SIZE);
    memcpy(aes_key2, temp_key2, WB_AES_KEY_SIZE);
    memcpy(des_key, aes_key1, WB_DES_KEY_SIZE);
    secure_wipe(temp_key1, SECURE_KEY_SIZE);
    secure_wipe(temp_key2, SECURE_KEY_SIZE);
    
    // Initialize cascade encryption
    WB_Cascade_Context ctx;
    if (wb_cascade_init(&ctx, aes_key1, des_key, aes_key2) != 0) {
        secure_free(plaintext, file_size);
        return -1;
    }
    
    // Encrypt
    size_t max_cipher_len = file_size + WB_AES_BLOCK_SIZE * 3;
    uint8_t* ciphertext = (uint8_t*)secure_malloc(max_cipher_len);
    if (!ciphertext) {
        wb_cascade_cleanup(&ctx);
        secure_free(plaintext, file_size);
        return -1;
    }
    
    int cipher_len = wb_cascade_encrypt(&ctx, plaintext, file_size, ciphertext, iv);
    if (cipher_len < 0) {
        secure_free(ciphertext, max_cipher_len);
        wb_cascade_cleanup(&ctx);
        secure_free(plaintext, file_size);
        return -1;
    }
    
    // Write encrypted file with header
    FILE* fout = fopen(output_path, "wb");
    if (!fout) {
        secure_free(ciphertext, max_cipher_len);
        wb_cascade_cleanup(&ctx);
        secure_free(plaintext, file_size);
        return -1;
    }
    
    WB_FileHeader header;
    header.magic = WB_FILE_MAGIC;
    header.version = WB_FILE_VERSION;
    header.layer_type = WB_LAYER_CASCADE;
    header.padding_size = cipher_len - file_size;
    header.original_size = file_size;
    memcpy(header.salt, salt, 16);
    memcpy(header.iv, iv, 16);
    // Compute simple HMAC over header fields (salt+iv) + ciphertext using password-derived key
    unsigned char hkey[32];
    // Derive HMAC key (reuse KDF)
    secure_derive_key(password, password_len, salt, 16, 4000, hkey);
    // Compute HMAC over (salt||iv||ciphertext)
    sha256_ctx shactx; sha256_init(&shactx);
    sha256_update(&shactx, salt, 16); sha256_update(&shactx, iv, 16);
    sha256_update(&shactx, (const uint8_t*)ciphertext, cipher_len);
    uint8_t digest[32]; sha256_final(&shactx, digest);
    hmac_sha256(hkey, 32, digest, 32, header.hmac);
    
    fwrite(&header, sizeof(header), 1, fout);
    fwrite(ciphertext, 1, cipher_len, fout);
    fclose(fout);
    
    // Cleanup
    secure_free(ciphertext, max_cipher_len);
    wb_cascade_cleanup(&ctx);
    secure_free(plaintext, file_size);
    secure_wipe(aes_key1, sizeof(aes_key1));
    secure_wipe(des_key, sizeof(des_key));
    secure_wipe(aes_key2, sizeof(aes_key2));
    
    return 0;
}

int wb_decrypt_file(const char* input_path, const char* output_path,
                    const char* password, size_t password_len) {
    if (!input_path || !output_path || !password) return -1;
    
    FILE* fin = fopen(input_path, "rb");
    if (!fin) return -1;
    
    // Read header
    WB_FileHeader header;
    if (fread(&header, sizeof(header), 1, fin) != 1) {
        fclose(fin);
        return -1;
    }
    
    // Verify magic number
    if (header.magic != WB_FILE_MAGIC) {
        fclose(fin);
        return -1;
    }
    
    // Read ciphertext
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin) - sizeof(header);
    fseek(fin, sizeof(header), SEEK_SET);
    
    uint8_t* ciphertext = (uint8_t*)secure_malloc(file_size);
    if (!ciphertext) {
        fclose(fin);
        return -1;
    }
    
    if (fread(ciphertext, 1, file_size, fin) != (size_t)file_size) {
        secure_free(ciphertext, file_size);
        fclose(fin);
        return -1;
    }
    fclose(fin);
    
    // Derive keys
    uint8_t aes_key1[WB_AES_KEY_SIZE];
    uint8_t des_key[WB_DES_KEY_SIZE];
    uint8_t aes_key2[WB_AES_KEY_SIZE];
    
    // Derive full keys and copy only needed bytes
    uint8_t temp_key1[SECURE_KEY_SIZE];
    uint8_t temp_key2[SECURE_KEY_SIZE];
    secure_derive_key(password, password_len, header.salt, 16, 10000, temp_key1);
    secure_derive_key(password, password_len, header.iv, 16, 5000, temp_key2);
    memcpy(aes_key1, temp_key1, WB_AES_KEY_SIZE);
    memcpy(aes_key2, temp_key2, WB_AES_KEY_SIZE);
    memcpy(des_key, aes_key1, WB_DES_KEY_SIZE);
    secure_wipe(temp_key1, SECURE_KEY_SIZE);
    secure_wipe(temp_key2, SECURE_KEY_SIZE);
    
    // Initialize cascade
    WB_Cascade_Context ctx;
    if (wb_cascade_init(&ctx, aes_key1, des_key, aes_key2) != 0) {
        secure_free(ciphertext, file_size);
        return -1;
    }
    
    // Decrypt
    uint8_t* plaintext = (uint8_t*)secure_malloc(file_size);
    if (!plaintext) {
        wb_cascade_cleanup(&ctx);
        secure_free(ciphertext, file_size);
        return -1;
    }
    
    int plain_len = wb_cascade_decrypt(&ctx, ciphertext, file_size, plaintext, header.iv);
    if (plain_len < 0) {
        secure_free(plaintext, file_size);
        wb_cascade_cleanup(&ctx);
        secure_free(ciphertext, file_size);
        return -1;
    }
    
    // Verify integrity (basic HMAC check)
    // Recompute HMAC and verify
    unsigned char hkey[32];
    secure_derive_key(password, password_len, header.salt, 16, 4000, hkey);
    sha256_ctx vctx; sha256_init(&vctx);
    sha256_update(&vctx, header.salt, 16); sha256_update(&vctx, header.iv, 16);
    sha256_update(&vctx, ciphertext, file_size);
    uint8_t vdigest[32]; sha256_final(&vctx, vdigest);
    uint8_t vhmac[32]; hmac_sha256(hkey, 32, vdigest, 32, vhmac);
    if (memcmp(header.hmac, vhmac, 32) != 0) {
        wb_cascade_cleanup(&ctx);
        secure_free(ciphertext, file_size);
        return -1;
    }

    // Write decrypted file
    FILE* fout = fopen(output_path, "wb");
    if (!fout) {
        secure_free(plaintext, file_size);
        wb_cascade_cleanup(&ctx);
        secure_free(ciphertext, file_size);
        return -1;
    }
    
    fwrite(plaintext, 1, plain_len, fout);
    fclose(fout);
    
    // Cleanup
    secure_free(plaintext, file_size);
    wb_cascade_cleanup(&ctx);
    secure_free(ciphertext, file_size);
    secure_wipe(aes_key1, sizeof(aes_key1));
    secure_wipe(des_key, sizeof(des_key));
    secure_wipe(aes_key2, sizeof(aes_key2));
    
    return 0;
}

uint8_t* wb_encrypt_buffer(const uint8_t* plaintext, size_t plaintext_len,
                           const char* password, size_t password_len,
                           size_t* ciphertext_len) {
    if (!plaintext || !password || !ciphertext_len) return NULL;
    
    uint8_t salt[16], iv[16];
    wb_generate_iv_salt(iv, salt);
    
    uint8_t aes_key1[WB_AES_KEY_SIZE];
    uint8_t des_key[WB_DES_KEY_SIZE];
    uint8_t aes_key2[WB_AES_KEY_SIZE];
    
    // Derive full keys and copy only needed bytes
    uint8_t temp_key1[SECURE_KEY_SIZE];
    uint8_t temp_key2[SECURE_KEY_SIZE];
    secure_derive_key(password, password_len, salt, 16, 10000, temp_key1);
    secure_derive_key(password, password_len, iv, 16, 5000, temp_key2);
    memcpy(aes_key1, temp_key1, WB_AES_KEY_SIZE);
    memcpy(aes_key2, temp_key2, WB_AES_KEY_SIZE);
    memcpy(des_key, aes_key1, WB_DES_KEY_SIZE);
    secure_wipe(temp_key1, SECURE_KEY_SIZE);
    secure_wipe(temp_key2, SECURE_KEY_SIZE);
    
    WB_Cascade_Context ctx;
    if (wb_cascade_init(&ctx, aes_key1, des_key, aes_key2) != 0) {
        return NULL;
    }
    
    size_t max_len = plaintext_len + WB_AES_BLOCK_SIZE * 3 + sizeof(WB_FileHeader);
    uint8_t* result = (uint8_t*)secure_malloc(max_len);
    if (!result) {
        wb_cascade_cleanup(&ctx);
        return NULL;
    }
    
    // Add header
    WB_FileHeader* header = (WB_FileHeader*)result;
    header->magic = WB_FILE_MAGIC;
    header->version = WB_FILE_VERSION;
    header->layer_type = WB_LAYER_CASCADE;
    header->original_size = plaintext_len;
    memcpy(header->salt, salt, 16);
    memcpy(header->iv, iv, 16);
    memset(header->hmac, 0, 32);
    
    int cipher_len = wb_cascade_encrypt(&ctx, plaintext, plaintext_len, 
                                        result + sizeof(WB_FileHeader), iv);
    if (cipher_len < 0) {
        secure_free(result, max_len);
        wb_cascade_cleanup(&ctx);
        return NULL;
    }
    
    *ciphertext_len = sizeof(WB_FileHeader) + cipher_len;
    header->padding_size = cipher_len - plaintext_len;
    
    wb_cascade_cleanup(&ctx);
    secure_wipe(aes_key1, sizeof(aes_key1));
    secure_wipe(des_key, sizeof(des_key));
    secure_wipe(aes_key2, sizeof(aes_key2));
    
    return result;
}

uint8_t* wb_decrypt_buffer(const uint8_t* ciphertext, size_t ciphertext_len,
                           const char* password, size_t password_len,
                           size_t* plaintext_len) {
    if (!ciphertext || !password || !plaintext_len) return NULL;
    if (ciphertext_len < sizeof(WB_FileHeader)) return NULL;
    
    const WB_FileHeader* header = (const WB_FileHeader*)ciphertext;
    if (header->magic != WB_FILE_MAGIC) return NULL;
    
    uint8_t aes_key1[WB_AES_KEY_SIZE];
    uint8_t des_key[WB_DES_KEY_SIZE];
    uint8_t aes_key2[WB_AES_KEY_SIZE];
    
    // Derive full keys and copy only needed bytes
    uint8_t temp_key1[SECURE_KEY_SIZE];
    uint8_t temp_key2[SECURE_KEY_SIZE];
    secure_derive_key(password, password_len, header->salt, 16, 10000, temp_key1);
    secure_derive_key(password, password_len, header->iv, 16, 5000, temp_key2);
    memcpy(aes_key1, temp_key1, WB_AES_KEY_SIZE);
    memcpy(aes_key2, temp_key2, WB_AES_KEY_SIZE);
    memcpy(des_key, aes_key1, WB_DES_KEY_SIZE);
    secure_wipe(temp_key1, SECURE_KEY_SIZE);
    secure_wipe(temp_key2, SECURE_KEY_SIZE);
    
    WB_Cascade_Context ctx;
    if (wb_cascade_init(&ctx, aes_key1, des_key, aes_key2) != 0) {
        return NULL;
    }
    
    size_t cipher_data_len = ciphertext_len - sizeof(WB_FileHeader);
    uint8_t* result = (uint8_t*)secure_malloc(cipher_data_len);
    if (!result) {
        wb_cascade_cleanup(&ctx);
        return NULL;
    }
    
    int plain_len = wb_cascade_decrypt(&ctx, ciphertext + sizeof(WB_FileHeader),
                                       cipher_data_len, result, header->iv);
    if (plain_len < 0) {
        secure_free(result, cipher_data_len);
        wb_cascade_cleanup(&ctx);
        return NULL;
    }
    
    *plaintext_len = plain_len;
    
    wb_cascade_cleanup(&ctx);
    secure_wipe(aes_key1, sizeof(aes_key1));
    secure_wipe(des_key, sizeof(des_key));
    secure_wipe(aes_key2, sizeof(aes_key2));
    
    return result;
}

int wb_verify_file_integrity(const char* file_path, const char* password, size_t password_len) {
    if (!file_path || !password) return -1;
    
    FILE* f = fopen(file_path, "rb");
    if (!f) return -1;
    
    WB_FileHeader header;
    if (fread(&header, sizeof(header), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    // Verify magic number
    if (header.magic != WB_FILE_MAGIC) return 0;
    if (header.version != WB_FILE_VERSION) return 0;
    
    // Basic HMAC presence check (non-zero) — full verification happens in decrypt path
    for (int i = 0; i < 32; ++i) {
        if (header.hmac[i] != 0) return 1;
    }
    return 0;
}

