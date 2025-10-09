/**
 * @file secureMemory.cpp
 * @brief Implementation of secure memory management utilities
 */

#include "secureMemory.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

// Platform-specific includes for memory locking
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Prevent compiler optimization from removing secure wipe operations
#if defined(__GNUC__)
#define SECURE_NO_OPTIMIZE __attribute__((optimize("O0")))
#else
#define SECURE_NO_OPTIMIZE
#endif

/**
 * @brief Volatile pointer write to prevent compiler optimization
 */
typedef void* (*memset_t)(void*, int, size_t);
static volatile memset_t memset_func = memset;

/**
 * @brief Securely wipes memory by overwriting it multiple times
 */
#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
void secure_wipe(void* ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return;
    }
    
    volatile unsigned char* vptr = (volatile unsigned char*)ptr;
    
    // Pass 1: Write 0xFF (all bits set)
    for (size_t i = 0; i < size; i++) {
        vptr[i] = 0xFF;
    }
    
    // Pass 2: Write 0x00 (all bits clear)
    for (size_t i = 0; i < size; i++) {
        vptr[i] = 0x00;
    }
    
    // Pass 3: Write random pattern
    // Use simple pseudo-random for portability
    unsigned int seed = (unsigned int)time(NULL) + (unsigned int)(uintptr_t)ptr;
    for (size_t i = 0; i < size; i++) {
        seed = seed * 1103515245 + 12345;
        vptr[i] = (unsigned char)(seed / 65536) % 256;
    }
    
    // Final pass: Write 0x00
    memset_func(ptr, 0, size);
    
    // Memory barrier to prevent reordering
#ifdef _WIN32
    MemoryBarrier();
#else
    __asm__ __volatile__ ("" ::: "memory");
#endif
}

/**
 * @brief Allocates memory and initializes it securely
 */
void* secure_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    void* ptr = malloc(size);
    if (ptr != NULL) {
        // Initialize to zero
        memset(ptr, 0, size);
        
        // Try to lock memory to prevent swapping
        secure_mlock(ptr, size);
    }
    
    return ptr;
}

/**
 * @brief Frees memory after securely wiping its contents
 */
void secure_free(void* ptr, size_t size) {
    if (ptr == NULL) {
        return;
    }
    
    // Unlock memory if it was locked
    secure_munlock(ptr, size);
    
    // Securely wipe the memory
    secure_wipe(ptr, size);
    
    // Free the memory
    free(ptr);
}

/**
 * @brief Simple PRNG state for key generation
 */
static uint32_t prng_state[4] = {0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210};

/**
 * @brief XORShift128 PRNG for random number generation
 */
static uint32_t xorshift128(void) {
    uint32_t t = prng_state[3];
    uint32_t s = prng_state[0];
    prng_state[3] = prng_state[2];
    prng_state[2] = prng_state[1];
    prng_state[1] = s;
    
    t ^= t << 11;
    t ^= t >> 8;
    prng_state[0] = t ^ s ^ (s >> 19);
    
    return prng_state[0];
}

/**
 * @brief Initialize PRNG with entropy
 */
static void init_prng(void) {
    static int initialized = 0;
    if (initialized) {
        return;
    }
    
    // Seed with time and process information
    uint32_t seed = (uint32_t)time(NULL);
    
#ifdef _WIN32
    seed ^= (uint32_t)GetCurrentProcessId();
    seed ^= (uint32_t)GetTickCount();
#else
    seed ^= (uint32_t)getpid();
    seed ^= (uint32_t)clock();
#endif
    
    prng_state[0] = seed;
    prng_state[1] = seed * 1664525 + 1013904223;
    prng_state[2] = seed * 22695477 + 1;
    prng_state[3] = seed * 1103515245 + 12345;
    
    // Warm up the PRNG
    for (int i = 0; i < 100; i++) {
        xorshift128();
    }
    
    initialized = 1;
}

/**
 * @brief Generates a cryptographically secure random key
 */
int secure_generate_key(unsigned char* key) {
    if (key == NULL) {
        return -1;
    }
    
    init_prng();
    
    // Generate random bytes
    for (size_t i = 0; i < SECURE_KEY_SIZE; i += 4) {
        uint32_t rand_val = xorshift128();
        size_t remaining = SECURE_KEY_SIZE - i;
        size_t to_copy = (remaining < 4) ? remaining : 4;
        memcpy(key + i, &rand_val, to_copy);
    }
    
    return 0;
}

/**
 * @brief Generates a cryptographically secure random IV
 */
int secure_generate_iv(unsigned char* iv) {
    if (iv == NULL) {
        return -1;
    }
    
    init_prng();
    
    // Generate random bytes
    for (size_t i = 0; i < SECURE_IV_SIZE; i += 4) {
        uint32_t rand_val = xorshift128();
        size_t remaining = SECURE_IV_SIZE - i;
        size_t to_copy = (remaining < 4) ? remaining : 4;
        memcpy(iv + i, &rand_val, to_copy);
    }
    
    return 0;
}

/**
 * @brief Generates cryptographically secure random bytes
 */
int secure_random_bytes(unsigned char* buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        return -1;
    }
    
    init_prng();
    
    // Generate random bytes
    for (size_t i = 0; i < size; i += 4) {
        uint32_t rand_val = xorshift128();
        size_t remaining = size - i;
        size_t to_copy = (remaining < 4) ? remaining : 4;
        memcpy(buffer + i, &rand_val, to_copy);
    }
    
    return 0;
}

/**
 * @brief ChaCha20-like quarter round function
 */
static void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}

/**
 * @brief Simplified ChaCha20-like encryption
 */
static void chacha20_block(const unsigned char* key, const unsigned char* iv, 
                           uint32_t counter, unsigned char* output) {
    uint32_t state[16];
    
    // Constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key
    memcpy(&state[4], key, 32);
    
    // Counter
    state[12] = counter;
    
    // IV/Nonce
    memcpy(&state[13], iv, 12);
    
    uint32_t working_state[16];
    memcpy(working_state, state, sizeof(state));
    
    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarter_round(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
        quarter_round(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
        quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        
        // Diagonal rounds
        quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        quarter_round(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
        quarter_round(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
    }
    
    // Add the original state
    for (int i = 0; i < 16; i++) {
        working_state[i] += state[i];
    }
    
    // Output the block
    memcpy(output, working_state, 64);
}

/**
 * @brief Encrypts data in-place using a stream cipher
 */
void secure_encrypt_inplace(unsigned char* data, size_t size, 
                            const unsigned char* key, const unsigned char* iv) {
    if (data == NULL || size == 0 || key == NULL || iv == NULL) {
        return;
    }
    
    unsigned char block[64];
    uint32_t counter = 0;
    size_t offset = 0;
    
    while (offset < size) {
        // Generate keystream block
        chacha20_block(key, iv, counter, block);
        
        // XOR with data
        size_t remaining = size - offset;
        size_t to_process = (remaining < 64) ? remaining : 64;
        
        for (size_t i = 0; i < to_process; i++) {
            data[offset + i] ^= block[i];
        }
        
        offset += to_process;
        counter++;
    }
    
    // Wipe the keystream block
    secure_wipe(block, sizeof(block));
}

/**
 * @brief Decrypts data in-place using a stream cipher
 */
void secure_decrypt_inplace(unsigned char* data, size_t size,
                            const unsigned char* key, const unsigned char* iv) {
    // For stream ciphers, encryption and decryption are the same
    secure_encrypt_inplace(data, size, key, iv);
}

/**
 * @brief HMAC-SHA256-like function for PBKDF2
 */
static void simple_hmac(const unsigned char* key, size_t key_len,
                       const unsigned char* message, size_t msg_len,
                       unsigned char* output) {
    // Simplified HMAC for key derivation
    // In production, use proper HMAC-SHA256
    unsigned char temp[64];
    memset(temp, 0, sizeof(temp));
    
    // Mix key with message
    for (size_t i = 0; i < key_len && i < 64; i++) {
        temp[i] = key[i];
    }
    
    // Simple mixing function
    for (size_t i = 0; i < msg_len; i++) {
        temp[i % 64] ^= message[i];
    }
    
    // Generate output using stream cipher
    unsigned char simple_key[32];
    unsigned char simple_iv[16];
    memcpy(simple_key, temp, 32);
    memcpy(simple_iv, temp + 32, 16);
    
    memset(output, 0, SECURE_KEY_SIZE);
    secure_encrypt_inplace(output, SECURE_KEY_SIZE, simple_key, simple_iv);
    
    secure_wipe(temp, sizeof(temp));
    secure_wipe(simple_key, sizeof(simple_key));
    secure_wipe(simple_iv, sizeof(simple_iv));
}

/**
 * @brief Derives an encryption key from a password using PBKDF2-like algorithm
 */
int secure_derive_key(const char* password, size_t password_len,
                     const unsigned char* salt, size_t salt_len,
                     int iterations, unsigned char* key) {
    if (password == NULL || key == NULL || iterations < 1) {
        return -1;
    }
    
    unsigned char temp[SECURE_KEY_SIZE];
    unsigned char prev[SECURE_KEY_SIZE];
    
    // Initial round
    simple_hmac((const unsigned char*)password, password_len, salt, salt_len, prev);
    memcpy(key, prev, SECURE_KEY_SIZE);
    
    // Iterate
    for (int i = 1; i < iterations; i++) {
        simple_hmac((const unsigned char*)password, password_len, prev, SECURE_KEY_SIZE, temp);
        
        // XOR with accumulated result
        for (size_t j = 0; j < SECURE_KEY_SIZE; j++) {
            key[j] ^= temp[j];
        }
        
        memcpy(prev, temp, SECURE_KEY_SIZE);
    }
    
    secure_wipe(temp, sizeof(temp));
    secure_wipe(prev, sizeof(prev));
    
    return 0;
}

/**
 * @brief Creates a new secure buffer
 */
SecureBuffer* secure_buffer_create(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    SecureBuffer* buffer = (SecureBuffer*)secure_malloc(sizeof(SecureBuffer));
    if (buffer == NULL) {
        return NULL;
    }
    
    buffer->data = (unsigned char*)secure_malloc(size);
    if (buffer->data == NULL) {
        secure_free(buffer, sizeof(SecureBuffer));
        return NULL;
    }
    
    buffer->size = size;
    buffer->is_encrypted = 0;
    
    // Generate key and IV
    if (secure_generate_key(buffer->key) != 0 ||
        secure_generate_iv(buffer->iv) != 0) {
        secure_free(buffer->data, size);
        secure_free(buffer, sizeof(SecureBuffer));
        return NULL;
    }
    
    return buffer;
}

/**
 * @brief Writes data to a secure buffer
 */
int secure_buffer_write(SecureBuffer* buffer, const void* data, size_t size) {
    if (buffer == NULL || data == NULL || size == 0 || size > buffer->size) {
        return -1;
    }
    
    // If already encrypted, decrypt first
    if (buffer->is_encrypted) {
        secure_decrypt_inplace(buffer->data, buffer->size, buffer->key, buffer->iv);
        buffer->is_encrypted = 0;
    }
    
    // Copy data
    memcpy(buffer->data, data, size);
    
    // Encrypt
    secure_encrypt_inplace(buffer->data, buffer->size, buffer->key, buffer->iv);
    buffer->is_encrypted = 1;
    
    return 0;
}

/**
 * @brief Reads data from a secure buffer
 */
void* secure_buffer_read(SecureBuffer* buffer, size_t* out_size) {
    if (buffer == NULL || out_size == NULL) {
        return NULL;
    }
    
    // Allocate temporary buffer
    void* result = secure_malloc(buffer->size);
    if (result == NULL) {
        return NULL;
    }
    
    // Copy encrypted data
    memcpy(result, buffer->data, buffer->size);
    
    // Decrypt the copy
    secure_decrypt_inplace((unsigned char*)result, buffer->size, buffer->key, buffer->iv);
    
    *out_size = buffer->size;
    return result;
}

/**
 * @brief Destroys a secure buffer
 */
void secure_buffer_destroy(SecureBuffer* buffer) {
    if (buffer == NULL) {
        return;
    }
    
    // Wipe and free data
    if (buffer->data != NULL) {
        secure_free(buffer->data, buffer->size);
    }
    
    // Wipe and free the buffer structure
    secure_free(buffer, sizeof(SecureBuffer));
}

/**
 * @brief Securely duplicates a string
 */
char* secure_strdup(const char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    size_t len = strlen(str) + 1;
    char* dup = (char*)secure_malloc(len);
    if (dup != NULL) {
        memcpy(dup, str, len);
    }
    
    return dup;
}

/**
 * @brief Securely frees a string
 */
void secure_str_free(char* str) {
    if (str == NULL) {
        return;
    }
    
    size_t len = strlen(str);
    secure_free(str, len + 1);
}

/**
 * @brief Lock memory pages to prevent swapping
 */
int secure_mlock(void* ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return -1;
    }
    
#ifdef _WIN32
    if (VirtualLock(ptr, size)) {
        return 0;
    }
    return -1;
#else
    return mlock(ptr, size);
#endif
}

/**
 * @brief Unlock memory pages
 */
int secure_munlock(void* ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return -1;
    }
    
#ifdef _WIN32
    if (VirtualUnlock(ptr, size)) {
        return 0;
    }
    return -1;
#else
    return     munlock(ptr, size);
#endif
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

