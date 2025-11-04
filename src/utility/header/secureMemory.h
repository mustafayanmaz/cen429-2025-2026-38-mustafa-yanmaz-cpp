/**
 * @file secureMemory.h
 * @brief Secure memory management utilities for runtime data security
 * 
 * This module provides secure memory handling including:
 * - Secure memory wiping before deallocation
 * - In-memory encryption for sensitive data
 * - Protection against memory dumps and forensic analysis
 */

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Key size for in-memory encryption (256 bits)
 */
#define SECURE_KEY_SIZE 32

/**
 * @brief Initialization vector size for encryption
 */
#define SECURE_IV_SIZE 16

/**
 * @brief Represents a secure memory buffer that stores encrypted data in memory
 */
typedef struct SecureBuffer {
    unsigned char* data;        /**< Encrypted data buffer */
    size_t size;                /**< Size of the buffer in bytes */
    unsigned char key[SECURE_KEY_SIZE];  /**< Encryption key */
    unsigned char iv[SECURE_IV_SIZE];    /**< Initialization vector */
    int is_encrypted;           /**< Flag indicating if data is currently encrypted */
} SecureBuffer;

/**
 * @brief Securely wipes memory by overwriting it multiple times
 * 
 * This function performs a secure memory wipe using multiple passes:
 * 1. Overwrites with 0xFF
 * 2. Overwrites with 0x00
 * 3. Overwrites with random data
 * 
 * This prevents sensitive data from being recovered from memory dumps
 * or through forensic analysis.
 * 
 * @param ptr Pointer to memory to wipe
 * @param size Size of memory block in bytes
 */
void secure_wipe(void* ptr, size_t size);

/**
 * @brief Allocates memory and initializes it securely
 * 
 * @param size Size of memory to allocate in bytes
 * @return Pointer to allocated memory, or NULL on failure
 */
void* secure_malloc(size_t size);

/**
 * @brief Frees memory after securely wiping its contents
 * 
 * @param ptr Pointer to memory to free
 * @param size Size of memory block in bytes
 */
void secure_free(void* ptr, size_t size);

/**
 * @brief Creates a new secure buffer for storing sensitive data in memory
 * 
 * The data is encrypted in memory using AES-256-like encryption
 * (implemented as ChaCha20-like stream cipher for portability)
 * 
 * @param size Size of data to store
 * @return Pointer to SecureBuffer structure, or NULL on failure
 */
SecureBuffer* secure_buffer_create(size_t size);

/**
 * @brief Writes data to a secure buffer (encrypts it in memory)
 * 
 * @param buffer Pointer to SecureBuffer
 * @param data Data to write
 * @param size Size of data
 * @return 0 on success, -1 on failure
 */
int secure_buffer_write(SecureBuffer* buffer, const void* data, size_t size);

/**
 * @brief Reads data from a secure buffer (decrypts it temporarily)
 * 
 * The returned pointer must be freed with secure_free() after use
 * 
 * @param buffer Pointer to SecureBuffer
 * @param out_size Pointer to store the size of returned data
 * @return Pointer to decrypted data, or NULL on failure
 */
void* secure_buffer_read(SecureBuffer* buffer, size_t* out_size);

/**
 * @brief Destroys a secure buffer and wipes all sensitive data
 * 
 * @param buffer Pointer to SecureBuffer to destroy
 */
void secure_buffer_destroy(SecureBuffer* buffer);

/**
 * @brief Encrypts data in-place using a stream cipher
 * 
 * This function implements a ChaCha20-like stream cipher for
 * encrypting sensitive data in memory.
 * 
 * @param data Pointer to data to encrypt
 * @param size Size of data in bytes
 * @param key Encryption key (32 bytes)
 * @param iv Initialization vector (16 bytes)
 */
void secure_encrypt_inplace(unsigned char* data, size_t size, 
                            const unsigned char* key, const unsigned char* iv);

/**
 * @brief Decrypts data in-place using a stream cipher
 * 
 * @param data Pointer to data to decrypt
 * @param size Size of data in bytes
 * @param key Encryption key (32 bytes)
 * @param iv Initialization vector (16 bytes)
 */
void secure_decrypt_inplace(unsigned char* data, size_t size,
                            const unsigned char* key, const unsigned char* iv);

/**
 * @brief Generates a cryptographically secure random key
 * 
 * @param key Buffer to store the key (must be at least SECURE_KEY_SIZE bytes)
 * @return 0 on success, -1 on failure
 */
int secure_generate_key(unsigned char* key);

/**
 * @brief Generates a cryptographically secure random IV
 * 
 * @param iv Buffer to store the IV (must be at least SECURE_IV_SIZE bytes)
 * @return 0 on success, -1 on failure
 */
int secure_generate_iv(unsigned char* iv);

/**
 * @brief Generates cryptographically secure random bytes
 * 
 * @param buffer Buffer to store random bytes
 * @param size Number of random bytes to generate
 * @return 0 on success, -1 on failure
 */
int secure_random_bytes(unsigned char* buffer, size_t size);

/**
 * @brief Derives an encryption key from a password using PBKDF2-like algorithm
 * 
 * @param password Password string
 * @param password_len Length of password
 * @param salt Salt for key derivation
 * @param salt_len Length of salt
 * @param iterations Number of iterations for key derivation
 * @param key Output buffer for derived key (SECURE_KEY_SIZE bytes)
 * @return 0 on success, -1 on failure
 */
int secure_derive_key(const char* password, size_t password_len,
                     const unsigned char* salt, size_t salt_len,
                     int iterations, unsigned char* key);

/**
 * @brief Securely duplicates a string (allocates and copies)
 * 
 * @param str String to duplicate
 * @return Pointer to duplicated string, or NULL on failure
 */
char* secure_strdup(const char* str);

/**
 * @brief Securely frees a string by wiping it first
 * 
 * @param str String to free
 */
void secure_str_free(char* str);

/**
 * @brief Lock memory pages to prevent swapping to disk (platform-specific)
 * 
 * This prevents sensitive data from being written to swap files
 * 
 * @param ptr Pointer to memory to lock
 * @param size Size of memory in bytes
 * @return 0 on success, -1 on failure
 */
int secure_mlock(void* ptr, size_t size);

/**
 * @brief Unlock previously locked memory pages
 * 
 * @param ptr Pointer to memory to unlock
 * @param size Size of memory in bytes
 * @return 0 on success, -1 on failure
 */
int secure_munlock(void* ptr, size_t size);

#ifdef __cplusplus
}

// RAII zeroize helper for C++ scopes
struct SecureAutoWipe {
    void* ptr;
    size_t len;
    explicit SecureAutoWipe(void* p, size_t l) : ptr(p), len(l) {}
    ~SecureAutoWipe() { if (ptr && len) secure_wipe(ptr, len); }
};
#endif

#endif // SECURE_MEMORY_H

