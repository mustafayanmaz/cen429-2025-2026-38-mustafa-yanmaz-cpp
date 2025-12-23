/**
 * @file sha256.h
 * @brief SHA-256 and HMAC-SHA256 cryptographic hash functions
 */

#ifndef SHA256_MINI_H
#define SHA256_MINI_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief SHA-256 context structure
 */
typedef struct {
    uint32_t state[8];   /**< Hash state values */
    uint64_t bitlen;     /**< Total bit length processed */
    uint8_t buffer[64];  /**< Input buffer for partial blocks */
    size_t buffer_len;   /**< Current buffer length */
} sha256_ctx;

/**
 * @brief Initialize SHA-256 context
 * @param ctx Pointer to SHA-256 context to initialize
 */
void sha256_init(sha256_ctx* ctx);

/**
 * @brief Update SHA-256 hash with data
 * @param ctx Pointer to SHA-256 context
 * @param data Input data to hash
 * @param len Length of input data in bytes
 */
void sha256_update(sha256_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-256 hash and output result
 * @param ctx Pointer to SHA-256 context
 * @param out Output buffer for 32-byte hash result
 */
void sha256_final(sha256_ctx* ctx, uint8_t out[32]);

/**
 * @brief Compute HMAC-SHA256 message authentication code
 * @param key Secret key for HMAC
 * @param key_len Length of key in bytes
 * @param data Input data to authenticate
 * @param data_len Length of input data in bytes
 * @param out Output buffer for 32-byte HMAC result
 */
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]);

#endif


