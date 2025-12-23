/**
 * @file whiteboxCrypto.h
 * @brief Whitebox cryptography implementation for secure data storage
 * 
 * This module provides whitebox implementations of AES and DES algorithms
 * where encryption keys are embedded within the algorithm implementation,
 * making it resistant to key extraction even with full code access.
 * 
 * Features:
 * - Whitebox AES-128 encryption/decryption
 * - Whitebox DES encryption/decryption  
 * - Cascaded multi-layer encryption (AES → DES → AES)
 * - File encryption/decryption with authenticated headers
 * - Key obfuscation techniques
 */

#ifndef WHITEBOX_CRYPTO_H
#define WHITEBOX_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES block size in bytes
 */
#define WB_AES_BLOCK_SIZE 16

/**
 * @brief DES block size in bytes
 */
#define WB_DES_BLOCK_SIZE 8

/**
 * @brief AES key size (128-bit)
 */
#define WB_AES_KEY_SIZE 16

/**
 * @brief DES key size (56-bit effective, 64-bit with parity)
 */
#define WB_DES_KEY_SIZE 8

/**
 * @brief Maximum file path length
 */
#define WB_MAX_PATH 260

/**
 * @brief File encryption header magic number
 */
#define WB_FILE_MAGIC 0x57424358  // "WBCX" in hex

/**
 * @brief File encryption version
 */
#define WB_FILE_VERSION 0x0001

/**
 * @brief Encryption layer types.
 */
typedef enum {
    WB_LAYER_AES = 0x01,      /**< Single-layer AES encryption. */
    WB_LAYER_DES = 0x02,      /**< Single-layer DES encryption (simplified). */
    WB_LAYER_CASCADE = 0x03   /**< Cascaded AES–DES–AES encryption. */
} WB_EncryptionLayer;

/**
 * @brief File encryption header structure
 */
typedef struct {
    uint32_t magic;          /**< Magic number for validation */
    uint16_t version;        /**< File format version */
    uint8_t layer_type;      /**< Encryption layer type */
    uint8_t padding_size;    /**< Size of padding added */
    uint64_t original_size;  /**< Original file size before encryption */
    uint8_t salt[16];        /**< Salt for key derivation */
    uint8_t iv[16];          /**< Initialization vector */
    uint8_t hmac[32];        /**< HMAC for integrity verification */
} WB_FileHeader;

/**
 * @brief Whitebox AES context structure
 */
typedef struct {
    uint32_t lookup_tables[11][16][256];  /**< Pre-computed lookup tables */
    uint8_t round_keys[11][16];           /**< Round keys (obfuscated) */
    int is_initialized;                    /**< Initialization flag */
} WB_AES_Context;

/**
 * @brief Whitebox DES context structure
 */
typedef struct {
    uint32_t sbox_tables[8][64];          /**< Pre-computed S-box tables */
    uint64_t round_keys[16];              /**< Round keys (obfuscated) */
    int is_initialized;                    /**< Initialization flag */
} WB_DES_Context;

/**
 * @brief Cascaded encryption context
 */
typedef struct {
    WB_AES_Context aes1;   /**< First AES layer */
    WB_DES_Context des;    /**< DES layer */
    WB_AES_Context aes2;   /**< Second AES layer */
} WB_Cascade_Context;

// ============================================================================
// Whitebox AES Functions
// ============================================================================

/**
 * @brief Initialize Whitebox AES context with embedded key
 * 
 * The key is embedded into the lookup tables during initialization,
 * making it difficult to extract even with full access to the binary.
 * 
 * @param ctx Pointer to AES context
 * @param key 16-byte AES key (will be obfuscated internally)
 * @return 0 on success, -1 on failure
 */
int wb_aes_init(WB_AES_Context* ctx, const uint8_t* key);

/**
 * @brief Encrypt a single AES block using whitebox implementation
 * 
 * @param ctx Pointer to initialized AES context
 * @param plaintext 16-byte input block
 * @param ciphertext 16-byte output block
 * @return 0 on success, -1 on failure
 */
int wb_aes_encrypt_block(const WB_AES_Context* ctx, const uint8_t* plaintext, uint8_t* ciphertext);

/**
 * @brief Decrypt a single AES block using whitebox implementation
 * 
 * @param ctx Pointer to initialized AES context
 * @param ciphertext 16-byte input block
 * @param plaintext 16-byte output block
 * @return 0 on success, -1 on failure
 */
int wb_aes_decrypt_block(const WB_AES_Context* ctx, const uint8_t* ciphertext, uint8_t* plaintext);

/**
 * @brief Encrypt data using AES-CBC mode
 * 
 * @param ctx Pointer to initialized AES context
 * @param plaintext Input data
 * @param plaintext_len Length of input data
 * @param ciphertext Output buffer (must be at least plaintext_len + padding)
 * @param iv 16-byte initialization vector
 * @return Length of ciphertext on success, -1 on failure
 */
int wb_aes_encrypt_cbc(const WB_AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_len,
                       uint8_t* ciphertext, const uint8_t* iv);

/**
 * @brief Decrypt data using AES-CBC mode
 * 
 * @param ctx Pointer to initialized AES context
 * @param ciphertext Input data
 * @param ciphertext_len Length of input data
 * @param plaintext Output buffer
 * @param iv 16-byte initialization vector
 * @return Length of plaintext on success, -1 on failure
 */
int wb_aes_decrypt_cbc(const WB_AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_len,
                       uint8_t* plaintext, const uint8_t* iv);

/**
 * @brief Clean up AES context and wipe keys
 * 
 * @param ctx Pointer to AES context
 */
void wb_aes_cleanup(WB_AES_Context* ctx);

// ============================================================================
// Whitebox DES Functions
// ============================================================================

/**
 * @brief Initialize Whitebox DES context with embedded key
 * 
 * @param ctx Pointer to DES context
 * @param key 8-byte DES key (will be obfuscated internally)
 * @return 0 on success, -1 on failure
 */
int wb_des_init(WB_DES_Context* ctx, const uint8_t* key);

/**
 * @brief Encrypt a single DES block using whitebox implementation
 * 
 * @param ctx Pointer to initialized DES context
 * @param plaintext 8-byte input block
 * @param ciphertext 8-byte output block
 * @return 0 on success, -1 on failure
 */
int wb_des_encrypt_block(const WB_DES_Context* ctx, const uint8_t* plaintext, uint8_t* ciphertext);

/**
 * @brief Decrypt a single DES block using whitebox implementation
 * 
 * @param ctx Pointer to initialized DES context
 * @param ciphertext 8-byte input block
 * @param plaintext 8-byte output block
 * @return 0 on success, -1 on failure
 */
int wb_des_decrypt_block(const WB_DES_Context* ctx, const uint8_t* ciphertext, uint8_t* plaintext);

/**
 * @brief Clean up DES context and wipe keys
 * 
 * @param ctx Pointer to DES context
 */
void wb_des_cleanup(WB_DES_Context* ctx);

// ============================================================================
// Cascaded Encryption Functions
// ============================================================================

/**
 * @brief Initialize cascaded encryption context
 * 
 * Sets up three encryption layers: AES → DES → AES
 * 
 * @param ctx Pointer to cascade context
 * @param aes_key1 First AES key (16 bytes)
 * @param des_key DES key (8 bytes)
 * @param aes_key2 Second AES key (16 bytes)
 * @return 0 on success, -1 on failure
 */
int wb_cascade_init(WB_Cascade_Context* ctx, const uint8_t* aes_key1, 
                    const uint8_t* des_key, const uint8_t* aes_key2);

/**
 * @brief Encrypt data using cascaded layers (AES → DES → AES)
 * 
 * @param ctx Pointer to initialized cascade context
 * @param plaintext Input data
 * @param plaintext_len Length of input data
 * @param ciphertext Output buffer
 * @param iv Initialization vector (16 bytes)
 * @return Length of ciphertext on success, -1 on failure
 */
int wb_cascade_encrypt(const WB_Cascade_Context* ctx, const uint8_t* plaintext, 
                       size_t plaintext_len, uint8_t* ciphertext, const uint8_t* iv);

/**
 * @brief Decrypt data using cascaded layers (AES → DES → AES in reverse)
 * 
 * @param ctx Pointer to initialized cascade context
 * @param ciphertext Input data
 * @param ciphertext_len Length of input data
 * @param plaintext Output buffer
 * @param iv Initialization vector (16 bytes)
 * @return Length of plaintext on success, -1 on failure
 */
int wb_cascade_decrypt(const WB_Cascade_Context* ctx, const uint8_t* ciphertext,
                       size_t ciphertext_len, uint8_t* plaintext, const uint8_t* iv);

/**
 * @brief Clean up cascade context
 * 
 * @param ctx Pointer to cascade context
 */
void wb_cascade_cleanup(WB_Cascade_Context* ctx);

// ============================================================================
// File Encryption Functions
// ============================================================================

/**
 * @brief Encrypt a file using cascaded encryption
 * 
 * Reads the input file, encrypts it using AES→DES→AES cascade,
 * and writes to output file with authentication header.
 * 
 * @param input_path Path to input file
 * @param output_path Path to output encrypted file
 * @param password Password for key derivation
 * @param password_len Length of password
 * @return 0 on success, -1 on failure
 */
int wb_encrypt_file(const char* input_path, const char* output_path,
                    const char* password, size_t password_len);

/**
 * @brief Decrypt a file encrypted with wb_encrypt_file
 * 
 * Reads the encrypted file, verifies authentication,
 * and decrypts using the reverse cascade.
 * 
 * @param input_path Path to encrypted file
 * @param output_path Path to output decrypted file
 * @param password Password for key derivation
 * @param password_len Length of password
 * @return 0 on success, -1 on failure
 */
int wb_decrypt_file(const char* input_path, const char* output_path,
                    const char* password, size_t password_len);

/**
 * @brief Encrypt data buffer and return encrypted buffer
 * 
 * @param plaintext Input data
 * @param plaintext_len Length of input data
 * @param password Password for encryption
 * @param password_len Length of password
 * @param ciphertext_len Output parameter for ciphertext length
 * @return Pointer to encrypted data (caller must free), NULL on failure
 */
uint8_t* wb_encrypt_buffer(const uint8_t* plaintext, size_t plaintext_len,
                           const char* password, size_t password_len,
                           size_t* ciphertext_len);

/**
 * @brief Decrypt data buffer
 * 
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of encrypted data
 * @param password Password for decryption
 * @param password_len Length of password
 * @param plaintext_len Output parameter for plaintext length
 * @return Pointer to decrypted data (caller must free), NULL on failure
 */
uint8_t* wb_decrypt_buffer(const uint8_t* ciphertext, size_t ciphertext_len,
                           const char* password, size_t password_len,
                           size_t* plaintext_len);

/**
 * @brief Verify file integrity using HMAC
 * 
 * @param file_path Path to encrypted file
 * @param password Password used for encryption
 * @param password_len Length of password
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int wb_verify_file_integrity(const char* file_path, const char* password, size_t password_len);

/**
 * @brief Generate random IV and salt
 * 
 * @param iv Buffer for IV (16 bytes)
 * @param salt Buffer for salt (16 bytes)
 * @return 0 on success, -1 on failure
 */
int wb_generate_iv_salt(uint8_t* iv, uint8_t* salt);

#ifdef __cplusplus
}
#endif

#endif // WHITEBOX_CRYPTO_H

