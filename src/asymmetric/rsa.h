/**
 * @file src/asymmetric/rsa.h
 * @brief Header file for RSA (Rivest-Shamir-Adleman cryptography algorithm) implementation
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#ifndef ASM_RSA_H
#define ASM_RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

// ERROR CODES
#define RSA_SUCCESS 1
#define RSA_ERR_INVALID_PARAM -EINVAL
#define RSA_ERR_MEMORY -ENOMEM
#define RSA_ERR_INVALID_KEY_LENGTH -2
#define RSA_ERR_INVALID_DATA_LENGTH -3
#define RSA_ERR_ENCRYPTION_FAILED -4
#define RSA_ERR_DECRYPTION_FAILED -5
#define RSA_ERR_KEY_GENERATION_FAILED -6

// RSA KEY SIZES (in bits)
#define RSA_KEY_SIZE_512  512
#define RSA_KEY_SIZE_1024 1024
#define RSA_KEY_SIZE_2048 2048
#define RSA_KEY_SIZE_4096 4096

// Maximum message size (in bytes) for different key sizes
#define RSA_MAX_MSG_SIZE_512  (512/8 - 11)   // 53 bytes
#define RSA_MAX_MSG_SIZE_1024 (1024/8 - 11)  // 117 bytes
#define RSA_MAX_MSG_SIZE_2048 (2048/8 - 11)  // 245 bytes
#define RSA_MAX_MSG_SIZE_4096 (4096/8 - 11)  // 501 bytes

// STRUCTURES

/**
 * @struct asm_rsa_bignum
 * @brief Big number representation for RSA calculations
 */
typedef struct asm_rsa_bignum {
    uint32_t *data;      // Array of 32-bit words
    size_t size;         // Number of words allocated
    size_t used;         // Number of words actually used
} asm_rsa_bignum_t;

/**
 * @struct asm_rsa_pub_key
 * @brief Public key for encryption
 */
typedef struct asm_rsa_pub_key {
    asm_rsa_bignum_t *n;  // Modulus (n = p * q)
    asm_rsa_bignum_t *e;  // Public exponent (typically 65537)
    size_t key_size;      // Key size in bits
} asm_rsa_pub_key_t;

/**
 * @struct asm_rsa_pvt_key
 * @brief Private key for encryption
 */
typedef struct asm_rsa_pvt_key {
    asm_rsa_bignum_t *n;  // Modulus (n = p * q)
    asm_rsa_bignum_t *d;  // Private exponent
    asm_rsa_bignum_t *p;  // First prime
    asm_rsa_bignum_t *q;  // Second prime
    asm_rsa_bignum_t *dp; // d mod (p-1) - for CRT optimization
    asm_rsa_bignum_t *dq; // d mod (q-1) - for CRT optimization
    asm_rsa_bignum_t *qinv; // q^(-1) mod p - for CRT optimization
    size_t key_size;      // Key size in bits
} asm_rsa_pvt_key_t;

/**
 * @struct asm_rsa_ctx
 * @brief Context for RSA encryption and decryption
 */
typedef struct asm_rsa_ctx {
    asm_rsa_pub_key_t *pub_key;
    asm_rsa_pvt_key_t *pvt_key;
    size_t key_size;        // Key size in bits
    int padding_mode;       // Padding mode (PKCS#1 v1.5, OAEP, etc.)
} asm_rsa_ctx_t;

// HELPER FUNCTIONS

/**
 * @brief Get maximum message size for given key size
 * @param key_size Key size in bits
 * @return Maximum message size in bytes
 */
size_t 
asm_rsa_get_max_msg_size(size_t key_size);

/**
 * @brief Allocate a new public key
 * @param key_size Key size in bits
 * @return Pointer to allocated public key or NULL on failure
 */
asm_rsa_pub_key_t *
asm_rsa_pub_key_new(size_t key_size);

/**
 * @brief Free a public key
 * @param pub_key Public key to free
 */
void
asm_rsa_pub_key_free(asm_rsa_pub_key_t *pub_key);

/**
 * @brief Allocate a new private key
 * @param key_size Key size in bits
 * @return Pointer to allocated private key or NULL on failure
 */
asm_rsa_pvt_key_t *
asm_rsa_pvt_key_new(size_t key_size);

/**
 * @brief Free a private key
 * @param pvt_key Private key to free
 */
void
asm_rsa_pvt_key_free(asm_rsa_pvt_key_t *pvt_key);

// BIGNUM FUNCTIONS

/**
 * @brief Allocate a new bignum
 * @param size Number of 32-bit words to allocate
 * @return Pointer to allocated bignum or NULL on failure
 */
asm_rsa_bignum_t *
asm_rsa_bignum_new(size_t size);

/**
 * @brief Free a bignum
 * @param bn Bignum to free
 */
void
asm_rsa_bignum_free(asm_rsa_bignum_t *bn);

/**
 * @brief Initialize bignum from byte array
 * @param bn Bignum to initialize
 * @param data Byte array
 * @param len Length of byte array
 * @return RSA_SUCCESS on success, negative on failure
 */
int
asm_rsa_bignum_from_bytes(asm_rsa_bignum_t *bn, 
    const uint8_t *data, size_t len);

/**
 * @brief Convert bignum to byte array
 * @param bn Bignum to convert
 * @param data Output byte array
 * @param len Length of output buffer
 * @return Number of bytes written or negative on failure
 */
int
asm_rsa_bignum_to_bytes(const asm_rsa_bignum_t *bn,
    uint8_t *data, size_t len);

// KEY GENERATION AND MANAGEMENT

/**
 * @brief Initialize RSA context
 * @param ctx Context to initialize
 * @param key_size Key size in bits (512, 1024, 2048, 4096)
 * @return RSA_SUCCESS on success, negative value on failure
 */
int
asm_rsa_ctx_init(asm_rsa_ctx_t *ctx, size_t key_size);

/**
 * @brief Free RSA context
 * @param ctx Context to free
 */
void
asm_rsa_ctx_free(asm_rsa_ctx_t *ctx);

/**
 * @brief Generate RSA key pair
 * @param ctx RSA context
 * @param key_size Key size in bits
 * @return RSA_SUCCESS on success, negative value on failure
 */
int
asm_rsa_generate_keypair(asm_rsa_ctx_t *ctx, size_t key_size);

/**
 * @brief Get public key from context
 * @param ctx RSA context
 * @return Pointer to public key or NULL on failure
 */
asm_rsa_pub_key_t *
asm_rsa_get_pub_key(asm_rsa_ctx_t *ctx);

/**
 * @brief Get private key from context
 * @param ctx RSA context
 * @return Pointer to private key or NULL on failure
 */
asm_rsa_pvt_key_t *
asm_rsa_get_pvt_key(asm_rsa_ctx_t *ctx);

// ENCRYPTION AND DECRYPTION

/**
 * @brief Main function for encryption
 * 
 * Sender encrypts the data using Public Key to get cipher text.
 * 
 * @param pub_key Public key for encryption
 * @param plaintext Input plaintext data
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext Output buffer for ciphertext
 * @param ciphertext_len Pointer to ciphertext length (input: buffer size, output: actual size)
 * @return RSA_SUCCESS on success, negative value on failure
 */
int
asm_rsa_encryption(const asm_rsa_pub_key_t *pub_key,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * @brief Main function for decryption
 * 
 * Decrypting the cipher text using Private Key to get the original data.
 * 
 * @param pvt_key Private key for decryption
 * @param ciphertext Input ciphertext data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param plaintext Output buffer for plaintext
 * @param plaintext_len Pointer to plaintext length (input: buffer size, output: actual size)
 * @return RSA_SUCCESS on success, negative value on failure
 */
int
asm_rsa_decryption(const asm_rsa_pvt_key_t *pvt_key,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif
#endif // ASM_RSA_H