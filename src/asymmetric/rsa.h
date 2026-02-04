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

/**
 * @enum RSA_DECRYPT_MODE
 * @brief Decryption algorithm selection
 * 
 * STANDARD: m = c^d mod n (slower, simpler)
 * CRT:      Uses Chinese Remainder Theorem (~4x faster)
 */
typedef enum {
    RSA_DECRYPT_STANDARD = 0,  // Standard: m = c^d mod n
    RSA_DECRYPT_CRT = 1        // CRT-optimized (default, ~4x faster)
} RSA_DECRYPT_MODE;

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
 * @brief Public key for encryption and signature verification
 */
typedef struct asm_rsa_pub_key {
    asm_rsa_bignum_t *n;  // Modulus (n = p * q)
    asm_rsa_bignum_t *e;  // Public exponent (65537)
    size_t key_size;      // Key size in bits
} asm_rsa_pub_key_t;

/**
 * @struct asm_rsa_pvt_key
 * @brief Private key for decryption and signing
 */
typedef struct asm_rsa_pvt_key {
    asm_rsa_bignum_t *n;  // Modulus (n = p * q)
    asm_rsa_bignum_t *d;  // Private exponent
    asm_rsa_bignum_t *p;  // First prime
    asm_rsa_bignum_t *q;  // Second prime
    asm_rsa_bignum_t *dp; // d mod (p-1) - for CRT
    asm_rsa_bignum_t *dq; // d mod (q-1) - for CRT
    asm_rsa_bignum_t *qinv; // q^(-1) mod p - for CRT
    size_t key_size;      // Key size in bits
} asm_rsa_pvt_key_t;

/**
 * @struct asm_rsa_ctx
 * @brief Context for RSA operations
 */
typedef struct asm_rsa_ctx {
    asm_rsa_pub_key_t *pub_key;
    asm_rsa_pvt_key_t *pvt_key;
    size_t key_size;        // Key size in bits
    RSA_DECRYPT_MODE decrypt_mode; // Decryption algorithm selection
    int padding_mode;       // Padding mode (PKCS#1 v1.5)
} asm_rsa_ctx_t;

// CONTEXT MANAGEMENT

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
 * @brief Set decryption mode for the context
 * @param ctx RSA context
 * @param mode RSA_DECRYPT_STANDARD or RSA_DECRYPT_CRT
 * @return RSA_SUCCESS on success, negative value on failure
 */
int
asm_rsa_set_decrypt_mode(asm_rsa_ctx_t *ctx, RSA_DECRYPT_MODE mode);

/**
 * @brief Get current decryption mode
 * @param ctx RSA context
 * @return Current decryption mode
 */
RSA_DECRYPT_MODE
asm_rsa_get_decrypt_mode(const asm_rsa_ctx_t *ctx);

// KEY GENERATION AND MANAGEMENT

/**
 * @brief Generate RSA key pair with proper prime generation
 * 
 * This function implements correct RSA key generation:
 * 1. Generates two distinct primes p and q using Miller-Rabin
 * 2. Computes n = p * q
 * 3. Computes φ(n) = (p-1)(q-1)
 * 4. Uses e = 65537
 * 5. Computes d = e^(-1) mod φ(n)
 * 6. Computes CRT parameters (dp, dq, qinv)
 * 
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

// PRIME NUMBER GENERATION
/**
 * @brief Miller-Rabin primality test
 * @param n Number to test for primality
 * @param rounds Number of test rounds (more rounds = higher confidence)
 * @return 1 if probably prime, 0 if composite
 */
static int miller_rabin(const asm_rsa_bignum_t *n,
                            int rounds);

/**
 * @brief Generate a random prime number of specified bit length
 */
static int generate_prime(asm_rsa_bignum_t *prime,
                            size_t bits);

// ENCRYPTION AND DECRYPTION

/**
 * @brief Encrypt data using RSA public key
 * 
 * Encrypts plaintext using the public key with PKCS#1 v1.5 padding.
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
                    const uint8_t *plaintext,
                    size_t plaintext_len,
                    uint8_t *ciphertext,
                    size_t *ciphertext_len);

/**
 * @brief Decrypt data using RSA private key
 * 
 * Uses the decryption mode set in the context:
 * - RSA_DECRYPT_STANDARD: m = c^d mod n
 * - RSA_DECRYPT_CRT: Chinese Remainder Theorem optimization (~4x faster)
 * 
 * @param pvt_key Private key for decryption
 * @param ciphertext Input ciphertext data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param plaintext Output buffer for plaintext
 * @param plaintext_len Pointer to plaintext length (input: buffer size, output: actual size)
 * @param mode Decryption mode (STANDARD or CRT)
 * @return RSA_SUCCESS on success, negative value on failure
 */
int asm_rsa_decryption(const asm_rsa_pvt_key_t *pvt_key,
                       const uint8_t *ciphertext,
                       size_t ciphertext_len,
                       uint8_t *plaintext,
                       size_t *plaintext_len,
                       RSA_DECRYPT_MODE mode);

// SIGNATURES

/**
 * @brief Sign a message using RSA private key (PKCS#1 v1.5 padding)
 * 
 * @param pvt_key Private key for signing
 * @param message Message to sign
 * @param message_len Length of message in bytes
 * @param signature Output buffer for signature
 * @param signature_len Pointer to signature length (input: buffer size, output: actual size)
 * @param mode Decryption mode for signing (uses same operation as decryption)
 * @return RSA_SUCCESS on success, negative value on failure
 */
int asm_rsa_sign(const asm_rsa_pvt_key_t *pvt_key,
                 const uint8_t *message,
                 size_t message_len,
                 uint8_t *signature,
                 size_t *signature_len,
                 RSA_DECRYPT_MODE mode);

/**
 * @brief Verify a signature using RSA public key
 * 
 * Verifies that a signature was created by the holder of the
 * corresponding private key for the given message.
 * 
 * @param pub_key Public key for verification
 * @param message Original message
 * @param message_len Length of message in bytes
 * @param signature Signature to verify
 * @param signature_len Length of signature in bytes
 * @return RSA_SUCCESS if signature is valid, negative value otherwise
 */
int
asm_rsa_verify(const asm_rsa_pub_key_t *pub_key,
               const uint8_t *message,
               size_t message_len,
               const uint8_t *signature,
               size_t signature_len);

// HELPER FUNCTIONS

/**
 * @brief Get maximum message size for given key size
 * @param key_size Key size in bits
 * @return Maximum message size in bytes
 */
size_t asm_rsa_get_max_msg_size(size_t key_size);

/**
 * @brief Allocate a new bignum
 * @param size Number of 32-bit words to allocate
 * @return Pointer to allocated bignum or NULL on failure
 */
asm_rsa_bignum_t *asm_rsa_bignum_new(size_t size);

/**
 * @brief Free a bignum
 * @param bn Bignum to free
 */
void asm_rsa_bignum_free(asm_rsa_bignum_t *bn);

/**
 * @brief Initialize bignum from byte array
 * @param bn Bignum to initialize
 * @param data Byte array
 * @param len Length of byte array
 * @return RSA_SUCCESS on success, negative on failure
 */
int asm_rsa_bignum_from_bytes(asm_rsa_bignum_t *bn, 
                              const uint8_t *data, size_t len);

/**
 * @brief Convert bignum to byte array
 * @param bn Bignum to convert
 * @param data Output byte array
 * @param len Length of output buffer
 * @return Number of bytes written or negative on failure
 */
int asm_rsa_bignum_to_bytes(const asm_rsa_bignum_t *bn,
                            uint8_t *data, size_t len);

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

#ifdef __cplusplus
}
#endif
#endif // ASM_RSA_H