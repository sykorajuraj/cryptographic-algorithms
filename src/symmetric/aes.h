/**
 * @file src/symmetric/aes.h
 * @brief Header file for AES-128 (Advanced Encryption Standard) implementation
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#ifndef SYM_AES_H
#define SYM_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

/** Key length represents 128 bits */
#define KEY_LENGTH 128

/** Key length in bytes */
#define KEY_LENGTH_BYTES 16

/** Block size in bytes */
#define AES_BLOCK_SIZE 16

/**Number of columns (32/bit words) in State (always 4 for AES) */
#define Nb 4

/** Number of 32-bit words in key (4 for AES-128) */
#define Nk 4

/** Number of rounds (10 for AES-128) */
#define Nr 10

// ERROR CODES
#define AES_SUCCESS 1
#define AES_ERROR_INVALID_PARAM -EINVAL
#define AES_ERROR_MEMORY -ENOMEM
#define AES_ERROR_INVALID_KEY_LENGTH -2
#define AES_ERROR_INVALID_DATA_LENGTH -3

// STRUCTURES

/**
 * @struct sym_aes_enc_ctx
 * @brief Context for AES encryption
 */
typedef struct sym_aes_enc_ctx 
{
   uint8_t round_keys[176];    /**< 11 round keys * 16 bytes = 176 bytes */
   uint8_t state[16];          /**< Current state (4x4 matrix in column-major order) */
   uint8_t iv[16];             /**< Initialization vector for CBC mode */
} sym_aes_enc_ctx_t;

/**
 * @struct sym_aes_dnc_ctx
 * @brief Context for AES decryption
 */
typedef struct sym_aes_dnc_ctx 
{
   uint8_t round_keys[176];    /**< 11 round keys * 16 bytes = 176 bytes */
   uint8_t state[16];          /**< Current state (4x4 matrix in column-major order) */
   uint8_t iv[16];             /**< Initialization vector for CBC mode */
} sym_aes_dnc_ctx_t;

/**
 * @struct sym_aes_key
 * @brief Key format with 128 bits
 */
typedef struct sym_aes_key 
{
   uint8_t key_data[KEY_LENGTH_BYTES];  /**< 128-bit key stored as array */
   size_t key_length;                    /**< Key length in bytes (must be 16) */
} sym_aes_key_t;

/**
 * @struct
 * @brief Encrypted cipher block with 128 bits
 */
typedef struct sym_aes_enc_block 
{
   uint8_t data[16];       /**< 128-bit block (16 bytes) */
} sym_aes_enc_block_t;

/**
 * @enum aes_mode
 * @brief AES modes of operation
 */
typedef enum {
    AES_MODE_ECB,    /**< Electronic Codebook (not recommended for production) */
    AES_MODE_CBC,    /**< Cipher Block Chaining */
    AES_MODE_CTR     /**< Counter mode */
} aes_mode_t;

// CONTEXT MANAGEMENT FUNCTIONS

/**
 * @brief Creation of AES encryption context
 * 
 * @param key Pointer to 128-bit (16 bytes) encryption key
 * @param key_len Length of the key in bytes (must be 16)
 * @return Pointer to context for AES encryption, NULL on failure
 */
sym_aes_enc_ctx_t *
sym_aes_enc_ctx_init(const uint8_t *key, size_t key_len);

/**
 * @brief Destruction of AES encryption context
 * 
 * @param ctx Pointer to encryption context to destroy
 * @return Pointer to context for AES encryption
 */
sym_aes_enc_ctx_t *
sym_aes_enc_ctx_destroy(sym_aes_enc_ctx_t *ctx);

/**
 * @brief Creation of AES decryption context
 * 
 * @param key Pointer to 128-bit (16 bytes) decryption key
 * @param key_len Length of the key in bytes (must be 16)
 * @return Context for AES decryption, NULL on failure
 */
sym_aes_dnc_ctx_t *
sym_aes_dnc_ctx_init(const uint8_t *key, size_t key_len);

/**
 * @brief Destruction of AES decryption context
 * @param ctx Decryption context to destroy
 * @return Pointer to context for AES decryption
 */
sym_aes_dnc_ctx_t *
sym_aes_dnc_ctx_destroy(sym_aes_dnc_ctx_t *ctx);

/**
 * @brief Set initialization vector for CBC/CTR modes
 * 
 * @param ctx Pointer to encryption context
 * @param iv Pointer to 16-byte IV
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_enc_set_iv(sym_aes_enc_ctx_t *ctx, const uint8_t *iv);

/**
 * @brief Set initialization vector for CBC/CTR modes (decryption)
 * 
 * @param ctx Pointer to decryption context
 * @param iv Pointer to 16-byte IV
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_dnc_set_iv(sym_aes_dnc_ctx_t *ctx, const uint8_t *iv);

// CORE ENCRYPTION FUNCTIONS

/**
 * @brief Main function for encryption function of AES-128 (single block, ECB mode)
 * 
 * @param ctx Pointer to encryption context
 * @param plaintext Pointer to 16-byte plaintext
 * @param ciphertext Pointer to 16-byte buffer for ciphertext output
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_encryption(
   sym_aes_enc_ctx_t *ctx,
   const uint8_t *plaintext,
   uint8_t *ciphertext);

/**
 * @brief Main function for decryption of AES-128 (single block, ECB mode)
 * 
 * @param ctx Pointer to decryption context
 * @param ciphertext Pointer to 16-bytes cipher block
 * @param plaintext Pointer to 16-bytes buffer for plaintext output 
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_decryption(
   sym_aes_dnc_ctx_t *ctx,
   const uint8_t *ciphertext,
   uint8_t *plaintext);

// MODE OF OPERATION FUNCTIONS

/**
 * @brief Encrypt data in CBC mode with PKCS#7 padding
 * 
 * @param ctx Pointer to encryption context
 * @param plaintext Pointer to plaintext data
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext Pointer to buffer for ciphertext (must be large enough)
 * @param ciphertext_len Pointer to store actual ciphertext length
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_encrypt_cbc(
   sym_aes_enc_ctx_t *ctx,
   const uint8_t *plaintext,
   size_t plaintext_len,
   uint8_t *ciphertext,
   size_t *ciphertext_len);

/**
 * @brief Decrypt data in CBC mode with PKCS#7 padding removal
 * 
 * @param ctx Pointer to decryption context
 * @param ciphertext Pointer to ciphertext data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param plaintext Pointer to buffer for plaintext
 * @param plaintext_len Pointer to store actual plaintext length
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_decrypt_cbc(
   sym_aes_dnc_ctx_t *ctx,
   const uint8_t *ciphertext,
   size_t ciphertext_len,
   uint8_t *plaintext,
   size_t *plaintext_len);

/**
 * @brief Encrypt data in CTR mode (no padding needed)
 * 
 * @param ctx Pointer to encryption context
 * @param plaintext Pointer to plaintext data
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext Pointer to buffer for ciphertext
 * @param ciphertext_len Pointer to store actual ciphertext length
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_encrypt_ctr(
   sym_aes_enc_ctx_t *ctx,
   const uint8_t *plaintext,
   size_t plaintext_len,
   uint8_t *ciphertext,
   size_t *ciphertext_len);

/**
 * @brief Decrypt data in CTR mode (no padding needed)
 * 
 * @param ctx Pointer to decryption context
 * @param ciphertext Pointer to ciphertext data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param plaintext Pointer to buffer for plaintext
 * @param plaintext_len Pointer to store actual plaintext length
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_decrypt_ctr(
   sym_aes_dnc_ctx_t *ctx,
   const uint8_t *ciphertext,
   size_t ciphertext_len,
   uint8_t *plaintext,
   size_t *plaintext_len);

// PADDING FUNCTIONS

/**
 * @brief Apply PKCS#7 padding to data
 * 
 * @param data Pointer to data buffer
 * @param data_len Length of actual data
 * @param padded_data Pointer to output buffer (must be large enough)
 * @param padded_len Pointer to store padded length
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_pkcs7_pad(
   const uint8_t *data,
   size_t data_len,
   uint8_t *padded_data,
   size_t *padded_len);

/**
 * @brief Remove PKCS#7 padding from data
 * 
 * @param padded_data Pointer to padded data
 * @param padded_len Length of padded data
 * @param data Pointer to output buffer
 * @param data_len Pointer to store unpadded length
 * @return AES_SUCCESS on success, negative value on failure
 */
int
sym_aes_pkcs7_unpad(
   const uint8_t *padded_data,
   size_t padded_len,
   uint8_t *data,
   size_t *data_len);

// KEY MANAGEMENT FUNCTIONS

/**
 * @brief Creation of round key
 * 
 * @param key_data Pointer to key data (128 bits / 16 bytes)
 * @param key_len Length of key data in bytes
 * @return Pointer to AES 128 bits key
 */
sym_aes_key_t *
sym_aes_create_key(const char *key_data, size_t key_len);

/**
 * @brief Destroy AES key structure and securely erase key data
 * 
 * @param key Pointer to key structure
 */
void
sym_aes_destroy_key(sym_aes_key_t *key);

// TRANSFORMATION FUNCTIONS

/**
 * @brief First step - bytes substitution
 * 
 * @param state Pointer to 16-byte state array
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_enc_sub_bytes(uint8_t *state);

/**
 * @brief Second step - shift rows
 * 
 * @param state Pointer to 16-bytes state array
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_enc_shift_rows(uint8_t *state);

/**
 * @brief Third step - mix columns
 * 
 * @param state Pointer to 16-bytes state array
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_enc_mix_cols(uint8_t *state);

/**
 * @brief Forth step - add round keys
 * 
 * @param state Pointer to 16-bytes state array
 * @param round_key Pointer to 16 bytes round key 
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_enc_add_round_keys(uint8_t *state, uint8_t *round_key);

/**
 * @brief First step - add round keys (decryption)
 * 
 * @param state Pointer to 16-bytes state array
 * @param round_key Pointer to 16-byte round key
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_dnc_add_round_keys(uint8_t *state, const uint8_t *round_key);

/**
 * @brief Second step - inverse mix columns (decryption)
 * 
 * @param state Pointer to 16-byte state array
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_dnc_inv_mix_cols(uint8_t *state);

/**
 * @brief Third step - shift rows (decryption)
 * 
 * @param state Pointer to 16-byte state array
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_dnc_shift_rows(uint8_t *state);

/**
 * @brief Forth step - inverse bytes substitution (decryption)
 * 
 * @param state Pointer to 16-byte state array
 * @return AES_SUCCESS on success, negative on failure
 */
int
sym_aes_dnc_inv_sub_bytes(uint8_t *state);

#ifdef __cplusplus
}
#endif
#endif // SYM_AES_H