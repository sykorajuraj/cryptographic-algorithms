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

/**Number of columns (32/bit words) in State (always 4 for AES) */
#define Nb 4

/** Number of 32-bit words in key (4 for AES-128) */
#define Nk 4

/** Number of rounds (10 for AES-128) */
#define Nr 10

// STRUCTURES

/**
 * @struct sym_aes_enc_ctx
 * @brief Context for AES encryption
 */
typedef struct sym_aes_enc_ctx 
{
   uint8_t round_keys[176];    /**< 11 round keys * 16 bytes = 176 bytes */
   uint8_t state[16];          /**< Current state (4x4 matrix in column-major order) */
} sym_aes_enc_ctx_t;

/**
 * @struct sym_aes_dnc_ctx
 * @brief Context for AES decryption
 */
typedef struct sym_aes_dnc_ctx 
{
   uint8_t round_keys[176];    /**< 11 round keys * 16 bytes = 176 bytes */
   uint8_t state[16];          /**< Current state (4x4 matrix in column-major order) */
} sym_aes_dnc_ctx_t;

/**
 * @struct sym_aes_key
 * @brief Key format with 128 bits
 */
typedef struct sym_aes_key 
{
   const char *array_key;      /**< Array of 128 bits store as pointer */
} sym_aes_key_t;

/**
 * @struct
 * @brief Encrypted cipher block with 128 bits
 */
typedef struct sym_aes_enc_block 
{
   uint8_t data[16];       /**< 128-bit block (16 bytes) */
} sym_aes_enc_block_t;

// FUNCTIONS

/**
 * @brief Creation of AES encryption context
 * 
 * @param key Pointer to 128-bit (16 bytes) encryption key
 * @return Pointer to context for AES encryption
 */
sym_aes_enc_ctx_t *
sym_aes_enc_ctx_init(const uint8_t *key);

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
 * @return Context for AES decryption
 */
sym_aes_dnc_ctx_t *
sym_aes_dnc_ctx_init(const uint8_t *key);

/**
 * @brief Destruction of AES decryption context
 * @param ctx Decryption context to destroy
 * @return Pointer to context for AES decryption
 */
sym_aes_dnc_ctx_t *
sym_aes_dnc_ctx_destroy(sym_aes_dnc_ctx_t *ctx);

/**
 * @brief Main function for encryption function of AES-128
 * 
 * @param ctx Pointer to encryption context
 * @param plaintext Pointer to 16-byte plaintext
 * @param ciphertext Pointer to 16-byte buffer for ciphertext output
 * @return 1 on success, negative value on failure
 */
int
sym_aes_encryption(
   sym_aes_enc_ctx_t *ctx,
   const uint8_t *plaintext,
   uint8_t *ciphertext);

/**
 * @brief Creation of round key
 * 
 * @param key_data Pointer to key data (128 bits / 16 bytes)
 * @return Pointer to AES 128 bits key
 */
sym_aes_key_t *
sym_aes_create_key(const char *key_data);

/**
 * @brief Function for getting the key
 * 
 * @param ctx Pointer to encryption context
 * @return Pointer to AES 128 bits key
 */
sym_aes_key_t *
sym_aes_get_key(sym_aes_enc_ctx_t *ctx);

/**
 * @brief First step - bytes substitution
 * 
 * @param state Pointer to 16-byte state array
 * @return 1 on success, negative on failure
 */
int
sym_aes_enc_sub_bytes(uint8_t *state);

/**
 * @brief Second step - shift rows
 * 
 * @param state Pointer to 16-bytes state array
 * @return 1 on success, negative on failure
 */
int
sym_aes_enc_shift_rows(uint8_t *state);

/**
 * @brief Third step - mix columns
 * 
 * @param state Pointer to 16-bytes state array
 * @return 1 on success, negative on failure
 */
int
sym_aes_enc_mix_cols(uint8_t *state);

/**
 * @brief Forth step - add round keys
 * 
 * @param state Pointer to 16-bytes state array
 * @param round_key Pointer to 16 bytes round key 
 * @return 1 on success, negative on failure
 */
int
sym_aes_enc_add_round_keys(uint8_t *state, uint8_t *round_key);

/**
 * @brief Main function for decryption of AES-128
 * 
 * @param ctx Pointer to decryption context
 * @param ciphertext Pointer to 16-bytes cipher block
 * @param plaintext Pointer to 16-bytes buffer for plaintext output 
 * @return 1 on success, negative value on failure
 */
int
sym_aes_decryption(
   sym_aes_dnc_ctx_t *ctx,
   const uint8_t *ciphertext,
   uint8_t *plaintext);

/**
 * @brief First step - add round keys (decryption)
 * 
 * @param state Pointer to 16-bytes state array
 * @param round_key Pointer to 16-byte round key
 * @return 1 on success, negative on failure
 */
int
sym_aes_dnc_add_round_keys(uint8_t *state, const uint8_t *round_key);

/**
 * @brief Second step - inverse mix columns (decryption)
 * 
 * @param state Pointer to 16-byte state array
 * @return 1 on success, negative on failure
 */
int
sym_aes_dnc_inv_mix_cols(uint8_t *state);

/**
 * @brief Third step - shift rows (decryption)
 * 
 * @param state Pointer to 16-byte state array
 * @return 1 on success, negative on failure
 */
int
sym_aes_dnc_shift_rows(uint8_t *state);

/**
 * @brief Forth step - inverse bytes substitution (decryption)
 * 
 * @param state Pointer to 16-byte state array
 * @return 1 on success, negative on failure
 */
int
sym_aes_dnc_inv_sub_bytes(uint8_t *state);

#ifdef __cplusplus
}
#endif
#endif // SYM_AES_H