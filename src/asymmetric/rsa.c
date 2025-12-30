/**
 * @file src/asymmetric/rsa.c
 * @brief RSA (Rivest-Shamir-Adleman) cryptography algorithm implementation
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Helper function to generate random bytes
static void random_bytes(uint8_t *buf, size_t len) {
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}

// Helper function to identify maximal message size
size_t asm_rsa_get_max_msg_size(size_t key_size) {
    switch (key_size) {
        case RSA_KEY_SIZE_512:  return RSA_MAX_MSG_SIZE_512;
        case RSA_KEY_SIZE_1024: return RSA_MAX_MSG_SIZE_1024;
        case RSA_KEY_SIZE_2048: return RSA_MAX_MSG_SIZE_2048;
        case RSA_KEY_SIZE_4096: return RSA_MAX_MSG_SIZE_4096;
        default: return 0;
    }
}

// BIGNUM FUNCTIONS

asm_rsa_bignum_t *asm_rsa_bignum_new(size_t size) {
    asm_rsa_bignum_t *bn = malloc(sizeof(asm_rsa_bignum_t));
    if (!bn) return NULL;
    
    bn->data = calloc(size, sizeof(uint32_t));
    if (!bn->data) {
        free(bn);
        return NULL;
    }
    
    bn->size = size;
    bn->used = 0;
    return bn;
}

void asm_rsa_bignum_free(asm_rsa_bignum_t *bn) {
    if (bn) {
        if (bn->data) {
            memset(bn->data, 0, bn->size * sizeof(uint32_t));
            free(bn->data);
        }
        free(bn);
    }
}

int asm_rsa_bignum_from_bytes(asm_rsa_bignum_t *bn, const uint8_t *data, size_t len) {
    if (!bn || !data || len == 0) return RSA_ERR_INVALID_PARAM;
    
    size_t words_needed = (len + 3) / 4;
    if (words_needed > bn->size) return RSA_ERR_INVALID_DATA_LENGTH;
    
    memset(bn->data, 0, bn->size * sizeof(uint32_t));
    bn->used = words_needed;
    
    for (size_t i = 0; i < len; i++) {
        size_t word_idx = i / 4;
        size_t byte_pos = i % 4;
        bn->data[word_idx] |= ((uint32_t)data[len - 1 - i]) << (byte_pos * 8);
    }
    
    return RSA_SUCCESS;
}

int asm_rsa_bignum_to_bytes(const asm_rsa_bignum_t *bn, uint8_t *data, size_t len) {
    if (!bn || !data) return RSA_ERR_INVALID_PARAM;
    
    size_t bytes_needed = bn->used * 4;
    if (bytes_needed > len) return RSA_ERR_INVALID_DATA_LENGTH;
    
    memset(data, 0, len);
    
    for (size_t i = 0; i < bn->used; i++) {
        for (int j = 0; j < 4; j++) {
            size_t byte_idx = bytes_needed - 1 - (i * 4 + j);
            if (byte_idx < len) {
                data[byte_idx] = (bn->data[i] >> (j * 8)) & 0xFF;
            }
        }
    }
    
    return bytes_needed;
}

// BIGNUM ARITHMETIC OPERATIONS

/**
 * @brief Compare two bignums
 * @return 1 if a > b, -1 if a < b, 0 if equal
 */
static int bignum_cmp(const asm_rsa_bignum_t *a, const asm_rsa_bignum_t *b) {
    if (a->used > b->used) return 1;
    if (a->used < b->used) return -1;
    
    for (int i = a->used - 1; i >= 0; i--) {
        if (a->data[i] > b->data[i]) return 1;
        if (a->data[i] < b->data[i]) return -1;
    }
    return 0;
}

/**
 * @brief Copy bignum
 */
static void bignum_copy(asm_rsa_bignum_t *dst, const asm_rsa_bignum_t *src) {
    if (dst->size < src->used) return;
    
    memcpy(dst->data, src->data, src->used * sizeof(uint32_t));
    dst->used = src->used;
    
    // Zero remaining words
    if (dst->used < dst->size) {
        memset(&dst->data[dst->used], 0, (dst->size - dst->used) * sizeof(uint32_t));
    }
}

/**
 * @brief Trim leading zeros from bignum
 */
static void bignum_trim(asm_rsa_bignum_t *bn) {
    while (bn->used > 0 && bn->data[bn->used - 1] == 0) {
        bn->used--;
    }
    if (bn->used == 0) bn->used = 1;
}

/**
 * @brief Add two bignums: result = a + b
 */
static int bignum_add(asm_rsa_bignum_t *result, 
                      const asm_rsa_bignum_t *a,
                      const asm_rsa_bignum_t *b) {
    size_t max_len = (a->used > b->used) ? a->used : b->used;
    if (result->size < max_len + 1) return RSA_ERR_MEMORY;
    
    uint64_t carry = 0;
    size_t i;
    
    for (i = 0; i < max_len || carry; i++) {
        uint64_t sum = carry;
        if (i < a->used) sum += a->data[i];
        if (i < b->used) sum += b->data[i];
        
        result->data[i] = (uint32_t)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
    
    result->used = i;
    bignum_trim(result);
    return RSA_SUCCESS;
}

/**
 * @brief Subtract two bignums: result = a - b (assumes a >= b)
 */
static int bignum_sub(asm_rsa_bignum_t *result,
                      const asm_rsa_bignum_t *a,
                      const asm_rsa_bignum_t *b) {
    if (bignum_cmp(a, b) < 0) return RSA_ERR_INVALID_PARAM;
    
    int64_t borrow = 0;
    size_t i;
    
    for (i = 0; i < a->used; i++) {
        int64_t diff = (int64_t)a->data[i] - borrow;
        if (i < b->used) diff -= b->data[i];
        
        if (diff < 0) {
            diff += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        
        result->data[i] = (uint32_t)diff;
    }
    
    result->used = a->used;
    bignum_trim(result);
    return RSA_SUCCESS;
}

/**
 * @brief Multiply two bignums: result = a * b
 */
static int bignum_mul(asm_rsa_bignum_t *result,
                      const asm_rsa_bignum_t *a,
                      const asm_rsa_bignum_t *b) {
    if (result->size < a->used + b->used) return RSA_ERR_MEMORY;
    
    // Initialize result to zero
    memset(result->data, 0, result->size * sizeof(uint32_t));
    result->used = 0;
    
    for (size_t i = 0; i < a->used; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->used; j++) {
            uint64_t prod = (uint64_t)a->data[i] * (uint64_t)b->data[j];
            prod += result->data[i + j] + carry;
            
            result->data[i + j] = (uint32_t)(prod & 0xFFFFFFFF);
            carry = prod >> 32;
        }
        
        if (carry > 0) {
            result->data[i + b->used] = (uint32_t)carry;
        }
    }
    
    result->used = a->used + b->used;
    bignum_trim(result);
    return RSA_SUCCESS;
}

/**
 * @brief Modular reduction: result = a mod m
 */
static int bignum_mod(asm_rsa_bignum_t *result,
                      const asm_rsa_bignum_t *a,
                      const asm_rsa_bignum_t *m) {
    if (bignum_cmp(a, m) < 0) {
        bignum_copy(result, a);
        return RSA_SUCCESS;
    }
    
    // Simple repeated subtraction for demonstration
    asm_rsa_bignum_t *temp = asm_rsa_bignum_new(a->used + 1);
    if (!temp) return RSA_ERR_MEMORY;
    
    bignum_copy(temp, a);
    
    while (bignum_cmp(temp, m) >= 0) {
        bignum_sub(temp, temp, m);
    }
    
    bignum_copy(result, temp);
    asm_rsa_bignum_free(temp);
    
    return RSA_SUCCESS;
}

/**
 * @brief Modular multiplication: result = (a * b) mod m
 */
static int bignum_mul_mod(asm_rsa_bignum_t *result,
                          const asm_rsa_bignum_t *a,
                          const asm_rsa_bignum_t *b,
                          const asm_rsa_bignum_t *m) {
    asm_rsa_bignum_t *temp = asm_rsa_bignum_new(a->used + b->used + 1);
    if (!temp) return RSA_ERR_MEMORY;
    
    int ret = bignum_mul(temp, a, b);
    if (ret != RSA_SUCCESS) {
        asm_rsa_bignum_free(temp);
        return ret;
    }
    
    ret = bignum_mod(result, temp, m);
    asm_rsa_bignum_free(temp);
    
    return ret;
}

/**
 * @brief Modular exponentiation: result = (base^exp) mod m
 * 
 * Uses binary exponentiation (square-and-multiply) algorithm.
 */
static int bignum_mod_exp(asm_rsa_bignum_t *result, 
                          const asm_rsa_bignum_t *base,
                          const asm_rsa_bignum_t *exp,
                          const asm_rsa_bignum_t *mod) {
    if (!result || !base || !exp || !mod) return RSA_ERR_INVALID_PARAM;
    
    // Check for zero modulus
    if (mod->used == 1 && mod->data[0] == 0) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    // Allocate temporary bignums
    asm_rsa_bignum_t *temp_base = asm_rsa_bignum_new(mod->used * 2 + 1);
    asm_rsa_bignum_t *temp_result = asm_rsa_bignum_new(mod->used * 2 + 1);
    
    if (!temp_base || !temp_result) {
        asm_rsa_bignum_free(temp_base);
        asm_rsa_bignum_free(temp_result);
        return RSA_ERR_MEMORY;
    }
    
    // Initialize result to 1
    memset(temp_result->data, 0, temp_result->size * sizeof(uint32_t));
    temp_result->data[0] = 1;
    temp_result->used = 1;
    
    // Copy base and reduce it modulo m
    bignum_copy(temp_base, base);
    bignum_mod(temp_base, temp_base, mod);
    
    // Binary exponentiation
    for (size_t i = 0; i < exp->used; i++) {
        uint32_t exp_word = exp->data[i];
        
        for (int bit = 0; bit < 32; bit++) {
            // If current bit is 1: result = (result * base) mod m
            if (exp_word & 1) {
                int ret = bignum_mul_mod(temp_result, temp_result, temp_base, mod);
                if (ret != RSA_SUCCESS) {
                    asm_rsa_bignum_free(temp_base);
                    asm_rsa_bignum_free(temp_result);
                    return ret;
                }
            }
            
            // base = (base * base) mod m
            int ret = bignum_mul_mod(temp_base, temp_base, temp_base, mod);
            if (ret != RSA_SUCCESS) {
                asm_rsa_bignum_free(temp_base);
                asm_rsa_bignum_free(temp_result);
                return ret;
            }
            
            exp_word >>= 1;
            
            // Early exit if remaining bits are zero
            if (i == exp->used - 1 && exp_word == 0) break;
        }
    }
    
    // Copy result
    bignum_copy(result, temp_result);
    
    // Clean up
    asm_rsa_bignum_free(temp_base);
    asm_rsa_bignum_free(temp_result);
    
    return RSA_SUCCESS;
}

// KEY MANAGEMENT

asm_rsa_pub_key_t *asm_rsa_pub_key_new(size_t key_size) {
    asm_rsa_pub_key_t *pub_key = malloc(sizeof(asm_rsa_pub_key_t));
    if (!pub_key) return NULL;
    
    size_t words = (key_size / 8 + 3) / 4;
    
    pub_key->n = asm_rsa_bignum_new(words);
    pub_key->e = asm_rsa_bignum_new(words);
    
    if (!pub_key->n || !pub_key->e) {
        asm_rsa_pub_key_free(pub_key);
        return NULL;
    }
    
    pub_key->key_size = key_size;
    return pub_key;
}

void asm_rsa_pub_key_free(asm_rsa_pub_key_t *pub_key) {
    if (pub_key) {
        asm_rsa_bignum_free(pub_key->n);
        asm_rsa_bignum_free(pub_key->e);
        free(pub_key);
    }
}

asm_rsa_pvt_key_t *asm_rsa_pvt_key_new(size_t key_size) {
    asm_rsa_pvt_key_t *pvt_key = malloc(sizeof(asm_rsa_pvt_key_t));
    if (!pvt_key) return NULL;
    
    size_t words = (key_size / 8 + 3) / 4;
    
    pvt_key->n = asm_rsa_bignum_new(words);
    pvt_key->d = asm_rsa_bignum_new(words);
    pvt_key->p = asm_rsa_bignum_new(words / 2);
    pvt_key->q = asm_rsa_bignum_new(words / 2);
    pvt_key->dp = asm_rsa_bignum_new(words / 2);
    pvt_key->dq = asm_rsa_bignum_new(words / 2);
    pvt_key->qinv = asm_rsa_bignum_new(words / 2);
    
    if (!pvt_key->n || !pvt_key->d || !pvt_key->p || !pvt_key->q ||
        !pvt_key->dp || !pvt_key->dq || !pvt_key->qinv) {
        asm_rsa_pvt_key_free(pvt_key);
        return NULL;
    }
    
    pvt_key->key_size = key_size;
    return pvt_key;
}

void asm_rsa_pvt_key_free(asm_rsa_pvt_key_t *pvt_key) {
    if (pvt_key) {
        asm_rsa_bignum_free(pvt_key->n);
        asm_rsa_bignum_free(pvt_key->d);
        asm_rsa_bignum_free(pvt_key->p);
        asm_rsa_bignum_free(pvt_key->q);
        asm_rsa_bignum_free(pvt_key->dp);
        asm_rsa_bignum_free(pvt_key->dq);
        asm_rsa_bignum_free(pvt_key->qinv);
        free(pvt_key);
    }
}

int asm_rsa_ctx_init(asm_rsa_ctx_t *ctx, size_t key_size) {
    if (!ctx) return RSA_ERR_INVALID_PARAM;
    
    if (key_size != RSA_KEY_SIZE_512 && key_size != RSA_KEY_SIZE_1024 &&
        key_size != RSA_KEY_SIZE_2048 && key_size != RSA_KEY_SIZE_4096) {
        return RSA_ERR_INVALID_KEY_LENGTH;
    }
    
    memset(ctx, 0, sizeof(asm_rsa_ctx_t));
    ctx->key_size = key_size;
    ctx->padding_mode = 1; // PKCS#1 v1.5
    
    return RSA_SUCCESS;
}

void asm_rsa_ctx_free(asm_rsa_ctx_t *ctx) {
    if (ctx) {
        asm_rsa_pub_key_free(ctx->pub_key);
        asm_rsa_pvt_key_free(ctx->pvt_key);
        memset(ctx, 0, sizeof(asm_rsa_ctx_t));
    }
}

// Simplified key generation (for demonstration)
int asm_rsa_generate_keypair(asm_rsa_ctx_t *ctx, size_t key_size) {
    if (!ctx) return RSA_ERR_INVALID_PARAM;
    
    if (key_size != RSA_KEY_SIZE_512 && key_size != RSA_KEY_SIZE_1024 &&
        key_size != RSA_KEY_SIZE_2048 && key_size != RSA_KEY_SIZE_4096) {
        return RSA_ERR_INVALID_KEY_LENGTH;
    }
    
    // Free existing keys if any
    if (ctx->pub_key) asm_rsa_pub_key_free(ctx->pub_key);
    if (ctx->pvt_key) asm_rsa_pvt_key_free(ctx->pvt_key);
    
    // Allocate new keys
    ctx->pub_key = asm_rsa_pub_key_new(key_size);
    ctx->pvt_key = asm_rsa_pvt_key_new(key_size);
    
    if (!ctx->pub_key || !ctx->pvt_key) {
        return RSA_ERR_MEMORY;
    }
    
    ctx->key_size = key_size;
    
    // Generate random key material (simplified for demonstration)
    // In production: generate two large primes p and q, compute n = p*q, etc.
    
    size_t n_bytes = key_size / 8;
    uint8_t *n_data = malloc(n_bytes);
    uint8_t *e_data = malloc(4);
    uint8_t *d_data = malloc(n_bytes);
    
    if (!n_data || !e_data || !d_data) {
        free(n_data);
        free(e_data);
        free(d_data);
        return RSA_ERR_MEMORY;
    }
    
    // Generate random n (modulus) - ensuring it's odd and large
    random_bytes(n_data, n_bytes);
    n_data[0] |= 0x80;  // Ensure MSB is set (number is large)
    n_data[n_bytes - 1] |= 0x01;  // Ensure LSB is set (number is odd)
    
    // Set e = 65537 (common choice for public exponent)
    e_data[0] = 0x01;
    e_data[1] = 0x00;
    e_data[2] = 0x01;
    e_data[3] = 0x00;
    
    // Generate random d (private exponent)
    random_bytes(d_data, n_bytes);
    d_data[0] |= 0x80;
    
    // Set the public key
    asm_rsa_bignum_from_bytes(ctx->pub_key->n, n_data, n_bytes);
    asm_rsa_bignum_from_bytes(ctx->pub_key->e, e_data, 4);
    
    // Set the private key
    asm_rsa_bignum_from_bytes(ctx->pvt_key->n, n_data, n_bytes);
    asm_rsa_bignum_from_bytes(ctx->pvt_key->d, d_data, n_bytes);
    
    // Generate p and q (simplified - should be proper primes)
    size_t half_bytes = n_bytes / 2;
    uint8_t *p_data = malloc(half_bytes);
    uint8_t *q_data = malloc(half_bytes);
    
    if (p_data && q_data) {
        random_bytes(p_data, half_bytes);
        random_bytes(q_data, half_bytes);
        p_data[0] |= 0x80;
        q_data[0] |= 0x80;
        
        asm_rsa_bignum_from_bytes(ctx->pvt_key->p, p_data, half_bytes);
        asm_rsa_bignum_from_bytes(ctx->pvt_key->q, q_data, half_bytes);
    }
    
    free(n_data);
    free(e_data);
    free(d_data);
    free(p_data);
    free(q_data);
    
    return RSA_SUCCESS;
}

asm_rsa_pub_key_t *asm_rsa_get_pub_key(asm_rsa_ctx_t *ctx) {
    if (!ctx) return NULL;
    return ctx->pub_key;
}

asm_rsa_pvt_key_t *asm_rsa_get_pvt_key(asm_rsa_ctx_t *ctx) {
    if (!ctx) return NULL;
    return ctx->pvt_key;
}

// PADDING (PKCS#1 v1.5)

static int pkcs1_pad(const uint8_t *input, size_t input_len,
                     uint8_t *output, size_t output_len) {
    if (input_len + 11 > output_len) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    // PKCS#1 v1.5 padding: 0x00 || 0x02 || PS || 0x00 || M
    output[0] = 0x00;
    output[1] = 0x02;
    
    size_t ps_len = output_len - input_len - 3;
    
    // Generate non-zero random padding
    for (size_t i = 0; i < ps_len; i++) {
        do {
            random_bytes(&output[2 + i], 1);
        } while (output[2 + i] == 0);
    }
    
    output[2 + ps_len] = 0x00;
    memcpy(&output[3 + ps_len], input, input_len);
    
    return RSA_SUCCESS;
}

static int pkcs1_unpad(const uint8_t *input, size_t input_len,
                       uint8_t *output, size_t *output_len) {
    if (input_len < 11) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    // Check PKCS#1 v1.5 format
    if (input[0] != 0x00 || input[1] != 0x02) {
        return RSA_ERR_DECRYPTION_FAILED;
    }
    
    // Find the 0x00 separator
    size_t i = 2;
    while (i < input_len && input[i] != 0x00) {
        i++;
    }
    
    if (i >= input_len) {
        return RSA_ERR_DECRYPTION_FAILED;
    }
    
    i++; // Skip the 0x00
    size_t msg_len = input_len - i;
    
    if (msg_len > *output_len) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    memcpy(output, &input[i], msg_len);
    *output_len = msg_len;
    
    return RSA_SUCCESS;
}

// ENCRYPTION AND DECRYPTION

int asm_rsa_encryption(const asm_rsa_pub_key_t *pub_key,
                       const uint8_t *plaintext,
                       size_t plaintext_len,
                       uint8_t *ciphertext,
                       size_t *ciphertext_len) {
    if (!pub_key || !plaintext || !ciphertext || !ciphertext_len) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    size_t key_bytes = pub_key->key_size / 8;
    size_t max_msg_size = key_bytes - 11;
    
    if (plaintext_len > max_msg_size) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    if (*ciphertext_len < key_bytes) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    // Allocate padded message buffer
    uint8_t *padded = malloc(key_bytes);
    if (!padded) return RSA_ERR_MEMORY;
    
    // Apply PKCS#1 padding
    int ret = pkcs1_pad(plaintext, plaintext_len, padded, key_bytes);
    if (ret != RSA_SUCCESS) {
        free(padded);
        return ret;
    }
    
    // Convert padded message to bignum
    asm_rsa_bignum_t *m = asm_rsa_bignum_new((key_bytes + 3) / 4);
    asm_rsa_bignum_t *c = asm_rsa_bignum_new((key_bytes + 3) / 4);
    
    if (!m || !c) {
        free(padded);
        asm_rsa_bignum_free(m);
        asm_rsa_bignum_free(c);
        return RSA_ERR_MEMORY;
    }
    
    asm_rsa_bignum_from_bytes(m, padded, key_bytes);
    
    // Perform RSA encryption: c = m^e mod n
    ret = bignum_mod_exp(c, m, pub_key->e, pub_key->n);
    
    if (ret == RSA_SUCCESS) {
        ret = asm_rsa_bignum_to_bytes(c, ciphertext, key_bytes);
        if (ret >= 0) {
            *ciphertext_len = key_bytes;
            ret = RSA_SUCCESS;
        }
    }
    
    free(padded);
    asm_rsa_bignum_free(m);
    asm_rsa_bignum_free(c);
    
    return ret;
}

int asm_rsa_decryption(const asm_rsa_pvt_key_t *pvt_key,
                       const uint8_t *ciphertext,
                       size_t ciphertext_len,
                       uint8_t *plaintext,
                       size_t *plaintext_len) {
    if (!pvt_key || !ciphertext || !plaintext || !plaintext_len) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    size_t key_bytes = pvt_key->key_size / 8;
    
    if (ciphertext_len != key_bytes) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    // Convert ciphertext to bignum
    asm_rsa_bignum_t *c = asm_rsa_bignum_new((key_bytes + 3) / 4);
    asm_rsa_bignum_t *m = asm_rsa_bignum_new((key_bytes + 3) / 4);
    
    if (!c || !m) {
        asm_rsa_bignum_free(c);
        asm_rsa_bignum_free(m);
        return RSA_ERR_MEMORY;
    }
    
    asm_rsa_bignum_from_bytes(c, ciphertext, ciphertext_len);
    
    // Perform RSA decryption: m = c^d mod n
    int ret = bignum_mod_exp(m, c, pvt_key->d, pvt_key->n);
    
    if (ret == RSA_SUCCESS) {
        uint8_t *padded = malloc(key_bytes);
        if (!padded) {
            asm_rsa_bignum_free(c);
            asm_rsa_bignum_free(m);
            return RSA_ERR_MEMORY;
        }
        
        ret = asm_rsa_bignum_to_bytes(m, padded, key_bytes);
        
        if (ret >= 0) {
            // Remove PKCS#1 padding
            ret = pkcs1_unpad(padded, key_bytes, plaintext, plaintext_len);
        }
        
        free(padded);
    }
    
    asm_rsa_bignum_free(c);
    asm_rsa_bignum_free(m);
    
    return ret;
}