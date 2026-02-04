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
int random_bytes(uint8_t *buf, size_t len) {
    static int seeded = 0;  // Added static keyword
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
    return RSA_SUCCESS;
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

/**
 * @brief Get the bit length of a bignum
 */
size_t bignum_bitlen(const asm_rsa_bignum_t *bn) {
    if (bn->used == 0 || (bn->used == 1 && bn->data[0] == 0)) {
        return 0;
    }
    
    size_t bits = (bn->used - 1) * 32;
    uint32_t top = bn->data[bn->used - 1];
    
    while (top) {
        bits++;
        top >>= 1;
    }
    
    return bits;
}

/**
 * @brief Shift bignum left by n bits (multiply by 2^n)
 */
void bignum_shift_left(asm_rsa_bignum_t *result, 
                              const asm_rsa_bignum_t *a, 
                              size_t shift_bits) {
    if (shift_bits == 0) {
        bignum_copy(result, a);
        return;
    }
    
    size_t word_shift = shift_bits / 32;
    size_t bit_shift = shift_bits % 32;
    
    memset(result->data, 0, result->size * sizeof(uint32_t));
    
    if (bit_shift == 0) {
        // Simple word shift
        for (size_t i = 0; i < a->used && (i + word_shift) < result->size; i++) {
            result->data[i + word_shift] = a->data[i];
        }
        result->used = a->used + word_shift;
    } else {
        // Bit shift with carry
        uint32_t carry = 0;
        for (size_t i = 0; i < a->used && (i + word_shift) < result->size; i++) {
            uint64_t val = ((uint64_t)a->data[i] << bit_shift) | carry;
            result->data[i + word_shift] = (uint32_t)(val & 0xFFFFFFFF);
            carry = (uint32_t)(val >> 32);
        }
        if (carry && (a->used + word_shift) < result->size) {
            result->data[a->used + word_shift] = carry;
            result->used = a->used + word_shift + 1;
        } else {
            result->used = a->used + word_shift;
        }
    }
    
    bignum_trim(result);
}

/**
 * @brief Efficient binary long division
 * Computes quotient and remainder: dividend = divisor * quotient + remainder
 * 
 * @param quotient Output quotient (can be NULL if not needed)
 * @param remainder Output remainder  
 * @param dividend Input dividend
 * @param divisor Input divisor
 * @return RSA_SUCCESS on success, negative on failure
 */
int bignum_div(asm_rsa_bignum_t *quotient,
                      asm_rsa_bignum_t *remainder,
                      const asm_rsa_bignum_t *dividend,
                      const asm_rsa_bignum_t *divisor) {
    if (!remainder || !dividend || !divisor) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    // Check for division by zero
    if (divisor->used == 0 || (divisor->used == 1 && divisor->data[0] == 0)) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    // If dividend < divisor, quotient = 0, remainder = dividend
    if (bignum_cmp(dividend, divisor) < 0) {
        if (quotient) {
            memset(quotient->data, 0, quotient->size * sizeof(uint32_t));
            quotient->data[0] = 0;
            quotient->used = 1;
        }
        bignum_copy(remainder, dividend);
        return RSA_SUCCESS;
    }
    
    // If divisor = 1, quotient = dividend, remainder = 0
    if (divisor->used == 1 && divisor->data[0] == 1) {
        if (quotient) {
            bignum_copy(quotient, dividend);
        }
        memset(remainder->data, 0, remainder->size * sizeof(uint32_t));
        remainder->data[0] = 0;
        remainder->used = 1;
        return RSA_SUCCESS;
    }
    
    // Binary long division algorithm
    size_t dividend_bits = bignum_bitlen(dividend);
    size_t divisor_bits = bignum_bitlen(divisor);
    
    // Allocate temporaries
    asm_rsa_bignum_t *temp_divisor = asm_rsa_bignum_new(dividend->size * 2);
    asm_rsa_bignum_t *temp_remainder = asm_rsa_bignum_new(dividend->size * 2);
    
    if (!temp_divisor || !temp_remainder) {
        asm_rsa_bignum_free(temp_divisor);
        asm_rsa_bignum_free(temp_remainder);
        return RSA_ERR_MEMORY;
    }
    
    // Initialize
    bignum_copy(temp_remainder, dividend);
    
    if (quotient) {
        memset(quotient->data, 0, quotient->size * sizeof(uint32_t));
        quotient->used = 1;
    }
    
    // Align divisor to dividend
    size_t shift = dividend_bits - divisor_bits;
    bignum_shift_left(temp_divisor, divisor, shift);
    
    // Long division
    for (size_t i = 0; i <= shift; i++) {
        // If remainder >= shifted divisor
        if (bignum_cmp(temp_remainder, temp_divisor) >= 0) {
            // Subtract
            bignum_sub(temp_remainder, temp_remainder, temp_divisor);
            
            // Set bit in quotient
            if (quotient) {
                size_t bit_pos = shift - i;
                size_t word_idx = bit_pos / 32;
                size_t bit_idx = bit_pos % 32;
                
                if (word_idx < quotient->size) {
                    quotient->data[word_idx] |= (1U << bit_idx);
                    if (word_idx >= quotient->used) {
                        quotient->used = word_idx + 1;
                    }
                }
            }
        }
        
        // Shift divisor right by 1
        if (i < shift) {
            uint32_t carry = 0;
            for (size_t j = temp_divisor->used; j > 0; j--) {
                size_t idx = j - 1;
                uint32_t new_carry = (temp_divisor->data[idx] & 1) ? 0x80000000 : 0;
                temp_divisor->data[idx] = (temp_divisor->data[idx] >> 1) | carry;
                carry = new_carry;
            }
            bignum_trim(temp_divisor);
        }
    }
    
    // Copy remainder
    bignum_copy(remainder, temp_remainder);
    
    // Trim quotient
    if (quotient) {
        bignum_trim(quotient);
    }
    
    // Cleanup
    asm_rsa_bignum_free(temp_divisor);
    asm_rsa_bignum_free(temp_remainder);
    
    return RSA_SUCCESS;
}

// CONTEXT MANAGEMENT

int asm_rsa_ctx_init(asm_rsa_ctx_t *ctx, size_t key_size) {
    if (!ctx) return RSA_ERR_INVALID_PARAM;
    
    if (key_size != RSA_KEY_SIZE_512 && key_size != RSA_KEY_SIZE_1024 &&
        key_size != RSA_KEY_SIZE_2048 && key_size != RSA_KEY_SIZE_4096) {
        return RSA_ERR_INVALID_KEY_LENGTH;
    }
    
    memset(ctx, 0, sizeof(asm_rsa_ctx_t));
    ctx->key_size = key_size;
    ctx->decrypt_mode = RSA_DECRYPT_STANDARD;
    ctx->padding_mode = 1; // PKCS#1 v1.5

    ctx->pub_key = asm_rsa_pub_key_new(key_size);
    ctx->pvt_key = asm_rsa_pvt_key_new(key_size);

    if (!ctx->pub_key || !ctx->pvt_key) {
        asm_rsa_pub_key_free(ctx->pub_key);
        asm_rsa_pvt_key_free(ctx->pvt_key);
        ctx->pub_key = NULL;
        ctx->pvt_key = NULL;
        return RSA_ERR_MEMORY;
    }
    
    return RSA_SUCCESS;
}

void asm_rsa_ctx_free(asm_rsa_ctx_t *ctx) {
    if (ctx) {
        asm_rsa_pub_key_free(ctx->pub_key);
        asm_rsa_pvt_key_free(ctx->pvt_key);
        memset(ctx, 0, sizeof(asm_rsa_ctx_t));
    }
}

/**
 * @brief Set decryption mode for the context
 */
int asm_rsa_set_decrypt_mode(asm_rsa_ctx_t *ctx, RSA_DECRYPT_MODE mode) {
    if (!ctx) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    if (mode != RSA_DECRYPT_STANDARD && mode != RSA_DECRYPT_CRT) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    ctx->decrypt_mode = mode;
    return RSA_SUCCESS;
}

/**
 * @brief Get current decryption mode
 */
RSA_DECRYPT_MODE asm_rsa_get_decrypt_mode(const asm_rsa_ctx_t *ctx) {
    if (!ctx) {
        return RSA_DECRYPT_STANDARD;
    }
    return ctx->decrypt_mode;
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

    // Trim leading zeros
    while (bn->used > 1 && bn->data[bn->used - 1] == 0) {
        bn->used--;
    }
    
    return RSA_SUCCESS;
}

int asm_rsa_bignum_to_bytes(const asm_rsa_bignum_t *bn, uint8_t *data, size_t len) {
    if (!bn || !data) return RSA_ERR_INVALID_PARAM;
    
    // Always zero the entire buffer first to handle padding/zeros
    memset(data, 0, len);
    
    // Calculate how many words we actually have
    size_t actual_words = bn->used;
    while (actual_words > 0 && bn->data[actual_words - 1] == 0) {
        actual_words--;
    }
    
    if (actual_words == 0) return len; // Buffer is already all zeros

    // Write bytes from the bignum into the END of the data buffer (Big-Endian)
    for (size_t i = 0; i < actual_words; i++) {
        uint32_t word = bn->data[i];
        for (int j = 0; j < 4; j++) {
            size_t byte_pos = (i * 4) + j;
            if (byte_pos < len) {
                data[len - 1 - byte_pos] = (word >> (j * 8)) & 0xFF;
            }
        }
    }
    return len;
}
// BIGNUM ARITHMETIC OPERATIONS

/**
 * @brief Compare two bignums
 * @return 1 if a > b, -1 if a < b, 0 if equal
 */
int bignum_cmp(const asm_rsa_bignum_t *a, const asm_rsa_bignum_t *b) {
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
void bignum_copy(asm_rsa_bignum_t *dst, const asm_rsa_bignum_t *src) {
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
void bignum_trim(asm_rsa_bignum_t *bn) {
    while (bn->used > 0 && bn->data[bn->used - 1] == 0) {
        bn->used--;
    }
}

/**
 * @brief Add two bignums: result = a + b
 */
int bignum_add(asm_rsa_bignum_t *result, 
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
int bignum_sub(asm_rsa_bignum_t *result,
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
int bignum_mul(asm_rsa_bignum_t *result,
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
 * OPTIMIZED: Uses binary long division instead of repeated subtraction
 */
int bignum_mod(asm_rsa_bignum_t *result,
                      const asm_rsa_bignum_t *a,
                      const asm_rsa_bignum_t *m) {
    if (!result || !a || !m) return RSA_ERR_INVALID_PARAM;

    if (bignum_cmp(a, m) < 0) {
        bignum_copy(result, a);
        return RSA_SUCCESS;
    }
    
    // Special case: if m is small enough, use simple repeated subtraction
    // This is safe because we're only iterating a bounded number of times
    if (m->used == 1 && a->used <= 2) {
        asm_rsa_bignum_t *temp = asm_rsa_bignum_new(a->used + 1);
        if (!temp) return RSA_ERR_MEMORY;
        
        bignum_copy(temp, a);
        
        // Safe: at most ~2^64 / m iterations, with safety counter
        int safety_counter = 0;
        while (bignum_cmp(temp, m) >= 0 && safety_counter++ < 1000000) {
            bignum_sub(temp, temp, m);
        }
        
        bignum_copy(result, temp);
        asm_rsa_bignum_free(temp);
        return RSA_SUCCESS;
    }
    
    // For large numbers, use binary long division (much faster!)
    asm_rsa_bignum_t *remainder = asm_rsa_bignum_new(a->used + 1);
    if (!remainder) return RSA_ERR_MEMORY;
    
    bignum_copy(remainder, a);
    
    // Count significant bits in a and m
    int a_bits = (a->used - 1) * 32;
    for (int i = 31; i >= 0; i--) {
        if (a->data[a->used - 1] & (1U << i)) {
            a_bits += i + 1;
            break;
        }
    }
    
    int m_bits = (m->used - 1) * 32;
    for (int i = 31; i >= 0; i--) {
        if (m->data[m->used - 1] & (1U << i)) {
            m_bits += i + 1;
            break;
        }
    }
    
    // Perform long division by repeatedly subtracting shifted versions of m
    for (int bit_pos = a_bits - m_bits; bit_pos >= 0; bit_pos--) {
        // Create (m << bit_pos)
        asm_rsa_bignum_t *shifted_m = asm_rsa_bignum_new(m->used + (bit_pos / 32) + 2);
        if (!shifted_m) {
            asm_rsa_bignum_free(remainder);
            return RSA_ERR_MEMORY;
        }
        
        // Shift m left by bit_pos bits
        int word_shift = bit_pos / 32;
        int bit_shift = bit_pos % 32;
        
        memset(shifted_m->data, 0, shifted_m->size * sizeof(uint32_t));
        
        if (bit_shift == 0) {
            // Word-aligned shift (fast path)
            for (size_t i = 0; i < m->used; i++) {
                shifted_m->data[i + word_shift] = m->data[i];
            }
            shifted_m->used = m->used + word_shift;
        } else {
            // Bit shift within words
            uint32_t carry = 0;
            for (size_t i = 0; i < m->used; i++) {
                uint64_t val = ((uint64_t)m->data[i] << bit_shift) | carry;
                shifted_m->data[i + word_shift] = (uint32_t)(val & 0xFFFFFFFF);
                carry = (uint32_t)(val >> 32);
            }
            if (carry) {
                shifted_m->data[m->used + word_shift] = carry;
                shifted_m->used = m->used + word_shift + 1;
            } else {
                shifted_m->used = m->used + word_shift;
            }
        }
        
        bignum_trim(shifted_m);
        
        // If remainder >= shifted_m, subtract it
        if (bignum_cmp(remainder, shifted_m) >= 0) {
            bignum_sub(remainder, remainder, shifted_m);
        }
        
        asm_rsa_bignum_free(shifted_m);
    }
    
    bignum_copy(result, remainder);
    asm_rsa_bignum_free(remainder);
    
    return RSA_SUCCESS;
}

/**
 * @brief Modular multiplication: result = (a * b) mod m
 */
int bignum_mul_mod(asm_rsa_bignum_t *result,
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
int bignum_mod_exp(asm_rsa_bignum_t *result, 
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
    asm_rsa_bignum_t *temp_mul = asm_rsa_bignum_new(mod->used * 2 + 1);
    
    if (!temp_base || !temp_result) {
        asm_rsa_bignum_free(temp_base);
        asm_rsa_bignum_free(temp_result);
        asm_rsa_bignum_free(temp_mul);
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
                int ret = bignum_mul_mod(temp_mul, temp_result, temp_base, mod);
                if (ret != RSA_SUCCESS) {
                    asm_rsa_bignum_free(temp_base);
                    asm_rsa_bignum_free(temp_result);
                    asm_rsa_bignum_free(temp_mul);
                    return ret;
                }
                bignum_copy(temp_result, temp_mul);
            }
            
            // base = (base * base) mod m
            int ret = bignum_mul_mod(temp_mul, temp_base, temp_base, mod);
            if (ret != RSA_SUCCESS) {
                asm_rsa_bignum_free(temp_base);
                asm_rsa_bignum_free(temp_result);
                asm_rsa_bignum_free(temp_mul);
                return ret;
            }
            bignum_copy(temp_base, temp_mul);
            
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
    asm_rsa_bignum_free(temp_mul);
    
    return RSA_SUCCESS;
}

/**
 * @brief Extended Euclidean Algorithm
 * Computes gcd(a,b) and coefficients x,y such that ax + by = gcd(a,b)
 */
int extended_gcd(asm_rsa_bignum_t *gcd,
                        asm_rsa_bignum_t *x,
                        asm_rsa_bignum_t *y,
                        const asm_rsa_bignum_t *a,
                        const asm_rsa_bignum_t *b) {
    if (!gcd || !x || !y || !a || !b) return RSA_ERR_INVALID_PARAM;
    
    size_t max_size = (a->used > b->used) ? a->used : b->used;
    max_size = (max_size > gcd->size) ? gcd->size : max_size;
    
    asm_rsa_bignum_t *old_r = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *r = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *old_s = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *s = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *old_t = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *t = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *quotient = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *temp = asm_rsa_bignum_new(max_size * 2 + 2);
    asm_rsa_bignum_t *temp2 = asm_rsa_bignum_new(max_size * 2 + 2);
    
    if (!old_r || !r || !old_s || !s || !old_t || !t || !quotient || !temp || !temp2) {
        asm_rsa_bignum_free(old_r); asm_rsa_bignum_free(r);
        asm_rsa_bignum_free(old_s); asm_rsa_bignum_free(s);
        asm_rsa_bignum_free(old_t); asm_rsa_bignum_free(t);
        asm_rsa_bignum_free(quotient); asm_rsa_bignum_free(temp);
        asm_rsa_bignum_free(temp2);
        return RSA_ERR_MEMORY;
    }
    
    bignum_copy(old_r, a);
    bignum_copy(r, b);
    
    old_s->data[0] = 1; old_s->used = 1;
    s->data[0] = 0; s->used = 1;
    old_t->data[0] = 0; old_t->used = 1;
    t->data[0] = 1; t->used = 1;
    
    while (!(r->used == 1 && r->data[0] == 0)) {
        // Use efficient division instead of repeated subtraction
        int ret = bignum_div(quotient, temp, old_r, r);
        if (ret != RSA_SUCCESS) {
            asm_rsa_bignum_free(old_r); asm_rsa_bignum_free(r);
            asm_rsa_bignum_free(old_s); asm_rsa_bignum_free(s);
            asm_rsa_bignum_free(old_t); asm_rsa_bignum_free(t);
            asm_rsa_bignum_free(quotient); asm_rsa_bignum_free(temp);
            asm_rsa_bignum_free(temp2);
            return ret;
        }
        
        // Now temp = old_r mod r (remainder from bignum_div)
        
        // Update: (old_r, r) = (r, old_r mod r)
        asm_rsa_bignum_t *new_r = temp;
        bignum_copy(old_r, r);
        bignum_copy(r, new_r);
        
        // Update: (old_s, s) = (s, old_s - quotient * s)
        bignum_mul(temp2, quotient, s);
        if (bignum_cmp(old_s, temp2) >= 0) {
            bignum_sub(temp, old_s, temp2);
        } else {
            memset(temp->data, 0, temp->size * sizeof(uint32_t));
            temp->used = 1;
        }
        bignum_copy(old_s, s);
        bignum_copy(s, temp);
        
        // Update: (old_t, t) = (t, old_t - quotient * t)
        bignum_mul(temp2, quotient, t);
        if (bignum_cmp(old_t, temp2) >= 0) {
            bignum_sub(temp, old_t, temp2);
        } else {
            memset(temp->data, 0, temp->size * sizeof(uint32_t));
            temp->used = 1;
        }
        bignum_copy(old_t, t);
        bignum_copy(t, temp);
    }
    
    bignum_copy(gcd, old_r);
    bignum_copy(x, old_s);
    bignum_copy(y, old_t);
    
    asm_rsa_bignum_free(old_r); asm_rsa_bignum_free(r);
    asm_rsa_bignum_free(old_s); asm_rsa_bignum_free(s);
    asm_rsa_bignum_free(old_t); asm_rsa_bignum_free(t);
    asm_rsa_bignum_free(quotient); asm_rsa_bignum_free(temp);
    asm_rsa_bignum_free(temp2);
    
    return RSA_SUCCESS;
}

/**
 * @brief Compute modular inverse: result = a^(-1) mod m
 */
int bignum_mod_inverse(asm_rsa_bignum_t *result,
                              const asm_rsa_bignum_t *a,
                              const asm_rsa_bignum_t *m) {
    if (!result || !a || !m) return RSA_ERR_INVALID_PARAM;
    
    size_t max_size = (a->used > m->used) ? a->used : m->used;
    
    asm_rsa_bignum_t *gcd = asm_rsa_bignum_new(max_size + 1);
    asm_rsa_bignum_t *x = asm_rsa_bignum_new(max_size * 2 + 2);
    asm_rsa_bignum_t *y = asm_rsa_bignum_new(max_size * 2 + 2);
    
    if (!gcd || !x || !y) {
        asm_rsa_bignum_free(gcd);
        asm_rsa_bignum_free(x);
        asm_rsa_bignum_free(y);
        return RSA_ERR_MEMORY;
    }
    
    int ret = extended_gcd(gcd, x, y, a, m);
    if (ret != RSA_SUCCESS) {
        asm_rsa_bignum_free(gcd);
        asm_rsa_bignum_free(x);
        asm_rsa_bignum_free(y);
        return ret;
    }
    
    // Check if gcd == 1 (inverse exists)
    if (gcd->used != 1 || gcd->data[0] != 1) {
        asm_rsa_bignum_free(gcd);
        asm_rsa_bignum_free(x);
        asm_rsa_bignum_free(y);
        return RSA_ERR_INVALID_PARAM;
    }
    
    // x might be negative, so compute x mod m
    bignum_mod(result, x, m);
    
    asm_rsa_bignum_free(gcd);
    asm_rsa_bignum_free(x);
    asm_rsa_bignum_free(y);
    
    return RSA_SUCCESS;
}

// PRIME NUMBER GENERATION

/**
 * @brief Check if number is divisible by small primes (trial division)
 * @param n Number to test
 * @return 1 if possibly prime (passed trial division), 0 if definitely composite
 */
int trial_division(const asm_rsa_bignum_t *n) {
    // First 100 primes - eliminates ~77% of composite numbers quickly
    const uint32_t small_primes[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
        157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
        331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
        509, 521, 523, 541
    };
    
    const size_t num_primes = sizeof(small_primes) / sizeof(small_primes[0]);
    
    // Special case: check if n is 0 or 1
    if (n->used == 0 || (n->used == 1 && n->data[0] <= 1)) {
        return 0;
    }
    
    // Check each small prime
    for (size_t i = 0; i < num_primes; i++) {
        uint32_t prime = small_primes[i];
        
        // If n equals this small prime, it's prime
        if (n->used == 1 && n->data[0] == prime) {
            return 1;
        }
        
        // Check if n % prime == 0 using long division
        uint64_t remainder = 0;
        for (int j = n->used - 1; j >= 0; j--) {
            remainder = (remainder << 32) | n->data[j];
            remainder %= prime;
        }
        
        if (remainder == 0) {
            return 0; // Divisible by this prime, definitely composite
        }
    }
    
    return 1; // Passed all trial divisions, might be prime
}


/**
 * @brief Miller-Rabin primality test
 * @param n Number to test for primality
 * @param rounds Number of test rounds (more rounds = higher confidence)
 * @return 1 if probably prime, 0 if composite
 */
int miller_rabin(const asm_rsa_bignum_t *n, int rounds) {
    if (!n) return 0;
    
    // Handle small cases
    if (n->used == 1) {
        uint32_t val = n->data[0];
        if (val < 2) return 0;
        if (val == 2 || val == 3) return 1;
        if (val % 2 == 0) return 0;
    }
    
    // Check if even
    if ((n->data[0] & 1) == 0) return 0;
    
    // Write n-1 as 2^r * d
    asm_rsa_bignum_t *n_minus_1 = asm_rsa_bignum_new(n->size);
    asm_rsa_bignum_t *one = asm_rsa_bignum_new(2);
    asm_rsa_bignum_t *d = asm_rsa_bignum_new(n->size);
    
    if (!n_minus_1 || !one || !d) {
        asm_rsa_bignum_free(n_minus_1);
        asm_rsa_bignum_free(one);
        asm_rsa_bignum_free(d);
        return 0;
    }
    
    one->data[0] = 1;
    one->used = 1;
    
    bignum_sub(n_minus_1, n, one);
    bignum_copy(d, n_minus_1);
    
    int r = 0;
    while ((d->data[0] & 1) == 0) {
        // d = d / 2
        uint64_t carry = 0;
        for (int i = d->used - 1; i >= 0; i--) {
            uint64_t val = ((uint64_t)carry << 32) | d->data[i];
            d->data[i] = (uint32_t)(val >> 1);
            carry = val & 1;
        }
        bignum_trim(d);
        r++;
    }
    
    // Perform rounds of Miller-Rabin
    for (int round = 0; round < rounds; round++) {
        // Generate random a in [2, n-2]
        asm_rsa_bignum_t *a = asm_rsa_bignum_new(n->size);
        if (!a) break;
        
        uint8_t *rand_bytes = malloc(n->used * 4);
        if (!rand_bytes) {
            asm_rsa_bignum_free(a);
            break;
        }
        
        random_bytes(rand_bytes, n->used * 4);
        asm_rsa_bignum_from_bytes(a, rand_bytes, n->used * 4);
        free(rand_bytes);
        
        // Ensure a is in range [2, n-2]
        bignum_mod(a, a, n);
        if (bignum_cmp(a, one) <= 0) {
            a->data[0] = 2;
            a->used = 1;
        }
        
        // x = a^d mod n
        asm_rsa_bignum_t *x = asm_rsa_bignum_new(n->size * 2);
        if (!x) {
            asm_rsa_bignum_free(a);
            break;
        }
        
        bignum_mod_exp(x, a, d, n);
        
        // Check if x == 1 or x == n-1
        if (bignum_cmp(x, one) == 0 || bignum_cmp(x, n_minus_1) == 0) {
            asm_rsa_bignum_free(a);
            asm_rsa_bignum_free(x);
            continue;
        }
        
        int is_prime = 0;
        for (int i = 0; i < r - 1; i++) {
            // x = x^2 mod n
            bignum_mul_mod(x, x, x, n);
            
            if (bignum_cmp(x, n_minus_1) == 0) {
                is_prime = 1;
                break;
            }
        }
        
        asm_rsa_bignum_free(a);
        asm_rsa_bignum_free(x);
        
        if (!is_prime) {
            asm_rsa_bignum_free(n_minus_1);
            asm_rsa_bignum_free(one);
            asm_rsa_bignum_free(d);
            return 0; // Composite
        }
    }
    
    asm_rsa_bignum_free(n_minus_1);
    asm_rsa_bignum_free(one);
    asm_rsa_bignum_free(d);
    
    return 1; // Probably prime
}

/**
 * @brief Generate a random prime number of specified bit length
 */
int generate_prime(asm_rsa_bignum_t *prime, size_t bits) {
    if (!prime) return RSA_ERR_INVALID_PARAM;
    
    size_t bytes = (bits + 7) / 8;
    uint8_t *rand_bytes = malloc(bytes);
    if (!rand_bytes) return RSA_ERR_MEMORY;
    
    int max_attempts = 10000;  // Increased from 1000
    int attempts = 0;
    int trial_division_passes = 0;
    int miller_rabin_tests = 0;
    
    while (attempts < max_attempts) {
        // Generate random bytes
        random_bytes(rand_bytes, bytes);
        
        // Set MSB to ensure number is large enough
        rand_bytes[0] |= 0x80;
        
        // Set LSB to ensure number is odd
        rand_bytes[bytes - 1] |= 0x01;
        
        // Convert to bignum
        asm_rsa_bignum_from_bytes(prime, rand_bytes, bytes);
        
        // OPTIMIZATION: Trial division first (very fast, eliminates ~77% of composites)
        if (!trial_division(prime)) {
            attempts++;
            continue;  // Failed trial division, try next candidate
        }
        
        trial_division_passes++;
        
        // Only run expensive Miller-Rabin if passed trial division
        miller_rabin_tests++;
        if (miller_rabin(prime, 5)) {  // Reduced from 10 to 5 for faster testing
            printf("    Found prime after %d attempts (%d passed trial division, %d Miller-Rabin tests)\n",
                   attempts, trial_division_passes, miller_rabin_tests);
            free(rand_bytes);
            return RSA_SUCCESS;
        }
        
        attempts++;
    }
    
    printf("    Failed to find prime after %d attempts\n", attempts);
    free(rand_bytes);
    return RSA_ERR_KEY_GENERATION_FAILED;
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

// RSA KEY GENERATION

/**
 * @brief Generate proper RSA key pair with correct mathematical relationships
 * 
 * This implementation:
 * 1. Generates two distinct primes p and q
 * 2. Computes n = p * q
 * 3. Computes φ(n) = (p-1)(q-1)
 * 4. Uses e = 65537
 * 5. Computes d = e^(-1) mod φ(n)
 * 6. Computes CRT parameters for optimization
 */
int asm_rsa_generate_keypair(asm_rsa_ctx_t *ctx, size_t key_size) {
    if (!ctx) return RSA_ERR_INVALID_PARAM;
    
    if (key_size != RSA_KEY_SIZE_512 && key_size != RSA_KEY_SIZE_1024 &&
        key_size != RSA_KEY_SIZE_2048 && key_size != RSA_KEY_SIZE_4096) {
        return RSA_ERR_INVALID_KEY_LENGTH;
    }
    
    printf("Generating %zu-bit RSA key pair...\n", key_size);
    
    // Free existing keys
    if (ctx->pub_key) asm_rsa_pub_key_free(ctx->pub_key);
    if (ctx->pvt_key) asm_rsa_pvt_key_free(ctx->pvt_key);
    
    // Allocate new keys
    ctx->pub_key = asm_rsa_pub_key_new(key_size);
    ctx->pvt_key = asm_rsa_pvt_key_new(key_size);
    
    if (!ctx->pub_key || !ctx->pvt_key) {
        return RSA_ERR_MEMORY;
    }
    
    ctx->key_size = key_size;
    
    size_t half_bits = key_size / 2;
    
    // Step 1: Generate prime p
    printf("  Generating prime p (%zu bits)...\n", half_bits);
    int ret = generate_prime(ctx->pvt_key->p, half_bits);
    if (ret != RSA_SUCCESS) {
        printf("  Failed to generate prime p\n");
        return ret;
    }
    
    // Step 2: Generate prime q (different from p)
    printf("  Generating prime q (%zu bits)...\n", half_bits);
    int max_attempts = 10;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        ret = generate_prime(ctx->pvt_key->q, half_bits);
        if (ret != RSA_SUCCESS) continue;
        
        // Ensure q != p
        if (bignum_cmp(ctx->pvt_key->p, ctx->pvt_key->q) != 0) {
            break;
        }
    }
    
    if (bignum_cmp(ctx->pvt_key->p, ctx->pvt_key->q) == 0) {
        printf("  Failed to generate distinct prime q\n");
        return RSA_ERR_KEY_GENERATION_FAILED;
    }
    
    // Step 3: Compute n = p * q
    printf("  Computing n = p * q...\n");
    ret = bignum_mul(ctx->pub_key->n, ctx->pvt_key->p, ctx->pvt_key->q);
    if (ret != RSA_SUCCESS) {
        printf("  Failed to compute n\n");
        return ret;
    }
    bignum_copy(ctx->pvt_key->n, ctx->pub_key->n);
    
    // Step 4: Set e = 65537 (0x10001)
    printf("  Setting e = 65537...\n");
    ctx->pub_key->e->data[0] = 0x10001;
    ctx->pub_key->e->used = 1;
    
    // Step 5: Compute φ(n) = (p-1)(q-1)
    printf("  Computing φ(n) = (p-1)(q-1)...\n");
    asm_rsa_bignum_t *one = asm_rsa_bignum_new(2);
    asm_rsa_bignum_t *p_minus_1 = asm_rsa_bignum_new(ctx->pvt_key->p->size);
    asm_rsa_bignum_t *q_minus_1 = asm_rsa_bignum_new(ctx->pvt_key->q->size);
    asm_rsa_bignum_t *phi = asm_rsa_bignum_new(ctx->pub_key->n->size * 2);
    
    if (!one || !p_minus_1 || !q_minus_1 || !phi) {
        asm_rsa_bignum_free(one);
        asm_rsa_bignum_free(p_minus_1);
        asm_rsa_bignum_free(q_minus_1);
        asm_rsa_bignum_free(phi);
        return RSA_ERR_MEMORY;
    }
    
    one->data[0] = 1;
    one->used = 1;
    
    bignum_sub(p_minus_1, ctx->pvt_key->p, one);
    bignum_sub(q_minus_1, ctx->pvt_key->q, one);
    bignum_mul(phi, p_minus_1, q_minus_1);
    
    // Step 6: Compute d = e^(-1) mod φ(n)
    printf("  Computing d = e^(-1) mod φ(n)...\n");
    ret = bignum_mod_inverse(ctx->pvt_key->d, ctx->pub_key->e, phi);
    if (ret != RSA_SUCCESS) {
        printf("  Failed to compute d\n");
        asm_rsa_bignum_free(one);
        asm_rsa_bignum_free(p_minus_1);
        asm_rsa_bignum_free(q_minus_1);
        asm_rsa_bignum_free(phi);
        return ret;
    }
    
    // Step 7: Compute CRT parameters
    printf("  Computing CRT parameters...\n");
    
    // dp = d mod (p-1)
    bignum_mod(ctx->pvt_key->dp, ctx->pvt_key->d, p_minus_1);
    
    // dq = d mod (q-1)
    bignum_mod(ctx->pvt_key->dq, ctx->pvt_key->d, q_minus_1);
    
    // qinv = q^(-1) mod p
    ret = bignum_mod_inverse(ctx->pvt_key->qinv, ctx->pvt_key->q, ctx->pvt_key->p);
    
    asm_rsa_bignum_free(one);
    asm_rsa_bignum_free(p_minus_1);
    asm_rsa_bignum_free(q_minus_1);
    asm_rsa_bignum_free(phi);
    
    if (ret != RSA_SUCCESS) {
        printf("  Failed to compute qinv\n");
        return ret;
    }
    
    printf("  Key generation complete!\n");
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

int pkcs1_pad(const uint8_t *input, size_t input_len,
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

int pkcs1_unpad(const uint8_t *input, size_t input_len,
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
                       size_t *plaintext_len,
                       RSA_DECRYPT_MODE mode) {
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
    
    // Choose decryption method based on mode parameter
    int ret;

    switch (mode) {
        case RSA_DECRYPT_CRT:
            // CRT-optimized decryption (~4x faster)
            ret = rsa_decrypt_crt(m, c, pvt_key);
            break;

        case RSA_DECRYPT_STANDARD:
        default:
            // Standard RSA decryption: m = c^d mod n
            ret = bignum_mod_exp(m, c, pvt_key->d, pvt_key->n);
            break;
    }
    
    if (ret == RSA_SUCCESS) {
        uint8_t *padded = malloc(key_bytes);
        if (!padded) {
            asm_rsa_bignum_free(c);
            asm_rsa_bignum_free(m);
            return RSA_ERR_MEMORY;
        }
        
        ret = asm_rsa_bignum_to_bytes(m, padded, key_bytes);
        
        if (padded[0] != 0x00 || padded[1] != 0x02) {
            ret = RSA_ERR_DECRYPTION_FAILED; // -5
        } else {
            // Find the 0x00 separator after the PS (padding string)
            size_t i = 2;
            while (i < key_bytes && padded[i] != 0x00) {
                i++;
            }

            if (i >= key_bytes || i < 10) {
                ret = RSA_ERR_DECRYPTION_FAILED;
            } else {
                i++; // Move past the 0x00 separator
                size_t actual_len = key_bytes - i;
                memcpy(plaintext, &padded[i], actual_len);
                *plaintext_len = actual_len;
                ret = RSA_SUCCESS;
            }
        }

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

/**
 * @brief RSA decryption using Chinese Remainder Theorem (CRT)
 * This is approximately 4x faster than standard decryption
 */
int rsa_decrypt_crt(asm_rsa_bignum_t *m,
                          const asm_rsa_bignum_t *c,
                          const asm_rsa_pvt_key_t *key) {
    if (!m || !c || !key) return RSA_ERR_INVALID_PARAM;
    
    // m1 = c^dp mod p
    asm_rsa_bignum_t *m1 = asm_rsa_bignum_new(key->p->size * 2);
    // m2 = c^dq mod q
    asm_rsa_bignum_t *m2 = asm_rsa_bignum_new(key->q->size * 2);
    // h = (m1 - m2) * qinv mod p
    asm_rsa_bignum_t *h = asm_rsa_bignum_new(key->p->size * 2);
    asm_rsa_bignum_t *temp = asm_rsa_bignum_new(key->p->size * 2);
    
    if (!m1 || !m2 || !h || !temp) {
        asm_rsa_bignum_free(m1);
        asm_rsa_bignum_free(m2);
        asm_rsa_bignum_free(h);
        asm_rsa_bignum_free(temp);
        return RSA_ERR_MEMORY;
    }
    
    // Reduce c modulo p and q
    asm_rsa_bignum_t *c_mod_p = asm_rsa_bignum_new(key->p->size);
    asm_rsa_bignum_t *c_mod_q = asm_rsa_bignum_new(key->q->size);
    
    if (!c_mod_p || !c_mod_q) {
        asm_rsa_bignum_free(m1); asm_rsa_bignum_free(m2);
        asm_rsa_bignum_free(h); asm_rsa_bignum_free(temp);
        asm_rsa_bignum_free(c_mod_p); asm_rsa_bignum_free(c_mod_q);
        return RSA_ERR_MEMORY;
    }
    
    bignum_mod(c_mod_p, c, key->p);
    bignum_mod(c_mod_q, c, key->q);
    
    // m1 = c^dp mod p
    int ret = bignum_mod_exp(m1, c_mod_p, key->dp, key->p);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    // m2 = c^dq mod q
    ret = bignum_mod_exp(m2, c_mod_q, key->dq, key->q);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    // h = ((m1 - m2) mod p) * qinv mod p
    asm_rsa_bignum_t *m2_mod_p = asm_rsa_bignum_new(key->p->size + 1);
    if (!m2_mod_p) {
        ret = RSA_ERR_MEMORY;
        goto cleanup;
    }
    
    bignum_mod(m2_mod_p, m2, key->p);
    
    if (bignum_cmp(m1, m2_mod_p) >= 0) {
        bignum_sub(h, m1, m2_mod_p);
    } else {
        // m1 < m2_mod_p, so add p to m1 first to avoid negative result
        bignum_add(temp, m1, key->p);
        bignum_sub(h, temp, m2_mod_p);
    }
    
    asm_rsa_bignum_free(m2_mod_p);
    
    ret = bignum_mul_mod(h, h, key->qinv, key->p);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    // m = m2 + h * q
    ret = bignum_mul(temp, h, key->q);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    ret = bignum_add(m, m2, temp);
    
cleanup:
    asm_rsa_bignum_free(m1);
    asm_rsa_bignum_free(m2);
    asm_rsa_bignum_free(h);
    asm_rsa_bignum_free(temp);
    asm_rsa_bignum_free(c_mod_p);
    asm_rsa_bignum_free(c_mod_q);
    
    return ret;
}

// RSA SIGNATURES

/**
 * @brief Sign a message using RSA private key
 * @param pvt_key Private key for signing
 * @param message Message to sign
 * @param message_len Length of message
 * @param signature Output buffer for signature
 * @param signature_len Pointer to signature length (input: buffer size, output: actual size)
 * @return RSA_SUCCESS on success, negative on failure
 */
int asm_rsa_sign(const asm_rsa_pvt_key_t *pvt_key,
                 const uint8_t *message,
                 size_t message_len,
                 uint8_t *signature,
                 size_t *signature_len,
                 RSA_DECRYPT_MODE mode) {
    if (!pvt_key || !message || !signature || !signature_len) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    size_t key_bytes = pvt_key->key_size / 8;
    size_t max_msg_size = key_bytes - 11;
    
    if (message_len > max_msg_size) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    if (*signature_len < key_bytes) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    uint8_t *padded = malloc(key_bytes);
    if (!padded) return RSA_ERR_MEMORY;
    
    // PKCS#1 v1.5 padding for signatures (type 1)
    padded[0] = 0x00;
    padded[1] = 0x01; // Type 1 for signatures
    
    size_t ps_len = key_bytes - message_len - 3;
    memset(&padded[2], 0xFF, ps_len); // Padding with 0xFF for signatures
    
    padded[2 + ps_len] = 0x00;
    memcpy(&padded[3 + ps_len], message, message_len);
    
    asm_rsa_bignum_t *m = asm_rsa_bignum_new((key_bytes + 3) / 4);
    asm_rsa_bignum_t *s = asm_rsa_bignum_new((key_bytes + 3) / 4);
    
    if (!m || !s) {
        free(padded);
        asm_rsa_bignum_free(m);
        asm_rsa_bignum_free(s);
        return RSA_ERR_MEMORY;
    }
    
    asm_rsa_bignum_from_bytes(m, padded, key_bytes);
    
    int ret;
    switch (mode) {
        case RSA_DECRYPT_CRT:
            // CRT-optimized signing (~4x faster)
            ret = rsa_decrypt_crt(s, m, pvt_key);
            break;

        case RSA_DECRYPT_STANDARD:
        default:
            // Standard RSA signing: s = m^d mod n
            ret = bignum_mod_exp(s, m, pvt_key->d, pvt_key->n);
            break;
    }
    
    if (ret == RSA_SUCCESS) {
        ret = asm_rsa_bignum_to_bytes(s, signature, key_bytes);
        if (ret >= 0) {
            *signature_len = key_bytes;
            ret = RSA_SUCCESS;
        }
    }
    
    free(padded);
    asm_rsa_bignum_free(m);
    asm_rsa_bignum_free(s);
    
    return ret;
}

/**
 * @brief Verify a signature using RSA public key
 * @param pub_key Public key for verification
 * @param message Original message
 * @param message_len Length of message
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return RSA_SUCCESS if signature is valid, negative otherwise
 */
int asm_rsa_verify(const asm_rsa_pub_key_t *pub_key,
                   const uint8_t *message,
                   size_t message_len,
                   const uint8_t *signature,
                   size_t signature_len) {
    if (!pub_key || !message || !signature) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    size_t key_bytes = pub_key->key_size / 8;
    
    if (signature_len != key_bytes) {
        return RSA_ERR_INVALID_DATA_LENGTH;
    }
    
    asm_rsa_bignum_t *s = asm_rsa_bignum_new((key_bytes + 3) / 4);
    asm_rsa_bignum_t *m = asm_rsa_bignum_new((key_bytes + 3) / 4);
    
    if (!s || !m) {
        asm_rsa_bignum_free(s);
        asm_rsa_bignum_free(m);
        return RSA_ERR_MEMORY;
    }
    
    asm_rsa_bignum_from_bytes(s, signature, signature_len);
    
    // Verify: m = s^e mod n
    int ret = bignum_mod_exp(m, s, pub_key->e, pub_key->n);
    
    if (ret == RSA_SUCCESS) {
        uint8_t *padded = malloc(key_bytes);
        if (!padded) {
            asm_rsa_bignum_free(s);
            asm_rsa_bignum_free(m);
            return RSA_ERR_MEMORY;
        }
        
        ret = asm_rsa_bignum_to_bytes(m, padded, key_bytes);
        
        if (ret >= 0) {
            // Verify PKCS#1 v1.5 padding type 1
            if (padded[0] != 0x00 || padded[1] != 0x01) {
                ret = RSA_ERR_DECRYPTION_FAILED;
            } else {
                // Find 0x00 separator
                size_t i = 2;
                while (i < key_bytes && padded[i] == 0xFF) {
                    i++;
                }
                
                if (i >= key_bytes || padded[i] != 0x00) {
                    ret = RSA_ERR_DECRYPTION_FAILED;
                } else {
                    i++;
                    size_t recovered_len = key_bytes - i;
                    
                    // Compare recovered message with original
                    if (recovered_len != message_len ||
                        memcmp(&padded[i], message, message_len) != 0) {
                        ret = RSA_ERR_DECRYPTION_FAILED;
                    } else {
                        ret = RSA_SUCCESS;
                    }
                }
            }
        }
        
        free(padded);
    }
    
    asm_rsa_bignum_free(s);
    asm_rsa_bignum_free(m);
    
    return ret;
}