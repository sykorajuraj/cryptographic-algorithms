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
    static int seeded = 0;
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

int bignum_cmp(const asm_rsa_bignum_t *a, const asm_rsa_bignum_t *b) {
    if (a->used > b->used) return 1;
    if (a->used < b->used) return -1;
    
    for (int i = a->used - 1; i >= 0; i--) {
        if (a->data[i] > b->data[i]) return 1;
        if (a->data[i] < b->data[i]) return -1;
    }
    return 0;
}

void bignum_copy(asm_rsa_bignum_t *dst, const asm_rsa_bignum_t *src) {
    if (dst->size < src->used) return;
    
    memcpy(dst->data, src->data, src->used * sizeof(uint32_t));
    dst->used = src->used;
    
    // Zero remaining words
    if (dst->used < dst->size) {
        memset(&dst->data[dst->used], 0, (dst->size - dst->used) * sizeof(uint32_t));
    }
}

void bignum_trim(asm_rsa_bignum_t *bn) {
    while (bn->used > 0 && bn->data[bn->used - 1] == 0) {
        bn->used--;
    }
}

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

int bignum_mod(asm_rsa_bignum_t *result,
                      const asm_rsa_bignum_t *a,
                      const asm_rsa_bignum_t *m) {
    if (!result || !a || !m) return RSA_ERR_INVALID_PARAM;

    if (bignum_cmp(a, m) < 0) {
        bignum_copy(result, a);
        return RSA_SUCCESS;
    }
    
    // Special case optimization for small m
    if (m->used == 1 && a->used <= 2) {
        asm_rsa_bignum_t *temp = asm_rsa_bignum_new(a->used + 1);
        if (!temp) return RSA_ERR_MEMORY;
        
        bignum_copy(temp, a);
        
        int safety_counter = 0;
        while (bignum_cmp(temp, m) >= 0 && safety_counter++ < 1000000) {
            bignum_sub(temp, temp, m);
        }
        
        bignum_copy(result, temp);
        asm_rsa_bignum_free(temp);
        return RSA_SUCCESS;
    }
    
    // For large numbers, use binary long division
    asm_rsa_bignum_t *remainder = asm_rsa_bignum_new(a->used + 1);
    if (!remainder) return RSA_ERR_MEMORY;
    
    bignum_copy(remainder, a);
    
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
    
    for (int bit_pos = a_bits - m_bits; bit_pos >= 0; bit_pos--) {
        asm_rsa_bignum_t *shifted_m = asm_rsa_bignum_new(m->used + (bit_pos / 32) + 2);
        if (!shifted_m) {
            asm_rsa_bignum_free(remainder);
            return RSA_ERR_MEMORY;
        }
        
        bignum_shift_left(shifted_m, m, bit_pos);
        
        if (bignum_cmp(remainder, shifted_m) >= 0) {
            bignum_sub(remainder, remainder, shifted_m);
        }
        
        asm_rsa_bignum_free(shifted_m);
    }
    
    bignum_copy(result, remainder);
    asm_rsa_bignum_free(remainder);
    
    return RSA_SUCCESS;
}

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

int bignum_mod_exp(asm_rsa_bignum_t *result, 
                          const asm_rsa_bignum_t *base,
                          const asm_rsa_bignum_t *exp,
                          const asm_rsa_bignum_t *mod) {
    if (!result || !base || !exp || !mod) return RSA_ERR_INVALID_PARAM;
    
    if (mod->used == 1 && mod->data[0] == 0) {
        return RSA_ERR_INVALID_PARAM;
    }
    
    asm_rsa_bignum_t *temp_base = asm_rsa_bignum_new(mod->used * 2 + 1);
    asm_rsa_bignum_t *temp_result = asm_rsa_bignum_new(mod->used * 2 + 1);
    asm_rsa_bignum_t *temp_mul = asm_rsa_bignum_new(mod->used * 2 + 1);
    
    if (!temp_base || !temp_result || !temp_mul) {
        asm_rsa_bignum_free(temp_base);
        asm_rsa_bignum_free(temp_result);
        asm_rsa_bignum_free(temp_mul);
        return RSA_ERR_MEMORY;
    }
    
    memset(temp_result->data, 0, temp_result->size * sizeof(uint32_t));
    temp_result->data[0] = 1;
    temp_result->used = 1;
    
    bignum_copy(temp_base, base);
    bignum_mod(temp_base, temp_base, mod);
    
    for (size_t i = 0; i < exp->used; i++) {
        uint32_t exp_word = exp->data[i];
        
        for (int bit = 0; bit < 32; bit++) {
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
            
            int ret = bignum_mul_mod(temp_mul, temp_base, temp_base, mod);
            if (ret != RSA_SUCCESS) {
                asm_rsa_bignum_free(temp_base);
                asm_rsa_bignum_free(temp_result);
                asm_rsa_bignum_free(temp_mul);
                return ret;
            }
            bignum_copy(temp_base, temp_mul);
            
            exp_word >>= 1;
            
            if (i == exp->used - 1 && exp_word == 0) break;
        }
    }
    
    bignum_copy(result, temp_result);
    
    asm_rsa_bignum_free(temp_base);
    asm_rsa_bignum_free(temp_result);
    asm_rsa_bignum_free(temp_mul);
    
    return RSA_SUCCESS;
}

/**
 * @brief Compute modular inverse: result = a^(-1) mod m
 * @note Replaces standard Extended Euclidean Algorithm with a version 
 * tailored for unsigned arithmetic to avoid negative coefficients.
 */
int bignum_mod_inverse(asm_rsa_bignum_t *result,
                              const asm_rsa_bignum_t *a,
                              const asm_rsa_bignum_t *m) {
    if (!result || !a || !m) return RSA_ERR_INVALID_PARAM;

    size_t max_size = (m->used > a->used ? m->used : a->used) + 2;

    asm_rsa_bignum_t *r0 = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *r1 = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *x0 = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *x1 = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *quotient = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *remainder = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *term = asm_rsa_bignum_new(max_size * 2);
    asm_rsa_bignum_t *new_x = asm_rsa_bignum_new(max_size);
    asm_rsa_bignum_t *one = asm_rsa_bignum_new(1);

    if (!r0 || !r1 || !x0 || !x1 || !quotient || !remainder || !term || !new_x || !one) {
        asm_rsa_bignum_free(r0); asm_rsa_bignum_free(r1);
        asm_rsa_bignum_free(x0); asm_rsa_bignum_free(x1);
        asm_rsa_bignum_free(quotient); asm_rsa_bignum_free(remainder);
        asm_rsa_bignum_free(term); asm_rsa_bignum_free(new_x);
        asm_rsa_bignum_free(one);
        return RSA_ERR_MEMORY;
    }

    // Initialize: r0 = m, r1 = a % m
    bignum_copy(r0, m);
    bignum_mod(r1, a, m);

    // Initialize x: x0 = 0, x1 = 1
    x0->data[0] = 0; x0->used = 1;
    x1->data[0] = 1; x1->used = 1;

    one->data[0] = 1; one->used = 1;

    int ret = RSA_SUCCESS;

    // Loop while r1 > 1
    while (bignum_cmp(r1, one) > 0) {
        // quotient = r0 / r1, remainder = r0 % r1
        ret = bignum_div(quotient, remainder, r0, r1);
        if (ret != RSA_SUCCESS) break;

        // r0 = r1, r1 = remainder
        bignum_copy(r0, r1);
        bignum_copy(r1, remainder);

        // Calculate x_new = x0 - quotient * x1 (mod m)
        // Since we are unsigned, we compute:
        // term = (quotient * x1) % m
        ret = bignum_mul_mod(term, quotient, x1, m);
        if (ret != RSA_SUCCESS) break;

        if (bignum_cmp(x0, term) >= 0) {
            // positive result directly
            bignum_sub(new_x, x0, term);
        } else {
            // negative result, add modulus: new_x = m - (term - x0)
            bignum_sub(term, term, x0); // reuse term for (term - x0)
            bignum_sub(new_x, m, term);
        }

        // x0 = x1, x1 = new_x
        bignum_copy(x0, x1);
        bignum_copy(x1, new_x);
    }

    if (ret == RSA_SUCCESS) {
        // If r1 == 1, then x1 is the inverse
        if (r1->used == 1 && r1->data[0] == 1) {
            bignum_copy(result, x1);
        } else {
            ret = RSA_ERR_KEY_GENERATION_FAILED; // Inverse does not exist
        }
    }

    asm_rsa_bignum_free(r0); asm_rsa_bignum_free(r1);
    asm_rsa_bignum_free(x0); asm_rsa_bignum_free(x1);
    asm_rsa_bignum_free(quotient); asm_rsa_bignum_free(remainder);
    asm_rsa_bignum_free(term); asm_rsa_bignum_free(new_x);
    asm_rsa_bignum_free(one);

    return ret;
}

// PRIME NUMBER GENERATION

int trial_division(const asm_rsa_bignum_t *n) {
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
    
    if (n->used == 0 || (n->used == 1 && n->data[0] <= 1)) {
        return 0;
    }
    
    for (size_t i = 0; i < num_primes; i++) {
        uint32_t prime = small_primes[i];
        
        if (n->used == 1 && n->data[0] == prime) {
            return 1;
        }
        
        uint64_t remainder = 0;
        for (int j = n->used - 1; j >= 0; j--) {
            remainder = (remainder << 32) | n->data[j];
            remainder %= prime;
        }
        
        if (remainder == 0) {
            return 0;
        }
    }
    
    return 1;
}

int miller_rabin(const asm_rsa_bignum_t *n, int rounds) {
    if (!n) return 0;
    
    if (n->used == 1) {
        uint32_t val = n->data[0];
        if (val < 2) return 0;
        if (val == 2 || val == 3) return 1;
        if (val % 2 == 0) return 0;
    }
    
    if ((n->data[0] & 1) == 0) return 0;
    
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
        uint64_t carry = 0;
        for (int i = d->used - 1; i >= 0; i--) {
            uint64_t val = ((uint64_t)carry << 32) | d->data[i];
            d->data[i] = (uint32_t)(val >> 1);
            carry = val & 1;
        }
        bignum_trim(d);
        r++;
    }
    
    for (int round = 0; round < rounds; round++) {
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
        
        bignum_mod(a, a, n);
        if (bignum_cmp(a, one) <= 0) {
            a->data[0] = 2;
            a->used = 1;
        }
        
        asm_rsa_bignum_t *x = asm_rsa_bignum_new(n->size * 2);
        if (!x) {
            asm_rsa_bignum_free(a);
            break;
        }
        
        bignum_mod_exp(x, a, d, n);
        
        if (bignum_cmp(x, one) == 0 || bignum_cmp(x, n_minus_1) == 0) {
            asm_rsa_bignum_free(a);
            asm_rsa_bignum_free(x);
            continue;
        }
        
        int is_prime = 0;
        for (int i = 0; i < r - 1; i++) {
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

int generate_prime(asm_rsa_bignum_t *prime, size_t bits) {
    if (!prime) return RSA_ERR_INVALID_PARAM;
    
    size_t bytes = (bits + 7) / 8;
    uint8_t *rand_bytes = malloc(bytes);
    if (!rand_bytes) return RSA_ERR_MEMORY;
    
    int max_attempts = 10000;
    int attempts = 0;
    
    while (attempts < max_attempts) {
        random_bytes(rand_bytes, bytes);
        rand_bytes[0] |= 0x80;
        rand_bytes[bytes - 1] |= 0x01;
        
        asm_rsa_bignum_from_bytes(prime, rand_bytes, bytes);
        
        if (!trial_division(prime)) {
            attempts++;
            continue;
        }
        
        if (miller_rabin(prime, 5)) {
            free(rand_bytes);
            return RSA_SUCCESS;
        }
        
        attempts++;
    }
    
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
    pvt_key->p = asm_rsa_bignum_new(words / 2 + 1);
    pvt_key->q = asm_rsa_bignum_new(words / 2 + 1);
    // Allocate CRT parameters with full size to handle intermediate calculations
    pvt_key->dp = asm_rsa_bignum_new(words);
    pvt_key->dq = asm_rsa_bignum_new(words);
    pvt_key->qinv = asm_rsa_bignum_new(words);
    
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

int asm_rsa_generate_keypair(asm_rsa_ctx_t *ctx, size_t key_size) {
    if (!ctx) return RSA_ERR_INVALID_PARAM;
    
    if (key_size != RSA_KEY_SIZE_512 && key_size != RSA_KEY_SIZE_1024 &&
        key_size != RSA_KEY_SIZE_2048 && key_size != RSA_KEY_SIZE_4096) {
        return RSA_ERR_INVALID_KEY_LENGTH;
    }
    
    if (ctx->pub_key) asm_rsa_pub_key_free(ctx->pub_key);
    if (ctx->pvt_key) asm_rsa_pvt_key_free(ctx->pvt_key);
    
    ctx->pub_key = asm_rsa_pub_key_new(key_size);
    ctx->pvt_key = asm_rsa_pvt_key_new(key_size);
    
    if (!ctx->pub_key || !ctx->pvt_key) {
        return RSA_ERR_MEMORY;
    }
    
    ctx->key_size = key_size;
    size_t half_bits = key_size / 2;
    
    int ret = generate_prime(ctx->pvt_key->p, half_bits);
    if (ret != RSA_SUCCESS) return ret;
    
    int max_attempts = 10;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        ret = generate_prime(ctx->pvt_key->q, half_bits);
        if (ret != RSA_SUCCESS) continue;
        
        if (bignum_cmp(ctx->pvt_key->p, ctx->pvt_key->q) != 0) {
            break;
        }
    }
    
    if (bignum_cmp(ctx->pvt_key->p, ctx->pvt_key->q) == 0) {
        return RSA_ERR_KEY_GENERATION_FAILED;
    }
    
    ret = bignum_mul(ctx->pub_key->n, ctx->pvt_key->p, ctx->pvt_key->q);
    if (ret != RSA_SUCCESS) return ret;
    bignum_copy(ctx->pvt_key->n, ctx->pub_key->n);
    
    ctx->pub_key->e->data[0] = 0x10001;
    ctx->pub_key->e->used = 1;
    
    asm_rsa_bignum_t *one = asm_rsa_bignum_new(2);
    asm_rsa_bignum_t *p_minus_1 = asm_rsa_bignum_new(ctx->pvt_key->p->size);
    asm_rsa_bignum_t *q_minus_1 = asm_rsa_bignum_new(ctx->pvt_key->q->size);
    asm_rsa_bignum_t *phi = asm_rsa_bignum_new(ctx->pub_key->n->size * 2);
    
    if (!one || !p_minus_1 || !q_minus_1 || !phi) {
        asm_rsa_bignum_free(one); asm_rsa_bignum_free(p_minus_1);
        asm_rsa_bignum_free(q_minus_1); asm_rsa_bignum_free(phi);
        return RSA_ERR_MEMORY;
    }
    
    one->data[0] = 1; one->used = 1;
    
    bignum_sub(p_minus_1, ctx->pvt_key->p, one);
    bignum_sub(q_minus_1, ctx->pvt_key->q, one);
    bignum_mul(phi, p_minus_1, q_minus_1);
    
    ret = bignum_mod_inverse(ctx->pvt_key->d, ctx->pub_key->e, phi);
    if (ret != RSA_SUCCESS) {
        asm_rsa_bignum_free(one); asm_rsa_bignum_free(p_minus_1);
        asm_rsa_bignum_free(q_minus_1); asm_rsa_bignum_free(phi);
        return ret;
    }
    
    // Compute CRT parameters: dp = d mod (p-1), dq = d mod (q-1)
    ret = bignum_mod(ctx->pvt_key->dp, ctx->pvt_key->d, p_minus_1);
    if (ret != RSA_SUCCESS) {
        asm_rsa_bignum_free(one); asm_rsa_bignum_free(p_minus_1);
        asm_rsa_bignum_free(q_minus_1); asm_rsa_bignum_free(phi);
        return ret;
    }
    
    ret = bignum_mod(ctx->pvt_key->dq, ctx->pvt_key->d, q_minus_1);
    if (ret != RSA_SUCCESS) {
        asm_rsa_bignum_free(one); asm_rsa_bignum_free(p_minus_1);
        asm_rsa_bignum_free(q_minus_1); asm_rsa_bignum_free(phi);
        return ret;
    }
    
    // Compute qinv = q^(-1) mod p
    ret = bignum_mod_inverse(ctx->pvt_key->qinv, ctx->pvt_key->q, ctx->pvt_key->p);
    
    asm_rsa_bignum_free(one);
    asm_rsa_bignum_free(p_minus_1);
    asm_rsa_bignum_free(q_minus_1);
    asm_rsa_bignum_free(phi);
    
    return ret;
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
    
    output[0] = 0x00;
    output[1] = 0x02;
    
    size_t ps_len = output_len - input_len - 3;
    
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
    
    if (input[0] != 0x00 || input[1] != 0x02) {
        return RSA_ERR_DECRYPTION_FAILED;
    }
    
    size_t i = 2;
    while (i < input_len && input[i] != 0x00) {
        i++;
    }
    
    if (i >= input_len) {
        return RSA_ERR_DECRYPTION_FAILED;
    }
    
    i++;
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
    
    uint8_t *padded = malloc(key_bytes);
    if (!padded) return RSA_ERR_MEMORY;
    
    int ret = pkcs1_pad(plaintext, plaintext_len, padded, key_bytes);
    if (ret != RSA_SUCCESS) {
        free(padded);
        return ret;
    }
    
    asm_rsa_bignum_t *m = asm_rsa_bignum_new((key_bytes + 3) / 4);
    asm_rsa_bignum_t *c = asm_rsa_bignum_new((key_bytes + 3) / 4);
    
    if (!m || !c) {
        free(padded);
        asm_rsa_bignum_free(m);
        asm_rsa_bignum_free(c);
        return RSA_ERR_MEMORY;
    }
    
    asm_rsa_bignum_from_bytes(m, padded, key_bytes);
    
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
    
    asm_rsa_bignum_t *c = asm_rsa_bignum_new((key_bytes + 3) / 4);
    // Allocate m with enough space for CRT intermediate results
    // CRT uses safe_size = p->size + q->size + 2, and p,q are allocated as (key_bytes/8 + 3)/4/2 + 1
    // For proper allocation, we need: 2 * (words/2 + 1) + 2 = words + 4
    size_t words = (key_bytes + 3) / 4;
    asm_rsa_bignum_t *m = asm_rsa_bignum_new(words + 4);
    
    if (!c || !m) {
        asm_rsa_bignum_free(c);
        asm_rsa_bignum_free(m);
        return RSA_ERR_MEMORY;
    }
    
    asm_rsa_bignum_from_bytes(c, ciphertext, ciphertext_len);
    
    int ret;

    switch (mode) {
        case RSA_DECRYPT_CRT:
            ret = rsa_decrypt_crt(m, c, pvt_key);
            break;

        case RSA_DECRYPT_STANDARD:
        default:
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
        
        if (ret >= 0) {
            ret = pkcs1_unpad(padded, key_bytes, plaintext, plaintext_len);
        }
        
        free(padded);
    }
    
    asm_rsa_bignum_free(c);
    asm_rsa_bignum_free(m);
    
    return ret;
}

int rsa_decrypt_crt(asm_rsa_bignum_t *m,
                          const asm_rsa_bignum_t *c,
                          const asm_rsa_pvt_key_t *key) {
    if (!m || !c || !key) return RSA_ERR_INVALID_PARAM;
    
    // Allocate larger buffers to handle carries and intermediate results
    size_t safe_size = key->p->size + key->q->size + 2;
    asm_rsa_bignum_t *m1 = asm_rsa_bignum_new(safe_size);
    asm_rsa_bignum_t *m2 = asm_rsa_bignum_new(safe_size);
    asm_rsa_bignum_t *h = asm_rsa_bignum_new(safe_size);
    asm_rsa_bignum_t *temp = asm_rsa_bignum_new(safe_size);
    asm_rsa_bignum_t *c_mod_p = asm_rsa_bignum_new(key->p->size + 1);
    asm_rsa_bignum_t *c_mod_q = asm_rsa_bignum_new(key->q->size + 1);
    
    if (!m1 || !m2 || !h || !temp || !c_mod_p || !c_mod_q) {
        asm_rsa_bignum_free(m1); asm_rsa_bignum_free(m2);
        asm_rsa_bignum_free(h); asm_rsa_bignum_free(temp);
        asm_rsa_bignum_free(c_mod_p); asm_rsa_bignum_free(c_mod_q);
        return RSA_ERR_MEMORY;
    }
    
    bignum_mod(c_mod_p, c, key->p);
    bignum_mod(c_mod_q, c, key->q);
    
    int ret = bignum_mod_exp(m1, c_mod_p, key->dp, key->p);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    ret = bignum_mod_exp(m2, c_mod_q, key->dq, key->q);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    asm_rsa_bignum_t *m2_mod_p = asm_rsa_bignum_new(key->p->size + 1);
    if (!m2_mod_p) {
        ret = RSA_ERR_MEMORY;
        goto cleanup;
    }
    
    bignum_mod(m2_mod_p, m2, key->p);
    
    if (bignum_cmp(m1, m2_mod_p) >= 0) {
        bignum_sub(h, m1, m2_mod_p);
    } else {
        bignum_add(temp, m1, key->p);
        bignum_sub(h, temp, m2_mod_p);
    }
    
    asm_rsa_bignum_free(m2_mod_p);
    
    ret = bignum_mul_mod(h, h, key->qinv, key->p);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    ret = bignum_mul(temp, h, key->q);
    if (ret != RSA_SUCCESS) goto cleanup;
    
    ret = bignum_add(m, m2, temp);
    
cleanup:
    asm_rsa_bignum_free(m1); asm_rsa_bignum_free(m2);
    asm_rsa_bignum_free(h); asm_rsa_bignum_free(temp);
    asm_rsa_bignum_free(c_mod_p); asm_rsa_bignum_free(c_mod_q);
    
    return ret;
}

// RSA SIGNATURES

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
    
    padded[0] = 0x00;
    padded[1] = 0x01; 
    
    size_t ps_len = key_bytes - message_len - 3;
    memset(&padded[2], 0xFF, ps_len); 
    
    padded[2 + ps_len] = 0x00;
    memcpy(&padded[3 + ps_len], message, message_len);
    
    asm_rsa_bignum_t *m = asm_rsa_bignum_new((key_bytes + 3) / 4);
    // Allocate s with enough space for CRT intermediate results  
    // CRT uses safe_size = p->size + q->size + 2, same as decryption
    size_t words = (key_bytes + 3) / 4;
    asm_rsa_bignum_t *s = asm_rsa_bignum_new(words + 4);
    
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
            ret = rsa_decrypt_crt(s, m, pvt_key);
            break;

        case RSA_DECRYPT_STANDARD:
        default:
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
            if (padded[0] != 0x00 || padded[1] != 0x01) {
                ret = RSA_ERR_DECRYPTION_FAILED;
            } else {
                size_t i = 2;
                while (i < key_bytes && padded[i] == 0xFF) {
                    i++;
                }
                
                if (i >= key_bytes || padded[i] != 0x00) {
                    ret = RSA_ERR_DECRYPTION_FAILED;
                } else {
                    i++;
                    size_t recovered_len = key_bytes - i;
                    
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