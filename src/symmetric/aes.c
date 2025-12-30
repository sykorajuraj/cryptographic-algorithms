/**
 * @file src/symmetric/aes.c
 * @brief Symmetrical AES-128 implementation
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include "src/symmetric/aes.h"

/**
 * @brief AES S-box (Substitution box) for SubBytes transformation
 * 
 * References:
 * - NIST FIPS 197 (2023): Advanced Encryption Standard (AES)
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 * - GeeksforGeeks: S-Box Substitution
 *   https://www.geeksforgeeks.org/computer-networks/what-is-s-box-substitution/
 * - Wikipedia: Rijndael S-box
 *   https://en.wikipedia.org/wiki/Rijndael_S-box
 */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/** 
 * @brief Inverse S-box for decryption
 */
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants for key expansion
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Galois Field multiplication by 2 in GF(2^8)
static uint8_t gf_mul2(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

// Galois Field multiplication
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// Secure memory clear using volatile pointer to prevent optimization
static void mem_clean(void *ptr, size_t len) {
    volatile uint8_t *vptr = (volatile uint8_t *)ptr;
    while (len--) {
        *vptr++ = 0;
    }
}

// Key expansion routine
static void key_expansion(const uint8_t *key, uint8_t *round_keys) {
    int i;
    uint8_t temp[4];
    
    // First round key is the original key
    for (i = 0; i < 16; i++) {
        round_keys[i] = key[i];
    }
    
    // Generate remaining round keys
    for (i = Nk; i < Nb * (Nr + 1); i++) {
        // Copy previous word
        for (int j = 0; j < 4; j++) {
            temp[j] = round_keys[(i - 1) * 4 + j];
        }
        
        if (i % Nk == 0) {
            // RotWord: rotate left by 1 byte
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            
            // SubWord: apply S-box
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            // XOR with round constant
            temp[0] ^= rcon[i / Nk];
        }
        
        // XOR with word Nk positions earlier
        for (int j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = round_keys[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

// Context initialization functions
sym_aes_ctx_t *sym_aes_ctx_init(const uint8_t *key, size_t key_len) {
    if (!key || key_len != KEY_LENGTH_BYTES) return NULL;
    
    sym_aes_ctx_t *ctx = (sym_aes_ctx_t *)malloc(sizeof(sym_aes_ctx_t));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(sym_aes_ctx_t));
    ctx->iv_initialized = 0;
    key_expansion(key, ctx->round_keys);
    
    return ctx;
}

// Context destruction function
void sym_aes_ctx_destroy(sym_aes_ctx_t *ctx) {
    if (ctx) {
        mem_clean(ctx, sizeof(sym_aes_ctx_t));
        free(ctx);
    }
}

// Context clear
sym_aes_ctx_t *sym_aes_ctx_clear(sym_aes_ctx_t *ctx) {
    if (ctx) {
        mem_clean(ctx, sizeof(sym_aes_ctx_t));
    }
    return ctx;
}

// Set IV functions
int sym_aes_enc_set_iv(sym_aes_ctx_t *ctx, const uint8_t *iv) {
    if (!ctx || !iv) {
        return AES_ERROR_INVALID_PARAM;
    }
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    ctx->iv_initialized = 1;
    return AES_SUCCESS;
}

int sym_aes_dnc_set_iv(sym_aes_ctx_t *ctx, const uint8_t *iv) {
    if (!ctx || !iv) {
        return AES_ERROR_INVALID_PARAM;
    }
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    ctx->iv_initialized = 1;
    return AES_SUCCESS;
}

// SubBytes transformation
int sym_aes_enc_sub_bytes(uint8_t *state) {
    if (!state) return AES_ERROR_INVALID_PARAM;
    
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
    return AES_SUCCESS;
}

// ShiftRows transformation
int sym_aes_enc_shift_rows(uint8_t *state) {
    if (!state) return AES_ERROR_INVALID_PARAM;
    
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
    
    return AES_SUCCESS;
}

// MixColumns transformation
int sym_aes_enc_mix_cols(uint8_t *state) {
    if (!state) return AES_ERROR_INVALID_PARAM;
    
    uint8_t temp[16];
    
    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        temp[col] = gf_mul(0x02, state[col]) ^ gf_mul(0x03, state[col + 1]) ^ 
                    state[col + 2] ^ state[col + 3];
        temp[col + 1] = state[col] ^ gf_mul(0x02, state[col + 1]) ^ 
                        gf_mul(0x03, state[col + 2]) ^ state[col + 3];
        temp[col + 2] = state[col] ^ state[col + 1] ^ 
                        gf_mul(0x02, state[col + 2]) ^ gf_mul(0x03, state[col + 3]);
        temp[col + 3] = gf_mul(0x03, state[col]) ^ state[col + 1] ^ 
                        state[col + 2] ^ gf_mul(0x02, state[col + 3]);
    }
    
    memcpy(state, temp, 16);
    return AES_SUCCESS;
}

// AddRoundKey transformation
int sym_aes_enc_add_round_keys(uint8_t *state, uint8_t *round_key) {
    if (!state || !round_key) return AES_ERROR_INVALID_PARAM;
    
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
    return AES_SUCCESS;
}

// Main encryption function
int sym_aes_encryption(sym_aes_ctx_t *ctx, const uint8_t *plaintext, uint8_t *ciphertext) {
    if (!ctx || !plaintext || !ciphertext) return AES_ERROR_INVALID_PARAM;
    
    // Copy plaintext to state
    memcpy(ctx->state, plaintext, 16);
    
    // Initial round key addition
    sym_aes_enc_add_round_keys(ctx->state, ctx->round_keys);
    
    // Main rounds (9 rounds for AES-128)
    for (int round = 1; round < Nr; round++) {
        sym_aes_enc_sub_bytes(ctx->state);
        sym_aes_enc_shift_rows(ctx->state);
        sym_aes_enc_mix_cols(ctx->state);
        sym_aes_enc_add_round_keys(ctx->state, ctx->round_keys + (round * 16));
    }
    
    // Final round (no MixColumns)
    sym_aes_enc_sub_bytes(ctx->state);
    sym_aes_enc_shift_rows(ctx->state);
    sym_aes_enc_add_round_keys(ctx->state, ctx->round_keys + (Nr * 16));
    
    // Copy state to ciphertext
    memcpy(ciphertext, ctx->state, 16);
    
    return AES_SUCCESS;
}

// Decryption functions
int sym_aes_dnc_inv_sub_bytes(uint8_t *state) {
    if (!state) return AES_ERROR_INVALID_PARAM;
    
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
    return AES_SUCCESS;
}

int sym_aes_dnc_shift_rows(uint8_t *state) {
    if (!state) return AES_ERROR_INVALID_PARAM;
    
    uint8_t temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
    
    return AES_SUCCESS;
}

int sym_aes_dnc_inv_mix_cols(uint8_t *state) {
    if (!state) return AES_ERROR_INVALID_PARAM;
    
    uint8_t temp[16];
    
    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        temp[col] = gf_mul(0x0e, state[col]) ^ gf_mul(0x0b, state[col + 1]) ^ 
                    gf_mul(0x0d, state[col + 2]) ^ gf_mul(0x09, state[col + 3]);
        temp[col + 1] = gf_mul(0x09, state[col]) ^ gf_mul(0x0e, state[col + 1]) ^ 
                        gf_mul(0x0b, state[col + 2]) ^ gf_mul(0x0d, state[col + 3]);
        temp[col + 2] = gf_mul(0x0d, state[col]) ^ gf_mul(0x09, state[col + 1]) ^ 
                        gf_mul(0x0e, state[col + 2]) ^ gf_mul(0x0b, state[col + 3]);
        temp[col + 3] = gf_mul(0x0b, state[col]) ^ gf_mul(0x0d, state[col + 1]) ^ 
                        gf_mul(0x09, state[col + 2]) ^ gf_mul(0x0e, state[col + 3]);
    }
    
    memcpy(state, temp, 16);
    return AES_SUCCESS;
}

int sym_aes_dnc_add_round_keys(uint8_t *state, const uint8_t *round_key) {
    if (!state || !round_key) return AES_ERROR_INVALID_PARAM;
    
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
    return AES_SUCCESS;
}

int sym_aes_decryption(sym_aes_ctx_t *ctx, const uint8_t *ciphertext, uint8_t *plaintext) {
    if (!ctx || !ciphertext || !plaintext) return AES_ERROR_INVALID_PARAM;
    
    // Copy ciphertext to state
    memcpy(ctx->state, ciphertext, 16);
    
    // Initial round key addition (last round key)
    sym_aes_dnc_add_round_keys(ctx->state, ctx->round_keys + (Nr * 16));
    
    // Main rounds in reverse
    for (int round = Nr - 1; round > 0; round--) {
        sym_aes_dnc_shift_rows(ctx->state);
        sym_aes_dnc_inv_sub_bytes(ctx->state);
        sym_aes_dnc_add_round_keys(ctx->state, ctx->round_keys + (round * 16));
        sym_aes_dnc_inv_mix_cols(ctx->state);
    }
    
    // Final round (no InvMixColumns)
    sym_aes_dnc_shift_rows(ctx->state);
    sym_aes_dnc_inv_sub_bytes(ctx->state);
    sym_aes_dnc_add_round_keys(ctx->state, ctx->round_keys);
    
    // Copy state to plaintext
    memcpy(plaintext, ctx->state, 16);
    
    return AES_SUCCESS;
}

// PKCS#7 Padding
int sym_aes_pkcs7_pad(const uint8_t *data, size_t data_len, uint8_t *padded_data, size_t *padded_len) {
    if (!data || !padded_data || !padded_len) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    size_t padding_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    *padded_len = data_len + padding_len;
    
    memcpy(padded_data, data, data_len);
    for (size_t i = 0; i < padding_len; i++) {
        padded_data[data_len + i] = (uint8_t)padding_len;
    }
    
    return AES_SUCCESS;
}

int sym_aes_pkcs7_unpad(const uint8_t *padded_data, size_t padded_len, uint8_t *data, size_t *data_len) {
    if (!padded_data || !data || !data_len || padded_len == 0 || padded_len % AES_BLOCK_SIZE != 0) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    uint8_t padding_len = padded_data[padded_len - 1];
    
    // Validate padding
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE) {
        return AES_ERROR_INVALID_PADDING;
    }
    
    // Constant-time padding validation to prevent timing attacks
    uint8_t padding_valid = 1;
    for (size_t i = 0; i < padding_len; i++) {
        if (padded_data[padded_len - 1 - i] != padding_len) {
            padding_valid = 0;
        }
    }
    
    if (!padding_valid) {
        return AES_ERROR_INVALID_PADDING;
    }
    
    *data_len = padded_len - padding_len;
    memcpy(data, padded_data, *data_len);
    
    return AES_SUCCESS;
}

// CBC Mode Encryption
int sym_aes_encrypt_cbc(sym_aes_ctx_t *ctx, const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) {
        return AES_ERROR_INVALID_PARAM;
    }

    // FIXED: Validate that IV has been initialized
    if (!ctx->iv_initialized) {
        return AES_ERROR_IV_NOT_SET;
    }
    
    // Calculate padded length
    size_t padded_len;
    uint8_t *padded_data = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!padded_data) {
        return AES_ERROR_MEMORY;
    }
    
    // Apply PKCS#7 padding
    int result = sym_aes_pkcs7_pad(plaintext, plaintext_len, padded_data, &padded_len);
    if (result != AES_SUCCESS) {
        free(padded_data);
        return result;
    }
    
    // Encrypt each block
    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, ctx->iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        
        // XOR with previous ciphertext block (or IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = padded_data[i + j] ^ prev_block[j];
        }
        
        // Encrypt block
        result = sym_aes_encryption(ctx, block, &ciphertext[i]);
        if (result != AES_SUCCESS) {
            mem_clean(padded_data, plaintext_len + AES_BLOCK_SIZE);
            free(padded_data);
            return result;
        }
        
        // Save ciphertext for next XOR
        memcpy(prev_block, &ciphertext[i], AES_BLOCK_SIZE);
    }
    
    *ciphertext_len = padded_len;
    mem_clean(padded_data, plaintext_len + AES_BLOCK_SIZE);
    free(padded_data);
    return AES_SUCCESS;
}

// CBC Mode Decryption
int sym_aes_decrypt_cbc(sym_aes_ctx_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *plaintext, size_t *plaintext_len) {
    if (!ctx || !ciphertext || !plaintext || !plaintext_len) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    // FIXED: Validate IV initialization
    if (!ctx->iv_initialized) {
        return AES_ERROR_IV_NOT_SET;
    }
    
    if (ciphertext_len == 0 || ciphertext_len % AES_BLOCK_SIZE != 0) {
        return AES_ERROR_INVALID_DATA_LENGTH;
    }
    
    uint8_t *decrypted_data = malloc(ciphertext_len);
    if (!decrypted_data) {
        return AES_ERROR_MEMORY;
    }
    
    // Decrypt each block
    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, ctx->iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        
        // Decrypt block
        int result = sym_aes_decryption(ctx, &ciphertext[i], block);
        if (result != AES_SUCCESS) {
            mem_clean(decrypted_data, ciphertext_len);
            free(decrypted_data);
            return result;
        }
        
        // XOR with previous ciphertext block (or IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            decrypted_data[i + j] = block[j] ^ prev_block[j];
        }
        
        // Save ciphertext for next XOR
        memcpy(prev_block, &ciphertext[i], AES_BLOCK_SIZE);
    }
    
    // Remove PKCS#7 padding
    int result = sym_aes_pkcs7_unpad(decrypted_data, ciphertext_len, plaintext, plaintext_len);
    mem_clean(decrypted_data, ciphertext_len);
    free(decrypted_data);
    
    return result;
}

// CTR Mode helper: increment counter
static void increment_counter(uint8_t *counter) {
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

// CTR Mode Encryption
int sym_aes_encrypt_ctr(sym_aes_ctx_t *ctx, const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    // FIXED: Validate IV initialization
    if (!ctx->iv_initialized) {
        return AES_ERROR_IV_NOT_SET;
    }
    
    uint8_t counter[AES_BLOCK_SIZE];
    memcpy(counter, ctx->iv, AES_BLOCK_SIZE);
    
    size_t offset = 0;
    while (offset < plaintext_len) {
        uint8_t keystream[AES_BLOCK_SIZE];
        
        // Encrypt counter to generate keystream
        int result = sym_aes_encryption(ctx, counter, keystream);
        if (result != AES_SUCCESS) {
            mem_clean(counter, AES_BLOCK_SIZE);
            return result;
        }
        
        // XOR plaintext with keystream
        size_t block_size = (plaintext_len - offset < AES_BLOCK_SIZE) ? 
                            (plaintext_len - offset) : AES_BLOCK_SIZE;
        
        for (size_t i = 0; i < block_size; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        increment_counter(counter);
    }
    
    *ciphertext_len = plaintext_len;
    mem_clean(counter, AES_BLOCK_SIZE);
    return AES_SUCCESS;
}

// CTR Mode Decryption (same as encryption in CTR mode)
int sym_aes_decrypt_ctr(sym_aes_ctx_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *plaintext, size_t *plaintext_len) {
    if (!ctx || !ciphertext || !plaintext || !plaintext_len) {
        return AES_ERROR_INVALID_PARAM;
    }

    // Validate IV has been initialized
    if (!ctx->iv_initialized) {
        return AES_ERROR_IV_NOT_SET;
    }
    
    // CTR mode uses encryption for both directions
    return sym_aes_encrypt_ctr(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);
}

// Key management functions
sym_aes_key_t *sym_aes_create_key(const uint8_t *key_data, size_t key_len) {
    if (!key_data || key_len != KEY_LENGTH_BYTES) return NULL;
    
    sym_aes_key_t *key = (sym_aes_key_t *)malloc(sizeof(sym_aes_key_t));
    if (!key) return NULL;
    
    memcpy(key->key_data, key_data, KEY_LENGTH_BYTES);
    key->key_length = KEY_LENGTH_BYTES;
    
    return key;
}

void sym_aes_destroy_key(sym_aes_key_t *key) {
    if (key) {
        mem_clean(key->key_data, KEY_LENGTH_BYTES);
        key->key_length = 0;
        free(key);
    }
}