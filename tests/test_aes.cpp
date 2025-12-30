/**
 * @file tests/test_aes.cpp
 * @brief Unit tests for AES-128 implementation using Google Test
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
    #include "src/symmetric/aes.h"
}

// Test fixture for AES tests
class AESTest : public ::testing::Test {
protected:
    sym_aes_ctx_t *ctx;
    uint8_t key[16];
    uint8_t iv[16];
    
    void SetUp() override {
        // Initialize with a standard test key
        uint8_t test_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        memcpy(key, test_key, 16);
        
        // Initialize IV
        uint8_t test_iv[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        memcpy(iv, test_iv, 16);
        
        ctx = nullptr;
    }
    
    void TearDown() override {
        if (ctx) {
            sym_aes_ctx_destroy(ctx);
            ctx = nullptr;
        }
    }
};

// ============================================================================
// Context Management Tests
// ============================================================================

TEST_F(AESTest, ContextInitialization) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->iv_initialized, 0);
}

TEST_F(AESTest, ContextInitializationNullKey) {
    ctx = sym_aes_ctx_init(nullptr, KEY_LENGTH_BYTES);
    EXPECT_EQ(ctx, nullptr);
}

TEST_F(AESTest, ContextInitializationInvalidKeyLength) {
    ctx = sym_aes_ctx_init(key, 8);
    EXPECT_EQ(ctx, nullptr);
    
    ctx = sym_aes_ctx_init(key, 24);
    EXPECT_EQ(ctx, nullptr);
}

TEST_F(AESTest, ContextDestroy) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    sym_aes_ctx_destroy(ctx);
    ctx = nullptr;  // Prevent double-free in TearDown
    
    SUCCEED();
}

TEST_F(AESTest, ContextDestroyNull) {
    sym_aes_ctx_destroy(nullptr);
    SUCCEED();
}

TEST_F(AESTest, ContextClear) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    sym_aes_ctx_t *result = sym_aes_ctx_clear(ctx);
    EXPECT_EQ(result, ctx);
}

// ============================================================================
// IV Management Tests
// ============================================================================

TEST_F(AESTest, SetIVEncryption) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    int result = sym_aes_enc_set_iv(ctx, iv);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ctx->iv_initialized, 1);
    EXPECT_EQ(memcmp(ctx->iv, iv, 16), 0);
}

TEST_F(AESTest, SetIVDecryption) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    int result = sym_aes_dnc_set_iv(ctx, iv);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ctx->iv_initialized, 1);
    EXPECT_EQ(memcmp(ctx->iv, iv, 16), 0);
}

TEST_F(AESTest, SetIVNullContext) {
    int result = sym_aes_enc_set_iv(nullptr, iv);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

TEST_F(AESTest, SetIVNullIV) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    int result = sym_aes_enc_set_iv(ctx, nullptr);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

// ============================================================================
// Single Block Encryption/Decryption Tests (ECB)
// ============================================================================

TEST_F(AESTest, SingleBlockEncryptionFIPS197) {
    // FIPS-197 test vector
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t expected_ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    uint8_t ciphertext[16];
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    int result = sym_aes_encryption(ctx, plaintext, ciphertext);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(memcmp(ciphertext, expected_ciphertext, 16), 0);
}

TEST_F(AESTest, SingleBlockDecryptionFIPS197) {
    uint8_t ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    uint8_t expected_plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t plaintext[16];
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    int result = sym_aes_decryption(ctx, ciphertext, plaintext);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(memcmp(plaintext, expected_plaintext, 16), 0);
}

TEST_F(AESTest, SingleBlockRoundTrip) {
    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    EXPECT_EQ(sym_aes_encryption(ctx, plaintext, ciphertext), AES_SUCCESS);
    EXPECT_EQ(sym_aes_decryption(ctx, ciphertext, decrypted), AES_SUCCESS);
    EXPECT_EQ(memcmp(plaintext, decrypted, 16), 0);
}

TEST_F(AESTest, AllZeroPlaintext) {
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    EXPECT_EQ(sym_aes_encryption(ctx, plaintext, ciphertext), AES_SUCCESS);
    EXPECT_EQ(sym_aes_decryption(ctx, ciphertext, decrypted), AES_SUCCESS);
    EXPECT_EQ(memcmp(plaintext, decrypted, 16), 0);
}

TEST_F(AESTest, AllOnesPlaintext) {
    uint8_t plaintext[16];
    memset(plaintext, 0xFF, 16);
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    EXPECT_EQ(sym_aes_encryption(ctx, plaintext, ciphertext), AES_SUCCESS);
    EXPECT_EQ(sym_aes_decryption(ctx, ciphertext, decrypted), AES_SUCCESS);
    EXPECT_EQ(memcmp(plaintext, decrypted, 16), 0);
}

TEST_F(AESTest, EncryptionNullPointers) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    
    EXPECT_EQ(sym_aes_encryption(nullptr, plaintext, ciphertext), 
              AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encryption(ctx, nullptr, ciphertext), 
              AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encryption(ctx, plaintext, nullptr), 
              AES_ERROR_INVALID_PARAM);
}

// ============================================================================
// PKCS#7 Padding Tests
// ============================================================================

TEST_F(AESTest, PKCS7PaddingOneBlock) {
    uint8_t data[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a};
    uint8_t padded[32];
    size_t padded_len;
    
    int result = sym_aes_pkcs7_pad(data, 10, padded, &padded_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(padded_len, 16);
    
    // Check padding bytes
    for (size_t i = 10; i < 16; i++) {
        EXPECT_EQ(padded[i], 6);
    }
}

TEST_F(AESTest, PKCS7PaddingFullBlock) {
    uint8_t data[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t padded[32];
    size_t padded_len;
    
    int result = sym_aes_pkcs7_pad(data, 16, padded, &padded_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(padded_len, 32);
    
    // Should add full block of padding (16 bytes of value 16)
    for (size_t i = 16; i < 32; i++) {
        EXPECT_EQ(padded[i], 16);
    }
}

TEST_F(AESTest, PKCS7UnpaddingValid) {
    uint8_t padded[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06
    };
    uint8_t data[16];
    size_t data_len;
    
    int result = sym_aes_pkcs7_unpad(padded, 16, data, &data_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(data_len, 10);
    
    // Check original data
    for (size_t i = 0; i < 10; i++) {
        EXPECT_EQ(data[i], i + 1);
    }
}

TEST_F(AESTest, PKCS7UnpaddingInvalid) {
    uint8_t padded[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x06, 0x06, 0x05, 0x06, 0x06, 0x06
    };
    uint8_t data[16];
    size_t data_len;
    
    int result = sym_aes_pkcs7_unpad(padded, 16, data, &data_len);
    EXPECT_EQ(result, AES_ERROR_INVALID_PADDING);
}

TEST_F(AESTest, PKCS7RoundTrip) {
    uint8_t original[25];
    for (int i = 0; i < 25; i++) original[i] = (uint8_t)i;
    
    uint8_t padded[48];
    uint8_t unpadded[48];
    size_t padded_len, unpadded_len;
    
    EXPECT_EQ(sym_aes_pkcs7_pad(original, 25, padded, &padded_len), AES_SUCCESS);
    EXPECT_EQ(sym_aes_pkcs7_unpad(padded, padded_len, unpadded, &unpadded_len), 
              AES_SUCCESS);
    EXPECT_EQ(unpadded_len, 25);
    EXPECT_EQ(memcmp(original, unpadded, 25), 0);
}

// ============================================================================
// CBC Mode Tests
// ============================================================================

TEST_F(AESTest, CBCEncryptionWithoutIV) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[32];
    size_t ciphertext_len;
    
    int result = sym_aes_encrypt_cbc(ctx, plaintext, 16, ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_ERROR_IV_NOT_SET);
}

TEST_F(AESTest, CBCEncryptionShortMessage) {
    const char *message = "Hello!";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[32];
    size_t ciphertext_len;
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    sym_aes_enc_set_iv(ctx, iv);
    
    int result = sym_aes_encrypt_cbc(ctx, (uint8_t *)message, msg_len, 
                                      ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ciphertext_len, 16);
}

TEST_F(AESTest, CBCRoundTrip) {
    const char *message = "This is a test message for CBC mode encryption!";
    size_t msg_len = strlen(message);
    
    uint8_t *ciphertext = new uint8_t[msg_len + AES_BLOCK_SIZE];
    uint8_t *decrypted = new uint8_t[msg_len + AES_BLOCK_SIZE];
    size_t ciphertext_len, decrypted_len;
    
    sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    ASSERT_NE(ctx_enc, nullptr);
    ASSERT_NE(ctx_dec, nullptr);
    
    sym_aes_enc_set_iv(ctx_enc, iv);
    sym_aes_dnc_set_iv(ctx_dec, iv);
    
    EXPECT_EQ(sym_aes_encrypt_cbc(ctx_enc, (uint8_t *)message, msg_len, 
                                   ciphertext, &ciphertext_len), AES_SUCCESS);
    EXPECT_EQ(sym_aes_decrypt_cbc(ctx_dec, ciphertext, ciphertext_len, 
                                   decrypted, &decrypted_len), AES_SUCCESS);
    
    EXPECT_EQ(decrypted_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
    
    delete[] ciphertext;
    delete[] decrypted;
    sym_aes_ctx_destroy(ctx_enc);
    sym_aes_ctx_destroy(ctx_dec);
}

TEST_F(AESTest, CBCMultipleBlocks) {
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) plaintext[i] = (uint8_t)(i & 0xFF);
    
    uint8_t ciphertext[80];
    uint8_t decrypted[80];
    size_t ciphertext_len, decrypted_len;
    
    sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    ASSERT_NE(ctx_enc, nullptr);
    ASSERT_NE(ctx_dec, nullptr);
    
    sym_aes_enc_set_iv(ctx_enc, iv);
    sym_aes_dnc_set_iv(ctx_dec, iv);
    
    EXPECT_EQ(sym_aes_encrypt_cbc(ctx_enc, plaintext, 64, 
                                   ciphertext, &ciphertext_len), AES_SUCCESS);
    EXPECT_EQ(ciphertext_len, 80);
    
    EXPECT_EQ(sym_aes_decrypt_cbc(ctx_dec, ciphertext, ciphertext_len, 
                                   decrypted, &decrypted_len), AES_SUCCESS);
    EXPECT_EQ(decrypted_len, 64);
    EXPECT_EQ(memcmp(plaintext, decrypted, 64), 0);
    
    sym_aes_ctx_destroy(ctx_enc);
    sym_aes_ctx_destroy(ctx_dec);
}

// ============================================================================
// CTR Mode Tests
// ============================================================================

TEST_F(AESTest, CTREncryptionWithoutIV) {
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    size_t ciphertext_len;
    
    int result = sym_aes_encrypt_ctr(ctx, plaintext, 16, ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_ERROR_IV_NOT_SET);
}

TEST_F(AESTest, CTRNoPadding) {
    const char *message = "Test";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[16];
    size_t ciphertext_len;
    
    uint8_t nonce[16] = {0};
    nonce[15] = 1;
    
    ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(ctx, nullptr);
    sym_aes_enc_set_iv(ctx, nonce);
    
    int result = sym_aes_encrypt_ctr(ctx, (uint8_t *)message, msg_len, 
                                      ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ciphertext_len, msg_len);
}

TEST_F(AESTest, CTRRoundTrip) {
    const char *message = "CTR mode test message - no padding needed!";
    size_t msg_len = strlen(message);
    
    uint8_t *ciphertext = new uint8_t[msg_len];
    uint8_t *decrypted = new uint8_t[msg_len];
    size_t ciphertext_len, decrypted_len;
    
    uint8_t nonce[16] = {0};
    nonce[15] = 1;
    
    sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    ASSERT_NE(ctx_enc, nullptr);
    ASSERT_NE(ctx_dec, nullptr);
    
    sym_aes_enc_set_iv(ctx_enc, nonce);
    sym_aes_dnc_set_iv(ctx_dec, nonce);
    
    EXPECT_EQ(sym_aes_encrypt_ctr(ctx_enc, (uint8_t *)message, msg_len, 
                                   ciphertext, &ciphertext_len), AES_SUCCESS);
    EXPECT_EQ(ciphertext_len, msg_len);
    
    EXPECT_EQ(sym_aes_decrypt_ctr(ctx_dec, ciphertext, ciphertext_len, 
                                   decrypted, &decrypted_len), AES_SUCCESS);
    EXPECT_EQ(decrypted_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
    
    delete[] ciphertext;
    delete[] decrypted;
    sym_aes_ctx_destroy(ctx_enc);
    sym_aes_ctx_destroy(ctx_dec);
}

TEST_F(AESTest, CTRStreamCipher) {
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t ciphertext1[16], ciphertext2[16];
    size_t len1, len2;
    
    uint8_t nonce1[16] = {0};
    nonce1[15] = 1;
    
    uint8_t nonce2[16] = {0};
    nonce2[15] = 2;
    
    sym_aes_ctx_t *ctx1 = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx2 = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    sym_aes_enc_set_iv(ctx1, nonce1);
    sym_aes_enc_set_iv(ctx2, nonce2);
    
    sym_aes_encrypt_ctr(ctx1, plaintext, 16, ciphertext1, &len1);
    sym_aes_encrypt_ctr(ctx2, plaintext, 16, ciphertext2, &len2);
    
    EXPECT_NE(memcmp(ciphertext1, ciphertext2, 16), 0);
    
    sym_aes_ctx_destroy(ctx1);
    sym_aes_ctx_destroy(ctx2);
}

// ============================================================================
// Key Management Tests
// ============================================================================

TEST_F(AESTest, CreateKey) {
    sym_aes_key_t *aes_key = sym_aes_create_key(key, KEY_LENGTH_BYTES);
    ASSERT_NE(aes_key, nullptr);
    EXPECT_EQ(aes_key->key_length, KEY_LENGTH_BYTES);
    EXPECT_EQ(memcmp(aes_key->key_data, key, KEY_LENGTH_BYTES), 0);
    
    sym_aes_destroy_key(aes_key);
}

TEST_F(AESTest, CreateKeyInvalidLength) {
    sym_aes_key_t *aes_key = sym_aes_create_key(key, 8);
    EXPECT_EQ(aes_key, nullptr);
}

TEST_F(AESTest, CreateKeyNull) {
    sym_aes_key_t *aes_key = sym_aes_create_key(nullptr, KEY_LENGTH_BYTES);
    EXPECT_EQ(aes_key, nullptr);
}

TEST_F(AESTest, DestroyKeyNull) {
    sym_aes_destroy_key(nullptr);
    SUCCEED();
}

// ============================================================================
// Transformation Tests
// ============================================================================

TEST_F(AESTest, SubBytes) {
    uint8_t state[16] = {
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
        0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0
    };
    
    int result = sym_aes_enc_sub_bytes(state);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(state[0], 0x63);
}

TEST_F(AESTest, SubBytesNull) {
    int result = sym_aes_enc_sub_bytes(nullptr);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

TEST_F(AESTest, ShiftRows) {
    uint8_t state[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    
    int result = sym_aes_enc_shift_rows(state);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(state[1], 0x05);
    EXPECT_EQ(state[5], 0x09);
}

TEST_F(AESTest, MixColumns) {
    uint8_t state[16] = {
        0xdb, 0x13, 0x53, 0x45,
        0xf2, 0x0a, 0x22, 0x5c,
        0x01, 0x01, 0x01, 0x01,
        0xc6, 0xc6, 0xc6, 0xc6
    };
    
    int result = sym_aes_enc_mix_cols(state);
    EXPECT_EQ(result, AES_SUCCESS);
}

TEST_F(AESTest, AddRoundKey) {
    uint8_t state[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    uint8_t round_key[16] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    
    int result = sym_aes_enc_add_round_keys(state, round_key);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(state[0], 0xff);
    EXPECT_EQ(state[15], 0xff);
}

// ============================================================================
// Edge Cases and Stress Tests
// ============================================================================

TEST_F(AESTest, LargeMessage) {
    size_t size = 1024;
    std::vector<uint8_t> plaintext(size);
    std::vector<uint8_t> ciphertext(size + AES_BLOCK_SIZE);
    std::vector<uint8_t> decrypted(size + AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < size; i++) {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }
    
    size_t ciphertext_len, decrypted_len;
    
    sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    ASSERT_NE(ctx_enc, nullptr);
    ASSERT_NE(ctx_dec, nullptr);
    
    sym_aes_enc_set_iv(ctx_enc, iv);
    sym_aes_dnc_set_iv(ctx_dec, iv);
    
    EXPECT_EQ(sym_aes_encrypt_cbc(ctx_enc, plaintext.data(), size,
                                   ciphertext.data(), &ciphertext_len), AES_SUCCESS);
    EXPECT_EQ(sym_aes_decrypt_cbc(ctx_dec, ciphertext.data(), ciphertext_len,
                                   decrypted.data(), &decrypted_len), AES_SUCCESS);
    
    EXPECT_EQ(decrypted_len, size);
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), size), 0);
    
    sym_aes_ctx_destroy(ctx_enc);
    sym_aes_ctx_destroy(ctx_dec);
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}