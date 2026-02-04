/**
 * @file tests/test_aes.cpp
 * @brief Unit tests for AES-128 implementation using Google Test
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <cmath>

extern "C" {
    #include "src/symmetric/aes.h"
}

// ============================================================================
// Test Fixture
// ============================================================================

class AESTest : public ::testing::Test {
protected:
    sym_aes_ctx_t *ctx;
    uint8_t key[KEY_LENGTH_BYTES];
    uint8_t iv[AES_BLOCK_SIZE];
    
    void SetUp() override {
        // Initialize with a standard test key
        for (int i = 0; i < KEY_LENGTH_BYTES; i++) {
            key[i] = i;
        }
        
        // Initialize with a standard test IV
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            iv[i] = i;
        }
        
        ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    }
    
    void TearDown() override {
        if (ctx) {
            sym_aes_ctx_destroy(ctx);
            ctx = nullptr;
        }
    }
    
    // Helper: compare two byte arrays
    bool compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
        return memcmp(a, b, len) == 0;
    }
    
    // Helper: get high-resolution time
    double get_time_ms() {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration<double, std::milli>(duration).count();
    }
};

// ============================================================================
// Context Management Tests
// ============================================================================

TEST_F(AESTest, ContextInitialization) {
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->iv_initialized, 0);
}

TEST_F(AESTest, ContextInitializationInvalidKeyLength) {
    sym_aes_ctx_t *invalid_ctx = sym_aes_ctx_init(key, 32); // Wrong length
    EXPECT_EQ(invalid_ctx, nullptr);
}

TEST_F(AESTest, ContextInitializationNullKey) {
    sym_aes_ctx_t *invalid_ctx = sym_aes_ctx_init(nullptr, KEY_LENGTH_BYTES);
    EXPECT_EQ(invalid_ctx, nullptr);
}

TEST_F(AESTest, ContextDestroy) {
    sym_aes_ctx_t *temp_ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    ASSERT_NE(temp_ctx, nullptr);
    sym_aes_ctx_destroy(temp_ctx);
    // If we get here without crash, test passes
    SUCCEED();
}

TEST_F(AESTest, ContextDestroyNull) {
    sym_aes_ctx_destroy(nullptr);
    SUCCEED();
}

TEST_F(AESTest, ContextClear) {
    sym_aes_ctx_t *cleared = sym_aes_ctx_clear(ctx);
    EXPECT_EQ(cleared, ctx);
    EXPECT_EQ(ctx->iv_initialized, 0);
}

TEST_F(AESTest, SetIVEncryption) {
    int result = sym_aes_enc_set_iv(ctx, iv);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ctx->iv_initialized, 1);
    EXPECT_TRUE(compare_bytes(ctx->iv, iv, AES_BLOCK_SIZE));
}

TEST_F(AESTest, SetIVDecryption) {
    int result = sym_aes_dnc_set_iv(ctx, iv);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ctx->iv_initialized, 1);
    EXPECT_TRUE(compare_bytes(ctx->iv, iv, AES_BLOCK_SIZE));
}

TEST_F(AESTest, SetIVNullContext) {
    int result = sym_aes_enc_set_iv(nullptr, iv);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

TEST_F(AESTest, SetIVNullIV) {
    int result = sym_aes_enc_set_iv(ctx, nullptr);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

// ============================================================================
// ECB Mode Tests - Known Test Vectors (NIST FIPS 197)
// ============================================================================

TEST_F(AESTest, ECBEncryptionNISTTestVector1) {
    // NIST Test Vector - Appendix B
    uint8_t test_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t expected_ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    uint8_t ciphertext[16];
    
    sym_aes_ctx_t *test_ctx = sym_aes_ctx_init(test_key, 16);
    ASSERT_NE(test_ctx, nullptr);
    
    int result = sym_aes_encryption(test_ctx, plaintext, ciphertext);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_TRUE(compare_bytes(ciphertext, expected_ciphertext, 16));
    
    sym_aes_ctx_destroy(test_ctx);
}

TEST_F(AESTest, ECBDecryptionNISTTestVector1) {
    // Same test vector as above, but decryption
    uint8_t test_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    uint8_t expected_plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t plaintext[16];
    
    sym_aes_ctx_t *test_ctx = sym_aes_ctx_init(test_key, 16);
    ASSERT_NE(test_ctx, nullptr);
    
    int result = sym_aes_decryption(test_ctx, ciphertext, plaintext);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_TRUE(compare_bytes(plaintext, expected_plaintext, 16));
    
    sym_aes_ctx_destroy(test_ctx);
}

TEST_F(AESTest, ECBEncryptDecryptRoundTrip) {
    uint8_t plaintext[16] = {
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'A',
        'E', 'S', '-', '1', '2', '8', '!', '!'
    };
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    int result = sym_aes_encryption(ctx, plaintext, ciphertext);
    EXPECT_EQ(result, AES_SUCCESS);
    
    result = sym_aes_decryption(ctx, ciphertext, decrypted);
    EXPECT_EQ(result, AES_SUCCESS);
    
    EXPECT_TRUE(compare_bytes(plaintext, decrypted, 16));
}

TEST_F(AESTest, ECBEncryptionNullParameters) {
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    
    EXPECT_EQ(sym_aes_encryption(nullptr, plaintext, ciphertext), AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encryption(ctx, nullptr, ciphertext), AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encryption(ctx, plaintext, nullptr), AES_ERROR_INVALID_PARAM);
}

// ============================================================================
// CBC Mode Tests
// ============================================================================

TEST_F(AESTest, CBCEncryptionBasic) {
    uint8_t plaintext[] = "This is a test message for CBC mode encryption!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    int result = sym_aes_encrypt_cbc(ctx, plaintext, plaintext_len, 
                                      ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_GT(ciphertext_len, plaintext_len);
    EXPECT_EQ(ciphertext_len % AES_BLOCK_SIZE, 0);
}

TEST_F(AESTest, CBCDecryptionBasic) {
    uint8_t plaintext[] = "This is a test message for CBC mode encryption!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    uint8_t decrypted[1024];
    size_t decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_cbc(ctx, plaintext, plaintext_len, 
                                      ciphertext, &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_cbc(ctx, ciphertext, ciphertext_len, 
                                  decrypted, &decrypted_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(decrypted_len, plaintext_len);
    EXPECT_TRUE(compare_bytes(plaintext, decrypted, plaintext_len));
}

TEST_F(AESTest, CBCEncryptionWithoutIV) {
    uint8_t plaintext[] = "Test message";
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    int result = sym_aes_encrypt_cbc(ctx, plaintext, strlen((char*)plaintext), 
                                      ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_ERROR_IV_NOT_SET);
}

TEST_F(AESTest, CBCDecryptionWithoutIV) {
    uint8_t ciphertext[32] = {0};
    uint8_t plaintext[1024];
    size_t plaintext_len;
    
    int result = sym_aes_decrypt_cbc(ctx, ciphertext, 32, 
                                      plaintext, &plaintext_len);
    EXPECT_EQ(result, AES_ERROR_IV_NOT_SET);
}

TEST_F(AESTest, CBCMultipleBlocks) {
    // Test with exactly 3 blocks (48 bytes)
    uint8_t plaintext[48];
    for (int i = 0; i < 48; i++) plaintext[i] = i;
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    uint8_t decrypted[1024];
    size_t decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_cbc(ctx, plaintext, 48, 
                                      ciphertext, &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_cbc(ctx, ciphertext, ciphertext_len, 
                                  decrypted, &decrypted_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(decrypted_len, 48);
    EXPECT_TRUE(compare_bytes(plaintext, decrypted, 48));
}

TEST_F(AESTest, CBCNullParameters) {
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[32];
    size_t len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    EXPECT_EQ(sym_aes_encrypt_cbc(nullptr, plaintext, 16, ciphertext, &len), 
              AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encrypt_cbc(ctx, nullptr, 16, ciphertext, &len), 
              AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encrypt_cbc(ctx, plaintext, 16, nullptr, &len), 
              AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_encrypt_cbc(ctx, plaintext, 16, ciphertext, nullptr), 
              AES_ERROR_INVALID_PARAM);
}

// ============================================================================
// CTR Mode Tests
// ============================================================================

TEST_F(AESTest, CTREncryptionBasic) {
    uint8_t plaintext[] = "CTR mode test message - any length works!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    int result = sym_aes_encrypt_ctr(ctx, plaintext, plaintext_len, 
                                      ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ciphertext_len, plaintext_len); // CTR doesn't add padding
}

TEST_F(AESTest, CTRDecryptionBasic) {
    uint8_t plaintext[] = "CTR mode test message - any length works!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    uint8_t decrypted[1024];
    size_t decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_ctr(ctx, plaintext, plaintext_len, 
                                      ciphertext, &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_ctr(ctx, ciphertext, ciphertext_len, 
                                  decrypted, &decrypted_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(decrypted_len, plaintext_len);
    EXPECT_TRUE(compare_bytes(plaintext, decrypted, plaintext_len));
}

TEST_F(AESTest, CTREncryptionWithoutIV) {
    uint8_t plaintext[] = "Test";
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    int result = sym_aes_encrypt_ctr(ctx, plaintext, 4, 
                                      ciphertext, &ciphertext_len);
    EXPECT_EQ(result, AES_ERROR_IV_NOT_SET);
}

TEST_F(AESTest, CTRNonBlockAlignedData) {
    // CTR mode should work with any length
    uint8_t plaintext[37]; // Not a multiple of 16
    for (int i = 0; i < 37; i++) plaintext[i] = i;
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    uint8_t decrypted[1024];
    size_t decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_ctr(ctx, plaintext, 37, 
                                      ciphertext, &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(ciphertext_len, 37);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_ctr(ctx, ciphertext, ciphertext_len, 
                                  decrypted, &decrypted_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(decrypted_len, 37);
    EXPECT_TRUE(compare_bytes(plaintext, decrypted, 37));
}

TEST_F(AESTest, CTRLargeData) {
    // Test with larger data
    size_t data_size = 1000;
    std::vector<uint8_t> plaintext(data_size);
    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = i % 256;
    }
    
    std::vector<uint8_t> ciphertext(data_size + 16);
    size_t ciphertext_len;
    
    std::vector<uint8_t> decrypted(data_size + 16);
    size_t decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_ctr(ctx, plaintext.data(), data_size, 
                                      ciphertext.data(), &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_ctr(ctx, ciphertext.data(), ciphertext_len, 
                                  decrypted.data(), &decrypted_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(decrypted_len, data_size);
    EXPECT_TRUE(compare_bytes(plaintext.data(), decrypted.data(), data_size));
}

// ============================================================================
// PKCS#7 Padding Tests
// ============================================================================

TEST_F(AESTest, PKCS7PaddingExactBlock) {
    // Data that is exactly one block (16 bytes)
    uint8_t data[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    uint8_t padded[32];
    size_t padded_len;
    
    int result = sym_aes_pkcs7_pad(data, 16, padded, &padded_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(padded_len, 32); // Should add full block of padding
    
    // Last 16 bytes should all be 0x10
    for (int i = 16; i < 32; i++) {
        EXPECT_EQ(padded[i], 16);
    }
}

TEST_F(AESTest, PKCS7PaddingPartialBlock) {
    // Data that needs 5 bytes of padding
    const char* hello_world = "Hello World";
    uint8_t data[11];
    memcpy(data, hello_world, 11);
    
    uint8_t padded[32];
    size_t padded_len;
    
    int result = sym_aes_pkcs7_pad(data, 11, padded, &padded_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(padded_len, 16);
    
    // Last 5 bytes should be 0x05
    for (int i = 11; i < 16; i++) {
        EXPECT_EQ(padded[i], 5);
    }
}

TEST_F(AESTest, PKCS7UnpaddingValid) {
    uint8_t padded[16] = {
        'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd',
        0x05, 0x05, 0x05, 0x05, 0x05
    };
    
    uint8_t data[16];
    size_t data_len;
    
    int result = sym_aes_pkcs7_unpad(padded, 16, data, &data_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(data_len, 11);
    EXPECT_EQ(memcmp(data, "Hello World", 11), 0);
}

TEST_F(AESTest, PKCS7UnpaddingInvalidPadding) {
    uint8_t padded[16] = {
        'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd',
        0x05, 0x05, 0x05, 0x04, 0x05  // Invalid: inconsistent padding
    };
    
    uint8_t data[16];
    size_t data_len;
    
    int result = sym_aes_pkcs7_unpad(padded, 16, data, &data_len);
    EXPECT_EQ(result, AES_ERROR_INVALID_PADDING);
}

TEST_F(AESTest, PKCS7PaddingRoundTrip) {
    uint8_t original[23] = "Test padding roundtrip";
    uint8_t padded[32];
    size_t padded_len;
    
    uint8_t unpadded[32];
    size_t unpadded_len;
    
    int result = sym_aes_pkcs7_pad(original, 23, padded, &padded_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    result = sym_aes_pkcs7_unpad(padded, padded_len, unpadded, &unpadded_len);
    EXPECT_EQ(result, AES_SUCCESS);
    EXPECT_EQ(unpadded_len, 23);
    EXPECT_TRUE(compare_bytes(original, unpadded, 23));
}

// ============================================================================
// Key Management Tests
// ============================================================================

TEST_F(AESTest, CreateKey) {
    uint8_t key_data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    sym_aes_key_t *aes_key = sym_aes_create_key(key_data, 16);
    ASSERT_NE(aes_key, nullptr);
    EXPECT_EQ(aes_key->key_length, 16);
    EXPECT_TRUE(compare_bytes(aes_key->key_data, key_data, 16));
    
    sym_aes_destroy_key(aes_key);
}

TEST_F(AESTest, CreateKeyInvalidLength) {
    uint8_t key_data[32] = {0};
    sym_aes_key_t *aes_key = sym_aes_create_key(key_data, 32);
    EXPECT_EQ(aes_key, nullptr);
}

TEST_F(AESTest, CreateKeyNullData) {
    sym_aes_key_t *aes_key = sym_aes_create_key(nullptr, 16);
    EXPECT_EQ(aes_key, nullptr);
}

TEST_F(AESTest, DestroyKey) {
    uint8_t key_data[16] = {0};
    sym_aes_key_t *aes_key = sym_aes_create_key(key_data, 16);
    ASSERT_NE(aes_key, nullptr);
    
    sym_aes_destroy_key(aes_key);
    SUCCEED();
}

TEST_F(AESTest, DestroyKeyNull) {
    sym_aes_destroy_key(nullptr);
    SUCCEED();
}

// ============================================================================
// Transformation Function Tests
// ============================================================================

TEST_F(AESTest, SubBytesTransformation) {
    uint8_t state[16] = {
        0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b,
        0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08
    };
    
    int result = sym_aes_enc_sub_bytes(state);
    EXPECT_EQ(result, AES_SUCCESS);
    
    // After SubBytes, values should be different
    EXPECT_NE(state[0], 0x19);
}

TEST_F(AESTest, SubBytesNullParameter) {
    int result = sym_aes_enc_sub_bytes(nullptr);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

TEST_F(AESTest, ShiftRowsTransformation) {
    uint8_t state[16];
    for (int i = 0; i < 16; i++) state[i] = i;
    
    int result = sym_aes_enc_shift_rows(state);
    EXPECT_EQ(result, AES_SUCCESS);
    
    // Row 0 should be unchanged
    EXPECT_EQ(state[0], 0);
    EXPECT_EQ(state[4], 4);
    EXPECT_EQ(state[8], 8);
    EXPECT_EQ(state[12], 12);
}

TEST_F(AESTest, ShiftRowsNullParameter) {
    int result = sym_aes_enc_shift_rows(nullptr);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

TEST_F(AESTest, MixColumnsTransformation) {
    uint8_t state[16] = {
        0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae,
        0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5
    };
    
    int result = sym_aes_enc_mix_cols(state);
    EXPECT_EQ(result, AES_SUCCESS);
}

TEST_F(AESTest, MixColumnsNullParameter) {
    int result = sym_aes_enc_mix_cols(nullptr);
    EXPECT_EQ(result, AES_ERROR_INVALID_PARAM);
}

TEST_F(AESTest, AddRoundKeyTransformation) {
    uint8_t state[16];
    uint8_t round_key[16];
    
    for (int i = 0; i < 16; i++) {
        state[i] = i;
        round_key[i] = i * 2;
    }
    
    int result = sym_aes_enc_add_round_keys(state, round_key);
    EXPECT_EQ(result, AES_SUCCESS);
    
    // XOR should have occurred
    for (int i = 0; i < 16; i++) {
        EXPECT_EQ(state[i], i ^ (i * 2));
    }
}

TEST_F(AESTest, AddRoundKeyNullParameter) {
    uint8_t state[16] = {0};
    uint8_t round_key[16] = {0};
    
    EXPECT_EQ(sym_aes_enc_add_round_keys(nullptr, round_key), 
              AES_ERROR_INVALID_PARAM);
    EXPECT_EQ(sym_aes_enc_add_round_keys(state, nullptr), 
              AES_ERROR_INVALID_PARAM);
}

// ============================================================================
// PERFORMANCE ANALYSIS TESTS
// ============================================================================

class AESPerformanceTest : public AESTest {
protected:
    struct PerformanceMetrics {
        double mean_time_ms;
        double std_dev_ms;
        double min_time_ms;
        double max_time_ms;
        double throughput_mbps;
        size_t iterations;
    };
    
    PerformanceMetrics measure_performance(
        std::function<void()> operation,
        size_t iterations,
        size_t data_size_bytes = 0) {
        
        std::vector<double> times;
        times.reserve(iterations);
        
        for (size_t i = 0; i < iterations; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            operation();
            auto end = std::chrono::high_resolution_clock::now();
            
            double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(duration_ms);
        }
        
        PerformanceMetrics metrics;
        metrics.iterations = iterations;
        
        // Calculate mean
        metrics.mean_time_ms = std::accumulate(times.begin(), times.end(), 0.0) / iterations;
        
        // Calculate standard deviation
        double variance = 0.0;
        for (double time : times) {
            variance += (time - metrics.mean_time_ms) * (time - metrics.mean_time_ms);
        }
        metrics.std_dev_ms = std::sqrt(variance / iterations);
        
        // Min and max
        metrics.min_time_ms = *std::min_element(times.begin(), times.end());
        metrics.max_time_ms = *std::max_element(times.begin(), times.end());
        
        // Throughput (if data size provided)
        if (data_size_bytes > 0 && metrics.mean_time_ms > 0) {
            double bytes_per_second = (data_size_bytes * iterations) / (metrics.mean_time_ms / 1000.0);
            metrics.throughput_mbps = (bytes_per_second * 8.0) / (1024.0 * 1024.0);
        } else {
            metrics.throughput_mbps = 0.0;
        }
        
        return metrics;
    }
    
    void print_performance_results(const std::string& test_name, const PerformanceMetrics& metrics) {
        std::cout << "\n=== " << test_name << " ===" << std::endl;
        std::cout << "Iterations: " << metrics.iterations << std::endl;
        std::cout << "Mean time: " << metrics.mean_time_ms << " ms" << std::endl;
        std::cout << "Std dev: " << metrics.std_dev_ms << " ms" << std::endl;
        std::cout << "Min time: " << metrics.min_time_ms << " ms" << std::endl;
        std::cout << "Max time: " << metrics.max_time_ms << " ms" << std::endl;
        if (metrics.throughput_mbps > 0) {
            std::cout << "Throughput: " << metrics.throughput_mbps << " Mbps" << std::endl;
        }
        std::cout << std::endl;
    }
};

TEST_F(AESPerformanceTest, ECBSingleBlockPerformance) {
    uint8_t plaintext[16] = {
        'T', 'e', 's', 't', ' ', 'b', 'l', 'o',
        'c', 'k', ' ', 'd', 'a', 't', 'a', '!'
    };
    uint8_t ciphertext[16];
    
    const size_t iterations = 10000;
    
    auto operation = [&]() {
        sym_aes_encryption(ctx, plaintext, ciphertext);
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations, 16);
    print_performance_results("ECB Single Block Encryption", metrics);
    
    EXPECT_GT(metrics.throughput_mbps, 0);
}

TEST_F(AESPerformanceTest, CBCThroughputSmallData) {
    const size_t data_size = 100;  // 100 bytes
    std::vector<uint8_t> plaintext(data_size, 0xAA);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    const size_t iterations = 1000;
    
    auto operation = [&]() {
        sym_aes_encrypt_cbc(ctx, plaintext.data(), data_size, 
                           ciphertext.data(), &ciphertext_len);
        sym_aes_enc_set_iv(ctx, iv); // Reset IV for next iteration
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations, data_size);
    print_performance_results("CBC Encryption (100 bytes)", metrics);
    
    EXPECT_GT(metrics.throughput_mbps, 0);
}

TEST_F(AESPerformanceTest, CBCThroughputMediumData) {
    const size_t data_size = 1024;  // 1 KB
    std::vector<uint8_t> plaintext(data_size, 0xBB);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    const size_t iterations = 1000;
    
    auto operation = [&]() {
        sym_aes_encrypt_cbc(ctx, plaintext.data(), data_size, 
                           ciphertext.data(), &ciphertext_len);
        sym_aes_enc_set_iv(ctx, iv);
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations, data_size);
    print_performance_results("CBC Encryption (1 KB)", metrics);
    
    EXPECT_GT(metrics.throughput_mbps, 0);
}

TEST_F(AESPerformanceTest, CBCThroughputLargeData) {
    const size_t data_size = 10240;  // 10 KB
    std::vector<uint8_t> plaintext(data_size, 0xCC);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    const size_t iterations = 500;
    
    auto operation = [&]() {
        sym_aes_encrypt_cbc(ctx, plaintext.data(), data_size, 
                           ciphertext.data(), &ciphertext_len);
        sym_aes_enc_set_iv(ctx, iv);
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations, data_size);
    print_performance_results("CBC Encryption (10 KB)", metrics);
    
    EXPECT_GT(metrics.throughput_mbps, 0);
}

TEST_F(AESPerformanceTest, CTRThroughputComparison) {
    const size_t data_size = 1024;  // 1 KB
    std::vector<uint8_t> plaintext(data_size, 0xDD);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    
    const size_t iterations = 1000;
    
    auto operation = [&]() {
        sym_aes_encrypt_ctr(ctx, plaintext.data(), data_size, 
                           ciphertext.data(), &ciphertext_len);
        sym_aes_enc_set_iv(ctx, iv);
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations, data_size);
    print_performance_results("CTR Encryption (1 KB)", metrics);
    
    EXPECT_GT(metrics.throughput_mbps, 0);
}

TEST_F(AESPerformanceTest, KeyExpansionPerformance) {
    uint8_t test_key[16] = {0};
    
    const size_t iterations = 10000;
    
    auto operation = [&]() {
        sym_aes_ctx_t *temp_ctx = sym_aes_ctx_init(test_key, 16);
        sym_aes_ctx_destroy(temp_ctx);
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations);
    print_performance_results("Key Expansion (Context Init/Destroy)", metrics);
    
    EXPECT_LT(metrics.mean_time_ms, 1.0); // Should be very fast
}

TEST_F(AESPerformanceTest, EncryptionDecryptionRoundTripPerformance) {
    const size_t data_size = 1024;
    std::vector<uint8_t> plaintext(data_size, 0xEE);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    std::vector<uint8_t> decrypted(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len, decrypted_len;
    
    const size_t iterations = 500;
    
    auto operation = [&]() {
        sym_aes_enc_set_iv(ctx, iv);
        sym_aes_encrypt_cbc(ctx, plaintext.data(), data_size, 
                           ciphertext.data(), &ciphertext_len);
        
        sym_aes_dnc_set_iv(ctx, iv);
        sym_aes_decrypt_cbc(ctx, ciphertext.data(), ciphertext_len, 
                           decrypted.data(), &decrypted_len);
    };
    
    PerformanceMetrics metrics = measure_performance(operation, iterations, data_size * 2);
    print_performance_results("CBC Round Trip (Encrypt + Decrypt, 1 KB)", metrics);
    
    EXPECT_GT(metrics.throughput_mbps, 0);
}

// ============================================================================
// DATA INTEGRITY TESTS
// ============================================================================

TEST_F(AESTest, DataIntegrityAfterMultipleOperations) {
    const size_t num_operations = 100;
    uint8_t original[64];
    for (int i = 0; i < 64; i++) original[i] = i;
    
    uint8_t ciphertext[128];
    size_t ciphertext_len;
    
    uint8_t decrypted[128];
    size_t decrypted_len;
    
    // Perform multiple encryption/decryption cycles
    for (size_t i = 0; i < num_operations; i++) {
        sym_aes_enc_set_iv(ctx, iv);
        int result = sym_aes_encrypt_cbc(ctx, original, 64, 
                                         ciphertext, &ciphertext_len);
        ASSERT_EQ(result, AES_SUCCESS);
        
        sym_aes_dnc_set_iv(ctx, iv);
        result = sym_aes_decrypt_cbc(ctx, ciphertext, ciphertext_len, 
                                     decrypted, &decrypted_len);
        ASSERT_EQ(result, AES_SUCCESS);
        
        ASSERT_TRUE(compare_bytes(original, decrypted, 64));
    }
}

TEST_F(AESTest, CiphertextDifferentWithDifferentIVs) {
    uint8_t plaintext[] = "Same plaintext for both encryptions";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t iv1[16], iv2[16];
    for (int i = 0; i < 16; i++) {
        iv1[i] = i;
        iv2[i] = i + 1;
    }
    
    uint8_t ciphertext1[128], ciphertext2[128];
    size_t ciphertext1_len, ciphertext2_len;
    
    sym_aes_enc_set_iv(ctx, iv1);
    sym_aes_encrypt_cbc(ctx, plaintext, plaintext_len, ciphertext1, &ciphertext1_len);
    
    sym_aes_enc_set_iv(ctx, iv2);
    sym_aes_encrypt_cbc(ctx, plaintext, plaintext_len, ciphertext2, &ciphertext2_len);
    
    // Ciphertexts should be different
    EXPECT_FALSE(compare_bytes(ciphertext1, ciphertext2, ciphertext1_len));
}

TEST_F(AESTest, CiphertextDifferentWithDifferentKeys) {
    uint8_t key1[16], key2[16];
    for (int i = 0; i < 16; i++) {
        key1[i] = i;
        key2[i] = i + 1;
    }
    
    uint8_t plaintext[] = "Same plaintext for both encryptions";
    size_t plaintext_len = strlen((char*)plaintext);
    
    sym_aes_ctx_t *ctx1 = sym_aes_ctx_init(key1, 16);
    sym_aes_ctx_t *ctx2 = sym_aes_ctx_init(key2, 16);
    
    uint8_t ciphertext1[128], ciphertext2[128];
    size_t ciphertext1_len, ciphertext2_len;
    
    sym_aes_enc_set_iv(ctx1, iv);
    sym_aes_encrypt_cbc(ctx1, plaintext, plaintext_len, ciphertext1, &ciphertext1_len);
    
    sym_aes_enc_set_iv(ctx2, iv);
    sym_aes_encrypt_cbc(ctx2, plaintext, plaintext_len, ciphertext2, &ciphertext2_len);
    
    // Ciphertexts should be different
    EXPECT_FALSE(compare_bytes(ciphertext1, ciphertext2, ciphertext1_len));
    
    sym_aes_ctx_destroy(ctx1);
    sym_aes_ctx_destroy(ctx2);
}

TEST_F(AESTest, BitFlipDetection) {
    uint8_t plaintext[] = "Original message for bit flip test";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    sym_aes_encrypt_cbc(ctx, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    
    // Flip a bit in the ciphertext
    ciphertext[5] ^= 0x01;
    
    uint8_t decrypted[128];
    size_t decrypted_len;
    
    sym_aes_dnc_set_iv(ctx, iv);
    int result = sym_aes_decrypt_cbc(ctx, ciphertext, ciphertext_len, 
                                     decrypted, &decrypted_len);
    
    // Decryption should succeed (CBC doesn't have built-in authentication)
    // but the plaintext should be different
    if (result == AES_SUCCESS) {
        EXPECT_FALSE(compare_bytes(plaintext, decrypted, plaintext_len));
    }
}

TEST_F(AESTest, ZeroDataEncryption) {
    const size_t data_size = 64;
    std::vector<uint8_t> zero_data(data_size, 0);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    std::vector<uint8_t> decrypted(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len, decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_cbc(ctx, zero_data.data(), data_size, 
                                     ciphertext.data(), &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    // Ciphertext should NOT be all zeros
    bool all_zeros = true;
    for (size_t i = 0; i < ciphertext_len; i++) {
        if (ciphertext[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_cbc(ctx, ciphertext.data(), ciphertext_len, 
                                 decrypted.data(), &decrypted_len);
    ASSERT_EQ(result, AES_SUCCESS);
    EXPECT_TRUE(compare_bytes(zero_data.data(), decrypted.data(), data_size));
}

TEST_F(AESTest, MaxDataEncryption) {
    const size_t data_size = 64;
    std::vector<uint8_t> max_data(data_size, 0xFF);
    std::vector<uint8_t> ciphertext(data_size + AES_BLOCK_SIZE);
    std::vector<uint8_t> decrypted(data_size + AES_BLOCK_SIZE);
    size_t ciphertext_len, decrypted_len;
    
    sym_aes_enc_set_iv(ctx, iv);
    int result = sym_aes_encrypt_cbc(ctx, max_data.data(), data_size, 
                                     ciphertext.data(), &ciphertext_len);
    ASSERT_EQ(result, AES_SUCCESS);
    
    sym_aes_dnc_set_iv(ctx, iv);
    result = sym_aes_decrypt_cbc(ctx, ciphertext.data(), ciphertext_len, 
                                 decrypted.data(), &decrypted_len);
    ASSERT_EQ(result, AES_SUCCESS);
    EXPECT_TRUE(compare_bytes(max_data.data(), decrypted.data(), data_size));
}

// ============================================================================
// SECURITY TESTS
// ============================================================================

TEST_F(AESTest, AvalancheEffect) {
    // Test that small change in plaintext causes significant change in ciphertext
    uint8_t plaintext1[16] = {
        'T', 'e', 's', 't', ' ', 'm', 'e', 's',
        's', 'a', 'g', 'e', ' ', '1', '2', '3'
    };
    uint8_t plaintext2[16] = {
        'T', 'e', 's', 't', ' ', 'm', 'e', 's',
        's', 'a', 'g', 'e', ' ', '1', '2', '4'  // Last char different
    };
    
    uint8_t ciphertext1[16];
    uint8_t ciphertext2[16];
    
    sym_aes_encryption(ctx, plaintext1, ciphertext1);
    sym_aes_encryption(ctx, plaintext2, ciphertext2);
    
    // Count different bits
    int different_bits = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t xor_result = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (xor_result & (1 << j)) {
                different_bits++;
            }
        }
    }
    
    // Should have significant difference (ideally ~50% of bits)
    // For 128 bits, expecting at least 40 bits different
    EXPECT_GT(different_bits, 40);
}

TEST_F(AESTest, KeyAvalancheEffect) {
    // Test that small change in key causes significant change in ciphertext
    uint8_t key1[16], key2[16];
    for (int i = 0; i < 16; i++) {
        key1[i] = i;
        key2[i] = i;
    }
    key2[0] ^= 0x01; // Flip one bit in key
    
    uint8_t plaintext[16] = {
        'T', 'e', 's', 't', ' ', 'm', 'e', 's',
        's', 'a', 'g', 'e', '!', '!', '!', '!'
    };
    uint8_t ciphertext1[16];
    uint8_t ciphertext2[16];
    
    sym_aes_ctx_t *ctx1 = sym_aes_ctx_init(key1, 16);
    sym_aes_ctx_t *ctx2 = sym_aes_ctx_init(key2, 16);
    
    sym_aes_encryption(ctx1, plaintext, ciphertext1);
    sym_aes_encryption(ctx2, plaintext, ciphertext2);
    
    // Count different bits
    int different_bits = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t xor_result = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (xor_result & (1 << j)) {
                different_bits++;
            }
        }
    }
    
    EXPECT_GT(different_bits, 40);
    
    sym_aes_ctx_destroy(ctx1);
    sym_aes_ctx_destroy(ctx2);
}

// ============================================================================
// Main function
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}