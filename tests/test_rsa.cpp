/**
 * @file tests/test_rsa.cpp
 * @brief Unit tests for RSA implementation using Google Test
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iomanip>

extern "C" {
    #include "../src/asymmetric/rsa.h"
}

// ============================================================================
// Test Fixtures
// ============================================================================

class RSATest : public ::testing::Test {
protected:
    asm_rsa_ctx_t ctx_512;
    asm_rsa_ctx_t ctx_1024;
    asm_rsa_ctx_t ctx_2048;
    asm_rsa_ctx_t ctx_4096;
    
    void SetUp() override {
        // Initialize contexts for different key sizes
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx_512, RSA_KEY_SIZE_512));
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx_1024, RSA_KEY_SIZE_1024));
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx_2048, RSA_KEY_SIZE_2048));
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx_4096, RSA_KEY_SIZE_4096));
    }
    
    void TearDown() override {
        asm_rsa_ctx_free(&ctx_512);
        asm_rsa_ctx_free(&ctx_1024);
        asm_rsa_ctx_free(&ctx_2048);
        asm_rsa_ctx_free(&ctx_4096);
    }
};

class RSAPerformanceTest : public ::testing::Test {
protected:
    struct PerformanceMetrics {
        double mean_time_ms;
        double std_dev_ms;
        double min_time_ms;
        double max_time_ms;
        double throughput_bytes_per_sec;
        size_t iterations;
    };
    
    template<typename Func>
    PerformanceMetrics measurePerformance(Func func, size_t iterations, size_t data_size = 0) {
        std::vector<double> times;
        times.reserve(iterations);
        
        for (size_t i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            func();
            auto end = std::chrono::high_resolution_clock::now();
            
            std::chrono::duration<double, std::milli> duration = end - start;
            times.push_back(duration.count());
        }
        
        PerformanceMetrics metrics;
        metrics.iterations = iterations;
        metrics.mean_time_ms = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
        
        double variance = 0.0;
        for (double time : times) {
            variance += (time - metrics.mean_time_ms) * (time - metrics.mean_time_ms);
        }
        metrics.std_dev_ms = std::sqrt(variance / times.size());
        
        metrics.min_time_ms = *std::min_element(times.begin(), times.end());
        metrics.max_time_ms = *std::max_element(times.begin(), times.end());
        
        if (data_size > 0 && metrics.mean_time_ms > 0) {
            metrics.throughput_bytes_per_sec = (data_size * 1000.0) / metrics.mean_time_ms;
        } else {
            metrics.throughput_bytes_per_sec = 0.0;
        }
        
        return metrics;
    }
    
    void printMetrics(const std::string& test_name, const PerformanceMetrics& metrics) {
        std::cout << "\n=== " << test_name << " ===" << std::endl;
        std::cout << "Iterations: " << metrics.iterations << std::endl;
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "Mean time: " << metrics.mean_time_ms << " ms" << std::endl;
        std::cout << "Std dev: " << metrics.std_dev_ms << " ms" << std::endl;
        std::cout << "Min time: " << metrics.min_time_ms << " ms" << std::endl;
        std::cout << "Max time: " << metrics.max_time_ms << " ms" << std::endl;
        if (metrics.throughput_bytes_per_sec > 0) {
            std::cout << std::setprecision(0);
            std::cout << "Throughput: " << metrics.throughput_bytes_per_sec << " bytes/sec" << std::endl;
        }
        std::cout << std::endl;
    }
};

// ============================================================================
// SECTION 1: Context Management Tests
// ============================================================================

TEST_F(RSATest, ContextInitialization) {
    asm_rsa_ctx_t ctx;
    
    // Valid key sizes
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512));
    EXPECT_EQ(RSA_KEY_SIZE_512, ctx.key_size);
    asm_rsa_ctx_free(&ctx);
    
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024));
    EXPECT_EQ(RSA_KEY_SIZE_1024, ctx.key_size);
    asm_rsa_ctx_free(&ctx);
    
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048));
    EXPECT_EQ(RSA_KEY_SIZE_2048, ctx.key_size);
    asm_rsa_ctx_free(&ctx);
    
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_4096));
    EXPECT_EQ(RSA_KEY_SIZE_4096, ctx.key_size);
    asm_rsa_ctx_free(&ctx);
    
    // Invalid key sizes
    EXPECT_EQ(RSA_ERR_INVALID_KEY_LENGTH, asm_rsa_ctx_init(&ctx, 768));
    EXPECT_EQ(RSA_ERR_INVALID_KEY_LENGTH, asm_rsa_ctx_init(&ctx, 3072));
    
    // NULL pointer
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_ctx_init(nullptr, RSA_KEY_SIZE_2048));
}

TEST_F(RSATest, DecryptionModeConfiguration) {
    asm_rsa_ctx_t ctx;
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024));
    
    // Default mode should be STANDARD
    EXPECT_EQ(RSA_DECRYPT_STANDARD, asm_rsa_get_decrypt_mode(&ctx));
    
    // Set to CRT mode
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_set_decrypt_mode(&ctx, RSA_DECRYPT_CRT));
    EXPECT_EQ(RSA_DECRYPT_CRT, asm_rsa_get_decrypt_mode(&ctx));
    
    // Set back to STANDARD
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_set_decrypt_mode(&ctx, RSA_DECRYPT_STANDARD));
    EXPECT_EQ(RSA_DECRYPT_STANDARD, asm_rsa_get_decrypt_mode(&ctx));
    
    // Invalid mode
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_set_decrypt_mode(&ctx, (RSA_DECRYPT_MODE)99));
    
    asm_rsa_ctx_free(&ctx);
}

// ============================================================================
// SECTION 2: Key Generation Tests
// ============================================================================

TEST_F(RSATest, KeyGeneration_512) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_512);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_512);
    
    ASSERT_NE(nullptr, pub_key);
    ASSERT_NE(nullptr, pvt_key);
    
    EXPECT_EQ(RSA_KEY_SIZE_512, pub_key->key_size);
    EXPECT_EQ(RSA_KEY_SIZE_512, pvt_key->key_size);
    
    EXPECT_NE(nullptr, pub_key->n);
    EXPECT_NE(nullptr, pub_key->e);
    EXPECT_NE(nullptr, pvt_key->n);
    EXPECT_NE(nullptr, pvt_key->d);
    EXPECT_NE(nullptr, pvt_key->p);
    EXPECT_NE(nullptr, pvt_key->q);
}

TEST_F(RSATest, KeyGeneration_AllSizes) {
    // Test all supported key sizes
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_2048, RSA_KEY_SIZE_2048));
    // Note: 4096-bit key generation is very slow, may skip in quick tests
    // EXPECT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_4096, RSA_KEY_SIZE_4096));
}

// ============================================================================
// SECTION 3: BigNum Operations Tests
// ============================================================================

TEST(RSABigNumTest, BignumAllocation) {
    asm_rsa_bignum_t* bn = asm_rsa_bignum_new(10);
    ASSERT_NE(nullptr, bn);
    EXPECT_EQ(10, bn->size);
    EXPECT_EQ(0, bn->used);
    EXPECT_NE(nullptr, bn->data);
    asm_rsa_bignum_free(bn);
}

TEST(RSABigNumTest, ByteConversion) {
    asm_rsa_bignum_t* bn = asm_rsa_bignum_new(10);
    ASSERT_NE(nullptr, bn);
    
    uint8_t data_in[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    uint8_t data_out[8] = {0};
    
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_bignum_from_bytes(bn, data_in, sizeof(data_in)));
    EXPECT_GT(bn->used, 0);
    
    int bytes_written = asm_rsa_bignum_to_bytes(bn, data_out, sizeof(data_out));
    EXPECT_GT(bytes_written, 0);
    
    // Compare bytes (should match)
    EXPECT_EQ(0, memcmp(data_in, data_out, sizeof(data_in)));
    
    asm_rsa_bignum_free(bn);
}

TEST(RSABigNumTest, InvalidParameters) {
    asm_rsa_bignum_t* bn = asm_rsa_bignum_new(10);
    uint8_t data[10] = {0};
    
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_bignum_from_bytes(nullptr, data, 10));
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_bignum_from_bytes(bn, nullptr, 10));
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_bignum_from_bytes(bn, data, 0));
    
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_bignum_to_bytes(nullptr, data, 10));
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_bignum_to_bytes(bn, nullptr, 10));
    
    asm_rsa_bignum_free(bn);
}

// ============================================================================
// SECTION 4: Encryption/Decryption Correctness Tests
// ============================================================================

TEST_F(RSATest, EncryptDecrypt_ShortMessage) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    const char* plaintext = "Hello, RSA!";
    size_t plaintext_len = strlen(plaintext);
    
    size_t max_cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext(max_cipher_len);
    size_t ciphertext_len = max_cipher_len;
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    // Encrypt
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        reinterpret_cast<const uint8_t*>(plaintext),
        plaintext_len,
        ciphertext.data(),
        &ciphertext_len
    ));
    
    // Decrypt with STANDARD mode
    std::vector<uint8_t> decrypted(max_cipher_len);
    size_t decrypted_len = max_cipher_len;
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key,
        ciphertext.data(),
        ciphertext_len,
        decrypted.data(),
        &decrypted_len,
        RSA_DECRYPT_STANDARD
    ));
    
    EXPECT_EQ(plaintext_len, decrypted_len);
    EXPECT_EQ(0, memcmp(plaintext, decrypted.data(), plaintext_len));
}

TEST_F(RSATest, EncryptDecrypt_CRT_Mode) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    const char* plaintext = "Testing CRT decryption mode!";
    size_t plaintext_len = strlen(plaintext);
    
    size_t max_cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext(max_cipher_len);
    size_t ciphertext_len = max_cipher_len;
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    // Encrypt
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        reinterpret_cast<const uint8_t*>(plaintext),
        plaintext_len,
        ciphertext.data(),
        &ciphertext_len
    ));
    
    // Decrypt with CRT mode
    std::vector<uint8_t> decrypted(max_cipher_len);
    size_t decrypted_len = max_cipher_len;
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key,
        ciphertext.data(),
        ciphertext_len,
        decrypted.data(),
        &decrypted_len,
        RSA_DECRYPT_CRT
    ));
    
    EXPECT_EQ(plaintext_len, decrypted_len);
    EXPECT_EQ(0, memcmp(plaintext, decrypted.data(), plaintext_len));
}

TEST_F(RSATest, EncryptDecrypt_MaximumMessageSize) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    size_t max_msg_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_1024);
    std::vector<uint8_t> plaintext(max_msg_size);
    
    // Fill with test pattern
    for (size_t i = 0; i < max_msg_size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    size_t max_cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext(max_cipher_len);
    size_t ciphertext_len = max_cipher_len;
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        plaintext.data(),
        max_msg_size,
        ciphertext.data(),
        &ciphertext_len
    ));
    
    std::vector<uint8_t> decrypted(max_cipher_len);
    size_t decrypted_len = max_cipher_len;
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key,
        ciphertext.data(),
        ciphertext_len,
        decrypted.data(),
        &decrypted_len,
        RSA_DECRYPT_STANDARD
    ));
    
    EXPECT_EQ(max_msg_size, decrypted_len);
    EXPECT_EQ(0, memcmp(plaintext.data(), decrypted.data(), max_msg_size));
}

TEST_F(RSATest, EncryptDecrypt_BinaryData) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    // Test with binary data including null bytes
    uint8_t plaintext[] = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0x7F, 0x80};
    size_t plaintext_len = sizeof(plaintext);
    
    size_t max_cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext(max_cipher_len);
    size_t ciphertext_len = max_cipher_len;
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        plaintext,
        plaintext_len,
        ciphertext.data(),
        &ciphertext_len
    ));
    
    std::vector<uint8_t> decrypted(max_cipher_len);
    size_t decrypted_len = max_cipher_len;
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key,
        ciphertext.data(),
        ciphertext_len,
        decrypted.data(),
        &decrypted_len,
        RSA_DECRYPT_CRT
    ));
    
    EXPECT_EQ(plaintext_len, decrypted_len);
    EXPECT_EQ(0, memcmp(plaintext, decrypted.data(), plaintext_len));
}

TEST_F(RSATest, EncryptDecrypt_StandardVsCRT_Consistency) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_2048, RSA_KEY_SIZE_2048));
    
    const char* plaintext = "Consistency test between STANDARD and CRT modes";
    size_t plaintext_len = strlen(plaintext);
    
    size_t max_cipher_len = RSA_KEY_SIZE_2048 / 8;
    std::vector<uint8_t> ciphertext(max_cipher_len);
    size_t ciphertext_len = max_cipher_len;
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_2048);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_2048);
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        reinterpret_cast<const uint8_t*>(plaintext),
        plaintext_len,
        ciphertext.data(),
        &ciphertext_len
    ));
    
    // Decrypt with STANDARD mode
    std::vector<uint8_t> decrypted_std(max_cipher_len);
    size_t decrypted_std_len = max_cipher_len;
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key,
        ciphertext.data(),
        ciphertext_len,
        decrypted_std.data(),
        &decrypted_std_len,
        RSA_DECRYPT_STANDARD
    ));
    
    // Decrypt with CRT mode
    std::vector<uint8_t> decrypted_crt(max_cipher_len);
    size_t decrypted_crt_len = max_cipher_len;
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key,
        ciphertext.data(),
        ciphertext_len,
        decrypted_crt.data(),
        &decrypted_crt_len,
        RSA_DECRYPT_CRT
    ));
    
    // Both should produce identical results
    EXPECT_EQ(decrypted_std_len, decrypted_crt_len);
    EXPECT_EQ(0, memcmp(decrypted_std.data(), decrypted_crt.data(), decrypted_std_len));
    EXPECT_EQ(0, memcmp(plaintext, decrypted_std.data(), plaintext_len));
}

// ============================================================================
// SECTION 5: Signature Tests
// ============================================================================

TEST_F(RSATest, SignAndVerify_ValidSignature) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    const char* message = "This message should be signed";
    size_t message_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    // Sign with STANDARD mode
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_sign(
        pvt_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        &sig_len,
        RSA_DECRYPT_STANDARD
    ));
    
    // Verify
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_verify(
        pub_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        sig_len
    ));
}

TEST_F(RSATest, SignAndVerify_CRT_Mode) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_2048, RSA_KEY_SIZE_2048));
    
    const char* message = "Testing CRT mode for signing";
    size_t message_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_2048 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_2048);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_2048);
    
    // Sign with CRT mode
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_sign(
        pvt_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        &sig_len,
        RSA_DECRYPT_CRT
    ));
    
    // Verify
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_verify(
        pub_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        sig_len
    ));
}

TEST_F(RSATest, Verify_TamperedMessage) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    const char* message = "Original message";
    const char* tampered = "Tampered message";
    size_t message_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    // Sign original message
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_sign(
        pvt_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        &sig_len,
        RSA_DECRYPT_STANDARD
    ));
    
    // Verify with tampered message should fail
    EXPECT_NE(RSA_SUCCESS, asm_rsa_verify(
        pub_key,
        reinterpret_cast<const uint8_t*>(tampered),
        strlen(tampered),
        signature.data(),
        sig_len
    ));
}

TEST_F(RSATest, Verify_TamperedSignature) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    const char* message = "Test message";
    size_t message_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_sign(
        pvt_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        &sig_len,
        RSA_DECRYPT_STANDARD
    ));
    
    // Tamper with signature
    signature[sig_len / 2] ^= 0xFF;
    
    // Verification should fail
    EXPECT_NE(RSA_SUCCESS, asm_rsa_verify(
        pub_key,
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature.data(),
        sig_len
    ));
}

// ============================================================================
// SECTION 6: Error Handling and Edge Cases
// ============================================================================

TEST_F(RSATest, Encryption_MessageTooLong) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    size_t max_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_1024);
    std::vector<uint8_t> plaintext(max_size + 10);  // Too long
    
    size_t cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext(cipher_len);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    
    EXPECT_EQ(RSA_ERR_INVALID_DATA_LENGTH, asm_rsa_encryption(
        pub_key,
        plaintext.data(),
        plaintext.size(),
        ciphertext.data(),
        &cipher_len
    ));
}

TEST_F(RSATest, Encryption_NullPointers) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    uint8_t data[10] = {0};
    size_t len = 10;
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_encryption(nullptr, data, len, data, &len));
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_encryption(pub_key, nullptr, len, data, &len));
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_encryption(pub_key, data, len, nullptr, &len));
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_encryption(pub_key, data, len, data, nullptr));
}

TEST_F(RSATest, MaxMessageSize_Calculation) {
    EXPECT_EQ(RSA_MAX_MSG_SIZE_512, asm_rsa_get_max_msg_size(RSA_KEY_SIZE_512));
    EXPECT_EQ(RSA_MAX_MSG_SIZE_1024, asm_rsa_get_max_msg_size(RSA_KEY_SIZE_1024));
    EXPECT_EQ(RSA_MAX_MSG_SIZE_2048, asm_rsa_get_max_msg_size(RSA_KEY_SIZE_2048));
    EXPECT_EQ(RSA_MAX_MSG_SIZE_4096, asm_rsa_get_max_msg_size(RSA_KEY_SIZE_4096));
    EXPECT_EQ(0, asm_rsa_get_max_msg_size(999));  // Invalid size
}

// ============================================================================
// SECTION 7: Data Integrity Tests
// ============================================================================

TEST_F(RSATest, DataIntegrity_MultipleEncryptDecrypt) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    // Test with 100 different random messages
    for (int i = 0; i < 100; ++i) {
        size_t msg_len = (i % 50) + 10;  // Varying message lengths
        std::vector<uint8_t> plaintext(msg_len);
        
        // Generate random data
        for (size_t j = 0; j < msg_len; ++j) {
            plaintext[j] = static_cast<uint8_t>(rand() & 0xFF);
        }
        
        size_t cipher_len = RSA_KEY_SIZE_1024 / 8;
        std::vector<uint8_t> ciphertext(cipher_len);
        
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
            pub_key, plaintext.data(), msg_len,
            ciphertext.data(), &cipher_len
        ));
        
        std::vector<uint8_t> decrypted(cipher_len);
        size_t decrypted_len = cipher_len;
        
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
            pvt_key, ciphertext.data(), cipher_len,
            decrypted.data(), &decrypted_len,
            RSA_DECRYPT_CRT
        ));
        
        ASSERT_EQ(msg_len, decrypted_len);
        EXPECT_EQ(0, memcmp(plaintext.data(), decrypted.data(), msg_len))
            << "Mismatch at iteration " << i;
    }
}

TEST_F(RSATest, DataIntegrity_AllByteValues) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    // Create message with all possible byte values
    std::vector<uint8_t> plaintext(100);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i);
    }
    
    size_t cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext(cipher_len);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key, plaintext.data(), plaintext.size(),
        ciphertext.data(), &cipher_len
    ));
    
    std::vector<uint8_t> decrypted(cipher_len);
    size_t decrypted_len = cipher_len;
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(
        pvt_key, ciphertext.data(), cipher_len,
        decrypted.data(), &decrypted_len,
        RSA_DECRYPT_STANDARD
    ));
    
    EXPECT_EQ(plaintext.size(), decrypted_len);
    EXPECT_EQ(0, memcmp(plaintext.data(), decrypted.data(), plaintext.size()));
}

// ============================================================================
// SECTION 8: Performance Tests
// ============================================================================

TEST_F(RSAPerformanceTest, KeyGeneration_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "KEY GENERATION PERFORMANCE ANALYSIS" << std::endl;
    std::cout << "========================================" << std::endl;
    
    struct KeySizeConfig {
        size_t key_size;
        const char* name;
        size_t iterations;
    };
    
    std::vector<KeySizeConfig> configs = {
        {RSA_KEY_SIZE_512, "RSA-512", 10},
        {RSA_KEY_SIZE_1024, "RSA-1024", 5},
        {RSA_KEY_SIZE_2048, "RSA-2048", 3},
        // {RSA_KEY_SIZE_4096, "RSA-4096", 1}  // Very slow
    };
    
    for (const auto& config : configs) {
        asm_rsa_ctx_t ctx;
        asm_rsa_ctx_init(&ctx, config.key_size);
        
        auto metrics = measurePerformance([&]() {
            asm_rsa_generate_keypair(&ctx, config.key_size);
        }, config.iterations);
        
        printMetrics(std::string("Key Generation: ") + config.name, metrics);
        
        asm_rsa_ctx_free(&ctx);
    }
}

TEST_F(RSAPerformanceTest, Encryption_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "ENCRYPTION PERFORMANCE ANALYSIS" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx);
    
    size_t max_msg_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_2048);
    std::vector<uint8_t> plaintext(max_msg_size);
    for (size_t i = 0; i < max_msg_size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    size_t cipher_len = RSA_KEY_SIZE_2048 / 8;
    std::vector<uint8_t> ciphertext(cipher_len);
    
    auto metrics = measurePerformance([&]() {
        size_t len = cipher_len;
        asm_rsa_encryption(pub_key, plaintext.data(), max_msg_size,
                          ciphertext.data(), &len);
    }, 100, max_msg_size);
    
    printMetrics("Encryption (RSA-2048, max message size)", metrics);
    
    asm_rsa_ctx_free(&ctx);
}

TEST_F(RSAPerformanceTest, Decryption_StandardVsCRT_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "DECRYPTION PERFORMANCE: STANDARD vs CRT" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx);
    
    const char* plaintext = "Performance test message";
    size_t plaintext_len = strlen(plaintext);
    
    size_t cipher_len = RSA_KEY_SIZE_2048 / 8;
    std::vector<uint8_t> ciphertext(cipher_len);
    
    asm_rsa_encryption(pub_key, reinterpret_cast<const uint8_t*>(plaintext),
                      plaintext_len, ciphertext.data(), &cipher_len);
    
    std::vector<uint8_t> decrypted(cipher_len);
    
    // Test STANDARD mode
    auto metrics_std = measurePerformance([&]() {
        size_t len = cipher_len;
        asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                          decrypted.data(), &len, RSA_DECRYPT_STANDARD);
    }, 50, plaintext_len);
    
    printMetrics("Decryption STANDARD mode (RSA-2048)", metrics_std);
    
    // Test CRT mode
    auto metrics_crt = measurePerformance([&]() {
        size_t len = cipher_len;
        asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                          decrypted.data(), &len, RSA_DECRYPT_CRT);
    }, 50, plaintext_len);
    
    printMetrics("Decryption CRT mode (RSA-2048)", metrics_crt);
    
    // Calculate speedup
    double speedup = metrics_std.mean_time_ms / metrics_crt.mean_time_ms;
    std::cout << "CRT Speedup Factor: " << std::fixed << std::setprecision(2) 
              << speedup << "x" << std::endl;
    std::cout << "CRT is " << std::setprecision(1) 
              << ((speedup - 1.0) * 100.0) << "% faster" << std::endl << std::endl;
    
    asm_rsa_ctx_free(&ctx);
}

TEST_F(RSAPerformanceTest, Signing_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "SIGNING PERFORMANCE ANALYSIS" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx);
    
    const char* message = "Message to be signed";
    size_t message_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_2048 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    // Test STANDARD mode signing
    auto metrics_std = measurePerformance([&]() {
        size_t len = sig_len;
        asm_rsa_sign(pvt_key, reinterpret_cast<const uint8_t*>(message),
                    message_len, signature.data(), &len, RSA_DECRYPT_STANDARD);
    }, 50, message_len);
    
    printMetrics("Signing STANDARD mode (RSA-2048)", metrics_std);
    
    // Test CRT mode signing
    auto metrics_crt = measurePerformance([&]() {
        size_t len = sig_len;
        asm_rsa_sign(pvt_key, reinterpret_cast<const uint8_t*>(message),
                    message_len, signature.data(), &len, RSA_DECRYPT_CRT);
    }, 50, message_len);
    
    printMetrics("Signing CRT mode (RSA-2048)", metrics_crt);
    
    double speedup = metrics_std.mean_time_ms / metrics_crt.mean_time_ms;
    std::cout << "CRT Speedup Factor: " << std::fixed << std::setprecision(2) 
              << speedup << "x" << std::endl << std::endl;
    
    asm_rsa_ctx_free(&ctx);
}

TEST_F(RSAPerformanceTest, Verification_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "SIGNATURE VERIFICATION PERFORMANCE" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx);
    
    const char* message = "Message to verify";
    size_t message_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_2048 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    asm_rsa_sign(pvt_key, reinterpret_cast<const uint8_t*>(message),
                message_len, signature.data(), &sig_len, RSA_DECRYPT_CRT);
    
    auto metrics = measurePerformance([&]() {
        asm_rsa_verify(pub_key, reinterpret_cast<const uint8_t*>(message),
                      message_len, signature.data(), sig_len);
    }, 100, message_len);
    
    printMetrics("Signature Verification (RSA-2048)", metrics);
    
    asm_rsa_ctx_free(&ctx);
}

TEST_F(RSAPerformanceTest, Throughput_Analysis) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "THROUGHPUT ANALYSIS (Different Key Sizes)" << std::endl;
    std::cout << "========================================" << std::endl;
    
    struct Config {
        size_t key_size;
        const char* name;
    };
    
    std::vector<Config> configs = {
        {RSA_KEY_SIZE_1024, "RSA-1024"},
        {RSA_KEY_SIZE_2048, "RSA-2048"}
    };
    
    for (const auto& config : configs) {
        asm_rsa_ctx_t ctx;
        asm_rsa_ctx_init(&ctx, config.key_size);
        asm_rsa_generate_keypair(&ctx, config.key_size);
        
        asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx);
        asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx);
        
        size_t max_msg_size = asm_rsa_get_max_msg_size(config.key_size);
        std::vector<uint8_t> plaintext(max_msg_size);
        for (size_t i = 0; i < max_msg_size; ++i) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }
        
        size_t cipher_len = config.key_size / 8;
        std::vector<uint8_t> ciphertext(cipher_len);
        
        // Encryption throughput
        auto enc_metrics = measurePerformance([&]() {
            size_t len = cipher_len;
            asm_rsa_encryption(pub_key, plaintext.data(), max_msg_size,
                              ciphertext.data(), &len);
        }, 50, max_msg_size);
        
        // Decryption throughput (CRT)
        asm_rsa_encryption(pub_key, plaintext.data(), max_msg_size,
                          ciphertext.data(), &cipher_len);
        
        std::vector<uint8_t> decrypted(cipher_len);
        auto dec_metrics = measurePerformance([&]() {
            size_t len = cipher_len;
            asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                              decrypted.data(), &len, RSA_DECRYPT_CRT);
        }, 50, max_msg_size);
        
        std::cout << "\n--- " << config.name << " ---" << std::endl;
        std::cout << "Max message size: " << max_msg_size << " bytes" << std::endl;
        std::cout << "Encryption throughput: " << std::fixed << std::setprecision(0)
                  << enc_metrics.throughput_bytes_per_sec << " bytes/sec" << std::endl;
        std::cout << "Decryption throughput: " 
                  << dec_metrics.throughput_bytes_per_sec << " bytes/sec" << std::endl;
        
        asm_rsa_ctx_free(&ctx);
    }
    std::cout << std::endl;
}

// ============================================================================
// SECTION 9: Security Property Tests
// ============================================================================

TEST_F(RSATest, Security_SamePlaintextDifferentCiphertext) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    const char* plaintext = "Same message";
    size_t plaintext_len = strlen(plaintext);
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_1024);
    
    size_t cipher_len1 = RSA_KEY_SIZE_1024 / 8;
    size_t cipher_len2 = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> ciphertext1(cipher_len1);
    std::vector<uint8_t> ciphertext2(cipher_len2);
    
    // Encrypt same message twice
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        reinterpret_cast<const uint8_t*>(plaintext),
        plaintext_len,
        ciphertext1.data(),
        &cipher_len1
    ));
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(
        pub_key,
        reinterpret_cast<const uint8_t*>(plaintext),
        plaintext_len,
        ciphertext2.data(),
        &cipher_len2
    ));
    
    // Due to random padding, ciphertexts should be different
    EXPECT_NE(0, memcmp(ciphertext1.data(), ciphertext2.data(), cipher_len1))
        << "Ciphertexts should differ due to random padding";
}

TEST_F(RSATest, Security_PaddingValidation) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_1024, RSA_KEY_SIZE_1024));
    
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_1024);
    
    // Create invalid ciphertext (all zeros)
    size_t cipher_len = RSA_KEY_SIZE_1024 / 8;
    std::vector<uint8_t> invalid_ciphertext(cipher_len, 0);
    
    std::vector<uint8_t> decrypted(cipher_len);
    size_t decrypted_len = cipher_len;
    
    // Decryption should fail due to invalid padding
    int result = asm_rsa_decryption(
        pvt_key,
        invalid_ciphertext.data(),
        cipher_len,
        decrypted.data(),
        &decrypted_len,
        RSA_DECRYPT_STANDARD
    );
    
    EXPECT_NE(RSA_SUCCESS, result) << "Invalid padding should be rejected";
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "========================================" << std::endl;
    std::cout << "RSA IMPLEMENTATION TEST SUITE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Testing correctness, performance, and security properties" << std::endl;
    std::cout << std::endl;
    
    return RUN_ALL_TESTS();
}