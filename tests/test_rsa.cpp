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
    
    void SetUp() override {
        ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx_512, RSA_KEY_SIZE_512));
    }
    
    void TearDown() override {
        asm_rsa_ctx_free(&ctx_512);
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
    // Check context was initialized correctly
    EXPECT_EQ(RSA_KEY_SIZE_512, ctx_512.key_size);
    EXPECT_NE(nullptr, ctx_512.pub_key);
    EXPECT_NE(nullptr, ctx_512.pvt_key);
}

TEST_F(RSATest, DecryptionModeConfiguration) {
    // Default mode should be STANDARD
    EXPECT_EQ(RSA_DECRYPT_STANDARD, asm_rsa_get_decrypt_mode(&ctx_512));
    
    // Set to CRT mode
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_set_decrypt_mode(&ctx_512, RSA_DECRYPT_CRT));
    EXPECT_EQ(RSA_DECRYPT_CRT, asm_rsa_get_decrypt_mode(&ctx_512));
    
    // Set back to STANDARD
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_set_decrypt_mode(&ctx_512, RSA_DECRYPT_STANDARD));
    EXPECT_EQ(RSA_DECRYPT_STANDARD, asm_rsa_get_decrypt_mode(&ctx_512));
    
    // Invalid mode
    EXPECT_EQ(RSA_ERR_INVALID_PARAM, asm_rsa_set_decrypt_mode(&ctx_512, (RSA_DECRYPT_MODE)99));
}

// ============================================================================
// SECTION 2: Key Generation Tests (Reduced to one size for speed)
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

// ============================================================================
// SECTION 4: Encryption/Decryption Tests (512-bit only for speed)
// ============================================================================

TEST_F(RSATest, EncryptDecrypt_ShortMessage) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_512);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_512);
    
    const char* message = "Hello RSA!";
    size_t msg_len = strlen(message);
    
    std::vector<uint8_t> ciphertext(RSA_KEY_SIZE_512 / 8);
    std::vector<uint8_t> decrypted(RSA_KEY_SIZE_512 / 8);
    
    size_t cipher_len = ciphertext.size();
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(pub_key, 
                                               reinterpret_cast<const uint8_t*>(message),
                                               msg_len, ciphertext.data(), &cipher_len));
    
    size_t decrypted_len = decrypted.size();
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                                               decrypted.data(), &decrypted_len,
                                               RSA_DECRYPT_STANDARD));
    
    EXPECT_EQ(msg_len, decrypted_len);
    EXPECT_EQ(0, memcmp(message, decrypted.data(), msg_len));
}

TEST_F(RSATest, EncryptDecrypt_MaxSize) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_512);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_512);
    
    size_t max_msg_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_512);
    std::vector<uint8_t> message(max_msg_size);
    for (size_t i = 0; i < max_msg_size; ++i) {
        message[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    std::vector<uint8_t> ciphertext(RSA_KEY_SIZE_512 / 8);
    std::vector<uint8_t> decrypted(RSA_KEY_SIZE_512 / 8);
    
    size_t cipher_len = ciphertext.size();
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(pub_key, message.data(), max_msg_size,
                                               ciphertext.data(), &cipher_len));
    
    size_t decrypted_len = decrypted.size();
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                                               decrypted.data(), &decrypted_len,
                                               RSA_DECRYPT_CRT));
    
    EXPECT_EQ(max_msg_size, decrypted_len);
    EXPECT_EQ(0, memcmp(message.data(), decrypted.data(), max_msg_size));
}

// ============================================================================
// SECTION 5: CRT vs STANDARD Comparison (Single test)
// ============================================================================

TEST_F(RSATest, CRT_vs_STANDARD_Correctness) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_512);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_512);
    
    const char* message = "Test CRT correctness";
    size_t msg_len = strlen(message);
    
    std::vector<uint8_t> ciphertext(RSA_KEY_SIZE_512 / 8);
    size_t cipher_len = ciphertext.size();
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_encryption(pub_key, 
                                               reinterpret_cast<const uint8_t*>(message),
                                               msg_len, ciphertext.data(), &cipher_len));
    
    // Decrypt with STANDARD mode
    std::vector<uint8_t> decrypted_std(RSA_KEY_SIZE_512 / 8);
    size_t decrypted_len_std = decrypted_std.size();
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                                               decrypted_std.data(), &decrypted_len_std,
                                               RSA_DECRYPT_STANDARD));
    
    // Decrypt with CRT mode
    std::vector<uint8_t> decrypted_crt(RSA_KEY_SIZE_512 / 8);
    size_t decrypted_len_crt = decrypted_crt.size();
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                                               decrypted_crt.data(), &decrypted_len_crt,
                                               RSA_DECRYPT_CRT));
    
    // Both should produce the same result
    EXPECT_EQ(decrypted_len_std, decrypted_len_crt);
    EXPECT_EQ(0, memcmp(decrypted_std.data(), decrypted_crt.data(), decrypted_len_std));
    EXPECT_EQ(0, memcmp(message, decrypted_std.data(), msg_len));
}

// ============================================================================
// SECTION 6: Signature Tests (Reduced)
// ============================================================================

TEST_F(RSATest, SignAndVerify_Basic) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_512);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_512);
    
    const char* message = "Sign this message";
    size_t msg_len = strlen(message);
    
    std::vector<uint8_t> signature(RSA_KEY_SIZE_512 / 8);
    size_t sig_len = signature.size();
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_sign(pvt_key,
                                         reinterpret_cast<const uint8_t*>(message),
                                         msg_len, signature.data(), &sig_len,
                                         RSA_DECRYPT_CRT));
    
    EXPECT_EQ(RSA_SUCCESS, asm_rsa_verify(pub_key,
                                           reinterpret_cast<const uint8_t*>(message),
                                           msg_len, signature.data(), sig_len));
}

TEST_F(RSATest, SignAndVerify_InvalidSignature) {
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx_512, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx_512);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx_512);
    
    const char* message = "Original message";
    const char* tampered = "Tampered message";
    size_t msg_len = strlen(message);
    
    std::vector<uint8_t> signature(RSA_KEY_SIZE_512 / 8);
    size_t sig_len = signature.size();
    
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_sign(pvt_key,
                                         reinterpret_cast<const uint8_t*>(message),
                                         msg_len, signature.data(), &sig_len,
                                         RSA_DECRYPT_STANDARD));
    
    // Verification should fail with tampered message
    EXPECT_NE(RSA_SUCCESS, asm_rsa_verify(pub_key,
                                           reinterpret_cast<const uint8_t*>(tampered),
                                           strlen(tampered), signature.data(), sig_len));
}

// ============================================================================
// SECTION 7: Performance Tests (Minimal, 512-bit only)
// ============================================================================

TEST_F(RSAPerformanceTest, KeyGeneration_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "KEY GENERATION PERFORMANCE (RSA-512)" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512));
    
    auto metrics = measurePerformance([&]() {
        asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    }, 10);  // Only 10 iterations for speed
    
    printMetrics("Key Generation (RSA-512)", metrics);
    
    asm_rsa_ctx_free(&ctx);
}

TEST_F(RSAPerformanceTest, Encryption_Decryption_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "ENCRYPTION/DECRYPTION PERFORMANCE" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512));
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx);
    
    const char* message = "Performance test message";
    size_t msg_len = strlen(message);
    
    size_t cipher_len = RSA_KEY_SIZE_512 / 8;
    std::vector<uint8_t> ciphertext(cipher_len);
    std::vector<uint8_t> decrypted(cipher_len);
    
    // Encryption
    auto enc_metrics = measurePerformance([&]() {
        size_t len = cipher_len;
        asm_rsa_encryption(pub_key, reinterpret_cast<const uint8_t*>(message),
                          msg_len, ciphertext.data(), &len);
    }, 50, msg_len);  // Reduced iterations
    
    printMetrics("Encryption (RSA-512)", enc_metrics);
    
    // Encrypt once for decryption test
    asm_rsa_encryption(pub_key, reinterpret_cast<const uint8_t*>(message),
                      msg_len, ciphertext.data(), &cipher_len);
    
    // Decryption STANDARD
    auto dec_std_metrics = measurePerformance([&]() {
        size_t len = cipher_len;
        asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                          decrypted.data(), &len, RSA_DECRYPT_STANDARD);
    }, 50, msg_len);
    
    printMetrics("Decryption STANDARD (RSA-512)", dec_std_metrics);
    
    // Decryption CRT
    auto dec_crt_metrics = measurePerformance([&]() {
        size_t len = cipher_len;
        asm_rsa_decryption(pvt_key, ciphertext.data(), cipher_len,
                          decrypted.data(), &len, RSA_DECRYPT_CRT);
    }, 50, msg_len);
    
    printMetrics("Decryption CRT (RSA-512)", dec_crt_metrics);
    
    double speedup = dec_std_metrics.mean_time_ms / dec_crt_metrics.mean_time_ms;
    std::cout << "CRT Speedup Factor: " << std::fixed << std::setprecision(2) 
              << speedup << "x" << std::endl << std::endl;
    
    asm_rsa_ctx_free(&ctx);
}

TEST_F(RSAPerformanceTest, Signature_Performance) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "SIGNATURE PERFORMANCE (RSA-512)" << std::endl;
    std::cout << "========================================" << std::endl;
    
    asm_rsa_ctx_t ctx;
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512));
    ASSERT_EQ(RSA_SUCCESS, asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512));
    
    asm_rsa_pub_key_t* pub_key = asm_rsa_get_pub_key(&ctx);
    asm_rsa_pvt_key_t* pvt_key = asm_rsa_get_pvt_key(&ctx);
    
    const char* message = "Message to sign";
    size_t msg_len = strlen(message);
    
    size_t sig_len = RSA_KEY_SIZE_512 / 8;
    std::vector<uint8_t> signature(sig_len);
    
    // Signing
    auto sign_metrics = measurePerformance([&]() {
        size_t len = sig_len;
        asm_rsa_sign(pvt_key, reinterpret_cast<const uint8_t*>(message),
                    msg_len, signature.data(), &len, RSA_DECRYPT_CRT);
    }, 50, msg_len);
    
    printMetrics("Signing (RSA-512)", sign_metrics);
    
    // Sign once for verification test
    asm_rsa_sign(pvt_key, reinterpret_cast<const uint8_t*>(message),
                msg_len, signature.data(), &sig_len, RSA_DECRYPT_CRT);
    
    // Verification
    auto verify_metrics = measurePerformance([&]() {
        asm_rsa_verify(pub_key, reinterpret_cast<const uint8_t*>(message),
                      msg_len, signature.data(), sig_len);
    }, 100, msg_len);
    
    printMetrics("Verification (RSA-512)", verify_metrics);
    
    asm_rsa_ctx_free(&ctx);
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "========================================" << std::endl;
    std::cout << "RSA IMPLEMENTATION TEST SUITE" << std::endl;
    std::cout << "  (Streamlined for faster execution)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Testing correctness and performance" << std::endl;
    std::cout << std::endl;
    
    return RUN_ALL_TESTS();
}