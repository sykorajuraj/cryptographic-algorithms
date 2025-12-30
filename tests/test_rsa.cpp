/**
 * @file tests/test_rsa.cpp
 * @brief Unit tests for RSA implementation using Google Test
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
    #include "src/asymmetric/rsa.h"
}

// Test fixture for RSA tests
class RSATest : public ::testing::Test {
protected:
    asm_rsa_ctx_t ctx;
    
    void SetUp() override {
        memset(&ctx, 0, sizeof(asm_rsa_ctx_t));
    }
    
    void TearDown() override {
        asm_rsa_ctx_free(&ctx);
    }
};

// ============================================================================
// Context Management Tests
// ============================================================================

TEST_F(RSATest, ContextInitialization512) {
    int result = asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_EQ(ctx.key_size, RSA_KEY_SIZE_512);
    EXPECT_EQ(ctx.padding_mode, 1);
}

TEST_F(RSATest, ContextInitialization1024) {
    int result = asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_EQ(ctx.key_size, RSA_KEY_SIZE_1024);
}

TEST_F(RSATest, ContextInitialization2048) {
    int result = asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_EQ(ctx.key_size, RSA_KEY_SIZE_2048);
}

TEST_F(RSATest, ContextInitialization4096) {
    int result = asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_4096);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_EQ(ctx.key_size, RSA_KEY_SIZE_4096);
}

TEST_F(RSATest, ContextInitializationInvalidKeySize) {
    int result = asm_rsa_ctx_init(&ctx, 1234);
    EXPECT_EQ(result, RSA_ERR_INVALID_KEY_LENGTH);
}

TEST_F(RSATest, ContextInitializationNullPointer) {
    int result = asm_rsa_ctx_init(nullptr, RSA_KEY_SIZE_1024);
    EXPECT_EQ(result, RSA_ERR_INVALID_PARAM);
}

TEST_F(RSATest, ContextFree) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_ctx_free(&ctx);
    EXPECT_EQ(ctx.pub_key, nullptr);
    EXPECT_EQ(ctx.pvt_key, nullptr);
    SUCCEED();
}

TEST_F(RSATest, ContextFreeNull) {
    asm_rsa_ctx_free(nullptr);
    SUCCEED();
}

// ============================================================================
// Helper Function Tests
// ============================================================================

TEST_F(RSATest, GetMaxMsgSize512) {
    size_t max_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_512);
    EXPECT_EQ(max_size, RSA_MAX_MSG_SIZE_512);
    EXPECT_EQ(max_size, 53);
}

TEST_F(RSATest, GetMaxMsgSize1024) {
    size_t max_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_1024);
    EXPECT_EQ(max_size, RSA_MAX_MSG_SIZE_1024);
    EXPECT_EQ(max_size, 117);
}

TEST_F(RSATest, GetMaxMsgSize2048) {
    size_t max_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_2048);
    EXPECT_EQ(max_size, RSA_MAX_MSG_SIZE_2048);
    EXPECT_EQ(max_size, 245);
}

TEST_F(RSATest, GetMaxMsgSize4096) {
    size_t max_size = asm_rsa_get_max_msg_size(RSA_KEY_SIZE_4096);
    EXPECT_EQ(max_size, RSA_MAX_MSG_SIZE_4096);
    EXPECT_EQ(max_size, 501);
}

TEST_F(RSATest, GetMaxMsgSizeInvalid) {
    size_t max_size = asm_rsa_get_max_msg_size(999);
    EXPECT_EQ(max_size, 0);
}

// ============================================================================
// BigNum Tests
// ============================================================================

TEST_F(RSATest, BignumNew) {
    asm_rsa_bignum_t *bn = asm_rsa_bignum_new(10);
    ASSERT_NE(bn, nullptr);
    EXPECT_EQ(bn->size, 10);
    EXPECT_EQ(bn->used, 0);
    EXPECT_NE(bn->data, nullptr);
    asm_rsa_bignum_free(bn);
}

TEST_F(RSATest, BignumFree) {
    asm_rsa_bignum_t *bn = asm_rsa_bignum_new(10);
    asm_rsa_bignum_free(bn);
    SUCCEED();
}

TEST_F(RSATest, BignumFreeNull) {
    asm_rsa_bignum_free(nullptr);
    SUCCEED();
}

TEST_F(RSATest, BignumFromBytes) {
    uint8_t data[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    asm_rsa_bignum_t *bn = asm_rsa_bignum_new(4);
    
    int result = asm_rsa_bignum_from_bytes(bn, data, 8);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_EQ(bn->used, 2);
    
    asm_rsa_bignum_free(bn);
}

TEST_F(RSATest, BignumFromBytesNull) {
    uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    int result = asm_rsa_bignum_from_bytes(nullptr, data, 4);
    EXPECT_EQ(result, RSA_ERR_INVALID_PARAM);
}

TEST_F(RSATest, BignumFromBytesTooLarge) {
    uint8_t data[20] = {0};
    asm_rsa_bignum_t *bn = asm_rsa_bignum_new(2);
    
    int result = asm_rsa_bignum_from_bytes(bn, data, 20);
    EXPECT_EQ(result, RSA_ERR_INVALID_DATA_LENGTH);
    
    asm_rsa_bignum_free(bn);
}

TEST_F(RSATest, BignumToBytes) {
    uint8_t input[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t output[8] = {0};
    
    asm_rsa_bignum_t *bn = asm_rsa_bignum_new(4);
    asm_rsa_bignum_from_bytes(bn, input, 8);
    
    int result = asm_rsa_bignum_to_bytes(bn, output, 8);
    EXPECT_GE(result, 0);
    
    asm_rsa_bignum_free(bn);
}

TEST_F(RSATest, BignumRoundTrip) {
    uint8_t input[16];
    for (int i = 0; i < 16; i++) input[i] = (uint8_t)i;
    
    uint8_t output[16] = {0};
    
    asm_rsa_bignum_t *bn = asm_rsa_bignum_new(8);
    
    EXPECT_EQ(asm_rsa_bignum_from_bytes(bn, input, 16), RSA_SUCCESS);
    int bytes_written = asm_rsa_bignum_to_bytes(bn, output, 16);
    EXPECT_GE(bytes_written, 0);
    
    asm_rsa_bignum_free(bn);
}

// ============================================================================
// Key Management Tests
// ============================================================================

TEST_F(RSATest, PublicKeyNew) {
    asm_rsa_pub_key_t *pub_key = asm_rsa_pub_key_new(RSA_KEY_SIZE_1024);
    ASSERT_NE(pub_key, nullptr);
    EXPECT_NE(pub_key->n, nullptr);
    EXPECT_NE(pub_key->e, nullptr);
    EXPECT_EQ(pub_key->key_size, RSA_KEY_SIZE_1024);
    asm_rsa_pub_key_free(pub_key);
}

TEST_F(RSATest, PublicKeyFree) {
    asm_rsa_pub_key_t *pub_key = asm_rsa_pub_key_new(RSA_KEY_SIZE_512);
    asm_rsa_pub_key_free(pub_key);
    SUCCEED();
}

TEST_F(RSATest, PublicKeyFreeNull) {
    asm_rsa_pub_key_free(nullptr);
    SUCCEED();
}

TEST_F(RSATest, PrivateKeyNew) {
    asm_rsa_pvt_key_t *pvt_key = asm_rsa_pvt_key_new(RSA_KEY_SIZE_1024);
    ASSERT_NE(pvt_key, nullptr);
    EXPECT_NE(pvt_key->n, nullptr);
    EXPECT_NE(pvt_key->d, nullptr);
    EXPECT_NE(pvt_key->p, nullptr);
    EXPECT_NE(pvt_key->q, nullptr);
    EXPECT_NE(pvt_key->dp, nullptr);
    EXPECT_NE(pvt_key->dq, nullptr);
    EXPECT_NE(pvt_key->qinv, nullptr);
    EXPECT_EQ(pvt_key->key_size, RSA_KEY_SIZE_1024);
    asm_rsa_pvt_key_free(pvt_key);
}

TEST_F(RSATest, PrivateKeyFree) {
    asm_rsa_pvt_key_t *pvt_key = asm_rsa_pvt_key_new(RSA_KEY_SIZE_512);
    asm_rsa_pvt_key_free(pvt_key);
    SUCCEED();
}

TEST_F(RSATest, PrivateKeyFreeNull) {
    asm_rsa_pvt_key_free(nullptr);
    SUCCEED();
}

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(RSATest, GenerateKeypair512) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    
    int result = asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_NE(ctx.pub_key, nullptr);
    EXPECT_NE(ctx.pvt_key, nullptr);
    EXPECT_EQ(ctx.pub_key->key_size, RSA_KEY_SIZE_512);
    EXPECT_EQ(ctx.pvt_key->key_size, RSA_KEY_SIZE_512);
}

TEST_F(RSATest, GenerateKeypair1024) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024);
    
    int result = asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_1024);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_NE(ctx.pub_key, nullptr);
    EXPECT_NE(ctx.pvt_key, nullptr);
}

TEST_F(RSATest, GenerateKeypair2048) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    
    int result = asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_NE(ctx.pub_key, nullptr);
    EXPECT_NE(ctx.pvt_key, nullptr);
}

TEST_F(RSATest, GenerateKeypairInvalidSize) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024);
    
    int result = asm_rsa_generate_keypair(&ctx, 768);
    EXPECT_EQ(result, RSA_ERR_INVALID_KEY_LENGTH);
}

TEST_F(RSATest, GenerateKeypairNull) {
    int result = asm_rsa_generate_keypair(nullptr, RSA_KEY_SIZE_1024);
    EXPECT_EQ(result, RSA_ERR_INVALID_PARAM);
}

TEST_F(RSATest, GetPublicKey) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    asm_rsa_pub_key_t *pub_key = asm_rsa_get_pub_key(&ctx);
    EXPECT_NE(pub_key, nullptr);
    EXPECT_EQ(pub_key, ctx.pub_key);
}

TEST_F(RSATest, GetPrivateKey) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    asm_rsa_pvt_key_t *pvt_key = asm_rsa_get_pvt_key(&ctx);
    EXPECT_NE(pvt_key, nullptr);
    EXPECT_EQ(pvt_key, ctx.pvt_key);
}

TEST_F(RSATest, GetKeysNull) {
    EXPECT_EQ(asm_rsa_get_pub_key(nullptr), nullptr);
    EXPECT_EQ(asm_rsa_get_pvt_key(nullptr), nullptr);
}

// ============================================================================
// Encryption/Decryption Tests
// ============================================================================

TEST_F(RSATest, EncryptionShortMessage) {
    const char *plaintext = "Hello, RSA!";
    size_t plaintext_len = strlen(plaintext);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    int result = asm_rsa_encryption(ctx.pub_key, 
                                     (const uint8_t *)plaintext, 
                                     plaintext_len,
                                     ciphertext, 
                                     &ciphertext_len);
    EXPECT_EQ(result, RSA_SUCCESS);
    EXPECT_EQ(ciphertext_len, RSA_KEY_SIZE_512 / 8);
}

TEST_F(RSATest, DecryptionShortMessage) {
    const char *plaintext = "Hello, RSA!";
    size_t plaintext_len = strlen(plaintext);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, 
                                  (const uint8_t *)plaintext, 
                                  plaintext_len,
                                  ciphertext, 
                                  &ciphertext_len), RSA_SUCCESS);
    
    int result = asm_rsa_decryption(ctx.pvt_key,
                                     ciphertext,
                                     ciphertext_len,
                                     decrypted,
                                     &decrypted_len);
    EXPECT_EQ(result, RSA_SUCCESS);
}

TEST_F(RSATest, EncryptDecryptRoundTrip512) {
    const char *message = "Test message for RSA encryption!";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, 
                                  (const uint8_t *)message, 
                                  msg_len,
                                  ciphertext, 
                                  &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key,
                                  ciphertext,
                                  ciphertext_len,
                                  decrypted,
                                  &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
}

TEST_F(RSATest, EncryptDecryptRoundTrip1024) {
    const char *message = "Testing RSA with 1024-bit keys. This is a longer message!";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_1024);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, 
                                  (const uint8_t *)message, 
                                  msg_len,
                                  ciphertext, 
                                  &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key,
                                  ciphertext,
                                  ciphertext_len,
                                  decrypted,
                                  &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
}

TEST_F(RSATest, EncryptMaxMessageSize) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    size_t max_size = RSA_MAX_MSG_SIZE_512;
    std::vector<uint8_t> plaintext(max_size, 0x42);
    std::vector<uint8_t> ciphertext(128);
    size_t ciphertext_len = ciphertext.size();
    
    int result = asm_rsa_encryption(ctx.pub_key,
                                     plaintext.data(),
                                     max_size,
                                     ciphertext.data(),
                                     &ciphertext_len);
    EXPECT_EQ(result, RSA_SUCCESS);
}

TEST_F(RSATest, EncryptTooLargeMessage) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    size_t too_large = RSA_MAX_MSG_SIZE_512 + 1;
    std::vector<uint8_t> plaintext(too_large, 0x42);
    std::vector<uint8_t> ciphertext(128);
    size_t ciphertext_len = ciphertext.size();
    
    int result = asm_rsa_encryption(ctx.pub_key,
                                     plaintext.data(),
                                     too_large,
                                     ciphertext.data(),
                                     &ciphertext_len);
    EXPECT_EQ(result, RSA_ERR_INVALID_DATA_LENGTH);
}

TEST_F(RSATest, EncryptionNullPointers) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    EXPECT_EQ(asm_rsa_encryption(nullptr, plaintext, 16, 
                                  ciphertext, &ciphertext_len),
              RSA_ERR_INVALID_PARAM);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, nullptr, 16,
                                  ciphertext, &ciphertext_len),
              RSA_ERR_INVALID_PARAM);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, plaintext, 16,
                                  nullptr, &ciphertext_len),
              RSA_ERR_INVALID_PARAM);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, plaintext, 16,
                                  ciphertext, nullptr),
              RSA_ERR_INVALID_PARAM);
}

TEST_F(RSATest, DecryptionNullPointers) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    uint8_t ciphertext[64] = {0};
    uint8_t plaintext[128];
    size_t plaintext_len = sizeof(plaintext);
    
    EXPECT_EQ(asm_rsa_decryption(nullptr, ciphertext, 64,
                                  plaintext, &plaintext_len),
              RSA_ERR_INVALID_PARAM);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, nullptr, 64,
                                  plaintext, &plaintext_len),
              RSA_ERR_INVALID_PARAM);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, 64,
                                  nullptr, &plaintext_len),
              RSA_ERR_INVALID_PARAM);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, 64,
                                  plaintext, nullptr),
              RSA_ERR_INVALID_PARAM);
}

TEST_F(RSATest, DecryptInvalidCiphertextLength) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    uint8_t ciphertext[32] = {0};
    uint8_t plaintext[128];
    size_t plaintext_len = sizeof(plaintext);
    
    int result = asm_rsa_decryption(ctx.pvt_key, ciphertext, 32,
                                     plaintext, &plaintext_len);
    EXPECT_EQ(result, RSA_ERR_INVALID_DATA_LENGTH);
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

TEST_F(RSATest, EncryptionProducesDifferentOutput) {
    const char *message = "Test";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext1[128];
    uint8_t ciphertext2[128];
    size_t len1 = sizeof(ciphertext1);
    size_t len2 = sizeof(ciphertext2);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    // Encrypt twice (padding randomness should make them different)
    asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                       ciphertext1, &len1);
    asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                       ciphertext2, &len2);
    
    // Due to random padding, ciphertexts should be different
    EXPECT_NE(memcmp(ciphertext1, ciphertext2, len1), 0);
}

TEST_F(RSATest, DifferentMessagesProduceDifferentCiphertexts) {
    const char *msg1 = "Message A";
    const char *msg2 = "Message B";
    
    uint8_t ciphertext1[128];
    uint8_t ciphertext2[128];
    size_t len1 = sizeof(ciphertext1);
    size_t len2 = sizeof(ciphertext2);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    asm_rsa_encryption(ctx.pub_key, (const uint8_t *)msg1, strlen(msg1),
                       ciphertext1, &len1);
    asm_rsa_encryption(ctx.pub_key, (const uint8_t *)msg2, strlen(msg2),
                       ciphertext2, &len2);
    
    EXPECT_NE(memcmp(ciphertext1, ciphertext2, len1), 0);
}

TEST_F(RSATest, BinaryData) {
    uint8_t binary_data[32];
    for (int i = 0; i < 32; i++) binary_data[i] = (uint8_t)i;
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, binary_data, 32,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ciphertext_len,
                                  decrypted, &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, 32);
    EXPECT_EQ(memcmp(binary_data, decrypted, 32), 0);
}

TEST_F(RSATest, AllZerosMessage) {
    uint8_t zeros[32] = {0};
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, zeros, 32,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ciphertext_len,
                                  decrypted, &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, 32);
    EXPECT_EQ(memcmp(zeros, decrypted, 32), 0);
}

TEST_F(RSATest, AllOnesMessage) {
    uint8_t ones[32];
    memset(ones, 0xFF, 32);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, ones, 32,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ciphertext_len,
                                  decrypted, &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, 32);
    EXPECT_EQ(memcmp(ones, decrypted, 32), 0);
}

// ============================================================================
// Multiple Operations Tests
// ============================================================================

TEST_F(RSATest, MultipleEncryptions) {
    const char *messages[] = {
        "First message",
        "Second message",
        "Third message"
    };
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    for (int i = 0; i < 3; i++) {
        uint8_t ciphertext[128];
        uint8_t decrypted[128];
        size_t ct_len = sizeof(ciphertext);
        size_t dec_len = sizeof(decrypted);
        size_t msg_len = strlen(messages[i]);
        
        EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, 
                                      (const uint8_t *)messages[i], 
                                      msg_len,
                                      ciphertext, &ct_len), RSA_SUCCESS);
        
        EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ct_len,
                                      decrypted, &dec_len), RSA_SUCCESS);
        
        EXPECT_EQ(dec_len, msg_len);
        EXPECT_EQ(memcmp(messages[i], decrypted, msg_len), 0);
    }
}

TEST_F(RSATest, RepeatedKeyGeneration) {
    for (int i = 0; i < 3; i++) {
        asm_rsa_ctx_t temp_ctx;
        memset(&temp_ctx, 0, sizeof(temp_ctx));
        
        asm_rsa_ctx_init(&temp_ctx, RSA_KEY_SIZE_512);
        EXPECT_EQ(asm_rsa_generate_keypair(&temp_ctx, RSA_KEY_SIZE_512), 
                  RSA_SUCCESS);
        
        EXPECT_NE(temp_ctx.pub_key, nullptr);
        EXPECT_NE(temp_ctx.pvt_key, nullptr);
        
        asm_rsa_ctx_free(&temp_ctx);
    }
}

TEST_F(RSATest, DifferentKeySizes) {
    size_t key_sizes[] = {
        RSA_KEY_SIZE_512,
        RSA_KEY_SIZE_1024,
        RSA_KEY_SIZE_2048
    };
    
    const char *message = "Test";
    
    for (int i = 0; i < 3; i++) {
        asm_rsa_ctx_t temp_ctx;
        memset(&temp_ctx, 0, sizeof(temp_ctx));
        
        size_t key_bytes = key_sizes[i] / 8;
        std::vector<uint8_t> ciphertext(key_bytes);
        std::vector<uint8_t> decrypted(key_bytes);
        size_t ct_len = ciphertext.size();
        size_t dec_len = decrypted.size();
        
        asm_rsa_ctx_init(&temp_ctx, key_sizes[i]);
        asm_rsa_generate_keypair(&temp_ctx, key_sizes[i]);
        
        EXPECT_EQ(asm_rsa_encryption(temp_ctx.pub_key, 
                                      (const uint8_t *)message, 
                                      strlen(message),
                                      ciphertext.data(), &ct_len), RSA_SUCCESS);
        
        EXPECT_EQ(asm_rsa_decryption(temp_ctx.pvt_key, 
                                      ciphertext.data(), ct_len,
                                      decrypted.data(), &dec_len), RSA_SUCCESS);
        
        EXPECT_EQ(dec_len, strlen(message));
        
        asm_rsa_ctx_free(&temp_ctx);
    }
}

// ============================================================================
// Edge Cases and Stress Tests
// ============================================================================

TEST_F(RSATest, SingleByteMessage) {
    uint8_t message = 0x42;
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, &message, 1,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ciphertext_len,
                                  decrypted, &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, 1);
    EXPECT_EQ(decrypted[0], message);
}

TEST_F(RSATest, EmptyMessage) {
    uint8_t message = 0;
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    // Try encrypting zero-length message
    int result = asm_rsa_encryption(ctx.pub_key, &message, 0,
                                     ciphertext, &ciphertext_len);
    
    // This might fail or succeed depending on implementation
    // Just verify it doesn't crash
    SUCCEED();
}

TEST_F(RSATest, VeryLongMessage2048) {
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    
    size_t max_size = RSA_MAX_MSG_SIZE_2048;
    std::vector<uint8_t> plaintext(max_size);
    for (size_t i = 0; i < max_size; i++) {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }
    
    std::vector<uint8_t> ciphertext(512);
    std::vector<uint8_t> decrypted(512);
    size_t ct_len = ciphertext.size();
    size_t dec_len = decrypted.size();
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, plaintext.data(), max_size,
                                  ciphertext.data(), &ct_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext.data(), ct_len,
                                  decrypted.data(), &dec_len), RSA_SUCCESS);
    
    EXPECT_EQ(dec_len, max_size);
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), max_size), 0);
}

TEST_F(RSATest, SpecialCharacters) {
    const char *message = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ciphertext_len,
                                  decrypted, &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
}

TEST_F(RSATest, UnicodeMessage) {
    const char *message = "Hello 世界 🌍";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    uint8_t decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(asm_rsa_decryption(ctx.pvt_key, ciphertext, ciphertext_len,
                                  decrypted, &decrypted_len), RSA_SUCCESS);
    
    EXPECT_EQ(decrypted_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted, msg_len), 0);
}

// ============================================================================
// Performance and Size Tests
// ============================================================================

TEST_F(RSATest, CiphertextSize512) {
    const char *message = "Test";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_512);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_512);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(ciphertext_len, 64);  // 512 bits = 64 bytes
}

TEST_F(RSATest, CiphertextSize1024) {
    const char *message = "Test";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_1024);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_1024);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(ciphertext_len, 128);  // 1024 bits = 128 bytes
}

TEST_F(RSATest, CiphertextSize2048) {
    const char *message = "Test";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[512];
    size_t ciphertext_len = sizeof(ciphertext);
    
    asm_rsa_ctx_init(&ctx, RSA_KEY_SIZE_2048);
    asm_rsa_generate_keypair(&ctx, RSA_KEY_SIZE_2048);
    
    EXPECT_EQ(asm_rsa_encryption(ctx.pub_key, (const uint8_t *)message, msg_len,
                                  ciphertext, &ciphertext_len), RSA_SUCCESS);
    
    EXPECT_EQ(ciphertext_len, 256);  // 2048 bits = 256 bytes
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}