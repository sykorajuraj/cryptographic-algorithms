/**
 * @file examples/example_aes.c
 * @brief Examples demonstrating AES-128 usage
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <stdio.h>
#include <string.h>
#include "src/symmetric/aes.h"

void example_single_block_ecb() {
    print_section_box("Example 1: Single Block ECB Mode", BOX_WIDTH);
    
    // Test key and plaintext from FIPS-197
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    // Initialize context
    sym_aes_ctx_t *ctx = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    if (!ctx) {
        print_error_box("Failed to initialize AES context", BOX_WIDTH);
        return;
    }
    
    // Encrypt
    if (sym_aes_encryption(ctx, plaintext, ciphertext) != AES_SUCCESS) {
        print_error_box("Encryption failed", BOX_WIDTH);
        sym_aes_ctx_destroy(ctx);
        return;
    }
    
    // Decrypt
    if (sym_aes_decryption(ctx, ciphertext, decrypted) != AES_SUCCESS) {
        print_error_box("Decryption failed", BOX_WIDTH);
        sym_aes_ctx_destroy(ctx);
        return;
    }
    
    // Display results
    print_hex("  Key:        ", key, 16);
    print_hex("  Plaintext:  ", plaintext, 16);
    print_hex("  Ciphertext: ", ciphertext, 16);
    print_hex("  Decrypted:  ", decrypted, 16);
    
    // Verify
    if (memcmp(plaintext, decrypted, 16) == 0) {
        printf(COLOR_GREEN "  ✓ Decryption matches original plaintext\n" COLOR_RESET);
    } else {
        printf(COLOR_RED "  ✗ Decryption mismatch!\n" COLOR_RESET);
    }
    
    sym_aes_ctx_destroy(ctx);
}

void example_cbc_mode() {
    print_section_box("Example 2: CBC Mode with Padding", BOX_WIDTH);
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    const char *message = "Hello, AES-128 CBC mode!";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    size_t ciphertext_len, decrypted_len;
    
    // Initialize contexts
    sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    if (!ctx_enc || !ctx_dec) {
        print_error_box("Failed to initialize contexts", BOX_WIDTH);
        return;
    }
    
    // Set IVs
    sym_aes_enc_set_iv(ctx_enc, iv);
    sym_aes_dnc_set_iv(ctx_dec, iv);
    
    // Encrypt
    if (sym_aes_encrypt_cbc(ctx_enc, (uint8_t *)message, msg_len, 
                            ciphertext, &ciphertext_len) != AES_SUCCESS) {
        print_error_box("CBC encryption failed", BOX_WIDTH);
        goto cleanup;
    }
    
    // Decrypt
    if (sym_aes_decrypt_cbc(ctx_dec, ciphertext, ciphertext_len, 
                            decrypted, &decrypted_len) != AES_SUCCESS) {
        print_error_box("CBC decryption failed", BOX_WIDTH);
        goto cleanup;
    }
    
    // Display results
    printf("  Message:    \"%s\"\n", message);
    printf("  Length:     %zu bytes\n", msg_len);
    print_hex_wrapped("  IV:         ", iv, 16, 16);
    print_hex_wrapped("  Ciphertext: ", ciphertext, ciphertext_len, 16);
    printf("  Decrypted:  \"%.*s\"\n", (int)decrypted_len, decrypted);
    
    // Verify
    if (decrypted_len == msg_len && memcmp(message, decrypted, msg_len) == 0) {
        printf(COLOR_GREEN "  ✓ CBC mode working correctly\n" COLOR_RESET);
    } else {
        printf(COLOR_RED "  ✗ CBC mode verification failed\n" COLOR_RESET);
    }
    
cleanup:
    sym_aes_ctx_destroy(ctx_enc);
    sym_aes_ctx_destroy(ctx_dec);
}

void example_ctr_mode() {
    print_section_box("Example 3: CTR Mode (Stream Cipher)", BOX_WIDTH);
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t nonce[16] = {0};
    nonce[15] = 1; // Counter starts at 1
    
    const char *message = "CTR mode - no padding!";
    size_t msg_len = strlen(message);
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    size_t ciphertext_len, decrypted_len;
    
    // Initialize contexts
    sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
    
    if (!ctx_enc || !ctx_dec) {
        print_error_box("Failed to initialize contexts", BOX_WIDTH);
        return;
    }
    
    // Set nonces
    sym_aes_enc_set_iv(ctx_enc, nonce);
    sym_aes_dnc_set_iv(ctx_dec, nonce);
    
    // Encrypt
    if (sym_aes_encrypt_ctr(ctx_enc, (uint8_t *)message, msg_len, 
                            ciphertext, &ciphertext_len) != AES_SUCCESS) {
        print_error_box("CTR encryption failed", BOX_WIDTH);
        goto cleanup;
    }
    
    // Decrypt
    if (sym_aes_decrypt_ctr(ctx_dec, ciphertext, ciphertext_len, 
                            decrypted, &decrypted_len) != AES_SUCCESS) {
        print_error_box("CTR decryption failed", BOX_WIDTH);
        goto cleanup;
    }
    
    // Display results
    printf("  Message:    \"%s\"\n", message);
    printf("  Length:     %zu bytes (no padding!)\n", msg_len);
    print_hex_wrapped("  Nonce:      ", nonce, 16, 16);
    print_hex_wrapped("  Ciphertext: ", ciphertext, ciphertext_len, 16);
    printf("  Decrypted:  \"%.*s\"\n", (int)decrypted_len, decrypted);
    
    // Verify
    if (ciphertext_len == msg_len && decrypted_len == msg_len && 
        memcmp(message, decrypted, msg_len) == 0) {
        printf(COLOR_GREEN "  ✓ CTR mode working correctly\n" COLOR_RESET);
    } else {
        printf(COLOR_RED "  ✗ CTR mode verification failed\n" COLOR_RESET);
    }
    
cleanup:
    sym_aes_ctx_destroy(ctx_enc);
    sym_aes_ctx_destroy(ctx_dec);
}

int main() {
    print_box("AES-128 Examples", BOX_WIDTH, COLOR_CYAN);
    
    example_single_block_ecb();
    example_cbc_mode();
    example_ctr_mode();
    
    print_success_box("All Examples Complete", BOX_WIDTH);
    
    return 0;
}