/**
 * @file benchmarks/bench_aes.c
 * @brief Performance benchmarks for AES-128 implementation
 * @author Juraj Sýkora <juraj.sykora@studio.unibo.it>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "src/symmetric/aes.h"

// CSV output structure
typedef struct {
    char algorithm[16];
    char mode[8];
    size_t data_size;
    char operation[16];
    double throughput_mbps;
    double time_us;
} benchmark_result_t;

static benchmark_result_t results[100];
static int result_count = 0;

void add_result(const char *algo, const char *mode, size_t size, 
                const char *op, double throughput, double time) {
    if (result_count < 100) {
        strncpy(results[result_count].algorithm, algo, 15);
        strncpy(results[result_count].mode, mode, 7);
        strncpy(results[result_count].operation, op, 15);
        results[result_count].data_size = size;
        results[result_count].throughput_mbps = throughput;
        results[result_count].time_us = time;
        result_count++;
    }
}

void benchmark_cbc_mode() {
    print_section_box("Benchmark: CBC Mode ", BOX_WIDTH);
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    size_t sizes[] = {64, 256, 1024, 4096, 16384};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    int iterations = 10000;
    
    printf("\nIterations per size: %d\n\n", iterations);
    
    for (int s = 0; s < num_sizes; s++) {
        size_t data_size = sizes[s];
        
        uint8_t *plaintext = malloc(data_size);
        uint8_t *ciphertext = malloc(data_size + AES_BLOCK_SIZE);
        uint8_t *decrypted = malloc(data_size + AES_BLOCK_SIZE);
        
        if (!plaintext || !ciphertext || !decrypted) {
            printf("Memory allocation failed!\n");
            free(plaintext);
            free(ciphertext);
            free(decrypted);
            continue;
        }
        
        size_t ciphertext_len, decrypted_len;
        
        // Fill with random data
        generate_random_bytes(plaintext, data_size);
        
        sym_aes_ctx_t *ctx_enc = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
        sym_aes_ctx_t *ctx_dec = sym_aes_ctx_init(key, KEY_LENGTH_BYTES);
        
        if (!ctx_enc || !ctx_dec) {
            printf("Context initialization failed!\n");
            free(plaintext);
            free(ciphertext);
            free(decrypted);
            sym_aes_ctx_destroy(ctx_enc);
            sym_aes_ctx_destroy(ctx_dec);
            continue;
        }
        
        // Set IV ONCE before benchmark loop
        if (sym_aes_enc_set_iv(ctx_enc, iv) != AES_SUCCESS) {
            printf("IV set failed!\n");
            goto cleanup;
        }
        
        // Warmup
        for (int i = 0; i < 100; i++) {
            sym_aes_enc_set_iv(ctx_enc, iv);
            sym_aes_encrypt_cbc(ctx_enc, plaintext, data_size, 
                              ciphertext, &ciphertext_len);
        }
        
        // Benchmark encryption
        double start = get_time_us();
        for (int i = 0; i < iterations; i++) {
            // Reset IV for each iteration (necessary for CBC)
            sym_aes_enc_set_iv(ctx_enc, iv);
            
            int result = sym_aes_encrypt_cbc(ctx_enc, plaintext, data_size, 
                                           ciphertext, &ciphertext_len);
            if (result != AES_SUCCESS) {
                printf("Encryption failed at iteration %d\n", i);
                goto cleanup;
            }
        }
        double end = get_time_us();
        double enc_time = end - start;
        
        double mb_per_sec = (data_size * iterations / (1024.0 * 1024.0)) / 
                           (enc_time / 1000000.0);
        double time_per_op = enc_time / iterations;
        
        char label[64];
        snprintf(label, sizeof(label), "CBC Encrypt (%zu bytes)", data_size);
        printf("  %-35s: %8.2f MB/s  (%8.2f µs/op)\n", 
               label, mb_per_sec, time_per_op);
        
        // Store result for CSV
        add_result("AES-128", "CBC", data_size, "Encrypt", 
                  mb_per_sec, time_per_op);
        
        // Benchmark decryption
        if (sym_aes_dnc_set_iv(ctx_dec, iv) != AES_SUCCESS) {
            printf("IV set failed!\n");
            goto cleanup;
        }
        
        start = get_time_us();
        for (int i = 0; i < iterations; i++) {
            sym_aes_dnc_set_iv(ctx_dec, iv);
            
            int result = sym_aes_decrypt_cbc(ctx_dec, ciphertext, ciphertext_len, 
                                           decrypted, &decrypted_len);
            if (result != AES_SUCCESS) {
                printf("Decryption failed at iteration %d\n", i);
                goto cleanup;
            }
        }
        end = get_time_us();
        double dec_time = end - start;
        
        mb_per_sec = (data_size * iterations / (1024.0 * 1024.0)) / 
                    (dec_time / 1000000.0);
        time_per_op = dec_time / iterations;
        
        snprintf(label, sizeof(label), "CBC Decrypt (%zu bytes)", data_size);
        printf("  %-35s: %8.2f MB/s  (%8.2f µs/op)\n", 
               label, mb_per_sec, time_per_op);
        
        add_result("AES-128", "CBC", data_size, "Decrypt", 
                  mb_per_sec, time_per_op);
        
        printf("\n");
        
cleanup:
        memset(plaintext, 0, data_size);
        memset(ciphertext, 0, data_size + AES_BLOCK_SIZE);
        memset(decrypted, 0, data_size + AES_BLOCK_SIZE);
        
        free(plaintext);
        free(ciphertext);
        free(decrypted);
        sym_aes_ctx_destroy(ctx_enc);
        sym_aes_ctx_destroy(ctx_dec);
    }
}

void save_results_csv() {
    // Create results directory if it doesn't exist
    system("mkdir -p results");
    
    FILE *fp = fopen("results/benchmarks.csv", "w");
    if (!fp) {
        printf(COLOR_RED "✗ Could not create results/benchmarks.csv\n" COLOR_RESET);
        return;
    }
    
    // Write header
    fprintf(fp, "Algorithm,Mode,DataSize,Operation,Throughput_MBps,Time_us\n");
    
    // Write actual benchmark results
    for (int i = 0; i < result_count; i++) {
        fprintf(fp, "%s,%s,%zu,%s,%.2f,%.2f\n",
                results[i].algorithm,
                results[i].mode,
                results[i].data_size,
                results[i].operation,
                results[i].throughput_mbps,
                results[i].time_us);
    }
    
    fclose(fp);
    printf(COLOR_GREEN "\n✓ Results saved to results/benchmarks.csv (%d entries)\n" COLOR_RESET, 
           result_count);
}

int main() {
    srand(time(NULL));
    
    print_box("AES-128 Performance Benchmarks", 58, COLOR_CYAN);
    
    printf("\n" COLOR_YELLOW "Note: Benchmarks include IV setup overhead per operation\n");
    printf("This reflects real-world usage where IV must be reset.\n" COLOR_RESET "\n");
    
    benchmark_cbc_mode();
    
    save_results_csv();
    
    print_success_box("Benchmarking Complete", 58);
    printf("\n");
    
    return 0;
}