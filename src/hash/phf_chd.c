/**
 * @file src/hash/phf_chd.c
 * @brief CHD (Compress, Hash, Displace) implementation
 */

#include "phf.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define CHD_MAX_ITERATIONS 1000
#define CHD_DEFAULT_NUM_BUCKETS_FACTOR 0.8

typedef struct {
    uint32_t *indices;
    uint32_t count;
    uint32_t capacity;
} bucket_t;

static int bucket_add(bucket_t *bucket, uint32_t index) {
    if (bucket->count >= bucket->capacity) {
        uint32_t new_cap = bucket->capacity == 0 ? 4 : bucket->capacity * 2;
        uint32_t *new_indices = realloc(bucket->indices, new_cap * sizeof(uint32_t));
        if (!new_indices) return -1;
        bucket->indices = new_indices;
        bucket->capacity = new_cap;
    }
    bucket->indices[bucket->count++] = index;
    return 0;
}

static void bucket_destroy(bucket_t *bucket) {
    if (bucket && bucket->indices) {
        free(bucket->indices);
        bucket->indices = NULL;
    }
}

int phf_chd_build(const phf_kv_pair_t *keys, uint32_t num_keys, float epsilon, phf_chd_t *chd) {
    if (!keys || !chd || num_keys == 0 || epsilon < 0.0f) return -1;
    
    memset(chd, 0, sizeof(phf_chd_t));
    
    /* Calculate parameters */
    chd->epsilon = epsilon;
    chd->table_size = (uint32_t)((1.0f + epsilon) * num_keys);
    chd->num_buckets = (uint32_t)(num_keys * CHD_DEFAULT_NUM_BUCKETS_FACTOR);
    
    if (chd->num_buckets == 0) chd->num_buckets = 1;
    
    /* Generate hash seeds */
    if (phf_hash_generate_seeds(&chd->hash, 2) != 0) {
        return -1;
    }
    
    /* Allocate displacement array (stores (a, b) pairs as single values) */
    chd->displacements = calloc(chd->num_buckets, sizeof(uint32_t));
    if (!chd->displacements) {
        return -1;
    }
    
    /* Create buckets */
    bucket_t *buckets = calloc(chd->num_buckets, sizeof(bucket_t));
    if (!buckets) {
        free(chd->displacements);
        return -1;
    }
    
    /* Distribute keys into buckets using g(x) = h0(x) */
    for (uint32_t i = 0; i < num_keys; i++) {
        uint32_t bucket_idx = phf_hash_universal(keys[i].key, keys[i].key_len, 
                                                  chd->hash.seed0, chd->num_buckets);
        if (bucket_add(&buckets[bucket_idx], i) != 0) {
            for (uint32_t j = 0; j < chd->num_buckets; j++) {
                bucket_destroy(&buckets[j]);
            }
            free(buckets);
            free(chd->displacements);
            return -1;
        }
    }
    
    /* Allocate bitmap to track used positions */
    uint32_t bitmap_size = (chd->table_size + 31) / 32;
    uint32_t *used_positions = calloc(bitmap_size, sizeof(uint32_t));
    if (!used_positions) {
        for (uint32_t j = 0; j < chd->num_buckets; j++) {
            bucket_destroy(&buckets[j]);
        }
        free(buckets);
        free(chd->displacements);
        return -1;
    }
    
    /* Sort buckets by size (largest first) for better placement */
    typedef struct { uint32_t idx; uint32_t size; } bucket_info_t;
    bucket_info_t *sorted_buckets = malloc(chd->num_buckets * sizeof(bucket_info_t));
    if (!sorted_buckets) {
        free(used_positions);
        for (uint32_t j = 0; j < chd->num_buckets; j++) {
            bucket_destroy(&buckets[j]);
        }
        free(buckets);
        free(chd->displacements);
        return -1;
    }
    
    for (uint32_t i = 0; i < chd->num_buckets; i++) {
        sorted_buckets[i].idx = i;
        sorted_buckets[i].size = buckets[i].count;
    }
    
    /* Simple bubble sort */
    for (uint32_t i = 0; i < chd->num_buckets - 1; i++) {
        for (uint32_t j = 0; j < chd->num_buckets - i - 1; j++) {
            if (sorted_buckets[j].size < sorted_buckets[j + 1].size) {
                bucket_info_t temp = sorted_buckets[j];
                sorted_buckets[j] = sorted_buckets[j + 1];
                sorted_buckets[j + 1] = temp;
            }
        }
    }
    
    /* Try to place each bucket */
    uint32_t max_displacement = (uint32_t)sqrt(chd->table_size) + 1;
    
    for (uint32_t bi = 0; bi < chd->num_buckets; bi++) {
        uint32_t bucket_idx = sorted_buckets[bi].idx;
        bucket_t *bucket = &buckets[bucket_idx];
        
        if (bucket->count == 0) {
            chd->displacements[bucket_idx] = 0;
            continue;
        }
        
        int placed = 0;
        
        /* Try different displacement values */
        for (uint32_t a = 0; a < max_displacement && !placed; a++) {
            for (uint32_t b = 0; b < max_displacement && !placed; b++) {
                int conflict = 0;
                
                /* Check if this (a, b) causes conflicts */
                for (uint32_t ki = 0; ki < bucket->count; ki++) {
                    uint32_t key_idx = bucket->indices[ki];
                    uint32_t h1 = phf_hash_universal(keys[key_idx].key, keys[key_idx].key_len,
                                                      chd->hash.seed1, chd->table_size);
                    uint32_t pos;
                    if (a > 0) {
                        uint32_t f2 = phf_hash_universal(keys[key_idx].key, keys[key_idx].key_len,
                                                          chd->hash.seed1 ^ 0x9e3779b9, chd->table_size);
                        pos = (h1 + a * f2 + b) % chd->table_size;
                    } else {
                        pos = (h1 + b) % chd->table_size;
                    }
                    
                    uint32_t word_idx = pos / 32;
                    uint32_t bit_idx = pos % 32;
                    
                    if (used_positions[word_idx] & (1u << bit_idx)) {
                        conflict = 1;
                        break;
                    }
                }
                
                if (!conflict) {
                    /* Place all keys with this displacement */
                    for (uint32_t ki = 0; ki < bucket->count; ki++) {
                        uint32_t key_idx = bucket->indices[ki];
                        uint32_t h1 = phf_hash_universal(keys[key_idx].key, keys[key_idx].key_len,
                                                          chd->hash.seed1, chd->table_size);
                        uint32_t pos;
                        if (a > 0) {
                            uint32_t f2 = phf_hash_universal(keys[key_idx].key, keys[key_idx].key_len,
                                                              chd->hash.seed1 ^ 0x9e3779b9, chd->table_size);
                            pos = (h1 + a * f2 + b) % chd->table_size;
                        } else {
                            pos = (h1 + b) % chd->table_size;
                        }
                        
                        uint32_t word_idx = pos / 32;
                        uint32_t bit_idx = pos % 32;
                        used_positions[word_idx] |= (1u << bit_idx);
                    }
                    
                    /* Store displacement as single value: index = a * max_displacement + b */
                    chd->displacements[bucket_idx] = a * max_displacement + b;
                    placed = 1;
                }
            }
        }
        
        if (!placed) {
            /* Failed to place bucket */
            free(sorted_buckets);
            free(used_positions);
            for (uint32_t j = 0; j < chd->num_buckets; j++) {
                bucket_destroy(&buckets[j]);
            }
            free(buckets);
            free(chd->displacements);
            chd->displacements = NULL;
            return -1;
        }
    }
    
    /* Cleanup */
    free(sorted_buckets);
    free(used_positions);
    for (uint32_t i = 0; i < chd->num_buckets; i++) {
        bucket_destroy(&buckets[i]);
    }
    free(buckets);
    
    return 0;
}

uint32_t phf_chd_hash(const phf_chd_t *chd, const void *key, size_t key_len) {
    if (!chd || !key || !chd->displacements) return 0;
    
    /* Get bucket index using first hash */
    uint32_t bucket_idx = phf_hash_universal(key, key_len, chd->hash.seed0, chd->num_buckets);
    
    /* Get displacement values */
    uint32_t max_displacement = (uint32_t)sqrt(chd->table_size) + 1;
    uint32_t displacement = chd->displacements[bucket_idx];
    uint32_t a = displacement / max_displacement;
    uint32_t b = displacement % max_displacement;
    
    /* Compute second hash */
    uint32_t h1 = phf_hash_universal(key, key_len, chd->hash.seed1, chd->table_size);
    
    /* Final position: h1 + a*m + b, where m is table_size
     * Simplified to: (h1 + b) mod table_size when a is for different iterations
     */
    uint32_t pos = h1 + b;
    
    /* For CHD: f1(x) + a * f2(x) + b */
    if (a > 0) {
        uint32_t f2 = phf_hash_universal(key, key_len, chd->hash.seed1 ^ 0x9e3779b9, chd->table_size);
        pos = (h1 + a * f2 + b) % chd->table_size;
    } else {
        pos = (h1 + b) % chd->table_size;
    }
    
    return pos;
}

void phf_chd_destroy(phf_chd_t *chd) {
    if (!chd) return;
    
    if (chd->displacements) {
        free(chd->displacements);
        chd->displacements = NULL;
    }
    
    memset(chd, 0, sizeof(phf_chd_t));
}