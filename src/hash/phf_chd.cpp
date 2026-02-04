/**
 * @file phf_chd.cpp
 * @brief CHD (Compress, Hash, Displace) implementation in C++
 */

#include "phf.h"
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <algorithm>
#include <iostream>

#define CHD_MAX_ITERATIONS 1000
#define CHD_DEFAULT_NUM_BUCKETS_FACTOR 0.8

struct bucket_t {
    std::vector<uint32_t> indices;
    
    void add(uint32_t index) {
        indices.push_back(index);
    }
    
    size_t count() const {
        return indices.size();
    }
};

int phf_chd_build(const phf_kv_pair_t *keys, uint32_t num_keys, float epsilon, phf_chd_t *chd) {
    if (!keys || !chd || num_keys == 0 || epsilon < 0.0f) return -1;
    
    // Clear existing data
    chd->displacements.clear();
    
    /* Calculate parameters */
    chd->epsilon = epsilon;
    chd->table_size = static_cast<uint32_t>((1.0f + epsilon) * num_keys);
    chd->num_buckets = static_cast<uint32_t>(num_keys * CHD_DEFAULT_NUM_BUCKETS_FACTOR);
    
    if (chd->num_buckets == 0) chd->num_buckets = 1;
    
    /* Generate hash seeds */
    if (phf_hash_generate_seeds(&chd->hash, 2) != 0) {
        return -1;
    }
    
    /* Allocate displacement array */
    chd->displacements.resize(chd->num_buckets, 0);
    
    /* Create buckets */
    std::vector<bucket_t> buckets(chd->num_buckets);
    
    /* Distribute keys into buckets using g(x) = h0(x) */
    for (uint32_t i = 0; i < num_keys; i++) {
        uint32_t bucket_idx = phf_hash_universal(keys[i].key, keys[i].key_len, 
                                                  chd->hash.seed0, chd->num_buckets);
        buckets[bucket_idx].add(i);
    }
    
    /* Allocate bitmap to track used positions */
    std::vector<uint32_t> used_positions((chd->table_size + 31) / 32, 0);
    
    /* Sort buckets by size (largest first) for better placement */
    struct bucket_info_t {
        uint32_t idx;
        size_t size;
    };
    
    std::vector<bucket_info_t> sorted_buckets(chd->num_buckets);
    for (uint32_t i = 0; i < chd->num_buckets; i++) {
        sorted_buckets[i].idx = i;
        sorted_buckets[i].size = buckets[i].count();
    }
    
    std::sort(sorted_buckets.begin(), sorted_buckets.end(),
              [](const bucket_info_t& a, const bucket_info_t& b) {
                  return a.size > b.size;
              });
    
    /* Try to place each bucket */
    uint32_t max_displacement = static_cast<uint32_t>(std::sqrt(chd->table_size)) + 1;
    
    for (uint32_t bi = 0; bi < chd->num_buckets; bi++) {
        uint32_t bucket_idx = sorted_buckets[bi].idx;
        bucket_t& bucket = buckets[bucket_idx];
        
        if (bucket.count() == 0) {
            chd->displacements[bucket_idx] = 0;
            continue;
        }
        
        bool placed = false;
        
        /* Try different displacement values */
        for (uint32_t a = 0; a < max_displacement && !placed; a++) {
            for (uint32_t b = 0; b < max_displacement && !placed; b++) {
                bool conflict = false;
                
                // Check intra-bucket collisions
                std::vector<uint32_t> temp_positions(bucket.count());
                
                /* Check if this (a, b) causes conflicts */
                for (size_t ki = 0; ki < bucket.count(); ki++) {
                    uint32_t key_idx = bucket.indices[ki];
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
                    
                    temp_positions[ki] = pos;
                    
                    /* Check against already used positions */
                    uint32_t word_idx = pos / 32;
                    uint32_t bit_idx = pos % 32;
                    
                    if (used_positions[word_idx] & (1u << bit_idx)) {
                        conflict = true;
                        break;
                    }
                    
                    /* Check for intra-bucket collisions */
                    for (size_t kj = 0; kj < ki; kj++) {
                        if (temp_positions[kj] == pos) {
                            conflict = true;
                            break;
                        }
                    }
                    
                    if (conflict) break;
                }
                
                if (!conflict) {
                    /* Place all keys with this displacement */
                    for (size_t ki = 0; ki < bucket.count(); ki++) {
                        uint32_t pos = temp_positions[ki];
                        
                        uint32_t word_idx = pos / 32;
                        uint32_t bit_idx = pos % 32;
                        used_positions[word_idx] |= (1u << bit_idx);
                    }
                    
                    /* Store displacement */
                    chd->displacements[bucket_idx] = a * max_displacement + b;
                    placed = true;
                }
            }
        }
        
        if (!placed) {
            /* Failed to place bucket */
            chd->displacements.clear();
            chd->num_buckets = 0;
            return -1;
        }
    }
    
    return 0;
}

uint32_t phf_chd_hash(const phf_chd_t *chd, const void *key, size_t key_len) {
    if (!chd || !key || chd->displacements.empty()) return 0;
    
    /* Get bucket index using first hash */
    uint32_t bucket_idx = phf_hash_universal(key, key_len, chd->hash.seed0, chd->num_buckets);
    
    /* Get displacement values */
    uint32_t max_displacement = static_cast<uint32_t>(std::sqrt(chd->table_size)) + 1;
    uint32_t displacement = chd->displacements[bucket_idx];
    uint32_t a = displacement / max_displacement;
    uint32_t b = displacement % max_displacement;
    
    /* Compute second hash */
    uint32_t h1 = phf_hash_universal(key, key_len, chd->hash.seed1, chd->table_size);
    
    uint32_t pos;
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
    
    chd->displacements.clear();
    chd->num_buckets = 0;
    chd->table_size = 0;
    chd->epsilon = 0.0f;
}