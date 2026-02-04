/**
 * @file phf_hash.cpp
 * @brief Hash function implementations for PHF
 */

#include "phf.h"
#include <cstdlib>
#include <cstring>
#include <ctime>

/* MurmurHash3 32-bit implementation */
static inline uint32_t rotl32(uint32_t x, int8_t r) {
    return (x << r) | (x >> (32 - r));
}

static inline uint32_t fmix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

uint32_t phf_hash_universal(const void *key, size_t key_len, uint64_t seed, uint32_t range) {
    if (!key || key_len == 0 || range == 0) return 0;
    
    const uint8_t *data = static_cast<const uint8_t *>(key);
    const int nblocks = key_len / 4;
    
    uint32_t h1 = static_cast<uint32_t>(seed);
    
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    
    /* Body */
    const uint32_t *blocks = reinterpret_cast<const uint32_t *>(data);
    
    for (int i = 0; i < nblocks; i++) {
        uint32_t k1 = blocks[i];
        
        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;
        
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }
    
    /* Tail */
    const uint8_t *tail = data + nblocks * 4;
    
    uint32_t k1 = 0;
    
    switch (key_len & 3) {
        case 3: k1 ^= tail[2] << 16;
                [[fallthrough]];
        case 2: k1 ^= tail[1] << 8;
                [[fallthrough]];
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = rotl32(k1, 15);
                k1 *= c2;
                h1 ^= k1;
    }
    
    /* Finalization */
    h1 ^= static_cast<uint32_t>(key_len);
    h1 = fmix32(h1);
    
    return h1 % range;
}

int phf_hash_generate_seeds(phf_hash_config_t *config, uint32_t num_seeds) {
    if (!config || num_seeds < 2 || num_seeds > 3) return -1;
    
    config->num_seeds = num_seeds;
    
    /* Use better randomness */
    uint64_t base_seed = static_cast<uint64_t>(std::time(nullptr));
    base_seed ^= static_cast<uint64_t>(std::rand());
    
    config->seed0 = base_seed;
    config->seed1 = base_seed ^ 0x9e3779b97f4a7c15ULL;
    
    if (num_seeds == 3) {
        config->seed2 = base_seed ^ 0x517cc1b727220a95ULL;
    } else {
        config->seed2 = 0;
    }
    
    return 0;
}