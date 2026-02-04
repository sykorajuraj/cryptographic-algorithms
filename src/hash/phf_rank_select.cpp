/**
 * @file phf_rank_select.cpp
 * @brief Rank and Select data structure for succinct compression
 */

#include "phf.h"
#include <cstdlib>
#include <cstring>
#include <vector>

#define BLOCK_SIZE 64      /* log2(n) sized blocks */
#define MINI_BLOCK_SIZE 8  /* Mini-blocks for fine-grained rank */

/* Popcount - count set bits */
static inline uint32_t popcount64(uint64_t x) {
#ifdef __GNUC__
    return __builtin_popcountll(x);
#else
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (x * 0x0101010101010101ULL) >> 56;
#endif
}

/* Count bits in a range */
static uint32_t popcount_range(const std::vector<uint64_t>& bitmap, uint32_t start_bit, uint32_t end_bit) {
    if (start_bit >= end_bit) return 0;
    
    uint32_t count = 0;
    uint32_t start_word = start_bit / 64;
    uint32_t end_word = end_bit / 64;
    
    if (start_word == end_word) {
        /* Same word */
        uint64_t mask = ((1ULL << (end_bit - start_bit)) - 1) << (start_bit % 64);
        count = popcount64(bitmap[start_word] & mask);
    } else {
        /* First word */
        uint64_t first_mask = ~((1ULL << (start_bit % 64)) - 1);
        count = popcount64(bitmap[start_word] & first_mask);
        
        /* Middle words */
        for (uint32_t i = start_word + 1; i < end_word; i++) {
            count += popcount64(bitmap[i]);
        }
        
        /* Last word */
        if (end_bit % 64 > 0) {
            uint64_t last_mask = (1ULL << (end_bit % 64)) - 1;
            count += popcount64(bitmap[end_word] & last_mask);
        }
    }
    
    return count;
}

int phf_rank_select_build(const uint64_t *bitmap_data, uint32_t bitmap_size, phf_rank_select_t *rs) {
    if (!bitmap_data || !rs || bitmap_size == 0) return -1;
    
    rs->bitmap.clear();
    rs->block_ranks.clear();
    rs->mini_ranks.clear();
    rs->select_samples.clear();
    
    rs->bitmap_size = bitmap_size;
    uint32_t num_words = (bitmap_size + 63) / 64;
    
    /* Copy bitmap */
    rs->bitmap.assign(bitmap_data, bitmap_data + num_words);
    
    /* Count total number of 1s */
    rs->num_ones = 0;
    for (uint32_t i = 0; i < num_words; i++) {
        rs->num_ones += popcount64(bitmap_data[i]);
    }
    
    /* Build block structure */
    rs->num_blocks = (bitmap_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    rs->block_ranks.resize(rs->num_blocks + 1);
    
    /* Compute block ranks (prefix sums) */
    rs->block_ranks[0] = 0;
    for (uint32_t i = 0; i < rs->num_blocks; i++) {
        uint32_t block_start = i * BLOCK_SIZE;
        uint32_t block_end = (i + 1) * BLOCK_SIZE;
        if (block_end > bitmap_size) block_end = bitmap_size;
        
        uint32_t block_ones = popcount_range(rs->bitmap, block_start, block_end);
        rs->block_ranks[i + 1] = rs->block_ranks[i] + block_ones;
    }
    
    /* Build mini-block structure */
    uint32_t num_mini_blocks = (bitmap_size + MINI_BLOCK_SIZE - 1) / MINI_BLOCK_SIZE;
    
    rs->mini_ranks.resize(num_mini_blocks);
    
    /* Compute mini-block ranks */
    for (uint32_t i = 0; i < num_mini_blocks; i++) {
        uint32_t block_idx = (i * MINI_BLOCK_SIZE) / BLOCK_SIZE;
        uint32_t block_start = block_idx * BLOCK_SIZE;
        uint32_t mini_start = i * MINI_BLOCK_SIZE;
        
        if (mini_start > block_start) {
            rs->mini_ranks[i] = popcount_range(rs->bitmap, block_start, mini_start);
        } else {
            rs->mini_ranks[i] = 0;
        }
    }
    
    /* Build select structure - sample every sqrt(n) ones */
    if (rs->num_ones > 0) {
        uint32_t sample_interval = 64;  /* Sample every 64 ones */
        uint32_t num_samples = (rs->num_ones + sample_interval - 1) / sample_interval;
        
        rs->select_samples.resize(num_samples);
        
        uint32_t ones_count = 0;
        uint32_t sample_idx = 0;
        
        for (uint32_t i = 0; i < bitmap_size && sample_idx < num_samples; i++) {
            uint32_t word_idx = i / 64;
            uint32_t bit_idx = i % 64;
            
            if (rs->bitmap[word_idx] & (1ULL << bit_idx)) {
                if (ones_count % sample_interval == 0) {
                    rs->select_samples[sample_idx++] = i;
                }
                ones_count++;
            }
        }
    }
    
    return 0;
}

uint32_t phf_rank(const phf_rank_select_t *rs, uint32_t position) {
    if (!rs || rs->bitmap.empty() || position >= rs->bitmap_size) {
        return 0;
    }
    
    /* Find block */
    uint32_t block_idx = position / BLOCK_SIZE;
    
    /* Get block rank */
    uint32_t rank = rs->block_ranks[block_idx];
    
    /* Find mini-block */
    uint32_t mini_idx = position / MINI_BLOCK_SIZE;
    
    /* Add mini-block rank */
    rank += rs->mini_ranks[mini_idx];
    
    /* Count remaining bits */
    uint32_t mini_start = mini_idx * MINI_BLOCK_SIZE;
    rank += popcount_range(rs->bitmap, mini_start, position + 1);
    
    return rank;
}

uint32_t phf_select(const phf_rank_select_t *rs, uint32_t k) {
    if (!rs || rs->bitmap.empty() || k >= rs->num_ones) {
        return rs->bitmap_size;  /* Out of bounds */
    }
    
    /* Use select samples for initial search */
    uint32_t sample_interval = 64;
    uint32_t sample_idx = k / sample_interval;
    
    uint32_t search_start = 0;
    if (!rs->select_samples.empty() && sample_idx > 0 && 
        sample_idx - 1 < rs->select_samples.size()) {
        search_start = rs->select_samples[sample_idx - 1];
    }
    
    /* Linear scan from sample position */
    uint32_t ones_count = (sample_idx > 0) ? sample_idx * sample_interval : 0;
    
    /* Recount from search_start to be accurate */
    if (search_start > 0) {
        ones_count = phf_rank(rs, search_start);
    }
    
    for (uint32_t i = search_start; i < rs->bitmap_size; i++) {
        uint32_t word_idx = i / 64;
        uint32_t bit_idx = i % 64;
        
        if (rs->bitmap[word_idx] & (1ULL << bit_idx)) {
            if (ones_count == k) {
                return i;
            }
            ones_count++;
        }
    }
    
    return rs->bitmap_size;  /* Not found */
}

void phf_rank_select_destroy(phf_rank_select_t *rs) {
    if (!rs) return;
    
    rs->bitmap.clear();
    rs->block_ranks.clear();
    rs->mini_ranks.clear();
    rs->select_samples.clear();
    rs->bitmap_size = 0;
    rs->num_blocks = 0;
    rs->num_ones = 0;
}