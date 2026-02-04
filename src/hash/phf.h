/**
 * @file src/hash/phf.h
 * @brief Perfect Hash Function (PHF) based encryption/decryption structures and functions
 * 
 * This header for PHF encryption and decryption using techniques from CHD (Compress,
 * Hash, Displace) and BDZ/BPZ algorithms.
 * 
 * References:
 * - CHD: Hash, Displace, and Compress algorithm
 * - BDZ/BPZ: Bipartite/3-partite graph-based minimal PHF
 * - Rank/Select: Succinct data structures for compression
 */

#ifndef PHF_CRYPTO_H
#define PHF_CRYPTO_H

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>

/* ========================================================================== */
/*                          Core Data Structures                              */
/* ========================================================================== */

/**
 * @brief Hash function configuration
 */
struct phf_hash_config_t {
    uint64_t seed0;          /* Primary hash seed */
    uint64_t seed1;          /* Secondary hash seed */
    uint64_t seed2;          /* Tertiary hash seed (for 3-partite) */
    uint32_t num_seeds;      /* Number of hash functions (2 or 3) */
};

/**
 * @brief CHD-based PHF configuration
 */
struct phf_chd_t {
    std::vector<uint32_t> displacements; /* Array of displacement values (a, b) pairs */
    uint32_t num_buckets;    /* Number of buckets (r) */
    uint32_t table_size;     /* Hash table size m = (1 + epsilon) * n */
    float epsilon;           /* Load factor overhead */
    phf_hash_config_t hash;  /* Hash function configuration */
    
    phf_chd_t() : num_buckets(0), table_size(0), epsilon(0.0f), hash{} {}
};

/**
 * @brief BDZ/BPZ graph-based PHF configuration
 */
struct phf_bdz_t {
    std::vector<uint8_t> g_array;  /* Selector/vertex value array */
    uint32_t g_size;         /* Size of g array (2*N for bipartite, 3*K for 3-partite) */
    uint32_t num_vertices;   /* Number of vertices per partition */
    uint8_t r;               /* Number of partitions (2 or 3) */
    bool is_minimal;         /* true for MPHF, false for PHF */
    phf_hash_config_t hash;  /* Hash function configuration */
    
    phf_bdz_t() : g_size(0), num_vertices(0), r(0), is_minimal(false), hash{} {}
};

/**
 * @brief Rank/Select data structure for compression
 */
struct phf_rank_select_t {
    std::vector<uint64_t> bitmap;        /* Bit array */
    std::vector<uint32_t> block_ranks;   /* Prefix sums per block */
    std::vector<uint16_t> mini_ranks;    /* Mini-block relative ranks */
    std::vector<uint32_t> select_samples;/* Sampled positions for select queries */
    uint32_t bitmap_size;    /* Size in bits */
    uint32_t num_blocks;     /* Number of blocks */
    uint32_t num_ones;       /* Count of 1-bits */
    
    phf_rank_select_t() : bitmap_size(0), num_blocks(0), num_ones(0) {}
};

/**
 * @brief PHF structure for indicating the type (CHD or BDZ)
 */
enum class phf_type_t {
    PHF_TYPE_CHD,            /* Compress, Hash, Displace */
    PHF_TYPE_BDZ_2PARTITE,   /* 2-partite BDZ */
    PHF_TYPE_BDZ_3PARTITE    /* 3-partite BDZ */
};

/**
 * @brief Context with unified PHF structure
 */
struct phf_ctx_t {
    phf_type_t type;         /* PHF algorithm type */
    
    // Named union with explicit constructors for non-trivial types
    union impl_union {
        phf_chd_t chd;       /* CHD-specific data */
        phf_bdz_t bdz;       /* BDZ-specific data */
        
        // Explicit union constructors/destructors for non-trivial types
        impl_union() {}  // Default constructor does nothing
        ~impl_union() {} // Destructor does nothing (handled by phf_ctx_t)
    } impl;
    
    std::unique_ptr<phf_rank_select_t> compression; /* Optional compression structure */
    uint32_t num_keys;       /* Number of keys */
    
    phf_ctx_t() : type(phf_type_t::PHF_TYPE_CHD), num_keys(0) {
        new (&impl.chd) phf_chd_t();
    }
    
    ~phf_ctx_t() {
        // Properly destroy union members
        if (type == phf_type_t::PHF_TYPE_CHD) {
            impl.chd.~phf_chd_t();
        } else {
            impl.bdz.~phf_bdz_t();
        }
    }
    
    // Delete copy constructor and assignment
    phf_ctx_t(const phf_ctx_t&) = delete;
    phf_ctx_t& operator=(const phf_ctx_t&) = delete;
    
    // Move constructor
    phf_ctx_t(phf_ctx_t&& other) noexcept : type(other.type), num_keys(other.num_keys) {
        if (type == phf_type_t::PHF_TYPE_CHD) {
            new (&impl.chd) phf_chd_t(std::move(other.impl.chd));
        } else {
            new (&impl.bdz) phf_bdz_t(std::move(other.impl.bdz));
        }
        compression = std::move(other.compression);
    }
    
    // Move assignment
    phf_ctx_t& operator=(phf_ctx_t&& other) noexcept {
        if (this != &other) {
            // Destroy current union member
            if (type == phf_type_t::PHF_TYPE_CHD) {
                impl.chd.~phf_chd_t();
            } else {
                impl.bdz.~phf_bdz_t();
            }
            
            // Copy type and construct new member
            type = other.type;
            num_keys = other.num_keys;
            
            if (type == phf_type_t::PHF_TYPE_CHD) {
                new (&impl.chd) phf_chd_t(std::move(other.impl.chd));
            } else {
                new (&impl.bdz) phf_bdz_t(std::move(other.impl.bdz));
            }
            
            compression = std::move(other.compression);
        }
        return *this;
    }
};

/**
 * @brief Key-value pair for encryption
 */
struct phf_kv_pair_t {
    void *key;               /* Key data */
    size_t key_len;          /* Key length in bytes */
    void *value;             /* Value/plaintext data */
    size_t value_len;        /* Value length in bytes */
};

/**
 * @brief Encryption context
 */
struct phf_encrypt_ctx_t {
    std::unique_ptr<phf_ctx_t> phf;  /* Perfect hash function */
    std::vector<std::unique_ptr<std::vector<uint8_t>>> encrypted_table;  /* Encrypted data table */
    uint32_t table_size;     /* Size of encrypted table */
    std::vector<uint8_t> nonce;  /* Cryptographic nonce */
    
    phf_encrypt_ctx_t() : table_size(0) {}
};

/* Hash Function Primitives */

/**
 * @brief Universal hash function with seed
 */
uint32_t phf_hash_universal(const void *key, size_t key_len, uint64_t seed, uint32_t range);

/**
 * @brief Generate random hash seeds
 */
int phf_hash_generate_seeds(phf_hash_config_t *config, uint32_t num_seeds);


/* CHD Implementation */

/**
 * @brief Build CHD-based PHF from keys
 */
int phf_chd_build(const phf_kv_pair_t *keys, uint32_t num_keys, float epsilon, phf_chd_t *chd);

/**
 * @brief Compute hash using CHD
 */
uint32_t phf_chd_hash(const phf_chd_t *chd, const void *key, size_t key_len);

/**
 * @brief Free CHD resources
 */
void phf_chd_destroy(phf_chd_t *chd);

/* BDZ Implementation */

/**
 * @brief Build BDZ-based PHF from keys
 */
int phf_bdz_build(const phf_kv_pair_t *keys, uint32_t num_keys, uint8_t r, bool minimal, phf_bdz_t *bdz);

/**
 * @brief Check if graph is acyclic (used during construction)
 */
bool phf_bdz_is_acyclic(const uint32_t (*edges)[3], uint32_t num_edges, 
                        uint32_t num_vertices, uint8_t r, uint32_t *ordering);

/**
 * @brief Assign values to graph vertices
 */
int phf_bdz_assign_values(const uint32_t (*edges)[3], uint32_t num_edges,
                          uint8_t *g_array, uint32_t g_size, uint8_t r);

/**
 * @brief Compute hash using BDZ
 */
uint32_t phf_bdz_hash(const phf_bdz_t *bdz, const void *key, size_t key_len);

/**
 * @brief Free BDZ resources
 */
void phf_bdz_destroy(phf_bdz_t *bdz);

/* Rank/Select for Compression */

/**
 * @brief Build rank/select structure from bitmap
 */
int phf_rank_select_build(const uint64_t *bitmap, uint32_t bitmap_size, phf_rank_select_t *rs);

/**
 * @brief Rank query: count 1-bits up to position
 */
uint32_t phf_rank(const phf_rank_select_t *rs, uint32_t position);

/**
 * @brief Select query: find position of k-th 1-bit
 */
uint32_t phf_select(const phf_rank_select_t *rs, uint32_t k);

/**
 * @brief Free rank/select resources
 */
void phf_rank_select_destroy(phf_rank_select_t *rs);

/* Elias-Fano Compression */

/**
 * @brief Compress array using Elias-Fano encoding
 */
int phf_elias_fano_compress(const uint32_t *array, uint32_t array_len,
                            uint64_t **compressed, uint32_t *compressed_size);

/**
 * @brief Decompress value at index using Elias-Fano
 */
uint32_t phf_elias_fano_decompress(const uint64_t *compressed, uint32_t index,
                                   const phf_rank_select_t *rs);

/* Encryption/Decryption API */

/**
 * @brief Initialize encryption context with PHF
 */
int phf_encrypt_init(const phf_kv_pair_t *keys, uint32_t num_keys, 
                     phf_type_t type, phf_encrypt_ctx_t *ctx);

/**
 * @brief Encrypt data using PHF-based mapping
 */
int phf_encrypt(phf_encrypt_ctx_t *ctx, const void *key, size_t key_len,
               const void *plaintext, size_t plaintext_len,
               void **ciphertext, size_t *ciphertext_len);

/**
 * @brief Decrypt data using PHF-based mapping
 */
int phf_decrypt(phf_encrypt_ctx_t *ctx, const void *key, size_t key_len,
               const void *ciphertext, size_t ciphertext_len,
               void **plaintext, size_t *plaintext_len);

/**
 * @brief Free encryption context
 */
void phf_encrypt_destroy(phf_encrypt_ctx_t *ctx);

/* Utilities */

/**
 * @brief Calculate optimal PHF parameters for given number of keys
 */
int phf_calculate_params(uint32_t num_keys, phf_type_t type, 
                        float *epsilon, uint32_t *table_size);

/**
 * @brief Get memory usage statistics
 */
int phf_get_memory_stats(const phf_ctx_t *phf, size_t *total_bytes, size_t *metadata_bytes);

/**
 * @brief Serialize PHF to buffer
 */
int phf_serialize(const phf_ctx_t *phf, void **buffer, size_t *buffer_len);

/**
 * @brief Deserialize PHF from buffer
 */
int phf_deserialize(const void *buffer, size_t buffer_len, phf_ctx_t *phf);

#endif /* PHF_CRYPTO_H */