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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ========================================================================== */
/*                          Core Data Structures                              */
/* ========================================================================== */

/**
 * @brief Hash function configuration
 */
typedef struct {
    uint64_t seed0;          /* Primary hash seed */
    uint64_t seed1;          /* Secondary hash seed */
    uint64_t seed2;          /* Tertiary hash seed (for 3-partite) */
    uint32_t num_seeds;      /* Number of hash functions (2 or 3) */
} phf_hash_config_t;

/**
 * @brief CHD-based PHF configuration
 */
typedef struct {
    uint32_t *displacements; /* Array of displacement values (a, b) pairs */
    uint32_t num_buckets;    /* Number of buckets (r) */
    uint32_t table_size;     /* Hash table size m = (1 + epsilon) * n */
    float epsilon;           /* Load factor overhead */
    phf_hash_config_t hash;  /* Hash function configuration */
} phf_chd_t;

/**
 * @brief BDZ/BPZ graph-based PHF configuration
 */
typedef struct {
    uint8_t *g_array;        /* Selector/vertex value array */
    uint32_t g_size;         /* Size of g array (2*N for bipartite, 3*K for 3-partite) */
    uint32_t num_vertices;   /* Number of vertices per partition */
    uint8_t r;               /* Number of partitions (2 or 3) */
    bool is_minimal;         /* true for MPHF, false for PHF */
    phf_hash_config_t hash;  /* Hash function configuration */
} phf_bdz_t;

/**
 * @brief Rank/Select data structure for compression
 */
typedef struct {
    uint64_t *bitmap;        /* Bit array */
    uint32_t *block_ranks;   /* Prefix sums per block */
    uint16_t *mini_ranks;    /* Mini-block relative ranks */
    uint32_t *select_samples;/* Sampled positions for select queries */
    uint32_t bitmap_size;    /* Size in bits */
    uint32_t num_blocks;     /* Number of blocks */
    uint32_t num_ones;       /* Count of 1-bits */
} phf_rank_select_t;

/**
 * @brief PHF structure for indicating the type (CHD or BDZ)
 */
typedef enum {
    PHF_TYPE_CHD,            /* Compress, Hash, Displace */
    PHF_TYPE_BDZ_2PARTITE,   /* 2-partite BDZ */
    PHF_TYPE_BDZ_3PARTITE    /* 3-partite BDZ */
} phf_type_t;

/**
 * @brief Context with unified PHF structure
 */
typedef struct {
    phf_type_t type;         /* PHF algorithm type */
    union {
        phf_chd_t chd;       /* CHD-specific data */
        phf_bdz_t bdz;       /* BDZ-specific data */
    } impl;
    phf_rank_select_t *compression; /* Optional compression structure */
    uint32_t num_keys;       /* Number of keys */
} phf_ctx_t;

/**
 * @brief Key-value pair for encryption
 */
typedef struct {
    void *key;               /* Key data */
    size_t key_len;          /* Key length in bytes */
    void *value;             /* Value/plaintext data */
    size_t value_len;        /* Value length in bytes */
} phf_kv_pair_t;

/**
 * @brief Encryption context
 */
typedef struct {
    phf_ctx_t *phf;          /* Perfect hash function */
    void **encrypted_table;  /* Encrypted data table */
    uint32_t table_size;     /* Size of encrypted table */
    uint8_t *nonce;          /* Cryptographic nonce */
    size_t nonce_len;        /* Nonce length */
} phf_encrypt_ctx_t;

/* Hash Function Primitives */

/**
 * @brief Universal hash function with seed
 * 
 * @param key Input key
 * @param key_len Length of key
 * @param seed Hash seed
 * @param range Output range [0, range)
 * @return Hash value in [0, range)
 */
uint32_t phf_hash_universal(const void *key, size_t key_len, uint64_t seed, uint32_t range);

/**
 * @brief Generate random hash seeds
 * 
 * @param config Hash configuration to populate
 * @param num_seeds Number of seeds to generate (2 or 3)
 * @return 0 on success, -1 on failure
 */
int phf_hash_generate_seeds(phf_hash_config_t *config, uint32_t num_seeds);


/* CHD Implementation */

/**
 * @brief Build CHD-based PHF from keys
 * 
 * @param keys Array of key-value pairs
 * @param num_keys Number of keys
 * @param epsilon Load factor overhead (typically 0.1 to 0.5)
 * @param chd Output CHD structure
 * @return 0 on success, -1 on failure
 */
int phf_chd_build(const phf_kv_pair_t *keys, uint32_t num_keys, float epsilon, phf_chd_t *chd);

/**
 * @brief Compute hash using CHD
 * 
 * @param chd CHD structure
 * @param key Input key
 * @param key_len Key length
 * @return Hash value (index into hash table)
 */
uint32_t phf_chd_hash(const phf_chd_t *chd, const void *key, size_t key_len);

/**
 * @brief Free CHD resources
 * 
 * @param chd CHD structure to free
 */
void phf_chd_destroy(phf_chd_t *chd);

/* BDZ Implementation */

/**
 * @brief Build BDZ-based PHF from keys
 * 
 * @param keys Array of key-value pairs
 * @param num_keys Number of keys
 * @param r Number of partitions (2 or 3)
 * @param minimal true for MPHF, false for PHF
 * @param bdz Output BDZ structure
 * @return 0 on success, -1 on failure
 */
int phf_bdz_build(const phf_kv_pair_t *keys, uint32_t num_keys, uint8_t r, bool minimal, phf_bdz_t *bdz);

/**
 * @brief Check if graph is acyclic (used during construction)
 * 
 * @param edges Edge list
 * @param num_edges Number of edges
 * @param num_vertices Number of vertices per partition
 * @param r Number of partitions
 * @param ordering Output: edge removal ordering
 * @return true if acyclic, false if cyclic
 */
bool phf_bdz_is_acyclic(const uint32_t (*edges)[3], uint32_t num_edges, 
                        uint32_t num_vertices, uint8_t r, uint32_t *ordering);

/**
 * @brief Assign values to graph vertices
 * 
 * @param edges Edge list in removal order
 * @param num_edges Number of edges
 * @param g_array Output: vertex value array
 * @param g_size Size of g array
 * @param r Number of partitions
 * @return 0 on success, -1 on failure
 */
int phf_bdz_assign_values(const uint32_t (*edges)[3], uint32_t num_edges,
                          uint8_t *g_array, uint32_t g_size, uint8_t r);

/**
 * @brief Compute hash using BDZ
 * 
 * @param bdz BDZ structure
 * @param key Input key
 * @param key_len Key length
 * @return Hash value (index into hash table)
 */
uint32_t phf_bdz_hash(const phf_bdz_t *bdz, const void *key, size_t key_len);

/**
 * @brief Free BDZ resources
 * 
 * @param bdz BDZ structure to free
 */
void phf_bdz_destroy(phf_bdz_t *bdz);

/* Rank/Select for Compression */

/**
 * @brief Build rank/select structure from bitmap
 * 
 * @param bitmap Bit array
 * @param bitmap_size Size in bits
 * @param rs Output rank/select structure
 * @return 0 on success, -1 on failure
 */
int phf_rank_select_build(const uint64_t *bitmap, uint32_t bitmap_size, phf_rank_select_t *rs);

/**
 * @brief Rank query: count 1-bits up to position
 * 
 * @param rs Rank/select structure
 * @param position Query position
 * @return Number of 1-bits in [0, position]
 */
uint32_t phf_rank(const phf_rank_select_t *rs, uint32_t position);

/**
 * @brief Select query: find position of k-th 1-bit
 * 
 * @param rs Rank/select structure
 * @param k Query index (0-based)
 * @return Position of (k+1)-th 1-bit
 */
uint32_t phf_select(const phf_rank_select_t *rs, uint32_t k);

/**
 * @brief Free rank/select resources
 * 
 * @param rs Rank/select structure to free
 */
void phf_rank_select_destroy(phf_rank_select_t *rs);

/* Elias-Fano Compression */

/**
 * @brief Compress array using Elias-Fano encoding
 * 
 * @param array Input array
 * @param array_len Array length
 * @param compressed Output compressed bitmap
 * @param compressed_size Output compressed size
 * @return 0 on success, -1 on failure
 */
int phf_elias_fano_compress(const uint32_t *array, uint32_t array_len,
                            uint64_t **compressed, uint32_t *compressed_size);

/**
 * @brief Decompress value at index using Elias-Fano
 * 
 * @param compressed Compressed bitmap
 * @param index Query index
 * @param rs Rank/select structure for compressed data
 * @return Decompressed value, CURENTLLY PLACEHOLDER 0
 */
uint32_t phf_elias_fano_decompress(const uint64_t *compressed, uint32_t index,
                                   const phf_rank_select_t *rs);

/* Encryption/Decryption API */

/**
 * @brief Initialize encryption context with PHF
 * 
 * @param keys Array of key-value pairs
 * @param num_keys Number of keys
 * @param type PHF type to use
 * @param ctx Output encryption context
 * @return 0 on success, -1 on failure
 */
int phf_encrypt_init(const phf_kv_pair_t *keys, uint32_t num_keys, 
                     phf_type_t type, phf_encrypt_ctx_t *ctx);

/**
 * @brief Encrypt data using PHF-based mapping
 * 
 * @param ctx Encryption context
 * @param key Lookup key
 * @param key_len Key length
 * @param plaintext Plaintext data
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext buffer
 * @param ciphertext_len Output ciphertext length
 * @return 0 on success, -1 on failure
 */
int phf_encrypt(phf_encrypt_ctx_t *ctx, const void *key, size_t key_len,
               const void *plaintext, size_t plaintext_len,
               void **ciphertext, size_t *ciphertext_len);

/**
 * @brief Decrypt data using PHF-based mapping
 * 
 * @param ctx Encryption context
 * @param key Lookup key
 * @param key_len Key length
 * @param ciphertext Ciphertext data
 * @param ciphertext_len Ciphertext length
 * @param plaintext Output plaintext buffer
 * @param plaintext_len Output plaintext length
 * @return 0 on success, -1 on failure
 */
int phf_decrypt(phf_encrypt_ctx_t *ctx, const void *key, size_t key_len,
               const void *ciphertext, size_t ciphertext_len,
               void **plaintext, size_t *plaintext_len);

/**
 * @brief Free encryption context
 * 
 * @param ctx Encryption context to free
 */
void phf_encrypt_destroy(phf_encrypt_ctx_t *ctx);

/* Utilities */

/**
 * @brief Calculate optimal PHF parameters for given number of keys
 * 
 * @param num_keys Number of keys
 * @param type PHF type
 * @param epsilon Output: recommended epsilon for CHD
 * @param table_size Output: recommended table size
 * @return 0 on success, -1 on failure
 */
int phf_calculate_params(uint32_t num_keys, phf_type_t type, 
                        float *epsilon, uint32_t *table_size);

/**
 * @brief Get memory usage statistics
 * 
 * @param phf COntext with PHF structure
 * @param total_bytes Output: total memory usage
 * @param metadata_bytes Output: metadata overhead
 * @return 0 on success, -1 on failure
 */
int phf_get_memory_stats(const phf_ctx_t *phf, size_t *total_bytes, size_t *metadata_bytes);

/**
 * @brief Serialize PHF to buffer
 * 
 * @param phf Context with PHF structure
 * @param buffer Output buffer
 * @param buffer_len Output buffer length
 * @return 0 on success, -1 on failure
 */
int phf_serialize(const phf_ctx_t *phf, void **buffer, size_t *buffer_len);

/**
 * @brief Deserialize PHF from buffer
 * 
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param phf Context with output PHF structure
 * @return 0 on success, -1 on failure
 */
int phf_deserialize(const void *buffer, size_t buffer_len, phf_ctx_t *phf);

#endif /* PHF_CRYPTO_H */