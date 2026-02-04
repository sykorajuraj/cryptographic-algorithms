/**
 * @file phf_api.cpp
 * @brief High-level PHF API for encryption/decryption
 */

#include "phf.h"
#include <cstdlib>
#include <cstring>
#include <memory>

int phf_encrypt_init(const phf_kv_pair_t *keys, uint32_t num_keys, 
                     phf_type_t type, phf_encrypt_ctx_t *ctx) {
    if (!keys || !ctx || num_keys == 0) return -1;
    
    // Clear existing data
    ctx->phf.reset();
    ctx->encrypted_table.clear();
    ctx->nonce.clear();
    ctx->table_size = 0;
    
    /* Allocate PHF context */
    ctx->phf = std::make_unique<phf_ctx_t>();
    ctx->phf->type = type;
    ctx->phf->num_keys = num_keys;
    
    // Destroy old union member and construct new one
    if (type == phf_type_t::PHF_TYPE_CHD) {
        ctx->phf->impl.chd.~phf_chd_t();
        new (&ctx->phf->impl.chd) phf_chd_t();
    } else {
        ctx->phf->impl.chd.~phf_chd_t();
        new (&ctx->phf->impl.bdz) phf_bdz_t();
    }
    
    int result = -1;
    
    /* Build PHF based on type */
    switch (type) {
        case phf_type_t::PHF_TYPE_CHD:
            result = phf_chd_build(keys, num_keys, 0.3f, &ctx->phf->impl.chd);
            if (result == 0) {
                ctx->table_size = ctx->phf->impl.chd.table_size;
            }
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
            result = phf_bdz_build(keys, num_keys, 2, false, &ctx->phf->impl.bdz);
            if (result == 0) {
                ctx->table_size = ctx->phf->impl.bdz.num_vertices * 2;
            }
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE:
            result = phf_bdz_build(keys, num_keys, 3, false, &ctx->phf->impl.bdz);
            if (result == 0) {
                ctx->table_size = ctx->phf->impl.bdz.num_vertices * 3;
            }
            break;
            
        default:
            ctx->phf.reset();
            return -1;
    }
    
    if (result != 0) {
        ctx->phf.reset();
        return -1;
    }
    
    /* Allocate encrypted data table */
    ctx->encrypted_table.resize(ctx->table_size);
    
    /* Generate nonce */
    ctx->nonce.resize(16);
    
    /* Fill with random data */
    for (size_t i = 0; i < ctx->nonce.size(); i++) {
        ctx->nonce[i] = std::rand() & 0xFF;
    }
    
    return 0;
}

int phf_encrypt(phf_encrypt_ctx_t *ctx, const void *key, size_t key_len,
               const void *plaintext, size_t plaintext_len,
               void **ciphertext, size_t *ciphertext_len) {
    if (!ctx || !key || !plaintext || !ciphertext || !ciphertext_len) return -1;
    
    /* Get hash position */
    uint32_t pos = 0;
    
    switch (ctx->phf->type) {
        case phf_type_t::PHF_TYPE_CHD:
            pos = phf_chd_hash(&ctx->phf->impl.chd, key, key_len);
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE:
            pos = phf_bdz_hash(&ctx->phf->impl.bdz, key, key_len);
            break;
            
        default:
            return -1;
    }
    
    if (pos >= ctx->table_size) return -1;
    
    /* Simple XOR encryption with nonce (for demonstration) */
    *ciphertext_len = plaintext_len;
    *ciphertext = std::malloc(*ciphertext_len);
    if (!*ciphertext) return -1;
    
    const uint8_t *pt = static_cast<const uint8_t *>(plaintext);
    uint8_t *ct = static_cast<uint8_t *>(*ciphertext);
    
    for (size_t i = 0; i < plaintext_len; i++) {
        ct[i] = pt[i] ^ ctx->nonce[i % ctx->nonce.size()] ^ (pos & 0xFF);
    }
    
    /* Store in table */
    ctx->encrypted_table[pos] = std::make_unique<std::vector<uint8_t>>(ct, ct + *ciphertext_len);
    
    return 0;
}

int phf_decrypt(phf_encrypt_ctx_t *ctx, const void *key, size_t key_len,
               const void *ciphertext, size_t ciphertext_len,
               void **plaintext, size_t *plaintext_len) {
    if (!ctx || !key || !ciphertext || !plaintext || !plaintext_len) return -1;
    
    /* Get hash position */
    uint32_t pos = 0;
    
    switch (ctx->phf->type) {
        case phf_type_t::PHF_TYPE_CHD:
            pos = phf_chd_hash(&ctx->phf->impl.chd, key, key_len);
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE:
            pos = phf_bdz_hash(&ctx->phf->impl.bdz, key, key_len);
            break;
            
        default:
            return -1;
    }
    
    if (pos >= ctx->table_size) return -1;
    
    /* Simple XOR decryption (same as encryption) */
    *plaintext_len = ciphertext_len;
    *plaintext = std::malloc(*plaintext_len);
    if (!*plaintext) return -1;
    
    const uint8_t *ct = static_cast<const uint8_t *>(ciphertext);
    uint8_t *pt = static_cast<uint8_t *>(*plaintext);
    
    for (size_t i = 0; i < ciphertext_len; i++) {
        pt[i] = ct[i] ^ ctx->nonce[i % ctx->nonce.size()] ^ (pos & 0xFF);
    }
    
    return 0;
}

void phf_encrypt_destroy(phf_encrypt_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->phf) {
        switch (ctx->phf->type) {
            case phf_type_t::PHF_TYPE_CHD:
                phf_chd_destroy(&ctx->phf->impl.chd);
                break;
                
            case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
            case phf_type_t::PHF_TYPE_BDZ_3PARTITE:
                phf_bdz_destroy(&ctx->phf->impl.bdz);
                break;
        }
        
        ctx->phf.reset();
    }
    
    ctx->encrypted_table.clear();
    ctx->nonce.clear();
    ctx->table_size = 0;
}

int phf_calculate_params(uint32_t num_keys, phf_type_t type, 
                        float *epsilon, uint32_t *table_size) {
    if (!epsilon || !table_size || num_keys == 0) return -1;
    
    switch (type) {
        case phf_type_t::PHF_TYPE_CHD:
            *epsilon = 0.3f;  /* 30% overhead */
            *table_size = static_cast<uint32_t>((1.0f + *epsilon) * num_keys);
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
            *epsilon = 1.0f;  /* 100% overhead (2n table) */
            *table_size = num_keys * 2;
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE:
            *epsilon = 0.23f;  /* 23% overhead (1.23n table) */
            *table_size = static_cast<uint32_t>(num_keys * 1.23f);
            break;
            
        default:
            return -1;
    }
    
    return 0;
}

int phf_get_memory_stats(const phf_ctx_t *phf, size_t *total_bytes, size_t *metadata_bytes) {
    if (!phf || !total_bytes || !metadata_bytes) return -1;
    
    *total_bytes = 0;
    *metadata_bytes = 0;
    
    switch (phf->type) {
        case phf_type_t::PHF_TYPE_CHD: {
            const phf_chd_t *chd = &phf->impl.chd;
            *metadata_bytes = chd->displacements.size() * sizeof(uint32_t);
            *total_bytes = *metadata_bytes + sizeof(phf_chd_t);
            break;
        }
        
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE: {
            const phf_bdz_t *bdz = &phf->impl.bdz;
            *metadata_bytes = bdz->g_array.size() * sizeof(uint8_t);
            *total_bytes = *metadata_bytes + sizeof(phf_bdz_t);
            break;
        }
        
        default:
            return -1;
    }
    
    if (phf->compression) {
        *total_bytes += sizeof(phf_rank_select_t);
        *total_bytes += phf->compression->bitmap_size / 8;
        *total_bytes += phf->compression->num_blocks * sizeof(uint32_t);
    }
    
    return 0;
}

int phf_serialize(const phf_ctx_t *phf, void **buffer, size_t *buffer_len) {
    if (!phf || !buffer || !buffer_len) return -1;
    
    /* Calculate required buffer size */
    size_t total_size = sizeof(phf_type_t) + sizeof(uint32_t);
    
    switch (phf->type) {
        case phf_type_t::PHF_TYPE_CHD:
            total_size += sizeof(phf_hash_config_t);
            total_size += 3 * sizeof(uint32_t) + sizeof(float);
            total_size += phf->impl.chd.displacements.size() * sizeof(uint32_t);
            break;
            
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE:
            total_size += sizeof(phf_hash_config_t);
            total_size += 2 * sizeof(uint32_t) + sizeof(uint8_t) + sizeof(bool);
            total_size += phf->impl.bdz.g_array.size() * sizeof(uint8_t);
            break;
            
        default:
            return -1;
    }
    
    /* Allocate buffer */
    *buffer = std::malloc(total_size);
    if (!*buffer) return -1;
    
    *buffer_len = total_size;
    
    uint8_t *ptr = static_cast<uint8_t *>(*buffer);
    
    /* Write type */
    std::memcpy(ptr, &phf->type, sizeof(phf_type_t));
    ptr += sizeof(phf_type_t);
    
    /* Write num_keys */
    std::memcpy(ptr, &phf->num_keys, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    /* Write type-specific data */
    switch (phf->type) {
        case phf_type_t::PHF_TYPE_CHD: {
            std::memcpy(ptr, &phf->impl.chd.hash, sizeof(phf_hash_config_t));
            ptr += sizeof(phf_hash_config_t);
            std::memcpy(ptr, &phf->impl.chd.num_buckets, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(ptr, &phf->impl.chd.table_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(ptr, &phf->impl.chd.epsilon, sizeof(float));
            ptr += sizeof(float);
            
            std::memcpy(ptr, phf->impl.chd.displacements.data(), 
                       phf->impl.chd.displacements.size() * sizeof(uint32_t));
            break;
        }
            
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE: {
            std::memcpy(ptr, &phf->impl.bdz.hash, sizeof(phf_hash_config_t));
            ptr += sizeof(phf_hash_config_t);
            std::memcpy(ptr, &phf->impl.bdz.g_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(ptr, &phf->impl.bdz.num_vertices, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(ptr, &phf->impl.bdz.r, sizeof(uint8_t));
            ptr += sizeof(uint8_t);
            std::memcpy(ptr, &phf->impl.bdz.is_minimal, sizeof(bool));
            ptr += sizeof(bool);
            
            std::memcpy(ptr, phf->impl.bdz.g_array.data(), 
                       phf->impl.bdz.g_array.size() * sizeof(uint8_t));
            break;
        }
    }
    
    return 0;
}

int phf_deserialize(const void *buffer, size_t buffer_len, phf_ctx_t *phf) {
    if (!buffer || !phf || buffer_len < sizeof(phf_type_t) + sizeof(uint32_t)) {
        return -1;
    }
    
    const uint8_t *ptr = static_cast<const uint8_t *>(buffer);
    
    /* Read type */
    std::memcpy(&phf->type, ptr, sizeof(phf_type_t));
    ptr += sizeof(phf_type_t);
    
    /* Read num_keys */
    std::memcpy(&phf->num_keys, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    /* Read type-specific data */
    switch (phf->type) {
        case phf_type_t::PHF_TYPE_CHD: {
            size_t min_size = sizeof(phf_type_t) + sizeof(uint32_t) + 
                             sizeof(phf_hash_config_t) + 3 * sizeof(uint32_t) + sizeof(float);
            if (buffer_len < min_size) return -1;
            
            // Construct CHD member
            new (&phf->impl.chd) phf_chd_t();
            
            std::memcpy(&phf->impl.chd.hash, ptr, sizeof(phf_hash_config_t));
            ptr += sizeof(phf_hash_config_t);
            std::memcpy(&phf->impl.chd.num_buckets, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(&phf->impl.chd.table_size, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(&phf->impl.chd.epsilon, ptr, sizeof(float));
            ptr += sizeof(float);
            
            phf->impl.chd.displacements.resize(phf->impl.chd.num_buckets);
            std::memcpy(phf->impl.chd.displacements.data(), ptr, 
                       phf->impl.chd.num_buckets * sizeof(uint32_t));
            break;
        }
        
        case phf_type_t::PHF_TYPE_BDZ_2PARTITE:
        case phf_type_t::PHF_TYPE_BDZ_3PARTITE: {
            size_t min_size = sizeof(phf_type_t) + sizeof(uint32_t) + 
                             sizeof(phf_hash_config_t) + 2 * sizeof(uint32_t) + 
                             sizeof(uint8_t) + sizeof(bool);
            if (buffer_len < min_size) return -1;
            
            // Construct BDZ member
            new (&phf->impl.bdz) phf_bdz_t();
            
            std::memcpy(&phf->impl.bdz.hash, ptr, sizeof(phf_hash_config_t));
            ptr += sizeof(phf_hash_config_t);
            std::memcpy(&phf->impl.bdz.g_size, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(&phf->impl.bdz.num_vertices, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            std::memcpy(&phf->impl.bdz.r, ptr, sizeof(uint8_t));
            ptr += sizeof(uint8_t);
            std::memcpy(&phf->impl.bdz.is_minimal, ptr, sizeof(bool));
            ptr += sizeof(bool);
            
            phf->impl.bdz.g_array.resize(phf->impl.bdz.g_size);
            std::memcpy(phf->impl.bdz.g_array.data(), ptr, 
                       phf->impl.bdz.g_size * sizeof(uint8_t));
            break;
        }
        
        default:
            return -1;
    }
    
    return 0;
}