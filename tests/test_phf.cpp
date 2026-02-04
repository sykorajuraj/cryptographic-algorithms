/**
 * @file tests/test_phf.cpp
 * @brief Google Test suite for Perfect Hash Function library
 * 
 * This test suite validates:
 * - Correctness of encryption/decryption
 * - Performance characteristics
 * - Data integrity
 * - Compression effectiveness
 * - Memory usage
 * - Collision detection
 */

#include <gtest/gtest.h>
#include <random>
#include <chrono>
#include <algorithm>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <cstring>

extern "C" {
    #include "../src/hash/phf.h"
}

using namespace std;
using namespace std::chrono;

// ============================================================================
// Test Fixtures
// ============================================================================

class PHFTest : public ::testing::Test {
protected:
    void SetUp() override {
        srand(42);  // Fixed seed for reproducibility
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    // Helper: Generate random string
    string random_string(size_t length) {
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        string result;
        result.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            result += alphanum[rand() % (sizeof(alphanum) - 1)];
        }
        return result;
    }
    
    // Helper: Create key-value pairs
    vector<phf_kv_pair_t> create_kv_pairs(const vector<string>& keys) {
        vector<phf_kv_pair_t> pairs;
        for (const auto& key : keys) {
            phf_kv_pair_t pair;
            pair.key = (void*)key.c_str();
            pair.key_len = key.length();
            pair.value = nullptr;
            pair.value_len = 0;
            pairs.push_back(pair);
        }
        return pairs;
    }
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(PHFTest, HashFunctionDeterminism) {
    const char* test_key = "test_key_123";
    uint64_t seed = 0x123456789ABCDEF0ULL;
    uint32_t range = 1000;
    
    uint32_t h1 = phf_hash_universal(test_key, strlen(test_key), seed, range);
    uint32_t h2 = phf_hash_universal(test_key, strlen(test_key), seed, range);
    
    EXPECT_EQ(h1, h2) << "Hash function must be deterministic";
    EXPECT_LT(h1, range) << "Hash must be within range";
}

TEST_F(PHFTest, HashFunctionDistribution) {
    const int NUM_KEYS = 10000;
    const int RANGE = 100;
    vector<int> buckets(RANGE, 0);
    
    for (int i = 0; i < NUM_KEYS; i++) {
        string key = "key_" + to_string(i);
        uint32_t hash = phf_hash_universal(key.c_str(), key.length(), 42, RANGE);
        buckets[hash]++;
    }
    
    // Check distribution (should be relatively uniform)
    int expected = NUM_KEYS / RANGE;
    int max_deviation = expected / 2;  // Allow 50% deviation
    
    for (int count : buckets) {
        EXPECT_GE(count, expected - max_deviation);
        EXPECT_LE(count, expected + max_deviation);
    }
}

// ============================================================================
// CHD Algorithm Tests
// ============================================================================

TEST_F(PHFTest, CHD_BasicConstruction) {
    vector<string> keys = {"apple", "banana", "cherry", "date", "elderberry"};
    auto pairs = create_kv_pairs(keys);
    
    phf_chd_t chd;
    int result = phf_chd_build(pairs.data(), pairs.size(), 0.3f, &chd);
    
    ASSERT_EQ(result, 0) << "CHD construction should succeed";
    EXPECT_GT(chd.table_size, 0);
    EXPECT_GT(chd.num_buckets, 0);
    EXPECT_NE(chd.displacements, nullptr);
    
    phf_chd_destroy(&chd);
}

TEST_F(PHFTest, CHD_NoCo llisions) {
    vector<string> keys;
    for (int i = 0; i < 100; i++) {
        keys.push_back("key_" + to_string(i));
    }
    auto pairs = create_kv_pairs(keys);
    
    phf_chd_t chd;
    ASSERT_EQ(phf_chd_build(pairs.data(), pairs.size(), 0.3f, &chd), 0);
    
    // Check for collisions
    set<uint32_t> positions;
    for (const auto& key : keys) {
        uint32_t pos = phf_chd_hash(&chd, key.c_str(), key.length());
        EXPECT_LT(pos, chd.table_size);
        EXPECT_EQ(positions.count(pos), 0) << "Collision detected at position " << pos;
        positions.insert(pos);
    }
    
    EXPECT_EQ(positions.size(), keys.size()) << "All keys should hash to unique positions";
    
    phf_chd_destroy(&chd);
}

TEST_F(PHFTest, CHD_LargeDataset) {
    const int NUM_KEYS = 10000;
    vector<string> keys;
    for (int i = 0; i < NUM_KEYS; i++) {
        keys.push_back(random_string(20));
    }
    auto pairs = create_kv_pairs(keys);
    
    auto start = high_resolution_clock::now();
    phf_chd_t chd;
    int result = phf_chd_build(pairs.data(), pairs.size(), 0.3f, &chd);
    auto end = high_resolution_clock::now();
    
    ASSERT_EQ(result, 0);
    
    auto duration = duration_cast<milliseconds>(end - start).count();
    cout << "CHD construction for " << NUM_KEYS << " keys: " << duration << "ms" << endl;
    cout << "Table size: " << chd.table_size << " (load factor: " 
         << (float)NUM_KEYS / chd.table_size << ")" << endl;
    
    // Verify no collisions
    set<uint32_t> positions;
    for (const auto& key : keys) {
        positions.insert(phf_chd_hash(&chd, key.c_str(), key.length()));
    }
    EXPECT_EQ(positions.size(), keys.size());
    
    phf_chd_destroy(&chd);
}

// ============================================================================
// BDZ Algorithm Tests
// ============================================================================

TEST_F(PHFTest, BDZ_BipartiteConstruction) {
    vector<string> keys = {"key1", "key2", "key3", "key4", "key5"};
    auto pairs = create_kv_pairs(keys);
    
    phf_bdz_t bdz;
    int result = phf_bdz_build(pairs.data(), pairs.size(), 2, false, &bdz);
    
    ASSERT_EQ(result, 0) << "BDZ-2 construction should succeed";
    EXPECT_EQ(bdz.r, 2);
    EXPECT_GT(bdz.num_vertices, 0);
    EXPECT_NE(bdz.g_array, nullptr);
    
    phf_bdz_destroy(&bdz);
}

TEST_F(PHFTest, BDZ_TripartiteConstruction) {
    vector<string> keys;
    for (int i = 0; i < 50; i++) {
        keys.push_back("test_key_" + to_string(i));
    }
    auto pairs = create_kv_pairs(keys);
    
    phf_bdz_t bdz;
    int result = phf_bdz_build(pairs.data(), pairs.size(), 3, false, &bdz);
    
    ASSERT_EQ(result, 0) << "BDZ-3 construction should succeed";
    EXPECT_EQ(bdz.r, 3);
    
    // All keys should hash to valid range [0, r)
    for (const auto& key : keys) {
        uint32_t hash = phf_bdz_hash(&bdz, key.c_str(), key.length());
        EXPECT_LT(hash, bdz.r);
    }
    
    phf_bdz_destroy(&bdz);
}

TEST_F(PHFTest, BDZ_MinimalPerfectHash) {
    vector<string> keys;
    for (int i = 0; i < 100; i++) {
        keys.push_back(random_string(10));
    }
    auto pairs = create_kv_pairs(keys);
    
    phf_bdz_t bdz;
    int result = phf_bdz_build(pairs.data(), pairs.size(), 3, true, &bdz);
    
    if (result == 0) {  // May fail after max attempts
        EXPECT_TRUE(bdz.is_minimal);
        
        // For MPHF, we expect very compact storage
        float bits_per_key = (float)(bdz.g_size * 8) / keys.size();
        cout << "BDZ-3 MPHF: " << bits_per_key << " bits/key" << endl;
        EXPECT_LT(bits_per_key, 4.0f) << "MPHF should be very space-efficient";
    }
    
    phf_bdz_destroy(&bdz);
}

// ============================================================================
// Encryption/Decryption Tests
// ============================================================================

TEST_F(PHFTest, Encryption_BasicRoundTrip) {
    vector<string> keys = {"user1", "user2", "user3"};
    auto pairs = create_kv_pairs(keys);
    
    phf_encrypt_ctx_t ctx;
    ASSERT_EQ(phf_encrypt_init(pairs.data(), pairs.size(), PHF_TYPE_CHD, &ctx), 0);
    
    const char* plaintext = "secret message";
    void* ciphertext = nullptr;
    size_t ciphertext_len = 0;
    
    // Encrypt
    ASSERT_EQ(phf_encrypt(&ctx, "user1", 5, plaintext, strlen(plaintext),
                         &ciphertext, &ciphertext_len), 0);
    ASSERT_NE(ciphertext, nullptr);
    
    // Decrypt
    void* decrypted = nullptr;
    size_t decrypted_len = 0;
    ASSERT_EQ(phf_decrypt(&ctx, "user1", 5, ciphertext, ciphertext_len,
                         &decrypted, &decrypted_len), 0);
    ASSERT_NE(decrypted, nullptr);
    
    // Verify
    EXPECT_EQ(decrypted_len, strlen(plaintext));
    EXPECT_EQ(memcmp(decrypted, plaintext, decrypted_len), 0);
    
    free(ciphertext);
    free(decrypted);
    phf_encrypt_destroy(&ctx);
}

TEST_F(PHFTest, Encryption_MultipleKeys) {
    vector<string> keys = {"alice", "bob", "charlie", "david", "eve"};
    auto pairs = create_kv_pairs(keys);
    
    phf_encrypt_ctx_t ctx;
    ASSERT_EQ(phf_encrypt_init(pairs.data(), pairs.size(), PHF_TYPE_BDZ_3PARTITE, &ctx), 0);
    
    map<string, string> messages = {
        {"alice", "Hello from Alice"},
        {"bob", "Bob's secret"},
        {"charlie", "Charlie was here"},
        {"david", "David's data"},
        {"eve", "Eve's encrypted message"}
    };
    
    // Encrypt all
    map<string, pair<void*, size_t>> encrypted;
    for (const auto& [key, msg] : messages) {
        void* ct = nullptr;
        size_t ct_len = 0;
        ASSERT_EQ(phf_encrypt(&ctx, key.c_str(), key.length(),
                             msg.c_str(), msg.length(), &ct, &ct_len), 0);
        encrypted[key] = {ct, ct_len};
    }
    
    // Decrypt and verify all
    for (const auto& [key, msg] : messages) {
        auto [ct, ct_len] = encrypted[key];
        void* pt = nullptr;
        size_t pt_len = 0;
        ASSERT_EQ(phf_decrypt(&ctx, key.c_str(), key.length(),
                             ct, ct_len, &pt, &pt_len), 0);
        
        EXPECT_EQ(pt_len, msg.length());
        EXPECT_EQ(memcmp(pt, msg.c_str(), pt_len), 0) << "Decryption failed for " << key;
        
        free(pt);
    }
    
    // Cleanup
    for (auto& [_, ct_pair] : encrypted) {
        free(ct_pair.first);
    }
    phf_encrypt_destroy(&ctx);
}

TEST_F(PHFTest, Encryption_DataIntegrity) {
    vector<string> keys = {"key1", "key2", "key3"};
    auto pairs = create_kv_pairs(keys);
    
    phf_encrypt_ctx_t ctx;
    ASSERT_EQ(phf_encrypt_init(pairs.data(), pairs.size(), PHF_TYPE_CHD, &ctx), 0);
    
    // Test with binary data
    uint8_t binary_data[256];
    for (int i = 0; i < 256; i++) {
        binary_data[i] = (uint8_t)i;
    }
    
    void* ct = nullptr;
    size_t ct_len = 0;
    ASSERT_EQ(phf_encrypt(&ctx, "key1", 4, binary_data, 256, &ct, &ct_len), 0);
    
    void* pt = nullptr;
    size_t pt_len = 0;
    ASSERT_EQ(phf_decrypt(&ctx, "key1", 4, ct, ct_len, &pt, &pt_len), 0);
    
    EXPECT_EQ(pt_len, 256);
    EXPECT_EQ(memcmp(pt, binary_data, 256), 0) << "Binary data integrity failed";
    
    free(ct);
    free(pt);
    phf_encrypt_destroy(&ctx);
}

// ============================================================================
// Rank/Select Tests
// ============================================================================

TEST_F(PHFTest, RankSelect_BasicOperations) {
    // Bitmap: 1 0 0 1 1 1 0 1 0 0 1 0 1 1 0 1 1 1 1 0 1
    uint64_t bitmap[1] = {0};
    uint32_t ones_positions[] = {0, 3, 4, 5, 7, 10, 12, 13, 15, 16, 17, 18, 20};
    
    for (uint32_t pos : ones_positions) {
        bitmap[0] |= (1ULL << pos);
    }
    
    phf_rank_select_t rs;
    ASSERT_EQ(phf_rank_select_build(bitmap, 21, &rs), 0);
    
    // Test rank
    EXPECT_EQ(phf_rank(&rs, 0), 1);   // rank(0) = 1
    EXPECT_EQ(phf_rank(&rs, 6), 4);   // rank(6) = 4
    EXPECT_EQ(phf_rank(&rs, 20), 13); // rank(20) = 13
    
    // Test select
    EXPECT_EQ(phf_select(&rs, 0), 0);   // select(0) = 0
    EXPECT_EQ(phf_select(&rs, 3), 5);   // select(3) = 5
    EXPECT_EQ(phf_select(&rs, 9), 16);  // select(9) = 16
    
    phf_rank_select_destroy(&rs);
}

TEST_F(PHFTest, RankSelect_Performance) {
    const uint32_t BITMAP_SIZE = 100000;
    const uint32_t NUM_QUERIES = 10000;
    
    // Create random bitmap
    uint32_t num_words = (BITMAP_SIZE + 63) / 64;
    vector<uint64_t> bitmap(num_words, 0);
    for (uint32_t i = 0; i < BITMAP_SIZE; i++) {
        if (rand() % 2) {
            bitmap[i / 64] |= (1ULL << (i % 64));
        }
    }
    
    phf_rank_select_t rs;
    auto build_start = high_resolution_clock::now();
    ASSERT_EQ(phf_rank_select_build(bitmap.data(), BITMAP_SIZE, &rs), 0);
    auto build_end = high_resolution_clock::now();
    
    cout << "Rank/Select build time: " 
         << duration_cast<microseconds>(build_end - build_start).count() << "μs" << endl;
    
    // Benchmark rank queries
    auto rank_start = high_resolution_clock::now();
    for (uint32_t i = 0; i < NUM_QUERIES; i++) {
        phf_rank(&rs, rand() % BITMAP_SIZE);
    }
    auto rank_end = high_resolution_clock::now();
    
    auto rank_time = duration_cast<nanoseconds>(rank_end - rank_start).count();
    cout << "Average rank query: " << rank_time / NUM_QUERIES << "ns" << endl;
    
    phf_rank_select_destroy(&rs);
}

// ============================================================================
// Elias-Fano Compression Tests
// ============================================================================

TEST_F(PHFTest, EliasFano_BasicCompression) {
    uint32_t array[] = {1, 5, 8, 12, 15, 20, 25, 30};
    uint32_t array_len = sizeof(array) / sizeof(array[0]);
    
    uint64_t* compressed = nullptr;
    uint32_t compressed_size = 0;
    
    ASSERT_EQ(phf_elias_fano_compress(array, array_len, &compressed, &compressed_size), 0);
    ASSERT_NE(compressed, nullptr);
    EXPECT_GT(compressed_size, 0);
    
    // Test decompression
    for (uint32_t i = 0; i < array_len; i++) {
        uint32_t value = phf_elias_fano_decompress(compressed, i, nullptr);
        EXPECT_EQ(value, array[i]) << "Decompression failed at index " << i;
    }
    
    free(compressed);
}

TEST_F(PHFTest, EliasFano_CompressionRatio) {
    const uint32_t N = 1000;
    vector<uint32_t> array;
    
    // Create array with extremes (sparse values)
    for (uint32_t i = 0; i < N; i++) {
        array.push_back(i * 100);  // Sparse distribution
    }
    
    uint64_t* compressed = nullptr;
    uint32_t compressed_size = 0;
    ASSERT_EQ(phf_elias_fano_compress(array.data(), array.size(), 
                                      &compressed, &compressed_size), 0);
    
    size_t original_bytes = array.size() * sizeof(uint32_t);
    size_t compressed_bytes = compressed_size * sizeof(uint64_t);
    float ratio = (float)compressed_bytes / original_bytes;
    
    cout << "Elias-Fano compression: " << original_bytes << " -> " 
         << compressed_bytes << " bytes (ratio: " << ratio << ")" << endl;
    
    EXPECT_LT(ratio, 1.0f) << "Compression should reduce size";
    
    free(compressed);
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

class PHFPerformanceTest : public PHFTest {
protected:
    struct BenchmarkResult {
        double build_time_ms;
        double query_time_ns;
        size_t memory_bytes;
        float bits_per_key;
        size_t table_size;
        bool has_collisions;
    };
    
    BenchmarkResult benchmark_chd(const vector<string>& keys) {
        BenchmarkResult result = {};
        auto pairs = create_kv_pairs(keys);
        
        phf_chd_t chd;
        auto start = high_resolution_clock::now();
        int build_result = phf_chd_build(pairs.data(), pairs.size(), 0.3f, &chd);
        auto end = high_resolution_clock::now();
        
        if (build_result != 0) return result;
        
        result.build_time_ms = duration_cast<microseconds>(end - start).count() / 1000.0;
        result.table_size = chd.table_size;
        
        // Benchmark queries
        start = high_resolution_clock::now();
        for (const auto& key : keys) {
            phf_chd_hash(&chd, key.c_str(), key.length());
        }
        end = high_resolution_clock::now();
        result.query_time_ns = duration_cast<nanoseconds>(end - start).count() / (double)keys.size();
        
        // Check collisions
        set<uint32_t> positions;
        for (const auto& key : keys) {
            positions.insert(phf_chd_hash(&chd, key.c_str(), key.length()));
        }
        result.has_collisions = (positions.size() != keys.size());
        
        // Memory usage
        phf_ctx_t ctx;
        ctx.type = PHF_TYPE_CHD;
        ctx.impl.chd = chd;
        size_t total, metadata;
        phf_get_memory_stats(&ctx, &total, &metadata);
        result.memory_bytes = total;
        result.bits_per_key = (total * 8.0f) / keys.size();
        
        phf_chd_destroy(&chd);
        return result;
    }
    
    BenchmarkResult benchmark_bdz(const vector<string>& keys, uint8_t r) {
        BenchmarkResult result = {};
        auto pairs = create_kv_pairs(keys);
        
        phf_bdz_t bdz;
        auto start = high_resolution_clock::now();
        int build_result = phf_bdz_build(pairs.data(), pairs.size(), r, false, &bdz);
        auto end = high_resolution_clock::now();
        
        if (build_result != 0) return result;
        
        result.build_time_ms = duration_cast<microseconds>(end - start).count() / 1000.0;
        result.table_size = bdz.num_vertices * r;
        
        // Benchmark queries
        start = high_resolution_clock::now();
        for (const auto& key : keys) {
            phf_bdz_hash(&bdz, key.c_str(), key.length());
        }
        end = high_resolution_clock::now();
        result.query_time_ns = duration_cast<nanoseconds>(end - start).count() / (double)keys.size();
        
        // Memory usage
        phf_ctx_t ctx;
        ctx.type = (r == 2) ? PHF_TYPE_BDZ_2PARTITE : PHF_TYPE_BDZ_3PARTITE;
        ctx.impl.bdz = bdz;
        size_t total, metadata;
        phf_get_memory_stats(&ctx, &total, &metadata);
        result.memory_bytes = total;
        result.bits_per_key = (total * 8.0f) / keys.size();
        
        phf_bdz_destroy(&bdz);
        return result;
    }
};

TEST_F(PHFPerformanceTest, ComprehensiveBenchmark) {
    vector<int> sizes = {100, 1000, 10000};
    
    cout << "\n=== PHF Performance Benchmark ===" << endl;
    cout << "Algorithm | Keys | Build(ms) | Query(ns) | Memory(KB) | Bits/Key | Collisions" << endl;
    cout << "----------|------|-----------|-----------|------------|----------|------------" << endl;
    
    for (int size : sizes) {
        vector<string> keys;
        for (int i = 0; i < size; i++) {
            keys.push_back("benchmark_key_" + to_string(i) + "_" + random_string(10));
        }
        
        // Benchmark CHD
        auto chd_result = benchmark_chd(keys);
        if (chd_result.memory_bytes > 0) {
            printf("CHD       | %5d | %9.2f | %9.1f | %10.2f | %8.2f | %s\n",
                   size, chd_result.build_time_ms, chd_result.query_time_ns,
                   chd_result.memory_bytes / 1024.0, chd_result.bits_per_key,
                   chd_result.has_collisions ? "YES" : "NO");
        }
        
        // Benchmark BDZ-2
        auto bdz2_result = benchmark_bdz(keys, 2);
        if (bdz2_result.memory_bytes > 0) {
            printf("BDZ-2     | %5d | %9.2f | %9.1f | %10.2f | %8.2f | N/A\n",
                   size, bdz2_result.build_time_ms, bdz2_result.query_time_ns,
                   bdz2_result.memory_bytes / 1024.0, bdz2_result.bits_per_key);
        }
        
        // Benchmark BDZ-3
        auto bdz3_result = benchmark_bdz(keys, 3);
        if (bdz3_result.memory_bytes > 0) {
            printf("BDZ-3     | %5d | %9.2f | %9.1f | %10.2f | %8.2f | N/A\n",
                   size, bdz3_result.build_time_ms, bdz3_result.query_time_ns,
                   bdz3_result.memory_bytes / 1024.0, bdz3_result.bits_per_key);
        }
        
        cout << "----------|------|-----------|-----------|------------|----------|------------" << endl;
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST_F(PHFTest, StressTest_RandomData) {
    const int NUM_ITERATIONS = 10;
    const int KEYS_PER_ITERATION = 1000;
    
    for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
        vector<string> keys;
        for (int i = 0; i < KEYS_PER_ITERATION; i++) {
            keys.push_back(random_string(rand() % 50 + 10));
        }
        
        auto pairs = create_kv_pairs(keys);
        phf_chd_t chd;
        ASSERT_EQ(phf_chd_build(pairs.data(), pairs.size(), 0.3f, &chd), 0)
            << "Failed at iteration " << iter;
        
        // Verify all keys
        set<uint32_t> positions;
        for (const auto& key : keys) {
            positions.insert(phf_chd_hash(&chd, key.c_str(), key.length()));
        }
        EXPECT_EQ(positions.size(), keys.size()) << "Collision in iteration " << iter;
        
        phf_chd_destroy(&chd);
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}