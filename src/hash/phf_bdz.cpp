/**
 * @file phf_bdz.cpp
 * @brief BDZ (Bipartite/3-partite graph) implementation in C++
 */

#include "phf.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include <array>

#define BDZ_MAX_ATTEMPTS 100

struct edge_node_t {
    uint32_t edge_idx;
    std::unique_ptr<edge_node_t> next;
    
    edge_node_t(uint32_t idx) : edge_idx(idx), next(nullptr) {}
};

class Graph {
private:
    std::vector<std::unique_ptr<edge_node_t>> adj_lists;
    std::vector<uint32_t> degrees;
    std::vector<std::array<uint32_t, 3>> edges_data;
    uint32_t num_vertices_;
    uint32_t num_edges_;
    uint8_t r_;

public:
    Graph(uint32_t num_edges, uint32_t num_vertices, uint8_t r)
        : adj_lists(num_vertices), degrees(num_vertices, 0),
          edges_data(num_edges), num_vertices_(num_vertices),
          num_edges_(num_edges), r_(r) {}
    
    int add_edge(uint32_t edge_idx, const uint32_t vertices[3]) {
        if (edge_idx >= num_edges_) {
            std::cerr << "ERROR: Edge index " << edge_idx << " exceeds num_edges " << num_edges_ << std::endl;
            return -1;
        }
        
        // Store edge vertices
        for (uint8_t i = 0; i < r_; i++) {
            edges_data[edge_idx][i] = vertices[i];
        }
        
        // Add to adjacency lists and update degrees
        for (uint8_t i = 0; i < r_; i++) {
            uint32_t v = vertices[i];
            
            if (v >= num_vertices_) {
                std::cerr << "ERROR: Vertex " << v << " exceeds num_vertices " << num_vertices_ << std::endl;
                return -1;
            }
            
            auto node = std::make_unique<edge_node_t>(edge_idx);
            node->next = std::move(adj_lists[v]);
            adj_lists[v] = std::move(node);
            
            degrees[v]++;
        }
        
        return 0;
    }
    
    const std::array<uint32_t, 3>& get_edge(uint32_t idx) const {
        return edges_data[idx];
    }
    
    uint32_t get_degree(uint32_t v) const {
        return v < num_vertices_ ? degrees[v] : 0;
    }
    
    void decrement_degree(uint32_t v) {
        if (v < num_vertices_ && degrees[v] > 0) {
            degrees[v]--;
        }
    }
    
    const edge_node_t* get_adj_list(uint32_t v) const {
        return v < num_vertices_ ? adj_lists[v].get() : nullptr;
    }
    
    uint32_t num_vertices() const { return num_vertices_; }
    uint32_t num_edges() const { return num_edges_; }
    uint8_t r() const { return r_; }
};

bool phf_bdz_is_acyclic(const uint32_t (*edges)[3], uint32_t num_edges, 
                        uint32_t num_vertices, uint8_t r, uint32_t *ordering) {
    if (!edges || !ordering || num_edges == 0) return false;
    
    auto graph = std::make_unique<Graph>(num_edges, num_vertices, r);
    
    for (uint32_t i = 0; i < num_edges; i++) {
        if (graph->add_edge(i, edges[i]) != 0) {
            return false;
        }
    }
    
    // Queue for edges to process
    std::vector<uint32_t> queue;
    std::vector<uint8_t> removed(num_edges, 0);
    queue.reserve(num_edges);
    
    // Find all edges with at least one degree-1 vertex
    for (uint32_t i = 0; i < num_edges; i++) {
        for (uint8_t j = 0; j < r; j++) {
            uint32_t vertex = edges[i][j];
            if (vertex < num_vertices && graph->get_degree(vertex) == 1) {
                queue.push_back(i);
                break;
            }
        }
    }
    
    uint32_t removed_count = 0;
    size_t queue_head = 0;
    
    // Process queue
    while (queue_head < queue.size()) {
        uint32_t edge_idx = queue[queue_head++];
        
        if (removed[edge_idx]) continue;
        
        // Add to ordering (from tail, so reverse order)
        ordering[removed_count++] = edge_idx;
        removed[edge_idx] = 1;
        
        // Update degrees of vertices
        for (uint8_t i = 0; i < r; i++) {
            uint32_t v = edges[edge_idx][i];
            graph->decrement_degree(v);
        }
        
        // Check all edges connected to these vertices
        for (uint8_t i = 0; i < r; i++) {
            uint32_t v = edges[edge_idx][i];
            
            if (v >= num_vertices) continue;
            
            const edge_node_t *node = graph->get_adj_list(v);
            while (node) {
                uint32_t e = node->edge_idx;
                if (!removed[e]) {
                    // Check if this edge now has a degree-1 vertex
                    for (uint8_t j = 0; j < r; j++) {
                        uint32_t edge_v = edges[e][j];
                        if (edge_v < num_vertices && graph->get_degree(edge_v) == 1) {
                            queue.push_back(e);
                            break;
                        }
                    }
                }
                node = node->next.get();
            }
        }
    }
    
    // Graph is acyclic if all edges were removed
    return removed_count == num_edges;
}

int phf_bdz_assign_values(const uint32_t (*edges)[3], uint32_t num_edges,
                          uint8_t *g_array, uint32_t g_size, uint8_t r) {
    if (!edges || !g_array || num_edges == 0) return -1;
    
    // Initialize g_array to r (unassigned)
    std::memset(g_array, r, g_size);
    
    std::vector<uint8_t> visited(g_size, 0);
    
    // Process edges in reverse order
    for (int i = static_cast<int>(num_edges) - 1; i >= 0; i--) {
        // Find first unvisited vertex
        int unvisited_idx = -1;
        uint32_t unvisited_vertex = 0;
        
        for (uint8_t j = 0; j < r; j++) {
            uint32_t vertex = edges[i][j];
            
            if (vertex >= g_size) {
                std::cerr << "ERROR: Vertex " << vertex << " exceeds g_size " << g_size 
                         << " at edge " << i << " partition " << static_cast<int>(j) << std::endl;
                return -1;
            }
            
            if (!visited[vertex]) {
                unvisited_idx = j;
                unvisited_vertex = vertex;
                break;
            }
        }
        
        if (unvisited_idx == -1) {
            std::cerr << "ERROR: All vertices visited at edge " << i << std::endl;
            return -1;
        }
        
        // Calculate sum of already-assigned vertices
        uint8_t sum = 0;
        for (uint8_t j = 0; j < r; j++) {
            uint32_t vertex = edges[i][j];
            
            if (vertex >= g_size) {
                std::cerr << "ERROR: Vertex " << vertex << " exceeds g_size " << g_size << std::endl;
                return -1;
            }
            
            if (j != unvisited_idx && g_array[vertex] < r) {
                sum += g_array[vertex];
            }
        }
        
        // Assign value to make sum equal to edge index mod r
        uint32_t target = static_cast<uint32_t>(i) % r;
        uint8_t g_value;
        
        if (target >= sum % r) {
            g_value = (target - (sum % r)) % r;
        } else {
            g_value = (r - ((sum % r) - target)) % r;
        }
        
        if (unvisited_vertex >= g_size) {
            std::cerr << "ERROR: Cannot assign to vertex " << unvisited_vertex 
                     << " (g_size=" << g_size << ")" << std::endl;
            return -1;
        }
        
        g_array[unvisited_vertex] = g_value;
        visited[unvisited_vertex] = 1;
    }
    
    return 0;
}

int phf_bdz_build(const phf_kv_pair_t *keys, uint32_t num_keys, uint8_t r, bool minimal, phf_bdz_t *bdz) {
    if (!keys || !bdz || num_keys == 0 || (r != 2 && r != 3)) return -1;
    
    // Clear existing data
    bdz->g_array.clear();
    bdz->g_size = 0;
    bdz->num_vertices = 0;
    
    bdz->r = r;
    bdz->is_minimal = minimal;
    
    // Calculate number of vertices per partition
    if (r == 2) {
        // Bipartite: need ~2n vertices total
        bdz->num_vertices = minimal ? num_keys : static_cast<uint32_t>(num_keys * 1.1);
    } else {
        // 3-partite needs larger multiplier to ensure success
        bdz->num_vertices = minimal ? static_cast<uint32_t>(num_keys * 0.41) : static_cast<uint32_t>(num_keys * 0.5);
    }
    
    if (bdz->num_vertices == 0) bdz->num_vertices = 1;
    
    // Calculate g_size = total vertices across all partitions
    bdz->g_size = bdz->num_vertices * r;
    
    if (bdz->g_size == 0) {
        std::cerr << "ERROR: Invalid g_size " << bdz->g_size << " for " << num_keys << " keys" << std::endl;
        return -1;
    }
    
    // Try to build acyclic graph
    int attempt = 0;
    bool success = false;
    
    std::vector<std::array<uint32_t, 3>> temp_edges(num_keys);
    std::vector<uint32_t> ordering(num_keys);
    
    while (!success && attempt < BDZ_MAX_ATTEMPTS) {
        attempt++;
        
        // Generate new hash seeds
        if (phf_hash_generate_seeds(&bdz->hash, r) != 0) {
            return -1;
        }
        
        // Build edges with validation
        bool edge_build_failed = false;
        for (uint32_t i = 0; i < num_keys; i++) {
            uint32_t h0 = phf_hash_universal(keys[i].key, keys[i].key_len,
                                              bdz->hash.seed0, bdz->num_vertices);
            uint32_t h1 = phf_hash_universal(keys[i].key, keys[i].key_len,
                                              bdz->hash.seed1, bdz->num_vertices);
            
            temp_edges[i][0] = h0;
            temp_edges[i][1] = bdz->num_vertices + h1;
            
            if (temp_edges[i][0] >= bdz->g_size || temp_edges[i][1] >= bdz->g_size) {
                std::cerr << "ERROR: Edge vertex exceeds g_size (attempt " << attempt 
                         << ", edge " << i << ": v0=" << temp_edges[i][0] 
                         << " v1=" << temp_edges[i][1] << " g_size=" << bdz->g_size << ")" << std::endl;
                edge_build_failed = true;
                break;
            }
            
            if (r == 3) {
                uint32_t h2 = phf_hash_universal(keys[i].key, keys[i].key_len,
                                                  bdz->hash.seed2, bdz->num_vertices);
                temp_edges[i][2] = 2 * bdz->num_vertices + h2;
                
                if (temp_edges[i][2] >= bdz->g_size) {
                    std::cerr << "ERROR: Edge vertex 2 exceeds g_size (attempt " << attempt 
                             << ", edge " << i << ": v2=" << temp_edges[i][2] 
                             << " g_size=" << bdz->g_size << ")" << std::endl;
                    edge_build_failed = true;
                    break;
                }
            } else {
                temp_edges[i][2] = 0;  // Not used for bipartite
            }
        }
        
        if (edge_build_failed) {
            continue;  // Try next attempt
        }
        
        // Check if acyclic - pass g_size as num_vertices parameter
        if (phf_bdz_is_acyclic(reinterpret_cast<const uint32_t (*)[3]>(temp_edges.data()), 
                               num_keys, bdz->g_size, r, ordering.data())) {
            success = true;
        }
    }
    
    if (!success) {
        std::cerr << "ERROR: Failed to build acyclic graph after " << BDZ_MAX_ATTEMPTS << " attempts" << std::endl;
        return -1;
    }
    
    // Allocate g_array
    bdz->g_array.resize(bdz->g_size);
    
    // Reorder edges according to removal order
    std::vector<std::array<uint32_t, 3>> ordered_edges(num_keys);
    
    for (uint32_t i = 0; i < num_keys; i++) {
        uint32_t edge_idx = ordering[i];
        
        if (edge_idx >= num_keys) {
            std::cerr << "ERROR: Invalid ordering index " << edge_idx << " >= " << num_keys << std::endl;
            bdz->g_array.clear();
            return -1;
        }
        
        ordered_edges[i] = temp_edges[edge_idx];
    }
    
    // Assign values
    if (phf_bdz_assign_values(reinterpret_cast<const uint32_t (*)[3]>(ordered_edges.data()), 
                              num_keys, bdz->g_array.data(), bdz->g_size, r) != 0) {
        bdz->g_array.clear();
        return -1;
    }
    
    return 0;
}

uint32_t phf_bdz_hash(const phf_bdz_t *bdz, const void *key, size_t key_len) {
    if (!bdz || !key || bdz->g_array.empty()) return 0;
    
    uint32_t h0 = phf_hash_universal(key, key_len, bdz->hash.seed0, bdz->num_vertices);
    uint32_t h1 = phf_hash_universal(key, key_len, bdz->hash.seed1, bdz->num_vertices);
    
    uint32_t v0 = h0;
    uint32_t v1 = bdz->num_vertices + h1;
    
    if (v0 >= bdz->g_array.size() || v1 >= bdz->g_array.size()) {
        return 0;
    }
    
    uint8_t g0 = bdz->g_array[v0];
    uint8_t g1 = bdz->g_array[v1];
    
    if (bdz->r == 3) {
        uint32_t h2 = phf_hash_universal(key, key_len, bdz->hash.seed2, bdz->num_vertices);
        uint32_t v2 = 2 * bdz->num_vertices + h2;
        
        if (v2 >= bdz->g_array.size()) {
            return 0;
        }
        
        uint8_t g2 = bdz->g_array[v2];
        return (g0 + g1 + g2) % bdz->r;
    } else {
        return (g0 + g1) % bdz->r;
    }
}

void phf_bdz_destroy(phf_bdz_t *bdz) {
    if (!bdz) return;
    
    bdz->g_array.clear();
    bdz->g_size = 0;
    bdz->num_vertices = 0;
    bdz->r = 0;
    bdz->is_minimal = false;
}