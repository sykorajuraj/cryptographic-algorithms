/**
 * @file phf_bdz.c
 * @brief BDZ (Bipartite/3-partite graph) implementation
 */

#include "phf.h"
#include <stdlib.h>
#include <string.h>

#define BDZ_MAX_ATTEMPTS 100

typedef struct edge_node {
    uint32_t edge_idx;
    struct edge_node *next;
} edge_node_t;

typedef struct {
    edge_node_t **adj_lists;  /* Adjacency lists for each vertex */
    uint32_t *degrees;         /* Vertex degrees */
    uint32_t num_vertices;
    uint32_t num_edges;
    uint32_t (*edges)[3];      /* Edge array [edge_idx][vertex_0/1/2] */
    uint8_t r;                 /* Number of partitions */
} graph_t;

static graph_t *graph_create(uint32_t num_edges, uint32_t num_vertices, uint8_t r) {
    graph_t *graph = calloc(1, sizeof(graph_t));
    if (!graph) return NULL;
    
    graph->num_vertices = num_vertices;
    graph->num_edges = num_edges;
    graph->r = r;
    
    graph->adj_lists = calloc(num_vertices, sizeof(edge_node_t *));
    graph->degrees = calloc(num_vertices, sizeof(uint32_t));
    graph->edges = calloc(num_edges, sizeof(uint32_t[3]));
    
    if (!graph->adj_lists || !graph->degrees || !graph->edges) {
        if (graph->adj_lists) free(graph->adj_lists);
        if (graph->degrees) free(graph->degrees);
        if (graph->edges) free(graph->edges);
        free(graph);
        return NULL;
    }
    
    return graph;
}

static void graph_destroy(graph_t *graph) {
    if (!graph) return;
    
    if (graph->adj_lists) {
        for (uint32_t i = 0; i < graph->num_vertices; i++) {
            edge_node_t *node = graph->adj_lists[i];
            while (node) {
                edge_node_t *next = node->next;
                free(node);
                node = next;
            }
        }
        free(graph->adj_lists);
    }
    
    if (graph->degrees) free(graph->degrees);
    if (graph->edges) free(graph->edges);
    free(graph);
}

static int graph_add_edge(graph_t *graph, uint32_t edge_idx, const uint32_t vertices[3]) {
    /* Store edge vertices */
    for (uint8_t i = 0; i < graph->r; i++) {
        graph->edges[edge_idx][i] = vertices[i];
    }
    
    /* Add to adjacency lists and update degrees */
    for (uint8_t i = 0; i < graph->r; i++) {
        uint32_t v = vertices[i];
        
        edge_node_t *node = malloc(sizeof(edge_node_t));
        if (!node) return -1;
        
        node->edge_idx = edge_idx;
        node->next = graph->adj_lists[v];
        graph->adj_lists[v] = node;
        
        graph->degrees[v]++;
    }
    
    return 0;
}

bool phf_bdz_is_acyclic(const uint32_t (*edges)[3], uint32_t num_edges, 
                        uint32_t num_vertices, uint8_t r, uint32_t *ordering) {
    if (!edges || !ordering || num_edges == 0) return false;
    
    /* Create working graph */
    graph_t *graph = graph_create(num_edges, num_vertices, r);
    if (!graph) return false;
    
    for (uint32_t i = 0; i < num_edges; i++) {
        if (graph_add_edge(graph, i, edges[i]) != 0) {
            graph_destroy(graph);
            return false;
        }
    }
    
    /* Queue for edges to process */
    uint32_t *queue = malloc(num_edges * sizeof(uint32_t));
    uint8_t *removed = calloc(num_edges, sizeof(uint8_t));
    
    if (!queue || !removed) {
        free(queue);
        free(removed);
        graph_destroy(graph);
        return false;
    }
    
    uint32_t queue_head = 0;
    uint32_t queue_tail = 0;
    
    /* Find all edges with at least one degree-1 vertex */
    for (uint32_t i = 0; i < num_edges; i++) {
        for (uint8_t j = 0; j < r; j++) {
            if (graph->degrees[edges[i][j]] == 1) {
                queue[queue_tail++] = i;
                break;
            }
        }
    }
    
    uint32_t removed_count = 0;
    
    /* Process queue */
    while (queue_head < queue_tail) {
        uint32_t edge_idx = queue[queue_head++];
        
        if (removed[edge_idx]) continue;
        
        /* Add to ordering (from tail, so reverse order) */
        ordering[removed_count++] = edge_idx;
        removed[edge_idx] = 1;
        
        /* Update degrees of vertices */
        for (uint8_t i = 0; i < r; i++) {
            uint32_t v = edges[edge_idx][i];
            if (graph->degrees[v] > 0) {
                graph->degrees[v]--;
            }
        }
        
        /* Check all edges connected to these vertices */
        for (uint8_t i = 0; i < r; i++) {
            uint32_t v = edges[edge_idx][i];
            
            edge_node_t *node = graph->adj_lists[v];
            while (node) {
                uint32_t e = node->edge_idx;
                if (!removed[e]) {
                    /* Check if this edge now has a degree-1 vertex */
                    for (uint8_t j = 0; j < r; j++) {
                        if (graph->degrees[edges[e][j]] == 1) {
                            queue[queue_tail++] = e;
                            break;
                        }
                    }
                }
                node = node->next;
            }
        }
    }
    
    free(queue);
    free(removed);
    graph_destroy(graph);
    
    /* Graph is acyclic if all edges were removed */
    return removed_count == num_edges;
}

int phf_bdz_assign_values(const uint32_t (*edges)[3], uint32_t num_edges,
                          uint8_t *g_array, uint32_t g_size, uint8_t r) {
    if (!edges || !g_array || num_edges == 0) return -1;
    
    /* Initialize g_array to r (unassigned) */
    memset(g_array, r, g_size);
    
    uint8_t *visited = calloc(g_size, sizeof(uint8_t));
    if (!visited) return -1;
    
    /* Process edges in reverse order */
    for (int i = (int)num_edges - 1; i >= 0; i--) {
        /* Find first unvisited vertex */
        int unvisited_idx = -1;
        uint32_t unvisited_vertex = 0;
        
        for (uint8_t j = 0; j < r; j++) {
            if (!visited[edges[i][j]]) {
                unvisited_idx = j;
                unvisited_vertex = edges[i][j];
                break;
            }
        }
        
        if (unvisited_idx == -1) {
            /* All vertices visited - shouldn't happen */
            free(visited);
            return -1;
        }
        
        /* Calculate sum of already-assigned vertices */
        uint32_t sum = 0;
        for (uint8_t j = 0; j < r; j++) {
            if (j != unvisited_idx && g_array[edges[i][j]] < r) {
                sum += g_array[edges[i][j]];
            }
        }
        
        /* Assign value to make sum equal to edge index mod r */
        uint32_t target = (uint32_t)i % r;
        uint8_t g_value;
        
        if (target >= sum % r) {
            g_value = (target - (sum % r)) % r;
        } else {
            g_value = (r - ((sum % r) - target)) % r;
        }
        
        g_array[unvisited_vertex] = g_value;
        visited[unvisited_vertex] = 1;
    }
    
    free(visited);
    return 0;
}

int phf_bdz_build(const phf_kv_pair_t *keys, uint32_t num_keys, uint8_t r, bool minimal, phf_bdz_t *bdz) {
    if (!keys || !bdz || num_keys == 0 || (r != 2 && r != 3)) return -1;
    
    memset(bdz, 0, sizeof(phf_bdz_t));
    
    bdz->r = r;
    bdz->is_minimal = minimal;
    
    /* Calculate number of vertices per partition */
    if (r == 2) {
        /* Bipartite: need ~2n vertices total */
        bdz->num_vertices = minimal ? num_keys : (uint32_t)(num_keys * 1.1);
    } else {
        /* 3-partite: need ~1.23n vertices total */
        bdz->num_vertices = minimal ? (uint32_t)(num_keys * 0.41) : (uint32_t)(num_keys * 0.45);
    }
    
    if (bdz->num_vertices == 0) bdz->num_vertices = 1;
    
    bdz->g_size = bdz->num_vertices * r;
    
    /* Try to build acyclic graph */
    int attempt = 0;
    int success = 0;
    
    uint32_t (*temp_edges)[3] = malloc(num_keys * sizeof(uint32_t[3]));
    uint32_t *ordering = malloc(num_keys * sizeof(uint32_t));
    
    if (!temp_edges || !ordering) {
        free(temp_edges);
        free(ordering);
        return -1;
    }
    
    while (!success && attempt < BDZ_MAX_ATTEMPTS) {
        attempt++;
        
        /* Generate new hash seeds */
        if (phf_hash_generate_seeds(&bdz->hash, r) != 0) {
            free(temp_edges);
            free(ordering);
            return -1;
        }
        
        /* Build edges */
        for (uint32_t i = 0; i < num_keys; i++) {
            temp_edges[i][0] = phf_hash_universal(keys[i].key, keys[i].key_len,
                                                   bdz->hash.seed0, bdz->num_vertices);
            temp_edges[i][1] = bdz->num_vertices + 
                              phf_hash_universal(keys[i].key, keys[i].key_len,
                                                  bdz->hash.seed1, bdz->num_vertices);
            
            if (r == 3) {
                temp_edges[i][2] = 2 * bdz->num_vertices + 
                                  phf_hash_universal(keys[i].key, keys[i].key_len,
                                                      bdz->hash.seed2, bdz->num_vertices);
            } else {
                temp_edges[i][2] = 0;  /* Not used for bipartite */
            }
        }
        
        /* Check if acyclic */
        if (phf_bdz_is_acyclic((const uint32_t (*)[3])temp_edges, num_keys, 
                               bdz->g_size, r, ordering)) {
            success = 1;
        }
    }
    
    if (!success) {
        free(temp_edges);
        free(ordering);
        return -1;
    }
    
    /* Allocate g_array */
    bdz->g_array = malloc(bdz->g_size * sizeof(uint8_t));
    if (!bdz->g_array) {
        free(temp_edges);
        free(ordering);
        return -1;
    }
    
    /* Reorder edges according to removal order */
    uint32_t (*ordered_edges)[3] = malloc(num_keys * sizeof(uint32_t[3]));
    if (!ordered_edges) {
        free(bdz->g_array);
        bdz->g_array = NULL;
        free(temp_edges);
        free(ordering);
        return -1;
    }
    
    for (uint32_t i = 0; i < num_keys; i++) {
        uint32_t edge_idx = ordering[i];
        for (uint8_t j = 0; j < 3; j++) {
            ordered_edges[i][j] = temp_edges[edge_idx][j];
        }
    }
    
    /* Assign values */
    if (phf_bdz_assign_values((const uint32_t (*)[3])ordered_edges, num_keys,
                              bdz->g_array, bdz->g_size, r) != 0) {
        free(bdz->g_array);
        bdz->g_array = NULL;
        free(ordered_edges);
        free(temp_edges);
        free(ordering);
        return -1;
    }
    
    free(ordered_edges);
    free(temp_edges);
    free(ordering);
    
    return 0;
}

uint32_t phf_bdz_hash(const phf_bdz_t *bdz, const void *key, size_t key_len) {
    if (!bdz || !key || !bdz->g_array) return 0;
    
    uint32_t h0 = phf_hash_universal(key, key_len, bdz->hash.seed0, bdz->num_vertices);
    uint32_t h1 = phf_hash_universal(key, key_len, bdz->hash.seed1, bdz->num_vertices);
    
    uint32_t v0 = h0;
    uint32_t v1 = bdz->num_vertices + h1;
    
    uint8_t g0 = bdz->g_array[v0];
    uint8_t g1 = bdz->g_array[v1];
    
    if (bdz->r == 3) {
        uint32_t h2 = phf_hash_universal(key, key_len, bdz->hash.seed2, bdz->num_vertices);
        uint32_t v2 = 2 * bdz->num_vertices + h2;
        uint8_t g2 = bdz->g_array[v2];
        
        return (g0 + g1 + g2) % bdz->r;
    } else {
        return (g0 + g1) % bdz->r;
    }
}

void phf_bdz_destroy(phf_bdz_t *bdz) {
    if (!bdz) return;
    
    if (bdz->g_array) {
        free(bdz->g_array);
        bdz->g_array = NULL;
    }
    
    memset(bdz, 0, sizeof(phf_bdz_t));
}