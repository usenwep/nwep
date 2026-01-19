/*
 * nwep
 *
 * Copyright (c) 2026 nwep contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <nwep/nwep.h>

#include <stdlib.h>
#include <string.h>

typedef struct cache_node {
  nwep_cached_identity identity;
  struct cache_node *prev;
  struct cache_node *next;
  struct cache_node *hash_next;
} cache_node;

#define HASH_BUCKETS 1021

struct nwep_identity_cache {
  cache_node **buckets;
  cache_node *head;
  cache_node *tail;
  size_t size;
  size_t capacity;
  nwep_tstamp ttl_ns;
  nwep_cache_stats stats;
};

static size_t hash_nodeid(const nwep_nodeid *nodeid) {
  size_t hash = 5381;
  for (size_t i = 0; i < NWEP_NODEID_LEN; i++) {
    hash = ((hash << 5) + hash) + nodeid->data[i];
  }
  return hash % HASH_BUCKETS;
}

static cache_node *find_node(nwep_identity_cache *cache,
                             const nwep_nodeid *nodeid, size_t bucket) {
  cache_node *node = cache->buckets[bucket];
  while (node != NULL) {
    if (nwep_nodeid_eq(&node->identity.nodeid, nodeid)) {
      return node;
    }
    node = node->hash_next;
  }
  return NULL;
}

static void lru_remove(nwep_identity_cache *cache, cache_node *node) {
  if (node->prev != NULL) {
    node->prev->next = node->next;
  } else {
    cache->head = node->next;
  }
  if (node->next != NULL) {
    node->next->prev = node->prev;
  } else {
    cache->tail = node->prev;
  }
  node->prev = NULL;
  node->next = NULL;
}

static void lru_insert_head(nwep_identity_cache *cache, cache_node *node) {
  node->prev = NULL;
  node->next = cache->head;
  if (cache->head != NULL) {
    cache->head->prev = node;
  }
  cache->head = node;
  if (cache->tail == NULL) {
    cache->tail = node;
  }
}

static void lru_touch(nwep_identity_cache *cache, cache_node *node) {
  if (node != cache->head) {
    lru_remove(cache, node);
    lru_insert_head(cache, node);
  }
}

static void hash_remove(nwep_identity_cache *cache, cache_node *node,
                        size_t bucket) {
  cache_node **pp = &cache->buckets[bucket];
  while (*pp != NULL) {
    if (*pp == node) {
      *pp = node->hash_next;
      node->hash_next = NULL;
      return;
    }
    pp = &(*pp)->hash_next;
  }
}

static void hash_insert(nwep_identity_cache *cache, cache_node *node,
                        size_t bucket) {
  node->hash_next = cache->buckets[bucket];
  cache->buckets[bucket] = node;
}

static void evict_lru(nwep_identity_cache *cache) {
  cache_node *node = cache->tail;
  if (node == NULL) {
    return;
  }

  lru_remove(cache, node);

  size_t bucket = hash_nodeid(&node->identity.nodeid);
  hash_remove(cache, node, bucket);

  cache->size--;
  cache->stats.evictions++;
  free(node);
}

void nwep_identity_cache_settings_default(nwep_identity_cache_settings *settings) {
  if (settings == NULL) {
    return;
  }
  settings->capacity = NWEP_CACHE_DEFAULT_CAPACITY;
  settings->ttl_ns = NWEP_CACHE_DEFAULT_TTL_NS;
}

int nwep_identity_cache_new(nwep_identity_cache **pcache,
                             const nwep_identity_cache_settings *settings) {
  nwep_identity_cache *cache;
  nwep_identity_cache_settings default_settings;

  if (pcache == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (settings == NULL) {
    nwep_identity_cache_settings_default(&default_settings);
    settings = &default_settings;
  }

  cache = calloc(1, sizeof(*cache));
  if (cache == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  cache->buckets = calloc(HASH_BUCKETS, sizeof(cache_node *));
  if (cache->buckets == NULL) {
    free(cache);
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  cache->capacity = settings->capacity;
  cache->ttl_ns = settings->ttl_ns;
  cache->size = 0;
  cache->head = NULL;
  cache->tail = NULL;
  memset(&cache->stats, 0, sizeof(cache->stats));

  *pcache = cache;
  return 0;
}

void nwep_identity_cache_free(nwep_identity_cache *cache) {
  if (cache == NULL) {
    return;
  }

  cache_node *node = cache->head;
  while (node != NULL) {
    cache_node *next = node->next;
    free(node);
    node = next;
  }

  free(cache->buckets);
  free(cache);
}

int nwep_identity_cache_lookup(nwep_identity_cache *cache,
                                const nwep_nodeid *nodeid, nwep_tstamp now,
                                nwep_cached_identity *identity) {
  size_t bucket;
  cache_node *node;

  if (cache == NULL || nodeid == NULL || identity == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  bucket = hash_nodeid(nodeid);
  node = find_node(cache, nodeid, bucket);

  if (node == NULL) {
    cache->stats.misses++;
    return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
  }

  if (now >= node->identity.expires_at) {
    lru_remove(cache, node);
    hash_remove(cache, node, bucket);
    cache->size--;
    free(node);

    cache->stats.misses++;
    return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
  }

  lru_touch(cache, node);

  memcpy(identity, &node->identity, sizeof(*identity));

  cache->stats.hits++;
  return 0;
}

int nwep_identity_cache_store(nwep_identity_cache *cache,
                               const nwep_nodeid *nodeid,
                               const uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN],
                               uint64_t log_index, nwep_tstamp now) {
  size_t bucket;
  cache_node *node;

  if (cache == NULL || nodeid == NULL || pubkey == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  bucket = hash_nodeid(nodeid);

  node = find_node(cache, nodeid, bucket);
  if (node != NULL) {
    memcpy(node->identity.pubkey, pubkey, NWEP_ED25519_PUBKEY_LEN);
    node->identity.log_index = log_index;
    node->identity.verified_at = now;
    node->identity.expires_at = now + cache->ttl_ns;
    lru_touch(cache, node);
    cache->stats.stores++;
    return 0;
  }

  while (cache->size >= cache->capacity) {
    evict_lru(cache);
  }

  node = calloc(1, sizeof(*node));
  if (node == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  memcpy(&node->identity.nodeid, nodeid, sizeof(nwep_nodeid));
  memcpy(node->identity.pubkey, pubkey, NWEP_ED25519_PUBKEY_LEN);
  node->identity.log_index = log_index;
  node->identity.verified_at = now;
  node->identity.expires_at = now + cache->ttl_ns;

  hash_insert(cache, node, bucket);

  lru_insert_head(cache, node);

  cache->size++;
  cache->stats.stores++;
  return 0;
}

int nwep_identity_cache_invalidate(nwep_identity_cache *cache,
                                    const nwep_nodeid *nodeid) {
  size_t bucket;
  cache_node *node;

  if (cache == NULL || nodeid == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  bucket = hash_nodeid(nodeid);
  node = find_node(cache, nodeid, bucket);

  if (node == NULL) {
    return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
  }

  lru_remove(cache, node);

  hash_remove(cache, node, bucket);

  cache->size--;
  cache->stats.invalidations++;
  free(node);

  return 0;
}

void nwep_identity_cache_clear(nwep_identity_cache *cache) {
  if (cache == NULL) {
    return;
  }

  cache_node *node = cache->head;
  while (node != NULL) {
    cache_node *next = node->next;
    free(node);
    node = next;
  }

  memset(cache->buckets, 0, HASH_BUCKETS * sizeof(cache_node *));
  cache->head = NULL;
  cache->tail = NULL;
  cache->size = 0;
}

size_t nwep_identity_cache_size(const nwep_identity_cache *cache) {
  if (cache == NULL) {
    return 0;
  }
  return cache->size;
}

size_t nwep_identity_cache_capacity(const nwep_identity_cache *cache) {
  if (cache == NULL) {
    return 0;
  }
  return cache->capacity;
}

int nwep_identity_cache_on_rotation(nwep_identity_cache *cache,
                                     const nwep_nodeid *nodeid,
                                     const uint8_t new_pubkey[NWEP_ED25519_PUBKEY_LEN],
                                     uint64_t new_log_index,
                                     nwep_tstamp now) {
  nwep_identity_cache_invalidate(cache, nodeid);
  return nwep_identity_cache_store(cache, nodeid, new_pubkey, new_log_index,
                                   now);
}

int nwep_identity_cache_on_revocation(nwep_identity_cache *cache,
                                       const nwep_nodeid *nodeid) {
  return nwep_identity_cache_invalidate(cache, nodeid);
}

void nwep_identity_cache_get_stats(const nwep_identity_cache *cache,
                                    nwep_cache_stats *stats) {
  if (cache == NULL || stats == NULL) {
    return;
  }
  memcpy(stats, &cache->stats, sizeof(*stats));
}

void nwep_identity_cache_reset_stats(nwep_identity_cache *cache) {
  if (cache == NULL) {
    return;
  }
  memset(&cache->stats, 0, sizeof(cache->stats));
}

struct nwep_log_server_pool {
  nwep_pool_server servers[NWEP_POOL_MAX_SERVERS];
  size_t count;
  size_t next_index;
  nwep_pool_strategy strategy;
  int max_failures;
  nwep_rand rand;
};

static nwep_pool_server *find_server(nwep_log_server_pool *pool,
                                     const char *url) {
  for (size_t i = 0; i < pool->count; i++) {
    if (strcmp(pool->servers[i].url, url) == 0) {
      return &pool->servers[i];
    }
  }
  return NULL;
}

static int default_rand(uint8_t *dest, size_t len, void *user_data) {
  (void)user_data;
  static uint32_t seed = 12345;
  for (size_t i = 0; i < len; i++) {
    seed = seed * 1103515245 + 12345;
    dest[i] = (uint8_t)(seed >> 16);
  }
  return 0;
}

void nwep_log_server_pool_settings_default(nwep_log_server_pool_settings *settings) {
  if (settings == NULL) {
    return;
  }
  settings->strategy = NWEP_POOL_ROUND_ROBIN;
  settings->max_failures = NWEP_POOL_HEALTH_CHECK_FAILURES;
  settings->rand = default_rand;
}

int nwep_log_server_pool_new(nwep_log_server_pool **ppool,
                              const nwep_log_server_pool_settings *settings) {
  nwep_log_server_pool *pool;
  nwep_log_server_pool_settings default_settings;

  if (ppool == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (settings == NULL) {
    nwep_log_server_pool_settings_default(&default_settings);
    settings = &default_settings;
  }

  pool = calloc(1, sizeof(*pool));
  if (pool == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  pool->count = 0;
  pool->next_index = 0;
  pool->strategy = settings->strategy;
  pool->max_failures = settings->max_failures;
  pool->rand = settings->rand ? settings->rand : default_rand;

  *ppool = pool;
  return 0;
}

void nwep_log_server_pool_free(nwep_log_server_pool *pool) {
  if (pool == NULL) {
    return;
  }
  free(pool);
}

int nwep_log_server_pool_add(nwep_log_server_pool *pool, const char *url) {
  size_t url_len;

  if (pool == NULL || url == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (pool->count >= NWEP_POOL_MAX_SERVERS) {
    return NWEP_ERR_CONFIG_VALIDATION_FAILED;
  }

  if (find_server(pool, url) != NULL) {
    return 0;
  }

  url_len = strlen(url);
  if (url_len >= sizeof(pool->servers[0].url)) {
    return NWEP_ERR_CONFIG_INVALID_VALUE;
  }

  nwep_pool_server *server = &pool->servers[pool->count];
  memcpy(server->url, url, url_len + 1);
  server->health = NWEP_SERVER_HEALTHY;
  server->consecutive_failures = 0;
  server->last_success = 0;
  server->last_failure = 0;

  pool->count++;
  return 0;
}

int nwep_log_server_pool_remove(nwep_log_server_pool *pool, const char *url) {
  if (pool == NULL || url == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (size_t i = 0; i < pool->count; i++) {
    if (strcmp(pool->servers[i].url, url) == 0) {
      for (size_t j = i; j < pool->count - 1; j++) {
        pool->servers[j] = pool->servers[j + 1];
      }
      pool->count--;

      if (pool->next_index > i && pool->next_index > 0) {
        pool->next_index--;
      }
      if (pool->next_index >= pool->count && pool->count > 0) {
        pool->next_index = 0;
      }

      return 0;
    }
  }

  return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
}

int nwep_log_server_pool_select(nwep_log_server_pool *pool,
                                 nwep_pool_server *server) {
  size_t start_index;
  size_t healthy_count = 0;

  if (pool == NULL || server == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (pool->count == 0) {
    return NWEP_ERR_NETWORK_NO_SERVERS;
  }

  for (size_t i = 0; i < pool->count; i++) {
    if (pool->servers[i].health == NWEP_SERVER_HEALTHY) {
      healthy_count++;
    }
  }

  if (healthy_count == 0) {
    return NWEP_ERR_NETWORK_NO_SERVERS;
  }

  if (pool->strategy == NWEP_POOL_RANDOM) {
    uint32_t rand_val;
    pool->rand((uint8_t *)&rand_val, sizeof(rand_val), NULL);
    size_t target = rand_val % healthy_count;
    size_t count = 0;

    for (size_t i = 0; i < pool->count; i++) {
      if (pool->servers[i].health == NWEP_SERVER_HEALTHY) {
        if (count == target) {
          memcpy(server, &pool->servers[i], sizeof(*server));
          return 0;
        }
        count++;
      }
    }
  } else {
    start_index = pool->next_index;

    for (size_t i = 0; i < pool->count; i++) {
      size_t idx = (start_index + i) % pool->count;
      if (pool->servers[idx].health == NWEP_SERVER_HEALTHY) {
        memcpy(server, &pool->servers[idx], sizeof(*server));
        pool->next_index = (idx + 1) % pool->count;
        return 0;
      }
    }
  }

  return NWEP_ERR_NETWORK_NO_SERVERS;
}

void nwep_log_server_pool_mark_success(nwep_log_server_pool *pool,
                                        const char *url, nwep_tstamp now) {
  nwep_pool_server *server;

  if (pool == NULL || url == NULL) {
    return;
  }

  server = find_server(pool, url);
  if (server == NULL) {
    return;
  }

  server->health = NWEP_SERVER_HEALTHY;
  server->consecutive_failures = 0;
  server->last_success = now;
}

void nwep_log_server_pool_mark_failure(nwep_log_server_pool *pool,
                                        const char *url, nwep_tstamp now) {
  nwep_pool_server *server;

  if (pool == NULL || url == NULL) {
    return;
  }

  server = find_server(pool, url);
  if (server == NULL) {
    return;
  }

  server->consecutive_failures++;
  server->last_failure = now;

  if (server->consecutive_failures >= pool->max_failures) {
    server->health = NWEP_SERVER_UNHEALTHY;
  }
}

size_t nwep_log_server_pool_size(const nwep_log_server_pool *pool) {
  if (pool == NULL) {
    return 0;
  }
  return pool->count;
}

size_t nwep_log_server_pool_healthy_count(const nwep_log_server_pool *pool) {
  size_t count = 0;

  if (pool == NULL) {
    return 0;
  }

  for (size_t i = 0; i < pool->count; i++) {
    if (pool->servers[i].health == NWEP_SERVER_HEALTHY) {
      count++;
    }
  }

  return count;
}

int nwep_log_server_pool_get(const nwep_log_server_pool *pool, size_t index,
                              nwep_pool_server *server) {
  if (pool == NULL || server == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (index >= pool->count) {
    return NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE;
  }

  memcpy(server, &pool->servers[index], sizeof(*server));
  return 0;
}

void nwep_log_server_pool_reset_health(nwep_log_server_pool *pool) {
  if (pool == NULL) {
    return;
  }

  for (size_t i = 0; i < pool->count; i++) {
    pool->servers[i].health = NWEP_SERVER_HEALTHY;
    pool->servers[i].consecutive_failures = 0;
  }
}
