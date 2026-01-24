/*
 * nwep - Cache Tests (Phase 17)
 */
#include <nwep/nwep.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %s... ", #name);                                                 \
    fflush(stdout);                                                            \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    return 1;                                                                  \
  } while (0)

#define ASSERT(cond, msg)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      FAIL(msg);                                                               \
    }                                                                          \
  } while (0)

/*
 * Helper: create a test NodeID
 */
static void make_test_nodeid(nwep_nodeid *nodeid, uint8_t seed) {
  memset(nodeid->data, seed, NWEP_NODEID_LEN);
}

/*
 * Helper: create a test pubkey
 */
static void make_test_pubkey(uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN],
                             uint8_t seed) {
  memset(pubkey, seed, NWEP_ED25519_PUBKEY_LEN);
}

/*
 * Identity Cache Tests
 */

static int test_cache_settings_default(void) {
  TEST(cache_settings_default);

  nwep_identity_cache_settings settings;
  nwep_identity_cache_settings_default(&settings);

  ASSERT(settings.capacity == NWEP_CACHE_DEFAULT_CAPACITY,
         "default capacity mismatch");
  ASSERT(settings.ttl_ns == NWEP_CACHE_DEFAULT_TTL_NS, "default TTL mismatch");

  PASS();
  return 0;
}

static int test_cache_create_free(void) {
  TEST(cache_create_free);

  nwep_identity_cache *cache;
  int rv = nwep_identity_cache_new(&cache, NULL);
  ASSERT(rv == 0, "cache creation failed");
  ASSERT(cache != NULL, "cache should not be NULL");

  ASSERT(nwep_identity_cache_size(cache) == 0, "initial size should be 0");
  ASSERT(nwep_identity_cache_capacity(cache) == NWEP_CACHE_DEFAULT_CAPACITY,
         "capacity mismatch");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_store_lookup(void) {
  TEST(cache_store_lookup);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&nodeid, 0x42);
  make_test_pubkey(pubkey, 0x43);

  nwep_tstamp now = 1000 * NWEP_SECONDS;

  int rv = nwep_identity_cache_store(cache, &nodeid, pubkey, 100, now);
  ASSERT(rv == 0, "store failed");
  ASSERT(nwep_identity_cache_size(cache) == 1, "size should be 1");

  nwep_cached_identity identity;
  rv = nwep_identity_cache_lookup(cache, &nodeid, now, &identity);
  ASSERT(rv == 0, "lookup failed");
  ASSERT(nwep_nodeid_eq(&identity.nodeid, &nodeid), "nodeid mismatch");
  ASSERT(memcmp(identity.pubkey, pubkey, NWEP_ED25519_PUBKEY_LEN) == 0,
         "pubkey mismatch");
  ASSERT(identity.log_index == 100, "log_index mismatch");
  ASSERT(identity.verified_at == now, "verified_at mismatch");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_lookup_not_found(void) {
  TEST(cache_lookup_not_found);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_nodeid nodeid;
  make_test_nodeid(&nodeid, 0x42);

  nwep_cached_identity identity;
  int rv = nwep_identity_cache_lookup(cache, &nodeid, 1000 * NWEP_SECONDS,
                                      &identity);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "should return not found");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_expiry(void) {
  TEST(cache_expiry);

  nwep_identity_cache_settings settings;
  settings.capacity = 100;
  settings.ttl_ns = 1000 * NWEP_SECONDS; /* 1000 second TTL */

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, &settings);

  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&nodeid, 0x42);
  make_test_pubkey(pubkey, 0x43);

  nwep_tstamp now = 1000 * NWEP_SECONDS;
  nwep_identity_cache_store(cache, &nodeid, pubkey, 100, now);

  /* Lookup before expiry - should succeed */
  nwep_cached_identity identity;
  int rv = nwep_identity_cache_lookup(cache, &nodeid, now + 500 * NWEP_SECONDS,
                                      &identity);
  ASSERT(rv == 0, "lookup before expiry should succeed");

  /* Lookup after expiry - should fail */
  rv = nwep_identity_cache_lookup(cache, &nodeid, now + 2000 * NWEP_SECONDS,
                                  &identity);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "should be expired");

  /* Entry should be removed */
  ASSERT(nwep_identity_cache_size(cache) == 0, "expired entry should be removed");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_invalidate(void) {
  TEST(cache_invalidate);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&nodeid, 0x42);
  make_test_pubkey(pubkey, 0x43);

  nwep_tstamp now = 1000 * NWEP_SECONDS;
  nwep_identity_cache_store(cache, &nodeid, pubkey, 100, now);
  ASSERT(nwep_identity_cache_size(cache) == 1, "size should be 1");

  int rv = nwep_identity_cache_invalidate(cache, &nodeid);
  ASSERT(rv == 0, "invalidate failed");
  ASSERT(nwep_identity_cache_size(cache) == 0, "size should be 0");

  /* Lookup should fail */
  nwep_cached_identity identity;
  rv = nwep_identity_cache_lookup(cache, &nodeid, now, &identity);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "should not find invalidated");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_clear(void) {
  TEST(cache_clear);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_tstamp now = 1000 * NWEP_SECONDS;

  /* Store several entries */
  for (int i = 0; i < 10; i++) {
    nwep_nodeid nodeid;
    uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
    make_test_nodeid(&nodeid, (uint8_t)i);
    make_test_pubkey(pubkey, (uint8_t)(i + 100));
    nwep_identity_cache_store(cache, &nodeid, pubkey, (uint64_t)i, now);
  }

  ASSERT(nwep_identity_cache_size(cache) == 10, "should have 10 entries");

  nwep_identity_cache_clear(cache);

  ASSERT(nwep_identity_cache_size(cache) == 0, "should be empty after clear");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_lru_eviction(void) {
  TEST(cache_lru_eviction);

  nwep_identity_cache_settings settings;
  settings.capacity = 5; /* Small capacity for testing */
  settings.ttl_ns = NWEP_CACHE_DEFAULT_TTL_NS;

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, &settings);

  nwep_tstamp now = 1000 * NWEP_SECONDS;

  /* Store 5 entries (fill capacity) */
  for (int i = 0; i < 5; i++) {
    nwep_nodeid nodeid;
    uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
    make_test_nodeid(&nodeid, (uint8_t)i);
    make_test_pubkey(pubkey, (uint8_t)(i + 100));
    nwep_identity_cache_store(cache, &nodeid, pubkey, (uint64_t)i, now);
  }

  ASSERT(nwep_identity_cache_size(cache) == 5, "should have 5 entries");

  /* Store one more - should evict LRU (entry 0) */
  nwep_nodeid new_nodeid;
  uint8_t new_pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&new_nodeid, 0xFF);
  make_test_pubkey(new_pubkey, 0xFE);
  nwep_identity_cache_store(cache, &new_nodeid, new_pubkey, 999, now);

  ASSERT(nwep_identity_cache_size(cache) == 5, "should still have 5 entries");

  /* Entry 0 should be evicted */
  nwep_nodeid evicted;
  make_test_nodeid(&evicted, 0);
  nwep_cached_identity identity;
  int rv = nwep_identity_cache_lookup(cache, &evicted, now, &identity);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "entry 0 should be evicted");

  /* New entry should exist */
  rv = nwep_identity_cache_lookup(cache, &new_nodeid, now, &identity);
  ASSERT(rv == 0, "new entry should exist");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_lru_touch(void) {
  TEST(cache_lru_touch);

  nwep_identity_cache_settings settings;
  settings.capacity = 3;
  settings.ttl_ns = NWEP_CACHE_DEFAULT_TTL_NS;

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, &settings);

  nwep_tstamp now = 1000 * NWEP_SECONDS;

  /* Store 3 entries: 0, 1, 2 (0 is LRU) */
  for (int i = 0; i < 3; i++) {
    nwep_nodeid nodeid;
    uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
    make_test_nodeid(&nodeid, (uint8_t)i);
    make_test_pubkey(pubkey, (uint8_t)(i + 100));
    nwep_identity_cache_store(cache, &nodeid, pubkey, (uint64_t)i, now);
  }

  /* Touch entry 0 by looking it up - makes it MRU */
  nwep_nodeid nodeid0;
  make_test_nodeid(&nodeid0, 0);
  nwep_cached_identity identity;
  nwep_identity_cache_lookup(cache, &nodeid0, now, &identity);

  /* Now add entry 3 - should evict entry 1 (now LRU) */
  nwep_nodeid new_nodeid;
  uint8_t new_pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&new_nodeid, 0xFF);
  make_test_pubkey(new_pubkey, 0xFE);
  nwep_identity_cache_store(cache, &new_nodeid, new_pubkey, 999, now);

  /* Entry 0 should still exist (was touched) */
  int rv = nwep_identity_cache_lookup(cache, &nodeid0, now, &identity);
  ASSERT(rv == 0, "entry 0 should still exist after touch");

  /* Entry 1 should be evicted */
  nwep_nodeid nodeid1;
  make_test_nodeid(&nodeid1, 1);
  rv = nwep_identity_cache_lookup(cache, &nodeid1, now, &identity);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "entry 1 should be evicted");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_on_rotation(void) {
  TEST(cache_on_rotation);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_nodeid nodeid;
  uint8_t old_pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint8_t new_pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&nodeid, 0x42);
  make_test_pubkey(old_pubkey, 0x43);
  make_test_pubkey(new_pubkey, 0x44);

  nwep_tstamp now = 1000 * NWEP_SECONDS;
  nwep_identity_cache_store(cache, &nodeid, old_pubkey, 100, now);

  /* Rotation - should invalidate old and store new */
  int rv = nwep_identity_cache_on_rotation(cache, &nodeid, new_pubkey, 101,
                                           now + 100 * NWEP_SECONDS);
  ASSERT(rv == 0, "on_rotation failed");

  nwep_cached_identity identity;
  rv = nwep_identity_cache_lookup(cache, &nodeid, now + 100 * NWEP_SECONDS,
                                  &identity);
  ASSERT(rv == 0, "lookup failed after rotation");
  ASSERT(memcmp(identity.pubkey, new_pubkey, NWEP_ED25519_PUBKEY_LEN) == 0,
         "should have new pubkey");
  ASSERT(identity.log_index == 101, "should have new log_index");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_on_revocation(void) {
  TEST(cache_on_revocation);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&nodeid, 0x42);
  make_test_pubkey(pubkey, 0x43);

  nwep_tstamp now = 1000 * NWEP_SECONDS;
  nwep_identity_cache_store(cache, &nodeid, pubkey, 100, now);

  int rv = nwep_identity_cache_on_revocation(cache, &nodeid);
  ASSERT(rv == 0, "on_revocation failed");

  nwep_cached_identity identity;
  rv = nwep_identity_cache_lookup(cache, &nodeid, now, &identity);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "revoked should not be found");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

static int test_cache_stats(void) {
  TEST(cache_stats);

  nwep_identity_cache *cache;
  nwep_identity_cache_new(&cache, NULL);

  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  make_test_nodeid(&nodeid, 0x42);
  make_test_pubkey(pubkey, 0x43);

  nwep_tstamp now = 1000 * NWEP_SECONDS;

  /* Store */
  nwep_identity_cache_store(cache, &nodeid, pubkey, 100, now);

  /* Hit */
  nwep_cached_identity identity;
  nwep_identity_cache_lookup(cache, &nodeid, now, &identity);

  /* Miss */
  nwep_nodeid other;
  make_test_nodeid(&other, 0x99);
  nwep_identity_cache_lookup(cache, &other, now, &identity);

  /* Invalidate */
  nwep_identity_cache_invalidate(cache, &nodeid);

  nwep_cache_stats stats;
  nwep_identity_cache_get_stats(cache, &stats);

  ASSERT(stats.stores == 1, "stores count wrong");
  ASSERT(stats.hits == 1, "hits count wrong");
  ASSERT(stats.misses == 1, "misses count wrong");
  ASSERT(stats.invalidations == 1, "invalidations count wrong");

  nwep_identity_cache_reset_stats(cache);
  nwep_identity_cache_get_stats(cache, &stats);
  ASSERT(stats.stores == 0, "stores should be reset");
  ASSERT(stats.hits == 0, "hits should be reset");

  nwep_identity_cache_free(cache);

  PASS();
  return 0;
}

/*
 * Log Server Pool Tests
 */

static int test_pool_settings_default(void) {
  TEST(pool_settings_default);

  nwep_log_server_pool_settings settings;
  nwep_log_server_pool_settings_default(&settings);

  ASSERT(settings.strategy == NWEP_POOL_ROUND_ROBIN,
         "default strategy should be round-robin");
  ASSERT(settings.max_failures == NWEP_POOL_HEALTH_CHECK_FAILURES,
         "default max_failures mismatch");

  PASS();
  return 0;
}

static int test_pool_create_free(void) {
  TEST(pool_create_free);

  nwep_log_server_pool *pool;
  int rv = nwep_log_server_pool_new(&pool, NULL);
  ASSERT(rv == 0, "pool creation failed");
  ASSERT(pool != NULL, "pool should not be NULL");

  ASSERT(nwep_log_server_pool_size(pool) == 0, "initial size should be 0");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

static int test_pool_add_remove(void) {
  TEST(pool_add_remove);

  nwep_log_server_pool *pool;
  nwep_log_server_pool_new(&pool, NULL);

  int rv = nwep_log_server_pool_add(pool, "web://server1.example.com:4433");
  ASSERT(rv == 0, "add server1 failed");
  ASSERT(nwep_log_server_pool_size(pool) == 1, "size should be 1");

  rv = nwep_log_server_pool_add(pool, "web://server2.example.com:4433");
  ASSERT(rv == 0, "add server2 failed");
  ASSERT(nwep_log_server_pool_size(pool) == 2, "size should be 2");

  /* Adding same server should succeed but not duplicate */
  rv = nwep_log_server_pool_add(pool, "web://server1.example.com:4433");
  ASSERT(rv == 0, "add duplicate should succeed");
  ASSERT(nwep_log_server_pool_size(pool) == 2, "size should still be 2");

  rv = nwep_log_server_pool_remove(pool, "web://server1.example.com:4433");
  ASSERT(rv == 0, "remove failed");
  ASSERT(nwep_log_server_pool_size(pool) == 1, "size should be 1");

  rv = nwep_log_server_pool_remove(pool, "web://nonexistent:4433");
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "should fail for nonexistent");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

static int test_pool_select_round_robin(void) {
  TEST(pool_select_round_robin);

  nwep_log_server_pool_settings settings;
  nwep_log_server_pool_settings_default(&settings);
  settings.strategy = NWEP_POOL_ROUND_ROBIN;

  nwep_log_server_pool *pool;
  nwep_log_server_pool_new(&pool, &settings);

  nwep_log_server_pool_add(pool, "web://server1:4433");
  nwep_log_server_pool_add(pool, "web://server2:4433");
  nwep_log_server_pool_add(pool, "web://server3:4433");

  nwep_pool_server server;

  /* First selection should be server1 */
  int rv = nwep_log_server_pool_select(pool, &server);
  ASSERT(rv == 0, "select 1 failed");
  ASSERT(strcmp(server.url, "web://server1:4433") == 0, "should be server1");

  /* Second selection should be server2 */
  rv = nwep_log_server_pool_select(pool, &server);
  ASSERT(rv == 0, "select 2 failed");
  ASSERT(strcmp(server.url, "web://server2:4433") == 0, "should be server2");

  /* Third selection should be server3 */
  rv = nwep_log_server_pool_select(pool, &server);
  ASSERT(rv == 0, "select 3 failed");
  ASSERT(strcmp(server.url, "web://server3:4433") == 0, "should be server3");

  /* Fourth selection should wrap to server1 */
  rv = nwep_log_server_pool_select(pool, &server);
  ASSERT(rv == 0, "select 4 failed");
  ASSERT(strcmp(server.url, "web://server1:4433") == 0, "should wrap to server1");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

static int test_pool_health_tracking(void) {
  TEST(pool_health_tracking);

  nwep_log_server_pool_settings settings;
  nwep_log_server_pool_settings_default(&settings);
  settings.max_failures = 3;

  nwep_log_server_pool *pool;
  nwep_log_server_pool_new(&pool, &settings);

  nwep_log_server_pool_add(pool, "web://server1:4433");
  nwep_log_server_pool_add(pool, "web://server2:4433");

  ASSERT(nwep_log_server_pool_healthy_count(pool) == 2, "both should be healthy");

  nwep_tstamp now = 1000 * NWEP_SECONDS;

  /* Mark server1 as failed 3 times */
  nwep_log_server_pool_mark_failure(pool, "web://server1:4433", now);
  ASSERT(nwep_log_server_pool_healthy_count(pool) == 2, "still healthy after 1 failure");

  nwep_log_server_pool_mark_failure(pool, "web://server1:4433", now);
  ASSERT(nwep_log_server_pool_healthy_count(pool) == 2, "still healthy after 2 failures");

  nwep_log_server_pool_mark_failure(pool, "web://server1:4433", now);
  ASSERT(nwep_log_server_pool_healthy_count(pool) == 1, "unhealthy after 3 failures");

  /* Selection should skip unhealthy server */
  nwep_pool_server server;
  int rv = nwep_log_server_pool_select(pool, &server);
  ASSERT(rv == 0, "select failed");
  ASSERT(strcmp(server.url, "web://server2:4433") == 0, "should select healthy server2");

  /* Mark server1 as successful - should become healthy */
  nwep_log_server_pool_mark_success(pool, "web://server1:4433", now);
  ASSERT(nwep_log_server_pool_healthy_count(pool) == 2, "should be healthy after success");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

static int test_pool_no_healthy_servers(void) {
  TEST(pool_no_healthy_servers);

  nwep_log_server_pool_settings settings;
  nwep_log_server_pool_settings_default(&settings);
  settings.max_failures = 1; /* Fail immediately */

  nwep_log_server_pool *pool;
  nwep_log_server_pool_new(&pool, &settings);

  nwep_log_server_pool_add(pool, "web://server1:4433");

  nwep_tstamp now = 1000 * NWEP_SECONDS;
  nwep_log_server_pool_mark_failure(pool, "web://server1:4433", now);

  ASSERT(nwep_log_server_pool_healthy_count(pool) == 0, "no healthy servers");

  nwep_pool_server server;
  int rv = nwep_log_server_pool_select(pool, &server);
  ASSERT(rv == NWEP_ERR_NETWORK_NO_SERVERS, "should fail with no healthy servers");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

static int test_pool_reset_health(void) {
  TEST(pool_reset_health);

  nwep_log_server_pool_settings settings;
  nwep_log_server_pool_settings_default(&settings);
  settings.max_failures = 1;

  nwep_log_server_pool *pool;
  nwep_log_server_pool_new(&pool, &settings);

  nwep_log_server_pool_add(pool, "web://server1:4433");
  nwep_log_server_pool_add(pool, "web://server2:4433");

  nwep_tstamp now = 1000 * NWEP_SECONDS;
  nwep_log_server_pool_mark_failure(pool, "web://server1:4433", now);
  nwep_log_server_pool_mark_failure(pool, "web://server2:4433", now);

  ASSERT(nwep_log_server_pool_healthy_count(pool) == 0, "no healthy servers");

  nwep_log_server_pool_reset_health(pool);

  ASSERT(nwep_log_server_pool_healthy_count(pool) == 2, "all should be healthy after reset");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

static int test_pool_get_server(void) {
  TEST(pool_get_server);

  nwep_log_server_pool *pool;
  nwep_log_server_pool_new(&pool, NULL);

  nwep_log_server_pool_add(pool, "web://server1:4433");
  nwep_log_server_pool_add(pool, "web://server2:4433");

  nwep_pool_server server;

  int rv = nwep_log_server_pool_get(pool, 0, &server);
  ASSERT(rv == 0, "get index 0 failed");
  ASSERT(strcmp(server.url, "web://server1:4433") == 0, "index 0 should be server1");

  rv = nwep_log_server_pool_get(pool, 1, &server);
  ASSERT(rv == 0, "get index 1 failed");
  ASSERT(strcmp(server.url, "web://server2:4433") == 0, "index 1 should be server2");

  rv = nwep_log_server_pool_get(pool, 2, &server);
  ASSERT(rv == NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE, "index 2 should fail");

  nwep_log_server_pool_free(pool);

  PASS();
  return 0;
}

int main(void) {
  printf("Cache Tests (Phase 17)\n");
  printf("======================\n\n");

  printf("Identity Cache:\n");
  test_cache_settings_default();
  test_cache_create_free();
  test_cache_store_lookup();
  test_cache_lookup_not_found();
  test_cache_expiry();
  test_cache_invalidate();
  test_cache_clear();
  test_cache_lru_eviction();
  test_cache_lru_touch();
  test_cache_on_rotation();
  test_cache_on_revocation();
  test_cache_stats();

  printf("\nLog Server Pool:\n");
  test_pool_settings_default();
  test_pool_create_free();
  test_pool_add_remove();
  test_pool_select_round_robin();
  test_pool_health_tracking();
  test_pool_no_healthy_servers();
  test_pool_reset_health();
  test_pool_get_server();

  printf("\n======================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return tests_passed == tests_run ? 0 : 1;
}
