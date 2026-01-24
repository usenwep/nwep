/*
 * nwep - Client Trust Verification Tests (Phase 15)
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
 * In-memory storage for testing Merkle log
 */

#define MAX_ENTRIES 100

typedef struct {
  uint8_t data[MAX_ENTRIES][NWEP_LOG_ENTRY_MAX_SIZE];
  size_t lengths[MAX_ENTRIES];
  uint64_t count;
} mem_log_storage;

static int mem_log_append(void *user_data, uint64_t index, const uint8_t *entry,
                          size_t entry_len) {
  mem_log_storage *storage = (mem_log_storage *)user_data;
  if (index >= MAX_ENTRIES || entry_len > NWEP_LOG_ENTRY_MAX_SIZE) {
    return NWEP_ERR_STORAGE_WRITE_ERROR;
  }
  memcpy(storage->data[index], entry, entry_len);
  storage->lengths[index] = entry_len;
  if (index >= storage->count) {
    storage->count = index + 1;
  }
  return 0;
}

static nwep_ssize mem_log_get(void *user_data, uint64_t index, uint8_t *buf,
                              size_t buflen) {
  mem_log_storage *storage = (mem_log_storage *)user_data;
  if (index >= storage->count) {
    return NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE;
  }
  size_t len = storage->lengths[index];
  if (buflen < len) {
    return NWEP_ERR_PROTO_MSG_TOO_LARGE;
  }
  memcpy(buf, storage->data[index], len);
  return (nwep_ssize)len;
}

static uint64_t mem_log_size(void *user_data) {
  mem_log_storage *storage = (mem_log_storage *)user_data;
  return storage->count;
}

/*
 * Helper: Create a valid checkpoint signed by given anchors
 */
static int create_signed_checkpoint(nwep_checkpoint *cp, uint64_t epoch,
                                    nwep_tstamp timestamp, uint64_t log_size,
                                    const nwep_merkle_hash *root,
                                    nwep_bls_keypair *anchors, size_t num_anchors) {
  int rv;

  rv = nwep_checkpoint_new(cp, epoch, timestamp, root, log_size);
  if (rv != 0) {
    return rv;
  }

  /* Sign with each anchor */
  for (size_t i = 0; i < num_anchors; i++) {
    rv = nwep_checkpoint_sign(cp, &anchors[i]);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

/*
 * Trust Store Creation Tests
 */

static int test_trust_store_new_default(void) {
  TEST(trust_store_new_default);

  nwep_trust_store *store;
  int rv;

  rv = nwep_trust_store_new(&store, NULL, NULL);
  ASSERT(rv == 0, "trust store creation failed");
  ASSERT(store != NULL, "store should not be NULL");

  const nwep_anchor_set *anchors = nwep_trust_store_get_anchors(store);
  ASSERT(anchors != NULL, "anchors should not be NULL");
  ASSERT(nwep_anchor_set_size(anchors) == 0, "initial anchor count should be 0");
  ASSERT(nwep_trust_store_checkpoint_count(store) == 0,
         "initial checkpoint count should be 0");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

static int test_trust_store_new_with_settings(void) {
  TEST(trust_store_new_with_settings);

  nwep_trust_store *store;
  nwep_trust_settings settings;
  int rv;

  nwep_trust_settings_default(&settings);
  settings.staleness_warning_ns = 30 * NWEP_SECONDS;
  settings.staleness_reject_ns = 60 * NWEP_SECONDS;
  settings.anchor_threshold = 3;

  rv = nwep_trust_store_new(&store, &settings, NULL);
  ASSERT(rv == 0, "trust store creation with settings failed");

  const nwep_anchor_set *anchors = nwep_trust_store_get_anchors(store);
  ASSERT(nwep_anchor_set_threshold(anchors) == 3, "threshold should be 3");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Anchor Management Tests
 */

static int test_trust_store_anchor_add_remove(void) {
  TEST(trust_store_anchor_add_remove);

  nwep_trust_store *store;
  nwep_bls_keypair kp1, kp2;
  nwep_bls_pubkey pk1, pk2;
  int rv;

  rv = nwep_trust_store_new(&store, NULL, NULL);
  ASSERT(rv == 0, "trust store creation failed");

  /* Generate keypairs */
  uint8_t seed1[32] = {0x01};
  uint8_t seed2[32] = {0x02};
  rv = nwep_bls_keypair_from_seed(&kp1, seed1, sizeof(seed1));
  ASSERT(rv == 0, "keypair 1 generation failed");
  rv = nwep_bls_keypair_from_seed(&kp2, seed2, sizeof(seed2));
  ASSERT(rv == 0, "keypair 2 generation failed");

  memcpy(pk1.data, kp1.pubkey, NWEP_BLS_PUBKEY_LEN);
  memcpy(pk2.data, kp2.pubkey, NWEP_BLS_PUBKEY_LEN);

  /* Add anchors */
  rv = nwep_trust_store_add_anchor(store, &pk1, 1); /* builtin */
  ASSERT(rv == 0, "add anchor 1 failed");

  rv = nwep_trust_store_add_anchor(store, &pk2, 0); /* non-builtin */
  ASSERT(rv == 0, "add anchor 2 failed");

  const nwep_anchor_set *anchors = nwep_trust_store_get_anchors(store);
  ASSERT(nwep_anchor_set_size(anchors) == 2, "should have 2 anchors");

  /* Remove non-builtin anchor */
  rv = nwep_trust_store_remove_anchor(store, &pk2);
  ASSERT(rv == 0, "remove anchor 2 failed");
  ASSERT(nwep_anchor_set_size(anchors) == 1, "should have 1 anchor");

  /* Cannot remove builtin anchor */
  rv = nwep_trust_store_remove_anchor(store, &pk1);
  ASSERT(rv != 0, "should not remove builtin anchor");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Checkpoint Management Tests
 */

static int test_trust_store_checkpoint_add_get(void) {
  TEST(trust_store_checkpoint_add_get);

  nwep_trust_store *store;
  nwep_trust_settings settings;
  nwep_bls_keypair anchors[5];
  nwep_bls_pubkey pks[5];
  nwep_checkpoint cp, retrieved;
  nwep_merkle_hash root;
  int rv;

  /* Create store with threshold 3 */
  nwep_trust_settings_default(&settings);
  settings.anchor_threshold = 3;
  rv = nwep_trust_store_new(&store, &settings, NULL);
  ASSERT(rv == 0, "trust store creation failed");

  /* Generate 5 anchor keypairs and add to store */
  for (int i = 0; i < 5; i++) {
    uint8_t seed[32];
    memset(seed, (uint8_t)i, sizeof(seed));
    rv = nwep_bls_keypair_from_seed(&anchors[i], seed, sizeof(seed));
    ASSERT(rv == 0, "keypair generation failed");
    memcpy(pks[i].data, anchors[i].pubkey, NWEP_BLS_PUBKEY_LEN);
    rv = nwep_trust_store_add_anchor(store, &pks[i], 1);
    ASSERT(rv == 0, "add anchor failed");
  }

  /* Create signed checkpoint */
  memset(&root, 0x42, sizeof(root));
  rv = create_signed_checkpoint(&cp, 100, 1000 * NWEP_SECONDS, 1000, &root,
                                anchors, 3);
  ASSERT(rv == 0, "checkpoint creation failed");

  /* Add checkpoint */
  rv = nwep_trust_store_add_checkpoint(store, &cp);
  ASSERT(rv == 0, "add checkpoint failed");
  ASSERT(nwep_trust_store_checkpoint_count(store) == 1, "should have 1 checkpoint");

  /* Get latest checkpoint */
  rv = nwep_trust_store_get_latest_checkpoint(store, &retrieved);
  ASSERT(rv == 0, "get latest checkpoint failed");
  ASSERT(retrieved.epoch == 100, "epoch should be 100");
  ASSERT(retrieved.log_size == 1000, "log size should be 1000");

  /* Get by epoch */
  rv = nwep_trust_store_get_checkpoint(store, 100, &retrieved);
  ASSERT(rv == 0, "get checkpoint by epoch failed");
  ASSERT(retrieved.epoch == 100, "epoch should be 100");

  /* Non-existent epoch */
  rv = nwep_trust_store_get_checkpoint(store, 999, &retrieved);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "should not find epoch 999");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Staleness Detection Tests
 */

static int test_trust_store_staleness(void) {
  TEST(trust_store_staleness);

  nwep_trust_store *store;
  nwep_trust_settings settings;
  nwep_bls_keypair anchors[3];
  nwep_bls_pubkey pks[3];
  nwep_checkpoint cp;
  nwep_merkle_hash root;
  nwep_staleness status;
  int rv;

  /* Create store with short staleness thresholds */
  nwep_trust_settings_default(&settings);
  settings.staleness_warning_ns = 10 * NWEP_SECONDS;
  settings.staleness_reject_ns = 20 * NWEP_SECONDS;
  settings.anchor_threshold = 2;
  rv = nwep_trust_store_new(&store, &settings, NULL);
  ASSERT(rv == 0, "trust store creation failed");

  /* No checkpoints = REJECT */
  status = nwep_trust_store_check_staleness(store, 100 * NWEP_SECONDS);
  ASSERT(status == NWEP_STALENESS_REJECT, "no checkpoints should reject");

  /* Generate 3 anchor keypairs and add to store */
  for (int i = 0; i < 3; i++) {
    uint8_t seed[32];
    memset(seed, (uint8_t)i, sizeof(seed));
    rv = nwep_bls_keypair_from_seed(&anchors[i], seed, sizeof(seed));
    ASSERT(rv == 0, "keypair generation failed");
    memcpy(pks[i].data, anchors[i].pubkey, NWEP_BLS_PUBKEY_LEN);
    rv = nwep_trust_store_add_anchor(store, &pks[i], 1);
    ASSERT(rv == 0, "add anchor failed");
  }

  /* Create checkpoint at t=100s */
  memset(&root, 0, sizeof(root));
  rv = create_signed_checkpoint(&cp, 1, 100 * NWEP_SECONDS, 10, &root,
                                anchors, 2);
  ASSERT(rv == 0, "checkpoint creation failed");
  rv = nwep_trust_store_add_checkpoint(store, &cp);
  ASSERT(rv == 0, "add checkpoint failed");

  /* Check at t=105s (5s old) = FRESH */
  status = nwep_trust_store_check_staleness(store, 105 * NWEP_SECONDS);
  ASSERT(status == NWEP_STALENESS_FRESH, "5s old should be fresh");

  /* Check at t=115s (15s old) = WARNING */
  status = nwep_trust_store_check_staleness(store, 115 * NWEP_SECONDS);
  ASSERT(status == NWEP_STALENESS_WARNING, "15s old should be warning");

  /* Check at t=125s (25s old) = REJECT */
  status = nwep_trust_store_check_staleness(store, 125 * NWEP_SECONDS);
  ASSERT(status == NWEP_STALENESS_REJECT, "25s old should be reject");

  /* Get staleness age */
  nwep_duration age = nwep_trust_store_get_staleness_age(store, 115 * NWEP_SECONDS);
  ASSERT(age == 15 * NWEP_SECONDS, "age should be 15 seconds");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Identity Verification Tests
 */

static int test_trust_store_verify_identity(void) {
  TEST(trust_store_verify_identity);

  nwep_trust_store *store;
  nwep_trust_settings settings;
  nwep_bls_keypair bls_anchors[3];
  nwep_bls_pubkey pks[3];
  nwep_keypair identity_kp;
  nwep_merkle_log *log;
  nwep_merkle_entry entry;
  nwep_merkle_proof proof;
  nwep_checkpoint cp;
  nwep_merkle_hash root;
  nwep_verified_identity result;
  mem_log_storage mem_storage;
  nwep_log_storage log_storage;
  int rv;

  /* Create store */
  nwep_trust_settings_default(&settings);
  settings.anchor_threshold = 2;
  settings.staleness_reject_ns = 100 * NWEP_SECONDS;
  rv = nwep_trust_store_new(&store, &settings, NULL);
  ASSERT(rv == 0, "trust store creation failed");

  /* Generate BLS anchors */
  for (int i = 0; i < 3; i++) {
    uint8_t seed[32];
    memset(seed, (uint8_t)i, sizeof(seed));
    rv = nwep_bls_keypair_from_seed(&bls_anchors[i], seed, sizeof(seed));
    ASSERT(rv == 0, "BLS keypair generation failed");
    memcpy(pks[i].data, bls_anchors[i].pubkey, NWEP_BLS_PUBKEY_LEN);
    rv = nwep_trust_store_add_anchor(store, &pks[i], 1);
    ASSERT(rv == 0, "add anchor failed");
  }

  /* Create identity and merkle log entry */
  rv = nwep_keypair_generate(&identity_kp);
  ASSERT(rv == 0, "identity keypair generation failed");

  rv = nwep_nodeid_from_pubkey(&entry.nodeid, identity_kp.pubkey);
  ASSERT(rv == 0, "nodeid derivation failed");
  memcpy(entry.pubkey, identity_kp.pubkey, NWEP_ED25519_PUBKEY_LEN);
  entry.type = NWEP_LOG_ENTRY_KEY_BINDING;
  entry.timestamp = 50 * NWEP_SECONDS;
  memset(entry.signature, 0, sizeof(entry.signature));
  memset(entry.recovery_pubkey, 0, sizeof(entry.recovery_pubkey));

  /* Create log with in-memory storage */
  memset(&mem_storage, 0, sizeof(mem_storage));
  log_storage.append = mem_log_append;
  log_storage.get = mem_log_get;
  log_storage.size = mem_log_size;
  log_storage.user_data = &mem_storage;

  rv = nwep_merkle_log_new(&log, &log_storage);
  ASSERT(rv == 0, "merkle log creation failed");

  rv = nwep_merkle_log_append(log, &entry, NULL);
  ASSERT(rv == 0, "merkle log append failed");

  /* Get root and proof */
  rv = nwep_merkle_log_root(log, &root);
  ASSERT(rv == 0, "merkle log root failed");

  rv = nwep_merkle_log_prove(log, 0, &proof);
  ASSERT(rv == 0, "merkle log prove failed");

  /* Create signed checkpoint with the merkle root */
  rv = create_signed_checkpoint(&cp, 1, 100 * NWEP_SECONDS, 1, &root,
                                bls_anchors, 2);
  ASSERT(rv == 0, "checkpoint creation failed");
  rv = nwep_trust_store_add_checkpoint(store, &cp);
  ASSERT(rv == 0, "add checkpoint failed");

  /* Verify identity against checkpoint */
  rv = nwep_trust_store_verify_identity(store, &entry, &proof, &cp,
                                         150 * NWEP_SECONDS, &result);
  ASSERT(rv == 0, "identity verification failed");
  ASSERT(memcmp(result.nodeid.data, entry.nodeid.data, NWEP_NODEID_LEN) == 0,
         "nodeid should match");
  ASSERT(result.log_index == 0, "log index should be 0");
  ASSERT(result.checkpoint_epoch == 1, "checkpoint epoch should be 1");
  ASSERT(result.revoked == 0, "should not be revoked");

  nwep_merkle_log_free(log);
  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Identity Caching Tests
 */

static int test_trust_store_identity_cache(void) {
  TEST(trust_store_identity_cache);

  nwep_trust_store *store;
  nwep_trust_settings settings;
  nwep_nodeid nodeid;
  nwep_verified_identity identity, retrieved;
  int rv;

  /* Create store with short cache TTL */
  nwep_trust_settings_default(&settings);
  settings.identity_cache_ttl = 10 * NWEP_SECONDS;
  rv = nwep_trust_store_new(&store, &settings, NULL);
  ASSERT(rv == 0, "trust store creation failed");

  /* Create identity */
  memset(&nodeid, 0x42, sizeof(nodeid));
  memset(&identity, 0, sizeof(identity));
  memcpy(&identity.nodeid, &nodeid, sizeof(nodeid));
  identity.verified_at = 100 * NWEP_SECONDS;
  identity.checkpoint_epoch = 5;

  /* Cache identity */
  rv = nwep_trust_store_cache_identity(store, &identity);
  ASSERT(rv == 0, "cache identity failed");

  /* Lookup within TTL */
  rv = nwep_trust_store_lookup_identity(store, &nodeid, 105 * NWEP_SECONDS, &retrieved);
  ASSERT(rv == 0, "lookup identity failed");
  ASSERT(memcmp(retrieved.nodeid.data, nodeid.data, NWEP_NODEID_LEN) == 0,
         "nodeid should match");
  ASSERT(retrieved.checkpoint_epoch == 5, "epoch should match");

  /* Lookup after TTL expired */
  rv = nwep_trust_store_lookup_identity(store, &nodeid, 115 * NWEP_SECONDS, &retrieved);
  ASSERT(rv == NWEP_ERR_TRUST_NODE_NOT_FOUND, "should not find expired identity");

  /* Lookup non-existent identity */
  nwep_nodeid other;
  memset(&other, 0x99, sizeof(other));
  rv = nwep_trust_store_lookup_identity(store, &other, 100 * NWEP_SECONDS, &retrieved);
  ASSERT(rv == NWEP_ERR_TRUST_NODE_NOT_FOUND, "should not find other identity");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Equivocation Detection Tests
 */

static int test_trust_store_equivocation(void) {
  TEST(trust_store_equivocation);

  nwep_trust_store *store;
  nwep_trust_settings settings;
  nwep_bls_keypair anchors[3];
  nwep_bls_pubkey pks[3];
  nwep_checkpoint cp1, cp2;
  nwep_merkle_hash root1, root2;
  nwep_equivocation eq;
  int rv;

  /* Create store */
  nwep_trust_settings_default(&settings);
  settings.anchor_threshold = 2;
  rv = nwep_trust_store_new(&store, &settings, NULL);
  ASSERT(rv == 0, "trust store creation failed");

  /* Generate anchors */
  for (int i = 0; i < 3; i++) {
    uint8_t seed[32];
    memset(seed, (uint8_t)i, sizeof(seed));
    rv = nwep_bls_keypair_from_seed(&anchors[i], seed, sizeof(seed));
    ASSERT(rv == 0, "keypair generation failed");
    memcpy(pks[i].data, anchors[i].pubkey, NWEP_BLS_PUBKEY_LEN);
    rv = nwep_trust_store_add_anchor(store, &pks[i], 1);
    ASSERT(rv == 0, "add anchor failed");
  }

  /* Create first checkpoint at epoch 10 */
  memset(&root1, 0x11, sizeof(root1));
  rv = create_signed_checkpoint(&cp1, 10, 100 * NWEP_SECONDS, 100, &root1,
                                anchors, 2);
  ASSERT(rv == 0, "checkpoint 1 creation failed");
  rv = nwep_trust_store_add_checkpoint(store, &cp1);
  ASSERT(rv == 0, "add checkpoint 1 failed");

  /* Same epoch, same root = OK (no equivocation) */
  rv = nwep_trust_store_check_equivocation(store, &cp1, &eq);
  ASSERT(rv == 0, "same checkpoint should not be equivocation");

  /* Create conflicting checkpoint at same epoch with different root */
  memset(&root2, 0x22, sizeof(root2));
  rv = create_signed_checkpoint(&cp2, 10, 100 * NWEP_SECONDS, 100, &root2,
                                anchors, 2);
  ASSERT(rv == 0, "checkpoint 2 creation failed");

  /* Check equivocation - should detect it */
  rv = nwep_trust_store_check_equivocation(store, &cp2, &eq);
  ASSERT(rv == NWEP_ERR_TRUST_EQUIVOCATION, "should detect equivocation");
  ASSERT(eq.epoch == 10, "equivocation epoch should be 10");
  ASSERT(memcmp(eq.root1.data, root1.data, 32) == 0, "root1 should match");
  ASSERT(memcmp(eq.root2.data, root2.data, 32) == 0, "root2 should match");

  /* Cannot add conflicting checkpoint */
  rv = nwep_trust_store_add_checkpoint(store, &cp2);
  ASSERT(rv == NWEP_ERR_TRUST_EQUIVOCATION, "should not add conflicting checkpoint");

  nwep_trust_store_free(store);

  PASS();
  return 0;
}

/*
 * Main
 */

int main(void) {
  int rv;

  printf("Client Trust Verification Tests (Phase 15)\n");
  printf("==========================================\n");

  printf("\nTrust Store Creation:\n");
  if ((rv = test_trust_store_new_default()) != 0) {
    return rv;
  }
  if ((rv = test_trust_store_new_with_settings()) != 0) {
    return rv;
  }

  printf("\nAnchor Management:\n");
  if ((rv = test_trust_store_anchor_add_remove()) != 0) {
    return rv;
  }

  printf("\nCheckpoint Management:\n");
  if ((rv = test_trust_store_checkpoint_add_get()) != 0) {
    return rv;
  }

  printf("\nStaleness Detection:\n");
  if ((rv = test_trust_store_staleness()) != 0) {
    return rv;
  }

  printf("\nIdentity Verification:\n");
  if ((rv = test_trust_store_verify_identity()) != 0) {
    return rv;
  }

  printf("\nIdentity Caching:\n");
  if ((rv = test_trust_store_identity_cache()) != 0) {
    return rv;
  }

  printf("\nEquivocation Detection:\n");
  if ((rv = test_trust_store_equivocation()) != 0) {
    return rv;
  }

  printf("\n==========================================\n");
  printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

  return tests_passed == tests_run ? 0 : 1;
}
